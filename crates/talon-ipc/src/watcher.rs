//! The polling watcher: namespace resolution, bounded scans, claim-then-
//! dispatch processing and quarantine bookkeeping.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde_json::json;
use talon_core::audit::{SharedAuditSink, event};
use talon_core::paths::is_valid_group_folder;
use talon_core::types::RegisteredGroup;
use tokio_util::sync::CancellationToken;

use crate::authz::{FnAuthorizer, IpcAuthorizer};
use crate::config::IpcWatcherConfig;
use crate::fsio::{
    QuarantineRecord, ReadOutcome, Removal, SubDir, list_json, open_base, open_errors_dir,
    open_subdir, prune_quarantine, read_entry, remove_entry, write_quarantine,
};
use crate::host::{IpcHost, SourceIdentity};
use crate::json::{parse_outbound, parse_task, truncate_reason};
use crate::process::IpcOutcome;
use crate::ratelimit::AuditLimiter;
use crate::store::TaskStore;

/// Counters for one scan (observability and tests).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Namespaces (registered lanes) visited.
    pub namespaces: usize,
    /// Files claimed (removed from the IPC directory) and handled.
    pub files: usize,
    /// Outbound messages delivered.
    pub messages_sent: usize,
    /// Task operations applied (including group registration / refresh).
    pub tasks_applied: usize,
    /// Requests denied by authorization or rejected by validation.
    pub denied: usize,
    /// Authorized requests whose execution failed (dead-lettered).
    pub failed: usize,
    /// Unsafe / malformed files quarantined.
    pub quarantined: usize,
    /// Files left in place for a later scan (per-scan limit or shutdown).
    pub deferred: usize,
}

/// Which IPC directory of a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirKind {
    Messages,
    Tasks,
}

impl DirKind {
    fn name(self) -> &'static str {
        match self {
            DirKind::Messages => "messages",
            DirKind::Tasks => "tasks",
        }
    }
}

/// `ipc_key -> identity` for the current registrations.
#[derive(Debug, Default)]
pub(crate) struct Namespaces {
    /// Keys owned unambiguously by one folder / privilege level.
    pub identities: BTreeMap<String, SourceIdentity>,
    /// Keys claimed by lanes that disagree on folder or main-ness. These are
    /// not processed at all (fail closed) until the registration is fixed.
    pub conflicts: BTreeSet<String>,
    /// Keys (or folders) that fail group-folder validation.
    pub invalid: BTreeSet<String>,
}

/// Map each registered lane's IPC key to its owning group's identity.
pub(crate) fn resolve_namespaces(groups: &HashMap<String, RegisteredGroup>) -> Namespaces {
    let mut ns = Namespaces::default();
    for g in groups.values() {
        let key = g.ipc_key();
        if !is_valid_group_folder(key) || !is_valid_group_folder(&g.folder) {
            ns.invalid.insert(truncate_reason(key));
            continue;
        }
        if ns.conflicts.contains(key) {
            continue;
        }
        let id = SourceIdentity::of_group(g);
        match ns.identities.get(key) {
            None => {
                ns.identities.insert(key.to_string(), id);
            }
            Some(prev) if *prev == id => {}
            Some(_) => {
                ns.identities.remove(key);
                ns.conflicts.insert(key.to_string());
            }
        }
    }
    ns
}

struct BatchEntry {
    name: CString,
    outcome: ReadOutcome,
    /// For rejected entries: result of removing them during the read phase.
    removal: Option<io::Result<Removal>>,
}

struct Batch {
    dir: OwnedFd,
    entries: Vec<BatchEntry>,
    deferred: usize,
    truncated: bool,
}

enum BatchResult {
    Missing,
    Unsafe(String),
    Ready(Batch),
}

/// Blocking read phase for one `<key>/<kind>/` directory: pin the directory
/// by descriptor, list, sort, take the per-scan quota, read each candidate
/// safely, and remove the ones that are rejected outright.
fn read_batch(
    base: &OwnedFd,
    key: &str,
    kind: DirKind,
    limit: usize,
    max_entries: usize,
    max_bytes: u64,
) -> io::Result<BatchResult> {
    let ns = match open_subdir(base.as_fd(), key)? {
        SubDir::Opened(fd) => fd,
        SubDir::Missing => return Ok(BatchResult::Missing),
        SubDir::Unsafe(r) => return Ok(BatchResult::Unsafe(r)),
    };
    let dir = match open_subdir(ns.as_fd(), kind.name())? {
        SubDir::Opened(fd) => fd,
        SubDir::Missing => return Ok(BatchResult::Missing),
        SubDir::Unsafe(r) => return Ok(BatchResult::Unsafe(r)),
    };
    let listing = list_json(dir.as_fd(), max_entries)?;
    let deferred = listing.names.len().saturating_sub(limit);
    let mut entries = Vec::with_capacity(listing.names.len().min(limit));
    for name in listing.names.into_iter().take(limit) {
        let outcome = read_entry(dir.as_fd(), &name, max_bytes);
        let removal = match outcome {
            ReadOutcome::Rejected { .. } => Some(remove_entry(dir.as_fd(), &name)),
            _ => None,
        };
        entries.push(BatchEntry {
            name,
            outcome,
            removal,
        });
    }
    Ok(BatchResult::Ready(Batch {
        dir,
        entries,
        deferred,
        truncated: listing.truncated,
    }))
}

/// Per-scan mutable bookkeeping.
struct ScanCtx<'a> {
    stats: ScanStats,
    quarantine: Vec<QuarantineRecord>,
    /// Problems observed in this scan (for warn-once logging).
    issues: HashSet<String>,
    /// Problems already reported in the previous scan.
    reported: &'a HashSet<String>,
}

impl ScanCtx<'_> {
    /// Track a persistent problem; true the first time it is seen.
    fn report_once(&mut self, key: String) -> bool {
        let first = !self.reported.contains(&key);
        self.issues.insert(key);
        first
    }
}

#[derive(Debug, Default)]
struct ScanState {
    reported: HashSet<String>,
}

/// Host-side IPC watcher (port of `src/ipc.ts`, hardened).
///
/// Polls `data/ipc/<ipc_key>/{messages,tasks}/` of every registered lane,
/// derives the sender identity from the directory, authorizes every request
/// through `talon_security::ipc_authz` (plus the built-in baseline), applies
/// task operations through the [`TaskStore`] and host callbacks through the
/// [`IpcHost`], and audits every decision.
///
/// Files are *claimed* (unlinked) before they are dispatched, so a crash can
/// never replay a request (at-most-once); files whose handling fails after
/// the claim are kept as dead letters in `data/ipc/errors/`.
pub struct IpcWatcher {
    pub(crate) config: IpcWatcherConfig,
    pub(crate) store: Arc<dyn TaskStore>,
    pub(crate) host: Arc<dyn IpcHost>,
    pub(crate) audit: SharedAuditSink,
    pub(crate) authorizer: Arc<dyn IpcAuthorizer>,
    pub(crate) audit_limiter: AuditLimiter,
    running: AtomicBool,
    scan: tokio::sync::Mutex<ScanState>,
    seq: AtomicU64,
}

impl std::fmt::Debug for IpcWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IpcWatcher")
            .field("config", &self.config)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

struct RunningGuard<'a>(&'a AtomicBool);

impl Drop for RunningGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl IpcWatcher {
    /// Create a watcher. `db` is normally a `talon_db::Db` clone; the
    /// production authorization policy (`talon_security::ipc_authz`) is
    /// installed by default.
    pub fn new(
        config: IpcWatcherConfig,
        db: impl TaskStore + 'static,
        host: Arc<dyn IpcHost>,
        audit: SharedAuditSink,
    ) -> Self {
        let audit_limiter = AuditLimiter::new(config.audit_max_per_window, config.audit_window);
        Self {
            config,
            store: Arc::new(db),
            host,
            audit,
            authorizer: Arc::new(FnAuthorizer::security_policy()),
            audit_limiter,
            running: AtomicBool::new(false),
            scan: tokio::sync::Mutex::new(ScanState::default()),
            seq: AtomicU64::new(0),
        }
    }

    /// Replace the authorization policy. The built-in baseline rules are
    /// still enforced on top of it (they can only deny).
    pub fn with_authorizer(mut self, authorizer: Arc<dyn IpcAuthorizer>) -> Self {
        self.authorizer = authorizer;
        self
    }

    /// The active configuration.
    pub fn config(&self) -> &IpcWatcherConfig {
        &self.config
    }

    /// Poll until `cancel` fires. A second concurrent `run` on the same
    /// watcher returns immediately. Cancellation is checked between files:
    /// unclaimed files stay on disk for the next start.
    pub async fn run(&self, cancel: CancellationToken) {
        if self.running.swap(true, Ordering::SeqCst) {
            tracing::debug!("IPC watcher already running, skipping duplicate start");
            return;
        }
        let _guard = RunningGuard(&self.running);
        tracing::info!(dir = %self.config.ipc_dir.display(), "IPC watcher started (per-lane namespaces)");
        loop {
            if cancel.is_cancelled() {
                break;
            }
            let stats = self.scan_inner(Some(&cancel)).await;
            if stats.files > 0 || stats.quarantined > 0 {
                tracing::debug!(?stats, "IPC scan complete");
            }
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(self.config.poll_interval) => {}
            }
        }
        tracing::info!("IPC watcher stopped");
    }

    /// Run a single scan over all registered namespaces.
    pub async fn scan_once(&self) -> ScanStats {
        self.scan_inner(None).await
    }

    async fn scan_inner(&self, cancel: Option<&CancellationToken>) -> ScanStats {
        let mut state = self.scan.lock().await;
        // Report audit rows suppressed in windows that have ended since the
        // last scan (MYTH-11).
        self.flush_audit_summaries();
        let groups = self.host.registered_groups();
        let ns = resolve_namespaces(&groups);
        let mut ctx = ScanCtx {
            stats: ScanStats::default(),
            quarantine: Vec::new(),
            issues: HashSet::new(),
            reported: &state.reported,
        };
        for key in &ns.conflicts {
            if ctx.report_once(format!("conflict:{key}")) {
                tracing::warn!(ipc_key = %key, "IPC namespace is shared by lanes with different folders or privileges; ignoring it until the registration is fixed");
            }
        }
        for key in &ns.invalid {
            if ctx.report_once(format!("invalid:{key}")) {
                tracing::warn!(ipc_key = %key, "registered lane has an invalid IPC key or folder; ignoring it");
            }
        }

        let path = self.config.ipc_dir.clone();
        let base = match tokio::task::spawn_blocking(move || open_base(&path)).await {
            Ok(Ok(fd)) => Arc::new(fd),
            Ok(Err(e)) => {
                if ctx.report_once("base".into()) {
                    tracing::error!(error = %e, dir = %self.config.ipc_dir.display(), "cannot open IPC directory");
                }
                let issues = std::mem::take(&mut ctx.issues);
                let stats = ctx.stats;
                state.reported = issues;
                return stats;
            }
            Err(e) => {
                tracing::error!(error = %e, "IPC scan task failed");
                return ctx.stats;
            }
        };

        'namespaces: for (key, identity) in &ns.identities {
            ctx.stats.namespaces += 1;
            for kind in [DirKind::Messages, DirKind::Tasks] {
                if cancel.is_some_and(CancellationToken::is_cancelled) {
                    break 'namespaces;
                }
                let limit = match kind {
                    DirKind::Messages => self.config.max_messages_per_scan,
                    DirKind::Tasks => self.config.max_tasks_per_scan,
                };
                let (base2, key2) = (Arc::clone(&base), key.clone());
                let (max_entries, max_bytes) =
                    (self.config.max_dir_entries, self.config.max_file_bytes);
                let result = tokio::task::spawn_blocking(move || {
                    read_batch(&base2, &key2, kind, limit, max_entries, max_bytes)
                })
                .await;
                match result {
                    Ok(Ok(BatchResult::Missing)) => {}
                    Ok(Ok(BatchResult::Unsafe(reason))) => {
                        if ctx.report_once(format!("unsafe:{key}/{}", kind.name())) {
                            let reason = truncate_reason(&reason);
                            tracing::warn!(ipc_key = %key, dir = kind.name(), %reason, "refusing to process IPC directory");
                            self.audit_event(
                                key,
                                &identity.folder,
                                event(
                                    "ipc.file.rejected",
                                    &identity.folder,
                                    Some(kind.name()),
                                    "denied",
                                    json!({ "ipcKey": key, "dir": kind.name(), "reason": reason }),
                                ),
                                false,
                            );
                        }
                    }
                    Ok(Ok(BatchResult::Ready(batch))) => {
                        self.process_batch(identity, kind, batch, cancel, &mut ctx)
                            .await;
                    }
                    Ok(Err(e)) => {
                        if ctx.report_once(format!("io:{key}/{}", kind.name())) {
                            tracing::error!(ipc_key = %key, dir = kind.name(), error = %e, "error reading IPC directory");
                        }
                    }
                    Err(e) => tracing::error!(error = %e, "IPC read task failed"),
                }
            }
        }

        let records = std::mem::take(&mut ctx.quarantine);
        self.persist_quarantine(&base, records).await;
        let issues = std::mem::take(&mut ctx.issues);
        let stats = ctx.stats;
        state.reported = issues;
        stats
    }

    async fn process_batch(
        &self,
        identity: &SourceIdentity,
        kind: DirKind,
        batch: Batch,
        cancel: Option<&CancellationToken>,
        ctx: &mut ScanCtx<'_>,
    ) {
        let Batch {
            dir,
            entries,
            deferred,
            truncated,
        } = batch;
        ctx.stats.deferred += deferred;
        if deferred > 0 {
            tracing::debug!(ipc_key = %identity.ipc_key, dir = kind.name(), deferred, "per-scan IPC limit reached; remaining files wait for the next scan");
        }
        if truncated && ctx.report_once(format!("flood:{}/{}", identity.ipc_key, kind.name())) {
            tracing::warn!(ipc_key = %identity.ipc_key, dir = kind.name(), max_entries = self.config.max_dir_entries, "IPC directory exceeds the entry limit; possible flood");
        }

        for entry in entries {
            let display = truncate_reason(&String::from_utf8_lossy(entry.name.to_bytes()));
            match entry.outcome {
                ReadOutcome::Vanished => {}
                ReadOutcome::Rejected { reason, content } => match entry.removal {
                    Some(Ok(Removal::Removed)) => {
                        self.quarantine(identity, kind, display, reason, content, ctx);
                    }
                    Some(Ok(Removal::Vanished)) => {}
                    Some(Err(e)) => self.report_stuck(identity, kind, &display, &e, ctx),
                    None => {}
                },
                ReadOutcome::Ok(bytes) => {
                    if cancel.is_some_and(CancellationToken::is_cancelled) {
                        ctx.stats.deferred += 1;
                        continue;
                    }
                    // Claim before dispatch: whoever unlinks the file owns it.
                    match remove_entry(dir.as_fd(), &entry.name) {
                        Ok(Removal::Removed) => {}
                        Ok(Removal::Vanished) => continue,
                        Err(e) => {
                            self.report_stuck(identity, kind, &display, &e, ctx);
                            continue;
                        }
                    }
                    ctx.stats.files += 1;
                    self.dispatch(identity, kind, display, bytes, ctx).await;
                }
            }
        }
    }

    async fn dispatch(
        &self,
        identity: &SourceIdentity,
        kind: DirKind,
        display: String,
        bytes: Vec<u8>,
        ctx: &mut ScanCtx<'_>,
    ) {
        let depth = self.config.max_json_depth;
        let outcome = match kind {
            DirKind::Messages => match parse_outbound(&bytes, depth) {
                Ok(msg) => self.process_message(identity, msg).await,
                Err(reason) => {
                    self.quarantine(identity, kind, display, reason, Some(bytes), ctx);
                    return;
                }
            },
            DirKind::Tasks => match parse_task(&bytes, depth) {
                Ok(task) => self.process_task(identity, task).await,
                Err(reason) => {
                    self.quarantine(identity, kind, display, reason, Some(bytes), ctx);
                    return;
                }
            },
        };
        match outcome {
            IpcOutcome::Applied => match kind {
                DirKind::Messages => ctx.stats.messages_sent += 1,
                DirKind::Tasks => ctx.stats.tasks_applied += 1,
            },
            IpcOutcome::Denied(_) | IpcOutcome::Rejected(_) => ctx.stats.denied += 1,
            IpcOutcome::Failed(error) => {
                ctx.stats.failed += 1;
                ctx.quarantine.push(QuarantineRecord {
                    ipc_key: identity.ipc_key.clone(),
                    folder: identity.folder.clone(),
                    dir: kind.name(),
                    file: display,
                    reason: truncate_reason(&error),
                    content: Some(bytes),
                    dead_letter: true,
                });
            }
        }
    }

    fn quarantine(
        &self,
        identity: &SourceIdentity,
        kind: DirKind,
        file: String,
        reason: String,
        content: Option<Vec<u8>>,
        ctx: &mut ScanCtx<'_>,
    ) {
        // `file` is already sanitized (see `process_batch`); reasons may echo
        // container input (serde errors), so neutralize them as well.
        let reason = truncate_reason(&reason);
        let written = self.audit_event(
            &identity.ipc_key,
            &identity.folder,
            event(
                "ipc.file.rejected",
                &identity.folder,
                Some(&file),
                "denied",
                json!({ "ipcKey": identity.ipc_key, "dir": kind.name(), "reason": reason }),
            ),
            false,
        );
        if written {
            tracing::warn!(ipc_key = %identity.ipc_key, dir = kind.name(), file = %file, reason = %reason, "rejected IPC file quarantined");
        } else {
            tracing::debug!(ipc_key = %identity.ipc_key, dir = kind.name(), file = %file, reason = %reason, "rejected IPC file quarantined (audit suppressed)");
        }
        ctx.stats.quarantined += 1;
        ctx.quarantine.push(QuarantineRecord {
            ipc_key: identity.ipc_key.clone(),
            folder: identity.folder.clone(),
            dir: kind.name(),
            file,
            reason,
            content,
            dead_letter: false,
        });
    }

    fn report_stuck(
        &self,
        identity: &SourceIdentity,
        kind: DirKind,
        file: &str,
        error: &io::Error,
        ctx: &mut ScanCtx<'_>,
    ) {
        if ctx.report_once(format!("stuck:{}/{}/{file}", identity.ipc_key, kind.name())) {
            tracing::error!(ipc_key = %identity.ipc_key, dir = kind.name(), file, %error, "cannot remove IPC file; it will not be processed");
        }
    }

    async fn persist_quarantine(&self, base: &Arc<OwnedFd>, records: Vec<QuarantineRecord>) {
        if records.is_empty() || self.config.max_error_files == 0 {
            return;
        }
        let first_seq = self.seq.fetch_add(records.len() as u64, Ordering::Relaxed);
        let base = Arc::clone(base);
        let (max_files, max_content) = (
            self.config.max_error_files,
            self.config.max_error_content_bytes,
        );
        let result = tokio::task::spawn_blocking(move || -> io::Result<usize> {
            let errors = open_errors_dir(base.as_fd())?;
            for (i, rec) in records.iter().enumerate() {
                if let Err(e) =
                    write_quarantine(errors.as_fd(), rec, first_seq + i as u64, max_content)
                {
                    tracing::error!(error = %e, ipc_key = %rec.ipc_key, "failed to write IPC quarantine record");
                }
            }
            prune_quarantine(errors.as_fd(), max_files)
        })
        .await;
        match result {
            Ok(Ok(pruned)) if pruned > 0 => {
                tracing::debug!(pruned, "pruned old IPC quarantine records");
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "IPC quarantine directory unavailable"),
            Err(e) => tracing::error!(error = %e, "IPC quarantine task failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{group, groups_fixture};

    #[test]
    fn namespaces_map_ipc_keys_to_owning_groups() {
        let mut g = groups_fixture();
        g.insert(
            "http:copilot:u:1".into(),
            group("copilot", Some("copilot-u-1"), false),
        );
        g.insert(
            "http:copilot:investigate".into(),
            group("copilot", Some("copilot-investigate"), false),
        );
        let ns = resolve_namespaces(&g);
        assert!(ns.conflicts.is_empty());
        assert_eq!(ns.identities["whatsapp_main"].folder, "whatsapp_main");
        assert!(ns.identities["whatsapp_main"].is_main);
        assert_eq!(ns.identities["copilot-u-1"].folder, "copilot");
        assert!(!ns.identities["copilot-u-1"].is_main);
        assert!(!ns.identities.contains_key("copilot"));
    }

    #[test]
    fn conflicting_keys_fail_closed() {
        let mut g = groups_fixture();
        // A non-main lane claiming the main group's namespace.
        g.insert(
            "evil@x".into(),
            group("other-group", Some("whatsapp_main"), false),
        );
        // Two lanes sharing a key *and* folder are fine.
        g.insert("other2@g.us".into(), group("other-group", None, false));
        let ns = resolve_namespaces(&g);
        assert!(ns.conflicts.contains("whatsapp_main"));
        assert!(!ns.identities.contains_key("whatsapp_main"));
        assert!(ns.identities.contains_key("other-group"));
    }

    #[test]
    fn invalid_keys_are_ignored() {
        let mut g = HashMap::new();
        g.insert("a@x".into(), group("good", Some("../escape"), false));
        g.insert("b@x".into(), group("errors", None, false));
        let ns = resolve_namespaces(&g);
        assert!(ns.identities.is_empty());
        assert_eq!(ns.invalid.len(), 2);
    }
}

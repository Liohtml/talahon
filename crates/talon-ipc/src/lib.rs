//! # talon-ipc — host-side IPC watcher
//!
//! **Owner: agent A10.** See `docs/RUST_ARCHITECTURE.md` §A10.
//!
//! Containers talk back to the host by dropping JSON files into their IPC
//! namespace (`data/ipc/<ipc_key>/messages/*.json` for chat messages,
//! `data/ipc/<ipc_key>/tasks/*.json` for task operations, see
//! [`talon_core::protocol`]). [`IpcWatcher`] polls those directories and
//! carries out the requests on behalf of the container — after checking that
//! the container is allowed to make them.
//!
//! ## Trust model
//!
//! Everything under `data/ipc/<ipc_key>/` is attacker-controlled (a container
//! may be compromised by prompt injection). Therefore:
//!
//! - **Identity** is derived only from the namespace directory: the
//!   registered lane whose [`RegisteredGroup::ipc_key`] owns it provides the
//!   folder and main-ness ([`SourceIdentity`]). Unknown directories are
//!   ignored; keys claimed by lanes that disagree on folder/privilege are
//!   skipped entirely (fail closed). The **principal** is the IPC key, not
//!   the folder: lanes sharing a folder (all CoPilot lanes live in
//!   `copilot`) can neither message, schedule into, nor manage the tasks of
//!   each other.
//! - **Authorization** goes through `talon_security::ipc_authz`
//!   ([`FnAuthorizer::security_policy`], replaceable via
//!   [`IpcWatcher::with_authorizer`]) *and* the TypeScript baseline rules
//!   ([`BaselineAuthorizer`]); both must allow. A panicking policy denies.
//!   Every decision is recorded on the [`talon_core::audit::SharedAuditSink`].
//! - **File handling** is descriptor-relative (`openat`/`unlinkat` with
//!   `O_NOFOLLOW`), accepts only regular, singly-linked files up to
//!   256 KiB, bounds JSON nesting, processes files in name order with a
//!   per-namespace per-scan quota, claims (unlinks) each file before acting
//!   on it (no replays), and quarantines anything malformed into
//!   `data/ipc/errors/` as host-written records with bounded retention.
//! - **Task operations** validate schedules with [`talon_core::schedule`] in
//!   the configured timezone and reject duplicate task ids. Every task
//!   created over IPC is recorded as owned by the creating namespace
//!   ([`TaskStore::set_task_owner`]); pause/resume/cancel/update are
//!   authorized against that owner, and tasks without an owner record are
//!   host-owned (immutable for non-main lanes). Only main may attach a
//!   `script`, and never to a host-owned task.
//! - **`register_group`** (main only) can never create, modify or
//!   impersonate the main group, and never applies a requested
//!   `containerConfig` (mounts, env, network are operator-only).
//! - **Audit hygiene**: audit rows are rate-limited per namespace
//!   ([`IpcWatcherConfig::audit_max_per_window`], with an
//!   `ipc.audit.suppressed` summary row), and file names / JIDs / reasons
//!   have control and bidi characters neutralized before they are logged or
//!   audited.
//!
//! [`RegisteredGroup::ipc_key`]: talon_core::types::RegisteredGroup::ipc_key

mod authz;
mod config;
mod fsio;
mod host;
mod json;
mod process;
mod ratelimit;
mod store;
mod watcher;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod testutil;

pub use authz::{BaselineAuthorizer, FnAuthorizer, IpcAuthorizer, MessageAuthzFn, TaskAuthzFn};
pub use config::{
    DEFAULT_AUDIT_MAX_PER_WINDOW, DEFAULT_AUDIT_WINDOW, DEFAULT_HOST_CALL_TIMEOUT,
    DEFAULT_MAX_DIR_ENTRIES, DEFAULT_MAX_ERROR_CONTENT_BYTES, DEFAULT_MAX_ERROR_FILES,
    DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_JSON_DEPTH, DEFAULT_MAX_MESSAGES_PER_SCAN,
    DEFAULT_MAX_TASKS_PER_SCAN, DEFAULT_POLL_INTERVAL, ERRORS_DIR_NAME, IpcWatcherConfig,
};
pub use host::{IpcHost, SourceIdentity};
pub use json::{
    exceeds_depth, is_valid_task_id, parse_outbound, parse_task, task_type_name,
    validate_outbound_shape, validate_task_shape,
};
pub use process::IpcOutcome;
pub use store::TaskStore;
pub use watcher::{IpcWatcher, ScanStats};

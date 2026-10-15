//! Search tools: `glob` (find files by name pattern) and `grep` (regex
//! search of file contents).
//!
//! Walks never follow symlinks, so they cannot leave the (guarded,
//! canonical) base directory. `.git` directories are skipped. Both tools
//! bound the number of visited entries, results and output bytes, and stop
//! early when the call is cancelled.

use std::collections::VecDeque;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use async_trait::async_trait;
use globset::{GlobBuilder, GlobMatcher};
use regex::{Regex, RegexBuilder};
use serde_json::json;
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};
use tokio_util::sync::CancellationToken;
use walkdir::WalkDir;

use crate::args::Args;
use crate::files::{FileLimits, looks_binary, read_line_capped};
use crate::guard::{Access, PathGuard};
use crate::output::truncate_end;
use crate::run_blocking;

/// Tool name of [`GlobTool`].
pub const GLOB: &str = "glob";
/// Tool name of [`GrepTool`].
pub const GREP: &str = "grep";

const GLOB_META: &[char] = &['*', '?', '[', ']', '{', '}'];

/// Display `p` relative to `cwd` when it lies below it, else absolute.
fn display_path(p: &Path, cwd: &Path) -> String {
    match p.strip_prefix(cwd) {
        Ok(rel) if !rel.as_os_str().is_empty() => rel.display().to_string(),
        _ => p.display().to_string(),
    }
}

fn compile_glob(pattern: &str) -> Result<GlobMatcher, String> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| format!("invalid glob pattern {pattern:?}: {e}"))
}

/// Walk depth needed for a relative glob (`None` = unbounded).
fn glob_depth(pattern: &str) -> Option<usize> {
    if pattern.contains("**") {
        None
    } else {
        Some(pattern.split('/').filter(|s| !s.is_empty()).count().max(1))
    }
}

/// Split an absolute glob such as `/workspace/group/**/*.json` into its
/// literal directory prefix and the relative pattern.
fn split_absolute_glob(pattern: &str) -> (String, String) {
    let parts: Vec<&str> = pattern.split('/').collect();
    let mut base = Vec::new();
    let mut idx = 0;
    // The last component is always part of the pattern.
    while idx + 1 < parts.len() && !parts[idx].contains(GLOB_META) {
        base.push(parts[idx]);
        idx += 1;
    }
    let base = if base.iter().all(|s| s.is_empty()) {
        "/".to_string()
    } else {
        base.join("/")
    };
    (base, parts[idx..].join("/"))
}

struct WalkStats {
    visited: usize,
    hit_walk_limit: bool,
    cancelled: bool,
}

/// Visit regular files below `base` (no symlink following, `.git` skipped).
/// `f` returns `false` to stop the walk.
fn walk_files(
    base: &Path,
    max_depth: Option<usize>,
    max_walk: usize,
    cancel: &CancellationToken,
    mut f: impl FnMut(&walkdir::DirEntry) -> bool,
) -> WalkStats {
    let mut wd = WalkDir::new(base)
        .follow_links(false)
        .min_depth(1)
        .sort_by_file_name();
    if let Some(d) = max_depth {
        wd = wd.max_depth(d);
    }
    let mut stats = WalkStats {
        visited: 0,
        hit_walk_limit: false,
        cancelled: false,
    };
    let iter = wd
        .into_iter()
        .filter_entry(|e| !(e.file_type().is_dir() && e.file_name() == ".git"));
    for entry in iter {
        stats.visited += 1;
        if stats.visited > max_walk {
            stats.hit_walk_limit = true;
            break;
        }
        if stats.visited % 512 == 0 && cancel.is_cancelled() {
            stats.cancelled = true;
            break;
        }
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_file() {
            continue;
        }
        if !f(&entry) {
            break;
        }
    }
    stats
}

// ---------------------------------------------------------------------------
// glob
// ---------------------------------------------------------------------------

/// `glob`: find files by glob pattern, newest first.
#[derive(Debug, Clone, Default)]
pub struct GlobTool {
    limits: FileLimits,
}

impl GlobTool {
    /// New tool with the given limits.
    pub fn new(limits: FileLimits) -> Self {
        Self { limits }
    }
}

fn glob_blocking(
    guard: &PathGuard,
    cwd: &Path,
    pattern: &str,
    base_raw: &str,
    limits: &FileLimits,
    cancel: &CancellationToken,
) -> ToolOutput {
    let g = match guard.resolve(base_raw, Access::Read) {
        Ok(g) => g,
        Err(e) => return ToolOutput::err(e),
    };
    let base = g.path;
    if !g.exists || !base.is_dir() {
        return ToolOutput::err(format!("{} is not an existing directory", base.display()));
    }
    let matcher = match compile_glob(pattern) {
        Ok(m) => m,
        Err(e) => return ToolOutput::err(e),
    };
    let mut hits: Vec<(PathBuf, SystemTime)> = Vec::new();
    let mut total = 0usize;
    let keep = limits
        .max_entries
        .saturating_mul(10)
        .max(limits.max_entries);
    let stats = walk_files(
        &base,
        glob_depth(pattern),
        limits.max_walk_entries,
        cancel,
        |entry| {
            let Ok(rel) = entry.path().strip_prefix(&base) else {
                return true;
            };
            if matcher.is_match(rel) {
                total += 1;
                if hits.len() < keep {
                    let mtime = entry
                        .metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .unwrap_or(SystemTime::UNIX_EPOCH);
                    hits.push((entry.path().to_path_buf(), mtime));
                }
            }
            true
        },
    );
    if stats.cancelled {
        return ToolOutput::err("glob cancelled");
    }
    hits.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let mut out = if total == 0 {
        format!("No files match {pattern:?} under {}.", base.display())
    } else {
        format!(
            "{total} file{} match{} {pattern:?} under {} (newest first):\n",
            if total == 1 { "" } else { "s" },
            if total == 1 { "es" } else { "" },
            base.display()
        )
    };
    for (p, _) in hits.iter().take(limits.max_entries) {
        out.push_str(&display_path(p, cwd));
        out.push('\n');
    }
    if total > limits.max_entries {
        out.push_str(&format!(
            "[... {} more not shown; use a more specific pattern]\n",
            total - limits.max_entries
        ));
    }
    if stats.hit_walk_limit {
        out.push_str(&format!(
            "[search stopped after visiting {} entries; narrow `path` or the pattern]\n",
            limits.max_walk_entries
        ));
    }
    ToolOutput::ok(truncate_end(
        out.trim_end(),
        limits.max_output_bytes,
        "\n[... output truncated]",
    ))
}

#[async_trait]
impl Tool for GlobTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: GLOB.to_string(),
            description: format!(
                "Find files whose path matches a glob pattern, newest first.\n\
                 \n\
                 - The pattern is matched against paths relative to `path` (default: the workspace). \
                 `*` and `?` do not cross `/`; `**` matches any number of directories; `{{a,b}}` is \
                 alternation; `[abc]` is a character class.\n\
                 - Examples: \"**/*.json\" (all JSON files, any depth), \"*.md\" (Markdown files in the \
                 top directory only), \"reports/**/incident-*.{{md,json}}\", \"**/CLAUDE.md\".\n\
                 - Returns files only (not directories), at most {} results. Paths below the workspace \
                 are shown relative to it. Symlinks are not followed; `.git` is skipped.\n\
                 - To search file contents use grep; to list a single directory use list_dir.",
                self.limits.max_entries
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern, e.g. \"**/*.log\"."},
                    "path": {"type": "string", "description": "Directory to search in (absolute or workspace-relative). Default: the workspace."}
                },
                "required": ["pattern"],
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolOutput {
        let args = match Args::parse(args) {
            Ok(a) => a,
            Err(e) => return ToolOutput::err(e),
        };
        let pattern = match args.str("pattern") {
            Ok(p) if !p.trim().is_empty() => p.trim().to_string(),
            Ok(_) => return ToolOutput::err("`pattern` must not be empty"),
            Err(e) => return ToolOutput::err(e),
        };
        let base = match args.opt_str("path") {
            Ok(p) => p.filter(|p| !p.trim().is_empty()),
            Err(e) => return ToolOutput::err(e),
        };
        // An absolute pattern carries its own base directory (`path` is ignored).
        let (base, pattern) = if pattern.starts_with('/') {
            split_absolute_glob(&pattern)
        } else {
            let p = pattern.strip_prefix("./").unwrap_or(&pattern).to_string();
            (base.unwrap_or_else(|| ".".to_string()), p)
        };
        if pattern.is_empty() {
            return ToolOutput::err("the glob pattern has no file-name part");
        }
        let guard = PathGuard::from_context(ctx);
        let cwd = fs::canonicalize(&ctx.cwd).unwrap_or_else(|_| ctx.cwd.clone());
        let limits = self.limits.clone();
        let cancel = ctx.cancel.clone();
        run_blocking(move || glob_blocking(&guard, &cwd, &pattern, &base, &limits, &cancel)).await
    }
}

// ---------------------------------------------------------------------------
// grep
// ---------------------------------------------------------------------------

/// What `grep` returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrepMode {
    Content,
    FilesWithMatches,
    Count,
}

struct GrepRequest {
    regex: Regex,
    pattern: String,
    base: String,
    include: Option<(GlobMatcher, bool)>,
    context: usize,
    mode: GrepMode,
    max_results: usize,
}

/// `grep`: regex search over file contents.
#[derive(Debug, Clone, Default)]
pub struct GrepTool {
    limits: FileLimits,
}

impl GrepTool {
    /// New tool with the given limits.
    pub fn new(limits: FileLimits) -> Self {
        Self { limits }
    }
}

/// Default number of matching lines returned in `content` mode.
const DEFAULT_GREP_RESULTS: usize = 200;
/// Hard cap on `max_results`.
const MAX_GREP_RESULTS: usize = 2000;
/// Maximum context lines.
const MAX_CONTEXT: usize = 10;
/// Longest line shown in grep output.
const GREP_LINE_CHARS: usize = 500;

fn clip_line(bytes: &[u8], cut: bool) -> String {
    let s = String::from_utf8_lossy(bytes);
    if s.chars().count() > GREP_LINE_CHARS || cut {
        let mut t: String = s.chars().take(GREP_LINE_CHARS).collect();
        t.push_str(" …");
        t
    } else {
        s.into_owned()
    }
}

#[derive(Default)]
struct GrepAcc {
    out: String,
    matches: usize,
    files_matched: usize,
    files_searched: usize,
    skipped_binary: usize,
    skipped_large: usize,
    output_full: bool,
    results_full: bool,
}

impl GrepAcc {
    fn push_line(&mut self, line: &str, max_out: usize) -> bool {
        if self.out.len() + line.len() + 1 > max_out {
            self.output_full = true;
            return false;
        }
        self.out.push_str(line);
        self.out.push('\n');
        true
    }
}

/// Search one file; returns `false` when the caller should stop.
fn grep_file(
    path: &Path,
    shown: &str,
    req: &GrepRequest,
    limits: &FileLimits,
    acc: &mut GrepAcc,
) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return true;
    };
    if meta.len() > limits.max_file_bytes {
        acc.skipped_large += 1;
        return true;
    }
    let Ok(file) = fs::File::open(path) else {
        return true;
    };
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut prefix = Vec::with_capacity(8192);
    if reader.by_ref().take(8192).read_to_end(&mut prefix).is_err() {
        return true;
    }
    if looks_binary(&prefix) {
        acc.skipped_binary += 1;
        return true;
    }
    acc.files_searched += 1;
    let mut reader = BufReader::new(std::io::Cursor::new(prefix).chain(reader));
    let keep = GREP_LINE_CHARS * 4 + 4096;
    let max_out = limits.max_output_bytes;

    let mut before: VecDeque<(usize, String)> = VecDeque::new();
    let mut after_left = 0usize;
    let mut last_printed: Option<usize> = None;
    let mut file_matches = 0usize;
    let mut lineno = 0usize;
    while let Ok(Some((bytes, cut))) = read_line_capped(&mut reader, keep) {
        lineno += 1;
        let text = String::from_utf8_lossy(&bytes);
        let is_match = req.regex.is_match(&text);
        if is_match {
            file_matches += 1;
            acc.matches += 1;
            match req.mode {
                GrepMode::FilesWithMatches => break,
                GrepMode::Count => continue,
                GrepMode::Content => {}
            }
            if req.context > 0 {
                let first_new = before.front().map(|(n, _)| *n).unwrap_or(lineno);
                if let Some(lp) = last_printed {
                    if first_new > lp + 1 && !acc.push_line("--", max_out) {
                        return false;
                    }
                } else if !acc.out.is_empty() && !acc.push_line("--", max_out) {
                    return false;
                }
            }
            while let Some((n, l)) = before.pop_front() {
                if !acc.push_line(&format!("{shown}-{n}-{l}"), max_out) {
                    return false;
                }
            }
            let line = format!("{shown}:{lineno}:{}", clip_line(&bytes, cut));
            if !acc.push_line(&line, max_out) {
                return false;
            }
            last_printed = Some(lineno);
            after_left = req.context;
            if acc.matches >= req.max_results {
                acc.results_full = true;
                break;
            }
        } else if req.mode == GrepMode::Content && req.context > 0 {
            if after_left > 0 {
                after_left -= 1;
                if !acc.push_line(
                    &format!("{shown}-{lineno}-{}", clip_line(&bytes, cut)),
                    max_out,
                ) {
                    return false;
                }
                last_printed = Some(lineno);
            } else {
                before.push_back((lineno, clip_line(&bytes, cut)));
                if before.len() > req.context {
                    before.pop_front();
                }
            }
        }
    }
    if file_matches > 0 {
        acc.files_matched += 1;
        match req.mode {
            GrepMode::FilesWithMatches => {
                if !acc.push_line(shown, max_out) {
                    return false;
                }
                if acc.files_matched >= req.max_results {
                    acc.results_full = true;
                    return false;
                }
            }
            GrepMode::Count => {
                if !acc.push_line(&format!("{shown}:{file_matches}"), max_out) {
                    return false;
                }
                if acc.files_matched >= req.max_results {
                    acc.results_full = true;
                    return false;
                }
            }
            GrepMode::Content => {}
        }
    }
    !acc.results_full
}

fn grep_blocking(
    guard: &PathGuard,
    cwd: &Path,
    req: &GrepRequest,
    limits: &FileLimits,
    cancel: &CancellationToken,
) -> ToolOutput {
    let g = match guard.resolve(&req.base, Access::Read) {
        Ok(g) => g,
        Err(e) => return ToolOutput::err(e),
    };
    if !g.exists {
        return ToolOutput::err(format!("path not found: {}", g.path.display()));
    }
    let base = g.path;
    let mut acc = GrepAcc::default();
    let mut walk_note = String::new();
    if base.is_file() {
        let shown = display_path(&base, cwd);
        grep_file(&base, &shown, req, limits, &mut acc);
    } else if base.is_dir() {
        let stats = walk_files(&base, None, limits.max_walk_entries, cancel, |entry| {
            if let Some((m, by_path)) = &req.include {
                let ok = if *by_path {
                    entry
                        .path()
                        .strip_prefix(&base)
                        .map(|rel| m.is_match(rel))
                        .unwrap_or(false)
                } else {
                    m.is_match(Path::new(entry.file_name()))
                };
                if !ok {
                    return true;
                }
            }
            let shown = display_path(entry.path(), cwd);
            grep_file(entry.path(), &shown, req, limits, &mut acc)
        });
        if stats.cancelled {
            return ToolOutput::err("grep cancelled");
        }
        if stats.hit_walk_limit {
            walk_note = format!(
                "[search stopped after visiting {} entries; narrow `path` or `include`]\n",
                limits.max_walk_entries
            );
        }
    } else {
        return ToolOutput::err(format!(
            "{} is not a regular file or directory",
            base.display()
        ));
    }

    let mut out = if acc.matches == 0 {
        format!(
            "No matches for /{}/ in {} ({} file{} searched).\n",
            req.pattern,
            base.display(),
            acc.files_searched,
            if acc.files_searched == 1 { "" } else { "s" }
        )
    } else {
        std::mem::take(&mut acc.out)
    };
    if acc.matches > 0 {
        out.push_str(&format!(
            "[{} matching line{} in {} file{}; {} file{} searched]\n",
            acc.matches,
            if acc.matches == 1 { "" } else { "s" },
            acc.files_matched,
            if acc.files_matched == 1 { "" } else { "s" },
            acc.files_searched,
            if acc.files_searched == 1 { "" } else { "s" },
        ));
    }
    if acc.results_full {
        out.push_str("[result limit reached; refine the pattern, `path` or `include`, or raise `max_results`]\n");
    }
    if acc.output_full {
        out.push_str("[output size limit reached; results are incomplete]\n");
    }
    if acc.skipped_binary > 0 || acc.skipped_large > 0 {
        out.push_str(&format!(
            "[skipped {} binary and {} oversized file(s)]\n",
            acc.skipped_binary, acc.skipped_large
        ));
    }
    out.push_str(&walk_note);
    ToolOutput::ok(out.trim_end().to_string())
}

#[async_trait]
impl Tool for GrepTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: GREP.to_string(),
            description: "Search file contents with a regular expression (Rust regex syntax, similar to \
                 PCRE without look-around/backreferences).\n\
                 \n\
                 - `path`: file or directory to search (default: the workspace); directories are \
                 searched recursively. Binary files, `.git` and files over the size limit are skipped.\n\
                 - `include`: only search files matching this glob. Without `/` it matches the file \
                 name (\"*.log\", \"*.{json,yaml}\"); with `/` the path relative to `path` \
                 (\"alerts/**/*.json\").\n\
                 - `output_mode`: \"content\" (default) prints `file:line:text` for each matching line \
                 (context lines as `file-line-text`, groups separated by `--`); \"files_with_matches\" \
                 lists matching files; \"count\" prints `file:count`.\n\
                 - `context`: lines of context before and after each match (0-10). \
                 `case_insensitive`: ignore case. `max_results`: matching lines (content mode) or files \
                 (other modes) to return; default 200, max 2000.\n\
                 - Escape regex metacharacters for literal searches: \"192\\\\.168\\\\.1\\\\.10\", \
                 \"cmd\\\\.exe /c\".\n\
                 \n\
                 Examples:\n\
                 {\"pattern\": \"Failed password for .* from 203\\\\.0\\\\.113\\\\.\", \"path\": \"logs\", \"include\": \"*.log\"}\n\
                 {\"pattern\": \"mimikatz|sekurlsa\", \"case_insensitive\": true, \"output_mode\": \"files_with_matches\"}"
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Regular expression to search for."},
                    "path": {"type": "string", "description": "File or directory to search (absolute or workspace-relative). Default: the workspace."},
                    "include": {"type": "string", "description": "Glob filter for files, e.g. \"*.log\" or \"**/*.{json,yml}\"."},
                    "case_insensitive": {"type": "boolean", "description": "Case-insensitive matching. Default false."},
                    "context": {"type": "integer", "minimum": 0, "maximum": MAX_CONTEXT, "description": "Context lines before and after each match (content mode). Default 0."},
                    "output_mode": {"type": "string", "enum": ["content", "files_with_matches", "count"], "description": "Result format. Default \"content\"."},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": MAX_GREP_RESULTS, "description": "Maximum matching lines (content) or files (other modes). Default 200."}
                },
                "required": ["pattern"],
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolOutput {
        let args = match Args::parse(args) {
            Ok(a) => a,
            Err(e) => return ToolOutput::err(e),
        };
        let req = match build_grep_request(&args) {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(e),
        };
        let guard = PathGuard::from_context(ctx);
        let cwd = fs::canonicalize(&ctx.cwd).unwrap_or_else(|_| ctx.cwd.clone());
        let limits = self.limits.clone();
        let cancel = ctx.cancel.clone();
        run_blocking(move || grep_blocking(&guard, &cwd, &req, &limits, &cancel)).await
    }
}

fn build_grep_request(args: &Args) -> Result<GrepRequest, String> {
    let pattern = args.str("pattern")?;
    if pattern.is_empty() {
        return Err("`pattern` must not be empty".to_string());
    }
    let ci = args.opt_bool("case_insensitive")?.unwrap_or(false);
    let regex = RegexBuilder::new(&pattern)
        .case_insensitive(ci)
        .size_limit(4 * 1024 * 1024)
        .dfa_size_limit(8 * 1024 * 1024)
        .build()
        .map_err(|e| format!("invalid regex: {e}"))?;
    let include = match args.opt_str("include")? {
        Some(i) if !i.trim().is_empty() => {
            let i = i.trim();
            let by_path = i.contains('/');
            Some((compile_glob(i.strip_prefix("./").unwrap_or(i))?, by_path))
        }
        _ => None,
    };
    let mode = match args.opt_str("output_mode")?.as_deref() {
        None | Some("content") => GrepMode::Content,
        Some("files_with_matches") | Some("files") => GrepMode::FilesWithMatches,
        Some("count") => GrepMode::Count,
        Some(other) => {
            return Err(format!(
                "invalid output_mode {other:?}: use \"content\", \"files_with_matches\" or \"count\""
            ));
        }
    };
    let context = (args.opt_u64("context")?.unwrap_or(0) as usize).min(MAX_CONTEXT);
    let max_results = (args
        .opt_u64("max_results")?
        .unwrap_or(DEFAULT_GREP_RESULTS as u64) as usize)
        .clamp(1, MAX_GREP_RESULTS);
    let base = args
        .opt_str("path")?
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| ".".to_string());
    Ok(GrepRequest {
        regex,
        pattern,
        base,
        include,
        context,
        mode,
        max_results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ctx_for;
    use std::os::unix::fs::symlink;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        fs::create_dir_all(p.join("logs/old")).unwrap();
        fs::create_dir_all(p.join(".git")).unwrap();
        fs::write(p.join("top.json"), "{\"ip\": \"10.0.0.1\"}\n").unwrap();
        fs::write(
            p.join("logs/auth.log"),
            "ok login\nFailed password for root from 203.0.113.5\nok\nok\nFailed password for admin from 203.0.113.9\n",
        )
        .unwrap();
        fs::write(p.join("logs/old/auth.log.1"), "Failed password for bob\n").unwrap();
        fs::write(p.join("logs/blob.bin"), b"Failed\0password").unwrap();
        fs::write(p.join(".git/config"), "Failed password\n").unwrap();
        dir
    }

    #[test]
    fn absolute_glob_split() {
        assert_eq!(
            split_absolute_glob("/workspace/group/**/*.json"),
            ("/workspace/group".to_string(), "**/*.json".to_string())
        );
        assert_eq!(
            split_absolute_glob("/x/file.txt"),
            ("/x".to_string(), "file.txt".to_string())
        );
        assert_eq!(
            split_absolute_glob("/*.md"),
            ("/".to_string(), "*.md".to_string())
        );
        assert_eq!(glob_depth("*.md"), Some(1));
        assert_eq!(glob_depth("a/*/b.txt"), Some(3));
        assert_eq!(glob_depth("**/x"), None);
    }

    #[tokio::test]
    async fn glob_matches_with_separator_semantics() {
        let dir = tree();
        let ctx = ctx_for(dir.path());
        let t = GlobTool::default();
        let out = t.call(json!({"pattern": "*.json"}), &ctx).await;
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.contains("1 file matches"));
        assert!(out.content.contains("\ntop.json"));
        let out = t.call(json!({"pattern": "**/auth.log*"}), &ctx).await;
        assert!(out.content.contains("logs/auth.log"));
        assert!(out.content.contains("logs/old/auth.log.1"));
        let out = t.call(json!({"pattern": "**/config"}), &ctx).await;
        assert!(out.content.starts_with("No files match"), "{}", out.content);
        let out = t
            .call(json!({"pattern": "*.log", "path": "logs"}), &ctx)
            .await;
        assert!(out.content.contains("logs/auth.log"));
        assert!(!out.content.contains("auth.log.1"));
        let abs = format!(
            "{}/**/*.json",
            fs::canonicalize(dir.path()).unwrap().display()
        );
        let out = t.call(json!({"pattern": abs}), &ctx).await;
        assert!(out.content.contains("top.json"), "{}", out.content);
        let out = t.call(json!({"pattern": "[unclosed"}), &ctx).await;
        assert!(out.is_error);
        let out = t.call(json!({"pattern": "*", "path": "/etc"}), &ctx).await;
        assert!(out.is_error);
    }

    #[tokio::test]
    async fn glob_does_not_follow_symlinks_out() {
        let dir = tree();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.json"), "{}").unwrap();
        symlink(outside.path(), dir.path().join("escape")).unwrap();
        let ctx = ctx_for(dir.path());
        let out = GlobTool::default()
            .call(json!({"pattern": "**/*.json"}), &ctx)
            .await;
        assert!(!out.content.contains("secret.json"), "{}", out.content);
        let out = GrepTool::default()
            .call(json!({"pattern": "\\{\\}"}), &ctx)
            .await;
        assert!(out.content.starts_with("No matches"), "{}", out.content);
    }

    #[tokio::test]
    async fn grep_content_mode_with_include_and_skips() {
        let dir = tree();
        let ctx = ctx_for(dir.path());
        let t = GrepTool::default();
        let out = t
            .call(
                json!({"pattern": "Failed password for \\w+ from", "include": "*.log"}),
                &ctx,
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert!(
            out.content
                .contains("logs/auth.log:2:Failed password for root")
        );
        assert!(
            out.content
                .contains("logs/auth.log:5:Failed password for admin")
        );
        assert!(!out.content.contains(".git"));
        assert!(out.content.contains("[2 matching lines in 1 file"));

        let out = t
            .call(
                json!({"pattern": "failed PASSWORD", "case_insensitive": true}),
                &ctx,
            )
            .await;
        assert!(out.content.contains("auth.log.1:1:"), "{}", out.content);
        assert!(out.content.contains("skipped 1 binary"));
    }

    #[tokio::test]
    async fn grep_context_and_modes() {
        let dir = tree();
        let ctx = ctx_for(dir.path());
        let t = GrepTool::default();
        let out = t
            .call(
                json!({"pattern": "Failed", "path": "logs/auth.log", "context": 1}),
                &ctx,
            )
            .await;
        let expected = "logs/auth.log-1-ok login\nlogs/auth.log:2:Failed password for root from 203.0.113.5\nlogs/auth.log-3-ok\nlogs/auth.log-4-ok\nlogs/auth.log:5:Failed password for admin from 203.0.113.9\n";
        assert!(out.content.starts_with(expected), "{}", out.content);

        let out = t
            .call(
                json!({"pattern": "Failed", "output_mode": "files_with_matches"}),
                &ctx,
            )
            .await;
        let files: Vec<&str> = out
            .content
            .lines()
            .take_while(|l| !l.starts_with('['))
            .collect();
        assert_eq!(files, vec!["logs/auth.log", "logs/old/auth.log.1"]);

        let out = t
            .call(json!({"pattern": "Failed", "output_mode": "count"}), &ctx)
            .await;
        assert!(out.content.contains("logs/auth.log:2"));
        assert!(out.content.contains("logs/old/auth.log.1:1"));

        let out = t
            .call(json!({"pattern": "Failed", "max_results": 1}), &ctx)
            .await;
        assert!(out.content.contains("result limit reached"));
    }

    #[tokio::test]
    async fn grep_validation() {
        let dir = tree();
        let ctx = ctx_for(dir.path());
        let t = GrepTool::default();
        assert!(t.call(json!({"pattern": "("}), &ctx).await.is_error);
        assert!(t.call(json!({"pattern": ""}), &ctx).await.is_error);
        assert!(
            t.call(json!({"pattern": "x", "output_mode": "bogus"}), &ctx)
                .await
                .is_error
        );
        assert!(
            t.call(json!({"pattern": "x", "path": "/etc"}), &ctx)
                .await
                .is_error
        );
        let out = t.call(json!({"pattern": "zzz-not-there"}), &ctx).await;
        assert!(!out.is_error && out.content.starts_with("No matches"));
    }
}

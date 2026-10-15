//! File tools: `read_file`, `write_file`, `edit_file`, `list_dir`.
//!
//! All paths go through the [`PathGuard`](crate::guard::PathGuard); tools
//! operate on the canonical path it returns. Filesystem work runs on the
//! blocking pool.

use std::fs;
use std::io::{BufRead, BufReader, Read};

use async_trait::async_trait;
use serde_json::json;
use talon_core::tool::{Tool, ToolConcurrency, ToolContext, ToolOutput, ToolSpec};

use crate::args::Args;
use crate::atomic::write_atomic;
use crate::guard::{Access, PathGuard};
use crate::output::truncate_end;
use crate::run_blocking;

/// Tool name of [`ReadFileTool`].
pub const READ_FILE: &str = "read_file";
/// Tool name of [`WriteFileTool`].
pub const WRITE_FILE: &str = "write_file";
/// Tool name of [`EditFileTool`].
pub const EDIT_FILE: &str = "edit_file";
/// Tool name of [`ListDirTool`].
pub const LIST_DIR: &str = "list_dir";

/// Size and output limits shared by the file and search tools.
#[derive(Debug, Clone)]
pub struct FileLimits {
    /// Files larger than this are refused by `edit_file` and skipped by `grep`.
    /// (`read_file` streams, so it only reads what it shows.) Default 50 MiB.
    pub max_file_bytes: u64,
    /// Largest content `write_file`/`edit_file` will write. Default 10 MiB.
    pub max_write_bytes: usize,
    /// Cap on a single tool result. Default 100 000 bytes.
    pub max_output_bytes: usize,
    /// Lines `read_file` returns when no `limit` is given. Default 2000.
    pub default_read_lines: usize,
    /// Longer lines are cut in `read_file`/`grep` output. Default 2000 chars.
    pub max_line_chars: usize,
    /// Max entries listed by `list_dir` / paths returned by `glob`. Default 1000.
    pub max_entries: usize,
    /// Max filesystem entries visited by one `glob`/`grep` walk. Default 200 000.
    pub max_walk_entries: usize,
}

impl Default for FileLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 50 * 1024 * 1024,
            max_write_bytes: 10 * 1024 * 1024,
            max_output_bytes: 100_000,
            default_read_lines: 2000,
            max_line_chars: 2000,
            max_entries: 1000,
            max_walk_entries: 200_000,
        }
    }
}

/// Human-readable byte size (`512 B`, `2.1 KB`, `3.4 MB`).
pub(crate) fn human_size(n: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut unit = UNITS[0];
    for u in UNITS.iter().skip(1) {
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
        unit = u;
    }
    format!("{v:.1} {unit}")
}

/// Heuristic binary detection on a file prefix: NUL bytes or a high share
/// of control characters.
pub(crate) fn looks_binary(prefix: &[u8]) -> bool {
    if prefix.contains(&0) {
        return true;
    }
    if prefix.is_empty() {
        return false;
    }
    let ctrl = prefix
        .iter()
        .filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c | 0x1b))
        .count();
    ctrl * 10 > prefix.len()
}

fn sniff_kind(prefix: &[u8]) -> &'static str {
    let starts = |m: &[u8]| prefix.starts_with(m);
    if starts(b"%PDF") {
        "PDF document"
    } else if starts(b"\x89PNG") {
        "PNG image"
    } else if starts(b"\xff\xd8\xff") {
        "JPEG image"
    } else if starts(b"GIF8") {
        "GIF image"
    } else if starts(b"PK\x03\x04") {
        "ZIP archive (or docx/xlsx/jar)"
    } else if starts(b"\x1f\x8b") {
        "gzip archive"
    } else if starts(b"\x7fELF") {
        "ELF executable"
    } else if starts(b"SQLite format 3") {
        "SQLite database"
    } else if starts(b"MZ") {
        "Windows executable"
    } else {
        "binary data"
    }
}

/// Read one line (up to and including `\n`) keeping at most `keep` bytes;
/// the rest of an over-long line is consumed and discarded. Returns
/// `None` at EOF.
pub(crate) fn read_line_capped<R: BufRead>(
    r: &mut R,
    keep: usize,
) -> std::io::Result<Option<(Vec<u8>, bool)>> {
    let mut line = Vec::new();
    let mut truncated = false;
    let mut saw_any = false;
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        saw_any = true;
        let (chunk, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (&buf[..i], Some(i + 1)),
            None => (buf, None),
        };
        let room = keep.saturating_sub(line.len());
        if chunk.len() > room {
            truncated = true;
        }
        line.extend_from_slice(&chunk[..chunk.len().min(room)]);
        let consumed = done.unwrap_or(buf.len());
        r.consume(consumed);
        if done.is_some() {
            break;
        }
    }
    if !saw_any {
        return Ok(None);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some((line, truncated)))
}

fn parse_or_err(args: serde_json::Value) -> Result<Args, ToolOutput> {
    Args::parse(args).map_err(ToolOutput::err)
}

// ---------------------------------------------------------------------------
// read_file
// ---------------------------------------------------------------------------

/// `read_file`: numbered lines with offset/limit, binary detection, caps.
#[derive(Debug, Clone, Default)]
pub struct ReadFileTool {
    limits: FileLimits,
}

impl ReadFileTool {
    /// New tool with the given limits.
    pub fn new(limits: FileLimits) -> Self {
        Self { limits }
    }
}

fn read_file_blocking(
    guard: &PathGuard,
    raw: &str,
    offset: usize,
    limit: usize,
    limits: &FileLimits,
) -> ToolOutput {
    let g = match guard.resolve(raw, Access::Read) {
        Ok(g) => g,
        Err(e) => return ToolOutput::err(e),
    };
    let path = &g.path;
    if !g.exists {
        return ToolOutput::err(format!("file not found: {}", path.display()));
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return ToolOutput::err(format!("cannot stat {}: {e}", path.display())),
    };
    if meta.is_dir() {
        return ToolOutput::err(format!(
            "{} is a directory; use list_dir to see its contents",
            path.display()
        ));
    }
    if !meta.is_file() {
        return ToolOutput::err(format!("{} is not a regular file", path.display()));
    }
    if meta.len() == 0 {
        return ToolOutput::ok(format!("{} is empty (0 bytes).", path.display()));
    }
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return ToolOutput::err(format!("cannot open {}: {e}", path.display())),
    };
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut prefix = Vec::with_capacity(8192);
    if let Err(e) = reader.by_ref().take(8192).read_to_end(&mut prefix) {
        return ToolOutput::err(format!("cannot read {}: {e}", path.display()));
    }
    if looks_binary(&prefix) {
        return ToolOutput::err(format!(
            "{} looks like a binary file ({}, {}); it is not displayed. Inspect it with bash, \
             e.g. `file <path>`, `xxd <path> | head -20` or `strings <path> | head -100`.",
            path.display(),
            sniff_kind(&prefix),
            human_size(meta.len())
        ));
    }
    // Re-chain the already consumed prefix in front of the rest.
    let mut reader =
        BufReader::with_capacity(64 * 1024, std::io::Cursor::new(prefix).chain(reader));

    let mut out = String::new();
    let mut lineno = 0usize;
    let mut shown = 0usize;
    let mut more = false;
    let mut cut_by_size = false;
    let keep_bytes = limits.max_line_chars.saturating_mul(4);
    loop {
        let line = match read_line_capped(&mut reader, keep_bytes) {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => return ToolOutput::err(format!("error reading {}: {e}", path.display())),
        };
        lineno += 1;
        if lineno < offset {
            continue;
        }
        if shown >= limit {
            more = true;
            break;
        }
        let (bytes, cut_bytes) = line;
        let decoded = String::from_utf8_lossy(&bytes);
        let too_long = decoded.chars().count() > limits.max_line_chars;
        let mut text: String = if too_long {
            decoded.chars().take(limits.max_line_chars).collect()
        } else {
            decoded.into_owned()
        };
        if too_long || cut_bytes {
            text.push_str(" … [line truncated]");
        }
        let entry = format!("{lineno:>6}\t{text}\n");
        if out.len() + entry.len() > limits.max_output_bytes {
            cut_by_size = true;
            more = true;
            break;
        }
        out.push_str(&entry);
        shown += 1;
    }
    if shown == 0 {
        if lineno == 0 {
            return ToolOutput::ok(format!("{} is empty.", path.display()));
        }
        return ToolOutput::err(format!(
            "{} has only {lineno} lines; offset {offset} is past the end",
            path.display()
        ));
    }
    let first = offset.max(1);
    let last = first + shown - 1;
    if more {
        let why = if cut_by_size {
            " (output size limit reached)"
        } else {
            ""
        };
        out.push_str(&format!(
            "[showing lines {first}-{last}{why}; more lines follow — continue with offset={}]",
            last + 1
        ));
    }
    ToolOutput::ok(out)
}

#[async_trait]
impl Tool for ReadFileTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: READ_FILE.to_string(),
            description: format!(
                "Read a text file and return its lines prefixed with line numbers (`     1\\t<line>`).\n\
                 \n\
                 - `path` is absolute or relative to the workspace, e.g. \"CLAUDE.md\" or \
                 \"/workspace/extra/logs/auth.log\".\n\
                 - By default up to {lines} lines are returned starting at line 1. For long files use \
                 `offset` (1-based first line) and `limit` (number of lines), e.g. \
                 {{\"path\": \"logs/app.log\", \"offset\": 2001, \"limit\": 500}}.\n\
                 - Lines longer than {chars} characters are cut. Binary files (images, archives, \
                 executables) are not displayed; use bash for those.\n\
                 - The line-number prefix is not part of the file: never include it in edit_file's \
                 `old_string`.\n\
                 - To find something in many files use grep; to list files use list_dir or glob.",
                lines = self.limits.default_read_lines,
                chars = self.limits.max_line_chars
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File to read (absolute or workspace-relative)."},
                    "offset": {"type": "integer", "minimum": 1, "description": "1-based line number to start at. Default 1."},
                    "limit": {"type": "integer", "minimum": 1, "description": format!("Maximum number of lines to return. Default {}.", self.limits.default_read_lines)}
                },
                "required": ["path"],
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolOutput {
        let args = match parse_or_err(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let path = match args.str("path") {
            Ok(p) => p,
            Err(e) => return ToolOutput::err(e),
        };
        let offset = match args.opt_u64("offset") {
            Ok(v) => v.unwrap_or(1).max(1) as usize,
            Err(e) => return ToolOutput::err(e),
        };
        let limit = match args.opt_u64("limit") {
            Ok(v) => v
                .map(|v| v as usize)
                .unwrap_or(self.limits.default_read_lines)
                .max(1),
            Err(e) => return ToolOutput::err(e),
        };
        let guard = PathGuard::from_context(ctx);
        let limits = self.limits.clone();
        run_blocking(move || read_file_blocking(&guard, &path, offset, limit, &limits)).await
    }
}

// ---------------------------------------------------------------------------
// write_file
// ---------------------------------------------------------------------------

/// `write_file`: create or replace a file atomically.
#[derive(Debug, Clone, Default)]
pub struct WriteFileTool {
    limits: FileLimits,
}

impl WriteFileTool {
    /// New tool with the given limits.
    pub fn new(limits: FileLimits) -> Self {
        Self { limits }
    }
}

fn write_file_blocking(guard: &PathGuard, raw: &str, content: &str) -> ToolOutput {
    let g = match guard.resolve(raw, Access::Write) {
        Ok(g) => g,
        Err(e) => return ToolOutput::err(e),
    };
    let path = &g.path;
    if g.exists {
        match fs::metadata(path) {
            Ok(m) if m.is_dir() => {
                return ToolOutput::err(format!("{} is a directory", path.display()));
            }
            Ok(m) if !m.is_file() => {
                return ToolOutput::err(format!("{} is not a regular file", path.display()));
            }
            Ok(_) => {}
            Err(e) => return ToolOutput::err(format!("cannot stat {}: {e}", path.display())),
        }
    }
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            return ToolOutput::err(format!("cannot create directory {}: {e}", parent.display()));
        }
        // Re-check after creating directories (a concurrent symlink swap
        // would make the parent resolve elsewhere).
        match fs::canonicalize(parent) {
            Ok(real) if guard.is_writable(&real) => {}
            Ok(real) => {
                return ToolOutput::err(format!(
                    "access denied: {} resolves outside the writable directories",
                    real.display()
                ));
            }
            Err(e) => return ToolOutput::err(format!("cannot resolve {}: {e}", parent.display())),
        }
    }
    if let Err(e) = write_atomic(path, content.as_bytes()) {
        return ToolOutput::err(format!("cannot write {}: {e}", path.display()));
    }
    let lines = content.lines().count();
    let verb = if g.exists { "Overwrote" } else { "Created" };
    ToolOutput::ok(format!(
        "{verb} {} ({} bytes, {lines} lines).",
        path.display(),
        content.len()
    ))
}

#[async_trait]
impl Tool for WriteFileTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: WRITE_FILE.to_string(),
            description: format!(
                "Create a file or completely replace its contents. The write is atomic (readers never \
                 see a half-written file) and missing parent directories are created.\n\
                 \n\
                 - `path` is absolute or relative to the workspace, e.g. \"reports/incident-4711.md\".\n\
                 - Overwrites existing files without asking: for small changes to an existing file \
                 prefer edit_file, and read the file first so you don't lose content.\n\
                 - Read-only locations (shared global memory, project files) cannot be written.\n\
                 - Maximum content size: {}.\n\
                 \n\
                 Example: {{\"path\": \"notes/triage.md\", \"content\": \"# Triage\\n- host: web-01\\n\"}}",
                human_size(self.limits.max_write_bytes as u64)
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File to create or overwrite (absolute or workspace-relative)."},
                    "content": {"type": "string", "description": "The complete new file content."}
                },
                "required": ["path", "content"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolOutput {
        let args = match parse_or_err(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let (path, content) = match (args.str("path"), args.str("content")) {
            (Ok(p), Ok(c)) => (p, c),
            (Err(e), _) | (_, Err(e)) => return ToolOutput::err(e),
        };
        if content.len() > self.limits.max_write_bytes {
            return ToolOutput::err(format!(
                "content is {} which exceeds the {} limit",
                human_size(content.len() as u64),
                human_size(self.limits.max_write_bytes as u64)
            ));
        }
        let guard = PathGuard::from_context(ctx);
        run_blocking(move || write_file_blocking(&guard, &path, &content)).await
    }
}

// ---------------------------------------------------------------------------
// edit_file
// ---------------------------------------------------------------------------

/// `edit_file`: exact string replacement (unique unless `replace_all`).
#[derive(Debug, Clone, Default)]
pub struct EditFileTool {
    limits: FileLimits,
}

impl EditFileTool {
    /// New tool with the given limits.
    pub fn new(limits: FileLimits) -> Self {
        Self { limits }
    }
}

struct EditRequest {
    path: String,
    old: String,
    new: String,
    replace_all: bool,
}

fn snippet_around(content: &str, byte_pos: usize, new_len: usize) -> String {
    let start_line = content[..byte_pos].matches('\n').count();
    let end_line = start_line + content[byte_pos..byte_pos + new_len].matches('\n').count();
    let from = start_line.saturating_sub(3);
    let to = (end_line + 3).min(from + 30);
    content
        .lines()
        .enumerate()
        .skip(from)
        .take(to.saturating_sub(from) + 1)
        .map(|(i, l)| {
            let l = truncate_end(l, 300, " …");
            format!("{:>6}\t{l}", i + 1)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn edit_file_blocking(guard: &PathGuard, req: EditRequest, limits: &FileLimits) -> ToolOutput {
    let g = match guard.resolve(&req.path, Access::Write) {
        Ok(g) => g,
        Err(e) => return ToolOutput::err(e),
    };
    let path = &g.path;
    if !g.exists {
        return ToolOutput::err(format!(
            "file not found: {} (use write_file to create a new file)",
            path.display()
        ));
    }
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(e) => return ToolOutput::err(format!("cannot stat {}: {e}", path.display())),
    };
    if !meta.is_file() {
        return ToolOutput::err(format!("{} is not a regular file", path.display()));
    }
    if meta.len() > limits.max_file_bytes.min(limits.max_write_bytes as u64) {
        return ToolOutput::err(format!(
            "{} is too large to edit ({}); use bash (sed/awk/python) instead",
            path.display(),
            human_size(meta.len())
        ));
    }
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(e) => return ToolOutput::err(format!("cannot read {}: {e}", path.display())),
    };
    let content = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => {
            return ToolOutput::err(format!(
                "{} is not valid UTF-8 text; edit it with bash instead",
                path.display()
            ));
        }
    };

    let (mut old, mut new) = (req.old, req.new);
    let mut count = content.matches(old.as_str()).count();
    if count == 0 && content.contains("\r\n") && old.contains('\n') && !old.contains('\r') {
        // The file uses CRLF line endings; retry with converted strings.
        let old_crlf = old.replace('\n', "\r\n");
        let c = content.matches(old_crlf.as_str()).count();
        if c > 0 {
            old = old_crlf;
            new = new.replace("\r\n", "\n").replace('\n', "\r\n");
            count = c;
        }
    }
    if count == 0 {
        let hint = if content.contains(old.trim()) && !old.trim().is_empty() {
            " It does appear with different leading/trailing whitespace; copy the text exactly."
        } else {
            ""
        };
        return ToolOutput::err(format!(
            "old_string was not found in {}. It must match the file exactly, including whitespace \
             and indentation (without read_file's line-number prefixes). Read the file again and \
             retry.{hint}",
            path.display()
        ));
    }
    if count > 1 && !req.replace_all {
        return ToolOutput::err(format!(
            "old_string occurs {count} times in {}. Include more surrounding lines to make it \
             unique, or set replace_all=true to replace every occurrence.",
            path.display()
        ));
    }
    let first_pos = content.find(old.as_str()).unwrap_or(0);
    let updated = if req.replace_all {
        content.replace(old.as_str(), &new)
    } else {
        content.replacen(old.as_str(), &new, 1)
    };
    if updated.len() > limits.max_write_bytes {
        return ToolOutput::err(format!(
            "the edited file would exceed the {} limit",
            human_size(limits.max_write_bytes as u64)
        ));
    }
    if let Err(e) = write_atomic(path, updated.as_bytes()) {
        return ToolOutput::err(format!("cannot write {}: {e}", path.display()));
    }
    let line = content[..first_pos].matches('\n').count() + 1;
    let snippet = snippet_around(&updated, first_pos, new.len());
    ToolOutput::ok(format!(
        "Edited {}: replaced {count} occurrence{} (first at line {line}).\n{snippet}",
        path.display(),
        if count == 1 { "" } else { "s" }
    ))
}

#[async_trait]
impl Tool for EditFileTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: EDIT_FILE.to_string(),
            description: "Edit a text file by exact string replacement: `old_string` is replaced with \
                 `new_string`.\n\
                 \n\
                 - `old_string` must match the file exactly, including whitespace and indentation. \
                 Copy it from read_file output WITHOUT the line-number prefix.\n\
                 - By default `old_string` must occur exactly once; include a few surrounding lines to \
                 make it unique. Set `replace_all: true` to replace every occurrence (e.g. renaming a \
                 variable).\n\
                 - To delete text, use an empty `new_string`. To create a new file, use write_file.\n\
                 - The write is atomic; the result shows the edited region with line numbers.\n\
                 \n\
                 Example: {\"path\": \"CLAUDE.md\", \"old_string\": \"severity: low\", \"new_string\": \
                 \"severity: high\"}"
                .to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File to edit (absolute or workspace-relative)."},
                    "old_string": {"type": "string", "description": "Exact text to replace (must exist in the file)."},
                    "new_string": {"type": "string", "description": "Replacement text (may be empty to delete)."},
                    "replace_all": {"type": "boolean", "description": "Replace every occurrence instead of requiring a unique match. Default false."}
                },
                "required": ["path", "old_string", "new_string"],
                "additionalProperties": false
            }),
        }
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolOutput {
        let args = match parse_or_err(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let req = match (|| -> Result<EditRequest, String> {
            Ok(EditRequest {
                path: args.str("path")?,
                old: args.str("old_string")?,
                new: args.str("new_string")?,
                replace_all: args.opt_bool("replace_all")?.unwrap_or(false),
            })
        })() {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(e),
        };
        if req.old.is_empty() {
            return ToolOutput::err(
                "old_string must not be empty (use write_file to create or overwrite a file)",
            );
        }
        if req.old == req.new {
            return ToolOutput::err("old_string and new_string are identical; nothing to change");
        }
        let guard = PathGuard::from_context(ctx);
        let limits = self.limits.clone();
        run_blocking(move || edit_file_blocking(&guard, req, &limits)).await
    }
}

// ---------------------------------------------------------------------------
// list_dir
// ---------------------------------------------------------------------------

/// `list_dir`: one directory level, directories first.
#[derive(Debug, Clone, Default)]
pub struct ListDirTool {
    limits: FileLimits,
}

impl ListDirTool {
    /// New tool with the given limits.
    pub fn new(limits: FileLimits) -> Self {
        Self { limits }
    }
}

fn list_dir_blocking(guard: &PathGuard, raw: &str, limits: &FileLimits) -> ToolOutput {
    let g = match guard.resolve(raw, Access::Read) {
        Ok(g) => g,
        Err(e) => return ToolOutput::err(e),
    };
    let path = &g.path;
    if !g.exists {
        return ToolOutput::err(format!("directory not found: {}", path.display()));
    }
    if !path.is_dir() {
        return ToolOutput::err(format!(
            "{} is a file, not a directory; use read_file to read it",
            path.display()
        ));
    }
    let rd = match fs::read_dir(path) {
        Ok(rd) => rd,
        Err(e) => return ToolOutput::err(format!("cannot list {}: {e}", path.display())),
    };
    struct Entry {
        name: String,
        line: String,
        is_dir: bool,
    }
    let mut entries = Vec::new();
    let mut uncollected = 0usize;
    for item in rd {
        let Ok(item) = item else { continue };
        if entries.len() >= limits.max_walk_entries {
            // Bound memory on huge directories; these are counted, not sorted.
            uncollected += 1;
            continue;
        }
        let name = item.file_name().to_string_lossy().into_owned();
        let Ok(ft) = item.file_type() else { continue };
        let (line, is_dir) = if ft.is_dir() {
            (format!("{name}/"), true)
        } else if ft.is_symlink() {
            let target = fs::read_link(item.path())
                .map(|t| t.display().to_string())
                .unwrap_or_else(|_| "?".to_string());
            (format!("{name} -> {target}"), false)
        } else if ft.is_file() {
            let size = item.metadata().map(|m| m.len()).unwrap_or(0);
            (format!("{name}  ({})", human_size(size)), false)
        } else {
            (format!("{name}  (special file)"), false)
        };
        entries.push(Entry { name, line, is_dir });
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    let total = entries.len() + uncollected;
    let mut out = format!(
        "{} ({total} entr{})\n",
        path.display(),
        if total == 1 { "y" } else { "ies" }
    );
    if total == 0 {
        out.push_str("(empty directory)");
        return ToolOutput::ok(out);
    }
    for e in entries.iter().take(limits.max_entries) {
        out.push_str(&e.line);
        out.push('\n');
        if out.len() > limits.max_output_bytes {
            break;
        }
    }
    if total > limits.max_entries {
        out.push_str(&format!(
            "[... {} more entries not shown; use glob with a pattern to narrow down]",
            total - limits.max_entries.min(entries.len())
        ));
    }
    ToolOutput::ok(truncate_end(
        out.trim_end(),
        limits.max_output_bytes,
        "\n[... output truncated]",
    ))
}

#[async_trait]
impl Tool for ListDirTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: LIST_DIR.to_string(),
            description: format!(
                "List the entries of one directory (not recursive). Directories are shown first with a \
                 trailing `/`, files with their size, symlinks as `name -> target`. Hidden files are \
                 included.\n\
                 \n\
                 - `path` defaults to the workspace; e.g. {{\"path\": \"conversations\"}} or \
                 {{\"path\": \"/workspace/extra\"}}.\n\
                 - At most {} entries are shown. To find files recursively by name use glob; to search \
                 contents use grep.",
                self.limits.max_entries
            ),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory to list (absolute or workspace-relative). Default: the workspace."}
                },
                "additionalProperties": false
            }),
        }
    }

    fn concurrency(&self) -> ToolConcurrency {
        ToolConcurrency::ReadOnly
    }

    async fn call(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolOutput {
        let args = match parse_or_err(args) {
            Ok(a) => a,
            Err(o) => return o,
        };
        let path = match args.opt_str("path") {
            Ok(p) => p
                .filter(|p| !p.trim().is_empty())
                .unwrap_or_else(|| ".".to_string()),
            Err(e) => return ToolOutput::err(e),
        };
        let guard = PathGuard::from_context(ctx);
        let limits = self.limits.clone();
        run_blocking(move || list_dir_blocking(&guard, &path, &limits)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ctx_for;
    use std::os::unix::fs::symlink;

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(10), "10 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MB");
    }

    #[test]
    fn binary_heuristic() {
        assert!(looks_binary(b"abc\0def"));
        assert!(!looks_binary(b"plain text\nwith lines\t"));
        assert!(looks_binary(&[1u8, 2, 3, 4, 5, 6, 7, 8, b'a', b'b']));
        assert!(!looks_binary(b""));
    }

    #[test]
    fn capped_line_reader() {
        let data = b"short\r\n0123456789abcdef\nlast";
        let mut r = BufReader::with_capacity(4, &data[..]);
        let (l, t) = read_line_capped(&mut r, 8).unwrap().unwrap();
        assert_eq!((l.as_slice(), t), (&b"short"[..], false));
        let (l, t) = read_line_capped(&mut r, 8).unwrap().unwrap();
        assert_eq!((l.as_slice(), t), (&b"01234567"[..], true));
        let (l, t) = read_line_capped(&mut r, 8).unwrap().unwrap();
        assert_eq!((l.as_slice(), t), (&b"last"[..], false));
        assert!(read_line_capped(&mut r, 8).unwrap().is_none());
    }

    #[tokio::test]
    async fn read_file_numbers_lines_with_offset_and_limit() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let body: String = (1..=10).map(|i| format!("line {i}\n")).collect();
        fs::write(dir.path().join("f.txt"), body).unwrap();
        let t = ReadFileTool::default();
        let out = t.call(json!({"path": "f.txt"}), &ctx).await;
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.starts_with("     1\tline 1\n"));
        assert!(out.content.contains("    10\tline 10"));
        let out = t
            .call(json!({"path": "f.txt", "offset": 3, "limit": 2}), &ctx)
            .await;
        assert_eq!(
            out.content,
            "     3\tline 3\n     4\tline 4\n[showing lines 3-4; more lines follow — continue with offset=5]"
        );
        let out = t.call(json!({"path": "f.txt", "offset": 50}), &ctx).await;
        assert!(out.is_error);
        assert!(out.content.contains("only 10 lines"));
    }

    #[tokio::test]
    async fn read_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let t = ReadFileTool::default();
        fs::write(dir.path().join("bin"), b"\x7fELF\0\0\0\x01").unwrap();
        fs::write(dir.path().join("empty"), b"").unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        let out = t.call(json!({"path": "bin"}), &ctx).await;
        assert!(
            out.is_error && out.content.contains("ELF"),
            "{}",
            out.content
        );
        let out = t.call(json!({"path": "empty"}), &ctx).await;
        assert!(!out.is_error && out.content.contains("empty"));
        let out = t.call(json!({"path": "d"}), &ctx).await;
        assert!(out.is_error && out.content.contains("directory"));
        let out = t.call(json!({"path": "missing"}), &ctx).await;
        assert!(out.is_error && out.content.contains("not found"));
        let out = t.call(json!({"path": "/etc/hostname"}), &ctx).await;
        assert!(out.is_error && out.content.contains("access denied"));
        let out = t.call(json!({}), &ctx).await;
        assert!(out.is_error);
    }

    #[tokio::test]
    async fn read_file_caps_long_lines_and_output() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let long = "x".repeat(10_000);
        fs::write(dir.path().join("long"), format!("{long}\nshort\n")).unwrap();
        let limits = FileLimits {
            max_line_chars: 100,
            ..FileLimits::default()
        };
        let out = ReadFileTool::new(limits)
            .call(json!({"path": "long"}), &ctx)
            .await;
        assert!(out.content.contains("[line truncated]"), "{}", out.content);
        assert!(out.content.contains("     2\tshort"));

        let many: String = (0..5000).map(|i| format!("row {i}\n")).collect();
        fs::write(dir.path().join("many"), many).unwrap();
        let limits = FileLimits {
            max_output_bytes: 500,
            ..FileLimits::default()
        };
        let out = ReadFileTool::new(limits)
            .call(json!({"path": "many"}), &ctx)
            .await;
        assert!(out.content.len() < 700);
        assert!(out.content.contains("output size limit reached"));
    }

    #[tokio::test]
    async fn write_file_creates_dirs_and_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let t = WriteFileTool::default();
        let out = t
            .call(json!({"path": "a/b/c.txt", "content": "hi\nthere\n"}), &ctx)
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.starts_with("Created"));
        assert_eq!(
            fs::read_to_string(dir.path().join("a/b/c.txt")).unwrap(),
            "hi\nthere\n"
        );
        let out = t
            .call(json!({"path": "a/b/c.txt", "content": "new"}), &ctx)
            .await;
        assert!(out.content.starts_with("Overwrote"));
        let out = t.call(json!({"path": "a", "content": "x"}), &ctx).await;
        assert!(out.is_error);
    }

    #[tokio::test]
    async fn write_file_refuses_escapes_and_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        fs::create_dir(&ro).unwrap();
        let mut ctx = ctx_for(dir.path());
        ctx.read_only_roots = vec![ro.clone()];
        symlink(outside.path(), dir.path().join("link")).unwrap();
        let t = WriteFileTool::default();
        for p in ["link/x.txt", "../x.txt", "ro/x.txt"] {
            let out = t.call(json!({"path": p, "content": "x"}), &ctx).await;
            assert!(out.is_error, "{p} should be refused");
        }
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
        let limits = FileLimits {
            max_write_bytes: 3,
            ..FileLimits::default()
        };
        let out = WriteFileTool::new(limits)
            .call(json!({"path": "big", "content": "four"}), &ctx)
            .await;
        assert!(out.is_error && out.content.contains("exceeds"));
    }

    #[tokio::test]
    async fn edit_file_unique_and_replace_all() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let p = dir.path().join("e.txt");
        fs::write(&p, "alpha\nbeta\nalpha\n").unwrap();
        let t = EditFileTool::default();
        let out = t
            .call(
                json!({"path": "e.txt", "old_string": "alpha", "new_string": "x"}),
                &ctx,
            )
            .await;
        assert!(out.is_error && out.content.contains("occurs 2 times"));
        let out = t
            .call(
                json!({"path": "e.txt", "old_string": "beta", "new_string": "gamma"}),
                &ctx,
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.contains("first at line 2"));
        assert!(out.content.contains("     2\tgamma"));
        assert_eq!(fs::read_to_string(&p).unwrap(), "alpha\ngamma\nalpha\n");
        let out = t
            .call(
                json!({"path": "e.txt", "old_string": "alpha", "new_string": "omega", "replace_all": true}),
                &ctx,
            )
            .await;
        assert!(out.content.contains("replaced 2 occurrences"));
        assert_eq!(fs::read_to_string(&p).unwrap(), "omega\ngamma\nomega\n");
    }

    #[tokio::test]
    async fn edit_file_errors_and_crlf() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        let p = dir.path().join("w.txt");
        fs::write(&p, "one\r\ntwo\r\nthree\r\n").unwrap();
        let t = EditFileTool::default();
        let out = t
            .call(
                json!({"path": "w.txt", "old_string": "one\ntwo", "new_string": "1\n2"}),
                &ctx,
            )
            .await;
        assert!(!out.is_error, "{}", out.content);
        assert_eq!(fs::read_to_string(&p).unwrap(), "1\r\n2\r\nthree\r\n");
        let out = t
            .call(
                json!({"path": "w.txt", "old_string": "nope", "new_string": "x"}),
                &ctx,
            )
            .await;
        assert!(out.is_error && out.content.contains("not found"));
        let out = t
            .call(
                json!({"path": "w.txt", "old_string": "", "new_string": "x"}),
                &ctx,
            )
            .await;
        assert!(out.is_error);
        let out = t
            .call(
                json!({"path": "w.txt", "old_string": "three", "new_string": "three"}),
                &ctx,
            )
            .await;
        assert!(out.is_error && out.content.contains("identical"));
        let out = t
            .call(
                json!({"path": "missing", "old_string": "a", "new_string": "b"}),
                &ctx,
            )
            .await;
        assert!(out.is_error && out.content.contains("write_file"));
    }

    #[tokio::test]
    async fn list_dir_sorted_with_dirs_first() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_for(dir.path());
        fs::create_dir(dir.path().join("zdir")).unwrap();
        fs::write(dir.path().join("a.txt"), "hello").unwrap();
        fs::write(dir.path().join(".hidden"), "").unwrap();
        symlink("a.txt", dir.path().join("lnk")).unwrap();
        let out = ListDirTool::default().call(json!({}), &ctx).await;
        assert!(!out.is_error, "{}", out.content);
        let lines: Vec<&str> = out.content.lines().collect();
        assert!(lines[0].ends_with("(4 entries)"));
        assert_eq!(lines[1], "zdir/");
        assert_eq!(lines[2], ".hidden  (0 B)");
        assert_eq!(lines[3], "a.txt  (5 B)");
        assert_eq!(lines[4], "lnk -> a.txt");
        let limits = FileLimits {
            max_entries: 2,
            ..FileLimits::default()
        };
        let out = ListDirTool::new(limits).call(json!({}), &ctx).await;
        assert_eq!(out.content.lines().count(), 4, "{}", out.content);
        assert!(
            out.content.ends_with(
                "[... 2 more entries not shown; use glob with a pattern to narrow down]"
            )
        );
        let out = ListDirTool::default()
            .call(json!({"path": "a.txt"}), &ctx)
            .await;
        assert!(out.is_error);
        let out = ListDirTool::default()
            .call(json!({"path": "/"}), &ctx)
            .await;
        assert!(out.is_error);
    }
}

//! Path guard for the file tools.
//!
//! Every path a file tool touches goes through [`PathGuard::resolve`]:
//!
//! 1. Relative paths are joined to `ToolContext.cwd`; the result is normalized
//!    lexically (`.`/`..` removed).
//! 2. The longest existing prefix (by `lstat`, so dangling symlinks count as
//!    existing) is canonicalized, which resolves every symlink in it. Dangling
//!    symlinks are refused. The not-yet-existing remainder is appended.
//! 3. The resulting real path must lie inside a canonicalized root:
//!    - **read** access: any of `allowed_roots` ∪ `read_only_roots`;
//!    - **write** access: one of `allowed_roots` and none of
//!      `read_only_roots`.
//!
//! Because the check runs on the canonical path, a symlink inside a root that
//! points outside of it is rejected, and tools then operate on the returned
//! canonical path rather than the user-supplied one.
//!
//! Empty root lists fail closed. The guard is defence in depth for the
//! dedicated file tools; the container boundary remains the real sandbox
//! (the `bash` tool is not confined by it).

use std::io;
use std::path::{Path, PathBuf};

use talon_core::paths::normalize_lexically;
use talon_core::tool::ToolContext;

/// Maximum accepted length of a user-supplied path.
const MAX_PATH_LEN: usize = 4096;

/// Kind of access requested for a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read or list.
    Read,
    /// Create, modify or replace.
    Write,
}

/// A path that passed the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedPath {
    /// Absolute real path (symlinks of the existing prefix resolved).
    pub path: PathBuf,
    /// Whether the full path currently exists.
    pub exists: bool,
}

/// Canonicalized view of a [`ToolContext`]'s roots.
#[derive(Debug, Clone)]
pub struct PathGuard {
    cwd: PathBuf,
    allowed: Vec<PathBuf>,
    read_only: Vec<PathBuf>,
    /// Display form of the configured roots (for error messages).
    display_roots: Vec<String>,
}

fn canonical_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    roots
        .iter()
        .filter_map(|r| match std::fs::canonicalize(r) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::debug!(root = %r.display(), error = %e, "ignoring unusable tool root");
                None
            }
        })
        .collect()
}

impl PathGuard {
    /// Build a guard from the context (canonicalizes the roots; roots that
    /// don't exist are ignored).
    pub fn from_context(ctx: &ToolContext) -> Self {
        Self::new(&ctx.cwd, &ctx.allowed_roots, &ctx.read_only_roots)
    }

    /// Build a guard from explicit roots.
    pub fn new(cwd: &Path, allowed_roots: &[PathBuf], read_only_roots: &[PathBuf]) -> Self {
        let display_roots = allowed_roots
            .iter()
            .chain(read_only_roots.iter())
            .map(|p| p.display().to_string())
            .collect();
        Self {
            cwd: cwd.to_path_buf(),
            allowed: canonical_roots(allowed_roots),
            read_only: canonical_roots(read_only_roots),
            display_roots,
        }
    }

    fn roots_hint(&self) -> String {
        if self.display_roots.is_empty() {
            "no directories are accessible in this context".to_string()
        } else {
            format!("accessible directories: {}", self.display_roots.join(", "))
        }
    }

    /// Is the canonical path `p` readable under the configured roots?
    pub fn is_readable(&self, p: &Path) -> bool {
        self.allowed
            .iter()
            .chain(self.read_only.iter())
            .any(|r| p.starts_with(r))
    }

    /// Is the canonical path `p` writable under the configured roots?
    pub fn is_writable(&self, p: &Path) -> bool {
        self.allowed.iter().any(|r| p.starts_with(r))
            && !self.read_only.iter().any(|r| p.starts_with(r))
    }

    /// Resolve and authorize a user-supplied path. Errors are phrased for
    /// the model.
    pub fn resolve(&self, raw: &str, access: Access) -> Result<GuardedPath, String> {
        if raw.trim().is_empty() {
            return Err("path must not be empty".to_string());
        }
        if raw.len() > MAX_PATH_LEN {
            return Err(format!("path is longer than {MAX_PATH_LEN} bytes"));
        }
        if raw.contains('\0') {
            return Err("path must not contain NUL bytes".to_string());
        }
        let joined = {
            let p = Path::new(raw);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                self.cwd.join(p)
            }
        };
        let normalized = normalize_lexically(&joined);
        if !normalized.is_absolute() {
            return Err(format!("could not resolve {raw:?} to an absolute path"));
        }

        // Walk up to the longest prefix that exists (lstat).
        let mut existing = normalized.clone();
        let mut rest: Vec<std::ffi::OsString> = Vec::new();
        loop {
            match std::fs::symlink_metadata(&existing) {
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let Some(name) = existing.file_name().map(|n| n.to_os_string()) else {
                        return Err(format!("could not resolve {raw:?}"));
                    };
                    rest.push(name);
                    if !existing.pop() {
                        return Err(format!("could not resolve {raw:?}"));
                    }
                }
                Err(e) => return Err(format!("cannot access {}: {e}", existing.display())),
            }
        }
        let canonical_prefix = std::fs::canonicalize(&existing).map_err(|e| {
            if e.kind() == io::ErrorKind::NotFound {
                format!(
                    "access denied: {} is (or passes through) a dangling symbolic link",
                    existing.display()
                )
            } else {
                format!("cannot resolve {}: {e}", existing.display())
            }
        })?;
        let exists = rest.is_empty();
        let mut full = canonical_prefix;
        for name in rest.iter().rev() {
            full.push(name);
        }

        let ok = match access {
            Access::Read => self.is_readable(&full),
            Access::Write => self.is_writable(&full),
        };
        if !ok {
            if access == Access::Write && self.is_readable(&full) {
                return Err(format!(
                    "access denied: {} is in a read-only directory",
                    full.display()
                ));
            }
            let shown = if full == normalized {
                full.display().to_string()
            } else {
                format!("{} (resolves to {})", normalized.display(), full.display())
            };
            return Err(format!(
                "access denied: {shown} is outside the allowed directories ({})",
                self.roots_hint()
            ));
        }
        Ok(GuardedPath { path: full, exists })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        ro: PathBuf,
        outside: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(tmp.path()).unwrap();
        let root = base.join("group");
        let ro = base.join("global");
        let outside = base.join("outside");
        for d in [&root, &ro, &outside] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(root.join("a.txt"), "a").unwrap();
        std::fs::write(ro.join("g.md"), "g").unwrap();
        std::fs::write(outside.join("secret"), "s").unwrap();
        Fixture {
            _tmp: tmp,
            root,
            ro,
            outside,
        }
    }

    fn guard(f: &Fixture) -> PathGuard {
        PathGuard::new(
            &f.root,
            std::slice::from_ref(&f.root),
            std::slice::from_ref(&f.ro),
        )
    }

    #[test]
    fn relative_and_absolute_inside_root() {
        let f = fixture();
        let g = guard(&f);
        let r = g.resolve("a.txt", Access::Read).unwrap();
        assert_eq!(r.path, f.root.join("a.txt"));
        assert!(r.exists);
        let w = g.resolve("new/dir/file.txt", Access::Write).unwrap();
        assert_eq!(w.path, f.root.join("new/dir/file.txt"));
        assert!(!w.exists);
        assert!(g.resolve(f.root.to_str().unwrap(), Access::Read).is_ok());
    }

    #[test]
    fn traversal_rejected() {
        let f = fixture();
        let g = guard(&f);
        let e = g.resolve("../outside/secret", Access::Read).unwrap_err();
        assert!(e.contains("outside the allowed"), "{e}");
        assert!(g.resolve("/etc/passwd", Access::Read).is_err());
        assert!(
            g.resolve("../../../../../../etc/passwd", Access::Read)
                .is_err()
        );
        assert!(g.resolve("", Access::Read).is_err());
        assert!(g.resolve("a\0b", Access::Read).is_err());
    }

    #[test]
    fn read_only_roots_readable_not_writable() {
        let f = fixture();
        let g = guard(&f);
        let p = f.ro.join("g.md");
        assert!(g.resolve(p.to_str().unwrap(), Access::Read).is_ok());
        let e = g.resolve(p.to_str().unwrap(), Access::Write).unwrap_err();
        assert!(e.contains("read-only"), "{e}");
        let e = g
            .resolve(f.ro.join("new.md").to_str().unwrap(), Access::Write)
            .unwrap_err();
        assert!(e.contains("read-only"), "{e}");
    }

    #[test]
    fn read_only_nested_inside_allowed_is_not_writable() {
        let f = fixture();
        let nested = f.root.join("ref");
        std::fs::create_dir_all(&nested).unwrap();
        let g = PathGuard::new(
            &f.root,
            std::slice::from_ref(&f.root),
            std::slice::from_ref(&nested),
        );
        assert!(g.resolve("ref/x", Access::Write).is_err());
        assert!(g.resolve("other/x", Access::Write).is_ok());
    }

    #[test]
    fn symlink_escape_rejected() {
        let f = fixture();
        symlink(&f.outside, f.root.join("escape")).unwrap();
        symlink(f.outside.join("secret"), f.root.join("secret-link")).unwrap();
        let g = guard(&f);
        assert!(g.resolve("escape/secret", Access::Read).is_err());
        assert!(g.resolve("secret-link", Access::Read).is_err());
        assert!(g.resolve("escape/new.txt", Access::Write).is_err());
        assert!(g.resolve("secret-link", Access::Write).is_err());
    }

    #[test]
    fn symlink_within_root_allowed_and_resolved() {
        let f = fixture();
        symlink(f.root.join("a.txt"), f.root.join("alias")).unwrap();
        let g = guard(&f);
        let r = g.resolve("alias", Access::Read).unwrap();
        assert_eq!(r.path, f.root.join("a.txt"));
    }

    #[test]
    fn dangling_symlink_rejected() {
        let f = fixture();
        symlink(f.outside.join("nope"), f.root.join("dangling")).unwrap();
        symlink(f.outside.join("nodir"), f.root.join("dangdir")).unwrap();
        let g = guard(&f);
        let e = g.resolve("dangling", Access::Write).unwrap_err();
        assert!(e.contains("dangling"), "{e}");
        assert!(g.resolve("dangdir/x/y", Access::Write).is_err());
    }

    #[test]
    fn empty_roots_fail_closed() {
        let f = fixture();
        let g = PathGuard::new(&f.root, &[], &[]);
        let e = g.resolve("a.txt", Access::Read).unwrap_err();
        assert!(e.contains("no directories"), "{e}");
    }

    #[test]
    fn prefix_sibling_not_confused_with_root() {
        let f = fixture();
        let sibling = f.root.parent().unwrap().join("group2");
        std::fs::create_dir_all(&sibling).unwrap();
        let g = guard(&f);
        assert!(g.resolve(sibling.to_str().unwrap(), Access::Read).is_err());
    }
}

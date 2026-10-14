//! Read-only mount detection from `/proc/self/mountinfo` (proc(5)).
//!
//! The supervisor launches MCP servers as `mcp-*` accounts that hold
//! secrets, so their command must not be modifiable from inside the
//! container. Besides living under an allowed root, the canonical command
//! (and its directory) must sit on a filesystem that is mounted read-only
//! **in this container** ([`MountTable::is_read_only`]).
//!
//! Which mount decides for a path:
//! - the **longest-prefix** mount point (component-wise, so
//!   `/workspace/project2` never matches `/workspace/project`); among
//!   several mounts stacked on that mount point, the topmost (the one no
//!   other entry is mounted on, else the last listed);
//! - and the mount actually **visible** at the path, found by walking the
//!   parent chain from the root (a later mount over a shallower directory
//!   hides deeper mounts listed before it).
//!
//! The path counts as read-only only if every deciding mount carries `ro`
//! in its per-mount options, so odd tables (reordered entries, hidden
//! mounts) fail closed. An unreadable or empty table makes every path
//! "not read-only".

use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

/// The mount table of the current process.
pub const DEFAULT_MOUNTINFO: &str = "/proc/self/mountinfo";
/// Mount tables larger than this are refused.
const MAX_MOUNTINFO_BYTES: u64 = 8 * 1024 * 1024;

/// One line of `mountinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Mount id (field 1).
    pub id: u64,
    /// Id of the mount this one is attached to (field 2).
    pub parent: u64,
    /// Mount point relative to the process root (field 5, unescaped).
    pub mount_point: PathBuf,
    /// `ro` among the per-mount options (field 6).
    pub read_only: bool,
}

/// A parsed mount table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MountTable {
    entries: Vec<MountEntry>,
}

impl MountTable {
    /// Parse `mountinfo` text. Malformed lines are skipped.
    pub fn parse(text: &str) -> Self {
        Self {
            entries: text.lines().filter_map(parse_line).collect(),
        }
    }

    /// Read and parse a `mountinfo` file (bounded).
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut text = String::new();
        file.take(MAX_MOUNTINFO_BYTES + 1)
            .read_to_string(&mut text)?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_MOUNTINFO_BYTES {
            return Err(std::io::Error::other("mount table is too large"));
        }
        let table = Self::parse(&text);
        if table.entries.is_empty() {
            return Err(std::io::Error::other("mount table has no usable entries"));
        }
        Ok(table)
    }

    /// The parsed entries, in table order.
    pub fn entries(&self) -> &[MountEntry] {
        &self.entries
    }

    fn candidates<'s, 'p>(&'s self, path: &'p Path) -> impl Iterator<Item = &'s MountEntry> + 'p
    where
        's: 'p,
    {
        self.entries
            .iter()
            .filter(move |e| path.starts_with(&e.mount_point))
    }

    /// The longest-prefix mount of the absolute, canonical `path` (topmost
    /// of a stack on the same mount point).
    pub fn longest_prefix_mount(&self, path: &Path) -> Option<&MountEntry> {
        let depth = self
            .candidates(path)
            .map(|e| e.mount_point.components().count())
            .max()?;
        let stack: Vec<&MountEntry> = self
            .candidates(path)
            .filter(|e| e.mount_point.components().count() == depth)
            .collect();
        stack
            .iter()
            .rev()
            .find(|e| !stack.iter().any(|o| o.id != e.id && o.parent == e.id))
            .or_else(|| stack.last())
            .copied()
    }

    /// The mount visible at `path`, following the parent chain from the
    /// shallowest mount point down.
    pub fn visible_mount(&self, path: &Path) -> Option<&MountEntry> {
        let mut candidates: Vec<&MountEntry> = self.candidates(path).collect();
        // Stable: table order within one depth.
        candidates.sort_by_key(|e| e.mount_point.components().count());
        let mut current: Option<&MountEntry> = None;
        for c in candidates {
            match current {
                None => current = Some(c),
                Some(cur) if c.parent == cur.id && c.id != cur.id => current = Some(c),
                Some(_) => {}
            }
        }
        current
    }

    /// Is the absolute, canonical `path` on a read-only mount? `false` when
    /// no mount covers it or the deciding mounts disagree.
    pub fn is_read_only(&self, path: &Path) -> bool {
        if !path.is_absolute() {
            return false;
        }
        match (self.longest_prefix_mount(path), self.visible_mount(path)) {
            (Some(longest), Some(visible)) => longest.read_only && visible.read_only,
            _ => false,
        }
    }
}

/// `36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue`
fn parse_line(line: &str) -> Option<MountEntry> {
    let fields: Vec<&str> = line.split(' ').collect();
    // Optional fields (index 6..) end with a lone "-" separator.
    fields.iter().skip(6).position(|f| *f == "-")?;
    let id = fields.first()?.parse().ok()?;
    let parent = fields.get(1)?.parse().ok()?;
    let mount_point = PathBuf::from(unescape(fields.get(4)?));
    if !mount_point.is_absolute() {
        return None;
    }
    let read_only = fields.get(5)?.split(',').any(|o| o == "ro");
    Some(MountEntry {
        id,
        parent,
        mount_point,
        read_only,
    })
}

/// Decode the kernel's `\ooo` octal escapes (space, tab, newline,
/// backslash) without assuming UTF-8.
fn unescape(field: &str) -> OsString {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let digits = bytes.get(i + 1..i + 4).unwrap_or_default();
            if digits.len() == 3 && digits.iter().all(|d| (b'0'..=b'7').contains(d)) {
                let value = digits
                    .iter()
                    .fold(0u32, |acc, d| acc * 8 + u32::from(d - b'0'));
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    OsString::from_vec(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shaped like a `docker run --read-only` container of the main group.
    const CONTAINER: &str = "\
1180 1050 0:120 / / ro,relatime master:400 - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
1181 1180 0:123 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1190 1180 0:130 / /tmp rw,nosuid,nodev,relatime - tmpfs tmpfs rw,size=1048576k
1200 1180 8:1 /srv/talon /workspace/project ro,relatime - ext4 /dev/sda1 rw
1201 1200 8:1 /dev/null /workspace/project/.env ro,relatime - devtmpfs udev rw
1202 1180 8:1 /srv/talon/groups/main /workspace/group rw,relatime - ext4 /dev/sda1 rw
1203 1202 8:1 /srv/talon/groups/main/CLAUDE.md /workspace/group/CLAUDE.md ro,relatime - ext4 /dev/sda1 rw
1204 1180 8:1 /srv/extra/siem /workspace/extra/siem ro,relatime - ext4 /dev/sda1 rw
1205 1180 8:1 /srv/extra/scratch /workspace/extra/scratch rw,relatime - ext4 /dev/sda1 rw
1206 1180 8:1 /srv/my\\040dir /workspace/extra/my\\040dir ro,relatime shared:5 master:7 - ext4 /dev/sda1 rw
";

    fn ro(table: &MountTable, p: &str) -> bool {
        table.is_read_only(Path::new(p))
    }

    #[test]
    fn parses_fields_and_escapes() {
        let t = MountTable::parse(CONTAINER);
        assert_eq!(t.entries().len(), 10);
        let e = &t.entries()[3];
        assert_eq!((e.id, e.parent), (1200, 1180));
        assert_eq!(e.mount_point, PathBuf::from("/workspace/project"));
        assert!(e.read_only);
        assert_eq!(
            t.entries()[9].mount_point,
            PathBuf::from("/workspace/extra/my dir")
        );
        assert_eq!(unescape("a\\011b\\134c\\012"), OsString::from("a\tb\\c\n"));
        assert_eq!(unescape("trail\\04"), OsString::from("trail\\04"));
        assert_eq!(unescape("bad\\089"), OsString::from("bad\\089"));
        // Malformed lines are skipped.
        let t = MountTable::parse(
            "garbage\n1 2 3 4\nx 1 0:1 / / ro - a b c\n1 0 0:1 / rel ro - a b c\n",
        );
        assert!(t.entries().is_empty());
    }

    #[test]
    fn longest_prefix_decides() {
        let t = MountTable::parse(CONTAINER);
        // Main's project mount (MYTH-13) and the image rootfs.
        assert!(ro(&t, "/workspace/project/mysql/mysql-mcp.sh"));
        assert!(ro(&t, "/workspace/project/mysql"));
        assert!(ro(&t, "/usr/local/bin/talon-agent"));
        assert!(ro(&t, "/opt/mysql-mcp/bin/python"));
        assert!(ro(&t, "/workspace/extra/siem/siem-mcp.sh"));
        assert!(ro(&t, "/workspace/extra/my dir/x.sh"));
        // Writable mounts.
        assert!(!ro(&t, "/workspace/group/run.sh"));
        assert!(!ro(&t, "/workspace/extra/scratch/x.sh"));
        assert!(!ro(&t, "/tmp/x"));
        // Component-wise matching: a sibling with a common string prefix
        // is decided by its own mount, not the read-only project.
        let sibling = MountTable::parse(
            "1 0 0:1 / / rw - ext4 a rw\n2 1 0:2 / /workspace/project ro - ext4 b rw\n",
        );
        assert!(ro(&sibling, "/workspace/project/x"));
        assert!(!ro(&sibling, "/workspace/project2/x"));
        assert!(!ro(&sibling, "relative/path"));
        // No table, no read-only.
        assert!(!ro(&MountTable::default(), "/usr/bin/python3"));
    }

    #[test]
    fn stacked_and_hidden_mounts_fail_closed() {
        // A writable mount stacked on top of a read-only one (listed in
        // either order) decides.
        let stacked =
            "1 0 0:1 / / ro - x a ro\n2 1 0:2 / /opt ro - x b ro\n3 2 0:3 / /opt rw - x c rw\n";
        assert!(!ro(&MountTable::parse(stacked), "/opt/tool"));
        let reordered =
            "3 2 0:3 / /opt rw - x c rw\n1 0 0:1 / / ro - x a ro\n2 1 0:2 / /opt ro - x b ro\n";
        assert!(!ro(&MountTable::parse(reordered), "/opt/tool"));
        // Read-only stacked over writable: read-only.
        let covered =
            "1 0 0:1 / / ro - x a ro\n2 1 0:2 / /opt rw - x b rw\n3 2 0:3 / /opt ro - x c ro\n";
        assert!(ro(&MountTable::parse(covered), "/opt/tool"));

        // A read-only mount at /opt/x hidden by a later writable mount over
        // /opt: the path really resolves to the writable one.
        let hidden =
            "1 0 0:1 / / ro - x a ro\n2 1 0:2 / /opt/x ro - x b ro\n3 1 0:3 / /opt rw - x c rw\n";
        let t = MountTable::parse(hidden);
        assert_eq!(t.visible_mount(Path::new("/opt/x/tool")).unwrap().id, 3);
        assert_eq!(
            t.longest_prefix_mount(Path::new("/opt/x/tool")).unwrap().id,
            2
        );
        assert!(!ro(&t, "/opt/x/tool"));

        // Root listed after its children (as some runtimes do).
        let late_root = "5 9 0:5 / /proc rw - proc p rw\n9 1 0:9 / / ro - x a ro\n10 9 0:10 / /workspace/project ro - x b rw\n";
        let t = MountTable::parse(late_root);
        assert!(ro(&t, "/workspace/project/mysql/mysql-mcp.sh"));
        assert!(ro(&t, "/usr/bin/python3"));
    }

    #[test]
    fn load_reads_files_and_rejects_empty_tables() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("mountinfo");
        std::fs::write(&f, CONTAINER).unwrap();
        assert_eq!(MountTable::load(&f).unwrap().entries().len(), 10);
        std::fs::write(&f, "nothing useful\n").unwrap();
        assert!(MountTable::load(&f).is_err());
        assert!(MountTable::load(&dir.path().join("missing")).is_err());
        // The real table of this process parses (Linux CI and containers).
        if let Ok(real) = MountTable::load(Path::new(DEFAULT_MOUNTINFO)) {
            assert!(real.visible_mount(Path::new("/")).is_some());
        }
    }
}

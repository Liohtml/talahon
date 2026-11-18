//! Who holds a listening TCP port?
//!
//! `talahon doctor` and `talahon setup environment` check that the LLM
//! gateway port is free. While the service runs it is not — this project's
//! Talahon listens there — and that must not count as a problem. On Linux
//! the listening process is identified from `/proc` (the listening socket's
//! inode in `/proc/net/tcp{,6}`, the process whose `fd/` holds that socket,
//! and its `exe` and `cwd` links), without sending anything to the port. A
//! Talahon of another project or checkout, or an unrelated program that is
//! merely called `talon`, would stop `talahon run` from binding just the
//! same, so the process must also belong to this project (see
//! [`is_project_talahon`]). Elsewhere, or when the process belongs to
//! another user (its `fd/` is unreadable), the owner is unknown and the
//! caller keeps treating the port as taken.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crate::context::{BINARY_NAME, LEGACY_BINARY_NAME};
use crate::steps::service::{legacy_pid_file_path, pid_file_path};

/// Listening sockets in the text of `/proc/net/tcp` or `/proc/net/tcp6`:
/// `(local address, local port, socket inode)` per `LISTEN` line.
pub fn parse_listeners(proc_net_tcp: &str) -> Vec<(IpAddr, u16, u64)> {
    /// `st` column of a listening socket (`TCP_LISTEN`).
    const LISTEN: &str = "0A";
    proc_net_tcp
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(3) != Some(&LISTEN) {
                return None;
            }
            let (addr, port) = fields.get(1)?.rsplit_once(':')?;
            let inode = fields.get(9)?.parse().ok()?;
            Some((
                parse_addr(addr)?,
                u16::from_str_radix(port, 16).ok()?,
                inode,
            ))
        })
        .collect()
}

/// The kernel prints an address as its 32-bit words in host byte order.
fn parse_addr(hex: &str) -> Option<IpAddr> {
    if !hex.is_ascii() || !matches!(hex.len(), 8 | 32) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for word in hex.as_bytes().chunks(8) {
        let word = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    match <[u8; 4]>::try_from(bytes.as_slice()) {
        Ok(v4) => Some(IpAddr::V4(Ipv4Addr::from(v4))),
        Err(_) => <[u8; 16]>::try_from(bytes.as_slice())
            .ok()
            .map(|v6| IpAddr::V6(Ipv6Addr::from(v6))),
    }
}

/// A socket listening on `local` also receives connections for `ip`: the
/// same address, or the wildcard address (`::` covers IPv4 as well).
fn covers(local: IpAddr, ip: IpAddr) -> bool {
    local == ip || local == IpAddr::V6(Ipv6Addr::UNSPECIFIED) || {
        local == IpAddr::V4(Ipv4Addr::UNSPECIFIED) && ip.is_ipv4()
    }
}

/// `exe` (a `/proc/<pid>/exe` target) is the Talahon host binary, under its
/// current or its pre-rename name. A binary replaced while the process
/// runs shows as `<path> (deleted)`.
pub fn is_talahon_exe(exe: &Path) -> bool {
    let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let name = name.strip_suffix(" (deleted)").unwrap_or(name);
    name == BINARY_NAME || name == LEGACY_BINARY_NAME
}

/// Pids of the processes listening on `ip:port` whose sockets this user may
/// inspect. Empty when nothing listens there, on other platforms than
/// Linux, and for another user's process.
pub fn listener_pids(ip: IpAddr, port: u16) -> Vec<u32> {
    let mut inodes = Vec::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        inodes.extend(
            parse_listeners(&text)
                .into_iter()
                .filter(|(local, p, _)| *p == port && covers(*local, ip))
                .map(|(_, _, inode)| format!("socket:[{inode}]")),
        );
    }
    if inodes.is_empty() {
        return Vec::new();
    }
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids = Vec::new();
    for entry in procs.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        let holds_socket = fds.flatten().any(|fd| {
            std::fs::read_link(fd.path())
                .ok()
                .and_then(|target| target.to_str().map(|t| inodes.iter().any(|i| i == t)))
                .unwrap_or(false)
        });
        if holds_socket {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids
}

/// What `/proc` shows about a process, as far as this user may read it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcessFacts {
    /// The process id.
    pub pid: u32,
    /// Target of `/proc/<pid>/exe`, `None` when unreadable.
    pub exe: Option<PathBuf>,
    /// Target of `/proc/<pid>/cwd`, `None` when unreadable.
    pub cwd: Option<PathBuf>,
}

impl ProcessFacts {
    /// Read the facts of `pid` from `/proc` (all `None` elsewhere, and for
    /// another user's process).
    pub fn read(pid: u32) -> Self {
        let link = |name: &str| std::fs::read_link(format!("/proc/{pid}/{name}")).ok();
        Self {
            pid,
            exe: link("exe"),
            cwd: link("cwd"),
        }
    }
}

/// `process` is this project's Talahon: it runs the host binary
/// ([`is_talahon_exe`]) and belongs to the project, i.e. its working
/// directory is `project_root` (canonical; the systemd unit and the launchd
/// plist set `WorkingDirectory`, the nohup wrapper `cd`s there) or its pid
/// is one of `recorded_pids` (the project's pid files). What cannot be read
/// counts against it: an unknown process is never taken for ours.
pub fn is_project_talahon(
    process: &ProcessFacts,
    project_root: &Path,
    recorded_pids: &[u32],
) -> bool {
    process.exe.as_deref().is_some_and(is_talahon_exe)
        && (process.cwd.as_deref() == Some(project_root) || recorded_pids.contains(&process.pid))
}

/// Pids in the project's pid files: `talahon.pid`, and `talon.pid` of an
/// instance started before the rename (both written by the nohup wrapper).
/// Missing or unparsable files contribute nothing.
pub fn recorded_pids(project_root: &Path) -> Vec<u32> {
    [
        pid_file_path(project_root),
        legacy_pid_file_path(project_root),
    ]
    .iter()
    .filter_map(|path| std::fs::read_to_string(path).ok())
    .filter_map(|raw| raw.trim().parse().ok())
    .collect()
}

/// The pid of this project's Talahon host process listening on `ip:port`,
/// if this user can tell (see the module documentation and
/// [`is_project_talahon`]).
pub fn project_talahon_listener(ip: IpAddr, port: u16, project_root: &Path) -> Option<u32> {
    // `/proc/<pid>/cwd` shows the resolved path.
    let root = std::fs::canonicalize(project_root).unwrap_or_else(|_| project_root.to_path_buf());
    let recorded = recorded_pids(project_root);
    listener_pids(ip, port)
        .into_iter()
        .find(|&pid| is_project_talahon(&ProcessFacts::read(pid), &root, &recorded))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BB9 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 7129 1 0000000000000000 100 0 0 10 0
   1: 00000000:006F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2205 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0BB9 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 9001 1 0000000000000000 20 4 30 10 -1
";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:006F 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 85 1 0000000000000000 100 0 0 10 0
";

    #[cfg(target_endian = "little")]
    #[test]
    fn listening_sockets_are_parsed_and_connections_skipped() {
        assert_eq!(
            parse_listeners(TCP),
            vec![
                (IpAddr::V4(Ipv4Addr::LOCALHOST), 3001, 7129),
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 111, 2205),
            ]
        );
        assert_eq!(
            parse_listeners(TCP6),
            vec![(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 111, 85)]
        );
        assert!(parse_listeners("garbage\nmore garbage\n").is_empty());
    }

    #[test]
    fn wildcard_listeners_cover_specific_addresses() {
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let other: IpAddr = "172.17.0.1".parse().unwrap();
        assert!(covers(lo, lo));
        assert!(!covers(lo, other));
        assert!(covers(IpAddr::V4(Ipv4Addr::UNSPECIFIED), other));
        assert!(covers(IpAddr::V6(Ipv6Addr::UNSPECIFIED), other));
        assert!(!covers(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        ));
    }

    #[test]
    fn the_host_binary_is_recognised_by_name() {
        for exe in [
            "/usr/local/bin/talahon",
            "/opt/talahon/target/release/talahon",
            "/usr/local/bin/talon",
            "/usr/local/bin/talahon (deleted)",
        ] {
            assert!(is_talahon_exe(Path::new(exe)), "{exe}");
        }
        for exe in [
            "/usr/bin/python3",
            "/usr/local/bin/talahon-agent",
            "/usr/bin/vllm",
            "",
        ] {
            assert!(!is_talahon_exe(Path::new(exe)), "{exe}");
        }
    }

    #[test]
    fn only_a_talahon_of_this_project_counts_as_ours() {
        let root = Path::new("/home/user/talahon");
        let ours = ProcessFacts {
            pid: 4242,
            exe: Some(PathBuf::from("/usr/local/bin/talahon")),
            cwd: Some(root.to_path_buf()),
        };
        // Started by the service unit / nohup wrapper in the project root.
        assert!(is_project_talahon(&ours, root, &[]));
        // A Talahon of another checkout or project.
        let elsewhere = ProcessFacts {
            cwd: Some(PathBuf::from("/home/user/talahon-dev")),
            ..ours.clone()
        };
        assert!(!is_project_talahon(&elsewhere, root, &[]));
        assert!(!is_project_talahon(&elsewhere, root, &[1, 4243]));
        // ... unless the project's pid file names it.
        assert!(is_project_talahon(&elsewhere, root, &[4242]));
        // A working directory that cannot be read: only the pid file helps.
        let no_cwd = ProcessFacts {
            cwd: None,
            ..ours.clone()
        };
        assert!(!is_project_talahon(&no_cwd, root, &[]));
        assert!(is_project_talahon(&no_cwd, root, &[4242]));
        // Not the host binary (or unknown), even in the project root and
        // named in the pid file.
        for exe in [None, Some(PathBuf::from("/usr/bin/python3"))] {
            let other = ProcessFacts {
                exe,
                ..ours.clone()
            };
            assert!(!is_project_talahon(&other, root, &[4242]));
        }
        // Nothing readable at all (another user's process, not Linux).
        let unknown = ProcessFacts {
            pid: 4242,
            ..ProcessFacts::default()
        };
        assert!(!is_project_talahon(&unknown, root, &[4242]));
    }

    #[test]
    fn pid_files_of_both_names_are_read() {
        let dir = tempfile::tempdir().unwrap();
        assert!(recorded_pids(dir.path()).is_empty());
        std::fs::write(dir.path().join("talahon.pid"), "4242\n").unwrap();
        assert_eq!(recorded_pids(dir.path()), vec![4242]);
        std::fs::write(dir.path().join("talon.pid"), "17\n").unwrap();
        assert_eq!(recorded_pids(dir.path()), vec![4242, 17]);
        std::fs::write(dir.path().join("talahon.pid"), "garbage").unwrap();
        assert_eq!(recorded_pids(dir.path()), vec![17]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_listener_of_this_process_is_found_but_is_not_talahon() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(listener_pids(addr.ip(), addr.port()).contains(&std::process::id()));
        // This process's links are readable; its cwd is the resolved path.
        let me = ProcessFacts::read(std::process::id());
        let cwd = std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap();
        assert_eq!(me.cwd.as_deref(), Some(cwd.as_path()));
        assert!(me.exe.is_some());
        // The test binary is not the host binary, even in "its" project.
        assert_eq!(project_talahon_listener(addr.ip(), addr.port(), &cwd), None);
        drop(listener);
        assert!(listener_pids(addr.ip(), addr.port()).is_empty());
    }
}

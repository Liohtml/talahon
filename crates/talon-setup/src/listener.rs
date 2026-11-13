//! Who holds a listening TCP port?
//!
//! `talahon doctor` and `talahon setup environment` check that the LLM
//! gateway port is free. While the service runs it is not — Talahon itself
//! listens there — and that must not count as a problem. On Linux the
//! listening process is identified from `/proc` (the listening socket's
//! inode in `/proc/net/tcp{,6}`, the process whose `fd/` holds that socket,
//! and its `exe` link), without sending anything to the port. Elsewhere, or
//! when the process belongs to another user (its `fd/` is unreadable), the
//! owner is unknown and the caller keeps treating the port as taken.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::context::{BINARY_NAME, LEGACY_BINARY_NAME};

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

/// The pid of a Talahon host process listening on `ip:port`, if this user
/// can tell (see the module documentation).
pub fn talahon_listener(ip: IpAddr, port: u16) -> Option<u32> {
    listener_pids(ip, port).into_iter().find(|pid| {
        std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| is_talahon_exe(&exe))
    })
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

    #[cfg(target_os = "linux")]
    #[test]
    fn a_listener_of_this_process_is_found_but_is_not_talahon() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(listener_pids(addr.ip(), addr.port()).contains(&std::process::id()));
        // The test binary is not the host binary.
        assert_eq!(talahon_listener(addr.ip(), addr.port()), None);
        drop(listener);
        assert!(listener_pids(addr.ip(), addr.port()).is_empty());
    }
}

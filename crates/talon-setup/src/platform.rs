//! Platform detection. Everything here reads files or environment variables only — no
//! `unsafe` libc calls.

use std::path::{Path, PathBuf};

use talon_core::time::is_valid_timezone;

/// Host operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS (launchd).
    MacOs,
    /// Linux (systemd or nohup fallback).
    Linux,
    /// Anything else.
    Unknown,
}

impl Platform {
    /// The platform this binary runs on.
    pub fn current() -> Self {
        match std::env::consts::OS {
            "macos" => Platform::MacOs,
            "linux" => Platform::Linux,
            _ => Platform::Unknown,
        }
    }

    /// `macos` | `linux` | `unknown` (status-block value).
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::MacOs => "macos",
            Platform::Linux => "linux",
            Platform::Unknown => "unknown",
        }
    }
}

/// Service manager available for installing Talon as a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceManager {
    /// macOS launchd.
    Launchd,
    /// systemd (PID 1).
    Systemd,
    /// None — a nohup wrapper script is generated instead.
    None,
}

impl ServiceManager {
    /// `launchd` | `systemd` | `none`.
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceManager::Launchd => "launchd",
            ServiceManager::Systemd => "systemd",
            ServiceManager::None => "none",
        }
    }
}

/// Snapshot of the host platform facts setup decisions depend on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformInfo {
    /// OS family.
    pub platform: Platform,
    /// Running under Windows Subsystem for Linux.
    pub is_wsl: bool,
    /// No display server (Linux without `DISPLAY`/`WAYLAND_DISPLAY`).
    pub is_headless: bool,
    /// systemd is PID 1.
    pub has_systemd: bool,
    /// Effective uid, when it could be determined.
    pub uid: Option<u32>,
}

impl PlatformInfo {
    /// Detect the current host.
    pub fn detect() -> Self {
        let platform = Platform::current();
        let linux = platform == Platform::Linux;
        Self {
            platform,
            is_wsl: linux && is_wsl_from(Path::new("/proc/version")),
            is_headless: linux
                && std::env::var_os("DISPLAY").is_none()
                && std::env::var_os("WAYLAND_DISPLAY").is_none(),
            has_systemd: linux && has_systemd_from(Path::new("/proc/1/comm")),
            uid: current_uid(),
        }
    }

    /// Running as root (uid 0).
    pub fn is_root(&self) -> bool {
        self.uid == Some(0)
    }

    /// The service manager to use.
    pub fn service_manager(&self) -> ServiceManager {
        match self.platform {
            Platform::MacOs => ServiceManager::Launchd,
            Platform::Linux if self.has_systemd => ServiceManager::Systemd,
            _ => ServiceManager::None,
        }
    }
}

/// `/proc/version` mentions Microsoft / WSL.
pub fn is_wsl_from(proc_version: &Path) -> bool {
    std::fs::read_to_string(proc_version)
        .map(|s| {
            let s = s.to_lowercase();
            s.contains("microsoft") || s.contains("wsl")
        })
        .unwrap_or(false)
}

/// `/proc/1/comm` is `systemd`.
pub fn has_systemd_from(proc_1_comm: &Path) -> bool {
    std::fs::read_to_string(proc_1_comm)
        .map(|s| s.trim() == "systemd")
        .unwrap_or(false)
}

/// Effective uid from `/proc/self/status` (Linux) or `id -u` (elsewhere).
pub fn current_uid() -> Option<u32> {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        if let Some(uid) = parse_proc_status_euid(&status) {
            return Some(uid);
        }
    }
    let out = std::process::Command::new("id").arg("-u").output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// The effective uid (second field) of the `Uid:` line of
/// `/proc/<pid>/status`.
pub fn parse_proc_status_euid(status: &str) -> Option<u32> {
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    line.split_whitespace().nth(2)?.parse().ok()
}

/// `$HOME`, falling back to `/root`.
pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"))
}

/// Best-effort IANA timezone of the host: the `/etc/localtime` symlink
/// target (`.../zoneinfo/Europe/Berlin`), then `/etc/timezone`.
pub fn detect_system_timezone() -> Option<String> {
    timezone_from(Path::new("/etc/localtime"), Path::new("/etc/timezone"))
}

/// [`detect_system_timezone`] against explicit paths (tests).
pub fn timezone_from(localtime: &Path, timezone_file: &Path) -> Option<String> {
    if let Ok(target) = std::fs::read_link(localtime) {
        let target = target.to_string_lossy();
        if let Some(idx) = target.find("zoneinfo/") {
            let tz = &target[idx + "zoneinfo/".len()..];
            if is_valid_timezone(tz) {
                return Some(tz.to_string());
            }
        }
    }
    let content = std::fs::read_to_string(timezone_file).ok()?;
    let tz = content.trim();
    is_valid_timezone(tz).then(|| tz.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_platform_is_valid() {
        assert!(["macos", "linux", "unknown"].contains(&Platform::current().as_str()));
    }

    #[test]
    fn detect_is_consistent() {
        let info = PlatformInfo::detect();
        if info.platform == Platform::MacOs {
            assert_eq!(info.service_manager(), ServiceManager::Launchd);
        } else {
            assert!(matches!(
                info.service_manager(),
                ServiceManager::Systemd | ServiceManager::None
            ));
        }
        if info.platform == Platform::Linux {
            assert!(info.uid.is_some());
        }
    }

    #[test]
    fn wsl_detection_reads_proc_version() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("version");
        std::fs::write(&p, "Linux version 5.15.90.1-microsoft-standard-WSL2").unwrap();
        assert!(is_wsl_from(&p));
        std::fs::write(&p, "Linux version 6.8.0-generic").unwrap();
        assert!(!is_wsl_from(&p));
        assert!(!is_wsl_from(&dir.path().join("missing")));
    }

    #[test]
    fn systemd_detection_reads_comm() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("comm");
        std::fs::write(&p, "systemd\n").unwrap();
        assert!(has_systemd_from(&p));
        std::fs::write(&p, "init\n").unwrap();
        assert!(!has_systemd_from(&p));
    }

    #[test]
    fn parses_effective_uid() {
        let status = "Name:\tx\nUid:\t1000\t1001\t1000\t1000\nGid:\t5\n";
        assert_eq!(parse_proc_status_euid(status), Some(1001));
        assert_eq!(parse_proc_status_euid("Name: x"), None);
    }

    #[test]
    fn service_manager_mapping() {
        let mut info = PlatformInfo {
            platform: Platform::Linux,
            is_wsl: false,
            is_headless: true,
            has_systemd: true,
            uid: Some(1000),
        };
        assert_eq!(info.service_manager(), ServiceManager::Systemd);
        info.has_systemd = false;
        assert_eq!(info.service_manager(), ServiceManager::None);
        info.platform = Platform::MacOs;
        assert_eq!(info.service_manager(), ServiceManager::Launchd);
        assert!(!info.is_root());
        info.uid = Some(0);
        assert!(info.is_root());
    }

    #[test]
    fn timezone_detection() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("localtime");
        std::os::unix::fs::symlink("/usr/share/zoneinfo/Europe/Berlin", &link).unwrap();
        let tzfile = dir.path().join("timezone");
        assert_eq!(
            timezone_from(&link, &tzfile).as_deref(),
            Some("Europe/Berlin")
        );

        std::fs::write(&tzfile, "Asia/Tokyo\n").unwrap();
        let missing = dir.path().join("nope");
        assert_eq!(
            timezone_from(&missing, &tzfile).as_deref(),
            Some("Asia/Tokyo")
        );

        std::fs::write(&tzfile, "IST-2\n").unwrap();
        assert_eq!(timezone_from(&missing, &tzfile), None);
    }
}

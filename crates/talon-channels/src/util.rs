//! Small helpers shared by the channels: env access, backoff, clocks and
//! atomic state files.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rand::Rng;
use talon_core::env::EnvFile;

/// Read a secret: the `.env` file wins (secrets belong there), then the
/// process environment (the TypeScript release accepted both). Blank values
/// count as unset.
pub(crate) fn secret_value(env: &EnvFile, key: &str) -> Option<String> {
    env.file_value(key)
        .map(str::to_string)
        .or_else(|| env.get(key))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Read a non-secret setting: process environment first, then `.env`.
/// Blank values count as unset.
pub(crate) fn setting(env: &EnvFile, key: &str) -> Option<String> {
    env.get(key)
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Comma-separated list setting (blank entries dropped).
pub(crate) fn list_setting(env: &EnvFile, key: &str) -> Vec<String> {
    setting(env, key)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The project root the `.env` was loaded from, else the current directory
/// (the TypeScript release used `process.cwd()`).
pub(crate) fn project_root(env: &EnvFile) -> Option<PathBuf> {
    env.path()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
}

/// Exponential backoff with "equal jitter": the delay for `attempt`
/// (0-based) is `min(max, base * 2^attempt)`, of which the upper half is
/// randomized. Never returns more than `max`.
pub(crate) fn backoff_delay(attempt: u32, base: Duration, max: Duration) -> Duration {
    let factor = 1u32.checked_shl(attempt.min(20)).unwrap_or(u32::MAX);
    let capped = base.saturating_mul(factor).min(max);
    let half = capped / 2;
    let half_ms = u64::try_from(half.as_millis()).unwrap_or(u64::MAX);
    let jitter = if half_ms == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..=half_ms)
    };
    (half + Duration::from_millis(jitter)).min(max)
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Hands out strictly increasing millisecond values that track wall-clock
/// time. Two calls within the same millisecond get distinct values, so
/// `since`-style cursors and generated message ids never collide.
#[derive(Debug, Default)]
pub(crate) struct MonotonicMillis {
    last: Mutex<i64>,
}

impl MonotonicMillis {
    pub(crate) fn next(&self) -> i64 {
        let now = now_ms();
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        let value = if now > *last { now } else { *last + 1 };
        *last = value;
        value
    }
}

/// Write `bytes` to `path` atomically (`<path>.tmp` + rename), creating the
/// parent directory if needed.
pub(crate) async fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    tokio::fs::write(&tmp, bytes).await?;
    tokio::fs::rename(&tmp, path).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_capped_and_grows() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(2);
        for attempt in 0..40 {
            let d = backoff_delay(attempt, base, max);
            assert!(d <= max, "attempt {attempt}: {d:?}");
        }
        // attempt 0: between 50 and 100 ms
        let d0 = backoff_delay(0, base, max);
        assert!(d0 >= Duration::from_millis(50) && d0 <= Duration::from_millis(100));
        // attempt 3: between 400 and 800 ms
        let d3 = backoff_delay(3, base, max);
        assert!(d3 >= Duration::from_millis(400) && d3 <= Duration::from_millis(800));
        assert_eq!(backoff_delay(5, Duration::ZERO, max), Duration::ZERO);
    }

    #[test]
    fn monotonic_millis_strictly_increase() {
        let clock = MonotonicMillis::default();
        let mut prev = clock.next();
        for _ in 0..1000 {
            let v = clock.next();
            assert!(v > prev);
            prev = v;
        }
    }

    #[test]
    fn env_helpers() {
        let env = EnvFile::from_str_content(
            "TALON_CH_TEST_SECRET=  s3cret \nTALON_CH_TEST_LIST= a, ,b ,c\nTALON_CH_BLANK=\" \"\n",
        );
        assert_eq!(
            secret_value(&env, "TALON_CH_TEST_SECRET").as_deref(),
            Some("s3cret")
        );
        assert_eq!(secret_value(&env, "TALON_CH_BLANK"), None);
        assert_eq!(secret_value(&env, "TALON_CH_MISSING"), None);
        assert_eq!(
            list_setting(&env, "TALON_CH_TEST_LIST"),
            vec!["a", "b", "c"]
        );
        assert!(list_setting(&env, "TALON_CH_MISSING").is_empty());
    }

    #[tokio::test]
    async fn atomic_write_creates_parent_and_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("state.json");
        write_atomic(&path, b"one").await.unwrap();
        write_atomic(&path, b"two").await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
        assert!(!dir.path().join("nested").join("state.json.tmp").exists());
    }
}

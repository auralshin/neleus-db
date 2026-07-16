use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};

#[derive(Debug)]
pub struct FileLockGuard {
    path: PathBuf,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Acquire an advisory lock by exclusive-creating a marker file.
///
/// **Single-host only.** Stale-lock detection relies on `kill(pid, 0)` to
/// check liveness, which only works for processes on the same machine.
/// On NFS or any shared filesystem accessed by multiple hosts, a lock held
/// by a peer on another host will appear "stale" here because we cannot
/// signal it; this primitive is therefore unsafe for cross-host concurrency.
/// For cross-host coordination, use OS advisory locks (`flock` /
/// `LockFileEx`) — which are also released automatically on process death —
/// or an external lease service.
pub fn acquire_lock(path: impl AsRef<Path>, timeout: Duration) -> Result<FileLockGuard> {
    let path = path.as_ref().to_path_buf();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating lock parent {}", parent.display()))?;
    }

    let start = SystemTime::now();
    loop {
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(mut file) => {
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                let pid = std::process::id();
                writeln!(file, "pid={pid}")?;
                writeln!(file, "created_at={now}")?;
                // No fsync: the lock is ephemeral advisory state. Concurrent
                // acquirers are excluded by O_EXCL create (a metadata op the
                // filesystem orders without fsync), and crash recovery is
                // PID-liveness based, not content based. An fsync here costs
                // ~5-10ms per acquisition on macOS (F_FULLFSYNC) for nothing.
                return Ok(FileLockGuard { path });
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if lock_is_stale(&path, timeout)? {
                    let _ = fs::remove_file(&path);
                    continue;
                }
                let elapsed = start.elapsed().unwrap_or(Duration::from_secs(0));
                if elapsed >= timeout {
                    return Err(anyhow!(
                        "timed out acquiring lock {} after {:?}",
                        path.display(),
                        timeout
                    ));
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to acquire lock {}", path.display()));
            }
        }
    }
}

/// Exclusive advisory lock via flock(2): ~3 cheap syscalls per acquisition
/// (open, flock, close-on-drop) vs ~6 expensive metadata ops for the
/// marker-file scheme, and the kernel releases it on process death — no
/// stale-lock heuristics. Used on hot paths (ref mutation); the marker-file
/// `acquire_lock` stays for rare maintenance locks where a human-readable
/// owner PID is worth the cost.
#[cfg(unix)]
pub struct FlockGuard {
    file: std::fs::File,
}

#[cfg(unix)]
impl Drop for FlockGuard {
    fn drop(&mut self) {
        // SAFETY: fd is valid for the lifetime of `file`.
        unsafe {
            libc::flock(
                std::os::unix::io::AsRawFd::as_raw_fd(&self.file),
                libc::LOCK_UN,
            );
        }
    }
}

#[cfg(unix)]
pub fn flock_exclusive(path: impl AsRef<Path>, timeout: Duration) -> Result<FlockGuard> {
    use std::os::unix::io::AsRawFd;
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .with_context(|| format!("opening lock file {}", path.display()))?;

    let deadline = SystemTime::now() + timeout;
    loop {
        // SAFETY: fd is valid; LOCK_NB makes this non-blocking.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(FlockGuard { file });
        }
        if SystemTime::now() >= deadline {
            return Err(anyhow!(
                "timed out acquiring lock {} after {:?}",
                path.display(),
                timeout
            ));
        }
        thread::sleep(Duration::from_micros(200));
    }
}

fn lock_is_stale(path: &Path, timeout: Duration) -> Result<bool> {
    let metadata = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("failed to stat {}", path.display())),
    };

    if let Ok(contents) = fs::read_to_string(path)
        && let Some(pid) = parse_pid(&contents)
        && !process_is_alive(pid)
    {
        return Ok(true);
    }

    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::from_secs(0));
    Ok(age > timeout.saturating_mul(20))
}

fn parse_pid(contents: &str) -> Option<u32> {
    for line in contents.lines() {
        if let Some(v) = line.strip_prefix("pid=")
            && let Ok(pid) = v.trim().parse::<u32>()
        {
            return Some(pid);
        }
    }
    None
}

#[cfg(unix)]
pub(crate) fn process_is_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) does not send a signal; it only performs existence/permission checks.
    let rc = unsafe { libc::kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    errno == libc::EPERM
}

#[cfg(not(unix))]
pub(crate) fn process_is_alive(_pid: u32) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn acquire_release_lock() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("x.lock");
        {
            let _g = acquire_lock(&p, Duration::from_secs(1)).unwrap();
            assert!(p.exists());
        }
        assert!(!p.exists());
    }

    #[test]
    fn second_acquire_times_out() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("x.lock");
        let _g = acquire_lock(&p, Duration::from_secs(1)).unwrap();
        let err = acquire_lock(&p, Duration::from_millis(80)).unwrap_err();
        assert!(err.to_string().contains("timed out acquiring lock"));
    }

    #[test]
    fn stale_lock_is_recovered() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("x.lock");
        // Use i32::MAX as the dead PID. Linux's max PID is at most 2^22
        // (~4M) and macOS defaults are far lower, so this value cannot
        // collide with any real process.
        fs::write(&p, format!("pid={}\ncreated_at=1\n", i32::MAX)).unwrap();
        let _g = acquire_lock(&p, Duration::from_millis(80)).unwrap();
        assert!(p.exists());
    }
}

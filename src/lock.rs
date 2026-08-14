use std::fs::{self, OpenOptions};
use std::path::Path;
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};

/// Exclusive advisory lock via flock(2): ~3 cheap syscalls per acquisition
/// (open, flock, close-on-drop), and the kernel releases it on process death
/// *and* across a reboot.
///
/// This replaced a marker-file scheme that inferred staleness from the owner
/// PID and the file's age. Every variant of that heuristic loses one way or the
/// other: trusting a live PID wedges the database forever once PIDs are recycled
/// across a reboot, and falling back to age evicts a legitimately long-running
/// GC. The kernel already knows the answer, so ask it instead of guessing.
///
/// **Single-host only.** flock semantics over NFS are unreliable; for
/// cross-host coordination use an external lease service.
#[cfg(unix)]
#[derive(Debug)]
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
    fn flock_excludes_a_second_holder() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("x.lock");
        let g = flock_exclusive(&p, Duration::from_secs(1)).unwrap();
        let err = flock_exclusive(&p, Duration::from_millis(80)).unwrap_err();
        assert!(err.to_string().contains("timed out acquiring lock"));
        drop(g);
        // Released on drop, and re-acquirable even though the file persists.
        let _g2 = flock_exclusive(&p, Duration::from_secs(1)).unwrap();
        assert!(p.exists());
    }

    #[test]
    fn a_leftover_lock_file_never_blocks_acquisition() {
        // The regression this primitive exists to prevent: an abandoned lock
        // file must not wedge the database. There is no owner recorded and
        // nothing to go stale: an unlocked file is simply free.
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("x.lock");
        fs::write(&p, b"leftover from a crashed process\n").unwrap();
        let _g = flock_exclusive(&p, Duration::from_millis(80)).unwrap();
    }
}

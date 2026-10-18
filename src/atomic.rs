use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};

use crate::lock::process_is_alive;

/// Per-process counter for atomic-write temp file uniqueness. Combined with
/// pid + nanos in `{stem}.tmp-{pid}-{nanos}-{seq}`, this prevents collisions
/// between concurrent writers in the same process that share a wall-clock
/// nanosecond.
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Process-wide durability policy (config `durability`), applied per file and
/// per directory on every atomic write:
/// - full (default): flush to stable storage (`F_FULLFSYNC` on macOS), so a
///   write is power-loss durable before it is acknowledged.
/// - barrier: order writes without forcing them to storage (`F_BARRIERFSYNC`
///   on macOS, the class SQLite's WAL commit uses there); a power loss can drop
///   recent writes but not reorder them. Platforms without a barrier flush.
/// - os: no sync. Renames stay crash-of-process atomic, but a power loss can
///   drop or tear a just-acknowledged write.
///
/// Global because `write_atomic` has no config context; set at open. Defaults
/// to full so an unset config never silently trades away crash safety.
static DURABILITY: AtomicU8 = AtomicU8::new(Durability::Full as u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Durability {
    Os = 0,
    Barrier = 1,
    Full = 2,
}

pub fn set_durability(mode: Durability) {
    DURABILITY.store(mode as u8, Ordering::Relaxed);
}

fn sync(f: &File) -> std::io::Result<()> {
    // Unit tests cannot observe power loss; syncing would only slow them down.
    if cfg!(test) {
        return Ok(());
    }
    match DURABILITY.load(Ordering::Relaxed) {
        m if m == Durability::Full as u8 => f.sync_all(),
        m if m == Durability::Barrier as u8 => barrier(f),
        _ => Ok(()),
    }
}

#[cfg(target_os = "macos")]
fn barrier(f: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: the fd is valid for the lifetime of `f`.
    if unsafe { libc::fcntl(f.as_raw_fd(), libc::F_BARRIERFSYNC) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn barrier(f: &File) -> std::io::Result<()> {
    f.sync_all()
}

pub(crate) fn maybe_sync_file(f: &File) -> std::io::Result<()> {
    sync(f)
}

pub(crate) fn maybe_sync_dir(path: &Path) -> std::io::Result<()> {
    if cfg!(test) || DURABILITY.load(Ordering::Relaxed) == Durability::Os as u8 {
        return Ok(());
    }
    sync(&File::open(path)?)
}

/// Build a unique temp filename of the shape `.{stem}.tmp-{pid}-{nanos}-{seq}`.
pub(crate) fn build_temp_name(stem: &str) -> Result<String> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let pid = std::process::id();
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    Ok(format!(".{stem}.tmp-{pid}-{nanos}-{seq}"))
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow!(
            "cannot write atomic file without parent: {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed creating parent dir {}", parent.display()))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("invalid file name: {}", path.display()))?
        .to_string_lossy();

    let tmp_path = parent.join(build_temp_name(&file_name)?);

    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .with_context(|| format!("failed creating temp file {}", tmp_path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("failed writing temp file {}", tmp_path.display()))?;
    maybe_sync_file(&f)
        .with_context(|| format!("failed syncing temp file {}", tmp_path.display()))?;

    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed renaming temp file {} -> {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    maybe_sync_dir(parent)
        .with_context(|| format!("failed syncing parent dir {}", parent.display()))?;

    Ok(())
}

/// Parse a temp filename of the form `.{stem}.tmp-{pid}-{nanos}-{seq}` and
/// return the PID. Used by the orphan cleanup pass; returns `None` for
/// unrelated dotfiles or temp files we did not produce.
pub(crate) fn parse_temp_pid(name: &str) -> Option<u32> {
    let inner = name.strip_prefix('.')?;
    let idx = inner.find(".tmp-")?;
    let suffix = &inner[idx + ".tmp-".len()..];
    let parts: Vec<&str> = suffix.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let pid: u32 = parts[0].parse().ok()?;
    parts[1].parse::<u128>().ok()?;
    parts[2].parse::<u64>().ok()?;
    Some(pid)
}

/// Walk `root` (recursively if `recursive`) and remove `.{stem}.tmp-{pid}-{nanos}`
/// files whose PID is no longer alive. Returns the count of files removed.
///
/// Safe to call without holding a lock: every active writer has the current
/// process's PID in its temp filename and `process_is_alive` returns true for
/// any live PID we can signal. Files we don't recognize (no `.tmp-` infix) are
/// left untouched.
pub fn cleanup_orphan_temps(root: &Path, recursive: bool) -> Result<usize> {
    if !root.exists() {
        return Ok(0);
    }

    let mut removed = 0usize;
    let entries =
        fs::read_dir(root).with_context(|| format!("failed reading dir {}", root.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        // A concurrent peer's atomic write may rename a temp away between
        // `read_dir` and our `file_type` call. Treat NotFound as benign.
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(e).context(format!("failed stat'ing {}", path.display()));
            }
        };

        if file_type.is_dir() {
            if recursive {
                removed += cleanup_orphan_temps(&path, recursive)?;
            }
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(pid) = parse_temp_pid(name) else {
            continue;
        };

        if process_is_alive(pid) {
            continue;
        }

        match fs::remove_file(&path) {
            Ok(()) => removed += 1,
            // Another writer raced us; safe to ignore.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).context(format!("failed removing {}", path.display())),
        }
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn atomic_write_roundtrip() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("x.txt");
        write_atomic(&p, b"hello").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn atomic_write_overwrites_file() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("x.txt");
        write_atomic(&p, b"v1").unwrap();
        write_atomic(&p, b"v2").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"v2");
    }

    /// The current temp-file pattern is `.{stem}.tmp-{pid}-{nanos}-{seq}`. An
    /// orphan with this real shape must not corrupt the visible content.
    #[test]
    fn leftover_real_pattern_tmp_does_not_affect_data() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("x.txt");
        write_atomic(&p, b"stable").unwrap();

        let parent = p.parent().unwrap();
        let tmp = parent.join(".x.txt.tmp-1-2-3");
        fs::write(&tmp, b"partial").unwrap();

        assert_eq!(fs::read(&p).unwrap(), b"stable");
    }

    #[test]
    fn parse_temp_pid_recognizes_real_pattern() {
        assert_eq!(super::parse_temp_pid(".x.txt.tmp-42-123456-7"), Some(42));
        // Sharded CAS filenames (no dot in stem) work too.
        assert_eq!(super::parse_temp_pid(".abcdef.tmp-7-1-0"), Some(7));
        // Unrelated dotfiles are not touched.
        assert_eq!(super::parse_temp_pid(".DS_Store"), None);
        assert_eq!(super::parse_temp_pid("regular.txt"), None);
        assert_eq!(super::parse_temp_pid(".x.txt.tmp-notanum-1-0"), None);
        // Old 3-part shape (pre-seq) no longer matches — those orphans
        // would have been left from a previous neleus-db version; they
        // don't block writes and will eventually be cleaned by hand.
        assert_eq!(super::parse_temp_pid(".x.txt.tmp-42-123456"), None);
    }

    #[test]
    fn cleanup_orphan_temps_removes_only_dead_pid_temps() {
        let dir = TempDir::new().unwrap();
        write_atomic(&dir.path().join("real.txt"), b"x").unwrap();
        // Dead PID — should be removed.
        let dead = dir
            .path()
            .join(format!(".real.txt.tmp-{}-1-0", i32::MAX as u32));
        fs::write(&dead, b"orphan").unwrap();
        // Live PID (our own) — must be preserved.
        let live = dir
            .path()
            .join(format!(".real.txt.tmp-{}-2-0", std::process::id()));
        fs::write(&live, b"live").unwrap();
        // Unrelated dotfile — must be preserved.
        let unrelated = dir.path().join(".keep-this");
        fs::write(&unrelated, b"k").unwrap();

        let removed = super::cleanup_orphan_temps(dir.path(), false).unwrap();
        assert_eq!(removed, 1);
        assert!(!dead.exists());
        assert!(live.exists());
        assert!(unrelated.exists());
    }
}

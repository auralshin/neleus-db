use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};

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

    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let tmp_name = format!(".{file_name}.tmp-{}-{nanos}", std::process::id());
    let tmp_path = parent.join(tmp_name);

    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp_path)
        .with_context(|| format!("failed creating temp file {}", tmp_path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("failed writing temp file {}", tmp_path.display()))?;
    f.sync_all()
        .with_context(|| format!("failed syncing temp file {}", tmp_path.display()))?;

    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "failed renaming temp file {} -> {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    File::open(parent)
        .with_context(|| format!("failed opening parent dir {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed syncing parent dir {}", parent.display()))?;

    Ok(())
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

    #[test]
    fn leftover_tmp_does_not_affect_data() {
        let dir = TempDir::new().unwrap();
        let p = dir.path().join("x.txt");
        write_atomic(&p, b"stable").unwrap();

        let parent = p.parent().unwrap();
        let tmp = parent.join(".x.txt.tmp-crash");
        fs::write(&tmp, b"partial").unwrap();

        assert_eq!(fs::read(&p).unwrap(), b"stable");
    }
}

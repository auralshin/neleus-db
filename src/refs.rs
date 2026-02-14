use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::atomic::write_atomic;
use crate::hash::Hash;
use crate::lock::acquire_lock;
use crate::wal::{Wal, WalOp};

#[derive(Clone, Debug)]
pub struct RefsStore {
    root: PathBuf,
    wal: Wal,
}

impl RefsStore {
    pub fn new(root: impl Into<PathBuf>, wal: Wal) -> Self {
        Self {
            root: root.into(),
            wal,
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(self.heads_dir())?;
        fs::create_dir_all(self.states_dir())?;
        Ok(())
    }

    pub fn head_get(&self, name: &str) -> Result<Option<Hash>> {
        validate_ref_name(name)?;
        read_hash(self.head_path(name))
    }

    pub fn head_set(&self, name: &str, hash: Hash) -> Result<()> {
        validate_ref_name(name)?;
        self.ensure_dirs()?;

        let _lock = acquire_lock(self.root.join(".refs.lock"), Duration::from_secs(10))?;
        let entry = Wal::make_ref_entry(WalOp::RefHeadSet, name, hash);
        let wal_path = self.wal.begin_entry(&entry)?;

        write_atomic(&self.head_path(name), format!("{hash}\n").as_bytes())?;
        self.wal.end(&wal_path)?;
        Ok(())
    }

    pub fn state_get(&self, name: &str) -> Result<Option<Hash>> {
        validate_ref_name(name)?;
        read_hash(self.state_path(name))
    }

    pub fn state_set(&self, name: &str, hash: Hash) -> Result<()> {
        validate_ref_name(name)?;
        self.ensure_dirs()?;

        let _lock = acquire_lock(self.root.join(".refs.lock"), Duration::from_secs(10))?;
        let entry = Wal::make_ref_entry(WalOp::RefStateSet, name, hash);
        let wal_path = self.wal.begin_entry(&entry)?;

        write_atomic(&self.state_path(name), format!("{hash}\n").as_bytes())?;
        self.wal.end(&wal_path)?;
        Ok(())
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    fn heads_dir(&self) -> PathBuf {
        self.root.join("heads")
    }

    fn states_dir(&self) -> PathBuf {
        self.root.join("states")
    }

    fn head_path(&self, name: &str) -> PathBuf {
        self.heads_dir().join(name)
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.states_dir().join(name)
    }
}

pub fn head_get(store: &RefsStore, name: &str) -> Result<Option<Hash>> {
    store.head_get(name)
}

pub fn head_set(store: &RefsStore, name: &str, hash: Hash) -> Result<()> {
    store.head_set(name, hash)
}

fn read_hash(path: PathBuf) -> Result<Option<Hash>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed reading ref file {}", path.display()))?;
    let h = raw.trim().parse::<Hash>()?;
    Ok(Some(h))
}

fn validate_ref_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("reference name cannot be empty"));
    }
    if name.starts_with('/') || name.contains("..") || name.contains('\0') {
        return Err(anyhow!("unsafe reference name: {name}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::hash::hash_blob;

    fn store(tmp: &TempDir) -> RefsStore {
        let wal = Wal::new(tmp.path().join("wal"));
        RefsStore::new(tmp.path().join("refs"), wal)
    }

    #[test]
    fn head_set_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"x");
        s.head_set("main", h).unwrap();
        assert_eq!(s.head_get("main").unwrap(), Some(h));
    }

    #[test]
    fn head_get_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        assert_eq!(s.head_get("main").unwrap(), None);
    }

    #[test]
    fn state_set_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"state");
        s.state_set("main", h).unwrap();
        assert_eq!(s.state_get("main").unwrap(), Some(h));
    }

    #[test]
    fn invalid_ref_name_rejected() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"x");
        assert!(s.head_set("../bad", h).is_err());
    }

    #[test]
    fn free_functions_delegate() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"x");
        super::head_set(&s, "main", h).unwrap();
        assert_eq!(super::head_get(&s, "main").unwrap(), Some(h));
    }

    #[test]
    fn wal_cleanup_after_ref_set() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        s.head_set("main", hash_blob(b"x")).unwrap();
        let wal = Wal::new(tmp.path().join("wal"));
        assert!(wal.pending().unwrap().is_empty());
    }

    #[test]
    fn head_overwrite_works() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let a = hash_blob(b"a");
        let b = hash_blob(b"b");
        s.head_set("main", a).unwrap();
        s.head_set("main", b).unwrap();
        assert_eq!(s.head_get("main").unwrap(), Some(b));
    }

    #[test]
    fn state_ref_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        assert_eq!(s.state_get("dev").unwrap(), None);
    }
}

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};

use crate::atomic::write_atomic;
use crate::hash::Hash;

#[derive(Clone, Debug)]
pub struct CasStore {
    root: PathBuf,
}

impl CasStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path_for(&self, hash: Hash) -> PathBuf {
        let hex = hash.to_string();
        let shard1 = &hex[0..2];
        let shard2 = &hex[2..4];
        self.root.join(shard1).join(shard2).join(hex)
    }

    pub fn exists(&self, hash: Hash) -> bool {
        self.path_for(hash).exists()
    }

    pub fn put_existing_hash(&self, hash: Hash, bytes: &[u8]) -> Result<()> {
        let path = self.path_for(hash);
        if path.exists() {
            return Ok(());
        }
        write_atomic(&path, bytes)
            .with_context(|| format!("failed writing CAS object {}", path.display()))?;
        Ok(())
    }

    pub fn get(&self, hash: Hash) -> Result<Vec<u8>> {
        let path = self.path_for(hash);
        let bytes = fs::read(&path)
            .with_context(|| format!("missing CAS object {} ({})", hash, path.display()))?;
        Ok(bytes)
    }

    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("failed creating CAS root {}", self.root.display()))?;
        Ok(())
    }

    pub fn put_and_hash<F>(&self, bytes: &[u8], hash_fn: F) -> Result<Hash>
    where
        F: Fn(&[u8]) -> Hash,
    {
        let hash = hash_fn(bytes);
        self.put_existing_hash(hash, bytes)?;
        Ok(hash)
    }

    pub fn verify_hash<F>(&self, bytes: &[u8], hash: Hash, hash_fn: F) -> Result<()>
    where
        F: Fn(&[u8]) -> Hash,
    {
        let computed = hash_fn(bytes);
        if computed != hash {
            return Err(anyhow!(
                "hash mismatch: expected {}, computed {}",
                hash,
                computed
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::hash::hash_blob;

    #[test]
    fn cas_path_is_sharded() {
        let dir = TempDir::new().unwrap();
        let cas = CasStore::new(dir.path());
        let h = hash_blob(b"hello");
        let p = cas.path_for(h);
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(name, h.to_string());
        assert!(p.to_string_lossy().contains(&h.to_string()[0..2]));
        assert!(p.to_string_lossy().contains(&h.to_string()[2..4]));
    }

    #[test]
    fn cas_put_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let cas = CasStore::new(dir.path());
        cas.ensure_dir().unwrap();
        let h = cas.put_and_hash(b"abc", hash_blob).unwrap();
        assert_eq!(cas.get(h).unwrap(), b"abc");
    }

    #[test]
    fn cas_dedups_existing_hash() {
        let dir = TempDir::new().unwrap();
        let cas = CasStore::new(dir.path());
        cas.ensure_dir().unwrap();
        let h = hash_blob(b"abc");
        cas.put_existing_hash(h, b"abc").unwrap();
        cas.put_existing_hash(h, b"abc").unwrap();
        assert!(cas.exists(h));
    }

    #[test]
    fn cas_verify_hash_detects_mismatch() {
        let dir = TempDir::new().unwrap();
        let cas = CasStore::new(dir.path());
        let expected = hash_blob(b"a");
        assert!(cas.verify_hash(b"b", expected, hash_blob).is_err());
    }
}

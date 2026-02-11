use std::path::PathBuf;

use anyhow::{Result, anyhow};

use crate::cas::CasStore;
use crate::hash::{Hash, hash_blob};

#[derive(Clone, Debug)]
pub struct BlobStore {
    pub root: PathBuf,
    cas: CasStore,
    verify_on_read: bool,
}

impl BlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            root: root.clone(),
            cas: CasStore::new(root),
            verify_on_read: false,
        }
    }

    pub fn with_options(root: impl Into<PathBuf>, verify_on_read: bool) -> Self {
        let root = root.into();
        Self {
            root: root.clone(),
            cas: CasStore::new(root),
            verify_on_read,
        }
    }

    pub fn verify_on_read(&self) -> bool {
        self.verify_on_read
    }

    pub fn ensure_dir(&self) -> Result<()> {
        self.cas.ensure_dir()
    }

    pub fn put(&self, bytes: &[u8]) -> Result<Hash> {
        self.cas.put_and_hash(bytes, hash_blob)
    }

    pub fn get(&self, hash: Hash) -> Result<Vec<u8>> {
        let bytes = self.cas.get(hash)?;
        if self.verify_on_read {
            let computed = hash_blob(&bytes);
            if computed != hash {
                return Err(anyhow!(
                    "blob hash mismatch for {} (computed {})",
                    hash,
                    computed
                ));
            }
        }
        Ok(bytes)
    }

    pub fn exists(&self, hash: Hash) -> bool {
        self.cas.exists(hash)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn blob_put_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let bs = BlobStore::new(dir.path());
        bs.ensure_dir().unwrap();

        let h = bs.put(b"hello").unwrap();
        assert_eq!(bs.get(h).unwrap(), b"hello");
    }

    #[test]
    fn blob_dedup_same_hash() {
        let dir = TempDir::new().unwrap();
        let bs = BlobStore::new(dir.path());
        bs.ensure_dir().unwrap();

        let a = bs.put(b"same").unwrap();
        let b = bs.put(b"same").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn blob_exists_false_for_missing() {
        let dir = TempDir::new().unwrap();
        let bs = BlobStore::new(dir.path());
        bs.ensure_dir().unwrap();
        let h = bs.put(b"x").unwrap();
        assert!(bs.exists(h));
        assert!(!bs.exists(crate::hash::hash_blob(b"missing")));
    }

    #[test]
    fn blob_hash_differs_by_content() {
        let dir = TempDir::new().unwrap();
        let bs = BlobStore::new(dir.path());
        bs.ensure_dir().unwrap();

        let a = bs.put(b"a").unwrap();
        let b = bs.put(b"b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn blob_store_sharded_paths_created() {
        let dir = TempDir::new().unwrap();
        let bs = BlobStore::new(dir.path());
        bs.ensure_dir().unwrap();

        let h = bs.put(b"hello").unwrap();
        assert!(bs.exists(h));
    }

    #[test]
    fn verify_on_read_detects_tampering() {
        let dir = TempDir::new().unwrap();
        let bs = BlobStore::with_options(dir.path(), true);
        bs.ensure_dir().unwrap();

        let h = bs.put(b"stable").unwrap();
        let cas = CasStore::new(dir.path());
        let path = cas.path_for(h);
        fs::write(path, b"mutated").unwrap();
        assert!(bs.get(h).is_err());
    }
}

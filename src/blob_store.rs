use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};

use crate::cas::CasStore;
use crate::compression;
use crate::encryption::EncryptionRuntime;
use crate::hash::{Hash, hash_blob};

#[derive(Clone, Debug)]
pub struct BlobStore {
    pub root: PathBuf,
    cas: CasStore,
    verify_on_read: bool,
    compress: bool,
    encryption: Option<Arc<EncryptionRuntime>>,
}

impl BlobStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            root: root.clone(),
            cas: CasStore::new(root),
            verify_on_read: false,
            compress: false,
            encryption: None,
        }
    }

    pub fn with_options(root: impl Into<PathBuf>, verify_on_read: bool) -> Self {
        Self::with_runtime_options(root, verify_on_read, false, None)
    }

    pub fn with_runtime_options(
        root: impl Into<PathBuf>,
        verify_on_read: bool,
        compress: bool,
        encryption: Option<Arc<EncryptionRuntime>>,
    ) -> Self {
        let root = root.into();
        Self {
            root: root.clone(),
            cas: CasStore::new(root),
            verify_on_read,
            compress,
            encryption,
        }
    }

    pub fn verify_on_read(&self) -> bool {
        self.verify_on_read
    }

    pub fn compress(&self) -> bool {
        self.compress
    }

    pub fn ensure_dir(&self) -> Result<()> {
        self.cas.ensure_dir()
    }

    pub fn put(&self, bytes: &[u8]) -> Result<Hash> {
        // Hash is always over the original (uncompressed, unencrypted) bytes.
        let hash = hash_blob(bytes);
        let after_compress: Vec<u8> = if self.compress {
            compression::compress(bytes)?
        } else {
            bytes.to_vec()
        };
        let stored = match &self.encryption {
            Some(runtime) => runtime.encrypt(&after_compress)?,
            None => after_compress,
        };
        self.cas.put_existing_hash(hash, &stored)?;
        Ok(hash)
    }

    pub fn get(&self, hash: Hash) -> Result<Vec<u8>> {
        let raw = self.cas.get(hash)?;
        let after_decrypt = match &self.encryption {
            Some(runtime) => runtime.decrypt(&raw)?,
            None => raw,
        };
        // Always try-decompress; backward-compatible because uncompressed blobs
        // won't start with the zstd magic number.
        let bytes = compression::decompress_if_compressed(&after_decrypt)?;
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

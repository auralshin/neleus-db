use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{Result, anyhow};

use crate::cas::CasStore;
use crate::compression;
use crate::encryption::EncryptionRuntime;
use crate::hash::{Hash, hash_blob};

/// Read-cache byte budget. Immutable content-addressed blobs can't go stale;
/// overflow clears. Cached plaintext stays in process memory (same trust
/// boundary as the master key).
const BLOB_CACHE_BUDGET_BYTES: usize = 64 * 1024 * 1024;
/// Larger blobs bypass the cache to protect the working set.
const BLOB_CACHE_MAX_ENTRY: usize = 1024 * 1024;

#[derive(Debug, Default)]
struct BlobCache {
    map: HashMap<Hash, Arc<Vec<u8>>>,
    bytes: usize,
}

#[derive(Clone, Debug)]
pub struct BlobStore {
    pub root: PathBuf,
    cas: CasStore,
    verify_on_read: bool,
    compress: bool,
    encryption: Option<Arc<EncryptionRuntime>>,
    cache: Arc<RwLock<BlobCache>>,
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
            cache: Arc::new(RwLock::new(BlobCache::default())),
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
            cache: Arc::new(RwLock::new(BlobCache::default())),
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

    /// Bulk ingest: hash/compress/encrypt in parallel, then write once via
    /// the pack-first path (one pack + index above the CAS threshold instead
    /// of one loose file per blob).
    pub fn put_many(&self, blobs: Vec<Vec<u8>>) -> Result<Vec<Hash>> {
        let prepared = crate::par::parallel_map(blobs, |bytes| -> Result<(Hash, Vec<u8>)> {
            let hash = hash_blob(&bytes);
            let after_compress = if self.compress {
                compression::compress(&bytes)?
            } else {
                bytes
            };
            let stored = match &self.encryption {
                Some(runtime) => runtime.encrypt(&after_compress)?,
                None => after_compress,
            };
            Ok((hash, stored))
        });
        let mut items = Vec::with_capacity(prepared.len());
        let mut hashes = Vec::with_capacity(prepared.len());
        for p in prepared {
            let (hash, stored) = p?;
            hashes.push(hash);
            items.push((hash, stored));
        }
        self.cas.put_many(items)?;
        Ok(hashes)
    }

    pub fn get(&self, hash: Hash) -> Result<Vec<u8>> {
        Ok(self.get_arc(hash)?.as_ref().clone())
    }

    /// Cached read; first access pays disk + decrypt, rest are map lookups.
    pub fn get_arc(&self, hash: Hash) -> Result<Arc<Vec<u8>>> {
        if let Some(bytes) = self
            .cache
            .read()
            .expect("blob cache poisoned")
            .map
            .get(&hash)
        {
            return Ok(Arc::clone(bytes));
        }
        let raw = self.cas.get(hash)?;
        let after_decrypt = match &self.encryption {
            Some(runtime) => runtime.decrypt(&raw)?,
            None => raw,
        };
        // Always try-decompress; the helper returns a borrow when no
        // decompression was needed, so the uncompressed path pays no copy.
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
        let bytes = Arc::new(bytes.into_owned());
        if bytes.len() <= BLOB_CACHE_MAX_ENTRY {
            let mut cache = self.cache.write().expect("blob cache poisoned");
            if cache.bytes + bytes.len() > BLOB_CACHE_BUDGET_BYTES {
                cache.map.clear();
                cache.bytes = 0;
            }
            cache.bytes += bytes.len();
            cache.map.insert(hash, Arc::clone(&bytes));
        }
        Ok(bytes)
    }

    pub fn exists(&self, hash: Hash) -> bool {
        self.cas.exists(hash)
    }

    /// Authorized erasure (GDPR): evict the plaintext cache for these blobs and
    /// shred their stored bytes. `physical` zero-overwrites before unlink, but
    /// that is best-effort on COW filesystems and SSDs — crypto-shredding
    /// (encryption on) is the robust guarantee. See `CasStore::shred_many`.
    pub fn shred(&self, hashes: &[Hash], physical: bool) -> Result<()> {
        {
            let mut cache = self.cache.write().expect("blob cache poisoned");
            for h in hashes {
                if let Some(b) = cache.map.remove(h) {
                    cache.bytes = cache.bytes.saturating_sub(b.len());
                }
            }
        }
        self.cas.shred_many(hashes, physical)
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

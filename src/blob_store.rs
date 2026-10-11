use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use anyhow::{Result, anyhow};

use crate::cas::CasStore;
use crate::compression;
use crate::encryption::EncryptionRuntime;
use crate::hash::{Hash, Key, hash_blob};

/// Read-cache byte budget. Immutable content-addressed blobs can't go stale;
/// overflow clears. Cached plaintext stays in process memory (same trust
/// boundary as the master key).
const BLOB_CACHE_BUDGET_BYTES: usize = 64 * 1024 * 1024;
/// Larger blobs bypass the cache to protect the working set.
const BLOB_CACHE_MAX_ENTRY: usize = 1024 * 1024;
/// Stored payload is `salt || content`; the id hashes the whole payload.
pub const SALT_LEN: usize = 32;
const SALT_CONTEXT: &str = "neleus-db blob salt";

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
    secret: Key,
    /// Salt key of the scope this handle writes into (see [`Self::for_head`]).
    salt_key: Key,
}

impl BlobStore {
    /// Store keyed by an all-zero secret; for tests and tools without a database.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_options(root, false)
    }

    pub fn with_options(root: impl Into<PathBuf>, verify_on_read: bool) -> Self {
        Self::with_runtime_options(root, verify_on_read, false, None, Key([0; 32]))
    }

    pub fn with_runtime_options(
        root: impl Into<PathBuf>,
        verify_on_read: bool,
        compress: bool,
        encryption: Option<Arc<EncryptionRuntime>>,
        secret: Key,
    ) -> Self {
        let root = root.into();
        Self {
            root: root.clone(),
            cas: CasStore::new(root),
            verify_on_read,
            compress,
            encryption,
            cache: Arc::new(RwLock::new(BlobCache::default())),
            secret,
            salt_key: secret.derive(SALT_CONTEXT, b""),
        }
    }

    /// Handle that writes into `head`'s namespace (the part before the first
    /// `/`, e.g. a tenant). Identical content in two namespaces gets two ids,
    /// so one tenant cannot detect another's documents through dedup, and an
    /// id reveals nothing about short content without the database secret.
    pub fn for_head(&self, head: &str) -> Self {
        let scope = head.split_once('/').map_or("", |(s, _)| s);
        Self {
            salt_key: self.secret.derive(SALT_CONTEXT, scope.as_bytes()),
            ..self.clone()
        }
    }

    fn payload(&self, content: &[u8]) -> Vec<u8> {
        let salt = blake3::keyed_hash(&self.salt_key.0, content);
        let mut out = Vec::with_capacity(SALT_LEN + content.len());
        out.extend_from_slice(salt.as_bytes());
        out.extend_from_slice(content);
        out
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
        // Hash is over the salted payload, before compression and encryption.
        let payload = self.payload(bytes);
        let hash = hash_blob(&payload);
        let framed = compression::frame(&payload, self.compress)?;
        let stored = match &self.encryption {
            Some(runtime) => runtime.encrypt(&framed)?,
            None => framed,
        };
        self.cas.put_existing_hash(hash, &stored)?;
        Ok(hash)
    }

    /// Bulk ingest: hash/compress/encrypt in parallel, then write once via
    /// the pack-first path (one pack + index above the CAS threshold instead
    /// of one loose file per blob).
    pub fn put_many(&self, blobs: Vec<Vec<u8>>) -> Result<Vec<Hash>> {
        let prepared = crate::par::parallel_map(blobs, |bytes| -> Result<(Hash, Vec<u8>)> {
            let payload = self.payload(&bytes);
            let hash = hash_blob(&payload);
            let framed = compression::frame(&payload, self.compress)?;
            let stored = match &self.encryption {
                Some(runtime) => runtime.encrypt(&framed)?,
                None => framed,
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
        let payload = self.read_payload(hash, self.verify_on_read)?;
        let bytes = Arc::new(payload[SALT_LEN..].to_vec());
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

    /// Stored `salt || content`, verified against `hash`: what a proof must
    /// carry so a verifier can recompute the id.
    pub fn get_payload(&self, hash: Hash) -> Result<Vec<u8>> {
        self.read_payload(hash, true)
    }

    fn read_payload(&self, hash: Hash, verify: bool) -> Result<Vec<u8>> {
        let raw = self.cas.get(hash)?;
        let after_decrypt = match &self.encryption {
            Some(runtime) => runtime.decrypt(&raw)?,
            None => raw,
        };
        let payload = compression::unframe(&after_decrypt)?.into_owned();
        if payload.len() < SALT_LEN {
            return Err(anyhow!("blob {hash} is shorter than its salt"));
        }
        if verify {
            let computed = hash_blob(&payload);
            if computed != hash {
                return Err(anyhow!(
                    "blob hash mismatch for {} (computed {})",
                    hash,
                    computed
                ));
            }
        }
        Ok(payload)
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
    fn namespaces_get_distinct_ids_and_ids_hide_content() {
        let dir = TempDir::new().unwrap();
        let bs = BlobStore::new(dir.path());
        bs.ensure_dir().unwrap();
        let (acme, rival) = (bs.for_head("acme/kb"), bs.for_head("rival/kb"));

        let a = acme.put(b"patient 4471 tested positive").unwrap();
        let r = rival.put(b"patient 4471 tested positive").unwrap();
        // No cross-tenant dedup, so no dedup side channel; dedup stays within one.
        assert_ne!(a, r);
        assert_eq!(
            a,
            bs.for_head("acme/other")
                .put(b"patient 4471 tested positive")
                .unwrap()
        );
        assert_ne!(a, bs.put(b"patient 4471 tested positive").unwrap());
        // The id is not a hash of the content, so guessing content does not confirm it.
        assert_ne!(a, hash_blob(b"patient 4471 tested positive"));

        assert_eq!(bs.get(a).unwrap(), b"patient 4471 tested positive");
        let payload = bs.get_payload(a).unwrap();
        assert_eq!(hash_blob(&payload), a);
        assert_eq!(&payload[SALT_LEN..], b"patient 4471 tested positive");
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

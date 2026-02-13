use std::path::PathBuf;

use anyhow::{Result, anyhow};
use serde::{Serialize, de::DeserializeOwned};

use crate::canonical::{from_cbor, to_cbor};
use crate::cas::CasStore;
use crate::hash::{Hash, hash_typed};

#[derive(Clone, Debug)]
pub struct ObjectStore {
    cas: CasStore,
    verify_on_read: bool,
}

impl ObjectStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            cas: CasStore::new(root),
            verify_on_read: false,
        }
    }

    pub fn with_options(root: impl Into<PathBuf>, verify_on_read: bool) -> Self {
        Self {
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

    pub fn put_typed_bytes(&self, tag: &[u8], bytes: &[u8]) -> Result<Hash> {
        let hash = hash_typed(tag, bytes);
        self.cas.put_existing_hash(hash, bytes)?;
        Ok(hash)
    }

    pub fn get_bytes(&self, hash: Hash) -> Result<Vec<u8>> {
        self.cas.get(hash)
    }

    pub fn get_typed_bytes(&self, tag: &[u8], hash: Hash) -> Result<Vec<u8>> {
        let bytes = self.cas.get(hash)?;
        if self.verify_on_read {
            let computed = hash_typed(tag, &bytes);
            if computed != hash {
                return Err(anyhow!(
                    "object hash mismatch for {} (computed {})",
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

    pub fn put_serialized<T: Serialize>(&self, tag: &[u8], value: &T) -> Result<Hash> {
        let bytes = to_cbor(value)?;
        self.put_typed_bytes(tag, &bytes)
    }

    pub fn get_deserialized<T: DeserializeOwned>(&self, hash: Hash) -> Result<T> {
        let bytes = self.get_bytes(hash)?;
        from_cbor(&bytes)
    }

    pub fn get_deserialized_typed<T: DeserializeOwned>(&self, tag: &[u8], hash: Hash) -> Result<T> {
        let bytes = self.get_typed_bytes(tag, hash)?;
        from_cbor(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    use super::*;
    use crate::hash::hash_typed;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Obj {
        x: u32,
    }

    #[test]
    fn object_store_serialized_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::new(dir.path());
        store.ensure_dir().unwrap();

        let hash = store.put_serialized(b"manifest:", &Obj { x: 7 }).unwrap();
        let out: Obj = store.get_deserialized_typed(b"manifest:", hash).unwrap();
        assert_eq!(out.x, 7);
    }

    #[test]
    fn object_store_is_deterministic_for_same_object() {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::new(dir.path());
        store.ensure_dir().unwrap();

        let a = store.put_serialized(b"manifest:", &Obj { x: 1 }).unwrap();
        let b = store.put_serialized(b"manifest:", &Obj { x: 1 }).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn object_store_domain_separator_changes_hash() {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::new(dir.path());
        store.ensure_dir().unwrap();

        let bytes = crate::canonical::to_cbor(&Obj { x: 1 }).unwrap();
        let a = store.put_typed_bytes(b"manifest:", &bytes).unwrap();
        let b = store.put_typed_bytes(b"commit:", &bytes).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn typed_read_verification_detects_corruption() {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::with_options(dir.path(), true);
        store.ensure_dir().unwrap();

        let hash = store.put_serialized(b"manifest:", &Obj { x: 7 }).unwrap();

        let cas = CasStore::new(dir.path());
        let path = cas.path_for(hash);
        fs::write(path, b"tampered").unwrap();

        assert!(
            store
                .get_deserialized_typed::<Obj>(b"manifest:", hash)
                .is_err()
        );
    }

    #[test]
    fn typed_hash_matches_expected() {
        let dir = TempDir::new().unwrap();
        let store = ObjectStore::new(dir.path());
        store.ensure_dir().unwrap();

        let bytes = crate::canonical::to_cbor(&Obj { x: 9 }).unwrap();
        let expected = hash_typed(b"commit:", &bytes);
        let h = store.put_typed_bytes(b"commit:", &bytes).unwrap();
        assert_eq!(h, expected);
    }
}

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, anyhow};

use crate::atomic::{build_temp_name, maybe_sync_dir, maybe_sync_file};
use crate::hash::Hash;
use crate::packstore::PackSet;

/// Below this many new objects, loose files beat pack overhead.
const PACK_WRITE_THRESHOLD: usize = 1024;

#[derive(Clone, Debug)]
pub struct CasStore {
    root: PathBuf,
    /// Pack index, lazily loaded and shared across clones. Refreshed after
    /// this handle writes a pack (`put_many`); a repack by ANOTHER process is
    /// seen only by stores built after it (reopen the `Database`).
    packs: Arc<RwLock<Option<Arc<PackSet>>>>,
}

impl CasStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            packs: Arc::new(RwLock::new(None)),
        }
    }

    /// Pack index for this root, loaded on first use. A corrupt/incomplete pack
    /// degrades to an empty set; affected objects then read as "missing".
    fn packs(&self) -> Arc<PackSet> {
        if let Some(p) = self.packs.read().expect("pack cache poisoned").as_ref() {
            return Arc::clone(p);
        }
        let loaded = Arc::new(PackSet::load(&self.root).unwrap_or_default());
        let mut slot = self.packs.write().expect("pack cache poisoned");
        slot.get_or_insert_with(|| Arc::clone(&loaded));
        slot.as_ref().map(Arc::clone).unwrap_or(loaded)
    }

    fn refresh_packs(&self) {
        let loaded = Arc::new(PackSet::load(&self.root).unwrap_or_default());
        *self.packs.write().expect("pack cache poisoned") = Some(loaded);
    }

    /// Remove specific objects for authorized erasure (GDPR). Loose files are
    /// unlinked; packed objects are dropped by rewriting the packs without them.
    /// Deliberately deletes *reachable* content — the opposite of GC — so the
    /// caller must record a signed ErasureRecord.
    ///
    /// `physical` zero-overwrites a loose file before unlink, but this is
    /// best-effort: on copy-on-write filesystems (APFS, Btrfs, ZFS) and on SSDs
    /// (wear-leveling) the original blocks may persist until the FS/FTL reclaims
    /// them. The robust guarantee is crypto-shredding — run with encryption on
    /// so erasure drops the per-blob key, or place the DB on encrypted media.
    pub fn shred_many(&self, hashes: &[Hash], physical: bool) -> Result<()> {
        use std::collections::HashSet;
        let targets: HashSet<Hash> = hashes.iter().copied().collect();
        if targets.is_empty() {
            return Ok(());
        }
        for h in &targets {
            let path = self.path_for(*h);
            if path.exists() {
                if physical && let Ok(len) = fs::metadata(&path).map(|m| m.len()) {
                    let _ = fs::write(&path, vec![0u8; len as usize]);
                }
                fs::remove_file(&path).with_context(|| format!("shredding loose object {h}"))?;
            }
        }
        let packed: HashSet<Hash> = self.packs().hashes().into_iter().collect();
        if packed.intersection(&targets).next().is_some() {
            let live: HashSet<Hash> = packed.difference(&targets).copied().collect();
            crate::packstore::rewrite_packs_keeping(&self.root, &live)?;
            self.refresh_packs();
        }
        Ok(())
    }

    /// Bulk write: above [`PACK_WRITE_THRESHOLD`] new objects, append one
    /// pack + index (two files, sequential IO) instead of one loose file per
    /// object. The pack is visible to this handle immediately and to other
    /// handles opened afterwards — the same contract as `db repack`.
    pub fn put_many(&self, items: Vec<(Hash, Vec<u8>)>) -> Result<()> {
        let packs = self.packs();
        let mut fresh: Vec<(Hash, Vec<u8>)> = items
            .into_iter()
            .filter(|(h, _)| !packs.contains(*h) && !self.path_for(*h).exists())
            .collect();
        fresh.sort_by(|a, b| a.0.cmp(&b.0));
        fresh.dedup_by(|a, b| a.0 == b.0);
        if fresh.is_empty() {
            return Ok(());
        }
        if fresh.len() < PACK_WRITE_THRESHOLD {
            for (hash, bytes) in fresh {
                self.put_existing_hash(hash, &bytes)?;
            }
            return Ok(());
        }
        let pack_dir = self.root.join(crate::packstore::PACK_DIR);
        fs::create_dir_all(&pack_dir)?;
        let count = fresh.len();
        crate::packstore::write_pack(
            &pack_dir,
            count,
            fresh.into_iter().map(|(h, bytes)| (h, move || Ok(bytes))),
        )?;
        self.refresh_packs();
        Ok(())
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
        self.path_for(hash).exists() || self.packs().contains(hash)
    }

    /// Write `bytes` under `hash`, treating the store as a content-addressed
    /// set. Uses a write-temp + hard-link sequence so that concurrent writers
    /// of the same hash converge deterministically on the first writer's
    /// payload — even when the payload bytes differ (the case under
    /// encryption, where each writer produces a fresh ciphertext envelope for
    /// the same plaintext hash). Without this, `rename` would let the last
    /// writer overwrite, leaving non-deterministic ciphertext on disk.
    pub fn put_existing_hash(&self, hash: Hash, bytes: &[u8]) -> Result<()> {
        let path = self.path_for(hash);
        // Already loose or packed — don't write a redundant second copy.
        if path.exists() || self.packs().contains(hash) {
            return Ok(());
        }
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("invalid CAS path {}", path.display()))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating parent dir {}", parent.display()))?;

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("invalid CAS file name {}", path.display()))?;
        let tmp = parent.join(build_temp_name(file_name)?);

        {
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp)
                .with_context(|| format!("failed creating temp file {}", tmp.display()))?;
            f.write_all(bytes)
                .with_context(|| format!("failed writing temp file {}", tmp.display()))?;
            maybe_sync_file(&f)
                .with_context(|| format!("failed syncing temp file {}", tmp.display()))?;
        }

        let link_result = fs::hard_link(&tmp, &path);
        // The temp's link count is incremented when hard_link succeeds, so
        // removing it here is safe in both branches.
        let _ = fs::remove_file(&tmp);

        match link_result {
            Ok(()) => {
                maybe_sync_dir(parent)
                    .with_context(|| format!("failed syncing parent dir {}", parent.display()))?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // A peer won the race. Their bytes are durable and equally
                // valid for this content hash; we discard ours and return Ok.
                Ok(())
            }
            Err(e) => {
                Err(e).with_context(|| format!("failed linking CAS object {}", path.display()))
            }
        }
    }

    pub fn get(&self, hash: Hash) -> Result<Vec<u8>> {
        let path = self.path_for(hash);
        match fs::read(&path) {
            Ok(bytes) => Ok(bytes),
            // Loose miss: fall back to packs before declaring the object gone.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match self.packs().get(hash)? {
                Some(bytes) => Ok(bytes),
                None => Err(anyhow!("missing CAS object {} ({})", hash, path.display())),
            },
            Err(e) => {
                Err(e).with_context(|| format!("reading CAS object {} ({})", hash, path.display()))
            }
        }
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

    /// Regression for issue #4: concurrent writers for the same hash that
    /// supply *different* bytes (the case under encryption, where each writer
    /// produces a fresh ciphertext) must converge on one durable copy. The
    /// link-based dedup makes the first writer's bytes durable and silently
    /// discards the others; both calls return Ok.
    #[test]
    fn cas_concurrent_writers_with_different_bytes_converge() {
        use std::sync::Arc;
        use std::sync::Barrier;

        let dir = TempDir::new().unwrap();
        let cas = Arc::new(CasStore::new(dir.path()));
        cas.ensure_dir().unwrap();
        let target_hash = hash_blob(b"plaintext");

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let cas = Arc::clone(&cas);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                // Distinct payload per thread, all sharing `target_hash`.
                let payload = vec![i; 64];
                cas.put_existing_hash(target_hash, &payload).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert!(cas.exists(target_hash));
        let stored = cas.get(target_hash).unwrap();
        // Must match exactly one writer's input — never a mix.
        let matches_a_writer = (0..8u8).any(|i| stored == vec![i; 64]);
        assert!(
            matches_a_writer,
            "stored bytes don't match any writer's input"
        );
    }

    #[test]
    fn cas_concurrent_writers_leave_no_temp_files() {
        // After the 8-writer race above, no `.tmp-*` files should remain in
        // the shard directory — both the winner's link target and the losers'
        // discarded temps must be cleaned up.
        use std::sync::Arc;
        use std::sync::Barrier;

        let dir = TempDir::new().unwrap();
        let cas = Arc::new(CasStore::new(dir.path()));
        cas.ensure_dir().unwrap();
        let target_hash = hash_blob(b"plaintext-2");

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let cas = Arc::clone(&cas);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let _ = cas.put_existing_hash(target_hash, &[i; 32]);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let shard = cas.path_for(target_hash);
        let parent = shard.parent().unwrap();
        let leftovers: Vec<_> = fs::read_dir(parent)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|n| n.starts_with('.') && n.contains(".tmp-"))
                    .unwrap_or(false)
            })
            .map(|e| e.file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp file leaked after link race: {:?}",
            leftovers
        );
    }
}

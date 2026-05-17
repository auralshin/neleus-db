use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::io;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::atomic::{cleanup_orphan_temps, write_atomic};
use crate::blob_store::BlobStore;
use crate::commit::CommitStore;
use crate::encryption::{EncryptionConfig, EncryptionRuntime};
use crate::hash::Hash;
use crate::index::SearchIndexStore;
use crate::lock::acquire_lock;
use crate::manifest::ManifestStore;
use crate::object_store::ObjectStore;
use crate::refs::RefsStore;
use crate::state::StateStore;
use crate::wal::{Wal, WalRecoveryReport};

const DB_CONFIG_SCHEMA_VERSION: u32 = 3;
const DEFAULT_CAS_RETRIES: usize = 16;

#[derive(Debug, Clone)]
pub struct Database {
    pub root: PathBuf,
    pub blob_store: BlobStore,
    pub object_store: ObjectStore,
    pub manifest_store: ManifestStore,
    pub state_store: StateStore,
    pub commit_store: CommitStore,
    pub index_store: SearchIndexStore,
    pub refs: RefsStore,
    pub wal: Wal,
    pub config: Config,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub schema_version: u32,
    pub hashing: String,
    pub created_at: u64,
    pub verify_on_read: bool,
    #[serde(default)]
    pub compression: Option<String>,
    #[serde(default)]
    pub encryption: Option<EncryptionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyConfigV1 {
    version: u32,
    hashing: String,
    created_at: u64,
}

impl Database {
    pub fn init(path: impl AsRef<Path>) -> Result<()> {
        let root = path.as_ref();
        fs::create_dir_all(root).with_context(|| format!("failed creating {}", root.display()))?;
        fs::create_dir_all(root.join("blobs"))?;
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("refs").join("heads"))?;
        fs::create_dir_all(root.join("refs").join("states"))?;
        fs::create_dir_all(root.join("index"))?;
        fs::create_dir_all(root.join("wal"))?;
        fs::create_dir_all(root.join("meta"))?;

        let cfg_path = root.join("meta").join("config.json");
        if !cfg_path.exists() {
            let cfg = Config {
                schema_version: DB_CONFIG_SCHEMA_VERSION,
                hashing: "blake3".into(),
                created_at: now_unix(),
                verify_on_read: false,
                compression: None,
                encryption: None,
            };
            let bytes = serde_json::to_vec_pretty(&cfg)?;
            write_atomic(&cfg_path, &bytes)?;
        }

        let db = Self::open(root)?;
        let _ = db.state_store.empty_root()?;
        Ok(())
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref().to_path_buf();
        let cfg_path = root.join("meta").join("config.json");
        if !cfg_path.exists() {
            return Err(anyhow::anyhow!(
                "database not initialized at {}",
                root.display()
            ));
        }

        let _recovery_lock = acquire_lock(
            root.join("meta").join("recovery.lock"),
            Duration::from_secs(10),
        )?;

        let (mut config, mut migrated) = load_and_migrate_config(&cfg_path)?;
        // Lazily generate the master_salt for any encryption config that
        // pre-dates the master-key flow. Persisted before the runtime is
        // built so the very first encrypted write can decrypt on next open.
        if let Some(enc) = config.encryption.as_mut()
            && enc.enabled
            && crate::encryption::ensure_master_salt(enc)?
        {
            migrated = true;
        }
        if migrated {
            let bytes = serde_json::to_vec_pretty(&config)?;
            write_atomic(&cfg_path, &bytes)?;
        }

        let encryption = build_encryption_runtime(&config)?;
        let compress = config.compression.as_deref() == Some("zstd");
        let blob_store = BlobStore::with_runtime_options(
            root.join("blobs"),
            config.verify_on_read,
            compress,
            encryption.clone(),
        );
        let object_store = ObjectStore::with_runtime_options(
            root.join("objects"),
            config.verify_on_read,
            compress,
            encryption.clone(),
        );
        let wal = Wal::new(root.join("wal"));
        let refs = RefsStore::new(root.join("refs"), wal.clone());
        let state_store = StateStore::new(object_store.clone(), blob_store.clone(), wal.clone());
        let manifest_store = ManifestStore::new(object_store.clone());
        let commit_store = CommitStore::new(object_store.clone());
        let index_store =
            SearchIndexStore::with_encryption(root.join("index"), encryption.clone());

        blob_store.ensure_dir()?;
        object_store.ensure_dir()?;
        wal.ensure_dir()?;
        refs.ensure_dirs()?;
        index_store.ensure_dir()?;

        let _report: WalRecoveryReport = wal.recover_refs(refs.root())?;

        // Remove orphan atomic-write temp files left by dead processes.
        // Recursive under blobs/objects (sharded) and refs (`feature/foo`
        // namespaces create subdirectories). Live PIDs (peers writing now,
        // or our own) are skipped by `cleanup_orphan_temps`.
        let _ = cleanup_orphan_temps(&root.join("blobs"), true)?;
        let _ = cleanup_orphan_temps(&root.join("objects"), true)?;
        let _ = cleanup_orphan_temps(&root.join("refs").join("heads"), true)?;
        let _ = cleanup_orphan_temps(&root.join("refs").join("states"), true)?;
        let _ = cleanup_orphan_temps(&root.join("meta"), false)?;

        Ok(Self {
            root,
            blob_store,
            object_store,
            manifest_store,
            state_store,
            commit_store,
            index_store,
            refs,
            wal,
            config,
        })
    }

    pub fn resolve_state_root(&self, head: &str) -> Result<Hash> {
        if let Some(staged) = self.refs.state_get(head)? {
            return Ok(staged);
        }

        if let Some(commit_hash) = self.refs.head_get(head)? {
            let commit = self.commit_store.get_commit(commit_hash)?;
            return Ok(commit.state_root);
        }

        self.state_store.empty_root()
    }

    pub fn state_set_at_head(&self, head: &str, key: &[u8], value: &[u8]) -> Result<Hash> {
        self.apply_state_update_with_cas(head, |base_root| {
            self.state_store.set(base_root, key, value)
        })
    }

    pub fn state_del_at_head(&self, head: &str, key: &[u8]) -> Result<Hash> {
        self.apply_state_update_with_cas(head, |base_root| self.state_store.del(base_root, key))
    }

    pub fn state_compact_at_head(&self, head: &str) -> Result<Hash> {
        self.apply_state_update_with_cas(head, |base_root| self.state_store.compact(base_root))
    }

    pub fn state_set_many_at_head(&self, head: &str, pairs: &[(&[u8], &[u8])]) -> Result<Hash> {
        self.apply_state_update_with_cas(head, |base_root| {
            self.state_store.set_many(base_root, pairs)
        })
    }

    pub fn state_del_many_at_head(&self, head: &str, keys: &[&[u8]]) -> Result<Hash> {
        self.apply_state_update_with_cas(head, |base_root| {
            self.state_store.del_many(base_root, keys)
        })
    }

    pub fn create_commit_at_head(
        &self,
        head: &str,
        author: &str,
        message: &str,
        manifests: Vec<Hash>,
    ) -> Result<Hash> {
        for _ in 0..DEFAULT_CAS_RETRIES {
            let parent = self.refs.head_get(head)?;
            let parents = parent.into_iter().collect::<Vec<_>>();

            // Capture the staged state ref so we can detect a concurrent
            // staged write between this snapshot and the ref-sync CAS below.
            // Derive `state_root` from the same snapshot rather than calling
            // `resolve_state_root` (which would re-read the ref and could
            // observe a peer's write, producing a spurious mismatch later).
            let staged_before = self.refs.state_get(head)?;
            let state_root = match staged_before {
                Some(s) => s,
                None => match parent {
                    Some(commit_hash) => self.commit_store.get_commit(commit_hash)?.state_root,
                    None => self.state_store.empty_root()?,
                },
            };
            let candidate = self.commit_store.create_commit(
                parents,
                state_root,
                manifests.clone(),
                author.to_string(),
                message.to_string(),
            )?;

            if !self
                .refs
                .state_compare_and_set(head, staged_before, state_root)?
            {
                // Either a peer committed (advancing both head + state ref),
                // in which case we should retry against the new parent — or
                // someone staged work without committing, in which case
                // landing this commit would silently roll their work back.
                // Distinguish by re-reading the head: if it moved, retry;
                // otherwise fail loudly so the caller can react.
                let parent_now = self.refs.head_get(head)?;
                if parent_now != parent {
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "concurrent state advance on head '{}': staged state changed during commit; \
                     refusing to overwrite. Retry the commit against the updated state.",
                    head
                ));
            }

            if self.refs.head_compare_and_set(head, parent, candidate)? {
                return Ok(candidate);
            }
            // Head moved after we synced state. State ref now equals `state_root`,
            // so the next iteration's `staged_before` will be `Some(state_root)`
            // and the resolve will agree, making the next state CAS a no-op.
        }

        Err(anyhow::anyhow!(
            "concurrent update contention while creating commit for '{}'",
            head
        ))
    }

    pub fn ensure_index_ready(&self, commit: Hash) -> Result<()> {
        if self.index_store.read_index(commit).is_ok() {
            return Ok(());
        }

        let _ = self.index_store.build_for_head(
            commit,
            &self.commit_store,
            &self.manifest_store,
            &self.blob_store,
        )?;
        Ok(())
    }

    fn resolve_base_root_for_state_update(
        &self,
        head: &str,
        expected_state: Option<Hash>,
    ) -> Result<Hash> {
        if let Some(root) = expected_state {
            return Ok(root);
        }

        if let Some(commit_hash) = self.refs.head_get(head)? {
            let commit = self.commit_store.get_commit(commit_hash)?;
            return Ok(commit.state_root);
        }

        self.state_store.empty_root()
    }

    fn apply_state_update_with_cas<F>(&self, head: &str, mut op: F) -> Result<Hash>
    where
        F: FnMut(Hash) -> Result<Hash>,
    {
        for _ in 0..DEFAULT_CAS_RETRIES {
            let expected_state = self.refs.state_get(head)?;
            let base_root = self.resolve_base_root_for_state_update(head, expected_state)?;
            let new_root = op(base_root)?;
            if self
                .refs
                .state_compare_and_set(head, expected_state, new_root)?
            {
                return Ok(new_root);
            }
        }

        Err(anyhow::anyhow!(
            "concurrent state update contention on head '{}', retry command",
            head
        ))
    }

    /// Re-encrypt all blobs and objects with a new password.
    ///
    /// Holds an exclusive `meta/rotation.lock` while running, so a second
    /// rotation cannot race this one. Per file, decryption is attempted
    /// first with the OLD runtime: success → re-encrypt with the new. If
    /// old-key decrypt fails, the new runtime is tried; success means the
    /// file was already rotated in a previous interrupted run, so it's left
    /// alone. If both fail, the file is genuinely corrupt and the rotation
    /// aborts rather than silently skipping the failure.
    ///
    /// **Caller responsibility:** other `Database` handles opened before
    /// this call hold an `EncryptionRuntime` derived from the *old* master
    /// key. After rotation completes those handles can no longer decrypt
    /// anything on disk and must be dropped; reopen with the new password.
    /// File operations remain atomic during rotation, but cross-instance
    /// coherence is not provided.
    ///
    /// Returns the number of files re-encrypted under the new key (i.e.,
    /// excludes already-rotated files).
    pub fn rotate_encryption_key(&self, new_password: &str) -> Result<usize> {
        let enc_config = self
            .config
            .encryption
            .as_ref()
            .filter(|e| e.enabled)
            .ok_or_else(|| anyhow::anyhow!("encryption is not enabled; nothing to rotate"))?;

        if new_password.is_empty() {
            return Err(anyhow::anyhow!("new password cannot be empty"));
        }

        let old_runtime = self
            .encryption_runtime()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "rotate_encryption_key needs the current runtime; \
                     set NELEUS_DB_ENCRYPTION_PASSWORD"
                )
            })?;

        let new_runtime = Arc::new(EncryptionRuntime::from_config(
            enc_config.clone(),
            new_password.to_string(),
        )?);

        // Serialize concurrent rotations and block any reader that takes the
        // same lock. (Regular reads do not take this lock today, so this
        // primarily protects against two rotations racing.)
        let _rotation_lock = acquire_lock(
            self.root.join("meta").join("rotation.lock"),
            Duration::from_secs(30),
        )?;

        let mut count = 0usize;
        for dir in [self.root.join("blobs"), self.root.join("objects")] {
            count += reencrypt_cas_dir(&dir, &old_runtime, &new_runtime)?;
        }

        // Persist the config (algorithm/iterations unchanged; master_salt is
        // long-lived and must not be rotated together with the password —
        // otherwise old ciphertext on disk becomes unreadable).
        let cfg_path = self.root.join("meta").join("config.json");
        let bytes = serde_json::to_vec_pretty(&self.config)?;
        crate::atomic::write_atomic(&cfg_path, &bytes)?;

        Ok(count)
    }

    fn encryption_runtime(&self) -> Option<Arc<EncryptionRuntime>> {
        // Re-derive from stored config + env var (same as Database::open).
        let enc = self.config.encryption.as_ref().filter(|e| e.enabled)?;
        let password = std::env::var("NELEUS_DB_ENCRYPTION_PASSWORD").ok()?;
        EncryptionRuntime::from_config(enc.clone(), password)
            .ok()
            .map(Arc::new)
    }

}

pub fn init(path: impl AsRef<Path>) -> Result<()> {
    Database::init(path)
}

pub fn open(path: impl AsRef<Path>) -> Result<Database> {
    Database::open(path)
}

fn load_and_migrate_config(cfg_path: &Path) -> Result<(Config, bool)> {
    let raw = fs::read(cfg_path)
        .with_context(|| format!("failed to read config {}", cfg_path.display()))?;

    if let Ok(cfg) = serde_json::from_slice::<Config>(&raw) {
        return Ok((migrate_config(cfg), false));
    }

    let old = serde_json::from_slice::<LegacyConfigV1>(&raw)
        .with_context(|| format!("failed to parse config {}", cfg_path.display()))?;
    let migrated = Config {
        schema_version: DB_CONFIG_SCHEMA_VERSION,
        hashing: old.hashing,
        created_at: old.created_at,
        verify_on_read: false,
        compression: None,
        encryption: None,
    };
    Ok((migrate_config(migrated), true))
}

fn migrate_config(mut cfg: Config) -> Config {
    if cfg.schema_version < DB_CONFIG_SCHEMA_VERSION {
        cfg.schema_version = DB_CONFIG_SCHEMA_VERSION;
    }
    if cfg.hashing.is_empty() {
        cfg.hashing = "blake3".into();
    }
    cfg
}

fn build_encryption_runtime(config: &Config) -> Result<Option<Arc<EncryptionRuntime>>> {
    let Some(enc) = &config.encryption else {
        return Ok(None);
    };
    if !enc.enabled {
        return Ok(None);
    }

    let password = std::env::var("NELEUS_DB_ENCRYPTION_PASSWORD").with_context(
        || "encryption is enabled in config but NELEUS_DB_ENCRYPTION_PASSWORD is not set",
    )?;
    let runtime = EncryptionRuntime::from_config(enc.clone(), password)?;
    Ok(Some(Arc::new(runtime)))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift before epoch")
        .as_secs()
}

/// Walk a CAS directory recursively and re-encrypt every file from
/// `old_runtime` to `new_runtime`.
///
/// Decryption with the new runtime is tried as a fallback before declaring
/// failure, so files left in the new format by a previously-interrupted
/// rotation are recognized and left alone. A file that decrypts with
/// neither key is genuinely corrupt; the rotation aborts with an error
/// rather than silently masking it.
fn reencrypt_cas_dir(
    dir: &Path,
    old_runtime: &Arc<EncryptionRuntime>,
    new_runtime: &Arc<EncryptionRuntime>,
) -> Result<usize> {
    let mut count = 0usize;
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            count += reencrypt_cas_dir(&path, old_runtime, new_runtime)?;
            continue;
        }
        let is_content = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.len() == 64 && n.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false);
        if !is_content {
            continue;
        }

        let raw = fs::read(&path)?;

        let plaintext = match old_runtime.decrypt(&raw) {
            Ok(p) => p,
            Err(_) => {
                // Old key failed — was this file already rotated?
                if new_runtime.decrypt(&raw).is_ok() {
                    // Yes; leave it. Resumes a previously-interrupted run.
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "rotation aborted: {} decrypts with neither old nor new key (likely corrupted)",
                    path.display()
                ));
            }
        };

        let new_ciphertext = new_runtime.encrypt(&plaintext)?;
        crate::atomic::write_atomic(&path, &new_ciphertext)?;
        count += 1;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::hash::hash_blob;
    use crate::wal::{WalEntry, WalOp, WalPayload};

    #[test]
    fn init_creates_expected_layout() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();

        assert!(db_root.join("blobs").exists());
        assert!(db_root.join("objects").exists());
        assert!(db_root.join("refs").join("heads").exists());
        assert!(db_root.join("index").exists());
        assert!(db_root.join("wal").exists());
        assert!(db_root.join("meta").join("config.json").exists());
    }

    #[test]
    fn open_after_init_works() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();
        let db = Database::open(&db_root).unwrap();
        assert_eq!(db.root, db_root);
    }

    #[test]
    fn open_fails_without_init() {
        let tmp = TempDir::new().unwrap();
        assert!(Database::open(tmp.path()).is_err());
    }

    #[test]
    fn init_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();
        Database::init(&db_root).unwrap();
        assert!(db_root.join("meta").join("config.json").exists());
    }

    #[test]
    fn config_is_valid_json() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();

        let raw = fs::read(db_root.join("meta").join("config.json")).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["hashing"], "blake3");
        assert_eq!(v["schema_version"], DB_CONFIG_SCHEMA_VERSION);
    }

    #[test]
    fn interrupted_temp_write_does_not_corrupt_refs() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();

        let db = Database::open(&db_root).unwrap();
        let stable = hash_blob(b"stable-commit");
        db.refs.head_set("main", stable).unwrap();

        let tmp_ref = db_root
            .join("refs")
            .join("heads")
            .join(".main.tmp-crash-simulated");
        fs::write(&tmp_ref, format!("{}\n", hash_blob(b"partial-commit"))).unwrap();

        let reopened = Database::open(&db_root).unwrap();
        let head = reopened.refs.head_get("main").unwrap();
        assert_eq!(head, Some(stable));
    }

    #[test]
    fn migrates_legacy_config() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        fs::create_dir_all(db_root.join("meta")).unwrap();
        fs::create_dir_all(db_root.join("blobs")).unwrap();
        fs::create_dir_all(db_root.join("objects")).unwrap();
        fs::create_dir_all(db_root.join("refs").join("heads")).unwrap();
        fs::create_dir_all(db_root.join("refs").join("states")).unwrap();
        fs::create_dir_all(db_root.join("wal")).unwrap();

        let legacy = LegacyConfigV1 {
            version: 1,
            hashing: "blake3".into(),
            created_at: 1,
        };
        fs::write(
            db_root.join("meta/config.json"),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let db = Database::open(&db_root).unwrap();
        assert_eq!(db.config.schema_version, DB_CONFIG_SCHEMA_VERSION);
        assert!(!db.config.verify_on_read);
    }

    #[test]
    fn wal_recovery_replays_pending_ref_update() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();

        let wal = Wal::new(db_root.join("wal"));
        let hash = hash_blob(b"recovered-commit");
        let entry = WalEntry {
            schema_version: 1,
            op: WalOp::RefHeadSet,
            payload: WalPayload::RefUpdate {
                name: "main".into(),
                hash,
            },
        };
        let _p = wal.begin_entry(&entry).unwrap();

        let db = Database::open(&db_root).unwrap();
        assert_eq!(db.refs.head_get("main").unwrap(), Some(hash));
        assert!(db.wal.pending().unwrap().is_empty());
    }

    #[test]
    fn wal_recovery_rolls_back_bad_entries() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();

        fs::write(db_root.join("wal").join("bad.wal"), b"not-cbor").unwrap();
        let db = Database::open(&db_root).unwrap();
        assert!(db.wal.pending().unwrap().is_empty());
    }

    #[test]
    fn high_level_state_set_and_get_work() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();
        let db = Database::open(&db_root).unwrap();

        let root = db.state_set_at_head("main", b"k", b"v").unwrap();
        let read_root = db.resolve_state_root("main").unwrap();
        assert_eq!(root, read_root);
        assert_eq!(db.state_store.get(root, b"k").unwrap(), Some(b"v".to_vec()));
    }

    /// Regression for issue #4: orphan temp files under a nested ref
    /// namespace (e.g. `refs/heads/feature/`) must be cleaned up by
    /// `Database::open`. Previously the walk under refs/ wasn't recursive,
    /// so disk leaked once `feature/foo`-style names were allowed.
    #[test]
    fn open_cleans_orphan_temp_under_nested_ref_namespace() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();

        let nested_dir = db_root.join("refs").join("heads").join("feature");
        fs::create_dir_all(&nested_dir).unwrap();
        let orphan = nested_dir.join(format!(".foo.tmp-{}-1-0", i32::MAX as u32));
        fs::write(&orphan, b"partial").unwrap();
        assert!(orphan.exists());

        let _db = Database::open(&db_root).unwrap();
        assert!(!orphan.exists(), "nested orphan temp survived open");
    }

    #[test]
    fn high_level_commit_updates_head() {
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();
        let db = Database::open(&db_root).unwrap();

        let _ = db.state_set_at_head("main", b"k", b"v").unwrap();
        let commit = db
            .create_commit_at_head("main", "agent", "m1", vec![])
            .unwrap();
        assert_eq!(db.refs.head_get("main").unwrap(), Some(commit));
    }

    #[test]
    fn commit_preserves_latest_staged_state_sequential() {
        // Baseline: after staging v1 then v2, a commit must capture v2 — never
        // a previously-observed staged value.
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();
        let db = Database::open(&db_root).unwrap();

        let s1 = db.state_set_at_head("main", b"k", b"v1").unwrap();
        let s2 = db.state_set_at_head("main", b"k", b"v2").unwrap();
        assert_ne!(s1, s2);

        let commit = db
            .create_commit_at_head("main", "agent", "m", vec![])
            .unwrap();

        assert_eq!(db.refs.state_get("main").unwrap(), Some(s2));
        let c = db.commit_store.get_commit(commit).unwrap();
        assert_eq!(c.state_root, s2);
        assert_eq!(
            db.state_store.get(c.state_root, b"k").unwrap(),
            Some(b"v2".to_vec())
        );
    }

    #[test]
    fn concurrent_staged_writes_never_silently_rolled_back() {
        // Regression for issue #2: a commit must not silently roll back staged
        // state. We run a writer that monotonically increases the stored value
        // and a committer that races against it, while a watcher samples the
        // state ref and flags any backwards movement. With the bug, the commit
        // path would CAS the state ref to a stale value, which the watcher
        // would observe as a decrease.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        Database::init(&db_root).unwrap();
        let db = Arc::new(Database::open(&db_root).unwrap());

        let _ = db.state_set_at_head("main", b"k", b"0").unwrap();
        let _ = db
            .create_commit_at_head("main", "init", "init", vec![])
            .unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let writer_db = Arc::clone(&db);
        let writer_stop = Arc::clone(&stop);
        let writer = std::thread::spawn(move || {
            for i in 1..=150u32 {
                if writer_stop.load(Ordering::Relaxed) {
                    break;
                }
                let v = i.to_string();
                let _ = writer_db.state_set_at_head("main", b"k", v.as_bytes());
            }
        });

        let watcher_db = Arc::clone(&db);
        let watcher_stop = Arc::clone(&stop);
        let watcher = std::thread::spawn(move || {
            let mut last_seen: Option<u32> = None;
            let mut violations: Vec<(u32, u32)> = Vec::new();
            while !watcher_stop.load(Ordering::Relaxed) {
                let n = match watcher_db.refs.state_get("main") {
                    Ok(Some(root)) => match watcher_db.state_store.get(root, b"k") {
                        Ok(Some(val)) => std::str::from_utf8(&val)
                            .ok()
                            .and_then(|s| s.parse::<u32>().ok()),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(n) = n {
                    if let Some(prev) = last_seen
                        && n < prev
                    {
                        violations.push((prev, n));
                    }
                    last_seen = Some(n);
                }
            }
            violations
        });

        for _ in 0..150 {
            let _ = db.create_commit_at_head("main", "agent", "m", vec![]);
        }
        stop.store(true, Ordering::Relaxed);
        writer.join().unwrap();
        let violations = watcher.join().unwrap();

        assert!(
            violations.is_empty(),
            "state ref moved backwards (rollback bug): {:?}",
            violations
        );
    }

    // ---------- Issue #3: encryption rebuild ----------

    /// Serialize encryption tests that touch the global
    /// `NELEUS_DB_ENCRYPTION_PASSWORD` env var. Cargo runs tests in parallel
    /// by default and `std::env::set_var` is process-global.
    fn encryption_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static M: std::sync::Mutex<()> = std::sync::Mutex::new(());
        M.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Build an encrypted DB from scratch: write an encryption-enabled config
    /// *before* the first open, so every object the DB writes (including the
    /// empty state root materialized by init) is encrypted under `password`.
    /// Returns the open Database; caller holds the encryption_test_lock for
    /// the duration.
    fn init_encrypted_db(path: &Path, password: &str) -> Database {
        use crate::encryption::EncryptionConfig;

        fs::create_dir_all(path.join("blobs")).unwrap();
        fs::create_dir_all(path.join("objects")).unwrap();
        fs::create_dir_all(path.join("refs").join("heads")).unwrap();
        fs::create_dir_all(path.join("refs").join("states")).unwrap();
        fs::create_dir_all(path.join("index")).unwrap();
        fs::create_dir_all(path.join("wal")).unwrap();
        fs::create_dir_all(path.join("meta")).unwrap();

        let cfg = Config {
            schema_version: DB_CONFIG_SCHEMA_VERSION,
            hashing: "blake3".into(),
            created_at: 0,
            verify_on_read: false,
            compression: None,
            encryption: Some(EncryptionConfig {
                enabled: true,
                algorithm: "aes-256-gcm".into(),
                ..EncryptionConfig::default()
            }),
        };
        write_atomic(
            &path.join("meta").join("config.json"),
            &serde_json::to_vec_pretty(&cfg).unwrap(),
        )
        .unwrap();
        // SAFETY: parallel tests touching this env var are serialized via
        // `encryption_test_lock`.
        unsafe { std::env::set_var("NELEUS_DB_ENCRYPTION_PASSWORD", password) };
        let db = Database::open(path).unwrap();
        // Materialize the empty state root under encryption.
        let _ = db.state_store.empty_root().unwrap();
        db
    }

    /// Issue #3: search index file must not contain plaintext chunk text
    /// when encryption is enabled. Previously the index was written via raw
    /// `write_atomic`, bypassing the encryption layer.
    #[test]
    fn search_index_is_encrypted_on_disk_when_encryption_enabled() {
        use crate::manifest::{ChunkingSpec, DocManifest};

        let _guard = encryption_test_lock();
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        let db = init_encrypted_db(&db_root, "index-test-password");

        // Add a doc manifest with distinctive plaintext.
        let needle = b"SECRET-NEEDLE-XYZZY-PLAINTEXT-CHUNK";
        let chunk_hash = db.blob_store.put(needle).unwrap();
        let original_hash = db.blob_store.put(needle).unwrap();
        let doc = DocManifest {
            schema_version: 1,
            source: "test".into(),
            created_at: 0,
            chunking: ChunkingSpec {
                method: "fixed".into(),
                chunk_size: needle.len(),
                overlap: 0,
            },
            chunks: vec![chunk_hash],
            original: original_hash,
        };
        let manifest_hash = db.manifest_store.put_manifest(&doc).unwrap();

        let _ = db.state_set_at_head("main", b"seed", b"v").unwrap();
        let commit = db
            .create_commit_at_head("main", "agent", "m", vec![manifest_hash])
            .unwrap();
        db.ensure_index_ready(commit).unwrap();

        let path = db_root
            .join("index")
            .join(commit.to_string())
            .join("search_index.json");
        let raw = fs::read(&path).unwrap();
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle),
            "plaintext chunk text leaked into on-disk search index"
        );

        // Reads through the store still succeed.
        let parsed = db.index_store.read_index(commit).unwrap();
        assert!(parsed.chunks.iter().any(|c| c.chunk_hash == chunk_hash));
    }

    /// Issue #3: rotation must read what it wrote — pre-rotation blobs are
    /// decryptable with the new password after a successful rotation.
    #[test]
    fn rotate_encryption_key_preserves_round_trip() {
        let _guard = encryption_test_lock();
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        let db = init_encrypted_db(&db_root, "old-password");

        let h = db.blob_store.put(b"secret-payload").unwrap();
        assert_eq!(db.blob_store.get(h).unwrap(), b"secret-payload");

        let rotated = db.rotate_encryption_key("new-strong-password").unwrap();
        assert!(rotated > 0, "expected at least one file rotated");

        // Reopen with the new password.
        drop(db);
        // SAFETY: serialized via `encryption_test_lock`.
        unsafe {
            std::env::set_var("NELEUS_DB_ENCRYPTION_PASSWORD", "new-strong-password")
        };
        let db = Database::open(&db_root).unwrap();
        assert_eq!(db.blob_store.get(h).unwrap(), b"secret-payload");
    }

    /// Issue #3: rotation must fail loudly on a genuinely-corrupted file
    /// rather than silently skip it.
    #[test]
    fn rotate_encryption_key_aborts_on_corruption() {
        use crate::cas::CasStore;

        let _guard = encryption_test_lock();
        let tmp = TempDir::new().unwrap();
        let db_root = tmp.path().join("neleus_db");
        let db = init_encrypted_db(&db_root, "old-password");

        let h = db.blob_store.put(b"victim").unwrap();
        let blob_path = CasStore::new(db_root.join("blobs")).path_for(h);

        // Overwrite the on-disk ciphertext with garbage that decrypts with
        // neither old nor new key.
        fs::write(&blob_path, b"this is not a valid envelope").unwrap();

        let err = db.rotate_encryption_key("new-password").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("rotation aborted"),
            "expected rotation-abort error, got: {msg}"
        );
    }
}

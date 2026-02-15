use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;
use crate::blob_store::BlobStore;
use crate::commit::CommitStore;
use crate::index::SearchIndexStore;
use crate::lock::acquire_lock;
use crate::manifest::ManifestStore;
use crate::object_store::ObjectStore;
use crate::refs::RefsStore;
use crate::state::StateStore;
use crate::wal::{Wal, WalRecoveryReport};

const DB_CONFIG_SCHEMA_VERSION: u32 = 2;

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

        let (config, migrated) = load_and_migrate_config(&cfg_path)?;
        if migrated {
            let bytes = serde_json::to_vec_pretty(&config)?;
            write_atomic(&cfg_path, &bytes)?;
        }

        let blob_store = BlobStore::with_options(root.join("blobs"), config.verify_on_read);
        let object_store = ObjectStore::with_options(root.join("objects"), config.verify_on_read);
        let wal = Wal::new(root.join("wal"));
        let refs = RefsStore::new(root.join("refs"), wal.clone());
        let state_store = StateStore::new(object_store.clone(), blob_store.clone(), wal.clone());
        let manifest_store = ManifestStore::new(object_store.clone());
        let commit_store = CommitStore::new(object_store.clone());
        let index_store = SearchIndexStore::new(root.join("index"));

        blob_store.ensure_dir()?;
        object_store.ensure_dir()?;
        wal.ensure_dir()?;
        refs.ensure_dirs()?;
        index_store.ensure_dir()?;

        let _report: WalRecoveryReport = wal.recover_refs(refs.root())?;

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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift before epoch")
        .as_secs()
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
}

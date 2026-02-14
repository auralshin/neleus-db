use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::canonical::to_cbor;
use crate::hash::{Hash, hash_typed};
use crate::object_store::ObjectStore;
use crate::state::StateRoot;

const COMMIT_TAG: &[u8] = b"commit:";
const COMMIT_PAYLOAD_TAG: &[u8] = b"commit_payload:";
const COMMIT_SCHEMA_VERSION: u32 = 1;

pub type CommitHash = Hash;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitSignature {
    pub scheme: String,
    pub key_id: Option<String>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    #[serde(default = "default_commit_schema_version")]
    pub schema_version: u32,
    pub parents: Vec<CommitHash>,
    pub timestamp: u64,
    pub author: String,
    pub message: String,
    pub state_root: StateRoot,
    pub manifests: Vec<Hash>,
    #[serde(default)]
    pub signature: Option<CommitSignature>,
}

pub trait CommitVerifier {
    fn verify(&self, commit_hash: CommitHash, commit: &Commit) -> Result<()>;
}

pub trait CommitSigner {
    fn sign(&self, payload_hash: Hash, commit: &Commit) -> Result<CommitSignature>;
}

#[derive(Clone, Debug)]
pub struct CommitStore {
    objects: ObjectStore,
}

impl CommitStore {
    pub fn new(objects: ObjectStore) -> Self {
        Self { objects }
    }

    pub fn create_commit(
        &self,
        parents: Vec<CommitHash>,
        state_root: StateRoot,
        manifests: Vec<Hash>,
        author: String,
        message: String,
    ) -> Result<CommitHash> {
        let commit = Commit {
            schema_version: COMMIT_SCHEMA_VERSION,
            parents,
            timestamp: now_unix(),
            author,
            message,
            state_root,
            manifests,
            signature: None,
        };
        self.objects.put_serialized(COMMIT_TAG, &commit)
    }

    pub fn create_signed_commit<S: CommitSigner>(
        &self,
        signer: &S,
        parents: Vec<CommitHash>,
        state_root: StateRoot,
        manifests: Vec<Hash>,
        author: String,
        message: String,
    ) -> Result<CommitHash> {
        let unsigned = Commit {
            schema_version: COMMIT_SCHEMA_VERSION,
            parents,
            timestamp: now_unix(),
            author,
            message,
            state_root,
            manifests,
            signature: None,
        };
        let payload_hash = hash_typed(COMMIT_PAYLOAD_TAG, &to_cbor(&unsigned)?);
        let signature = signer.sign(payload_hash, &unsigned)?;

        let signed = Commit {
            signature: Some(signature),
            ..unsigned
        };
        self.objects.put_serialized(COMMIT_TAG, &signed)
    }

    pub fn get_commit(&self, hash: CommitHash) -> Result<Commit> {
        let mut commit: Commit = self.objects.get_deserialized_typed(COMMIT_TAG, hash)?;
        migrate_commit_in_place(&mut commit);
        Ok(commit)
    }

    pub fn verify_commit_with<V: CommitVerifier>(
        &self,
        hash: CommitHash,
        verifier: &V,
    ) -> Result<()> {
        let commit = self.get_commit(hash)?;
        verifier.verify(hash, &commit)
    }
}

pub fn create_commit(
    store: &CommitStore,
    parents: Vec<CommitHash>,
    state_root: StateRoot,
    manifests: Vec<Hash>,
    author: String,
    message: String,
) -> Result<CommitHash> {
    store.create_commit(parents, state_root, manifests, author, message)
}

pub fn get_commit(store: &CommitStore, hash: CommitHash) -> Result<Commit> {
    store.get_commit(hash)
}

fn default_commit_schema_version() -> u32 {
    COMMIT_SCHEMA_VERSION
}

fn migrate_commit_in_place(commit: &mut Commit) {
    if commit.schema_version == 0 {
        commit.schema_version = COMMIT_SCHEMA_VERSION;
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock drift before epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::blob_store::BlobStore;
    use crate::object_store::ObjectStore;
    use crate::state::StateStore;
    use crate::wal::Wal;

    fn stores(tmp: &TempDir) -> (CommitStore, StateStore, BlobStore) {
        let objects = ObjectStore::new(tmp.path().join("objects"));
        objects.ensure_dir().unwrap();
        let commit_store = CommitStore::new(objects.clone());

        let blobs = BlobStore::new(tmp.path().join("blobs"));
        blobs.ensure_dir().unwrap();

        let state = StateStore::new(objects, blobs.clone(), Wal::new(tmp.path().join("wal")));
        (commit_store, state, blobs)
    }

    #[test]
    fn commit_create_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let h = cs
            .create_commit(vec![], root, vec![], "agent".into(), "msg".into())
            .unwrap();
        let c = cs.get_commit(h).unwrap();
        assert_eq!(c.author, "agent");
        assert_eq!(c.message, "msg");
        assert_eq!(c.schema_version, COMMIT_SCHEMA_VERSION);
    }

    #[test]
    fn commit_hash_changes_with_message() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let a = cs
            .create_commit(vec![], root, vec![], "a".into(), "m1".into())
            .unwrap();
        let b = cs
            .create_commit(vec![], root, vec![], "a".into(), "m2".into())
            .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn commit_parent_reference_preserved() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let p = cs
            .create_commit(vec![], root, vec![], "a".into(), "p".into())
            .unwrap();
        let c = cs
            .create_commit(vec![p], root, vec![], "a".into(), "c".into())
            .unwrap();
        let out = cs.get_commit(c).unwrap();
        assert_eq!(out.parents, vec![p]);
    }

    #[test]
    fn commit_can_reference_manifests() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, blobs) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let manifest_hash = blobs.put(b"manifest ref").unwrap();
        let c = cs
            .create_commit(
                vec![],
                root,
                vec![manifest_hash],
                "agent".into(),
                "with manifest".into(),
            )
            .unwrap();
        let out = cs.get_commit(c).unwrap();
        assert_eq!(out.manifests, vec![manifest_hash]);
    }

    #[test]
    fn commit_timestamp_nonzero() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let h = cs
            .create_commit(vec![], root, vec![], "agent".into(), "msg".into())
            .unwrap();
        let c = cs.get_commit(h).unwrap();
        assert!(c.timestamp > 0);
    }

    #[test]
    fn commit_free_functions_work() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();

        let h = super::create_commit(&cs, vec![], root, vec![], "a".into(), "m".into()).unwrap();
        let c = super::get_commit(&cs, h).unwrap();
        assert_eq!(c.message, "m");
    }

    struct DummySigner;

    impl CommitSigner for DummySigner {
        fn sign(&self, payload_hash: Hash, _commit: &Commit) -> Result<CommitSignature> {
            Ok(CommitSignature {
                scheme: "dummy".into(),
                key_id: Some("k1".into()),
                signature: payload_hash.as_bytes().to_vec(),
            })
        }
    }

    struct DummyVerifier;

    impl CommitVerifier for DummyVerifier {
        fn verify(&self, _hash: CommitHash, commit: &Commit) -> Result<()> {
            if commit.signature.is_some() {
                Ok(())
            } else {
                Err(anyhow::anyhow!("missing signature"))
            }
        }
    }

    #[test]
    fn signed_commit_hook_works() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let h = cs
            .create_signed_commit(
                &DummySigner,
                vec![],
                root,
                vec![],
                "agent".into(),
                "msg".into(),
            )
            .unwrap();
        let c = cs.get_commit(h).unwrap();
        assert!(c.signature.is_some());
        cs.verify_commit_with(h, &DummyVerifier).unwrap();
    }
}

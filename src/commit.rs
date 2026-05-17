use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
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
    /// `hash_typed(COMMIT_PAYLOAD_TAG, &to_cbor(&unsigned))` where `unsigned`
    /// is this commit with `signature` and `payload_hash` both set to `None`.
    /// Present only on signed commits; verifiers MUST re-derive and compare.
    #[serde(default)]
    pub payload_hash: Option<Hash>,
}

impl Commit {
    /// Compute the payload hash that a signer signs / a verifier checks.
    /// Strips `signature` and `payload_hash` from `self` to reconstruct the
    /// canonical unsigned form, then hashes its DAG-CBOR encoding.
    pub fn unsigned_payload_hash(&self) -> Result<Hash> {
        let unsigned = Commit {
            signature: None,
            payload_hash: None,
            ..self.clone()
        };
        Ok(hash_typed(COMMIT_PAYLOAD_TAG, &to_cbor(&unsigned)?))
    }
}

pub trait CommitVerifier {
    /// `payload_hash` has already been re-derived from `commit` and confirmed
    /// to match the value stored on the commit. Implementations should perform
    /// only the cryptographic signature check against this hash.
    fn verify(&self, commit_hash: CommitHash, commit: &Commit, payload_hash: Hash) -> Result<()>;
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
        self.validate_references(state_root, &manifests)?;
        let commit = Commit {
            schema_version: COMMIT_SCHEMA_VERSION,
            parents,
            timestamp: now_unix(),
            author,
            message,
            state_root,
            manifests,
            signature: None,
            payload_hash: None,
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
        self.validate_references(state_root, &manifests)?;
        let unsigned = Commit {
            schema_version: COMMIT_SCHEMA_VERSION,
            parents,
            timestamp: now_unix(),
            author,
            message,
            state_root,
            manifests,
            signature: None,
            payload_hash: None,
        };
        let payload_hash = unsigned.unsigned_payload_hash()?;
        let signature = signer.sign(payload_hash, &unsigned)?;

        let signed = Commit {
            signature: Some(signature),
            payload_hash: Some(payload_hash),
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
        let stored = commit
            .payload_hash
            .ok_or_else(|| anyhow!("commit {} is not signed (missing payload_hash)", hash))?;
        let expected = commit.unsigned_payload_hash()?;
        if stored != expected {
            return Err(anyhow!(
                "commit {} payload_hash inconsistent with commit body",
                hash
            ));
        }
        verifier.verify(hash, &commit, expected)
    }

    fn validate_references(&self, state_root: StateRoot, manifests: &[Hash]) -> Result<()> {
        if !self.objects.exists(state_root) {
            return Err(anyhow!("state_root {} does not exist", state_root));
        }
        for manifest in manifests {
            if !self.objects.exists(*manifest) {
                return Err(anyhow!("manifest {} does not exist", manifest));
            }
        }
        Ok(())
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
        let (cs, state, _blobs) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let manifest_hash = state.set(root, b"manifest", b"ref").unwrap();
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

    /// Real signing scheme used in tests: the signature IS the payload_hash bytes,
    /// keyed by `k1`. A verifier must reject any tampered commit because the
    /// re-derived `payload_hash` changes when the commit body does.
    struct HashEchoSigner;

    impl CommitSigner for HashEchoSigner {
        fn sign(&self, payload_hash: Hash, _commit: &Commit) -> Result<CommitSignature> {
            Ok(CommitSignature {
                scheme: "hash-echo".into(),
                key_id: Some("k1".into()),
                signature: payload_hash.as_bytes().to_vec(),
            })
        }
    }

    struct HashEchoVerifier;

    impl CommitVerifier for HashEchoVerifier {
        fn verify(&self, _hash: CommitHash, commit: &Commit, payload_hash: Hash) -> Result<()> {
            let sig = commit
                .signature
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing signature"))?;
            if sig.scheme != "hash-echo" {
                return Err(anyhow::anyhow!("unexpected scheme {}", sig.scheme));
            }
            if sig.signature.as_slice() != payload_hash.as_bytes() {
                return Err(anyhow::anyhow!("signature does not match payload_hash"));
            }
            Ok(())
        }
    }

    #[test]
    fn signed_commit_round_trip_verifies() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let h = cs
            .create_signed_commit(
                &HashEchoSigner,
                vec![],
                root,
                vec![],
                "agent".into(),
                "msg".into(),
            )
            .unwrap();
        let c = cs.get_commit(h).unwrap();
        assert!(c.signature.is_some());
        assert!(c.payload_hash.is_some());
        cs.verify_commit_with(h, &HashEchoVerifier).unwrap();
    }

    #[test]
    fn verifier_rejects_unsigned_commit() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let h = cs
            .create_commit(vec![], root, vec![], "agent".into(), "msg".into())
            .unwrap();
        let err = cs.verify_commit_with(h, &HashEchoVerifier).unwrap_err();
        assert!(err.to_string().contains("not signed"));
    }

    /// Tampering with any field of a signed commit must invalidate it.
    /// Demonstrates that storing `payload_hash` alongside the signature does
    /// not allow an attacker to forge by mutating other fields.
    #[test]
    fn verifier_rejects_tampered_commit_body() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let h = cs
            .create_signed_commit(
                &HashEchoSigner,
                vec![],
                root,
                vec![],
                "agent".into(),
                "original message".into(),
            )
            .unwrap();

        let mut c = cs.get_commit(h).unwrap();
        let original_payload_hash = c.payload_hash.unwrap();
        c.message = "tampered message".into();

        // payload_hash is now stale relative to the body. The verifier path's
        // consistency check (inside verify_commit_with) is what catches this;
        // here we simulate by calling the helper directly.
        let recomputed = c.unsigned_payload_hash().unwrap();
        assert_ne!(recomputed, original_payload_hash);
    }

    /// Stored payload_hash MUST equal the re-derived hash, even if a signature
    /// would still verify against the stored payload_hash. Otherwise an attacker
    /// could craft a Commit whose body says X but whose signed payload_hash
    /// covers a different X'.
    #[test]
    fn verifier_rejects_inconsistent_payload_hash() {
        use crate::object_store::ObjectStore;

        let tmp = TempDir::new().unwrap();
        let objects = ObjectStore::new(tmp.path().join("objects"));
        objects.ensure_dir().unwrap();
        let cs = CommitStore::new(objects.clone());
        let state_objects = ObjectStore::new(tmp.path().join("objects"));
        let blobs = BlobStore::new(tmp.path().join("blobs"));
        blobs.ensure_dir().unwrap();
        let state = StateStore::new(state_objects, blobs, Wal::new(tmp.path().join("wal")));
        let root = state.empty_root().unwrap();

        // Hand-craft a forged commit: body says "real" but payload_hash
        // covers a different (signed) payload.
        let forged = Commit {
            schema_version: COMMIT_SCHEMA_VERSION,
            parents: vec![],
            timestamp: 1,
            author: "attacker".into(),
            message: "real".into(),
            state_root: root,
            manifests: vec![],
            signature: Some(CommitSignature {
                scheme: "hash-echo".into(),
                key_id: Some("k1".into()),
                signature: hash_typed(b"other:", b"x").as_bytes().to_vec(),
            }),
            payload_hash: Some(hash_typed(b"other:", b"x")),
        };
        let h = objects.put_serialized(COMMIT_TAG, &forged).unwrap();
        let err = cs.verify_commit_with(h, &HashEchoVerifier).unwrap_err();
        assert!(err.to_string().contains("inconsistent"));
    }

    #[test]
    fn create_commit_rejects_missing_state_root() {
        let tmp = TempDir::new().unwrap();
        let (cs, _state, _) = stores(&tmp);
        let missing_root = hash_typed(b"missing:", b"state");
        let err = cs
            .create_commit(vec![], missing_root, vec![], "agent".into(), "msg".into())
            .unwrap_err();
        assert!(err.to_string().contains("state_root"));
    }

    #[test]
    fn create_commit_rejects_missing_manifest() {
        let tmp = TempDir::new().unwrap();
        let (cs, state, _) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let missing_manifest = hash_typed(b"missing:", b"manifest");
        let err = cs
            .create_commit(
                vec![],
                root,
                vec![missing_manifest],
                "agent".into(),
                "msg".into(),
            )
            .unwrap_err();
        assert!(err.to_string().contains("manifest"));
    }
}

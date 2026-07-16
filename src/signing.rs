//! ed25519 [`CommitSigner`]/[`CommitVerifier`] implementation.
//! Key file: 64 hex chars (32-byte seed), mode 0600. The signature's
//! `key_id` embeds the public key as a routing hint only; verification
//! always uses the caller-supplied key.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

use crate::commit::{Commit, CommitHash, CommitSignature, CommitSigner, CommitVerifier};
use crate::hash::Hash;

pub const SIGNATURE_SCHEME: &str = "ed25519";

/// Generate a keypair; writes the seed to `path`, returns the public hex.
pub fn generate_keypair_file(path: &Path) -> Result<String> {
    if path.exists() {
        return Err(anyhow!(
            "refusing to overwrite existing key {}",
            path.display()
        ));
    }
    let seed = crate::encryption::utils::random_bytes(32)?;
    let seed = Zeroizing::new(seed);
    let signing = SigningKey::from_bytes(
        seed.as_slice()
            .try_into()
            .expect("random_bytes(32) returns 32 bytes"),
    );
    let public_hex = hex::encode(signing.verifying_key().as_bytes());

    let body = Zeroizing::new(format!("{}\n", hex::encode(seed.as_slice())));
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, body.as_bytes())
        .with_context(|| format!("writing key file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(public_hex)
}

pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn from_seed_file(path: &Path) -> Result<Self> {
        let raw = Zeroizing::new(
            fs::read_to_string(path)
                .with_context(|| format!("reading signing key {}", path.display()))?,
        );
        let seed = Zeroizing::new(
            hex::decode(raw.trim()).map_err(|_| anyhow!("signing key file is not valid hex"))?,
        );
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("signing key must be a 32-byte hex seed"))?;
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().as_bytes())
    }
}

impl CommitSigner for Ed25519Signer {
    fn sign(&self, payload_hash: Hash, _commit: &Commit) -> Result<CommitSignature> {
        let sig: Signature = self.key.sign(payload_hash.as_bytes());
        Ok(CommitSignature {
            scheme: SIGNATURE_SCHEME.into(),
            key_id: Some(format!("{SIGNATURE_SCHEME}:{}", self.public_key_hex())),
            signature: sig.to_bytes().to_vec(),
        })
    }
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

impl Ed25519Verifier {
    pub fn from_public_hex(public_hex: &str) -> Result<Self> {
        let bytes =
            hex::decode(public_hex.trim()).map_err(|_| anyhow!("public key is not valid hex"))?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ed25519 public key must be 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| anyhow!("invalid ed25519 public key: {e}"))?;
        Ok(Self { key })
    }

    /// Raw signature check; checkpoints sign payload hashes, not commits.
    pub fn verify_raw(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| anyhow!("malformed ed25519 signature: {e}"))?;
        self.key
            .verify(payload, &sig)
            .map_err(|_| anyhow!("ed25519 signature verification failed"))
    }
}

impl CommitVerifier for Ed25519Verifier {
    fn verify(&self, _commit_hash: CommitHash, commit: &Commit, payload_hash: Hash) -> Result<()> {
        let sig = commit
            .signature
            .as_ref()
            .ok_or_else(|| anyhow!("commit is not signed"))?;
        if sig.scheme != SIGNATURE_SCHEME {
            return Err(anyhow!(
                "unexpected signature scheme '{}' (expected {SIGNATURE_SCHEME})",
                sig.scheme
            ));
        }
        self.verify_raw(payload_hash.as_bytes(), &sig.signature)
    }
}

/// Sign raw bytes (checkpoint chains).
pub fn sign_raw(signer: &Ed25519Signer, payload: &[u8]) -> Vec<u8> {
    signer.key.sign(payload).to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::blob_store::BlobStore;
    use crate::commit::CommitStore;
    use crate::object_store::ObjectStore;
    use crate::state::StateStore;

    fn stores(tmp: &TempDir) -> (CommitStore, StateStore) {
        let objects = ObjectStore::new(tmp.path().join("objects"));
        objects.ensure_dir().unwrap();
        let blobs = BlobStore::new(tmp.path().join("blobs"));
        blobs.ensure_dir().unwrap();
        let state = StateStore::new(objects.clone(), blobs);
        (CommitStore::new(objects), state)
    }

    #[test]
    fn keygen_sign_verify_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("agent.key");
        let public_hex = generate_keypair_file(&key_path).unwrap();

        let signer = Ed25519Signer::from_seed_file(&key_path).unwrap();
        assert_eq!(signer.public_key_hex(), public_hex);

        let (cs, state) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let h = cs
            .create_signed_commit(&signer, vec![], root, vec![], "agent".into(), "m".into())
            .unwrap();

        let verifier = Ed25519Verifier::from_public_hex(&public_hex).unwrap();
        cs.verify_commit_with(h, &verifier).unwrap();
    }

    #[test]
    fn wrong_public_key_rejects() {
        let tmp = TempDir::new().unwrap();
        let key_a = tmp.path().join("a.key");
        let key_b = tmp.path().join("b.key");
        let _pub_a = generate_keypair_file(&key_a).unwrap();
        let pub_b = generate_keypair_file(&key_b).unwrap();

        let signer = Ed25519Signer::from_seed_file(&key_a).unwrap();
        let (cs, state) = stores(&tmp);
        let root = state.empty_root().unwrap();
        let h = cs
            .create_signed_commit(&signer, vec![], root, vec![], "agent".into(), "m".into())
            .unwrap();

        let wrong = Ed25519Verifier::from_public_hex(&pub_b).unwrap();
        assert!(cs.verify_commit_with(h, &wrong).is_err());
    }

    #[test]
    fn keygen_refuses_overwrite() {
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("k");
        generate_keypair_file(&key_path).unwrap();
        assert!(generate_keypair_file(&key_path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let key_path = tmp.path().join("k");
        generate_keypair_file(&key_path).unwrap();
        let mode = fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

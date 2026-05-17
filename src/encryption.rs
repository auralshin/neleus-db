//! Authenticated, at-rest encryption for content-addressed blobs and objects.
//!
//! Design overview
//! ---------------
//!
//! 1. A 32-byte **master key** is derived once at `Database::open` from the
//!    user's password and a long-lived random `master_salt` (persisted in
//!    `meta/config.json`) via PBKDF2-HMAC-SHA256 at the configured iteration
//!    count (default 600k, OWASP-2024).
//!
//! 2. For each encryption operation we generate a fresh random per-blob
//!    `salt` and `nonce`, then derive a **per-blob key** via
//!    HKDF-SHA256(master_key, salt, info=algorithm). The per-blob key is
//!    used once with an AEAD (AES-256-GCM or ChaCha20-Poly1305) and zeroized
//!    immediately.
//!
//! 3. The on-disk envelope (`EncryptedData v2`) records `salt`, `nonce`, and
//!    `ciphertext` only — no per-blob KDF parameters, since the master KDF
//!    config lives at the database level and is fixed for a given DB.
//!
//! Why master + HKDF
//! -----------------
//!
//! Earlier versions ran PBKDF2 with 210k iterations *per blob operation*,
//! which made encryption unusable at any real throughput (~100 ms per read
//! or write). With master+HKDF, the PBKDF2 cost is paid once at open; each
//! subsequent operation pays nanosecond-scale HKDF.
//!
//! Why zeroize
//! -----------
//!
//! Passwords and derived keys are wrapped in `Zeroizing<...>` so they are
//! wiped from memory on drop. Decrypted plaintext flows through callers and
//! escapes our control, so it's not zeroized here — document and move on.

use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use anyhow::{Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

/// On-disk envelope format version emitted by current writes.
const ENVELOPE_VERSION: u32 = 2;

/// PBKDF2 iteration count below which the config is rejected. Matches OWASP
/// 2024 guidance for PBKDF2-HMAC-SHA256.
pub const MIN_KDF_ITERATIONS: u32 = 600_000;

/// AEAD nonce length in bytes (AES-256-GCM and ChaCha20-Poly1305 both use 12).
const AEAD_NONCE_LEN: usize = 12;
/// AEAD key length in bytes (both algorithms use 32).
const AEAD_KEY_LEN: usize = 32;
/// HKDF salt length in bytes (per-blob, random).
const PER_BLOB_SALT_LEN: usize = 16;
/// Master salt length in bytes (long-lived, persisted in config).
pub const MASTER_SALT_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub kdf_iterations: u32,
    /// Long-lived random salt for master-key derivation. Persisted in
    /// `meta/config.json`. Hex-encoded so the config remains human-readable.
    /// Set on first open of an encryption-enabled database; never rotated.
    /// Rotating the *password* (via `Database::rotate_encryption_key`)
    /// rewrites every ciphertext but leaves `master_salt` unchanged.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub master_salt: String,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: "aes-256-gcm".to_string(),
            kdf_iterations: MIN_KDF_ITERATIONS,
            master_salt: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub version: u32,
    pub algorithm: String,
    #[serde(with = "hex_serde")]
    pub salt: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub ciphertext: Vec<u8>,
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Algorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Algorithm {
    fn parse(name: &str) -> Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-poly1305" => Ok(Self::ChaCha20Poly1305),
            other => Err(anyhow!(
                "unsupported encryption algorithm '{}'; expected aes-256-gcm or chacha20-poly1305",
                other
            )),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// Runtime encryption handle. Owns the master key and zeroizes it on drop.
///
/// Constructed once per `Database::open` via `from_config`. Cheap to clone
/// (the wrapped state lives behind `Arc`).
#[derive(Clone)]
pub struct EncryptionRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    algorithm: Algorithm,
    master_key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for EncryptionRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionRuntime")
            .field("algorithm", &self.inner.algorithm.name())
            .field("master_key", &"<redacted>")
            .finish()
    }
}

impl EncryptionRuntime {
    /// Derive the master key and build a runtime.
    ///
    /// `password` is consumed and zeroized before this function returns.
    /// Errors if encryption is disabled in `config`, the password is empty,
    /// or the config fails validation.
    pub fn from_config(config: EncryptionConfig, password: String) -> Result<Self> {
        if !config.enabled {
            return Err(anyhow!(
                "encryption runtime requires enabled encryption config"
            ));
        }
        validate_config(&config)?;
        let password = Zeroizing::new(password);
        if password.is_empty() {
            return Err(anyhow!("encryption password cannot be empty"));
        }
        let master_salt = hex::decode(&config.master_salt)
            .map_err(|_| anyhow!("master_salt is not valid hex"))?;
        if master_salt.len() != MASTER_SALT_LEN {
            return Err(anyhow!(
                "master_salt must be {} bytes (got {})",
                MASTER_SALT_LEN,
                master_salt.len()
            ));
        }
        let algorithm = Algorithm::parse(&config.algorithm)?;

        let mut master_key = Zeroizing::new(vec![0u8; AEAD_KEY_LEN]);
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            &master_salt,
            config.kdf_iterations,
            &mut master_key,
        );

        Ok(Self {
            inner: Arc::new(RuntimeInner {
                algorithm,
                master_key,
            }),
        })
    }

    /// Encrypt `plaintext`, returning the serialized envelope.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let salt = utils::random_bytes(PER_BLOB_SALT_LEN)?;
        let nonce = utils::random_bytes(AEAD_NONCE_LEN)?;
        let per_blob_key = derive_per_blob_key(
            &self.inner.master_key,
            &salt,
            self.inner.algorithm.name(),
        )?;
        let ciphertext =
            aead_encrypt(self.inner.algorithm, per_blob_key.as_slice(), &nonce, plaintext)?;

        let envelope = EncryptedData {
            version: ENVELOPE_VERSION,
            algorithm: self.inner.algorithm.name().to_string(),
            salt,
            nonce,
            ciphertext,
        };
        Ok(serde_json::to_vec(&envelope)?)
    }

    /// Decrypt a serialized envelope.
    pub fn decrypt(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let envelope: EncryptedData = serde_json::from_slice(bytes)
            .map_err(|e| anyhow!("invalid encryption envelope: {e}"))?;
        if envelope.version != ENVELOPE_VERSION {
            return Err(anyhow!(
                "unsupported envelope version {}; this build only reads v{}",
                envelope.version,
                ENVELOPE_VERSION
            ));
        }
        let algorithm = Algorithm::parse(&envelope.algorithm)?;
        if algorithm != self.inner.algorithm {
            return Err(anyhow!(
                "algorithm mismatch: runtime={} envelope={}",
                self.inner.algorithm.name(),
                envelope.algorithm
            ));
        }
        if envelope.nonce.len() != AEAD_NONCE_LEN {
            return Err(anyhow!(
                "invalid nonce size: expected {}, got {}",
                AEAD_NONCE_LEN,
                envelope.nonce.len()
            ));
        }
        let per_blob_key = derive_per_blob_key(
            &self.inner.master_key,
            &envelope.salt,
            self.inner.algorithm.name(),
        )?;
        aead_decrypt(
            self.inner.algorithm,
            per_blob_key.as_slice(),
            &envelope.nonce,
            &envelope.ciphertext,
        )
    }

    pub fn algorithm(&self) -> &'static str {
        self.inner.algorithm.name()
    }

    pub fn is_enabled(&self) -> bool {
        true
    }
}

/// Validate an `EncryptionConfig` before constructing a runtime.
pub fn validate_config(config: &EncryptionConfig) -> Result<()> {
    if !config.enabled {
        return Err(anyhow!("encryption is disabled in config"));
    }
    Algorithm::parse(&config.algorithm)?;
    if config.kdf_iterations < MIN_KDF_ITERATIONS {
        return Err(anyhow!(
            "kdf_iterations must be at least {} (OWASP 2024 minimum for PBKDF2-HMAC-SHA256)",
            MIN_KDF_ITERATIONS
        ));
    }
    if config.master_salt.is_empty() {
        return Err(anyhow!(
            "master_salt is missing from config; call ensure_master_salt before runtime construction"
        ));
    }
    Ok(())
}

/// Ensure the config has a `master_salt`. If missing, generate one and set it.
/// Returns `true` if a new salt was generated and the config should be persisted.
pub fn ensure_master_salt(config: &mut EncryptionConfig) -> Result<bool> {
    if !config.master_salt.is_empty() {
        return Ok(false);
    }
    let salt = utils::random_bytes(MASTER_SALT_LEN)?;
    config.master_salt = hex::encode(&salt);
    Ok(true)
}

fn derive_per_blob_key(
    master_key: &[u8],
    salt: &[u8],
    algorithm_name: &str,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hk.expand(algorithm_name.as_bytes(), key.as_mut())
        .map_err(|e| anyhow!("HKDF expand failed: {e}"))?;
    Ok(key)
}

fn aead_encrypt(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid AES-256-GCM key size"))?;
            cipher
                .encrypt(AesNonce::from_slice(nonce), plaintext)
                .map_err(|e| anyhow!("AES-256-GCM encryption failed: {e}"))
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key size"))?;
            cipher
                .encrypt(ChaChaNonce::from_slice(nonce), plaintext)
                .map_err(|e| anyhow!("ChaCha20-Poly1305 encryption failed: {e}"))
        }
    }
}

fn aead_decrypt(
    algorithm: Algorithm,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| anyhow!("invalid AES-256-GCM key size"))?;
            cipher
                .decrypt(AesNonce::from_slice(nonce), ciphertext)
                .map_err(|_| {
                    anyhow!("AES-256-GCM authentication failed (wrong password or tampered data)")
                })
        }
        Algorithm::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key size"))?;
            cipher
                .decrypt(ChaChaNonce::from_slice(nonce), ciphertext)
                .map_err(|_| {
                    anyhow!(
                        "ChaCha20-Poly1305 authentication failed (wrong password or tampered data)"
                    )
                })
        }
    }
}

pub mod utils {
    use super::*;

    pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut output = vec![0u8; len];
        getrandom::getrandom(&mut output)
            .map_err(|e| anyhow!("secure random generation failed: {e}"))?;
        Ok(output)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_aes_config() -> EncryptionConfig {
        let mut c = EncryptionConfig {
            enabled: true,
            algorithm: "aes-256-gcm".into(),
            ..EncryptionConfig::default()
        };
        ensure_master_salt(&mut c).unwrap();
        c
    }

    fn enabled_chacha_config() -> EncryptionConfig {
        let mut c = EncryptionConfig {
            enabled: true,
            algorithm: "chacha20-poly1305".into(),
            ..EncryptionConfig::default()
        };
        ensure_master_salt(&mut c).unwrap();
        c
    }

    #[test]
    fn defaults_are_safe() {
        let c = EncryptionConfig::default();
        assert!(!c.enabled);
        assert_eq!(c.algorithm, "aes-256-gcm");
        assert_eq!(c.kdf_iterations, MIN_KDF_ITERATIONS);
    }

    #[test]
    fn ensure_master_salt_only_generates_once() {
        let mut c = EncryptionConfig {
            enabled: true,
            algorithm: "aes-256-gcm".into(),
            ..EncryptionConfig::default()
        };
        assert!(ensure_master_salt(&mut c).unwrap());
        let salt = c.master_salt.clone();
        assert!(!ensure_master_salt(&mut c).unwrap());
        assert_eq!(c.master_salt, salt);
    }

    #[test]
    fn config_below_min_iterations_rejected() {
        let mut c = enabled_aes_config();
        c.kdf_iterations = 100_000;
        let err = validate_config(&c).unwrap_err();
        assert!(err.to_string().contains("kdf_iterations"));
    }

    #[test]
    fn config_without_master_salt_rejected() {
        let c = EncryptionConfig {
            enabled: true,
            algorithm: "aes-256-gcm".into(),
            ..EncryptionConfig::default()
        };
        let err = validate_config(&c).unwrap_err();
        assert!(err.to_string().contains("master_salt"));
    }

    #[test]
    fn aes_runtime_roundtrip() {
        let runtime =
            EncryptionRuntime::from_config(enabled_aes_config(), "strong-password".into())
                .unwrap();
        let plaintext = b"runtime payload";
        let envelope = runtime.encrypt(plaintext).unwrap();
        let decrypted = runtime.decrypt(&envelope).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(runtime.algorithm(), "aes-256-gcm");
    }

    #[test]
    fn chacha_runtime_roundtrip() {
        let runtime =
            EncryptionRuntime::from_config(enabled_chacha_config(), "strong-password".into())
                .unwrap();
        let plaintext = b"runtime payload";
        let envelope = runtime.encrypt(plaintext).unwrap();
        let decrypted = runtime.decrypt(&envelope).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(runtime.algorithm(), "chacha20-poly1305");
    }

    #[test]
    fn wrong_password_fails() {
        let cfg = enabled_aes_config();
        let runtime = EncryptionRuntime::from_config(cfg.clone(), "right".into()).unwrap();
        let envelope = runtime.encrypt(b"x").unwrap();

        let other = EncryptionRuntime::from_config(cfg, "wrong".into()).unwrap();
        assert!(other.decrypt(&envelope).is_err());
    }

    /// Same plaintext encrypted twice must yield distinct envelopes
    /// (different per-blob salt and nonce). This is what makes the encryption
    /// IND-CPA across writes.
    #[test]
    fn same_plaintext_different_ciphertext() {
        let runtime =
            EncryptionRuntime::from_config(enabled_aes_config(), "pw".into()).unwrap();
        let a = runtime.encrypt(b"same").unwrap();
        let b = runtime.encrypt(b"same").unwrap();
        assert_ne!(a, b);
    }

    /// Throughput sanity check: 100 encrypt ops must complete in well under
    /// a second. Pre-refactor PBKDF2-per-blob would take ~10 seconds for
    /// this loop on a modern laptop.
    #[test]
    fn per_op_cost_is_fast() {
        let runtime =
            EncryptionRuntime::from_config(enabled_aes_config(), "pw".into()).unwrap();
        let start = std::time::Instant::now();
        for i in 0..100 {
            let payload = format!("payload-{i}");
            let _ = runtime.encrypt(payload.as_bytes()).unwrap();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "100 encrypts took {:?}; per-op derivation is likely regressed",
            elapsed
        );
    }

    #[test]
    fn v1_envelope_is_rejected() {
        // Hand-craft an old v1 envelope shape; the new runtime must refuse it.
        let v1 = serde_json::json!({
            "version": 1,
            "algorithm": "aes-256-gcm",
            "kdf": "pbkdf2",
            "iterations": 210000,
            "salt": "00112233445566778899aabbccddeeff",
            "nonce": "000102030405060708090a0b",
            "ciphertext": "deadbeef",
            "created_at": 0,
            "metadata": {}
        });
        let bytes = serde_json::to_vec(&v1).unwrap();
        let runtime =
            EncryptionRuntime::from_config(enabled_aes_config(), "pw".into()).unwrap();
        let err = runtime.decrypt(&bytes).unwrap_err();
        assert!(err.to_string().contains("unsupported envelope version"));
    }

    #[test]
    fn algorithm_mismatch_between_runtime_and_envelope_fails() {
        let aes = EncryptionRuntime::from_config(enabled_aes_config(), "pw".into()).unwrap();
        let envelope = aes.encrypt(b"x").unwrap();
        let chacha =
            EncryptionRuntime::from_config(enabled_chacha_config(), "pw".into()).unwrap();
        let err = chacha.decrypt(&envelope).unwrap_err();
        assert!(err.to_string().contains("algorithm mismatch"));
    }

    #[test]
    fn empty_password_rejected() {
        let err = EncryptionRuntime::from_config(enabled_aes_config(), "".into()).unwrap_err();
        assert!(err.to_string().contains("password"));
    }
}

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use anyhow::{Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    pub enabled: bool,
    pub algorithm: String,
    pub kdf: String,
    pub key_size: usize,
    pub salt_size: usize,
    #[serde(default = "default_nonce_size")]
    pub nonce_size: usize,
    #[serde(default = "default_kdf_iterations")]
    pub kdf_iterations: u32,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            algorithm: "aes-256-gcm".to_string(),
            kdf: "pbkdf2".to_string(),
            key_size: 32,
            salt_size: 16,
            nonce_size: default_nonce_size(),
            kdf_iterations: default_kdf_iterations(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub version: u32,
    pub algorithm: String,
    #[serde(default = "default_kdf")]
    pub kdf: String,
    #[serde(default = "default_kdf_iterations")]
    pub iterations: u32,
    #[serde(with = "hex_serde")]
    pub salt: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_serde")]
    pub ciphertext: Vec<u8>,
    #[serde(default = "now_unix")]
    pub created_at: u64,
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
}

fn default_kdf() -> String {
    "pbkdf2".to_string()
}

fn default_kdf_iterations() -> u32 {
    210_000
}

fn default_nonce_size() -> usize {
    12
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

pub trait EncryptionProvider: Send + Sync {
    fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<EncryptedData>;
    fn decrypt(&self, encrypted: &EncryptedData, password: &str) -> Result<Vec<u8>>;
    fn algorithm(&self) -> &str;
}

pub struct NoOpEncryption;

impl EncryptionProvider for NoOpEncryption {
    fn encrypt(&self, plaintext: &[u8], _password: &str) -> Result<EncryptedData> {
        Ok(EncryptedData {
            version: 1,
            algorithm: "none".to_string(),
            kdf: "none".to_string(),
            iterations: 0,
            salt: Vec::new(),
            nonce: Vec::new(),
            ciphertext: plaintext.to_vec(),
            created_at: now_unix(),
            metadata: Default::default(),
        })
    }

    fn decrypt(&self, encrypted: &EncryptedData, _password: &str) -> Result<Vec<u8>> {
        if encrypted.algorithm != "none" {
            return Err(anyhow!(
                "NoOp provider can only decrypt algorithm 'none', got '{}'",
                encrypted.algorithm
            ));
        }
        Ok(encrypted.ciphertext.clone())
    }

    fn algorithm(&self) -> &str {
        "none"
    }
}

pub struct EncryptionManager {
    provider: Box<dyn EncryptionProvider>,
    config: EncryptionConfig,
}

impl EncryptionManager {
    pub fn new(config: EncryptionConfig, provider: Box<dyn EncryptionProvider>) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                provider: Box::new(NoOpEncryption),
                config,
            });
        }

        Ok(Self { provider, config })
    }

    pub fn from_config(config: EncryptionConfig) -> Result<Self> {
        if !config.enabled {
            return Ok(Self {
                provider: Box::new(NoOpEncryption),
                config,
            });
        }

        let normalized = config.algorithm.to_ascii_lowercase();
        let provider: Box<dyn EncryptionProvider> = match normalized.as_str() {
            "aes-256-gcm" => Box::new(Aes256GcmEncryption::new(config.clone())?),
            "chacha20-poly1305" => Box::new(ChaCha20Poly1305Encryption::new(config.clone())?),
            "none" => Box::new(NoOpEncryption),
            _ => {
                return Err(anyhow!(
                    "unsupported encryption algorithm '{}'; expected aes-256-gcm or chacha20-poly1305",
                    config.algorithm
                ));
            }
        };

        Ok(Self { provider, config })
    }

    pub fn disabled() -> Self {
        Self {
            provider: Box::new(NoOpEncryption),
            config: EncryptionConfig::default(),
        }
    }

    pub fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<Vec<u8>> {
        let encrypted = self.provider.encrypt(plaintext, password)?;
        let serialized = serde_json::to_vec(&encrypted)?;
        Ok(serialized)
    }

    pub fn decrypt(&self, ciphertext: &[u8], password: &str) -> Result<Vec<u8>> {
        let encrypted: EncryptedData = serde_json::from_slice(ciphertext)?;
        self.provider.decrypt(&encrypted, password)
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn config(&self) -> &EncryptionConfig {
        &self.config
    }
}

pub struct Aes256GcmEncryption {
    config: EncryptionConfig,
}

impl Aes256GcmEncryption {
    pub fn new(config: EncryptionConfig) -> Result<Self> {
        validate_aead_config(&config, "aes-256-gcm")?;
        Ok(Self { config })
    }
}

impl EncryptionProvider for Aes256GcmEncryption {
    fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<EncryptedData> {
        let salt = utils::random_bytes(self.config.salt_size)?;
        let nonce = utils::random_bytes(self.config.nonce_size)?;
        let key = derive_key(
            password,
            &salt,
            &self.config.kdf,
            self.config.kdf_iterations,
            self.config.key_size,
        )?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid AES-256-GCM key size"))?;
        let nonce_ref = AesNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_ref, plaintext)
            .map_err(|e| anyhow!("AES-256-GCM encryption failed: {e}"))?;

        Ok(EncryptedData {
            version: 1,
            algorithm: self.algorithm().to_string(),
            kdf: self.config.kdf.clone(),
            iterations: self.config.kdf_iterations,
            salt,
            nonce,
            ciphertext,
            created_at: now_unix(),
            metadata: Default::default(),
        })
    }

    fn decrypt(&self, encrypted: &EncryptedData, password: &str) -> Result<Vec<u8>> {
        if encrypted.algorithm != self.algorithm() {
            return Err(anyhow!(
                "algorithm mismatch: provider={} payload={}",
                self.algorithm(),
                encrypted.algorithm
            ));
        }
        if encrypted.nonce.len() != self.config.nonce_size {
            return Err(anyhow!(
                "invalid nonce size: expected {}, got {}",
                self.config.nonce_size,
                encrypted.nonce.len()
            ));
        }

        let kdf = if encrypted.kdf.is_empty() {
            &self.config.kdf
        } else {
            &encrypted.kdf
        };
        let iterations = if encrypted.iterations == 0 {
            self.config.kdf_iterations
        } else {
            encrypted.iterations
        };

        let key = derive_key(
            password,
            &encrypted.salt,
            kdf,
            iterations,
            self.config.key_size,
        )?;

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid AES-256-GCM key size"))?;
        let nonce_ref = AesNonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce_ref, encrypted.ciphertext.as_ref())
            .map_err(|_| anyhow!("AES-256-GCM authentication failed (wrong password or tampered data)"))
    }

    fn algorithm(&self) -> &str {
        "aes-256-gcm"
    }
}

pub struct ChaCha20Poly1305Encryption {
    config: EncryptionConfig,
}

impl ChaCha20Poly1305Encryption {
    pub fn new(config: EncryptionConfig) -> Result<Self> {
        validate_aead_config(&config, "chacha20-poly1305")?;
        Ok(Self { config })
    }
}

impl EncryptionProvider for ChaCha20Poly1305Encryption {
    fn encrypt(&self, plaintext: &[u8], password: &str) -> Result<EncryptedData> {
        let salt = utils::random_bytes(self.config.salt_size)?;
        let nonce = utils::random_bytes(self.config.nonce_size)?;
        let key = derive_key(
            password,
            &salt,
            &self.config.kdf,
            self.config.kdf_iterations,
            self.config.key_size,
        )?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key size"))?;
        let nonce_ref = ChaChaNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_ref, plaintext)
            .map_err(|e| anyhow!("ChaCha20-Poly1305 encryption failed: {e}"))?;

        Ok(EncryptedData {
            version: 1,
            algorithm: self.algorithm().to_string(),
            kdf: self.config.kdf.clone(),
            iterations: self.config.kdf_iterations,
            salt,
            nonce,
            ciphertext,
            created_at: now_unix(),
            metadata: Default::default(),
        })
    }

    fn decrypt(&self, encrypted: &EncryptedData, password: &str) -> Result<Vec<u8>> {
        if encrypted.algorithm != self.algorithm() {
            return Err(anyhow!(
                "algorithm mismatch: provider={} payload={}",
                self.algorithm(),
                encrypted.algorithm
            ));
        }
        if encrypted.nonce.len() != self.config.nonce_size {
            return Err(anyhow!(
                "invalid nonce size: expected {}, got {}",
                self.config.nonce_size,
                encrypted.nonce.len()
            ));
        }

        let kdf = if encrypted.kdf.is_empty() {
            &self.config.kdf
        } else {
            &encrypted.kdf
        };
        let iterations = if encrypted.iterations == 0 {
            self.config.kdf_iterations
        } else {
            encrypted.iterations
        };

        let key = derive_key(
            password,
            &encrypted.salt,
            kdf,
            iterations,
            self.config.key_size,
        )?;

        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| anyhow!("invalid ChaCha20-Poly1305 key size"))?;
        let nonce_ref = ChaChaNonce::from_slice(&encrypted.nonce);

        cipher
            .decrypt(nonce_ref, encrypted.ciphertext.as_ref())
            .map_err(|_| {
                anyhow!("ChaCha20-Poly1305 authentication failed (wrong password or tampered data)")
            })
    }

    fn algorithm(&self) -> &str {
        "chacha20-poly1305"
    }
}

fn validate_aead_config(config: &EncryptionConfig, expected_algorithm: &str) -> Result<()> {
    if !config.enabled {
        return Err(anyhow!("encryption provider requires enabled config"));
    }
    if config.key_size != 32 {
        return Err(anyhow!("{expected_algorithm} requires 32-byte key"));
    }
    if config.nonce_size != 12 {
        return Err(anyhow!("{expected_algorithm} requires 12-byte nonce"));
    }
    if config.salt_size < 16 {
        return Err(anyhow!("salt_size must be at least 16 bytes"));
    }
    if config.kdf_iterations < 10_000 {
        return Err(anyhow!(
            "kdf_iterations must be at least 10,000 for production safety"
        ));
    }
    Ok(())
}

fn derive_key(
    password: &str,
    salt: &[u8],
    kdf: &str,
    iterations: u32,
    key_size: usize,
) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(anyhow!("password cannot be empty"));
    }
    if salt.is_empty() {
        return Err(anyhow!("salt cannot be empty"));
    }
    if iterations == 0 {
        return Err(anyhow!("kdf iterations must be > 0"));
    }

    match kdf.to_ascii_lowercase().as_str() {
        "pbkdf2" => utils::derive_key_pbkdf2(password, salt, iterations, key_size),
        other => Err(anyhow!("unsupported kdf '{}'; only pbkdf2 is supported", other)),
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

    pub fn derive_key_pbkdf2(
        password: &str,
        salt: &[u8],
        iterations: u32,
        key_size: usize,
    ) -> Result<Vec<u8>> {
        if key_size == 0 {
            return Err(anyhow!("key_size must be > 0"));
        }
        if iterations == 0 {
            return Err(anyhow!("iterations must be > 0"));
        }

        let mut key = vec![0u8; key_size];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut key);
        Ok(key)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_aes_config() -> EncryptionConfig {
        EncryptionConfig {
            enabled: true,
            algorithm: "aes-256-gcm".to_string(),
            ..EncryptionConfig::default()
        }
    }

    fn enabled_chacha_config() -> EncryptionConfig {
        EncryptionConfig {
            enabled: true,
            algorithm: "chacha20-poly1305".to_string(),
            ..EncryptionConfig::default()
        }
    }

    #[test]
    fn encryption_config_default() {
        let config = EncryptionConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.algorithm, "aes-256-gcm");
        assert_eq!(config.key_size, 32);
        assert_eq!(config.nonce_size, 12);
    }

    #[test]
    fn noop_encryption_roundtrip() {
        let provider = Box::new(NoOpEncryption);
        let plaintext = b"test data";
        let encrypted = provider.encrypt(plaintext, "password").unwrap();
        let decrypted = provider.decrypt(&encrypted, "password").unwrap();
        assert_eq!(plaintext, &decrypted[..]);
        assert_eq!(encrypted.algorithm, "none");
    }

    #[test]
    fn encryption_manager_disabled() {
        let manager = EncryptionManager::disabled();
        assert!(!manager.is_enabled());

        let plaintext = b"test data";
        let encrypted = manager.encrypt(plaintext, "password").unwrap();
        let decrypted = manager.decrypt(&encrypted, "password").unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn encryption_manager_from_config_selects_aes() {
        let manager = EncryptionManager::from_config(enabled_aes_config()).unwrap();
        assert!(manager.is_enabled());
        assert_eq!(manager.config().algorithm, "aes-256-gcm");
    }

    #[test]
    fn encryption_manager_from_config_selects_chacha() {
        let manager = EncryptionManager::from_config(enabled_chacha_config()).unwrap();
        assert!(manager.is_enabled());
        assert_eq!(manager.config().algorithm, "chacha20-poly1305");
    }

    #[test]
    fn encrypted_data_serialization() {
        let encrypted = EncryptedData {
            version: 1,
            algorithm: "aes-256-gcm".to_string(),
            kdf: "pbkdf2".to_string(),
            iterations: 1000,
            salt: vec![1, 2, 3, 4],
            nonce: vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            ciphertext: vec![9, 10, 11, 12],
            created_at: 1,
            metadata: Default::default(),
        };

        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedData = serde_json::from_str(&json).unwrap();

        assert_eq!(encrypted.version, deserialized.version);
        assert_eq!(encrypted.algorithm, deserialized.algorithm);
        assert_eq!(encrypted.salt, deserialized.salt);
    }

    #[test]
    fn aes_encryption_roundtrip() {
        let provider = Aes256GcmEncryption::new(enabled_aes_config()).unwrap();
        let plaintext = b"secret data";
        let encrypted = provider.encrypt(plaintext, "strong-password").unwrap();
        let decrypted = provider.decrypt(&encrypted, "strong-password").unwrap();
        assert_eq!(plaintext, &decrypted[..]);
        assert_ne!(encrypted.ciphertext, plaintext);
    }

    #[test]
    fn aes_wrong_password_fails() {
        let provider = Aes256GcmEncryption::new(enabled_aes_config()).unwrap();
        let encrypted = provider.encrypt(b"secret", "correct-password").unwrap();
        assert!(provider.decrypt(&encrypted, "wrong-password").is_err());
    }

    #[test]
    fn chacha_encryption_roundtrip() {
        let provider = ChaCha20Poly1305Encryption::new(enabled_chacha_config()).unwrap();
        let plaintext = b"secret data";
        let encrypted = provider.encrypt(plaintext, "strong-password").unwrap();
        let decrypted = provider.decrypt(&encrypted, "strong-password").unwrap();
        assert_eq!(plaintext, &decrypted[..]);
        assert_ne!(encrypted.ciphertext, plaintext);
    }

    #[test]
    fn chacha_wrong_password_fails() {
        let provider = ChaCha20Poly1305Encryption::new(enabled_chacha_config()).unwrap();
        let encrypted = provider.encrypt(b"secret", "correct-password").unwrap();
        assert!(provider.decrypt(&encrypted, "wrong-password").is_err());
    }

    #[test]
    fn pbkdf2_key_derivation() {
        let password = "super_secret";
        let salt = b"random_salt";
        let key1 = utils::derive_key_pbkdf2(password, salt, 1000, 32).unwrap();
        let key2 = utils::derive_key_pbkdf2(password, salt, 1000, 32).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn random_bytes_generation() {
        let bytes1 = utils::random_bytes(16).unwrap();
        let bytes2 = utils::random_bytes(16).unwrap();

        assert_eq!(bytes1.len(), 16);
        assert_eq!(bytes2.len(), 16);
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn invalid_kdf_rejected() {
        let mut config = enabled_aes_config();
        config.kdf = "unsupported".into();
        let provider = Aes256GcmEncryption::new(config).unwrap();
        assert!(provider.encrypt(b"x", "pw").is_err());
    }

    #[test]
    fn weak_config_is_rejected() {
        let mut config = enabled_aes_config();
        config.kdf_iterations = 100;
        assert!(Aes256GcmEncryption::new(config).is_err());
    }
}

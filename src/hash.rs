use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Hash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(anyhow!("expected 64-char hex hash, got {}", s.len()));
        }

        let mut out = [0u8; 32];
        for (idx, chunk) in s.as_bytes().chunks(2).enumerate() {
            let chunk_str = std::str::from_utf8(chunk)?;
            out[idx] = u8::from_str_radix(chunk_str, 16)
                .map_err(|e| anyhow!("invalid hex at byte {idx}: {e}"))?;
        }
        Ok(Self(out))
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Hash::from_str(&s).map_err(serde::de::Error::custom)
    }
}

pub fn hash_typed(tag: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(bytes);
    let out = hasher.finalize();
    Hash(*out.as_bytes())
}

pub fn hash_blob(bytes: &[u8]) -> Hash {
    hash_typed(b"blob:", bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_parse_roundtrip() {
        let h = hash_blob(b"hello");
        let parsed = Hash::from_str(&h.to_string()).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn hash_parse_rejects_invalid_len() {
        assert!(Hash::from_str("abcd").is_err());
    }

    #[test]
    fn hash_parse_rejects_invalid_hex() {
        let bad = "g".repeat(64);
        assert!(Hash::from_str(&bad).is_err());
    }

    #[test]
    fn hash_blob_is_deterministic() {
        assert_eq!(hash_blob(b"abc"), hash_blob(b"abc"));
    }

    #[test]
    fn hash_typed_domain_separates() {
        let a = hash_typed(b"blob:", b"abc");
        let b = hash_typed(b"commit:", b"abc");
        assert_ne!(a, b);
    }
}

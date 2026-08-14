use std::fmt::{Display, Formatter};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A 32-byte BLAKE3 content hash. Displays and parses as 64-char lowercase hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    /// The all-zero hash (sentinel for "absent").
    pub fn zero() -> Self {
        Self([0u8; 32])
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap raw 32 bytes as a hash.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Display for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Single-pass hex into a stack buffer beats 32 separate `write!`
        // formatter calls measurably — `path_for` runs on every CAS I/O.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut buf = [0u8; 64];
        for (i, b) in self.0.iter().enumerate() {
            buf[i * 2] = HEX[(b >> 4) as usize];
            buf[i * 2 + 1] = HEX[(b & 0x0f) as usize];
        }
        // All bytes are ASCII hex digits by construction.
        f.write_str(std::str::from_utf8(&buf).expect("hex buffer is ASCII"))
    }
}

impl FromStr for Hash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(anyhow!("expected 64-char hex hash, got {}", s.len()));
        }

        // Lowercase hex only. `from_str_radix` would also accept `+`-prefixed
        // and uppercase digits, so many distinct strings would parse to one
        // hash while `Display` reproduced none of them, so one logical object
        // could then be addressed under several spellings.
        let mut out = [0u8; 32];
        for (idx, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0], idx)?;
            let lo = hex_digit(chunk[1], idx)?;
            out[idx] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn hex_digit(b: u8, idx: usize) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(anyhow!(
            "invalid hex at byte {idx}: expected lowercase [0-9a-f]"
        )),
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

/// Domain-separated content hash: BLAKE3 over `tag || bytes`. Every object
/// family uses a distinct `tag` so different types cannot collide.
pub fn hash_typed(tag: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(bytes);
    let out = hasher.finalize();
    Hash(*out.as_bytes())
}

/// Content hash of a raw blob (BLAKE3, `blob:` domain).
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

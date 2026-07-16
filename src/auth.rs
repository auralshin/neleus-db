//! API-key auth for server mode. Tokens are `nlk_<hex>` 32-byte secrets;
//! only their BLAKE3 hash is stored (meta/auth.json), compared constant-time.
//! Roles: reader < writer < admin. Tenant-pinned keys are hard-partitioned
//! to `<tenant>/` heads and forced tenant filters. Key management is
//! CLI-only: no HTTP endpoint can mint credentials.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::atomic::write_atomic;

pub const AUTH_SCHEMA_VERSION: u32 = 1;
const TOKEN_PREFIX: &str = "nlk_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Reader,
    Writer,
    Admin,
}

impl std::str::FromStr for Role {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "reader" => Ok(Self::Reader),
            "writer" => Ok(Self::Writer),
            "admin" => Ok(Self::Admin),
            other => Err(anyhow!("unknown role '{other}' (reader|writer|admin)")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRecord {
    pub id: String,
    /// BLAKE3 hex of the full bearer token.
    pub key_hash: String,
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthFile {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub keys: Vec<KeyRecord>,
}

/// Authenticated caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub key_id: String,
    pub role: Role,
    pub tenant: Option<String>,
}

impl Principal {
    pub fn allows(&self, required: Role) -> bool {
        self.role >= required
    }
}

#[derive(Debug, Clone)]
pub struct AuthRegistry {
    keys: Vec<KeyRecord>,
}

fn auth_path(db_root: &Path) -> PathBuf {
    db_root.join("meta").join("auth.json")
}

fn load_file(db_root: &Path) -> Result<AuthFile> {
    let path = auth_path(db_root);
    match fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AuthFile::default()),
        Err(e) => Err(e.into()),
    }
}

fn store_file(db_root: &Path, file: &AuthFile) -> Result<()> {
    let path = auth_path(db_root);
    write_atomic(&path, &serde_json::to_vec_pretty(file)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Constant-time equality; length leaks, but inputs are fixed-size digests.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

fn hash_token(token: &str) -> [u8; 32] {
    *blake3::hash(token.as_bytes()).as_bytes()
}

impl AuthRegistry {
    pub fn load(db_root: &Path) -> Result<Self> {
        Ok(Self {
            keys: load_file(db_root)?.keys,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Compares every stored hash (no early exit) to keep timing flat.
    pub fn authenticate(&self, token: &str) -> Option<Principal> {
        let presented = hash_token(token);
        let mut found: Option<&KeyRecord> = None;
        for record in &self.keys {
            let stored = hex::decode(&record.key_hash).unwrap_or_default();
            if ct_eq(&presented, &stored) {
                found = Some(record);
            }
        }
        found.map(|record| Principal {
            key_id: record.id.clone(),
            role: record.role,
            tenant: record.tenant.clone(),
        })
    }
}

/// Mint a key; the returned token is shown once and never stored.
pub fn add_key(db_root: &Path, id: &str, role: Role, tenant: Option<&str>) -> Result<String> {
    if id.is_empty() || id.len() > 128 {
        return Err(anyhow!("key id must be 1..=128 chars"));
    }
    if let Some(t) = tenant
        && crate::refs::validate_tenant(t).is_err()
    {
        return Err(anyhow!("invalid tenant name {t:?}"));
    }
    let mut file = load_file(db_root)?;
    if file.keys.iter().any(|k| k.id == id) {
        return Err(anyhow!("key id '{id}' already exists"));
    }
    let secret = crate::encryption::utils::random_bytes(32)?;
    let token = format!("{TOKEN_PREFIX}{}", hex::encode(&secret));
    file.schema_version = AUTH_SCHEMA_VERSION;
    file.keys.push(KeyRecord {
        id: id.to_string(),
        key_hash: hex::encode(hash_token(&token)),
        role,
        tenant: tenant.map(str::to_string),
        created_at: crate::clock::now_unix()?,
    });
    store_file(db_root, &file)?;
    Ok(token)
}

/// Revoke a key by id. Returns true if it existed.
pub fn remove_key(db_root: &Path, id: &str) -> Result<bool> {
    let mut file = load_file(db_root)?;
    let before = file.keys.len();
    file.keys.retain(|k| k.id != id);
    let removed = file.keys.len() != before;
    if removed {
        store_file(db_root, &file)?;
    }
    Ok(removed)
}

/// Key metadata only; never hashes or secrets.
pub fn list_keys(db_root: &Path) -> Result<Vec<(String, Role, Option<String>)>> {
    Ok(load_file(db_root)?
        .keys
        .into_iter()
        .map(|k| (k.id, k.role, k.tenant))
        .collect())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn root(tmp: &TempDir) -> PathBuf {
        let r = tmp.path().join("db");
        fs::create_dir_all(r.join("meta")).unwrap();
        r
    }

    #[test]
    fn mint_authenticate_revoke() {
        let tmp = TempDir::new().unwrap();
        let root = root(&tmp);
        let token = add_key(&root, "ci", Role::Writer, None).unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));

        let registry = AuthRegistry::load(&root).unwrap();
        let principal = registry.authenticate(&token).unwrap();
        assert_eq!(principal.key_id, "ci");
        assert!(principal.allows(Role::Reader));
        assert!(principal.allows(Role::Writer));
        assert!(!principal.allows(Role::Admin));

        assert!(registry.authenticate("nlk_wrong").is_none());
        assert!(remove_key(&root, "ci").unwrap());
        let registry = AuthRegistry::load(&root).unwrap();
        assert!(registry.authenticate(&token).is_none());
    }

    #[test]
    fn auth_file_contains_no_secret() {
        let tmp = TempDir::new().unwrap();
        let root = root(&tmp);
        let token = add_key(&root, "k", Role::Reader, Some("acme")).unwrap();
        let raw = fs::read_to_string(root.join("meta").join("auth.json")).unwrap();
        assert!(!raw.contains(&token), "auth file must not store the token");
        let secret_part = token.strip_prefix(TOKEN_PREFIX).unwrap();
        assert!(!raw.contains(secret_part));
    }

    #[test]
    fn duplicate_ids_rejected() {
        let tmp = TempDir::new().unwrap();
        let root = root(&tmp);
        add_key(&root, "k", Role::Reader, None).unwrap();
        assert!(add_key(&root, "k", Role::Reader, None).is_err());
    }

    #[test]
    fn tenant_keys_carry_tenant() {
        let tmp = TempDir::new().unwrap();
        let root = root(&tmp);
        let token = add_key(&root, "t", Role::Writer, Some("acme")).unwrap();
        let registry = AuthRegistry::load(&root).unwrap();
        let p = registry.authenticate(&token).unwrap();
        assert_eq!(p.tenant.as_deref(), Some("acme"));
    }

    #[test]
    fn role_ladder_ordering() {
        assert!(Role::Admin > Role::Writer);
        assert!(Role::Writer > Role::Reader);
    }
}

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

use crate::atomic::write_atomic;
use crate::hash::Hash;
use crate::lock::acquire_lock;
use crate::wal::{Wal, WalOp};

#[derive(Clone, Debug)]
pub struct RefsStore {
    root: PathBuf,
    wal: Wal,
}

impl RefsStore {
    pub fn new(root: impl Into<PathBuf>, wal: Wal) -> Self {
        Self {
            root: root.into(),
            wal,
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(self.heads_dir())?;
        fs::create_dir_all(self.states_dir())?;
        Ok(())
    }

    pub fn head_get(&self, name: &str) -> Result<Option<Hash>> {
        validate_ref_name(name)?;
        read_hash(self.head_path(name))
    }

    pub fn head_set(&self, name: &str, hash: Hash) -> Result<()> {
        validate_ref_name(name)?;
        self.ensure_dirs()?;

        let _lock = acquire_lock(self.root.join(".refs.lock"), Duration::from_secs(10))?;
        let entry = Wal::make_ref_entry(WalOp::RefHeadSet, name, hash);
        let wal_path = self.wal.begin_entry(&entry)?;

        write_atomic(&self.head_path(name), format!("{hash}\n").as_bytes())?;
        self.wal.end(&wal_path)?;
        Ok(())
    }

    pub fn head_compare_and_set(
        &self,
        name: &str,
        expected: Option<Hash>,
        new_hash: Hash,
    ) -> Result<bool> {
        self.compare_and_set(
            name,
            expected,
            new_hash,
            WalOp::RefHeadSet,
            self.head_path(name),
        )
    }

    pub fn state_get(&self, name: &str) -> Result<Option<Hash>> {
        validate_ref_name(name)?;
        read_hash(self.state_path(name))
    }

    pub fn state_set(&self, name: &str, hash: Hash) -> Result<()> {
        validate_ref_name(name)?;
        self.ensure_dirs()?;

        let _lock = acquire_lock(self.root.join(".refs.lock"), Duration::from_secs(10))?;
        let entry = Wal::make_ref_entry(WalOp::RefStateSet, name, hash);
        let wal_path = self.wal.begin_entry(&entry)?;

        write_atomic(&self.state_path(name), format!("{hash}\n").as_bytes())?;
        self.wal.end(&wal_path)?;
        Ok(())
    }

    pub fn state_compare_and_set(
        &self,
        name: &str,
        expected: Option<Hash>,
        new_hash: Hash,
    ) -> Result<bool> {
        self.compare_and_set(
            name,
            expected,
            new_hash,
            WalOp::RefStateSet,
            self.state_path(name),
        )
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }

    fn heads_dir(&self) -> PathBuf {
        self.root.join("heads")
    }

    fn states_dir(&self) -> PathBuf {
        self.root.join("states")
    }

    fn head_path(&self, name: &str) -> PathBuf {
        self.heads_dir().join(name)
    }

    fn state_path(&self, name: &str) -> PathBuf {
        self.states_dir().join(name)
    }

    fn compare_and_set(
        &self,
        name: &str,
        expected: Option<Hash>,
        new_hash: Hash,
        wal_op: WalOp,
        path: PathBuf,
    ) -> Result<bool> {
        validate_ref_name(name)?;
        self.ensure_dirs()?;

        let _lock = acquire_lock(self.root.join(".refs.lock"), Duration::from_secs(10))?;
        let current = read_hash(path.clone())?;
        if current != expected {
            return Ok(false);
        }

        let entry = Wal::make_ref_entry(wal_op, name, new_hash);
        let wal_path = self.wal.begin_entry(&entry)?;
        write_atomic(&path, format!("{new_hash}\n").as_bytes())?;
        self.wal.end(&wal_path)?;
        Ok(true)
    }
}

pub fn head_get(store: &RefsStore, name: &str) -> Result<Option<Hash>> {
    store.head_get(name)
}

pub fn head_set(store: &RefsStore, name: &str, hash: Hash) -> Result<()> {
    store.head_set(name, hash)
}

fn read_hash(path: PathBuf) -> Result<Option<Hash>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("failed reading ref file {}", path.display()))?;
    let h = raw.trim().parse::<Hash>()?;
    Ok(Some(h))
}

/// Maximum number of `/`-separated components in a ref name. Caps directory
/// depth created under `refs/heads/` and `refs/states/`.
const MAX_REF_DEPTH: usize = 5;

/// Whitelist-based ref-name validation. Mirrors a strict subset of git's
/// refspec rules (`git check-ref-format`):
///
/// - non-empty
/// - characters limited to `A-Za-z0-9_-/.`
/// - no leading `-` (avoids confusion with CLI flags)
/// - no leading or trailing `/`
/// - no consecutive `/`
/// - at most `MAX_REF_DEPTH` `/`-separated components
/// - no `..` substring (path traversal)
/// - no trailing `.` and no `.lock` suffix (mirrors git)
///
/// Tightening from previous (laxer) behavior: names like `feature/foo`
/// still pass, while names like `name//other`, `~weird`, or arbitrarily
/// nested `a/b/c/d/e/f/g` are now rejected. Untrusted ref names cannot
/// produce surprising directory hierarchies under `refs/`.
pub(crate) fn validate_ref_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("reference name cannot be empty"));
    }
    if name.starts_with('/') || name.ends_with('/') {
        return Err(anyhow!("reference name has leading/trailing '/': {name}"));
    }
    if name.starts_with('-') {
        return Err(anyhow!("reference name cannot start with '-': {name}"));
    }
    if name.contains("..") || name.contains("//") || name.contains('\0') {
        return Err(anyhow!("unsafe reference name: {name}"));
    }
    if name.ends_with('.') || name.ends_with(".lock") {
        return Err(anyhow!("reference name has reserved suffix: {name}"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/' | '.'))
    {
        return Err(anyhow!(
            "reference name contains disallowed characters: {name}"
        ));
    }
    let depth = name.split('/').count();
    if depth > MAX_REF_DEPTH {
        return Err(anyhow!(
            "reference name exceeds max depth {} (got {}): {name}",
            MAX_REF_DEPTH,
            depth,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::hash::hash_blob;

    fn store(tmp: &TempDir) -> RefsStore {
        let wal = Wal::new(tmp.path().join("wal"));
        RefsStore::new(tmp.path().join("refs"), wal)
    }

    #[test]
    fn head_set_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"x");
        s.head_set("main", h).unwrap();
        assert_eq!(s.head_get("main").unwrap(), Some(h));
    }

    #[test]
    fn head_get_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        assert_eq!(s.head_get("main").unwrap(), None);
    }

    #[test]
    fn state_set_get_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"state");
        s.state_set("main", h).unwrap();
        assert_eq!(s.state_get("main").unwrap(), Some(h));
    }

    #[test]
    fn invalid_ref_name_rejected() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"x");
        assert!(s.head_set("../bad", h).is_err());
    }

    /// Regression for issue #4: ref-name validator rejects a known-bad set.
    #[test]
    fn validate_ref_name_rejects_unsafe_inputs() {
        for bad in [
            "",
            "/leading",
            "trailing/",
            "double//slash",
            "../escape",
            "ab..cd",
            "with\0null",
            "-flag-like",
            "trailing.",
            "ends.lock",
            "has spaces",
            "weird~char",
            "weird?char",
            "weird*char",
            "a/b/c/d/e/f", // depth 6 > MAX_REF_DEPTH
        ] {
            assert!(
                super::validate_ref_name(bad).is_err(),
                "validator must reject: {bad:?}"
            );
        }
    }

    #[test]
    fn validate_ref_name_accepts_canonical_names() {
        for good in [
            "main",
            "dev",
            "feature/foo",
            "release/v1.0",
            "user_42/topic-x",
            "a/b/c/d/e", // depth 5 == MAX_REF_DEPTH
        ] {
            assert!(
                super::validate_ref_name(good).is_ok(),
                "validator must accept: {good:?}"
            );
        }
    }

    /// Creating a ref with a `/` produces a subdirectory under refs/heads/.
    /// This is the intended git-style namespacing; verify it still works
    /// post-tightening.
    #[test]
    fn slash_in_ref_name_creates_subdirectory() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"x");
        s.head_set("feature/foo", h).unwrap();
        assert!(tmp.path().join("refs/heads/feature/foo").exists());
        assert_eq!(s.head_get("feature/foo").unwrap(), Some(h));
    }

    #[test]
    fn free_functions_delegate() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let h = hash_blob(b"x");
        super::head_set(&s, "main", h).unwrap();
        assert_eq!(super::head_get(&s, "main").unwrap(), Some(h));
    }

    #[test]
    fn wal_cleanup_after_ref_set() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        s.head_set("main", hash_blob(b"x")).unwrap();
        let wal = Wal::new(tmp.path().join("wal"));
        assert!(wal.pending().unwrap().is_empty());
    }

    #[test]
    fn head_overwrite_works() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let a = hash_blob(b"a");
        let b = hash_blob(b"b");
        s.head_set("main", a).unwrap();
        s.head_set("main", b).unwrap();
        assert_eq!(s.head_get("main").unwrap(), Some(b));
    }

    #[test]
    fn state_ref_missing_returns_none() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        assert_eq!(s.state_get("dev").unwrap(), None);
    }

    #[test]
    fn state_compare_and_set_succeeds_on_match() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let a = hash_blob(b"a");
        let b = hash_blob(b"b");
        s.state_set("main", a).unwrap();
        let ok = s.state_compare_and_set("main", Some(a), b).unwrap();
        assert!(ok);
        assert_eq!(s.state_get("main").unwrap(), Some(b));
    }

    #[test]
    fn head_compare_and_set_fails_on_mismatch() {
        let tmp = TempDir::new().unwrap();
        let s = store(&tmp);
        let a = hash_blob(b"a");
        let b = hash_blob(b"b");
        s.head_set("main", a).unwrap();
        let ok = s.head_compare_and_set("main", Some(b), b).unwrap();
        assert!(!ok);
        assert_eq!(s.head_get("main").unwrap(), Some(a));
    }
}

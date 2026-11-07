//! Git-style push/pull over the whole-DB pack format. Objects are immutable
//! and self-identifying, so merge = copy what's missing; refs fast-forward
//! only (no force-push — divergence is reported, never overwritten).
//! Transport: std-only HTTP/1.1 to a `serve` peer; TLS terminates in front.
//! Encrypted DBs replicate ciphertext verbatim, so both sides need the same
//! encryption config and boundary key (checked before any copy).

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

use crate::atomic::{build_temp_name, create_dir_durable, maybe_sync_dir, maybe_sync_file};
use crate::commit::CommitHash;
use crate::db::Database;
use crate::hash::Hash;

/// Cap on ancestry walks during fast-forward checks.
const MAX_ANCESTRY_WALK: usize = 100_000;
/// Cap on HTTP response bodies (a full DB pack can be large).
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    pub objects_added: usize,
    pub packs_copied: usize,
    pub refs_updated: Vec<String>,
    pub refs_skipped: Vec<String>,
    pub checkpoints_updated: Vec<String>,
    pub records_updated: Vec<String>,
}

/// Merge a remote tree: copy missing blobs/objects, fast-forward heads,
/// adopt checkpoint tips whose chain contains ours. states/wal/meta/index
/// stay local.
/// `gate` runs before each ref is adopted, with the head it belongs to.
pub fn merge_tree(
    db: &Database,
    remote_root: &Path,
    gate: &dyn Fn(&str) -> Result<()>,
) -> Result<MergeReport> {
    // Encryption compatibility gate: ciphertext is keyed by master_salt.
    let remote_cfg_path = remote_root.join("meta").join("config.json");
    let remote_cfg: serde_json::Value =
        serde_json::from_slice(&fs::read(&remote_cfg_path).with_context(|| {
            format!("remote tree has no config at {}", remote_cfg_path.display())
        })?)?;
    let local_cfg = serde_json::to_value(&db.config)?;
    // Trees cut under different keys share no nodes and break canonical roots.
    if remote_cfg.get("secret") != local_cfg.get("secret") {
        bail!(
            "refusing to merge: database secrets differ (create the replica with \
             `db init --replica-of <url>`)"
        );
    }
    if remote_cfg.get("encryption") != local_cfg.get("encryption") {
        bail!(
            "refusing to merge: encryption configs differ (replication requires \
             identical master_salt/algorithm so ciphertext stays readable)"
        );
    }

    let mut report = MergeReport::default();

    for store in ["blobs", "objects"] {
        let local_root = db.root.join(store);
        let remote_store = remote_root.join(store);

        // Loose objects: copy verbatim bytes for hashes we don't hold. The
        // address is taken from the filename and not re-derived: these bytes
        // are below the crypto boundary, so re-hashing would need the master
        // key and the object's type tag. A hostile peer can therefore land
        // bytes under an address they do not hash to; reads are what reject
        // them (typed object reads always re-derive, and `verify_on_read`
        // covers blobs), so never treat a merge as attestation.
        let local_cas = crate::cas::CasStore::new(&local_root);
        for (hash, path) in crate::packstore::loose_objects(&remote_store)? {
            if local_cas.exists(hash) {
                continue;
            }
            let bytes = fs::read(&path)?;
            local_cas.put_existing_hash(hash, &bytes)?;
            report.objects_added += 1;
        }

        // Packs are content-named: missing filename = missing object set.
        // Each file lands through a temp name and `.pack` before `.idx`, so a
        // reader never loads an index whose pack is missing or short.
        let remote_pack_dir = remote_store.join(crate::packstore::PACK_DIR);
        if remote_pack_dir.is_dir() {
            let local_pack_dir = local_root.join(crate::packstore::PACK_DIR);
            create_dir_durable(&local_pack_dir)?;
            let mut files: Vec<_> = fs::read_dir(&remote_pack_dir)?
                .map(|e| e.map(|e| e.path()))
                .collect::<std::io::Result<_>>()?;
            files.retain(|p| p.is_file());
            let ext = |p: &Path| p.extension().and_then(|e| e.to_str()).map(str::to_owned);
            files.sort_by_key(|p| ext(p).as_deref() == Some("idx"));
            for path in files {
                let name = path.file_name().expect("read_dir entry has a name");
                let target = local_pack_dir.join(name);
                if target.exists() {
                    continue;
                }
                let tmp = local_pack_dir.join(build_temp_name(&name.to_string_lossy())?);
                fs::copy(&path, &tmp)?;
                maybe_sync_file(&File::open(&tmp)?)?;
                fs::rename(&tmp, &target)?;
                if ext(&path).as_deref() == Some("pack") {
                    report.packs_copied += 1;
                }
            }
            maybe_sync_dir(&local_pack_dir)?;
            db.blob_store.refresh_packs();
            db.object_store.refresh_packs();
        }
    }

    // Objects merged first so ancestry walks resolve locally.
    let remote_refs = crate::refs::RefsStore::new(
        remote_root.join("refs"),
        crate::wal::Wal::new(remote_root.join("wal")),
    );
    for (name, remote_hash) in remote_refs.list_heads()? {
        // Every ref moves only from the value the decision was made on: a
        // local writer landing in between keeps its write and we skip.
        match db.refs.head_get(&name)? {
            None => {
                gate(&name)?;
                if db.refs.head_compare_and_set(&name, None, remote_hash)? {
                    report.refs_updated.push(name);
                } else {
                    report.refs_skipped.push(name);
                }
            }
            Some(local_hash) if local_hash == remote_hash => {}
            Some(local_hash) => {
                if is_ancestor(db, local_hash, remote_hash)? {
                    // Refuse to fast-forward over locally staged, uncommitted
                    // writes: advancing the state ref to the remote root would
                    // silently drop them (create_commit_at_head guards the same
                    // way). A staged ref that still matches the local commit's
                    // state has no pending work and is safe to advance.
                    let local_state = db.commit_store.get_commit(local_hash)?.state_root;
                    let staged = db.refs.state_get(&name)?;
                    if matches!(staged, Some(s) if s != local_state) {
                        report.refs_skipped.push(name);
                        continue;
                    }
                    gate(&name)?;
                    // Read the commit before the head names it.
                    let commit = db.commit_store.get_commit(remote_hash)?;
                    if !db
                        .refs
                        .head_compare_and_set(&name, Some(local_hash), remote_hash)?
                    {
                        report.refs_skipped.push(name);
                        continue;
                    }
                    // Keep the staged-state ref in step so the next commit
                    // builds on the merged state; a concurrent local writer
                    // that re-staged meanwhile reconciles in its own CAS loop.
                    db.refs
                        .state_compare_and_set(&name, staged, commit.state_root)?;
                    report.refs_updated.push(name);
                } else {
                    report.refs_skipped.push(name);
                }
            }
        }
    }

    // Checkpoints: adopt remote tip when our tip is inside its chain.
    let checkpoints = crate::checkpoint::CheckpointStore::new(db);
    for (name, remote_cp) in remote_refs.list_checkpoints()? {
        let local_cp = db.refs.checkpoint_get(&name)?;
        let adopt = match local_cp {
            None => true,
            Some(l) if l == remote_cp => continue,
            Some(l) => checkpoint_chain_contains(&checkpoints, remote_cp, l)?,
        };
        if adopt {
            gate(&name)?;
        }
        if adopt
            && db
                .refs
                .checkpoint_compare_and_set(&name, local_cp, remote_cp)?
        {
            report.checkpoints_updated.push(name);
        } else {
            report.refs_skipped.push(format!("checkpoint:{name}"));
        }
    }

    // Record chains: adopt the remote tip when our tip is in its prev chain.
    // Recorders hold `.audit.lock` across read-tip, build, set; so must this.
    let _audit_lock = crate::lock::flock_exclusive(
        db.root.join(".audit.lock"),
        std::time::Duration::from_secs(10),
    )?;
    for (name, remote_tip) in remote_refs.list_records()? {
        match db.refs.record_get(&name)? {
            Some(local) if local == remote_tip => {}
            Some(local) if !record_chain_contains(db, remote_tip, local)? => {
                report.refs_skipped.push(format!("records:{name}"));
            }
            _ => {
                gate(&name)?;
                db.refs.record_set(&name, remote_tip)?;
                report.records_updated.push(name);
            }
        }
    }

    Ok(report)
}

/// Merge a pack file (the `db pack` format) into `db` via a staging unpack.
pub fn merge_pack_file(
    db: &Database,
    pack_file: &Path,
    gate: &dyn Fn(&str) -> Result<()>,
) -> Result<MergeReport> {
    // Inside the root: a sibling puts an incoming peer's whole unpacked tree
    // outside the encryption boundary. `pack` skips temp-named dirs.
    let dir = db.root.join("meta");
    fs::create_dir_all(&dir)?;
    let staging = dir.join(crate::atomic::build_temp_name("merge-staging")?);
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    crate::pack::unpack(pack_file, &staging, true)?;
    let result = merge_tree(db, &staging, gate);
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Is `ancestor` reachable from `descendant` through any parent edges?
pub(crate) fn is_ancestor(
    db: &Database,
    ancestor: CommitHash,
    descendant: CommitHash,
) -> Result<bool> {
    let mut queue = vec![descendant];
    let mut seen = std::collections::HashSet::new();
    let mut steps = 0usize;
    while let Some(hash) = queue.pop() {
        if hash == ancestor {
            return Ok(true);
        }
        if !seen.insert(hash) {
            continue;
        }
        steps += 1;
        if steps > MAX_ANCESTRY_WALK {
            bail!("ancestry walk exceeded {MAX_ANCESTRY_WALK} commits");
        }
        let commit = db.commit_store.get_commit(hash)?;
        queue.extend(commit.parents);
    }
    Ok(false)
}

fn record_chain_contains(db: &Database, tip: Hash, needle: Hash) -> Result<bool> {
    let mut cursor = Some(tip);
    let mut steps = 0usize;
    while let Some(hash) = cursor {
        if hash == needle {
            return Ok(true);
        }
        steps += 1;
        if steps > MAX_ANCESTRY_WALK {
            bail!("record chain walk exceeded {MAX_ANCESTRY_WALK}");
        }
        cursor = db
            .manifest_store
            .get_query_manifest(hash)
            .with_context(|| format!("reading record {hash}"))?
            .prev;
    }
    Ok(false)
}

fn checkpoint_chain_contains(
    store: &crate::checkpoint::CheckpointStore,
    tip: Hash,
    needle: Hash,
) -> Result<bool> {
    let mut cursor = Some(tip);
    let mut steps = 0usize;
    while let Some(hash) = cursor {
        if hash == needle {
            return Ok(true);
        }
        steps += 1;
        if steps > MAX_ANCESTRY_WALK {
            bail!("checkpoint chain walk exceeded {MAX_ANCESTRY_WALK}");
        }
        cursor = store.get(hash)?.prev;
    }
    Ok(false)
}

// ---------- transport ----------

/// Fetch the remote's pack and merge locally.
pub fn pull(
    db: &Database,
    remote_url: &str,
    token: Option<&str>,
    gate: &dyn Fn(&str) -> Result<()>,
) -> Result<MergeReport> {
    let body = http_request(remote_url, "GET", "/v1/pack", token, &[], None)?;
    let dir = db.root.join("meta");
    fs::create_dir_all(&dir)?;
    let tmp = dir.join(crate::atomic::build_temp_name("pull")?);
    fs::write(&tmp, &body)?;
    let result = merge_pack_file(db, &tmp, gate);
    let _ = fs::remove_file(&tmp);
    result
}

/// Create a database at `path` as a replica of a remote peer: adopt its
/// boundary key, then merge its pack.
pub fn clone(path: &Path, remote_url: &str, token: Option<&str>) -> Result<MergeReport> {
    let body = http_request(remote_url, "GET", "/v1/pack", token, &[], None)?;
    let meta = path.join("meta");
    fs::create_dir_all(&meta)?;
    let tmp = meta.join(crate::atomic::build_temp_name("clone")?);
    let staging = meta.join(crate::atomic::build_temp_name("clone-staging")?);
    fs::write(&tmp, &body)?;
    let result = (|| {
        crate::pack::unpack(&tmp, &staging, true)?;
        let remote_cfg: serde_json::Value =
            serde_json::from_slice(&fs::read(staging.join("meta").join("config.json"))?)?;
        let key = remote_cfg
            .get("secret")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("remote config has no secret"))?;
        let encryption = match remote_cfg.get("encryption") {
            Some(v) => serde_json::from_value(v.clone())?,
            None => None,
        };
        Database::init_with_secret(path, key, encryption)?;
        // A fresh replica has no policies yet.
        merge_tree(&Database::open(path)?, &staging, &|_| Ok(()))
    })();
    let _ = fs::remove_file(&tmp);
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Pack the local DB and POST it; remote merges fast-forward-only.
pub fn push(db: &Database, remote_url: &str, token: Option<&str>) -> Result<String> {
    // Inside the root so `cleanup_orphan_temps` reclaims it; `pack` skips
    // temp-named files, so it cannot capture itself.
    let dir = db.root.join("meta");
    fs::create_dir_all(&dir)?;
    let tmp = dir.join(crate::atomic::build_temp_name("push")?);
    crate::pack::pack(&db.root, &tmp, true)?;
    let body = fs::read(&tmp);
    let _ = fs::remove_file(&tmp);
    let response = http_request(
        remote_url,
        "POST",
        "/v1/pack",
        token,
        &[("content-type", "application/octet-stream")],
        Some(&body?),
    )?;
    Ok(String::from_utf8_lossy(&response).to_string())
}

/// Minimal HTTP/1.1 client; `base_url` must be `http://host:port`.
pub fn http_request(
    base_url: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let rest = base_url
        .strip_prefix("http://")
        .ok_or_else(|| {
            anyhow!(
                "only http:// URLs are supported in-process (got {base_url}); \
                 use an SSH tunnel or TLS-terminating proxy for remote peers"
            )
        })?
        .trim_end_matches('/');
    let host_port = rest.split('/').next().unwrap_or(rest);
    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };

    let mut stream = TcpStream::connect(&addr).with_context(|| format!("connecting to {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    stream.set_write_timeout(Some(Duration::from_secs(600)))?;

    let mut req = format!("{method} {path} HTTP/1.1\r\nhost: {host_port}\r\nconnection: close\r\n");
    if let Some(token) = token {
        req.push_str(&format!("authorization: Bearer {token}\r\n"));
    }
    for (k, v) in extra_headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!(
        "content-length: {}\r\n\r\n",
        body.map_or(0, |b| b.len())
    ));
    stream.write_all(req.as_bytes())?;
    if let Some(body) = body {
        stream.write_all(body)?;
    }
    stream.flush()?;

    let mut raw = Vec::new();
    stream.take(MAX_RESPONSE_BYTES).read_to_end(&mut raw)?;

    let header_end =
        find_header_end(&raw).ok_or_else(|| anyhow!("malformed HTTP response from {addr}"))?;
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| anyhow!("malformed HTTP status line"))?;
    let body = raw[header_end + 4..].to_vec();
    if !(200..300).contains(&status) {
        bail!(
            "remote returned HTTP {status}: {}",
            String::from_utf8_lossy(&body[..body.len().min(512)])
        );
    }
    Ok(body)
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn test_db(tmp: &TempDir, name: &str) -> Database {
        let root = tmp.path().join(name);
        Database::init_with_secret(&root, &"07".repeat(32), None).unwrap();
        Database::open(&root).unwrap()
    }

    #[test]
    fn merge_refuses_a_different_secret() {
        let tmp = TempDir::new().unwrap();
        let a = test_db(&tmp, "a");
        let other = tmp.path().join("other");
        Database::init(&other).unwrap();
        let err = merge_tree(&a, &other, &|_| Ok(())).unwrap_err().to_string();
        assert!(err.contains("secrets differ"), "{err}");
    }

    #[test]
    fn merge_copies_objects_and_fast_forwards() {
        let tmp = TempDir::new().unwrap();
        let a = test_db(&tmp, "a");
        let b = test_db(&tmp, "b");

        let _ = a.state_set_at_head("main", b"k", b"v1").unwrap();
        let c1 = a
            .create_commit_at_head("main", "agent", "c1", vec![])
            .unwrap();

        let report = merge_tree(&b, &a.root, &|_| Ok(())).unwrap();
        assert!(report.objects_added > 0);
        assert_eq!(report.refs_updated, vec!["main".to_string()]);
        let b = Database::open(&b.root).unwrap();
        assert_eq!(b.refs.head_get("main").unwrap(), Some(c1));
        let root = b.resolve_state_root("main").unwrap();
        assert_eq!(b.state_store.get(root, b"k").unwrap(), Some(b"v1".to_vec()));

        // Advance A and merge again: fast-forward.
        let _ = a.state_set_at_head("main", b"k", b"v2").unwrap();
        let c2 = a
            .create_commit_at_head("main", "agent", "c2", vec![])
            .unwrap();
        let report = merge_tree(&b, &a.root, &|_| Ok(())).unwrap();
        assert_eq!(report.refs_updated, vec!["main".to_string()]);
        assert_eq!(b.refs.head_get("main").unwrap(), Some(c2));
    }

    #[test]
    fn merge_copies_packs_without_leaving_temp_files() {
        let tmp = TempDir::new().unwrap();
        let a = test_db(&tmp, "a");
        let b = test_db(&tmp, "b");

        let _ = a.state_set_at_head("main", b"k", b"v1").unwrap();
        let c1 = a
            .create_commit_at_head("main", "agent", "c1", vec![])
            .unwrap();
        crate::packstore::pack_loose(&a.root.join("objects")).unwrap();

        let report = merge_tree(&b, &a.root, &|_| Ok(())).unwrap();
        assert_eq!(report.packs_copied, 1);
        let names: Vec<String> = fs::read_dir(b.root.join("objects").join("pack"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.iter().all(|n| !n.contains(".tmp-")), "{names:?}");
        let b = Database::open(&b.root).unwrap();
        assert_eq!(b.refs.head_get("main").unwrap(), Some(c1));
        let root = b.resolve_state_root("main").unwrap();
        assert_eq!(b.state_store.get(root, b"k").unwrap(), Some(b"v1".to_vec()));
    }

    #[test]
    fn divergent_heads_are_skipped_not_overwritten() {
        let tmp = TempDir::new().unwrap();
        let a = test_db(&tmp, "a");
        let b = test_db(&tmp, "b");

        let _ = a.state_set_at_head("main", b"k", b"a").unwrap();
        a.create_commit_at_head("main", "a", "ca", vec![]).unwrap();
        let _ = b.state_set_at_head("main", b"k", b"b").unwrap();
        let local_head = b.create_commit_at_head("main", "b", "cb", vec![]).unwrap();

        let report = merge_tree(&b, &a.root, &|_| Ok(())).unwrap();
        assert_eq!(report.refs_skipped, vec!["main".to_string()]);
        assert!(report.refs_updated.is_empty());
        assert_eq!(b.refs.head_get("main").unwrap(), Some(local_head));
    }

    #[test]
    fn pack_roundtrip_merge() {
        let tmp = TempDir::new().unwrap();
        let a = test_db(&tmp, "a");
        let b = test_db(&tmp, "b");

        let _ = a.state_set_at_head("main", b"key", b"value").unwrap();
        let c1 = a
            .create_commit_at_head("main", "agent", "c1", vec![])
            .unwrap();

        let pack_path = tmp.path().join("a.pack");
        crate::pack::pack(&a.root, &pack_path, true).unwrap();
        let report = merge_pack_file(&b, &pack_path, &|_| Ok(())).unwrap();
        assert!(report.objects_added > 0);
        assert_eq!(b.refs.head_get("main").unwrap(), Some(c1));
    }

    #[test]
    fn checkpoint_chains_fast_forward() {
        let tmp = TempDir::new().unwrap();
        let a = test_db(&tmp, "a");
        let b = test_db(&tmp, "b");

        a.create_commit_at_head("main", "agent", "c1", vec![])
            .unwrap();
        let cps = crate::checkpoint::CheckpointStore::new(&a);
        cps.create("main", None).unwrap();
        merge_tree(&b, &a.root, &|_| Ok(())).unwrap();

        a.create_commit_at_head("main", "agent", "c2", vec![])
            .unwrap();
        let cp2 = cps.create("main", None).unwrap();
        let report = merge_tree(&b, &a.root, &|_| Ok(())).unwrap();
        assert_eq!(report.checkpoints_updated, vec!["main".to_string()]);
        assert_eq!(b.refs.checkpoint_get("main").unwrap(), Some(cp2));
    }
}

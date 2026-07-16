//! Git-style push/pull over the whole-DB pack format. Objects are immutable
//! and self-identifying, so merge = copy what's missing; refs fast-forward
//! only (no force-push — divergence is reported, never overwritten).
//! Transport: std-only HTTP/1.1 to a `serve` peer; TLS terminates in front.
//! Encrypted DBs replicate ciphertext verbatim, so both sides need the same
//! encryption config (checked before any copy).

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};

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
}

/// Merge a remote tree: copy missing blobs/objects, fast-forward heads,
/// adopt checkpoint tips whose chain contains ours. states/wal/meta/index
/// stay local.
pub fn merge_tree(db: &Database, remote_root: &Path) -> Result<MergeReport> {
    // Encryption compatibility gate: ciphertext is keyed by master_salt.
    let remote_cfg_path = remote_root.join("meta").join("config.json");
    let remote_cfg: serde_json::Value =
        serde_json::from_slice(&fs::read(&remote_cfg_path).with_context(|| {
            format!("remote tree has no config at {}", remote_cfg_path.display())
        })?)?;
    let local_cfg = serde_json::to_value(&db.config)?;
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

        // Loose objects: copy verbatim bytes for hashes we don't hold.
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
        // Visible to handles opened after the merge (same as `db repack`).
        let remote_pack_dir = remote_store.join(crate::packstore::PACK_DIR);
        if remote_pack_dir.is_dir() {
            let local_pack_dir = local_root.join(crate::packstore::PACK_DIR);
            fs::create_dir_all(&local_pack_dir)?;
            for entry in fs::read_dir(&remote_pack_dir)? {
                let entry = entry?;
                let name = entry.file_name();
                let target = local_pack_dir.join(&name);
                if target.exists() || entry.path().is_dir() {
                    continue;
                }
                fs::copy(entry.path(), &target)?;
                if entry.path().extension().and_then(|e| e.to_str()) == Some("pack") {
                    report.packs_copied += 1;
                }
            }
        }
    }

    // Objects merged first so ancestry walks resolve locally.
    let remote_refs = crate::refs::RefsStore::new(
        remote_root.join("refs"),
        crate::wal::Wal::new(remote_root.join("wal")),
    );
    for (name, remote_hash) in remote_refs.list_heads()? {
        match db.refs.head_get(&name)? {
            None => {
                db.refs.head_set(&name, remote_hash)?;
                report.refs_updated.push(name);
            }
            Some(local_hash) if local_hash == remote_hash => {}
            Some(local_hash) => {
                if is_ancestor(db, local_hash, remote_hash)? {
                    db.refs.head_set(&name, remote_hash)?;
                    // Keep the staged-state ref in step so the next commit
                    // builds on the merged state rather than rolling it back.
                    let commit = db.commit_store.get_commit(remote_hash)?;
                    db.refs.state_set(&name, commit.state_root)?;
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
        match db.refs.checkpoint_get(&name)? {
            None => {
                db.refs.checkpoint_set(&name, remote_cp)?;
                report.checkpoints_updated.push(name);
            }
            Some(local_cp) if local_cp == remote_cp => {}
            Some(local_cp) => {
                if checkpoint_chain_contains(&checkpoints, remote_cp, local_cp)? {
                    db.refs.checkpoint_set(&name, remote_cp)?;
                    report.checkpoints_updated.push(name);
                } else {
                    report.refs_skipped.push(format!("checkpoint:{name}"));
                }
            }
        }
    }

    Ok(report)
}

/// Merge a pack file (the `db pack` format) into `db` via a staging unpack.
pub fn merge_pack_file(db: &Database, pack_file: &Path) -> Result<MergeReport> {
    let staging = db
        .root
        .with_extension(format!("merge-staging-{}", std::process::id()));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    crate::pack::unpack(pack_file, &staging, true)?;
    let result = merge_tree(db, &staging);
    let _ = fs::remove_dir_all(&staging);
    result
}

/// Is `ancestor` reachable from `descendant` through any parent edges?
fn is_ancestor(db: &Database, ancestor: CommitHash, descendant: CommitHash) -> Result<bool> {
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
pub fn pull(db: &Database, remote_url: &str, token: Option<&str>) -> Result<MergeReport> {
    let body = http_request(remote_url, "GET", "/v1/pack", token, &[], None)?;
    let tmp = db
        .root
        .with_extension(format!("pull-{}.pack", std::process::id()));
    fs::write(&tmp, &body)?;
    let result = merge_pack_file(db, &tmp);
    let _ = fs::remove_file(&tmp);
    result
}

/// Pack the local DB and POST it; remote merges fast-forward-only.
pub fn push(db: &Database, remote_url: &str, token: Option<&str>) -> Result<String> {
    let tmp = db
        .root
        .with_extension(format!("push-{}.pack", std::process::id()));
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
        Database::init(&root).unwrap();
        Database::open(&root).unwrap()
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

        let report = merge_tree(&b, &a.root).unwrap();
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
        let report = merge_tree(&b, &a.root).unwrap();
        assert_eq!(report.refs_updated, vec!["main".to_string()]);
        assert_eq!(b.refs.head_get("main").unwrap(), Some(c2));
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

        let report = merge_tree(&b, &a.root).unwrap();
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
        let report = merge_pack_file(&b, &pack_path).unwrap();
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
        merge_tree(&b, &a.root).unwrap();

        a.create_commit_at_head("main", "agent", "c2", vec![])
            .unwrap();
        let cp2 = cps.create("main", None).unwrap();
        let report = merge_tree(&b, &a.root).unwrap();
        assert_eq!(report.checkpoints_updated, vec!["main".to_string()]);
        assert_eq!(b.refs.checkpoint_get("main").unwrap(), Some(cp2));
    }
}

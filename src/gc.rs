//! Garbage collection: reclaim objects unreachable from any ref.
//!
//! Marks from `refs/heads/*` commits and `refs/states/*` roots, walking:
//!
//! ```text
//! commit ── parents ──▶ commit
//!   ├─ state_root ─▶ StateManifest ─▶ StateNode tree ─▶ value blob
//!   └─ manifests  ─▶ {Doc,Run,Chunk,Provenance}Manifest ─▶ blobs / nested objects
//! ```
//!
//! Object and blob hashes share one reachable set — their hash-spaces are
//! disjoint, so a hash protects only the store that holds it. Fail-closed: a
//! manifest is classified only if its type round-trips byte-for-byte, else GC
//! aborts. A grace period skips objects newer than the run start. Pruning is
//! opt-in (`prune == false` reports without touching disk).

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use crate::canonical::{from_cbor, to_cbor};
use crate::db::Database;
use crate::hash::Hash;
use crate::lock::acquire_lock;
use crate::manifest::{ChunkManifest, DocManifest, ManifestReferences, RunManifest};
use crate::packstore;
use crate::provenance::ProvenanceManifest;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcStats {
    /// Distinct hashes reachable from the roots.
    pub reachable: usize,
    /// Unreachable objects — removed when `pruned`, otherwise candidates.
    pub unreachable: usize,
    /// Bytes the unreachable objects occupy (loose file len + packed data len).
    pub reclaimed_bytes: u64,
    /// Loose objects left in place because they are newer than the grace cutoff.
    pub skipped_recent: usize,
    /// `false` for a dry run.
    pub pruned: bool,
}

/// Mark from refs, then sweep unreachable objects (loose and packed) from both
/// stores. Dry run unless `prune`. Held under `meta/maintenance.lock` (shared
/// with repack) so the two never run at once.
pub fn gc(db: &Database, prune: bool, grace: Duration) -> Result<GcStats> {
    let _lock = acquire_lock(
        db.root.join("meta").join("maintenance.lock"),
        Duration::from_secs(30),
    )?;
    let start = SystemTime::now();

    let reachable = mark_reachable(db)?;

    let mut stats = GcStats {
        reachable: reachable.len(),
        pruned: prune,
        ..Default::default()
    };
    // Same set sweeps both stores (disjoint hash-spaces).
    for store in ["objects", "blobs"] {
        let (n, bytes, skipped) =
            sweep_store(&db.root.join(store), &reachable, prune, start, grace)?;
        stats.unreachable += n;
        stats.reclaimed_bytes += bytes;
        stats.skipped_recent += skipped;
    }
    Ok(stats)
}

/// Walk the reachable DAG. Fails (pruning nothing) if any reachable object
/// can't be read or, for a manifest, classified.
fn mark_reachable(db: &Database) -> Result<HashSet<Hash>> {
    let mut reach = HashSet::new();

    // Empty state root is a structural constant; keep it live.
    mark_state(db, db.state_store.empty_root()?, &mut reach)?;

    // Commits, transitively through parents.
    let mut stack = collect_refs(&db.root.join("refs").join("heads"))?;
    while let Some(commit_hash) = stack.pop() {
        if !reach.insert(commit_hash) {
            continue;
        }
        let commit = db
            .commit_store
            .get_commit(commit_hash)
            .with_context(|| format!("gc: reading commit {commit_hash}"))?;
        stack.extend(commit.parents.iter().copied());
        mark_state(db, commit.state_root, &mut reach)?;
        for manifest in &commit.manifests {
            mark_manifest(db, *manifest, &mut reach)?;
        }
    }

    // Staged state roots that no commit captured yet.
    for state_root in collect_refs(&db.root.join("refs").join("states"))? {
        mark_state(db, state_root, &mut reach)?;
    }

    Ok(reach)
}

fn mark_state(db: &Database, root: Hash, reach: &mut HashSet<Hash>) -> Result<()> {
    if reach.contains(&root) && db.object_store.exists(root) {
        return Ok(()); // already walked
    }
    let hashes = db
        .state_store
        .reachable_from(root)
        .with_context(|| format!("gc: walking state root {root}"))?;
    reach.extend(hashes);
    Ok(())
}

/// Mark a referenced hash and walk what it points at. A raw blob terminates
/// (its `object_store.exists` is false); an object manifest is classified and
/// its references walked recursively, so a nested object (e.g. a `ChunkManifest`
/// carried in `RunManifest.retrieved_chunks`) gets its own children marked too.
fn mark_manifest(db: &Database, hash: Hash, reach: &mut HashSet<Hash>) -> Result<()> {
    if !reach.insert(hash) {
        return Ok(());
    }
    // Not an object: a raw blob (already marked) or a dangling link
    // (e.g. a zero run_manifest). Nothing to walk.
    if !db.object_store.exists(hash) {
        return Ok(());
    }

    let bytes = db
        .manifest_store
        .raw_manifest_bytes(hash)
        .with_context(|| format!("gc: reading manifest object {hash}"))?;

    let mut matched = false;
    if let Some(doc) = exact_type::<DocManifest>(&bytes) {
        for h in doc.referenced_blobs() {
            mark_manifest(db, h, reach)?;
        }
        matched = true;
    }
    if let Some(run) = exact_type::<RunManifest>(&bytes) {
        for h in run.referenced_blobs() {
            mark_manifest(db, h, reach)?;
        }
        matched = true;
    }
    if let Some(chunk) = exact_type::<ChunkManifest>(&bytes) {
        for h in chunk.referenced_blobs() {
            mark_manifest(db, h, reach)?;
        }
        matched = true;
    }
    if let Some(prov) = exact_type::<ProvenanceManifest>(&bytes) {
        matched = true;
        for record in &prov.records {
            for evidence in &record.evidence {
                mark_manifest(db, evidence.source_blob, reach)?;
            }
            mark_manifest(db, record.run_manifest, reach)?;
        }
    }

    if !matched {
        bail!(
            "gc refusing to prune: reachable manifest object {hash} did not round-trip as any \
             known manifest type (fail-closed); upgrade neleus-db or do not run --prune"
        );
    }
    Ok(())
}

/// Decode `bytes` as `T` only if `T` round-trips to the same bytes — guards a
/// future manifest variant from being read as a known type that drops blobs.
fn exact_type<T>(bytes: &[u8]) -> Option<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let value: T = from_cbor(bytes).ok()?;
    let reencoded = to_cbor(&value).ok()?;
    (reencoded == bytes).then_some(value)
}

/// Parse every ref hash under `dir` (recursive). Dotfiles (temps/locks) are
/// skipped; a non-dotfile that won't parse is corruption and aborts.
fn collect_refs(dir: &Path) -> Result<Vec<Hash>> {
    let mut out = Vec::new();
    collect_refs_into(dir, &mut out)?;
    Ok(out)
}

fn collect_refs_into(dir: &Path, out: &mut Vec<Hash>) -> Result<()> {
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("gc: reading refs {}", dir.display())),
    };
    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_refs_into(&path, out)?;
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Skip atomic-write temps and lock files.
        if name.starts_with('.') {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("gc: reading ref {}", path.display()))?;
        let hash = raw
            .trim()
            .parse::<Hash>()
            .with_context(|| format!("gc: ref {} is not a valid hash", path.display()))?;
        out.push(hash);
    }
    Ok(())
}

/// Sweep one CAS root. Returns `(unreachable, reclaimed_bytes, skipped_recent)`.
fn sweep_store(
    cas_root: &Path,
    reach: &HashSet<Hash>,
    prune: bool,
    start: SystemTime,
    grace: Duration,
) -> Result<(usize, u64, usize)> {
    let mut unreachable = 0usize;
    let mut bytes = 0u64;
    let mut skipped = 0usize;

    for (hash, path) in packstore::loose_objects(cas_root)? {
        if reach.contains(&hash) {
            continue;
        }
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("gc: stat {}", path.display())),
        };
        // Protect anything written too recently to be sure it is really garbage.
        match meta.modified() {
            Ok(modified) if !within_grace(modified, start, grace) => {}
            _ => {
                skipped += 1;
                continue;
            }
        }
        unreachable += 1;
        bytes += meta.len();
        if prune {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e).with_context(|| format!("gc: removing {}", path.display()));
                }
            }
        }
    }

    // Packed objects: rewrite packs to drop the dead ones, or just count them.
    let (packed_n, packed_bytes) = if prune {
        packstore::rewrite_packs_keeping(cas_root, reach)?
    } else {
        packstore::packed_garbage(cas_root, reach)?
    };
    unreachable += packed_n;
    bytes += packed_bytes;

    Ok((unreachable, bytes, skipped))
}

/// True if `modified` is within `grace` before `start`, or at/after it (clock
/// skew → protect). Such objects are too fresh to sweep.
fn within_grace(modified: SystemTime, start: SystemTime, grace: Duration) -> bool {
    match start.duration_since(modified) {
        Ok(age) => age < grace,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{ChunkManifest, ChunkingSpec, MANIFEST_SCHEMA_VERSION, RunManifest};
    use tempfile::TempDir;

    const NO_GRACE: Duration = Duration::from_secs(0);

    fn open_db(tmp: &TempDir) -> (std::path::PathBuf, Database) {
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let db = Database::open(&root).unwrap();
        (root, db)
    }

    #[test]
    fn unreachable_blob_is_pruned_reachable_survives() {
        let tmp = TempDir::new().unwrap();
        let (_root, db) = open_db(&tmp);

        // Reachable: referenced by a doc manifest inside a commit.
        let doc = db
            .manifest_store
            .put_doc_manifest_from_bytes(
                &db.blob_store,
                "src".into(),
                b"reachable-document-bytes",
                ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 8,
                    overlap: 0,
                },
                Some(0),
            )
            .unwrap();
        let reachable_chunk = db.manifest_store.get_doc_manifest(doc).unwrap().chunks[0];
        let _ = db.state_set_at_head("main", b"k", b"v").unwrap();
        db.create_commit_at_head("main", "agent", "m", vec![doc])
            .unwrap();

        // Unreachable: a loose blob nothing points at.
        let orphan = db.blob_store.put(b"orphan-bytes-xyz").unwrap();

        let dry = gc(&db, false, NO_GRACE).unwrap();
        assert!(!dry.pruned);
        assert!(dry.unreachable >= 1, "orphan should be a candidate");

        let pruned = gc(&db, true, NO_GRACE).unwrap();
        assert!(pruned.pruned);
        assert!(pruned.unreachable >= 1);

        assert!(!db.blob_store.exists(orphan), "orphan must be gone");
        assert!(
            db.blob_store.exists(reachable_chunk),
            "reachable chunk kept"
        );
        assert_eq!(db.blob_store.get(reachable_chunk).unwrap().len(), 8);
    }

    #[test]
    fn grace_period_protects_recent_objects() {
        let tmp = TempDir::new().unwrap();
        let (_root, db) = open_db(&tmp);
        let orphan = db.blob_store.put(b"fresh-orphan").unwrap();

        // Large grace -> the just-written orphan is protected.
        let stats = gc(&db, true, Duration::from_secs(3600)).unwrap();
        assert!(stats.skipped_recent >= 1);
        assert!(db.blob_store.exists(orphan), "recent orphan must survive");
    }

    #[test]
    fn gc_prunes_packed_garbage_after_repack() {
        let tmp = TempDir::new().unwrap();
        let (root, db) = open_db(&tmp);

        let _ = db.state_set_at_head("main", b"k", b"v").unwrap();
        db.create_commit_at_head("main", "agent", "m", vec![])
            .unwrap();
        let orphan = db.blob_store.put(b"packed-orphan").unwrap();

        db.repack().unwrap();
        // Reopen so the handle sees the packs.
        let db = Database::open(&root).unwrap();
        assert!(db.blob_store.exists(orphan));

        let stats = gc(&db, true, NO_GRACE).unwrap();
        assert!(stats.unreachable >= 1, "packed orphan should be pruned");

        let db = Database::open(&root).unwrap();
        assert!(!db.blob_store.exists(orphan), "packed orphan must be gone");
        // The reachable commit + state are still readable.
        assert!(db.refs.head_get("main").unwrap().is_some());
        let sroot = db.resolve_state_root("main").unwrap();
        assert_eq!(
            db.state_store.get(sroot, b"k").unwrap(),
            Some(b"v".to_vec())
        );
    }

    #[test]
    fn fail_closed_on_unclassifiable_reachable_manifest() {
        // A commit referencing a "manifest" hash whose object is actually a raw
        // blob (round-trips as no known manifest type) must abort GC.
        let tmp = TempDir::new().unwrap();
        let (_root, db) = open_db(&tmp);

        // Store an object under the manifest tag that is not a valid manifest:
        // an empty CBOR map decodes as none of the known types.
        let bogus = db
            .object_store
            .put_typed_bytes(b"manifest:", &to_cbor(&serde_json::json!({})).unwrap())
            .unwrap();
        let _ = db.state_set_at_head("main", b"k", b"v").unwrap();
        // Force the bogus hash into a commit's manifest list. create_commit
        // validates existence (it exists), so this is accepted.
        db.create_commit_at_head("main", "agent", "m", vec![bogus])
            .unwrap();

        let err = gc(&db, true, NO_GRACE).unwrap_err();
        assert!(err.to_string().contains("fail-closed"), "got: {err}");
    }

    #[test]
    fn nested_chunk_manifest_in_retrieved_chunks_survives_prune() {
        // A RunManifest may carry a ChunkManifest *object* hash in
        // retrieved_chunks. GC must walk that nested object so its own
        // chunk_text/embedding blobs are not pruned out from under it.
        let tmp = TempDir::new().unwrap();
        let (_root, db) = open_db(&tmp);

        let chunk_text = db.blob_store.put(b"retrieved-chunk-text-payload").unwrap();
        let chunk_manifest = db
            .manifest_store
            .put_manifest(&ChunkManifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                chunk_text,
                start: 0,
                end: 10,
                embedding: None,
                metadata: None,
            })
            .unwrap();

        let prompt = db.blob_store.put(b"the-prompt").unwrap();
        let run = db
            .manifest_store
            .put_manifest(&RunManifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                model: "m".into(),
                prompt,
                tool_calls: vec![],
                inputs: vec![],
                outputs: vec![],
                started_at: 1,
                ended_at: 2,
                provider: None,
                system_prompt: None,
                model_parameters: None,
                // The object hash, not a raw blob.
                retrieved_chunks: vec![chunk_manifest],
                sdk_version: None,
                agent_id: None,
                trace_id: None,
                parent_span: None,
                delegated_from: None,
                subject: None,
            })
            .unwrap();

        let _ = db.state_set_at_head("main", b"k", b"v").unwrap();
        db.create_commit_at_head("main", "agent", "m", vec![run])
            .unwrap();

        gc(&db, true, NO_GRACE).unwrap();

        assert!(
            db.object_store.exists(chunk_manifest),
            "nested ChunkManifest object must survive"
        );
        // The discriminating assertion: fails unless GC walks the nested object.
        assert!(
            db.blob_store.exists(chunk_text),
            "nested ChunkManifest's chunk_text blob must survive prune"
        );
    }

    #[test]
    fn blob_reachable_only_through_ancestor_commit_survives_prune() {
        // Exercises parent traversal: a blob reachable only via an ancestor
        // commit (not the tip) must survive prune.
        let tmp = TempDir::new().unwrap();
        let (_root, db) = open_db(&tmp);

        let doc = db
            .manifest_store
            .put_doc_manifest_from_bytes(
                &db.blob_store,
                "src".into(),
                b"ancestor-only-document-body",
                ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 8,
                    overlap: 0,
                },
                Some(0),
            )
            .unwrap();
        let b1 = db.manifest_store.get_doc_manifest(doc).unwrap().chunks[0];
        let _ = db.state_set_at_head("main", b"k", b"v1").unwrap();
        let c1 = db
            .create_commit_at_head("main", "agent", "c1", vec![doc])
            .unwrap();

        // C2 on top of C1, carrying no manifests. B1 is reachable ONLY via C1.
        let _ = db.state_set_at_head("main", b"k", b"v2").unwrap();
        let c2 = db
            .create_commit_at_head("main", "agent", "c2", vec![])
            .unwrap();
        assert_ne!(c1, c2);
        assert_eq!(db.refs.head_get("main").unwrap(), Some(c2));

        gc(&db, true, NO_GRACE).unwrap();

        assert!(
            db.blob_store.exists(b1),
            "blob reachable only through an ancestor commit must survive prune"
        );
        assert!(db.object_store.exists(c1), "ancestor commit retained");
        assert!(
            db.object_store.exists(doc),
            "ancestor commit's manifest retained"
        );
    }

    #[test]
    fn empty_db_gc_is_clean() {
        let tmp = TempDir::new().unwrap();
        let (_root, db) = open_db(&tmp);
        let stats = gc(&db, true, NO_GRACE).unwrap();
        assert_eq!(stats.unreachable, 0);
    }
}

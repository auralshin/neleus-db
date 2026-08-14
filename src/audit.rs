//! Audit surface: collect retrieval audit records (QueryManifests reachable
//! from a head), export them as a self-contained signed bundle, and verify
//! that bundle offline.
//!
//! Bundle format (single file):
//!
//! ```text
//! magic "NELAUDIT" | u32 version | u32 entry_count
//! per entry: u32 name_len | name | u64 data_len | data
//! footer: 32-byte BLAKE3 over everything above
//! optional trailer: "SIG1" | u32 key_id_len | key_id | 64-byte ed25519 sig
//!                   (signature over the footer hash)
//! ```
//!
//! Entries: `meta.json`, `summary.txt`, `retrievals.jsonl`,
//! `objects/<hash>` (canonical commit + manifest bytes),
//! `checkpoints/<hash>` (canonical checkpoint bytes).
//!
//! The verifier needs no database and makes no network calls: every claim in
//! the bundle is re-derived from the carried bytes by hash equations.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::canonical::{from_cbor, to_cbor};
use crate::checkpoint::Checkpoint;
use crate::commit::{COMMIT_TAG, Commit, CommitHash};
use crate::db::Database;
use crate::hash::{Hash, hash_typed};
use crate::manifest::{MANIFEST_TAG, QueryManifest};
use crate::signing::{Ed25519Signer, Ed25519Verifier, sign_raw};

const BUNDLE_MAGIC: &[u8; 8] = b"NELAUDIT";
const BUNDLE_VERSION: u32 = 1;
const SIG_MAGIC: &[u8; 4] = b"SIG1";
const CHECKPOINT_TAG: &[u8] = b"checkpoint:";
const MAX_WALK: usize = 1_000_000;

/// Decoded bundle: named entries, integrity footer, optional (key_id, sig).
type DecodedBundle = (
    HashMap<String, Vec<u8>>,
    [u8; 32],
    Option<(String, Vec<u8>)>,
);

/// One retrieval audit record, resolved from a QueryManifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Commit that carries the QueryManifest (the audit anchor).
    pub commit: String,
    /// QueryManifest hash.
    pub manifest: String,
    /// Commit root the query executed against.
    pub queried_commit: String,
    pub executed_at: u64,
    pub principal: Option<String>,
    pub mode: String,
    pub top_k: u32,
    pub filters: Option<String>,
    pub hits: Vec<AuditHit>,
    /// Position in the head's retrieval chain; a gap means a withheld record.
    #[serde(default)]
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditHit {
    pub chunk: String,
    pub score_micro: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleMeta {
    pub version: u32,
    pub head: String,
    /// Head tip commit at export time; ancestry in the bundle roots here.
    pub tip: String,
    pub from: u64,
    pub to: u64,
    pub generated_at: u64,
    pub retrievals: usize,
    /// Latest checkpoint hash for the head, when one exists.
    pub checkpoint_tip: Option<String>,
    pub tool_version: String,
}

#[derive(Debug, Clone)]
pub struct ExportSummary {
    pub retrievals: usize,
    pub commits: usize,
    pub checkpoints: usize,
    pub bytes: u64,
    pub signed: bool,
}

#[derive(Debug, Clone)]
pub struct VerifyReport {
    pub retrievals: usize,
    pub from: u64,
    pub to: u64,
    pub head: String,
    pub commits: usize,
    pub checkpoints: usize,
    pub checkpoints_signed: usize,
    pub bundle_key_id: Option<String>,
    /// Retrieval sequence numbers form a contiguous run: nothing was withheld
    /// between the first and last record in the window.
    pub chain_complete: bool,
}

/// QueryManifest decode pinned by canonical round-trip, so other manifest
/// kinds cannot be misread as audit records.
fn decode_query_manifest(bytes: &[u8]) -> Option<QueryManifest> {
    let qm: QueryManifest = from_cbor(bytes).ok()?;
    (to_cbor(&qm).ok()? == bytes).then_some(qm)
}

/// Walk `head`'s first-parent chain and collect retrieval audit records in
/// `[from, to]` (unix seconds, inclusive). Returns records newest-first
/// along with the carrying-commit set.
pub fn collect(
    db: &Database,
    head: &str,
    from: u64,
    to: u64,
) -> Result<(Vec<AuditRecord>, Vec<CommitHash>)> {
    let tip = db
        .refs
        .head_get(head)?
        .ok_or_else(|| anyhow!("head '{head}' has no commits"))?;

    let mut records = Vec::new();
    let mut carrying = Vec::new();
    // Records are content-addressed, so the same retrieval committed twice is
    // one retrieval, not two.
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut cursor = Some(tip);
    let mut steps = 0usize;
    while let Some(commit_hash) = cursor {
        steps += 1;
        if steps > MAX_WALK {
            bail!("audit walk exceeded {MAX_WALK} commits");
        }
        let commit = db.commit_store.get_commit(commit_hash)?;
        let mut carries = false;
        for &m in &commit.manifests {
            let bytes = match db.manifest_store.raw_manifest_bytes(m) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let Some(qm) = decode_query_manifest(&bytes) else {
                continue;
            };
            if qm.executed_at < from || qm.executed_at > to || !seen.insert(m) {
                continue;
            }
            carries = true;
            records.push(AuditRecord {
                commit: commit_hash.to_string(),
                manifest: m.to_string(),
                queried_commit: qm.commit.to_string(),
                executed_at: qm.executed_at,
                principal: qm.principal.clone(),
                mode: qm.mode.clone(),
                top_k: qm.top_k,
                filters: qm.filters.clone(),
                hits: qm
                    .hits
                    .iter()
                    .map(|h| AuditHit {
                        chunk: h.chunk.to_string(),
                        score_micro: h.score_micro,
                    })
                    .collect(),
                seq: qm.seq,
                prev: qm.prev.map(|h| h.to_string()),
            });
        }
        if carries {
            carrying.push(commit_hash);
        }
        cursor = commit.parents.first().copied();
    }
    Ok((records, carrying))
}

/// Export a self-contained audit bundle for `[from, to]`. With `signer`,
/// the bundle footer is ed25519-signed.
pub fn export(
    db: &Database,
    head: &str,
    from: u64,
    to: u64,
    out: &Path,
    signer: Option<&Ed25519Signer>,
) -> Result<ExportSummary> {
    let tip = db
        .refs
        .head_get(head)?
        .ok_or_else(|| anyhow!("head '{head}' has no commits"))?;
    let (records, carrying) = collect(db, head, from, to)?;

    // Ancestry objects: full first-parent chain from tip so the verifier can
    // anchor every carrying commit to the tip by hash-links alone.
    let mut objects: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut cursor = Some(tip);
    let mut commit_count = 0usize;
    while let Some(h) = cursor {
        let bytes = db.commit_store.raw_commit_bytes(h)?;
        let c: Commit = from_cbor(&bytes)?;
        objects.insert(h.to_string(), bytes);
        commit_count += 1;
        cursor = c.parents.first().copied();
        if commit_count > MAX_WALK {
            bail!("ancestry walk exceeded {MAX_WALK}");
        }
    }
    for record in &records {
        let m: Hash = record.manifest.parse()?;
        objects.insert(
            record.manifest.clone(),
            db.manifest_store.raw_manifest_bytes(m)?,
        );
    }

    // Checkpoint chain bytes, newest to genesis.
    let mut checkpoints: Vec<(String, Vec<u8>)> = Vec::new();
    let checkpoint_tip = db.refs.checkpoint_get(head)?;
    let mut cp_cursor = checkpoint_tip;
    while let Some(h) = cp_cursor {
        let bytes = db.object_store.get_typed_bytes(CHECKPOINT_TAG, h)?;
        let cp: Checkpoint = from_cbor(&bytes)?;
        checkpoints.push((h.to_string(), bytes));
        cp_cursor = cp.prev;
    }

    let meta = BundleMeta {
        version: BUNDLE_VERSION,
        head: head.to_string(),
        tip: tip.to_string(),
        from,
        to,
        generated_at: crate::clock::now_unix()?,
        retrievals: records.len(),
        checkpoint_tip: checkpoint_tip.map(|h| h.to_string()),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
    };

    let principals: BTreeSet<&str> = records
        .iter()
        .filter_map(|r| r.principal.as_deref())
        .collect();
    let summary = format!(
        "neleus-db audit bundle\n\
         head: {head}\n\
         period: {from}..{to} (unix seconds)\n\
         retrievals: {}\n\
         principals: {}\n\
         carrying commits: {}\n\
         ancestry commits: {commit_count}\n\
         checkpoints: {}\n\
         tip: {tip}\n\
         generated_at: {}\n\
         verify with: neleus-verify <bundle> [--public-key <hex>]\n",
        records.len(),
        if principals.is_empty() {
            "-".to_string()
        } else {
            principals.into_iter().collect::<Vec<_>>().join(", ")
        },
        carrying.len(),
        checkpoints.len(),
        meta.generated_at,
    );

    let mut jsonl = String::new();
    for r in &records {
        jsonl.push_str(&serde_json::to_string(r)?);
        jsonl.push('\n');
    }

    let mut entries: Vec<(String, Vec<u8>)> = vec![
        ("meta.json".into(), serde_json::to_vec_pretty(&meta)?),
        ("summary.txt".into(), summary.into_bytes()),
        ("retrievals.jsonl".into(), jsonl.into_bytes()),
    ];
    for (name, bytes) in objects {
        entries.push((format!("objects/{name}"), bytes));
    }
    for (name, bytes) in &checkpoints {
        entries.push((format!("checkpoints/{name}"), bytes.clone()));
    }

    let bundle = build_bundle(&entries, signer);
    File::create(out)
        .with_context(|| format!("creating bundle {}", out.display()))?
        .write_all(&bundle)?;
    Ok(ExportSummary {
        retrievals: records.len(),
        commits: commit_count,
        checkpoints: checkpoints.len(),
        bytes: bundle.len() as u64,
        signed: signer.is_some(),
    })
}

/// Bundle as bytes, staged through a temp file under `meta/` and unlinked.
pub fn export_bytes(
    db: &Database,
    head: &str,
    from: u64,
    to: u64,
    signer: Option<&Ed25519Signer>,
) -> Result<(Vec<u8>, ExportSummary)> {
    // Stage inside the database, not the shared temp dir: a PID-derived name in
    // /tmp is guessable, so a local attacker could pre-create it as a symlink
    // and redirect the bundle (or read it) on a multi-user host. Keep the exact
    // atomic-write temp name, nothing appended, so `pack` excludes it from
    // backups and `cleanup_orphan_temps` reclaims it if we die mid-export.
    let dir = db.root.join("meta");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(crate::atomic::build_temp_name("export")?);
    let outcome = export(db, head, from, to, &path, signer).and_then(|summary| {
        let bytes = std::fs::read(&path)?;
        Ok((bytes, summary))
    });
    // Unlink on the error path too, or a failed export leaks a full bundle.
    let _ = std::fs::remove_file(&path);
    outcome
}

fn build_bundle(entries: &[(String, Vec<u8>)], signer: Option<&Ed25519Signer>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(BUNDLE_MAGIC);
    out.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (name, data) in entries {
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    }
    let footer = blake3::hash(&out);
    out.extend_from_slice(footer.as_bytes());

    if let Some(signer) = signer {
        let sig = sign_raw(signer, footer.as_bytes());
        let key_id = format!("ed25519:{}", signer.public_key_hex());
        out.extend_from_slice(SIG_MAGIC);
        out.extend_from_slice(&(key_id.len() as u32).to_le_bytes());
        out.extend_from_slice(key_id.as_bytes());
        out.extend_from_slice(&sig);
    }
    out
}

fn read_bundle(path: &Path) -> Result<DecodedBundle> {
    let mut raw = Vec::new();
    File::open(path)
        .with_context(|| format!("opening bundle {}", path.display()))?
        .read_to_end(&mut raw)?;
    if raw.len() < 16 + 32 {
        bail!("bundle too short");
    }
    if &raw[0..8] != BUNDLE_MAGIC {
        bail!("not a neleus audit bundle (bad magic)");
    }
    let version = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    if version != BUNDLE_VERSION {
        bail!("unsupported bundle version {version}");
    }
    let count = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;

    let mut entries = HashMap::new();
    let mut p = 16usize;
    for _ in 0..count {
        if p + 4 > raw.len() {
            bail!("bundle truncated");
        }
        let name_len = u32::from_le_bytes(raw[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let name = String::from_utf8(raw.get(p..p + name_len).context("truncated")?.to_vec())?;
        p += name_len;
        let data_len =
            u64::from_le_bytes(raw.get(p..p + 8).context("truncated")?.try_into()?) as usize;
        p += 8;
        let data = raw.get(p..p + data_len).context("truncated")?.to_vec();
        p += data_len;
        entries.insert(name, data);
    }

    let footer: [u8; 32] = raw.get(p..p + 32).context("missing footer")?.try_into()?;
    let computed = blake3::hash(&raw[..p]);
    if computed.as_bytes() != &footer {
        bail!("bundle integrity check failed (corrupt or tampered)");
    }
    let mut trailer = None;
    let mut q = p + 32;
    if raw.len() > q {
        if raw.get(q..q + 4) != Some(SIG_MAGIC.as_slice()) {
            bail!("unexpected trailing bytes after footer");
        }
        q += 4;
        let key_len =
            u32::from_le_bytes(raw.get(q..q + 4).context("truncated sig")?.try_into()?) as usize;
        q += 4;
        let key_id = String::from_utf8(raw.get(q..q + key_len).context("truncated sig")?.to_vec())?;
        q += key_len;
        let sig = raw.get(q..q + 64).context("truncated sig")?.to_vec();
        trailer = Some((key_id, sig));
    }
    Ok((entries, footer, trailer))
}

/// Verify a bundle offline. With `public_key`, the bundle signature and
/// every signed checkpoint must verify under it; `require_signature` makes
/// an unsigned bundle an error.
pub fn verify_bundle(
    path: &Path,
    public_key: Option<&str>,
    require_signature: bool,
) -> Result<VerifyReport> {
    let (entries, footer, trailer) = read_bundle(path)?;

    let verifier = public_key
        .map(Ed25519Verifier::from_public_hex)
        .transpose()?;
    let bundle_key_id = match (&trailer, &verifier) {
        (Some((key_id, sig)), Some(v)) => {
            v.verify_raw(&footer, sig)
                .map_err(|e| anyhow!("bundle signature: {e}"))?;
            Some(key_id.clone())
        }
        (Some((key_id, _)), None) => Some(key_id.clone()),
        (None, _) if require_signature => bail!("bundle is unsigned"),
        (None, _) => None,
    };

    let meta: BundleMeta = serde_json::from_slice(
        entries
            .get("meta.json")
            .ok_or_else(|| anyhow!("missing meta.json"))?,
    )?;
    let jsonl = entries
        .get("retrievals.jsonl")
        .ok_or_else(|| anyhow!("missing retrievals.jsonl"))?;
    let records: Vec<AuditRecord> = String::from_utf8_lossy(jsonl)
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    if records.len() != meta.retrievals {
        bail!(
            "meta declares {} retrievals, jsonl carries {}",
            meta.retrievals,
            records.len()
        );
    }

    // Re-derive every object hash from carried bytes.
    let mut commits: HashMap<String, Commit> = HashMap::new();
    let mut manifest_objects: HashSet<String> = HashSet::new();
    for (name, bytes) in &entries {
        let Some(hex) = name.strip_prefix("objects/") else {
            continue;
        };
        let claimed: Hash = hex.parse()?;
        if hash_typed(COMMIT_TAG, bytes) == claimed {
            commits.insert(hex.to_string(), from_cbor(bytes)?);
        } else if hash_typed(MANIFEST_TAG, bytes) == claimed {
            manifest_objects.insert(hex.to_string());
        } else {
            bail!("object {hex} matches neither commit nor manifest hash domain");
        }
    }

    // Tip ancestry: every commit in the bundle must be reachable from the
    // declared tip via first-parent links carried in the bundle.
    let mut reachable: HashSet<String> = HashSet::new();
    let mut cursor = Some(meta.tip.clone());
    while let Some(h) = cursor {
        let Some(c) = commits.get(&h) else {
            bail!("ancestry breaks at {h}: commit bytes not in bundle");
        };
        reachable.insert(h);
        cursor = c.parents.first().map(|p| p.to_string());
    }

    for r in &records {
        if r.executed_at < meta.from || r.executed_at > meta.to {
            bail!("record {} outside declared period", r.manifest);
        }
        let manifest_bytes = entries
            .get(&format!("objects/{}", r.manifest))
            .ok_or_else(|| anyhow!("manifest {} bytes missing", r.manifest))?;
        let claimed: Hash = r.manifest.parse()?;
        if hash_typed(MANIFEST_TAG, manifest_bytes) != claimed {
            bail!("manifest {} bytes do not match its hash", r.manifest);
        }
        let qm = decode_query_manifest(manifest_bytes)
            .ok_or_else(|| anyhow!("object {} is not a QueryManifest", r.manifest))?;
        // Compare every field the record claims. The jsonl is a rendering of
        // the manifest, which is the only hash-bound copy; anything left
        // uncompared here is a field an exporter can rewrite freely.
        if qm.executed_at != r.executed_at
            || qm.principal.as_deref() != r.principal.as_deref()
            || qm.mode != r.mode
            || qm.top_k != r.top_k
            || qm.filters.as_deref() != r.filters.as_deref()
            || qm.commit.to_string() != r.queried_commit
            || qm.seq != r.seq
            || qm.prev.map(|p| p.to_string()) != r.prev
            || qm.hits.len() != r.hits.len()
            || qm
                .hits
                .iter()
                .zip(&r.hits)
                .any(|(h, a)| h.chunk.to_string() != a.chunk || h.score_micro != a.score_micro)
        {
            bail!("jsonl record {} disagrees with its manifest", r.manifest);
        }
        let carrier = commits
            .get(&r.commit)
            .ok_or_else(|| anyhow!("carrying commit {} not in bundle", r.commit))?;
        if !carrier
            .manifests
            .iter()
            .any(|m| m.to_string() == r.manifest)
        {
            bail!(
                "commit {} does not reference manifest {}",
                r.commit,
                r.manifest
            );
        }
        if !reachable.contains(&r.commit) {
            bail!("commit {} not reachable from declared tip", r.commit);
        }
    }

    // Export writes manifest bytes only for records inside the window, so a
    // carried QueryManifest with no matching line means the line was removed.
    let recorded: HashSet<&str> = records.iter().map(|r| r.manifest.as_str()).collect();
    for hex in &manifest_objects {
        if recorded.contains(hex.as_str()) {
            continue;
        }
        if let Some(bytes) = entries.get(&format!("objects/{hex}"))
            && decode_query_manifest(bytes).is_some()
        {
            bail!(
                "QueryManifest {hex} is carried by the bundle but has no line in \
                 retrievals.jsonl: the record was withheld from the index"
            );
        }
    }

    // Retrieval chain: sequence numbers must be contiguous and the prev-links
    // must agree. This is the only check that can catch a *withheld* record;
    // every other check assumes what is present is all there was.
    let mut chain: Vec<&AuditRecord> = records.iter().collect();
    chain.sort_by_key(|r| r.seq);
    let mut gaps = Vec::new();
    for pair in chain.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        if b.seq == a.seq {
            bail!("duplicate retrieval sequence {}", a.seq);
        }
        if b.seq != a.seq + 1 {
            gaps.push((a.seq, b.seq));
        }
        if let Some(prev) = &b.prev
            && prev != &a.manifest
            && b.seq == a.seq + 1
        {
            bail!(
                "retrieval {} claims predecessor {} but sequence {} is {}",
                b.seq,
                prev,
                a.seq,
                a.manifest
            );
        }
    }
    // Complete iff contiguous (no internal gaps) and anchored at the genesis
    // record seq 0 — a bundle that starts mid-chain is internally consistent
    // but missing its prefix. An empty bundle is vacuously complete.
    let complete = gaps.is_empty() && chain.first().map(|r| r.seq == 0).unwrap_or(true);
    if !gaps.is_empty() {
        bail!(
            "retrieval chain has {} gap(s), e.g. between sequence {} and {}: records were \
             withheld from this bundle",
            gaps.len(),
            gaps[0].0,
            gaps[0].1
        );
    }

    // Checkpoint chain: hashes, prev-links, sequences, signatures.
    let mut checkpoints_count = 0usize;
    let mut checkpoints_signed = 0usize;
    if let Some(cp_tip) = &meta.checkpoint_tip {
        let mut cursor = Some(cp_tip.clone());
        let mut expected_seq: Option<u64> = None;
        while let Some(h) = cursor {
            let bytes = entries
                .get(&format!("checkpoints/{h}"))
                .ok_or_else(|| anyhow!("checkpoint {h} bytes missing"))?;
            let claimed: Hash = h.parse()?;
            if hash_typed(CHECKPOINT_TAG, bytes) != claimed {
                bail!("checkpoint {h} bytes do not match its hash");
            }
            let cp: Checkpoint = from_cbor(bytes)?;
            if let Some(exp) = expected_seq
                && cp.sequence != exp
            {
                bail!("checkpoint chain sequence break at {h}");
            }
            // Genesis is exactly "sequence 0 and no predecessor"; without both
            // directions a forged `sequence: 0` carrying a `prev` resets the
            // chain, because `checked_sub` then skips every check below it.
            if cp.prev.is_none() != (cp.sequence == 0) {
                bail!(
                    "checkpoint {h} has sequence {} but a mismatched predecessor",
                    cp.sequence
                );
            }
            expected_seq = cp.sequence.checked_sub(1);
            match (&cp.signature, &verifier) {
                (Some(sig), Some(v)) => {
                    let payload = cp.payload_hash()?;
                    v.verify_raw(payload.as_bytes(), sig)
                        .map_err(|e| anyhow!("checkpoint {h}: {e}"))?;
                    checkpoints_signed += 1;
                }
                (Some(_), None) => checkpoints_signed += 1,
                (None, _) => {}
            }
            checkpoints_count += 1;
            cursor = cp.prev.map(|p| p.to_string());
        }
    }

    Ok(VerifyReport {
        retrievals: records.len(),
        from: meta.from,
        to: meta.to,
        head: meta.head,
        commits: reachable.len(),
        checkpoints: checkpoints_count,
        checkpoints_signed,
        bundle_key_id,
        chain_complete: complete,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;
    use crate::engine::{Engine, SearchFilter};
    use crate::signing::generate_keypair_file;

    fn db_with_audited_queries() -> (TempDir, Database, String) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();
        let (_, commit) = engine
            .put_document(
                "main",
                "kb.txt",
                b"alpha retrieval corpus with searchable words",
                crate::manifest::ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 64,
                    overlap: 0,
                },
                None,
                "test",
            )
            .unwrap();
        for i in 0..3 {
            let hits = engine
                .search_semantic(commit, "retrieval corpus", 5, &SearchFilter::default())
                .unwrap();
            engine
                .record_query_at_head(
                    "main",
                    commit,
                    "semantic",
                    Some("retrieval corpus"),
                    None,
                    5,
                    &SearchFilter::default(),
                    Some(&format!("key:agent-{i}")),
                    &hits,
                )
                .unwrap();
        }
        let db = Database::open(&root).unwrap();
        (tmp, db, "main".to_string())
    }

    #[test]
    fn collect_finds_records_in_period() {
        let (_tmp, db, head) = db_with_audited_queries();
        let (records, carrying) = collect(&db, &head, 0, u64::MAX).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(carrying.len(), 3);
        assert!(records.iter().all(|r| r.principal.is_some()));

        let (none, _) = collect(&db, &head, 1, 2).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn export_verify_roundtrip_signed() {
        let (tmp, db, head) = db_with_audited_queries();
        let key = tmp.path().join("audit.key");
        let public_hex = generate_keypair_file(&key).unwrap();
        let signer = Ed25519Signer::from_seed_file(&key).unwrap();

        let out = tmp.path().join("q.nelaudit");
        let summary = export(&db, &head, 0, u64::MAX, &out, Some(&signer)).unwrap();
        assert_eq!(summary.retrievals, 3);
        assert!(summary.signed);

        let report = verify_bundle(&out, Some(&public_hex), true).unwrap();
        assert_eq!(report.retrievals, 3);
        assert_eq!(report.head, head);
        assert!(report.bundle_key_id.unwrap().starts_with("ed25519:"));

        // Wrong key must fail.
        let other = tmp.path().join("other.key");
        let other_pub = generate_keypair_file(&other).unwrap();
        assert!(verify_bundle(&out, Some(&other_pub), true).is_err());
    }

    #[test]
    fn tampered_bundle_fails_verification() {
        let (tmp, db, head) = db_with_audited_queries();
        let out = tmp.path().join("q.nelaudit");
        export(&db, &head, 0, u64::MAX, &out, None).unwrap();

        let mut bytes = fs::read(&out).unwrap();
        // Corrupt the 32-byte integrity footer (the tail of an unsigned bundle).
        // A mid-file flip can land on a length field and desync the parser into
        // an unrelated error; footer corruption deterministically trips the
        // integrity check.
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        fs::write(&out, &bytes).unwrap();
        let err = verify_bundle(&out, None, false).unwrap_err();
        assert!(err.to_string().contains("integrity") || err.to_string().contains("truncated"));
    }

    #[test]
    fn unsigned_bundle_rejected_when_signature_required() {
        let (tmp, db, head) = db_with_audited_queries();
        let out = tmp.path().join("q.nelaudit");
        export(&db, &head, 0, u64::MAX, &out, None).unwrap();
        assert!(verify_bundle(&out, None, true).is_err());
        verify_bundle(&out, None, false).unwrap();
    }
}

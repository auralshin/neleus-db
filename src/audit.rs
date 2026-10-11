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
//! `checkpoints/<hash>` (the latest checkpoint; its Merkle root covers the
//! rest), `pinned/<hash>` (the retrieval record it pins), and for an anchored
//! export `anchor/<hash>` + `anchor_proof` (consistency from the anchor).
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
use crate::checkpoint::{Checkpoint, CheckpointStore, verify_append_only};
use crate::commit::{COMMIT_TAG, Commit, CommitHash};
use crate::db::Database;
use crate::hash::{Hash, hash_typed};
use crate::manifest::{MANIFEST_TAG, QueryManifest};
use crate::merkle::ConsistencyProof;
use crate::signing::{Ed25519Signer, Ed25519Verifier, sign_raw};

const BUNDLE_MAGIC: &[u8; 8] = b"NELAUDIT";
const BUNDLE_VERSION: u32 = 2;
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
    /// Checkpoints carried: the latest one, or none.
    pub checkpoints: usize,
    pub checkpoints_signed: usize,
    /// Commits in the checkpoint log the latest checkpoint's root covers.
    pub log_size: u64,
    /// Latest checkpoint digest; compare it with any anchor held out of band.
    pub checkpoint_tip: Option<String>,
    /// An anchor was given and its log is a prefix of the bundle's.
    pub anchored: bool,
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

/// Cache entry cap; overflow clears (perf reset, never a correctness event).
const QUERY_TIP_CACHE_CAP: usize = 65_536;

/// Latest retrieval record as of `commit`: the highest-sequence QueryManifest
/// in the nearest first-parent commit that carries one. Derived from the
/// commit graph rather than a ref, so a crash between committing a record and
/// updating a ref cannot hand the next record a reused sequence number.
pub fn query_tip(db: &Database, commit: Option<CommitHash>) -> Result<Option<(Hash, u64)>> {
    let mut walked = Vec::new();
    let mut cursor = commit;
    let mut found = None;
    while let Some(c) = cursor {
        if let Some(hit) = db.query_tips.lock().expect("query tip cache").get(&c) {
            found = *hit;
            break;
        }
        if walked.len() >= MAX_WALK {
            bail!("query tip walk exceeded {MAX_WALK} commits");
        }
        walked.push(c);
        let commit = db.commit_store.get_commit(c)?;
        let tip = commit
            .manifests
            .iter()
            .filter_map(|&m| {
                let bytes = db.manifest_store.raw_manifest_bytes(m).ok()?;
                decode_query_manifest(&bytes).map(|qm| (m, qm.seq))
            })
            .max_by_key(|&(_, seq)| seq);
        if tip.is_some() {
            found = tip;
            break;
        }
        cursor = commit.parents.first().copied();
    }
    let mut cache = db.query_tips.lock().expect("query tip cache");
    if cache.len() + walked.len() > QUERY_TIP_CACHE_CAP {
        cache.clear();
    }
    for c in walked {
        cache.insert(c, found);
    }
    Ok(found)
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
    export_inner(db, head, from, to, out, signer, None)
}

/// [`export`] plus a consistency proof from the checkpoint `anchor`, which an
/// auditor retained earlier, to the head's current checkpoint.
pub fn export_anchored(
    db: &Database,
    head: &str,
    from: u64,
    to: u64,
    out: &Path,
    signer: Option<&Ed25519Signer>,
    anchor: Hash,
) -> Result<ExportSummary> {
    export_inner(db, head, from, to, out, signer, Some(anchor))
}

fn export_inner(
    db: &Database,
    head: &str,
    from: u64,
    to: u64,
    out: &Path,
    signer: Option<&Ed25519Signer>,
    anchor: Option<Hash>,
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

    // Only the latest checkpoint: its Merkle root commits to every earlier
    // one, and an anchor is tied to it by a consistency proof, not a walk.
    let mut checkpoints: Vec<(String, Vec<u8>)> = Vec::new();
    let mut pinned: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let checkpoint_tip = db.refs.checkpoint_get(head)?;
    let mut tip_cp = None;
    if let Some(h) = checkpoint_tip {
        let bytes = db.object_store.get_typed_bytes(CHECKPOINT_TAG, h)?;
        let cp: Checkpoint = from_cbor(&bytes)?;
        if let Some(t) = cp.query_tip {
            pinned.insert(t.to_string(), db.manifest_store.raw_manifest_bytes(t)?);
        }
        checkpoints.push((h.to_string(), bytes));
        tip_cp = Some(cp);
    }
    let mut anchor_entries: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(a) = anchor {
        let tip_cp = tip_cp
            .as_ref()
            .ok_or_else(|| anyhow!("head '{head}' has no checkpoint to anchor against"))?;
        let bytes = db.object_store.get_typed_bytes(CHECKPOINT_TAG, a)?;
        let acp: Checkpoint = from_cbor(&bytes)?;
        let old_count = usize::try_from(acp.sequence)?
            .checked_add(1)
            .ok_or_else(|| anyhow!("anchor {a}: sequence out of range"))?;
        let (old_root, new_root, proof) =
            CheckpointStore::new(db).prove_append_only(head, old_count)?;
        if acp.head != head || old_root != acp.log_root || new_root != tip_cp.log_root {
            bail!("anchor {a} is not in head '{head}''s checkpoint log");
        }
        anchor_entries.push((format!("anchor/{a}"), bytes));
        anchor_entries.push(("anchor_proof".into(), to_cbor(&proof)?));
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
    for (name, bytes) in pinned {
        entries.push((format!("pinned/{name}"), bytes));
    }
    entries.extend(anchor_entries);

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
    anchor: Option<Hash>,
) -> Result<(Vec<u8>, ExportSummary)> {
    // Stage inside the database, not the shared temp dir: a PID-derived name in
    // /tmp is guessable, so a local attacker could pre-create it as a symlink
    // and redirect the bundle (or read it) on a multi-user host. Keep the exact
    // atomic-write temp name, nothing appended, so `pack` excludes it from
    // backups and `cleanup_orphan_temps` reclaims it if we die mid-export.
    let dir = db.root.join("meta");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(crate::atomic::build_temp_name("export")?);
    let outcome = export_inner(db, head, from, to, &path, signer, anchor).and_then(|summary| {
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
    verify_inner(path, public_key, require_signature, None)
}

/// [`verify_bundle`], and check that the checkpoint `anchor` the auditor
/// retained is a prefix of the bundle's checkpoint log.
pub fn verify_bundle_anchored(
    path: &Path,
    public_key: Option<&str>,
    require_signature: bool,
    anchor: Hash,
) -> Result<VerifyReport> {
    verify_inner(path, public_key, require_signature, Some(anchor))
}

fn verify_inner(
    path: &Path,
    public_key: Option<&str>,
    require_signature: bool,
    anchor: Option<Hash>,
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

    // Latest checkpoint: hash, pinned record, signature, and that it pins a
    // commit inside the exported history.
    let mut checkpoints_signed = 0usize;
    let mut tip_cp: Option<Checkpoint> = None;
    if let Some(h) = &meta.checkpoint_tip {
        let bytes = entries
            .get(&format!("checkpoints/{h}"))
            .ok_or_else(|| anyhow!("checkpoint {h} bytes missing"))?;
        let claimed: Hash = h.parse()?;
        if hash_typed(CHECKPOINT_TAG, bytes) != claimed {
            bail!("checkpoint {h} bytes do not match its hash");
        }
        let cp: Checkpoint = from_cbor(bytes)?;
        if cp.head != meta.head || !reachable.contains(&cp.commit.to_string()) {
            bail!(
                "checkpoint {h} pins commit {} outside the exported history",
                cp.commit
            );
        }
        // Gaps only show between records; the pin shows a missing tail.
        if let Some(t) = cp.query_tip {
            let bytes = entries.get(&format!("pinned/{t}")).ok_or_else(|| {
                anyhow!("checkpoint {h} pins record {t}, whose bytes are missing")
            })?;
            if hash_typed(MANIFEST_TAG, bytes) != t {
                bail!("pinned record {t} bytes do not match its hash");
            }
            let qm = decode_query_manifest(bytes)
                .ok_or_else(|| anyhow!("pinned object {t} is not a QueryManifest"))?;
            if qm.executed_at >= meta.from
                && qm.executed_at <= meta.to
                && !recorded.contains(t.to_string().as_str())
            {
                bail!(
                    "checkpoint {h} pins retrieval record {t} (sequence {}), which the \
                     bundle omits: the record chain was truncated",
                    qm.seq
                );
            }
        }
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
        tip_cp = Some(cp);
    }

    // Anchor: the auditor's retained checkpoint must be a prefix of this log.
    if let Some(a) = anchor {
        let tip = tip_cp
            .as_ref()
            .ok_or_else(|| anyhow!("bundle carries no checkpoint to check anchor {a} against"))?;
        let bytes = entries
            .get(&format!("anchor/{a}"))
            .ok_or_else(|| anyhow!("bundle was not exported against anchor {a}"))?;
        if hash_typed(CHECKPOINT_TAG, bytes) != a {
            bail!("anchor {a} bytes do not match its hash");
        }
        let acp: Checkpoint = from_cbor(bytes)?;
        let proof: ConsistencyProof = from_cbor(
            entries
                .get("anchor_proof")
                .ok_or_else(|| anyhow!("anchor proof missing"))?,
        )?;
        let counts_match = u64::try_from(proof.old_count).ok() == acp.sequence.checked_add(1)
            && u64::try_from(proof.new_count).ok() == tip.sequence.checked_add(1);
        if acp.head != tip.head
            || !counts_match
            || !verify_append_only(acp.log_root, tip.log_root, &proof)
        {
            bail!(
                "anchor {a} is not a prefix of the bundle's checkpoint log: history was rewritten"
            );
        }
    }

    Ok(VerifyReport {
        retrievals: records.len(),
        from: meta.from,
        to: meta.to,
        head: meta.head,
        commits: reachable.len(),
        checkpoints: usize::from(tip_cp.is_some()),
        checkpoints_signed,
        log_size: tip_cp.as_ref().map_or(0, |c| c.sequence + 1),
        checkpoint_tip: meta.checkpoint_tip.clone(),
        anchored: anchor.is_some(),
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
                .search_semantic_unrecorded(commit, "retrieval corpus", 5, &SearchFilter::default())
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
    fn record_chain_continues_across_handles_and_unrelated_commits() {
        let (tmp, db, head) = db_with_audited_queries();
        let root = tmp.path().join("db");
        let a = Engine::open(&root).unwrap();
        let b = Engine::open(&root).unwrap();
        let commit = db.refs.head_get(&head).unwrap().unwrap();
        let record = |e: &Engine| {
            e.record_query_at_head(
                &head,
                commit,
                "semantic",
                Some("q"),
                None,
                5,
                &SearchFilter::default(),
                None,
                &[],
            )
            .unwrap()
        };
        // Each handle has its own tip cache; the chain must not fork.
        record(&a);
        record(&b);
        db.create_commit_at_head(&head, "t", "unrelated", vec![])
            .unwrap();
        record(&a);
        let (mut records, _) = collect(&db, &head, 0, u64::MAX).unwrap();
        records.sort_by_key(|r| r.seq);
        let seqs: Vec<u64> = records.iter().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![0, 1, 2, 3, 4, 5]);
        for w in records.windows(2) {
            assert_eq!(w[1].prev.as_deref(), Some(w[0].manifest.as_str()));
        }
    }

    #[test]
    fn concurrent_records_share_commits_and_stay_gapless() {
        let (tmp, db, head) = db_with_audited_queries();
        let engine = std::sync::Arc::new(Engine::open(tmp.path().join("db")).unwrap());
        let commit = db.refs.head_get(&head).unwrap().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        std::thread::scope(|s| {
            for t in 0..8 {
                let (engine, barrier, head) = (engine.clone(), barrier.clone(), head.clone());
                s.spawn(move || {
                    barrier.wait();
                    for _ in 0..5 {
                        let p = format!("t{t}");
                        let f = SearchFilter::default();
                        engine
                            .record_query_at_head(
                                &head,
                                commit,
                                "semantic",
                                Some("q"),
                                None,
                                5,
                                &f,
                                Some(&p),
                                &[],
                            )
                            .unwrap();
                    }
                });
            }
        });
        let (mut records, carrying) = collect(&db, &head, 0, u64::MAX).unwrap();
        records.sort_by_key(|r| r.seq);
        assert_eq!(records.len(), 43);
        assert!(records.iter().enumerate().all(|(i, r)| r.seq == i as u64));
        for w in records.windows(2) {
            assert_eq!(w[1].prev.as_deref(), Some(w[0].manifest.as_str()));
        }
        assert!(
            carrying.len() < records.len(),
            "concurrent records never batched"
        );
    }

    #[test]
    fn anchored_export_proves_the_log_only_grew() {
        let (tmp, db, head) = db_with_audited_queries();
        let store = CheckpointStore::new(&db);
        let anchor = store.create(&head, None).unwrap();
        db.create_commit_at_head(&head, "t", "later", vec![])
            .unwrap();
        let later = store.create(&head, None).unwrap();

        let out = tmp.path().join("anchored.nelaudit");
        export_anchored(&db, &head, 0, u64::MAX, &out, None, anchor).unwrap();
        let report = verify_bundle_anchored(&out, None, false, anchor).unwrap();
        assert!(report.anchored);
        assert_eq!(report.log_size, 2);
        assert_eq!(report.checkpoint_tip, Some(later.to_string()));

        // Wrong anchor, or a bundle exported without one, does not verify.
        assert!(verify_bundle_anchored(&out, None, false, later).is_err());
        let plain = tmp.path().join("plain.nelaudit");
        export(&db, &head, 0, u64::MAX, &plain, None).unwrap();
        verify_bundle(&plain, None, false).unwrap();
        assert!(verify_bundle_anchored(&plain, None, false, anchor).is_err());

        // A tampered consistency proof is caught even with a repaired footer.
        let (mut entries, _, _) = read_bundle(&out).unwrap();
        let mut proof: ConsistencyProof = from_cbor(&entries["anchor_proof"]).unwrap();
        proof.nodes.push(Hash::zero());
        entries.insert("anchor_proof".into(), to_cbor(&proof).unwrap());
        let forged = tmp.path().join("forged.nelaudit");
        let entries: Vec<(String, Vec<u8>)> = entries.into_iter().collect();
        fs::write(&forged, build_bundle(&entries, None)).unwrap();
        assert!(verify_bundle_anchored(&forged, None, false, anchor).is_err());

        // The exporter refuses an anchor from another log.
        let other_tmp = TempDir::new().unwrap();
        let other = other_tmp.path().join("db");
        Database::init(&other).unwrap();
        let other = Database::open(&other).unwrap();
        other
            .create_commit_at_head(&head, "t", "x", vec![])
            .unwrap();
        let foreign = CheckpointStore::new(&other).create(&head, None).unwrap();
        assert!(export_anchored(&db, &head, 0, u64::MAX, &out, None, foreign).is_err());
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

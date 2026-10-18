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
//! rest), `pinned/<hash>` (the retrieval record it pins), `edge/<hash>`
//! (the record before the window and every record from the window up to each
//! pin, so the window is provably complete), and for an anchored export
//! `anchor/<hash>` + `anchor_proof` (consistency from the anchor).
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
use crate::checkpoint::{
    Checkpoint, CheckpointStore, checkpoint_leaf, verify_append_only, verify_commit_logged,
};
use crate::commit::{COMMIT_TAG, Commit};
use crate::db::Database;
use crate::hash::{Hash, hash_typed};
use crate::manifest::{MANIFEST_TAG, QueryManifest};
use crate::merkle::{ConsistencyProof, MerkleLeaf, MerkleProof, prove_inclusion};
use crate::signing::{Ed25519Signer, Ed25519Verifier, sign_raw};

const BUNDLE_MAGIC: &[u8; 8] = b"NELAUDIT";
const BUNDLE_VERSION: u32 = 3;
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
    /// Carried commits whose own signature verified, and the keys that signed
    /// them; compare those keys with the principals you trust.
    pub commits_signed: usize,
    pub commit_keys: Vec<String>,
}

/// QueryManifest decode pinned by canonical round-trip, so other manifest
/// kinds cannot be misread as audit records.
fn decode_query_manifest(bytes: &[u8]) -> Option<QueryManifest> {
    let qm: QueryManifest = from_cbor(bytes).ok()?;
    (to_cbor(&qm).ok()? == bytes).then_some(qm)
}

/// Newest retrieval record on `head`: its hash, sequence number, and time.
/// The record ref is the chain's only pointer, so it cannot disagree with a
/// durable record.
pub fn query_tip(db: &Database, head: &str) -> Result<Option<(Hash, u64, u64)>> {
    let Some(tip) = db.refs.record_get(head)? else {
        return Ok(None);
    };
    let qm = decode_query_manifest(&db.manifest_store.raw_manifest_bytes(tip)?)
        .ok_or_else(|| anyhow!("record ref for '{head}' names a non-QueryManifest {tip}"))?;
    Ok(Some((tip, qm.seq, qm.executed_at)))
}

/// Every record on `head`'s chain, newest first.
fn chain(db: &Database, head: &str) -> Result<Vec<(Hash, QueryManifest)>> {
    let mut out = Vec::new();
    let mut cursor = db.refs.record_get(head)?;
    while let Some(m) = cursor {
        if out.len() >= MAX_WALK {
            bail!("record chain walk exceeded {MAX_WALK}");
        }
        let qm = decode_query_manifest(&db.manifest_store.raw_manifest_bytes(m)?)
            .ok_or_else(|| anyhow!("record chain of '{head}' reaches non-QueryManifest {m}"))?;
        cursor = qm.prev;
        out.push((m, qm));
    }
    Ok(out)
}

fn audit_record(m: Hash, qm: &QueryManifest) -> AuditRecord {
    AuditRecord {
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
    }
}

/// Records on `head` executed in `[from, to]` (unix seconds, inclusive),
/// newest first.
pub fn collect(db: &Database, head: &str, from: u64, to: u64) -> Result<Vec<AuditRecord>> {
    Ok(chain(db, head)?
        .iter()
        .filter(|(_, qm)| qm.executed_at >= from && qm.executed_at <= to)
        .map(|(m, qm)| audit_record(*m, qm))
        .collect())
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
    let all = chain(db, head)?;
    let records: Vec<AuditRecord> = all
        .iter()
        .filter(|(_, qm)| qm.executed_at >= from && qm.executed_at <= to)
        .map(|(m, qm)| audit_record(*m, qm))
        .collect();

    // Ancestry objects: full first-parent chain from tip, so the verifier can
    // place the latest checkpoint's commit in the exported history.
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
    let mut anchor_entries: Vec<(String, Vec<u8>)> = Vec::new();
    let checkpoint_tip = db.refs.checkpoint_get(head)?;
    let leaves: Vec<MerkleLeaf> = CheckpointStore::new(db)
        .logged_commits(head)?
        .into_iter()
        .map(checkpoint_leaf)
        .collect();
    // A checkpoint's commit must be the last leaf of its own log root;
    // otherwise the root could describe a log the chain never recorded.
    let self_inclusion = |cp: &Checkpoint| -> Result<Vec<u8>> {
        let index = usize::try_from(cp.sequence)?;
        let proof = leaves
            .get(..=index)
            .and_then(|l| prove_inclusion(l, index))
            .ok_or_else(|| anyhow!("checkpoint log shorter than sequence {index}"))?;
        to_cbor(&proof)
    };
    let mut tip_cp = None;
    if let Some(h) = checkpoint_tip {
        let bytes = db.object_store.get_typed_bytes(CHECKPOINT_TAG, h)?;
        let cp: Checkpoint = from_cbor(&bytes)?;
        if let Some(t) = cp.query_tip {
            pinned.insert(t.to_string(), db.manifest_store.raw_manifest_bytes(t)?);
        }
        anchor_entries.push(("checkpoint_inclusion".into(), self_inclusion(&cp)?));
        checkpoints.push((h.to_string(), bytes));
        tip_cp = Some(cp);
    }
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
        if let Some(t) = acp.query_tip {
            pinned.insert(t.to_string(), db.manifest_store.raw_manifest_bytes(t)?);
        }
        anchor_entries.push(("anchor_inclusion".into(), self_inclusion(&acp)?));
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
    for (name, bytes) in &pinned {
        entries.push((format!("pinned/{name}"), bytes.clone()));
    }
    entries.extend(anchor_entries);

    // Edges: the record before the window proves nothing older in the window
    // was dropped, and records from the window up to each pin tie the window
    // to the checkpoints, so neither end can be truncated.
    let pin_seq = pinned
        .values()
        .filter_map(|b| decode_query_manifest(b).map(|qm| qm.seq))
        .max();
    let window_end = all
        .iter()
        .filter(|(_, qm)| qm.executed_at <= to)
        .map(|(_, qm)| qm.seq)
        .max();
    let before_seq = all
        .iter()
        .filter(|(_, qm)| qm.executed_at < from)
        .map(|(_, qm)| qm.seq)
        .max();
    for (m, qm) in &all {
        let before = Some(qm.seq) == before_seq;
        let link = qm.executed_at > to
            && pin_seq.is_some_and(|p| qm.seq <= p)
            && window_end.is_none_or(|e| qm.seq > e);
        if before || link {
            entries.push((
                format!("edge/{m}"),
                db.manifest_store.raw_manifest_bytes(*m)?,
            ));
        }
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
    let mut commit_keys: Vec<String> = Vec::new();
    let mut manifest_objects: HashSet<String> = HashSet::new();
    for (name, bytes) in &entries {
        let Some(hex) = name.strip_prefix("objects/") else {
            continue;
        };
        let claimed: Hash = hex.parse()?;
        if hash_typed(COMMIT_TAG, bytes) == claimed {
            let commit: Commit = from_cbor(bytes)?;
            if let Some(key) = crate::signing::verify_commit_signature(&commit)
                .map_err(|e| anyhow!("commit {hex}: {e}"))?
            {
                commit_keys.push(key);
            }
            commits.insert(hex.to_string(), commit);
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

    // Retrieval chain: the window's records plus the edge records around it
    // must form one contiguous, prev-linked run with non-decreasing times.
    // The record before the window (or genesis) shows nothing older in the
    // window was dropped; the pin checks below show nothing newer was.
    struct Link {
        manifest: String,
        seq: u64,
        prev: Option<String>,
        executed_at: u64,
        in_window: bool,
    }
    let mut chain: Vec<Link> = records
        .iter()
        .map(|r| Link {
            manifest: r.manifest.clone(),
            seq: r.seq,
            prev: r.prev.clone(),
            executed_at: r.executed_at,
            in_window: true,
        })
        .collect();
    for (name, bytes) in &entries {
        let Some(hex) = name.strip_prefix("edge/") else {
            continue;
        };
        let claimed: Hash = hex.parse()?;
        if hash_typed(MANIFEST_TAG, bytes) != claimed {
            bail!("edge record {hex} bytes do not match its hash");
        }
        let qm = decode_query_manifest(bytes)
            .ok_or_else(|| anyhow!("edge object {hex} is not a QueryManifest"))?;
        if qm.executed_at >= meta.from && qm.executed_at <= meta.to {
            bail!("edge record {hex} lies inside the window but has no line in retrievals.jsonl");
        }
        chain.push(Link {
            manifest: hex.to_string(),
            seq: qm.seq,
            prev: qm.prev.map(|p| p.to_string()),
            executed_at: qm.executed_at,
            in_window: false,
        });
    }
    chain.sort_by_key(|l| l.seq);
    for pair in chain.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        if b.seq == a.seq {
            bail!("duplicate retrieval sequence {}", a.seq);
        }
        if b.seq != a.seq + 1 {
            bail!(
                "retrieval chain has a gap between sequence {} and {}: records were withheld \
                 from this bundle",
                a.seq,
                b.seq
            );
        }
        if b.prev.as_deref() != Some(a.manifest.as_str()) {
            bail!(
                "retrieval {} does not link to sequence {} ({})",
                b.seq,
                a.seq,
                a.manifest
            );
        }
        if b.executed_at < a.executed_at {
            bail!("retrieval {} is timestamped before its predecessor", b.seq);
        }
    }
    if let Some(first) = chain.first() {
        let genesis = first.seq == 0 && first.prev.is_none();
        let before_window = !first.in_window && first.executed_at < meta.from;
        if !genesis && !before_window {
            bail!(
                "retrieval chain starts at sequence {} without the record before the window: \
                 older records in the window may have been withheld",
                first.seq
            );
        }
    }
    let chain_seqs: HashMap<u64, &str> =
        chain.iter().map(|l| (l.seq, l.manifest.as_str())).collect();

    // A carried checkpoint is checked against its own log (its commit is the
    // last leaf of its root) and its pinned record against the record chain:
    // gaps only show between records, the pin shows a missing tail.
    let check_checkpoint = |name: &str, cp: &Checkpoint, inclusion: &str| -> Result<()> {
        let proof: MerkleProof = from_cbor(
            entries
                .get(inclusion)
                .ok_or_else(|| anyhow!("checkpoint {name}: log inclusion proof missing"))?,
        )?;
        if u64::try_from(proof.index).ok() != Some(cp.sequence)
            || u64::try_from(proof.leaf_count).ok() != cp.sequence.checked_add(1)
            || !verify_commit_logged(cp.log_root, cp.commit, &proof)
        {
            bail!("checkpoint {name}: its commit is not the last leaf of its log root");
        }
        if let Some(t) = cp.query_tip {
            let bytes = entries.get(&format!("pinned/{t}")).ok_or_else(|| {
                anyhow!("checkpoint {name} pins record {t}, whose bytes are missing")
            })?;
            if hash_typed(MANIFEST_TAG, bytes) != t {
                bail!("pinned record {t} bytes do not match its hash");
            }
            let qm = decode_query_manifest(bytes)
                .ok_or_else(|| anyhow!("pinned object {t} is not a QueryManifest"))?;
            // A pin before the carried run predates the window; any other pin
            // must be in the run, which ties every carried record to it.
            let predates = chain.first().is_some_and(|f| qm.seq < f.seq);
            if !predates && chain_seqs.get(&qm.seq) != Some(&t.to_string().as_str()) {
                bail!(
                    "checkpoint {name} pins retrieval record {t} (sequence {}), which the \
                     bundle's chain omits: the record chain was truncated or rewritten",
                    qm.seq
                );
            }
        }
        Ok(())
    };

    // Latest checkpoint: hash, own log, pin, signature, and that it pins a
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
        check_checkpoint(h, &cp, "checkpoint_inclusion")?;
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

    // Anchor: the auditor's retained checkpoint must be a prefix of this log,
    // and the record it pinned must still be in the chain, so no record at or
    // below the anchor's pin can be edited and re-chained.
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
        check_checkpoint(&a.to_string(), &acp, "anchor_inclusion")?;
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
        commits_signed: commit_keys.len(),
        commit_keys: commit_keys
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
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
        let mut records = collect(&db, &head, 0, u64::MAX).unwrap();
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
        let mut records = collect(&db, &head, 0, u64::MAX).unwrap();
        records.sort_by_key(|r| r.seq);
        assert_eq!(records.len(), 43);
        assert!(records.iter().enumerate().all(|(i, r)| r.seq == i as u64));
        for w in records.windows(2) {
            assert_eq!(w[1].prev.as_deref(), Some(w[0].manifest.as_str()));
        }
        // Records never touch data history, so chunk proofs stay O(writes).
        assert_eq!(db.refs.head_get(&head).unwrap(), Some(commit));
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
    fn checkpoint_root_must_end_in_its_own_commit() {
        let (tmp, db, head) = db_with_audited_queries();
        CheckpointStore::new(&db).create(&head, None).unwrap();
        let out = tmp.path().join("b.nelaudit");
        export(&db, &head, 0, u64::MAX, &out, None).unwrap();
        verify_bundle(&out, None, false).unwrap();

        // Forge a checkpoint whose root covers a log that does not end in its
        // commit, give it a valid hash, and point the bundle at it.
        let (mut entries, _, _) = read_bundle(&out).unwrap();
        let mut meta: BundleMeta = serde_json::from_slice(&entries["meta.json"]).unwrap();
        let old = meta.checkpoint_tip.clone().unwrap();
        let mut cp: Checkpoint = from_cbor(&entries[&format!("checkpoints/{old}")]).unwrap();
        cp.log_root = crate::merkle::root(&[checkpoint_leaf(Hash::zero())]);
        let bytes = to_cbor(&cp).unwrap();
        let forged = hash_typed(CHECKPOINT_TAG, &bytes).to_string();
        entries.remove(&format!("checkpoints/{old}"));
        entries.insert(format!("checkpoints/{forged}"), bytes);
        meta.checkpoint_tip = Some(forged);
        entries.insert(
            "meta.json".into(),
            serde_json::to_vec_pretty(&meta).unwrap(),
        );
        let path = tmp.path().join("forged.nelaudit");
        let entries: Vec<(String, Vec<u8>)> = entries.into_iter().collect();
        fs::write(&path, build_bundle(&entries, None)).unwrap();
        let err = verify_bundle(&path, None, false).unwrap_err().to_string();
        assert!(err.contains("last leaf"), "{err}");
    }

    #[test]
    fn collect_finds_records_in_period() {
        let (_tmp, db, head) = db_with_audited_queries();
        let records = collect(&db, &head, 0, u64::MAX).unwrap();
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|r| r.principal.is_some()));

        let none = collect(&db, &head, 1, 2).unwrap();
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

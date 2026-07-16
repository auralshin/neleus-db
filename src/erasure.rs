//! Subject-scoped erasure (GDPR right-to-erasure / storage limitation). Shreds a
//! data subject's content blobs while keeping the signed commitment chain intact:
//! the manifest hashes, commits, and checkpoints stay, so you can still prove an
//! event happened without revealing what it said.
//!
//! An erased blob is byte-identical to a tampered-away one. The signed
//! [`ErasureRecord`] is what makes the deletion *authorized* rather than tamper:
//! a missing blob covered by a valid record is legitimately erased; a missing
//! blob with no record is corruption. Records live in the hash-chained event log.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::canonical::{from_cbor, to_cbor};
use crate::db::Database;
use crate::engine::Engine;
use crate::hash::Hash;
use crate::manifest::{ChunkManifest, DocManifest, RunManifest};
use crate::signing::{Ed25519Signer, Ed25519Verifier, sign_raw};

pub const ERASURE_SCHEMA_VERSION: u32 = 1;
const MAX_WALK: usize = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErasureRecord {
    pub schema_version: u32,
    pub subject: String,
    /// Content blobs physically shredded.
    pub blobs: Vec<Hash>,
    /// `request` | `ttl` | `account-closure`.
    pub reason: String,
    /// `crypto-shred` (encryption on) | `physical` (encryption off).
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    pub erased_at: u64,
    /// ed25519 public key hex of the authorizer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// Hex ed25519 signature over the record with signature fields cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ErasureRecord {
    fn unsigned_bytes(&self) -> Vec<u8> {
        let mut bare = self.clone();
        bare.signed_by = None;
        bare.signature = None;
        serde_json::to_vec(&bare).expect("ErasureRecord serializes")
    }
}

pub struct EraseOptions<'a> {
    pub reason: &'a str,
    pub requested_by: Option<&'a str>,
    pub signer: Option<&'a Ed25519Signer>,
}

/// Erase a subject's content. Shreds blobs referenced *only* by that subject's
/// runs and documents (a blob shared with another subject — e.g. via dedup — is
/// kept), rebuilds the index if any shredded blob fed it, then appends a signed
/// record to the event log.
pub fn erase_subject(engine: &Engine, subject: &str, opts: EraseOptions) -> Result<ErasureRecord> {
    let db = engine.db();
    let scan = scan_subject_blobs(db, subject)?;
    let mut blobs: Vec<Hash> = scan.mine.difference(&scan.foreign).copied().collect();
    blobs.sort();

    let encrypted = db.config.encryption.as_ref().is_some_and(|e| e.enabled);
    let touched_index = blobs.iter().any(|b| scan.chunk_content.contains(b));
    db.blob_store.shred(&blobs, !encrypted)?;

    let mut record = ErasureRecord {
        schema_version: ERASURE_SCHEMA_VERSION,
        subject: subject.to_string(),
        blobs,
        reason: opts.reason.to_string(),
        method: if encrypted {
            "crypto-shred"
        } else {
            "physical"
        }
        .to_string(),
        requested_by: opts.requested_by.map(str::to_string),
        erased_at: crate::clock::now_unix()?,
        signed_by: None,
        signature: None,
    };
    if let Some(signer) = opts.signer {
        let sig = sign_raw(signer, &record.unsigned_bytes());
        record.signed_by = Some(signer.public_key_hex());
        record.signature = Some(hex::encode(sig));
    }
    // Record before reindexing: the rebuild reads shredded blobs and relies on
    // `covers()` (which reads this event) to skip them instead of erroring.
    crate::events::append(&db.root, "erasure", serde_json::to_value(&record)?)?;

    // Shredded chunk text/vectors still live as derived copies in index
    // segments; rebuild every head so they physically drop out.
    if touched_index {
        engine.reindex_all_heads()?;
    }
    Ok(record)
}

/// True if some recorded erasure covers `hash` — i.e. the blob is legitimately
/// gone, not tampered. Verifiers use this to accept a missing blob.
pub fn covers(db_root: &Path, hash: Hash) -> Result<bool> {
    let needle = hash.to_string();
    for e in crate::events::read(db_root)? {
        if e.kind != "erasure" {
            continue;
        }
        if let Some(blobs) = e.data.get("blobs").and_then(|b| b.as_array())
            && blobs.iter().any(|h| h.as_str() == Some(needle.as_str()))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Verify an erasure record's authorization signature against a known public key.
pub fn verify_record(record: &ErasureRecord, public_key_hex: &str) -> Result<()> {
    let sig = record
        .signature
        .as_ref()
        .ok_or_else(|| anyhow!("erasure record is unsigned"))?;
    let sig = hex::decode(sig).map_err(|_| anyhow!("erasure signature is not hex"))?;
    Ed25519Verifier::from_public_hex(public_key_hex)?.verify_raw(&record.unsigned_bytes(), &sig)
}

/// A run's own content blobs (PII). Excludes `retrieved_chunks`: those are
/// shared knowledge-base chunks, not the subject's data.
fn content_blobs(run: &RunManifest) -> Vec<Hash> {
    let mut v = vec![run.prompt];
    if let Some(h) = run.system_prompt {
        v.push(h);
    }
    v.extend(run.inputs.iter().copied());
    v.extend(run.outputs.iter().copied());
    v
}

fn decode_run_manifest(bytes: &[u8]) -> Option<RunManifest> {
    let rm: RunManifest = from_cbor(bytes).ok()?;
    (to_cbor(&rm).ok()? == bytes).then_some(rm)
}

fn decode_doc_manifest(bytes: &[u8]) -> Option<DocManifest> {
    let dm: DocManifest = from_cbor(bytes).ok()?;
    (to_cbor(&dm).ok()? == bytes).then_some(dm)
}

fn decode_chunk_manifest(bytes: &[u8]) -> Option<ChunkManifest> {
    let cm: ChunkManifest = from_cbor(bytes).ok()?;
    (to_cbor(&cm).ok()? == bytes).then_some(cm)
}

fn subject_of(meta: &Option<crate::manifest::ChunkMetadata>) -> Option<&str> {
    meta.as_ref().and_then(|m| m.subject.as_deref())
}

/// Subject blobs, partitioned for dedup-safe shredding.
#[derive(Default)]
struct Scan {
    /// This subject's content blobs.
    mine: HashSet<Hash>,
    /// Everyone else's content blobs; a blob here must not be shredded.
    foreign: HashSet<Hash>,
    /// Subset of `mine` that feeds the search index (chunk text/vectors), so
    /// the caller knows whether shredding requires an index rebuild.
    chunk_content: HashSet<Hash>,
}

/// Walk every head's history, partitioning the content blobs of runs, documents,
/// and standalone chunks into this subject's vs everyone else's.
fn scan_subject_blobs(db: &Database, subject: &str) -> Result<Scan> {
    let mut scan = Scan::default();
    let mut seen = HashSet::new();
    for (_, tip) in db.refs.list_heads()? {
        let mut cursor = Some(tip);
        let mut steps = 0usize;
        while let Some(c) = cursor {
            if !seen.insert(c) {
                break;
            }
            steps += 1;
            if steps > MAX_WALK {
                bail!("erasure walk exceeded {MAX_WALK} commits");
            }
            let commit = db.commit_store.get_commit(c)?;
            for &m in &commit.manifests {
                let Ok(bytes) = db.manifest_store.raw_manifest_bytes(m) else {
                    continue;
                };
                classify_manifest(&bytes, subject, &mut scan);
            }
            cursor = commit.parents.first().copied();
        }
    }
    Ok(scan)
}

fn classify_manifest(bytes: &[u8], subject: &str, scan: &mut Scan) {
    if let Some(run) = decode_run_manifest(bytes) {
        let mine = run.subject.as_deref() == Some(subject);
        for b in content_blobs(&run) {
            if mine {
                scan.mine.insert(b);
            } else {
                scan.foreign.insert(b);
            }
        }
        return;
    }
    if let Some(doc) = decode_doc_manifest(bytes) {
        let mine = subject_of(&doc.metadata) == Some(subject);
        let dest = if mine {
            &mut scan.mine
        } else {
            &mut scan.foreign
        };
        dest.insert(doc.original);
        for &chunk in &doc.chunks {
            dest.insert(chunk);
        }
        if mine {
            scan.chunk_content.extend(doc.chunks.iter().copied());
        }
        return;
    }
    if let Some(chunk) = decode_chunk_manifest(bytes) {
        let mine = subject_of(&chunk.metadata) == Some(subject);
        let blobs: Vec<Hash> = std::iter::once(chunk.chunk_text)
            .chain(chunk.embedding)
            .collect();
        if mine {
            scan.mine.extend(blobs.iter().copied());
            scan.chunk_content.extend(blobs);
        } else {
            scan.foreign.extend(blobs);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Engine;
    use crate::manifest::{MANIFEST_SCHEMA_VERSION, RunManifest};
    use crate::signing::generate_keypair_file;
    use tempfile::TempDir;

    fn run(subject: &str, prompt: Hash, out: Hash) -> RunManifest {
        RunManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            model: "m".into(),
            prompt,
            tool_calls: vec![],
            inputs: vec![],
            outputs: vec![out],
            started_at: 1,
            ended_at: 2,
            provider: None,
            system_prompt: None,
            model_parameters: None,
            retrieved_chunks: vec![],
            sdk_version: None,
            agent_id: None,
            trace_id: None,
            parent_span: None,
            delegated_from: None,
            subject: Some(subject.into()),
        }
    }

    #[test]
    fn erase_shreds_unique_blobs_keeps_shared() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();
        let db = engine.db();

        // `shared` is identical bytes for both subjects -> dedups to one blob.
        let shared = db.blob_store.put(b"shared prompt").unwrap();
        let a_out = db.blob_store.put(b"alice output").unwrap();
        let b_out = db.blob_store.put(b"bob output").unwrap();
        let ma = db
            .manifest_store
            .put_manifest(&run("alice", shared, a_out))
            .unwrap();
        let mb = db
            .manifest_store
            .put_manifest(&run("bob", shared, b_out))
            .unwrap();
        engine.commit("main", "t", "alice run", vec![ma]).unwrap();
        engine.commit("main", "t", "bob run", vec![mb]).unwrap();

        let rec = erase_subject(
            &engine,
            "alice",
            EraseOptions {
                reason: "request",
                requested_by: Some("dpo"),
                signer: None,
            },
        )
        .unwrap();

        assert!(
            !db.blob_store.exists(a_out),
            "alice's output must be shredded"
        );
        assert!(
            db.blob_store.exists(shared),
            "shared blob must survive (bob uses it)"
        );
        assert!(db.blob_store.exists(b_out), "bob's output is untouched");
        assert!(rec.blobs.contains(&a_out));
        assert!(!rec.blobs.contains(&shared));
        assert!(covers(&root, a_out).unwrap());
        assert!(!covers(&root, shared).unwrap());
    }

    #[test]
    fn erasure_record_signature_verifies() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();
        let db = engine.db();

        let prompt = db.blob_store.put(b"p").unwrap();
        let out = db.blob_store.put(b"o").unwrap();
        let m = db
            .manifest_store
            .put_manifest(&run("u1", prompt, out))
            .unwrap();
        engine.commit("main", "t", "run", vec![m]).unwrap();

        let key = tmp.path().join("erase.key");
        let pubhex = generate_keypair_file(&key).unwrap();
        let signer = Ed25519Signer::from_seed_file(&key).unwrap();

        let rec = erase_subject(
            &engine,
            "u1",
            EraseOptions {
                reason: "request",
                requested_by: None,
                signer: Some(&signer),
            },
        )
        .unwrap();

        verify_record(&rec, &pubhex).unwrap();
        let other = generate_keypair_file(&tmp.path().join("other.key")).unwrap();
        assert!(verify_record(&rec, &other).is_err());
    }

    #[test]
    fn erase_shreds_chunk_content_and_purges_index() {
        use crate::engine::SearchFilter;
        use crate::manifest::{ChunkMetadata, ChunkingSpec};

        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();

        let spec = || ChunkingSpec {
            method: "fixed".into(),
            chunk_size: 64,
            overlap: 0,
        };
        let meta = |s: &str| {
            Some(ChunkMetadata {
                subject: Some(s.into()),
                ..Default::default()
            })
        };

        let (adoc, _) = engine
            .put_document(
                "main",
                "kb",
                b"alice has a rare diabetes diagnosis",
                spec(),
                meta("alice"),
                "agent",
            )
            .unwrap();
        let (_, commit) = engine
            .put_document(
                "main",
                "kb",
                b"bob enjoys mountain hiking trips",
                spec(),
                meta("bob"),
                "agent",
            )
            .unwrap();
        let alice_chunk = engine
            .db()
            .manifest_store
            .get_doc_manifest(adoc)
            .unwrap()
            .chunks[0];

        // Before erasure: alice's chunk is indexed and retrievable.
        let hits = engine
            .search_hybrid(commit, Some("diabetes"), None, 5, &SearchFilter::default())
            .unwrap();
        assert!(
            hits.iter().any(|h| h.chunk_hash == alice_chunk),
            "alice indexed pre-erasure"
        );

        erase_subject(
            &engine,
            "alice",
            EraseOptions {
                reason: "request",
                requested_by: None,
                signer: None,
            },
        )
        .unwrap();

        assert!(
            !engine.db().blob_store.exists(alice_chunk),
            "alice's chunk shredded"
        );
        assert!(covers(&root, alice_chunk).unwrap());

        // Index purged: alice's term is gone; bob's content still searchable.
        let after = engine
            .search_hybrid(commit, Some("diabetes"), None, 5, &SearchFilter::default())
            .unwrap();
        assert!(
            after.iter().all(|h| h.chunk_hash != alice_chunk),
            "alice purged from index"
        );
        let bob = engine
            .search_hybrid(commit, Some("hiking"), None, 5, &SearchFilter::default())
            .unwrap();
        assert!(!bob.is_empty(), "bob's content survives erasure");
    }

    #[test]
    fn concurrent_reads_survive_erasure_reindex() {
        use crate::engine::SearchFilter;
        use crate::manifest::{ChunkMetadata, ChunkingSpec};

        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();

        let spec = || ChunkingSpec {
            method: "fixed".into(),
            chunk_size: 64,
            overlap: 0,
        };
        // Several subjects so the rebuild deletes and regenerates many segments.
        let mut u3_doc = None;
        for i in 0..8 {
            let body = format!("subject {i} keeps a unique medical record number {i}{i}{i}");
            let (doc, _) = engine
                .put_document(
                    "main",
                    "kb",
                    body.as_bytes(),
                    spec(),
                    Some(ChunkMetadata {
                        subject: Some(format!("u{i}")),
                        ..Default::default()
                    }),
                    "agent",
                )
                .unwrap();
            if i == 3 {
                u3_doc = Some(doc);
            }
        }
        let u3_chunk = engine
            .db()
            .manifest_store
            .get_doc_manifest(u3_doc.unwrap())
            .unwrap()
            .chunks[0];
        let commit = engine.resolve_commit("main").unwrap();
        engine
            .search_hybrid(commit, Some("record"), None, 5, &SearchFilter::default())
            .unwrap();

        // Readers hammer search while one thread erases a subject (deleting +
        // rebuilding every segment). The index gate must keep each read
        // consistent — never a mid-delete "missing CAS object".
        std::thread::scope(|s| {
            s.spawn(|| {
                erase_subject(
                    &engine,
                    "u3",
                    EraseOptions {
                        reason: "request",
                        requested_by: None,
                        signer: None,
                    },
                )
                .unwrap();
            });
            for _ in 0..4 {
                s.spawn(|| {
                    for _ in 0..150 {
                        engine
                            .search_hybrid(
                                commit,
                                Some("record"),
                                None,
                                5,
                                &SearchFilter::default(),
                            )
                            .expect("search during erasure must not error");
                    }
                });
            }
        });

        // u3's content is gone; the surviving subjects still serve.
        let after = engine
            .search_hybrid(commit, Some("record"), None, 20, &SearchFilter::default())
            .unwrap();
        assert!(!after.is_empty(), "surviving subjects still searchable");
        assert!(after.iter().all(|h| h.chunk_hash != u3_chunk), "u3 purged");
        assert!(
            !engine.db().blob_store.exists(u3_chunk),
            "u3's chunk shredded"
        );
    }
}

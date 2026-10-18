//! Adversarial evaluation: concrete attacks by an operator that controls
//! storage and serving code, against what verification actually detects.
//!
//! The security argument reduces to collision resistance and unforgeability,
//! so a bounded adversary cannot usefully attack the primitives. It attacks the
//! *system*: rewriting history, equivocating, withholding evidence, replaying
//! proofs out of context, or simply never recording anything.
//!
//! Every attack asserts its outcome, including the ones that succeed. An
//! undetected attack that later becomes detected will fail this suite, which is
//! the point: the gaps are pinned, not merely admitted.
//!
//! `cargo test --test adversarial -- --nocapture` prints the results table.

use std::sync::Mutex;

use neleus_db::checkpoint::{
    CheckpointStore, checkpoint_leaf, verify_append_only, verify_commit_logged,
};
use neleus_db::engine::{Engine, SearchFilter};
use neleus_db::hash::hash_typed;
use neleus_db::manifest::ChunkingSpec;
use neleus_db::merkle::{self, MerkleLeaf};
use neleus_db::retrieval_proof::{prove_chunk, verify_chunk_proof};
use neleus_db::{Database, Hash, audit};
use tempfile::TempDir;

/// One recorded attack outcome for the printed report. Correctness is asserted
/// in `record` against the expectation; only the display fields are kept here.
#[derive(Clone)]
struct Outcome {
    attack: &'static str,
    detected: bool,
    by: &'static str,
}

static RESULTS: Mutex<Vec<Outcome>> = Mutex::new(Vec::new());

fn record(attack: &'static str, detected: bool, expected: bool, by: &'static str) {
    assert_eq!(
        detected, expected,
        "attack '{attack}': detection changed (detected={detected}, expected={expected}). \
         If this is an improvement, update the expectation."
    );
    RESULTS.lock().unwrap().push(Outcome {
        attack,
        detected,
        by,
    });
}

fn spec() -> ChunkingSpec {
    ChunkingSpec {
        method: "fixed".into(),
        chunk_size: 64,
        overlap: 0,
    }
}

/// Interleave commits and checkpoints so each checkpoint pins a *distinct*
/// commit. Checkpointing a static head repeatedly makes every log leaf
/// identical, which silently makes index-binding attacks unfalsifiable.
fn history(engine: &Engine, n: usize) {
    let store = CheckpointStore::new(engine.db());
    for i in 0..n {
        engine
            .put_document(
                "main",
                "kb",
                format!("entry {i} with searchable content").as_bytes(),
                spec(),
                None,
                "agent",
            )
            .unwrap();
        store.create("main", None).unwrap();
    }
    let commits = store.logged_commits("main").unwrap();
    assert_eq!(commits.len(), n);
    let unique: std::collections::HashSet<_> = commits.iter().collect();
    assert_eq!(
        unique.len(),
        n,
        "each checkpoint must pin a distinct commit"
    );
}

fn fixture(commits: usize) -> (TempDir, Engine, Vec<Hash>) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let engine = Engine::open(&root).unwrap();
    let mut hashes = Vec::new();
    for i in 0..commits {
        let (_doc, c) = engine
            .put_document(
                "main",
                "kb",
                format!("record {i} with searchable content").as_bytes(),
                spec(),
                None,
                "agent",
            )
            .unwrap();
        hashes.push(c);
    }
    (tmp, engine, hashes)
}

// ---------------------------------------------------------------- history

/// A1. Claim a commit was checkpointed that never was, reusing a genuine proof.
#[test]
fn a1_forge_commit_into_anchored_log() {
    let (_t, engine, _c) = fixture(0);
    history(&engine, 6);
    let store = CheckpointStore::new(engine.db());
    let (root, proof) = store.prove_commit_logged("main", 3).unwrap();
    let real = store.logged_commits("main").unwrap()[3];
    assert!(verify_commit_logged(root, real, &proof));

    let forged = hash_typed(b"forged:", b"commit that was never checkpointed");
    let detected = !verify_commit_logged(root, forged, &proof);
    record(
        "Forge a commit into an anchored log",
        detected,
        true,
        "log root",
    );
}

/// A2. Move a genuine commit to a position it never occupied.
#[test]
fn a2_replay_proof_at_another_index() {
    let (_t, engine, _c) = fixture(0);
    history(&engine, 8);
    let store = CheckpointStore::new(engine.db());
    let (root, proof) = store.prove_commit_logged("main", 2).unwrap();
    let commits = store.logged_commits("main").unwrap();
    let mut moved = proof.clone();
    moved.index = 5;
    let detected = !verify_commit_logged(root, commits[2], &moved);
    record(
        "Replay a proof at another index",
        detected,
        true,
        "sealed index",
    );
}

/// A3. Rewrite history and present it as an append to an old anchor.
#[test]
fn a3_rewrite_history_below_anchor() {
    let (_t, engine, _c) = fixture(0);
    history(&engine, 8);
    let store = CheckpointStore::new(engine.db());
    let (honest_old, new_root, proof) = store.prove_append_only("main", 4).unwrap();
    assert!(verify_append_only(honest_old, new_root, &proof));

    // Same prefix length, different content.
    let commits = store.logged_commits("main").unwrap();
    let mut forged: Vec<MerkleLeaf> = commits[..4].iter().copied().map(checkpoint_leaf).collect();
    forged[1] = checkpoint_leaf(hash_typed(b"forged:", b"rewritten"));
    let detected = !verify_append_only(merkle::root(&forged), new_root, &proof);
    record(
        "Rewrite history below an anchor",
        detected,
        true,
        "consistency proof",
    );
}

/// A4. Truncate the log and claim the shorter history is the real one.
#[test]
fn a4_truncate_the_log() {
    let (_t, engine, _c) = fixture(0);
    history(&engine, 8);
    let store = CheckpointStore::new(engine.db());
    let commits = store.logged_commits("main").unwrap();
    let leaves: Vec<MerkleLeaf> = commits.iter().copied().map(checkpoint_leaf).collect();
    let full = merkle::root(&leaves);
    let truncated = merkle::root(&leaves[..5]);

    // A verifier holding the full root must reject the truncated one, and the
    // truncated log cannot prove the full root is a prefix of it.
    let backwards = merkle::prove_consistency(&leaves[..5], 5).unwrap();
    let detected = full != truncated && !verify_append_only(full, truncated, &backwards);
    record("Truncate the log", detected, true, "root mismatch");
}

/// A5. Show two divergent histories to two verifiers.
#[test]
fn a5_equivocate_between_verifiers() {
    let (_t, engine, _c) = fixture(0);
    history(&engine, 6);
    let store = CheckpointStore::new(engine.db());
    let commits = store.logged_commits("main").unwrap();
    let honest: Vec<MerkleLeaf> = commits.iter().copied().map(checkpoint_leaf).collect();
    let mut other = honest.clone();
    other[4] = checkpoint_leaf(hash_typed(b"forged:", b"alternate branch"));

    // Two verifiers comparing anchors see different roots at the same size.
    let detected = merkle::root(&honest) != merkle::root(&other);
    record(
        "Equivocate between verifiers",
        detected,
        true,
        "anchor comparison",
    );
}

// ---------------------------------------------------------------- evidence

/// A6. Delete a retrieval record from an exported bundle, repairing the
/// container so only the sequence gap betrays it.
#[test]
fn a6_withhold_a_record_from_a_bundle() {
    let (tmp, engine, _c) = fixture(1);
    let commit = engine.resolve_commit("main").unwrap();
    let filter = SearchFilter::default();
    for i in 0..5 {
        let hits = engine
            .search_semantic_unrecorded(commit, "searchable content", 5, &filter)
            .unwrap();
        engine
            .record_query_at_head(
                "main",
                commit,
                "semantic",
                Some("searchable content"),
                None,
                5,
                &filter,
                Some(&format!("agent-{i}")),
                &hits,
            )
            .unwrap();
    }
    let out = tmp.path().join("full.nelaudit");
    audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap();
    audit::verify_bundle(&out, None, false).unwrap();

    let records = audit::collect(engine.db(), "main", 0, u64::MAX).unwrap();
    let kept: Vec<String> = records
        .iter()
        .filter(|r| r.seq != 2)
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();
    let mut jsonl = kept.join("\n");
    jsonl.push('\n');
    let tampered = tmp.path().join("withheld.nelaudit");
    rebuild_bundle(&std::fs::read(&out).unwrap(), &jsonl, kept.len(), &tampered);

    let detected = audit::verify_bundle(&tampered, None, false).is_err();
    record(
        "Withhold a record from a bundle",
        detected,
        true,
        "sequence gap",
    );
}

/// A7. Serve a retrieval and simply never record it.
#[test]
fn a7_never_record_the_retrieval() {
    let (tmp, engine, _c) = fixture(1);
    let commit = engine.resolve_commit("main").unwrap();
    let filter = SearchFilter::default();
    // Ten retrievals actually served; none recorded.
    for _ in 0..10 {
        engine
            .search_semantic_unrecorded(commit, "searchable content", 5, &filter)
            .unwrap();
    }
    let out = tmp.path().join("silent.nelaudit");
    audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap();
    let report = audit::verify_bundle(&out, None, false).unwrap();

    // The bundle is internally perfect and describes nothing.
    let detected = report.retrievals != 0;
    record(
        "Serve retrievals, record none",
        detected,
        false,
        "NOT DETECTED: empty log is a valid log",
    );
}

// ---------------------------------------------------------------- proofs

/// A8. Substitute content into a chunk proof.
#[test]
fn a8_swap_chunk_content() {
    let (_t, engine, _c) = fixture(1);
    let commit = engine.resolve_commit("main").unwrap();
    let hits = engine
        .search_semantic_unrecorded(commit, "searchable content", 1, &SearchFilter::default())
        .unwrap();
    let mut proof = prove_chunk(engine.db(), commit, hits[0].chunk_hash, true).unwrap();
    assert!(verify_chunk_proof(&proof).is_ok());
    proof.chunk_bytes = Some(b"content the agent never retrieved".to_vec());
    let detected = verify_chunk_proof(&proof).is_err();
    record(
        "Swap content into a chunk proof",
        detected,
        true,
        "blob hash",
    );
}

/// A9. Graft a chunk proof's manifest-index path from another state onto the
/// queried commit, claiming a manifest that commit never introduced.
#[test]
fn a9_graft_chunk_state_path() {
    let (_t, engine, _c) = fixture(4);
    let commit = engine.resolve_commit("main").unwrap();
    let hits = engine
        .search_semantic_unrecorded(commit, "record 0", 5, &SearchFilter::default())
        .unwrap();
    let mut proof = prove_chunk(engine.db(), commit, hits[0].chunk_hash, false).unwrap();
    let elsewhere = engine.db().state_set_at_head("other", b"k", b"v").unwrap();
    proof.manifest_proof = engine
        .db()
        .state_store
        .proof(
            elsewhere,
            &neleus_db::db::manifest_index_key(proof.manifest_hash),
        )
        .unwrap();
    let detected = verify_chunk_proof(&proof).is_err();
    record(
        "Graft a chunk proof's state path",
        detected,
        true,
        "state root",
    );
}

/// A10. Replay a state proof against a state root it was not taken from.
#[test]
fn a10_replay_state_proof_across_roots() {
    let (_t, engine, _c) = fixture(1);
    let db = engine.db();
    let mut root = db.state_store.empty_root().unwrap();
    for i in 0..200u32 {
        root = db
            .state_store
            .set(root, format!("k{i:04}").as_bytes(), b"v")
            .unwrap();
    }
    let proof = db.state_store.proof(root, b"k0100").unwrap();
    assert!(proof.verify(root, b"k0100"));
    let moved = db.state_store.set(root, b"extra", b"v").unwrap();
    let detected = !proof.verify(moved, b"k0100");
    record(
        "Replay a state proof at another root",
        detected,
        true,
        "sealed root",
    );
}

/// A11. Claim a key is absent when it is present.
#[test]
fn a11_forge_non_membership() {
    let (_t, engine, _c) = fixture(1);
    let db = engine.db();
    let mut root = db.state_store.empty_root().unwrap();
    for i in 0..200u32 {
        root = db
            .state_store
            .set(root, format!("k{i:04}").as_bytes(), b"v")
            .unwrap();
    }
    let mut proof = db.state_store.proof(root, b"k0100").unwrap();
    proof.outcome = neleus_db::state::StateOutcome::Missing;
    let detected = !proof.verify(root, b"k0100");
    record(
        "Claim a present key is absent",
        detected,
        true,
        "leaf inspection",
    );
}

/// A12. Restore content to a proof whose subject exercised erasure.
#[test]
fn a12_reattach_erased_content() {
    use neleus_db::erasure::{EraseOptions, erase_subject};
    use neleus_db::manifest::ChunkMetadata;

    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("db");
    Database::init(&root).unwrap();
    let engine = Engine::open(&root).unwrap();
    let (doc, commit) = engine
        .put_document(
            "main",
            "kb",
            b"subject content to erase",
            spec(),
            Some(ChunkMetadata {
                subject: Some("u1".into()),
                ..Default::default()
            }),
            "agent",
        )
        .unwrap();
    let chunk = engine
        .db()
        .manifest_store
        .get_doc_manifest(doc)
        .unwrap()
        .chunks[0];
    erase_subject(
        &engine,
        "u1",
        EraseOptions {
            reason: "request",
            requested_by: None,
            signer: None,
        },
    )
    .unwrap();

    let mut proof = prove_chunk(engine.db(), commit, chunk, true).unwrap();
    assert!(proof.content_erased && verify_chunk_proof(&proof).is_ok());
    proof.chunk_bytes = Some(b"restored".to_vec());
    let detected = verify_chunk_proof(&proof).is_err();
    record("Reattach erased content", detected, true, "erasure flag");
}

// ---------------------------------------------------------------- report

/// Prints whatever attacks have reported so far. Correctness is asserted per
/// attack inside `record()` (before the shared lock is touched), so this test
/// carries no assertions and no cross-test ordering dependency — it only
/// snapshots and prints, never holding the lock across a panic.
#[test]
fn zz_report() {
    let mut rows = {
        let guard = RESULTS.lock().unwrap();
        guard.clone()
    };
    rows.sort_by_key(|r| r.attack);
    eprintln!("\n  ADVERSARIAL EVALUATION: operator controls storage and serving code");
    eprintln!("  {:<42} {:<10} by", "attack", "detected");
    eprintln!("  {}", "-".repeat(84));
    let (mut caught, mut missed) = (0, 0);
    for r in rows.iter() {
        if r.detected {
            caught += 1
        } else {
            missed += 1
        }
        eprintln!(
            "  {:<42} {:<10} {}",
            r.attack,
            if r.detected { "yes" } else { "NO" },
            r.by
        );
    }
    eprintln!("  {}", "-".repeat(84));
    eprintln!(
        "  {caught} detected, {missed} undetected (of {} reported)\n",
        rows.len()
    );
}

/// Re-emit a bundle with a shortened `retrievals.jsonl`, a corrected count in
/// `meta.json`, and a recomputed integrity footer, so nothing is inconsistent
/// except the missing sequence number.
fn rebuild_bundle(raw: &[u8], jsonl: &str, count: usize, out: &std::path::Path) {
    let mut entries = parse_bundle(raw);
    set_records(&mut entries, jsonl, count);
    write_bundle(&entries, out);
}

fn parse_bundle(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
    let n = u32::from_le_bytes(raw[12..16].try_into().unwrap()) as usize;
    let mut p = 16usize;
    let mut entries = Vec::new();
    for _ in 0..n {
        let nl = u32::from_le_bytes(raw[p..p + 4].try_into().unwrap()) as usize;
        p += 4;
        let name = String::from_utf8(raw[p..p + nl].to_vec()).unwrap();
        p += nl;
        let dl = u64::from_le_bytes(raw[p..p + 8].try_into().unwrap()) as usize;
        p += 8;
        entries.push((name, raw[p..p + dl].to_vec()));
        p += dl;
    }
    entries
}

/// Replace the record index and its declared count, as an exporter would.
fn set_records(entries: &mut [(String, Vec<u8>)], jsonl: &str, count: usize) {
    for (name, data) in entries.iter_mut() {
        if name == "retrievals.jsonl" {
            *data = jsonl.as_bytes().to_vec();
        } else if name == "meta.json" {
            let mut v: serde_json::Value = serde_json::from_slice(data).unwrap();
            v["retrievals"] = serde_json::json!(count);
            *data = serde_json::to_vec_pretty(&v).unwrap();
        }
    }
}

/// Serialize with a freshly computed footer: unsigned bundles are repairable.
fn write_bundle(entries: &[(String, Vec<u8>)], out: &std::path::Path) {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"NELAUDIT");
    buf.extend_from_slice(&3u32.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (name, data) in entries {
        buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
        buf.extend_from_slice(data);
    }
    let footer = blake3::hash(&buf);
    buf.extend_from_slice(footer.as_bytes());
    std::fs::write(out, &buf).unwrap();
}

// ---------------------------------------------------------------- injection

/// Seeded random tampering by an exporter that repairs every container-level
/// check it can (footer, declared count, orphaned manifest objects), against
/// an untouched control. `--nocapture` prints detection per class.
#[test]
fn tamper_injection_trials() {
    use neleus_db::audit::AuditRecord;
    use neleus_db::canonical::{from_cbor, to_cbor};
    use neleus_db::manifest::{MANIFEST_TAG, QueryManifest};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    const TRIALS: usize = 200;
    const RECORDS: usize = 20;
    // Written after the last checkpoint, so no anchor covers them.
    const UNANCHORED: usize = 5;

    let (tmp, engine, _c) = fixture(1);
    let commit = engine.resolve_commit("main").unwrap();
    let filter = SearchFilter::default();
    let mut anchor = None;
    for i in 0..RECORDS + UNANCHORED {
        if i == RECORDS {
            anchor = Some(
                CheckpointStore::new(engine.db())
                    .create("main", None)
                    .unwrap(),
            );
        }
        let hits = engine
            .search_semantic_unrecorded(commit, "searchable content", 5, &filter)
            .unwrap();
        engine
            .record_query_at_head(
                "main",
                commit,
                "semantic",
                Some("searchable content"),
                None,
                5,
                &filter,
                Some(&format!("agent-{i}")),
                &hits,
            )
            .unwrap();
    }
    // The auditor retained this checkpoint; without an anchor an exporter can
    // forge the latest checkpoint too, so every trial verifies against it.
    let anchor = anchor.unwrap();
    let out = tmp.path().join("base.nelaudit");
    audit::export_anchored(engine.db(), "main", 0, u64::MAX, &out, None, anchor).unwrap();
    let base = parse_bundle(&std::fs::read(&out).unwrap());
    let base_records: Vec<AuditRecord> = base
        .iter()
        .find(|(n, _)| n == "retrievals.jsonl")
        .map(|(_, d)| {
            String::from_utf8_lossy(d)
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        })
        .unwrap();
    assert_eq!(base_records.len(), RECORDS + UNANCHORED);
    assert!(base_records.iter().all(|r| !r.hits.is_empty()));

    let drop_object = |entries: &mut Vec<(String, Vec<u8>)>, manifest: &str| {
        let name = format!("objects/{manifest}");
        entries.retain(|(n, _)| *n != name);
    };
    // Edit the record at `from` and re-hash and re-link every record above it,
    // as an operator controlling the store can.
    let rechain = |entries: &mut Vec<(String, Vec<u8>)>, recs: &mut [AuditRecord], from: u64| {
        let mut order: Vec<usize> = (0..recs.len()).collect();
        order.sort_by_key(|&k| recs[k].seq);
        let mut prev: Option<String> = None;
        for k in order {
            let r = &mut recs[k];
            if r.seq < from {
                prev = Some(r.manifest.clone());
                continue;
            }
            let name = format!("objects/{}", r.manifest);
            let bytes = entries.iter().find(|(n, _)| *n == name).unwrap().1.clone();
            let mut qm: QueryManifest = from_cbor(&bytes).unwrap();
            if r.seq == from {
                qm.principal = Some("forged".into());
            }
            qm.prev = prev.as_ref().map(|p| p.parse::<Hash>().unwrap());
            let forged = to_cbor(&qm).unwrap();
            let hash = hash_typed(MANIFEST_TAG, &forged).to_string();
            entries.retain(|(n, _)| *n != name);
            entries.push((format!("objects/{hash}"), forged));
            r.manifest = hash.clone();
            r.principal = qm.principal.clone();
            r.prev = prev.clone();
            prev = Some(hash);
        }
    };

    // (class, expected detections out of TRIALS)
    let classes = [
        ("control (no change)", 0),
        ("edit a record line", TRIALS),
        ("re-forge a manifest at or below the pin", TRIALS),
        ("drop a middle record", TRIALS),
        ("drop the oldest records", TRIALS),
        ("truncate from an anchored record", TRIALS),
        // NOT DETECTED: no anchor covers records after the last checkpoint.
        ("truncate unanchored records only", 0),
        ("edit and re-chain at or below the pin", TRIALS),
        // NOT DETECTED: re-chaining above the anchor's pin leaves it intact.
        ("edit and re-chain after the checkpoint", 0),
        ("duplicate a record", TRIALS),
        ("swap two sequence numbers", TRIALS),
    ];
    let mut rng = StdRng::seed_from_u64(7);
    let path = tmp.path().join("trial.nelaudit");
    println!(
        "\n  TAMPER INJECTION (coverage of a deterministic verifier): {TRIALS} seeded \
         trials per class, {} records ({UNANCHORED} after the anchored checkpoint)",
        RECORDS + UNANCHORED
    );
    println!("  {:<40} {:>9}", "class", "detected");
    for (class, expected) in classes {
        let mut detected = 0;
        for _ in 0..TRIALS {
            let mut entries = base.clone();
            let mut recs = base_records.clone();
            let i = rng.gen_range(0..recs.len());
            match class {
                "edit a record line" => match rng.gen_range(0..5) {
                    0 => recs[i].principal = Some("forged".into()),
                    1 => recs[i].top_k += 1,
                    2 => recs[i].executed_at -= 1,
                    3 => recs[i].hits[0].score_micro += 1,
                    _ => recs[i].mode = "vector".into(),
                },
                "re-forge a manifest at or below the pin" => {
                    // Above the pin, the newest record has no successor to
                    // break; that case is "edit and re-chain after".
                    let seq = rng.gen_range(0..RECORDS as u64);
                    let i = recs.iter().position(|r| r.seq == seq).unwrap();
                    let old = recs[i].manifest.clone();
                    let name = format!("objects/{old}");
                    let bytes = &entries.iter().find(|(n, _)| *n == name).unwrap().1;
                    let mut qm: QueryManifest = from_cbor(bytes).unwrap();
                    qm.principal = Some("forged".into());
                    let forged = to_cbor(&qm).unwrap();
                    let hash = hash_typed(MANIFEST_TAG, &forged).to_string();
                    drop_object(&mut entries, &old);
                    entries.push((format!("objects/{hash}"), forged));
                    recs[i].manifest = hash;
                    recs[i].principal = Some("forged".into());
                }
                "drop a middle record" => {
                    let i = rng.gen_range(1..recs.len() - 1);
                    let r = recs.remove(i);
                    drop_object(&mut entries, &r.manifest);
                }
                "drop the oldest records" => {
                    let to = rng.gen_range(1..(RECORDS + UNANCHORED) as u64);
                    for r in recs.iter().filter(|r| r.seq < to) {
                        drop_object(&mut entries, &r.manifest);
                    }
                    recs.retain(|r| r.seq >= to);
                }
                "truncate from an anchored record" | "truncate unanchored records only" => {
                    let from = if class.starts_with("truncate from") {
                        rng.gen_range(1..RECORDS as u64)
                    } else {
                        rng.gen_range(RECORDS as u64..(RECORDS + UNANCHORED) as u64)
                    };
                    for r in recs.iter().filter(|r| r.seq >= from) {
                        drop_object(&mut entries, &r.manifest);
                    }
                    recs.retain(|r| r.seq < from);
                }
                "edit and re-chain at or below the pin" => {
                    rechain(&mut entries, &mut recs, rng.gen_range(0..RECORDS as u64));
                }
                "edit and re-chain after the checkpoint" => {
                    let from = rng.gen_range(RECORDS as u64..(RECORDS + UNANCHORED) as u64);
                    rechain(&mut entries, &mut recs, from);
                }
                "duplicate a record" => recs.push(recs[i].clone()),
                "swap two sequence numbers" => {
                    let j = (i + rng.gen_range(1..recs.len())) % recs.len();
                    let (a, b) = (recs[i].seq, recs[j].seq);
                    recs[i].seq = b;
                    recs[j].seq = a;
                }
                _ => {}
            }
            let mut jsonl: String = recs
                .iter()
                .map(|r| serde_json::to_string(r).unwrap() + "\n")
                .collect();
            if jsonl.is_empty() {
                jsonl.push('\n');
            }
            set_records(&mut entries, &jsonl, recs.len());
            write_bundle(&entries, &path);
            let accepted = audit::verify_bundle_anchored(&path, None, false, anchor).is_ok();
            if !accepted {
                detected += 1;
            }
        }
        println!("  {class:<40} {detected:>5}/{TRIALS}");
        assert_eq!(detected, expected, "{class}");
    }
}

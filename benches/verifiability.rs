//! Experiments backing the verifiability claims: checkpoint-chain scaling,
//! cold (auditor-side) verification cost, audit-bundle growth, and the BM25
//! cross-tenant statistics channel. Run: cargo bench --bench verifiability
//!
//! Measurements print to stderr with a `[q<N>]` tag; criterion timings cover
//! the paths that sit on an auditor's critical path.

mod common;

use std::process::Command;
use std::time::Instant;

use criterion::{Criterion, criterion_group, criterion_main};
use neleus_db::audit;
use neleus_db::canonical::to_cbor;
use neleus_db::checkpoint::{self, CheckpointStore};
use neleus_db::db::Database;
use neleus_db::engine::segment::{ChunkInput, IndexSegment};
use neleus_db::engine::{Engine, SearchFilter};
use neleus_db::hash::hash_typed;
use neleus_db::manifest::{ChunkMetadata, ChunkingSpec};
use tempfile::TempDir;

// ---------------------------------------------------------------- Q2
// Checkpoint chains are linear, so verification is O(J). Measure the
// constant and locate the length at which it stops being free.

fn q2_checkpoint_chain(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("db");
    common::init_db(&root);
    let db = Database::open(&root).unwrap();
    db.create_commit_at_head("main", "bench", "base", vec![])
        .unwrap();
    let store = CheckpointStore::new(&db);

    let mut group = c.benchmark_group("q2_checkpoint_chain_verify");
    let mut built = 0usize;
    for &target in &[1usize, 10, 100, 1_000, 10_000] {
        // Chains are append-only: extend rather than rebuild.
        let start = Instant::now();
        while built < target {
            store.create("main", None).unwrap();
            built += 1;
        }
        let build = start.elapsed();

        let report = store.verify_chain("main", None, false).unwrap();
        assert_eq!(report.length as usize, target);

        let start = Instant::now();
        let reps = if target >= 1_000 { 5 } else { 50 };
        for _ in 0..reps {
            store.verify_chain("main", None, false).unwrap();
        }
        let per = start.elapsed() / reps;
        eprintln!(
            "[q2] J={target:>6}: verify {per:>12.3?} ({:>8.3?}/checkpoint), append {build:?}",
            per / target as u32
        );
        group.bench_function(format!("J={target}"), |b| {
            b.iter(|| store.verify_chain("main", None, false).unwrap())
        });
    }
    group.finish();

    // The Merkle root answers the same questions in O(log J), without the walk.
    let (root, incl) = store.prove_commit_logged("main", 0).unwrap();
    let logged = store.logged_commits("main").unwrap()[0];
    let (old, new, cons) = store.prove_append_only("main", built / 2).unwrap();
    let reps = 10_000u32;
    let start = Instant::now();
    for _ in 0..reps {
        assert!(checkpoint::verify_commit_logged(root, logged, &incl));
    }
    let incl_t = start.elapsed() / reps;
    let start = Instant::now();
    for _ in 0..reps {
        assert!(checkpoint::verify_append_only(old, new, &cons));
    }
    let cons_t = start.elapsed() / reps;
    eprintln!(
        "[q2] J={built}: inclusion proof {} B verify {incl_t:?}; consistency proof ({} -> {built}) {} B verify {cons_t:?}",
        to_cbor(&incl).unwrap().len(),
        built / 2,
        to_cbor(&cons).unwrap().len(),
    );
}

// ---------------------------------------------------------------- Q3/Q4
// The auditor's real cost: a cold process verifying a bundle it was handed,
// with no database and no warm cache. Also the O(R) growth curve the paper
// previously reported only as a single point.

fn build_bundle(dir: &std::path::Path, retrievals: usize) -> (std::path::PathBuf, u64) {
    let root = dir.join(format!("db{retrievals}"));
    common::init_db(&root);
    let engine = Engine::open(&root).unwrap();
    let text = "agent context retrieval memory vector index commit proof merkle search ".repeat(64);
    let (_doc, commit) = engine
        .put_document(
            "main",
            "corpus",
            text.as_bytes(),
            ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 64,
                overlap: 0,
            },
            None,
            "bench",
        )
        .unwrap();
    let filter = SearchFilter::default();
    for _ in 0..retrievals {
        let hits = engine
            .search_semantic_unrecorded(commit, "vector retrieval proof", 10, &filter)
            .unwrap();
        // Sequence-chained: identical retrievals would otherwise be one
        // content-addressed object, collapsing the R-scaling measurement.
        engine
            .record_query_at_head(
                "main",
                commit,
                "semantic",
                Some("vector retrieval proof"),
                None,
                10,
                &filter,
                Some("auditor-bench"),
                &hits,
            )
            .unwrap();
    }
    let out = dir.join(format!("bundle-{retrievals}.nelaudit"));
    let summary = audit::export(engine.db(), "main", 0, u64::MAX, &out, None).unwrap();
    (out, summary.bytes)
}

fn q3_q4_auditor(c: &mut Criterion) {
    let dir = TempDir::new().unwrap();

    // Bundle growth in the retrieval count.
    eprintln!("[q4] bundle growth (unsigned):");
    let mut sizes = Vec::new();
    for &r in &[1usize, 8, 64, 512] {
        let (path, bytes) = build_bundle(dir.path(), r);
        let start = Instant::now();
        let reps = 20;
        for _ in 0..reps {
            audit::verify_bundle(&path, None, false).unwrap();
        }
        let verify = start.elapsed() / reps;
        eprintln!(
            "[q4] R={r:>4}: {bytes:>9} B ({:>6.1} B/retrieval), in-process verify {verify:>10.3?} ({:>8.3?}/retrieval)",
            bytes as f64 / r as f64,
            verify / r as u32
        );
        sizes.push((r, path, bytes, verify));
    }

    // Q3: cold auditor. Spawn the standalone verifier as a fresh process, so
    // the number includes process start, dynamic linking, file read and
    // verification -- everything the auditor actually pays.
    let verifier = option_env!("CARGO_BIN_EXE_neleus-verify");
    match verifier {
        Some(bin) => {
            for (r, path, bytes, in_proc) in &sizes {
                let reps = 20;
                let start = Instant::now();
                for _ in 0..reps {
                    let status = Command::new(bin)
                        .arg(path)
                        .arg("--json")
                        .output()
                        .expect("spawn neleus-verify");
                    assert!(status.status.success(), "verifier rejected a valid bundle");
                }
                let cold = start.elapsed() / reps;
                eprintln!(
                    "[q3] R={r:>4} ({bytes} B): cold standalone verify {cold:>10.3?} \
                     (in-process {in_proc:>10.3?}; process overhead {:>10.3?})",
                    cold.saturating_sub(*in_proc)
                );
            }
        }
        None => eprintln!("[q3] CARGO_BIN_EXE_neleus-verify unset; skipped cold-process run"),
    }

    // Q3: cold *state* proof -- a freshly opened database with empty caches,
    // versus the warm path the paper previously reported.
    {
        let root = dir.path().join("state");
        common::init_db(&root);
        let db = Database::open(&root).unwrap();
        let mut sroot = db.state_store.empty_root().unwrap();
        for i in 0..1000u32 {
            sroot = db
                .state_store
                .set(sroot, format!("key_{i:05}").as_bytes(), b"v")
                .unwrap();
        }
        let proof = db.state_store.proof(sroot, b"key_00042").unwrap();
        let proof_bytes = to_cbor(&proof).unwrap().len();

        // Warm: caches populated by the writes above.
        let start = Instant::now();
        for _ in 0..1000 {
            assert!(db.state_store.verify_proof(sroot, b"key_00042", &proof));
        }
        let warm = start.elapsed() / 1000;

        // Cold: a brand-new handle, so node/manifest caches start empty. Each
        // iteration reopens to keep the first-touch cost in the measurement.
        let start = Instant::now();
        let reps = 200;
        for _ in 0..reps {
            let fresh = Database::open(&root).unwrap();
            assert!(fresh.state_store.verify_proof(sroot, b"key_00042", &proof));
        }
        let cold = start.elapsed() / reps;

        // Store-free: decode the proof bytes and verify; no database is opened.
        let bytes = to_cbor(&proof).unwrap();
        let start = Instant::now();
        for _ in 0..reps {
            let p: neleus_db::state::StateProof = neleus_db::canonical::from_cbor(&bytes).unwrap();
            assert!(p.verify(sroot, b"key_00042"));
        }
        let offline = start.elapsed() / reps;
        eprintln!(
            "[q3] state proof ({proof_bytes} B, 1000 keys): warm verify {warm:?}, \
             cold verify (reopened db) {cold:?}, store-free decode+verify {offline:?}"
        );
    }

    // Proof size depends on the tree shape, which each database's secret
    // keys: report the spread over fresh databases, not one sample.
    {
        let mut sizes: Vec<(usize, usize)> = (0..20)
            .map(|i| {
                let root = dir.path().join(format!("shape{i}"));
                common::init_db(&root);
                let db = Database::open(&root).unwrap();
                let mut sroot = db.state_store.empty_root().unwrap();
                let keys: Vec<Vec<u8>> = (0..1000u32)
                    .map(|k| format!("key_{k:05}").into_bytes())
                    .collect();
                let pairs: Vec<(&[u8], &[u8])> =
                    keys.iter().map(|k| (k.as_slice(), &b"v"[..])).collect();
                sroot = db.state_store.set_many(sroot, &pairs).unwrap();
                let proof = db.state_store.proof(sroot, b"key_00042").unwrap();
                (to_cbor(&proof).unwrap().len(), proof.path.len())
            })
            .collect();
        sizes.sort();
        eprintln!(
            "[q3] state proof over 20 databases (1000 keys): min {} B, median {} B, max {} B; \
             depth {}-{}",
            sizes[0].0,
            sizes[10].0,
            sizes[19].0,
            sizes.iter().map(|s| s.1).min().unwrap(),
            sizes.iter().map(|s| s.1).max().unwrap()
        );
    }

    // Signed bundle: the footer signature and the checkpoint signature are
    // checked against the auditor's public key.
    {
        let key = dir.path().join("audit.key");
        let public = neleus_db::signing::generate_keypair_file(&key).unwrap();
        let signer = neleus_db::signing::Ed25519Signer::from_seed_file(&key).unwrap();
        let path = sizes.iter().find(|s| s.0 == 64).unwrap().1.clone();
        let db = Database::open(dir.path().join("db64")).unwrap();
        CheckpointStore::new(&db)
            .create("main", Some(&signer))
            .unwrap();
        let signed = dir.path().join("signed.nelaudit");
        audit::export(&db, "main", 0, u64::MAX, &signed, Some(&signer)).unwrap();
        let reps = 50;
        let start = Instant::now();
        for _ in 0..reps {
            audit::verify_bundle(&signed, Some(&public), true).unwrap();
        }
        let signed_t = start.elapsed() / reps;
        let start = Instant::now();
        for _ in 0..reps {
            audit::verify_bundle(&path, None, false).unwrap();
        }
        eprintln!(
            "[q4] R=64 signed bundle ({} B): verify with key {signed_t:?} (unsigned {:?})",
            std::fs::metadata(&signed).unwrap().len(),
            start.elapsed() / reps
        );
    }

    let mut group = c.benchmark_group("q3_auditor_verify");
    for (r, path, _, _) in &sizes {
        group.bench_function(format!("in_process_R={r}"), |b| {
            b.iter(|| audit::verify_bundle(path, None, false).unwrap())
        });
    }
    group.finish();
}

// ---------------------------------------------------------------- Q5
// BM25 collection statistics are segment-global: document frequency and
// collection size are computed over every chunk, including chunks the caller
// is forbidden to see. Measure what a tenant can infer from its own scores.

fn q5_idf_leakage(_c: &mut Criterion) {
    let mine = ChunkMetadata {
        tenant: Some("attacker".into()),
        ..Default::default()
    };
    let theirs = ChunkMetadata {
        tenant: Some("victim".into()),
        ..Default::default()
    };
    let filter = SearchFilter {
        tenant: Some("attacker".into()),
        ..Default::default()
    };

    // One probe document owned by the attacker, containing the probe term.
    let probe = |i: usize, text: &str, meta: ChunkMetadata| ChunkInput {
        chunk_hash: hash_typed(b"q5:", format!("{i}").as_bytes()),
        text: text.to_string(),
        embedding: None,
        meta: Some(meta),
    };

    // Historical: with segment-global collection statistics the attacker's own
    // score was strictly monotone in the hidden count, so inverting BM25 gave
    // exact recovery of another tenant's per-term document frequency. Scoring
    // statistics are now partition-scoped; this measures that the channel is
    // closed rather than merely narrowed.
    eprintln!("[q5] attacker sees ONLY its own document; victim docs are filtered pre-scoring");
    let mut observed = Vec::new();
    for victim_docs in [0usize, 1, 2, 5, 10, 25, 50, 100, 250, 500] {
        for (label, victim_text) in [
            ("with-term", "secret probe term"),
            ("no-term", "unrelated filler words"),
        ] {
            let mut inputs = vec![probe(0, "secret probe term", mine.clone())];
            for j in 0..victim_docs {
                inputs.push(probe(1000 + j, victim_text, theirs.clone()));
            }
            let seg = IndexSegment::build(vec![], inputs);
            let hits = seg.bm25("probe", 10, &filter);
            assert_eq!(hits.len(), 1, "filter must hide every victim document");
            observed.push((victim_docs, label, hits[0].score));
        }
    }

    let distinct: std::collections::BTreeSet<u32> =
        observed.iter().map(|(_, _, s)| s.to_bits()).collect();
    for (n, label, score) in &observed {
        eprintln!(
            "[q5]   hidden victim docs = {n:>4} ({label:>9}) -> attacker's score = {score:.9}"
        );
    }
    eprintln!(
        "[q5] {} probes -> {} distinct observable score(s); 1 means the hidden \
         corpus is unobservable",
        observed.len(),
        distinct.len()
    );
    assert_eq!(
        distinct.len(),
        1,
        "cross-tenant statistics channel is open: the attacker's own score \
         varies with documents it cannot see"
    );

    // A term occurring only in hidden documents must look exactly like a term
    // that does not occur at all.
    let mut inputs = vec![probe(0, "alpha", mine.clone())];
    inputs.push(probe(9000, "confidential", theirs.clone()));
    let seg = IndexSegment::build(vec![], inputs);
    assert!(seg.bm25("confidential", 10, &filter).is_empty());
    assert!(seg.bm25("nonexistentword", 10, &filter).is_empty());
    eprintln!(
        "[q5] a term present only in hidden documents is indistinguishable from an absent one"
    );
}

// ---------------------------------------------------------------- Q4b/Q5b
// Chunk-proof size must not grow with recorded searches (records live off the
// data head), and a tenant's filtered BM25 time against others' corpus size.

fn q4b_q5b_scaling(_c: &mut Criterion) {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("db");
    common::init_db(&root);
    let engine = Engine::open(&root).unwrap();
    let (_doc, commit) = engine
        .put_document(
            "main",
            "kb",
            b"agent memory chunk that a proof will cover",
            ChunkingSpec {
                method: "fixed".into(),
                chunk_size: 64,
                overlap: 0,
            },
            None,
            "bench",
        )
        .unwrap();
    let chunk = engine
        .search_semantic_unrecorded(commit, "agent memory", 1, &SearchFilter::default())
        .unwrap()[0]
        .chunk_hash;
    let mut done = 0usize;
    for target in [0usize, 100, 1000] {
        while done < target {
            engine
                .search(
                    "main",
                    None,
                    neleus_db::engine::SearchQuery::Semantic("agent memory"),
                    5,
                    &SearchFilter::default(),
                    None,
                )
                .unwrap();
            done += 1;
        }
        let tip = engine.resolve_commit("main").unwrap();
        let proof = engine.prove(tip, chunk, false).unwrap();
        eprintln!(
            "[q4b] after {target:>4} recorded searches: chunk proof {} B, {} state node(s) in path",
            to_cbor(&proof).unwrap().len(),
            proof.manifest_proof.path.len()
        );
    }

    // Nor do writes: the proof is one state path, not the ancestry since.
    let mut written = 0usize;
    for target in [100usize, 1000] {
        while written < target {
            engine
                .db()
                .create_commit_at_head("main", "bench", "write", vec![])
                .unwrap();
            written += 1;
        }
        let tip = engine.resolve_commit("main").unwrap();
        let proof = engine.prove(tip, chunk, false).unwrap();
        eprintln!(
            "[q4b] after {target:>4} writes: chunk proof {} B, {} state node(s) in path",
            to_cbor(&proof).unwrap().len(),
            proof.manifest_proof.path.len()
        );
    }

    let tenant = |t: &str| ChunkMetadata {
        tenant: Some(t.into()),
        ..Default::default()
    };
    let filter = SearchFilter {
        tenant: Some("a".into()),
        ..Default::default()
    };
    let doc = |i: usize, text: &str, meta: ChunkMetadata| ChunkInput {
        chunk_hash: hash_typed(b"q5b:", format!("{i}").as_bytes()),
        text: text.to_string(),
        embedding: None,
        meta: Some(meta),
    };
    // 30 independent batches per size; a channel shows as a shift in batch
    // medians. Permutation test on the 0-vs-100k difference of medians.
    let batches = 30usize;
    let mut medians: Vec<(usize, Vec<f64>)> = Vec::new();
    for others in [0usize, 10_000, 100_000] {
        let mut inputs: Vec<ChunkInput> = (0..1000)
            .map(|i| doc(i, "shared probe term and filler", tenant("a")))
            .collect();
        inputs.extend((0..others).map(|i| doc(10_000_000 + i, "shared probe term", tenant("b"))));
        let seg = IndexSegment::build(vec![], inputs);
        let mut per_batch = Vec::with_capacity(batches);
        for _ in 0..batches {
            let reps = 200u32;
            let start = Instant::now();
            for _ in 0..reps {
                assert!(!seg.bm25("probe", 10, &filter).is_empty());
            }
            per_batch.push((start.elapsed() / reps).as_secs_f64() * 1e6);
        }
        let (lo, mid, hi) = bootstrap_median(&per_batch);
        eprintln!(
            "[q5b] tenant a (1000 docs) filtered BM25 with {others:>6} other-tenant docs: \
             median {mid:.2} us (95% CI {lo:.2}-{hi:.2}) over {batches} batches"
        );
        medians.push((others, per_batch));
    }
    let p = permutation_p(&medians[0].1, &medians[2].1);
    eprintln!("[q5b] 0 vs 100000 other-tenant docs: permutation p = {p:.4}");
    let p = permutation_p(&medians[1].1, &medians[2].1);
    eprintln!("[q5b] 10000 vs 100000 other-tenant docs: permutation p = {p:.4}");
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[s.len() / 2]
}

/// Median with a 95% percentile-bootstrap interval.
fn bootstrap_median(v: &[f64]) -> (f64, f64, f64) {
    use rand::{Rng, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(1);
    let mut boots: Vec<f64> = (0..2000)
        .map(|_| {
            median(
                &(0..v.len())
                    .map(|_| v[rng.gen_range(0..v.len())])
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    boots.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (boots[50], median(v), boots[1949])
}

/// Two-sided permutation test on the difference of medians.
fn permutation_p(a: &[f64], b: &[f64]) -> f64 {
    use rand::SeedableRng;
    use rand::seq::SliceRandom;
    let observed = (median(a) - median(b)).abs();
    let mut pooled: Vec<f64> = a.iter().chain(b).copied().collect();
    let mut rng = rand::rngs::StdRng::seed_from_u64(2);
    let trials = 10_000;
    let hits = (0..trials)
        .filter(|_| {
            pooled.shuffle(&mut rng);
            let (x, y) = pooled.split_at(a.len());
            (median(x) - median(y)).abs() >= observed
        })
        .count();
    (hits + 1) as f64 / (trials + 1) as f64
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = q2_checkpoint_chain, q3_q4_auditor, q5_idf_leakage, q4b_q5b_scaling
}
criterion_main!(benches);

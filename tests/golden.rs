//! Golden digests of every canonical encoding a proof re-hashes. A change to
//! any struct's field set, order, or encoding changes its digest here.

use neleus_db::canonical::to_cbor;
use neleus_db::checkpoint::{CHECKPOINT_TAG, Checkpoint};
use neleus_db::commit::{COMMIT_TAG, Commit, CommitSignature};
use neleus_db::hash::{Hash, hash_typed};
use neleus_db::manifest::{
    ChunkManifest, ChunkMetadata, ChunkingSpec, DocManifest, MANIFEST_TAG, QueryHit, QueryManifest,
    RunManifest, SummaryManifest, ToolCallRef,
};
use neleus_db::merkle::MerkleProof;
use neleus_db::retrieval_proof::{ChunkProof, ProofAnchor};
use neleus_db::state::{StateOutcome, StateProof};
use serde::Serialize;

fn h(n: u8) -> Hash {
    Hash([n; 32])
}

fn digest<T: Serialize>(tag: &[u8], v: &T) -> String {
    hash_typed(tag, &to_cbor(v).unwrap()).to_string()
}

fn meta() -> Option<ChunkMetadata> {
    Some(ChunkMetadata {
        tenant: Some("acme".into()),
        language: Some("en".into()),
        ..Default::default()
    })
}

#[test]
fn golden_encodings() {
    let commit = Commit {
        schema_version: 1,
        parents: vec![h(1)],
        timestamp: 1_700_000_000,
        author: "key:agent".into(),
        message: "m".into(),
        state_root: h(2),
        manifests: vec![h(3), h(4)],
        signature: Some(CommitSignature {
            scheme: "ed25519".into(),
            key_id: Some("k".into()),
            signature: vec![7; 64],
        }),
        payload_hash: Some(h(5)),
    };
    let checkpoint = Checkpoint {
        schema_version: 1,
        prev: Some(h(6)),
        head: "acme/main".into(),
        commit: h(7),
        sequence: 3,
        created_at: 1_700_000_001,
        signature: None,
        key_id: None,
        log_root: h(8),
        log_spine: vec![h(9), h(10)],
        query_tip: Some(h(11)),
        event_tip: Some((4, h(12))),
    };
    let chunk = ChunkManifest {
        schema_version: 1,
        chunk_text: h(13),
        start: 0,
        end: 42,
        embedding: Some(h(14)),
        metadata: meta(),
    };
    let doc = DocManifest {
        schema_version: 1,
        source: "kb.txt".into(),
        created_at: 1_700_000_002,
        chunking: ChunkingSpec {
            method: "fixed".into(),
            chunk_size: 512,
            overlap: 64,
        },
        chunks: vec![h(15)],
        original: h(16),
        metadata: meta(),
    };
    let summary = SummaryManifest {
        schema_version: 1,
        summary_text: h(17),
        embedding: None,
        children: vec![h(18)],
        level: 1,
        metadata: None,
    };
    let query = QueryManifest {
        schema_version: 1,
        commit: h(19),
        mode: "hybrid".into(),
        query_text: Some(h(20)),
        query_embedding: None,
        top_k: 10,
        filters: Some("{\"tenant\":\"acme\"}".into()),
        principal: Some("key:agent".into()),
        executed_at: 1_700_000_003,
        hits: vec![QueryHit {
            chunk: h(21),
            score_micro: -5,
        }],
        seq: 9,
        prev: Some(h(22)),
    };
    let run = RunManifest {
        schema_version: 1,
        model: "m".into(),
        prompt: h(23),
        tool_calls: vec![ToolCallRef {
            tool: "t".into(),
            input: Some(h(24)),
            output: None,
        }],
        inputs: vec![h(25)],
        outputs: vec![h(26)],
        started_at: 1,
        ended_at: 2,
        provider: Some("p".into()),
        system_prompt: None,
        model_parameters: None,
        retrieved_chunks: vec![h(27)],
        sdk_version: None,
        agent_id: Some("a".into()),
        trace_id: None,
        parent_span: None,
        delegated_from: None,
        subject: Some("s".into()),
    };
    let proof = ChunkProof {
        schema_version: 2,
        commit: h(28),
        commit_bytes: vec![1, 2],
        manifest_proof: StateProof {
            manifest_schema_version: 1,
            root: Some(h(32)),
            path: vec![],
            outcome: StateOutcome::Found(h(33)),
        },
        manifest_hash: h(29),
        manifest_bytes: vec![3, 4],
        chunk_hash: h(30),
        chunk_bytes: Some(vec![5]),
        content_erased: false,
        anchor: Some(ProofAnchor {
            checkpoint: vec![6],
            inclusion: MerkleProof {
                leaf_count: 4,
                index: 2,
                siblings: vec![h(31)],
            },
            path: vec![vec![7]],
        }),
    };

    let got = [
        ("commit", digest(COMMIT_TAG, &commit)),
        ("checkpoint", digest(CHECKPOINT_TAG, &checkpoint)),
        ("chunk", digest(MANIFEST_TAG, &chunk)),
        ("doc", digest(MANIFEST_TAG, &doc)),
        ("summary", digest(MANIFEST_TAG, &summary)),
        ("query", digest(MANIFEST_TAG, &query)),
        ("run", digest(MANIFEST_TAG, &run)),
        ("chunk_proof", digest(b"chunk_proof:", &proof)),
    ];
    let want = [
        (
            "commit",
            "00956597a39d16184c6586a50754b749f8696431023aa64649b60b09c0d790eb",
        ),
        (
            "checkpoint",
            "39a7dff9f079a6652ef085a3753ff5360c25f465c1de0bb476fc80e2950346ea",
        ),
        (
            "chunk",
            "ce45568ad00e81e460f3bdaeacf2f3bfc763ccf2872c58710ad9ea182db895fc",
        ),
        (
            "doc",
            "62073911f7798d4cb50ef74f64c88c0ec3dbf9a993585bd70a79ca81ac917fa2",
        ),
        (
            "summary",
            "1e7ed994ffa31e505a82bb5202ae8e9d2dd83047039da89856715b06900cdc6b",
        ),
        (
            "query",
            "a891e50ca24c9fd12ec57eb2a19cb6e351edffa85c58841a862e8fb3ea8852fe",
        ),
        (
            "run",
            "7aaabaf6c32bbc922e31800649d15a94ca44ec88b4e01d235e6921dd65df4224",
        ),
        (
            "chunk_proof",
            "467b59ba7c382ec9ebc36657cfffe44795580aea2bf62b77111d4849710024fa",
        ),
    ];
    for ((name, g), (_, w)) in got.iter().zip(want) {
        assert_eq!(g, w, "{name} encoding changed");
    }
}

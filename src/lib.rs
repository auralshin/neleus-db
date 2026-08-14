//! Tamper-evident state for AI agents: prove what your agent knew when it
//! decided.
//!
//! neleus-db is a local-first, content-addressed (Merkle-DAG) database for AI
//! agent memory. Blobs, manifests, commits, and state are BLAKE3-addressed
//! immutable objects, so tampering changes the hash and the hash is the
//! identity. Any search hit becomes a self-contained proof you can verify
//! offline with nothing but BLAKE3 and a CBOR decoder: no database, no network.
//!
//! # Two planes
//!
//! - **Canonical** (immutable, verifiable): [`BlobStore`], [`ManifestStore`],
//!   [`CommitStore`], [`StateStore`], and the [`CheckpointStore`] transparency
//!   log. Hashed into identity; the trust anchor.
//! - **Serving** (derived, fast, rebuildable): the retrieval [`Engine`] (BM25 +
//!   HNSW + metadata filters). Never hashed into identity; delete it and lose
//!   nothing but warm-up time.
//!
//! # Example
//!
//! Ingest a document, search it, and turn a hit into an offline-verifiable
//! proof:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use neleus_db::{Engine, SearchFilter, verify_chunk_proof};
//! use neleus_db::manifest::ChunkingSpec;
//!
//! let engine = Engine::open("./agent_db")?;
//! let spec = ChunkingSpec { method: "fixed".into(), chunk_size: 512, overlap: 64 };
//! let (_doc, commit) = engine.put_document(
//!     "main", "policy.md", b"reset your password in settings", spec, None, "ingest",
//! )?;
//! let hits = engine.search_semantic(commit, "password reset", 5, &SearchFilter::default())?;
//!
//! // The proof carries everything a verifier needs. No store, no network.
//! let proof = engine.prove(commit, hits[0].chunk_hash, true)?;
//! assert!(verify_chunk_proof(&proof).is_ok());
//! # Ok(())
//! # }
//! ```
//!
//! # Where to look
//!
//! - [`Database`] is the embedded entry point (commits, state, refs); [`Engine`]
//!   wraps it with retrieval and proofs.
//! - [`CheckpointStore`] anchors each head's history in an append-only Merkle
//!   transparency log; the `audit` module exports offline-verifiable bundles.
//! - Runnable programs live in `examples/` in the [source repository]; the
//!   `serve` subcommand of the `neleus-db` binary exposes the same engine over
//!   HTTP.
//!
//! [source repository]: https://github.com/auralshin/neleus-db/tree/main/examples

pub mod alert;
pub(crate) mod atomic;
pub mod audit;
pub mod auth;
pub mod blob_store;
pub mod canonical;
pub mod cas;
pub mod checkpoint;
pub mod clock;
pub mod commit;
pub mod compression;
pub mod db;
pub mod encryption;
pub mod engine;
pub mod erasure;
pub mod events;
pub mod gc;
pub mod hash;
pub(crate) mod lock;
pub mod manifest;
pub mod merkle;
pub mod object_store;
pub mod pack;
pub mod packstore;
pub(crate) mod par;
pub mod policy;
pub mod provenance;
pub mod refs;
pub mod retrieval_proof;
pub mod server;
pub mod session;
pub mod signing;
pub mod state;
pub mod sync;
pub mod wal;

pub use blob_store::BlobStore;
pub use checkpoint::{Checkpoint, CheckpointStore};
pub use commit::{Commit, CommitHash, CommitStore};
pub use db::Database;
pub use encryption::{EncryptionConfig, EncryptionRuntime};
pub use engine::{Engine, EngineHit, SearchFilter};
pub use hash::Hash;
pub use manifest::{DocManifest, ManifestStore, RunManifest};
pub use provenance::{Evidence, ProvenanceManifest, ProvenanceRecord, ProvenanceStore, SourceType};
pub use refs::RefsStore;
pub use retrieval_proof::{ChunkProof, prove_chunk, verify_chunk_proof};
pub use session::{SessionRecord, SessionStore};
pub use signing::{Ed25519Signer, Ed25519Verifier};
pub use state::{StateProof, StateRoot, StateStore};

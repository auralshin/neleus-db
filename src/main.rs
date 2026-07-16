use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Parser, Subcommand, ValueEnum};
use neleus_db::canonical::from_cbor;
use neleus_db::clock::now_unix;
use neleus_db::commit::Commit;
use neleus_db::db::Database;
use neleus_db::hash::Hash;
use neleus_db::manifest::{
    ChunkManifest, ChunkingSpec, DocManifest, MANIFEST_SCHEMA_VERSION, RunManifest,
};
use neleus_db::state::{StateManifest, StateNode};

#[derive(Debug, Parser)]
#[command(name = "neleus-db")]
#[command(about = "Local-first Merkle Agent DB")]
struct Cli {
    #[arg(long, global = true, default_value = "./neleus_db")]
    db: PathBuf,

    #[arg(long, global = true, default_value_t = false)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },
    Blob {
        #[command(subcommand)]
        command: BlobCommands,
    },
    Manifest {
        #[command(subcommand)]
        command: ManifestCommands,
    },
    State {
        #[command(subcommand)]
        command: StateCommands,
    },
    Commit {
        #[command(subcommand)]
        command: CommitCommands,
    },
    Index {
        #[command(subcommand)]
        command: IndexCommands,
    },
    Search {
        #[command(subcommand)]
        command: SearchCommands,
    },
    Log {
        head: String,
    },
    Proof {
        #[command(subcommand)]
        command: ProofCommands,
    },
    Object {
        #[command(subcommand)]
        command: ObjectCommands,
    },
    /// Serve the database over HTTP (the same engine as embedded use).
    Serve {
        /// Bind address. Non-loopback requires --allow-remote and auth keys.
        #[arg(long, default_value = "127.0.0.1:7117")]
        addr: String,
        /// Permit binding non-loopback addresses (TLS-terminate in front!).
        #[arg(long)]
        allow_remote: bool,
        /// Disable authentication (loopback-only development escape hatch).
        #[arg(long)]
        no_auth: bool,
        /// Allow browser clients from this origin (Access-Control-Allow-Origin),
        /// e.g. http://localhost:5173 for the dev console. "*" allows any. The
        /// bundled console is same-origin and needs no CORS.
        #[arg(long)]
        cors_origin: Option<String>,
        /// Open the bundled console in a browser once the server is up.
        #[arg(long)]
        open: bool,
        /// Require minted API keys even on loopback (disable the auto bootstrap
        /// admin token).
        #[arg(long)]
        no_bootstrap: bool,
    },
    /// API-key management for server mode (CLI-only by design).
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// Policy-as-code: monitor and enforce compliance rules.
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    /// Tamper-evident policy/enforcement event log.
    Events {
        #[command(subcommand)]
        command: EventsCommands,
    },
    /// Subject-scoped erasure (GDPR right-to-be-forgotten).
    Erasure {
        #[command(subcommand)]
        command: ErasureCommands,
    },
    /// ed25519 signing-key management.
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    /// Transparency-log checkpoints over a head's history.
    Checkpoint {
        #[command(subcommand)]
        command: CheckpointCommands,
    },
    /// Episodic session memory with TTL.
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },
    /// Retrieval audit: list, export, verify, and report.
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    /// Per-jurisdiction AI/data law checks against live audit data.
    Compliance {
        #[command(subcommand)]
        command: ComplianceCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ComplianceCommands {
    /// List the framework catalog, grouped by jurisdiction.
    Frameworks,
    /// Per-law overall status (satisfied / in review / gap) for a head.
    Status {
        #[arg(long)]
        head: String,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = u64::MAX)]
        to: u64,
    },
    /// Full check list for one framework against a head.
    Check {
        #[arg(long)]
        head: String,
        /// Framework id (see `compliance frameworks`).
        #[arg(long)]
        framework: String,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = u64::MAX)]
        to: u64,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommands {
    /// List retrieval audit records (QueryManifests) on a head.
    Log {
        #[arg(long)]
        head: String,
        /// Unix seconds, inclusive. Defaults to the full history.
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = u64::MAX)]
        to: u64,
    },
    /// Export a self-contained, optionally signed audit bundle.
    Export {
        #[arg(long)]
        head: String,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = u64::MAX)]
        to: u64,
        /// Output file (convention: .nelaudit).
        #[arg(long)]
        out: PathBuf,
        /// ed25519 seed file; signs the bundle footer.
        #[arg(long)]
        sign_key: Option<PathBuf>,
    },
    /// Verify a bundle offline (same checks as the neleus-verify binary).
    Verify {
        input: PathBuf,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long)]
        require_signature: bool,
    },
    /// Generate a markdown compliance report from live audit data.
    Report {
        #[arg(long)]
        head: String,
        /// eu-ai-act | hipaa | sec-occ
        #[arg(long)]
        framework: String,
        #[arg(long, default_value_t = 0)]
        from: u64,
        #[arg(long, default_value_t = u64::MAX)]
        to: u64,
        /// Write to a file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum AuthCommands {
    /// Mint an API key. The token is printed ONCE and never stored.
    AddKey {
        #[arg(long)]
        id: String,
        /// reader | writer | admin
        #[arg(long)]
        role: String,
        /// Pin the key to a tenant (hard partition under '<tenant>/').
        #[arg(long)]
        tenant: Option<String>,
    },
    RemoveKey {
        #[arg(long)]
        id: String,
    },
    ListKeys,
}

#[derive(Debug, Subcommand)]
enum PolicyCommands {
    /// Print the current policy set.
    List,
    /// Replace the whole policy set from a JSON file (policy-as-code apply).
    Set {
        /// Path to a JSON file: {"policies":[{"id":...,"rule":{...},"mode":...}]}
        file: PathBuf,
    },
    /// Remove one policy by id.
    Rm {
        #[arg(long)]
        id: String,
    },
    /// Evaluate every enabled policy against live state.
    Eval {
        /// Restrict to a single head.
        #[arg(long)]
        head: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum EventsCommands {
    /// List recorded events (optionally only those after a sequence number).
    List {
        #[arg(long)]
        since: Option<u64>,
    },
    /// Verify the event chain is intact (tamper-evident).
    Verify,
}

#[derive(Debug, Subcommand)]
enum ErasureCommands {
    /// Shred a subject's content; keeps the signed commitment chain.
    Request {
        #[arg(long)]
        subject: String,
        /// request | ttl | account-closure.
        #[arg(long, default_value = "request")]
        reason: String,
        /// ed25519 seed file to authorize the erasure record.
        #[arg(long)]
        sign_key: Option<PathBuf>,
    },
    /// List recorded erasure records.
    List,
    /// Verify every signed erasure record against a public key.
    Verify {
        #[arg(long)]
        public_key: String,
    },
}

#[derive(Debug, Subcommand)]
enum KeyCommands {
    /// Generate an ed25519 keypair; prints the public key, stores the seed.
    Generate {
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CheckpointCommands {
    /// Append a checkpoint for the head's current commit.
    New {
        #[arg(long)]
        head: String,
        /// Sign the checkpoint with this ed25519 seed file.
        #[arg(long)]
        sign_key: Option<PathBuf>,
    },
    /// Verify the full checkpoint chain back to genesis.
    Verify {
        #[arg(long)]
        head: String,
        /// Verify signatures against this hex public key.
        #[arg(long)]
        public_key: Option<String>,
        /// Fail on any unsigned checkpoint.
        #[arg(long)]
        require_signatures: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SessionCommands {
    Append {
        #[arg(long)]
        head: String,
        #[arg(long)]
        session_id: String,
        /// user | assistant | tool | summary | ...
        #[arg(long)]
        role: Option<String>,
        #[arg(long)]
        content: Option<String>,
        #[arg(long)]
        content_file: Option<PathBuf>,
        /// Expire this turn after N seconds.
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    List {
        #[arg(long)]
        head: String,
        #[arg(long)]
        session_id: String,
        /// Include expired records (replay view).
        #[arg(long)]
        include_expired: bool,
    },
    /// Physically remove expired session records and compact.
    Gc {
        #[arg(long)]
        head: String,
    },
}

#[derive(Debug, Subcommand)]
enum DbCommands {
    Init {
        path: PathBuf,
    },
    /// Re-encrypt all blobs and objects with a new password.
    /// The new password is read from the environment variable given by --new-password-env.
    /// The current password must still be set in NELEUS_DB_ENCRYPTION_PASSWORD.
    Reencrypt {
        #[arg(long, default_value = "NELEUS_DB_NEW_ENCRYPTION_PASSWORD")]
        new_password_env: String,
    },
    /// Export the database (--db) into a single self-contained pack file.
    /// Cold copy: quiesce writers (or open the DB once) before packing.
    Pack {
        /// Destination pack file.
        out: PathBuf,
        /// zstd-compress the pack stream (smaller for plaintext databases).
        #[arg(long)]
        compress: bool,
    },
    /// Restore a database directory (--db) from a pack file.
    Unpack {
        /// Source pack file.
        input: PathBuf,
        /// Overwrite the target directory if it already exists.
        #[arg(long)]
        force: bool,
        /// Check the pack's integrity and structure without writing anything.
        #[arg(long)]
        verify_only: bool,
    },
    /// Consolidate loose blobs/objects into pack files, reclaiming the per-file
    /// disk and inode overhead. Crash-safe; already-packed objects are untouched.
    Repack,
    /// List the internal pack files under blobs/ and objects/.
    Packs,
    /// Reclaim objects unreachable from any ref. Dry-run by default — pass
    /// --prune to actually delete.
    Gc {
        /// Delete unreachable objects (default: report only).
        #[arg(long)]
        prune: bool,
        /// Protect objects modified within this many seconds of the run start.
        #[arg(long, default_value_t = 3600)]
        grace_secs: u64,
    },
    /// Pull missing objects + fast-forward refs from a remote `serve` peer.
    Pull {
        /// Remote base URL, e.g. http://127.0.0.1:7117
        #[arg(long)]
        remote: String,
        /// Env var holding the bearer token (admin key on the remote).
        #[arg(long, default_value = "NELEUS_DB_TOKEN")]
        token_env: String,
    },
    /// Push this database to a remote `serve` peer (fast-forward only).
    Push {
        /// Remote base URL, e.g. http://127.0.0.1:7117
        #[arg(long)]
        remote: String,
        /// Env var holding the bearer token (admin key on the remote).
        #[arg(long, default_value = "NELEUS_DB_TOKEN")]
        token_env: String,
    },
}

#[derive(Debug, Subcommand)]
enum BlobCommands {
    Put { file: PathBuf },
    Get { hash: String, out_file: PathBuf },
}

// PutRun carries many optional string fields; boxing here adds complexity with no runtime
// benefit since ManifestCommands is instantiated exactly once per CLI invocation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum ManifestCommands {
    PutDoc {
        #[arg(long)]
        source: String,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        chunk_size: usize,
        #[arg(long, default_value_t = 0)]
        overlap: usize,
        /// Tenant stamp applied to every chunk.
        #[arg(long)]
        tenant: Option<String>,
        #[arg(long)]
        doc_type: Option<String>,
        #[arg(long)]
        language: Option<String>,
        /// Unix seconds the chunks become retrievable.
        #[arg(long)]
        valid_from: Option<u64>,
        /// Unix seconds the chunks stop being retrievable.
        #[arg(long)]
        valid_to: Option<u64>,
        /// Unix seconds the chunks expire.
        #[arg(long)]
        expires_at: Option<u64>,
        /// ACL tag required to retrieve these chunks; may be repeated.
        #[arg(long = "acl")]
        acl: Vec<String>,
    },
    PutRun {
        #[arg(long)]
        model: String,
        #[arg(long)]
        prompt_file: PathBuf,
        #[arg(long = "io-hashes")]
        io_hashes: Vec<String>,
        /// AI provider name, e.g. `anthropic` or `openai`.
        #[arg(long)]
        provider: Option<String>,
        /// File containing the system prompt bytes.
        #[arg(long)]
        system_prompt_file: Option<PathBuf>,
        /// JSON file with model sampling parameters, e.g. `{"temperature": 0.2}`.
        #[arg(long)]
        params_json: Option<PathBuf>,
        /// Individual model parameter as `key=value`; may be repeated.
        /// Numbers and booleans are type-inferred; anything else is stored as a string.
        #[arg(long = "param")]
        params: Vec<String>,
        /// Hash of a chunk blob retrieved from the knowledge base for this run; may be repeated.
        #[arg(long = "retrieved-chunk")]
        retrieved_chunks: Vec<String>,
        /// SDK version string, e.g. `anthropic-python/0.40.0`.
        #[arg(long)]
        sdk_version: Option<String>,
        /// Logical agent name or version, e.g. `policy-reviewer-v1`.
        #[arg(long)]
        agent_id: Option<String>,
        /// Unix timestamp for run start; defaults to the time of this call.
        #[arg(long)]
        started_at: Option<u64>,
        /// Unix timestamp for run end; defaults to the time of this call.
        #[arg(long)]
        ended_at: Option<u64>,
    },
}

#[derive(Debug, Subcommand)]
enum StateCommands {
    Set {
        head: String,
        key: String,
        value_file: PathBuf,
        #[arg(long, default_value = "utf8")]
        key_encoding: KeyEncoding,
    },
    Get {
        head: String,
        key: String,
        #[arg(long, default_value = "utf8")]
        key_encoding: KeyEncoding,
        #[arg(long)]
        out_file: Option<PathBuf>,
    },
    Del {
        head: String,
        key: String,
        #[arg(long, default_value = "utf8")]
        key_encoding: KeyEncoding,
    },
    Compact {
        head: String,
    },
    /// Apply multiple key-value writes in one segment from a JSON file.
    /// The file must be a JSON array: [{"key": "<utf8>", "value_base64": "<base64>"}]
    SetMany {
        head: String,
        entries_file: PathBuf,
    },
    /// Delete multiple keys in one new state version from a JSON file.
    /// The file must be a JSON array of UTF-8 key strings: ["key1", "key2"]
    DelMany {
        head: String,
        keys_file: PathBuf,
    },
}

#[derive(Debug, Clone, ValueEnum)]
enum KeyEncoding {
    Utf8,
    Hex,
    Base64,
}

#[derive(Debug, Subcommand)]
enum CommitCommands {
    New {
        #[arg(long)]
        head: String,
        #[arg(long)]
        author: String,
        #[arg(long)]
        message: String,
        #[arg(long = "manifest")]
        manifests: Vec<String>,
        /// Sign the commit with this ed25519 seed file.
        #[arg(long)]
        sign_key: Option<PathBuf>,
    },
    /// Verify a signed commit against an ed25519 public key.
    Verify {
        hash: String,
        #[arg(long)]
        public_key: String,
    },
}

#[derive(Debug, Subcommand)]
enum IndexCommands {
    Build {
        #[arg(long)]
        head: String,
    },
    Stats {
        #[arg(long)]
        head: String,
    },
}

#[derive(Debug, Subcommand)]
enum ObjectCommands {
    /// Inspect a raw object by hash, attempting to decode it as known types.
    Inspect { hash: String },
}

/// Metadata/temporal filter flags shared by every search mode.
#[derive(Debug, Clone, clap::Args)]
struct FilterArgs {
    /// Only chunks stamped with this tenant.
    #[arg(long)]
    tenant: Option<String>,
    #[arg(long)]
    doc_type: Option<String>,
    #[arg(long)]
    language: Option<String>,
    /// ACL tag the caller holds; may be repeated.
    #[arg(long = "acl")]
    acl: Vec<String>,
    /// Validity instant (unix seconds). Filters valid_from/valid_to/expires_at.
    #[arg(long)]
    valid_at: Option<u64>,
}

impl FilterArgs {
    fn into_filter(self) -> neleus_db::SearchFilter {
        neleus_db::SearchFilter {
            tenant: self.tenant,
            doc_type: self.doc_type,
            language: self.language,
            acl: self.acl,
            at: self.valid_at,
        }
    }
}

#[derive(Debug, Subcommand)]
enum SearchCommands {
    Semantic {
        /// Head name or 64-hex commit hash (time-travel queries).
        #[arg(long)]
        head: String,
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        query_file: Option<PathBuf>,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
        #[command(flatten)]
        filter: FilterArgs,
        /// Record a content-addressed QueryManifest audit record.
        #[arg(long)]
        audit: bool,
    },
    Vector {
        /// Head name or 64-hex commit hash (time-travel queries).
        #[arg(long)]
        head: String,
        #[arg(long)]
        embedding_file: PathBuf,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
        #[command(flatten)]
        filter: FilterArgs,
        #[arg(long)]
        audit: bool,
    },
    /// BM25 + vector fused with Reciprocal Rank Fusion.
    Hybrid {
        /// Head name or 64-hex commit hash (time-travel queries).
        #[arg(long)]
        head: String,
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        query_file: Option<PathBuf>,
        #[arg(long)]
        embedding_file: Option<PathBuf>,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
        #[command(flatten)]
        filter: FilterArgs,
        #[arg(long)]
        audit: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProofCommands {
    State {
        head: String,
        key: String,
        #[arg(long, default_value = "utf8")]
        key_encoding: KeyEncoding,
    },
    /// Prove a chunk was in the retrievable corpus at a commit.
    Chunk {
        /// Head name or commit hash the retrieval ran against.
        #[arg(long)]
        head: String,
        /// Chunk hash (from a search hit).
        #[arg(long)]
        chunk: String,
        /// Embed the chunk content in the bundle.
        #[arg(long)]
        include_content: bool,
        /// Write the CBOR proof bundle here (default: stdout as base64 JSON).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a chunk-proof bundle fully offline.
    VerifyChunk {
        /// CBOR proof bundle produced by `proof chunk --out`.
        input: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let Cli {
        db: db_path,
        json: json_output,
        command,
    } = cli;

    match command {
        Commands::Db { command } => match command {
            DbCommands::Init { path } => {
                Database::init(path.clone())?;
                emit(
                    json_output,
                    serde_json::json!({"status": "ok", "path": path}),
                    "initialized",
                )?;
            }
            DbCommands::Reencrypt { new_password_env } => {
                let new_password = std::env::var(&new_password_env)
                    .map_err(|_| anyhow!("environment variable {new_password_env} is not set"))?;
                let db = Database::open(&db_path)?;
                let count = db.rotate_encryption_key(&new_password)?;
                emit(
                    json_output,
                    serde_json::json!({"status": "ok", "files_reencrypted": count}),
                    &format!("reencrypted {count} files"),
                )?;
            }
            DbCommands::Pack { out, compress } => {
                let stats = neleus_db::pack::pack(&db_path, &out, compress)?;
                emit(
                    json_output,
                    serde_json::json!({"status": "ok", "pack": out, "entries": stats.entries, "bytes": stats.bytes, "compressed": compress}),
                    &format!(
                        "packed {} files ({} bytes) -> {}",
                        stats.entries,
                        stats.bytes,
                        out.display()
                    ),
                )?;
            }
            DbCommands::Unpack {
                input,
                force,
                verify_only,
            } => {
                if verify_only {
                    let stats = neleus_db::pack::verify(&input)?;
                    emit(
                        json_output,
                        serde_json::json!({"status": "ok", "verified": input, "entries": stats.entries, "bytes": stats.bytes}),
                        &format!(
                            "verified {} ({} entries, {} stored bytes)",
                            input.display(),
                            stats.entries,
                            stats.bytes
                        ),
                    )?;
                } else {
                    let stats = neleus_db::pack::unpack(&input, &db_path, force)?;
                    emit(
                        json_output,
                        serde_json::json!({"status": "ok", "db": db_path, "entries": stats.entries, "bytes": stats.bytes}),
                        &format!(
                            "unpacked {} files ({} bytes) -> {}",
                            stats.entries,
                            stats.bytes,
                            db_path.display()
                        ),
                    )?;
                }
            }
            DbCommands::Repack => {
                let db = Database::open(&db_path)?;
                let s = db.repack()?;
                emit(
                    json_output,
                    serde_json::json!({
                        "status": "ok",
                        "packed_objects": s.packed_objects(),
                        "reclaimed_loose": s.reclaimed_loose(),
                        "pack_bytes": s.pack_bytes(),
                    }),
                    &format!(
                        "repacked {} objects ({} bytes), removed {} loose files",
                        s.packed_objects(),
                        s.pack_bytes(),
                        s.reclaimed_loose()
                    ),
                )?;
            }
            DbCommands::Packs => {
                let mut groups = serde_json::Map::new();
                let mut lines = Vec::new();
                for store in ["blobs", "objects"] {
                    let packs = neleus_db::packstore::list_packs(&db_path.join(store))?;
                    let list: Vec<_> = packs
                        .iter()
                        .map(|p| serde_json::json!({"id": p.id, "entries": p.entries, "bytes": p.bytes}))
                        .collect();
                    for p in &packs {
                        lines.push(format!(
                            "{store}/pack-{} {} objects ({} bytes)",
                            p.id, p.entries, p.bytes
                        ));
                    }
                    groups.insert(store.to_string(), serde_json::Value::Array(list));
                }
                let text = if lines.is_empty() {
                    "no pack files".to_string()
                } else {
                    lines.join("\n")
                };
                emit(
                    json_output,
                    serde_json::json!({"status": "ok", "packs": groups}),
                    &text,
                )?;
            }
            DbCommands::Gc { prune, grace_secs } => {
                let db = Database::open(&db_path)?;
                let stats =
                    neleus_db::gc::gc(&db, prune, std::time::Duration::from_secs(grace_secs))?;
                emit(
                    json_output,
                    serde_json::json!({
                        "status": "ok",
                        "pruned": stats.pruned,
                        "reachable": stats.reachable,
                        "unreachable": stats.unreachable,
                        "reclaimed_bytes": stats.reclaimed_bytes,
                        "skipped_recent": stats.skipped_recent,
                    }),
                    &format!(
                        "{} {} unreachable objects ({} bytes), {} reachable, {} protected by grace",
                        if stats.pruned {
                            "pruned"
                        } else {
                            "would prune"
                        },
                        stats.unreachable,
                        stats.reclaimed_bytes,
                        stats.reachable,
                        stats.skipped_recent
                    ),
                )?;
            }
            DbCommands::Pull { remote, token_env } => {
                let token = std::env::var(&token_env).ok();
                let db = Database::open(&db_path)?;
                let report = neleus_db::sync::pull(&db, &remote, token.as_deref())?;
                emit(
                    json_output,
                    serde_json::json!({
                        "objects_added": report.objects_added,
                        "packs_copied": report.packs_copied,
                        "refs_updated": report.refs_updated,
                        "refs_skipped": report.refs_skipped,
                        "checkpoints_updated": report.checkpoints_updated,
                    }),
                    &format!(
                        "pulled {} objects, {} refs updated, {} skipped (diverged)",
                        report.objects_added,
                        report.refs_updated.len(),
                        report.refs_skipped.len()
                    ),
                )?;
            }
            DbCommands::Push { remote, token_env } => {
                let token = std::env::var(&token_env).ok();
                let db = Database::open(&db_path)?;
                let response = neleus_db::sync::push(&db, &remote, token.as_deref())?;
                emit(
                    json_output,
                    serde_json::from_str(&response)
                        .unwrap_or_else(|_| serde_json::json!({"response": response})),
                    &response,
                )?;
            }
        },
        Commands::Blob { command } => {
            let db = Database::open(&db_path)?;
            match command {
                BlobCommands::Put { file } => {
                    let bytes = fs::read(file.clone())?;
                    let h = db.blob_store.put(&bytes)?;
                    emit(
                        json_output,
                        serde_json::json!({"hash": h.to_string(), "bytes": bytes.len(), "file": file}),
                        &h.to_string(),
                    )?;
                }
                BlobCommands::Get { hash, out_file } => {
                    let h: Hash = hash.parse()?;
                    let bytes = db.blob_store.get(h)?;
                    fs::write(out_file.clone(), bytes)?;
                    emit(
                        json_output,
                        serde_json::json!({"hash": h.to_string(), "out_file": out_file}),
                        "ok",
                    )?;
                }
            }
        }
        Commands::Manifest { command } => {
            let db = Database::open(&db_path)?;
            match command {
                ManifestCommands::PutDoc {
                    source,
                    file,
                    chunk_size,
                    overlap,
                    tenant,
                    doc_type,
                    language,
                    valid_from,
                    valid_to,
                    expires_at,
                    acl,
                } => {
                    let bytes = fs::read(file.clone())?;
                    let metadata = neleus_db::manifest::ChunkMetadata {
                        tenant,
                        doc_type,
                        language,
                        valid_from,
                        valid_to,
                        expires_at,
                        acl,
                        subject: None,
                    };
                    let h = db
                        .manifest_store
                        .put_doc_manifest_from_bytes_with_metadata(
                            &db.blob_store,
                            source,
                            &bytes,
                            ChunkingSpec {
                                method: "fixed".into(),
                                chunk_size,
                                overlap,
                            },
                            None,
                            Some(metadata),
                        )?;
                    emit(
                        json_output,
                        serde_json::json!({"manifest_hash": h.to_string(), "source_file": file}),
                        &h.to_string(),
                    )?;
                }
                ManifestCommands::PutRun {
                    model,
                    prompt_file,
                    io_hashes,
                    provider,
                    system_prompt_file,
                    params_json,
                    params,
                    retrieved_chunks,
                    sdk_version,
                    agent_id,
                    started_at,
                    ended_at,
                } => {
                    let prompt = db.blob_store.put(&fs::read(prompt_file.clone())?)?;
                    let (inputs, outputs) = parse_io_hashes(&io_hashes)?;

                    let system_prompt = system_prompt_file
                        .map(|p| db.blob_store.put(&fs::read(p)?))
                        .transpose()?;

                    let model_parameters = build_model_parameters_blob(&db, params_json, &params)?;

                    let retrieved_chunk_hashes = retrieved_chunks
                        .iter()
                        .map(|s| s.parse::<Hash>())
                        .collect::<Result<Vec<_>, _>>()?;

                    let now = now_unix()?;
                    let run = RunManifest {
                        schema_version: MANIFEST_SCHEMA_VERSION,
                        model,
                        prompt,
                        tool_calls: vec![],
                        inputs,
                        outputs,
                        started_at: started_at.unwrap_or(now),
                        ended_at: match ended_at {
                            Some(t) => t,
                            None => now_unix()?,
                        },
                        provider,
                        system_prompt,
                        model_parameters,
                        retrieved_chunks: retrieved_chunk_hashes,
                        sdk_version,
                        agent_id,
                        trace_id: None,
                        parent_span: None,
                        delegated_from: None,
                        subject: None,
                    };
                    let h = db.manifest_store.put_manifest(&run)?;
                    emit(
                        json_output,
                        serde_json::json!({"manifest_hash": h.to_string(), "prompt_file": prompt_file}),
                        &h.to_string(),
                    )?;
                }
            }
        }
        Commands::State { command } => {
            let db = Database::open(&db_path)?;
            match command {
                StateCommands::Set {
                    head,
                    key,
                    value_file,
                    key_encoding,
                } => {
                    let key_bytes = decode_key(&key, &key_encoding)?;
                    let value = fs::read(value_file.clone())?;
                    let new_root = db.state_set_at_head(&head, &key_bytes, &value)?;
                    emit(
                        json_output,
                        serde_json::json!({"state_root": new_root.to_string(), "head": head}),
                        &new_root.to_string(),
                    )?;
                }
                StateCommands::Get {
                    head,
                    key,
                    key_encoding,
                    out_file,
                } => {
                    let key_bytes = decode_key(&key, &key_encoding)?;
                    let root = resolve_state_root(&db, &head)?;
                    match db.state_store.get(root, &key_bytes)? {
                        Some(value) => {
                            if let Some(path) = out_file.clone() {
                                fs::write(path.clone(), &value)?;
                                emit(
                                    json_output,
                                    serde_json::json!({
                                        "state_root": root.to_string(),
                                        "head": head,
                                        "key_base64": BASE64.encode(&key_bytes),
                                        "out_file": path,
                                        "bytes": value.len()
                                    }),
                                    "ok",
                                )?;
                            } else if json_output {
                                emit(
                                    json_output,
                                    serde_json::json!({
                                        "state_root": root.to_string(),
                                        "head": head,
                                        "key_base64": BASE64.encode(&key_bytes),
                                        "value_base64": BASE64.encode(&value)
                                    }),
                                    "",
                                )?;
                            } else {
                                match String::from_utf8(value.clone()) {
                                    Ok(s) => println!("{s}"),
                                    Err(_) => println!("0x{}", to_hex(&value)),
                                }
                            }
                        }
                        None => return Err(anyhow!("key not found")),
                    }
                }
                StateCommands::Del {
                    head,
                    key,
                    key_encoding,
                } => {
                    let key_bytes = decode_key(&key, &key_encoding)?;
                    let new_root = db.state_del_at_head(&head, &key_bytes)?;
                    emit(
                        json_output,
                        serde_json::json!({"state_root": new_root.to_string(), "head": head}),
                        &new_root.to_string(),
                    )?;
                }
                StateCommands::Compact { head } => {
                    let compacted = db.state_compact_at_head(&head)?;
                    emit(
                        json_output,
                        serde_json::json!({"state_root": compacted.to_string(), "head": head}),
                        &compacted.to_string(),
                    )?;
                }
                StateCommands::SetMany { head, entries_file } => {
                    #[derive(serde::Deserialize)]
                    struct Entry {
                        key: String,
                        value_base64: String,
                    }
                    let raw = fs::read(entries_file)?;
                    let entries: Vec<Entry> = serde_json::from_slice(&raw)?;
                    let decoded: Vec<(Vec<u8>, Vec<u8>)> = entries
                        .iter()
                        .map(|e| {
                            let v = BASE64.decode(e.value_base64.as_bytes())?;
                            Ok((e.key.as_bytes().to_vec(), v))
                        })
                        .collect::<Result<_>>()?;
                    let pairs: Vec<(&[u8], &[u8])> = decoded
                        .iter()
                        .map(|(k, v)| (k.as_slice(), v.as_slice()))
                        .collect();
                    let new_root = db.state_set_many_at_head(&head, &pairs)?;
                    emit(
                        json_output,
                        serde_json::json!({"state_root": new_root.to_string(), "head": head, "count": pairs.len()}),
                        &new_root.to_string(),
                    )?;
                }
                StateCommands::DelMany { head, keys_file } => {
                    let raw = fs::read(keys_file)?;
                    let key_strs: Vec<String> = serde_json::from_slice(&raw)?;
                    let key_bytes: Vec<Vec<u8>> =
                        key_strs.iter().map(|s| s.as_bytes().to_vec()).collect();
                    let keys: Vec<&[u8]> = key_bytes.iter().map(|k| k.as_slice()).collect();
                    let new_root = db.state_del_many_at_head(&head, &keys)?;
                    emit(
                        json_output,
                        serde_json::json!({"state_root": new_root.to_string(), "head": head, "count": keys.len()}),
                        &new_root.to_string(),
                    )?;
                }
            }
        }
        Commands::Commit { command } => {
            let db = Database::open(&db_path)?;
            match command {
                CommitCommands::New {
                    head,
                    author,
                    message,
                    manifests,
                    sign_key,
                } => {
                    let manifest_hashes = manifests
                        .into_iter()
                        .map(|m| m.parse::<Hash>())
                        .collect::<Result<Vec<_>, _>>()?;
                    let commit_hash = match sign_key {
                        None => {
                            db.create_commit_at_head(&head, &author, &message, manifest_hashes)?
                        }
                        Some(key_path) => {
                            let signer =
                                neleus_db::signing::Ed25519Signer::from_seed_file(&key_path)?;
                            // Signed commits build on the staged/committed
                            // state of the head, then advance the head ref.
                            let parent = db.refs.head_get(&head)?;
                            // Snapshot staged state once: the commit is signed
                            // over it and the CAS guards on it. Re-reading at the
                            // CAS would let a write that raced the signing window
                            // pass the check and be silently rolled back.
                            let expected_state = db.refs.state_get(&head)?;
                            let state_root = db.resolve_state_root(&head)?;
                            let candidate = db.commit_store.create_signed_commit(
                                &signer,
                                parent.into_iter().collect(),
                                state_root,
                                manifest_hashes,
                                author.clone(),
                                message.clone(),
                            )?;
                            if !db
                                .refs
                                .state_compare_and_set(&head, expected_state, state_root)?
                                || !db.refs.head_compare_and_set(&head, parent, candidate)?
                            {
                                return Err(anyhow!(
                                    "concurrent update on head '{head}' while signing; retry"
                                ));
                            }
                            candidate
                        }
                    };
                    // Index eagerly so the next query is warm.
                    let engine = neleus_db::Engine::new(db);
                    engine.ensure_indexed(commit_hash)?;
                    emit(
                        json_output,
                        serde_json::json!({"commit_hash": commit_hash.to_string(), "head": head}),
                        &commit_hash.to_string(),
                    )?;
                }
                CommitCommands::Verify { hash, public_key } => {
                    let h: Hash = hash.parse()?;
                    let verifier =
                        neleus_db::signing::Ed25519Verifier::from_public_hex(&public_key)?;
                    db.commit_store.verify_commit_with(h, &verifier)?;
                    emit(
                        json_output,
                        serde_json::json!({"commit": h.to_string(), "verified": true}),
                        "signature valid",
                    )?;
                }
            }
        }
        Commands::Index { command } => {
            let engine = neleus_db::Engine::open(&db_path)?;
            match command {
                IndexCommands::Build { head } => {
                    let commit = engine.resolve_commit(&head)?;
                    engine.ensure_indexed(commit)?;
                    emit(
                        json_output,
                        serde_json::json!({"head": head, "commit": commit.to_string(), "indexed": true}),
                        &format!("indexed {commit}"),
                    )?;
                }
                IndexCommands::Stats { head } => {
                    let commit = engine.resolve_commit(&head)?;
                    let stats = engine.index_stats(commit)?;
                    emit(
                        json_output,
                        serde_json::json!({
                            "head": head,
                            "commit": commit.to_string(),
                            "segments": stats.segments,
                            "chunks": stats.chunks,
                            "chunks_with_embeddings": stats.chunks_with_embeddings,
                            "unique_terms": stats.unique_terms,
                            "vector_dim": stats.vector_dim,
                            "hnsw_segments": stats.hnsw_segments,
                        }),
                        &format!(
                            "segments={} chunks={} terms={} embeddings={} vector_dim={:?} hnsw={}",
                            stats.segments,
                            stats.chunks,
                            stats.unique_terms,
                            stats.chunks_with_embeddings,
                            stats.vector_dim,
                            stats.hnsw_segments,
                        ),
                    )?;
                }
            }
        }
        Commands::Search { command } => {
            let engine = neleus_db::Engine::open(&db_path)?;
            match command {
                SearchCommands::Semantic {
                    head,
                    query,
                    query_file,
                    top_k,
                    filter,
                    audit,
                } => {
                    let q = resolve_query_text(query, query_file)?;
                    let commit = engine.resolve_commit(&head)?;
                    let filter = filter.into_filter();
                    let hits = engine.search_semantic(commit, &q, top_k, &filter)?;
                    let audit_hash = maybe_audit(
                        &engine,
                        audit,
                        commit,
                        "semantic",
                        Some(&q),
                        None,
                        top_k,
                        &filter,
                        &hits,
                    )?;
                    emit_hits(json_output, "semantic", &head, commit, &hits, audit_hash)?;
                }
                SearchCommands::Vector {
                    head,
                    embedding_file,
                    top_k,
                    filter,
                    audit,
                } => {
                    let commit = engine.resolve_commit(&head)?;
                    let bytes = fs::read(embedding_file)?;
                    let query_vec = neleus_db::engine::parse_embedding(&bytes)?;
                    let filter = filter.into_filter();
                    let hits = engine.search_vector(commit, &query_vec, top_k, &filter)?;
                    let audit_hash = maybe_audit(
                        &engine,
                        audit,
                        commit,
                        "vector",
                        None,
                        Some(&query_vec),
                        top_k,
                        &filter,
                        &hits,
                    )?;
                    emit_hits(json_output, "vector", &head, commit, &hits, audit_hash)?;
                }
                SearchCommands::Hybrid {
                    head,
                    query,
                    query_file,
                    embedding_file,
                    top_k,
                    filter,
                    audit,
                } => {
                    let q = match (&query, &query_file) {
                        (None, None) => None,
                        _ => Some(resolve_query_text(query, query_file)?),
                    };
                    let embedding = embedding_file
                        .map(|p| -> Result<Vec<f32>> {
                            neleus_db::engine::parse_embedding(&fs::read(p)?)
                        })
                        .transpose()?;
                    let commit = engine.resolve_commit(&head)?;
                    let filter = filter.into_filter();
                    let hits = engine.search_hybrid(
                        commit,
                        q.as_deref(),
                        embedding.as_deref(),
                        top_k,
                        &filter,
                    )?;
                    let audit_hash = maybe_audit(
                        &engine,
                        audit,
                        commit,
                        "hybrid",
                        q.as_deref(),
                        embedding.as_deref(),
                        top_k,
                        &filter,
                        &hits,
                    )?;
                    emit_hits(json_output, "hybrid", &head, commit, &hits, audit_hash)?;
                }
            }
        }
        Commands::Log { head } => {
            let db = Database::open(&db_path)?;
            let mut cursor = resolve_head_commit(&db, &head)?;
            let mut commits = Vec::new();

            loop {
                let commit = db.commit_store.get_commit(cursor)?;
                commits.push((cursor, commit.clone()));
                if let Some(parent) = commit.parents.first().copied() {
                    cursor = parent;
                } else {
                    break;
                }
            }

            if json_output {
                let json = commits
                    .iter()
                    .map(|(hash, c)| {
                        serde_json::json!({
                            "hash": hash.to_string(),
                            "author": c.author,
                            "timestamp": c.timestamp,
                            "state_root": c.state_root.to_string(),
                            "message": c.message,
                            "parents": c.parents.iter().map(|h| h.to_string()).collect::<Vec<_>>()
                        })
                    })
                    .collect::<Vec<_>>();
                println!("{}", serde_json::to_string_pretty(&json)?);
            } else {
                for (hash, commit) in commits {
                    println!("commit {hash}");
                    println!("author {}", commit.author);
                    println!("timestamp {}", commit.timestamp);
                    println!("state_root {}", commit.state_root);
                    println!("message {}", commit.message);
                    println!();
                }
            }
        }
        Commands::Proof { command } => {
            let db = Database::open(&db_path)?;
            match command {
                ProofCommands::State {
                    head,
                    key,
                    key_encoding,
                } => {
                    let key_bytes = decode_key(&key, &key_encoding)?;
                    let root = resolve_state_root(&db, &head)?;
                    let proof = db.state_store.proof(root, &key_bytes)?;
                    let verified = db.state_store.verify_proof(root, &key_bytes, &proof);
                    let out = serde_json::json!({
                        "root_hash": root.to_string(),
                        "key": BASE64.encode(&key_bytes),
                        "proof": proof,
                        "verified": verified,
                    });
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
                ProofCommands::Chunk {
                    head,
                    chunk,
                    include_content,
                    out,
                } => {
                    let engine = neleus_db::Engine::new(db);
                    let commit = engine.resolve_commit(&head)?;
                    let chunk_hash: Hash = chunk.parse()?;
                    let proof = engine.prove(commit, chunk_hash, include_content)?;
                    let bytes = neleus_db::canonical::to_cbor(&proof)?;
                    match out {
                        Some(path) => {
                            fs::write(&path, &bytes)?;
                            emit(
                                json_output,
                                serde_json::json!({
                                    "proof": path,
                                    "commit": commit.to_string(),
                                    "chunk": chunk_hash.to_string(),
                                    "bytes": bytes.len(),
                                }),
                                &format!("wrote {} byte proof to {}", bytes.len(), path.display()),
                            )?;
                        }
                        None => {
                            println!(
                                "{}",
                                serde_json::json!({
                                    "commit": commit.to_string(),
                                    "chunk": chunk_hash.to_string(),
                                    "proof_cbor": BASE64.encode(&bytes),
                                })
                            );
                        }
                    }
                }
                ProofCommands::VerifyChunk { input } => {
                    let bytes = fs::read(&input)?;
                    let proof: neleus_db::ChunkProof = from_cbor(&bytes)?;
                    match neleus_db::verify_chunk_proof(&proof) {
                        Ok(kind) => emit(
                            json_output,
                            serde_json::json!({
                                "valid": true,
                                "anchor": kind,
                                "commit": proof.commit.to_string(),
                                "chunk": proof.chunk_hash.to_string(),
                            }),
                            &format!(
                                "VALID: chunk {} was retrievable at commit {} (anchored by a {} manifest)",
                                proof.chunk_hash, proof.commit, kind
                            ),
                        )?,
                        Err(e) => {
                            emit(
                                json_output,
                                serde_json::json!({"valid": false, "error": e.to_string()}),
                                &format!("INVALID: {e}"),
                            )?;
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        Commands::Serve {
            addr,
            allow_remote,
            no_auth,
            cors_origin,
            open,
            no_bootstrap,
        } => {
            let engine = neleus_db::Engine::open(&db_path)?;
            let handle = neleus_db::server::start(
                engine,
                neleus_db::server::ServerConfig {
                    addr,
                    allow_remote,
                    no_auth,
                    cors_origin,
                    bootstrap: !no_bootstrap,
                },
            )?;
            let url = format!("http://{}/", handle.addr);
            eprintln!(
                "neleus-db {} — ready (Ctrl-C to stop)",
                env!("CARGO_PKG_VERSION")
            );
            eprintln!();
            eprintln!("  Console             {url}");
            match &handle.bootstrap_token {
                Some(tok) => {
                    eprintln!("  Connection string   neleus://{tok}@{}", handle.addr);
                    eprintln!();
                    eprintln!(
                        "  Paste it into any SDK, e.g.  neleus.connect(\"neleus://…\")  /  export NELEUS_URL=…"
                    );
                    eprintln!(
                        "  This loopback token is admin and resets on restart. For apps/CI mint a"
                    );
                    eprintln!("  durable key:  neleus-db auth add-key --id app --role writer");
                }
                None => {
                    eprintln!("  Connection string   neleus://<token>@{}", handle.addr);
                    eprintln!(
                        "  Mint a key first:   neleus-db auth add-key --id app --role writer"
                    );
                }
            }
            if open && let Err(e) = open_browser(&url) {
                eprintln!("  could not open browser: {e}");
            }
            // Foreground server: park until killed.
            loop {
                std::thread::park();
            }
        }
        Commands::Auth { command } => match command {
            AuthCommands::AddKey { id, role, tenant } => {
                let role: neleus_db::auth::Role = role.parse()?;
                let token = neleus_db::auth::add_key(&db_path, &id, role, tenant.as_deref())?;
                emit(
                    json_output,
                    serde_json::json!({"id": id, "token": token, "role": format!("{role:?}"), "tenant": tenant}),
                    &format!("token (shown once, store it now): {token}"),
                )?;
            }
            AuthCommands::RemoveKey { id } => {
                let removed = neleus_db::auth::remove_key(&db_path, &id)?;
                emit(
                    json_output,
                    serde_json::json!({"id": id, "removed": removed}),
                    if removed { "removed" } else { "no such key" },
                )?;
            }
            AuthCommands::ListKeys => {
                let keys = neleus_db::auth::list_keys(&db_path)?;
                let rows: Vec<_> = keys
                    .iter()
                    .map(|(id, role, tenant)| {
                        serde_json::json!({"id": id, "role": format!("{role:?}"), "tenant": tenant})
                    })
                    .collect();
                let text = keys
                    .iter()
                    .map(|(id, role, tenant)| {
                        format!(
                            "{id} role={role:?} tenant={}",
                            tenant.as_deref().unwrap_or("-")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                emit(
                    json_output,
                    serde_json::json!({"keys": rows}),
                    if text.is_empty() { "no keys" } else { &text },
                )?;
            }
        },
        Commands::Policy { command } => match command {
            PolicyCommands::List => {
                let set = neleus_db::policy::load(&db_path)?;
                let text = if set.policies.is_empty() {
                    "no policies".to_string()
                } else {
                    set.policies
                        .iter()
                        .map(|p| {
                            format!(
                                "{:<20} {:<28} mode={:?} severity={:?} enabled={}",
                                p.id,
                                p.rule.id(),
                                p.mode,
                                p.severity,
                                p.enabled
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                emit(json_output, serde_json::to_value(&set)?, &text)?;
            }
            PolicyCommands::Set { file } => {
                let set: neleus_db::policy::PolicySet =
                    serde_json::from_slice(&fs::read(&file)?)
                        .map_err(|e| anyhow!("invalid policy json: {e}"))?;
                let stored = neleus_db::policy::store(&db_path, set)?;
                emit(
                    json_output,
                    serde_json::to_value(&stored)?,
                    &format!("applied {} polic(ies)", stored.policies.len()),
                )?;
            }
            PolicyCommands::Rm { id } => {
                let (_, removed) = neleus_db::policy::remove(&db_path, &id)?;
                emit(
                    json_output,
                    serde_json::json!({"id": id, "removed": removed}),
                    if removed { "removed" } else { "no such policy" },
                )?;
            }
            PolicyCommands::Eval { head } => {
                let engine = neleus_db::Engine::open(&db_path)?;
                let report = neleus_db::policy::evaluate(engine.db(), &engine, head.as_deref())?;
                let text = if report.statuses.is_empty() {
                    "no policies to evaluate".to_string()
                } else {
                    let mut lines: Vec<String> = report
                        .statuses
                        .iter()
                        .map(|s| {
                            format!(
                                "[{:?}] {:<20} {:<24} head={:<12} {}",
                                s.status, s.policy_id, s.rule, s.head, s.detail
                            )
                        })
                        .collect();
                    lines.push(format!(
                        "— {} pass / {} warn / {} fail",
                        report.pass, report.warn, report.fail
                    ));
                    lines.join("\n")
                };
                emit(json_output, serde_json::to_value(&report)?, &text)?;
            }
        },
        Commands::Events { command } => match command {
            EventsCommands::List { since } => {
                let events = match since {
                    Some(after) => neleus_db::events::read_since(&db_path, after)?,
                    None => neleus_db::events::read(&db_path)?,
                };
                let text = if events.is_empty() {
                    "no events".to_string()
                } else {
                    events
                        .iter()
                        .map(|e| format!("#{} {} {}", e.seq, e.kind, e.data))
                        .collect::<Vec<_>>()
                        .join("\n")
                };
                emit(json_output, serde_json::json!({"events": events}), &text)?;
            }
            EventsCommands::Verify => {
                let count = neleus_db::events::verify(&db_path)?;
                emit(
                    json_output,
                    serde_json::json!({"verified": true, "events": count}),
                    &format!("chain intact: {count} event(s)"),
                )?;
            }
        },
        Commands::Erasure { command } => match command {
            ErasureCommands::Request {
                subject,
                reason,
                sign_key,
            } => {
                let engine = neleus_db::engine::Engine::open(&db_path)?;
                let signer = match &sign_key {
                    Some(p) => Some(neleus_db::Ed25519Signer::from_seed_file(p)?),
                    None => None,
                };
                let record = neleus_db::erasure::erase_subject(
                    &engine,
                    &subject,
                    neleus_db::erasure::EraseOptions {
                        reason: &reason,
                        requested_by: Some("cli"),
                        signer: signer.as_ref(),
                    },
                )?;
                emit(
                    json_output,
                    serde_json::to_value(&record)?,
                    &format!(
                        "erased {} blob(s) for subject '{subject}' ({})",
                        record.blobs.len(),
                        record.method
                    ),
                )?;
            }
            ErasureCommands::List => {
                let records: Vec<_> = neleus_db::events::read(&db_path)?
                    .into_iter()
                    .filter(|e| e.kind == "erasure")
                    .map(|e| e.data)
                    .collect();
                let text = records
                    .iter()
                    .map(|r| {
                        format!(
                            "subject={} blobs={} reason={} method={}",
                            r.get("subject").and_then(|v| v.as_str()).unwrap_or("?"),
                            r.get("blobs")
                                .and_then(|v| v.as_array())
                                .map_or(0, |a| a.len()),
                            r.get("reason").and_then(|v| v.as_str()).unwrap_or("?"),
                            r.get("method").and_then(|v| v.as_str()).unwrap_or("?"),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                emit(
                    json_output,
                    serde_json::json!({"records": records}),
                    if text.is_empty() {
                        "no erasure records"
                    } else {
                        &text
                    },
                )?;
            }
            ErasureCommands::Verify { public_key } => {
                let mut checked = 0usize;
                for e in neleus_db::events::read(&db_path)? {
                    if e.kind != "erasure" {
                        continue;
                    }
                    let record: neleus_db::erasure::ErasureRecord = serde_json::from_value(e.data)?;
                    if record.signature.is_some() {
                        neleus_db::erasure::verify_record(&record, &public_key)?;
                        checked += 1;
                    }
                }
                emit(
                    json_output,
                    serde_json::json!({"verified": true, "signed_records": checked}),
                    &format!("verified {checked} signed erasure record(s)"),
                )?;
            }
        },
        Commands::Key { command } => match command {
            KeyCommands::Generate { out } => {
                let public_hex = neleus_db::signing::generate_keypair_file(&out)?;
                emit(
                    json_output,
                    serde_json::json!({"key_file": out, "public_key": public_hex}),
                    &format!(
                        "public key: {public_hex}\nseed written to {}",
                        out.display()
                    ),
                )?;
            }
        },
        Commands::Checkpoint { command } => {
            let db = Database::open(&db_path)?;
            let store = neleus_db::CheckpointStore::new(&db);
            match command {
                CheckpointCommands::New { head, sign_key } => {
                    let signer = sign_key
                        .map(|p| neleus_db::signing::Ed25519Signer::from_seed_file(&p))
                        .transpose()?;
                    let hash = store.create(&head, signer.as_ref())?;
                    emit(
                        json_output,
                        serde_json::json!({"head": head, "checkpoint": hash.to_string(), "signed": signer.is_some()}),
                        &hash.to_string(),
                    )?;
                }
                CheckpointCommands::Verify {
                    head,
                    public_key,
                    require_signatures,
                } => {
                    let verifier = public_key
                        .map(|p| neleus_db::signing::Ed25519Verifier::from_public_hex(&p))
                        .transpose()?;
                    let report =
                        store.verify_chain(&head, verifier.as_ref(), require_signatures)?;
                    emit(
                        json_output,
                        serde_json::json!({
                            "head": head,
                            "length": report.length,
                            "signed": report.signed,
                            "latest": report.latest.to_string(),
                            "genesis": report.genesis.to_string(),
                        }),
                        &format!(
                            "chain valid: {} checkpoints ({} signed), latest {}",
                            report.length, report.signed, report.latest
                        ),
                    )?;
                }
            }
        }
        Commands::Audit { command } => {
            let db = Database::open(&db_path)?;
            match command {
                AuditCommands::Log { head, from, to } => {
                    let (records, _) = neleus_db::audit::collect(&db, &head, from, to)?;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&records)?);
                    } else {
                        for r in &records {
                            println!(
                                "{} {} {} top_k={} hits={} principal={}",
                                r.executed_at,
                                r.mode,
                                &r.manifest[..16],
                                r.top_k,
                                r.hits.len(),
                                r.principal.as_deref().unwrap_or("-")
                            );
                        }
                        if records.is_empty() {
                            println!("no audit records in period");
                        }
                    }
                }
                AuditCommands::Export {
                    head,
                    from,
                    to,
                    out,
                    sign_key,
                } => {
                    let signer = sign_key
                        .map(|p| neleus_db::signing::Ed25519Signer::from_seed_file(&p))
                        .transpose()?;
                    let s = neleus_db::audit::export(&db, &head, from, to, &out, signer.as_ref())?;
                    emit(
                        json_output,
                        serde_json::json!({
                            "bundle": out,
                            "retrievals": s.retrievals,
                            "commits": s.commits,
                            "checkpoints": s.checkpoints,
                            "bytes": s.bytes,
                            "signed": s.signed,
                        }),
                        &format!(
                            "exported {} retrievals ({} bytes, {}) -> {}",
                            s.retrievals,
                            s.bytes,
                            if s.signed { "signed" } else { "unsigned" },
                            out.display()
                        ),
                    )?;
                }
                AuditCommands::Verify {
                    input,
                    public_key,
                    require_signature,
                } => {
                    match neleus_db::audit::verify_bundle(
                        &input,
                        public_key.as_deref(),
                        require_signature,
                    ) {
                        Ok(r) => emit(
                            json_output,
                            serde_json::json!({
                                "valid": true,
                                "retrievals": r.retrievals,
                                "head": r.head,
                                "commits": r.commits,
                                "checkpoints": r.checkpoints,
                                "checkpoints_signed": r.checkpoints_signed,
                                "bundle_key_id": r.bundle_key_id,
                            }),
                            &format!(
                                "VERIFIED: {} retrievals on head '{}', chain intact across {} commits, {} checkpoints ({} signed)",
                                r.retrievals,
                                r.head,
                                r.commits,
                                r.checkpoints,
                                r.checkpoints_signed
                            ),
                        )?,
                        Err(e) => {
                            emit(
                                json_output,
                                serde_json::json!({"valid": false, "error": e.to_string()}),
                                &format!("INVALID: {e}"),
                            )?;
                            std::process::exit(1);
                        }
                    }
                }
                AuditCommands::Report {
                    head,
                    framework,
                    from,
                    to,
                    out,
                } => {
                    let md = neleus_db::audit::report(&db, &head, &framework, from, to)?;
                    match out {
                        Some(path) => {
                            fs::write(&path, &md)?;
                            emit(
                                json_output,
                                serde_json::json!({"report": path, "framework": framework}),
                                &format!("wrote {}", path.display()),
                            )?;
                        }
                        None => println!("{md}"),
                    }
                }
            }
        }
        Commands::Compliance { command } => {
            let db = Database::open(&db_path)?;
            match command {
                ComplianceCommands::Frameworks => {
                    let fws = neleus_db::compliance::frameworks();
                    if json_output {
                        let rows: Vec<_> = fws
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "id": f.id,
                                    "jurisdiction": f.jurisdiction,
                                    "region": f.region,
                                    "name": f.name,
                                    "citation": f.citation,
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&rows)?);
                    } else {
                        let mut jurisdiction = "";
                        for f in &fws {
                            if f.jurisdiction != jurisdiction {
                                jurisdiction = f.jurisdiction;
                                println!("\n{jurisdiction}");
                            }
                            println!("  {:<14} {}  ({})", f.id, f.name, f.citation);
                        }
                    }
                }
                ComplianceCommands::Status { head, from, to } => {
                    let mut rows = Vec::new();
                    for f in neleus_db::compliance::frameworks() {
                        let r = neleus_db::compliance::check(&db, &head, f.id, from, to)?;
                        rows.push((f, r.overall));
                    }
                    if json_output {
                        let json: Vec<_> = rows
                            .iter()
                            .map(|(f, status)| {
                                serde_json::json!({
                                    "id": f.id,
                                    "name": f.name,
                                    "jurisdiction": f.jurisdiction,
                                    "region": f.region,
                                    "overall": status,
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&json)?);
                    } else {
                        for (f, status) in &rows {
                            println!(
                                "{:<8} {:<10} {}",
                                compliance_word(*status),
                                f.region,
                                f.name
                            );
                        }
                    }
                }
                ComplianceCommands::Check {
                    head,
                    framework,
                    from,
                    to,
                } => {
                    let r = neleus_db::compliance::check(&db, &head, &framework, from, to)?;
                    if json_output {
                        println!("{}", serde_json::to_string_pretty(&r)?);
                    } else {
                        println!(
                            "{} — {} ({})\noverall: {}   retrievals: {}\n",
                            r.name,
                            r.jurisdiction,
                            r.citation,
                            compliance_word(r.overall),
                            r.retrievals
                        );
                        for c in &r.checks {
                            println!(
                                "  [{}] {:<11} {}\n        {}",
                                compliance_word(c.status),
                                format!("{:?}", c.severity).to_lowercase(),
                                c.label,
                                c.detail
                            );
                        }
                    }
                }
            }
        }
        Commands::Session { command } => {
            let db = Database::open(&db_path)?;
            let sessions = neleus_db::SessionStore::new(&db);
            match command {
                SessionCommands::Append {
                    head,
                    session_id,
                    role,
                    content,
                    content_file,
                    ttl_secs,
                } => {
                    let bytes = match (content, content_file) {
                        (Some(c), None) => c.into_bytes(),
                        (None, Some(p)) => fs::read(p)?,
                        _ => {
                            return Err(anyhow!(
                                "provide exactly one of --content or --content-file"
                            ));
                        }
                    };
                    let (seq, content_hash) =
                        sessions.append(&head, &session_id, role.as_deref(), &bytes, ttl_secs)?;
                    emit(
                        json_output,
                        serde_json::json!({"session_id": session_id, "seq": seq, "content_hash": content_hash.to_string()}),
                        &format!("turn {seq} appended"),
                    )?;
                }
                SessionCommands::List {
                    head,
                    session_id,
                    include_expired,
                } => {
                    let now = if include_expired {
                        None
                    } else {
                        Some(now_unix()?)
                    };
                    let records = sessions.list(&head, &session_id, now)?;
                    if json_output {
                        let rows: Result<Vec<_>> = records
                            .iter()
                            .map(|r| {
                                let content = sessions.content(r)?;
                                Ok(serde_json::json!({
                                    "seq": r.seq,
                                    "role": r.role,
                                    "created_at": r.created_at,
                                    "expires_at": r.expires_at,
                                    "content": String::from_utf8_lossy(&content),
                                }))
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&rows?)?);
                    } else {
                        for r in &records {
                            let content = sessions.content(r)?;
                            println!(
                                "[{}] {}: {}",
                                r.seq,
                                r.role.as_deref().unwrap_or("-"),
                                String::from_utf8_lossy(&content)
                            );
                        }
                        if records.is_empty() {
                            println!("no turns");
                        }
                    }
                }
                SessionCommands::Gc { head } => {
                    let removed = sessions.gc(&head, now_unix()?)?;
                    emit(
                        json_output,
                        serde_json::json!({"head": head, "removed": removed}),
                        &format!("removed {removed} expired records"),
                    )?;
                }
            }
        }
        Commands::Object { command } => {
            let db = Database::open(&db_path)?;
            match command {
                ObjectCommands::Inspect { hash } => {
                    let h: Hash = hash.parse()?;
                    let out = inspect_object(&db, h)?;
                    println!("{}", serde_json::to_string_pretty(&out)?);
                }
            }
        }
    }

    std::io::stdout().flush()?;
    Ok(())
}

fn resolve_state_root(db: &Database, head: &str) -> Result<Hash> {
    db.resolve_state_root(head)
}

fn resolve_head_commit(db: &Database, head: &str) -> Result<Hash> {
    db.refs
        .head_get(head)?
        .ok_or_else(|| anyhow!("head '{head}' not found"))
}

fn resolve_query_text(query: Option<String>, query_file: Option<PathBuf>) -> Result<String> {
    match (query, query_file) {
        (Some(q), None) => Ok(q),
        (None, Some(path)) => Ok(String::from_utf8_lossy(&fs::read(path)?).to_string()),
        (Some(_), Some(_)) => Err(anyhow!("provide either --query or --query-file, not both")),
        (None, None) => Err(anyhow!("provide one of --query or --query-file")),
    }
}

/// Best-effort open of `url` in the platform browser; never blocks the server.
fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");
    cmd.arg(url).spawn().map(|_| ())
}

/// `--param` flags override `--params-json` keys; sorted before hashing so equal
/// parameter sets hash identically. Returns `None` when both sources are empty.
fn build_model_parameters_blob(
    db: &neleus_db::db::Database,
    params_json: Option<PathBuf>,
    params: &[String],
) -> Result<Option<Hash>> {
    if params_json.is_none() && params.is_empty() {
        return Ok(None);
    }

    let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();

    if let Some(path) = params_json {
        let raw = fs::read(path)?;
        let obj: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(&raw)
            .map_err(|e| anyhow!("--params-json must be a JSON object: {e}"))?;
        map.extend(obj);
    }

    for kv in params {
        let (key, raw_val) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("--param must be key=value, got: {kv}"))?;
        let value: serde_json::Value = serde_json::from_str(raw_val)
            .unwrap_or_else(|_| serde_json::Value::String(raw_val.to_string()));
        map.insert(key.to_string(), value);
    }

    let json_bytes = serde_json::to_vec(&map)?;
    Ok(Some(db.blob_store.put(&json_bytes)?))
}

fn parse_io_hashes(values: &[String]) -> Result<(Vec<Hash>, Vec<Hash>)> {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();

    for raw in values {
        let (kind, value) = raw
            .split_once(':')
            .ok_or_else(|| anyhow!("--io-hashes entries must be in:<hash> or out:<hash>"))?;
        let hash: Hash = value.parse()?;
        match kind {
            "in" => inputs.push(hash),
            "out" => outputs.push(hash),
            _ => {
                return Err(anyhow!(
                    "unsupported io kind '{kind}'; expected in:<hash> or out:<hash>"
                ));
            }
        }
    }

    Ok((inputs, outputs))
}

fn decode_key(key: &str, enc: &KeyEncoding) -> Result<Vec<u8>> {
    match enc {
        KeyEncoding::Utf8 => Ok(key.as_bytes().to_vec()),
        KeyEncoding::Hex => Ok(hex::decode(key)?),
        KeyEncoding::Base64 => Ok(BASE64.decode(key.as_bytes())?),
    }
}

#[allow(clippy::too_many_arguments)]
/// Compliance vocabulary as a CCO reads it, not the engine's pass/warn/fail.
fn compliance_word(s: neleus_db::compliance::Status) -> &'static str {
    use neleus_db::compliance::Status;
    match s {
        Status::Pass => "satisfied",
        Status::Warn => "in-review",
        Status::Fail => "gap",
    }
}

#[allow(clippy::too_many_arguments)]
fn maybe_audit(
    engine: &neleus_db::Engine,
    audit: bool,
    commit: Hash,
    mode: &str,
    query: Option<&str>,
    embedding: Option<&[f32]>,
    top_k: usize,
    filter: &neleus_db::SearchFilter,
    hits: &[neleus_db::EngineHit],
) -> Result<Option<Hash>> {
    if !audit {
        return Ok(None);
    }
    Ok(Some(engine.record_query(
        commit,
        mode,
        query,
        embedding,
        top_k,
        filter,
        Some("cli"),
        hits,
    )?))
}

fn emit_hits(
    json_output: bool,
    mode: &str,
    head: &str,
    commit: Hash,
    hits: &[neleus_db::EngineHit],
    audit_manifest: Option<Hash>,
) -> Result<()> {
    if json_output {
        let json = serde_json::json!({
            "mode": mode,
            "head": head,
            "commit": commit.to_string(),
            "audit_manifest": audit_manifest.map(|h| h.to_string()),
            "hits": hits.iter().map(|h| {
                serde_json::json!({
                    "chunk_hash": h.chunk_hash.to_string(),
                    "score": h.score,
                    "text_preview": h.text_preview,
                })
            }).collect::<Vec<_>>()
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        for (idx, hit) in hits.iter().enumerate() {
            println!("{}. {} score={:.6}", idx + 1, hit.chunk_hash, hit.score);
            println!("   {}", hit.text_preview);
        }
        if hits.is_empty() {
            println!("no results");
        }
        if let Some(h) = audit_manifest {
            println!("audit manifest: {h} (attach with `commit new --manifest {h}`)");
        }
    }
    Ok(())
}

fn emit(json_output: bool, json_value: serde_json::Value, text: &str) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(&json_value)?);
    } else if !text.is_empty() {
        println!("{text}");
    }
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Decode an object by hash, trying each known typed structure.
fn inspect_object(db: &Database, hash: Hash) -> Result<serde_json::Value> {
    if db.blob_store.exists(hash) {
        let bytes = db.blob_store.get(hash)?;
        let text = String::from_utf8(bytes.clone()).ok();
        return Ok(serde_json::json!({
            "kind": "blob",
            "hash": hash.to_string(),
            "bytes": bytes.len(),
            "utf8": text,
            "hex_preview": to_hex(&bytes[..bytes.len().min(64)]),
        }));
    }

    if db.object_store.exists(hash) {
        let raw = db.object_store.get_bytes(hash)?;

        if let Ok(obj) = from_cbor::<Commit>(&raw) {
            return Ok(serde_json::json!({
                "kind": "commit",
                "hash": hash.to_string(),
                "object": obj,
            }));
        }
        if let Ok(obj) = from_cbor::<DocManifest>(&raw) {
            return Ok(serde_json::json!({
                "kind": "doc_manifest",
                "hash": hash.to_string(),
                "object": obj,
            }));
        }
        if let Ok(obj) = from_cbor::<RunManifest>(&raw) {
            return Ok(serde_json::json!({
                "kind": "run_manifest",
                "hash": hash.to_string(),
                "object": obj,
            }));
        }
        if let Ok(obj) = from_cbor::<ChunkManifest>(&raw) {
            return Ok(serde_json::json!({
                "kind": "chunk_manifest",
                "hash": hash.to_string(),
                "object": obj,
            }));
        }
        if let Ok(obj) = from_cbor::<StateManifest>(&raw) {
            return Ok(serde_json::json!({
                "kind": "state_manifest",
                "hash": hash.to_string(),
                "object": obj,
            }));
        }
        if let Ok(obj) = from_cbor::<StateNode>(&raw) {
            return Ok(serde_json::json!({
                "kind": "state_node",
                "hash": hash.to_string(),
                "object": obj,
            }));
        }

        return Ok(serde_json::json!({
            "kind": "unknown_object",
            "hash": hash.to_string(),
            "bytes": raw.len(),
            "hex_preview": to_hex(&raw[..raw.len().min(64)]),
        }));
    }

    Err(anyhow!("hash {} not found in blob or object store", hash))
}

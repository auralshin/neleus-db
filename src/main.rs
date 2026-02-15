use std::fs;
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use clap::{Parser, Subcommand, ValueEnum};
use neleus_db::db::Database;
use neleus_db::hash::Hash;
use neleus_db::index::{SearchHit, SearchIndexStore};
use neleus_db::manifest::{ChunkingSpec, RunManifest, now_unix};

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
}

#[derive(Debug, Subcommand)]
enum DbCommands {
    Init { path: PathBuf },
}

#[derive(Debug, Subcommand)]
enum BlobCommands {
    Put { file: PathBuf },
    Get { hash: String, out_file: PathBuf },
}

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
    },
    PutRun {
        #[arg(long)]
        model: String,
        #[arg(long)]
        prompt_file: PathBuf,
        #[arg(long = "io-hashes")]
        io_hashes: Vec<String>,
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
    },
}

#[derive(Debug, Subcommand)]
enum IndexCommands {
    Build {
        #[arg(long)]
        head: String,
    },
}

#[derive(Debug, Subcommand)]
enum SearchCommands {
    Semantic {
        #[arg(long)]
        head: String,
        #[arg(long)]
        query: Option<String>,
        #[arg(long)]
        query_file: Option<PathBuf>,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
    },
    Vector {
        #[arg(long)]
        head: String,
        #[arg(long)]
        embedding_file: PathBuf,
        #[arg(long, default_value_t = 10)]
        top_k: usize,
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
                } => {
                    let bytes = fs::read(file.clone())?;
                    let h = db.manifest_store.put_doc_manifest_from_bytes(
                        &db.blob_store,
                        source,
                        &bytes,
                        ChunkingSpec {
                            method: "fixed".into(),
                            chunk_size,
                            overlap,
                        },
                        None,
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
                } => {
                    let prompt = db.blob_store.put(&fs::read(prompt_file.clone())?)?;
                    let (inputs, outputs) = parse_io_hashes(&io_hashes)?;

                    let run = RunManifest {
                        schema_version: 1,
                        model,
                        prompt,
                        tool_calls: vec![],
                        inputs,
                        outputs,
                        started_at: now_unix(),
                        ended_at: now_unix(),
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
                    let base_root = resolve_state_root(&db, &head)?;
                    let value = fs::read(value_file.clone())?;
                    let new_root = db.state_store.set(base_root, &key_bytes, &value)?;
                    db.refs.state_set(&head, new_root)?;
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
                    let base_root = resolve_state_root(&db, &head)?;
                    let new_root = db.state_store.del(base_root, &key_bytes)?;
                    db.refs.state_set(&head, new_root)?;
                    emit(
                        json_output,
                        serde_json::json!({"state_root": new_root.to_string(), "head": head}),
                        &new_root.to_string(),
                    )?;
                }
                StateCommands::Compact { head } => {
                    let base_root = resolve_state_root(&db, &head)?;
                    let compacted = db.state_store.compact(base_root)?;
                    db.refs.state_set(&head, compacted)?;
                    emit(
                        json_output,
                        serde_json::json!({"state_root": compacted.to_string(), "head": head}),
                        &compacted.to_string(),
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
                } => {
                    let parent = db.refs.head_get(&head)?;
                    let parents = parent.into_iter().collect::<Vec<_>>();
                    let state_root = resolve_state_root(&db, &head)?;
                    let manifest_hashes = manifests
                        .into_iter()
                        .map(|m| m.parse::<Hash>())
                        .collect::<Result<Vec<_>, _>>()?;

                    let commit_hash = db.commit_store.create_commit(
                        parents,
                        state_root,
                        manifest_hashes,
                        author,
                        message,
                    )?;
                    db.refs.head_set(&head, commit_hash)?;
                    db.refs.state_set(&head, state_root)?;
                    emit(
                        json_output,
                        serde_json::json!({"commit_hash": commit_hash.to_string(), "head": head}),
                        &commit_hash.to_string(),
                    )?;
                }
            }
        }
        Commands::Index { command } => {
            let db = Database::open(&db_path)?;
            match command {
                IndexCommands::Build { head } => {
                    let commit = resolve_head_commit(&db, &head)?;
                    let index_hash = db.index_store.build_for_head(
                        commit,
                        &db.commit_store,
                        &db.manifest_store,
                        &db.blob_store,
                    )?;
                    emit(
                        json_output,
                        serde_json::json!({"head": head, "commit": commit.to_string(), "index_version": index_hash.to_string()}),
                        &index_hash.to_string(),
                    )?;
                }
            }
        }
        Commands::Search { command } => {
            let db = Database::open(&db_path)?;
            match command {
                SearchCommands::Semantic {
                    head,
                    query,
                    query_file,
                    top_k,
                } => {
                    let q = resolve_query_text(query, query_file)?;
                    let commit = resolve_head_commit(&db, &head)?;
                    let _ = db.index_store.build_for_head(
                        commit,
                        &db.commit_store,
                        &db.manifest_store,
                        &db.blob_store,
                    )?;
                    let hits = db.index_store.semantic_search(commit, &q, top_k)?;
                    emit_hits(json_output, "semantic", &head, commit, &hits)?;
                }
                SearchCommands::Vector {
                    head,
                    embedding_file,
                    top_k,
                } => {
                    let commit = resolve_head_commit(&db, &head)?;
                    let _ = db.index_store.build_for_head(
                        commit,
                        &db.commit_store,
                        &db.manifest_store,
                        &db.blob_store,
                    )?;
                    let bytes = fs::read(embedding_file)?;
                    let query_vec = SearchIndexStore::parse_embedding(&bytes)?;
                    let hits = db.index_store.vector_search(commit, &query_vec, top_k)?;
                    emit_hits(json_output, "vector", &head, commit, &hits)?;
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
            }
        }
    }

    std::io::stdout().flush()?;
    Ok(())
}

fn resolve_state_root(db: &Database, head: &str) -> Result<Hash> {
    if let Some(staged) = db.refs.state_get(head)? {
        return Ok(staged);
    }

    if let Some(commit_hash) = db.refs.head_get(head)? {
        let commit = db.commit_store.get_commit(commit_hash)?;
        return Ok(commit.state_root);
    }

    db.state_store.empty_root()
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

fn emit_hits(
    json_output: bool,
    mode: &str,
    head: &str,
    commit: Hash,
    hits: &[SearchHit],
) -> Result<()> {
    if json_output {
        let json = serde_json::json!({
            "mode": mode,
            "head": head,
            "commit": commit.to_string(),
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

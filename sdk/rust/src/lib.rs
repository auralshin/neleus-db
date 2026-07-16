//! Rust HTTP client for `neleus-db serve`.
//!
//! ```no_run
//! use neleus_client::{Client, SearchOpts};
//!
//! # fn main() -> Result<(), neleus_client::Error> {
//! let client = Client::new("http://127.0.0.1:7117", Some("nlk_…".into()));
//! let doc = client.put_document("main", "kb.md", "policy text", Default::default())?;
//! let res = client.search("main", SearchOpts { query: Some("policy".into()), audit: true, ..Default::default() })?;
//! let proof = client.prove(&res.commit, &res.hits[0].chunk, true)?;
//! assert!(client.verify(&proof)?.valid);
//! # Ok(()) }
//! ```
//!
//! For the embedded, in-process engine (no server), depend on the
//! `neleus-db` crate and use `neleus_db::Engine` directly.

mod http;

use std::time::Duration;

use serde::Deserialize;
use serde_json::json;

use http::Http;

#[derive(Debug)]
pub enum Error {
    Url(String),
    Io(String),
    Protocol(String),
    Status {
        status: u16,
        message: String,
        code: Option<String>, // stable neleus code, e.g. policy_violation
        hint: Option<String>,
    },
    Json(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Url(s) => write!(f, "url error: {s}"),
            Error::Io(s) => write!(f, "io error: {s}"),
            Error::Protocol(s) => write!(f, "protocol error: {s}"),
            Error::Status { status, message, hint: Some(h), .. } => {
                write!(f, "HTTP {status}: {message} (fix: {h})")
            }
            Error::Status { status, message, .. } => write!(f, "HTTP {status}: {message}"),
            Error::Json(s) => write!(f, "json error: {s}"),
        }
    }
}
impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

// ---- response types ----

#[derive(Debug, Clone, Deserialize)]
pub struct Hit {
    pub chunk: String,
    pub score: f32,
    pub preview: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SearchResult {
    pub commit: String,
    pub hits: Vec<Hit>,
    pub audit_manifest: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Verdict {
    pub valid: bool,
    pub anchor: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DocOpts {
    pub chunk_size: Option<usize>,
    pub overlap: Option<usize>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default)]
pub struct SearchOpts {
    pub mode: Option<String>,
    pub query: Option<String>,
    pub embedding: Option<Vec<f32>>,
    pub top_k: Option<usize>,
    pub filter: Option<serde_json::Value>,
    pub audit: bool,
}

// neleus://[token@]host[:port] -> (http base url, token); default port 7117.
fn parse_conn_str(conn: &str) -> Result<(String, Option<String>), Error> {
    let rest = conn.strip_prefix("neleus://").ok_or_else(|| {
        if conn.starts_with("neleuss://") {
            Error::Url("neleuss:// (TLS) needs a proxy; this client is http-only".into())
        } else {
            Error::Url(format!("not a neleus:// connection string: {conn}"))
        }
    })?;
    let rest = rest.trim_end_matches('/');
    let (token, hostport) = match rest.split_once('@') {
        Some((t, h)) => ((!t.is_empty()).then(|| t.to_string()), h),
        None => (None, rest),
    };
    let hostport = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:7117")
    };
    Ok((format!("http://{hostport}"), token))
}

pub struct Client {
    http: Http,
}

impl Client {
    pub fn new(url: &str, token: Option<String>) -> Self {
        Self {
            http: Http::new(url, token, Duration::from_secs(600)),
        }
    }

    /// Build from a `neleus://[token@]host[:port]` string. `neleuss://` is
    /// rejected: this client is http-only, so terminate TLS in a proxy.
    pub fn connect(conn_str: &str) -> Result<Self, Error> {
        let (url, token) = parse_conn_str(conn_str)?;
        Ok(Self::new(&url, token))
    }

    pub fn with_timeout(url: &str, token: Option<String>, timeout: Duration) -> Self {
        Self {
            http: Http::new(url, token, timeout),
        }
    }

    fn post<T: for<'de> Deserialize<'de>>(&self, path: &str, body: &serde_json::Value) -> Result<T, Error> {
        let raw = self
            .http
            .request("POST", path, Some("application/json"), Some(body.to_string().as_bytes()))?;
        Ok(serde_json::from_slice(&raw)?)
    }

    fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, Error> {
        let raw = self.http.request("GET", path, None, None)?;
        Ok(serde_json::from_slice(&raw)?)
    }

    // ---- core ----

    pub fn health(&self) -> Result<serde_json::Value, Error> {
        self.get("/v1/health")
    }

    pub fn blob_put(&self, bytes: &[u8]) -> Result<String, Error> {
        let raw = self
            .http
            .request("POST", "/v1/blobs", Some("application/octet-stream"), Some(bytes))?;
        let v: serde_json::Value = serde_json::from_slice(&raw)?;
        Ok(v["hash"].as_str().unwrap_or_default().to_string())
    }

    /// Fetch a blob (e.g. a retrieved chunk's full text) by hash.
    pub fn blob_get(&self, hash: &str) -> Result<Vec<u8>, Error> {
        self.http.request("GET", &format!("/v1/blobs/{hash}"), None, None)
    }

    pub fn put_document(
        &self,
        head: &str,
        source: &str,
        text: &str,
        opts: DocOpts,
    ) -> Result<serde_json::Value, Error> {
        self.post(
            "/v1/documents",
            &json!({
                "head": head,
                "source": source,
                "text": text,
                "chunk_size": opts.chunk_size.unwrap_or(512),
                "overlap": opts.overlap.unwrap_or(64),
                "metadata": opts.metadata,
            }),
        )
    }

    pub fn commit(&self, head: &str, message: &str, manifests: &[String]) -> Result<serde_json::Value, Error> {
        self.post("/v1/commits", &json!({"head": head, "message": message, "manifests": manifests}))
    }

    pub fn search(&self, at: &str, opts: SearchOpts) -> Result<SearchResult, Error> {
        self.post(
            "/v1/search",
            &json!({
                "at": at,
                "mode": opts.mode.unwrap_or_else(|| "hybrid".into()),
                "query": opts.query,
                "embedding": opts.embedding,
                "top_k": opts.top_k.unwrap_or(10),
                "filter": opts.filter,
                "audit": opts.audit,
            }),
        )
    }

    pub fn prove(&self, commit: &str, chunk: &str, include_content: bool) -> Result<String, Error> {
        let v: serde_json::Value = self.post(
            "/v1/proofs/chunk",
            &json!({"commit": commit, "chunk": chunk, "include_content": include_content}),
        )?;
        Ok(v["proof_cbor"].as_str().unwrap_or_default().to_string())
    }

    pub fn verify(&self, proof_cbor: &str) -> Result<Verdict, Error> {
        self.post("/v1/proofs/verify", &json!({"proof_cbor": proof_cbor}))
    }

    // ---- sessions ----

    pub fn session_append(
        &self,
        head: &str,
        session_id: &str,
        content: &str,
        role: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> Result<serde_json::Value, Error> {
        self.post(
            "/v1/sessions/append",
            &json!({"head": head, "session_id": session_id, "content": content, "role": role, "ttl_secs": ttl_secs}),
        )
    }

    pub fn session_list(&self, head: &str, session_id: &str) -> Result<serde_json::Value, Error> {
        self.post("/v1/sessions/list", &json!({"head": head, "session_id": session_id}))
    }

    pub fn checkpoint(&self, head: &str) -> Result<String, Error> {
        let v: serde_json::Value = self.post("/v1/checkpoints", &json!({"head": head}))?;
        Ok(v["checkpoint"].as_str().unwrap_or_default().to_string())
    }

    // ---- audit ----

    /// Download a self-contained, offline-verifiable `.nelaudit` bundle.
    pub fn export_bundle(&self, head: &str, from: Option<u64>, to: Option<u64>) -> Result<Vec<u8>, Error> {
        let mut body = json!({"head": head});
        if let Some(f) = from {
            body["from"] = json!(f);
        }
        if let Some(t) = to {
            body["to"] = json!(t);
        }
        self.http.request(
            "POST",
            "/v1/audit/export",
            Some("application/json"),
            Some(body.to_string().as_bytes()),
        )
    }

    // ---- run capture ----

    pub fn run(&self, provider: &str, model: &str) -> Run<'_> {
        Run {
            client: self,
            head: "main".into(),
            provider: provider.into(),
            model: model.into(),
            agent_id: None,
            prompt: None,
            system_prompt: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            retrieved: Vec::new(),
            message: None,
        }
    }
}

/// Records one model invocation; `commit()` persists it as a `RunManifest`.
pub struct Run<'a> {
    client: &'a Client,
    head: String,
    provider: String,
    model: String,
    agent_id: Option<String>,
    prompt: Option<String>,
    system_prompt: Option<String>,
    inputs: Vec<String>,
    outputs: Vec<String>,
    retrieved: Vec<String>,
    message: Option<String>,
}

impl Run<'_> {
    pub fn head(mut self, head: &str) -> Self {
        self.head = head.into();
        self
    }
    pub fn agent_id(mut self, id: &str) -> Self {
        self.agent_id = Some(id.into());
        self
    }
    pub fn prompt(mut self, text: &str) -> Self {
        self.prompt = Some(text.into());
        self
    }
    pub fn system_prompt(mut self, text: &str) -> Self {
        self.system_prompt = Some(text.into());
        self
    }
    pub fn retrieved_chunks(mut self, hashes: &[String]) -> Self {
        self.retrieved.extend_from_slice(hashes);
        self
    }
    pub fn input(mut self, content: &[u8]) -> Result<Self, Error> {
        self.inputs.push(self.client.blob_put(content)?);
        Ok(self)
    }
    pub fn output(mut self, content: &[u8]) -> Result<Self, Error> {
        self.outputs.push(self.client.blob_put(content)?);
        Ok(self)
    }
    pub fn message(mut self, msg: &str) -> Self {
        self.message = Some(msg.into());
        self
    }

    pub fn commit(self) -> Result<serde_json::Value, Error> {
        self.client.post(
            "/v1/runs",
            &json!({
                "head": self.head,
                "model": self.model,
                "provider": self.provider,
                "prompt": self.prompt.unwrap_or_default(),
                "system_prompt": self.system_prompt,
                "inputs": self.inputs,
                "outputs": self.outputs,
                "retrieved_chunks": self.retrieved,
                "agent_id": self.agent_id,
                "message": self.message,
                "commit": true,
            }),
        )
    }
}

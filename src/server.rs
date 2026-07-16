//! std-only HTTP/1.1 server over [`Engine`]; no async runtime, no in-process
//! TLS (terminate in front).
//!
//! Security invariants:
//! - auth required unless `--no-auth` (loopback-only)
//! - non-loopback bind requires `allow_remote` + configured keys
//! - tenant keys: heads under `<tenant>/` only, forced tenant filter,
//!   no access to blobs/pack/refs endpoints
//! - single writer mutex; readers run concurrently on commit snapshots
//! - bounds: headers 64 KiB, JSON 8 MiB, pack 4 GiB, top_k 1000, conns 256

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::auth::{AuthRegistry, Principal, Role};
use crate::engine::{Engine, SearchFilter};
use crate::hash::Hash;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_JSON_BODY: usize = 8 * 1024 * 1024;
const MAX_PACK_BODY: usize = 4 * 1024 * 1024 * 1024;
const MAX_TOP_K: usize = 1000;
const MAX_CONNECTIONS: usize = 256;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub addr: String,
    /// Permit binding non-loopback addresses (still requires auth keys).
    pub allow_remote: bool,
    /// Run without authentication. Loopback-only escape hatch for dev.
    pub no_auth: bool,
    /// `Access-Control-Allow-Origin` value for browser clients. None = no CORS
    /// headers; cross-origin browser calls fail. The bundled console is
    /// same-origin and needs no CORS.
    pub cors_origin: Option<String>,
    /// Mint a per-process admin token accepted only from loopback peers and
    /// injected into the served console, so localhost "just works". Ignored on
    /// remote binds and under `--no-auth`. Default on.
    pub bootstrap: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:7117".into(),
            allow_remote: false,
            no_auth: false,
            cors_origin: None,
            bootstrap: true,
        }
    }
}

pub struct ServerHandle {
    pub addr: SocketAddr,
    /// The per-process loopback bootstrap admin token, if one was minted.
    pub bootstrap_token: Option<String>,
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl ServerHandle {
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Unblock accept() with a no-op connection.
        let _ = TcpStream::connect(self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct ServerState {
    engine: Engine,
    cors_origin: Option<String>,
    /// `Some(db_root)` when auth is enabled; registry reloads per request so
    /// revocation is immediate.
    auth_root: Option<std::path::PathBuf>,
    /// Loopback-only admin token (see [`ServerConfig::bootstrap`]).
    bootstrap_token: Option<String>,
    write_lock: Mutex<()>,
}

/// Binds and serves on background threads until [`ServerHandle::shutdown`].
pub fn start(engine: Engine, config: ServerConfig) -> Result<ServerHandle> {
    let listener =
        TcpListener::bind(&config.addr).with_context(|| format!("binding {}", config.addr))?;
    let addr = listener.local_addr()?;
    let loopback = addr.ip().is_loopback();

    // Per-process bootstrap admin token: only minted on a loopback bind with
    // auth on, only honored for loopback peers, never persisted. Lets a fresh
    // db serve a working console with zero key setup.
    let bootstrap_token = if !config.no_auth && config.bootstrap && loopback {
        Some(format!(
            "nlk_{}",
            hex::encode(crate::encryption::utils::random_bytes(32)?)
        ))
    } else {
        None
    };

    let auth_root = if config.no_auth {
        None
    } else {
        let registry = AuthRegistry::load(&engine.db().root)?;
        if registry.is_empty() && bootstrap_token.is_none() {
            bail!(
                "no API keys configured (meta/auth.json). Mint one with \
                 `neleus-db auth add-key --id <name> --role <role>`, serve on \
                 loopback for an auto bootstrap token, or pass --no-auth for \
                 loopback-only development."
            );
        }
        Some(engine.db().root.clone())
    };

    if !loopback {
        if !config.allow_remote {
            bail!(
                "refusing non-loopback bind {addr} without --allow-remote \
                 (and put a TLS terminator in front of it)"
            );
        }
        if auth_root.is_none() {
            bail!("refusing non-loopback bind {addr} with --no-auth");
        }
    }

    let state = Arc::new(ServerState {
        engine,
        cors_origin: config.cors_origin.clone(),
        auth_root,
        bootstrap_token: bootstrap_token.clone(),
        write_lock: Mutex::new(()),
    });
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));

    let stop_accept = Arc::clone(&stop);
    let join = std::thread::spawn(move || {
        for conn in listener.incoming() {
            if stop_accept.load(Ordering::SeqCst) {
                break;
            }
            let Ok(stream) = conn else { continue };
            if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                let _ = respond_raw(
                    &stream,
                    503,
                    "application/json",
                    br#"{"error":"server overloaded","code":"overloaded","hint":"retry shortly; the connection cap was reached"}"#,
                );
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);
            let state = Arc::clone(&state);
            let active = Arc::clone(&active);
            std::thread::spawn(move || {
                let _ = handle_connection(stream, &state);
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });

    Ok(ServerHandle {
        addr,
        bootstrap_token,
        stop,
        join: Some(join),
    })
}

// ---------- embedded web console ----------

#[cfg(feature = "console")]
mod console_assets {
    include!(concat!(env!("OUT_DIR"), "/console_assets.rs"));
}
#[cfg(not(feature = "console"))]
mod console_assets {
    pub static ASSETS: &[(&str, &str, bool, &[u8])] = &[];
}

struct StaticResponse {
    content_type: &'static str,
    cache: &'static str,
    /// `Some("zstd")` when the body is served compressed as-is.
    encoding: Option<&'static str>,
    body: Vec<u8>,
}

/// Resolve `raw_path` (may carry a query/fragment) to an embedded console
/// asset. Extension-less paths fall back to `index.html` for SPA client
/// routing. `bootstrap` injects a one-time admin token into `index.html` for
/// loopback callers. zstd-compressed assets are served as-is when the client
/// sent `accept-encoding: zstd`, else decompressed on the fly so no client
/// breaks.
fn serve_console(
    raw_path: &str,
    bootstrap: Option<&str>,
    accepts_zstd: bool,
) -> Option<StaticResponse> {
    let path = raw_path.split(['?', '#']).next().unwrap_or("/");
    let path = if path == "/" { "/index.html" } else { path };

    if let Some((ct, compressed, bytes)) = console_lookup(path) {
        return build_static(
            ct,
            cache_control(path),
            path,
            compressed,
            bytes,
            bootstrap,
            accepts_zstd,
        );
    }
    // Unknown, extension-less path -> hand the SPA its shell.
    let extensionless = !path.rsplit('/').next().unwrap_or("").contains('.');
    if extensionless && let Some((ct, compressed, bytes)) = console_lookup("/index.html") {
        return build_static(
            ct,
            "no-cache",
            "/index.html",
            compressed,
            bytes,
            bootstrap,
            accepts_zstd,
        );
    }
    None
}

fn build_static(
    content_type: &'static str,
    cache: &'static str,
    path: &str,
    compressed: bool,
    bytes: &'static [u8],
    bootstrap: Option<&str>,
    accepts_zstd: bool,
) -> Option<StaticResponse> {
    let (body, encoding) = if compressed {
        if accepts_zstd {
            (bytes.to_vec(), Some("zstd"))
        } else {
            // Rare client without zstd: decompress with the same crate.
            (
                crate::compression::decompress_if_compressed(bytes)
                    .ok()?
                    .into_owned(),
                None,
            )
        }
    } else {
        (inject_bootstrap(path, bytes, bootstrap), None)
    };
    Some(StaticResponse {
        content_type,
        cache,
        encoding,
        body,
    })
}

fn console_lookup(path: &str) -> Option<(&'static str, bool, &'static [u8])> {
    console_assets::ASSETS
        .iter()
        .find(|(p, _, _, _)| *p == path)
        .map(|(_, ct, compressed, bytes)| (*ct, *compressed, *bytes))
}

/// Vite fingerprints everything under `/assets/`, so those are immutable;
/// the HTML shell must always be revalidated.
fn cache_control(path: &str) -> &'static str {
    if path.starts_with("/assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    }
}

fn inject_bootstrap(path: &str, bytes: &'static [u8], bootstrap: Option<&str>) -> Vec<u8> {
    let Some(token) = bootstrap else {
        return bytes.to_vec();
    };
    if path != "/index.html" {
        return bytes.to_vec();
    }
    let html = String::from_utf8_lossy(bytes);
    let snippet = format!(
        "<script>window.__NELEUS_BOOTSTRAP__={};window.__NELEUS_ORIGIN__=location.origin;</script>",
        Value::from(token)
    );
    match html.find("</head>") {
        Some(i) => {
            let mut out = String::with_capacity(html.len() + snippet.len());
            out.push_str(&html[..i]);
            out.push_str(&snippet);
            out.push_str(&html[i..]);
            out.into_bytes()
        }
        None => bytes.to_vec(),
    }
}

// ---------- request plumbing ----------

struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
    principal: Option<Principal>,
}

fn handle_connection(stream: TcpStream, state: &ServerState) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(600)))?;
    stream.set_write_timeout(Some(Duration::from_secs(600)))?;
    let loopback_peer = stream
        .peer_addr()
        .map(|a| a.ip().is_loopback())
        .unwrap_or(false);
    let mut reader = BufReader::new(stream.try_clone()?);

    // Request line + headers, bounded.
    let mut head = String::new();
    let mut total = 0usize;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(()); // peer closed
        }
        total += n;
        if total > MAX_HEADER_BYTES {
            return respond(&stream, 431, &err_json(431, "request headers too large"));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        head.push_str(&line);
    }

    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_uppercase();
    let path = parts.next().unwrap_or_default().to_string();

    let mut content_length = 0usize;
    let mut bearer: Option<String> = None;
    let mut accepts_zstd = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.to_ascii_lowercase().as_str() {
            "content-length" => content_length = v.parse().unwrap_or(0),
            "authorization" => {
                bearer = v
                    .strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
                    .map(str::to_string);
            }
            "accept-encoding" => accepts_zstd = v.to_ascii_lowercase().contains("zstd"),
            _ => {}
        }
    }

    // CORS preflight: answered before auth (browsers cannot attach the
    // Authorization header to OPTIONS).
    if method == "OPTIONS" {
        return match &state.cors_origin {
            Some(origin) => Ok(respond_cors(&stream, 204, "text/plain", b"", origin)?),
            None => Ok(respond_raw(&stream, 204, "text/plain", b"")?),
        };
    }

    // Console assets are public — the browser fetches them before it has any
    // token — so they are served ahead of the auth gate. The API (`/v1/*`)
    // never takes this path and stays authenticated.
    if method == "GET" && !path.starts_with("/v1/") {
        let bootstrap = if loopback_peer {
            state.bootstrap_token.as_deref()
        } else {
            None
        };
        if let Some(res) = serve_console(&path, bootstrap, accepts_zstd) {
            return Ok(respond_static(&stream, &res)?);
        }
        if path == "/" {
            let hint = b"neleus-db is running, but the web console was not bundled \
                         in this build. Rebuild with the `console` feature.\n";
            return Ok(respond_raw(
                &stream,
                200,
                "text/plain; charset=utf-8",
                hint,
            )?);
        }
    }

    let body_cap = if path == "/v1/pack" {
        MAX_PACK_BODY
    } else {
        MAX_JSON_BODY
    };
    if content_length > body_cap {
        return respond(&stream, 413, &err_json(413, "request body too large"));
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;

    // Fresh registry per request: revocation takes effect immediately. The
    // loopback bootstrap token authenticates as admin, but only from a loopback
    // peer — a leaked token is useless off-box.
    let principal = match &state.auth_root {
        None => None,
        Some(root) => {
            let registry = AuthRegistry::load(root)?;
            match bearer.as_deref().and_then(|t| registry.authenticate(t)) {
                Some(p) => Some(p),
                None => match (&state.bootstrap_token, loopback_peer) {
                    (Some(bt), true) if bearer.as_deref() == Some(bt.as_str()) => Some(Principal {
                        key_id: "bootstrap".into(),
                        role: Role::Admin,
                        tenant: None,
                    }),
                    _ => {
                        return respond(
                            &stream,
                            401,
                            &err_json(401, "missing or invalid bearer token"),
                        );
                    }
                },
            }
        }
    };

    let request = Request {
        method,
        path,
        body,
        principal,
    };
    let (status, content_type, payload): (u16, &str, Vec<u8>) = match route(state, &request) {
        Ok(Response::Json(status, value)) => {
            (status, "application/json", value.to_string().into_bytes())
        }
        Ok(Response::Bytes(content_type, bytes)) => (200, content_type, bytes),
        Err(e) => {
            let (status, msg) = classify_error(&e);
            (
                status,
                "application/json",
                err_json(status, &msg).to_string().into_bytes(),
            )
        }
    };
    match &state.cors_origin {
        Some(origin) => respond_cors(&stream, status, content_type, &payload, origin)?,
        None => respond_raw(&stream, status, content_type, &payload)?,
    }
    Ok(())
}

fn classify_error(e: &anyhow::Error) -> (u16, String) {
    let msg = e.to_string();
    let status = if msg.starts_with("forbidden") {
        403
    } else if msg.contains("not found") || msg.contains("missing") || msg.contains("has no commits")
    {
        404
    } else if msg.starts_with("bad request") || msg.contains("invalid") {
        400
    } else {
        500
    };
    (status, msg)
}

// Stable code + fix hint per status; policy_violation is split from a plain
// auth forbidden so clients can branch on it.
fn error_meta(status: u16, msg: &str) -> (&'static str, Option<&'static str>) {
    match status {
        400 => (
            "bad_request",
            Some("check the request fields and value types"),
        ),
        401 => (
            "unauthorized",
            Some("send `Authorization: Bearer <nlk_…>`; mint a key with `neleus-db auth add-key`"),
        ),
        403 if msg.contains("policy '") => (
            "policy_violation",
            Some(
                "satisfy the rule, or relax the policy to monitor mode with `neleus-db policy set`",
            ),
        ),
        403 => (
            "forbidden",
            Some("use a key whose role/tenant is permitted for this endpoint"),
        ),
        404 => ("not_found", None),
        413 => (
            "payload_too_large",
            Some("shrink the body (JSON ≤ 8 MiB, pack ≤ 4 GiB)"),
        ),
        431 => ("headers_too_large", None),
        503 => (
            "overloaded",
            Some("retry shortly; the connection cap was reached"),
        ),
        _ => ("internal", None),
    }
}

/// The neleus error envelope: `{ error, code, hint? }`.
fn err_json(status: u16, msg: &str) -> Value {
    let (code, hint) = error_meta(status, msg);
    match hint {
        Some(h) => json!({"error": msg, "code": code, "hint": h}),
        None => json!({"error": msg, "code": code}),
    }
}

enum Response {
    Json(u16, Value),
    Bytes(&'static str, Vec<u8>),
}

fn respond(stream: &TcpStream, status: u16, body: &Value) -> Result<()> {
    respond_raw(
        stream,
        status,
        "application/json",
        body.to_string().as_bytes(),
    )?;
    Ok(())
}

fn respond_cors(
    stream: &TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    origin: &str,
) -> std::io::Result<()> {
    respond_with_headers(
        stream,
        status,
        content_type,
        body,
        &format!(
            "access-control-allow-origin: {origin}\r\naccess-control-allow-headers: authorization, content-type\r\naccess-control-allow-methods: GET, POST, OPTIONS\r\n"
        ),
    )
}

fn respond_raw(
    stream: &TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    respond_with_headers(stream, status, content_type, body, "")
}

fn respond_static(stream: &TcpStream, res: &StaticResponse) -> std::io::Result<()> {
    let mut extra = format!("cache-control: {}\r\n", res.cache);
    if let Some(enc) = res.encoding {
        extra.push_str(&format!(
            "content-encoding: {enc}\r\nvary: accept-encoding\r\n"
        ));
    }
    respond_with_headers(stream, 200, res.content_type, &res.body, &extra)
}

fn respond_with_headers(
    mut stream: &TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    stream.write_all(
        format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n{extra}connection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    )?;
    stream.write_all(body)?;
    stream.flush()
}

// ---------- authorization helpers ----------

fn require(req: &Request, role: Role) -> Result<()> {
    if let Some(p) = &req.principal
        && !p.allows(role)
    {
        bail!("forbidden: requires {role:?} role");
    }
    Ok(())
}

/// Gate for endpoints below the tenancy boundary (blobs, packs, refs).
fn require_untenanted(req: &Request, role: Role) -> Result<()> {
    require(req, role)?;
    if req.principal.as_ref().is_some_and(|p| p.tenant.is_some()) {
        bail!("forbidden: endpoint is not available to tenant-scoped keys");
    }
    Ok(())
}

/// Tenant keys may only touch heads under their prefix.
fn scope_head<'a>(req: &Request, head: &'a str) -> Result<&'a str> {
    if let Some(p) = &req.principal
        && let Some(tenant) = &p.tenant
        && !head.starts_with(&format!("{tenant}/"))
    {
        bail!("forbidden: head must be under '{tenant}/' for this key");
    }
    Ok(head)
}

/// Pin a tenant key's filter to its partition.
fn scope_filter(req: &Request, mut filter: SearchFilter) -> SearchFilter {
    if let Some(p) = &req.principal
        && let Some(tenant) = &p.tenant
    {
        filter.tenant = Some(tenant.clone());
    }
    filter
}

fn principal_id(req: &Request) -> Option<String> {
    req.principal.as_ref().map(|p| format!("key:{}", p.key_id))
}

// ---------- routing ----------

fn parse_json(body: &[u8]) -> Result<Value> {
    serde_json::from_slice(body).map_err(|e| anyhow!("bad request: invalid JSON: {e}"))
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("bad request: missing string field '{key}'"))
}

fn hash_field(v: &Value, key: &str) -> Result<Hash> {
    str_field(v, key)?
        .parse::<Hash>()
        .map_err(|e| anyhow!("bad request: field '{key}' is not a hash: {e}"))
}

fn b64_field(v: &Value, key: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let raw = str_field(v, key)?;
    base64::engine::general_purpose::STANDARD
        .decode(raw)
        .map_err(|e| anyhow!("bad request: field '{key}' is not base64: {e}"))
}

fn filter_from(v: &Value) -> Result<SearchFilter> {
    match v.get("filter") {
        None | Some(Value::Null) => Ok(SearchFilter::default()),
        Some(f) => serde_json::from_value(f.clone())
            .map_err(|e| anyhow!("bad request: invalid filter: {e}")),
    }
}

fn route(state: &ServerState, req: &Request) -> Result<Response> {
    let engine = &state.engine;
    let db = engine.db();

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/health") => Ok(Response::Json(
            200,
            json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}),
        )),

        ("GET", "/v1/refs") => {
            require_untenanted(req, Role::Reader)?;
            let heads: Vec<Value> = db
                .refs
                .list_heads()?
                .into_iter()
                .map(|(name, hash)| json!({"name": name, "commit": hash.to_string()}))
                .collect();
            let checkpoints: Vec<Value> = db
                .refs
                .list_checkpoints()?
                .into_iter()
                .map(|(name, hash)| json!({"name": name, "checkpoint": hash.to_string()}))
                .collect();
            Ok(Response::Json(
                200,
                json!({"heads": heads, "checkpoints": checkpoints}),
            ))
        }

        ("POST", "/v1/blobs") => {
            require_untenanted(req, Role::Writer)?;
            let _w = state.write_lock.lock().expect("write lock poisoned");
            let hash = db.blob_store.put(&req.body)?;
            Ok(Response::Json(200, json!({"hash": hash.to_string()})))
        }

        ("GET", path) if path.starts_with("/v1/blobs/") => {
            require_untenanted(req, Role::Reader)?;
            let hash: Hash = path["/v1/blobs/".len()..]
                .parse()
                .map_err(|e| anyhow!("bad request: invalid hash: {e}"))?;
            Ok(Response::Bytes(
                "application/octet-stream",
                db.blob_store.get(hash)?,
            ))
        }

        ("POST", "/v1/state/get") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let key = b64_field(&v, "key")?;
            let root = db.resolve_state_root(head)?;
            use base64::Engine as _;
            let value = db
                .state_store
                .get(root, &key)?
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes));
            Ok(Response::Json(
                200,
                json!({"root": root.to_string(), "value": value}),
            ))
        }

        ("POST", "/v1/state/set") => {
            require(req, Role::Writer)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let key = b64_field(&v, "key")?;
            let value = b64_field(&v, "value")?;
            let _w = state.write_lock.lock().expect("write lock poisoned");
            let root = db.state_set_at_head(head, &key, &value)?;
            Ok(Response::Json(200, json!({"root": root.to_string()})))
        }

        ("POST", "/v1/state/delete") => {
            require(req, Role::Writer)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let key = b64_field(&v, "key")?;
            let _w = state.write_lock.lock().expect("write lock poisoned");
            let root = db.state_del_at_head(head, &key)?;
            Ok(Response::Json(200, json!({"root": root.to_string()})))
        }

        ("POST", "/v1/state/prove") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let key = b64_field(&v, "key")?;
            let root = db.resolve_state_root(head)?;
            let proof = db.state_store.proof(root, &key)?;
            use base64::Engine as _;
            let bundle = base64::engine::general_purpose::STANDARD
                .encode(crate::canonical::to_cbor(&proof)?);
            Ok(Response::Json(
                200,
                json!({"root": root.to_string(), "proof_cbor": bundle}),
            ))
        }

        ("POST", "/v1/documents") => {
            require(req, Role::Writer)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let source = str_field(&v, "source")?;
            let text = str_field(&v, "text")?;
            let chunk_size = v.get("chunk_size").and_then(Value::as_u64).unwrap_or(512) as usize;
            let overlap = v.get("overlap").and_then(Value::as_u64).unwrap_or(64) as usize;
            let mut metadata: Option<crate::manifest::ChunkMetadata> = match v.get("metadata") {
                None | Some(Value::Null) => None,
                Some(m) => Some(
                    serde_json::from_value(m.clone())
                        .map_err(|e| anyhow!("bad request: invalid metadata: {e}"))?,
                ),
            };
            // Ingested chunks always carry the tenant of a tenant key.
            if let Some(p) = &req.principal
                && let Some(tenant) = &p.tenant
            {
                let mut m = metadata.unwrap_or_default();
                m.tenant = Some(tenant.clone());
                metadata = Some(m);
            }
            let author = principal_id(req).unwrap_or_else(|| "server".into());
            let _w = state.write_lock.lock().expect("write lock poisoned");
            crate::policy::enforce_write(
                db,
                &crate::policy::WriteContext {
                    op: "documents",
                    head,
                    principal: req.principal.as_ref().map(|p| p.key_id.as_str()),
                    has_provenance: false,
                },
            )?;
            let (manifest, commit) = engine.put_document(
                head,
                source,
                text.as_bytes(),
                crate::manifest::ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size,
                    overlap,
                },
                metadata,
                &author,
            )?;
            Ok(Response::Json(
                200,
                json!({"manifest": manifest.to_string(), "commit": commit.to_string()}),
            ))
        }

        ("POST", "/v1/runs") => {
            require(req, Role::Writer)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let model = str_field(&v, "model")?;
            let now = crate::clock::now_unix()?;

            let hashes = |key: &str| -> Result<Vec<Hash>> {
                match v.get(key) {
                    None | Some(Value::Null) => Ok(vec![]),
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|i| {
                            i.as_str()
                                .ok_or_else(|| anyhow!("bad request: {key} entry not a string"))?
                                .parse::<Hash>()
                                .map_err(|e| anyhow!("bad request: invalid hash in {key}: {e}"))
                        })
                        .collect(),
                    Some(_) => Err(anyhow!("bad request: {key} must be an array")),
                }
            };

            let _w = state.write_lock.lock().expect("write lock poisoned");
            let has_provenance = v.get("provider").and_then(Value::as_str).is_some()
                || v.get("inputs")
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty())
                || v.get("retrieved_chunks")
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty());
            crate::policy::enforce_write(
                db,
                &crate::policy::WriteContext {
                    op: "runs",
                    head,
                    principal: req.principal.as_ref().map(|p| p.key_id.as_str()),
                    has_provenance,
                },
            )?;
            let prompt = db.blob_store.put(
                v.get("prompt")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .as_bytes(),
            )?;
            let system_prompt = match v.get("system_prompt").and_then(Value::as_str) {
                Some(sp) => Some(db.blob_store.put(sp.as_bytes())?),
                None => None,
            };
            let model_parameters = match v.get("model_parameters") {
                None | Some(Value::Null) => None,
                Some(params) => {
                    // Sorted-keys JSON: identical parameter sets dedup.
                    let canonical: std::collections::BTreeMap<String, Value> =
                        serde_json::from_value(params.clone())
                            .map_err(|e| anyhow!("bad request: model_parameters: {e}"))?;
                    Some(
                        db.blob_store
                            .put(serde_json::to_string(&canonical)?.as_bytes())?,
                    )
                }
            };

            let manifest = crate::manifest::RunManifest {
                schema_version: crate::manifest::MANIFEST_SCHEMA_VERSION,
                model: model.to_string(),
                prompt,
                tool_calls: vec![],
                inputs: hashes("inputs")?,
                outputs: hashes("outputs")?,
                started_at: v.get("started_at").and_then(Value::as_u64).unwrap_or(now),
                ended_at: v.get("ended_at").and_then(Value::as_u64).unwrap_or(now),
                provider: v
                    .get("provider")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                system_prompt,
                model_parameters,
                retrieved_chunks: hashes("retrieved_chunks")?,
                sdk_version: v
                    .get("sdk_version")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                agent_id: v
                    .get("agent_id")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                trace_id: v
                    .get("trace_id")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                parent_span: match v.get("parent_span").and_then(Value::as_str) {
                    Some(s) => Some(
                        s.parse::<Hash>()
                            .map_err(|e| anyhow!("bad request: invalid parent_span: {e}"))?,
                    ),
                    None => None,
                },
                delegated_from: v
                    .get("delegated_from")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                subject: v.get("subject").and_then(Value::as_str).map(str::to_string),
            };
            let manifest_hash = db.manifest_store.put_manifest(&manifest)?;

            let commit = if v.get("commit").and_then(Value::as_bool).unwrap_or(true) {
                let author = principal_id(req).unwrap_or_else(|| "server".into());
                let message = v
                    .get("message")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("{model} run"));
                Some(
                    engine
                        .commit(head, &author, &message, vec![manifest_hash])?
                        .to_string(),
                )
            } else {
                None
            };
            Ok(Response::Json(
                200,
                json!({"manifest": manifest_hash.to_string(), "commit": commit}),
            ))
        }

        ("POST", "/v1/commits") => {
            require(req, Role::Writer)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let message = str_field(&v, "message")?;
            let author = principal_id(req).unwrap_or_else(|| "server".into());
            let manifests: Vec<Hash> = match v.get("manifests") {
                None | Some(Value::Null) => vec![],
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|i| {
                        i.as_str()
                            .ok_or_else(|| anyhow!("bad request: manifest not a string"))?
                            .parse::<Hash>()
                            .map_err(|e| anyhow!("bad request: invalid manifest hash: {e}"))
                    })
                    .collect::<Result<_>>()?,
                Some(_) => bail!("bad request: manifests must be an array"),
            };
            let _w = state.write_lock.lock().expect("write lock poisoned");
            crate::policy::enforce_write(
                db,
                &crate::policy::WriteContext {
                    op: "commits",
                    head,
                    principal: req.principal.as_ref().map(|p| p.key_id.as_str()),
                    has_provenance: false,
                },
            )?;
            let commit = engine.commit(head, &author, message, manifests)?;
            Ok(Response::Json(200, json!({"commit": commit.to_string()})))
        }

        ("POST", "/v1/search") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let at = str_field(&v, "at")?;
            // Commit hashes pass: results are tenant-filtered below.
            if at.len() != 64 {
                scope_head(req, at)?;
            }
            let commit = engine.resolve_commit(at)?;
            let mode = v.get("mode").and_then(Value::as_str).unwrap_or("hybrid");
            let top_k =
                (v.get("top_k").and_then(Value::as_u64).unwrap_or(10) as usize).min(MAX_TOP_K);
            let filter = scope_filter(req, filter_from(&v)?);
            let query = v.get("query").and_then(Value::as_str);
            let embedding: Option<Vec<f32>> = match v.get("embedding") {
                None | Some(Value::Null) => None,
                Some(e) => Some(
                    serde_json::from_value(e.clone())
                        .map_err(|e| anyhow!("bad request: invalid embedding: {e}"))?,
                ),
            };

            let hits = match mode {
                "semantic" => engine.search_semantic(
                    commit,
                    query.ok_or_else(|| anyhow!("bad request: semantic mode needs 'query'"))?,
                    top_k,
                    &filter,
                )?,
                "vector" => engine.search_vector(
                    commit,
                    embedding
                        .as_deref()
                        .ok_or_else(|| anyhow!("bad request: vector mode needs 'embedding'"))?,
                    top_k,
                    &filter,
                )?,
                "hybrid" => {
                    engine.search_hybrid(commit, query, embedding.as_deref(), top_k, &filter)?
                }
                other => bail!("bad request: unknown mode '{other}'"),
            };

            let audit = v.get("audit").and_then(Value::as_bool).unwrap_or(false);
            let audit_manifest = if audit {
                Some(
                    engine
                        .record_query(
                            commit,
                            mode,
                            query,
                            embedding.as_deref(),
                            top_k,
                            &filter,
                            principal_id(req).as_deref(),
                            &hits,
                        )?
                        .to_string(),
                )
            } else {
                None
            };

            let hits_json: Vec<Value> = hits
                .iter()
                .map(|h| {
                    json!({
                        "chunk": h.chunk_hash.to_string(),
                        "score": h.score,
                        "preview": h.text_preview,
                    })
                })
                .collect();
            Ok(Response::Json(
                200,
                json!({
                    "commit": commit.to_string(),
                    "hits": hits_json,
                    "audit_manifest": audit_manifest,
                }),
            ))
        }

        ("POST", "/v1/proofs/chunk") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let commit = hash_field(&v, "commit")?;
            let chunk = hash_field(&v, "chunk")?;
            let include = v
                .get("include_content")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let proof = engine.prove(commit, chunk, include)?;
            use base64::Engine as _;
            let bundle = base64::engine::general_purpose::STANDARD
                .encode(crate::canonical::to_cbor(&proof)?);
            Ok(Response::Json(200, json!({"proof_cbor": bundle})))
        }

        ("POST", "/v1/proofs/verify") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            use base64::Engine as _;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(str_field(&v, "proof_cbor")?)
                .map_err(|e| anyhow!("bad request: proof_cbor is not base64: {e}"))?;
            let proof: crate::retrieval_proof::ChunkProof = crate::canonical::from_cbor(&bytes)
                .map_err(|e| anyhow!("bad request: not a chunk proof: {e}"))?;
            match crate::retrieval_proof::verify_chunk_proof(&proof) {
                Ok(kind) => Ok(Response::Json(200, json!({"valid": true, "anchor": kind}))),
                Err(e) => Ok(Response::Json(
                    200,
                    json!({"valid": false, "error": e.to_string()}),
                )),
            }
        }

        ("POST", "/v1/sessions/append") => {
            require(req, Role::Writer)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let session_id = str_field(&v, "session_id")?;
            let content = str_field(&v, "content")?;
            let role = v.get("role").and_then(Value::as_str);
            let ttl_secs = v.get("ttl_secs").and_then(Value::as_u64);
            let _w = state.write_lock.lock().expect("write lock poisoned");
            let (seq, content_hash) =
                engine
                    .sessions()
                    .append(head, session_id, role, content.as_bytes(), ttl_secs)?;
            Ok(Response::Json(
                200,
                json!({"seq": seq, "content_hash": content_hash.to_string()}),
            ))
        }

        ("POST", "/v1/sessions/list") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let session_id = str_field(&v, "session_id")?;
            let now = v
                .get("at")
                .and_then(Value::as_u64)
                .map(Some)
                .unwrap_or_else(|| Some(crate::clock::now_unix().unwrap_or(0)));
            let sessions = engine.sessions();
            let records = sessions.list(head, session_id, now)?;
            let out: Result<Vec<Value>> = records
                .iter()
                .map(|r| {
                    let content = sessions.content(r)?;
                    Ok(json!({
                        "seq": r.seq,
                        "role": r.role,
                        "created_at": r.created_at,
                        "expires_at": r.expires_at,
                        "content": String::from_utf8_lossy(&content),
                    }))
                })
                .collect();
            Ok(Response::Json(200, json!({"turns": out?})))
        }

        ("POST", "/v1/checkpoints") => {
            require(req, Role::Writer)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let _w = state.write_lock.lock().expect("write lock poisoned");
            let hash = engine.checkpoints().create(head, None)?;
            Ok(Response::Json(200, json!({"checkpoint": hash.to_string()})))
        }

        ("GET", "/v1/pack") => {
            require_untenanted(req, Role::Admin)?;
            let tmp = db
                .root
                .with_extension(format!("serve-pack-{}", std::process::id()));
            crate::pack::pack(&db.root, &tmp, true)?;
            let bytes = std::fs::read(&tmp);
            let _ = std::fs::remove_file(&tmp);
            Ok(Response::Bytes("application/octet-stream", bytes?))
        }

        ("POST", "/v1/pack") => {
            require_untenanted(req, Role::Admin)?;
            let tmp = db
                .root
                .with_extension(format!("recv-pack-{}", std::process::id()));
            std::fs::write(&tmp, &req.body)?;
            let _w = state.write_lock.lock().expect("write lock poisoned");
            let result = crate::sync::merge_pack_file(db, &tmp);
            let _ = std::fs::remove_file(&tmp);
            let report = result?;
            Ok(Response::Json(
                200,
                json!({
                    "objects_added": report.objects_added,
                    "packs_copied": report.packs_copied,
                    "refs_updated": report.refs_updated,
                    "refs_skipped": report.refs_skipped,
                    "checkpoints_updated": report.checkpoints_updated,
                }),
            ))
        }

        ("GET", "/v1/compliance/summary") => {
            require_untenanted(req, Role::Reader)?;
            let now = crate::clock::now_unix()?;
            let month_ago = now.saturating_sub(30 * 24 * 3600);
            let mut heads = Vec::new();
            for (name, commit) in db.refs.list_heads()? {
                let chain = engine.checkpoints().verify_chain(&name, None, false);
                let (records, _) =
                    crate::audit::collect(db, &name, month_ago, now).unwrap_or_default();
                let mut principals: Vec<&str> = records
                    .iter()
                    .filter_map(|r| r.principal.as_deref())
                    .collect();
                principals.sort_unstable();
                principals.dedup();
                heads.push(json!({
                    "name": name,
                    "commit": commit.to_string(),
                    "chain": match &chain {
                        Ok(c) => json!({
                            "intact": true,
                            "length": c.length,
                            "signed": c.signed,
                            "latest": c.latest.to_string(),
                        }),
                        Err(e) if e.to_string().contains("no checkpoints") =>
                            json!({"intact": null, "length": 0, "signed": 0}),
                        Err(e) => json!({"intact": false, "error": e.to_string()}),
                    },
                    "retrievals_30d": records.len(),
                    "principals_30d": principals,
                    "last_retrieval_at": records.first().map(|r| r.executed_at),
                }));
            }
            Ok(Response::Json(
                200,
                json!({
                    "generated_at": now,
                    "heads": heads,
                    "encryption_enabled": db.config.encryption.as_ref().is_some_and(|e| e.enabled),
                    "retention_min_secs": db.config.retention_min_secs,
                }),
            ))
        }

        ("GET", "/v1/compliance/frameworks") => {
            require(req, Role::Reader)?;
            let fws: Vec<Value> = crate::compliance::frameworks()
                .into_iter()
                .map(|f| {
                    json!({
                        "id": f.id,
                        "jurisdiction": f.jurisdiction,
                        "region": f.region,
                        "name": f.name,
                        "citation": f.citation,
                    })
                })
                .collect();
            Ok(Response::Json(200, json!({"frameworks": fws})))
        }

        // Per-framework status across the whole catalog: powers the
        // "Regulatory framework status" panel (per-country / per-law checks).
        ("POST", "/v1/compliance/status") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let from = v.get("from").and_then(Value::as_u64).unwrap_or(0);
            let to = v.get("to").and_then(Value::as_u64).unwrap_or(u64::MAX);
            let mut out = Vec::new();
            for fw in crate::compliance::frameworks() {
                let r = crate::compliance::check(db, head, fw.id, from, to)?;
                out.push(json!({
                    "id": fw.id,
                    "name": fw.name,
                    "jurisdiction": fw.jurisdiction,
                    "region": fw.region,
                    "citation": fw.citation,
                    "overall": r.overall,
                    "required_fails": r.checks.iter()
                        .filter(|c| matches!(c.severity, crate::compliance::Severity::Required)
                            && matches!(c.status, crate::compliance::Status::Fail))
                        .count(),
                }));
            }
            Ok(Response::Json(
                200,
                json!({"head": head, "frameworks": out}),
            ))
        }

        // Full check list for one framework: powers the report view checklist.
        ("POST", "/v1/compliance/check") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let framework = str_field(&v, "framework")?;
            let from = v.get("from").and_then(Value::as_u64).unwrap_or(0);
            let to = v.get("to").and_then(Value::as_u64).unwrap_or(u64::MAX);
            let report = crate::compliance::check(db, head, framework, from, to)?;
            Ok(Response::Json(200, serde_json::to_value(report)?))
        }

        ("POST", "/v1/audit/queries") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let from = v.get("from").and_then(Value::as_u64).unwrap_or(0);
            let to = v.get("to").and_then(Value::as_u64).unwrap_or(u64::MAX);
            let (records, _) = crate::audit::collect(db, head, from, to)?;
            Ok(Response::Json(
                200,
                json!({"head": head, "from": from, "to": to, "records": records}),
            ))
        }

        ("POST", "/v1/audit/export") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let from = v.get("from").and_then(Value::as_u64).unwrap_or(0);
            let to = v.get("to").and_then(Value::as_u64).unwrap_or(u64::MAX);
            // Server export carries the integrity footer (tamper-evident,
            // offline-verifiable). Origin signing is a CLI/KMS operation.
            let (bytes, _) = crate::audit::export_bytes(db, head, from, to, None)?;
            Ok(Response::Bytes("application/octet-stream", bytes))
        }

        ("POST", "/v1/audit/report") => {
            require(req, Role::Reader)?;
            let v = parse_json(&req.body)?;
            let head = scope_head(req, str_field(&v, "head")?)?;
            let framework = str_field(&v, "framework")?;
            let from = v.get("from").and_then(Value::as_u64).unwrap_or(0);
            let to = v.get("to").and_then(Value::as_u64).unwrap_or(u64::MAX);
            let markdown = crate::audit::report(db, head, framework, from, to)?;
            Ok(Response::Json(
                200,
                json!({"framework": framework, "markdown": markdown}),
            ))
        }

        // ---- policy-as-code ----
        ("GET", "/v1/policy") => {
            require_untenanted(req, Role::Reader)?;
            let set = crate::policy::load(&db.root)?;
            Ok(Response::Json(200, json!({"policy": set})))
        }

        // Replace the whole policy set (policy-as-code apply).
        ("POST", "/v1/policy") => {
            require_untenanted(req, Role::Admin)?;
            let set: crate::policy::PolicySet = serde_json::from_slice(&req.body)
                .map_err(|e| anyhow!("bad request: invalid policy json: {e}"))?;
            let _w = state.write_lock.lock().expect("write lock poisoned");
            let stored = crate::policy::store(&db.root, set)?;
            Ok(Response::Json(200, json!({"policy": stored})))
        }

        // Score every enabled policy against live head state.
        ("POST", "/v1/policy/evaluate") => {
            require_untenanted(req, Role::Reader)?;
            let head = parse_json(&req.body)
                .ok()
                .as_ref()
                .and_then(|v| v.get("head").and_then(Value::as_str).map(str::to_string));
            let report = crate::policy::evaluate(db, engine, head.as_deref())?;
            Ok(Response::Json(200, serde_json::to_value(report)?))
        }

        // Tamper-evident event feed (policy violations, enforcement actions).
        // `?since=<seq>` returns only newer events — the live-monitor cursor.
        ("GET", p) if p == "/v1/events" || p.starts_with("/v1/events?") => {
            require_untenanted(req, Role::Reader)?;
            let query = p.split_once('?').map(|(_, q)| q).unwrap_or("");
            let param = |k: &str| {
                query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                    .and_then(|s| s.parse::<u64>().ok())
            };
            let since = param("since");
            let read = |db: &crate::db::Database| match since {
                Some(after) => crate::events::read_since(&db.root, after),
                None => crate::events::read(&db.root),
            };
            let mut events = read(db)?;
            // Long-poll: hold the connection up to `wait` (≤30s) for new events.
            if let Some(wait) = param("wait").map(|w| w.min(30)) {
                let mut waited = 0;
                while events.is_empty() && waited < wait {
                    std::thread::sleep(Duration::from_secs(1));
                    waited += 1;
                    events = read(db)?;
                }
            }
            Ok(Response::Json(200, json!({"events": events})))
        }

        // ---- erasure (GDPR right-to-be-forgotten) ----
        ("POST", "/v1/erasure") => {
            require_untenanted(req, Role::Admin)?;
            let v = parse_json(&req.body)?;
            let subject = str_field(&v, "subject")?;
            let reason = v.get("reason").and_then(Value::as_str).unwrap_or("request");
            let requested_by = req.principal.as_ref().map(|p| p.key_id.as_str());
            let _w = state.write_lock.lock().expect("write lock poisoned");
            let record = crate::erasure::erase_subject(
                engine,
                subject,
                crate::erasure::EraseOptions {
                    reason,
                    requested_by,
                    signer: None,
                },
            )?;
            Ok(Response::Json(200, serde_json::to_value(record)?))
        }

        ("GET", "/v1/erasure") => {
            require_untenanted(req, Role::Reader)?;
            let records: Vec<Value> = crate::events::read(&db.root)?
                .into_iter()
                .filter(|e| e.kind == "erasure")
                .map(|e| e.data)
                .collect();
            Ok(Response::Json(200, json!({"records": records})))
        }

        _ => Ok(Response::Json(404, err_json(404, "no such route"))),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::auth::add_key;
    use crate::db::Database;
    use crate::sync::http_request;

    fn start_server(tmp: &TempDir, no_auth: bool) -> (ServerHandle, String, Option<String>) {
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let token = if no_auth {
            None
        } else {
            Some(add_key(&root, "test", Role::Admin, None).unwrap())
        };
        let engine = Engine::open(&root).unwrap();
        let handle = start(
            engine,
            ServerConfig {
                addr: "127.0.0.1:0".into(),
                allow_remote: false,
                no_auth: false,
                cors_origin: None,
                bootstrap: false,
            },
        )
        .unwrap();
        let url = format!("http://{}", handle.addr);
        (handle, url, token)
    }

    fn post_json(url: &str, path: &str, token: Option<&str>, body: serde_json::Value) -> Value {
        let raw = http_request(
            url,
            "POST",
            path,
            token,
            &[("content-type", "application/json")],
            Some(body.to_string().as_bytes()),
        )
        .unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    #[test]
    fn health_and_auth_gates() {
        let tmp = TempDir::new().unwrap();
        let (handle, url, token) = start_server(&tmp, false);

        // Health works without auth? No — everything is behind auth.
        let unauthed = http_request(&url, "GET", "/v1/health", None, &[], None);
        assert!(unauthed.is_err(), "requests without token must be rejected");

        let ok = http_request(&url, "GET", "/v1/health", token.as_deref(), &[], None).unwrap();
        let v: Value = serde_json::from_slice(&ok).unwrap();
        assert_eq!(v["ok"], true);

        handle.shutdown();
    }

    #[test]
    fn end_to_end_ingest_search_prove_over_http() {
        let tmp = TempDir::new().unwrap();
        let (handle, url, token) = start_server(&tmp, false);
        let token = token.as_deref();

        let doc = post_json(
            &url,
            "/v1/documents",
            token,
            serde_json::json!({
                "head": "main",
                "source": "kb.txt",
                "text": "rust is a systems programming language",
                "chunk_size": 128,
                "overlap": 0
            }),
        );
        assert!(doc["commit"].is_string(), "ingest failed: {doc}");

        let search = post_json(
            &url,
            "/v1/search",
            token,
            serde_json::json!({
                "at": "main",
                "mode": "semantic",
                "query": "rust systems",
                "top_k": 5,
                "audit": true
            }),
        );
        let hits = search["hits"].as_array().unwrap();
        assert!(!hits.is_empty());
        assert!(search["audit_manifest"].is_string());

        // Prove the top hit and verify it server-side.
        let proof = post_json(
            &url,
            "/v1/proofs/chunk",
            token,
            serde_json::json!({
                "commit": search["commit"],
                "chunk": hits[0]["chunk"],
                "include_content": true
            }),
        );
        let verdict = post_json(
            &url,
            "/v1/proofs/verify",
            token,
            serde_json::json!({"proof_cbor": proof["proof_cbor"]}),
        );
        assert_eq!(verdict["valid"], true, "{verdict}");

        handle.shutdown();
    }

    #[test]
    fn tenant_keys_are_hard_partitioned() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let admin = add_key(&root, "root", Role::Admin, None).unwrap();
        let acme = add_key(&root, "acme-key", Role::Writer, Some("acme")).unwrap();
        let engine = Engine::open(&root).unwrap();
        let handle = start(
            engine,
            ServerConfig {
                addr: "127.0.0.1:0".into(),
                allow_remote: false,
                no_auth: false,
                cors_origin: None,
                bootstrap: false,
            },
        )
        .unwrap();
        let url = format!("http://{}", handle.addr);

        // Tenant ingests under its own head — works, tenant auto-stamped.
        let doc = post_json(
            &url,
            "/v1/documents",
            Some(&acme),
            serde_json::json!({
                "head": "acme/kb",
                "source": "acme.txt",
                "text": "acme internal secret roadmap details",
            }),
        );
        assert!(doc["commit"].is_string(), "{doc}");

        // Tenant cannot touch a foreign head.
        let foreign = http_request(
            &url,
            "POST",
            "/v1/state/set",
            Some(&acme),
            &[],
            Some(br#"{"head":"main","key":"aw==","value":"aw=="}"#),
        );
        assert!(foreign.is_err());

        // Tenant cannot reach below-the-boundary endpoints.
        let refs = http_request(&url, "GET", "/v1/refs", Some(&acme), &[], None);
        assert!(refs.is_err());

        // A DIFFERENT tenant searching the same commit gets nothing: its
        // key forces filter.tenant="rival", and acme-stamped chunks fail it.
        let rival = add_key(&root, "rival-key", Role::Reader, Some("rival")).unwrap();
        let commit = doc["commit"].as_str().unwrap();
        let cross = post_json(
            &url,
            "/v1/search",
            Some(&rival),
            serde_json::json!({"at": commit, "mode": "semantic", "query": "roadmap secret"}),
        );
        assert!(
            cross["hits"].as_array().unwrap().is_empty(),
            "tenant must never see another tenant's chunks: {cross}"
        );

        // The admin (trust root, untenanted) can see everything, scoped or not.
        let scoped = post_json(
            &url,
            "/v1/search",
            Some(&admin),
            serde_json::json!({
                "at": "acme/kb",
                "mode": "semantic",
                "query": "roadmap",
                "filter": {"tenant": "acme"}
            }),
        );
        assert!(!scoped["hits"].as_array().unwrap().is_empty());

        handle.shutdown();
    }

    #[test]
    fn compliance_and_audit_endpoints() {
        let tmp = TempDir::new().unwrap();
        let (handle, url, token) = start_server(&tmp, false);
        let token = token.as_deref();

        post_json(
            &url,
            "/v1/documents",
            token,
            serde_json::json!({"head": "main", "source": "kb", "text": "auditable policy corpus text"}),
        );
        let search = post_json(
            &url,
            "/v1/search",
            token,
            serde_json::json!({"at": "main", "mode": "semantic", "query": "policy", "audit": true}),
        );
        let qm = search["audit_manifest"].as_str().unwrap();
        post_json(
            &url,
            "/v1/commits",
            token,
            serde_json::json!({"head": "main", "message": "audit", "manifests": [qm]}),
        );
        post_json(
            &url,
            "/v1/checkpoints",
            token,
            serde_json::json!({"head": "main"}),
        );

        // Compliance summary: chain intact, one retrieval in window.
        let summary: Value = serde_json::from_slice(
            &http_request(&url, "GET", "/v1/compliance/summary", token, &[], None).unwrap(),
        )
        .unwrap();
        let head = &summary["heads"][0];
        assert_eq!(head["chain"]["intact"], true);
        assert!(head["retrievals_30d"].as_u64().unwrap() >= 1);

        // Audit queries return the recorded retrieval.
        let queries = post_json(
            &url,
            "/v1/audit/queries",
            token,
            serde_json::json!({"head": "main"}),
        );
        assert!(!queries["records"].as_array().unwrap().is_empty());

        // Report renders for a framework.
        let report = post_json(
            &url,
            "/v1/audit/report",
            token,
            serde_json::json!({"head": "main", "framework": "hipaa"}),
        );
        assert!(
            report["markdown"]
                .as_str()
                .unwrap()
                .contains("Requirement mapping")
        );

        // Export returns a bundle that the offline verifier accepts.
        let bundle = http_request(
            &url,
            "POST",
            "/v1/audit/export",
            token,
            &[("content-type", "application/json")],
            Some(br#"{"head":"main"}"#),
        )
        .unwrap();
        let path = tmp.path().join("dl.nelaudit");
        std::fs::write(&path, &bundle).unwrap();
        let report = crate::audit::verify_bundle(&path, None, false).unwrap();
        assert_eq!(report.retrievals, 1);

        handle.shutdown();
    }

    #[test]
    fn cors_preflight_answered_without_auth() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        add_key(&root, "k", Role::Admin, None).unwrap();
        let engine = Engine::open(&root).unwrap();
        let handle = start(
            engine,
            ServerConfig {
                addr: "127.0.0.1:0".into(),
                allow_remote: false,
                no_auth: false,
                cors_origin: Some("http://localhost:8089".into()),
                bootstrap: false,
            },
        )
        .unwrap();
        let url = format!("http://{}", handle.addr);
        // OPTIONS carries no bearer token; must still succeed with CORS headers.
        let raw = http_request(&url, "OPTIONS", "/v1/compliance/summary", None, &[], None).unwrap();
        assert!(raw.is_empty(), "preflight body should be empty");
        handle.shutdown();
    }

    #[test]
    fn bootstrap_token_admits_loopback_and_serves_console() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        // No keys minted: the loopback bootstrap token must let serve start.
        let engine = Engine::open(&root).unwrap();
        let handle = start(
            engine,
            ServerConfig {
                addr: "127.0.0.1:0".into(),
                allow_remote: false,
                no_auth: false,
                cors_origin: None,
                bootstrap: true,
            },
        )
        .unwrap();
        let url = format!("http://{}", handle.addr);
        let token = handle
            .bootstrap_token
            .clone()
            .expect("bootstrap token minted");

        // API stays gated: no token -> 401; bootstrap token -> admin.
        assert!(http_request(&url, "GET", "/v1/health", None, &[], None).is_err());
        let ok = http_request(&url, "GET", "/v1/health", Some(&token), &[], None).unwrap();
        assert!(!ok.is_empty());
        http_request(&url, "GET", "/v1/refs", Some(&token), &[], None).unwrap();

        // Console shell is public (no token) and carries the injected bootstrap.
        if !console_assets::ASSETS.is_empty() {
            let html = http_request(&url, "GET", "/", None, &[], None).unwrap();
            let html = String::from_utf8_lossy(&html);
            assert!(
                html.contains("__NELEUS_BOOTSTRAP__"),
                "served index.html must inject the bootstrap token on loopback"
            );
        }
        handle.shutdown();
    }

    #[test]
    fn run_records_trace_fields_and_validates_parent_span() {
        let tmp = TempDir::new().unwrap();
        let (handle, url, token) = start_server(&tmp, false);

        // Trace + handoff fields are accepted and the run commits.
        let ok = post_json(
            &url,
            "/v1/runs",
            token.as_deref(),
            serde_json::json!({
                "head": "main", "model": "gpt-4", "provider": "openai",
                "trace_id": "trace-1", "delegated_from": "planner-v1"
            }),
        );
        assert!(ok.get("manifest").is_some(), "run should commit: {ok}");

        // A malformed parent_span is a 400, not a silent drop.
        let bad = http_request(
            &url,
            "POST",
            "/v1/runs",
            token.as_deref(),
            &[],
            Some(br#"{"head":"main","model":"gpt-4","parent_span":"not-a-hash"}"#),
        );
        assert!(bad.is_err(), "invalid parent_span must be rejected");
        handle.shutdown();
    }

    #[test]
    fn erasure_endpoint_shreds_subject_content() {
        let tmp = TempDir::new().unwrap();
        let (handle, url, token) = start_server(&tmp, false);
        let t = token.as_deref();

        // Store an output blob and capture its hash.
        let blob = http_request(
            &url,
            "POST",
            "/v1/blobs",
            t,
            &[],
            Some(b"alice secret output"),
        )
        .unwrap();
        let blob: Value = serde_json::from_slice(&blob).unwrap();
        let out_hash = blob["hash"].as_str().unwrap().to_string();

        // A run tagged to subject "alice", referencing that output.
        post_json(
            &url,
            "/v1/runs",
            t,
            serde_json::json!({
                "head": "main", "model": "m", "provider": "openai",
                "subject": "alice", "prompt": "hi", "outputs": [out_hash]
            }),
        );
        let blob_path = format!("/v1/blobs/{out_hash}");
        assert!(
            http_request(&url, "GET", &blob_path, t, &[], None).is_ok(),
            "blob exists pre-erasure"
        );

        // Erase the subject; the response lists the shredded blobs.
        let rec = post_json(
            &url,
            "/v1/erasure",
            t,
            serde_json::json!({"subject": "alice"}),
        );
        assert!(
            rec["blobs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|h| h.as_str() == Some(out_hash.as_str())),
            "record must list the output: {rec}"
        );

        // The content is gone; the record is listed.
        assert!(
            http_request(&url, "GET", &blob_path, t, &[], None).is_err(),
            "blob must be shredded"
        );
        let list = http_request(&url, "GET", "/v1/erasure", t, &[], None).unwrap();
        assert!(String::from_utf8_lossy(&list).contains("alice"));
        handle.shutdown();
    }

    #[test]
    fn enforce_policy_blocks_write_and_logs_violation() {
        let tmp = TempDir::new().unwrap();
        let (handle, url, token) = start_server(&tmp, false);

        // Apply an enforce policy: encryption at rest (a fresh db has none).
        http_request(
            &url,
            "POST",
            "/v1/policy",
            token.as_deref(),
            &[],
            Some(br#"{"policies":[{"id":"enc","rule":{"kind":"require-encryption-at-rest"},"mode":"enforce"}]}"#),
        )
        .unwrap();

        // The write must be refused (403 -> Err).
        let blocked = http_request(
            &url,
            "POST",
            "/v1/documents",
            token.as_deref(),
            &[],
            Some(br#"{"head":"main","source":"k","text":"x"}"#),
        );
        assert!(blocked.is_err(), "enforced policy must block the write");

        // ...and recorded in the tamper-evident event log.
        let events = http_request(&url, "GET", "/v1/events", token.as_deref(), &[], None).unwrap();
        let body = String::from_utf8_lossy(&events);
        assert!(
            body.contains("policy.violation"),
            "violation must be logged: {body}"
        );
        assert!(body.contains("\"enc\""));
        handle.shutdown();
    }

    #[test]
    fn replication_pull_over_http() {
        let tmp = TempDir::new().unwrap();
        let (handle, url, token) = start_server(&tmp, false);
        let token = token.as_deref();

        post_json(
            &url,
            "/v1/documents",
            token,
            serde_json::json!({
                "head": "main",
                "source": "kb",
                "text": "replicated knowledge base"
            }),
        );

        // A second database pulls the first via HTTP.
        let replica_root = tmp.path().join("replica");
        Database::init(&replica_root).unwrap();
        let replica = Database::open(&replica_root).unwrap();
        let report = crate::sync::pull(&replica, &url, token).unwrap();
        assert!(report.objects_added > 0);
        assert_eq!(report.refs_updated, vec!["main".to_string()]);

        // The replica can answer the same query locally.
        let replica_engine = Engine::open(&replica_root).unwrap();
        let commit = replica_engine.resolve_commit("main").unwrap();
        let hits = replica_engine
            .search_semantic(commit, "replicated knowledge", 5, &SearchFilter::default())
            .unwrap();
        assert!(!hits.is_empty());

        handle.shutdown();
    }
}

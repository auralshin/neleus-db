//! Policy-as-code: declarative rules that bind compliance mechanisms to heads,
//! either monitor (observe and record) or enforce (reject violating writes).
//! Policies live in `meta/policy.json`. [`evaluate`] scores them against live
//! state; [`enforce_write`] gates an incoming write.

use serde::{Deserialize, Serialize};

use anyhow::{Result, anyhow};

use crate::atomic::write_atomic;
use crate::commit::{Commit, CommitStore};
use crate::db::Database;
use crate::engine::Engine;

pub const POLICY_SCHEMA_VERSION: u32 = 1;
/// Monitoring window for record-based rules (principal coverage, etc.).
const MONITOR_WINDOW_SECS: u64 = 30 * 24 * 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Observe and record violations; never block a write.
    Monitor,
    /// Reject the write that would create a violation.
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Required,
    Recommended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

/// A concrete, evaluable requirement. `kind` is the tagged discriminant in
/// JSON, e.g. `{"kind":"retention-floor","min_secs":220752000}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Rule {
    /// The head's checkpoint chain must verify (tamper-evident).
    RequireTamperEvidentChain,
    /// Every checkpoint on the head must be signed.
    RequireSignedCheckpoints,
    /// Encryption at rest must be enabled (database-global).
    RequireEncryptionAtRest,
    /// A retention floor of at least `min_secs` must be configured (global).
    RetentionFloor { min_secs: u64 },
    /// Every retrieval/run must name an acting principal.
    RequirePrincipal,
    /// Commits must carry an ed25519 signature.
    RequireSignedCommits,
    /// Runs must carry provenance: a declared provider or links to the data
    /// they used (inputs / retrieved chunks).
    RequireProvenance,
}

impl Rule {
    pub fn id(&self) -> &'static str {
        match self {
            Rule::RequireTamperEvidentChain => "require-tamper-evident-chain",
            Rule::RequireSignedCheckpoints => "require-signed-checkpoints",
            Rule::RequireEncryptionAtRest => "require-encryption-at-rest",
            Rule::RetentionFloor { .. } => "retention-floor",
            Rule::RequirePrincipal => "require-principal",
            Rule::RequireSignedCommits => "require-signed-commits",
            Rule::RequireProvenance => "require-provenance",
        }
    }

    /// Database-global rules ignore the head selector and evaluate once.
    fn is_global(&self) -> bool {
        matches!(
            self,
            Rule::RequireEncryptionAtRest | Rule::RetentionFloor { .. }
        )
    }

    /// Evaluate this rule against an incoming write. `None` = not gateable at
    /// write time (it is a continuous/historical property instead).
    fn gate(&self, db: &Database, ctx: &WriteContext) -> Option<(bool, String)> {
        match self {
            Rule::RequireEncryptionAtRest => {
                let ok = db.config.encryption.as_ref().is_some_and(|e| e.enabled);
                Some((ok, "encryption at rest is required for writes".into()))
            }
            Rule::RetentionFloor { min_secs } => {
                let ok = db.config.retention_min_secs.is_some_and(|c| c >= *min_secs);
                Some((
                    ok,
                    format!("a retention floor of ≥ {min_secs}s is required"),
                ))
            }
            Rule::RequirePrincipal => Some((
                ctx.principal.is_some(),
                "the write must name an authenticated principal".into(),
            )),
            Rule::RequireProvenance if ctx.op == "runs" => Some((
                ctx.has_provenance,
                "the run must declare provenance (provider or input/retrieved data)".into(),
            )),
            _ => None,
        }
    }
}

/// What an incoming mutating request carries, for write-time gating.
pub struct WriteContext<'a> {
    /// `documents` | `runs` | `commits`.
    pub op: &'a str,
    pub head: &'a str,
    pub principal: Option<&'a str>,
    pub has_provenance: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    #[serde(default)]
    pub description: String,
    /// Head selectors: exact names, `prefix*` wildcards, or `*`/empty = all.
    #[serde(default)]
    pub heads: Vec<String>,
    pub rule: Rule,
    pub mode: Mode,
    #[serde(default = "default_severity")]
    pub severity: Severity,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_severity() -> Severity {
    Severity::Required
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicySet {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub policies: Vec<Policy>,
    /// Optional `http://` webhook posted on each recorded violation. HTTPS
    /// targets go through a local TLS-terminating forwarder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook: Option<String>,
    #[serde(default)]
    pub updated_at: u64,
}

impl PolicySet {
    fn validate(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for p in &self.policies {
            if p.id.is_empty() || p.id.len() > 128 {
                return Err(anyhow!("policy id must be 1..=128 chars"));
            }
            if !seen.insert(&p.id) {
                return Err(anyhow!("duplicate policy id '{}'", p.id));
            }
            if let Rule::RetentionFloor { min_secs } = &p.rule
                && *min_secs == 0
            {
                return Err(anyhow!(
                    "policy '{}': retention-floor min_secs must be > 0",
                    p.id
                ));
            }
        }
        Ok(())
    }
}

// ---------- storage (meta/policy.json) ----------

fn policy_path(db_root: &std::path::Path) -> std::path::PathBuf {
    db_root.join("meta").join("policy.json")
}

pub fn load(db_root: &std::path::Path) -> Result<PolicySet> {
    match std::fs::read(policy_path(db_root)) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(PolicySet::default()),
        Err(e) => Err(e.into()),
    }
}

/// Replace the whole policy set (the policy-as-code apply path).
pub fn store(db_root: &std::path::Path, mut set: PolicySet) -> Result<PolicySet> {
    set.validate()?;
    set.schema_version = POLICY_SCHEMA_VERSION;
    set.updated_at = crate::clock::now_unix()?;
    write_atomic(&policy_path(db_root), &serde_json::to_vec_pretty(&set)?)?;
    Ok(set)
}

/// Insert or replace a single policy by id.
pub fn upsert(db_root: &std::path::Path, policy: Policy) -> Result<PolicySet> {
    let mut set = load(db_root)?;
    set.policies.retain(|p| p.id != policy.id);
    set.policies.push(policy);
    store(db_root, set)
}

/// Remove a policy by id; returns the new set and whether it existed.
pub fn remove(db_root: &std::path::Path, id: &str) -> Result<(PolicySet, bool)> {
    let mut set = load(db_root)?;
    let before = set.policies.len();
    set.policies.retain(|p| p.id != id);
    let removed = set.policies.len() != before;
    let set = store(db_root, set)?;
    Ok((set, removed))
}

// ---------- evaluation ----------

#[derive(Debug, Clone, Serialize)]
pub struct PolicyStatus {
    pub policy_id: String,
    pub rule: &'static str,
    pub head: String,
    pub mode: Mode,
    pub severity: Severity,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvalReport {
    pub generated_at: u64,
    pub pass: usize,
    pub warn: usize,
    pub fail: usize,
    pub statuses: Vec<PolicyStatus>,
}

/// `*` or empty matches all; a trailing `*` is a prefix match; else exact.
fn head_matches(selectors: &[String], head: &str) -> bool {
    if selectors.is_empty() || selectors.iter().any(|s| s == "*") {
        return true;
    }
    selectors.iter().any(|s| match s.strip_suffix('*') {
        Some(prefix) => head.starts_with(prefix),
        None => s == head,
    })
}

/// Evaluate every enabled policy against live state. `head_filter` restricts to
/// one head (the rest still report if globally scoped).
pub fn evaluate(db: &Database, engine: &Engine, head_filter: Option<&str>) -> Result<EvalReport> {
    let set = load(&db.root)?;
    let all_heads: Vec<String> = db.refs.list_heads()?.into_iter().map(|(n, _)| n).collect();
    let now = crate::clock::now_unix()?;
    let mut statuses = Vec::new();

    for policy in set.policies.iter().filter(|p| p.enabled) {
        if policy.rule.is_global() {
            let (status, detail) = eval_global(db, &policy.rule);
            statuses.push(mk_status(policy, "(database)", status, detail));
            continue;
        }
        for head in &all_heads {
            if let Some(f) = head_filter
                && f != head
            {
                continue;
            }
            if !head_matches(&policy.heads, head) {
                continue;
            }
            let (status, detail) = eval_head(db, engine, &policy.rule, head, now);
            statuses.push(mk_status(policy, head, status, detail));
        }
    }

    let (mut pass, mut warn, mut fail) = (0, 0, 0);
    for s in &statuses {
        match s.status {
            Status::Pass => pass += 1,
            Status::Warn => warn += 1,
            Status::Fail => fail += 1,
        }
    }
    Ok(EvalReport {
        generated_at: now,
        pass,
        warn,
        fail,
        statuses,
    })
}

fn mk_status(policy: &Policy, head: &str, status: Status, detail: String) -> PolicyStatus {
    PolicyStatus {
        policy_id: policy.id.clone(),
        rule: policy.rule.id(),
        head: head.to_string(),
        mode: policy.mode,
        severity: policy.severity,
        status,
        detail,
    }
}

fn eval_global(db: &Database, rule: &Rule) -> (Status, String) {
    match rule {
        Rule::RequireEncryptionAtRest => {
            if db.config.encryption.as_ref().is_some_and(|e| e.enabled) {
                (Status::Pass, "Encryption at rest enabled.".into())
            } else {
                (Status::Fail, "Encryption at rest is not enabled.".into())
            }
        }
        Rule::RetentionFloor { min_secs } => match db.config.retention_min_secs {
            Some(cur) if cur >= *min_secs => (
                Status::Pass,
                format!("Retention floor {cur}s ≥ required {min_secs}s."),
            ),
            Some(cur) => (
                Status::Fail,
                format!("Retention floor {cur}s < required {min_secs}s."),
            ),
            None => (Status::Fail, "No retention floor configured.".into()),
        },
        _ => (Status::Pass, String::new()),
    }
}

fn eval_head(
    db: &Database,
    engine: &Engine,
    rule: &Rule,
    head: &str,
    now: u64,
) -> (Status, String) {
    match rule {
        Rule::RequireTamperEvidentChain => {
            match engine.checkpoints().verify_chain(head, None, false) {
                Ok(c) => (
                    Status::Pass,
                    format!("Chain intact across {} checkpoint(s).", c.length),
                ),
                Err(e) if e.to_string().contains("no checkpoints") => {
                    (Status::Fail, "No checkpoint chain anchored.".into())
                }
                Err(e) => (Status::Fail, format!("Chain broken: {e}")),
            }
        }
        Rule::RequireSignedCheckpoints => {
            match engine.checkpoints().verify_chain(head, None, false) {
                Ok(c) if c.signed == c.length && c.length > 0 => (
                    Status::Pass,
                    format!("All {} checkpoint(s) signed.", c.length),
                ),
                Ok(c) => (
                    Status::Fail,
                    format!("{} of {} checkpoint(s) signed.", c.signed, c.length),
                ),
                Err(_) => (Status::Fail, "No checkpoint chain to sign.".into()),
            }
        }
        Rule::RequirePrincipal => {
            let from = now.saturating_sub(MONITOR_WINDOW_SECS);
            let (records, _) = crate::audit::collect(db, head, from, now).unwrap_or_default();
            if records.is_empty() {
                (Status::Pass, "No retrievals in window.".into())
            } else if records.iter().all(|r| r.principal.is_some()) {
                (
                    Status::Pass,
                    format!("All {} retrieval(s) name a principal.", records.len()),
                )
            } else {
                let missing = records.iter().filter(|r| r.principal.is_none()).count();
                (
                    Status::Fail,
                    format!("{missing} retrieval(s) have no principal."),
                )
            }
        }
        Rule::RequireSignedCommits => match tip_commit(db, head) {
            Ok(Some(c)) if c.signature.is_some() => (Status::Pass, "Head commit is signed.".into()),
            Ok(Some(_)) => (Status::Fail, "Head commit is unsigned.".into()),
            Ok(None) => (Status::Pass, "Head has no commits.".into()),
            Err(e) => (Status::Warn, format!("Could not read head commit: {e}")),
        },
        Rule::RequireProvenance => (Status::Pass, "Enforced at write time.".into()),
        _ => (Status::Pass, String::new()),
    }
}

/// Run all enabled policies against an incoming write. Records violations to the
/// tamper-evident event log and returns an error (mapped to 403 by the server)
/// when an `enforce`-mode rule is violated. Global monitor-only failures are
/// left to continuous evaluation rather than logged on every write.
pub fn enforce_write(db: &Database, ctx: &WriteContext) -> Result<()> {
    let set = load(&db.root)?;
    let mut blocked: Option<(String, String)> = None;
    for policy in set.policies.iter().filter(|p| p.enabled) {
        let Some((pass, why)) = policy.rule.gate(db, ctx) else {
            continue;
        };
        if !policy.rule.is_global() && !head_matches(&policy.heads, ctx.head) {
            continue;
        }
        if pass {
            continue;
        }
        let enforced = policy.mode == Mode::Enforce;
        if enforced || !policy.rule.is_global() {
            if let Ok(event) = crate::events::append(
                &db.root,
                "policy.violation",
                serde_json::json!({
                    "policy_id": policy.id,
                    "rule": policy.rule.id(),
                    "head": ctx.head,
                    "op": ctx.op,
                    "mode": policy.mode,
                    "severity": policy.severity,
                    "principal": ctx.principal,
                    "enforced": enforced,
                    "detail": why,
                }),
            ) {
                notify(set.webhook.as_deref(), &event);
            }
        }
        if enforced && blocked.is_none() {
            blocked = Some((policy.id.clone(), why));
        }
    }
    if let Some((id, why)) = blocked {
        return Err(anyhow!(
            "forbidden: policy '{id}' blocked this {}: {why}",
            ctx.op
        ));
    }
    Ok(())
}

/// Fire the violation webhook off-thread so write latency never depends on it.
fn notify(webhook: Option<&str>, event: &crate::events::Event) {
    let Some(url) = webhook else { return };
    let url = url.to_string();
    let payload = serde_json::to_value(event).unwrap_or_default();
    std::thread::spawn(move || {
        let _ = crate::alert::post_webhook(&url, &payload);
    });
}

fn tip_commit(db: &Database, head: &str) -> Result<Option<Commit>> {
    let Some(hash) = db.refs.head_get(head)? else {
        return Ok(None);
    };
    let store = CommitStore::new(db.object_store.clone());
    Ok(Some(store.get_commit(hash)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use tempfile::TempDir;

    fn policy(id: &str, rule: Rule, mode: Mode) -> Policy {
        Policy {
            id: id.into(),
            description: String::new(),
            heads: vec![],
            rule,
            mode,
            severity: Severity::Required,
            enabled: true,
        }
    }

    #[test]
    fn store_load_roundtrip_and_dedup() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();

        upsert(
            &root,
            policy("enc", Rule::RequireEncryptionAtRest, Mode::Monitor),
        )
        .unwrap();
        let set = upsert(
            &root,
            policy("ret", Rule::RetentionFloor { min_secs: 100 }, Mode::Enforce),
        )
        .unwrap();
        assert_eq!(set.policies.len(), 2);
        assert_eq!(set.schema_version, POLICY_SCHEMA_VERSION);

        // upsert replaces by id, never duplicates.
        let set = upsert(
            &root,
            policy("enc", Rule::RequireEncryptionAtRest, Mode::Enforce),
        )
        .unwrap();
        assert_eq!(set.policies.iter().filter(|p| p.id == "enc").count(), 1);

        let (_, removed) = remove(&root, "enc").unwrap();
        assert!(removed);
        assert_eq!(load(&root).unwrap().policies.len(), 1);
    }

    #[test]
    fn head_selector_matching() {
        assert!(head_matches(&[], "main"));
        assert!(head_matches(&["*".into()], "anything"));
        assert!(head_matches(&["acme/*".into()], "acme/clinical"));
        assert!(!head_matches(&["acme/*".into()], "globex/x"));
        assert!(head_matches(&["main".into()], "main"));
        assert!(!head_matches(&["main".into()], "dev"));
    }

    #[test]
    fn evaluate_flags_unconfigured_global_rules() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();

        upsert(
            &root,
            policy("enc", Rule::RequireEncryptionAtRest, Mode::Enforce),
        )
        .unwrap();
        upsert(
            &root,
            policy("ret", Rule::RetentionFloor { min_secs: 100 }, Mode::Monitor),
        )
        .unwrap();

        let report = evaluate(engine.db(), &engine, None).unwrap();
        // Both global rules fail on a fresh, unencrypted db with no retention.
        assert_eq!(report.fail, 2);
        assert!(report.statuses.iter().all(|s| s.head == "(database)"));
    }

    #[test]
    fn evaluate_scores_head_scoped_rules() {
        use crate::manifest::ChunkingSpec;
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();
        engine
            .put_document(
                "main",
                "kb",
                b"hello",
                ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 512,
                    overlap: 0,
                },
                None,
                "tester",
            )
            .unwrap();

        for (id, rule, heads) in [
            (
                "signed",
                Rule::RequireSignedCommits,
                vec!["main".to_string()],
            ),
            (
                "chain",
                Rule::RequireTamperEvidentChain,
                vec!["main".to_string()],
            ),
            ("prin", Rule::RequirePrincipal, vec!["*".to_string()]),
        ] {
            let mut p = policy(id, rule, Mode::Monitor);
            p.heads = heads;
            upsert(&root, p).unwrap();
        }

        let report = evaluate(engine.db(), &engine, None).unwrap();
        let find = |id: &str| report.statuses.iter().find(|s| s.policy_id == id).unwrap();
        assert_eq!(find("signed").status, Status::Fail); // tip commit is unsigned
        assert_eq!(find("chain").status, Status::Fail); // no checkpoint chain
        assert_eq!(find("prin").status, Status::Pass); // no retrievals in window
    }

    #[test]
    fn enforce_write_blocks_in_enforce_allows_in_monitor() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let db = Database::open(&root).unwrap();

        let ctx = WriteContext {
            op: "runs",
            head: "main",
            principal: None,
            has_provenance: false,
        };

        let mut p = policy("need-principal", Rule::RequirePrincipal, Mode::Enforce);
        p.heads = vec!["*".into()];
        upsert(&root, p).unwrap();
        assert!(
            enforce_write(&db, &ctx).is_err(),
            "enforce + no principal must block"
        );

        // Same rule in monitor mode: the write proceeds (violation only recorded).
        let mut p = policy("need-principal", Rule::RequirePrincipal, Mode::Monitor);
        p.heads = vec!["*".into()];
        upsert(&root, p).unwrap();
        assert!(enforce_write(&db, &ctx).is_ok(), "monitor must not block");
    }
}

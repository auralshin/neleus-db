//! Jurisdiction-organized catalog of AI/data regulations, with checks that
//! run against live audit data and return pass / warn / fail.
//!
//! Each framework declares which checks apply and at what severity. A check
//! is a concrete, evaluable property of the head (audit records present,
//! checkpoint chain intact, encryption at rest, principal recorded, retention
//! configured, data-version linkage). Required checks drive the framework's
//! overall status; recommended checks surface as warnings.
//!
//! This maps mechanisms to requirements. It is not legal advice and not a
//! certification — whether a mechanism satisfies an obligation for a given
//! system is a determination for compliance and legal teams.

use serde::Serialize;

use crate::audit::{self, AuditRecord};
use crate::checkpoint::CheckpointStore;
use crate::db::Database;
pub use crate::policy::Status;

use anyhow::{Result, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Required,
    Recommended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    AuditLogging,
    TamperEvidentChain,
    CheckpointsSigned,
    EncryptionAtRest,
    PrincipalRecorded,
    RetentionConfigured,
    DataVersionLinkage,
}

impl Check {
    fn id(self) -> &'static str {
        match self {
            Check::AuditLogging => "audit-logging",
            Check::TamperEvidentChain => "tamper-evident-chain",
            Check::CheckpointsSigned => "checkpoints-signed",
            Check::EncryptionAtRest => "encryption-at-rest",
            Check::PrincipalRecorded => "principal-recorded",
            Check::RetentionConfigured => "retention-configured",
            Check::DataVersionLinkage => "data-version-linkage",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Check::AuditLogging => "Retrieval audit logging in place",
            Check::TamperEvidentChain => "Tamper-evident checkpoint chain",
            Check::CheckpointsSigned => "Checkpoints cryptographically signed",
            Check::EncryptionAtRest => "Encryption at rest enabled",
            Check::PrincipalRecorded => "Acting principal recorded on every retrieval",
            Check::RetentionConfigured => "Retention policy configured",
            Check::DataVersionLinkage => "Each decision linked to its exact data version",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    pub id: &'static str,
    pub label: &'static str,
    pub status: Status,
    pub severity: Severity,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FrameworkInfo {
    pub id: &'static str,
    pub jurisdiction: &'static str,
    /// Region/country code used to group frameworks in a selector.
    pub region: &'static str,
    pub name: &'static str,
    pub citation: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReport {
    pub framework: &'static str,
    pub jurisdiction: &'static str,
    pub region: &'static str,
    pub name: &'static str,
    pub citation: &'static str,
    pub head: String,
    pub from: u64,
    pub to: u64,
    pub retrievals: usize,
    pub overall: Status,
    pub checks: Vec<CheckResult>,
    pub mappings: Vec<Mapping>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Mapping {
    pub requirement: &'static str,
    pub mechanism: &'static str,
}

struct FrameworkDef {
    info: FrameworkInfo,
    checks: &'static [(Check, Severity)],
    mappings: &'static [(&'static str, &'static str)],
}

use Check::*;
use Severity::{Recommended, Required};

fn catalog() -> Vec<FrameworkDef> {
    vec![
        FrameworkDef {
            info: FrameworkInfo {
                id: "eu-ai-act",
                jurisdiction: "European Union",
                region: "EU",
                name: "EU AI Act",
                citation: "Regulation (EU) 2024/1689",
            },
            checks: &[
                (AuditLogging, Required),
                (TamperEvidentChain, Required),
                (DataVersionLinkage, Required),
                (PrincipalRecorded, Required),
                (CheckpointsSigned, Recommended),
                (EncryptionAtRest, Recommended),
            ],
            mappings: &[
                (
                    "Art. 12(1) — automatic recording of events over the system lifetime",
                    "Every retrieval writes a content-addressed QueryManifest committed to immutable history.",
                ),
                (
                    "Art. 12(2) — traceability appropriate to the intended purpose",
                    "Each record links principal, query, the exact commit queried, filters, and every returned chunk hash.",
                ),
                (
                    "Art. 19 / 12(3) — logs kept and available to authorities",
                    "Self-contained signed bundle, offline-verifiable with no vendor dependency.",
                ),
            ],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "gdpr",
                jurisdiction: "European Union",
                region: "EU",
                name: "GDPR",
                citation: "Regulation (EU) 2016/679",
            },
            checks: &[
                (AuditLogging, Required),
                (EncryptionAtRest, Required),
                (RetentionConfigured, Required),
                (PrincipalRecorded, Required),
            ],
            mappings: &[
                (
                    "Art. 5(1)(f) — integrity and confidentiality",
                    "AES-256-GCM / ChaCha20-Poly1305 per object; content addressing detects alteration.",
                ),
                (
                    "Art. 5(1)(e) — storage limitation",
                    "Engine-enforced retention floor on episodic records.",
                ),
                (
                    "Art. 30 — records of processing activities",
                    "Per-retrieval audit records with principal and timestamp.",
                ),
            ],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "nist-ai-rmf",
                jurisdiction: "United States (federal)",
                region: "US",
                name: "NIST AI RMF",
                citation: "NIST AI 100-1",
            },
            checks: &[
                (AuditLogging, Recommended),
                (TamperEvidentChain, Recommended),
                (DataVersionLinkage, Recommended),
            ],
            mappings: &[
                (
                    "MEASURE 2.x — traceability and documentation",
                    "Per-retrieval audit records with cryptographic provenance.",
                ),
                (
                    "MANAGE 4.x — monitoring and incident response",
                    "Chain-integrity status; a broken chain is a detectable tamper event.",
                ),
            ],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "hipaa",
                jurisdiction: "United States (federal)",
                region: "US",
                name: "HIPAA Security Rule",
                citation: "45 CFR Part 164, Subpart C",
            },
            checks: &[
                (AuditLogging, Required),
                (TamperEvidentChain, Required),
                (EncryptionAtRest, Required),
                (PrincipalRecorded, Required),
                (RetentionConfigured, Required),
            ],
            mappings: &[
                (
                    "§ 164.312(b) — audit controls",
                    "Tamper-evident retrieval log anchored in a signed checkpoint chain.",
                ),
                (
                    "§ 164.312(c)(1) — integrity",
                    "BLAKE3 content addressing; alteration changes the hash and breaks the chain.",
                ),
                (
                    "§ 164.316(b)(2) — 6-year retention",
                    "Engine-enforced retention floor; canonical history is never auto-removed.",
                ),
            ],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "sec-occ",
                jurisdiction: "United States (federal)",
                region: "US",
                name: "SEC 17a-4 / OCC SR 11-7",
                citation: "17 CFR 240.17a-4; OCC/Fed SR 11-7",
            },
            checks: &[
                (AuditLogging, Required),
                (TamperEvidentChain, Required),
                (DataVersionLinkage, Required),
                (RetentionConfigured, Required),
            ],
            mappings: &[
                (
                    "17a-4 — non-rewriteable, non-erasable (WORM) records",
                    "Content-addressed immutable objects; append-only tamper-evident history.",
                ),
                (
                    "Model risk — record inputs to each decision",
                    "Retrieved context linked to the exact data version used.",
                ),
            ],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "colorado-ai",
                jurisdiction: "United States — Colorado",
                region: "US-CO",
                name: "Colorado AI Act",
                citation: "SB 24-205",
            },
            checks: &[
                (AuditLogging, Required),
                (DataVersionLinkage, Required),
                (PrincipalRecorded, Recommended),
            ],
            mappings: &[(
                "Developer/deployer record-keeping for high-risk AI",
                "Per-retrieval audit records linking each decision to its inputs.",
            )],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "ccpa",
                jurisdiction: "United States — California",
                region: "US-CA",
                name: "CCPA / CPRA (ADMT)",
                citation: "Cal. Civ. Code 1798.100 et seq.",
            },
            checks: &[
                (AuditLogging, Required),
                (PrincipalRecorded, Required),
                (RetentionConfigured, Recommended),
            ],
            mappings: &[(
                "Automated decision-making transparency",
                "Auditable record of what data drove each automated retrieval.",
            )],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "uk-dpa",
                jurisdiction: "United Kingdom",
                region: "UK",
                name: "UK GDPR / DPA 2018",
                citation: "Data Protection Act 2018",
            },
            checks: &[
                (AuditLogging, Required),
                (EncryptionAtRest, Required),
                (PrincipalRecorded, Required),
            ],
            mappings: &[
                (
                    "Accountability principle",
                    "Demonstrable per-retrieval records with provenance.",
                ),
                (
                    "Security of processing",
                    "Encryption at rest with authenticated ciphers.",
                ),
            ],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "canada-aida",
                jurisdiction: "Canada",
                region: "CA",
                name: "AIDA (Bill C-27)",
                citation: "Artificial Intelligence and Data Act",
            },
            checks: &[
                (AuditLogging, Required),
                (TamperEvidentChain, Required),
                (DataVersionLinkage, Required),
            ],
            mappings: &[(
                "Record-keeping for high-impact systems",
                "Tamper-evident audit log with data-version linkage.",
            )],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "china-genai",
                jurisdiction: "China",
                region: "CN",
                name: "Interim Measures for Generative AI Services",
                citation: "CAC, 2023",
            },
            checks: &[
                (AuditLogging, Required),
                (PrincipalRecorded, Required),
                (RetentionConfigured, Recommended),
            ],
            mappings: &[(
                "Service provider logging and traceability",
                "Per-retrieval records identifying the acting principal.",
            )],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "singapore-mgf",
                jurisdiction: "Singapore",
                region: "SG",
                name: "Model AI Governance Framework",
                citation: "IMDA/PDPC",
            },
            checks: &[
                (AuditLogging, Recommended),
                (TamperEvidentChain, Recommended),
                (DataVersionLinkage, Recommended),
            ],
            mappings: &[(
                "Traceability and explainability",
                "Provenance from each decision back to its source chunks.",
            )],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "brazil-lgpd",
                jurisdiction: "Brazil",
                region: "BR",
                name: "LGPD",
                citation: "Lei 13.709/2018",
            },
            checks: &[
                (AuditLogging, Required),
                (EncryptionAtRest, Required),
                (PrincipalRecorded, Required),
            ],
            mappings: &[
                (
                    "Art. 37 — records of processing operations",
                    "Per-retrieval audit records with principal and timestamp.",
                ),
                (
                    "Art. 46 — security measures",
                    "Encryption at rest; tamper-evident history.",
                ),
            ],
        },
        FrameworkDef {
            info: FrameworkInfo {
                id: "iso-42001",
                jurisdiction: "International",
                region: "Global",
                name: "ISO/IEC 42001 (AI management)",
                citation: "ISO/IEC 42001:2023",
            },
            checks: &[
                (AuditLogging, Required),
                (DataVersionLinkage, Required),
                (TamperEvidentChain, Recommended),
                (RetentionConfigured, Recommended),
            ],
            mappings: &[
                (
                    "Operational records and traceability",
                    "Content-addressed audit records with cryptographic linkage.",
                ),
                (
                    "Integrity controls",
                    "Checkpoint chain makes history rewrites detectable.",
                ),
            ],
        },
    ]
}

/// Every framework, ordered for a jurisdiction-grouped selector.
pub fn frameworks() -> Vec<FrameworkInfo> {
    catalog().into_iter().map(|f| f.info).collect()
}

enum ChainState {
    Intact { length: u64, signed: u64 },
    Broken(String),
    None,
}

fn chain_state(db: &Database, head: &str) -> ChainState {
    match CheckpointStore::new(db).verify_chain(head, None, false) {
        Ok(c) => ChainState::Intact {
            length: c.length,
            signed: c.signed,
        },
        Err(e) if e.to_string().contains("no checkpoints") => ChainState::None,
        Err(e) => ChainState::Broken(e.to_string()),
    }
}

fn evaluate(
    check: Check,
    records: &[AuditRecord],
    chain: &ChainState,
    encryption: bool,
    retention: bool,
) -> (Status, String) {
    match check {
        AuditLogging => {
            if records.is_empty() {
                (
                    Status::Fail,
                    "No retrieval audit records in this period.".into(),
                )
            } else {
                (
                    Status::Pass,
                    format!("{} retrieval(s) recorded.", records.len()),
                )
            }
        }
        TamperEvidentChain => match chain {
            ChainState::Intact { length, .. } => (
                Status::Pass,
                format!("Chain intact across {length} checkpoint(s)."),
            ),
            ChainState::Broken(why) => (Status::Fail, format!("Chain broken: {why}")),
            ChainState::None => (
                Status::Warn,
                "No checkpoint chain anchored. Run `checkpoint new --sign-key`.".into(),
            ),
        },
        CheckpointsSigned => match chain {
            ChainState::Intact { length, signed } if signed == length => {
                (Status::Pass, format!("All {length} checkpoint(s) signed."))
            }
            ChainState::Intact { length, signed } => (
                Status::Warn,
                format!("{signed} of {length} checkpoint(s) signed."),
            ),
            _ => (Status::Warn, "No checkpoint chain to sign.".into()),
        },
        EncryptionAtRest => {
            if encryption {
                (Status::Pass, "Encryption at rest enabled.".into())
            } else {
                (Status::Warn, "Encryption at rest is not enabled.".into())
            }
        }
        PrincipalRecorded => {
            if records.is_empty() {
                (Status::Warn, "No records to evaluate.".into())
            } else if records.iter().all(|r| r.principal.is_some()) {
                (Status::Pass, "Every retrieval names a principal.".into())
            } else {
                let missing = records.iter().filter(|r| r.principal.is_none()).count();
                (
                    Status::Warn,
                    format!("{missing} retrieval(s) have no principal."),
                )
            }
        }
        RetentionConfigured => {
            if retention {
                (Status::Pass, "Retention floor configured.".into())
            } else {
                (
                    Status::Warn,
                    "No `retention_min_secs` set in meta/config.json.".into(),
                )
            }
        }
        DataVersionLinkage => (
            Status::Pass,
            "Each record links to the exact commit queried (structural).".into(),
        ),
    }
}

/// Run a framework's checks against the head's audit data for `[from, to]`.
pub fn check(
    db: &Database,
    head: &str,
    framework: &str,
    from: u64,
    to: u64,
) -> Result<ComplianceReport> {
    let cat = catalog();
    let def = cat.iter().find(|f| f.info.id == framework).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown framework '{framework}'; see `compliance frameworks` for the catalog"
        )
    })?;

    let (records, _) = audit::collect(db, head, from, to)?;
    let chain = chain_state(db, head);
    let encryption = db.config.encryption.as_ref().is_some_and(|e| e.enabled);
    let retention = db.config.retention_min_secs.is_some();

    let mut checks = Vec::new();
    let mut overall = Status::Pass;
    for &(kind, severity) in def.checks {
        let (status, detail) = evaluate(kind, &records, &chain, encryption, retention);
        if severity == Required {
            match status {
                Status::Fail => overall = Status::Fail,
                Status::Warn if overall != Status::Fail => overall = Status::Warn,
                _ => {}
            }
        }
        checks.push(CheckResult {
            id: kind.id(),
            label: kind.label(),
            status,
            severity,
            detail,
        });
    }

    Ok(ComplianceReport {
        framework: def.info.id,
        jurisdiction: def.info.jurisdiction,
        region: def.info.region,
        name: def.info.name,
        citation: def.info.citation,
        head: head.to_string(),
        from,
        to,
        retrievals: records.len(),
        overall,
        checks,
        mappings: def
            .mappings
            .iter()
            .map(|&(requirement, mechanism)| Mapping {
                requirement,
                mechanism,
            })
            .collect(),
    })
}

/// Markdown rendering of a [`ComplianceReport`].
pub fn render_report(
    db: &Database,
    head: &str,
    framework: &str,
    from: u64,
    to: u64,
) -> Result<String> {
    if catalog().iter().all(|f| f.info.id != framework) {
        bail!("unknown framework '{framework}'; see `compliance frameworks` for the catalog");
    }
    let r = check(db, head, framework, from, to)?;
    let status_word = |s: Status| match s {
        Status::Pass => "PASS",
        Status::Warn => "WARN",
        Status::Fail => "FAIL",
    };

    let mut out = String::new();
    out.push_str(&format!(
        "# AI retrieval audit report — {} ({})\n\n\
         framework: {} — {}\nhead: `{head}`\nperiod: {from}..{to} (unix seconds)\ngenerated: {}\n\n",
        r.name, r.jurisdiction, r.name, r.citation, crate::clock::now_unix()?
    ));
    out.push_str(&format!("## Overall: **{}**\n\n", status_word(r.overall)));
    out.push_str("## Evidence summary\n\n");
    out.push_str(&format!("- retrievals recorded: **{}**\n", r.retrievals));
    let principals: std::collections::BTreeSet<&str> = {
        let (records, _) = audit::collect(db, head, from, to)?;
        records
            .iter()
            .filter_map(|r| r.principal.clone())
            .collect::<Vec<_>>()
            .leak()
            .iter()
            .map(|s| s.as_str())
            .collect()
    };
    out.push_str(&format!(
        "- principals: {}\n\n",
        if principals.is_empty() {
            "-".to_string()
        } else {
            principals.into_iter().collect::<Vec<_>>().join(", ")
        }
    ));

    out.push_str("## Checks\n\n| Check | Severity | Status | Detail |\n|---|---|---|---|\n");
    for c in &r.checks {
        out.push_str(&format!(
            "| {} | {} | **{}** | {} |\n",
            c.label,
            match c.severity {
                Severity::Required => "required",
                Severity::Recommended => "recommended",
            },
            status_word(c.status),
            c.detail,
        ));
    }

    out.push_str("\n## Requirement mapping\n\n| Requirement | Mechanism |\n|---|---|\n");
    for m in &r.mappings {
        out.push_str(&format!("| {} | {} |\n", m.requirement, m.mechanism));
    }

    out.push_str(
        "\n## Verification\n\nExport the period's bundle and verify it independently:\n\n\
         ```\nneleus-db audit export --head HEAD --from FROM --to TO --out bundle.nelaudit\n\
         neleus-verify bundle.nelaudit [--public-key <hex>]\n```\n\n\
         This is generated evidence tooling, not legal advice; the mapping describes \
         technical mechanisms only.\n",
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::engine::{Engine, SearchFilter};

    fn seeded() -> (TempDir, Database) {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let engine = Engine::open(&root).unwrap();
        let (_, commit) = engine
            .put_document(
                "main",
                "kb",
                b"compliance corpus with auditable searchable content",
                crate::manifest::ChunkingSpec {
                    method: "fixed".into(),
                    chunk_size: 64,
                    overlap: 0,
                },
                None,
                "test",
            )
            .unwrap();
        let hits = engine
            .search_semantic(commit, "auditable content", 5, &SearchFilter::default())
            .unwrap();
        let qm = engine
            .record_query(
                commit,
                "semantic",
                Some("auditable content"),
                None,
                5,
                &SearchFilter::default(),
                Some("key:agent"),
                &hits,
            )
            .unwrap();
        engine.commit("main", "auditor", "audit", vec![qm]).unwrap();
        (tmp, Database::open(&root).unwrap())
    }

    #[test]
    fn catalog_groups_by_jurisdiction() {
        let fws = frameworks();
        assert!(fws.len() >= 12);
        assert!(fws.iter().any(|f| f.region == "EU" && f.id == "eu-ai-act"));
        assert!(fws.iter().any(|f| f.region == "US-CA"));
        assert!(fws.iter().any(|f| f.region == "Global"));
        // ids unique
        let mut ids: Vec<_> = fws.iter().map(|f| f.id).collect();
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn checks_pass_when_audit_records_present() {
        let (_t, db) = seeded();
        let r = check(&db, "main", "eu-ai-act", 0, u64::MAX).unwrap();
        let logging = r.checks.iter().find(|c| c.id == "audit-logging").unwrap();
        assert_eq!(logging.status, Status::Pass);
        // No checkpoint chain seeded -> required tamper-evidence warns -> overall Warn.
        assert_eq!(r.overall, Status::Warn);
        assert!(r.retrievals >= 1);
    }

    #[test]
    fn missing_records_fails_required_logging() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("db");
        Database::init(&root).unwrap();
        let db = Database::open(&root).unwrap();
        db.create_commit_at_head("main", "a", "empty", vec![])
            .unwrap();
        let r = check(&db, "main", "hipaa", 0, u64::MAX).unwrap();
        assert_eq!(r.overall, Status::Fail);
        assert_eq!(
            r.checks
                .iter()
                .find(|c| c.id == "audit-logging")
                .unwrap()
                .status,
            Status::Fail
        );
    }

    #[test]
    fn render_keeps_legacy_substrings() {
        let (_t, db) = seeded();
        for fw in ["eu-ai-act", "hipaa", "sec-occ"] {
            let md = render_report(&db, "main", fw, 0, u64::MAX).unwrap();
            assert!(md.contains("Requirement mapping"), "{fw}");
            assert!(md.contains("retrievals recorded: **1**"), "{fw}");
            assert!(md.contains("## Checks"), "{fw}");
        }
        assert!(render_report(&db, "main", "soc2", 0, u64::MAX).is_err());
    }
}

//! Standalone audit-bundle verifier. No database, no network: every claim
//! is re-derived from bytes carried in the bundle. Hand this binary to an
//! auditor with the bundle; nothing else is needed.
//!
//! ```text
//! neleus-verify bundle.nelaudit [--public-key <hex>] [--require-signature] [--anchor <checkpoint>] [--json]
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut bundle: Option<PathBuf> = None;
    let mut public_key: Option<String> = None;
    let mut require_signature = false;
    let mut anchor: Option<String> = None;
    let mut json = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--public-key" => public_key = args.next(),
            "--require-signature" => require_signature = true,
            "--anchor" => anchor = args.next(),
            "--json" => json = true,
            "--help" | "-h" => {
                eprintln!(
                    "usage: neleus-verify <bundle> [--public-key <hex>] [--require-signature] [--anchor <checkpoint>] [--json]"
                );
                return ExitCode::SUCCESS;
            }
            other if bundle.is_none() => bundle = Some(PathBuf::from(other)),
            other => {
                eprintln!("unexpected argument: {other}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(bundle) = bundle else {
        eprintln!("usage: neleus-verify <bundle> [--public-key <hex>] [--require-signature]");
        return ExitCode::from(2);
    };

    let verified = match anchor.as_deref().map(str::parse::<neleus_db::Hash>) {
        None => neleus_db::audit::verify_bundle(&bundle, public_key.as_deref(), require_signature),
        Some(Ok(a)) => neleus_db::audit::verify_bundle_anchored(
            &bundle,
            public_key.as_deref(),
            require_signature,
            a,
        ),
        Some(Err(e)) => {
            eprintln!("invalid --anchor: {e}");
            return ExitCode::from(2);
        }
    };
    match verified {
        Ok(report) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "valid": true,
                        "retrievals": report.retrievals,
                        "head": report.head,
                        "from": report.from,
                        "to": report.to,
                        "commits": report.commits,
                        "checkpoints": report.checkpoints,
                        "checkpoints_signed": report.checkpoints_signed,
                        "checkpoint_tip": report.checkpoint_tip,
                        "log_size": report.log_size,
                        "anchored": report.anchored,
                        "bundle_key_id": report.bundle_key_id,
                        "commits_signed": report.commits_signed,
                        "commit_keys": report.commit_keys,
                    })
                );
            } else {
                let signed = match &report.bundle_key_id {
                    Some(key) => format!("signed by {key}"),
                    None => "unsigned".to_string(),
                };
                println!(
                    "VERIFIED: {} retrievals on head '{}', {} — chain intact across {} commits, checkpoint log of {} ({}){}, period {}..{}",
                    report.retrievals,
                    report.head,
                    signed,
                    report.commits,
                    report.log_size,
                    report.checkpoint_tip.as_deref().unwrap_or("none"),
                    if report.anchored {
                        ", extends the given anchor"
                    } else {
                        ""
                    },
                    report.from,
                    report.to,
                );
                if !report.commit_keys.is_empty() {
                    println!(
                        "{} signed commits, by: {}",
                        report.commits_signed,
                        report.commit_keys.join(", ")
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({"valid": false, "error": e.to_string()})
                );
            } else {
                eprintln!("INVALID: {e}");
            }
            ExitCode::FAILURE
        }
    }
}

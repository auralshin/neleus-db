//! Standalone audit-bundle verifier. No database, no network: every claim
//! is re-derived from bytes carried in the bundle. Hand this binary to an
//! auditor with the bundle; nothing else is needed.
//!
//! ```text
//! neleus-verify bundle.nelaudit [--public-key <hex>] [--require-signature] [--json]
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut bundle: Option<PathBuf> = None;
    let mut public_key: Option<String> = None;
    let mut require_signature = false;
    let mut json = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--public-key" => public_key = args.next(),
            "--require-signature" => require_signature = true,
            "--json" => json = true,
            "--help" | "-h" => {
                eprintln!(
                    "usage: neleus-verify <bundle> [--public-key <hex>] [--require-signature] [--json]"
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

    match neleus_db::audit::verify_bundle(&bundle, public_key.as_deref(), require_signature) {
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
                        "bundle_key_id": report.bundle_key_id,
                    })
                );
            } else {
                let signed = match &report.bundle_key_id {
                    Some(key) => format!("signed by {key}"),
                    None => "unsigned".to_string(),
                };
                println!(
                    "VERIFIED: {} retrievals on head '{}', {} — chain intact across {} commits, {} checkpoints ({} signed), period {}..{}",
                    report.retrievals,
                    report.head,
                    signed,
                    report.commits,
                    report.checkpoints,
                    report.checkpoints_signed,
                    report.from,
                    report.to,
                );
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

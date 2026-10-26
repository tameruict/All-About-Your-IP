//! `probe` — headless bridge for the §13.1 live test.
//!
//! The QA harness (`tests/harness/spec13.test.mjs`) runs under Node, but
//! `check_ip` is a Tauri command that normally only exists inside a WebView.
//! This binary calls the same pipeline directly, prints one JSON object on
//! stdout, and exits — no window, no database, no cache.
//!
//! Usage (run from `src-tauri/`):
//!
//! ```powershell
//! $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
//! $env:CARGO_TARGET_DIR = "C:\cargo-target\ip-checker"
//! cargo run --bin probe -- 8.8.8.8
//! cargo run --bin probe -- 1.1.1.1 --timeout-ms 20000
//! ```
//!
//! Contract with the harness:
//!
//! * stdout carries **exactly one JSON object**, nothing else. All logging goes
//!   to stderr so stdout stays machine-parseable.
//! * exit `0` = completed a check (even if the verdict is "not enough data").
//! * exit `2` = blocked before any provider ran (offline, DNS, invalid input).
//!   The JSON carries `"blocked": true` and a human `reason`. **The harness maps
//!   this to BLOCKED, never to PASS** — an unreachable network must not look
//!   like a passing test.
//! * exit `1` = unexpected internal error.
//!
//! §8.4 / §10.1: no credentials, no cache, no SQLite. Nothing is persisted.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use ip_checker_lib::models::{CheckOptions, ModuleStatus};
use ip_checker_lib::orchestrator;

/// Per-request network timeout handed to the orchestrator, in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 15_000;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Logs -> stderr only. Keep stdout clean for the single JSON document.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let mut args = std::env::args().skip(1);
    let mut target: Option<String> = None;
    let mut timeout_ms = DEFAULT_TIMEOUT_MS;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--timeout-ms" => {
                if let Some(v) = args.next() {
                    if let Ok(parsed) = v.parse::<u64>() {
                        timeout_ms = parsed.max(1_000);
                    }
                }
            }
            "--help" | "-h" => {
                eprintln!("usage: probe <ip-or-ip:port> [--timeout-ms N]");
                return ExitCode::SUCCESS;
            }
            other => {
                if target.is_none() {
                    target = Some(other.to_string());
                }
            }
        }
    }

    let Some(input) = target else {
        emit(&serde_json::json!({
            "blocked": true,
            "reason": "no input given (usage: probe <ip-or-ip:port>)",
        }));
        return ExitCode::from(2);
    };

    // Pre-flight: prove the machine can actually reach a provider before blaming
    // the app for returning no evidence. A firewall that silently drops traffic
    // would otherwise surface as "0 providers answered", which reads like an app
    // bug. A DNS failure is the clearest offline signal and needs no HTTP client.
    if let Err(reason) = preflight().await {
        emit(&serde_json::json!({
            "blocked": true,
            "input": input,
            "reason": reason,
            "hint": "sandbox/proxy/firewall blocks outbound DNS or HTTPS; §13.1 live cannot be measured here",
        }));
        return ExitCode::from(2);
    }

    let options = CheckOptions {
        protocol: None,
        credentials: None,
        use_cache: Some(false),      // §10.2 — a probe must never read a cached row
        save_to_history: Some(false), // §10.1 — nothing is persisted
        run_leak_check: Some(false),  // IP-only mode: leak needs a proxy (§1.2)
        run_speed_check: Some(false), // IP-only mode: speed needs a proxy (§1.2)
        timeout_ms: Some(timeout_ms),
        modules: None,
    };

    let started = Instant::now();
    let outcome = orchestrator::run_check(&input, options).await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let session = outcome.session;
    let Some(result) = session.result.clone() else {
        emit(&serde_json::json!({
            "blocked": true,
            "input": input,
            "reason": "orchestrator returned no result",
            "errors": session.errors,
        }));
        return ExitCode::from(2);
    };

    // Count what actually came back so the harness can tell "the app is broken"
    // apart from "every provider was skipped for a legitimate reason".
    let surveyed = session
        .modules
        .iter()
        .filter(|m| m.status == ModuleStatus::Done)
        .count();
    let skipped = session
        .modules
        .iter()
        .filter(|m| m.status == ModuleStatus::Skipped)
        .count();
    let errored = session
        .modules
        .iter()
        .filter(|m| m.status == ModuleStatus::Error)
        .count();

    let evidence = result.evidence.len();

    // A check that ran but gathered zero evidence means the network path to the
    // providers is dead. That is BLOCKED, not a pass: §13.1 asks whether a public
    // IP yields a verdict + geo + ASN, and with no evidence we cannot tell.
    let blocked = evidence == 0 && result.is_private == false && result.validation_error.is_none();

    emit(&serde_json::json!({
        "blocked": blocked,
        "blocked_reason": if blocked {
            Some("no provider returned evidence — outbound HTTPS to providers appears blocked")
        } else {
            None
        },
        "input": input,
        "ip": result.ip,
        "mode": result.mode,
        "verdict": result.verdict,
        "verdict_reason": result.verdict_reason,
        "clean_score": result.clean_score,
        "confidence_score": result.confidence_score,
        "evidence_count": evidence,
        "is_private": result.is_private,
        "validation_error": result.validation_error,
        "ip_version": result.ip_version,
        "geo": {
            "country": result.location.as_ref().and_then(|l| l.country.clone()),
            "country_code": result.location.as_ref().and_then(|l| l.country_code.clone()),
            "city": result.location.as_ref().and_then(|l| l.city.clone()),
            "points": result.location.as_ref().map(|l| l.points.len()).unwrap_or(0),
            "spread": result.location.as_ref().map(|l| l.spread.clone()),
            "big_divergence": result.location.as_ref().map(|l| l.big_divergence).unwrap_or(false),
        },
        "asn": {
            "asn": result.asn.as_ref().and_then(|a| a.asn),
            "organisation": result.asn.as_ref().and_then(|a| a.organisation.clone()),
            "isp": result.asn.as_ref().and_then(|a| a.isp.clone()),
            "consensus": result.asn.as_ref().map(|a| a.consensus).unwrap_or(false),
            "records": result.asn.as_ref().map(|a| a.records.len()).unwrap_or(0),
        },
        "leak_measured": result.leak.as_ref().map(|l| l.measured).unwrap_or(false),
        "speed_measured": result.speed.as_ref().map(|s| s.measured).unwrap_or(false),
        "modules": { "done": surveyed, "skipped": skipped, "error": errored },
        "errors": session.errors,
        "elapsed_ms": elapsed_ms,
        "timeout_ms": timeout_ms,
    }));

    if blocked {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// Print exactly one JSON line on stdout. Never mix diagnostics into stdout.
fn emit(value: &serde_json::Value) {
    println!("{value}");
}

/// Cheap connectivity gate: resolve a provider host over DNS.
///
/// Deliberately DNS-only — it needs no HTTP client, so it stays honest about a
/// dead network without pretending to test the app.
async fn preflight() -> Result<(), String> {
    match tokio::time::timeout(Duration::from_secs(6), tokio::net::lookup_host("ipwho.is:443"))
        .await
    {
        Ok(Ok(mut addrs)) => {
            if addrs.next().is_some() {
                Ok(())
            } else {
                Err("DNS for ipwho.is returned no addresses".to_string())
            }
        }
        Ok(Err(e)) => Err(format!("DNS lookup for ipwho.is failed: {e}")),
        Err(_) => Err("DNS lookup for ipwho.is timed out after 6s".to_string()),
    }
}

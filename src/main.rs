//! broadside — deterministic build, verify, and deploy MCP
//! server for qompass.ai (stdio).
//!
//! Six tools (broadside_status, broadside_live_check,
//! broadside_build, broadside_verify, broadside_deploy,
//! broadside_census), an
//! append-only hash-chained receipt log (broadside.receipt v1)
//! that vongola consumes read-only, the Agent Card JWKS duty
//! (published from a signed key record, fail-closed), and the
//! honeypot layer: signed canary manifests, injection quarantine,
//! hash-chained evidence packets, no hack-back ever.
//!
//! Modern protocol era only (2026-07-28): sessions open with
//! `server/discover`; legacy `initialize` contact is refused at
//! the stdio front door (see `guard`) with the typed `-32022`
//! unsupported-version error naming 2026-07-28.
//!
//! Usage:
//!   broadside-mcp [flags]                 serve MCP on stdio
//!   broadside-mcp packet [--out <dir>]    assemble an H5 evidence
//!                                         packet + abuse draft
//!   broadside-mcp feed [--out <file>]     write the H4 blocklist
//!                                         feed from receipts
//!
//! Flags: --site-root, --state-dir, --base-url, --deploy-target,
//! --ssh-key, --canary-signer-pubkey (BROADSIDE_* env equivalents;
//! see config.rs). A production deploy is per-call confirmed
//! inside the broadside_deploy tool itself; there is no CLI path
//! that deploys.

#![forbid(unsafe_code)]

use broadside_mcp::{config, guard, h4, packet, server};

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use rmcp::ServiceExt;
use rmcp::transport::async_rw::AsyncRwTransport;
use tokio::sync::Mutex;

/// Duplex buffer between the era guard and the SDK service.
const DUPLEX_BUFFER_BYTES: usize = 1024 * 1024;

enum Mode {
    Serve,
    Packet { out: PathBuf },
    Feed { out: PathBuf },
}

fn parse_args(args: &[String]) -> Result<(config::Config, Mode), ExitCode> {
    let mut cfg = config::from_env();
    let mut mode = Mode::Serve;
    let mut argv = args.iter().peekable();
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "packet" => {
                mode = Mode::Packet {
                    out: cfg.state_dir.join("packets"),
                };
            }
            "feed" => {
                mode = Mode::Feed {
                    out: cfg.state_dir.join("blocklist-feed.txt"),
                };
            }
            "--out" => {
                let value = argv.next().map(PathBuf::from);
                match (&mut mode, value) {
                    (Mode::Packet { out }, Some(v)) => *out = v,
                    (Mode::Feed { out }, Some(v)) => *out = v,
                    _ => {
                        eprintln!("broadside: --out needs a value after packet/feed");
                        return Err(ExitCode::from(2));
                    }
                }
            }
            "--site-root" => {
                if let Some(v) = argv.next() {
                    cfg.site_root = PathBuf::from(v);
                }
            }
            "--state-dir" => {
                if let Some(v) = argv.next() {
                    cfg.state_dir = PathBuf::from(v);
                }
            }
            "--base-url" => {
                if let Some(v) = argv.next() {
                    cfg.base_url = v.clone();
                }
            }
            "--deploy-target" => {
                if let Some(v) = argv.next() {
                    cfg.deploy_target = v.clone();
                }
            }
            "--ssh-key" => {
                if let Some(v) = argv.next() {
                    cfg.ssh_key = PathBuf::from(v);
                }
            }
            "--canary-signer-pubkey" => {
                if let Some(v) = argv.next() {
                    cfg.canary_signer_pubkey = Some(v.clone());
                }
            }
            other => eprintln!("broadside: ignoring unknown arg {other}"),
        }
    }
    Ok((cfg, mode))
}

/// Wire the serve loop: the guard owns stdio, the SDK service sits
/// behind an in-process duplex, and a pump copies responses back
/// (the fleet pattern, unchanged).
async fn run(cfg: config::Config) -> std::io::Result<()> {
    let (client_side, server_side) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
    let (server_read, server_write) = tokio::io::split(server_side);
    let (client_read, client_write) = tokio::io::split(client_side);
    let stdout: guard::SharedStdout = Arc::new(Mutex::new(tokio::io::stdout()));

    let ordering = guard::Ordering::new();
    let handler = server::BroadsideServer::new(cfg);
    let serve = tokio::spawn(async move {
        let transport = AsyncRwTransport::new_server(server_read, server_write);
        match handler.serve(transport).await {
            Ok(running) => running
                .waiting()
                .await
                .map(|_| ())
                .map_err(|e| std::io::Error::other(e.to_string())),
            Err(rmcp::service::ServerInitializeError::ConnectionClosed(_)) => Ok(()),
            Err(e) => Err(std::io::Error::other(e.to_string())),
        }
    });
    let mut pump = tokio::spawn(guard::pump(
        client_read,
        Arc::clone(&stdout),
        Arc::clone(&ordering),
    ));

    let guard_result = guard::run(tokio::io::stdin(), client_write, stdout, ordering).await;
    let serve_result = match serve.await {
        Ok(result) => result,
        Err(e) => Err(std::io::Error::other(e.to_string())),
    };
    if tokio::time::timeout(std::time::Duration::from_secs(2), &mut pump)
        .await
        .is_err()
    {
        pump.abort();
    }
    guard_result.and(serve_result)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cfg, mode) = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    match mode {
        Mode::Packet { out } => match packet::assemble_packet(&cfg, &out) {
            Ok(summary) => {
                println!("{summary}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("broadside packet: {e}");
                ExitCode::FAILURE
            }
        },
        Mode::Feed { out } => match h4::write_feed(&cfg, &out) {
            Ok(summary) => {
                println!("{summary}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("broadside feed: {e}");
                ExitCode::FAILURE
            }
        },
        Mode::Serve => {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(e) => {
                    eprintln!("broadside: cannot start runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match runtime.block_on(run(cfg)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("broadside: serve loop ended: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_modes_and_flags() {
        let (cfg, mode) = parse_args(&[
            "--site-root".to_string(),
            "/tmp/site".to_string(),
            "--deploy-target".to_string(),
            "/tmp/staging".to_string(),
        ])
        .expect("parse");
        assert!(matches!(mode, Mode::Serve));
        assert_eq!(cfg.site_root, PathBuf::from("/tmp/site"));
        assert_eq!(cfg.deploy_target, "/tmp/staging");
        let (_, mode) = parse_args(&["packet".to_string()]).expect("packet parse");
        assert!(matches!(mode, Mode::Packet { .. }));
        let (_, mode) = parse_args(&[
            "feed".to_string(),
            "--out".to_string(),
            "/tmp/feed.txt".to_string(),
        ])
        .expect("feed parse");
        match mode {
            Mode::Feed { out } => assert_eq!(out, PathBuf::from("/tmp/feed.txt")),
            _ => panic!("expected feed mode"),
        }
    }
}

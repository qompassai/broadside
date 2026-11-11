//! broadside_deploy, broadside_live_check, broadside_status.
//!
//! deploy discipline (PROGRAM.md + the task's hard boundaries):
//! - exactly one dist hash, named by the caller;
//! - only behind a passing verify receipt for that identical
//!   hash — no receipt, no deploy; a changed dist, no deploy;
//! - per-call confirmation: `confirm: true` or the call is
//!   refused (and the refusal is receipted);
//! - live read-back after transfer, written into the deploy
//!   receipt; a failed read-back is a failed deploy.
//!
//! A production deploy is an Owner-confirmed act by design; the
//! server's staging mode (a local target directory) proves the
//! full mechanics without touching the live site.
//!
//! live_check reads the live site and the host's canary log and
//! compares both against the deployed manifest — drift and hits
//! are findings in a receipt, never silently absorbed.

use std::time::Duration;

use serde_json::{Value, json};

use crate::config::{Config, HOST_ACCESS_LOG, PROD_HOST};
use crate::crypto::sha256_hex;
use crate::dist::manifest_of;
use crate::honeypot;
use crate::http;
use crate::jwks;
use crate::proc::{run_bounded, tail};
use crate::receipts::gate;

const TRANSFER_DEADLINE: Duration = Duration::from_secs(1200);
const STEP_DEADLINE: Duration = Duration::from_secs(120);

/// Routes live_check always probes (plus the JWKS document).
pub const LIVE_ROUTES: &[&str] = &["/", "/research", "/solutions", "/solutions/mcp-servers"];

pub fn deploy(
    cfg: &Config,
    dist_hash: &str,
    confirm: bool,
    dry_run: bool,
) -> Result<Value, String> {
    let log = cfg.receipts();
    let mut gates: Vec<Value> = Vec::new();
    let inputs = json!({
        "dist_hash": dist_hash, "confirm": confirm, "dry_run": dry_run,
        "target": cfg.deploy_target,
    });
    let refuse = |log: &crate::receipts::ReceiptLog,
                  gates: Vec<Value>,
                  inputs: &Value|
     -> Result<Value, String> {
        log.append(json!({
            "action": "deploy", "site_head": null, "inputs": inputs,
            "outputs": {}, "gates": gates, "result": "refused",
        }))
    };

    // Gate: per-call confirmation.
    if !confirm {
        gates.push(gate(
            "confirmation",
            "fail",
            "deploy requires confirm: true on this call (per-call Owner confirmation by design)",
        ));
        return refuse(&log, gates, &inputs);
    }
    gates.push(gate("confirmation", "pass", "confirm: true present"));

    // Gate: a passing verify receipt for this identical hash.
    let verified = log.read_all()?.into_iter().rev().find(|r| {
        r.get("action").and_then(Value::as_str) == Some("verify")
            && r.get("result").and_then(Value::as_str) == Some("pass")
            && r.get("outputs")
                .and_then(|o| o.get("dist_hash"))
                .and_then(Value::as_str)
                == Some(dist_hash)
    });
    match verified {
        None => {
            gates.push(gate(
                "verify_receipt",
                "fail",
                "no passing verify receipt for this dist hash; deploy refused",
            ));
            return refuse(&log, gates, &inputs);
        }
        Some(r) => gates.push(gate(
            "verify_receipt",
            "pass",
            &format!(
                "verify receipt seq {} covers hash {dist_hash}",
                r.get("seq").cloned().unwrap_or(Value::Null)
            ),
        )),
    }

    // Gate: the dist on disk is still exactly that hash.
    let dist = cfg.dist();
    let manifest = match manifest_of(&dist) {
        Ok(m) => m,
        Err(e) => {
            gates.push(gate("dist_identity", "fail", &e));
            return refuse(&log, gates, &inputs);
        }
    };
    if manifest.tree_hash != dist_hash {
        gates.push(gate(
            "dist_identity",
            "fail",
            &format!(
                "dist on disk hashes to {}, not the verified {dist_hash}",
                manifest.tree_hash
            ),
        ));
        return refuse(&log, gates, &inputs);
    }
    gates.push(gate(
        "dist_identity",
        "pass",
        "dist on disk == verified hash",
    ));

    // Transfer.
    let dist_arg = format!("{}/", dist.display());
    let (program, args): (&str, Vec<String>) = if cfg.target_is_local() {
        let mut a = vec!["-az".to_string(), "--delete".to_string()];
        if dry_run {
            a.push("--dry-run".to_string());
        }
        a.push(dist_arg);
        a.push(format!("{}/", cfg.deploy_target.trim_end_matches('/')));
        ("rsync", a)
    } else {
        let mut a = vec!["-az".to_string(), "--delete".to_string()];
        if dry_run {
            a.push("--dry-run".to_string());
        }
        a.push("-e".to_string());
        a.push(format!(
            "ssh -i {} -o StrictHostKeyChecking=accept-new",
            cfg.ssh_key.display()
        ));
        a.push(dist_arg);
        a.push(cfg.deploy_target.clone());
        ("rsync", a)
    };
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let transfer = run_bounded(program, &arg_refs, None, TRANSFER_DEADLINE)?;
    if !transfer.success {
        gates.push(gate(
            "transfer",
            "fail",
            &format!("rsync failed: {}", tail(&transfer.stderr, 400)),
        ));
        return log.append(json!({
            "action": "deploy", "site_head": null, "inputs": inputs,
            "outputs": {}, "gates": gates, "result": "fail",
        }));
    }
    gates.push(gate(
        "transfer",
        "pass",
        if dry_run {
            "rsync --dry-run completed (nothing transferred)"
        } else {
            "rsync completed"
        },
    ));

    // Read-back: what is now served/staged must hash to the
    // manifest. Staging: re-hash the target tree. Production:
    // fetch key routes and compare body hashes.
    let mut outputs = json!({"manifest": manifest.to_json(), "dist_hash": dist_hash});
    let readback_ok = if dry_run {
        outputs["readback"] = json!({"mode": "dry-run", "performed": false});
        gates.push(gate(
            "readback",
            "skip",
            "dry run: no read-back against the target",
        ));
        true
    } else if cfg.target_is_local() {
        let target_manifest = manifest_of(std::path::Path::new(&cfg.deploy_target));
        match target_manifest {
            Ok(tm) if tm.tree_hash == dist_hash => {
                outputs["readback"] = json!({"mode": "staging-rehash", "tree_hash": tm.tree_hash});
                gates.push(gate(
                    "readback",
                    "pass",
                    "staging tree rehashes to the deployed hash",
                ));
                true
            }
            Ok(tm) => {
                outputs["readback"] = json!({"mode": "staging-rehash", "tree_hash": tm.tree_hash});
                gates.push(gate(
                    "readback",
                    "fail",
                    &format!("staging tree hashes to {}, not {dist_hash}", tm.tree_hash),
                ));
                false
            }
            Err(e) => {
                gates.push(gate("readback", "fail", &e));
                false
            }
        }
    } else {
        let (ok, detail, pages) = http_readback(cfg, &manifest);
        outputs["readback"] = json!({"mode": "http", "pages": pages});
        gates.push(gate("readback", if ok { "pass" } else { "fail" }, &detail));
        ok
    };

    log.append(json!({
        "action": "deploy", "site_head": null, "inputs": inputs,
        "outputs": outputs, "gates": gates,
        "result": if readback_ok { "pass" } else { "fail" },
    }))
}

/// Fetch the live routes and compare each body hash against the
/// deployed manifest.
fn http_readback(cfg: &Config, manifest: &crate::dist::DistManifest) -> (bool, String, Vec<Value>) {
    let mut pages = Vec::new();
    let mut all_ok = true;
    for route in LIVE_ROUTES.iter().chain([jwks::JWKS_ROUTE].iter()) {
        let url = format!("{}{}", cfg.base_url.trim_end_matches('/'), route);
        match http::get(&url) {
            Ok(fetch) => {
                let body_hash = sha256_hex(&fetch.body);
                let expected = manifest.entry_for_route(route).map(|e| e.1.clone());
                let matches = expected.as_deref() == Some(body_hash.as_str());
                if !matches || fetch.status != 200 {
                    all_ok = false;
                }
                pages.push(json!({
                    "route": route, "status": fetch.status,
                    "sha256": body_hash, "manifest_sha256": expected,
                    "match": matches,
                }));
            }
            Err(e) => {
                all_ok = false;
                pages.push(json!({"route": route, "error": e}));
            }
        }
    }
    (
        all_ok,
        if all_ok {
            "all read-back routes match the deployed manifest".to_string()
        } else {
            "read-back mismatch (see outputs.readback.pages)".to_string()
        },
        pages,
    )
}

pub fn live_check(cfg: &Config) -> Result<Value, String> {
    let log = cfg.receipts();
    let mut findings: Vec<Value> = Vec::new();
    let mut pages: Vec<Value> = Vec::new();

    // Deployed baseline: the newest passing deploy receipt.
    let deploy_receipt = log.latest("deploy", Some("pass"))?;
    let deployed_manifest = deploy_receipt
        .as_ref()
        .and_then(|r| r.get("outputs"))
        .and_then(|o| o.get("manifest"))
        .cloned();

    for route in LIVE_ROUTES.iter().chain([jwks::JWKS_ROUTE].iter()) {
        let url = format!("{}{}", cfg.base_url.trim_end_matches('/'), route);
        match http::get(&url) {
            Ok(fetch) => {
                let body_hash = sha256_hex(&fetch.body);
                let expected = deployed_manifest.as_ref().and_then(|m| {
                    m.get("files")
                        .and_then(Value::as_array)
                        .and_then(|files| {
                            let rel = crate::dist::route_to_relpath(route);
                            files.iter().find(|f| {
                                f.get("path").and_then(Value::as_str) == Some(rel.as_str())
                            })
                        })
                        .and_then(|f| f.get("sha256"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                });
                let state = match (&expected, fetch.status) {
                    (Some(exp), 200) if *exp == body_hash => "match",
                    (Some(_), 200) => "drift",
                    // No deploy baseline yet: the page is simply
                    // observed. (First calibration run mislabeled
                    // this "error-status" on healthy 200s.)
                    (None, 200) => "observed",
                    (_, 404) => "missing",
                    _ => "error-status",
                };
                if state == "drift" {
                    findings.push(json!({
                        "kind": "drift", "route": route,
                        "detail": "live body hash differs from the deployed manifest",
                    }));
                }
                if *route == jwks::JWKS_ROUTE {
                    match fetch.status {
                        404 => findings.push(json!({
                            "kind": "jwks-missing", "route": route,
                            "detail": "the live site serves no JWKS document",
                        })),
                        200 => {
                            if let Some((record, record_json)) =
                                jwks::load_key_record(&cfg.site_root)?
                            {
                                let live: Value =
                                    serde_json::from_slice(&fetch.body).unwrap_or(Value::Null);
                                if jwks::record_signature_valid(&record_json, &record)
                                    && live != jwks::jwks_document(&record)
                                {
                                    findings.push(json!({
                                        "kind": "jwks-mismatch", "route": route,
                                        "detail": "live JWKS does not match the signed key record",
                                    }));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                pages.push(json!({
                    "route": route, "status": fetch.status,
                    "sha256": body_hash, "state": state,
                }));
            }
            Err(e) => {
                findings.push(json!({"kind": "unreachable", "route": route, "detail": e}));
                pages.push(json!({"route": route, "error": "fetch failed"}));
            }
        }
    }

    // Canary-log read-back (H1): hits on decoy paths in the host
    // access log since the log's tail window. Any hit is hostile
    // by construction (the paths are Disallow'd and unlinked).
    let canary = canary_log_readback(cfg);
    if let Some(hits) = canary.get("hits").and_then(Value::as_array)
        && !hits.is_empty()
    {
        findings.push(json!({
            "kind": "canary-hit", "severity": "HIGH",
            "detail": format!("{} canary-path hits in the host access log", hits.len()),
        }));
    }

    let result = if findings
        .iter()
        .any(|f| f.get("kind").and_then(Value::as_str) == Some("canary-hit"))
    {
        "alert"
    } else if findings.is_empty() {
        "pass"
    } else {
        "drift"
    };
    log.append(json!({
        "action": "live_check",
        "site_head": crate::pipeline::git_state(&cfg.site_root).0,
        "inputs": {"base_url": cfg.base_url},
        "outputs": {"pages": pages, "canary_log": canary, "findings": findings},
        "gates": [],
        "result": result,
    }))
}

/// Read the host access log's tail over SSH and grep the canary
/// paths from the local signed manifest. Degrades to
/// "unavailable" with the reason — a read-back that cannot happen
/// is reported, never faked.
fn canary_log_readback(cfg: &Config) -> Value {
    let manifest = match honeypot::load_manifest(&cfg.site_root) {
        Ok(Some((m, _))) => m,
        Ok(None) => return json!({"state": "unavailable", "reason": "no local honeypot manifest"}),
        Err(e) => return json!({"state": "unavailable", "reason": e}),
    };
    let mut grep_args = String::from("grep -F");
    for canary in &manifest.canaries {
        grep_args.push_str(&format!(" -e '{}'", canary.path.replace('\'', "")));
    }
    let remote = format!("tail -n 20000 {HOST_ACCESS_LOG} | {grep_args} | tail -n 50");
    let out = run_bounded(
        "ssh",
        &[
            "-i",
            &cfg.ssh_key.to_string_lossy(),
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "StrictHostKeyChecking=accept-new",
            &format!("ubuntu@{PROD_HOST}"),
            &remote,
        ],
        None,
        STEP_DEADLINE,
    );
    match out {
        Ok(o) if o.success || !o.stdout.trim().is_empty() => {
            let hits: Vec<Value> = o
                .stdout
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| json!({"line": tail(l, 300)}))
                .collect();
            json!({"state": "read", "hits": hits})
        }
        Ok(o) => json!({
            "state": "unavailable",
            "reason": format!("ssh/log read failed: {}", tail(&o.stderr, 200)),
        }),
        Err(e) => json!({"state": "unavailable", "reason": e}),
    }
}

/// broadside_status: receipts and tree state, read-only. Status
/// reports what the log proves; anything absent is null, never
/// inferred.
pub fn status(cfg: &Config) -> Result<Value, String> {
    let log = cfg.receipts();
    let all = log.read_all();
    let (head, dirty) = crate::pipeline::git_state(&cfg.site_root);
    let dist_hash = manifest_of(&cfg.dist()).ok().map(|m| m.tree_hash);
    let latest = |action: &str| -> Value {
        match &all {
            Ok(receipts) => receipts
                .iter()
                .rev()
                .find(|r| r.get("action").and_then(Value::as_str) == Some(action))
                .map(|r| {
                    json!({
                        "seq": r.get("seq"), "ts": r.get("ts"),
                        "result": r.get("result"),
                        "dist_hash": r.get("outputs").and_then(|o| o.get("dist_hash")),
                    })
                })
                .unwrap_or(Value::Null),
            Err(_) => Value::Null,
        }
    };
    let key_record = match jwks::load_key_record(&cfg.site_root)? {
        Some((record, record_json)) => json!({
            "kid": record.kid, "fixture": record.fixture,
            "signature_valid": jwks::record_signature_valid(&record_json, &record),
        }),
        None => Value::Null,
    };
    let manifest = match honeypot::load_manifest(&cfg.site_root)? {
        Some((m, _)) => json!({
            "revision": m.revision, "signer_kid": m.signer_kid,
            "canaries": m.canaries.len(), "fixture": m.fixture,
            "signer_pinned": cfg.canary_signer_pubkey.is_some(),
        }),
        None => Value::Null,
    };
    Ok(json!({
        "site_root": cfg.site_root.display().to_string(),
        "site_head": head,
        "site_dirty_files": dirty,
        "dist_hash_now": dist_hash,
        "receipts": {
            "count": all.as_ref().map(|r| r.len()).unwrap_or(0),
            "chain_ok": all.is_ok(),
            "path": log.path().display().to_string(),
        },
        "latest": {
            "build": latest("build"),
            "verify": latest("verify"),
            "deploy": latest("deploy"),
            "live_check": latest("live_check"),
            "quarantine": latest("quarantine"),
        },
        "key_record": key_record,
        "honeypot_manifest": manifest,
        "deploy_target": cfg.deploy_target,
        "target_is_production": cfg.target_is_production(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::ReceiptLog;

    fn fixture_cfg() -> (std::path::PathBuf, Config) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("broadside-deploy-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let site = dir.join("site");
        std::fs::create_dir_all(site.join("dist")).expect("mkdir");
        std::fs::write(site.join("dist/index.html"), "<html>fixture</html>").expect("write");
        let cfg = Config {
            site_root: site,
            state_dir: dir.join("state"),
            base_url: "https://example.invalid".to_string(),
            deploy_target: dir.join("staging").display().to_string(),
            ssh_key: dir.join("no-key"),
            canary_signer_pubkey: None,
        };
        (dir, cfg)
    }

    #[test]
    fn deploy_refuses_without_confirmation_and_without_verify() {
        let (dir, cfg) = fixture_cfg();
        // No confirmation -> refused, and the refusal is receipted.
        let receipt = deploy(&cfg, "abc", false, false).expect("refusal receipt");
        assert_eq!(receipt["result"], json!("refused"));
        // Confirmation but no verify receipt -> refused.
        let receipt = deploy(&cfg, "abc", true, false).expect("refusal receipt 2");
        assert_eq!(receipt["result"], json!("refused"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deploy_to_staging_after_passing_verify() {
        let (dir, cfg) = fixture_cfg();
        let manifest = manifest_of(&cfg.dist()).expect("manifest");
        let log: ReceiptLog = cfg.receipts();
        log.append(json!({
            "action": "verify", "site_head": null, "inputs": {},
            "outputs": {"dist_hash": manifest.tree_hash},
            "gates": [], "result": "pass",
        }))
        .expect("verify receipt");
        let receipt = deploy(&cfg, &manifest.tree_hash, true, false).expect("deploy");
        assert_eq!(receipt["result"], json!("pass"));
        // The staging tree holds exactly the deployed bytes.
        let staged = manifest_of(std::path::Path::new(&cfg.deploy_target)).expect("staged");
        assert_eq!(staged.tree_hash, manifest.tree_hash);
        // Adversarial: mutate the dist after verify -> refused.
        std::fs::write(cfg.dist().join("index.html"), "<html>tampered</html>").expect("tamper");
        let receipt = deploy(&cfg, &manifest.tree_hash, true, false).expect("refusal 3");
        assert_eq!(receipt["result"], json!("refused"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deploy_refuses_when_verify_receipt_covers_a_different_hash() {
        // Adversarial: a passing verify for one dist must not
        // authorize deploying another, however the call is framed.
        let (dir, cfg) = fixture_cfg();
        let log: ReceiptLog = cfg.receipts();
        log.append(json!({
            "action": "verify", "site_head": null, "inputs": {},
            "outputs": {"dist_hash": "some-other-hash"},
            "gates": [], "result": "pass",
        }))
        .expect("verify receipt");
        let manifest = manifest_of(&cfg.dist()).expect("manifest");
        let receipt = deploy(&cfg, &manifest.tree_hash, true, false).expect("refusal receipt");
        assert_eq!(receipt["result"], json!("refused"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

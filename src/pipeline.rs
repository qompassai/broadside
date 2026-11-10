//! broadside_build and broadside_verify: the deterministic
//! pipeline over the site tree.
//!
//! build: cargo-leptos release build → prerender → JWKS placement
//! (from the signed key record) → canary injection (signature
//! checked BEFORE anything is planted, H6) → dist manifest.
//! A missing key record or manifest does not stop the compile, but
//! it fails the build's gates and therefore the build: the dist is
//! marked ineligible, and deploy will refuse it. Fail closed, with
//! the reason in the receipt — never a silent skip.
//!
//! verify: the gate battery over the current dist — site tests,
//! generated-data freshness, citation verification (H3 hook),
//! internal links/figures, dist manifest identity, JWKS vs the
//! signed record, canary integrity. Every gate lands in the
//! receipt with its evidence; verify passes only if all do.

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

use crate::citations::{Verifier, extract_from_dist};
use crate::config::Config;
use crate::dist::manifest_of;
use crate::honeypot;
use crate::jwks;
use crate::proc::{run_bounded, tail};
use crate::receipts::{ReceiptLog, gate};
use crate::sources::SourceRegistry;

const BUILD_DEADLINE: Duration = Duration::from_secs(2400);
const PRERENDER_DEADLINE: Duration = Duration::from_secs(900);
const TEST_DEADLINE: Duration = Duration::from_secs(1800);
const STEP_DEADLINE: Duration = Duration::from_secs(120);

/// git HEAD + dirty-file count for the site tree (None when the
/// tree is not a git checkout — recorded, not guessed).
pub fn git_state(site_root: &std::path::Path) -> (Option<String>, Option<usize>) {
    let head = run_bounded(
        "git",
        &["-C", &site_root.to_string_lossy(), "rev-parse", "HEAD"],
        None,
        STEP_DEADLINE,
    )
    .ok()
    .filter(|o| o.success)
    .map(|o| o.stdout.trim().to_string());
    let dirty = run_bounded(
        "git",
        &["-C", &site_root.to_string_lossy(), "status", "--porcelain"],
        None,
        STEP_DEADLINE,
    )
    .ok()
    .filter(|o| o.success)
    .map(|o| o.stdout.lines().filter(|l| !l.trim().is_empty()).count());
    (head, dirty)
}

fn result_of(gates: &[Value]) -> &'static str {
    if gates
        .iter()
        .any(|g| g.get("result").and_then(Value::as_str) == Some("fail"))
    {
        "fail"
    } else {
        "pass"
    }
}

/// broadside_build. Returns the receipt body (also appended to
/// the log by the caller-visible path inside).
pub fn build(cfg: &Config) -> Result<Value, String> {
    let log = cfg.receipts();
    let mut gates: Vec<Value> = Vec::new();
    let (head, dirty) = git_state(&cfg.site_root);

    // 1. Compile.
    let build_out = run_bounded(
        "cargo",
        &["leptos", "build", "--release"],
        Some(&cfg.site_root),
        BUILD_DEADLINE,
    )?;
    if build_out.success {
        gates.push(gate("compile", "pass", "cargo leptos build --release"));
    } else {
        gates.push(gate(
            "compile",
            "fail",
            &format!(
                "cargo leptos build --release failed: {}",
                tail(&build_out.stderr, 400)
            ),
        ));
        return finish(&log, "build", head, &gates, json!({}));
    }

    // 2. Prerender into dist/.
    let pre = run_bounded(
        "bash",
        &["scripts/prerender.sh"],
        Some(&cfg.site_root),
        PRERENDER_DEADLINE,
    )?;
    if pre.success {
        gates.push(gate("prerender", "pass", &tail(pre.stdout.trim(), 200)));
    } else {
        gates.push(gate(
            "prerender",
            "fail",
            &format!("prerender.sh failed: {}", tail(&pre.stderr, 400)),
        ));
        return finish(&log, "build", head, &gates, json!({}));
    }
    let dist = cfg.dist();

    // 3. JWKS placement from the signed key record.
    let mut outputs = json!({});
    match jwks::load_key_record(&cfg.site_root)? {
        None => gates.push(gate(
            "jwks",
            "fail",
            "no signed key record in the site tree (keys/agent-card-key-record.json); JWKS cannot be placed",
        )),
        Some((record, record_json)) => {
            if !jwks::record_signature_valid(&record_json, &record) {
                gates.push(gate(
                    "jwks",
                    "fail",
                    "key record signature does not verify; refusing to publish its key",
                ));
                return finish(&log, "build", head, &gates, outputs);
            }
            jwks::place_jwks(&dist, &record)?;
            outputs["jwks_kid"] = json!(record.kid);
            outputs["jwks_fixture"] = json!(record.fixture);
            gates.push(gate(
                "jwks",
                "pass",
                &format!(
                    "placed /.well-known/jwks.json for kid {}{}",
                    record.kid,
                    if record.fixture { " (FIXTURE record)" } else { "" }
                ),
            ));
        }
    }

    // 4. Canary injection — signature verified BEFORE injection.
    match honeypot::load_manifest(&cfg.site_root)? {
        None => gates.push(gate(
            "canary_injection",
            "fail",
            "no honeypot manifest in the site tree (honeypot/manifest.json); nothing injected",
        )),
        Some((manifest, manifest_json)) => {
            match honeypot::manifest_signature_valid(
                &manifest_json,
                &manifest,
                cfg.canary_signer_pubkey.as_deref(),
            ) {
                Err(e) => {
                    gates.push(gate("canary_injection", "fail", &e));
                    return finish(&log, "build", head, &gates, outputs);
                }
                Ok(()) => {
                    let injected = honeypot::inject(&dist, &manifest)?;
                    outputs["canary"] = injected;
                    gates.push(gate(
                        "canary_injection",
                        "pass",
                        &format!(
                            "{} canaries injected at revision {}{}",
                            manifest.canaries.len(),
                            manifest.revision,
                            if manifest.fixture {
                                " (FIXTURE manifest)"
                            } else {
                                ""
                            }
                        ),
                    ));
                }
            }
        }
    }

    // 5. Manifest of exactly what would ship.
    let manifest = manifest_of(&dist)?;
    outputs["dist"] = manifest.to_json();
    outputs["dist_hash"] = json!(manifest.tree_hash);
    let _ = dirty;
    finish(&log, "build", head, &gates, outputs)
}

fn finish(
    log: &ReceiptLog,
    action: &str,
    site_head: Option<String>,
    gates: &[Value],
    outputs: Value,
) -> Result<Value, String> {
    let body = json!({
        "action": action,
        "site_head": site_head,
        "inputs": {},
        "outputs": outputs,
        "gates": gates,
        "result": result_of(gates),
    });
    log.append(body)
}

/// broadside_verify over the current dist. `expected_hash`, when
/// given, must equal the dist's recomputed tree hash.
pub fn verify(cfg: &Config, expected_hash: Option<&str>) -> Result<Value, String> {
    let log = cfg.receipts();
    let mut gates: Vec<Value> = Vec::new();
    let (head, _) = git_state(&cfg.site_root);
    let dist = cfg.dist();
    let mut outputs = json!({});

    // Gate: site tests.
    let test_out = run_bounded("cargo", &["test"], Some(&cfg.site_root), TEST_DEADLINE)?;
    let (passed, failed) = parse_test_counts(&test_out.stdout);
    if test_out.success && failed == 0 && passed > 0 {
        gates.push(gate(
            "site_tests",
            "pass",
            &format!("cargo test: {passed} passed, 0 failed"),
        ));
    } else {
        gates.push(gate(
            "site_tests",
            "fail",
            &format!(
                "cargo test: {passed} passed, {failed} failed; {}",
                tail(&test_out.stderr, 300)
            ),
        ));
    }

    // Gate: generated-data freshness (manuscript rollup snapshot).
    gates.push(freshness_gate(cfg));

    // Gate: dist manifest identity.
    let manifest = manifest_of(&dist);
    match &manifest {
        Ok(m) => {
            outputs["dist_hash"] = json!(m.tree_hash);
            outputs["dist"] = m.to_json();
            let mut problems: Vec<String> = Vec::new();
            if let Some(expected) = expected_hash
                && expected != m.tree_hash
            {
                problems.push(format!(
                    "expected dist hash {expected}, recomputed {}",
                    m.tree_hash
                ));
            }
            if let Some(build_receipt) = log.latest("build", Some("pass"))?
                && let Some(built) = build_receipt
                    .get("outputs")
                    .and_then(|o| o.get("dist_hash"))
                    .and_then(Value::as_str)
                && built != m.tree_hash
            {
                problems.push(format!(
                    "dist changed since the last passing build (built {built})"
                ));
            }
            if problems.is_empty() {
                gates.push(gate(
                    "dist_manifest",
                    "pass",
                    &format!("tree hash {}", m.tree_hash),
                ));
            } else {
                gates.push(gate("dist_manifest", "fail", &problems.join("; ")));
            }
        }
        Err(e) => gates.push(gate("dist_manifest", "fail", e)),
    }

    // Gate: citations (with the H3 quarantine hook).
    match extract_from_dist(&dist) {
        Ok(citations) => {
            let mut registry = SourceRegistry::load(cfg.sources_path())?;
            let report = Verifier::default().verify_all(&citations, &mut registry);
            registry.save()?;
            for (source, reason) in &report.newly_hostile {
                log.append(json!({
                    "action": "quarantine",
                    "site_head": head,
                    "inputs": {"source": source},
                    "outputs": {"reason": reason},
                    "gates": [],
                    "result": "alert",
                }))?;
            }
            outputs["citations"] = report.to_json();
            if report.failures.is_empty() {
                gates.push(gate(
                    "citations",
                    "pass",
                    &format!(
                        "{} citations verified ({} classes)",
                        report.verified,
                        report.by_class.len()
                    ),
                ));
            } else {
                let sample: Vec<String> = report
                    .failures
                    .iter()
                    .take(5)
                    .map(|f| format!("{}: {}", f.key, f.detail))
                    .collect();
                gates.push(gate(
                    "citations",
                    "fail",
                    &format!(
                        "{} of {} citations failed: {}",
                        report.failures.len(),
                        report.total,
                        sample.join(" | ")
                    ),
                ));
            }
        }
        Err(e) => gates.push(gate("citations", "fail", &e)),
    }

    // Gate: internal links and figures.
    match links_gate(&dist) {
        Ok(detail) => gates.push(gate("links_figures", "pass", &detail)),
        Err(detail) => gates.push(gate("links_figures", "fail", &detail)),
    }

    // Gate: JWKS vs the signed key record.
    match jwks::load_key_record(&cfg.site_root)? {
        None => gates.push(gate(
            "jwks",
            "fail",
            "no signed key record in the site tree; JWKS unverifiable (fail closed)",
        )),
        Some((record, record_json)) => {
            if !jwks::record_signature_valid(&record_json, &record) {
                gates.push(gate("jwks", "fail", "key record signature invalid"));
            } else {
                match jwks::check_jwks(&dist, &record) {
                    Ok(()) => gates.push(gate(
                        "jwks",
                        "pass",
                        &format!("dist JWKS matches signed record kid {}", record.kid),
                    )),
                    Err(e) => gates.push(gate("jwks", "fail", &e)),
                }
            }
        }
    }

    // Gate: canary integrity (signature re-verified here too —
    // verify never trusts that build checked).
    match honeypot::load_manifest(&cfg.site_root)? {
        None => gates.push(gate(
            "canary_integrity",
            "fail",
            "no honeypot manifest in the site tree; canaries unverifiable (fail closed)",
        )),
        Some((manifest, manifest_json)) => {
            match honeypot::manifest_signature_valid(
                &manifest_json,
                &manifest,
                cfg.canary_signer_pubkey.as_deref(),
            ) {
                Err(e) => gates.push(gate("canary_integrity", "fail", &e)),
                Ok(()) => match honeypot::check_integrity(&dist, &manifest) {
                    Ok(detail) => gates.push(gate("canary_integrity", "pass", &detail)),
                    Err(e) => gates.push(gate("canary_integrity", "fail", &e)),
                },
            }
        }
    }

    let body = json!({
        "action": "verify",
        "site_head": head,
        "inputs": {"expected_dist_hash": expected_hash},
        "outputs": outputs,
        "gates": gates,
        "result": result_of(&gates),
    });
    log.append(body)
}

/// Parse `test result: ... N passed; M failed` summary lines
/// (sums across test binaries; the digits immediately before
/// " passed"/" failed" are the counts).
fn parse_test_counts(stdout: &str) -> (usize, usize) {
    fn sum_before(text: &str, suffix: &str) -> usize {
        let mut total = 0usize;
        let mut rest = text;
        while let Some(pos) = rest.find(suffix) {
            let digits: String = rest[..pos]
                .chars()
                .rev()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            total += digits.parse::<usize>().unwrap_or(0);
            rest = &rest[pos + suffix.len()..];
        }
        total
    }
    let mut passed = 0usize;
    let mut failed = 0usize;
    for line in stdout.lines() {
        if line.contains("test result:") {
            passed += sum_before(line, " passed");
            failed += sum_before(line, " failed");
        }
    }
    (passed, failed)
}

/// The generated-data freshness gate: regenerate
/// src/manuscript_data.rs from the Odyssey rollup into a scratch
/// file and compare bytes. Skip (recorded) only when the tree has
/// no generator; a generator whose inputs are gone fails.
fn freshness_gate(cfg: &Config) -> Value {
    let script = cfg.site_root.join("scripts/generate-manuscript-data.py");
    let target = cfg.site_root.join("src/manuscript_data.rs");
    if !script.exists() {
        return gate(
            "generated_freshness",
            "skip",
            "tree has no manuscript-data generator",
        );
    }
    if !target.exists() {
        return gate(
            "generated_freshness",
            "fail",
            "generator exists but src/manuscript_data.rs is missing",
        );
    }
    let rollup: PathBuf = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".GH/Qompass/Odyssey/manuscripts/rollup.json");
    if !rollup.exists() {
        return gate(
            "generated_freshness",
            "fail",
            "Odyssey manuscripts rollup not found on this machine",
        );
    }
    let scratch = cfg.state_dir.join("freshness-manuscript_data.rs");
    if let Some(parent) = scratch.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let out = match run_bounded(
        "python3",
        &[
            &script.to_string_lossy(),
            &rollup.to_string_lossy(),
            &scratch.to_string_lossy(),
        ],
        Some(&cfg.site_root),
        STEP_DEADLINE,
    ) {
        Ok(o) => o,
        Err(e) => return gate("generated_freshness", "fail", &e),
    };
    if !out.success {
        return gate(
            "generated_freshness",
            "fail",
            &format!("generator failed: {}", tail(&out.stderr, 300)),
        );
    }
    let fresh = std::fs::read(&scratch).unwrap_or_default();
    let committed = std::fs::read(&target).unwrap_or_default();
    if fresh == committed {
        gate(
            "generated_freshness",
            "pass",
            "src/manuscript_data.rs is byte-identical to a fresh regeneration",
        )
    } else {
        gate(
            "generated_freshness",
            "fail",
            "src/manuscript_data.rs differs from a fresh regeneration (stale generated data)",
        )
    }
}

/// Internal link + figure gate: every root-relative href/src in
/// dist HTML must resolve to a file inside dist.
fn links_gate(dist: &std::path::Path) -> Result<String, String> {
    let mut checked = 0usize;
    let mut missing: Vec<String> = Vec::new();
    let mut stack = vec![dist.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
        for entry in entries {
            let path = entry.map_err(|e| format!("dir entry: {e}"))?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().map(|e| e == "html").unwrap_or(false) {
                let html = std::fs::read_to_string(&path)
                    .map_err(|e| format!("read {}: {e}", path.display()))?;
                for reference in extract_internal_refs(&html) {
                    checked += 1;
                    let rel = crate::dist::route_to_relpath(&reference);
                    if !dist.join(&rel).is_file() && !dist.join(&reference[1..]).is_file() {
                        missing.push(reference);
                    }
                }
            }
        }
    }
    if missing.is_empty() {
        Ok(format!("{checked} internal references resolve"))
    } else {
        missing.sort();
        missing.dedup();
        Err(format!(
            "{} of {checked} internal references broken: {}",
            missing.len(),
            missing
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ))
    }
}

/// Root-relative href/src targets from an HTML document.
fn extract_internal_refs(html: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for needle in ["href=\"", "src=\""] {
        let mut rest = html;
        while let Some(pos) = rest.find(needle) {
            let tail = &rest[pos + needle.len()..];
            let end = tail.find('"').unwrap_or(0);
            let target = &tail[..end];
            if target.starts_with('/') && !target.starts_with("//") && !target.contains('{') {
                let clean = target.split(['#', '?']).next().unwrap_or(target);
                if !clean.is_empty() && clean != "/" {
                    refs.push(clean.to_string());
                } else if clean == "/" {
                    refs.push("/".to_string());
                }
            }
            rest = &tail[end..];
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_parsing() {
        let out = "test result: ok. 68 passed; 0 failed; 0 ignored\n\
                   test result: ok. 3 passed; 0 failed; 0 ignored\n";
        assert_eq!(parse_test_counts(out), (71, 0));
        let bad = "test result: FAILED. 2 passed; 1 failed; 0 ignored\n";
        assert_eq!(parse_test_counts(bad), (2, 1));
    }

    #[test]
    fn internal_ref_extraction() {
        let html = r##"<a href="/research">r</a><img src="/img/a.png" />
            <a href="https://example.com/x">ext</a><a href="#frag">f</a>
            <a href="/standards/rust-reference">s</a>"##;
        let refs = extract_internal_refs(html);
        assert_eq!(
            refs,
            vec!["/research", "/standards/rust-reference", "/img/a.png"]
        );
    }

    #[test]
    fn links_gate_catches_missing_targets() {
        // Adversarial: a page linking nowhere must fail the gate.
        let dir = std::env::temp_dir().join(format!("broadside-links-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join("index.html"), "<a href=\"/nowhere\">x</a>").expect("write");
        assert!(links_gate(&dir).is_err());
        std::fs::create_dir_all(dir.join("nowhere")).expect("mkdir2");
        std::fs::write(dir.join("nowhere/index.html"), "ok").expect("write2");
        assert!(links_gate(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! The narrow surface the TUI programs against (DESIGN §D2).
//!
//! Two real implementations: [`LibFacade`] over the member's own
//! library crate (the preferred route — broadside ships a lib),
//! and [`McpStdioFacade`], an MCP stdio client spawning the
//! member's own `broadside-mcp` server (the fallback route, and
//! the transport shape the §D4 trigger layer reuses). Tests use
//! [`FakeFacade`], which is scripted and records every call, so a
//! test can prove a call did *not* happen.
//!
//! Verification honesty: receipt verification status comes from
//! the member's machinery — [`broadside_mcp::receipts::ReceiptLog::
//! read_all`] chain verification and
//! [`broadside_mcp::receipts::receipt_hash`] recomputation. This
//! crate never labels a receipt "valid" on its own authority; a
//! chain it cannot verify is [`VerificationStatus::Unverifiable`]
//! or [`VerificationStatus::Failed`], never a silent ok.

use std::collections::VecDeque;
use std::fmt;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

use broadside_mcp::receipts::{SCHEMA_NAME, SCHEMA_VERSION, receipt_hash};

use crate::MEMBER_TOOLS;

/// Seconds a single MCP stdio call may take before the server is
/// declared dead for this call.
pub const MCP_CALL_TIMEOUT_SECS: u64 = 120;
/// Lines of MCP server output buffered for one call.
pub const MCP_RESPONSE_LINES_MAX: usize = 64;

/// A typed facade failure. `ServerDied` is distinct because a
/// pipeline must halt on it, not retry blindly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FacadeError {
    /// The backend cannot be reached at all (spawn failed, no lib).
    Unavailable(String),
    /// The call was made and the member reported a failure.
    CallFailed(String),
    /// The server process died (EOF / timeout) mid-call.
    ServerDied(String),
}

impl fmt::Display for FacadeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FacadeError::Unavailable(msg) => write!(f, "unavailable: {msg}"),
            FacadeError::CallFailed(msg) => write!(f, "call failed: {msg}"),
            FacadeError::ServerDied(msg) => write!(f, "server died: {msg}"),
        }
    }
}

impl std::error::Error for FacadeError {}

/// Verification status of a receipt or the whole chain, as decided
/// by the member's own verification machinery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationStatus {
    /// The member's chain/hash verification passed.
    Verified,
    /// The member's verification ran and failed; carries its reason.
    Failed(String),
    /// Verification could not be performed; carries why. Rendered
    /// as unverifiable — never upgraded to ok.
    Unverifiable(String),
}

impl VerificationStatus {
    /// The short label panels render.
    pub fn label(&self) -> String {
        match self {
            VerificationStatus::Verified => "verified (member chain check)".to_string(),
            VerificationStatus::Failed(reason) => format!("FAILED verification: {reason}"),
            VerificationStatus::Unverifiable(reason) => {
                format!("unverifiable: {reason}")
            }
        }
    }
}

/// Verify one receipt against its expected position in the chain
/// using the member's own hash machinery: schema, version, `seq`,
/// `prev_hash` linkage, and `hash` recomputation via
/// [`receipt_hash`]. This is the same check `ReceiptLog::read_all`
/// performs per receipt; it exists separately so the viewer can
/// report on one receipt (including a tampered copy) honestly.
pub fn verify_receipt_detail(
    receipt: &Value,
    expected_seq: u64,
    expected_prev_hash: &str,
) -> VerificationStatus {
    if receipt.get("schema").and_then(Value::as_str) != Some(SCHEMA_NAME) {
        return VerificationStatus::Failed("schema is not broadside.receipt".to_string());
    }
    if receipt.get("version").and_then(Value::as_u64) != Some(SCHEMA_VERSION) {
        return VerificationStatus::Failed("version is not 1".to_string());
    }
    if receipt.get("seq").and_then(Value::as_u64) != Some(expected_seq) {
        return VerificationStatus::Failed(format!(
            "seq is {}, expected {expected_seq}",
            receipt
                .get("seq")
                .map(ToString::to_string)
                .unwrap_or_default()
        ));
    }
    if receipt.get("prev_hash").and_then(Value::as_str) != Some(expected_prev_hash) {
        return VerificationStatus::Failed(
            "prev_hash does not match the previous receipt's hash".to_string(),
        );
    }
    let claimed = match receipt.get("hash").and_then(Value::as_str) {
        Some(hash) => hash,
        None => return VerificationStatus::Failed("hash missing".to_string()),
    };
    match receipt_hash(receipt) {
        Ok(computed) if computed == claimed => VerificationStatus::Verified,
        Ok(_) => {
            VerificationStatus::Failed("hash does not recompute (receipt was altered)".to_string())
        }
        Err(e) => VerificationStatus::Unverifiable(e),
    }
}

/// The operations the TUI needs from broadside.
pub trait BroadsideFacade {
    /// `broadside_status`: pipeline state read from receipts.
    fn status(&mut self) -> Result<Value, FacadeError>;
    /// The member's MCP tool names.
    fn tools(&mut self) -> Result<Vec<String>, FacadeError>;
    /// Call one member tool by name with JSON arguments.
    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError>;
    /// All receipts, chain-verified by the member's reader. An
    /// error here means the chain is broken — callers must surface
    /// it, not an empty-but-ok list.
    fn receipts(&mut self) -> Result<Vec<Value>, FacadeError>;
    /// The member machinery's verdict on the whole receipt chain.
    fn chain_verification(&mut self) -> VerificationStatus;
    /// Honeypot state the library exposes (signed canary manifest
    /// summary from `broadside_status`), or an error.
    fn honeypot(&mut self) -> Result<Value, FacadeError> {
        let status = self.status()?;
        Ok(json!({
            "manifest": status.get("honeypot_manifest").cloned().unwrap_or(Value::Null),
            "key_record": status.get("key_record").cloned().unwrap_or(Value::Null),
        }))
    }
}

// ---------------------------------------------------------------------
// FakeFacade: scripted, call-recording, for tests.
// ---------------------------------------------------------------------

/// An in-memory [`BroadsideFacade`] for tests: scripted results,
/// recorded calls, and a scriptable mid-pipeline death.
#[derive(Debug, Default)]
pub struct FakeFacade {
    /// Result returned by [`FakeFacade::status`].
    pub status_result: Value,
    /// Receipts returned by [`FakeFacade::receipts`].
    pub receipts_result: Vec<Value>,
    /// Chain verdict returned by [`FakeFacade::chain_verification`].
    pub chain_status: Option<VerificationStatus>,
    /// Scripted results for successive `call`s; when the queue is
    /// empty, `call` returns a passing echo receipt.
    pub call_results: VecDeque<Result<Value, FacadeError>>,
    /// Every `(tool, args)` passed to `call`, in order. The plan
    /// mode proofs assert this stays empty before approval.
    pub calls: Vec<(String, Value)>,
    /// When set, the Nth call (1-based) fails as a server death.
    pub die_on_call: Option<usize>,
}

impl FakeFacade {
    /// A fake whose status reports version 1.0.0 and no receipts.
    pub fn new() -> FakeFacade {
        FakeFacade {
            status_result: json!({
                "receipts": {"count": 0, "chain_ok": true},
                "latest": {"build": null, "verify": null, "deploy": null},
                "honeypot_manifest": null,
                "key_record": null,
                "deploy_target": "/tmp/fake-staging",
                "target_is_production": false,
            }),
            chain_status: Some(VerificationStatus::Verified),
            ..FakeFacade::default()
        }
    }

    /// Queue one scripted result for the next `call`.
    pub fn queue_call_result(&mut self, result: Result<Value, FacadeError>) {
        self.call_results.push_back(result);
    }
}

impl BroadsideFacade for FakeFacade {
    fn status(&mut self) -> Result<Value, FacadeError> {
        Ok(self.status_result.clone())
    }

    fn tools(&mut self) -> Result<Vec<String>, FacadeError> {
        Ok(MEMBER_TOOLS.iter().map(ToString::to_string).collect())
    }

    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError> {
        self.calls.push((tool.to_string(), args.clone()));
        if self.die_on_call == Some(self.calls.len()) {
            return Err(FacadeError::ServerDied(
                "fake server died mid-pipeline (scripted)".to_string(),
            ));
        }
        if let Some(scripted) = self.call_results.pop_front() {
            return scripted;
        }
        Ok(json!({"action": tool, "result": "pass", "outputs": {}, "gates": []}))
    }

    fn receipts(&mut self) -> Result<Vec<Value>, FacadeError> {
        Ok(self.receipts_result.clone())
    }

    fn chain_verification(&mut self) -> VerificationStatus {
        self.chain_status
            .clone()
            .unwrap_or(VerificationStatus::Verified)
    }
}

// ---------------------------------------------------------------------
// LibFacade: the preferred real route, over broadside's own lib.
// ---------------------------------------------------------------------

/// The real facade over `broadside_mcp`'s library: status,
/// pipeline, deploy, and receipts are the member's own functions.
pub struct LibFacade {
    cfg: broadside_mcp::config::Config,
}

impl LibFacade {
    /// Build from the member's own configuration.
    pub fn new(cfg: broadside_mcp::config::Config) -> LibFacade {
        LibFacade { cfg }
    }
}

impl BroadsideFacade for LibFacade {
    fn status(&mut self) -> Result<Value, FacadeError> {
        broadside_mcp::deploy_live::status(&self.cfg).map_err(FacadeError::CallFailed)
    }

    fn tools(&mut self) -> Result<Vec<String>, FacadeError> {
        Ok(MEMBER_TOOLS.iter().map(ToString::to_string).collect())
    }

    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError> {
        let result = match tool {
            "broadside_status" => broadside_mcp::deploy_live::status(&self.cfg),
            "broadside_build" => broadside_mcp::pipeline::build(&self.cfg),
            "broadside_verify" => {
                let expected = args.get("dist_hash").and_then(Value::as_str);
                broadside_mcp::pipeline::verify(&self.cfg, expected)
            }
            "broadside_deploy" => {
                let dist_hash = args
                    .get("dist_hash")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if dist_hash.is_empty() {
                    return Err(FacadeError::CallFailed("dist_hash is required".to_string()));
                }
                let confirm = args
                    .get("confirm")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let dry_run = args
                    .get("dry_run")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                broadside_mcp::deploy_live::deploy(&self.cfg, dist_hash, confirm, dry_run)
            }
            "broadside_live_check" => broadside_mcp::deploy_live::live_check(&self.cfg),
            other => {
                return Err(FacadeError::CallFailed(format!("unknown tool {other}")));
            }
        };
        result.map_err(FacadeError::CallFailed)
    }

    fn receipts(&mut self) -> Result<Vec<Value>, FacadeError> {
        // ReceiptLog::read_all chain-verifies every receipt; its
        // error is the member's own "chain broken" verdict.
        self.cfg
            .receipts()
            .read_all()
            .map_err(FacadeError::CallFailed)
    }

    fn chain_verification(&mut self) -> VerificationStatus {
        match self.cfg.receipts().read_all() {
            Ok(_) => VerificationStatus::Verified,
            Err(e) => VerificationStatus::Failed(e),
        }
    }
}

// ---------------------------------------------------------------------
// McpStdioFacade: the fallback route, an MCP stdio client.
// ---------------------------------------------------------------------

/// An MCP stdio client facade: spawns the member's own server
/// binary and speaks the modern era (2026-07-28) — `server/discover`
/// first, then `tools/list` / `tools/call` / `resources/read`.
/// Synchronous, one request at a time, bounded by
/// [`MCP_CALL_TIMEOUT_SECS`]; EOF or timeout is `ServerDied`.
pub struct McpStdioFacade {
    program: String,
    args: Vec<String>,
    timeout: Duration,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    lines: Option<mpsc::Receiver<String>>,
    next_id: u64,
    discovered: bool,
}

impl McpStdioFacade {
    /// A facade that will spawn `program` with `args` on first use.
    pub fn new(program: String, args: Vec<String>) -> McpStdioFacade {
        McpStdioFacade {
            program,
            args,
            timeout: Duration::from_secs(MCP_CALL_TIMEOUT_SECS),
            child: None,
            stdin: None,
            lines: None,
            next_id: 0,
            discovered: false,
        }
    }

    /// Override the per-call timeout (tests use a short one).
    pub fn with_timeout(mut self, timeout: Duration) -> McpStdioFacade {
        self.timeout = timeout;
        self
    }

    fn ensure_started(&mut self) -> Result<(), FacadeError> {
        if self.child.is_some() {
            return Ok(());
        }
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command
            .spawn()
            .map_err(|e| FacadeError::Unavailable(format!("cannot spawn {}: {e}", self.program)))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| FacadeError::Unavailable("server stdin unavailable".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| FacadeError::Unavailable("server stdout unavailable".to_string()))?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        self.child = Some(child);
        self.stdin = Some(stdin);
        self.lines = Some(rx);
        Ok(())
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, FacadeError> {
        self.ensure_started()?;
        self.next_id += 1;
        let id = self.next_id;
        let mut params = params;
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
        });
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| FacadeError::ServerDied("server stdin closed".to_string()))?;
        let mut line = frame.to_string();
        line.push('\n');
        stdin
            .write_all(line.as_bytes())
            .and_then(|()| stdin.flush())
            .map_err(|e| FacadeError::ServerDied(format!("write to server failed: {e}")))?;
        let lines = self
            .lines
            .as_ref()
            .ok_or_else(|| FacadeError::ServerDied("server stdout closed".to_string()))?;
        for _ in 0..MCP_RESPONSE_LINES_MAX {
            let raw = lines.recv_timeout(self.timeout).map_err(|_| {
                FacadeError::ServerDied(format!(
                    "no response to {method} within {}s (server died or hung)",
                    self.timeout.as_secs()
                ))
            })?;
            let message: Value = serde_json::from_str(&raw)
                .map_err(|e| FacadeError::ServerDied(format!("malformed server frame: {e}")))?;
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                return Err(FacadeError::CallFailed(format!("{method}: {error}")));
            }
            return Ok(message.get("result").cloned().unwrap_or(Value::Null));
        }
        Err(FacadeError::ServerDied(
            "response line budget exhausted".to_string(),
        ))
    }

    fn ensure_discovered(&mut self) -> Result<(), FacadeError> {
        if self.discovered {
            return Ok(());
        }
        self.request("server/discover", json!({}))?;
        self.discovered = true;
        Ok(())
    }

    fn call_tool_raw(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError> {
        self.ensure_discovered()?;
        let result = self.request("tools/call", json!({"name": tool, "arguments": args}))?;
        let text = result
            .get("content")
            .and_then(Value::as_array)
            .and_then(|blocks| blocks.first())
            .and_then(|block| block.get("text"))
            .and_then(Value::as_str)
            .ok_or_else(|| FacadeError::CallFailed(format!("{tool}: no text content in result")))?;
        let parsed: Value = serde_json::from_str(text)
            .map_err(|e| FacadeError::CallFailed(format!("{tool}: result is not JSON: {e}")))?;
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if is_error {
            return Err(FacadeError::CallFailed(format!(
                "{tool}: {}",
                parsed
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("member reported an error")
            )));
        }
        Ok(parsed)
    }
}

impl Drop for McpStdioFacade {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl BroadsideFacade for McpStdioFacade {
    fn status(&mut self) -> Result<Value, FacadeError> {
        self.call_tool_raw("broadside_status", &json!({}))
    }

    fn tools(&mut self) -> Result<Vec<String>, FacadeError> {
        self.ensure_discovered()?;
        let result = self.request("tools/list", json!({}))?;
        let names = result
            .get("tools")
            .and_then(Value::as_array)
            .map(|tools| {
                tools
                    .iter()
                    .filter_map(|tool| {
                        tool.get("name")
                            .and_then(Value::as_str)
                            .map(ToString::to_string)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(names)
    }

    fn call(&mut self, tool: &str, args: &Value) -> Result<Value, FacadeError> {
        self.call_tool_raw(tool, args)
    }

    fn receipts(&mut self) -> Result<Vec<Value>, FacadeError> {
        self.ensure_discovered()?;
        let result = self.request("resources/read", json!({"uri": "broadside://receipts"}))?;
        let text = result
            .get("contents")
            .and_then(Value::as_array)
            .and_then(|contents| contents.first())
            .and_then(|content| content.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut receipts = Vec::new();
        let mut prev_hash = String::new();
        for (idx, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let receipt: Value = serde_json::from_str(line).map_err(|e| {
                FacadeError::CallFailed(format!("receipt line {} is not JSON: {e}", idx + 1))
            })?;
            // Verify as we parse: the stdio route re-runs the
            // member's per-receipt chain check on what it received.
            match verify_receipt_detail(&receipt, idx as u64 + 1, &prev_hash) {
                VerificationStatus::Verified => {}
                VerificationStatus::Failed(reason) | VerificationStatus::Unverifiable(reason) => {
                    return Err(FacadeError::CallFailed(format!(
                        "receipt chain broken at line {}: {reason}",
                        idx + 1
                    )));
                }
            }
            prev_hash = receipt
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    fn chain_verification(&mut self) -> VerificationStatus {
        match self.receipts() {
            Ok(_) => VerificationStatus::Verified,
            Err(FacadeError::CallFailed(reason)) => VerificationStatus::Failed(reason),
            Err(other) => VerificationStatus::Unverifiable(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_receipt() -> (std::path::PathBuf, Value) {
        // Build a genuine receipt with the member's own log so the
        // hash is real, then hand back its JSON.
        let dir = std::env::temp_dir().join(format!("broadside-tui-facade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = broadside_mcp::receipts::ReceiptLog::new(dir.join("receipts.jsonl"));
        let receipt = log
            .append(json!({
                "action": "verify", "result": "pass",
                "inputs": {}, "outputs": {"dist_hash": "abc123"}, "gates": [],
            }))
            .expect("append fixture receipt");
        (dir, receipt)
    }

    #[test]
    fn genuine_receipt_verifies_through_member_machinery() {
        let (dir, receipt) = sample_receipt();
        assert_eq!(
            verify_receipt_detail(&receipt, 1, ""),
            VerificationStatus::Verified
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        // Adversarial: any post-hoc edit must fail the recompute,
        // never render as ok.
        let (dir, mut receipt) = sample_receipt();
        receipt["result"] = json!("fail-to-pass-edit");
        receipt["outputs"]["dist_hash"] = json!("evil-hash");
        match verify_receipt_detail(&receipt, 1, "") {
            VerificationStatus::Failed(reason) => {
                assert!(reason.contains("hash does not recompute"), "{reason}");
            }
            other => panic!("tampered receipt must fail, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn receipt_with_wrong_linkage_fails() {
        let (dir, receipt) = sample_receipt();
        assert!(matches!(
            verify_receipt_detail(&receipt, 1, "not-the-prev-hash"),
            VerificationStatus::Failed(_)
        ));
        assert!(matches!(
            verify_receipt_detail(&receipt, 7, ""),
            VerificationStatus::Failed(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fake_records_calls_and_scripts_death() {
        let mut fake = FakeFacade::new();
        let first = fake.call("broadside_build", &json!({}));
        assert!(first.is_ok());
        fake.die_on_call = Some(2);
        let second = fake.call("broadside_verify", &json!({}));
        assert!(matches!(second, Err(FacadeError::ServerDied(_))));
        assert_eq!(fake.calls.len(), 2);
    }

    #[test]
    fn mcp_facade_missing_binary_is_unavailable_not_panic() {
        let mut facade = McpStdioFacade::new("/nonexistent/broadside-mcp".to_string(), Vec::new())
            .with_timeout(Duration::from_millis(200));
        match facade.status() {
            Err(FacadeError::Unavailable(_)) => {}
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    #[test]
    fn mcp_facade_instant_exit_is_server_died() {
        // Adversarial: a "server" that exits at once must surface
        // as ServerDied (EOF), never a hang or a fake success.
        let mut facade = McpStdioFacade::new("/bin/false".to_string(), Vec::new())
            .with_timeout(Duration::from_secs(2));
        match facade.status() {
            Err(FacadeError::ServerDied(_)) | Err(FacadeError::CallFailed(_)) => {}
            other => panic!("expected a death/failure, got {other:?}"),
        }
    }

    #[test]
    fn lib_facade_reads_empty_state_from_temp_dirs() {
        let dir =
            std::env::temp_dir().join(format!("broadside-tui-libfacade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("site")).expect("mkdir site");
        let cfg = broadside_mcp::config::Config {
            site_root: dir.join("site"),
            state_dir: dir.join("state"),
            base_url: "https://example.invalid".to_string(),
            deploy_target: dir.join("staging").display().to_string(),
            ssh_key: dir.join("no-key"),
            canary_signer_pubkey: None,
        };
        let mut facade = LibFacade::new(cfg);
        let status = facade.status().expect("status on empty state");
        assert_eq!(status["receipts"]["count"], json!(0));
        assert_eq!(facade.chain_verification(), VerificationStatus::Verified);
        assert!(facade.receipts().expect("empty receipts").is_empty());
        let honeypot = facade.honeypot().expect("honeypot on empty state");
        assert_eq!(honeypot["manifest"], Value::Null);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

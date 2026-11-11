//! The append-only receipt log: `broadside.receipt` v1.
//!
//! Format (full spec: docs/RECEIPT-SCHEMA.md in this repo): one JSON
//! object per line, UTF-8, LF-terminated, append-only. Each receipt
//! hash-chains to its predecessor: `prev_hash` is the previous
//! receipt's `hash` (`""` for the genesis receipt), and `hash` is
//! the SHA-256 of the receipt's RFC 8785 canonical form with the
//! `hash` field removed. Any edit, deletion, or reordering of
//! history breaks the chain, and readers verify the whole chain
//! before trusting any single receipt — status never guesses.
//!
//! Appends are single `write_all` calls on an O_APPEND handle plus a
//! sync, so concurrent appenders cannot interleave a line.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::canonical::canonicalize;
use crate::crypto::sha256_hex;

pub const SCHEMA_NAME: &str = "broadside.receipt";
pub const SCHEMA_VERSION: u64 = 1;

/// Current UTC time as RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_from_unix(secs)
}

/// Convert unix seconds to RFC 3339 UTC (civil-from-days algorithm,
/// Howard Hinnant's, public domain math).
pub fn rfc3339_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// One gate outcome inside a receipt.
pub fn gate(name: &str, result: &str, detail: &str) -> Value {
    json!({"name": name, "result": result, "detail": detail})
}

/// The receipt log at a fixed path (state dir / receipts.jsonl).
pub struct ReceiptLog {
    path: PathBuf,
}

impl ReceiptLog {
    pub fn new(path: PathBuf) -> Self {
        ReceiptLog { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read and chain-verify every receipt. A broken chain is an
    /// error naming the first bad sequence number — readers fail
    /// closed instead of reporting partial history as fact.
    pub fn read_all(&self) -> Result<Vec<Value>, String> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let mut raw = String::new();
        std::fs::File::open(&self.path)
            .and_then(|mut f| f.read_to_string(&mut raw))
            .map_err(|e| format!("cannot read receipt log {}: {e}", self.path.display()))?;
        let mut receipts = Vec::new();
        let mut prev_hash = String::new();
        for (idx, line) in raw.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let receipt: Value = serde_json::from_str(line)
                .map_err(|e| format!("receipt line {} is not JSON: {e}", idx + 1))?;
            verify_receipt(&receipt, idx as u64 + 1, &prev_hash)
                .map_err(|e| format!("receipt chain broken at line {}: {e}", idx + 1))?;
            prev_hash = receipt
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    /// Append one receipt. `body` carries action/inputs/outputs/
    /// gates/result; this function stamps schema, seq, ts, actor,
    /// prev_hash, and hash. Returns the stamped receipt.
    pub fn append(&self, mut body: Value) -> Result<Value, String> {
        let existing = self.read_all()?;
        let seq = existing.len() as u64 + 1;
        let prev_hash = existing
            .last()
            .and_then(|r| r.get("hash"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        {
            let obj = body
                .as_object_mut()
                .ok_or("receipt body must be a JSON object")?;
            obj.insert("schema".to_string(), json!(SCHEMA_NAME));
            obj.insert("version".to_string(), json!(SCHEMA_VERSION));
            obj.insert("seq".to_string(), json!(seq));
            obj.insert("ts".to_string(), json!(now_rfc3339()));
            obj.insert(
                "actor".to_string(),
                json!(format!("broadside-mcp/{}", env!("CARGO_PKG_VERSION"))),
            );
            obj.insert("prev_hash".to_string(), json!(prev_hash));
        }
        let hash = receipt_hash(&body)?;
        body.as_object_mut()
            .ok_or("receipt body must be a JSON object")?
            .insert("hash".to_string(), json!(hash));
        let line = serde_json::to_string(&body).map_err(|e| format!("serialize receipt: {e}"))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create state dir {}: {e}", parent.display()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("cannot open receipt log {}: {e}", self.path.display()))?;
        file.write_all(format!("{line}\n").as_bytes())
            .and_then(|()| file.sync_data())
            .map_err(|e| format!("cannot append receipt: {e}"))?;
        Ok(body)
    }

    /// The newest receipt for `action` whose `result` equals
    /// `result` (any result when `result` is None).
    pub fn latest(&self, action: &str, result: Option<&str>) -> Result<Option<Value>, String> {
        let all = self.read_all()?;
        Ok(all.into_iter().rev().find(|r| {
            r.get("action").and_then(Value::as_str) == Some(action)
                && result
                    .map(|want| r.get("result").and_then(Value::as_str) == Some(want))
                    .unwrap_or(true)
        }))
    }
}

/// SHA-256 of the receipt's canonical form without its `hash` field.
pub fn receipt_hash(receipt: &Value) -> Result<String, String> {
    let mut stripped = receipt.clone();
    if let Some(obj) = stripped.as_object_mut() {
        obj.remove("hash");
    }
    let canonical = canonicalize(&stripped)?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn verify_receipt(receipt: &Value, expect_seq: u64, expect_prev: &str) -> Result<(), String> {
    if receipt.get("schema").and_then(Value::as_str) != Some(SCHEMA_NAME) {
        return Err("schema is not broadside.receipt".to_string());
    }
    if receipt.get("version").and_then(Value::as_u64) != Some(SCHEMA_VERSION) {
        return Err("version is not 1".to_string());
    }
    if receipt.get("seq").and_then(Value::as_u64) != Some(expect_seq) {
        return Err(format!(
            "seq is {}, expected {expect_seq}",
            receipt
                .get("seq")
                .map(ToString::to_string)
                .unwrap_or_default()
        ));
    }
    if receipt.get("prev_hash").and_then(Value::as_str) != Some(expect_prev) {
        return Err("prev_hash does not match the previous receipt's hash".to_string());
    }
    let claimed = receipt
        .get("hash")
        .and_then(Value::as_str)
        .ok_or("hash missing")?;
    let computed = receipt_hash(receipt)?;
    if claimed != computed {
        return Err("hash does not recompute (receipt was altered)".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log() -> (std::path::PathBuf, ReceiptLog) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "broadside-receipts-test-{}-{nanos}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let log = ReceiptLog::new(dir.join("receipts.jsonl"));
        (dir, log)
    }

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(rfc3339_from_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_from_unix(1_763_000_000), "2025-11-13T02:13:20Z");
        assert_eq!(rfc3339_from_unix(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn append_and_read_back_chain() {
        let (dir, log) = temp_log();
        let first = log
            .append(json!({"action": "build", "result": "pass", "inputs": {}, "outputs": {}, "gates": []}))
            .expect("append 1");
        assert_eq!(first["seq"], json!(1));
        assert_eq!(first["prev_hash"], json!(""));
        let second = log
            .append(json!({"action": "verify", "result": "pass", "inputs": {}, "outputs": {}, "gates": []}))
            .expect("append 2");
        assert_eq!(second["prev_hash"], first["hash"]);
        let all = log.read_all().expect("read back");
        assert_eq!(all.len(), 2);
        let latest = log.latest("verify", Some("pass")).expect("latest");
        assert_eq!(latest.expect("found")["seq"], json!(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tampered_history_fails_closed() {
        // Adversarial: editing any field of a written receipt, or
        // deleting a line, must break verification.
        let (dir, log) = temp_log();
        log.append(
            json!({"action": "deploy", "result": "pass", "inputs": {}, "outputs": {}, "gates": []}),
        )
        .expect("append 1");
        log.append(
            json!({"action": "deploy", "result": "pass", "inputs": {}, "outputs": {}, "gates": []}),
        )
        .expect("append 2");
        let path = log.path().to_path_buf();
        let raw = std::fs::read_to_string(&path).expect("raw");
        let tampered = raw.replacen("\"pass\"", "\"fail\"", 1);
        std::fs::write(&path, tampered).expect("write tampered");
        assert!(log.read_all().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_log_reads_empty() {
        let (_dir, log) = temp_log();
        assert_eq!(log.read_all().expect("empty ok").len(), 0);
        assert!(log.latest("build", None).expect("latest ok").is_none());
    }

    #[test]
    fn truncated_final_line_fails_closed() {
        // Adversarial: a log cut short mid-line (crash during
        // append, or a hostile truncation) must not read back as
        // a shorter valid history.
        let (dir, log) = temp_log();
        log.append(
            json!({"action": "build", "result": "pass", "inputs": {}, "outputs": {}, "gates": []}),
        )
        .expect("append 1");
        log.append(
            json!({"action": "verify", "result": "pass", "inputs": {}, "outputs": {}, "gates": []}),
        )
        .expect("append 2");
        let path = log.path().to_path_buf();
        let raw = std::fs::read_to_string(&path).expect("raw");
        let cut = raw.len() - 10;
        std::fs::write(&path, &raw[..cut]).expect("truncate");
        assert!(log.read_all().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deleted_middle_receipt_fails_closed() {
        // Adversarial: deleting one receipt from the middle
        // leaves a sequence gap the chain check must catch.
        let (dir, log) = temp_log();
        for action in ["build", "verify", "deploy"] {
            log.append(
                json!({"action": action, "result": "pass", "inputs": {}, "outputs": {}, "gates": []}),
            )
            .expect("append");
        }
        let path = log.path().to_path_buf();
        let raw = std::fs::read_to_string(&path).expect("raw");
        let mut lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 3);
        lines.remove(1);
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).expect("rewrite");
        assert!(log.read_all().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

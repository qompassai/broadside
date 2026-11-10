//! H5: evidence packets and the abuse-report draft.
//!
//! An evidence packet bundles the receipt chain segment that
//! documents an incident (canary hits, quarantines, the deploys
//! around them) into one hash-chained, self-verifying document:
//! the packet carries the receipts verbatim, the chain head they
//! end at, and its own hash over the canonical form. The packet
//! supports a drafted abuse report — drafted only. Sending is an
//! Owner-stamped act that this server never performs.
//!
//! Packet signing uses an Owner-held key provided out of band
//! (BROADSIDE_PACKET_KEY_FILE: a file holding a base64url Ed25519
//! seed). Absent the key, the packet is a draft and says so in
//! its own body: `"state": "draft-unsigned"`. An unsigned packet
//! presented as signed is exactly the failure this field exists
//! to prevent.

use std::path::Path;

use serde_json::{Value, json};

use crate::canonical::canonicalize;
use crate::config::Config;
use crate::crypto::{b64url_decode, b64url_encode, sha256_hex, sign_for_fixture};
use crate::receipts::now_rfc3339;

/// Assemble a packet from the whole receipt chain (the chain is
/// verified by the read itself) and write packet.json +
/// abuse-report-draft.md into `out_dir`.
pub fn assemble_packet(cfg: &Config, out_dir: &Path) -> Result<Value, String> {
    let log = cfg.receipts();
    let receipts = log.read_all()?; // chain-verified on read
    if receipts.is_empty() {
        return Err("no receipts to packet (the log is empty)".to_string());
    }
    let chain_head = receipts
        .last()
        .and_then(|r| r.get("hash"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mut packet = json!({
        "packet": "broadside.evidence-packet",
        "version": 1,
        "assembled": now_rfc3339(),
        "assembler": format!("broadside-mcp/{}", env!("CARGO_PKG_VERSION")),
        "receipt_count": receipts.len(),
        "chain_head": chain_head,
        "receipts": receipts,
        "signature": Value::Null,
        "state": "draft-unsigned",
    });
    let canonical = canonicalize(&packet)?;
    let packet_hash = sha256_hex(canonical.as_bytes());
    packet["packet_hash"] = json!(packet_hash);

    // Optional Owner-key signing (the key never transits the MCP
    // surface; it is read from a local file the Owner controls).
    let mut signed = false;
    if let Ok(key_path) = std::env::var("BROADSIDE_PACKET_KEY_FILE")
        && !key_path.trim().is_empty()
    {
        let raw = std::fs::read_to_string(&key_path)
            .map_err(|e| format!("cannot read packet key file: {e}"))?;
        let seed_bytes =
            b64url_decode(raw.trim()).map_err(|e| format!("packet key file malformed: {e}"))?;
        let seed: [u8; 32] = seed_bytes
            .try_into()
            .map_err(|_| "packet key seed must be 32 bytes".to_string())?;
        let (public, signature) = sign_for_fixture(&seed, packet_hash.as_bytes());
        packet["signature"] = json!({
            "alg": "EdDSA",
            "public_key": b64url_encode(&public),
            "signature": b64url_encode(&signature),
        });
        packet["state"] = json!("signed");
        signed = true;
    }

    std::fs::create_dir_all(out_dir).map_err(|e| format!("cannot create packet dir: {e}"))?;
    let packet_path = out_dir.join("packet.json");
    std::fs::write(
        &packet_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&packet).map_err(|e| format!("serialize packet: {e}"))?
        ),
    )
    .map_err(|e| format!("cannot write packet: {e}"))?;

    let draft = abuse_report_draft(&packet);
    let draft_path = out_dir.join("abuse-report-draft.md");
    std::fs::write(&draft_path, draft).map_err(|e| format!("cannot write draft: {e}"))?;

    Ok(json!({
        "packet": packet_path.display().to_string(),
        "draft": draft_path.display().to_string(),
        "packet_hash": packet_hash,
        "receipt_count": receipts.len(),
        "signed": signed,
    }))
}

/// The abuse-report draft: a factual summary for the Owner to
/// review, address, and send (or not). Never sent by broadside.
fn abuse_report_draft(packet: &Value) -> String {
    let receipts = packet
        .get("receipts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut lines = vec![
        "# Abuse report — DRAFT (not sent)".to_string(),
        String::new(),
        "Status: drafted by broadside-mcp from its receipt chain. Review, address, and send manually; broadside never sends.".to_string(),
        String::new(),
        format!(
            "Evidence packet hash: {}",
            packet.get("packet_hash").and_then(Value::as_str).unwrap_or("?")
        ),
        String::new(),
        "## Observed hostile activity against qompass.ai".to_string(),
        String::new(),
    ];
    let mut incidents = 0usize;
    for receipt in &receipts {
        let action = receipt.get("action").and_then(Value::as_str).unwrap_or("");
        let ts = receipt.get("ts").and_then(Value::as_str).unwrap_or("?");
        if action == "quarantine" {
            incidents += 1;
            let source = receipt
                .get("inputs")
                .and_then(|i| i.get("source"))
                .and_then(Value::as_str)
                .unwrap_or("?");
            lines.push(format!(
                "- {ts}: citation source quarantined as hostile: {source}"
            ));
        }
        if action == "live_check" && receipt.get("result").and_then(Value::as_str) == Some("alert")
        {
            incidents += 1;
            lines.push(format!(
                "- {ts}: canary endpoint hits observed in the host access log (see packet receipt seq {})",
                receipt.get("seq").cloned().unwrap_or(Value::Null)
            ));
        }
    }
    if incidents == 0 {
        lines.push("- No hostile incidents in this packet's receipt range.".to_string());
    }
    lines.push(String::new());
    lines.push(
        "The decoy endpoints involved are never linked, never in the sitemap, and are Disallow'd in robots.txt; requests to them are hostile by construction. Full hash-chained evidence is in the accompanying packet.json.".to_string(),
    );
    lines.push(String::new());
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json as j;

    fn cfg_with_receipts() -> (std::path::PathBuf, Config) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir =
            std::env::temp_dir().join(format!("broadside-packet-{}-{nanos}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            site_root: dir.join("site"),
            state_dir: dir.join("state"),
            base_url: "https://example.invalid".to_string(),
            deploy_target: "/tmp/staging".to_string(),
            ssh_key: dir.join("no-key"),
            canary_signer_pubkey: None,
        };
        let log = cfg.receipts();
        log.append(j!({"action": "live_check", "result": "alert", "inputs": {}, "outputs": {}, "gates": []}))
            .expect("receipt 1");
        log.append(j!({"action": "quarantine", "result": "alert",
                        "inputs": {"source": "10.9999/evil"}, "outputs": {}, "gates": []}))
            .expect("receipt 2");
        (dir, cfg)
    }

    #[test]
    fn packet_assembles_unsigned_draft_by_default() {
        // SAFETY default: with no Owner key file, the packet must
        // declare itself a draft — never silently "signed".
        let (dir, cfg) = cfg_with_receipts();
        let out = dir.join("out");
        let summary = assemble_packet(&cfg, &out).expect("assemble");
        assert_eq!(summary["signed"], j!(false));
        let packet: Value =
            serde_json::from_str(&std::fs::read_to_string(out.join("packet.json")).expect("read"))
                .expect("json");
        assert_eq!(packet["state"], j!("draft-unsigned"));
        assert_eq!(packet["receipt_count"], j!(2));
        let draft = std::fs::read_to_string(out.join("abuse-report-draft.md")).expect("draft");
        assert!(draft.contains("DRAFT (not sent)"));
        assert!(draft.contains("10.9999/evil"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_log_refuses_to_packet() {
        let dir =
            std::env::temp_dir().join(format!("broadside-packet-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            site_root: dir.join("site"),
            state_dir: dir.join("state"),
            base_url: "https://example.invalid".to_string(),
            deploy_target: "/tmp/staging".to_string(),
            ssh_key: dir.join("no-key"),
            canary_signer_pubkey: None,
        };
        assert!(assemble_packet(&cfg, &dir.join("out")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

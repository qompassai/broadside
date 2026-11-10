//! H4 support: the blocklist feed.
//!
//! The host-side enforcement (fail2ban jail + tarpit) ships as
//! config in this repo under deploy/honeypot/ and is applied by
//! the Owner — never by broadside. What broadside produces is the
//! feed those configs consume: the source IPs of canary hits from
//! live_check receipts, decayed after 30 days, with the allowlist
//! applied FIRST (the Owner's own addresses and known-good
//! scanners are never listed, whatever the log says).

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::config::Config;
use crate::receipts::rfc3339_from_unix;

/// Parse an RFC 3339 UTC timestamp back to unix seconds (the
/// inverse of receipts::rfc3339_from_unix for the Z form).
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let (date, time) = text.split_once('T')?;
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    let time = time.trim_end_matches('Z');
    let mut t = time.split(':');
    let hh: u64 = t.next()?.parse().ok()?;
    let mm: u64 = t.next()?.parse().ok()?;
    let ss: u64 = t.next()?.parse().ok()?;
    // days-from-civil (Hinnant), inverse of the receipts encoder.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let mp = if month > 2 { month - 3 } else { month + 9 } as u64;
    let doy = (153 * mp + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    Some((days as u64) * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// Extract an IPv4 address from a Caddy JSON log line
/// ("remote_ip" field preferred; first dotted-quad otherwise).
pub fn extract_ipv4(line: &str) -> Option<String> {
    if let Ok(value) = serde_json::from_str::<Value>(line)
        && let Some(ip) = value
            .get("request")
            .and_then(|r| r.get("remote_ip"))
            .and_then(Value::as_str)
    {
        return Some(ip.to_string());
    }
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0usize;
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                if bytes[j] == b'.' {
                    dots += 1;
                }
                j += 1;
            }
            let candidate = &line[start..j];
            if dots == 3
                && candidate
                    .split('.')
                    .all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
            {
                return Some(candidate.to_string());
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    None
}

/// Decay window for blocklist entries: 30 days (HONEYPOT H4).
pub const DECAY_SECONDS: u64 = 30 * 86_400;

/// Build the current blocklist from the receipt chain: source IPs
/// of canary hits in live_check receipts newer than the decay
/// window, minus the allowlist. Returns (ips, detail).
pub fn current_blocklist(cfg: &Config, now_unix: u64) -> Result<(Vec<String>, String), String> {
    let log = cfg.receipts();
    let receipts = log.read_all()?;
    let allowlist = load_allowlist(cfg);
    let mut ips: BTreeSet<String> = BTreeSet::new();
    let mut incidents = 0usize;
    for receipt in &receipts {
        if receipt.get("action").and_then(Value::as_str) != Some("live_check") {
            continue;
        }
        let ts = receipt
            .get("ts")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339)
            .unwrap_or(0);
        if now_unix.saturating_sub(ts) > DECAY_SECONDS {
            continue;
        }
        let hits = receipt
            .get("outputs")
            .and_then(|o| o.get("canary_log"))
            .and_then(|c| c.get("hits"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for hit in hits {
            incidents += 1;
            if let Some(line) = hit.get("line").and_then(Value::as_str)
                && let Some(ip) = extract_ipv4(line)
                && !allowlist.contains(&ip)
            {
                ips.insert(ip);
            }
        }
    }
    Ok((
        ips.into_iter().collect(),
        format!(
            "{incidents} canary-hit lines in the decay window; allowlist holds {} entries",
            allowlist.len()
        ),
    ))
}

/// The allowlist: BROADSIDE_BLOCKLIST_ALLOWLIST (comma-separated)
/// plus state/allowlist.txt (one IP per line, # comments).
fn load_allowlist(cfg: &Config) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    if let Ok(env) = std::env::var("BROADSIDE_BLOCKLIST_ALLOWLIST") {
        for part in env.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                set.insert(trimmed.to_string());
            }
        }
    }
    if let Ok(text) = std::fs::read_to_string(cfg.state_dir.join("allowlist.txt")) {
        for line in text.lines() {
            let trimmed = line.split('#').next().unwrap_or("").trim();
            if !trimmed.is_empty() {
                set.insert(trimmed.to_string());
            }
        }
    }
    set
}

/// Write the feed file the host configs consume: a header naming
/// the generator + timestamp, then one IP per line.
pub fn write_feed(cfg: &Config, out: &std::path::Path) -> Result<Value, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (ips, detail) = current_blocklist(cfg, now)?;
    let mut text = format!(
        "# broadside blocklist feed — generated {} by broadside-mcp/{}\n# {}\n",
        rfc3339_from_unix(now),
        env!("CARGO_PKG_VERSION"),
        detail
    );
    for ip in &ips {
        text.push_str(ip);
        text.push('\n');
    }
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create feed dir: {e}"))?;
    }
    std::fs::write(out, text).map_err(|e| format!("write feed: {e}"))?;
    Ok(json!({"feed": out.display().to_string(), "blocked": ips, "detail": detail}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json as j;

    #[test]
    fn rfc3339_round_trip() {
        for secs in [0u64, 951_782_400, 1_763_000_000] {
            assert_eq!(parse_rfc3339(&rfc3339_from_unix(secs)), Some(secs));
        }
        assert_eq!(parse_rfc3339("not a date"), None);
    }

    #[test]
    fn ipv4_extraction_prefers_remote_ip() {
        let line = r#"{"request": {"remote_ip": "203.0.113.7", "uri": "/.env"}, "ts": 1.5}"#;
        assert_eq!(extract_ipv4(line).as_deref(), Some("203.0.113.7"));
        assert_eq!(
            extract_ipv4("plain 198.51.100.23 text").as_deref(),
            Some("198.51.100.23")
        );
        assert_eq!(extract_ipv4("no address here"), None);
        assert_eq!(extract_ipv4("999.1.1.1 is not an ip"), None);
    }

    #[test]
    fn blocklist_decays_and_allowlist_wins() {
        // Adversarial pair: a fresh hit is listed; a 31-day-old
        // hit is decayed; an allowlisted fresh hit is NOT listed
        // (allowlist first, always).
        let dir = std::env::temp_dir().join(format!("broadside-h4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg = Config {
            site_root: dir.join("site"),
            state_dir: dir.join("state"),
            base_url: "https://example.invalid".to_string(),
            deploy_target: "/tmp/staging".to_string(),
            ssh_key: dir.join("no-key"),
            canary_signer_pubkey: None,
        };
        std::fs::create_dir_all(&cfg.state_dir).expect("state");
        std::fs::write(cfg.state_dir.join("allowlist.txt"), "198.51.100.9\n").expect("allowlist");
        let log = cfg.receipts();
        // Receipts carry real wall-clock timestamps; evaluate
        // against real now, then against now + the decay window.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        log.append(j!({"action": "live_check", "result": "alert", "inputs": {},
            "outputs": {"canary_log": {"hits": [
                {"line": "{\"request\": {\"remote_ip\": \"203.0.113.7\"}}"},
                {"line": "{\"request\": {\"remote_ip\": \"198.51.100.9\"}}"}
            ]}}, "gates": []}))
            .expect("receipt");
        let (ips, _) = current_blocklist(&cfg, now).expect("blocklist");
        assert_eq!(ips, vec!["203.0.113.7".to_string()]);
        let (ips, _) = current_blocklist(&cfg, now + DECAY_SECONDS + 1).expect("decayed");
        assert!(ips.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! Pure ratatui panel constructors (DESIGN §D2): no I/O, no
//! terminal access — `(data) -> Paragraph`, tested through
//! ratatui's `TestBackend`.
//!
//! Every panel that embeds member-controlled text truncates it
//! with a named bound: [`VALUE_CHARS_MAX`] for scalar values,
//! [`LINE_CHARS_MAX`] for log/audit lines, [`DETAIL_CHARS_MAX`]
//! for a receipt's pretty-printed JSON.

use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Paragraph, Wrap};

use serde_json::Value;

use crate::facade::VerificationStatus;
use crate::screens::{PipelineRun, RunMode, StagedCall, Workflow};
use crate::triggers::TriggerRule;

/// Scalar values render at most this many characters.
pub const VALUE_CHARS_MAX: usize = 120;
/// Log and audit lines render at most this many characters.
pub const LINE_CHARS_MAX: usize = 200;
/// A receipt detail renders at most this many characters.
pub const DETAIL_CHARS_MAX: usize = 4000;
/// Receipt rows shown in the list panel.
pub const RECEIPT_ROWS_MAX: usize = 30;
/// Audit lines shown in the Fleet panel.
pub const AUDIT_ROWS_MAX: usize = 8;

/// Truncate `text` to `max_chars` characters with a `...` marker.
pub fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars.saturating_sub(3)).collect();
    format!("{kept}...")
}

fn titled(text: String, title: &str, color: Color) -> Paragraph<'static> {
    Paragraph::new(text)
        .block(
            Block::bordered()
                .title(title.to_string())
                .border_style(Style::default().fg(color)),
        )
        .wrap(Wrap { trim: false })
}

fn scalar(value: &Value) -> String {
    let text = match value {
        Value::Null => "-".to_string(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    truncate_chars(&text, VALUE_CHARS_MAX)
}

/// Overview: member version line, last pipeline states, receipt
/// count and chain state, deploy target.
pub fn overview_panel(status: &Value, tui_version: &str, tool_count: usize) -> Paragraph<'static> {
    let receipts = status.get("receipts").cloned().unwrap_or(Value::Null);
    let latest = status.get("latest").cloned().unwrap_or(Value::Null);
    let mut text = format!("broadside (member) + broadside-tui {tui_version}\n");
    text.push_str(&format!("tools: {tool_count}\n"));
    text.push_str(&format!(
        "receipts: {} (chain_ok: {})\n",
        scalar(receipts.get("count").unwrap_or(&Value::Null)),
        scalar(receipts.get("chain_ok").unwrap_or(&Value::Null)),
    ));
    for action in ["build", "verify", "deploy", "live_check"] {
        let entry = latest.get(action).cloned().unwrap_or(Value::Null);
        if entry.is_null() {
            text.push_str(&format!("last {action}: -\n"));
        } else {
            text.push_str(&format!(
                "last {action}: {} seq {} at {}\n",
                scalar(entry.get("result").unwrap_or(&Value::Null)),
                scalar(entry.get("seq").unwrap_or(&Value::Null)),
                scalar(entry.get("ts").unwrap_or(&Value::Null)),
            ));
        }
    }
    text.push_str(&format!(
        "dist_hash_now: {}\n",
        scalar(status.get("dist_hash_now").unwrap_or(&Value::Null))
    ));
    text.push_str(&format!(
        "deploy_target: {} (production: {})",
        scalar(status.get("deploy_target").unwrap_or(&Value::Null)),
        scalar(status.get("target_is_production").unwrap_or(&Value::Null)),
    ));
    titled(text, "Overview", Color::Green)
}

/// Workflows: the selectable operations, the run mode, any staged
/// call awaiting approval, and this run's stage records.
pub fn workflows_panel(
    selected: Workflow,
    mode: RunMode,
    staged: Option<&StagedCall>,
    run: &PipelineRun,
    provider_note: &str,
) -> Paragraph<'static> {
    let mut text = format!("mode: {} (m toggles; plan is the default)\n", mode.label());
    text.push_str(&format!("provider: {provider_note}\n"));
    for workflow in Workflow::ALL {
        let marker = if workflow == selected { ">" } else { " " };
        let consequential = if workflow.is_consequential() {
            " [consequential]"
        } else {
            ""
        };
        text.push_str(&format!(
            "{marker} {} ({}){consequential}\n",
            workflow.name(),
            workflow.tool()
        ));
    }
    match staged {
        Some(staged) => {
            text.push_str(&format!(
                "\nstaged (a approves, x aborts):\n  {}",
                truncate_chars(&staged.describe(), DETAIL_CHARS_MAX)
            ));
        }
        None => text.push_str("\nnothing staged"),
    }
    if !run.stages().is_empty() {
        text.push_str("\n\nthis run:");
        for stage in run.stages() {
            text.push_str(&format!(
                "\n  {}: {}",
                stage.workflow.name(),
                truncate_chars(&stage.state.label(), LINE_CHARS_MAX)
            ));
        }
    }
    if let Some(hash) = run.verified_hash_in_run() {
        text.push_str(&format!("\nverified in this run: {hash}"));
    }
    titled(text, "Workflows", Color::Cyan)
}

/// Receipts list: one row per receipt (seq, action, result, hash
/// prefix), the selected row marked, and the chain verdict from
/// the member's machinery at the top — never the TUI's own word.
pub fn receipts_panel(
    receipts: &[Value],
    selected: usize,
    chain: &VerificationStatus,
) -> Paragraph<'static> {
    let mut text = format!("chain: {}\n", chain.label());
    if receipts.is_empty() {
        text.push_str("(no receipts)");
        return titled(text, "Receipts", Color::Yellow);
    }
    for (index, receipt) in receipts.iter().take(RECEIPT_ROWS_MAX).enumerate() {
        let marker = if index == selected { ">" } else { " " };
        let hash = receipt
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        text.push_str(&format!(
            "{marker} seq {} {} {} hash {}\n",
            scalar(receipt.get("seq").unwrap_or(&Value::Null)),
            scalar(receipt.get("action").unwrap_or(&Value::Null)),
            scalar(receipt.get("result").unwrap_or(&Value::Null)),
            truncate_chars(hash, 16),
        ));
    }
    titled(text, "Receipts", Color::Yellow)
}

/// Receipt detail: the receipt's own JSON plus its verification
/// status from the member's machinery.
pub fn receipt_detail_panel(
    receipt: &Value,
    verification: &VerificationStatus,
) -> Paragraph<'static> {
    let pretty = serde_json::to_string_pretty(receipt).unwrap_or_else(|_| "{}".to_string());
    let text = format!(
        "verification: {}\n{}",
        verification.label(),
        truncate_chars(&pretty, DETAIL_CHARS_MAX)
    );
    titled(text, "Receipt detail", Color::Yellow)
}

/// Honeypot: the signed canary manifest state the library
/// exposes through status (revision, signer, canary count,
/// fixture flag, signer pinning), plus the key record.
pub fn honeypot_panel(honeypot: &Value) -> Paragraph<'static> {
    let manifest = honeypot.get("manifest").cloned().unwrap_or(Value::Null);
    let key_record = honeypot.get("key_record").cloned().unwrap_or(Value::Null);
    let mut text = String::new();
    if manifest.is_null() {
        text.push_str("honeypot manifest: none in the site tree\n");
    } else {
        text.push_str(&format!(
            "manifest revision: {}\n",
            scalar(manifest.get("revision").unwrap_or(&Value::Null))
        ));
        text.push_str(&format!(
            "signer kid: {}\n",
            scalar(manifest.get("signer_kid").unwrap_or(&Value::Null))
        ));
        text.push_str(&format!(
            "canaries: {}\n",
            scalar(manifest.get("canaries").unwrap_or(&Value::Null))
        ));
        text.push_str(&format!(
            "fixture: {}\n",
            scalar(manifest.get("fixture").unwrap_or(&Value::Null))
        ));
        text.push_str(&format!(
            "signer pinned in server config: {}\n",
            scalar(manifest.get("signer_pinned").unwrap_or(&Value::Null))
        ));
    }
    if key_record.is_null() {
        text.push_str("agent-card key record: none\n");
    } else {
        text.push_str(&format!(
            "agent-card key record: kid {} fixture {} signature_valid {}",
            scalar(key_record.get("kid").unwrap_or(&Value::Null)),
            scalar(key_record.get("fixture").unwrap_or(&Value::Null)),
            scalar(key_record.get("signature_valid").unwrap_or(&Value::Null)),
        ));
    }
    titled(text, "Honeypot", Color::Magenta)
}

/// Log / Live: the bounded event buffer, oldest first.
pub fn log_panel(lines: &[String]) -> Paragraph<'static> {
    let text = lines
        .iter()
        .map(|line| truncate_chars(line, LINE_CHARS_MAX))
        .collect::<Vec<_>>()
        .join("\n");
    titled(text, "Log / Live", Color::Blue)
}

/// Fleet: the member roster with reachability as far as rung 1
/// knows it, this member's declared trigger rules with enable
/// state, and the trigger audit tail.
pub fn fleet_panel(
    rules: &[TriggerRule],
    audit_tail: &[String],
    transport_note: &str,
) -> Paragraph<'static> {
    let mut text = String::from("fleet members:\n");
    text.push_str("  broadside (this member): local\n");
    text.push_str("  bloch (trigger target): via MCP client transport\n");
    text.push_str(&format!("trigger transport: {transport_note}\n"));
    text.push_str("\ntrigger rules (§D4):\n");
    if rules.is_empty() {
        text.push_str("  (none declared)\n");
    }
    for rule in rules {
        text.push_str(&format!(
            "  [{}] {}: {} -> {}.{} mode {} labels {}/{}\n",
            if rule.enabled { "on" } else { "off" },
            rule.id,
            rule.event,
            rule.target_mcp,
            rule.target_tool,
            match rule.mode {
                crate::triggers::RuleMode::Auto => "auto",
                crate::triggers::RuleMode::Plan => "plan",
            },
            rule.origin_lane,
            rule.content_label,
        ));
    }
    text.push_str("\ntrigger audit (tail):");
    if audit_tail.is_empty() {
        text.push_str("\n  (no evaluations yet)");
    }
    for line in audit_tail.iter().rev().take(AUDIT_ROWS_MAX).rev() {
        text.push_str(&format!("\n  {}", truncate_chars(line, LINE_CHARS_MAX)));
    }
    titled(text, "Fleet / MCP", Color::Green)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::widgets::Widget;

    use serde_json::json;

    use crate::screens::StageState;

    fn render_text<W: Widget>(widget: W, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        terminal
            .draw(|frame| frame.render_widget(widget, frame.area()))
            .expect("test draw");
        let buffer = terminal.backend().buffer().clone();
        let mut rows = Vec::new();
        for y in 0..height {
            let row: String = (0..width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect();
            rows.push(row);
        }
        rows.join("\n")
    }

    #[test]
    fn overview_renders_version_and_receipt_count() {
        let status = json!({
            "receipts": {"count": 7, "chain_ok": true},
            "latest": {"build": {"result": "pass", "seq": 3, "ts": "2026-11-16T00:00:00Z"},
                       "verify": null, "deploy": null, "live_check": null},
            "dist_hash_now": "abc123",
            "deploy_target": "/tmp/staging",
            "target_is_production": false,
        });
        let text = render_text(overview_panel(&status, "0.1.0", 5), 80, 14);
        assert!(text.contains("broadside-tui 0.1.0"), "{text}");
        assert!(text.contains("receipts: 7"), "{text}");
        assert!(text.contains("last build: pass"), "{text}");
    }

    #[test]
    fn workflows_panel_shows_staged_call_and_mode() {
        let staged = StagedCall::single(Workflow::Verify, Some("abc123")).expect("stage");
        let run = PipelineRun::new();
        let text = render_text(
            workflows_panel(
                Workflow::Verify,
                RunMode::Plan,
                Some(&staged),
                &run,
                "n/a (no model routing)",
            ),
            80,
            16,
        );
        assert!(text.contains("mode: plan"), "{text}");
        assert!(text.contains("broadside_verify"), "{text}");
        assert!(text.contains("consequential"), "{text}");
    }

    #[test]
    fn receipts_panel_never_hides_a_failed_chain() {
        // Adversarial: a broken chain renders as FAILED, in the
        // panel's first line, not buried or softened.
        let chain = VerificationStatus::Failed("chain broken at line 2".to_string());
        let receipts = vec![json!({"seq": 1, "action": "build", "result": "pass",
                                   "hash": "aaaa1111bbbb2222"})];
        let text = render_text(receipts_panel(&receipts, 0, &chain), 80, 10);
        assert!(text.contains("FAILED verification"), "{text}");
        assert!(text.contains("seq 1 build pass"), "{text}");
    }

    #[test]
    fn receipt_detail_labels_unverifiable_as_unverifiable() {
        let receipt = json!({"seq": 1, "action": "build"});
        let status = VerificationStatus::Unverifiable("no chain context".to_string());
        let text = render_text(receipt_detail_panel(&receipt, &status), 80, 10);
        assert!(text.contains("unverifiable"), "{text}");
        assert!(!text.contains("verified (member"), "{text}");
    }

    #[test]
    fn honeypot_panel_renders_manifest_state() {
        let honeypot = json!({
            "manifest": {"revision": "r7", "signer_kid": "canary-1", "canaries": 4,
                         "fixture": true, "signer_pinned": true},
            "key_record": {"kid": "card-1", "fixture": true, "signature_valid": true},
        });
        let text = render_text(honeypot_panel(&honeypot), 80, 12);
        assert!(text.contains("manifest revision: r7"), "{text}");
        assert!(text.contains("canaries: 4"), "{text}");
        assert!(text.contains("signature_valid true"), "{text}");
    }

    #[test]
    fn oversized_values_are_truncated_with_named_bounds() {
        // Adversarial: member-controlled text cannot blow the
        // panel up; it truncates at VALUE_CHARS_MAX.
        let big = "x".repeat(VALUE_CHARS_MAX * 4);
        let status = json!({
            "receipts": {"count": 0, "chain_ok": true},
            "latest": {},
            "dist_hash_now": big,
            "deploy_target": "/tmp/staging",
            "target_is_production": false,
        });
        let text = render_text(overview_panel(&status, "0.1.0", 5), 200, 14);
        assert!(text.contains("..."), "{text}");
        assert!(
            !text.contains(&"x".repeat(VALUE_CHARS_MAX + 1)),
            "truncated"
        );
    }

    #[test]
    fn fleet_panel_lists_the_declared_rule_with_labels() {
        let rules =
            crate::triggers::parse_rules(crate::triggers::DEFAULT_TRIGGERS_TOML).expect("rules");
        let text = render_text(fleet_panel(&rules, &[], "fake (tests)"), 100, 16);
        assert!(
            text.contains("broadside-deploy-verified-to-bloch-lesson"),
            "{text}"
        );
        assert!(text.contains("bloch.lesson_candidate"), "{text}");
        assert!(text.contains("qompass/sfw"), "{text}");
    }

    #[test]
    fn log_panel_bounds_line_length() {
        let lines = vec!["y".repeat(LINE_CHARS_MAX * 3)];
        let text = render_text(log_panel(&lines), 300, 6);
        assert!(!text.contains(&"y".repeat(LINE_CHARS_MAX + 1)), "bounded");
    }

    #[test]
    fn run_stage_labels_render_in_workflows_panel() {
        let mut run = PipelineRun::new();
        run.record_stage(Workflow::Build, StageState::Passed, None);
        let text = render_text(
            workflows_panel(Workflow::Build, RunMode::Auto, None, &run, "n/a"),
            80,
            14,
        );
        assert!(text.contains("build: pass"), "{text}");
    }
}

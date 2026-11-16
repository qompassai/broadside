//! The §D4 cross-MCP trigger layer for broadside: one typed rule
//! engine over declared rules (data, not code).
//!
//! Rules load from `triggers.toml`, are listed in the Fleet panel,
//! and fire as ordinary MCP client calls through a
//! [`TriggerTransport`]. Semantics (DESIGN §D4):
//!
//! - `where` is a bounded predicate over named event fields:
//!   comparisons (`==`, `!=`, `>`, `<`, `>=`, `<=`) joined by
//!   `&&`. No expression language, no eval.
//! - Depth: an event deeper than a rule's `max_depth` never fires
//!   it; `max_depth` itself is capped at
//!   [`crate::TRIGGER_DEPTH_HARD_MAX`] at load.
//! - Idempotency: a firing is keyed by the hash of (rule id,
//!   event payload); a key that already fired is dropped.
//! - Audit: every match, firing, refusal, and drop appends one
//!   JSON line carrying the rule's `origin_lane` + `content_label`
//!   birth labels, retained up to [`crate::AUDIT_LINES_MAX`].
//! - Consequential targets may only fire in `plan` mode unless
//!   the target's own gate authorizes the call; broadside's one
//!   rule targets a draft lesson candidate (not consequential),
//!   so `auto` is honest here.
//!
//! Live firing is *not* proven in rung 1: the production binary
//! wires [`UnavailableTransport`], which refuses with the reason
//! recorded in the audit log. Tests wire [`FakeTransport`] and
//! prove the full evaluation path against it.

use std::collections::{HashSet, VecDeque};

use serde::Deserialize;
use serde_json::{Value, json};

use broadside_mcp::crypto::sha256_hex;

use crate::{AUDIT_LINES_MAX, TRIGGER_DEPTH_HARD_MAX, TRIGGER_RULES_MAX};

/// The shipped rule file, embedded so the Fleet panel always lists
/// the declared rules even before a config path is chosen.
pub const DEFAULT_TRIGGERS_TOML: &str = include_str!("../triggers.toml");

/// Whether a matched rule fires on its own or stages a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleMode {
    /// Fire the target call directly.
    Auto,
    /// Stage the call for operator approval; nothing fires.
    Plan,
}

/// One declared trigger rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TriggerRule {
    /// Stable rule id (idempotency keys include it).
    pub id: String,
    /// BLOCH lane law: origin lane, stamped from birth.
    pub origin_lane: String,
    /// BLOCH lane law: content label, stamped from birth.
    pub content_label: String,
    /// Event name this rule listens for, e.g. `deploy.verified`.
    pub event: String,
    /// The bounded `where` predicate text, if any.
    pub where_clause: Option<String>,
    /// Target MCP server name, e.g. `bloch`.
    pub target_mcp: String,
    /// Target tool on that server, e.g. `lesson_candidate`.
    pub target_tool: String,
    /// `args_from` source: only `event` is supported in rung 1.
    pub args_from: String,
    /// Auto or plan firing.
    pub mode: RuleMode,
    /// Idempotency strategy name; only `event-hash` exists.
    pub idempotency: String,
    /// Maximum event depth this rule fires at.
    pub max_depth: u32,
    /// Operator enable state (Fleet panel can disable; takes
    /// effect without restart).
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
struct RulesFile {
    #[serde(default)]
    rule: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    id: String,
    origin_lane: String,
    content_label: String,
    on: RawOn,
    then: RawThen,
    mode: String,
    idempotency: String,
    max_depth: u32,
}

#[derive(Debug, Deserialize)]
struct RawOn {
    event: String,
    #[serde(default, rename = "where")]
    where_clause: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawThen {
    mcp: String,
    tool: String,
    args_from: String,
}

/// Parse and validate a `triggers.toml` document. Invalid rules
/// fail the whole load (fail closed): a half-loaded rule set would
/// be hidden behaviour.
pub fn parse_rules(toml_text: &str) -> Result<Vec<TriggerRule>, String> {
    let file: RulesFile = toml::from_str(toml_text).map_err(|e| format!("triggers.toml: {e}"))?;
    if file.rule.len() > TRIGGER_RULES_MAX {
        return Err(format!(
            "triggers.toml declares {} rules, over TRIGGER_RULES_MAX {TRIGGER_RULES_MAX}",
            file.rule.len()
        ));
    }
    let mut rules = Vec::new();
    for raw in file.rule {
        if raw.id.is_empty() || raw.origin_lane.is_empty() || raw.content_label.is_empty() {
            return Err("trigger rule with an empty id/lane/label".to_string());
        }
        if raw.max_depth > TRIGGER_DEPTH_HARD_MAX {
            return Err(format!(
                "rule {} max_depth {} exceeds the hard ceiling {TRIGGER_DEPTH_HARD_MAX}",
                raw.id, raw.max_depth
            ));
        }
        if raw.idempotency != "event-hash" {
            return Err(format!(
                "rule {} idempotency {:?} is not supported (only event-hash)",
                raw.id, raw.idempotency
            ));
        }
        if raw.then.args_from != "event" {
            return Err(format!(
                "rule {} args_from {:?} is not supported (only event)",
                raw.id, raw.then.args_from
            ));
        }
        let mode = match raw.mode.as_str() {
            "auto" => RuleMode::Auto,
            "plan" => RuleMode::Plan,
            other => {
                return Err(format!("rule {} mode {other:?} is not auto|plan", raw.id));
            }
        };
        if let Some(clause) = &raw.on.where_clause {
            // Validate the predicate now so a malformed rule is a
            // load error, not a silent never-fire at runtime.
            parse_where(clause)?;
        }
        rules.push(TriggerRule {
            id: raw.id,
            origin_lane: raw.origin_lane,
            content_label: raw.content_label,
            event: raw.on.event,
            where_clause: raw.on.where_clause,
            target_mcp: raw.then.mcp,
            target_tool: raw.then.tool,
            args_from: raw.then.args_from,
            mode,
            idempotency: raw.idempotency,
            max_depth: raw.max_depth,
            enabled: true,
        });
    }
    Ok(rules)
}

/// One typed event on broadside's own event stream (the same
/// stream the Log screen renders).
#[derive(Clone, Debug, PartialEq)]
pub struct FleetEvent {
    /// Dotted event name, e.g. `deploy.verified`.
    pub name: String,
    /// Named fields the `where` predicates read.
    pub payload: Value,
    /// Trigger depth: 0 for operator-originated work, +1 per
    /// trigger hop. Rules never fire beyond their `max_depth`.
    pub depth: u32,
}

impl FleetEvent {
    /// An operator-originated (depth 0) event.
    pub fn new(name: &str, payload: Value) -> FleetEvent {
        FleetEvent {
            name: name.to_string(),
            payload,
            depth: 0,
        }
    }
}

/// The transport a trigger firing travels over: an ordinary MCP
/// client call to the target member's server.
pub trait TriggerTransport {
    /// Call `tool` on the `mcp` server with `args`.
    fn call(&mut self, mcp: &str, tool: &str, args: &Value) -> Result<Value, String>;
    /// Calls recorded so far (test transports only; live
    /// transports return an empty list and rely on the audit log).
    fn recorded_calls(&self) -> Vec<(String, String, Value)> {
        Vec::new()
    }
}

/// A scripted in-memory transport for tests: records every call,
/// returns queued results (default: an acceptance echo).
#[derive(Debug, Default)]
pub struct FakeTransport {
    /// Every `(mcp, tool, args)` call, in order.
    pub calls: Vec<(String, String, Value)>,
    /// Scripted results for successive calls.
    pub results: VecDeque<Result<Value, String>>,
}

impl TriggerTransport for FakeTransport {
    fn call(&mut self, mcp: &str, tool: &str, args: &Value) -> Result<Value, String> {
        self.calls
            .push((mcp.to_string(), tool.to_string(), args.clone()));
        self.results
            .pop_front()
            .unwrap_or_else(|| Ok(json!({"accepted": true})))
    }

    fn recorded_calls(&self) -> Vec<(String, String, Value)> {
        self.calls.clone()
    }
}

/// The rung-1 production transport: no live cross-MCP client is
/// wired yet, so every firing attempt refuses with the reason —
/// recorded in the audit log, never silently dropped or faked.
pub struct UnavailableTransport;

impl TriggerTransport for UnavailableTransport {
    fn call(&mut self, _mcp: &str, _tool: &str, _args: &Value) -> Result<Value, String> {
        Err("no live trigger transport wired in rung 1 (fake-transport tested only)".to_string())
    }
}

/// The rule engine: evaluates events against the declared rules,
/// fires through its transport, and keeps the audit tail.
pub struct TriggerEngine {
    rules: Vec<TriggerRule>,
    fired_keys: HashSet<String>,
    audit: VecDeque<String>,
    transport: Box<dyn TriggerTransport>,
    /// Plan-mode proposals awaiting operator approval.
    pub pending: Vec<Value>,
}

impl TriggerEngine {
    /// An engine over `rules` firing through `transport`.
    pub fn new(rules: Vec<TriggerRule>, transport: Box<dyn TriggerTransport>) -> TriggerEngine {
        TriggerEngine {
            rules,
            fired_keys: HashSet::new(),
            audit: VecDeque::new(),
            transport,
            pending: Vec::new(),
        }
    }

    /// The declared rules, as the Fleet panel lists them.
    pub fn rules(&self) -> &[TriggerRule] {
        &self.rules
    }

    /// Disable or enable one rule by id (Fleet panel; immediate).
    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) -> bool {
        match self.rules.iter_mut().find(|rule| rule.id == rule_id) {
            Some(rule) => {
                rule.enabled = enabled;
                true
            }
            None => false,
        }
    }

    /// The audit tail (JSON lines, oldest first).
    pub fn audit_lines(&self) -> Vec<String> {
        self.audit.iter().cloned().collect()
    }

    /// Calls the transport has recorded (test observability).
    pub fn transport_calls(&self) -> Vec<(String, String, Value)> {
        self.transport.recorded_calls()
    }

    fn audit(&mut self, entry: Value) {
        if self.audit.len() >= AUDIT_LINES_MAX {
            self.audit.pop_front();
        }
        self.audit.push_back(entry.to_string());
    }

    /// Evaluate one event against every rule. Returns the audit
    /// entries this evaluation produced.
    pub fn evaluate(&mut self, event: &FleetEvent) -> Vec<Value> {
        let mut entries = Vec::new();
        let matched: Vec<TriggerRule> = self
            .rules
            .iter()
            .filter(|rule| rule.enabled && rule.event == event.name)
            .cloned()
            .collect();
        for rule in matched {
            let entry = self.evaluate_one(&rule, event);
            self.audit(entry.clone());
            entries.push(entry);
        }
        entries
    }

    fn evaluate_one(&mut self, rule: &TriggerRule, event: &FleetEvent) -> Value {
        let base = json!({
            "rule": rule.id,
            "event": event.name,
            "origin_lane": rule.origin_lane,
            "content_label": rule.content_label,
        });
        if event.depth > rule.max_depth {
            return merge(
                base,
                json!({"outcome": "dropped-depth",
                "detail": format!("event depth {} > max_depth {}", event.depth, rule.max_depth)}),
            );
        }
        if let Some(clause) = &rule.where_clause {
            match eval_where(clause, &event.payload) {
                Ok(true) => {}
                Ok(false) => {
                    return merge(
                        base,
                        json!({"outcome": "no-match",
                        "detail": format!("where {clause} is false")}),
                    );
                }
                Err(e) => {
                    return merge(
                        base,
                        json!({"outcome": "refused-predicate",
                        "detail": e}),
                    );
                }
            }
        }
        let key = firing_key(rule, event);
        if self.fired_keys.contains(&key) {
            return merge(
                base,
                json!({"outcome": "dropped-duplicate",
                "detail": "event-hash already fired"}),
            );
        }
        let args = candidate_args(rule, event);
        match rule.mode {
            RuleMode::Plan => {
                self.pending.push(json!({
                    "rule": rule.id, "mcp": rule.target_mcp,
                    "tool": rule.target_tool, "args": args,
                }));
                merge(
                    base,
                    json!({"outcome": "plan-pending",
                    "detail": "staged for operator approval; nothing fired"}),
                )
            }
            RuleMode::Auto => match self
                .transport
                .call(&rule.target_mcp, &rule.target_tool, &args)
            {
                Ok(_) => {
                    self.fired_keys.insert(key);
                    merge(
                        base,
                        json!({"outcome": "fired",
                        "target": format!("{}.{}", rule.target_mcp, rule.target_tool)}),
                    )
                }
                Err(e) => merge(
                    base,
                    json!({"outcome": "fire-failed",
                    "detail": e}),
                ),
            },
        }
    }
}

fn merge(mut base: Value, extra: Value) -> Value {
    if let (Some(base_obj), Some(extra_obj)) = (base.as_object_mut(), extra.as_object()) {
        for (key, value) in extra_obj {
            base_obj.insert(key.clone(), value.clone());
        }
    }
    base
}

/// The idempotency key: hash of (rule id, canonical event payload).
fn firing_key(rule: &TriggerRule, event: &FleetEvent) -> String {
    let material = format!("{}|{}|{}", rule.id, event.name, event.payload);
    sha256_hex(material.as_bytes())
}

/// Build the lesson-candidate arguments from the event: the draft
/// summary plus the rule's birth labels (BLOCH lane law: labels
/// ride from birth, never added later).
pub fn candidate_args(rule: &TriggerRule, event: &FleetEvent) -> Value {
    let dist_hash = event
        .payload
        .get("dist_hash")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let result = event
        .payload
        .get("result")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    json!({
        "origin_lane": rule.origin_lane,
        "content_label": rule.content_label,
        "event": event.name,
        "summary": format!(
            "broadside {event_name} completed: result {result}, dist_hash {dist_hash}",
            event_name = event.name
        ),
        "dist_hash": dist_hash,
        "result": result,
        "receipt_seq": event.payload.get("receipt_seq").cloned().unwrap_or(Value::Null),
    })
}

// ---------------------------------------------------------------------
// The bounded `where` predicate: comparisons joined by &&.
// ---------------------------------------------------------------------

#[derive(Debug, PartialEq)]
struct Comparison {
    field: String,
    op: String,
    literal: Literal,
}

#[derive(Debug, PartialEq)]
enum Literal {
    Text(String),
    Number(f64),
}

fn parse_where(clause: &str) -> Result<Vec<Comparison>, String> {
    if clause.len() > 512 {
        return Err("where clause exceeds 512 bytes".to_string());
    }
    let mut comparisons = Vec::new();
    for term in clause.split("&&") {
        comparisons.push(parse_comparison(term.trim())?);
        if comparisons.len() > 8 {
            return Err("where clause exceeds 8 comparisons".to_string());
        }
    }
    Ok(comparisons)
}

fn parse_comparison(term: &str) -> Result<Comparison, String> {
    for op in ["==", "!=", ">=", "<=", ">", "<"] {
        if let Some(pos) = term.find(op) {
            let field = term[..pos].trim().to_string();
            let raw = term[pos + op.len()..].trim();
            if field.is_empty() || raw.is_empty() {
                return Err(format!("malformed comparison {term:?}"));
            }
            let literal =
                if let Some(stripped) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
                    Literal::Text(stripped.to_string())
                } else if let Ok(number) = raw.parse::<f64>() {
                    Literal::Number(number)
                } else {
                    Literal::Text(raw.to_string())
                };
            return Ok(Comparison {
                field,
                op: op.to_string(),
                literal,
            });
        }
    }
    Err(format!("comparison {term:?} has no operator"))
}

/// Evaluate a `where` clause against an event payload. Missing
/// fields and type mismatches are `false` (no match), never errors
/// that could be mistaken for a match.
pub fn eval_where(clause: &str, payload: &Value) -> Result<bool, String> {
    for comparison in parse_where(clause)? {
        if !eval_comparison(&comparison, payload) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn eval_comparison(comparison: &Comparison, payload: &Value) -> bool {
    let Some(actual) = payload.get(&comparison.field) else {
        return false;
    };
    match (&comparison.literal, actual) {
        (Literal::Number(want), Value::Number(got)) => {
            let Some(got) = got.as_f64() else {
                return false;
            };
            compare_ordered(&comparison.op, got.partial_cmp(want))
        }
        (Literal::Text(want), Value::String(got)) => match comparison.op.as_str() {
            "==" => got == want,
            "!=" => got != want,
            _ => false,
        },
        (Literal::Text(want), Value::Bool(got)) => match comparison.op.as_str() {
            "==" => got.to_string() == *want,
            "!=" => got.to_string() != *want,
            _ => false,
        },
        _ => false,
    }
}

fn compare_ordered(op: &str, ordering: Option<std::cmp::Ordering>) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    matches!(
        (op, ordering),
        ("==", Some(Equal))
            | ("!=", Some(Less | Greater))
            | (">", Some(Greater))
            | ("<", Some(Less))
            | (">=", Some(Greater | Equal))
            | ("<=", Some(Less | Equal))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with(fake: FakeTransport) -> TriggerEngine {
        let rules = parse_rules(DEFAULT_TRIGGERS_TOML).expect("shipped rules parse");
        TriggerEngine::new(rules, Box::new(fake))
    }

    fn deploy_event() -> FleetEvent {
        FleetEvent::new(
            "deploy.verified",
            json!({"result": "pass", "dist_hash": "abc123", "receipt_seq": 5}),
        )
    }

    #[test]
    fn shipped_rule_has_lane_law_birth_labels() {
        let rules = parse_rules(DEFAULT_TRIGGERS_TOML).expect("parse");
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.origin_lane, "qompass");
        assert_eq!(rule.content_label, "sfw");
        assert_eq!(rule.target_mcp, "bloch");
        assert_eq!(rule.target_tool, "lesson_candidate");
        assert_eq!(rule.mode, RuleMode::Auto);
        assert_eq!(rule.max_depth, 1);
    }

    #[test]
    fn deploy_verified_fires_lesson_candidate_via_fake_transport() {
        let mut engine = engine_with(FakeTransport::default());
        let entries = engine.evaluate(&deploy_event());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["outcome"], json!("fired"));
        assert_eq!(entries[0]["origin_lane"], json!("qompass"));
        assert_eq!(entries[0]["content_label"], json!("sfw"));
        let calls = engine.transport_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "bloch");
        assert_eq!(calls[0].1, "lesson_candidate");
        assert_eq!(calls[0].2["origin_lane"], json!("qompass"));
        assert_eq!(calls[0].2["content_label"], json!("sfw"));
        assert_eq!(calls[0].2["dist_hash"], json!("abc123"));
    }

    #[test]
    fn duplicate_event_never_refires() {
        let mut engine = engine_with(FakeTransport::default());
        engine.evaluate(&deploy_event());
        let second = engine.evaluate(&deploy_event());
        assert_eq!(second[0]["outcome"], json!("dropped-duplicate"));
        assert_eq!(engine.transport_calls().len(), 1);
    }

    #[test]
    fn failed_deploy_does_not_fire() {
        let mut engine = engine_with(FakeTransport::default());
        let event = FleetEvent::new(
            "deploy.verified",
            json!({"result": "fail", "dist_hash": "abc123"}),
        );
        let entries = engine.evaluate(&event);
        assert_eq!(entries[0]["outcome"], json!("no-match"));
        assert!(engine.transport_calls().is_empty());
    }

    #[test]
    fn depth_beyond_max_is_dropped() {
        // Adversarial: a triggered event re-entering at depth 2
        // must not fire a max_depth-1 rule (no trigger chains).
        let mut engine = engine_with(FakeTransport::default());
        let mut event = deploy_event();
        event.depth = 2;
        let entries = engine.evaluate(&event);
        assert_eq!(entries[0]["outcome"], json!("dropped-depth"));
        assert!(engine.transport_calls().is_empty());
    }

    #[test]
    fn disabled_rule_does_not_fire() {
        let mut engine = engine_with(FakeTransport::default());
        let id = engine.rules()[0].id.clone();
        assert!(engine.set_rule_enabled(&id, false));
        assert!(engine.evaluate(&deploy_event()).is_empty());
        assert!(engine.transport_calls().is_empty());
    }

    #[test]
    fn transport_failure_is_audited_not_marked_fired() {
        let mut fake = FakeTransport::default();
        fake.results.push_back(Err("bloch unreachable".to_string()));
        fake.results.push_back(Ok(json!({"accepted": true})));
        let mut engine = engine_with(fake);
        let first = engine.evaluate(&deploy_event());
        assert_eq!(first[0]["outcome"], json!("fire-failed"));
        // Not marked fired: the same event may retry and succeed.
        let second = engine.evaluate(&deploy_event());
        assert_eq!(second[0]["outcome"], json!("fired"));
        assert_eq!(engine.transport_calls().len(), 2);
    }

    #[test]
    fn unavailable_transport_refuses_honestly() {
        let rules = parse_rules(DEFAULT_TRIGGERS_TOML).expect("parse");
        let mut engine = TriggerEngine::new(rules, Box::new(UnavailableTransport));
        let entries = engine.evaluate(&deploy_event());
        assert_eq!(entries[0]["outcome"], json!("fire-failed"));
        let detail = entries[0]["detail"].as_str().unwrap_or_default();
        assert!(detail.contains("no live trigger transport"), "{detail}");
    }

    #[test]
    fn malformed_rules_fail_closed_at_load() {
        // Adversarial: depth over the hard ceiling, an unknown
        // mode, and a broken predicate are all load errors.
        let depth = DEFAULT_TRIGGERS_TOML.replace("max_depth = 1", "max_depth = 3");
        assert!(parse_rules(&depth).is_err());
        let mode = DEFAULT_TRIGGERS_TOML.replace("mode = \"auto\"", "mode = \"yolo\"");
        assert!(parse_rules(&mode).is_err());
        let pred = DEFAULT_TRIGGERS_TOML.replace("result == pass", "result pass");
        assert!(parse_rules(&pred).is_err());
    }

    #[test]
    fn where_predicates_compare_named_fields_only() {
        let payload = json!({"result": "pass", "error_count": 3});
        assert!(eval_where("result == pass", &payload).expect("eval"));
        assert!(eval_where("error_count > 0", &payload).expect("eval"));
        assert!(eval_where("result == pass && error_count >= 3", &payload).expect("eval"));
        assert!(!eval_where("result == fail", &payload).expect("eval"));
        // Missing fields never match.
        assert!(!eval_where("missing == pass", &payload).expect("eval"));
    }
}

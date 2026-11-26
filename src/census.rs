//! The census module (CENSUS.md C1–C5): a classified record of
//! every bot that operates against the site, computed from one
//! bounded window of the host access log.
//!
//! Design rules that shape this module (from the spec):
//!
//! - The census observes; it never triggers. Nothing here feeds
//!   H4, plants bait, or issues the H1 HIGH receipt — canary hits
//!   are flagged in the document, and the HIGH receipt stays
//!   vongola's live-check finding.
//! - Fail closed on the window: a truncated, unreadable, or
//!   oversized log window fails the run with a receipt saying so.
//!   A partial census is never presented as a whole one.
//! - Deterministic: the same window inputs (log bytes, robots.txt
//!   bytes, canary list, previous census) produce a byte-identical
//!   census document. The document carries no wall-clock fields;
//!   its window is anchored at the newest log entry in the slice.
//! - No credentials, no signing material. Identity verification
//!   runs behind the `Resolver` seam; census_dns.rs is the
//!   production implementation and tests fixture the seam, so the
//!   gate suite performs no live DNS.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use serde_json::{Value, json};

use crate::config::{Config, HOST_ACCESS_LOG, PROD_HOST};
use crate::crypto::sha256_hex;
use crate::honeypot;
use crate::http;
use crate::proc::{run_bounded, tail};
use crate::receipts::gate;

/// Deadline for the SSH log-slice fetch (the canary read-back's
/// 120 s step deadline is too tight for a 30-day tail).
const FETCH_DEADLINE: Duration = Duration::from_secs(300);

/// Named bounds for one census run (spec: Bounds and failure
/// behaviour). Tests shrink these; production uses `Default`.
#[derive(Clone, Copy, Debug)]
pub struct CensusCaps {
    /// A log window larger than this is refused whole. Kept below
    /// proc.rs's 8 MiB capture bound so a fetched slice can never
    /// be silently truncated upstream of this check.
    pub max_window_bytes: usize,
    /// Species table cap; saturation is counted in the document.
    pub max_species: usize,
    /// Session table cap; saturation is counted in the document.
    pub max_sessions: usize,
    /// Inactivity gap that ends a session, in seconds.
    pub session_gap_secs: u64,
    /// DNS verification budget for one run (distinct species/IP
    /// pairs checked); pairs past the budget stay UNVERIFIED.
    pub dns_budget: usize,
}

impl Default for CensusCaps {
    fn default() -> Self {
        CensusCaps {
            max_window_bytes: 4 * 1024 * 1024,
            max_species: 512,
            max_sessions: 100_000,
            session_gap_secs: 1_800,
            dns_budget: 256,
        }
    }
}

/// The window selector for `broadside_census`. The window is
/// anchored at the newest entry of the fetched log slice, not at
/// the wall clock — that is what makes a re-run over the same
/// slice byte-identical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowKind {
    Hour,
    Day,
    Rollup30,
}

impl WindowKind {
    pub fn parse(text: &str) -> Result<WindowKind, String> {
        match text {
            "hour" => Ok(WindowKind::Hour),
            "day" => Ok(WindowKind::Day),
            "30d" => Ok(WindowKind::Rollup30),
            other => Err(format!(
                "unknown census window {other:?} (want hour|day|30d)"
            )),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            WindowKind::Hour => "hour",
            WindowKind::Day => "day",
            WindowKind::Rollup30 => "30d",
        }
    }

    pub fn span_secs(&self) -> u64 {
        match self {
            WindowKind::Hour => 3_600,
            WindowKind::Day => 86_400,
            WindowKind::Rollup30 => 30 * 86_400,
        }
    }

    /// Log-slice size to fetch per window (tail lines over SSH).
    fn fetch_lines(&self) -> usize {
        match self {
            WindowKind::Hour => 20_000,
            WindowKind::Day => 100_000,
            WindowKind::Rollup30 => 200_000,
        }
    }
}

/// DNS seam for Passport Control (C3). `Err` means the check could
/// not be run (transport failure, timeout, no resolver) and the
/// session stays UNVERIFIED; `Ok(None)` / `Ok` of an empty vec
/// means the lookup ran and found nothing — a definitive answer
/// the caller may act on.
pub trait Resolver {
    /// Reverse lookup: the PTR hostname for `ip`, if one exists.
    fn ptr(&self, ip: &str) -> Result<Option<String>, String>;
    /// Forward lookup: every address `host` resolves to.
    fn forward(&self, host: &str) -> Result<Vec<String>, String>;
}

/// Everything one census computation consumes. The document is a
/// pure function of these inputs plus the caps and the resolver's
/// answers.
pub struct CensusInputs {
    pub window: WindowKind,
    pub log_text: String,
    pub robots_txt: String,
    /// Canary paths from the signed honeypot manifest (read-only).
    /// Used only to flag touches; never written into the document.
    pub canary_paths: Vec<String>,
    /// Species → sessions in the previous census, for movement.
    pub previous_species_sessions: Option<BTreeMap<String, u64>>,
}

// ---------------------------------------------------------------------------
// C1 — log parsing and species identification
// ---------------------------------------------------------------------------

/// One parsed access-log line (Caddy JSON access log shape).
struct LogEntry {
    ts: u64,
    ip: String,
    path: String,
    user_agent: String,
    bytes: u64,
}

/// Parse one Caddy JSON access-log line. `None` = malformed: the
/// caller counts it, never drops it silently, never fails on it.
/// A missing User-Agent is not malformed (real requests omit it);
/// it files as an empty claim.
fn parse_log_line(line: &str) -> Option<LogEntry> {
    let v: Value = serde_json::from_str(line).ok()?;
    let ts = v.get("ts")?.as_f64()?;
    if !ts.is_finite() || ts < 0.0 {
        return None;
    }
    let req = v.get("request")?;
    let ip = req
        .get("client_ip")
        .and_then(Value::as_str)
        .or_else(|| req.get("remote_ip").and_then(Value::as_str))?;
    let path = req.get("uri").and_then(Value::as_str)?;
    let user_agent = req
        .get("headers")
        .and_then(|h| h.get("User-Agent"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let bytes = v.get("size").and_then(Value::as_u64).unwrap_or(0);
    Some(LogEntry {
        ts: ts as u64,
        ip: ip.to_string(),
        path: path.to_string(),
        user_agent,
        bytes,
    })
}

/// User-agent token (lowercase) → canonical species name. Order
/// matters: specific tokens are tested before the generic
/// fallbacks in `identify_species`.
const SPECIES_TOKENS: &[(&str, &str)] = &[
    ("googlebot", "Googlebot"),
    ("bingbot", "Bingbot"),
    ("applebot", "Applebot"),
    ("duckduckbot", "DuckDuckBot"),
    ("yandexbot", "YandexBot"),
    ("baiduspider", "Baiduspider"),
    ("gptbot", "GPTBot"),
    ("oai-searchbot", "OAI-SearchBot"),
    ("chatgpt-user", "ChatGPT-User"),
    ("claudebot", "ClaudeBot"),
    ("claude-user", "Claude-User"),
    ("anthropic-ai", "anthropic-ai"),
    ("amazonbot", "Amazonbot"),
    ("meta-webindexer", "Meta-WebIndexer"),
    ("meta-externalagent", "Meta-ExternalAgent"),
    ("facebookexternalhit", "facebookexternalhit"),
    ("twitterbot", "Twitterbot"),
    ("linkedinbot", "LinkedInBot"),
    ("ahrefsbot", "AhrefsBot"),
    ("semrushbot", "SemrushBot"),
    ("dotbot", "DotBot"),
    ("mj12bot", "MJ12bot"),
    ("dataforseobot", "DataForSeoBot"),
    ("perplexitybot", "PerplexityBot"),
    ("ccbot", "CCBot"),
    ("bytespider", "Bytespider"),
    ("petalbot", "PetalBot"),
    ("censysinspect", "CensysInspect"),
    ("zgrab", "zgrab"),
    ("masscan", "masscan"),
    ("headlesschrome", "HeadlessChrome"),
    ("python-requests", "python-requests"),
    ("python-urllib", "python-urllib"),
    ("go-http-client", "Go-http-client"),
    ("apache-httpclient", "Apache-HttpClient"),
    ("aiohttp", "aiohttp"),
    ("httpx", "httpx"),
    ("okhttp", "okhttp"),
    ("scrapy", "Scrapy"),
    ("curl", "curl"),
    ("wget", "Wget"),
    ("nmap", "nmap"),
];

/// The pseudo-species a session is filed under when its claimed
/// identity fails Passport Control (C3).
pub const IMPOSTOR_SPECIES: &str = "Impostor";
/// The pseudo-species for requests claiming nothing recognisable.
pub const UNPLACED_SPECIES: &str = "Unplaced";
/// The pseudo-species for ordinary browser user-agents. Browsers
/// are counted in the window totals only; they never appear in
/// the census species table (the orders classify bots).
pub const BROWSER_SPECIES: &str = "Browser";

/// The normalised identity a user-agent claims: a known species
/// token, else the product token of a `(compatible; X/…)` claim,
/// else Browser for a plain browser agent, else Unplaced.
pub fn identify_species(user_agent: &str) -> String {
    let lower = user_agent.to_lowercase();
    for (token, species) in SPECIES_TOKENS {
        if lower.contains(token) {
            return (*species).to_string();
        }
    }
    if let Some(claim) = compatible_claim(user_agent) {
        return claim;
    }
    if lower.contains("mozilla/")
        && (lower.contains("chrome/")
            || lower.contains("safari/")
            || lower.contains("firefox/")
            || lower.contains("applewebkit/"))
    {
        return BROWSER_SPECIES.to_string();
    }
    UNPLACED_SPECIES.to_string()
}

/// Extract the product token from `(compatible; Token/1.0; …)`.
fn compatible_claim(user_agent: &str) -> Option<String> {
    let lower = user_agent.to_lowercase();
    let start = lower.find("compatible;")? + "compatible;".len();
    let rest = user_agent[start..].trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .collect();
    if token.len() >= 2 && token.chars().any(|c| c.is_ascii_alphabetic()) {
        Some(token)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// C2 — orders: classification by behaviour, as data with a basis
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    Searchers,
    Learners,
    Surveyors,
    Couriers,
    Burglars,
    Strays,
}

impl Order {
    pub fn as_str(&self) -> &'static str {
        match self {
            Order::Searchers => "Searchers",
            Order::Learners => "Learners",
            Order::Surveyors => "Surveyors",
            Order::Couriers => "Couriers",
            Order::Burglars => "Burglars",
            Order::Strays => "Strays",
        }
    }
}

/// Species → (order, basis). The basis states what the
/// classification rests on (claimed identity, operator programme);
/// it is estate-side data, reviewed when behaviour changes —
/// never a claim about intent beyond what requests show.
const ORDER_TABLE: &[(&str, Order, &str)] = &[
    (
        "Googlebot",
        Order::Searchers,
        "operator search crawler (Google); fetches indexable pages and robots.txt",
    ),
    (
        "Bingbot",
        Order::Searchers,
        "operator search crawler (Microsoft)",
    ),
    (
        "Applebot",
        Order::Searchers,
        "operator search crawler (Apple)",
    ),
    (
        "DuckDuckBot",
        Order::Searchers,
        "operator search crawler (DuckDuckGo)",
    ),
    (
        "YandexBot",
        Order::Searchers,
        "operator search crawler (Yandex)",
    ),
    (
        "Baiduspider",
        Order::Searchers,
        "operator search crawler (Baidu)",
    ),
    (
        "GPTBot",
        Order::Learners,
        "operator AI-training crawler (OpenAI)",
    ),
    (
        "OAI-SearchBot",
        Order::Learners,
        "operator AI search crawler (OpenAI)",
    ),
    (
        "ClaudeBot",
        Order::Learners,
        "operator AI-training crawler (Anthropic)",
    ),
    (
        "anthropic-ai",
        Order::Learners,
        "operator AI crawler (Anthropic)",
    ),
    (
        "Amazonbot",
        Order::Learners,
        "operator AI/search crawler (Amazon)",
    ),
    (
        "Meta-WebIndexer",
        Order::Learners,
        "operator AI indexing crawler (Meta)",
    ),
    (
        "Meta-ExternalAgent",
        Order::Learners,
        "operator AI fetch agent (Meta)",
    ),
    (
        "PerplexityBot",
        Order::Learners,
        "operator AI search crawler (Perplexity)",
    ),
    (
        "CCBot",
        Order::Learners,
        "Common Crawl corpus crawler; its corpus feeds AI training",
    ),
    (
        "AhrefsBot",
        Order::Surveyors,
        "SEO measurement crawler (Ahrefs)",
    ),
    (
        "SemrushBot",
        Order::Surveyors,
        "SEO measurement crawler (Semrush)",
    ),
    ("DotBot", Order::Surveyors, "SEO measurement crawler (Moz)"),
    (
        "MJ12bot",
        Order::Surveyors,
        "SEO measurement crawler (Majestic)",
    ),
    (
        "DataForSeoBot",
        Order::Surveyors,
        "SEO measurement crawler (DataForSEO)",
    ),
    (
        "facebookexternalhit",
        Order::Couriers,
        "link-preview fetcher (Meta); fetches on a user's behalf",
    ),
    (
        "Twitterbot",
        Order::Couriers,
        "link-preview fetcher (X); fetches on a user's behalf",
    ),
    (
        "LinkedInBot",
        Order::Couriers,
        "link-preview fetcher (LinkedIn); fetches on a user's behalf",
    ),
    (
        "ChatGPT-User",
        Order::Couriers,
        "fetches pages on behalf of a ChatGPT user request",
    ),
    (
        "Claude-User",
        Order::Couriers,
        "fetches pages on behalf of a Claude user request",
    ),
    (
        "curl",
        Order::Strays,
        "command-line HTTP tool; no operator crawling programme",
    ),
    (
        "Wget",
        Order::Strays,
        "command-line HTTP tool; no operator crawling programme",
    ),
    (
        "python-requests",
        Order::Strays,
        "HTTP library user-agent; the programme behind it is undeclared",
    ),
    (
        "python-urllib",
        Order::Strays,
        "HTTP library user-agent; the programme behind it is undeclared",
    ),
    (
        "Go-http-client",
        Order::Strays,
        "HTTP library user-agent; the programme behind it is undeclared",
    ),
    (
        "aiohttp",
        Order::Strays,
        "HTTP library user-agent; the programme behind it is undeclared",
    ),
    (
        "httpx",
        Order::Strays,
        "HTTP library user-agent; the programme behind it is undeclared",
    ),
    (
        "okhttp",
        Order::Strays,
        "HTTP library user-agent; the programme behind it is undeclared",
    ),
    (
        "Apache-HttpClient",
        Order::Strays,
        "HTTP library user-agent; the programme behind it is undeclared",
    ),
    (
        "HeadlessChrome",
        Order::Strays,
        "headless browser; the driver behind it is undeclared",
    ),
    (
        "Scrapy",
        Order::Strays,
        "scraping framework; the programme behind it is undeclared",
    ),
    (
        "zgrab",
        Order::Strays,
        "internet-wide scanner banner grabber",
    ),
    (
        "CensysInspect",
        Order::Strays,
        "internet measurement scanner (Censys)",
    ),
    ("masscan", Order::Strays, "internet-wide port scanner"),
    ("nmap", Order::Strays, "network scanner scripting engine"),
];

fn order_table_entry(species: &str) -> Option<(Order, &'static str)> {
    ORDER_TABLE
        .iter()
        .find(|(name, _, _)| *name == species)
        .map(|(_, order, basis)| (*order, *basis))
}

/// Path markers of hostile probing (secret-seeking, login
/// knocking, vulnerability scanning). Observed probing is the
/// Burglars basis — behaviour, not identity.
const HOSTILE_MARKERS: &[&str] = &[
    "/.env",
    "/.git",
    "/.aws",
    "/.svn",
    "/wp-login",
    "/wp-admin",
    "/phpmyadmin",
    "/config.php",
    "/backup",
    ".sql",
    "/actuator",
    "/vendor/phpunit",
    "/server-status",
    "/.ds_store",
];

fn path_is_hostile(path: &str) -> bool {
    let lower = path.to_lowercase();
    HOSTILE_MARKERS.iter().any(|m| lower.contains(m))
}

// ---------------------------------------------------------------------------
// C3 — Passport Control: forward-confirmed reverse DNS
// ---------------------------------------------------------------------------

/// Species whose operators publish an FCrDNS verification method,
/// with the domains a genuine PTR must sit under.
const VERIFY_DOMAINS: &[(&str, &[&str])] = &[
    ("Googlebot", &["googlebot.com", "google.com"]),
    ("Bingbot", &["search.msn.com"]),
    ("Applebot", &["applebot.apple.com"]),
    ("DuckDuckBot", &["duckduckgo.com"]),
    ("YandexBot", &["yandex.com", "yandex.net", "yandex.ru"]),
    ("Baiduspider", &["baidu.com", "baidu.jp"]),
];

fn verify_domains(species: &str) -> Option<&'static [&'static str]> {
    VERIFY_DOMAINS
        .iter()
        .find(|(name, _)| *name == species)
        .map(|(_, domains)| *domains)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CheckOutcome {
    Verified,
    /// No published method, the budget ran out, or the check
    /// could not be run — stated as unverified, never rounded up.
    Unverified,
    /// The session claims a verifiable identity and the check
    /// ran and failed.
    Impostor,
}

/// Check one (species, ip) pair. A missing PTR or a PTR outside
/// the operator's domains is a ran-and-failed check (Impostor):
/// a genuine major crawler always publishes a PTR. A transport
/// failure is could-not-run (Unverified).
fn check_identity(resolver: &dyn Resolver, species: &str, ip: &str) -> CheckOutcome {
    let Some(domains) = verify_domains(species) else {
        return CheckOutcome::Unverified;
    };
    let host = match resolver.ptr(ip) {
        Err(_) => return CheckOutcome::Unverified,
        Ok(None) => return CheckOutcome::Impostor,
        Ok(Some(host)) => host,
    };
    let host = host.trim_end_matches('.').to_lowercase();
    let under_operator = domains
        .iter()
        .any(|d| host == *d || host.ends_with(&format!(".{d}")));
    if !under_operator {
        return CheckOutcome::Impostor;
    }
    match resolver.forward(&host) {
        Err(_) => CheckOutcome::Unverified,
        Ok(addrs) => {
            if addrs.iter().any(|a| a == ip) {
                CheckOutcome::Verified
            } else {
                CheckOutcome::Impostor
            }
        }
    }
}

// ---------------------------------------------------------------------------
// C4 — robots.txt stamps
// ---------------------------------------------------------------------------

/// One robots.txt group: (user-agent tokens, rules), where a
/// rule is (is_allow, path prefix).
type RobotsGroup = (Vec<String>, Vec<(bool, String)>);

/// Parsed robots.txt: groups in file order.
struct RobotsRules {
    groups: Vec<RobotsGroup>,
}

fn parse_robots(text: &str) -> RobotsRules {
    let mut groups: Vec<RobotsGroup> = Vec::new();
    let mut current: Option<usize> = None;
    let mut group_has_rules = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim().to_string();
        match key.as_str() {
            "user-agent" => {
                if current.is_none() || group_has_rules {
                    groups.push((Vec::new(), Vec::new()));
                    current = Some(groups.len() - 1);
                    group_has_rules = false;
                }
                if let Some(idx) = current {
                    groups[idx].0.push(value.to_lowercase());
                }
            }
            "allow" | "disallow" => {
                if let Some(idx) = current
                    && !value.is_empty()
                {
                    groups[idx].1.push((key == "allow", value));
                    group_has_rules = true;
                }
            }
            _ => {}
        }
    }
    RobotsRules { groups }
}

impl RobotsRules {
    /// Is `path` disallowed for the species' product token?
    /// Group selection: the species' own group, else the `*`
    /// group. Decision: longest matching prefix wins, Allow
    /// breaks ties (RFC 9309).
    fn disallows(&self, species: &str, path: &str) -> bool {
        let token = species.to_lowercase();
        let group = self
            .groups
            .iter()
            .find(|(tokens, _)| tokens.iter().any(|t| t == &token))
            .or_else(|| {
                self.groups
                    .iter()
                    .find(|(tokens, _)| tokens.iter().any(|t| t == "*"))
            });
        let Some((_, rules)) = group else {
            return false;
        };
        let mut best: Option<(usize, bool)> = None; // (prefix len, is_allow)
        for (is_allow, prefix) in rules {
            if path.starts_with(prefix.as_str()) {
                let better = match best {
                    None => true,
                    Some((len, was_allow)) => {
                        prefix.len() > len || (prefix.len() == len && *is_allow && !was_allow)
                    }
                };
                if better {
                    best = Some((prefix.len(), *is_allow));
                }
            }
        }
        matches!(best, Some((_, false)))
    }
}

/// One stamp per species per window (C4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stamp {
    Followed,
    Defied,
    Skipped,
    Untested,
    Sent,
}

impl Stamp {
    fn as_str(&self) -> &'static str {
        match self {
            Stamp::Followed => "FOLLOWED",
            Stamp::Defied => "DEFIED",
            Stamp::Skipped => "SKIPPED",
            Stamp::Untested => "UNTESTED",
            Stamp::Sent => "SENT",
        }
    }
}

// ---------------------------------------------------------------------------
// C1/C5 — sessionize, aggregate, and the census document
// ---------------------------------------------------------------------------

struct Session {
    ip: String,
    claimed_species: String,
    start: u64,
    end: u64,
    requests: u64,
    bytes: u64,
    read_robots: bool,
    disallowed_hits: u64,
    canary_touch: bool,
    hostile_probe: bool,
}

impl Session {
    fn new(ip: String, claimed_species: String, ts: u64) -> Session {
        Session {
            ip,
            claimed_species,
            start: ts,
            end: ts,
            requests: 0,
            bytes: 0,
            read_robots: false,
            disallowed_hits: 0,
            canary_touch: false,
            hostile_probe: false,
        }
    }
}

/// The path component used for rule matching (query stripped).
fn path_only(uri: &str) -> &str {
    uri.split('?').next().unwrap_or(uri)
}

fn canary_matches(canary_paths: &[String], path: &str) -> bool {
    canary_paths.iter().any(|canary| {
        path == canary
            || (canary.ends_with('/') && path.starts_with(canary.as_str()))
            || path == canary.trim_end_matches('/')
    })
}

/// Compute the census document from the window inputs. Pure
/// apart from the resolver seam; deterministic in its inputs.
pub fn compute_census(
    inputs: &CensusInputs,
    caps: &CensusCaps,
    resolver: &dyn Resolver,
) -> Result<Value, String> {
    if inputs.log_text.len() > caps.max_window_bytes {
        return Err(format!(
            "census window refused: log slice is {} bytes, over the {}-byte cap; refusing whole rather than truncating",
            inputs.log_text.len(),
            caps.max_window_bytes
        ));
    }
    let robots = parse_robots(&inputs.robots_txt);

    // Parse + window-filter. The window is anchored at the
    // newest entry; older entries in the slice are outside the
    // requested window, not malformed.
    let mut malformed: u64 = 0;
    let mut parsed: Vec<LogEntry> = Vec::new();
    for line in inputs.log_text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_log_line(line) {
            Some(entry) => parsed.push(entry),
            None => malformed += 1,
        }
    }
    if parsed.is_empty() {
        return Err(
            "census window refused: no parseable access-log entries in the slice".to_string(),
        );
    }
    let window_end = parsed.iter().map(|e| e.ts).max().unwrap_or(0);
    let window_start = window_end.saturating_sub(inputs.window.span_secs());
    let mut entries: Vec<LogEntry> = parsed
        .into_iter()
        .filter(|e| e.ts >= window_start)
        .collect();
    entries.sort_by_key(|e| e.ts);
    let total_requests = entries.len() as u64;

    // Sessionize by (ip, user-agent), gap-bounded.
    let mut by_key: BTreeMap<(String, String), Vec<LogEntry>> = BTreeMap::new();
    for entry in entries {
        by_key
            .entry((entry.ip.clone(), entry.user_agent.clone()))
            .or_default()
            .push(entry);
    }
    let mut sessions: Vec<Session> = Vec::new();
    let mut sessions_saturated: u64 = 0;
    for ((ip, ua), group) in by_key {
        let claimed = identify_species(&ua);
        let mut current: Option<Session> = None;
        let mut key_saturated = false;
        for entry in group {
            let gap_exceeded = match &current {
                None => true,
                Some(s) => entry.ts.saturating_sub(s.end) > caps.session_gap_secs,
            };
            if gap_exceeded && !key_saturated {
                let had_current = current.is_some();
                if let Some(done) = current.take() {
                    sessions.push(done);
                }
                if sessions.len() >= caps.max_sessions {
                    // Saturation counted, not hidden: the refusal
                    // is counted once per key, and the key's
                    // remaining entries fold into its own last
                    // session (reopened) when it has one; a key
                    // with no session yet drops its entries.
                    sessions_saturated += 1;
                    key_saturated = true;
                    if had_current {
                        current = sessions.pop();
                    }
                } else {
                    current = Some(Session::new(ip.clone(), claimed.clone(), entry.ts));
                }
            }
            let Some(s) = current.as_mut() else {
                continue; // saturated key with no session: dropped, counted above
            };
            s.end = entry.ts;
            s.requests += 1;
            s.bytes += entry.bytes;
            let path = path_only(&entry.path);
            if path == "/robots.txt" {
                s.read_robots = true;
            }
            if robots.disallows(&claimed, path) {
                s.disallowed_hits += 1;
            }
            if canary_matches(&inputs.canary_paths, path) {
                s.canary_touch = true;
            }
            if path_is_hostile(path) {
                s.hostile_probe = true;
            }
        }
        if let Some(done) = current.take() {
            sessions.push(done);
        }
    }

    // Passport Control: one check per distinct (species, ip),
    // budgeted; impostor sessions are refiled under Impostor.
    let mut checks: HashMap<(String, String), CheckOutcome> = HashMap::new();
    let mut budget_used: usize = 0;
    let mut budget_exhausted: u64 = 0;
    for s in &sessions {
        if verify_domains(&s.claimed_species).is_none() {
            continue;
        }
        let key = (s.claimed_species.clone(), s.ip.clone());
        if checks.contains_key(&key) {
            continue;
        }
        if budget_used >= caps.dns_budget {
            budget_exhausted += 1;
            checks.insert(key, CheckOutcome::Unverified);
            continue;
        }
        budget_used += 1;
        let outcome = check_identity(resolver, &s.claimed_species, &s.ip);
        checks.insert(key, outcome);
    }

    // Aggregate per final species.
    struct Agg {
        sessions: u64,
        requests: u64,
        bytes: u64,
        first_seen: u64,
        last_seen: u64,
        read_robots: bool,
        disallowed_hits: u64,
        canary_touch_sessions: u64,
        hostile_probe: bool,
        verified_sessions: u64,
        unverified_sessions: u64,
        claimed_identities: BTreeMap<String, u64>,
    }
    impl Agg {
        fn new() -> Self {
            Agg {
                sessions: 0,
                requests: 0,
                bytes: 0,
                first_seen: u64::MAX,
                last_seen: 0,
                read_robots: false,
                disallowed_hits: 0,
                canary_touch_sessions: 0,
                hostile_probe: false,
                verified_sessions: 0,
                unverified_sessions: 0,
                claimed_identities: BTreeMap::new(),
            }
        }

        fn absorb(&mut self, s: &Session, outcome: CheckOutcome) {
            self.sessions += 1;
            self.requests += s.requests;
            self.bytes += s.bytes;
            self.first_seen = self.first_seen.min(s.start);
            self.last_seen = self.last_seen.max(s.end);
            self.read_robots |= s.read_robots;
            self.disallowed_hits += s.disallowed_hits;
            if s.canary_touch {
                self.canary_touch_sessions += 1;
            }
            self.hostile_probe |= s.hostile_probe;
            match outcome {
                CheckOutcome::Verified => self.verified_sessions += 1,
                CheckOutcome::Unverified => self.unverified_sessions += 1,
                CheckOutcome::Impostor => {
                    *self
                        .claimed_identities
                        .entry(s.claimed_species.clone())
                        .or_insert(0) += 1;
                }
            }
        }
    }
    let mut species: BTreeMap<String, Agg> = BTreeMap::new();
    let mut species_saturated: u64 = 0;
    let mut browser_sessions: u64 = 0;
    let mut browser_requests: u64 = 0;
    for s in &sessions {
        let outcome = checks
            .get(&(s.claimed_species.clone(), s.ip.clone()))
            .copied()
            .unwrap_or(CheckOutcome::Unverified);
        let final_species = if outcome == CheckOutcome::Impostor {
            IMPOSTOR_SPECIES.to_string()
        } else {
            s.claimed_species.clone()
        };
        if final_species == BROWSER_SPECIES {
            browser_sessions += 1;
            browser_requests += s.requests;
            continue;
        }
        // Species-table saturation: a new species past the cap
        // folds into Unplaced (counts stay whole, saturation is
        // counted in totals). The Impostor row is exempt — it is
        // one fixed row, and a security signal never folds away.
        if final_species != IMPOSTOR_SPECIES
            && !species.contains_key(&final_species)
            && species.len() >= caps.max_species
        {
            species_saturated += 1;
            species
                .entry(UNPLACED_SPECIES.to_string())
                .or_insert_with(Agg::new)
                .absorb(s, outcome);
            continue;
        }
        species
            .entry(final_species)
            .or_insert_with(Agg::new)
            .absorb(s, outcome);
    }

    // Rows: order, stamp, verification, movement.
    let mut rows: Vec<Value> = Vec::new();
    for (name, agg) in &species {
        let (order, basis) = resolve_order(name, agg.hostile_probe);
        let stamp = resolve_stamp(order, agg.read_robots, agg.disallowed_hits);
        let verification = if name == IMPOSTOR_SPECIES {
            "IMPOSTOR"
        } else if agg.verified_sessions > 0 && agg.unverified_sessions == 0 {
            "VERIFIED"
        } else if agg.verified_sessions > 0 {
            "MIXED"
        } else {
            "UNVERIFIED"
        };
        let movement = match &inputs.previous_species_sessions {
            None => "unknown",
            Some(prev) => match prev.get(name) {
                None => "new",
                Some(&before) if agg.sessions > before => "up",
                Some(&before) if agg.sessions < before => "down",
                Some(_) => "same",
            },
        };
        let mut row = json!({
            "name": name,
            "order": order.as_str(),
            "order_basis": basis,
            "sessions": agg.sessions,
            "requests": agg.requests,
            "bytes": agg.bytes,
            "first_seen": agg.first_seen,
            "last_seen": agg.last_seen,
            "movement": movement,
            "stamp": stamp.as_str(),
            "verification": verification,
            "canary_touch": agg.canary_touch_sessions > 0,
            "canary_touch_sessions": agg.canary_touch_sessions,
        });
        if name == IMPOSTOR_SPECIES {
            row["claimed_identities"] = json!(agg.claimed_identities);
        }
        rows.push(row);
    }

    let bot_requests: u64 = species.values().map(|a| a.requests).sum();
    let total_sessions: u64 = species.values().map(|a| a.sessions).sum::<u64>() + browser_sessions;
    Ok(json!({
        "kind": "broadside.census",
        "version": 1,
        "window": {
            "kind": inputs.window.as_str(),
            "start": window_start,
            "end": window_end,
            "log_sha256": sha256_hex(inputs.log_text.as_bytes()),
            "robots_sha256": sha256_hex(inputs.robots_txt.as_bytes()),
        },
        "totals": {
            "requests": total_requests,
            "bot_requests": bot_requests,
            "browser_requests": browser_requests,
            "browser_visits": browser_sessions,
            "sessions": total_sessions,
            "malformed_lines": malformed,
            "species_seen": species.len(),
            "species_saturated": species_saturated,
            "sessions_saturated": sessions_saturated,
            "verification_budget_exhausted": budget_exhausted,
        },
        "species": rows,
    }))
}

/// Order resolution (C2): the data table first; observed hostile
/// probing upgrades a Stray to Burglars (behaviour is the basis);
/// anything unclassified is a Stray with the basis stated.
fn resolve_order(species: &str, hostile_probe: bool) -> (Order, String) {
    if species == IMPOSTOR_SPECIES {
        return (
            Order::Strays,
            "claimed a verifiable identity; Passport Control verification failed".to_string(),
        );
    }
    if species == UNPLACED_SPECIES {
        if hostile_probe {
            return (
                Order::Burglars,
                "no recognisable claimed identity; observed probing of hostile paths in this window".to_string(),
            );
        }
        return (
            Order::Strays,
            "no recognisable claimed identity in the user-agent".to_string(),
        );
    }
    match order_table_entry(species) {
        Some((Order::Strays, _)) if hostile_probe => (
            Order::Burglars,
            "tool or library user-agent; observed probing of hostile paths in this window"
                .to_string(),
        ),
        Some((order, basis)) => (order, basis.to_string()),
        None => {
            if hostile_probe {
                (
                    Order::Burglars,
                    "self-declared bot token; observed probing of hostile paths in this window"
                        .to_string(),
                )
            } else {
                (
                    Order::Strays,
                    "self-declared bot token in the user-agent; no estate classification recorded"
                        .to_string(),
                )
            }
        }
    }
}

/// Stamp resolution (C4). A Courier's disallowed fetch is SENT —
/// not counted against it; a Courier with no disallowed fetch
/// stamps by the ordinary rule.
fn resolve_stamp(order: Order, read_robots: bool, disallowed_hits: u64) -> Stamp {
    if order == Order::Couriers && disallowed_hits > 0 {
        return Stamp::Sent;
    }
    match (read_robots, disallowed_hits > 0) {
        (true, true) => Stamp::Defied,
        (true, false) => Stamp::Followed,
        (false, true) => Stamp::Skipped,
        (false, false) => Stamp::Untested,
    }
}

// ---------------------------------------------------------------------------
// Public projection — built, and deliberately wired to nothing
// ---------------------------------------------------------------------------

/// The projection refuses windows that ended less than this long
/// ago (spec: at least 24 hours delayed, by construction).
pub const PROJECTION_MIN_AGE_SECS: u64 = 24 * 3_600;

/// Aggregate-only public view of a census document. The type has
/// no IP field and no canary field: leakage of either is
/// unrepresentable, not merely filtered. Per Q-CENSUS-1 the
/// generator is built but stays dark — nothing in the server
/// surface calls `project`, and publishing its output is a
/// separate Owner act.
#[derive(serde::Serialize)]
pub struct PublicProjection {
    pub window_kind: String,
    pub window_end: u64,
    pub totals: PublicTotals,
    pub orders: Vec<PublicOrderTotal>,
    pub species: Vec<PublicSpecies>,
}

#[derive(serde::Serialize)]
pub struct PublicTotals {
    pub bot_requests: u64,
    pub browser_requests: u64,
    pub species_seen: u64,
}

#[derive(serde::Serialize)]
pub struct PublicOrderTotal {
    pub order: String,
    pub species: u64,
    pub sessions: u64,
    pub requests: u64,
}

#[derive(serde::Serialize)]
pub struct PublicSpecies {
    pub name: String,
    pub order: String,
    pub sessions: u64,
    pub requests: u64,
    pub stamp: String,
    pub movement: String,
}

/// Build the public projection of a census document as of
/// `now_unix`. Refuses a window that ended less than
/// PROJECTION_MIN_AGE_SECS ago.
pub fn project(document: &Value, now_unix: u64) -> Result<PublicProjection, String> {
    let window_end = document
        .pointer("/window/end")
        .and_then(Value::as_u64)
        .ok_or("census document has no window end")?;
    if now_unix < window_end || now_unix - window_end < PROJECTION_MIN_AGE_SECS {
        return Err(format!(
            "public projection refused: window ended {window_end}, less than {PROJECTION_MIN_AGE_SECS}s before {now_unix} (24h delay is structural)"
        ));
    }
    let totals = document
        .get("totals")
        .ok_or("census document has no totals")?;
    let mut orders: BTreeMap<String, PublicOrderTotal> = BTreeMap::new();
    let mut species_rows: Vec<PublicSpecies> = Vec::new();
    if let Some(rows) = document.get("species").and_then(Value::as_array) {
        for row in rows {
            let order = row
                .get("order")
                .and_then(Value::as_str)
                .unwrap_or("Strays")
                .to_string();
            let sessions = row.get("sessions").and_then(Value::as_u64).unwrap_or(0);
            let requests = row.get("requests").and_then(Value::as_u64).unwrap_or(0);
            let total = orders.entry(order.clone()).or_insert(PublicOrderTotal {
                order: order.clone(),
                species: 0,
                sessions: 0,
                requests: 0,
            });
            total.species += 1;
            total.sessions += sessions;
            total.requests += requests;
            species_rows.push(PublicSpecies {
                name: row
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                order,
                sessions,
                requests,
                stamp: row
                    .get("stamp")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                movement: row
                    .get("movement")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    Ok(PublicProjection {
        window_kind: document
            .pointer("/window/kind")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        window_end,
        totals: PublicTotals {
            bot_requests: totals
                .get("bot_requests")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            browser_requests: totals
                .get("browser_requests")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            species_seen: totals
                .get("species_seen")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        },
        orders: orders.into_values().collect(),
        species: species_rows,
    })
}

// ---------------------------------------------------------------------------
// C5 — the tool: fetch the window, compute, receipt
// ---------------------------------------------------------------------------

/// broadside_census: run one census over the requested window and
/// append its receipt. Failures of the run itself (unreadable
/// window, missing robots.txt, refused window) append a fail
/// receipt — a partial census is never presented as a whole one.
pub fn run_census(cfg: &Config, window_text: &str) -> Result<Value, String> {
    let window = WindowKind::parse(window_text)?;
    let log = cfg.receipts();
    let mut inputs = json!({"window": window.as_str()});
    let fail = |log: &crate::receipts::ReceiptLog,
                inputs: &Value,
                reason: String|
     -> Result<Value, String> {
        log.append(json!({
            "action": "census",
            "site_head": crate::pipeline::git_state(&cfg.site_root).0,
            "inputs": inputs,
            "outputs": {},
            "gates": [gate("census_run", "fail", &reason)],
            "result": "fail",
        }))
    };

    // The log slice, through the same SSH read-back channel as
    // the canary log.
    let remote = format!("tail -n {} {HOST_ACCESS_LOG}", window.fetch_lines());
    let fetched = run_bounded(
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
        FETCH_DEADLINE,
    );
    let log_text = match fetched {
        Ok(o) if o.success || !o.stdout.trim().is_empty() => o.stdout,
        Ok(o) => {
            return fail(
                &log,
                &inputs,
                format!("host access log read failed: {}", tail(&o.stderr, 200)),
            );
        }
        Err(e) => return fail(&log, &inputs, format!("host access log read failed: {e}")),
    };
    inputs["log_sha256"] = json!(sha256_hex(log_text.as_bytes()));

    // The deployed robots.txt: stamps are computed against what
    // the site actually serves.
    let robots_url = format!("{}/robots.txt", cfg.base_url.trim_end_matches('/'));
    let robots_txt = match http::get(&robots_url) {
        Ok(fetch) if fetch.status == 200 && !fetch.truncated => {
            String::from_utf8_lossy(&fetch.body).to_string()
        }
        Ok(fetch) => {
            return fail(
                &log,
                &inputs,
                format!(
                    "deployed robots.txt unavailable (status {}, truncated {})",
                    fetch.status, fetch.truncated
                ),
            );
        }
        Err(e) => {
            return fail(
                &log,
                &inputs,
                format!("deployed robots.txt fetch failed: {e}"),
            );
        }
    };
    inputs["robots_sha256"] = json!(sha256_hex(robots_txt.as_bytes()));

    // Canary paths from the local manifest (read-only; flagging
    // only — signature verification is broadside_verify's gate,
    // and a malformed manifest fails this run closed rather than
    // silently dropping the flags).
    let (canary_paths, manifest_revision) = match honeypot::load_manifest(&cfg.site_root) {
        Ok(Some((manifest, _))) => (
            manifest
                .canaries
                .iter()
                .map(|c| c.path.clone())
                .collect::<Vec<String>>(),
            Value::String(manifest.revision.clone()),
        ),
        Ok(None) => (Vec::new(), Value::Null),
        Err(e) => return fail(&log, &inputs, format!("honeypot manifest unreadable: {e}")),
    };
    inputs["canary_manifest"] = manifest_revision;

    // Movement baseline: the previous passing census receipt's
    // document.
    let previous = match log.latest("census", Some("pass"))? {
        Some(receipt) => receipt
            .pointer("/outputs/document/species")
            .and_then(Value::as_array)
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| {
                        Some((
                            r.get("name")?.as_str()?.to_string(),
                            r.get("sessions")?.as_u64()?,
                        ))
                    })
                    .collect::<BTreeMap<String, u64>>()
            }),
        None => None,
    };

    let census_inputs = CensusInputs {
        window,
        log_text,
        robots_txt,
        canary_paths,
        previous_species_sessions: previous,
    };
    let resolver = crate::census_dns::UdpResolver::from_system();
    let document = match compute_census(&census_inputs, &CensusCaps::default(), &resolver) {
        Ok(doc) => doc,
        Err(e) => return fail(&log, &inputs, e),
    };
    let canonical = crate::canonical::canonicalize(&document)?;
    let document_sha256 = sha256_hex(canonical.as_bytes());
    let doc_dir = cfg.state_dir.join("census");
    std::fs::create_dir_all(&doc_dir)
        .map_err(|e| format!("cannot create census dir {}: {e}", doc_dir.display()))?;
    let doc_path = doc_dir.join(format!("{document_sha256}.json"));
    std::fs::write(&doc_path, format!("{canonical}\n"))
        .map_err(|e| format!("cannot write census document {}: {e}", doc_path.display()))?;

    log.append(json!({
        "action": "census",
        "site_head": crate::pipeline::git_state(&cfg.site_root).0,
        "inputs": inputs,
        "outputs": {
            "document": document,
            "document_sha256": document_sha256,
            "document_path": doc_path.to_string_lossy(),
        },
        "gates": [gate("census_run", "pass", "window computed whole; document written and hashed")],
        "result": "pass",
    }))
}

// ---------------------------------------------------------------------------
// Tests: fixture access-log suites, resolver fixtured (no live DNS)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A resolver with canned answers. `fail_all` simulates a
    /// resolver that cannot run at all (every check UNVERIFIED).
    #[derive(Default)]
    struct FixtureResolver {
        ptrs: HashMap<String, Option<String>>,
        forwards: HashMap<String, Vec<String>>,
        fail_all: bool,
    }

    impl Resolver for FixtureResolver {
        fn ptr(&self, ip: &str) -> Result<Option<String>, String> {
            if self.fail_all {
                return Err("fixture resolver down".to_string());
            }
            Ok(self.ptrs.get(ip).cloned().unwrap_or(None))
        }
        fn forward(&self, host: &str) -> Result<Vec<String>, String> {
            if self.fail_all {
                return Err("fixture resolver down".to_string());
            }
            Ok(self.forwards.get(host).cloned().unwrap_or_default())
        }
    }

    fn google_resolver() -> FixtureResolver {
        let mut r = FixtureResolver::default();
        r.ptrs.insert(
            "66.249.66.1".to_string(),
            Some("crawl-66-249-66-1.googlebot.com".to_string()),
        );
        r.forwards.insert(
            "crawl-66-249-66-1.googlebot.com".to_string(),
            vec!["66.249.66.1".to_string()],
        );
        r
    }

    const GOOGLE_UA: &str =
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    const T0: u64 = 1_799_000_000;

    /// One Caddy-shaped access-log line.
    fn line(ts: u64, ip: &str, ua: &str, uri: &str, size: u64) -> String {
        json!({
            "ts": ts as f64 + 0.25,
            "request": {
                "remote_ip": ip,
                "client_ip": ip,
                "method": "GET",
                "host": "qompass.ai",
                "uri": uri,
                "headers": {"User-Agent": [ua]},
            },
            "size": size,
            "status": 200,
        })
        .to_string()
    }

    fn inputs(log_text: String) -> CensusInputs {
        CensusInputs {
            window: WindowKind::Day,
            log_text,
            robots_txt: "User-agent: *\nDisallow: /admin/\n".to_string(),
            canary_paths: vec!["/.env".to_string(), "/wp-login.php".to_string()],
            previous_species_sessions: None,
        }
    }

    fn species_row<'a>(doc: &'a Value, name: &str) -> Option<&'a Value> {
        doc.get("species")?
            .as_array()?
            .iter()
            .find(|r| r.get("name").and_then(Value::as_str) == Some(name))
    }

    #[test]
    fn verified_major_crawler_followed() {
        let log = [
            line(T0, "66.249.66.1", GOOGLE_UA, "/robots.txt", 300),
            line(T0 + 60, "66.249.66.1", GOOGLE_UA, "/research", 5000),
            line(T0 + 120, "66.249.66.1", GOOGLE_UA, "/solutions", 4000),
        ]
        .join("\n");
        let doc = compute_census(&inputs(log), &CensusCaps::default(), &google_resolver())
            .expect("census");
        let row = species_row(&doc, "Googlebot").expect("googlebot row");
        assert_eq!(row["sessions"], json!(1));
        assert_eq!(row["requests"], json!(3));
        assert_eq!(row["verification"], json!("VERIFIED"));
        assert_eq!(row["stamp"], json!("FOLLOWED"));
        assert_eq!(row["order"], json!("Searchers"));
        assert_eq!(row["canary_touch"], json!(false));
        assert_eq!(doc["totals"]["bot_requests"], json!(3));
        assert_eq!(doc["totals"]["malformed_lines"], json!(0));
    }

    #[test]
    fn spoofed_crawler_filed_as_impostor() {
        // Adversarial: claims Googlebot from an address whose PTR
        // is not under a Google domain. The session must land on
        // Impostor and Googlebot must not appear at all.
        let log = [
            line(T0, "203.0.113.9", GOOGLE_UA, "/robots.txt", 300),
            line(T0 + 60, "203.0.113.9", GOOGLE_UA, "/research", 5000),
        ]
        .join("\n");
        let mut resolver = FixtureResolver::default();
        resolver.ptrs.insert(
            "203.0.113.9".to_string(),
            Some("static.hostile.example.net".to_string()),
        );
        let doc = compute_census(&inputs(log), &CensusCaps::default(), &resolver).expect("census");
        assert!(species_row(&doc, "Googlebot").is_none());
        let row = species_row(&doc, "Impostor").expect("impostor row");
        assert_eq!(row["sessions"], json!(1));
        assert_eq!(row["requests"], json!(2));
        assert_eq!(row["verification"], json!("IMPOSTOR"));
        assert_eq!(row["claimed_identities"]["Googlebot"], json!(1));
    }

    #[test]
    fn forward_mismatch_is_impostor() {
        // Adversarial: PTR sits under the operator domain but the
        // name does not resolve back to the source address.
        let log = line(T0, "198.51.100.7", GOOGLE_UA, "/research", 100);
        let mut resolver = FixtureResolver::default();
        resolver.ptrs.insert(
            "198.51.100.7".to_string(),
            Some("crawl-66-249-66-1.googlebot.com".to_string()),
        );
        resolver.forwards.insert(
            "crawl-66-249-66-1.googlebot.com".to_string(),
            vec!["66.249.66.1".to_string()],
        );
        let doc = compute_census(&inputs(log), &CensusCaps::default(), &resolver).expect("census");
        assert!(species_row(&doc, "Googlebot").is_none());
        assert_eq!(
            species_row(&doc, "Impostor").expect("row")["sessions"],
            json!(1)
        );
    }

    #[test]
    fn resolver_failure_is_unverified_never_impostor() {
        // Adversarial-adjacent: when the check cannot run, the
        // session is UNVERIFIED — a DNS outage must not manufacture
        // impostors.
        let log = line(T0, "66.249.66.1", GOOGLE_UA, "/research", 100);
        let resolver = FixtureResolver {
            fail_all: true,
            ..Default::default()
        };
        let doc = compute_census(&inputs(log), &CensusCaps::default(), &resolver).expect("census");
        let row = species_row(&doc, "Googlebot").expect("row");
        assert_eq!(row["verification"], json!("UNVERIFIED"));
        assert!(species_row(&doc, "Impostor").is_none());
    }

    #[test]
    fn defied_stamp_reads_rules_then_breaks_them() {
        let ua = "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)";
        let log = [
            line(T0, "185.220.101.4", ua, "/robots.txt", 300),
            line(T0 + 30, "185.220.101.4", ua, "/admin/panel", 900),
        ]
        .join("\n");
        let doc = compute_census(
            &inputs(log),
            &CensusCaps::default(),
            &FixtureResolver::default(),
        )
        .expect("census");
        let row = species_row(&doc, "SemrushBot").expect("row");
        assert_eq!(row["stamp"], json!("DEFIED"));
        assert_eq!(row["order"], json!("Surveyors"));
    }

    #[test]
    fn skipped_stamp_breaks_rules_unread() {
        let ua = "AhrefsBot/7.0; +http://ahrefs.com/robot/";
        let log = line(T0, "54.36.148.1", ua, "/admin/panel", 900);
        let doc = compute_census(
            &inputs(log),
            &CensusCaps::default(),
            &FixtureResolver::default(),
        )
        .expect("census");
        assert_eq!(
            species_row(&doc, "AhrefsBot").expect("row")["stamp"],
            json!("SKIPPED")
        );
    }

    #[test]
    fn courier_disallowed_fetch_is_sent() {
        let ua = "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)";
        let log = line(T0, "57.141.0.14", ua, "/admin/panel", 900);
        let doc = compute_census(
            &inputs(log),
            &CensusCaps::default(),
            &FixtureResolver::default(),
        )
        .expect("census");
        let row = species_row(&doc, "facebookexternalhit").expect("row");
        assert_eq!(row["stamp"], json!("SENT"));
        assert_eq!(row["order"], json!("Couriers"));
    }

    #[test]
    fn canary_touch_flagged_and_probing_stray_is_burglar() {
        // curl is a Stray by identity; fetching the canary /.env
        // is hostile probing, so the order upgrades to Burglars
        // and the session carries the canary-touch flag.
        let log = [
            line(T0, "45.148.10.7", "curl/8.5.0", "/.env", 226),
            line(T0 + 5, "45.148.10.7", "curl/8.5.0", "/wp-login.php", 1200),
        ]
        .join("\n");
        let doc = compute_census(
            &inputs(log),
            &CensusCaps::default(),
            &FixtureResolver::default(),
        )
        .expect("census");
        let row = species_row(&doc, "curl").expect("row");
        assert_eq!(row["canary_touch"], json!(true));
        assert_eq!(row["canary_touch_sessions"], json!(1));
        assert_eq!(row["order"], json!("Burglars"));
    }

    #[test]
    fn malformed_lines_counted_never_fatal() {
        let log = [
            line(T0, "66.249.66.1", GOOGLE_UA, "/research", 100),
            "this is not json".to_string(),
            "{\"ts\": \"not-a-number\"}".to_string(),
            "{\"request\": {}}".to_string(),
            String::new(),
        ]
        .join("\n");
        let doc = compute_census(&inputs(log), &CensusCaps::default(), &google_resolver())
            .expect("census");
        assert_eq!(doc["totals"]["malformed_lines"], json!(3));
        assert_eq!(doc["totals"]["requests"], json!(1));
    }

    #[test]
    fn oversized_window_refused_whole() {
        let log = line(T0, "66.249.66.1", GOOGLE_UA, "/research", 100);
        let caps = CensusCaps {
            max_window_bytes: 16,
            ..CensusCaps::default()
        };
        let err = compute_census(&inputs(log), &caps, &google_resolver()).expect_err("must refuse");
        assert!(err.contains("refused"), "error names the refusal: {err}");
    }

    #[test]
    fn empty_window_refused() {
        let err = compute_census(
            &inputs("garbage\nmore garbage".to_string()),
            &CensusCaps::default(),
            &google_resolver(),
        )
        .expect_err("must refuse");
        assert!(err.contains("no parseable"));
    }

    #[test]
    fn determinism_same_fixture_byte_identical() {
        let log = [
            line(T0, "66.249.66.1", GOOGLE_UA, "/robots.txt", 300),
            line(T0 + 60, "66.249.66.1", GOOGLE_UA, "/research", 5000),
            line(T0 + 30, "45.148.10.7", "curl/8.5.0", "/.env", 226),
            line(
                T0 + 90,
                "57.141.0.14",
                "facebookexternalhit/1.1",
                "/admin/x",
                10,
            ),
        ]
        .join("\n");
        let a = compute_census(
            &inputs(log.clone()),
            &CensusCaps::default(),
            &google_resolver(),
        )
        .expect("run a");
        let b = compute_census(&inputs(log), &CensusCaps::default(), &google_resolver())
            .expect("run b");
        assert_eq!(
            crate::canonical::canonicalize(&a).expect("canon a"),
            crate::canonical::canonicalize(&b).expect("canon b"),
        );
    }

    #[test]
    fn session_gap_bounds_sessions() {
        let ua = "python-requests/2.31.0";
        let log = [
            line(T0, "91.108.4.2", ua, "/a", 10),
            line(T0 + 600, "91.108.4.2", ua, "/b", 10), // within the 30-min gap
            line(T0 + 600 + 7_200, "91.108.4.2", ua, "/c", 10), // 2h later: new session
        ]
        .join("\n");
        let doc = compute_census(
            &inputs(log),
            &CensusCaps::default(),
            &FixtureResolver::default(),
        )
        .expect("census");
        let row = species_row(&doc, "python-requests").expect("row");
        assert_eq!(row["sessions"], json!(2));
        assert_eq!(row["requests"], json!(3));
    }

    #[test]
    fn browser_traffic_counts_in_totals_only() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";
        let log = [
            line(T0, "192.0.2.55", ua, "/", 8000),
            line(T0 + 60, "192.0.2.55", ua, "/research", 5000),
        ]
        .join("\n");
        let doc = compute_census(
            &inputs(log),
            &CensusCaps::default(),
            &FixtureResolver::default(),
        )
        .expect("census");
        assert_eq!(doc["totals"]["browser_requests"], json!(2));
        assert_eq!(doc["totals"]["browser_visits"], json!(1));
        assert_eq!(doc["totals"]["bot_requests"], json!(0));
        assert!(species_row(&doc, "Browser").is_none());
    }

    #[test]
    fn movement_against_previous_census() {
        let mut prev = BTreeMap::new();
        prev.insert("Googlebot".to_string(), 1u64);
        prev.insert("curl".to_string(), 5u64);
        let log = [
            line(T0, "66.249.66.1", GOOGLE_UA, "/robots.txt", 1),
            line(T0 + 7_200, "66.249.66.1", GOOGLE_UA, "/robots.txt", 1), // second session
            line(T0, "45.148.10.7", "curl/8.5.0", "/", 1),
            line(T0, "54.36.148.1", "AhrefsBot/7.0", "/", 1),
        ]
        .join("\n");
        let mut inp = inputs(log);
        inp.previous_species_sessions = Some(prev);
        let doc = compute_census(&inp, &CensusCaps::default(), &google_resolver()).expect("census");
        assert_eq!(
            species_row(&doc, "Googlebot").expect("g")["movement"],
            json!("up")
        );
        assert_eq!(
            species_row(&doc, "curl").expect("c")["movement"],
            json!("down")
        );
        assert_eq!(
            species_row(&doc, "AhrefsBot").expect("a")["movement"],
            json!("new")
        );
    }

    #[test]
    fn projection_refuses_fresh_window_and_leaks_nothing() {
        let log = [
            line(T0, "203.0.113.9", GOOGLE_UA, "/research", 100),
            line(T0 + 5, "45.148.10.7", "curl/8.5.0", "/.env", 226),
        ]
        .join("\n");
        let doc = compute_census(
            &inputs(log),
            &CensusCaps::default(),
            &FixtureResolver::default(),
        )
        .expect("census");
        let end = doc["window"]["end"].as_u64().expect("end");
        // Too fresh: refused by construction.
        assert!(project(&doc, end + 3_600).is_err());
        // A day later: fine, and the serialised projection cannot
        // contain an address or anything canary-shaped.
        let proj = project(&doc, end + 25 * 3_600).expect("projection");
        let text = serde_json::to_string(&proj).expect("serialize");
        assert!(!text.contains("203.0.113"), "no IP in projection: {text}");
        assert!(!text.contains("45.148"), "no IP in projection: {text}");
        assert!(
            !text.to_lowercase().contains("canary"),
            "no canary field: {text}"
        );
        assert!(!text.contains(".env"), "no canary path: {text}");
        assert!(
            text.contains("Impostor"),
            "aggregate species survive: {text}"
        );
    }

    #[test]
    fn species_saturation_folds_into_unplaced_and_counts() {
        let caps = CensusCaps {
            max_species: 2,
            ..CensusCaps::default()
        };
        let log = [
            line(T0, "66.249.66.1", GOOGLE_UA, "/research", 1),
            line(T0, "45.148.10.7", "curl/8.5.0", "/", 1),
            line(T0, "54.36.148.1", "AhrefsBot/7.0", "/", 1),
        ]
        .join("\n");
        let doc = compute_census(&inputs(log), &caps, &google_resolver()).expect("census");
        assert_eq!(doc["totals"]["species_saturated"], json!(1));
        // First species (BTreeMap order of keys is by (ip, ua);
        // the folded species' requests stay counted somewhere.
        assert_eq!(doc["totals"]["bot_requests"], json!(3));
    }
}

//! `broadside-tui`: the fleet-pattern terminal console for
//! broadside (fleet TUI programme D-1562, DESIGN §D2).
//!
//! Screens: Overview (version, last pipeline states, receipt
//! count), Workflows (build / verify / deploy pipelines as staged
//! runs with live progress into Log), Receipts (the hash-chained
//! receipt log, verification reported from broadside's own
//! machinery — never from this crate's say-so), Honeypot (the
//! signed canary manifest state the library exposes), Log / Live,
//! and Fleet (trigger rules per §D4 with their audit tail). There
//! is deliberately no Media screen: broadside's use case has no
//! images or video, and §D2 forbids stubbing one.
//!
//! Deploy discipline: plan mode is the default — a workflow is
//! staged with its exact tool + args and nothing is called until
//! the operator approves. In auto mode a deploy additionally
//! requires this run's own verify stage to have passed for the
//! identical dist hash; that rule lives in the run state machine
//! ([`screens::PipelineRun`]), not in operator vigilance.
//!
//! # Bounds (named, with units)
//!
//! - [`LOG_LINES_MAX`] log lines retained in the Log screen.
//! - [`AUDIT_LINES_MAX`] trigger audit lines retained.
//! - [`RECEIPTS_LIST_MAX`] receipts held by the viewer.
//! - [`INPUT_LINE_BYTES_MAX`] bytes per line-mode input line.
//! - [`TRIGGER_RULES_MAX`] rules loaded from one `triggers.toml`.
//! - [`TRIGGER_DEPTH_HARD_MAX`] is the §D4 depth ceiling (2).

#![forbid(unsafe_code)]

pub mod app;
pub mod facade;
pub mod panels;
pub mod screens;
pub mod triggers;

/// Log lines retained in the Log / Live screen buffer.
pub const LOG_LINES_MAX: usize = 500;
/// Trigger audit lines retained for the Fleet panel tail.
pub const AUDIT_LINES_MAX: usize = 200;
/// Receipts held by the viewer at once (the log itself is the
/// member's append-only file; the viewer is a bounded window).
pub const RECEIPTS_LIST_MAX: usize = 500;
/// Bytes accepted on one line-mode input line.
pub const INPUT_LINE_BYTES_MAX: usize = 4096;
/// Trigger rules accepted from one `triggers.toml` file.
pub const TRIGGER_RULES_MAX: usize = 32;
/// §D4 hard ceiling for trigger depth; no rule may exceed it.
pub const TRIGGER_DEPTH_HARD_MAX: u32 = 2;

/// The member's MCP tool names, in catalog order.
pub const MEMBER_TOOLS: [&str; 5] = [
    "broadside_status",
    "broadside_live_check",
    "broadside_build",
    "broadside_verify",
    "broadside_deploy",
];

pub use app::{App, CommandOutcome, run_line_mode};
pub use facade::{
    BroadsideFacade, FacadeError, FakeFacade, LibFacade, McpStdioFacade, VerificationStatus,
    verify_receipt_detail,
};
pub use screens::{PipelineRun, RunMode, Screen, Workflow};
pub use triggers::{TriggerEngine, TriggerRule};

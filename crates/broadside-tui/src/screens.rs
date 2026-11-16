//! Screen identity and the workflow run state machine.
//!
//! The state machine is where the deploy discipline lives
//! (DESIGN §D2 + the member's own deploy law):
//!
//! - Plan mode is the default. Staging a workflow records its
//!   exact tool + args and performs **no** call; approval executes
//!   the staged call, abort discards it.
//! - Auto mode executes declared operations directly — except
//!   deploy. An auto deploy is authorized only by
//!   [`PipelineRun::record_verify_pass`] in the *same* run, for
//!   the *identical* dist hash. Anything else is a typed refusal
//!   from [`PipelineRun::deploy_decision`], before any call.
//! - In plan mode the human approval is the gate for the TUI call,
//!   and the member's own deploy machinery still refuses without
//!   a passing verify receipt for the identical hash — defence in
//!   depth, two independent gates.
//!
//! Invalid states are unrepresentable: a staged call is an
//! `Option<StagedCall>`, stage outcomes are a closed enum, and a
//! finished stage cannot be re-run without a fresh staging.

use serde_json::{Value, json};

/// The comparable-capability screens (DESIGN §D2). No Media
/// screen exists for broadside — absent, not stubbed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Version, last pipeline states, receipt count.
    Overview,
    /// Build / verify / deploy pipelines as staged runs.
    Workflows,
    /// Signed (hash-chained) receipt list + detail.
    Receipts,
    /// Honeypot manifest state, as the library exposes it.
    Honeypot,
    /// Bounded scrolling event view.
    Log,
    /// Fleet members, trigger rules, audit tail.
    Fleet,
}

impl Screen {
    /// All screens in tab order.
    pub const ALL: [Screen; 6] = [
        Screen::Overview,
        Screen::Workflows,
        Screen::Receipts,
        Screen::Honeypot,
        Screen::Log,
        Screen::Fleet,
    ];

    /// The screen's display name.
    pub fn name(self) -> &'static str {
        match self {
            Screen::Overview => "Overview",
            Screen::Workflows => "Workflows",
            Screen::Receipts => "Receipts",
            Screen::Honeypot => "Honeypot",
            Screen::Log => "Log",
            Screen::Fleet => "Fleet",
        }
    }

    /// Parse a screen name (line mode `screen <name>`).
    pub fn from_name(name: &str) -> Option<Screen> {
        Screen::ALL
            .iter()
            .find(|screen| screen.name().eq_ignore_ascii_case(name))
            .copied()
    }

    /// The next screen in tab order (wraps).
    pub fn next(self) -> Screen {
        let index = Screen::ALL
            .iter()
            .position(|screen| *screen == self)
            .unwrap_or(0);
        Screen::ALL[(index + 1) % Screen::ALL.len()]
    }
}

/// Run control for workflows: plan stages, auto executes.
/// Plan is the default — auto is opt-in per session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RunMode {
    /// Stage the call, show exact tool + args, wait for approval.
    #[default]
    Plan,
    /// Execute declared operations directly (deploy still gated
    /// by the same-run verify rule).
    Auto,
}

impl RunMode {
    /// The mode's display label.
    pub fn label(self) -> &'static str {
        match self {
            RunMode::Plan => "plan",
            RunMode::Auto => "auto",
        }
    }

    /// Parse `plan` / `auto`.
    pub fn from_label(label: &str) -> Option<RunMode> {
        match label {
            "plan" => Some(RunMode::Plan),
            "auto" => Some(RunMode::Auto),
            _ => None,
        }
    }

    /// The other mode (the `m` key toggle).
    pub fn toggled(self) -> RunMode {
        match self {
            RunMode::Plan => RunMode::Auto,
            RunMode::Auto => RunMode::Plan,
        }
    }
}

/// One of broadside's primary operations as a workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Workflow {
    /// `broadside_build`.
    Build,
    /// `broadside_verify`.
    Verify,
    /// `broadside_deploy` (consequential).
    Deploy,
    /// `broadside_live_check`.
    LiveCheck,
}

impl Workflow {
    /// All workflows in display order.
    pub const ALL: [Workflow; 4] = [
        Workflow::Build,
        Workflow::Verify,
        Workflow::Deploy,
        Workflow::LiveCheck,
    ];

    /// The workflow's display name.
    pub fn name(self) -> &'static str {
        match self {
            Workflow::Build => "build",
            Workflow::Verify => "verify",
            Workflow::Deploy => "deploy",
            Workflow::LiveCheck => "live-check",
        }
    }

    /// Parse a workflow name.
    pub fn from_name(name: &str) -> Option<Workflow> {
        Workflow::ALL
            .iter()
            .find(|workflow| workflow.name() == name)
            .copied()
    }

    /// The MCP tool this workflow calls.
    pub fn tool(self) -> &'static str {
        match self {
            Workflow::Build => "broadside_build",
            Workflow::Verify => "broadside_verify",
            Workflow::Deploy => "broadside_deploy",
            Workflow::LiveCheck => "broadside_live_check",
        }
    }

    /// Deploy is the consequential workflow: writes outside this
    /// machine, gated in both modes (see the module docs).
    pub fn is_consequential(self) -> bool {
        matches!(self, Workflow::Deploy)
    }

    /// Default arguments for one run of this workflow. Deploy
    /// carries the run's dist hash and `confirm: true` — the
    /// member's per-call confirmation — but only when a hash is
    /// known; without one the workflow cannot be staged at all.
    pub fn default_args(self, dist_hash: Option<&str>) -> Result<Value, String> {
        match self {
            Workflow::Build | Workflow::LiveCheck => Ok(json!({})),
            Workflow::Verify => Ok(match dist_hash {
                Some(hash) => json!({"dist_hash": hash}),
                None => json!({}),
            }),
            Workflow::Deploy => {
                let hash = dist_hash.ok_or_else(|| {
                    "deploy needs a dist hash: run verify first or pass one explicitly".to_string()
                })?;
                Ok(json!({"dist_hash": hash, "confirm": true, "dry_run": false}))
            }
        }
    }
}

/// A staged unit of work awaiting approval (plan mode), or about
/// to execute (auto mode). Pipelines stage as one unit.
#[derive(Clone, Debug, PartialEq)]
pub enum StagedCall {
    /// One workflow with its exact tool + args.
    Single {
        /// The workflow being run.
        workflow: Workflow,
        /// The exact MCP tool name.
        tool: String,
        /// The exact arguments that will be sent.
        args: Value,
    },
    /// The build → verify → deploy pipeline, in order.
    Pipeline,
}

impl StagedCall {
    /// Stage one workflow with its default arguments.
    pub fn single(workflow: Workflow, dist_hash: Option<&str>) -> Result<StagedCall, String> {
        Ok(StagedCall::Single {
            workflow,
            tool: workflow.tool().to_string(),
            args: workflow.default_args(dist_hash)?,
        })
    }

    /// A one-line rendering of exactly what approval will do.
    pub fn describe(&self) -> String {
        match self {
            StagedCall::Single { tool, args, .. } => format!("{tool} {args}"),
            StagedCall::Pipeline => {
                "pipeline: broadside_build -> broadside_verify -> broadside_deploy".to_string()
            }
        }
    }
}

/// The outcome of one stage in a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StageState {
    /// Staged, not yet executed.
    Staged,
    /// Executed and the member reported `pass`.
    Passed,
    /// Executed; the member reported a non-pass result.
    Failed(String),
    /// Refused before any call (a gate, not a failure).
    Refused(String),
    /// The server died during this stage; the run halts.
    Died(String),
    /// Staged, then aborted by the operator.
    Aborted,
}

impl StageState {
    /// The state's short label.
    pub fn label(&self) -> String {
        match self {
            StageState::Staged => "staged".to_string(),
            StageState::Passed => "pass".to_string(),
            StageState::Failed(result) => format!("failed ({result})"),
            StageState::Refused(reason) => format!("refused ({reason})"),
            StageState::Died(reason) => format!("server died ({reason})"),
            StageState::Aborted => "aborted".to_string(),
        }
    }
}

/// One stage's record inside a run.
#[derive(Clone, Debug, PartialEq)]
pub struct StageRecord {
    /// The workflow this stage ran.
    pub workflow: Workflow,
    /// Its outcome.
    pub state: StageState,
}

/// The deploy authorization decision for one attempted deploy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeployDecision {
    /// The deploy call may be made.
    Allowed,
    /// Refused before any call; carries the reason.
    Refused(String),
}

/// One pipeline run's state: its stages and — load-bearing — the
/// dist hash this run's own verify stage passed for, if any.
#[derive(Clone, Debug, Default)]
pub struct PipelineRun {
    stages: Vec<StageRecord>,
    verified_hash_in_run: Option<String>,
    halted: bool,
}

impl PipelineRun {
    /// A fresh run with no stages.
    pub fn new() -> PipelineRun {
        PipelineRun::default()
    }

    /// This run's stages, in order.
    pub fn stages(&self) -> &[StageRecord] {
        &self.stages
    }

    /// The dist hash this run's verify stage passed for.
    pub fn verified_hash_in_run(&self) -> Option<&str> {
        self.verified_hash_in_run.as_deref()
    }

    /// True once a stage has died or failed: later stages of a
    /// pipeline must not run (a dead server runs nothing, and a
    /// failed verify authorizes no deploy).
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    /// Record a stage outcome. A verify pass with a dist hash is
    /// what arms [`PipelineRun::deploy_decision`] for auto mode.
    pub fn record_stage(&mut self, workflow: Workflow, state: StageState, dist_hash: Option<&str>) {
        if workflow == Workflow::Verify
            && state == StageState::Passed
            && let Some(hash) = dist_hash
        {
            self.verified_hash_in_run = Some(hash.to_string());
        }
        if matches!(state, StageState::Failed(_) | StageState::Died(_)) {
            self.halted = true;
        }
        self.stages.push(StageRecord { workflow, state });
    }

    /// Decide whether a deploy of `requested_hash` may proceed.
    ///
    /// Auto mode: only a same-run verify pass for the identical
    /// hash authorizes the call — a hash verified in an earlier
    /// run, or a different hash, or no verify at all, is refused.
    /// Plan mode: the operator's explicit approval is the TUI-side
    /// gate; the member's own verify-receipt gate still applies
    /// inside the deploy call itself.
    pub fn deploy_decision(&self, mode: RunMode, requested_hash: Option<&str>) -> DeployDecision {
        match mode {
            RunMode::Plan => DeployDecision::Allowed,
            RunMode::Auto => match (self.verified_hash_in_run.as_deref(), requested_hash) {
                (Some(verified), Some(requested)) if verified == requested => {
                    DeployDecision::Allowed
                }
                (Some(verified), Some(requested)) => DeployDecision::Refused(format!(
                    "auto deploy refused: this run verified {verified}, not {requested}"
                )),
                (Some(_), None) => DeployDecision::Allowed,
                (None, _) => DeployDecision::Refused(
                    "auto deploy refused: no passing verify stage in this run \
                     (plan mode + approval, or run verify first)"
                        .to_string(),
                ),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_the_default_mode() {
        assert_eq!(RunMode::default(), RunMode::Plan);
    }

    #[test]
    fn auto_deploy_without_verify_in_run_is_refused() {
        // The core state-machine rule: no same-run verify, no
        // auto deploy — for any hash, including none.
        let run = PipelineRun::new();
        assert!(matches!(
            run.deploy_decision(RunMode::Auto, Some("abc123")),
            DeployDecision::Refused(_)
        ));
        assert!(matches!(
            run.deploy_decision(RunMode::Auto, None),
            DeployDecision::Refused(_)
        ));
    }

    #[test]
    fn auto_deploy_after_same_run_verify_pass_is_allowed() {
        let mut run = PipelineRun::new();
        run.record_stage(Workflow::Verify, StageState::Passed, Some("abc123"));
        assert_eq!(
            run.deploy_decision(RunMode::Auto, Some("abc123")),
            DeployDecision::Allowed
        );
        assert_eq!(
            run.deploy_decision(RunMode::Auto, None),
            DeployDecision::Allowed
        );
    }

    #[test]
    fn auto_deploy_of_a_different_hash_is_refused() {
        // Adversarial: a verify pass for one dist must not
        // authorize deploying another.
        let mut run = PipelineRun::new();
        run.record_stage(Workflow::Verify, StageState::Passed, Some("abc123"));
        match run.deploy_decision(RunMode::Auto, Some("evil999")) {
            DeployDecision::Refused(reason) => {
                assert!(reason.contains("abc123"), "{reason}");
                assert!(reason.contains("evil999"), "{reason}");
            }
            DeployDecision::Allowed => panic!("different hash must be refused"),
        }
    }

    #[test]
    fn failed_verify_does_not_arm_deploy() {
        // Adversarial: a verify stage that ran and failed is not
        // a verify pass, however its args were framed.
        let mut run = PipelineRun::new();
        run.record_stage(
            Workflow::Verify,
            StageState::Failed("fail".to_string()),
            Some("abc123"),
        );
        assert!(matches!(
            run.deploy_decision(RunMode::Auto, Some("abc123")),
            DeployDecision::Refused(_)
        ));
        assert!(run.is_halted());
    }

    #[test]
    fn verify_from_an_earlier_run_does_not_carry_over() {
        // A fresh run starts unarmed even if a previous run in
        // the same session verified the same hash.
        let mut first = PipelineRun::new();
        first.record_stage(Workflow::Verify, StageState::Passed, Some("abc123"));
        let second = PipelineRun::new();
        assert!(matches!(
            second.deploy_decision(RunMode::Auto, Some("abc123")),
            DeployDecision::Refused(_)
        ));
    }

    #[test]
    fn plan_mode_deploy_uses_approval_gate() {
        let run = PipelineRun::new();
        assert_eq!(
            run.deploy_decision(RunMode::Plan, Some("abc123")),
            DeployDecision::Allowed
        );
    }

    #[test]
    fn deploy_staging_needs_a_hash() {
        assert!(Workflow::Deploy.default_args(None).is_err());
        let staged = StagedCall::single(Workflow::Deploy, Some("abc123")).expect("stage deploy");
        assert!(staged.describe().contains("broadside_deploy"));
        assert!(staged.describe().contains("abc123"));
    }

    #[test]
    fn screen_tab_order_wraps() {
        assert_eq!(Screen::Fleet.next(), Screen::Overview);
        assert_eq!(Screen::from_name("receipts"), Some(Screen::Receipts));
        assert_eq!(Screen::from_name("media"), None);
    }
}

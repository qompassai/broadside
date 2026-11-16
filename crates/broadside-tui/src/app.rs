//! The application: screen state, the shared execute path for
//! the full-screen and line modes, and the workflow runner.
//!
//! Both modes drive the same [`App::handle_command`] / key
//! handling, so a behaviour proven in line mode (and in tests,
//! through [`FakeFacade`](crate::facade::FakeFacade)) is the
//! behaviour the full-screen TUI has. The runner is synchronous:
//! each stage emits `started` / `done` / `failed` events into the
//! Log buffer and the trigger engine as it runs — live progress
//! at stage granularity in rung 1.
//!
//! A [`PipelineRun`] persists across commands until `newrun`:
//! "the same run" for the auto-deploy verify rule means the same
//! run object, and starting a pipeline resets it.

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use serde_json::{Value, json};

use crate::facade::{BroadsideFacade, FacadeError, VerificationStatus, verify_receipt_detail};
use crate::panels;
use crate::screens::{
    DeployDecision, PipelineRun, RunMode, Screen, StageState, StagedCall, Workflow,
};
use crate::triggers::{FleetEvent, TriggerEngine};
use crate::{INPUT_LINE_BYTES_MAX, LOG_LINES_MAX, MEMBER_TOOLS, RECEIPTS_LIST_MAX};

/// Provider control note (DESIGN §D3): broadside routes no model
/// calls, so the provider control is honestly absent — shown
/// disabled with this reason, never faked.
pub const PROVIDER_NOTE: &str = "n/a — broadside routes no model calls (control disabled per §D3)";

/// The outcome of one line-mode command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutcome {
    /// Text to print for the operator.
    pub text: String,
    /// True when the session should end (`quit`).
    pub quit: bool,
}

impl CommandOutcome {
    fn say(text: impl Into<String>) -> CommandOutcome {
        CommandOutcome {
            text: text.into(),
            quit: false,
        }
    }
}

/// The TUI application over a facade `F`.
pub struct App<F: BroadsideFacade> {
    facade: F,
    engine: TriggerEngine,
    transport_note: String,
    /// The visible screen.
    pub screen: Screen,
    /// The run control (plan is the default).
    pub mode: RunMode,
    selected_workflow: usize,
    selected_receipt: usize,
    staged: Option<StagedCall>,
    run: PipelineRun,
    log: VecDeque<String>,
    status_cache: Value,
    receipts_cache: Vec<Value>,
    chain_cache: VerificationStatus,
    known_hash: Option<String>,
}

impl<F: BroadsideFacade> App<F> {
    /// Build the app and load the first status + receipts. Load
    /// failures land in the Log, never a panic and never a fake ok.
    pub fn new(facade: F, engine: TriggerEngine, transport_note: &str) -> App<F> {
        let mut app = App {
            facade,
            engine,
            transport_note: transport_note.to_string(),
            screen: Screen::Overview,
            mode: RunMode::Plan,
            selected_workflow: 0,
            selected_receipt: 0,
            staged: None,
            run: PipelineRun::new(),
            log: VecDeque::new(),
            status_cache: Value::Null,
            receipts_cache: Vec::new(),
            chain_cache: VerificationStatus::Unverifiable("chain not checked yet".to_string()),
            known_hash: None,
        };
        app.refresh();
        app
    }

    /// The facade (tests inspect the fake through here).
    pub fn facade(&self) -> &F {
        &self.facade
    }

    /// The trigger engine (tests inspect firings through here).
    pub fn engine(&self) -> &TriggerEngine {
        &self.engine
    }

    /// The currently staged call, if any.
    pub fn staged(&self) -> Option<&StagedCall> {
        self.staged.as_ref()
    }

    /// The current run's state.
    pub fn run(&self) -> &PipelineRun {
        &self.run
    }

    /// The chain verdict from the member's machinery.
    pub fn chain_status(&self) -> &VerificationStatus {
        &self.chain_cache
    }

    /// The receipts the viewer holds.
    pub fn receipts(&self) -> &[Value] {
        &self.receipts_cache
    }

    /// The Log buffer's lines, oldest first.
    pub fn log_lines(&self) -> Vec<String> {
        self.log.iter().cloned().collect()
    }

    /// The selected workflow on the Workflows screen.
    pub fn selected_workflow(&self) -> Workflow {
        Workflow::ALL[self.selected_workflow % Workflow::ALL.len()]
    }

    fn push_log(&mut self, line: String) {
        if self.log.len() >= LOG_LINES_MAX {
            self.log.pop_front();
        }
        self.log.push_back(line);
    }

    /// Reload status, receipts, and the chain verdict.
    pub fn refresh(&mut self) {
        match self.facade.status() {
            Ok(status) => {
                if let Some(hash) = status
                    .get("latest")
                    .and_then(|latest| latest.get("verify"))
                    .filter(|verify| verify.get("result").and_then(Value::as_str) == Some("pass"))
                    .and_then(|verify| verify.get("dist_hash"))
                    .and_then(Value::as_str)
                {
                    self.known_hash = Some(hash.to_string());
                }
                self.status_cache = status;
            }
            Err(e) => self.push_log(format!("status: {e}")),
        }
        self.chain_cache = self.facade.chain_verification();
        match self.facade.receipts() {
            Ok(mut receipts) => {
                receipts.truncate(RECEIPTS_LIST_MAX);
                self.receipts_cache = receipts;
            }
            Err(e) => {
                self.receipts_cache = Vec::new();
                self.push_log(format!("receipts: {e}"));
            }
        }
        if self.selected_receipt >= self.receipts_cache.len() {
            self.selected_receipt = self.receipts_cache.len().saturating_sub(1);
        }
    }

    /// Verification of the receipt at `index`, computed from the
    /// member's hash machinery against its chain position. A
    /// receipt outside the loaded chain context is Unverifiable.
    pub fn receipt_detail(&self, index: usize) -> Option<(Value, VerificationStatus)> {
        let receipt = self.receipts_cache.get(index)?.clone();
        let expected_prev = if index == 0 {
            String::new()
        } else {
            self.receipts_cache
                .get(index - 1)
                .and_then(|prev| prev.get("hash"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let status = verify_receipt_detail(&receipt, index as u64 + 1, &expected_prev);
        Some((receipt, status))
    }

    // ---------------------------------------------------------
    // Command execution (shared by line mode and tests).
    // ---------------------------------------------------------

    /// Execute one operator command line. Pure dispatch over the
    /// same state the full-screen keys mutate.
    pub fn handle_command(&mut self, line: &str) -> CommandOutcome {
        let words: Vec<&str> = line.split_whitespace().collect();
        let Some(command) = words.first() else {
            return CommandOutcome::say("");
        };
        match *command {
            "quit" | "exit" => CommandOutcome {
                text: "bye".to_string(),
                quit: true,
            },
            "help" => CommandOutcome::say(help_text()),
            "screen" => match words.get(1).and_then(|name| Screen::from_name(name)) {
                Some(screen) => {
                    self.screen = screen;
                    CommandOutcome::say(format!("screen: {}", screen.name()))
                }
                None => CommandOutcome::say(
                    "usage: screen overview|workflows|receipts|honeypot|log|fleet",
                ),
            },
            "overview" => {
                self.screen = Screen::Overview;
                CommandOutcome::say(self.overview_text())
            }
            "status" => {
                self.refresh();
                CommandOutcome::say(self.overview_text())
            }
            "tools" => match self.facade.tools() {
                Ok(tools) => CommandOutcome::say(format!("tools: {}", tools.join(", "))),
                Err(e) => CommandOutcome::say(format!("tools: {e}")),
            },
            "mode" => self.mode_command(words.get(1).copied()),
            "workflows" => {
                self.screen = Screen::Workflows;
                CommandOutcome::say(self.workflows_text())
            }
            "run" | "stage" => self.run_command(&words, *command == "stage"),
            "pipeline" => self.pipeline_command(),
            "approve" => CommandOutcome::say(self.approve()),
            "abort" => CommandOutcome::say(self.abort()),
            "newrun" => {
                self.run = PipelineRun::new();
                CommandOutcome::say("run reset: no stage has verified in the new run")
            }
            "receipts" => {
                self.screen = Screen::Receipts;
                self.refresh();
                CommandOutcome::say(self.receipts_text())
            }
            "receipt" => self.receipt_command(words.get(1).copied()),
            "honeypot" => {
                self.screen = Screen::Honeypot;
                self.refresh();
                CommandOutcome::say(self.honeypot_text())
            }
            "fleet" | "triggers" => {
                self.screen = Screen::Fleet;
                CommandOutcome::say(self.fleet_text())
            }
            "trigger" => self.trigger_command(&words),
            "log" => {
                self.screen = Screen::Log;
                CommandOutcome::say(self.log_lines().join("\n"))
            }
            other => CommandOutcome::say(format!("unknown command {other:?} — try `help`")),
        }
    }

    fn mode_command(&mut self, arg: Option<&str>) -> CommandOutcome {
        match arg {
            None => CommandOutcome::say(format!("mode: {}", self.mode.label())),
            Some(label) => match RunMode::from_label(label) {
                Some(mode) => {
                    self.mode = mode;
                    CommandOutcome::say(format!("mode: {}", mode.label()))
                }
                None => CommandOutcome::say("usage: mode plan|auto"),
            },
        }
    }

    fn run_command(&mut self, words: &[&str], force_stage: bool) -> CommandOutcome {
        let Some(workflow) = words.get(1).and_then(|name| Workflow::from_name(name)) else {
            return CommandOutcome::say("usage: run build|verify|deploy|live-check [dist_hash]");
        };
        let hash = words
            .get(2)
            .map(ToString::to_string)
            .or_else(|| self.known_hash.clone());
        if force_stage || self.mode == RunMode::Plan {
            CommandOutcome::say(self.stage_workflow(workflow, hash.as_deref()))
        } else {
            match StagedCall::single(workflow, hash.as_deref()) {
                Ok(StagedCall::Single { args, .. }) => {
                    CommandOutcome::say(self.execute_stage(workflow, &args, false))
                }
                Ok(StagedCall::Pipeline) => {
                    CommandOutcome::say("internal: single() never stages a pipeline")
                }
                Err(e) => CommandOutcome::say(e),
            }
        }
    }

    fn pipeline_command(&mut self) -> CommandOutcome {
        if self.mode == RunMode::Plan {
            self.staged = Some(StagedCall::Pipeline);
            CommandOutcome::say(format!(
                "staged (approve to run, abort to discard): {}",
                StagedCall::Pipeline.describe()
            ))
        } else {
            CommandOutcome::say(self.run_pipeline(false))
        }
    }

    fn receipt_command(&mut self, arg: Option<&str>) -> CommandOutcome {
        let Some(seq) = arg.and_then(|text| text.parse::<usize>().ok()) else {
            return CommandOutcome::say("usage: receipt <seq>");
        };
        match seq
            .checked_sub(1)
            .and_then(|index| self.receipt_detail(index))
        {
            Some((receipt, status)) => CommandOutcome::say(format!(
                "verification: {}\n{}",
                status.label(),
                serde_json::to_string_pretty(&receipt).unwrap_or_default()
            )),
            None => CommandOutcome::say(format!("no receipt at seq {seq}")),
        }
    }

    fn trigger_command(&mut self, words: &[&str]) -> CommandOutcome {
        match (words.get(1).copied(), words.get(2).copied()) {
            (Some("on"), Some(id)) | (Some("off"), Some(id)) => {
                let enabled = words[1] == "on";
                if self.engine.set_rule_enabled(id, enabled) {
                    CommandOutcome::say(format!(
                        "rule {id} {}",
                        if enabled { "enabled" } else { "disabled" }
                    ))
                } else {
                    CommandOutcome::say(format!("no rule {id:?}"))
                }
            }
            _ => CommandOutcome::say("usage: trigger on|off <rule-id>"),
        }
    }

    // ---------------------------------------------------------
    // Staging, approval, execution.
    // ---------------------------------------------------------

    /// Stage a workflow (plan mode): records the exact tool +
    /// args and makes **no** facade call.
    pub fn stage_workflow(&mut self, workflow: Workflow, dist_hash: Option<&str>) -> String {
        match StagedCall::single(workflow, dist_hash) {
            Ok(staged) => {
                let text = format!("staged: {}", staged.describe());
                self.staged = Some(staged);
                text
            }
            Err(e) => e,
        }
    }

    /// Approve the staged call and execute it. Approval is the
    /// plan-mode gate, including for deploy.
    pub fn approve(&mut self) -> String {
        let Some(staged) = self.staged.take() else {
            return "nothing staged".to_string();
        };
        match staged {
            StagedCall::Single { workflow, args, .. } => self.execute_stage(workflow, &args, true),
            StagedCall::Pipeline => self.run_pipeline(true),
        }
    }

    /// Abort the staged call: discarded, nothing executed.
    pub fn abort(&mut self) -> String {
        match self.staged.take() {
            Some(staged) => {
                if let StagedCall::Single { workflow, .. } = staged {
                    self.run.record_stage(workflow, StageState::Aborted, None);
                }
                format!("aborted: {}", staged.describe())
            }
            None => "nothing staged".to_string(),
        }
    }

    /// Run the build → verify → deploy pipeline in one run. The
    /// run resets first, so the deploy's same-run verify is this
    /// pipeline's own verify stage.
    pub fn run_pipeline(&mut self, approved: bool) -> String {
        self.run = PipelineRun::new();
        let mut summaries = Vec::new();
        for workflow in [Workflow::Build, Workflow::Verify, Workflow::Deploy] {
            if self.run.is_halted() {
                summaries.push(format!("{}: skipped (run halted)", workflow.name()));
                break;
            }
            let hash = match workflow {
                Workflow::Deploy => self.run.verified_hash_in_run().map(ToString::to_string),
                _ => None,
            };
            match workflow.default_args(hash.as_deref()) {
                Ok(args) => summaries.push(self.execute_stage(workflow, &args, approved)),
                Err(e) => {
                    self.run
                        .record_stage(workflow, StageState::Refused(e.clone()), None);
                    summaries.push(format!("{}: refused ({e})", workflow.name()));
                }
            }
        }
        summaries.join("\n")
    }

    /// Execute one workflow stage through the facade, recording
    /// its outcome, streaming events to the Log, and feeding the
    /// trigger engine. `approved` marks a plan-mode approval (the
    /// human gate for deploy); in auto mode the same-run verify
    /// rule decides deploys.
    pub fn execute_stage(&mut self, workflow: Workflow, args: &Value, approved: bool) -> String {
        if self.run.is_halted() {
            return format!(
                "{}: refused (run halted by an earlier stage; `newrun` to reset)",
                workflow.name()
            );
        }
        if workflow == Workflow::Deploy {
            let requested = args.get("dist_hash").and_then(Value::as_str);
            let gate_mode = if approved { RunMode::Plan } else { self.mode };
            if let DeployDecision::Refused(reason) = self.run.deploy_decision(gate_mode, requested)
            {
                self.run
                    .record_stage(workflow, StageState::Refused(reason.clone()), None);
                self.push_log(format!("deploy: refused before any call: {reason}"));
                return format!("deploy: refused ({reason})");
            }
        }
        self.push_log(format!(
            "{}: started ({} {args})",
            workflow.name(),
            workflow.tool()
        ));
        let outcome = self.facade.call(workflow.tool(), args);
        match outcome {
            Err(FacadeError::ServerDied(detail)) => {
                self.run
                    .record_stage(workflow, StageState::Died(detail.clone()), None);
                self.push_log(format!(
                    "{}: server died mid-stage: {detail} — pipeline halted",
                    workflow.name()
                ));
                format!("{}: server died ({detail})", workflow.name())
            }
            Err(e) => {
                self.run
                    .record_stage(workflow, StageState::Failed(e.to_string()), None);
                self.push_log(format!("{}: failed: {e}", workflow.name()));
                format!("{}: failed ({e})", workflow.name())
            }
            Ok(result) => self.finish_stage(workflow, args, &result),
        }
    }

    fn finish_stage(&mut self, workflow: Workflow, args: &Value, result: &Value) -> String {
        let result_text = result
            .get("result")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let dist_hash = result
            .get("outputs")
            .and_then(|outputs| outputs.get("dist_hash"))
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let state = match result_text.as_str() {
            "pass" => StageState::Passed,
            "refused" => StageState::Refused("member refused this call".to_string()),
            other => StageState::Failed(other.to_string()),
        };
        self.run
            .record_stage(workflow, state.clone(), dist_hash.as_deref());
        if let Some(hash) = &dist_hash {
            self.known_hash = Some(hash.clone());
        }
        self.push_log(format!(
            "{}: done result={result_text} dist_hash={}",
            workflow.name(),
            dist_hash.as_deref().unwrap_or("-")
        ));
        if workflow == Workflow::Deploy && result_text == "pass" {
            self.fire_deploy_verified(args, result, dist_hash.as_deref());
        }
        self.refresh();
        format!("{}: {result_text}", workflow.name())
    }

    /// Emit `deploy.verified` (the deploy receipt proves the
    /// identical-hash verify gate + live read-back) and let the
    /// trigger engine evaluate it.
    fn fire_deploy_verified(&mut self, args: &Value, result: &Value, dist_hash: Option<&str>) {
        let payload = json!({
            "result": "pass",
            "dist_hash": dist_hash
                .or_else(|| args.get("dist_hash").and_then(Value::as_str))
                .unwrap_or("unknown"),
            "receipt_seq": result.get("seq").cloned().unwrap_or(Value::Null),
        });
        let event = FleetEvent::new("deploy.verified", payload);
        for entry in self.engine.evaluate(&event) {
            self.push_log(format!("trigger: {entry}"));
        }
    }

    // ---------------------------------------------------------
    // Plain-text views (line mode renders these; the full-screen
    // mode renders the panels over the same state).
    // ---------------------------------------------------------

    fn overview_text(&self) -> String {
        let status = &self.status_cache;
        let count = status
            .get("receipts")
            .and_then(|receipts| receipts.get("count"))
            .cloned()
            .unwrap_or(Value::Null);
        format!(
            "broadside-tui {} | member tools: {} | receipts: {} | chain: {}",
            env!("CARGO_PKG_VERSION"),
            MEMBER_TOOLS.len(),
            count,
            self.chain_cache.label()
        )
    }

    fn workflows_text(&self) -> String {
        let mut text = format!("mode: {}\nprovider: {PROVIDER_NOTE}", self.mode.label());
        for workflow in Workflow::ALL {
            text.push_str(&format!("\n  {} ({})", workflow.name(), workflow.tool()));
        }
        if let Some(staged) = &self.staged {
            text.push_str(&format!("\nstaged: {}", staged.describe()));
        }
        text
    }

    fn receipts_text(&self) -> String {
        let mut text = format!("chain: {}\n", self.chain_cache.label());
        if self.receipts_cache.is_empty() {
            text.push_str("(no receipts)");
        }
        for receipt in &self.receipts_cache {
            text.push_str(&format!(
                "seq {} {} {}\n",
                receipt.get("seq").cloned().unwrap_or(Value::Null),
                receipt.get("action").and_then(Value::as_str).unwrap_or("?"),
                receipt.get("result").and_then(Value::as_str).unwrap_or("?"),
            ));
        }
        text.trim_end().to_string()
    }

    fn honeypot_text(&self) -> String {
        // Reads the cached status (refreshed on `status`/`receipts`
        // and after every stage) — the same value the Honeypot
        // panel renders, so line and full-screen modes agree.
        let honeypot = self.honeypot_value();
        let manifest = honeypot.get("manifest").cloned().unwrap_or(Value::Null);
        if manifest.is_null() {
            "honeypot manifest: none in the site tree".to_string()
        } else {
            format!(
                "honeypot manifest revision {} signer {} canaries {} fixture {} signer_pinned {}",
                manifest.get("revision").cloned().unwrap_or(Value::Null),
                manifest.get("signer_kid").cloned().unwrap_or(Value::Null),
                manifest.get("canaries").cloned().unwrap_or(Value::Null),
                manifest.get("fixture").cloned().unwrap_or(Value::Null),
                manifest
                    .get("signer_pinned")
                    .cloned()
                    .unwrap_or(Value::Null),
            )
        }
    }

    fn fleet_text(&self) -> String {
        let mut text = format!("trigger transport: {}", self.transport_note);
        for rule in self.engine.rules() {
            text.push_str(&format!(
                "\nrule [{}] {}: {} -> {}.{} mode {} labels {}/{}",
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
        for line in self.engine.audit_lines() {
            text.push_str(&format!("\naudit: {line}"));
        }
        text
    }

    // ---------------------------------------------------------
    // Full-screen mode: key handling + drawing.
    // ---------------------------------------------------------

    /// Handle one key in full-screen mode. Returns true to quit.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Tab => self.screen = self.screen.next(),
            KeyCode::Char(digit @ '1'..='6') => {
                let index = (digit as usize) - ('1' as usize);
                self.screen = Screen::ALL[index];
            }
            KeyCode::Char('m') => self.mode = self.mode.toggled(),
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Enter => {
                let workflow = self.selected_workflow();
                let hash = self.known_hash.clone();
                if self.mode == RunMode::Plan {
                    self.stage_workflow(workflow, hash.as_deref());
                } else if let Ok(StagedCall::Single { args, .. }) =
                    StagedCall::single(workflow, hash.as_deref())
                {
                    self.execute_stage(workflow, &args, false);
                }
                self.screen = Screen::Workflows;
            }
            KeyCode::Char('a') => {
                self.approve();
            }
            KeyCode::Char('x') => {
                self.abort();
            }
            KeyCode::Char('p') => {
                if self.mode == RunMode::Plan {
                    self.staged = Some(StagedCall::Pipeline);
                } else {
                    self.run_pipeline(false);
                }
                self.screen = Screen::Workflows;
            }
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('n') => self.run = PipelineRun::new(),
            _ => {}
        }
        false
    }

    fn move_selection(&mut self, delta: i32) {
        match self.screen {
            Screen::Workflows => {
                let len = Workflow::ALL.len() as i32;
                let next = (self.selected_workflow as i32 + delta).rem_euclid(len);
                self.selected_workflow = next as usize;
            }
            Screen::Receipts => {
                let len = self.receipts_cache.len().max(1) as i32;
                let next = (self.selected_receipt as i32 + delta).rem_euclid(len);
                self.selected_receipt = next as usize;
            }
            _ => {}
        }
    }

    /// Draw the current screen into a ratatui frame.
    pub fn draw(&self, frame: &mut ratatui::Frame<'_>) {
        let area = frame.area();
        match self.screen {
            Screen::Overview => frame.render_widget(
                panels::overview_panel(
                    &self.status_cache,
                    env!("CARGO_PKG_VERSION"),
                    MEMBER_TOOLS.len(),
                ),
                area,
            ),
            Screen::Workflows => frame.render_widget(
                panels::workflows_panel(
                    self.selected_workflow(),
                    self.mode,
                    self.staged.as_ref(),
                    &self.run,
                    PROVIDER_NOTE,
                ),
                area,
            ),
            Screen::Receipts => {
                // The list is the screen; one receipt's detail is
                // the `receipt <seq>` command in line mode and the
                // receipt_detail_panel constructor (both share
                // receipt_detail()).
                frame.render_widget(
                    panels::receipts_panel(
                        &self.receipts_cache,
                        self.selected_receipt,
                        &self.chain_cache,
                    ),
                    area,
                );
            }
            Screen::Honeypot => {
                let honeypot = self.honeypot_value();
                frame.render_widget(panels::honeypot_panel(&honeypot), area);
            }
            Screen::Log => {
                frame.render_widget(panels::log_panel(&self.log_lines()), area);
            }
            Screen::Fleet => frame.render_widget(
                panels::fleet_panel(
                    self.engine.rules(),
                    &self.engine.audit_lines(),
                    &self.transport_note,
                ),
                area,
            ),
        }
    }

    fn honeypot_value(&self) -> Value {
        // The full-screen draw cannot mutate the facade; it reads
        // the honeypot summary from the cached status instead.
        json!({
            "manifest": self
                .status_cache
                .get("honeypot_manifest")
                .cloned()
                .unwrap_or(Value::Null),
            "key_record": self
                .status_cache
                .get("key_record")
                .cloned()
                .unwrap_or(Value::Null),
        })
    }
}

/// The `help` text: every line-mode command.
pub fn help_text() -> String {
    [
        "commands:",
        "  status | overview        refresh + overview",
        "  tools                    member tool list",
        "  workflows                list workflows + staged call",
        "  mode [plan|auto]         show or set the run mode (default plan)",
        "  run <workflow> [hash]    plan: stage only; auto: execute (deploy gated)",
        "  stage <workflow> [hash]  stage without executing, any mode",
        "  pipeline                 plan: stage the pipeline; auto: run it",
        "  approve | abort          execute or discard the staged call",
        "  newrun                   reset the run (clears same-run verify)",
        "  receipts                 receipt list + chain verdict",
        "  receipt <seq>            one receipt + its verification status",
        "  honeypot                 honeypot manifest state",
        "  fleet | triggers         trigger rules + audit tail",
        "  trigger on|off <id>      enable/disable a rule (immediate)",
        "  log                      the event log",
        "  screen <name>            switch screen",
        "  quit                     exit",
    ]
    .join("\n")
}

/// Run the full-screen TUI: raw mode + alternate screen, keys
/// through [`App::handle_key`], draw through [`App::draw`].
pub fn run_fullscreen<F: BroadsideFacade>(app: &mut App<F>) -> io::Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;
    let result = fullscreen_loop(app, &mut terminal);
    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    result
}

fn fullscreen_loop<F: BroadsideFacade>(
    app: &mut App<F>,
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| app.draw(frame))?;
        if event::poll(Duration::from_millis(250))?
            && let Event::Key(key) = event::read()?
            && app.handle_key(key)
        {
            return Ok(());
        }
    }
}

/// Run line mode over any reader/writer pair (pipes, CI, tests):
/// the same [`App::handle_command`] execute path as the
/// full-screen mode, one command per line, `quit` or EOF ends.
pub fn run_line_mode<F: BroadsideFacade, R: BufRead, W: Write>(
    app: &mut App<F>,
    reader: &mut R,
    writer: &mut W,
) -> io::Result<()> {
    writeln!(
        writer,
        "broadside-tui {} (line mode)",
        env!("CARGO_PKG_VERSION")
    )?;
    writeln!(writer, "type `help` for commands, `quit` to exit")?;
    writer.flush()?;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            return Ok(());
        }
        if bytes > INPUT_LINE_BYTES_MAX {
            writeln!(
                writer,
                "error: input line exceeds {INPUT_LINE_BYTES_MAX} bytes"
            )?;
            writer.flush()?;
            continue;
        }
        let outcome = app.handle_command(&line);
        if !outcome.text.is_empty() {
            writeln!(writer, "{}", outcome.text)?;
        }
        writer.flush()?;
        if outcome.quit {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::facade::FakeFacade;
    use crate::triggers::{DEFAULT_TRIGGERS_TOML, FakeTransport, parse_rules};

    fn test_app(fake: FakeFacade) -> App<FakeFacade> {
        let rules = parse_rules(DEFAULT_TRIGGERS_TOML).expect("rules");
        let engine = TriggerEngine::new(rules, Box::new(FakeTransport::default()));
        App::new(fake, engine, "fake (tests)")
    }

    fn pass_receipt(action: &str, dist_hash: Option<&str>) -> Value {
        let mut outputs = json!({});
        if let Some(hash) = dist_hash {
            outputs["dist_hash"] = json!(hash);
        }
        json!({"action": action, "result": "pass", "outputs": outputs, "gates": []})
    }

    #[test]
    fn plan_mode_stages_without_any_call() {
        // The plan-mode proof: staging records the exact call and
        // the fake records zero calls until approval.
        let mut app = test_app(FakeFacade::new());
        assert_eq!(app.mode, RunMode::Plan);
        let outcome = app.handle_command("run build");
        assert!(outcome.text.contains("staged"), "{}", outcome.text);
        assert!(app.staged().is_some());
        assert!(app.facade().calls.is_empty(), "no call before approval");
        let outcome = app.handle_command("approve");
        assert!(outcome.text.contains("build: pass"), "{}", outcome.text);
        assert_eq!(app.facade().calls.len(), 1);
        assert_eq!(app.facade().calls[0].0, "broadside_build");
    }

    #[test]
    fn plan_abort_makes_no_call() {
        let mut app = test_app(FakeFacade::new());
        app.handle_command("run verify");
        let outcome = app.handle_command("abort");
        assert!(outcome.text.contains("aborted"), "{}", outcome.text);
        assert!(app.staged().is_none());
        assert!(app.facade().calls.is_empty());
    }

    #[test]
    fn auto_deploy_without_verify_is_refused_before_any_call() {
        let mut app = test_app(FakeFacade::new());
        app.handle_command("mode auto");
        let outcome = app.handle_command("run deploy abc123");
        assert!(outcome.text.contains("refused"), "{}", outcome.text);
        assert!(
            app.facade().calls.is_empty(),
            "refusal must happen before any facade call"
        );
    }

    #[test]
    fn auto_verify_then_deploy_same_run_fires_the_bloch_trigger() {
        let mut fake = FakeFacade::new();
        fake.queue_call_result(Ok(pass_receipt("verify", Some("abc123"))));
        fake.queue_call_result(Ok(json!({
            "action": "deploy", "result": "pass", "seq": 9,
            "outputs": {"dist_hash": "abc123"}, "gates": [],
        })));
        let mut app = test_app(fake);
        app.handle_command("mode auto");
        let verified = app.handle_command("run verify");
        assert!(verified.text.contains("verify: pass"), "{}", verified.text);
        let deployed = app.handle_command("run deploy abc123");
        assert!(deployed.text.contains("deploy: pass"), "{}", deployed.text);
        assert_eq!(app.facade().calls.len(), 2);
        // The deploy.verified event fired the §D4 rule through
        // the fake transport, with the lane-law labels.
        let calls = app.engine().transport_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "bloch");
        assert_eq!(calls[0].1, "lesson_candidate");
        assert_eq!(calls[0].2["origin_lane"], json!("qompass"));
        assert_eq!(calls[0].2["content_label"], json!("sfw"));
    }

    #[test]
    fn auto_deploy_of_unverified_hash_is_refused() {
        let mut fake = FakeFacade::new();
        fake.queue_call_result(Ok(pass_receipt("verify", Some("abc123"))));
        let mut app = test_app(fake);
        app.handle_command("mode auto");
        app.handle_command("run verify");
        let outcome = app.handle_command("run deploy evil999");
        assert!(outcome.text.contains("refused"), "{}", outcome.text);
        assert_eq!(app.facade().calls.len(), 1, "only the verify call happened");
    }

    #[test]
    fn newrun_clears_the_same_run_verify() {
        let mut fake = FakeFacade::new();
        fake.queue_call_result(Ok(pass_receipt("verify", Some("abc123"))));
        let mut app = test_app(fake);
        app.handle_command("mode auto");
        app.handle_command("run verify");
        app.handle_command("newrun");
        let outcome = app.handle_command("run deploy abc123");
        assert!(outcome.text.contains("refused"), "{}", outcome.text);
        assert_eq!(app.facade().calls.len(), 1);
    }

    #[test]
    fn server_death_mid_pipeline_halts_before_deploy() {
        // Adversarial: the server dies on the verify call; the
        // pipeline must halt and deploy must never be attempted.
        let mut fake = FakeFacade::new();
        fake.queue_call_result(Ok(pass_receipt("build", Some("abc123"))));
        fake.die_on_call = Some(2);
        let mut app = test_app(fake);
        app.handle_command("mode auto");
        let outcome = app.handle_command("pipeline");
        assert!(outcome.text.contains("server died"), "{}", outcome.text);
        assert_eq!(app.facade().calls.len(), 2, "build + dying verify only");
        assert!(app.run().is_halted());
        assert!(
            app.log_lines()
                .iter()
                .any(|line| line.contains("pipeline halted")),
            "log records the halt"
        );
    }

    #[test]
    fn malformed_tool_result_fails_the_stage_without_panicking() {
        // Adversarial: a result that is not a receipt object is a
        // failed stage ("unknown" result), never a panic or pass.
        let mut fake = FakeFacade::new();
        fake.queue_call_result(Ok(json!("not a receipt")));
        let mut app = test_app(fake);
        app.handle_command("mode auto");
        let outcome = app.handle_command("run build");
        assert!(outcome.text.contains("build: unknown"), "{}", outcome.text);
        assert!(app.run().is_halted());
    }

    #[test]
    fn receipt_detail_verifies_and_tamper_fails() {
        // Genuine receipts from the member's own log verify; a
        // tampered copy in the viewer's cache fails detail
        // verification through the same machinery.
        let dir = std::env::temp_dir().join(format!("broadside-tui-app-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let log = broadside_mcp::receipts::ReceiptLog::new(dir.join("receipts.jsonl"));
        let first = log
            .append(json!({"action": "build", "result": "pass",
                           "inputs": {}, "outputs": {}, "gates": []}))
            .expect("append");
        let mut fake = FakeFacade::new();
        fake.receipts_result = vec![first.clone()];
        let app = test_app(fake);
        let (_, status) = app.receipt_detail(0).expect("detail");
        assert_eq!(status, VerificationStatus::Verified);

        let mut tampered = first;
        tampered["result"] = json!("refused-to-pass-edit");
        let mut fake = FakeFacade::new();
        fake.receipts_result = vec![tampered];
        let app = test_app(fake);
        let (_, status) = app.receipt_detail(0).expect("tampered detail");
        assert!(
            matches!(status, VerificationStatus::Failed(_)),
            "{status:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn line_mode_answers_commands_from_a_pipe() {
        // Headless smoke: line mode shares the execute path and
        // answers from a pipe, ending on quit.
        let mut app = test_app(FakeFacade::new());
        let mut input = io::Cursor::new(b"status\nreceipts\nrun build\nquit\n".to_vec());
        let mut output: Vec<u8> = Vec::new();
        run_line_mode(&mut app, &mut input, &mut output).expect("line mode");
        let text = String::from_utf8(output).expect("utf8 output");
        assert!(text.contains("broadside-tui"), "{text}");
        assert!(text.contains("receipts:"), "{text}");
        assert!(text.contains("staged"), "{text}");
        // The staged build in plan mode made no call.
        assert!(app.facade().calls.is_empty());
    }

    #[test]
    fn first_screen_renders_headless() {
        // Headless smoke: the Overview screen renders through a
        // TestBackend terminal without a real TTY.
        let app = test_app(FakeFacade::new());
        let backend = ratatui::backend::TestBackend::new(80, 12);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| app.draw(frame))
            .expect("draw overview");
        let buffer = terminal.backend().buffer().clone();
        let mut text = String::new();
        for y in 0..12u16 {
            for x in 0..80u16 {
                text.push_str(buffer[(x, y)].symbol());
            }
        }
        assert!(text.contains("Overview"), "{text}");
        assert!(text.contains("broadside-tui"), "{text}");
    }
}

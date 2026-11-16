//! broadside-tui binary: parse args, build the real facade, run.
//!
//! The facade prefers the member's library ([`LibFacade`]);
//! `--mcp <path>` selects the MCP stdio client fallback spawning
//! that `broadside-mcp` binary instead. Full-screen ratatui runs
//! where stdout is a TTY; otherwise (pipes, CI) the line mode
//! runs — both share the same execute path.
//!
//! Trigger rules load from `--triggers <path>`, else
//! `./triggers.toml`, else the shipped defaults embedded in the
//! crate. The trigger transport is
//! [`UnavailableTransport`] in rung 1: rule evaluations are
//! audited in the Fleet panel, and a firing attempt records its
//! refusal — live firing is not claimed until a live MCP client
//! transport is wired and proven.
//!
//! Safety: this binary never deploys on its own. Plan mode is the
//! default, auto deploy requires a same-run verify pass, and the
//! member's own per-call confirmation + verify-receipt gate apply
//! inside every deploy. Tests never run this binary against a
//! production target.

#![forbid(unsafe_code)]

use std::io::{BufReader, IsTerminal};
use std::process::ExitCode;

use broadside_tui::app::{run_fullscreen, run_line_mode};
use broadside_tui::facade::{LibFacade, McpStdioFacade};
use broadside_tui::triggers::{
    DEFAULT_TRIGGERS_TOML, TriggerEngine, UnavailableTransport, parse_rules,
};
use broadside_tui::{App, BroadsideFacade};

struct Args {
    line: bool,
    mcp_program: Option<String>,
    triggers_path: Option<String>,
}

fn parse_args(argv: &[String]) -> Result<Args, ExitCode> {
    let mut args = Args {
        line: false,
        mcp_program: None,
        triggers_path: None,
    };
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--line" => args.line = true,
            "--mcp" => match iter.next() {
                Some(path) => args.mcp_program = Some(path.clone()),
                None => {
                    eprintln!("broadside-tui: --mcp needs a server binary path");
                    return Err(ExitCode::from(2));
                }
            },
            "--triggers" => match iter.next() {
                Some(path) => args.triggers_path = Some(path.clone()),
                None => {
                    eprintln!("broadside-tui: --triggers needs a path");
                    return Err(ExitCode::from(2));
                }
            },
            "--help" | "-h" => {
                println!(
                    "usage: broadside-tui [--line] [--mcp <broadside-mcp path>] \
                     [--triggers <triggers.toml>]"
                );
                println!("member config: BROADSIDE_* env (see broadside-mcp config)");
                return Err(ExitCode::SUCCESS);
            }
            other => {
                eprintln!("broadside-tui: unknown arg {other} (try --help)");
                return Err(ExitCode::from(2));
            }
        }
    }
    Ok(args)
}

fn load_rules(args: &Args) -> Result<Vec<broadside_tui::TriggerRule>, String> {
    if let Some(path) = &args.triggers_path {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read triggers {path}: {e}"))?;
        return parse_rules(&text);
    }
    let local = std::path::Path::new("triggers.toml");
    if local.exists() {
        let text = std::fs::read_to_string(local)
            .map_err(|e| format!("cannot read triggers.toml: {e}"))?;
        return parse_rules(&text);
    }
    parse_rules(DEFAULT_TRIGGERS_TOML)
}

fn run_with<F: BroadsideFacade>(facade: F, args: &Args) -> ExitCode {
    let rules = match load_rules(args) {
        Ok(rules) => rules,
        Err(e) => {
            eprintln!("broadside-tui: {e}");
            return ExitCode::FAILURE;
        }
    };
    let engine = TriggerEngine::new(rules, Box::new(UnavailableTransport));
    let mut app = App::new(facade, engine, "unavailable (rung 1: not wired live)");
    let result = if args.line || !std::io::stdout().is_terminal() {
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut stdout = std::io::stdout();
        run_line_mode(&mut app, &mut reader, &mut stdout)
    } else {
        run_fullscreen(&mut app)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("broadside-tui: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(args) => args,
        Err(code) => return code,
    };
    match &args.mcp_program {
        Some(program) => {
            let facade = McpStdioFacade::new(program.clone(), Vec::new());
            run_with(facade, &args)
        }
        None => {
            let facade = LibFacade::new(broadside_mcp::config::from_env());
            run_with(facade, &args)
        }
    }
}

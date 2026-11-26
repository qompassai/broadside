//! End-to-end protocol tests over the real binary's stdio:
//! era refusal, modern discover, tools/list shape, and a tool
//! round trip against fixture state. These are the same frames
//! the fleet conformance runner sends.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

struct Session {
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
}

fn spawn_session(envs: &[(&str, &str)]) -> Session {
    let mut command = Command::new(env!("CARGO_BIN_EXE_broadside-mcp"));
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn broadside-mcp");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    Session {
        child,
        stdin,
        lines: rx,
    }
}

impl Session {
    fn send(&mut self, frame: &Value) {
        let mut line = frame.to_string();
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).expect("write frame");
        self.stdin.flush().expect("flush");
    }

    fn recv(&self) -> Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(15))
            .expect("response within timeout");
        serde_json::from_str(&line).expect("response is JSON")
    }

    fn request(&mut self, frame: &Value) -> Value {
        self.send(frame);
        self.recv()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn modern_frame(id: u64, method: &str, params: Value) -> Value {
    // Modern-era frame: per-request _meta lives inside params and
    // carries the namespaced protocolVersion + clientCapabilities.
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

#[test]
fn classic_initialize_is_refused_with_typed_error() {
    let mut session = spawn_session(&[]);
    let response = session.request(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "probe", "version": "0"}},
    }));
    assert_eq!(response["error"]["code"], json!(-32022));
    assert_eq!(
        response["error"]["data"]["supported"],
        json!(["2026-07-28"])
    );
    // The connection survives the refusal: a modern frame on the
    // same session still answers.
    let discover = session.request(&modern_frame(2, "server/discover", json!({})));
    assert!(
        discover.get("result").is_some(),
        "discover answered: {discover}"
    );
}

#[test]
fn discover_advertises_exactly_one_version_and_six_tools() {
    let mut session = spawn_session(&[]);
    let discover = session.request(&modern_frame(1, "server/discover", json!({})));
    let versions = discover["result"]["supportedVersions"].clone();
    assert_eq!(versions, json!(["2026-07-28"]), "discover: {discover}");
    let tools = session.request(&modern_frame(2, "tools/list", json!({})));
    let names: Vec<String> = tools["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap_or_default().to_string())
        .collect();
    assert_eq!(names.len(), 6);
    assert!(names.iter().all(|n| n.starts_with("broadside_")));
    // Schema discipline: every tool's input schema carries an
    // object `properties` (never null — the fleet's D-1210 lesson).
    for tool in tools["result"]["tools"].as_array().expect("tools") {
        assert!(
            tool["inputSchema"]["properties"].is_object(),
            "properties object on {}",
            tool["name"]
        );
    }
}

#[test]
fn status_round_trip_on_empty_state() {
    let dir = std::env::temp_dir().join(format!("broadside-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    let state = dir.join("state");
    let site = dir.join("site");
    std::fs::create_dir_all(&site).expect("site mkdir");
    let mut session = spawn_session(&[
        ("BROADSIDE_STATE_DIR", state.to_str().expect("state path")),
        ("BROADSIDE_SITE_ROOT", site.to_str().expect("site path")),
    ]);
    let _ = session.request(&modern_frame(1, "server/discover", json!({})));
    let response = session.request(&modern_frame(
        2,
        "tools/call",
        json!({"name": "broadside_status", "arguments": {}}),
    ));
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let status: Value = serde_json::from_str(text).expect("status json");
    assert_eq!(status["receipts"]["count"], json!(0));
    assert_eq!(status["receipts"]["chain_ok"], json!(true));
    assert_eq!(status["key_record"], Value::Null);
    let _ = std::fs::remove_dir_all(&dir);
}

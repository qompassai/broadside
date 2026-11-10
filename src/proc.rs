//! Bounded subprocess execution for the pipeline steps (cargo,
//! git, rsync, ssh, python generators). Every run has a wall-clock
//! deadline and a captured-output bound; a step that exceeds
//! either is killed and reported, never waited on forever. Pipes
//! are drained on threads while the child runs — a child that
//! fills an undrained pipe would otherwise deadlock against the
//! deadline poll.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct ProcOutcome {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

fn drain<R: Read + Send + 'static>(mut reader: R) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if buf.len() < MAX_CAPTURE_BYTES {
                        let take = (MAX_CAPTURE_BYTES - buf.len()).min(n);
                        buf.extend_from_slice(&chunk[..take]);
                    }
                }
            }
        }
        buf
    })
}

/// Run `program args` in `dir` with the given deadline.
pub fn run_bounded(
    program: &str,
    args: &[&str],
    dir: Option<&std::path::Path>,
    deadline: Duration,
) -> Result<ProcOutcome, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot spawn {program}: {e}"))?;
    let out_thread = child.stdout.take().map(drain);
    let err_thread = child.stderr.take().map(drain);
    let started = Instant::now();
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) => {
                if started.elapsed() > deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (None, true);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("waiting on {program}: {e}")),
        }
    };
    let stdout_bytes = out_thread.and_then(|t| t.join().ok()).unwrap_or_default();
    let stderr_bytes = err_thread.and_then(|t| t.join().ok()).unwrap_or_default();
    Ok(ProcOutcome {
        success: status.map(|s| s.success()).unwrap_or(false),
        code: status.and_then(|s| s.code()),
        stdout: String::from_utf8_lossy(&stdout_bytes).to_string(),
        stderr: if timed_out {
            format!(
                "killed after {}s deadline; stderr tail: {}",
                deadline.as_secs(),
                tail(&String::from_utf8_lossy(&stderr_bytes), 400)
            )
        } else {
            String::from_utf8_lossy(&stderr_bytes).to_string()
        },
        timed_out,
    })
}

/// Tail of a text for receipt details (receipts carry summaries,
/// not log dumps; full logs stay on the machine).
pub fn tail(text: &str, max_chars: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars {
        return text.to_string();
    }
    chars[chars.len() - max_chars..].iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_and_captures() {
        let out = run_bounded("echo", &["hello"], None, Duration::from_secs(5)).expect("echo");
        assert!(out.success);
        assert_eq!(out.stdout.trim(), "hello");
    }

    #[test]
    fn large_output_does_not_deadlock() {
        // 200 KiB of stdout exceeds any pipe buffer; the drain
        // threads must keep the child unblocked.
        let out = run_bounded(
            "sh",
            &["-c", "head -c 200000 /dev/zero | tr '\\0' 'a'"],
            None,
            Duration::from_secs(10),
        )
        .expect("big output");
        assert!(out.success);
        assert!(out.stdout.len() >= 200_000 - 10);
    }

    #[test]
    fn deadline_kills_runaway() {
        // Adversarial: a step that never ends is killed at the
        // deadline and reported as timed out, not awaited.
        let out = run_bounded("sleep", &["30"], None, Duration::from_millis(300)).expect("sleep");
        assert!(!out.success);
        assert!(out.timed_out);
    }

    #[test]
    fn missing_program_is_an_error() {
        assert!(
            run_bounded(
                "broadside-no-such-program",
                &[],
                None,
                Duration::from_secs(2)
            )
            .is_err()
        );
    }
}

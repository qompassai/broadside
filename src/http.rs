//! Bounded HTTP client for live checks and citation routes.
//! Every fetch has a connect/read timeout and a body size bound;
//! an unbounded fetch in a verification path is a hang waiting for
//! a hostile server to schedule it.

use std::time::Duration;

/// Response body bound (4 MiB): pages and registry records are far
/// below this; anything larger is truncated and reported.
pub const MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(20);

pub struct Fetch {
    pub status: u16,
    pub body: Vec<u8>,
    /// True when the body hit the size bound and was truncated.
    pub truncated: bool,
}

fn agent() -> Result<ureq::Agent, String> {
    let config = ureq::Agent::config_builder()
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_recv_body(Some(READ_TIMEOUT))
        .timeout_recv_response(Some(READ_TIMEOUT))
        .http_status_as_error(false)
        .user_agent("broadside-mcp/1.0.0 (qompass.ai verification; +https://qompass.ai/solutions/mcp/broadside)")
        .build();
    Ok(ureq::Agent::new_with_config(config))
}

/// GET `url`. Transport failures are Err; any HTTP status is Ok —
/// the caller decides what a status means for its route.
pub fn get(url: &str) -> Result<Fetch, String> {
    get_with_accept(url, None)
}

/// GET with an optional Accept header (DOI content negotiation and
/// registry APIs are header-sensitive).
pub fn get_with_accept(url: &str, accept: Option<&str>) -> Result<Fetch, String> {
    let agent = agent()?;
    let mut request = agent.get(url);
    if let Some(accept) = accept {
        request = request.header("Accept", accept);
    }
    let mut response = request
        .call()
        .map_err(|e| format!("fetch {url} failed: {e}"))?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(MAX_BODY_BYTES + 1)
        .read_to_vec()
        .map_err(|e| format!("reading {url} body failed: {e}"))?;
    let truncated = body.len() as u64 > MAX_BODY_BYTES;
    Ok(Fetch {
        status,
        body,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Serve one canned HTTP response on a loopback port.
    fn serve_once(status: u16, body: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let reason = if status == 200 { "OK" } else { "Nope" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        port
    }

    #[test]
    fn fetch_reads_status_and_body() {
        let port = serve_once(200, "{\"ok\":true}");
        let fetch = get(&format!("http://127.0.0.1:{port}/x")).expect("fetch");
        assert_eq!(fetch.status, 200);
        assert_eq!(fetch.body, b"{\"ok\":true}");
        assert!(!fetch.truncated);
    }

    #[test]
    fn fetch_surfaces_error_status_without_throwing() {
        let port = serve_once(404, "missing");
        let fetch = get(&format!("http://127.0.0.1:{port}/x")).expect("fetch");
        assert_eq!(fetch.status, 404);
    }

    #[test]
    fn fetch_refuses_unroutable() {
        // Adversarial: a dead endpoint is an Err, not a hang or a
        // fabricated empty success.
        let result = get("http://127.0.0.1:1/never");
        assert!(result.is_err());
    }
}

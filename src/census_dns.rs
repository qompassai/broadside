//! The production `Resolver` for Passport Control (CENSUS.md
//! C3): a minimal, bounded DNS client over UDP — PTR plus A/AAAA
//! forward confirmation. It exists because the crate takes no
//! DNS library dependency and std exposes no reverse lookup.
//!
//! Bounds (Tiger Style): one configured nameserver, a 2 s
//! deadline per query, a 4 KiB response cap, at most 64 answers
//! read, name decompression capped at 10 jumps. Every failure
//! mode is an `Err` (the check could not be run → the session
//! stays UNVERIFIED) or an empty answer set (the lookup ran and
//! found nothing — definitive); a malformed packet is an `Err`,
//! never a panic and never a loop.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;

use crate::census::Resolver;

const DNS_PORT: u16 = 53;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RESPONSE_BYTES: usize = 4_096;
const MAX_NAME_JUMPS: usize = 10;
const MAX_ANSWERS: usize = 64;

const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_AAAA: u16 = 28;

/// A DNS client bound to the system's first configured
/// nameserver. When none can be determined, every query errors —
/// Passport Control then reports UNVERIFIED, never a guess.
pub struct UdpResolver {
    server: Option<IpAddr>,
}

impl UdpResolver {
    pub fn from_system() -> UdpResolver {
        UdpResolver {
            server: system_nameserver(),
        }
    }

    fn query(&self, name: &str, qtype: u16) -> Result<Vec<RData>, String> {
        let Some(server) = self.server else {
            return Err("no system nameserver configured".to_string());
        };
        let id = query_id();
        let packet = build_query(id, name, qtype)?;
        let bind: IpAddr = if server.is_ipv4() {
            Ipv4Addr::UNSPECIFIED.into()
        } else {
            Ipv6Addr::UNSPECIFIED.into()
        };
        let socket = UdpSocket::bind((bind, 0)).map_err(|e| format!("dns bind: {e}"))?;
        socket
            .set_read_timeout(Some(QUERY_TIMEOUT))
            .map_err(|e| format!("dns timeout set: {e}"))?;
        socket
            .connect((server, DNS_PORT))
            .map_err(|e| format!("dns connect: {e}"))?;
        socket.send(&packet).map_err(|e| format!("dns send: {e}"))?;
        let mut buf = vec![0u8; MAX_RESPONSE_BYTES];
        let n = socket
            .recv(&mut buf)
            .map_err(|e| format!("dns recv: {e}"))?;
        buf.truncate(n);
        parse_response(&buf, id, qtype)
    }
}

impl Resolver for UdpResolver {
    fn ptr(&self, ip: &str) -> Result<Option<String>, String> {
        let name = ptr_query_name(ip)?;
        let answers = self.query(&name, TYPE_PTR)?;
        Ok(answers.into_iter().find_map(|r| match r {
            RData::Ptr(host) => Some(host),
            _ => None,
        }))
    }

    fn forward(&self, host: &str) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        let mut any_ran = false;
        for qtype in [TYPE_A, TYPE_AAAA] {
            match self.query(host, qtype) {
                Ok(answers) => {
                    any_ran = true;
                    for answer in answers {
                        if let RData::Addr(ip) = answer {
                            out.push(ip);
                        }
                    }
                }
                Err(_) => continue,
            }
        }
        if any_ran {
            Ok(out)
        } else {
            Err("forward lookup could not be run".to_string())
        }
    }
}

/// The first `nameserver` in /etc/resolv.conf that parses.
fn system_nameserver() -> Option<IpAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    text.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("nameserver"), Some(addr)) => addr.parse::<IpAddr>().ok(),
            _ => None,
        }
    })
}

/// A query id from the clock and pid — uniqueness against stale
/// replies, not a security boundary (the socket is connected to
/// the configured server only, and answers are re-validated by
/// forward confirmation before anything is believed).
fn query_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (std::process::id() << 8)) as u16
}

/// The reverse-lookup name for an address: in-addr.arpa for IPv4,
/// ip6.arpa nibble form for IPv6.
fn ptr_query_name(ip: &str) -> Result<String, String> {
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        let o = v4.octets();
        return Ok(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]));
    }
    if let Ok(v6) = ip.parse::<Ipv6Addr>() {
        let mut nibbles: Vec<String> = Vec::with_capacity(32);
        for octet in v6.octets() {
            nibbles.push(format!("{:x}", octet >> 4));
            nibbles.push(format!("{:x}", octet & 0xf));
        }
        nibbles.reverse();
        return Ok(format!("{}.ip6.arpa", nibbles.join(".")));
    }
    Err(format!("unparseable address {ip:?}"))
}

/// Encode one question into a query packet (RD set, one question,
/// class IN). Names are validated label by label.
fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    write_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    Ok(out)
}

fn write_name(out: &mut Vec<u8>, name: &str) -> Result<(), String> {
    let name = name.trim_end_matches('.');
    if name.len() > 253 {
        return Err("dns name too long".to_string());
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("dns label invalid in {name:?}"));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("dns label has bad characters in {name:?}"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

enum RData {
    Ptr(String),
    Addr(String),
    Other,
}

/// Parse a response packet for answers of `qtype`. NXDOMAIN is
/// an empty answer set (definitive); other rcodes, a mismatched
/// id, or a truncated bit are errors (could-not-run).
fn parse_response(msg: &[u8], want_id: u16, qtype: u16) -> Result<Vec<RData>, String> {
    if msg.len() < 12 {
        return Err("dns response shorter than a header".to_string());
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    if id != want_id {
        return Err("dns response id mismatch".to_string());
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 == 0 {
        return Err("dns packet is not a response".to_string());
    }
    if flags & 0x0200 != 0 {
        return Err("dns response truncated (TC set)".to_string());
    }
    match flags & 0x000f {
        0 => {}
        3 => return Ok(Vec::new()), // NXDOMAIN: ran, found nothing
        rcode => return Err(format!("dns rcode {rcode}")),
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut off = 12;
    for _ in 0..qd {
        let (_, next) = read_name(msg, off, 0)?;
        off = next.checked_add(4).ok_or("dns question overruns packet")?;
        if off > msg.len() {
            return Err("dns question overruns packet".to_string());
        }
    }
    let mut out: Vec<RData> = Vec::new();
    for _ in 0..an.min(MAX_ANSWERS) {
        let (_, next) = read_name(msg, off, 0)?;
        off = next;
        if off.checked_add(10).is_none_or(|end| end > msg.len()) {
            return Err("dns answer overruns packet".to_string());
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        let rdata_off = off + 10;
        let rdata_end = rdata_off
            .checked_add(rdlen)
            .ok_or("dns rdata overruns packet")?;
        if rdata_end > msg.len() {
            return Err("dns rdata overruns packet".to_string());
        }
        let rdata = match (rtype, qtype) {
            (TYPE_PTR, TYPE_PTR) => {
                let (host, _) = read_name(msg, rdata_off, 0)?;
                RData::Ptr(host)
            }
            (TYPE_A, TYPE_A) if rdlen == 4 => RData::Addr(
                Ipv4Addr::new(
                    msg[rdata_off],
                    msg[rdata_off + 1],
                    msg[rdata_off + 2],
                    msg[rdata_off + 3],
                )
                .to_string(),
            ),
            (TYPE_AAAA, TYPE_AAAA) if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&msg[rdata_off..rdata_end]);
                RData::Addr(Ipv6Addr::from(octets).to_string())
            }
            _ => RData::Other,
        };
        out.push(rdata);
        off = rdata_end;
    }
    Ok(out)
}

/// Read a possibly-compressed name at `off`; returns the name
/// (no trailing dot) and the offset just past the name *at its
/// original position*. Jump count is capped and every offset is
/// bounds-checked — a pointer loop is an error, not a hang.
fn read_name(msg: &[u8], off: usize, depth: usize) -> Result<(String, usize), String> {
    if depth > MAX_NAME_JUMPS {
        return Err("dns name has too many compression jumps".to_string());
    }
    let mut labels: Vec<String> = Vec::new();
    let mut pos = off;
    let mut next: Option<usize> = None;
    loop {
        let len = *msg.get(pos).ok_or("dns name overruns packet")?;
        match len {
            0 => {
                return Ok((labels.join("."), next.unwrap_or(pos + 1)));
            }
            0xc0..=0xff => {
                let second = *msg
                    .get(pos + 1)
                    .ok_or("dns compression pointer overruns packet")?;
                let target = (((len as usize) & 0x3f) << 8) | second as usize;
                if target >= msg.len() {
                    return Err("dns compression pointer out of bounds".to_string());
                }
                if next.is_none() {
                    next = Some(pos + 2);
                }
                let (rest, _) = read_name(msg, target, depth + 1)?;
                if !rest.is_empty() {
                    labels.push(rest);
                }
                return Ok((labels.join("."), next.expect("next set above")));
            }
            1..=63 => {
                let start = pos + 1;
                let end = start + len as usize;
                if end > msg.len() {
                    return Err("dns label overruns packet".to_string());
                }
                labels.push(String::from_utf8_lossy(&msg[start..end]).to_string());
                pos = end;
            }
            _ => return Err("dns label length invalid".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal response packet by hand: one question,
    /// one answer of the given type/rdata (name = pointer to the
    /// question name at offset 12).
    fn canned_response(id: u16, qtype: u16, rtype: u16, rdata: &[u8], rcode: u16) -> Vec<u8> {
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&(0x8180u16 | rcode).to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        // question: 1.example.arpa PTR IN
        msg.extend_from_slice(&[
            1, b'1', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b'a', b'r', b'p', b'a', 0,
        ]);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        // answer: name = pointer to 12, type, class, ttl, rdlen, rdata
        msg.extend_from_slice(&[0xc0, 12]);
        msg.extend_from_slice(&rtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        msg.extend_from_slice(rdata);
        msg
    }

    fn name_bytes(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        write_name(&mut out, name).expect("name");
        out
    }

    #[test]
    fn ptr_answer_parses() {
        let msg = canned_response(
            42,
            TYPE_PTR,
            TYPE_PTR,
            &name_bytes("crawl-1.googlebot.com"),
            0,
        );
        let answers = parse_response(&msg, 42, TYPE_PTR).expect("parse");
        assert_eq!(answers.len(), 1);
        match &answers[0] {
            RData::Ptr(host) => assert_eq!(host, "crawl-1.googlebot.com"),
            _ => panic!("expected PTR"),
        }
    }

    #[test]
    fn a_answer_parses() {
        let msg = canned_response(7, TYPE_A, TYPE_A, &[66, 249, 66, 1], 0);
        let answers = parse_response(&msg, 7, TYPE_A).expect("parse");
        match &answers[0] {
            RData::Addr(ip) => assert_eq!(ip, "66.249.66.1"),
            _ => panic!("expected A"),
        }
    }

    #[test]
    fn nxdomain_is_empty_not_error() {
        // rcode 3 returns before any answer parsing: the lookup
        // ran and found nothing, which is a definitive empty set.
        let msg = canned_response(9, TYPE_PTR, TYPE_PTR, &[], 3);
        let answers = parse_response(&msg, 9, TYPE_PTR).expect("nxdomain ok");
        assert!(answers.is_empty());
    }

    #[test]
    fn compression_pointer_loop_errors_not_hangs() {
        // Adversarial: the answer name points at itself.
        let mut msg: Vec<u8> = Vec::new();
        msg.extend_from_slice(&5u16.to_be_bytes());
        msg.extend_from_slice(&0x8180u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT 0
        msg.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT 1
        msg.extend_from_slice(&0u16.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        let answer_off = msg.len();
        msg.extend_from_slice(&[0xc0, answer_off as u8]); // pointer to itself
        msg.extend_from_slice(&TYPE_PTR.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&0u32.to_be_bytes());
        msg.extend_from_slice(&0u16.to_be_bytes());
        assert!(parse_response(&msg, 5, TYPE_PTR).is_err());
    }

    #[test]
    fn truncated_and_wrong_id_error() {
        assert!(parse_response(&[0u8; 8], 1, TYPE_A).is_err());
        let msg = canned_response(3, TYPE_A, TYPE_A, &[1, 2, 3, 4], 0);
        assert!(parse_response(&msg, 4, TYPE_A).is_err());
        let cut = &msg[..msg.len() - 2];
        assert!(parse_response(cut, 3, TYPE_A).is_err());
    }

    #[test]
    fn ptr_query_names() {
        assert_eq!(
            ptr_query_name("66.249.66.1").expect("v4"),
            "1.66.249.66.in-addr.arpa"
        );
        let v6 = ptr_query_name("2001:db8::1").expect("v6");
        assert!(v6.ends_with(".ip6.arpa"));
        assert!(v6.starts_with("1.0.0.0"));
        assert!(ptr_query_name("not-an-ip").is_err());
    }

    #[test]
    fn query_encoding_validates_names() {
        assert!(build_query(1, "crawl-1.googlebot.com", TYPE_PTR).is_ok());
        assert!(build_query(1, "bad..name", TYPE_PTR).is_err());
        assert!(build_query(1, "bad name.example", TYPE_PTR).is_err());
        assert!(build_query(1, &"a".repeat(300), TYPE_PTR).is_err());
    }
}

//! H3 extraction layer: a fetched publisher page becomes
//! markdown before it is screened or read (estate fetched-content
//! doctrine, Class 1 — fetched web content → removal of hidden
//! text; RE evidence is Class 2 and never passes through here).
//!
//! The extractor is svipall-extract, pinned `=2.2.0` (MIT OR
//! Apache-2.0; both licence texts ship in the crate), adopted
//! under the 2026-11-26 re-measurement gate. Two gate conditions
//! are load-bearing in this module:
//!
//! 1. **Default options, never `main_content_only`.** The gate
//!    measured main-only collapsing recall to 0.0 on BBC / MDN /
//!    Spiegel-class pages (completeness 0.718 mean against 0.921
//!    for default mode). A citation verifier cannot verify what
//!    the extractor dropped, so this module exposes exactly one
//!    extraction shape: `ExtractOpts::default()`.
//! 2. **The hidden-text guarantee is narrower than the vendor's
//!    slogan.** Extraction removes text hidden by inline styles
//!    and attributes (gate: 0 of 13 such canaries leaked), but
//!    class-hidden text reaches the markdown unmarked (gate: 4 of
//!    8 class canaries leaked). Extraction is therefore never the
//!    only screen: the citation pipeline scans the extracted
//!    markdown AND the raw body, and the union decides hostility.
//!    The regression fixtures in tests/extract_gate.rs document
//!    this boundary; nothing in this module may claim more.
//!
//! The retained markdown is capped at [`MAX_EXTRACT_BYTES`]. The
//! cap is receipted — every extraction yields an
//! [`ExtractionRecord`] carrying the full size, the cap, and the
//! truncated flag, which lands in the verify receipt through
//! `CitationReport`. Screening runs over the FULL extraction,
//! before the cap: the cap bounds the retained working copy,
//! never the screen.

use serde_json::{Value, json};
use svipall_extract::{ExtractOpts, extract_markdown_opts};

use crate::sources::scan_for_injection;

/// Cap on retained extracted markdown (64 KiB). Consonant with
/// the H3 fetch bound (http::MAX_BODY_BYTES, 4 MiB) as the
/// working-material fraction of it: the gate's largest observed
/// extraction was a 165 KiB Frontiers page, and a verifier's
/// retained copy has no business growing past a quarter of that
/// order. Truncation at the cap is receipted, never silent.
pub const MAX_EXTRACT_BYTES: usize = 64 * 1024;

/// One extraction: the retained (capped) markdown, the screen
/// result over the full markdown, and the integrity label.
pub struct Extraction {
    /// Retained markdown, capped at [`MAX_EXTRACT_BYTES`].
    pub markdown: String,
    /// Byte length of the full extraction before the cap.
    pub full_bytes: usize,
    /// The cap in force for this extraction.
    pub cap: usize,
    /// True when the full extraction exceeded the cap and the
    /// retained markdown was truncated.
    pub truncated: bool,
    /// Integrity label: "full" | "partial" | "thin". Labels
    /// advise the consumer; they never discard a source.
    pub integrity: String,
    /// Named reasons behind the label (empty for "full").
    pub integrity_reasons: Vec<String>,
    /// Injection patterns found in the FULL extracted markdown.
    pub patterns: Vec<String>,
}

/// The receipted record of one extraction. Serialized into
/// `CitationReport`, which the pipeline places in the verify
/// receipt's outputs — the receipt is where a truncation is
/// allowed to exist; a silent one is a defect.
pub struct ExtractionRecord {
    pub source: String,
    pub wall_kind: String,
    pub integrity: String,
    pub integrity_reasons: Vec<String>,
    pub full_bytes: usize,
    pub cap: usize,
    pub truncated: bool,
}

impl ExtractionRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "source": self.source,
            "wall_kind": self.wall_kind,
            "integrity": self.integrity,
            "integrity_reasons": self.integrity_reasons,
            "extract_bytes": self.full_bytes,
            "extract_cap": self.cap,
            "extract_truncated": self.truncated,
        })
    }
}

/// Does this body look like an HTML page (vs a JSON record, a
/// plain-text file, or binary)? Extraction is an HTML operation;
/// non-HTML bodies keep the raw-body screen only.
pub fn looks_like_html(body: &str) -> bool {
    body.contains('<')
}

/// Screen extracted markdown. The screen reads the extract's
/// TEXT, not its markup: markdown emphasis would otherwise split
/// a payload the extractor itself rejoined — "Ignore **previous**
/// instructions" is one instruction to a reader and zero to a
/// substring scan (measured on the first wiring run, 2026-11-26:
/// a tag-split payload passed the extract screen unflagged until
/// the emphasis was stripped). Emphasis characters are removed,
/// not replaced, so the words close up exactly as a reader sees
/// them. The calibrated raw-body scanner is untouched; this
/// normalization applies to extracted markdown only.
fn screen(markdown: &str) -> Vec<String> {
    let text: String = markdown
        .chars()
        .filter(|c| !matches!(c, '*' | '_' | '`'))
        .collect();
    scan_for_injection(&text)
}

/// Extract one HTML page to markdown with default options and
/// screen the full extraction for injection payloads.
pub fn extract_and_screen(html: &str) -> Extraction {
    let full = extract_markdown_opts(html, &ExtractOpts::default());
    let patterns = screen(&full);
    let full_bytes = full.len();
    let truncated = full_bytes > MAX_EXTRACT_BYTES;
    let markdown = if truncated {
        let mut end = MAX_EXTRACT_BYTES;
        while !full.is_char_boundary(end) {
            end -= 1;
        }
        full[..end].to_string()
    } else {
        full
    };
    let mut reasons: Vec<String> = Vec::new();
    let integrity = if full_bytes == 0 {
        reasons.push("empty extraction (husk)".to_string());
        "thin"
    } else if full_bytes < 256 {
        reasons.push("very short extraction (script-rendered shell suspect)".to_string());
        "thin"
    } else if truncated {
        reasons.push("retained markdown hit the output cap".to_string());
        "partial"
    } else {
        "full"
    };
    Extraction {
        markdown,
        full_bytes,
        cap: MAX_EXTRACT_BYTES,
        truncated,
        integrity: integrity.to_string(),
        integrity_reasons: reasons,
        patterns,
    }
}

/// Classify the wall a fetch hit, per the estate fetch taxonomy:
/// `none / cloudflare / vendor / empty / status / gate / login /
/// paywall / notfound / softnotfound`. A named wall is reported
/// as a wall, never laundered into a content summary. The
/// classification is heuristic by construction (status line +
/// body markers + extraction shape) and is reported beside the
/// status it was derived from, never instead of it.
pub fn wall_kind(status: u16, body: &str, extraction: Option<&Extraction>) -> String {
    match status {
        404 | 410 => return "notfound".to_string(),
        401 => return "login".to_string(),
        402 => return "paywall".to_string(),
        403 => {
            let lowered = body.to_lowercase();
            let cloudflare = lowered.contains("cloudflare")
                && (lowered.contains("attention required")
                    || lowered.contains("just a moment")
                    || lowered.contains("checking your browser"));
            return if cloudflare {
                "cloudflare".to_string()
            } else {
                "vendor".to_string()
            };
        }
        500..=599 => return "status".to_string(),
        200..=299 => {}
        _ => return "status".to_string(),
    }
    let Some(extraction) = extraction else {
        return "none".to_string();
    };
    if extraction.full_bytes == 0 {
        return "empty".to_string();
    }
    // softnotfound: a 200 whose own text says the page is not
    // there. Checked against the head of the extraction only —
    // an article *about* a 404 is content, not a wall.
    let head: String = extraction
        .markdown
        .chars()
        .take(512)
        .collect::<String>()
        .to_lowercase();
    if head.contains("page not found") || head.contains("404 not found") {
        return "softnotfound".to_string();
    }
    "none".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_truncates_and_receipts() {
        let paragraph = "<p>The quick brown fox jumps over the lazy dog, and the \
                         log book records the weather for the third time today.</p>";
        let html = format!(
            "<html><body><article>{}</article></body></html>",
            paragraph.repeat(2000)
        );
        let extraction = extract_and_screen(&html);
        assert!(extraction.full_bytes > MAX_EXTRACT_BYTES);
        assert!(extraction.truncated);
        assert!(extraction.markdown.len() <= MAX_EXTRACT_BYTES);
        assert_eq!(extraction.cap, MAX_EXTRACT_BYTES);
        assert_eq!(extraction.integrity, "partial");
    }

    #[test]
    fn empty_page_is_thin_and_an_empty_wall() {
        let extraction = extract_and_screen("<html><body></body></html>");
        assert_eq!(extraction.full_bytes, 0);
        assert_eq!(extraction.integrity, "thin");
        assert_eq!(wall_kind(200, "<html></html>", Some(&extraction)), "empty");
    }

    #[test]
    fn wall_kinds_by_status() {
        assert_eq!(wall_kind(404, "", None), "notfound");
        assert_eq!(wall_kind(410, "", None), "notfound");
        assert_eq!(wall_kind(401, "", None), "login");
        assert_eq!(wall_kind(503, "", None), "status");
        assert_eq!(
            wall_kind(403, "<title>Attention Required! | Cloudflare</title>", None),
            "cloudflare"
        );
        assert_eq!(wall_kind(403, "Forbidden", None), "vendor");
    }

    #[test]
    fn record_serializes_the_receipt_fields() {
        let record = ExtractionRecord {
            source: "https://example.org/paper".to_string(),
            wall_kind: "none".to_string(),
            integrity: "partial".to_string(),
            integrity_reasons: vec!["retained markdown hit the output cap".to_string()],
            full_bytes: 200_000,
            cap: MAX_EXTRACT_BYTES,
            truncated: true,
        };
        let value = record.to_json();
        assert_eq!(value["extract_bytes"], 200_000);
        assert_eq!(value["extract_cap"], MAX_EXTRACT_BYTES);
        assert_eq!(value["extract_truncated"], true);
        assert_eq!(value["wall_kind"], "none");
    }
}

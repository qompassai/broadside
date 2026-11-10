//! Fixture generator for the broadside e2e: writes a FIXTURE
//! signed key record and a FIXTURE signed honeypot manifest into
//! a site-tree copy, signed with deterministic fixture keys.
//!
//! Fixtures exist so the whole pipeline (build → verify → deploy
//! to staging) can run end to end without the Owner's real keys.
//! Every artifact carries `"fixture": true`, receipts surface the
//! flag, and a fixture record must never reach production — the
//! production key record and canary manifest are Owner-signed
//! with keys that never enter this repository or server.
//!
//! Usage: cargo run --example make_fixtures -- <site_root>
//! Prints the canary signer public key to pin in the server
//! config (BROADSIDE_CANARY_SIGNER_PUBKEY) for the fixture run.

use broadside_mcp::canonical::canonicalize;
use broadside_mcp::crypto::{b64url_encode, sign_for_fixture};
use serde_json::{Value, json};

/// Deterministic fixture seeds (label-derived constants; these
/// keys protect nothing and are published here on purpose).
const CARD_SEED: [u8; 32] = [
    0x42, 0x52, 0x4f, 0x41, 0x44, 0x53, 0x49, 0x44, 0x45, 0x2d, 0x43, 0x41, 0x52, 0x44, 0x2d, 0x46,
    0x49, 0x58, 0x54, 0x55, 0x52, 0x45, 0x2d, 0x4b, 0x45, 0x59, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x31,
];
const CANARY_SEED: [u8; 32] = [
    0x42, 0x52, 0x4f, 0x41, 0x44, 0x53, 0x49, 0x44, 0x45, 0x2d, 0x43, 0x41, 0x4e, 0x41, 0x52, 0x59,
    0x2d, 0x46, 0x49, 0x58, 0x54, 0x55, 0x52, 0x45, 0x2d, 0x53, 0x55, 0x42, 0x4b, 0x45, 0x59, 0x31,
];

fn sign_record(unsigned: &Value, seed: &[u8; 32]) -> Value {
    let canonical = canonicalize(unsigned).expect("canonical fixture");
    let (_, signature) = sign_for_fixture(seed, canonical.as_bytes());
    let mut signed = unsigned.clone();
    signed["signature"] = json!(b64url_encode(&signature));
    signed
}

fn main() {
    let site = std::env::args()
        .nth(1)
        .expect("usage: make_fixtures <site_root>");
    let site = std::path::PathBuf::from(site);

    // Fixture Agent Card key record (self-signed by the fixture
    // card key, exactly the production record's shape).
    let (card_public, _) = sign_for_fixture(&CARD_SEED, b"");
    let record = sign_record(
        &json!({
            "record": "broadside.agent-card-key", "version": 1,
            "kid": "fixture-agent-card-1", "kty": "OKP", "crv": "Ed25519",
            "use": "sig", "alg": "EdDSA",
            "x": b64url_encode(&card_public),
            "issued": "2026-11-10", "fixture": true,
        }),
        &CARD_SEED,
    );
    let keys_dir = site.join("keys");
    std::fs::create_dir_all(&keys_dir).expect("keys dir");
    std::fs::write(
        keys_dir.join("agent-card-key-record.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&record).expect("record json")
        ),
    )
    .expect("write key record");

    // Fixture honeypot manifest (signed by the fixture canary
    // subkey under the pinned-signer rule).
    let (canary_public, _) = sign_for_fixture(&CANARY_SEED, b"");
    let manifest = sign_record(
        &json!({
            "manifest": "broadside.honeypot", "version": 1,
            "revision": "fixture-2026-11-10.1",
            "signer_kid": "fixture-canary-subkey-1",
            "canaries": [
                {"path": "/.env", "kind": "env"},
                {"path": "/wp-login.php", "kind": "page"},
                {"path": "/admin/", "kind": "page"},
                {"path": "/backup.zip", "kind": "page"},
            ],
            "credential": {
                "slot": "QOMPASS_DEPLOY_TOKEN",
                "value": "canary-fixture-4f2a9c1e5b8d2046",
            },
            "fixture": true,
        }),
        &CANARY_SEED,
    );
    let honeypot_dir = site.join("honeypot");
    std::fs::create_dir_all(&honeypot_dir).expect("honeypot dir");
    std::fs::write(
        honeypot_dir.join("manifest.json"),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&manifest).expect("manifest json")
        ),
    )
    .expect("write manifest");

    println!("FIXTURE_CARD_KID=fixture-agent-card-1");
    println!("CANARY_SIGNER_PUBKEY={}", b64url_encode(&canary_public));
}

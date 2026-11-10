//! The Agent Card key record and the JWKS document it publishes.
//!
//! The estate's Agent Card signing key is Owner-held: its private
//! half never enters broadside or the site host. What the site tree
//! carries is a *signed key record* (`keys/agent-card-key-record.json`):
//! the public JWK plus an Ed25519 signature by the card key itself
//! over the record's RFC 8785 canonical form. Build places
//! `dist/.well-known/jwks.json` from the record; verify fails
//! closed on any mismatch between the three: record signature,
//! record contents, published JWKS. Rotation is a new signed
//! record with a new kid — the old kid stays published as long as
//! its record is in the tree's record list.
//!
//! A record with `"fixture": true` is a test key record: the whole
//! pipeline runs against it, and every receipt that touches it
//! says so. A fixture record must never be what production serves
//! — status surfaces the flag so the substitution cannot hide.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::canonical::canonicalize;
use crate::crypto::{b64url_decode, ed25519_verify};

pub const RECORD_KIND: &str = "broadside.agent-card-key";
pub const RECORD_PATH: &str = "keys/agent-card-key-record.json";
pub const JWKS_ROUTE: &str = "/.well-known/jwks.json";
pub const JWKS_RELPATH: &str = ".well-known/jwks.json";

#[derive(Clone, Debug, Deserialize)]
pub struct KeyRecord {
    pub record: String,
    pub version: u64,
    pub kid: String,
    pub kty: String,
    pub crv: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub alg: String,
    pub x: String,
    pub issued: String,
    #[serde(default)]
    pub fixture: bool,
    pub signature: String,
}

/// Load the key record from the site tree. Absent file = Ok(None):
/// absence is a state callers report, not corruption. A present
/// but malformed or wrongly-shaped record is an error.
pub fn load_key_record(site_root: &Path) -> Result<Option<(KeyRecord, Value)>, String> {
    let path: PathBuf = site_root.join(RECORD_PATH);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read key record {}: {e}", path.display()))?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|e| format!("key record is not JSON: {e}"))?;
    let record: KeyRecord = serde_json::from_value(value.clone())
        .map_err(|e| format!("key record shape invalid: {e}"))?;
    if record.record != RECORD_KIND || record.version != 1 {
        return Err("key record kind/version not recognized".to_string());
    }
    if record.kty != "OKP" || record.crv != "Ed25519" || record.alg != "EdDSA" {
        return Err("key record is not an Ed25519 OKP record".to_string());
    }
    Ok(Some((record, value)))
}

/// Verify the record's self-signature over its canonical form
/// (record object minus the `signature` field), using the record's
/// own public key.
pub fn record_signature_valid(record_json: &Value, record: &KeyRecord) -> bool {
    let mut stripped = record_json.clone();
    if let Some(obj) = stripped.as_object_mut() {
        obj.remove("signature");
    }
    let Ok(canonical) = canonicalize(&stripped) else {
        return false;
    };
    let (Ok(public), Ok(signature)) = (b64url_decode(&record.x), b64url_decode(&record.signature))
    else {
        return false;
    };
    ed25519_verify(&public, canonical.as_bytes(), &signature)
}

/// The JWKS document for one record: exactly the public JWK.
pub fn jwks_document(record: &KeyRecord) -> Value {
    json!({
        "keys": [{
            "kid": record.kid,
            "kty": record.kty,
            "crv": record.crv,
            "use": record.key_use,
            "alg": record.alg,
            "x": record.x,
        }]
    })
}

/// The exact bytes build writes for the JWKS artifact.
pub fn jwks_bytes(record: &KeyRecord) -> Vec<u8> {
    let mut text = serde_json::to_string_pretty(&jwks_document(record)).unwrap_or_default();
    text.push('\n');
    text.into_bytes()
}

/// Place the JWKS artifact into a dist tree.
pub fn place_jwks(dist: &Path, record: &KeyRecord) -> Result<(), String> {
    let dir = dist.join(".well-known");
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    std::fs::write(dir.join("jwks.json"), jwks_bytes(record))
        .map_err(|e| format!("cannot write JWKS artifact: {e}"))
}

/// Check a dist tree's JWKS artifact against the record: the file
/// must exist and parse to exactly the expected document.
pub fn check_jwks(dist: &Path, record: &KeyRecord) -> Result<(), String> {
    let path = dist.join(JWKS_RELPATH);
    let raw = std::fs::read_to_string(&path)
        .map_err(|_| "dist has no .well-known/jwks.json".to_string())?;
    let actual: Value =
        serde_json::from_str(&raw).map_err(|e| format!("dist JWKS is not JSON: {e}"))?;
    if actual != jwks_document(record) {
        return Err("dist JWKS does not match the signed key record".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{b64url_encode, sign_for_fixture};

    /// Build a signed fixture record with a fixed seed.
    fn fixture_record(fixture: bool) -> (Value, KeyRecord) {
        let mut unsigned = json!({
            "record": RECORD_KIND, "version": 1,
            "kid": "fixture-kid-1", "kty": "OKP", "crv": "Ed25519",
            "use": "sig", "alg": "EdDSA", "x": "",
            "issued": "2026-11-10", "fixture": fixture,
        });
        let (public, _) = sign_for_fixture(&[3u8; 32], b"");
        unsigned["x"] = json!(b64url_encode(&public));
        let canonical = canonicalize(&unsigned).expect("canonical");
        let (_, signature) = sign_for_fixture(&[3u8; 32], canonical.as_bytes());
        let mut signed = unsigned.clone();
        signed["signature"] = json!(b64url_encode(&signature));
        let record: KeyRecord = serde_json::from_value(signed.clone()).expect("record shape");
        (signed, record)
    }

    #[test]
    fn valid_fixture_record_verifies() {
        let (value, record) = fixture_record(true);
        assert!(record_signature_valid(&value, &record));
        assert!(record.fixture);
    }

    #[test]
    fn tampered_record_fails_closed() {
        // Adversarial: swapping the public key (or kid) after
        // signing must invalidate the record.
        let (mut value, record) = fixture_record(false);
        let (other_public, _) = sign_for_fixture(&[4u8; 32], b"");
        value["x"] = json!(b64url_encode(&other_public));
        let tampered: KeyRecord = serde_json::from_value(value.clone()).expect("shape");
        assert!(!record_signature_valid(&value, &tampered));
        let (mut value2, _) = fixture_record(false);
        value2["kid"] = json!("swapped-kid");
        let tampered2: KeyRecord = serde_json::from_value(value2.clone()).expect("shape");
        assert!(!record_signature_valid(&value2, &tampered2));
        let _ = record;
    }

    #[test]
    fn jwks_place_and_check_round_trip() {
        let (_, record) = fixture_record(true);
        let dir = std::env::temp_dir().join(format!("broadside-jwks-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        place_jwks(&dir, &record).expect("place");
        check_jwks(&dir, &record).expect("check");
        // Adversarial: a doctored JWKS in dist is a mismatch.
        let path = dir.join(JWKS_RELPATH);
        let mut doc: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        doc["keys"][0]["x"] = json!("AAAA");
        std::fs::write(&path, doc.to_string()).expect("rewrite");
        assert!(check_jwks(&dir, &record).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_record_is_none_not_error() {
        let dir = std::env::temp_dir().join("broadside-no-record-xyz");
        assert!(load_key_record(&dir).expect("ok").is_none());
    }
}

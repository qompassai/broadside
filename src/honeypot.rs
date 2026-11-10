//! The honeypot layer's build side (HONEYPOT.md H1/H2/H6): a
//! signed canary manifest in the site tree names decoy endpoints
//! and one canary credential; build injects the decoys into dist,
//! verify checks their integrity. Rules that shape this module:
//!
//! - The manifest is an RFC 8785 canonical document signed by the
//!   Owner under a dedicated canary subkey. broadside verifies the
//!   signature against a *pinned* signer key (server config)
//!   BEFORE any injection; unpinned or invalid = fail closed.
//! - The bait is never signed and carries no marker: nothing in a
//!   planted file reveals it is a canary.
//! - A canary path that collides with real content is a hard
//!   failure — the layer never overwrites a real page.
//! - No hack-back exists anywhere in this design; detection is
//!   receipts and (host-side, Owner-applied) H4 config.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::canonical::canonicalize;
use crate::crypto::{b64url_decode, ed25519_verify, sha256_hex};

pub const MANIFEST_KIND: &str = "broadside.honeypot";
pub const MANIFEST_PATH: &str = "honeypot/manifest.json";

#[derive(Clone, Debug, Deserialize)]
pub struct Canary {
    /// Served path, e.g. "/.env" or "/wp-login.php" or "/admin/".
    pub path: String,
    /// "env" (a decoy environment file) or "page" (a decoy page).
    pub kind: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Credential {
    /// The variable name the credential is planted under.
    pub slot: String,
    /// The canary value: a real-looking secret, valid nowhere.
    pub value: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Manifest {
    pub manifest: String,
    pub version: u64,
    pub revision: String,
    pub signer_kid: String,
    pub canaries: Vec<Canary>,
    pub credential: Credential,
    #[serde(default)]
    pub fixture: bool,
    pub signature: String,
}

/// Load the manifest from the site tree. Absent = Ok(None).
pub fn load_manifest(site_root: &Path) -> Result<Option<(Manifest, Value)>, String> {
    let path: PathBuf = site_root.join(MANIFEST_PATH);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read honeypot manifest {}: {e}", path.display()))?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|e| format!("honeypot manifest is not JSON: {e}"))?;
    let manifest: Manifest = serde_json::from_value(value.clone())
        .map_err(|e| format!("honeypot manifest shape invalid: {e}"))?;
    if manifest.manifest != MANIFEST_KIND || manifest.version != 1 {
        return Err("honeypot manifest kind/version not recognized".to_string());
    }
    if manifest.canaries.is_empty() || manifest.canaries.len() > 64 {
        return Err("honeypot manifest canary count outside 1..=64".to_string());
    }
    for canary in &manifest.canaries {
        validate_canary_path(&canary.path)?;
        if canary.kind != "env" && canary.kind != "page" {
            return Err(format!("unknown canary kind {}", canary.kind));
        }
    }
    Ok(Some((manifest, value)))
}

/// A canary path must be absolute, traversal-free, and not a path
/// the real site legitimately serves from source.
fn validate_canary_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains("..") || path.contains('\\') {
        return Err(format!("canary path {path} is not a clean absolute path"));
    }
    if path == "/" || path == "/index.html" || path.starts_with("/.well-known/") {
        return Err(format!(
            "canary path {path} collides with a real route class"
        ));
    }
    Ok(())
}

/// Verify the manifest signature against the pinned signer public
/// key (base64url). Unpinned signer = failure: H6's enforcement is
/// meaningless if any self-presented key is trusted.
pub fn manifest_signature_valid(
    manifest_json: &Value,
    manifest: &Manifest,
    pinned_signer_pubkey_b64: Option<&str>,
) -> Result<(), String> {
    let Some(pinned) = pinned_signer_pubkey_b64 else {
        return Err("no canary signer pinned in server config; refusing to trust manifest".into());
    };
    let pinned_bytes =
        b64url_decode(pinned).map_err(|e| format!("pinned signer key malformed: {e}"))?;
    let signature = b64url_decode(&manifest.signature)
        .map_err(|_| "manifest signature malformed".to_string())?;
    let mut stripped = manifest_json.clone();
    if let Some(obj) = stripped.as_object_mut() {
        obj.remove("signature");
    }
    let canonical = canonicalize(&stripped)?;
    if ed25519_verify(&pinned_bytes, canonical.as_bytes(), &signature) {
        Ok(())
    } else {
        Err("honeypot manifest signature does not verify against the pinned canary signer".into())
    }
}

/// Dist-relative file for a canary path (directory paths get an
/// index.html, as the static host serves them).
pub fn canary_relpath(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.ends_with('/') || trimmed.is_empty() {
        format!("{trimmed}index.html")
    } else {
        trimmed.to_string()
    }
}

/// The exact bytes a canary serves. Deterministic from the
/// manifest, so integrity checking is a byte comparison. The
/// content is bait-shaped and carries no canary marker (H6).
pub fn canary_bytes(manifest: &Manifest, canary: &Canary) -> Vec<u8> {
    match canary.kind.as_str() {
        "env" => format!(
            "APP_ENV=production\nAPP_DEBUG=false\nDATABASE_URL=postgres://app:dbpass@db.internal:5432/qompass\n{}={}\nSESSION_SECRET=7f3a9c1e5b8d2046a1f7c9e3b5d70812\n",
            manifest.credential.slot, manifest.credential.value
        )
        .into_bytes(),
        _ => format!(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\" /><title>Sign in</title></head>\n<body>\n<h1>Administration</h1>\n<form method=\"post\" action=\"{path}\">\n<label>Username <input name=\"username\" /></label>\n<label>Password <input type=\"password\" name=\"password\" /></label>\n<button type=\"submit\">Sign in</button>\n</form>\n</body>\n</html>\n",
            path = canary.path
        )
        .into_bytes(),
    }
}

/// Inject all canaries into dist plus the robots.txt Disallow
/// lines. Refuses to overwrite any existing file that is not
/// already the exact canary content (collision with real content).
pub fn inject(dist: &Path, manifest: &Manifest) -> Result<Value, String> {
    let mut placed: Vec<Value> = Vec::new();
    for canary in &manifest.canaries {
        let rel = canary_relpath(&canary.path);
        let target = dist.join(&rel);
        let bytes = canary_bytes(manifest, canary);
        if target.exists() {
            let existing = std::fs::read(&target)
                .map_err(|e| format!("cannot read {}: {e}", target.display()))?;
            if existing != bytes {
                return Err(format!(
                    "canary path {} collides with real dist content at {rel}",
                    canary.path
                ));
            }
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            std::fs::write(&target, &bytes)
                .map_err(|e| format!("cannot write canary {rel}: {e}"))?;
        }
        placed.push(json!({"path": canary.path, "file": rel, "sha256": sha256_hex(&bytes)}));
    }
    merge_robots(dist, manifest)?;
    Ok(json!({"canaries": placed, "revision": manifest.revision, "fixture": manifest.fixture}))
}

/// Ensure dist/robots.txt disallows every canary path (H1: decoys
/// are excluded from legitimate crawling, so any hit is hostile
/// by construction). Existing content is preserved.
fn merge_robots(dist: &Path, manifest: &Manifest) -> Result<(), String> {
    let path = dist.join("robots.txt");
    let mut text = if path.exists() {
        std::fs::read_to_string(&path).map_err(|e| format!("cannot read robots.txt: {e}"))?
    } else {
        "User-agent: *\n".to_string()
    };
    for canary in &manifest.canaries {
        let line = format!("Disallow: {}", canary.path);
        if !text.lines().any(|l| l.trim() == line) {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&line);
            text.push('\n');
        }
    }
    std::fs::write(&path, text).map_err(|e| format!("cannot write robots.txt: {e}"))
}

/// Verify-side integrity: every canary present with exact bytes,
/// the credential planted in the env canary, robots disallows in
/// place. Returns a detail string on success.
pub fn check_integrity(dist: &Path, manifest: &Manifest) -> Result<String, String> {
    for canary in &manifest.canaries {
        let rel = canary_relpath(&canary.path);
        let target = dist.join(&rel);
        let actual = std::fs::read(&target)
            .map_err(|_| format!("canary {} missing from dist ({rel})", canary.path))?;
        if actual != canary_bytes(manifest, canary) {
            return Err(format!(
                "canary {} content differs from the signed manifest",
                canary.path
            ));
        }
        if canary.kind == "env" {
            let text = String::from_utf8_lossy(&actual);
            let planted = format!("{}={}", manifest.credential.slot, manifest.credential.value);
            if !text.contains(&planted) {
                return Err("canary credential not planted in the env canary".to_string());
            }
        }
    }
    let robots = std::fs::read_to_string(dist.join("robots.txt"))
        .map_err(|_| "dist robots.txt missing (canary disallows absent)".to_string())?;
    for canary in &manifest.canaries {
        let line = format!("Disallow: {}", canary.path);
        if !robots.lines().any(|l| l.trim() == line) {
            return Err(format!("robots.txt does not disallow {}", canary.path));
        }
    }
    Ok(format!(
        "{} canaries intact at revision {}",
        manifest.canaries.len(),
        manifest.revision
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{b64url_encode, sign_for_fixture};

    const SEED: [u8; 32] = [11u8; 32];

    fn signed_manifest() -> (Manifest, Value, String) {
        let (public, _) = sign_for_fixture(&SEED, b"");
        let mut unsigned = json!({
            "manifest": MANIFEST_KIND, "version": 1, "revision": "test-1",
            "signer_kid": "canary-subkey-test",
            "canaries": [
                {"path": "/.env", "kind": "env"},
                {"path": "/wp-login.php", "kind": "page"},
                {"path": "/admin/", "kind": "page"},
            ],
            "credential": {"slot": "QOMPASS_DEPLOY_TOKEN", "value": "canary-deadbeef-token"},
            "fixture": true,
        });
        let canonical = canonicalize(&unsigned).expect("canonical");
        let (_, signature) = sign_for_fixture(&SEED, canonical.as_bytes());
        unsigned["signature"] = json!(b64url_encode(&signature));
        let manifest: Manifest = serde_json::from_value(unsigned.clone()).expect("shape");
        (manifest, unsigned, b64url_encode(&public))
    }

    #[test]
    fn valid_signature_verifies_against_pinned_key() {
        let (manifest, value, pinned) = signed_manifest();
        assert!(manifest_signature_valid(&value, &manifest, Some(&pinned)).is_ok());
    }

    #[test]
    fn unpinned_or_wrong_signer_fails_closed() {
        // Adversarial (H6): no pinned key, a stranger's key, or a
        // post-signing edit must all stop injection.
        let (manifest, value, _pinned) = signed_manifest();
        assert!(manifest_signature_valid(&value, &manifest, None).is_err());
        let (stranger, _) = sign_for_fixture(&[12u8; 32], b"");
        assert!(
            manifest_signature_valid(&value, &manifest, Some(&b64url_encode(&stranger))).is_err()
        );
        let mut edited = value.clone();
        edited["canaries"][0]["path"] = json!("/config.php");
        let edited_manifest: Manifest = serde_json::from_value(edited.clone()).expect("shape");
        let (_, _, pinned) = signed_manifest();
        assert!(manifest_signature_valid(&edited, &edited_manifest, Some(&pinned)).is_err());
    }

    #[test]
    fn inject_and_integrity_round_trip() {
        let (manifest, _, _) = signed_manifest();
        let dir = std::env::temp_dir().join(format!("broadside-honeypot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        inject(&dir, &manifest).expect("inject");
        let detail = check_integrity(&dir, &manifest).expect("integrity");
        assert!(detail.contains("3 canaries"));
        // The credential is planted, byte-exact.
        let env = std::fs::read_to_string(dir.join(".env")).expect("env canary");
        assert!(env.contains("QOMPASS_DEPLOY_TOKEN=canary-deadbeef-token"));
        // Adversarial: tamper with one canary -> integrity fails.
        std::fs::write(dir.join("wp-login.php"), b"pwned").expect("tamper");
        assert!(check_integrity(&dir, &manifest).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn injection_refuses_to_overwrite_real_content() {
        // Adversarial: if a real page already sits at a canary
        // path, injection stops instead of replacing it.
        let (manifest, _, _) = signed_manifest();
        let dir = std::env::temp_dir().join(format!("broadside-collide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        std::fs::write(dir.join(".env"), b"REAL=content").expect("real file");
        assert!(inject(&dir, &manifest).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join(".env")).expect("unchanged"),
            "REAL=content"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_validation_rejects_traversal_and_real_routes() {
        assert!(validate_canary_path("/.env").is_ok());
        assert!(validate_canary_path("/../etc/passwd").is_err());
        assert!(validate_canary_path("/").is_err());
        assert!(validate_canary_path("/.well-known/jwks.json").is_err());
        assert!(validate_canary_path("relative/path").is_err());
    }
}

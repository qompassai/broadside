//! Small cryptographic helpers: SHA-256 hex digests, base64url
//! (RFC 4648 §5, no padding — the JWK/JWS encoding), and Ed25519
//! signature verification. Signing keys never enter this server:
//! verification only. Fixture signing for tests and the fixture
//! generator example lives behind the `sign_for_fixture` helper,
//! which callers outside tests must not use on production records.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// base64url-no-pad encoding, as used by JWK `x` values and the
/// signature fields in broadside records.
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url (padding optional on input).
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, String> {
    let trimmed = text.trim().trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| format!("base64url decode failed: {e}"))
}

/// Verify an Ed25519 signature. `public_key` is the raw 32-byte key,
/// `signature` the raw 64-byte signature. Any malformed input is a
/// verification failure, never a panic — fail closed.
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key_bytes) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    key.verify(message, &Signature::from_bytes(&sig_bytes))
        .is_ok()
}

/// Sign with a 32-byte seed. FIXTURE USE ONLY: production records
/// are signed by Owner-held keys outside this server (the Agent Card
/// key and the canary subkey never enter broadside).
#[doc(hidden)]
pub fn sign_for_fixture(seed: &[u8; 32], message: &[u8]) -> ([u8; 32], [u8; 64]) {
    use ed25519_dalek::{Signer, SigningKey};
    let signing = SigningKey::from_bytes(seed);
    let public = signing.verifying_key().to_bytes();
    let signature = signing.sign(message).to_bytes();
    (public, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn b64url_round_trip_and_rejects_garbage() {
        let data = [0u8, 1, 250, 251, 252, 253, 254, 255, 66];
        let encoded = b64url_encode(&data);
        assert!(!encoded.contains('='));
        assert_eq!(b64url_decode(&encoded).expect("round trip"), data);
        assert!(b64url_decode("!!!not-base64!!!").is_err());
    }

    #[test]
    fn ed25519_fixture_sign_verify_and_tamper_fails() {
        let seed = [7u8; 32];
        let (public, signature) = sign_for_fixture(&seed, b"broadside");
        assert!(ed25519_verify(&public, b"broadside", &signature));
        // Adversarial: tampered message, tampered signature, wrong
        // key, and truncated inputs all fail closed.
        assert!(!ed25519_verify(&public, b"broadside!", &signature));
        let mut bad_sig = signature;
        bad_sig[0] ^= 1;
        assert!(!ed25519_verify(&public, b"broadside", &bad_sig));
        let (other_public, _) = sign_for_fixture(&[9u8; 32], b"broadside");
        assert!(!ed25519_verify(&other_public, b"broadside", &signature));
        assert!(!ed25519_verify(&public[..16], b"broadside", &signature));
        assert!(!ed25519_verify(&public, b"broadside", &signature[..32]));
        assert!(!ed25519_verify(&[], b"", &[]));
    }
}

//! The dist tree manifest: every file under dist/, its SHA-256,
//! and one tree hash over the whole set. The manifest is the unit
//! of identity for the pipeline — build produces it, verify checks
//! it, deploy ships exactly it, live check compares the live site
//! against it. Two trees with the same tree hash are byte-identical
//! in content and layout; nothing weaker is ever called "the same
//! dist".
//!
//! Tree hash: SHA-256 over the concatenation, in byte-sorted
//! relative-path order, of `"<relpath>\0<file-sha256-hex>\n"` lines.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::crypto::sha256_hex;

/// One manifest: sorted entries plus the tree hash.
pub struct DistManifest {
    pub entries: Vec<(String, String, u64)>, // (relpath, sha256 hex, bytes)
    pub tree_hash: String,
}

/// Bound on files in one dist tree — a runaway tree is a defect,
/// not something to hash forever.
pub const MAX_DIST_FILES: usize = 20_000;
/// Bound on one file's size inside dist (the WASM bundle is the
/// largest legitimate artifact; 256 MiB is generous headroom).
pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

/// Walk `dist` and build its manifest. Symlinks are refused: a
/// deployed tree must be plain files, and following links would
/// let the manifest certify content outside the tree.
pub fn manifest_of(dist: &Path) -> Result<DistManifest, String> {
    if !dist.is_dir() {
        return Err(format!("dist tree {} is not a directory", dist.display()));
    }
    let mut files: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![dist.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("cannot read dir entry: {e}"))?;
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
            if kind.is_symlink() {
                return Err(format!("dist contains a symlink: {}", path.display()));
            } else if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() {
                files.push(path);
            }
        }
        if files.len() > MAX_DIST_FILES {
            return Err(format!("dist exceeds {MAX_DIST_FILES} files"));
        }
    }
    let mut entries: Vec<(String, String, u64)> = Vec::with_capacity(files.len());
    for path in files {
        let rel = path
            .strip_prefix(dist)
            .map_err(|_| "walk escaped the dist root".to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        let meta =
            std::fs::metadata(&path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if meta.len() > MAX_FILE_BYTES {
            return Err(format!("dist file exceeds size bound: {rel}"));
        }
        let bytes =
            std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        entries.push((rel, sha256_hex(&bytes), meta.len()));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher_input = String::new();
    for (rel, hash, _) in &entries {
        hasher_input.push_str(rel);
        hasher_input.push('\0');
        hasher_input.push_str(hash);
        hasher_input.push('\n');
    }
    Ok(DistManifest {
        tree_hash: sha256_hex(hasher_input.as_bytes()),
        entries,
    })
}

impl DistManifest {
    /// Manifest as receipt JSON: tree hash, file count, total
    /// bytes, and the per-file entries.
    pub fn to_json(&self) -> Value {
        let files: Vec<Value> = self
            .entries
            .iter()
            .map(|(rel, hash, bytes)| json!({"path": rel, "sha256": hash, "bytes": bytes}))
            .collect();
        let total: u64 = self.entries.iter().map(|e| e.2).sum();
        json!({
            "tree_hash": self.tree_hash,
            "file_count": self.entries.len(),
            "total_bytes": total,
            "files": files,
        })
    }

    /// The manifest entry for one served path (e.g. "/research" →
    /// "research/index.html"; "/" → "index.html").
    pub fn entry_for_route(&self, route: &str) -> Option<&(String, String, u64)> {
        let rel = route_to_relpath(route);
        self.entries.iter().find(|e| e.0 == rel)
    }
}

/// Map a served route to its dist-relative file path.
pub fn route_to_relpath(route: &str) -> String {
    let trimmed = route.trim_start_matches('/');
    if trimmed.is_empty() {
        return "index.html".to_string();
    }
    let last_segment = trimmed.rsplit('/').next().unwrap_or(trimmed);
    if last_segment.contains('.') {
        // A file route (jwks.json, robots.txt, an image, a page
        // asset): served as-is by the static host.
        return trimmed.to_string();
    }
    format!("{trimmed}/index.html")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dist() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("broadside-dist-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("research")).expect("mkdir");
        std::fs::write(dir.join("index.html"), b"<html>home</html>").expect("write");
        std::fs::write(dir.join("research/index.html"), b"<html>research</html>").expect("write");
        dir
    }

    #[test]
    fn manifest_is_deterministic_and_content_addressed() {
        let dir = temp_dist();
        let a = manifest_of(&dir).expect("manifest a");
        let b = manifest_of(&dir).expect("manifest b");
        assert_eq!(a.tree_hash, b.tree_hash);
        assert_eq!(a.entries.len(), 2);
        std::fs::write(dir.join("index.html"), b"<html>changed</html>").expect("rewrite");
        let c = manifest_of(&dir).expect("manifest c");
        assert_ne!(a.tree_hash, c.tree_hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn route_mapping() {
        assert_eq!(route_to_relpath("/"), "index.html");
        assert_eq!(route_to_relpath("/research"), "research/index.html");
        assert_eq!(
            route_to_relpath("/.well-known/jwks.json"),
            ".well-known/jwks.json"
        );
    }

    #[test]
    fn missing_dist_is_an_error_not_an_empty_manifest() {
        // Adversarial: a missing dist must never hash as "empty but
        // valid" — that would let verify certify nothing.
        let dir = std::env::temp_dir().join("broadside-dist-absent-xyz");
        assert!(manifest_of(&dir).is_err());
    }
}

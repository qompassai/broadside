//! Server configuration: where the site tree lives, where
//! broadside keeps its state (receipt log, source registry), and
//! the deploy coordinates. Every value comes from the CLI or the
//! environment; defaults are the estate's real coordinates, named
//! in one place so a staging run overrides them explicitly —
//! never silently.

use std::path::PathBuf;

/// The production deploy target (OCI host, Caddy root for
/// qompass.ai) and its access-log path. Deploy refuses to treat
/// any other target as production.
pub const PROD_TARGET: &str = "ubuntu@137.131.28.242:/var/www/qompass.ai/";
pub const PROD_HOST: &str = "137.131.28.242";
pub const HOST_ACCESS_LOG: &str = "/var/log/caddy/qompass.ai.log";

#[derive(Clone, Debug)]
pub struct Config {
    /// The qompass.ai site package tree (cargo-leptos).
    pub site_root: PathBuf,
    /// broadside's own state: receipts.jsonl + sources.json.
    pub state_dir: PathBuf,
    /// Public base URL of the site.
    pub base_url: String,
    /// Deploy target: the production coordinates, or a local
    /// staging directory (deploy treats local paths as staging).
    pub deploy_target: String,
    /// SSH key for the deploy host (read-back + rsync + canary log).
    pub ssh_key: PathBuf,
    /// Pinned canary-manifest signer: base64url Ed25519 public key.
    /// None = no signer pinned = honeypot injection fails closed.
    pub canary_signer_pubkey: Option<String>,
}

impl Config {
    pub fn receipts(&self) -> crate::receipts::ReceiptLog {
        crate::receipts::ReceiptLog::new(self.state_dir.join("receipts.jsonl"))
    }

    pub fn sources_path(&self) -> PathBuf {
        self.state_dir.join("sources.json")
    }

    pub fn dist(&self) -> PathBuf {
        self.site_root.join("dist")
    }

    /// Production means the exact estate coordinates over SSH.
    pub fn target_is_production(&self) -> bool {
        self.deploy_target == PROD_TARGET
    }

    /// A staging target is a local directory path (no SSH syntax).
    pub fn target_is_local(&self) -> bool {
        !self.deploy_target.contains('@') && !self.deploy_target.contains(':')
    }
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Defaults overlaid by BROADSIDE_* environment variables; the CLI
/// parser in main.rs overlays flags on top of this.
pub fn from_env() -> Config {
    let env_path = |name: &str| std::env::var_os(name).map(PathBuf::from);
    Config {
        site_root: env_path("BROADSIDE_SITE_ROOT")
            .unwrap_or_else(|| home().join("qompass-site-package-wt")),
        state_dir: env_path("BROADSIDE_STATE_DIR")
            .unwrap_or_else(|| home().join(".local").join("share").join("broadside")),
        base_url: std::env::var("BROADSIDE_BASE_URL")
            .unwrap_or_else(|_| "https://qompass.ai".to_string()),
        deploy_target: std::env::var("BROADSIDE_DEPLOY_TARGET")
            .unwrap_or_else(|_| PROD_TARGET.to_string()),
        ssh_key: env_path("BROADSIDE_SSH_KEY")
            .unwrap_or_else(|| home().join(".ssh").join("oci_qompass_ed25519")),
        canary_signer_pubkey: std::env::var("BROADSIDE_CANARY_SIGNER_PUBKEY")
            .ok()
            .filter(|s| !s.trim().is_empty()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_target_recognition() {
        let mut cfg = from_env();
        cfg.deploy_target = PROD_TARGET.to_string();
        assert!(cfg.target_is_production());
        assert!(!cfg.target_is_local());
        cfg.deploy_target = "/tmp/staging-site".to_string();
        assert!(!cfg.target_is_production());
        assert!(cfg.target_is_local());
        // Adversarial: a lookalike SSH target is not production.
        cfg.deploy_target = "ubuntu@137.131.28.242:/var/www/evil/".to_string();
        assert!(!cfg.target_is_production());
        assert!(!cfg.target_is_local());
    }
}

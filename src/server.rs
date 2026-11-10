//! The rmcp server: broadside's five tools and two resources.
//!
//! Framing follows the fleet pattern (lupin/phaedrus WS2 shape):
//! the era guard owns the stdio front door (see `guard.rs`), the
//! handler pins `supported_protocol_versions` to 2026-07-28 so
//! `server/discover` advertises exactly one version, and domain
//! failures return as `isError` content carrying `{"error": msg}`.
//! Handlers are synchronous domain calls on a blocking thread —
//! the pipeline shells out to cargo/rsync/ssh and must not stall
//! the runtime.

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    InitializeResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
    ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse, ReadResourceResult, Resource,
    ResourceContents, ServerCapabilities, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{Value, json};

use crate::config::Config;
use crate::deploy_live;
use crate::pipeline;

fn tool_definitions() -> Vec<Tool> {
    let specs: Vec<(&str, &str, Value)> = vec![
        (
            "broadside_status",
            "Read-only status: site tree git state, current dist hash, receipt-chain summary, latest build/verify/deploy/live_check receipts, key-record and honeypot-manifest state. Reads receipts; never guesses.",
            json!({"type": "object", "properties": {}}),
        ),
        (
            "broadside_live_check",
            "Read-only check of the live site against the deployed manifest: key routes, the JWKS document vs the signed key record, and the H1 canary-log read-back from the host access log. Appends a live_check receipt; drift and canary hits are findings, never silently absorbed.",
            json!({"type": "object", "properties": {}}),
        ),
        (
            "broadside_build",
            "Build qompass.ai deterministically: cargo leptos build --release, prerender, JWKS placement from the signed key record, canary injection (manifest signature verified before injection), dist manifest. Appends a build receipt; missing signed records fail the build's gates closed.",
            json!({"type": "object", "properties": {}}),
        ),
        (
            "broadside_verify",
            "Run the verify battery over the current dist: site tests, generated-data freshness, citation verification by route with the H3 injection quarantine, internal links/figures, dist manifest identity, JWKS vs the signed key record, canary integrity. Appends a verify receipt; only an all-pass receipt makes a dist hash deployable.",
            json!({"type": "object", "properties": {
                "dist_hash": {"type": "string", "description": "Optional expected dist tree hash; verify fails if the recomputed hash differs."}
            }}),
        ),
        (
            "broadside_deploy",
            "Deploy exactly one dist hash, only behind a passing verify receipt for that identical hash, only with confirm: true on this call (per-call Owner confirmation by design — flowguard_broadside_deploy). Transfers by rsync, then reads back what is served and writes it into the deploy receipt; a failed read-back is a failed deploy. dry_run proves the mechanics without transferring.",
            json!({"type": "object", "properties": {
                "dist_hash": {"type": "string", "description": "The dist tree hash to deploy (from a passing verify receipt)."},
                "confirm": {"type": "boolean", "description": "Must be true: per-call confirmation that this exact hash may ship to the configured target."},
                "dry_run": {"type": "boolean", "description": "When true, rsync runs with --dry-run and no read-back is attempted."}
            }, "required": ["dist_hash", "confirm"]}),
        ),
    ];
    specs
        .into_iter()
        .map(|(name, description, schema)| {
            let Value::Object(map) = schema else {
                unreachable!("catalog schemas are objects");
            };
            Tool::new(name, description, map)
        })
        .collect()
}

fn resource_definitions() -> Vec<Resource> {
    [
        ("broadside://receipts", "Receipt log (broadside.receipt v1)"),
        (
            "broadside://status",
            "Current status (same payload as broadside_status)",
        ),
    ]
    .into_iter()
    .map(|(uri, name)| Resource::new(uri, name).with_mime_type("application/json"))
    .collect()
}

fn text_result(value: &Value, is_error: bool) -> CallToolResult {
    let content = vec![ContentBlock::text(value.to_string())];
    if is_error {
        CallToolResult::error(content)
    } else {
        CallToolResult::success(content)
    }
}

fn err_result(msg: &str) -> CallToolResult {
    text_result(&json!({"error": msg}), true)
}

fn receipt_result(receipt: Result<Value, String>) -> CallToolResult {
    match receipt {
        Ok(receipt) => {
            let failed = matches!(
                receipt.get("result").and_then(Value::as_str),
                Some("fail") | Some("refused")
            );
            text_result(&receipt, failed)
        }
        Err(e) => err_result(&e),
    }
}

fn call_tool(cfg: &Config, name: &str, args: &Value) -> CallToolResult {
    match name {
        "broadside_status" => match deploy_live::status(cfg) {
            Ok(status) => text_result(&status, false),
            Err(e) => err_result(&e),
        },
        "broadside_live_check" => receipt_result(deploy_live::live_check(cfg)),
        "broadside_build" => receipt_result(pipeline::build(cfg)),
        "broadside_verify" => {
            let expected = args.get("dist_hash").and_then(Value::as_str);
            receipt_result(pipeline::verify(cfg, expected))
        }
        "broadside_deploy" => {
            let dist_hash = args.get("dist_hash").and_then(Value::as_str).unwrap_or("");
            if dist_hash.is_empty() {
                return err_result("dist_hash is required");
            }
            let confirm = args
                .get("confirm")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let dry_run = args
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            receipt_result(deploy_live::deploy(cfg, dist_hash, confirm, dry_run))
        }
        _ => err_result("unknown tool"),
    }
}

fn read_resource(cfg: &Config, uri: &str) -> Result<ReadResourceResult, ErrorData> {
    let text = match uri {
        "broadside://receipts" => {
            let path = cfg.receipts().path().to_path_buf();
            std::fs::read_to_string(&path).unwrap_or_default()
        }
        "broadside://status" => match deploy_live::status(cfg) {
            Ok(status) => status.to_string(),
            Err(e) => return Err(ErrorData::internal_error(e, None)),
        },
        _ => return Err(ErrorData::invalid_params("unknown resource uri", None)),
    };
    Ok(ReadResourceResult::new(vec![
        ResourceContents::TextResourceContents {
            uri: uri.to_string(),
            mime_type: Some("application/json".to_string()),
            text,
            meta: None,
        },
    ]))
}

pub struct BroadsideServer {
    cfg: Arc<Config>,
}

impl BroadsideServer {
    pub fn new(cfg: Config) -> Self {
        BroadsideServer { cfg: Arc::new(cfg) }
    }
}

impl ServerHandler for BroadsideServer {
    fn get_info(&self) -> InitializeResult {
        let mut server_info = Implementation::default();
        server_info.name = "broadside".to_string();
        server_info.version = env!("CARGO_PKG_VERSION").to_string();
        let mut info = InitializeResult::default();
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_resources()
            .build();
        info.server_info = server_info;
        info
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult {
            tools: tool_definitions(),
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let cfg = Arc::clone(&self.cfg);
        let outcome = tokio::task::spawn_blocking(move || call_tool(&cfg, &name, &arguments)).await;
        match outcome {
            Ok(result) => Ok(result.into()),
            Err(join) => Err(ErrorData::internal_error(
                format!("tool task failed: {join}"),
                None,
            )),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(ListResourcesResult {
            resources: resource_definitions(),
            ..Default::default()
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let cfg = Arc::clone(&self.cfg);
        let outcome = tokio::task::spawn_blocking(move || read_resource(&cfg, &request.uri)).await;
        match outcome {
            Ok(result) => result.map(ReadResourceResponse::from),
            Err(join) => Err(ErrorData::internal_error(
                format!("resource task failed: {join}"),
                None,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_has_the_five_programme_tools() {
        let tools = tool_definitions();
        let names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
        assert_eq!(
            names,
            vec![
                "broadside_status",
                "broadside_live_check",
                "broadside_build",
                "broadside_verify",
                "broadside_deploy"
            ]
        );
        for tool in &tools {
            // Every schema is a JSON object (never null properties).
            assert!(tool.input_schema.get("type").is_some());
        }
    }

    #[test]
    fn deploy_without_hash_is_an_error_not_a_refusal() {
        let cfg = crate::config::Config {
            site_root: std::path::PathBuf::from("/nonexistent"),
            state_dir: std::path::PathBuf::from("/nonexistent-state"),
            base_url: "https://example.invalid".to_string(),
            deploy_target: "/tmp/staging".to_string(),
            ssh_key: std::path::PathBuf::from("/nonexistent"),
            canary_signer_pubkey: None,
        };
        let result = call_tool(&cfg, "broadside_deploy", &json!({"confirm": true}));
        assert!(result.is_error.unwrap_or(false));
    }
}

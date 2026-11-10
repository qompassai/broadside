//! broadside-mcp library: the modules behind the `broadside-mcp`
//! binary (MCP serve mode plus the packet/feed CLI modes). The
//! binary is a thin wrapper; everything testable lives here.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod citations;
pub mod config;
pub mod crypto;
pub mod deploy_live;
pub mod dist;
pub mod guard;
pub mod h4;
pub mod honeypot;
pub mod http;
pub mod jwks;
pub mod packet;
pub mod pipeline;
pub mod proc;
pub mod receipts;
pub mod server;
pub mod sources;

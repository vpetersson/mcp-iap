//! An identity-aware proxy for LLM agents.
//!
//! The goal in one sentence: give an agent access to an API or an MCP server
//! without ever giving it the credential. Everything else here — the ACL, the
//! interactive prompt, the hash-chained audit log — exists to make that grant
//! narrow, observable and revocable.

pub mod acl;
pub mod admin;
pub mod approval;
pub mod audit;
pub mod config;
pub mod credentials;
pub mod enroll;
pub mod identity;
pub mod init;
pub mod list;
pub mod mcp;
pub mod profiles;
pub mod proxy;
pub mod secrets;
pub mod service_account;
pub mod state;
pub mod tokens;
pub mod tui;
pub mod workload;

//! Everything the request path needs, assembled once at startup.

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use std::time::Duration;

use crate::acl::Acl;
use crate::approval::ApprovalBroker;
use crate::audit::{AuditLog, AuditRecord};
use crate::config::Config;
use crate::config::WorkloadMode;
use crate::credentials::CredentialInjector;
use crate::identity::{AgentRegistry, AuthFailure, Caller};
use crate::secrets::SecretResolver;
use crate::workload::{WorkloadError, WorkloadIssuer};

pub struct AppState {
    pub config: Config,
    pub agents: AgentRegistry,
    pub acl: Acl,
    pub audit: Arc<AuditLog>,
    pub injector: CredentialInjector,
    pub broker: Arc<ApprovalBroker>,
    pub http: reqwest::Client,
    pub resolver: Arc<SecretResolver>,
    pub admin_token: String,
    pub workload: WorkloadIssuer,
}

/// Resolve every reference the policy file names, before anything binds a port.
///
/// Reports all of the failures rather than the first: a proxy fronting twenty
/// upstreams should not need twenty restarts to discover that three of its
/// references are wrong.
fn preload_secrets(config: &Config, resolver: &SecretResolver) -> Result<()> {
    let references = config.secret_refs();
    let mut failures = Vec::new();
    for reference in &references {
        if let Err(error) = resolver.resolve(reference) {
            failures.push((reference.clone(), format!("{error:#}")));
        }
    }
    if failures.is_empty() {
        return Ok(());
    }

    // Only mention `op` when an `op://` reference is one of the ones that
    // actually failed. Blaming 1Password for an unset environment variable
    // sends the operator to sign into a vault this config never mentions —
    // and `op` is never even invoked unless a reference asks for it.
    let hint = if failures
        .iter()
        .any(|(reference, _)| reference.starts_with("op://"))
    {
        " — is `op` signed in?"
    } else {
        ""
    };

    let detail = failures
        .iter()
        .map(|(reference, error)| format!("  {reference}: {error}"))
        .collect::<Vec<_>>()
        .join("\n");

    bail!(
        "{} of {} secret references could not be resolved{hint}\n{detail}",
        failures.len(),
        references.len(),
    )
}

impl AppState {
    pub fn build(config: Config, audit_to_stderr: bool) -> Result<Arc<Self>> {
        let resolver = Arc::new(SecretResolver::new(config.server.op_binary.clone()));

        // Resolve everything now: a missing key or a locked 1Password vault should
        // stop startup, not surface as a mystery 502 on the first real request.
        preload_secrets(&config, &resolver)?;

        let agents = AgentRegistry::build(&config, &resolver)?;
        let acl = Acl::compile(&config)?;
        let audit = Arc::new(AuditLog::open(&config.audit, audit_to_stderr)?);

        let http = reqwest::Client::builder()
            // `read_timeout` bounds the gap between chunks; `timeout` would bound
            // the whole response, silently truncating any stream that ran longer
            // than it — which for streamed LLM output is the normal case.
            .read_timeout(Duration::from_secs(config.server.upstream_timeout_secs))
            .connect_timeout(Duration::from_secs(
                config.server.upstream_connect_timeout_secs,
            ))
            .user_agent(concat!("mcp-iap/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building the upstream HTTP client")?;

        let injector = CredentialInjector::new(
            Arc::clone(&resolver),
            http.clone(),
            Some(Arc::clone(&audit)),
        );

        // Parse every service-account key now. A malformed key should stop the
        // process here, not turn into a 502 the first time an agent calls.
        for upstream in &config.upstreams {
            injector.warm(&upstream.name, &upstream.auth)?;
        }
        for server in &config.mcp_servers {
            injector.warm(&server.name, &server.auth)?;
        }
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(
            config.server.approval_timeout_secs,
        )));

        let admin_token = match &config.server.admin_token {
            Some(reference) => resolver
                .resolve(reference)
                .context("resolving server.admin_token")?
                .expose()
                .to_string(),
            None => crate::identity::generate_token()?,
        };

        let workload = WorkloadIssuer::new(&config.server.workload_identity)?;

        Ok(Arc::new(AppState {
            config,
            agents,
            acl,
            audit,
            injector,
            broker,
            http,
            resolver,
            admin_token,
            workload,
        }))
    }

    /// Resolve whatever credential a caller presented on the data plane.
    ///
    /// A workload token is tried first and only when it *is* one: `NotAToken`
    /// falls through to the agent registry, so an agent token is never reported
    /// as a malformed JWT and a malformed JWT is never reported as an unknown
    /// agent. In `required` mode a perfectly good agent token stops here — it
    /// mints, and that is all it does.
    pub fn authenticate(&self, presented: &str) -> Result<Caller, AuthFailure> {
        if self.workload.mode().enabled() {
            match self.workload.verify(presented) {
                Ok(token) => {
                    let Some(agent) = self.agents.by_id(&token.agent) else {
                        // The token is ours and still valid, but the agent it
                        // names has been removed from the policy file since.
                        return Err(AuthFailure::Workload(WorkloadError::UnknownAgent(
                            token.agent.clone(),
                        )));
                    };
                    return Ok(Caller::Workload { agent, token });
                }
                Err(WorkloadError::NotAToken) => {}
                Err(error) => return Err(AuthFailure::Workload(error)),
            }
        }

        match self.agents.authenticate(presented) {
            Some(_) if self.workload.mode() == WorkloadMode::Required => {
                Err(AuthFailure::WorkloadRequired)
            }
            Some(agent) => Ok(Caller::Agent(agent)),
            None => Err(AuthFailure::UnknownAgent),
        }
    }

    /// Record that the proxy came up, so every log begins with its own provenance.
    ///
    /// Fallible: a proxy that cannot write its own startup line will not be able
    /// to record anything it allows either, and should not come up at all.
    pub fn log_startup(&self) -> Result<()> {
        let mut record = AuditRecord::new("proxy", "startup");
        record.target = self.config.server.listen.to_string();
        record.detail = Some(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "agents": self.agents.len(),
            "upstreams": self.config.upstreams.len(),
            "mcp_servers": self.config.mcp_servers.len(),
            "acl_rules": self.acl.rule_count(),
            "acl_default": self.acl.default_action().to_string(),
            // Whether this process came up handing out standing grants or
            // short-lived ones is evidence, and the log is where evidence goes.
            "workload_identity": self.workload.mode().to_string(),
            "workload_lifetime_secs": self.workload.lifetime_secs(),
        }));
        self.audit
            .write(record)
            .context("writing the first audit record — is the log path writable?")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config whose every secret reference is broken, so startup has to
    /// report on all of them.
    fn config_with(refs: &[&str]) -> Config {
        let upstreams: String = refs
            .iter()
            .enumerate()
            .map(|(index, reference)| {
                format!(
                    r#"
[[upstreams]]
name = "up{index}"
base_url = "https://example.invalid"
auth = {{ type = "bearer", secret = "{reference}" }}
"#
                )
            })
            .collect();
        toml::from_str(&format!(
            r#"
[[agents]]
id = "a"
token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
{upstreams}"#
        ))
        .unwrap()
    }

    #[test]
    fn every_broken_reference_is_reported_not_just_the_first() {
        // Twenty upstreams should not mean twenty restarts to find three typos.
        let config = config_with(&["env:MCP_IAP_NOT_SET_ONE", "env:MCP_IAP_NOT_SET_TWO"]);
        let resolver = SecretResolver::new("op");
        let error = preload_secrets(&config, &resolver).unwrap_err().to_string();

        assert!(error.contains("2 of 2"), "{error}");
        assert!(error.contains("MCP_IAP_NOT_SET_ONE"), "{error}");
        assert!(error.contains("MCP_IAP_NOT_SET_TWO"), "{error}");
    }

    #[test]
    fn an_unset_environment_variable_is_never_blamed_on_1password() {
        // The whole defect: `op` is not invoked unless a reference asks for it,
        // so naming it here sends the operator to sign into a vault this config
        // does not mention.
        let config = config_with(&["env:MCP_IAP_NOT_SET_ONE"]);
        let resolver = SecretResolver::new("op");
        let error = preload_secrets(&config, &resolver).unwrap_err().to_string();

        assert!(!error.contains("op"), "{error}");
        assert!(error.contains("is not set"), "{error}");
    }

    #[test]
    fn the_1password_hint_appears_when_an_op_reference_is_the_one_failing() {
        let config = config_with(&["env:MCP_IAP_NOT_SET_ONE", "op://Vault/Item/field"]);
        // A binary that cannot exist, so the `op` branch fails without needing
        // the real CLI installed or signed in.
        let resolver = SecretResolver::new("mcp-iap-no-such-op-binary");
        let error = preload_secrets(&config, &resolver).unwrap_err().to_string();

        assert!(error.contains("is `op` signed in?"), "{error}");
        assert!(error.contains("op://Vault/Item/field"), "{error}");
    }

    #[test]
    fn a_config_whose_references_all_resolve_preloads_cleanly() {
        let config = config_with(&["literal:sk-test"]);
        let resolver = SecretResolver::new("op");
        preload_secrets(&config, &resolver).unwrap();
    }
}

//! Everything the request path needs, assembled once at startup.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;

use crate::acl::Acl;
use crate::approval::ApprovalBroker;
use crate::audit::{AuditLog, AuditRecord};
use crate::config::Config;
use crate::credentials::CredentialInjector;
use crate::identity::AgentRegistry;
use crate::secrets::SecretResolver;

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
}

impl AppState {
    pub fn build(config: Config, audit_to_stderr: bool) -> Result<Arc<Self>> {
        let resolver = Arc::new(SecretResolver::new(config.server.op_binary.clone()));

        // Resolve everything now: a missing key or a locked 1Password vault should
        // stop startup, not surface as a mystery 502 on the first real request.
        for reference in config.secret_refs() {
            resolver
                .resolve(&reference)
                .with_context(|| "preloading secrets (is `op` signed in?)")?;
        }

        let agents = AgentRegistry::build(&config, &resolver)?;
        let acl = Acl::compile(&config)?;
        let audit = Arc::new(AuditLog::open(&config.audit, audit_to_stderr)?);

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.server.upstream_timeout_secs))
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
        }))
    }

    /// Record that the proxy came up, so every log begins with its own provenance.
    pub fn log_startup(&self) {
        let mut record = AuditRecord::new("proxy", "startup");
        record.target = self.config.server.listen.to_string();
        record.detail = Some(serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "agents": self.agents.len(),
            "upstreams": self.config.upstreams.len(),
            "mcp_servers": self.config.mcp_servers.len(),
            "acl_rules": self.acl.rule_count(),
            "acl_default": self.acl.default_action().to_string(),
        }));
        self.audit.write(record);
    }
}

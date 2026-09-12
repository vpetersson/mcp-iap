//! Agent identity.
//!
//! An agent presents a token that is minted for the proxy and is not any
//! upstream credential. Only its sha256 needs to live in the config file, and
//! lookup is constant-time-ish by hash so the plaintext never has to be compared.
//!
//! That token says *who*. What a given run may do, and for how long, is a
//! workload token — see `crate::workload`. `Caller` is whichever of the two
//! arrived, resolved to the same agent either way.

use anyhow::{bail, Context, Result};
use http::StatusCode;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

use crate::acl::AccessRequest;
use crate::config::{AgentConfig, Config};
use crate::secrets::SecretResolver;
use crate::workload::{Verified, WorkloadError};

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

/// Generate a fresh agent token: 32 bytes from the OS CSPRNG, hex-encoded.
///
/// Fallible on purpose. `rand` surfaces entropy failures rather than panicking,
/// and a token this process cannot generate securely must stop it rather than
/// quietly become something weaker.
pub fn generate_token() -> Result<String> {
    use rand::TryRng;
    let mut bytes = [0u8; 32];
    rand::rng()
        .try_fill_bytes(&mut bytes)
        .context("drawing 32 random bytes from the operating system")?;
    Ok(format!("iap_{}", hex::encode(bytes)))
}

#[derive(Debug)]
pub struct AgentRegistry {
    by_hash: HashMap<String, Arc<AgentConfig>>,
    by_id: HashMap<String, Arc<AgentConfig>>,
}

impl AgentRegistry {
    /// Build the registry, resolving any `token_ref` into its hash.
    pub fn build(config: &Config, resolver: &SecretResolver) -> Result<Self> {
        let mut by_hash = HashMap::new();
        let mut by_id = HashMap::new();

        for agent in &config.agents {
            let hash = match (&agent.token_sha256, &agent.token_ref) {
                (Some(hash), _) => hash.to_ascii_lowercase(),
                (None, Some(reference)) => {
                    let secret = resolver.resolve(reference)?;
                    token_hash(secret.expose())
                }
                (None, None) => bail!("agent `{}` has no token configured", agent.id),
            };

            let shared = Arc::new(agent.clone());
            if let Some(existing) = by_hash.insert(hash, Arc::clone(&shared)) {
                bail!(
                    "agents `{}` and `{}` share the same token",
                    existing.id,
                    agent.id
                );
            }
            by_id.insert(agent.id.clone(), shared);
        }

        Ok(AgentRegistry { by_hash, by_id })
    }

    pub fn authenticate(&self, token: &str) -> Option<Arc<AgentConfig>> {
        self.by_hash.get(&token_hash(token)).cloned()
    }

    pub fn by_id(&self, id: &str) -> Option<Arc<AgentConfig>> {
        self.by_id.get(id).cloned()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// Who is calling, after whichever credential they presented has been checked.
///
/// Both arms resolve to the same `AgentConfig`; the difference is what else the
/// credential asserted. A workload token also narrows what this particular run
/// may ask for, which is checked before the ACL ever sees the request.
#[derive(Debug, Clone)]
pub enum Caller {
    Agent(Arc<AgentConfig>),
    Workload {
        agent: Arc<AgentConfig>,
        token: Verified,
    },
}

impl Caller {
    pub fn agent(&self) -> &AgentConfig {
        match self {
            Caller::Agent(agent) => agent,
            Caller::Workload { agent, .. } => agent,
        }
    }

    pub fn id(&self) -> &str {
        &self.agent().id
    }

    pub fn display_name(&self) -> &str {
        self.agent().display_name()
    }

    pub fn workload(&self) -> Option<&Verified> {
        match self {
            Caller::Agent(_) => None,
            Caller::Workload { token, .. } => Some(token),
        }
    }

    /// The workload label for the audit record, or `None` for a bare agent token.
    pub fn label(&self) -> Option<String> {
        self.workload().map(Verified::label)
    }

    /// Whether the credential presented covers this request at all.
    ///
    /// Never an authorisation: a scope can only narrow, so the ACL still runs
    /// afterwards and can still refuse. A bare agent token narrows nothing.
    pub fn permits(&self, request: &AccessRequest) -> bool {
        match self {
            Caller::Agent(_) => true,
            Caller::Workload { token, .. } => token.scope.permits(request),
        }
    }
}

/// Why a caller was not accepted. Carries its own status and code so the proxy
/// and the control plane refuse the same thing the same way.
#[derive(Debug, Clone)]
pub enum AuthFailure {
    /// No credential at all.
    Missing,
    /// A credential that is not any configured agent's.
    UnknownAgent,
    /// A valid agent token where policy requires a workload token.
    WorkloadRequired,
    /// A workload token that did not hold up.
    Workload(WorkloadError),
}

impl AuthFailure {
    pub fn status(&self) -> StatusCode {
        StatusCode::UNAUTHORIZED
    }

    pub fn code(&self) -> &'static str {
        match self {
            AuthFailure::Missing => "missing_credentials",
            AuthFailure::UnknownAgent => "unknown_agent",
            AuthFailure::WorkloadRequired => "workload_token_required",
            AuthFailure::Workload(error) => error.code(),
        }
    }

    pub fn message(&self) -> String {
        match self {
            AuthFailure::Missing => {
                "no agent token — send `Authorization: Bearer <iap-token>` or `X-IAP-Token`"
                    .to_string()
            }
            AuthFailure::UnknownAgent => "the agent token is not recognised".to_string(),
            AuthFailure::WorkloadRequired => {
                "this proxy takes workload tokens on the data plane — exchange the agent \
                 token at `POST /_iap/token` for one scoped to what this run needs"
                    .to_string()
            }
            AuthFailure::Workload(error) => error.message(),
        }
    }

    /// What goes in the audit record's `rule` column. The specific reason, not
    /// just "authentication": a replayed token and a token nobody ever issued
    /// are the same status code and very different events.
    pub fn rule(&self) -> String {
        match self {
            AuthFailure::Missing | AuthFailure::UnknownAgent => "<authentication>".to_string(),
            AuthFailure::WorkloadRequired => "<workload-token-required>".to_string(),
            AuthFailure::Workload(error) => format!("<{}>", error.code().replace('_', "-")),
        }
    }

    /// Who this was, when the credential said so even though it did not hold up.
    /// A replay names an agent; an unrecognised token cannot.
    pub fn agent(&self) -> Option<&str> {
        match self {
            AuthFailure::Workload(WorkloadError::Replayed { agent, .. })
            | AuthFailure::Workload(WorkloadError::UnknownAgent(agent)) => Some(agent),
            _ => None,
        }
    }

    /// Anything else worth keeping about the refusal, for the audit record.
    pub fn detail(&self) -> Option<serde_json::Value> {
        match self {
            AuthFailure::Workload(WorkloadError::Replayed { lineage, .. }) => {
                Some(serde_json::json!({ "lineage": lineage, "revoked": "lineage" }))
            }
            _ => None,
        }
    }
}

/// Whether an agent is even allowed to address this target, before the ACL runs.
/// An empty `targets` list means "any configured target"; the ACL still decides.
pub fn agent_may_address(agent: &AgentConfig, target: &str) -> bool {
    agent.targets.is_empty() || agent.targets.iter().any(|t| t == target)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(token: &str) -> Config {
        toml::from_str(&format!(
            r#"
[[agents]]
id = "claude"
name = "Claude Code"
token_sha256 = "{}"
targets = ["anthropic"]

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"

[[agents]]
id = "other"
token_sha256 = "{}"
"#,
            token_hash(token),
            token_hash("other-token")
        ))
        .unwrap()
    }

    #[test]
    fn authenticates_by_token_hash_only() {
        let resolver = SecretResolver::new("op");
        let registry = AgentRegistry::build(&config_with("iap_secret"), &resolver).unwrap();

        let agent = registry.authenticate("iap_secret").expect("known token");
        assert_eq!(agent.id, "claude");
        assert_eq!(agent.display_name(), "Claude Code");
        assert!(registry.authenticate("iap_wrong").is_none());
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn whitespace_around_a_token_does_not_break_authentication() {
        let resolver = SecretResolver::new("op");
        let registry = AgentRegistry::build(&config_with("iap_secret"), &resolver).unwrap();
        assert!(registry.authenticate("  iap_secret\n").is_some());
    }

    #[test]
    fn two_agents_cannot_share_a_token() {
        let mut config = config_with("iap_secret");
        config.agents[1].token_sha256 = config.agents[0].token_sha256.clone();
        let resolver = SecretResolver::new("op");
        let err = AgentRegistry::build(&config, &resolver)
            .unwrap_err()
            .to_string();
        assert!(err.contains("share the same token"), "{err}");
    }

    #[test]
    fn target_list_scopes_an_agent_before_the_acl_runs() {
        let config = config_with("iap_secret");
        assert!(agent_may_address(&config.agents[0], "anthropic"));
        assert!(!agent_may_address(&config.agents[0], "github"));
        // An empty list means the ACL alone decides.
        assert!(agent_may_address(&config.agents[1], "anything"));
    }

    #[test]
    fn generated_tokens_are_unique_and_prefixed() {
        let one = generate_token().unwrap();
        assert!(one.starts_with("iap_"));
        assert_eq!(
            one.len(),
            4 + 64,
            "32 bytes, hex encoded, behind the prefix"
        );
        assert_ne!(one, generate_token().unwrap());
    }
}

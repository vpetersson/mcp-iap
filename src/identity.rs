//! Agent identity.
//!
//! An agent presents a token that is minted for the proxy and is not any
//! upstream credential. Only its sha256 needs to live in the config file, and
//! lookup is constant-time-ish by hash so the plaintext never has to be compared.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::{AgentConfig, Config};
use crate::secrets::SecretResolver;

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.trim().as_bytes()))
}

/// Generate a fresh agent token. 32 bytes of randomness, URL-safe.
pub fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("iap_{}", hex::encode(bytes))
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
        let one = generate_token();
        assert!(one.starts_with("iap_"));
        assert_ne!(one, generate_token());
    }
}

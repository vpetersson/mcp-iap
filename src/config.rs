//! Configuration model.
//!
//! One TOML file describes every agent that may connect, every upstream it may
//! reach, the credential to inject on the way out, and the ACL that decides
//! allow / deny / ask. The file holds *references* to credentials, not
//! credentials, so it is safe to keep in a repository.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::secrets::SecretRef;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub agents: Vec<AgentConfig>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    #[serde(default)]
    pub mcp_servers: Vec<McpServerConfig>,
    #[serde(default)]
    pub acl: Vec<AclRuleConfig>,
    #[serde(default)]
    pub acl_default: AclDefault,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Where agents connect. Loopback by default — this process holds credentials.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Control plane for the TUI and the MCP bridge. `false`/omitted disables it.
    #[serde(default = "default_admin_listen")]
    pub admin_listen: Option<SocketAddr>,
    /// Shared secret for the control plane, as a secret reference (`env:`,
    /// `file:`, `op://`). Generated at startup and written to `admin-token`
    /// beside the audit log when absent.
    #[serde(default)]
    pub admin_token: Option<String>,
    /// How long an `ask` request waits for a human before failing closed.
    #[serde(default = "default_approval_timeout")]
    pub approval_timeout_secs: u64,
    /// How long an upstream may go silent mid-response before the proxy gives up.
    ///
    /// This is an idle timeout, not a total one: a token-by-token LLM response
    /// can stream for as long as it likes provided it keeps arriving.
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_secs: u64,
    /// How long to wait for the upstream connection itself.
    #[serde(default = "default_connect_timeout")]
    pub upstream_connect_timeout_secs: u64,
    /// Largest request body the proxy will buffer.
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    /// Binary used to resolve `op://` references.
    #[serde(default = "default_op_bin")]
    pub op_binary: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            listen: default_listen(),
            admin_listen: default_admin_listen(),
            admin_token: None,
            approval_timeout_secs: default_approval_timeout(),
            upstream_timeout_secs: default_upstream_timeout(),
            upstream_connect_timeout_secs: default_connect_timeout(),
            max_body_bytes: default_max_body(),
            op_binary: default_op_bin(),
        }
    }
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}
fn default_admin_listen() -> Option<SocketAddr> {
    Some("127.0.0.1:8081".parse().unwrap())
}
fn default_approval_timeout() -> u64 {
    120
}
fn default_upstream_timeout() -> u64 {
    300
}
fn default_connect_timeout() -> u64 {
    30
}
fn default_max_body() -> usize {
    10 * 1024 * 1024
}
fn default_op_bin() -> String {
    "op".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Append-only, hash-chained JSONL. This is the primary deliverable of the proxy.
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,
    /// Also emit human-readable lines on stderr (disabled automatically under the TUI).
    #[serde(default = "yes")]
    pub stderr: bool,
    /// Record request/response bodies. Off by default: bodies carry prompts and data.
    #[serde(default)]
    pub log_bodies: bool,
    /// Record JSON-RPC `params` for MCP calls. Off by default for the same reason.
    #[serde(default)]
    pub log_mcp_params: bool,
    #[serde(default = "default_max_logged_body")]
    pub max_logged_body_bytes: usize,
    /// Headers whose values are replaced with `***` before anything is written.
    #[serde(default = "default_redact_headers")]
    pub redact_headers: Vec<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            path: default_audit_path(),
            stderr: true,
            log_bodies: false,
            log_mcp_params: false,
            max_logged_body_bytes: default_max_logged_body(),
            redact_headers: default_redact_headers(),
        }
    }
}

fn default_audit_path() -> PathBuf {
    PathBuf::from("iap-audit.jsonl")
}
fn yes() -> bool {
    true
}
fn default_max_logged_body() -> usize {
    4096
}
fn default_redact_headers() -> Vec<String> {
    [
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "cookie",
        "set-cookie",
        "x-iap-token",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// A caller. Agents authenticate with a token that is *not* any upstream credential.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Hex sha256 of the agent's bearer token — produced by `mcp-iap gen-token`.
    #[serde(default)]
    pub token_sha256: Option<String>,
    /// Alternative: a secret reference holding the plaintext token (hashed on load).
    #[serde(default)]
    pub token_ref: Option<String>,
    /// Upstreams and MCP servers this agent may address at all. Empty = any (ACL still applies).
    #[serde(default)]
    pub targets: Vec<String>,
}

impl AgentConfig {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.id)
    }
}

/// An HTTP API the proxy fronts, plus the credential injected on the way out.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub name: String,
    pub base_url: String,
    #[serde(default)]
    pub auth: AuthConfig,
    /// Extra static headers to add upstream (never credentials — use `auth`).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// Credential injection. Covers the schemes real APIs and MCP servers actually use.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthConfig {
    /// Pass through with nothing added.
    #[default]
    None,
    /// `Authorization: Bearer <secret>`
    Bearer { secret: String },
    /// Arbitrary header, e.g. `x-api-key` for Anthropic.
    Header {
        header: String,
        secret: String,
        #[serde(default)]
        prefix: Option<String>,
    },
    /// `Authorization: Basic base64(username:secret)`
    Basic { username: String, secret: String },
    /// Credential in the query string, e.g. `?key=<secret>`.
    Query { param: String, secret: String },
    /// OAuth2 client-credentials grant; the access token is fetched and cached here.
    Oauth2ClientCredentials {
        token_url: String,
        client_id: String,
        client_secret: String,
        #[serde(default)]
        scope: Option<String>,
        #[serde(default)]
        audience: Option<String>,
    },
    /// Service account → short-lived access token (RFC 7523), the flow Google uses.
    ///
    /// The proxy signs a JWT with the account's private key, exchanges it for an
    /// access token, and injects the token. The key never leaves this process and
    /// the agent never sees either one.
    ServiceAccountJwt {
        /// Secret reference to a Google-style service-account JSON key. Supplies
        /// the issuer, key id and token endpoint on its own.
        #[serde(default)]
        key_file: Option<String>,
        /// Or spell the pieces out, for any other RFC 7523 provider.
        #[serde(default)]
        issuer: Option<String>,
        /// Secret reference to a PKCS#8 PEM private key.
        #[serde(default)]
        private_key: Option<String>,
        #[serde(default)]
        key_id: Option<String>,
        #[serde(default)]
        token_url: Option<String>,
        /// The `aud` claim. Defaults to `token_url`, which is what Google wants.
        #[serde(default)]
        audience: Option<String>,
        /// Requested scopes, sent as one space-delimited `scope` claim.
        #[serde(default)]
        scopes: Vec<String>,
        /// Impersonate this user (Google domain-wide delegation).
        #[serde(default)]
        subject: Option<String>,
        /// Assertion lifetime. Clamped to one hour, which is Google's ceiling.
        #[serde(default)]
        lifetime_secs: Option<u64>,
    },
}

impl AuthConfig {
    /// Every secret reference this scheme needs, for preloading and validation.
    pub fn secret_refs(&self) -> Vec<&str> {
        match self {
            AuthConfig::None => vec![],
            AuthConfig::Bearer { secret }
            | AuthConfig::Header { secret, .. }
            | AuthConfig::Basic { secret, .. }
            | AuthConfig::Query { secret, .. } => vec![secret.as_str()],
            AuthConfig::Oauth2ClientCredentials { client_secret, .. } => {
                vec![client_secret.as_str()]
            }
            AuthConfig::ServiceAccountJwt {
                key_file,
                private_key,
                ..
            } => key_file
                .iter()
                .chain(private_key.iter())
                .map(String::as_str)
                .collect(),
        }
    }

    /// True for schemes where the proxy mints a short-lived token of its own
    /// rather than forwarding a long-lived secret.
    pub fn mints_tokens(&self) -> bool {
        matches!(
            self,
            AuthConfig::Oauth2ClientCredentials { .. } | AuthConfig::ServiceAccountJwt { .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportKind {
    /// Spawn the real MCP server as a child process; credentials go in its env.
    #[default]
    Stdio,
    /// Relay JSON-RPC to a remote MCP endpoint over HTTP.
    Http,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerConfig {
    pub name: String,
    #[serde(default)]
    pub transport: McpTransportKind,
    // stdio
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment for the child process. Values are *secret references*.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    // http
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    /// Hold the request and ask a human — the Little Snitch behaviour.
    Ask,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Ask => "ask",
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AclRuleConfig {
    /// Shown in the audit log and the TUI so a decision is traceable to a rule.
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "star")]
    pub agent: String,
    /// `http`, `mcp`, or `*`.
    #[serde(default = "star")]
    pub kind: String,
    /// Upstream or MCP server name.
    #[serde(default = "star")]
    pub target: String,
    /// HTTP verbs, or JSON-RPC methods such as `tools/call`.
    #[serde(default = "star_vec")]
    pub methods: Vec<String>,
    /// URL paths, or for MCP the tool / resource name.
    #[serde(default = "doublestar_vec")]
    pub paths: Vec<String>,
    pub action: Action,
}

fn star() -> String {
    "*".to_string()
}
fn star_vec() -> Vec<String> {
    vec!["*".to_string()]
}
fn doublestar_vec() -> Vec<String> {
    vec!["**".to_string()]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AclDefault {
    pub action: Action,
}

impl Default for AclDefault {
    /// Deny. An IAP that fails open is not an IAP.
    fn default() -> Self {
        AclDefault {
            action: Action::Deny,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config `{}`", path.display()))?;
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("parsing config `{}`", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn upstream(&self, name: &str) -> Option<&UpstreamConfig> {
        self.upstreams.iter().find(|u| u.name == name)
    }

    pub fn mcp_server(&self, name: &str) -> Option<&McpServerConfig> {
        self.mcp_servers.iter().find(|s| s.name == name)
    }

    pub fn agent(&self, id: &str) -> Option<&AgentConfig> {
        self.agents.iter().find(|a| a.id == id)
    }

    /// Structural checks that would otherwise surface as a confusing runtime failure.
    pub fn validate(&self) -> Result<()> {
        if let Some(reference) = &self.server.admin_token {
            SecretRef::parse(reference).context("server.admin_token")?;
        }

        let mut seen = std::collections::HashSet::new();
        for agent in &self.agents {
            if !seen.insert(&agent.id) {
                bail!("duplicate agent id `{}`", agent.id);
            }
            match (&agent.token_sha256, &agent.token_ref) {
                (None, None) => bail!(
                    "agent `{}` has neither `token_sha256` nor `token_ref` — run `mcp-iap gen-token`",
                    agent.id
                ),
                (Some(_), Some(_)) => bail!(
                    "agent `{}` sets both `token_sha256` and `token_ref`; pick one",
                    agent.id
                ),
                (Some(hash), None) => {
                    if hex::decode(hash).map(|b| b.len()) != Ok(32) {
                        bail!(
                            "agent `{}`: `token_sha256` must be 64 hex characters",
                            agent.id
                        );
                    }
                }
                (None, Some(reference)) => {
                    SecretRef::parse(reference)
                        .with_context(|| format!("agent `{}`: token_ref", agent.id))?;
                }
            }
        }

        let mut targets = std::collections::HashSet::new();
        for upstream in &self.upstreams {
            if !targets.insert(upstream.name.clone()) {
                bail!("duplicate upstream name `{}`", upstream.name);
            }
            url::Url::parse(&upstream.base_url)
                .with_context(|| format!("upstream `{}`: base_url", upstream.name))?;
            check_auth(&upstream.auth, &format!("upstream `{}`", upstream.name))?;
        }
        for server in &self.mcp_servers {
            if !targets.insert(server.name.clone()) {
                bail!(
                    "`{}` is used as both an upstream and an MCP server name; names share one namespace",
                    server.name
                );
            }
            match server.transport {
                McpTransportKind::Stdio => {
                    if server.command.is_none() {
                        bail!(
                            "mcp server `{}`: stdio transport needs `command`",
                            server.name
                        );
                    }
                    for (key, reference) in &server.env {
                        SecretRef::parse(reference).with_context(|| {
                            format!("mcp server `{}`: env `{}`", server.name, key)
                        })?;
                    }
                }
                McpTransportKind::Http => {
                    let url = server.url.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("mcp server `{}`: http transport needs `url`", server.name)
                    })?;
                    url::Url::parse(url)
                        .with_context(|| format!("mcp server `{}`: url", server.name))?;
                }
            }
            check_auth(&server.auth, &format!("mcp server `{}`", server.name))?;
        }

        for agent in &self.agents {
            for target in &agent.targets {
                if !targets.contains(target) {
                    bail!(
                        "agent `{}` lists target `{}`, which is not a configured upstream or MCP server",
                        agent.id,
                        target
                    );
                }
            }
        }

        for (index, rule) in self.acl.iter().enumerate() {
            let label = rule.name.clone().unwrap_or_else(|| format!("acl[{index}]"));
            if !matches!(rule.kind.as_str(), "http" | "mcp" | "*") {
                bail!(
                    "{label}: `kind` must be `http`, `mcp` or `*` (got `{}`)",
                    rule.kind
                );
            }
            if rule.methods.is_empty() || rule.paths.is_empty() {
                bail!("{label}: `methods` and `paths` must not be empty lists");
            }
        }

        Ok(())
    }

    /// Every secret reference in the config, for `check` and startup preloading.
    pub fn secret_refs(&self) -> Vec<String> {
        let mut refs = Vec::new();
        if let Some(reference) = &self.server.admin_token {
            refs.push(reference.clone());
        }
        for agent in &self.agents {
            if let Some(reference) = &agent.token_ref {
                refs.push(reference.clone());
            }
        }
        for upstream in &self.upstreams {
            refs.extend(upstream.auth.secret_refs().into_iter().map(str::to_string));
        }
        for server in &self.mcp_servers {
            refs.extend(server.auth.secret_refs().into_iter().map(str::to_string));
            refs.extend(server.env.values().cloned());
        }
        refs.sort();
        refs.dedup();
        refs
    }
}

/// Shortest assertion lifetime worth signing; below this, clock skew alone
/// makes the token endpoint reject it.
pub const MIN_ASSERTION_LIFETIME_SECS: u64 = 60;

fn check_auth(auth: &AuthConfig, label: &str) -> Result<()> {
    for reference in auth.secret_refs() {
        let parsed =
            SecretRef::parse(reference).with_context(|| format!("{label}: auth secret"))?;
        if parsed.is_inline() {
            tracing::warn!(
                "{label}: uses a `literal:` secret — fine for a demo, but move it to \
                 `op://`, `env:` or `file:` before this touches a real credential"
            );
        }
    }
    if let AuthConfig::Oauth2ClientCredentials { token_url, .. } = auth {
        url::Url::parse(token_url).with_context(|| format!("{label}: token_url"))?;
    }

    if let AuthConfig::ServiceAccountJwt {
        key_file,
        issuer,
        private_key,
        token_url,
        audience,
        ..
    } = auth
    {
        // Either a Google JSON key, or the pieces spelled out — never a mixture,
        // because then it is ambiguous which issuer or key actually applies.
        match (key_file, private_key) {
            (Some(_), Some(_)) => {
                bail!("{label}: set either `key_file` or `private_key`, not both")
            }
            (None, None) => bail!(
                "{label}: a service-account credential needs `key_file`                  (a Google JSON key) or `private_key` plus `issuer` and `token_url`"
            ),
            (Some(_), None) => {
                if issuer.is_some() {
                    bail!("{label}: `issuer` comes from the key file; remove it or use `private_key` instead");
                }
            }
            (None, Some(_)) => {
                if issuer.is_none() {
                    bail!("{label}: `private_key` also needs `issuer`");
                }
                if token_url.is_none() {
                    bail!("{label}: `private_key` also needs `token_url`");
                }
            }
        }
        if let AuthConfig::ServiceAccountJwt {
            lifetime_secs: Some(seconds),
            ..
        } = auth
        {
            // Clamping the ceiling was not enough: `0` produced `exp == iat` and
            // an assertion every provider rejects, discovered one 502 at a time.
            if *seconds < MIN_ASSERTION_LIFETIME_SECS {
                bail!(
                    "{label}: `lifetime_secs` must be at least {MIN_ASSERTION_LIFETIME_SECS}; \
                     it is clamped to one hour at the top"
                );
            }
        }

        for (field, value) in [("token_url", token_url), ("audience", audience)] {
            if let Some(value) = value {
                url::Url::parse(value).with_context(|| format!("{label}: {field}"))?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
[[agents]]
id = "claude"
token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"
auth = { type = "header", header = "x-api-key", secret = "env:ANTHROPIC_API_KEY" }

[[acl]]
agent = "claude"
target = "anthropic"
methods = ["POST"]
paths = ["/v1/messages"]
action = "allow"
"#;

    #[test]
    fn minimal_config_round_trips_and_defaults_to_deny() {
        let config: Config = toml::from_str(MINIMAL).unwrap();
        config.validate().unwrap();
        assert_eq!(config.acl_default.action, Action::Deny);
        assert_eq!(config.server.listen.port(), 8080);
        assert!(
            !config.audit.log_bodies,
            "bodies must not be logged by default"
        );
        assert_eq!(config.secret_refs(), vec!["env:ANTHROPIC_API_KEY"]);
    }

    #[test]
    fn unknown_keys_are_rejected_so_a_typo_never_silently_widens_access() {
        let text = format!("{MINIMAL}\n[[acl]]\nagent = \"x\"\nactoin = \"allow\"\n");
        assert!(toml::from_str::<Config>(&text).is_err());
    }

    #[test]
    fn agent_without_a_token_is_rejected() {
        let text = "[[agents]]\nid = \"claude\"\n";
        let config: Config = toml::from_str(text).unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("gen-token"), "{err}");
    }

    #[test]
    fn agent_target_must_exist() {
        let text = format!("{MINIMAL}\n");
        let mut config: Config = toml::from_str(&text).unwrap();
        config.agents[0].targets = vec!["typo".into()];
        assert!(config.validate().unwrap_err().to_string().contains("typo"));
    }

    /// The shipped example is documentation people copy, so it has to be real.
    ///
    /// The token placeholder is deliberately invalid — an unedited file must not
    /// start — so the test fills it in the way a reader would before checking
    /// the rest.
    #[test]
    fn the_example_config_parses_and_validates() {
        let text = include_str!("../iap.example.toml");
        assert!(
            text.contains("REPLACE_ME_WITH_THE_OUTPUT_OF_gen-token"),
            "the example must ship a placeholder that fails validation"
        );
        assert!(
            toml::from_str::<Config>(text).unwrap().validate().is_err(),
            "an unedited example must refuse to start"
        );

        let filled = text.replace(
            "REPLACE_ME_WITH_THE_OUTPUT_OF_gen-token",
            &crate::identity::token_hash("iap_example"),
        );
        let config: Config = toml::from_str(&filled).expect("iap.example.toml must parse");
        config.validate().expect("iap.example.toml must validate");

        assert!(
            config
                .upstreams
                .iter()
                .any(|u| matches!(u.auth, AuthConfig::ServiceAccountJwt { .. })),
            "the example should demonstrate a service account"
        );
        for reference in config.secret_refs() {
            SecretRef::parse(&reference).expect("every example secret reference must parse");
        }

        // Parsing is not the bar: every upstream the example grants an agent has
        // to be reachable under the example's own policy, or copying the file
        // produces a proxy that denies everything it advertises.
        let acl = crate::acl::Acl::compile(&config).unwrap();
        for agent in &config.agents {
            for target in &agent.targets {
                let reachable = config.upstreams.iter().any(|u| &u.name == target)
                    || config.mcp_servers.iter().any(|s| &s.name == target);
                assert!(reachable, "`{target}` is not a configured target");
                assert!(
                    acl.rules_mentioning(target) > 0,
                    "the example grants `{}` access to `{target}` but no ACL rule ever names it",
                    agent.id
                );
            }
        }
    }

    #[test]
    fn a_service_account_needs_exactly_one_source_of_key_material() {
        let base = r#"
[[upstreams]]
name = "gcs"
base_url = "https://storage.googleapis.com"
[upstreams.auth]
type = "service_account_jwt"
"#;
        let both = format!(
            "{base}key_file = \"env:SA\"\nprivate_key = \"env:PEM\"\nissuer = \"a@b\"\ntoken_url = \"https://x/token\"\n"
        );
        assert!(toml::from_str::<Config>(&both)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string()
            .contains("not both"));

        assert!(toml::from_str::<Config>(base)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string()
            .contains("needs `key_file`"));

        let no_issuer =
            format!("{base}private_key = \"env:PEM\"\ntoken_url = \"https://x/token\"\n");
        assert!(toml::from_str::<Config>(&no_issuer)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string()
            .contains("needs `issuer`"));

        let no_token_url = format!("{base}private_key = \"env:PEM\"\nissuer = \"a@b\"\n");
        assert!(toml::from_str::<Config>(&no_token_url)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string()
            .contains("needs `token_url`"));

        let key_file_only = format!("{base}key_file = \"env:SA\"\n");
        let config = toml::from_str::<Config>(&key_file_only).unwrap();
        config
            .validate()
            .expect("a bare key_file is the Google case");
        assert_eq!(config.secret_refs(), vec!["env:SA"]);
        assert!(config.upstreams[0].auth.mints_tokens());
    }

    #[test]
    fn upstream_and_mcp_names_share_one_namespace() {
        let text =
            format!("{MINIMAL}\n[[mcp_servers]]\nname = \"anthropic\"\ncommand = \"true\"\n");
        let config: Config = toml::from_str(&text).unwrap();
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("one namespace"));
    }
}

//! The access-control engine.
//!
//! One ordered rule list covers both surfaces the proxy fronts. An HTTP call is
//! `(agent, http, upstream, "POST", "/v1/messages")`; an MCP call is
//! `(agent, mcp, server, "tools/call", "create_issue")`. First match wins, and
//! anything that matches nothing falls through to the default — which is `deny`.

use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use serde::{Deserialize, Serialize};

use crate::config::{AclRuleConfig, Action, Config};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Http,
    Mcp,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Http => "http",
            Kind::Mcp => "mcp",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One thing an agent is trying to do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequest {
    pub agent: String,
    pub kind: Kind,
    pub target: String,
    /// HTTP verb, or JSON-RPC method.
    pub method: String,
    /// URL path, or MCP tool / resource name.
    pub path: String,
}

impl AccessRequest {
    pub fn http(agent: &str, upstream: &str, method: &str, path: &str) -> Self {
        AccessRequest {
            agent: agent.to_string(),
            kind: Kind::Http,
            target: upstream.to_string(),
            method: method.to_uppercase(),
            path: path.to_string(),
        }
    }

    pub fn mcp(agent: &str, server: &str, method: &str, name: &str) -> Self {
        AccessRequest {
            agent: agent.to_string(),
            kind: Kind::Mcp,
            target: server.to_string(),
            method: method.to_string(),
            path: name.to_string(),
        }
    }

    /// One line a human can judge in the TUI without reading the config.
    pub fn summary(&self) -> String {
        match self.kind {
            Kind::Http => format!("{} {} {}", self.target, self.method, self.path),
            Kind::Mcp if self.path.is_empty() => format!("{} {}", self.target, self.method),
            Kind::Mcp => format!("{} {} → {}", self.target, self.method, self.path),
        }
    }

    /// Key under which a "remember for this session" decision is cached.
    pub fn session_key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.agent, self.kind, self.target, self.method, self.path
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    /// Which rule decided, for the audit log. `None` means the default applied.
    pub rule: Option<String>,
}

impl Decision {
    pub fn rule_label(&self) -> &str {
        self.rule.as_deref().unwrap_or("<default>")
    }
}

/// A path pattern, plus whether it is the unconstrained one.
///
/// Some access requests have no path at all — `tools/list` names no tool. An
/// empty path is "not applicable" rather than an empty string to glob against,
/// so it is accepted only by a rule that places no constraint on the path.
struct PathPattern {
    matcher: GlobMatcher,
    unconstrained: bool,
}

struct CompiledRule {
    label: String,
    agent: GlobMatcher,
    kind: Option<Kind>,
    target: GlobMatcher,
    methods: Vec<GlobMatcher>,
    paths: Vec<PathPattern>,
    action: Action,
}

impl CompiledRule {
    fn matches(&self, request: &AccessRequest) -> bool {
        if let Some(kind) = self.kind {
            if kind != request.kind {
                return false;
            }
        }
        self.agent.is_match(&request.agent)
            && self.target.is_match(&request.target)
            && self.methods.iter().any(|m| m.is_match(&request.method))
            && self.matches_path(&request.path)
    }

    fn matches_path(&self, path: &str) -> bool {
        if path.is_empty() {
            return self.paths.iter().any(|p| p.unconstrained);
        }
        self.paths.iter().any(|p| p.matcher.is_match(path))
    }
}

pub struct Acl {
    rules: Vec<CompiledRule>,
    default: Action,
}

impl Acl {
    pub fn compile(config: &Config) -> Result<Self> {
        let mut rules = Vec::with_capacity(config.acl.len());
        for (index, rule) in config.acl.iter().enumerate() {
            rules.push(compile_rule(index, rule)?);
        }
        Ok(Acl {
            rules,
            default: config.acl_default.action,
        })
    }

    pub fn evaluate(&self, request: &AccessRequest) -> Decision {
        for rule in &self.rules {
            if rule.matches(request) {
                return Decision {
                    action: rule.action,
                    rule: Some(rule.label.clone()),
                };
            }
        }
        Decision {
            action: self.default,
            rule: None,
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// How many rules could ever apply to a target. Used to catch a config that
    /// grants an agent an upstream the policy never mentions, which denies.
    pub fn rules_mentioning(&self, target: &str) -> usize {
        self.rules
            .iter()
            .filter(|rule| rule.target.is_match(target))
            .count()
    }

    pub fn default_action(&self) -> Action {
        self.default
    }
}

fn compile_rule(index: usize, rule: &AclRuleConfig) -> Result<CompiledRule> {
    let label = rule.name.clone().unwrap_or_else(|| format!("acl[{index}]"));

    let kind = match rule.kind.as_str() {
        "http" => Some(Kind::Http),
        "mcp" => Some(Kind::Mcp),
        _ => None,
    };

    Ok(CompiledRule {
        agent: plain_glob(&rule.agent).with_context(|| format!("{label}: agent"))?,
        kind,
        target: plain_glob(&rule.target).with_context(|| format!("{label}: target"))?,
        methods: rule
            .methods
            .iter()
            .map(|m| method_glob(m))
            .collect::<Result<_>>()
            .with_context(|| format!("{label}: methods"))?,
        paths: rule
            .paths
            .iter()
            .map(|p| path_glob(p))
            .collect::<Result<_>>()
            .with_context(|| format!("{label}: paths"))?,
        action: rule.action,
        label,
    })
}

/// `*` matches anything, including `/`. Used for names and for JSON-RPC methods,
/// which contain a separator of their own (`tools/call`).
fn plain_glob(pattern: &str) -> Result<GlobMatcher> {
    Ok(Glob::new(pattern)
        .with_context(|| format!("invalid pattern `{pattern}`"))?
        .compile_matcher())
}

/// HTTP verbs are conventionally upper-case and JSON-RPC methods lower-case, and
/// a JSON-RPC method carries its own separator (`tools/call`), so `*` spans `/`.
fn method_glob(pattern: &str) -> Result<GlobMatcher> {
    Ok(globset::GlobBuilder::new(pattern)
        .case_insensitive(true)
        .build()
        .with_context(|| format!("invalid method pattern `{pattern}`"))?
        .compile_matcher())
}

/// `*` stops at `/`, `**` crosses it — the behaviour people expect from URL paths.
fn path_glob(pattern: &str) -> Result<PathPattern> {
    Ok(PathPattern {
        matcher: globset::GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .with_context(|| format!("invalid path pattern `{pattern}`"))?
            .compile_matcher(),
        unconstrained: matches!(pattern, "*" | "**" | "/**"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AclDefault;

    fn config_from(toml_text: &str) -> Config {
        let config: Config = toml::from_str(toml_text).unwrap();
        config
    }

    fn acl(toml_text: &str) -> Acl {
        Acl::compile(&config_from(toml_text)).unwrap()
    }

    #[test]
    fn empty_acl_denies_everything() {
        let acl = acl("");
        let decision = acl.evaluate(&AccessRequest::http("a", "u", "GET", "/x"));
        assert_eq!(decision.action, Action::Deny);
        assert_eq!(decision.rule_label(), "<default>");
    }

    #[test]
    fn first_matching_rule_wins() {
        let acl = acl(r#"
[[acl]]
name = "block-writes"
target = "gh"
methods = ["POST", "DELETE"]
action = "deny"

[[acl]]
name = "allow-gh"
target = "gh"
action = "allow"
"#);
        assert_eq!(
            acl.evaluate(&AccessRequest::http("a", "gh", "DELETE", "/repos/x"))
                .rule_label(),
            "block-writes"
        );
        let read = acl.evaluate(&AccessRequest::http("a", "gh", "GET", "/repos/x"));
        assert_eq!(read.action, Action::Allow);
        assert_eq!(read.rule_label(), "allow-gh");
    }

    #[test]
    fn single_star_does_not_cross_a_path_separator() {
        let acl = acl(r#"
[[acl]]
target = "gh"
paths = ["/repos/*"]
action = "allow"
"#);
        assert_eq!(
            acl.evaluate(&AccessRequest::http("a", "gh", "GET", "/repos/one"))
                .action,
            Action::Allow
        );
        assert_eq!(
            acl.evaluate(&AccessRequest::http("a", "gh", "GET", "/repos/one/issues"))
                .action,
            Action::Deny,
            "`/repos/*` must not silently grant everything below /repos"
        );
    }

    #[test]
    fn double_star_crosses_separators() {
        let acl = acl(r#"
[[acl]]
target = "gh"
paths = ["/repos/**"]
action = "allow"
"#);
        assert_eq!(
            acl.evaluate(&AccessRequest::http("a", "gh", "GET", "/repos/one/issues"))
                .action,
            Action::Allow
        );
    }

    #[test]
    fn kind_separates_http_from_mcp() {
        let acl = acl(r#"
[[acl]]
kind = "mcp"
target = "gh"
methods = ["tools/call"]
paths = ["get_*"]
action = "allow"

[[acl]]
kind = "mcp"
target = "gh"
methods = ["tools/list", "initialize", "notifications/*"]
action = "allow"
"#);
        assert_eq!(
            acl.evaluate(&AccessRequest::mcp("a", "gh", "tools/call", "get_issue"))
                .action,
            Action::Allow
        );
        assert_eq!(
            acl.evaluate(&AccessRequest::mcp("a", "gh", "tools/call", "delete_repo"))
                .action,
            Action::Deny
        );
        assert_eq!(
            acl.evaluate(&AccessRequest::mcp(
                "a",
                "gh",
                "notifications/initialized",
                ""
            ))
            .action,
            Action::Allow,
            "a slash inside a JSON-RPC method must still be globbable"
        );
        assert_eq!(
            acl.evaluate(&AccessRequest::http("a", "gh", "TOOLS/CALL", "get_issue"))
                .action,
            Action::Deny,
            "an mcp rule must never apply to an http request"
        );
    }

    #[test]
    fn a_call_with_no_path_needs_a_rule_that_does_not_constrain_the_path() {
        let acl = acl(r#"
[[acl]]
name = "named-tools"
kind = "mcp"
paths = ["get_*"]
action = "allow"

[[acl]]
name = "handshake"
kind = "mcp"
methods = ["initialize"]
action = "allow"
"#);
        // `tools/list` names no tool, so the path-constrained rule must not apply.
        assert_eq!(
            acl.evaluate(&AccessRequest::mcp("a", "gh", "tools/list", ""))
                .action,
            Action::Deny
        );
        let handshake = acl.evaluate(&AccessRequest::mcp("a", "gh", "initialize", ""));
        assert_eq!(handshake.action, Action::Allow);
        assert_eq!(handshake.rule_label(), "handshake");
    }

    #[test]
    fn methods_match_case_insensitively() {
        let acl = acl(r#"
[[acl]]
methods = ["get"]
action = "allow"
"#);
        assert_eq!(
            acl.evaluate(&AccessRequest::http("a", "u", "GET", "/x"))
                .action,
            Action::Allow
        );
    }

    #[test]
    fn ask_is_a_first_class_action() {
        let acl = acl(r#"
[[acl]]
name = "confirm-writes"
methods = ["POST"]
action = "ask"
"#);
        let decision = acl.evaluate(&AccessRequest::http("a", "u", "POST", "/x"));
        assert_eq!(decision.action, Action::Ask);
        assert_eq!(decision.rule_label(), "confirm-writes");
    }

    #[test]
    fn default_action_is_configurable_but_deny_out_of_the_box() {
        let mut config = config_from("");
        assert_eq!(
            Acl::compile(&config).unwrap().default_action(),
            Action::Deny
        );
        config.acl_default = AclDefault {
            action: Action::Ask,
        };
        assert_eq!(Acl::compile(&config).unwrap().default_action(), Action::Ask);
    }

    #[test]
    fn session_key_distinguishes_agents_and_targets() {
        let one = AccessRequest::http("a", "gh", "GET", "/x").session_key();
        let two = AccessRequest::http("b", "gh", "GET", "/x").session_key();
        let three = AccessRequest::http("a", "anthropic", "GET", "/x").session_key();
        assert_ne!(one, two);
        assert_ne!(one, three);
    }
}

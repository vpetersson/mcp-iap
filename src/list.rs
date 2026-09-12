//! `mcp-iap list` — what this proxy exposes.
//!
//! `check` prints a summary too, but as a side effect of validating, and in the
//! wrong shape: it comma-joins every upstream onto one line. That reads fine at
//! two services and not at all at twenty. This is the command whose only job is
//! the inventory — one row per thing, aligned, ordered.
//!
//! It reads the policy file and nothing else, so it answers while the proxy is
//! down, and it prints credential *references* only. A `literal:` reference is
//! the credential rather than a pointer to one, so it is masked here.

use anyhow::{Context, Result};
use serde::Serialize;

use crate::acl::{Acl, Kind};
use crate::config::{
    Action, AgentConfig, Config, McpServerConfig, McpTransportKind, UpstreamConfig,
};
use crate::secrets::display_ref;

/// Which part of the policy to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum What {
    #[default]
    All,
    Agents,
    Upstreams,
    Mcp,
    Acl,
}

impl What {
    fn shows(self, section: What) -> bool {
        self == What::All || self == section
    }
}

#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub what: What,
    /// Narrow the whole view to one agent: only the targets it may address, and
    /// only the rules whose agent glob matches it.
    pub agent: Option<String>,
}

/// Placeholder for a cell with nothing in it. Never an empty string: a blank
/// cell in an aligned table reads as a rendering bug.
const NONE: &str = "—";

/// The agent id column value for an agent whose `targets` is empty, which means
/// it may address anything the ACL lets through.
const ANY: &str = "*";

#[derive(Debug, Clone, Serialize)]
pub struct AgentRow {
    pub id: String,
    pub name: String,
    /// Upstreams and MCP servers this agent may address. Empty means any.
    pub targets: Vec<String>,
    /// Where the agent's own token comes from — a hash in the file, or a
    /// reference. Never the token.
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpstreamRow {
    pub name: String,
    pub base_url: String,
    /// Scheme plus the detail that tells two of the same kind apart.
    pub auth: String,
    /// Credential *references*. Never a resolved secret.
    pub credentials: Vec<String>,
    /// How many rules could reach this target as the `--agent`. `None` when no
    /// agent was named, because the count is meaningless across all of them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpRow {
    pub name: String,
    pub transport: String,
    /// The command for a stdio server, the URL for an HTTP one.
    pub endpoint: String,
    /// Credential references, including the child process's environment, which
    /// is where a stdio MCP server's credentials are injected.
    pub credentials: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AclRow {
    /// Position in the file. First match wins, so this ordering is the policy —
    /// it survives `--agent` filtering rather than being renumbered.
    pub index: usize,
    pub name: String,
    pub agent: String,
    pub kind: String,
    pub target: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub action: Action,
}

/// Everything the policy file exposes, in the sections that were asked for.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Inventory {
    /// Set when the view was narrowed with `--agent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<AgentRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstreams: Option<Vec<UpstreamRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_servers: Option<Vec<McpRow>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl: Option<Vec<AclRow>>,
    /// What happens when no rule matches. Only meaningful beside the rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acl_default: Option<Action>,
}

impl Inventory {
    pub fn build(config: &Config, options: &ListOptions) -> Result<Self> {
        // Only the agent-scoped view needs the globs compiled; a plain listing
        // should still print for a file whose ACL patterns do not compile.
        let scope = match &options.agent {
            Some(id) => {
                let agent = config.agent(id).with_context(|| {
                    format!(
                        "no agent `{id}` in this policy file — `mcp-iap list agents` shows the ids"
                    )
                })?;
                let acl = Acl::compile(config).context("compiling the ACL to resolve --agent")?;
                Some(Scope { agent, acl })
            }
            None => None,
        };

        let mut inventory = Inventory {
            agent: options.agent.clone(),
            ..Inventory::default()
        };

        if options.what.shows(What::Agents) {
            let mut agents: Vec<&AgentConfig> = match &scope {
                Some(scope) => vec![scope.agent],
                None => config.agents.iter().collect(),
            };
            agents.sort_by(|a, b| a.id.cmp(&b.id));
            inventory.agents = Some(agents.into_iter().map(agent_row).collect());
        }

        if options.what.shows(What::Upstreams) {
            let mut upstreams: Vec<&UpstreamConfig> = config
                .upstreams
                .iter()
                .filter(|u| scope.as_ref().is_none_or(|s| s.may_address(&u.name)))
                .collect();
            upstreams.sort_by(|a, b| a.name.cmp(&b.name));
            inventory.upstreams = Some(
                upstreams
                    .into_iter()
                    .map(|upstream| upstream_row(upstream, scope.as_ref()))
                    .collect(),
            );
        }

        if options.what.shows(What::Mcp) {
            let mut servers: Vec<&McpServerConfig> = config
                .mcp_servers
                .iter()
                .filter(|s| scope.as_ref().is_none_or(|sc| sc.may_address(&s.name)))
                .collect();
            servers.sort_by(|a, b| a.name.cmp(&b.name));
            inventory.mcp_servers = Some(
                servers
                    .into_iter()
                    .map(|server| mcp_row(server, scope.as_ref()))
                    .collect(),
            );
        }

        if options.what.shows(What::Acl) {
            let rows = match &scope {
                Some(scope) => scope
                    .acl
                    .rule_indices_for_agent(&scope.agent.id)
                    .into_iter()
                    .map(|index| acl_row(index, &config.acl[index]))
                    .collect(),
                None => config
                    .acl
                    .iter()
                    .enumerate()
                    .map(|(index, rule)| acl_row(index, rule))
                    .collect(),
            };
            inventory.acl = Some(rows);
            inventory.acl_default = Some(config.acl_default.action);
        }

        Ok(inventory)
    }

    /// The human view: one aligned table per section.
    pub fn render(&self) -> String {
        let mut out = String::new();

        if let Some(id) = &self.agent {
            out.push_str(&format!(
                "Everything `{id}` can address. Rules are in match order — first match wins.\n\n"
            ));
        }

        let mut section = |heading: &str, table: String| {
            if !out.is_empty() && !out.ends_with("\n\n") {
                out.push('\n');
            }
            out.push_str(heading);
            out.push('\n');
            out.push_str(&table);
        };

        if let Some(agents) = &self.agents {
            let rows: Vec<Vec<String>> = agents
                .iter()
                .map(|a| {
                    vec![
                        a.id.clone(),
                        a.name.clone(),
                        join_or_any(&a.targets),
                        a.token.clone(),
                    ]
                })
                .collect();
            section(
                "AGENTS",
                render_table(&["ID", "NAME", "TARGETS", "TOKEN"], &rows),
            );
        }

        if let Some(upstreams) = &self.upstreams {
            let scoped = upstreams.iter().any(|u| u.rules.is_some());
            let rows: Vec<Vec<String>> = upstreams
                .iter()
                .map(|u| {
                    let mut row = vec![
                        u.name.clone(),
                        u.base_url.clone(),
                        u.auth.clone(),
                        join_or_none(&u.credentials),
                    ];
                    if scoped {
                        row.push(reach(u.rules));
                    }
                    row
                })
                .collect();
            let mut headers = vec!["NAME", "BASE URL", "AUTH", "CREDENTIAL"];
            if scoped {
                headers.push("RULES");
            }
            section("UPSTREAMS", render_table(&headers, &rows));
        }

        if let Some(servers) = &self.mcp_servers {
            let scoped = servers.iter().any(|s| s.rules.is_some());
            let rows: Vec<Vec<String>> = servers
                .iter()
                .map(|s| {
                    let mut row = vec![
                        s.name.clone(),
                        s.transport.clone(),
                        s.endpoint.clone(),
                        join_or_none(&s.credentials),
                    ];
                    if scoped {
                        row.push(reach(s.rules));
                    }
                    row
                })
                .collect();
            let mut headers = vec!["NAME", "TRANSPORT", "COMMAND OR URL", "CREDENTIALS"];
            if scoped {
                headers.push("RULES");
            }
            section("MCP SERVERS", render_table(&headers, &rows));
        }

        if let Some(acl) = &self.acl {
            let rows: Vec<Vec<String>> = acl
                .iter()
                .map(|r| {
                    vec![
                        r.index.to_string(),
                        r.name.clone(),
                        r.agent.clone(),
                        r.kind.clone(),
                        r.target.clone(),
                        r.methods.join(","),
                        r.paths.join(","),
                        r.action.to_string(),
                    ]
                })
                .collect();
            let mut table = render_table(
                &[
                    "#", "NAME", "AGENT", "KIND", "TARGET", "METHODS", "PATHS", "ACTION",
                ],
                &rows,
            );
            if let Some(default) = self.acl_default {
                table.push_str(&format!("\nnothing matched → {default}\n"));
            }
            section("ACL", table);
        }

        out
    }
}

/// The `--agent` narrowing: who, and the compiled rules to ask about them.
struct Scope<'a> {
    agent: &'a AgentConfig,
    acl: Acl,
}

impl Scope<'_> {
    /// An empty `targets` means no restriction, so everything is addressable.
    fn may_address(&self, target: &str) -> bool {
        self.agent.targets.is_empty() || self.agent.targets.iter().any(|t| t == target)
    }
}

fn agent_row(agent: &AgentConfig) -> AgentRow {
    AgentRow {
        id: agent.id.clone(),
        name: agent.display_name().to_string(),
        targets: agent.targets.clone(),
        token: match (&agent.token_sha256, &agent.token_ref) {
            (Some(_), _) => "sha256 in file".to_string(),
            (None, Some(reference)) => display_ref(reference),
            (None, None) => NONE.to_string(),
        },
    }
}

fn upstream_row(upstream: &UpstreamConfig, scope: Option<&Scope>) -> UpstreamRow {
    UpstreamRow {
        name: upstream.name.clone(),
        base_url: upstream.base_url.clone(),
        auth: upstream.auth.describe(),
        credentials: upstream
            .auth
            .secret_refs()
            .into_iter()
            .map(display_ref)
            .collect(),
        rules: scope.map(|s| s.acl.rules_for(&s.agent.id, Kind::Http, &upstream.name)),
    }
}

fn mcp_row(server: &McpServerConfig, scope: Option<&Scope>) -> McpRow {
    let endpoint = match server.transport {
        McpTransportKind::Stdio => match &server.command {
            Some(command) if server.args.is_empty() => command.clone(),
            Some(command) => format!("{command} {}", server.args.join(" ")),
            None => NONE.to_string(),
        },
        McpTransportKind::Http => server.url.clone().unwrap_or_else(|| NONE.to_string()),
    };

    // A stdio server's credentials arrive as the child's environment, so the
    // variable name is half the answer: `GITHUB_TOKEN=op://…` says what the
    // server will see, which `op://…` alone does not.
    let mut credentials: Vec<String> = server
        .auth
        .secret_refs()
        .into_iter()
        .map(display_ref)
        .collect();
    credentials.extend(
        server
            .env
            .iter()
            .map(|(key, reference)| format!("{key}={}", display_ref(reference))),
    );

    McpRow {
        name: server.name.clone(),
        transport: match server.transport {
            McpTransportKind::Stdio => "stdio".to_string(),
            McpTransportKind::Http => "http".to_string(),
        },
        endpoint,
        credentials,
        rules: scope.map(|s| s.acl.rules_for(&s.agent.id, Kind::Mcp, &server.name)),
    }
}

fn acl_row(index: usize, rule: &crate::config::AclRuleConfig) -> AclRow {
    AclRow {
        index,
        // The same label the ACL engine and the audit log use, so a row here is
        // greppable against a decision there.
        name: rule.name.clone().unwrap_or_else(|| format!("acl[{index}]")),
        agent: rule.agent.clone(),
        kind: rule.kind.clone(),
        target: rule.target.clone(),
        methods: rule.methods.clone(),
        paths: rule.paths.clone(),
        action: rule.action,
    }
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        NONE.to_string()
    } else {
        values.join(", ")
    }
}

fn join_or_any(values: &[String]) -> String {
    if values.is_empty() {
        ANY.to_string()
    } else {
        values.join(", ")
    }
}

/// A rule count read as an answer. Zero is the one worth spelling out: a target
/// the agent may address but that no rule names falls through to the default.
fn reach(rules: Option<usize>) -> String {
    match rules {
        Some(0) => "none".to_string(),
        Some(count) => count.to_string(),
        None => NONE.to_string(),
    }
}

/// Left-aligned columns, two spaces apart, no trailing whitespace.
///
/// Widths are counted in `char`s. That is wrong for double-width glyphs and
/// right for everything this prints — names, URLs and secret references.
fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "  (none)\n".to_string();
    }

    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            let width = cell.chars().count();
            if width > widths[index] {
                widths[index] = width;
            }
        }
    }

    let mut out = String::new();
    let mut line = |cells: &[String]| {
        let mut rendered = String::new();
        for (index, cell) in cells.iter().enumerate() {
            if index + 1 == cells.len() {
                rendered.push_str(cell);
            } else {
                rendered.push_str(cell);
                let pad = widths[index] - cell.chars().count() + 2;
                rendered.extend(std::iter::repeat_n(' ', pad));
            }
        }
        out.push_str(rendered.trim_end());
        out.push('\n');
    };

    line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    for row in rows {
        line(row);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
[[agents]]
id = "ci-bot"
name = "CI Bot"
token_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
targets = ["github", "linear"]

[[agents]]
id = "analyst"
token_ref = "op://Private/analyst/token"

[[upstreams]]
name = "github"
base_url = "https://api.github.com"
auth = { type = "bearer", secret = "op://Private/GitHub/token" }

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"
auth = { type = "header", header = "x-api-key", secret = "env:ANTHROPIC_API_KEY" }

[[mcp_servers]]
name = "linear"
command = "linear-mcp"
args = ["--stdio"]
env = { LINEAR_API_KEY = "op://Private/Linear/key" }

[[acl]]
name = "github-reads"
agent = "ci-*"
kind = "http"
target = "github"
methods = ["GET"]
paths = ["/repos/**"]
action = "allow"

[[acl]]
name = "linear-tools"
agent = "ci-bot"
kind = "mcp"
target = "linear"
methods = ["tools/call"]
paths = ["create_*"]
action = "ask"

[[acl]]
name = "analyst-anything"
agent = "analyst"
action = "allow"
"#;

    fn policy() -> Config {
        let config: Config = toml::from_str(POLICY).unwrap();
        config.validate().unwrap();
        config
    }

    fn inventory(options: ListOptions) -> Inventory {
        Inventory::build(&policy(), &options).unwrap()
    }

    /// The complaint that motivated the command: `check` puts every upstream on
    /// one line. One row per thing is the whole point.
    #[test]
    fn every_service_gets_its_own_row() {
        let rendered = inventory(ListOptions::default()).render();
        let upstream_lines: Vec<&str> = rendered
            .lines()
            .filter(|line| line.contains("api.github.com") || line.contains("api.anthropic.com"))
            .collect();
        assert_eq!(upstream_lines.len(), 2, "{rendered}");
        for line in upstream_lines {
            assert!(!line.contains(", "), "upstreams must not be joined: {line}");
        }
    }

    #[test]
    fn columns_line_up_under_their_headers() {
        let table = render_table(
            &["NAME", "URL"],
            &[
                vec!["a".into(), "http://one".into()],
                vec!["much-longer".into(), "http://two".into()],
            ],
        );
        let lines: Vec<&str> = table.lines().collect();
        let column = lines[0].find("URL").unwrap();
        assert_eq!(lines[1].find("http://one"), Some(column));
        assert_eq!(lines[2].find("http://two"), Some(column));
        for line in &lines {
            assert_eq!(*line, line.trim_end(), "no trailing whitespace");
        }
    }

    #[test]
    fn an_empty_section_says_so_rather_than_rendering_a_bare_header() {
        let config: Config = toml::from_str("").unwrap();
        let rendered = Inventory::build(&config, &ListOptions::default())
            .unwrap()
            .render();
        assert!(rendered.contains("UPSTREAMS\n  (none)"), "{rendered}");
    }

    /// The constraint that matters most: a reference is a pointer to a
    /// credential, but `literal:` *is* the credential.
    #[test]
    fn a_literal_secret_is_masked_and_a_reference_is_not() {
        let text = r#"
[[upstreams]]
name = "demo"
base_url = "https://example.test"
auth = { type = "bearer", secret = "literal:sk-super-secret" }
"#;
        let config: Config = toml::from_str(text).unwrap();
        let rendered = Inventory::build(&config, &ListOptions::default())
            .unwrap()
            .render();
        assert!(!rendered.contains("sk-super-secret"), "{rendered}");
        assert!(rendered.contains("literal:***"), "{rendered}");

        let rendered = inventory(ListOptions::default()).render();
        assert!(
            rendered.contains("op://Private/GitHub/token"),
            "a reference is safe to print: {rendered}"
        );
    }

    #[test]
    fn auth_names_the_header_because_two_header_schemes_are_not_the_same_grant() {
        let rows = inventory(ListOptions {
            what: What::Upstreams,
            ..ListOptions::default()
        })
        .upstreams
        .unwrap();
        let anthropic = rows.iter().find(|u| u.name == "anthropic").unwrap();
        assert_eq!(anthropic.auth, "header x-api-key");
        assert_eq!(anthropic.credentials, vec!["env:ANTHROPIC_API_KEY"]);
    }

    #[test]
    fn an_mcp_row_shows_the_command_and_the_env_the_child_will_see() {
        let rows = inventory(ListOptions {
            what: What::Mcp,
            ..ListOptions::default()
        })
        .mcp_servers
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].transport, "stdio");
        assert_eq!(rows[0].endpoint, "linear-mcp --stdio");
        assert_eq!(
            rows[0].credentials,
            vec!["LINEAR_API_KEY=op://Private/Linear/key"]
        );
    }

    #[test]
    fn acl_rows_keep_file_order_because_first_match_wins() {
        let rows = inventory(ListOptions {
            what: What::Acl,
            ..ListOptions::default()
        })
        .acl
        .unwrap();
        let order: Vec<usize> = rows.iter().map(|r| r.index).collect();
        assert_eq!(order, vec![0, 1, 2]);
        assert_eq!(rows[0].name, "github-reads");
    }

    #[test]
    fn an_unnamed_rule_gets_the_label_the_audit_log_uses() {
        let text = "[[acl]]\naction = \"deny\"\n";
        let config: Config = toml::from_str(text).unwrap();
        let rows = Inventory::build(&config, &ListOptions::default())
            .unwrap()
            .acl
            .unwrap();
        assert_eq!(rows[0].name, "acl[0]");
    }

    #[test]
    fn agent_scope_keeps_only_the_targets_and_rules_that_agent_can_reach() {
        let inventory = inventory(ListOptions {
            what: What::All,
            agent: Some("ci-bot".into()),
        });

        let agents = inventory.agents.unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "CI Bot");

        let upstreams: Vec<String> = inventory
            .upstreams
            .unwrap()
            .into_iter()
            .map(|u| u.name)
            .collect();
        assert_eq!(
            upstreams,
            vec!["github"],
            "`anthropic` is not in ci-bot's targets"
        );

        // `ci-*` matches, `analyst` does not — and the surviving rules keep the
        // indices they have in the file, because that is the evaluation order.
        let indices: Vec<usize> = inventory.acl.unwrap().iter().map(|r| r.index).collect();
        assert_eq!(indices, vec![0, 1]);
    }

    #[test]
    fn an_agent_with_no_targets_reaches_everything_the_acl_allows() {
        let inventory = inventory(ListOptions {
            what: What::All,
            agent: Some("analyst".into()),
        });
        let upstreams: Vec<String> = inventory
            .upstreams
            .unwrap()
            .into_iter()
            .map(|u| u.name)
            .collect();
        assert_eq!(upstreams, vec!["anthropic", "github"]);
        assert_eq!(inventory.mcp_servers.unwrap().len(), 1);
    }

    /// The diagnostic worth having: a target an agent may address that no rule
    /// ever names denies at request time, and reads as a grant in the file.
    #[test]
    fn a_target_with_no_matching_rule_is_reported_as_none() {
        let text = format!(
            "{POLICY}\n[[upstreams]]\nname = \"stripe\"\nbase_url = \"https://api.stripe.com\"\n"
        );
        let mut config: Config = toml::from_str(&text).unwrap();
        config.agents[0].targets.push("stripe".into());
        config.validate().unwrap();

        let inventory = Inventory::build(
            &config,
            &ListOptions {
                what: What::Upstreams,
                agent: Some("ci-bot".into()),
            },
        )
        .unwrap();
        let rows = inventory.upstreams.clone().unwrap();
        let stripe = rows.iter().find(|u| u.name == "stripe").unwrap();
        assert_eq!(stripe.rules, Some(0));
        assert_eq!(
            rows.iter().find(|u| u.name == "github").unwrap().rules,
            Some(1)
        );

        let rendered = inventory.render();
        let line = rendered
            .lines()
            .find(|line| line.starts_with("stripe"))
            .unwrap();
        assert!(line.ends_with("none"), "{rendered}");
    }

    /// An `http` rule can never grant an MCP server, so it must not be counted
    /// as reach for one.
    #[test]
    fn rule_counts_respect_the_kind_of_the_target() {
        let inventory = inventory(ListOptions {
            what: What::All,
            agent: Some("ci-bot".into()),
        });
        assert_eq!(inventory.mcp_servers.unwrap()[0].rules, Some(1));
        assert_eq!(inventory.upstreams.unwrap()[0].rules, Some(1));
    }

    #[test]
    fn asking_for_one_section_returns_only_that_section() {
        let inventory = inventory(ListOptions {
            what: What::Agents,
            ..ListOptions::default()
        });
        assert!(inventory.agents.is_some());
        assert!(inventory.upstreams.is_none());
        assert!(inventory.acl.is_none());

        let json = serde_json::to_value(&inventory).unwrap();
        assert!(json.get("agents").is_some());
        assert!(
            json.get("upstreams").is_none(),
            "an absent section must not serialise as null"
        );
    }

    #[test]
    fn an_unknown_agent_is_an_error_that_says_where_to_look() {
        let error = Inventory::build(
            &policy(),
            &ListOptions {
                what: What::All,
                agent: Some("nobody".into()),
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("nobody"), "{error}");
        assert!(error.contains("list agents"), "{error}");
    }

    #[test]
    fn json_carries_the_default_action_beside_the_rules() {
        let inventory = inventory(ListOptions {
            what: What::Acl,
            ..ListOptions::default()
        });
        assert_eq!(inventory.acl_default, Some(Action::Deny));
        let json = serde_json::to_value(&inventory).unwrap();
        assert_eq!(json["acl_default"], "deny");
        assert_eq!(json["acl"][0]["action"], "allow");
    }
}

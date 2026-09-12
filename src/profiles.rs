//! Helper profiles: a service the proxy can front, already spelled out.
//!
//! `upstream add` and `mcp-server add` can express any service, which means
//! they ask you for everything — the base URL, the scheme, the header name, the
//! OAuth scopes, and a set of paths narrow enough to be worth calling a policy.
//! Getting a service wrong in that list does not fail loudly: a scope typo is a
//! 403 an hour later, and `--paths '/**'` is a grant nobody reviews.
//!
//! A profile is that answer, written down once. `mcp-iap profile add graylog`
//! knows Graylog authenticates an access token as `<token>:token`, that its API
//! hangs off `/api`, and which of its routes are reads. What it does *not* know
//! is your credential, and it never asks for one: `--secret` takes the same
//! reference every other command takes.
//!
//! Profiles are a starting point, not a ceiling. Everything one writes is
//! ordinary TOML in the policy file, and `--dry-run` prints it before anything
//! is written, because a policy you did not read is not a policy you can rely
//! on.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

use crate::enroll::{self, AuthSpec, McpTransportSpec};

/// What credential the profile needs, so `profile show` can say what to fetch
/// before the first call fails with a 401 that names nothing.
#[derive(Debug, Clone)]
pub struct Credential {
    /// One line: what the thing is called where you go to create it.
    pub about: String,
    /// Where to create it.
    pub url: String,
}

/// A value the caller has to supply because it is theirs, not the vendor's —
/// a self-hosted host name, a data region, an account login.
#[derive(Debug, Clone)]
pub struct Var {
    pub name: String,
    pub about: String,
    pub default: Option<String>,
}

/// The credential scheme, minus the reference the caller supplies as `--secret`.
#[derive(Debug, Clone)]
pub enum AuthTemplate {
    None,
    Bearer,
    Header {
        header: String,
        prefix: Option<String>,
    },
    /// Ordinary basic auth; the user half comes from a profile variable.
    Basic {
        username_var: String,
    },
    /// Basic auth where the *user* field is the credential and the password is
    /// a documented constant — Graylog's `<token>:token`.
    BasicSecretUser {
        password: String,
    },
    /// Google and anything else doing RFC 7523. Scopes come from the access
    /// level, because "read" and "write" are different scopes, not just
    /// different paths.
    ServiceAccountJwt,
}

/// What the profile adds to the policy file.
#[derive(Debug, Clone)]
pub enum Service {
    Http {
        base_url: String,
        auth: AuthTemplate,
    },
    McpHttp {
        url: String,
        auth: AuthTemplate,
    },
    /// A child process. Used for vendors whose remote MCP server speaks OAuth
    /// rather than a bearer token: `mcp-remote` does the browser flow and
    /// caches the result, and the proxy still sees every JSON-RPC message.
    McpStdio {
        command: String,
        args: Vec<String>,
        /// Child environment. Values are secret references; `{secret}` is
        /// substituted with whatever `--secret` was given.
        env: Vec<(String, String)>,
    },
}

impl Service {
    pub fn kind(&self) -> &'static str {
        match self {
            Service::Http { .. } => "http",
            Service::McpHttp { .. } | Service::McpStdio { .. } => "mcp",
        }
    }

    fn endpoint(&self) -> String {
        match self {
            Service::Http { base_url, .. } => base_url.clone(),
            Service::McpHttp { url, .. } => url.clone(),
            Service::McpStdio { command, args, .. } => {
                format!("{command} {}", args.join(" "))
            }
        }
    }
}

/// One ACL rule the access level contributes.
#[derive(Debug, Clone)]
pub struct RuleTemplate {
    pub suffix: String,
    pub methods: Vec<String>,
    pub paths: Vec<String>,
    pub action: String,
}

/// A named bundle of scopes and rules: what "read" means for this service.
#[derive(Debug, Clone)]
pub struct Access {
    pub name: String,
    pub about: String,
    /// OAuth scopes this level needs. Empty for schemes that have none.
    pub scopes: Vec<String>,
    pub rules: Vec<RuleTemplate>,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub id: String,
    pub title: String,
    pub vendor: String,
    pub summary: String,
    pub default_name: String,
    pub credential: Credential,
    pub vars: Vec<Var>,
    pub service: Service,
    pub access: Vec<Access>,
    /// Anything true about this profile that would otherwise be found out the
    /// hard way — an auth flow the proxy cannot do, a call that costs money.
    pub note: Option<String>,
}

impl Profile {
    pub fn default_access(&self) -> &Access {
        &self.access[0]
    }

    pub fn find_access(&self, name: &str) -> Result<&Access> {
        self.access
            .iter()
            .find(|level| level.name == name)
            .with_context(|| {
                format!(
                    "profile `{}` has no access level `{name}` — it has {}",
                    self.id,
                    self.access
                        .iter()
                        .map(|level| level.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    pub fn endpoint(&self) -> String {
        self.service.endpoint()
    }
}

/// The MCP methods that carry the session rather than doing anything with it.
///
/// These name no tool and no resource, so they match a rule only when it places
/// no constraint on `paths`. Any tool-scoped rule therefore leaves `initialize`
/// falling through to the default — and the default is deny, so the handshake
/// fails and the agent sees a server that never came up. Every MCP profile
/// emits this rule first, before the rule that scopes the tools.
pub const MCP_SESSION_METHODS: &[&str] = &[
    "initialize",
    "notifications/*",
    "ping",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
    "completion/complete",
    "logging/setLevel",
];

/// Options for materialising a profile into a policy file.
pub struct AddOptions {
    /// Name the service takes in the policy file. Defaults to the profile's.
    pub name: Option<String>,
    /// Credential reference. Required unless the profile needs none.
    pub secret: Option<String>,
    /// Access level; defaults to the profile's first, which is the narrowest.
    pub access: Option<String>,
    pub vars: Vec<String>,
    /// Restrict the rules to one agent. Defaults to every agent.
    pub agent: Option<String>,
    /// Print what would be written and write nothing.
    pub dry_run: bool,
}

/// A rule the profile is about to write, with the name and target it will
/// actually carry — resolved from `--as`, not from the profile id.
struct PlannedRule {
    name: String,
    kind: String,
    methods: Vec<String>,
    paths: Vec<String>,
    action: String,
}

/// What `profile add` did, so the caller can print it without re-deriving it.
pub struct Added {
    pub name: String,
    pub kind: &'static str,
    pub endpoint: String,
    pub access: String,
    pub rules: Vec<String>,
    pub scopes: Vec<String>,
    pub note: Option<String>,
}

pub fn get(id: &str) -> Result<Profile> {
    catalog()
        .into_iter()
        .find(|profile| profile.id == id)
        .with_context(|| {
            format!("no profile `{id}` — `mcp-iap profile list` shows every one there is")
        })
}

/// Add a profile to the policy file: the service, then its rules.
pub fn add(path: &Path, profile: &Profile, options: &AddOptions) -> Result<Added> {
    let name = options
        .name
        .clone()
        .unwrap_or_else(|| profile.default_name.clone());
    let access = match &options.access {
        Some(level) => profile.find_access(level)?,
        None => profile.default_access(),
    };
    let vars = resolve_vars(profile, &options.vars)?;

    let needs_secret = !matches!(
        service_auth(&profile.service),
        Some(AuthTemplate::None) | None
    );
    let secret = match (&options.secret, needs_secret) {
        (Some(secret), _) => secret.clone(),
        (None, true) => bail!(
            "profile `{}` needs `--secret <REF>`: {} — create one at {}",
            profile.id,
            profile.credential.about,
            profile.credential.url
        ),
        (None, false) => String::new(),
    };

    let service = substitute_service(&profile.service, &vars, &secret)?;
    let auth = build_auth(&service, &secret, &vars, &access.scopes)?;

    // Rules are named after the service as it was actually added, not after the
    // profile: two PostHog accounts on one proxy would otherwise produce two
    // sets of rules with identical names in the audit log.
    let agent = options.agent.clone().unwrap_or_else(|| "*".to_string());
    let mut rules: Vec<PlannedRule> = Vec::new();
    if service.kind() == "mcp" {
        // First, so it is matched before any tool-scoped rule can shadow it.
        rules.push(PlannedRule {
            name: format!("{name}-session"),
            kind: "mcp".to_string(),
            methods: MCP_SESSION_METHODS.iter().map(|m| m.to_string()).collect(),
            paths: vec!["**".to_string()],
            action: "allow".to_string(),
        });
    }
    for rule in &access.rules {
        rules.push(PlannedRule {
            name: format!("{name}-{}", rule.suffix),
            kind: service.kind().to_string(),
            methods: rule.methods.clone(),
            paths: rule.paths.clone(),
            action: rule.action.clone(),
        });
    }

    let added = Added {
        name: name.clone(),
        kind: service.kind(),
        endpoint: service.endpoint(),
        access: access.name.clone(),
        rules: rules.iter().map(|rule| rule.name.clone()).collect(),
        scopes: access.scopes.clone(),
        note: profile.note.clone(),
    };

    if options.dry_run {
        print_dry_run(&name, &service, &auth, &rules, &agent);
        return Ok(added);
    }

    match &service {
        Service::Http { base_url, .. } => {
            enroll::add_upstream(path, &name, base_url, &auth, &[])?;
        }
        Service::McpHttp { url, .. } => {
            enroll::add_mcp_server(
                path,
                &name,
                &McpTransportSpec::Http { url: url.clone() },
                &auth,
            )?;
        }
        Service::McpStdio { command, args, env } => {
            enroll::add_mcp_server(
                path,
                &name,
                &McpTransportSpec::Stdio {
                    command: command.clone(),
                    args: args.clone(),
                    env: env.clone(),
                    cwd: None,
                },
                &auth,
            )?;
        }
    }

    for rule in &rules {
        enroll::add_rule(
            path,
            Some(&rule.name),
            &agent,
            &rule.kind,
            &name,
            &rule.methods,
            &rule.paths,
            &rule.action,
        )?;
    }

    Ok(added)
}

fn print_dry_run(
    name: &str,
    service: &Service,
    auth: &AuthSpec,
    rules: &[PlannedRule],
    agent: &str,
) {
    println!("# would append to the policy file:");
    println!(
        "{}",
        enroll::render_service(name, service_spec(service), auth)
    );
    for rule in rules {
        println!(
            "{}",
            enroll::render_rule(
                Some(&rule.name),
                agent,
                &rule.kind,
                name,
                &rule.methods,
                &rule.paths,
                &rule.action,
            )
        );
    }
}

fn service_spec(service: &Service) -> enroll::ServiceSpec<'_> {
    match service {
        Service::Http { base_url, .. } => enroll::ServiceSpec::Upstream { base_url },
        Service::McpHttp { url, .. } => enroll::ServiceSpec::McpHttp { url },
        Service::McpStdio { command, args, env } => {
            enroll::ServiceSpec::McpStdio { command, args, env }
        }
    }
}

fn service_auth(service: &Service) -> Option<AuthTemplate> {
    match service {
        Service::Http { auth, .. } | Service::McpHttp { auth, .. } => Some(auth.clone()),
        // A stdio server takes its credential through the environment, which is
        // still a `--secret` reference — just not an `auth` block.
        Service::McpStdio { env, .. } => {
            if env.is_empty() {
                Some(AuthTemplate::None)
            } else {
                None
            }
        }
    }
}

fn resolve_vars(profile: &Profile, given: &[String]) -> Result<BTreeMap<String, String>> {
    let mut supplied = BTreeMap::new();
    for entry in given {
        let (key, value) = entry
            .split_once('=')
            .with_context(|| format!("`--var {entry}` should be `name=value`"))?;
        if !profile.vars.iter().any(|var| var.name == key) {
            bail!(
                "profile `{}` has no variable `{key}` — it takes {}",
                profile.id,
                if profile.vars.is_empty() {
                    "none".to_string()
                } else {
                    profile
                        .vars
                        .iter()
                        .map(|var| var.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
        }
        supplied.insert(key.to_string(), value.to_string());
    }

    let mut resolved = BTreeMap::new();
    for var in &profile.vars {
        let value = supplied
            .get(&var.name)
            .cloned()
            .or_else(|| var.default.clone())
            .with_context(|| {
                format!(
                    "profile `{}` needs `--var {}=…` ({})",
                    profile.id, var.name, var.about
                )
            })?;
        resolved.insert(var.name.clone(), value);
    }
    Ok(resolved)
}

/// `{var}` and `{secret}` substitution. An unresolved placeholder is an error
/// rather than a literal brace in a base URL nobody notices until the 404.
fn expand(template: &str, vars: &BTreeMap<String, String>, secret: &str) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .with_context(|| format!("unterminated `{{` in `{template}`"))?
            + open;
        let key = &rest[open + 1..close];
        let value = if key == "secret" {
            secret.to_string()
        } else {
            vars.get(key)
                .cloned()
                .with_context(|| format!("`{{{key}}}` in `{template}` has no value"))?
        };
        out.push_str(&value);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn substitute_service(
    service: &Service,
    vars: &BTreeMap<String, String>,
    secret: &str,
) -> Result<Service> {
    Ok(match service {
        Service::Http { base_url, auth } => Service::Http {
            base_url: expand(base_url, vars, secret)?,
            auth: auth.clone(),
        },
        Service::McpHttp { url, auth } => Service::McpHttp {
            url: expand(url, vars, secret)?,
            auth: auth.clone(),
        },
        Service::McpStdio { command, args, env } => Service::McpStdio {
            command: command.clone(),
            args: args
                .iter()
                .map(|arg| expand(arg, vars, secret))
                .collect::<Result<_>>()?,
            env: env
                .iter()
                .map(|(key, value)| Ok((key.clone(), expand(value, vars, secret)?)))
                .collect::<Result<_>>()?,
        },
    })
}

fn build_auth(
    service: &Service,
    secret: &str,
    vars: &BTreeMap<String, String>,
    scopes: &[String],
) -> Result<AuthSpec> {
    let template = match service {
        Service::Http { auth, .. } | Service::McpHttp { auth, .. } => auth.clone(),
        Service::McpStdio { .. } => return Ok(AuthSpec::None),
    };
    Ok(match template {
        AuthTemplate::None => AuthSpec::None,
        AuthTemplate::Bearer => AuthSpec::Bearer {
            secret: secret.to_string(),
        },
        AuthTemplate::Header { header, prefix } => AuthSpec::Header {
            header,
            secret: secret.to_string(),
            prefix,
        },
        AuthTemplate::Basic { username_var } => AuthSpec::Basic {
            username: Some(
                vars.get(&username_var)
                    .cloned()
                    .with_context(|| format!("basic auth needs `--var {username_var}=…`"))?,
            ),
            username_secret: None,
            secret: secret.to_string(),
        },
        AuthTemplate::BasicSecretUser { password } => AuthSpec::Basic {
            username: None,
            username_secret: Some(secret.to_string()),
            secret: format!("literal:{password}"),
        },
        AuthTemplate::ServiceAccountJwt => AuthSpec::ServiceAccountJwt {
            key_file: Some(secret.to_string()),
            issuer: None,
            private_key: None,
            key_id: None,
            token_url: None,
            audience: None,
            scopes: scopes.to_vec(),
            subject: None,
            lifetime_secs: None,
        },
    })
}

// ---------------------------------------------------------------------------
// The catalog
// ---------------------------------------------------------------------------

fn v(name: &str, about: &str, default: Option<&str>) -> Var {
    Var {
        name: name.into(),
        about: about.into(),
        default: default.map(Into::into),
    }
}

fn rule(suffix: &str, methods: &[&str], paths: &[&str], action: &str) -> RuleTemplate {
    RuleTemplate {
        suffix: suffix.into(),
        methods: methods.iter().map(|m| m.to_string()).collect(),
        paths: paths.iter().map(|p| p.to_string()).collect(),
        action: action.into(),
    }
}

fn access(name: &str, about: &str, scopes: &[&str], rules: Vec<RuleTemplate>) -> Access {
    Access {
        name: name.into(),
        about: about.into(),
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        rules,
    }
}

/// A Google API fronted by one service account. Read and write differ by scope
/// as well as by path, which is why the scopes live on the access level.
fn google(id: &str, title: &str, summary: &str, base_url: &str, levels: Vec<Access>) -> Profile {
    Profile {
        id: id.into(),
        title: title.into(),
        vendor: "Google".into(),
        summary: summary.into(),
        default_name: id.into(),
        credential: Credential {
            about: "the service-account JSON key, exactly as Google issues it".into(),
            url: "https://console.cloud.google.com/iam-admin/serviceaccounts".into(),
        },
        vars: vec![],
        service: Service::Http {
            base_url: base_url.into(),
            auth: AuthTemplate::ServiceAccountJwt,
        },
        access: levels,
        note: Some(
            "Grant the service account access to the property itself — a key with no \
             binding authenticates fine and then 403s. For Search Console add the \
             service-account email as a user on the site; for GA4 add it to the property. \
             `--subject` on the upstream turns on domain-wide delegation if you need to \
             act as a person instead."
                .into(),
        ),
    }
}

fn cloudflare_mcp(slug: &str, host: &str, title: &str, summary: &str) -> Profile {
    Profile {
        id: format!("cloudflare-mcp-{slug}"),
        title: title.into(),
        vendor: "Cloudflare".into(),
        summary: summary.into(),
        default_name: format!("cf-{slug}"),
        credential: Credential {
            about: "nothing up front — `mcp-remote` opens a browser for Cloudflare's OAuth \
                    flow on first use and caches the grant"
                .into(),
            url: "https://developers.cloudflare.com/agents/model-context-protocol/".into(),
        },
        vars: vec![],
        service: Service::McpStdio {
            command: "npx".into(),
            args: vec![
                "-y".into(),
                "mcp-remote".into(),
                format!("https://{host}/mcp"),
            ],
            env: vec![],
        },
        access: vec![
            access(
                "read",
                "read-only tools",
                &[],
                vec![
                    // Cloudflare's MCP tools are underscore-named — `zones_list`,
                    // `workers_get_worker`, `query_worker_observability`.
                    rule(
                        "reads",
                        &["tools/call"],
                        &[
                            "get_*",
                            "*_get",
                            "*_get_*",
                            "list_*",
                            "*_list",
                            "search_*",
                            "*_search",
                            "query_*",
                            "*_query",
                            "*_read",
                            "*_analytics",
                        ],
                        "allow",
                    ),
                    rule("other-tools", &["tools/call"], &["**"], "ask"),
                ],
            ),
            access(
                "write",
                "every tool the server exposes",
                &[],
                vec![rule("tools", &["tools/call"], &["**"], "allow")],
            ),
            access(
                "ask",
                "prompt for every tool call",
                &[],
                vec![rule("tools", &["tools/call"], &["**"], "ask")],
            ),
        ],
        note: Some(
            "Cloudflare's hosted MCP servers authenticate with an interactive OAuth flow, \
             not an API token, so this profile runs them through `mcp-remote` rather than \
             fronting the endpoint directly. That means the OAuth grant lives in the \
             child's cache, outside the proxy — the proxy still sees and rules on every \
             JSON-RPC message, but it is not what holds the credential. For a credential \
             the proxy does hold, use the `cloudflare` REST profile."
                .into(),
        ),
    }
}

/// A plain bearer-token REST API: the shape most vendors ship.
/// The shape most vendors ship: one base URL, one bearer token, three levels.
struct BearerApi<'a> {
    id: &'a str,
    title: &'a str,
    vendor: &'a str,
    summary: &'a str,
    base_url: &'a str,
    credential: Credential,
    read_paths: &'a [&'a str],
    write_paths: &'a [&'a str],
}

fn bearer_api(spec: BearerApi<'_>) -> Profile {
    let BearerApi {
        id,
        title,
        vendor,
        summary,
        base_url,
        credential,
        read_paths,
        write_paths,
    } = spec;
    Profile {
        id: id.into(),
        title: title.into(),
        vendor: vendor.into(),
        summary: summary.into(),
        default_name: id.into(),
        credential,
        vars: vec![],
        service: Service::Http {
            base_url: base_url.into(),
            auth: AuthTemplate::Bearer,
        },
        access: vec![
            access(
                "read",
                "GET only",
                &[],
                vec![rule("reads", &["GET"], read_paths, "allow")],
            ),
            access(
                "write",
                "every method",
                &[],
                vec![rule("all", &["*"], write_paths, "allow")],
            ),
            access(
                "ask-writes",
                "reads allowed, anything else prompts, DELETE denied",
                &[],
                vec![
                    rule("reads", &["GET"], read_paths, "allow"),
                    rule("deletes", &["DELETE"], write_paths, "deny"),
                    rule("writes", &["*"], write_paths, "ask"),
                ],
            ),
        ],
        note: None,
    }
}

pub fn catalog() -> Vec<Profile> {
    let mut profiles = vec![
        // ---------------- Google ----------------
        google(
            "google-search-console",
            "Google Search Console",
            "Search analytics, sitemaps and URL inspection for a verified property.",
            "https://searchconsole.googleapis.com",
            vec![
                access(
                    "read",
                    "search analytics and site listings; the query endpoints are POST",
                    &["https://www.googleapis.com/auth/webmasters.readonly"],
                    vec![
                        rule("reads", &["GET"], &["/webmasters/v3/**", "/v1/**"], "allow"),
                        // `searchAnalytics.query` and `urlInspection` are reads
                        // that happen to be POSTs, so a GET-only rule would make
                        // the read-only level unable to read anything.
                        rule(
                            "queries",
                            &["POST"],
                            &[
                                "/webmasters/v3/sites/*/searchAnalytics/query",
                                "/v1/urlInspection/index:inspect",
                            ],
                            "allow",
                        ),
                    ],
                ),
                access(
                    "write",
                    "also sitemap submission and site management",
                    &["https://www.googleapis.com/auth/webmasters"],
                    vec![rule("all", &["*"], &["/webmasters/v3/**", "/v1/**"], "allow")],
                ),
            ],
        ),
        google(
            "google-analytics-data",
            "Google Analytics 4 — Data API",
            "runReport, runRealtimeReport and the rest of the GA4 reporting surface.",
            "https://analyticsdata.googleapis.com",
            vec![access(
                "read",
                "the whole Data API, which has no mutations — its reads are POSTs",
                &["https://www.googleapis.com/auth/analytics.readonly"],
                vec![rule("reports", &["GET", "POST"], &["/v1beta/**"], "allow")],
            )],
        ),
        google(
            "google-analytics-admin",
            "Google Analytics 4 — Admin API",
            "Accounts, properties, data streams and custom dimensions.",
            "https://analyticsadmin.googleapis.com",
            vec![
                access(
                    "read",
                    "list and get",
                    &["https://www.googleapis.com/auth/analytics.readonly"],
                    vec![rule("reads", &["GET"], &["/v1beta/**", "/v1alpha/**"], "allow")],
                ),
                access(
                    "write",
                    "also create, update and delete",
                    &["https://www.googleapis.com/auth/analytics.edit"],
                    vec![rule("all", &["*"], &["/v1beta/**", "/v1alpha/**"], "allow")],
                ),
            ],
        ),
        google(
            "google-indexing",
            "Google Indexing API",
            "Notify Google that a URL was updated or deleted.",
            "https://indexing.googleapis.com",
            vec![access(
                "write",
                "publish notifications — the API has no read surface worth scoping",
                &["https://www.googleapis.com/auth/indexing"],
                vec![rule(
                    "publish",
                    &["POST"],
                    &["/v3/urlNotifications:publish"],
                    "allow",
                )],
            )],
        ),
        google(
            "google-bigquery",
            "Google BigQuery",
            "Run queries and read datasets, tables and job results.",
            "https://bigquery.googleapis.com",
            vec![
                access(
                    "read",
                    "list metadata and run queries",
                    &["https://www.googleapis.com/auth/bigquery.readonly"],
                    vec![
                        rule("reads", &["GET"], &["/bigquery/v2/**"], "allow"),
                        rule(
                            "queries",
                            &["POST"],
                            &["/bigquery/v2/projects/*/queries", "/bigquery/v2/projects/*/jobs"],
                            "allow",
                        ),
                    ],
                ),
                access(
                    "write",
                    "also create and delete datasets and tables",
                    &["https://www.googleapis.com/auth/bigquery"],
                    vec![rule("all", &["*"], &["/bigquery/v2/**"], "allow")],
                ),
            ],
        ),
        google(
            "google-drive",
            "Google Drive",
            "List, search and download files.",
            "https://www.googleapis.com",
            vec![
                access(
                    "read",
                    "list, get and download",
                    &["https://www.googleapis.com/auth/drive.readonly"],
                    vec![rule("reads", &["GET"], &["/drive/v3/**"], "allow")],
                ),
                access(
                    "write",
                    "also upload, update and delete",
                    &["https://www.googleapis.com/auth/drive"],
                    vec![rule("all", &["*"], &["/drive/v3/**", "/upload/drive/v3/**"], "allow")],
                ),
            ],
        ),
        google(
            "google-sheets",
            "Google Sheets",
            "Read and write spreadsheet values.",
            "https://sheets.googleapis.com",
            vec![
                access(
                    "read",
                    "get values and metadata",
                    &["https://www.googleapis.com/auth/spreadsheets.readonly"],
                    vec![rule("reads", &["GET"], &["/v4/spreadsheets/**"], "allow")],
                ),
                access(
                    "write",
                    "also update and append",
                    &["https://www.googleapis.com/auth/spreadsheets"],
                    vec![rule("all", &["*"], &["/v4/spreadsheets/**"], "allow")],
                ),
            ],
        ),
        google(
            "google-cloud-logging",
            "Google Cloud Logging",
            "Read log entries out of Cloud Logging.",
            "https://logging.googleapis.com",
            vec![access(
                "read",
                "list entries — `entries:list` is a POST",
                &["https://www.googleapis.com/auth/logging.read"],
                vec![
                    rule("reads", &["GET"], &["/v2/**"], "allow"),
                    rule("list-entries", &["POST"], &["/v2/entries:list"], "allow"),
                ],
            )],
        ),
        google(
            "google-cloud-storage",
            "Google Cloud Storage",
            "Read objects and bucket metadata.",
            "https://storage.googleapis.com",
            vec![
                access(
                    "read",
                    "get objects and list buckets",
                    &["https://www.googleapis.com/auth/devstorage.read_only"],
                    vec![rule("reads", &["GET"], &["/**"], "allow")],
                ),
                access(
                    "write",
                    "also upload and delete",
                    &["https://www.googleapis.com/auth/devstorage.read_write"],
                    vec![rule("all", &["*"], &["/**"], "allow")],
                ),
            ],
        ),
        // ---------------- PostHog ----------------
        Profile {
            id: "posthog".into(),
            title: "PostHog REST API".into(),
            vendor: "PostHog".into(),
            summary: "Projects, insights, events, feature flags and HogQL queries.".into(),
            default_name: "posthog".into(),
            credential: Credential {
                about: "a personal API key, scoped to the projects you want reachable".into(),
                url: "https://app.posthog.com/settings/user-api-keys".into(),
            },
            vars: vec![v(
                "region",
                "PostHog cloud region: `us` or `eu`",
                Some("us"),
            )],
            service: Service::Http {
                base_url: "https://{region}.posthog.com".into(),
                auth: AuthTemplate::Bearer,
            },
            access: vec![
                access(
                    "read",
                    "GET the API, plus the HogQL query endpoint, which is a POST",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/api/**"], "allow"),
                        rule(
                            "queries",
                            &["POST"],
                            &["/api/projects/*/query", "/api/projects/*/query/", "/api/environments/*/query/"],
                            "allow",
                        ),
                    ],
                ),
                access(
                    "write",
                    "every method",
                    &[],
                    vec![rule("all", &["*"], &["/api/**"], "allow")],
                ),
            ],
            note: Some(
                "One proxy fronts as many PostHog accounts as you have keys — add the \
                 profile once per account with `--as posthog-<account> --secret <that \
                 account's key>`. Each gets its own rules, its own audit rows and its own \
                 line in `mcp-iap list`, and an agent scoped to one cannot reach the other."
                    .into(),
            ),
        },
        Profile {
            id: "posthog-mcp".into(),
            title: "PostHog MCP server".into(),
            vendor: "PostHog".into(),
            summary: "PostHog's hosted MCP server, fronted with a personal API key.".into(),
            default_name: "posthog-mcp".into(),
            credential: Credential {
                about: "a personal API key — the MCP server takes it as a bearer token".into(),
                url: "https://app.posthog.com/settings/user-api-keys".into(),
            },
            vars: vec![],
            service: Service::McpHttp {
                url: "https://mcp.posthog.com/mcp".into(),
                auth: AuthTemplate::Bearer,
            },
            access: vec![
                access(
                    "read",
                    "read-shaped tools; everything else prompts",
                    &[],
                    vec![
                        // PostHog names over a thousand tools by verb, and the
                        // read verbs are a closed set: `-get`, `-list`,
                        // `-retrieve`, `-search`, `query-`. Anything outside it
                        // falls to the `ask` rule below rather than being
                        // denied, because a catalog this size will always have
                        // a read this list has not met yet.
                        rule(
                            "reads",
                            &["tools/call"],
                            &[
                                "get-*",
                                "*-get",
                                "*-get-*",
                                "list-*",
                                "*-list",
                                "*-retrieve",
                                "*-search",
                                "*-describe",
                                "query-*",
                                "*-query",
                                "*-stats",
                                "*-count",
                                "*-summary",
                                "*-status",
                                "*-history",
                                "*-logs",
                                "*-reference",
                                "read-*",
                            ],
                            "allow",
                        ),
                        rule("other-tools", &["tools/call"], &["**"], "ask"),
                    ],
                ),
                access(
                    "write",
                    "every tool",
                    &[],
                    vec![rule("tools", &["tools/call"], &["**"], "allow")],
                ),
            ],
            note: Some(
                "PostHog exposes well over a thousand tools, so the `read` level allows the \
                 read verbs and sends everything else to `ask` rather than denying it — an \
                 unrecognised tool prompts instead of failing silently. Watch the audit log \
                 for `ask` rows and turn the ones you want into their own rule. One proxy \
                 fronts several accounts: add the profile once per account with `--as \
                 posthog-<account>` and its own key."
                    .into(),
            ),
        },
        // ---------------- Cloudflare ----------------
        Profile {
            id: "cloudflare".into(),
            title: "Cloudflare REST API".into(),
            vendor: "Cloudflare".into(),
            summary: "The whole client/v4 surface: DNS, zones, Workers, R2, WAF, Access."
                .into(),
            default_name: "cloudflare".into(),
            credential: Credential {
                about: "an API token, scoped to the zones and permissions you want reachable"
                    .into(),
                url: "https://dash.cloudflare.com/profile/api-tokens".into(),
            },
            vars: vec![],
            service: Service::Http {
                base_url: "https://api.cloudflare.com/client/v4".into(),
                auth: AuthTemplate::Bearer,
            },
            access: vec![
                access(
                    "read",
                    "GET across every service",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/**"], "allow"),
                        // GraphQL analytics is a POST to one path, and it is a read.
                        rule("graphql", &["POST"], &["/graphql"], "allow"),
                    ],
                ),
                access(
                    "write",
                    "every method across every service",
                    &[],
                    vec![rule("all", &["*"], &["/**"], "allow")],
                ),
                access(
                    "ask-writes",
                    "reads allowed, writes prompt, DELETE denied outright",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/**"], "allow"),
                        rule("graphql", &["POST"], &["/graphql"], "allow"),
                        rule("deletes", &["DELETE"], &["/**"], "deny"),
                        rule("writes", &["POST", "PUT", "PATCH"], &["/**"], "ask"),
                    ],
                ),
            ],
            note: Some(
                "This is the profile that gives full coverage of Cloudflare's services: \
                 one base URL and one token reach all of them, and the token's own scopes \
                 are a second limit under the ACL. Cloudflare's MCP servers are separate \
                 profiles (`cloudflare-mcp-*`) and authenticate differently."
                    .into(),
            ),
        },
        // ---------------- DataForSEO ----------------
        Profile {
            id: "dataforseo".into(),
            title: "DataForSEO API".into(),
            vendor: "DataForSEO".into(),
            summary: "SERP, Keywords Data, Backlinks, On-Page and the rest of v3.".into(),
            default_name: "dataforseo".into(),
            credential: Credential {
                about: "the API password that pairs with your API login".into(),
                url: "https://app.dataforseo.com/api-access".into(),
            },
            vars: vec![v("login", "your DataForSEO API login (an email)", None)],
            service: Service::Http {
                base_url: "https://api.dataforseo.com".into(),
                auth: AuthTemplate::Basic {
                    username_var: "login".into(),
                },
            },
            access: vec![
                access(
                    "queued",
                    "task_post / task_get and every GET; the `live` endpoints prompt",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/v3/**"], "allow"),
                        // `live` bills per call at a higher rate than the queued
                        // equivalent, and nothing in method or path shape tells
                        // an agent that. Making it prompt is the whole point of
                        // having an `ask` action.
                        rule("live", &["POST"], &["/v3/**/live/**"], "ask"),
                        rule("tasks", &["POST"], &["/v3/**"], "allow"),
                    ],
                ),
                access(
                    "all",
                    "every endpoint including the live ones, no prompt",
                    &[],
                    vec![rule("all", &["GET", "POST"], &["/v3/**"], "allow")],
                ),
            ],
            note: Some(
                "DataForSEO bills per call and its `live` endpoints cost more than the \
                 queued ones, so the default level makes those prompt. `mcp-iap audit tail \
                 --target dataforseo` is the per-agent spend trail."
                    .into(),
            ),
        },
        Profile {
            id: "dataforseo-mcp".into(),
            title: "DataForSEO MCP server".into(),
            vendor: "DataForSEO".into(),
            summary: "DataForSEO's hosted MCP server, over the same login and password."
                .into(),
            default_name: "dataforseo-mcp".into(),
            credential: Credential {
                about: "the API password that pairs with your API login".into(),
                url: "https://app.dataforseo.com/api-access".into(),
            },
            vars: vec![v("login", "your DataForSEO API login (an email)", None)],
            service: Service::McpHttp {
                url: "https://mcp.dataforseo.com/mcp".into(),
                auth: AuthTemplate::Basic {
                    username_var: "login".into(),
                },
            },
            access: vec![
                access(
                    "read",
                    "every tool, since the API has no mutations — only charges",
                    &[],
                    vec![rule("tools", &["tools/call"], &["**"], "allow")],
                ),
                access(
                    "ask",
                    "prompt for every tool call, because every call bills",
                    &[],
                    vec![rule("tools", &["tools/call"], &["**"], "ask")],
                ),
            ],
            note: None,
        },
        // ---------------- Graylog ----------------
        Profile {
            id: "graylog".into(),
            title: "Graylog REST API".into(),
            vendor: "Graylog".into(),
            summary: "Search messages, and read streams, dashboards and system state."
                .into(),
            default_name: "graylog".into(),
            credential: Credential {
                about: "a REST API access token (User → Edit tokens), *not* your password"
                    .into(),
                url: "https://go2docs.graylog.org/current/setting_up_graylog/rest_api_access_tokens.htm"
                    .into(),
            },
            vars: vec![v(
                "host",
                "your Graylog host and port, e.g. `graylog.example.com:9000`",
                None,
            )],
            service: Service::Http {
                base_url: "https://{host}/api".into(),
                auth: AuthTemplate::BasicSecretUser {
                    // Graylog authenticates `<token>:token`: the token goes in
                    // the user field and the password is this fixed word. It is
                    // documented and public, so it is a `literal:` on purpose —
                    // the credential is the user half, and that stays a
                    // reference.
                    password: "token".into(),
                },
            },
            access: vec![
                access(
                    "read",
                    "search and read; searches are POSTs",
                    &[],
                    vec![
                        rule("reads", &["GET"], &["/**"], "allow"),
                        rule(
                            "searches",
                            &["POST"],
                            &["/views/search", "/views/search/**", "/search/**"],
                            "allow",
                        ),
                    ],
                ),
                access(
                    "write",
                    "every method",
                    &[],
                    vec![rule("all", &["*"], &["/**"], "allow")],
                ),
            ],
            note: Some(
                "Graylog authenticates an access token as basic `<token>:token` — the \
                 credential is the *user* field. This profile puts it in `username_secret`, \
                 so the token stays a reference and the policy file stays committable. \
                 A session token works the same way with `session` as the password."
                    .into(),
            ),
        },
        // ---------------- Common neighbours ----------------
        Profile {
            id: "anthropic".into(),
            title: "Anthropic API".into(),
            vendor: "Anthropic".into(),
            summary: "Messages, batches and models.".into(),
            default_name: "anthropic".into(),
            credential: Credential {
                about: "an API key".into(),
                url: "https://console.anthropic.com/settings/keys".into(),
            },
            vars: vec![],
            service: Service::Http {
                base_url: "https://api.anthropic.com".into(),
                auth: AuthTemplate::Header {
                    header: "x-api-key".into(),
                    prefix: None,
                },
            },
            access: vec![
                access(
                    "inference",
                    "messages and token counting",
                    &[],
                    vec![rule(
                        "messages",
                        &["POST"],
                        &["/v1/messages", "/v1/messages/count_tokens"],
                        "allow",
                    ), rule("models", &["GET"], &["/v1/models", "/v1/models/*"], "allow")],
                ),
                access(
                    "all",
                    "every endpoint",
                    &[],
                    vec![rule("all", &["*"], &["/v1/**"], "allow")],
                ),
            ],
            note: None,
        },
        Profile {
            id: "openai".into(),
            title: "OpenAI API".into(),
            vendor: "OpenAI".into(),
            summary: "Responses, chat completions, embeddings and models.".into(),
            default_name: "openai".into(),
            credential: Credential {
                about: "an API key".into(),
                url: "https://platform.openai.com/api-keys".into(),
            },
            vars: vec![],
            service: Service::Http {
                base_url: "https://api.openai.com".into(),
                auth: AuthTemplate::Bearer,
            },
            access: vec![
                access(
                    "inference",
                    "the endpoints that generate, and nothing that manages the account",
                    &[],
                    vec![
                        rule(
                            "generate",
                            &["POST"],
                            &["/v1/responses", "/v1/chat/completions", "/v1/embeddings"],
                            "allow",
                        ),
                        rule("models", &["GET"], &["/v1/models", "/v1/models/*"], "allow"),
                    ],
                ),
                access(
                    "all",
                    "every endpoint",
                    &[],
                    vec![rule("all", &["*"], &["/v1/**"], "allow")],
                ),
            ],
            note: None,
        },
        bearer_api(BearerApi {
            id: "github",
            title: "GitHub REST API",
            vendor: "GitHub",
            summary: "Repos, issues, pull requests and actions.",
            base_url: "https://api.github.com",
            credential: Credential {
                about: "a fine-grained personal access token".into(),
                url: "https://github.com/settings/personal-access-tokens".into(),
            },
            read_paths: &["/**"],
            write_paths: &["/**"],
        }),
        bearer_api(BearerApi {
            id: "linear",
            title: "Linear API",
            vendor: "Linear",
            summary: "Issues and projects, over GraphQL.",
            base_url: "https://api.linear.app",
            credential: Credential {
                about: "a personal API key".into(),
                url: "https://linear.app/settings/api".into(),
            },
            read_paths: &["/graphql"],
            write_paths: &["/graphql"],
        }),
        bearer_api(BearerApi {
            id: "sentry",
            title: "Sentry API",
            vendor: "Sentry",
            summary: "Issues, events and releases.",
            base_url: "https://sentry.io/api/0",
            credential: Credential {
                about: "an auth token".into(),
                url: "https://sentry.io/settings/account/api/auth-tokens/".into(),
            },
            read_paths: &["/**"],
            write_paths: &["/**"],
        }),
        bearer_api(BearerApi {
            id: "slack",
            title: "Slack Web API",
            vendor: "Slack",
            summary: "Post messages and read channel history.",
            base_url: "https://slack.com/api",
            credential: Credential {
                about: "a bot user OAuth token (`xoxb-…`)".into(),
                url: "https://api.slack.com/apps".into(),
            },
            read_paths: &["/conversations.*", "/users.*", "/team.info"],
            write_paths: &["/**"],
        }),
        bearer_api(BearerApi {
            id: "stripe",
            title: "Stripe API",
            vendor: "Stripe",
            summary: "Customers, subscriptions, invoices and charges.",
            base_url: "https://api.stripe.com",
            credential: Credential {
                about: "a restricted API key — not the live secret key".into(),
                url: "https://dashboard.stripe.com/apikeys".into(),
            },
            read_paths: &["/v1/**"],
            write_paths: &["/v1/**"],
        }),
    ];

    // Cloudflare ships a remote MCP server per product area, and "full coverage"
    // means all of them rather than the two everyone remembers.
    for (slug, host, title, summary) in [
        (
            "api",
            "mcp.cloudflare.com",
            "Cloudflare API MCP",
            "The account-wide API surface as MCP tools.",
        ),
        (
            "docs",
            "docs.mcp.cloudflare.com",
            "Cloudflare Documentation MCP",
            "Search Cloudflare's documentation. No account access.",
        ),
        (
            "bindings",
            "bindings.mcp.cloudflare.com",
            "Workers Bindings MCP",
            "KV, R2, D1 and Durable Object bindings for Workers.",
        ),
        (
            "builds",
            "builds.mcp.cloudflare.com",
            "Workers Builds MCP",
            "Inspect Workers build history and logs.",
        ),
        (
            "observability",
            "observability.mcp.cloudflare.com",
            "Workers Observability MCP",
            "Query Workers logs and analytics.",
        ),
        (
            "radar",
            "radar.mcp.cloudflare.com",
            "Cloudflare Radar MCP",
            "Global internet traffic and routing insights.",
        ),
        (
            "containers",
            "containers.mcp.cloudflare.com",
            "Cloudflare Containers MCP",
            "Run a sandboxed container.",
        ),
        (
            "browser",
            "browser.mcp.cloudflare.com",
            "Browser Rendering MCP",
            "Fetch and render pages in a managed browser.",
        ),
        (
            "logs",
            "logs.mcp.cloudflare.com",
            "Logpush MCP",
            "Manage and inspect Logpush jobs.",
        ),
        (
            "ai-gateway",
            "ai-gateway.mcp.cloudflare.com",
            "AI Gateway MCP",
            "Inspect AI Gateway logs and configuration.",
        ),
        (
            "autorag",
            "autorag.mcp.cloudflare.com",
            "AI Search (AutoRAG) MCP",
            "Query AutoRAG indexes.",
        ),
        (
            "auditlogs",
            "auditlogs.mcp.cloudflare.com",
            "Audit Logs MCP",
            "Read Cloudflare account audit logs.",
        ),
        (
            "dns-analytics",
            "dns-analytics.mcp.cloudflare.com",
            "DNS Analytics MCP",
            "DNS query analytics and reporting.",
        ),
        (
            "dex",
            "dex.mcp.cloudflare.com",
            "Digital Experience Monitoring MCP",
            "Cloudflare One endpoint and network insights.",
        ),
        (
            "casb",
            "casb.mcp.cloudflare.com",
            "Cloudflare One CASB MCP",
            "SaaS security posture findings.",
        ),
        (
            "graphql",
            "graphql.mcp.cloudflare.com",
            "Cloudflare GraphQL MCP",
            "Run GraphQL analytics queries.",
        ),
    ] {
        profiles.push(cloudflare_mcp(slug, host, title, summary));
    }

    profiles.sort_by(|a, b| a.id.cmp(&b.id));
    profiles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_is_internally_consistent() {
        for profile in catalog() {
            assert!(
                !profile.access.is_empty(),
                "{}: no access levels",
                profile.id
            );
            assert!(
                !profile.default_name.is_empty(),
                "{}: no default name",
                profile.id
            );
            for level in &profile.access {
                assert!(
                    !level.rules.is_empty(),
                    "{}/{}: no rules",
                    profile.id,
                    level.name
                );
                for rule in &level.rules {
                    assert!(
                        matches!(rule.action.as_str(), "allow" | "deny" | "ask"),
                        "{}/{}: bad action `{}`",
                        profile.id,
                        level.name,
                        rule.action
                    );
                    assert!(!rule.methods.is_empty() && !rule.paths.is_empty());
                }
            }
        }
    }

    #[test]
    fn profile_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for profile in catalog() {
            assert!(
                seen.insert(profile.id.clone()),
                "duplicate id {}",
                profile.id
            );
        }
    }

    #[test]
    fn google_read_and_write_ask_for_different_scopes() {
        let gsc = get("google-search-console").unwrap();
        let read = gsc.find_access("read").unwrap();
        let write = gsc.find_access("write").unwrap();
        assert!(read.scopes[0].ends_with("webmasters.readonly"));
        assert!(write.scopes[0].ends_with("/webmasters"));
    }

    #[test]
    fn expand_substitutes_vars_and_the_secret() {
        let vars = BTreeMap::from([("host".to_string(), "graylog.example.com".to_string())]);
        assert_eq!(
            expand("https://{host}/api", &vars, "op://x/y/z").unwrap(),
            "https://graylog.example.com/api"
        );
        assert_eq!(expand("{secret}", &vars, "env:TOKEN").unwrap(), "env:TOKEN");
        assert!(expand("{nope}", &vars, "").is_err());
        assert!(expand("{unterminated", &vars, "").is_err());
    }

    #[test]
    fn graylog_puts_the_token_in_the_user_field() {
        let profile = get("graylog").unwrap();
        let vars = BTreeMap::from([("host".to_string(), "g.example.com".to_string())]);
        let service = substitute_service(&profile.service, &vars, "op://P/Graylog/token").unwrap();
        let auth = build_auth(&service, "op://P/Graylog/token", &vars, &[]).unwrap();
        match auth {
            AuthSpec::Basic {
                username,
                username_secret,
                secret,
            } => {
                assert!(username.is_none());
                assert_eq!(username_secret.as_deref(), Some("op://P/Graylog/token"));
                assert_eq!(secret, "literal:token");
            }
            other => panic!("expected basic, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_var_is_rejected_rather_than_ignored() {
        let profile = get("posthog").unwrap();
        let err = resolve_vars(&profile, &["regoin=eu".to_string()]).unwrap_err();
        assert!(err.to_string().contains("no variable `regoin`"));
    }

    #[test]
    fn a_var_without_a_default_must_be_supplied() {
        let profile = get("graylog").unwrap();
        assert!(resolve_vars(&profile, &[]).is_err());
        assert!(resolve_vars(&profile, &["host=g.example.com".to_string()]).is_ok());
    }
}

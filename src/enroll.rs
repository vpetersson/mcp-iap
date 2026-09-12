//! Enrolling agents, upstreams and rules into a policy file from the CLI.
//!
//! `init` used to be the only way to get a usable file, which forced it to
//! guess: it minted a token nobody asked for and wrote an Anthropic upstream
//! that may not be the one you wanted. The alternative was editing TOML by
//! hand, and a policy file is exactly the kind of file where a typo is a
//! security bug rather than a parse error.
//!
//! So these commands append to the file instead. Two properties matter and
//! both are load-bearing:
//!
//! * **Comments survive.** The generated file is mostly comments explaining
//!   what each block does, and a round-trip through `toml::to_string` would
//!   delete every one of them. `toml_edit` keeps the document as written.
//! * **The result is validated before it is saved.** Every edit is applied to
//!   an in-memory document, parsed back through `Config` and run through the
//!   same `validate()` the proxy uses at startup. A rejected edit leaves the
//!   file untouched, so a bad flag can never be the reason the proxy stops
//!   coming up.

use anyhow::{bail, Context, Result};
use std::path::Path;
use toml_edit::{Array, DocumentMut, Item, Table, Value};

use crate::config::Config;
use crate::identity;
use crate::secrets::SecretRef;

/// An agent enrolled into the file, and the token that proves it is that agent.
pub struct EnrolledAgent {
    pub id: String,
    /// Plaintext, existing only here and in the one line that prints it — the
    /// file got the hash.
    pub token: String,
}

/// Redacted for the same reason `init::Initialized` is: a `{:?}` in a test
/// failure or an error chain must not be what spills the token.
impl std::fmt::Debug for EnrolledAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrolledAgent")
            .field("id", &self.id)
            .field("token", &"***")
            .finish()
    }
}

/// How an upstream authenticates, in the shape the CLI accepts it.
#[derive(Debug, Clone)]
pub enum AuthSpec {
    None,
    Bearer {
        secret: String,
    },
    Header {
        header: String,
        secret: String,
        prefix: Option<String>,
    },
    Basic {
        /// A plain user field, or `None` when the user field is itself the
        /// credential and `username_secret` carries the reference.
        username: Option<String>,
        username_secret: Option<String>,
        secret: String,
    },
    Query {
        param: String,
        secret: String,
    },
    /// The two schemes that mint a short-lived token instead of forwarding a
    /// long-lived secret. They were reachable only by hand-editing the file,
    /// which meant the credential the proxy handles best — a Google service
    /// account — was the one the CLI could not enrol.
    Oauth2ClientCredentials {
        token_url: String,
        client_id: String,
        client_secret: String,
        scope: Option<String>,
        audience: Option<String>,
    },
    ServiceAccountJwt {
        key_file: Option<String>,
        issuer: Option<String>,
        private_key: Option<String>,
        key_id: Option<String>,
        token_url: Option<String>,
        audience: Option<String>,
        scopes: Vec<String>,
        subject: Option<String>,
        lifetime_secs: Option<u64>,
    },
}

/// Add `[[agents]]`, minting the token and writing only its hash.
pub fn add_agent(
    path: &Path,
    id: &str,
    name: Option<&str>,
    targets: &[String],
) -> Result<EnrolledAgent> {
    check_id(id, "agent id")?;

    let mut document = read(path)?;
    let existing = document_config(&document)?;
    if existing.agents.iter().any(|agent| agent.id == id) {
        bail!(
            "`{}` already has an agent `{id}` — ids are how a request is attributed, \
             so two of them would make the audit log ambiguous",
            path.display()
        );
    }

    // Targets that name nothing are the failure this command exists to catch:
    // the file stays valid, the agent looks scoped, and every call it makes is
    // denied by a rule that never mentions the target it was pointed at.
    let reachable: Vec<&str> = existing
        .upstreams
        .iter()
        .map(|up| up.name.as_str())
        .chain(
            existing
                .mcp_servers
                .iter()
                .map(|server| server.name.as_str()),
        )
        .collect();
    for target in targets {
        if !reachable.iter().any(|name| *name == target) {
            bail!(
                "no upstream or MCP server named `{target}` in `{}` — add it first with \
                 `mcp-iap upstream add {target} --base-url <url>`, or drop the `--target`",
                path.display()
            );
        }
    }

    let token = identity::generate_token()?;

    let mut entry = Table::new();
    entry["id"] = toml_edit::value(id);
    if let Some(name) = name {
        entry["name"] = toml_edit::value(name);
    }
    entry["token_sha256"] = toml_edit::value(identity::token_hash(&token));
    if !targets.is_empty() {
        entry["targets"] = toml_edit::value(string_array(targets));
    }

    append(&mut document, "agents", entry);
    save(path, document)?;

    Ok(EnrolledAgent {
        id: id.to_string(),
        token,
    })
}

/// Add `[[upstreams]]`: a base URL and the credential to attach on the way out.
pub fn add_upstream(
    path: &Path,
    name: &str,
    base_url: &str,
    auth: &AuthSpec,
    headers: &[(String, String)],
) -> Result<()> {
    check_id(name, "upstream name")?;
    check_base_url(base_url)?;
    check_secret_refs(auth)?;

    let mut document = read(path)?;
    let existing = document_config(&document)?;
    if existing.upstreams.iter().any(|up| up.name == name) {
        bail!("`{}` already has an upstream `{name}`", path.display());
    }
    // The routing prefix is the name, and an MCP server sharing it would make
    // `/{name}/...` ambiguous.
    if existing
        .mcp_servers
        .iter()
        .any(|server| server.name == name)
    {
        bail!(
            "`{}` already has an MCP server named `{name}`, and both are addressed \
             as `/{name}/…`",
            path.display()
        );
    }

    append(
        &mut document,
        "upstreams",
        upstream_entry(name, base_url, auth, headers),
    );
    save(path, document)
}

fn upstream_entry(
    name: &str,
    base_url: &str,
    auth: &AuthSpec,
    headers: &[(String, String)],
) -> Table {
    let mut entry = Table::new();
    entry["name"] = toml_edit::value(name);
    entry["base_url"] = toml_edit::value(base_url);
    entry["auth"] = toml_edit::value(auth_value(auth));
    if !headers.is_empty() {
        let mut table = toml_edit::InlineTable::new();
        for (key, value) in headers {
            table.insert(key, Value::from(value.as_str()));
        }
        entry["headers"] = toml_edit::value(table);
    }
    entry
}

/// An MCP server as the CLI accepts it: a child process to spawn, or a remote
/// endpoint to relay to.
#[derive(Debug, Clone)]
pub enum McpTransportSpec {
    Stdio {
        command: String,
        args: Vec<String>,
        /// Child environment. Values are secret *references*, resolved inside
        /// the proxy — the same rule the rest of the file follows.
        env: Vec<(String, String)>,
        cwd: Option<String>,
    },
    Http {
        url: String,
    },
}

/// Add `[[mcp_servers]]`. Without this an MCP server could only be enrolled by
/// hand-editing TOML, which is the one thing the enrolment commands exist to
/// avoid — and MCP is where most of the interesting credentials now live.
pub fn add_mcp_server(
    path: &Path,
    name: &str,
    transport: &McpTransportSpec,
    auth: &AuthSpec,
) -> Result<()> {
    check_id(name, "mcp server name")?;
    check_secret_refs(auth)?;
    if let McpTransportSpec::Stdio { env, .. } = transport {
        for (key, reference) in env {
            let parsed = SecretRef::parse(reference)
                .with_context(|| format!("`--env {key}=…` takes a credential reference"))?;
            if parsed.is_inline() {
                bail!(
                    "`literal:` puts the credential in the policy file itself — use `op://`, \
                     `env:` or `file:` so the file stays safe to commit"
                );
            }
        }
    }
    if let McpTransportSpec::Http { url } = transport {
        check_base_url(url)?;
    }

    let mut document = read(path)?;
    let existing = document_config(&document)?;
    if existing
        .mcp_servers
        .iter()
        .any(|server| server.name == name)
    {
        bail!("`{}` already has an MCP server `{name}`", path.display());
    }
    // One namespace: `/{name}/…` routes to an upstream, and the ACL `target`
    // and the agent's `targets` are matched against the same set of names.
    if existing.upstreams.iter().any(|up| up.name == name) {
        bail!(
            "`{}` already has an upstream named `{name}`, and both share one namespace",
            path.display()
        );
    }

    append(
        &mut document,
        "mcp_servers",
        mcp_entry(name, transport, auth),
    );
    save(path, document)
}

fn mcp_entry(name: &str, transport: &McpTransportSpec, auth: &AuthSpec) -> Table {
    let mut entry = Table::new();
    entry["name"] = toml_edit::value(name);
    match transport {
        McpTransportSpec::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            entry["transport"] = toml_edit::value("stdio");
            entry["command"] = toml_edit::value(command.as_str());
            if !args.is_empty() {
                entry["args"] = toml_edit::value(string_array(args));
            }
            if !env.is_empty() {
                let mut table = toml_edit::InlineTable::new();
                for (key, reference) in env {
                    table.insert(key, Value::from(reference.as_str()));
                }
                entry["env"] = toml_edit::value(table);
            }
            if let Some(cwd) = cwd {
                entry["cwd"] = toml_edit::value(cwd.as_str());
            }
        }
        McpTransportSpec::Http { url } => {
            entry["transport"] = toml_edit::value("http");
            entry["url"] = toml_edit::value(url.as_str());
        }
    }
    if !matches!(auth, AuthSpec::None) {
        entry["auth"] = toml_edit::value(auth_value(auth));
    }
    entry
}

/// Add `[[acl]]`. Appended last, because first match wins and an earlier rule
/// would silently take precedence over everything already in the file.
#[allow(clippy::too_many_arguments)]
pub fn add_rule(
    path: &Path,
    name: Option<&str>,
    agent: &str,
    kind: &str,
    target: &str,
    methods: &[String],
    paths: &[String],
    action: &str,
) -> Result<()> {
    let mut document = read(path)?;
    let entry = rule_entry(name, agent, kind, target, methods, paths, action);
    append(&mut document, "acl", entry);
    save(path, document)
}

#[allow(clippy::too_many_arguments)]
fn rule_entry(
    name: Option<&str>,
    agent: &str,
    kind: &str,
    target: &str,
    methods: &[String],
    paths: &[String],
    action: &str,
) -> Table {
    let mut entry = Table::new();
    if let Some(name) = name {
        entry["name"] = toml_edit::value(name);
    }
    entry["agent"] = toml_edit::value(agent);
    entry["kind"] = toml_edit::value(kind);
    entry["target"] = toml_edit::value(target);
    entry["methods"] = toml_edit::value(string_array(methods));
    entry["paths"] = toml_edit::value(string_array(paths));
    entry["action"] = toml_edit::value(action);
    entry
}

/// A service to render without writing it, for `profile add --dry-run`.
pub enum ServiceSpec<'a> {
    Upstream {
        base_url: &'a str,
    },
    McpHttp {
        url: &'a str,
    },
    McpStdio {
        command: &'a str,
        args: &'a [String],
        env: &'a [(String, String)],
    },
}

/// The exact TOML `add_upstream` / `add_mcp_server` would append. Built from
/// the same entry builders they use, so a dry run cannot promise one thing and
/// the write produce another.
pub fn render_service(name: &str, spec: ServiceSpec<'_>, auth: &AuthSpec) -> String {
    let (key, entry) = match spec {
        ServiceSpec::Upstream { base_url } => {
            ("upstreams", upstream_entry(name, base_url, auth, &[]))
        }
        ServiceSpec::McpHttp { url } => (
            "mcp_servers",
            mcp_entry(
                name,
                &McpTransportSpec::Http {
                    url: url.to_string(),
                },
                auth,
            ),
        ),
        ServiceSpec::McpStdio { command, args, env } => (
            "mcp_servers",
            mcp_entry(
                name,
                &McpTransportSpec::Stdio {
                    command: command.to_string(),
                    args: args.to_vec(),
                    env: env.to_vec(),
                    cwd: None,
                },
                auth,
            ),
        ),
    };
    render(key, entry)
}

/// The exact TOML `add_rule` would append.
#[allow(clippy::too_many_arguments)]
pub fn render_rule(
    name: Option<&str>,
    agent: &str,
    kind: &str,
    target: &str,
    methods: &[String],
    paths: &[String],
    action: &str,
) -> String {
    render(
        "acl",
        rule_entry(name, agent, kind, target, methods, paths, action),
    )
}

fn render(key: &str, entry: Table) -> String {
    let mut document = DocumentMut::new();
    append(&mut document, key, entry);
    document.to_string()
}

/// Position in the rule list, so the caller can say where a new rule landed —
/// "rule 3 of 3" is the difference between a rule that applies and one that an
/// earlier `deny` already shadowed.
pub fn rule_count(path: &Path) -> Result<usize> {
    Ok(document_config(&read(path)?)?.acl.len())
}

fn read(path: &Path) -> Result<DocumentMut> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading `{}` — `mcp-iap init` writes one if you have not yet",
            path.display()
        )
    })?;
    text.parse::<DocumentMut>()
        .with_context(|| format!("parsing `{}`", path.display()))
}

/// Parse the in-memory document as a `Config`, so an edit is checked against
/// the real schema rather than against what this module believes it wrote.
fn document_config(document: &DocumentMut) -> Result<Config> {
    toml::from_str(&document.to_string()).context("the policy file does not match the schema")
}

fn append(document: &mut DocumentMut, key: &str, entry: Table) {
    let array = document
        .entry(key)
        .or_insert_with(|| Item::ArrayOfTables(Default::default()));
    if let Item::ArrayOfTables(tables) = array {
        tables.push(entry);
    }
}

/// Validate before writing, and write whole: a half-written policy file is a
/// proxy that will not restart.
fn save(path: &Path, document: DocumentMut) -> Result<()> {
    let text = document.to_string();
    let config: Config =
        toml::from_str(&text).context("the edit produced a policy file that does not parse")?;
    config
        .validate()
        .context("the edit produced a policy file the proxy would reject")?;
    std::fs::write(path, text).with_context(|| format!("writing `{}`", path.display()))
}

/// Every credential *reference* the spec carries. All of them are checked, not
/// just the first: `--username-secret op://… --secret literal:token` would
/// otherwise slip a literal past the check that exists to stop exactly that.
fn auth_secrets(auth: &AuthSpec) -> Vec<&str> {
    match auth {
        AuthSpec::None => vec![],
        AuthSpec::Bearer { secret }
        | AuthSpec::Header { secret, .. }
        | AuthSpec::Query { secret, .. } => vec![secret.as_str()],
        AuthSpec::Basic {
            username_secret,
            secret,
            ..
        } => username_secret
            .iter()
            .map(String::as_str)
            .chain(std::iter::once(secret.as_str()))
            .collect(),
        AuthSpec::Oauth2ClientCredentials { client_secret, .. } => vec![client_secret.as_str()],
        AuthSpec::ServiceAccountJwt {
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

/// Reject a credential where a *reference* belongs, before anything is written.
fn check_secret_refs(auth: &AuthSpec) -> Result<()> {
    // `<token>:token` — Graylog, and Graylog's session variant — puts the
    // credential in the user field and a documented constant in the password.
    // That constant is not a secret, and refusing `literal:token` here would
    // leave the scheme expressible only by writing the real token into the
    // file: the exact outcome this check exists to prevent.
    if let AuthSpec::Basic {
        username_secret: Some(reference),
        secret,
        ..
    } = auth
    {
        let parsed = SecretRef::parse(reference)
            .context("`--username-secret` takes a credential *reference*, not the credential")?;
        if parsed.is_inline() {
            bail!(
                "`literal:` in `--username-secret` puts the credential in the policy file \
                 itself — use `op://`, `env:` or `file:`"
            );
        }
        // The password is still parsed, so a bare word is still caught.
        SecretRef::parse(secret)
            .context("`--secret` takes a credential *reference*, not the credential")?;
        return Ok(());
    }

    for reference in auth_secrets(auth) {
        // Catch `--secret ANTHROPIC_API_KEY` — a bare name is not a reference,
        // and left alone it would be resolved as a literal and sent upstream.
        // Deliberately not echoing the value: `--secret sk-live-…` is exactly
        // the mistake this catches, and `SecretRef::parse` redacts it for the
        // same reason. Naming the flag is as much as can be said safely.
        let parsed = SecretRef::parse(reference)
            .context("`--secret` takes a credential *reference*, not the credential")?;
        if parsed.is_inline() {
            // Same refusal `init` makes: the policy file is meant to be
            // committable, and `literal:` is the one thing that would stop it.
            bail!(
                "`literal:` puts the credential in the policy file itself — use `op://`, \
                 `env:` or `file:` so the file stays safe to commit"
            );
        }
    }
    Ok(())
}

fn auth_value(auth: &AuthSpec) -> Value {
    let mut table = toml_edit::InlineTable::new();
    match auth {
        AuthSpec::None => {
            table.insert("type", "none".into());
        }
        AuthSpec::Bearer { secret } => {
            table.insert("type", "bearer".into());
            table.insert("secret", secret.as_str().into());
        }
        AuthSpec::Header {
            header,
            secret,
            prefix,
        } => {
            table.insert("type", "header".into());
            table.insert("header", header.as_str().into());
            table.insert("secret", secret.as_str().into());
            if let Some(prefix) = prefix {
                table.insert("prefix", prefix.as_str().into());
            }
        }
        AuthSpec::Basic {
            username,
            username_secret,
            secret,
        } => {
            table.insert("type", "basic".into());
            if let Some(username) = username {
                table.insert("username", username.as_str().into());
            }
            if let Some(reference) = username_secret {
                table.insert("username_secret", reference.as_str().into());
            }
            table.insert("secret", secret.as_str().into());
        }
        AuthSpec::Query { param, secret } => {
            table.insert("type", "query".into());
            table.insert("param", param.as_str().into());
            table.insert("secret", secret.as_str().into());
        }
        AuthSpec::Oauth2ClientCredentials {
            token_url,
            client_id,
            client_secret,
            scope,
            audience,
        } => {
            table.insert("type", "oauth2_client_credentials".into());
            table.insert("token_url", token_url.as_str().into());
            table.insert("client_id", client_id.as_str().into());
            table.insert("client_secret", client_secret.as_str().into());
            if let Some(scope) = scope {
                table.insert("scope", scope.as_str().into());
            }
            if let Some(audience) = audience {
                table.insert("audience", audience.as_str().into());
            }
        }
        AuthSpec::ServiceAccountJwt {
            key_file,
            issuer,
            private_key,
            key_id,
            token_url,
            audience,
            scopes,
            subject,
            lifetime_secs,
        } => {
            table.insert("type", "service_account_jwt".into());
            if let Some(value) = key_file {
                table.insert("key_file", value.as_str().into());
            }
            if let Some(value) = issuer {
                table.insert("issuer", value.as_str().into());
            }
            if let Some(value) = private_key {
                table.insert("private_key", value.as_str().into());
            }
            if let Some(value) = key_id {
                table.insert("key_id", value.as_str().into());
            }
            if let Some(value) = token_url {
                table.insert("token_url", value.as_str().into());
            }
            if let Some(value) = audience {
                table.insert("audience", value.as_str().into());
            }
            if !scopes.is_empty() {
                table.insert("scopes", Value::Array(string_array(scopes)));
            }
            if let Some(value) = subject {
                table.insert("subject", value.as_str().into());
            }
            if let Some(value) = lifetime_secs {
                table.insert("lifetime_secs", Value::from(*value as i64));
            }
        }
    }
    Value::InlineTable(table)
}

fn string_array(values: &[String]) -> Array {
    values.iter().map(|value| value.as_str()).collect()
}

/// Same rule `init` applies to `--agent`: these names become URL path segments
/// and audit-log fields, and anything exotic here is a problem somewhere else.
fn check_id(id: &str, what: &str) -> Result<()> {
    if id.is_empty() {
        bail!("{what} must not be empty");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("{what} `{id}` must be ASCII letters, digits, `-`, `_` or `.`");
    }
    Ok(())
}

fn check_base_url(url: &str) -> Result<()> {
    let parsed = url
        .parse::<http::Uri>()
        .with_context(|| format!("`{url}` is not a valid base URL"))?;
    match parsed.scheme_str() {
        Some("http") | Some("https") => {}
        Some(scheme) => bail!("base URL scheme `{scheme}` is not supported — use http or https"),
        None => bail!("base URL `{url}` needs a scheme, e.g. `https://{url}`"),
    }
    if parsed.authority().is_none() {
        bail!("base URL `{url}` has no host");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::{self, InitOptions, Template};

    /// A fresh minimal policy file — the state an operator is actually in when
    /// they reach for these commands.
    fn empty_policy() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        init::init(&InitOptions {
            path: path.clone(),
            template: Template::Minimal,
            ..Default::default()
        })
        .unwrap();
        (dir, path)
    }

    fn load(path: &Path) -> Config {
        toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    /// The whole point of the change: `init` then three commands, no editor.
    #[test]
    fn a_proxy_can_be_built_from_nothing_without_touching_the_file() {
        let (_dir, path) = empty_policy();

        add_upstream(
            &path,
            "anthropic",
            "https://api.anthropic.com",
            &AuthSpec::Header {
                header: "x-api-key".into(),
                secret: "env:ANTHROPIC_API_KEY".into(),
                prefix: None,
            },
            &[("anthropic-version".into(), "2023-06-01".into())],
        )
        .unwrap();
        add_rule(
            &path,
            Some("inference"),
            "*",
            "http",
            "anthropic",
            &["POST".to_string()],
            &["/v1/messages".to_string()],
            "allow",
        )
        .unwrap();
        let agent = add_agent(&path, "claude-code", None, &["anthropic".to_string()]).unwrap();

        let config = load(&path);
        config
            .validate()
            .expect("the assembled file must start a proxy");
        assert_eq!(config.upstreams.len(), 1);
        assert_eq!(config.acl.len(), 1);
        assert_eq!(config.agents.len(), 1);
        assert_eq!(config.agents[0].targets, vec!["anthropic".to_string()]);
        assert_eq!(
            config.agents[0].token_sha256.as_deref(),
            Some(identity::token_hash(&agent.token).as_str()),
            "the file gets the hash, the operator gets the token"
        );
    }

    /// The file is mostly comments explaining itself; a round-trip that ate
    /// them would make every later edit harder than the one it saved.
    #[test]
    fn editing_preserves_the_comments_the_template_wrote() {
        let (_dir, path) = empty_policy();
        let before = std::fs::read_to_string(&path).unwrap();
        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        let after = std::fs::read_to_string(&path).unwrap();

        for line in before.lines().filter(|l| l.starts_with('#')) {
            assert!(after.contains(line), "comment was dropped: {line}");
        }
    }

    /// Plaintext must never reach the file, and `Debug` must not be the hole.
    #[test]
    fn the_token_is_never_written_and_never_printed_by_debug() {
        let (_dir, path) = empty_policy();
        let agent = add_agent(&path, "ci", None, &[]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&agent.token));
        assert!(text.contains(&identity::token_hash(&agent.token)));
        assert!(!format!("{agent:?}").contains(&agent.token));
    }

    #[test]
    fn a_duplicate_agent_id_is_refused() {
        let (_dir, path) = empty_policy();
        add_agent(&path, "ci", None, &[]).unwrap();
        let error = add_agent(&path, "ci", None, &[]).unwrap_err().to_string();
        assert!(error.contains("already has an agent"), "{error}");
    }

    /// `--target` naming nothing reads like a grant and denies every call, so
    /// it is refused at the point it is typed rather than discovered in a log.
    #[test]
    fn a_target_that_names_nothing_is_refused() {
        let (_dir, path) = empty_policy();
        let error = add_agent(&path, "ci", None, &["githbu".to_string()])
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no upstream or MCP server named `githbu`"),
            "{error}"
        );
        assert!(
            load(&path).agents.is_empty(),
            "a refused edit must not half-apply"
        );
    }

    /// `--secret ANTHROPIC_API_KEY` instead of `--secret env:ANTHROPIC_API_KEY`
    /// would otherwise be stored and sent upstream as the literal string.
    #[test]
    fn a_bare_name_is_not_accepted_as_a_credential_reference() {
        let (_dir, path) = empty_policy();
        let error = add_upstream(
            &path,
            "anthropic",
            "https://api.anthropic.com",
            &AuthSpec::Bearer {
                secret: "ANTHROPIC_API_KEY".into(),
            },
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("credential *reference*"), "{error}");
    }

    /// The error that reports a bad `--secret` must not be the thing that
    /// prints the credential someone passed by mistake.
    #[test]
    fn a_mistyped_secret_is_not_echoed_back_in_the_error() {
        let (_dir, path) = empty_policy();
        let error = format!(
            "{:#}",
            add_upstream(
                &path,
                "stripe",
                "https://api.stripe.com",
                &AuthSpec::Bearer {
                    secret: "sk-live-REALKEY123".into(),
                },
                &[],
            )
            .unwrap_err()
        );
        assert!(
            !error.contains("sk-live-REALKEY123"),
            "the error leaked the credential: {error}"
        );
    }

    #[test]
    fn a_literal_credential_is_refused_as_it_is_by_init() {
        let (_dir, path) = empty_policy();
        let error = add_upstream(
            &path,
            "anthropic",
            "https://api.anthropic.com",
            &AuthSpec::Bearer {
                secret: "literal:sk-real-key".into(),
            },
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("literal:"), "{error}");
        assert!(!error.contains("sk-real-key"), "the error must not echo it");
    }

    #[test]
    fn a_base_url_without_a_scheme_is_refused() {
        let (_dir, path) = empty_policy();
        let error = add_upstream(&path, "gh", "api.github.com", &AuthSpec::None, &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("scheme"), "{error}");
    }

    /// First match wins, so a rule appended last cannot change what an existing
    /// rule already decides. Inserting would have made this silently possible.
    #[test]
    fn rules_are_appended_so_existing_ones_keep_precedence() {
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        add_rule(
            &path,
            Some("first"),
            "*",
            "http",
            "github",
            &["GET".into()],
            &["/**".into()],
            "deny",
        )
        .unwrap();
        add_rule(
            &path,
            Some("second"),
            "*",
            "http",
            "github",
            &["GET".into()],
            &["/**".into()],
            "allow",
        )
        .unwrap();

        let config = load(&path);
        assert_eq!(config.acl[0].name.as_deref(), Some("first"));
        assert_eq!(config.acl[1].name.as_deref(), Some("second"));
        assert_eq!(rule_count(&path).unwrap(), 2);
    }

    /// An upstream and an MCP server are both addressed as `/<name>/…`.
    #[test]
    fn a_name_already_taken_by_an_mcp_server_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        init::init(&InitOptions {
            path: path.clone(),
            template: Template::Full,
            ..Default::default()
        })
        .unwrap();
        let taken = load(&path).mcp_servers[0].name.clone();

        let error = add_upstream(&path, &taken, "https://example.com", &AuthSpec::None, &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("MCP server"), "{error}");
    }

    #[test]
    fn a_service_account_can_be_enrolled_without_editing_the_file() {
        // The scheme the proxy handles best used to be the one the CLI could
        // not express, so a Google upstream meant hand-writing TOML.
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "gsc",
            "https://searchconsole.googleapis.com",
            &AuthSpec::ServiceAccountJwt {
                key_file: Some("op://Private/GCP/credential".into()),
                issuer: None,
                private_key: None,
                key_id: None,
                token_url: None,
                audience: None,
                scopes: vec!["https://www.googleapis.com/auth/webmasters.readonly".into()],
                subject: Some("person@example.com".into()),
                lifetime_secs: None,
            },
            &[],
        )
        .unwrap();

        let config = load(&path);
        config.validate().unwrap();
        match &config.upstreams[0].auth {
            crate::config::AuthConfig::ServiceAccountJwt {
                key_file,
                scopes,
                subject,
                ..
            } => {
                assert_eq!(key_file.as_deref(), Some("op://Private/GCP/credential"));
                assert_eq!(scopes.len(), 1);
                assert_eq!(subject.as_deref(), Some("person@example.com"));
            }
            other => panic!("expected a service account, got {other:?}"),
        }
    }

    #[test]
    fn an_mcp_server_can_be_enrolled_without_editing_the_file() {
        let (_dir, path) = empty_policy();
        add_mcp_server(
            &path,
            "posthog",
            &McpTransportSpec::Http {
                url: "https://mcp.posthog.com/mcp".into(),
            },
            &AuthSpec::Bearer {
                secret: "op://Private/PostHog/key".into(),
            },
        )
        .unwrap();
        add_mcp_server(
            &path,
            "local-notes",
            &McpTransportSpec::Stdio {
                command: "notes-mcp".into(),
                args: vec!["--stdio".into()],
                env: vec![("NOTES_TOKEN".into(), "env:NOTES_TOKEN".into())],
                cwd: None,
            },
            &AuthSpec::None,
        )
        .unwrap();

        let config = load(&path);
        config.validate().unwrap();
        assert_eq!(config.mcp_servers.len(), 2);
        assert_eq!(
            config.mcp_servers[0].url.as_deref(),
            Some("https://mcp.posthog.com/mcp")
        );
        assert_eq!(
            config.mcp_servers[1]
                .env
                .get("NOTES_TOKEN")
                .map(String::as_str),
            Some("env:NOTES_TOKEN")
        );
    }

    #[test]
    fn an_mcp_name_already_taken_by_an_upstream_is_refused() {
        // Both are addressed as `/{name}/…` and both are matched by the same
        // ACL `target`, so the collision is not cosmetic.
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        let error = add_mcp_server(
            &path,
            "github",
            &McpTransportSpec::Http {
                url: "https://example.com/mcp".into(),
            },
            &AuthSpec::None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("upstream"), "{error}");
    }

    #[test]
    fn a_credential_in_an_mcp_child_environment_must_be_a_reference() {
        let (_dir, path) = empty_policy();
        let error = add_mcp_server(
            &path,
            "leaky",
            &McpTransportSpec::Stdio {
                command: "server".into(),
                args: vec![],
                env: vec![("TOKEN".into(), "literal:ghp_realtoken".into())],
                cwd: None,
            },
            &AuthSpec::None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("literal:"), "{error}");
        assert!(
            !error.contains("ghp_realtoken"),
            "the error echoed the credential: {error}"
        );
    }

    #[test]
    fn basic_auth_can_put_the_credential_in_the_user_field() {
        // Graylog's `<token>:token`. The token stays a reference; the password
        // is a documented constant and is allowed to be a literal.
        let (_dir, path) = empty_policy();
        add_upstream(
            &path,
            "graylog",
            "https://graylog.example.com/api",
            &AuthSpec::Basic {
                username: None,
                username_secret: Some("op://Private/Graylog/token".into()),
                secret: "literal:token".into(),
            },
            &[],
        )
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("username_secret = \"op://Private/Graylog/token\""));
        load(&path).validate().unwrap();
    }

    #[test]
    fn a_literal_in_the_user_field_is_still_refused() {
        // The exception is narrow: the *password* may be a scheme constant.
        // The user field is where the credential actually is.
        let (_dir, path) = empty_policy();
        let error = add_upstream(
            &path,
            "graylog",
            "https://graylog.example.com/api",
            &AuthSpec::Basic {
                username: None,
                username_secret: Some("literal:the-real-token".into()),
                secret: "literal:token".into(),
            },
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("--username-secret"), "{error}");
        assert!(!error.contains("the-real-token"), "{error}");
    }

    #[test]
    fn basic_auth_with_neither_user_field_is_rejected_by_validate() {
        let (_dir, path) = empty_policy();
        let error = add_upstream(
            &path,
            "broken",
            "https://example.com",
            &AuthSpec::Basic {
                username: None,
                username_secret: None,
                secret: "env:PASSWORD".into(),
            },
            &[],
        )
        .unwrap_err();
        // The refusal comes from `validate()`, so it is in the cause chain
        // rather than the top-level "the edit produced a policy file…".
        let error = format!("{error:#}");
        assert!(error.contains("username"), "{error}");
    }

    #[test]
    fn the_dry_run_renderer_matches_what_would_be_written() {
        // If these drift, `--dry-run` becomes a promise the write does not keep.
        let (_dir, path) = empty_policy();
        let auth = AuthSpec::Bearer {
            secret: "env:TOKEN".into(),
        };
        let rendered = render_service(
            "svc",
            ServiceSpec::Upstream {
                base_url: "https://x.example.com",
            },
            &auth,
        );
        add_upstream(&path, "svc", "https://x.example.com", &auth, &[]).unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        for line in rendered.lines().filter(|line| !line.trim().is_empty()) {
            assert!(
                written.contains(line),
                "`--dry-run` printed a line the write did not produce: {line}"
            );
        }
    }

    /// TLS is configured by hand in `[server.tls]`; enrolment is done by these
    /// commands. A rewrite that dropped the block would take the proxy off
    /// HTTPS as a side effect of adding an agent.
    #[test]
    fn enrolling_does_not_disturb_a_tls_block() {
        let (_dir, path) = empty_policy();
        let text = std::fs::read_to_string(&path).unwrap();
        let text = text.replace(
            "[audit]",
            "[server.tls]\ncert = \"file:/etc/mcp-iap/fullchain.pem\"\nkey = \"file:/etc/mcp-iap/key.pem\"\n\n[audit]",
        );
        std::fs::write(&path, &text).unwrap();

        add_upstream(
            &path,
            "github",
            "https://api.github.com",
            &AuthSpec::None,
            &[],
        )
        .unwrap();
        add_rule(
            &path,
            None,
            "*",
            "http",
            "github",
            &["GET".into()],
            &["/**".into()],
            "allow",
        )
        .unwrap();
        add_agent(&path, "ci", None, &["github".to_string()]).unwrap();

        let config = load(&path);
        let tls = config
            .server
            .tls
            .expect("`[server.tls]` must survive enrolment");
        assert_eq!(tls.cert, "file:/etc/mcp-iap/fullchain.pem");
        assert_eq!(tls.key, "file:/etc/mcp-iap/key.pem");
    }
}

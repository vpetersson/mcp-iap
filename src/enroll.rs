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
        username: String,
        secret: String,
    },
    Query {
        param: String,
        secret: String,
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
    if let Some(reference) = auth_secret(auth) {
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

    append(&mut document, "upstreams", entry);
    save(path, document)
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

    append(&mut document, "acl", entry);
    save(path, document)
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

fn auth_secret(auth: &AuthSpec) -> Option<&str> {
    match auth {
        AuthSpec::None => None,
        AuthSpec::Bearer { secret }
        | AuthSpec::Header { secret, .. }
        | AuthSpec::Basic { secret, .. }
        | AuthSpec::Query { secret, .. } => Some(secret),
    }
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
        AuthSpec::Basic { username, secret } => {
            table.insert("type", "basic".into());
            table.insert("username", username.as_str().into());
            table.insert("secret", secret.as_str().into());
        }
        AuthSpec::Query { param, secret } => {
            table.insert("type", "query".into());
            table.insert("param", param.as_str().into());
            table.insert("secret", secret.as_str().into());
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

//! `mcp-iap init` — write a policy file that is ready to run.
//!
//! The alternative was `cp iap.example.toml iap.toml && $EDITOR iap.toml`, which
//! has two problems: it needs the repository checked out (a `cargo install`d
//! binary has no example beside it), and it leaves the one field you cannot
//! guess — the agent's token hash — as a placeholder you have to paste in from a
//! second command. `init` mints the token itself and writes the hash in place,
//! so the file it produces starts a proxy rather than failing validation.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::identity;
use crate::secrets::SecretRef;

/// The fully annotated example, embedded so the binary carries it without the
/// repository. `--template full` writes this instead of the starter.
const EXAMPLE: &str = include_str!("../iap.example.toml");

/// The placeholder the example ships in place of a token hash. Left invalid on
/// purpose so an unedited copy refuses to start; `init` substitutes it.
const EXAMPLE_TOKEN_PLACEHOLDER: &str = "REPLACE_ME_WITH_THE_OUTPUT_OF_gen-token";

/// The agent id the example uses throughout, in `[[agents]]` and in every rule.
const EXAMPLE_AGENT_ID: &str = "claude-code";

/// The example's display name for that agent, which `--agent` has to move too
/// or the console labels the new agent with the old one's name.
const EXAMPLE_AGENT_NAME: &str = "Claude Code";

pub const DEFAULT_AGENT_ID: &str = "claude-code";
pub const DEFAULT_SECRET_REF: &str = "env:ANTHROPIC_API_KEY";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Template {
    /// One agent, one upstream, one rule, default deny.
    #[default]
    Starter,
    /// The shipped example: GitHub, an MCP server and a service account too.
    Full,
}

#[derive(Debug, Clone)]
pub struct InitOptions {
    pub path: PathBuf,
    pub agent: String,
    /// Credential reference for the starter upstream. `Full` brings its own.
    pub secret: Option<String>,
    pub template: Template,
    /// Overwrite an existing file. Doing so mints a new token, which retires
    /// the old one.
    pub force: bool,
}

impl Default for InitOptions {
    fn default() -> Self {
        InitOptions {
            path: PathBuf::from("iap.toml"),
            agent: DEFAULT_AGENT_ID.to_string(),
            secret: None,
            template: Template::Starter,
            force: false,
        }
    }
}

/// What `init` wrote, so the caller can tell the operator what to do next.
pub struct Initialized {
    pub path: PathBuf,
    /// The agent's token in plaintext. This is the only time it exists — only
    /// its hash was written to the file.
    pub token: String,
    pub agent: String,
    /// Credential reference in the written file, when the template has exactly
    /// one to point at.
    pub secret: Option<String>,
    /// Where the file says the proxy will listen, for the agent's base URL.
    pub listen: std::net::SocketAddr,
}

/// Redacting, so that a stray `{:?}` — in a test failure, a log line, an error
/// chain — can never be the thing that spills the token this struct exists to
/// carry to exactly one `println!`.
impl std::fmt::Debug for Initialized {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initialized")
            .field("path", &self.path)
            .field("token", &"***")
            .field("agent", &self.agent)
            .field("secret", &self.secret)
            .field("listen", &self.listen)
            .finish()
    }
}

pub fn init(options: &InitOptions) -> Result<Initialized> {
    check_agent_id(&options.agent)?;
    let secret = match (options.template, options.secret.as_deref()) {
        (Template::Full, Some(_)) => bail!(
            "`--secret` applies to the starter template; the full template ships its own \
             credential references for several upstreams"
        ),
        (Template::Full, None) => None,
        (Template::Starter, reference) => {
            let reference = reference.unwrap_or(DEFAULT_SECRET_REF);
            check_secret_ref(reference)?;
            Some(reference.to_string())
        }
    };

    let token = identity::generate_token()?;
    let text = render(
        options.template,
        &options.agent,
        &identity::token_hash(&token),
        secret.as_deref(),
    );

    // Parse back what we are about to write rather than trusting the template:
    // a policy file that does not load is worse than no file at all, because it
    // is the thing the operator will now edit.
    let config: Config = toml::from_str(&text)
        .context("the generated policy file did not parse — this is a bug in `init`")?;
    config
        .validate()
        .context("the generated policy file did not validate — this is a bug in `init`")?;

    write_new(&options.path, &text, options.force)?;

    Ok(Initialized {
        path: options.path.clone(),
        token,
        agent: options.agent.clone(),
        secret,
        listen: config.server.listen,
    })
}

/// Create the file, refusing to clobber unless asked.
///
/// `create_new` does the existence check and the create in one syscall, so two
/// `init`s racing in the same directory cannot both decide the path was free
/// and have the second silently replace the first's token.
fn write_new(path: &Path, text: &str, force: bool) -> Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating `{}`", parent.display()))?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if force {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }

    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "`{}` already exists — pass `--force` to replace it, which mints a new \
                 agent token and retires the current one",
                path.display()
            )
        } else {
            anyhow::Error::new(error).context(format!("creating `{}`", path.display()))
        }
    })?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("writing `{}`", path.display()))?;
    Ok(())
}

fn render(template: Template, agent: &str, token_hash: &str, secret: Option<&str>) -> String {
    match template {
        Template::Starter => starter(agent, token_hash, secret.unwrap_or(DEFAULT_SECRET_REF)),
        Template::Full => EXAMPLE
            .replace(EXAMPLE_TOKEN_PLACEHOLDER, token_hash)
            .replace(EXAMPLE_AGENT_ID, agent)
            .replace(EXAMPLE_AGENT_NAME, agent),
    }
}

fn starter(agent: &str, token_hash: &str, secret: &str) -> String {
    format!(
        r##"# mcp-iap policy file, written by `mcp-iap init`.
#
# Nothing here is a credential — only a *reference* to one, resolved inside the
# proxy at startup, and the sha256 of a token that is not any upstream's. This
# file is safe to commit.
#
# `mcp-iap init --template full` writes the annotated example instead, with
# GitHub, an MCP server and a Google service account already worked out.

[server]
listen = "127.0.0.1:8080"        # where agents connect
admin_listen = "127.0.0.1:8081"  # control plane: the TUI and the MCP bridge
approval_timeout_secs = 120      # an unanswered `ask` denies after this

[audit]
path = "audit/iap-audit.jsonl"
stderr = true
log_bodies = false               # bodies carry prompts and customer data

# --- who may connect -------------------------------------------------------
# `init` minted the token this hashes and printed it once. Only the hash lives
# here, so this line grants nothing on its own. `mcp-iap gen-token <id>` mints
# another agent the same way.

[[agents]]
id = "{agent}"
token_sha256 = "{token_hash}"
targets = ["anthropic"]

# --- what it may reach -----------------------------------------------------
# The agent calls http://127.0.0.1:8080/anthropic/<path>; the proxy strips the
# prefix and attaches the real credential on the way out.

[[upstreams]]
name = "anthropic"
base_url = "https://api.anthropic.com"
auth = {{ type = "header", header = "x-api-key", secret = "{secret}" }}
headers = {{ "anthropic-version" = "2023-06-01" }}

# Other schemes, for the upstreams you add next:
#   auth = {{ type = "bearer", secret = "op://Private/GitHub/token" }}
#   auth = {{ type = "basic", username = "user", secret = "env:PASSWORD" }}
#   auth = {{ type = "query", param = "key", secret = "file:/run/secrets/key" }}
#   auth = {{ type = "none" }}

# --- policy ----------------------------------------------------------------
# First matching rule wins. Anything unmatched falls through to acl_default,
# so an upstream with no rule is an upstream the agent cannot reach.
# `action` is "allow", "deny" or "ask" — "ask" prompts a human in `run --tui`.

[[acl]]
name = "anthropic-inference"
agent = "{agent}"
kind = "http"
target = "anthropic"
methods = ["POST"]
paths = ["/v1/messages", "/v1/messages/count_tokens"]
action = "allow"

[acl_default]
action = "deny"
"##
    )
}

/// Keep the id to characters that are safe to drop into TOML unquoted-ish and
/// read back in a log line. This is also what makes the templates' plain
/// `id = "{{agent}}"` interpolation safe: a quote or a newline here would
/// otherwise let `--agent` write arbitrary policy.
fn check_agent_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("agent id must not be empty");
    }
    if id.len() > 64 {
        bail!("agent id must be 64 characters or fewer");
    }
    if let Some(bad) = id
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !matches!(c, '-' | '_' | '.'))
    {
        bail!("agent id may only contain letters, digits, `-`, `_` and `.` (got `{bad}`)");
    }
    Ok(())
}

fn check_secret_ref(reference: &str) -> Result<()> {
    let parsed = SecretRef::parse(reference)?;
    if parsed.is_inline() {
        // `literal:` would put the credential in a file this template's own
        // header calls safe to commit. Config only warns about that; refusing
        // to write one in the first place is cheaper than noticing later.
        bail!(
            "`literal:` puts the credential in the policy file itself — use `op://`, `env:` \
             or `file:` so the file stays safe to commit"
        );
    }
    if reference
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\\'))
    {
        bail!("secret reference must not contain quotes, backslashes or control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::Acl;
    use crate::config::Action;

    fn load(text: &str) -> Config {
        let config: Config = toml::from_str(text).expect("generated config must parse");
        config.validate().expect("generated config must validate");
        config
    }

    /// The point of `init`: what it writes starts a proxy, with no editing.
    #[test]
    fn the_starter_is_usable_exactly_as_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        let written = init(&InitOptions {
            path: path.clone(),
            ..Default::default()
        })
        .unwrap();

        let config = load(&std::fs::read_to_string(&path).unwrap());
        let agent = config.agent(DEFAULT_AGENT_ID).expect("agent is written");

        // The hash in the file is the hash of the token we printed, so the
        // agent can authenticate with it and nothing else can.
        assert_eq!(
            agent.token_sha256.as_deref(),
            Some(identity::token_hash(&written.token).as_str())
        );
        assert!(written.token.starts_with("iap_"));
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains(&written.token),
            "the plaintext token must never reach the file"
        );

        // Default deny plus a rule for every target the agent is granted —
        // otherwise the file advertises an upstream it silently refuses.
        assert_eq!(config.acl_default.action, Action::Deny);
        let acl = Acl::compile(&config).unwrap();
        for target in &agent.targets {
            assert!(
                config.upstream(target).is_some() || config.mcp_server(target).is_some(),
                "`{target}` is not configured"
            );
            assert!(
                acl.rules_mentioning(target) > 0,
                "`{target}` is granted but no rule mentions it"
            );
        }
    }

    #[test]
    fn the_full_template_is_the_shipped_example_with_the_token_filled_in() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        let written = init(&InitOptions {
            path: path.clone(),
            template: Template::Full,
            ..Default::default()
        })
        .unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(EXAMPLE_TOKEN_PLACEHOLDER),
            "the placeholder must be substituted, or the file will not start"
        );
        let config = load(&text);
        assert_eq!(
            config
                .agent(DEFAULT_AGENT_ID)
                .and_then(|a| a.token_sha256.as_deref()),
            Some(identity::token_hash(&written.token).as_str())
        );
        assert!(
            config.mcp_servers.iter().any(|s| s.name == "github-mcp"),
            "the full template should carry the example's MCP server"
        );
    }

    /// `--agent` has to reach every place the template names the agent, or the
    /// rules apply to an id that no longer exists and everything denies.
    #[test]
    fn a_custom_agent_id_replaces_every_occurrence_in_both_templates() {
        for template in [Template::Starter, Template::Full] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("iap.toml");
            init(&InitOptions {
                path: path.clone(),
                agent: "codex".into(),
                secret: None,
                template,
                force: false,
            })
            .unwrap();

            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains(EXAMPLE_AGENT_ID),
                "{template:?}: the default id must not survive `--agent`"
            );
            let config = load(&text);
            assert!(config.agent("codex").is_some(), "{template:?}");
            assert!(
                config.acl.iter().any(|r| r.agent == "codex"),
                "{template:?}: no rule names the agent it just wrote"
            );
        }
    }

    #[test]
    fn an_existing_file_is_not_clobbered_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        let options = InitOptions {
            path: path.clone(),
            ..Default::default()
        };
        let first = init(&options).unwrap();

        let error = init(&options).unwrap_err().to_string();
        assert!(error.contains("--force"), "{error}");
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains(&identity::token_hash(&first.token)),
            "the refused run must leave the original token in place"
        );

        let second = init(&InitOptions {
            force: true,
            ..options
        })
        .unwrap();
        assert_ne!(
            first.token, second.token,
            "replacing the file must mint a new token"
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&identity::token_hash(&second.token)));
        assert!(
            !text.contains(&identity::token_hash(&first.token)),
            "the replaced token must not still authenticate"
        );
    }

    #[test]
    fn the_secret_reference_is_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        init(&InitOptions {
            path: path.clone(),
            secret: Some("op://Private/Anthropic API/credential".into()),
            ..Default::default()
        })
        .unwrap();

        let config = load(&std::fs::read_to_string(&path).unwrap());
        assert_eq!(
            config.secret_refs(),
            vec!["op://Private/Anthropic API/credential"]
        );
    }

    #[test]
    fn a_hostile_agent_id_cannot_write_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iap.toml");
        for id in [
            "",
            "a\"\nname = \"x",
            "has space",
            "back\\slash",
            &"x".repeat(65),
        ] {
            assert!(
                init(&InitOptions {
                    path: path.clone(),
                    agent: id.to_string(),
                    ..Default::default()
                })
                .is_err(),
                "`{id}` should be rejected"
            );
        }
        assert!(
            !path.exists(),
            "a rejected run must not leave a file behind"
        );
    }

    #[test]
    fn a_credential_is_never_written_into_the_policy_file() {
        let dir = tempfile::tempdir().unwrap();
        let error = init(&InitOptions {
            path: dir.path().join("iap.toml"),
            secret: Some("literal:sk-real-key".into()),
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("literal:"), "{error}");
        assert!(!error.contains("sk-real-key"), "{error}");
    }

    #[test]
    fn the_full_template_refuses_a_secret_that_would_be_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let error = init(&InitOptions {
            path: dir.path().join("iap.toml"),
            secret: Some("env:ANTHROPIC_API_KEY".into()),
            template: Template::Full,
            ..Default::default()
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("--secret"), "{error}");
    }

    #[test]
    fn a_missing_parent_directory_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("etc").join("iap.toml");
        init(&InitOptions {
            path: path.clone(),
            ..Default::default()
        })
        .unwrap();
        assert!(path.exists());
    }
}

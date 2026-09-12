use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mcp_iap::audit;
use mcp_iap::config::Config;
use mcp_iap::enroll;
use mcp_iap::identity;
use mcp_iap::init::{self, InitOptions, Template};
use mcp_iap::list::{Inventory, ListOptions, What};
use mcp_iap::mcp;
use mcp_iap::state::AppState;

#[derive(Parser)]
#[command(
    name = "mcp-iap",
    version,
    about = "Identity-aware proxy for LLM agents — authenticated, ACL-gated, audited access to APIs and MCP servers without handing over the credential."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct ConfigArg {
    /// Path to the TOML policy file.
    #[arg(
        short,
        long,
        default_value = "iap.toml",
        env = "IAP_CONFIG",
        global = true
    )]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Write a policy file the proxy will start with.
    Init {
        #[command(flatten)]
        config: ConfigArg,
        /// Id of the agent to mint a token for.
        #[arg(long, default_value = init::DEFAULT_AGENT_ID)]
        agent: String,
        /// Credential reference for the starter upstream: `env:NAME`,
        /// `file:/path` or `op://vault/item/field`. Starter template only.
        #[arg(long, value_name = "REF")]
        secret: Option<String>,
        /// `minimal` is the proxy and nothing else; `starter` adds one agent
        /// and one Anthropic upstream; `full` is the annotated example, with
        /// GitHub, MCP and a service account worked out.
        #[arg(long, value_enum, default_value_t = TemplateArg::Minimal)]
        template: TemplateArg,
        /// Replace an existing file. Mints a new token, retiring the old one.
        #[arg(short, long)]
        force: bool,
    },
    /// Run the proxy.
    Run {
        #[command(flatten)]
        config: ConfigArg,
        /// Where agents connect: `HOST:PORT`, or a bare port to keep the
        /// interface the config file chose. Overrides `server.listen`.
        #[arg(long, value_name = "ADDR", env = "IAP_LISTEN")]
        listen: Option<String>,
        /// Where the control plane listens, or `off` to disable it. Overrides
        /// `server.admin_listen`.
        #[arg(long, value_name = "ADDR", env = "IAP_ADMIN_LISTEN")]
        admin_listen: Option<String>,
        /// Open the interactive approval console.
        #[arg(long)]
        tui: bool,
    },
    /// Bridge one MCP server for an agent. Requires a running `mcp-iap run`.
    Mcp {
        #[command(flatten)]
        config: ConfigArg,
        /// Name of the `[[mcp_servers]]` entry to front.
        #[arg(short, long)]
        server: String,
        /// The agent's IAP token.
        #[arg(long, env = "IAP_TOKEN", hide_env_values = true)]
        token: String,
        /// Control-plane address of the running proxy.
        #[arg(long, env = "IAP_ADMIN_URL")]
        admin_url: Option<String>,
    },
    /// Show every service this proxy exposes: agents, upstreams, MCP servers, ACL.
    List {
        #[command(flatten)]
        config: ConfigArg,
        /// Limit the view to one section. Omit for all of them.
        #[arg(value_enum)]
        what: Option<WhatArg>,
        /// Show only what this agent can reach: the targets it may address and
        /// the rules that match it.
        #[arg(long, value_name = "ID")]
        agent: Option<String>,
        /// `table` for a terminal, `json` for an inventory script.
        #[arg(long, value_enum, default_value_t = OutputArg::Table)]
        output: OutputArg,
    },
    /// Validate the policy file and resolve every secret reference in it.
    Check {
        #[command(flatten)]
        config: ConfigArg,
    },
    /// Enrol an agent, an upstream or a rule into the policy file.
    #[command(subcommand)]
    Agent(AgentCommand),
    /// Add or inspect the services the proxy fronts.
    #[command(subcommand)]
    Upstream(UpstreamCommand),
    /// Add a rule to the ACL.
    #[command(subcommand)]
    Acl(AclCommand),
    /// Mint an agent token and print the config block to paste.
    GenToken {
        /// Agent id to use in the printed block.
        #[arg(default_value = "my-agent")]
        id: String,
    },
    /// Print the sha256 of a token you already have (reads stdin when omitted).
    HashToken { token: Option<String> },
    /// Inspect the audit log.
    #[command(subcommand)]
    Audit(AuditCommand),
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum WhatArg {
    Agents,
    Upstreams,
    Mcp,
    Acl,
}

impl From<WhatArg> for What {
    fn from(arg: WhatArg) -> Self {
        match arg {
            WhatArg::Agents => What::Agents,
            WhatArg::Upstreams => What::Upstreams,
            WhatArg::Mcp => What::Mcp,
            WhatArg::Acl => What::Acl,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum OutputArg {
    Table,
    Json,
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum TemplateArg {
    Minimal,
    Starter,
    Full,
}

impl From<TemplateArg> for Template {
    fn from(arg: TemplateArg) -> Self {
        match arg {
            TemplateArg::Minimal => Template::Minimal,
            TemplateArg::Starter => Template::Starter,
            TemplateArg::Full => Template::Full,
        }
    }
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Mint a token, enrol the agent, and write only the hash to the file.
    Add {
        /// Id the agent authenticates as, and the name every audit record uses.
        id: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Display name for the console, when the id is not what a human calls it.
        #[arg(long)]
        name: Option<String>,
        /// Upstream or MCP server this agent may address at all. Repeatable.
        /// Omit for "any", which still leaves the ACL in charge.
        #[arg(long = "target", value_name = "NAME")]
        targets: Vec<String>,
    },
}

#[derive(Subcommand)]
enum UpstreamCommand {
    /// Add a service the proxy fronts, and the credential it attaches.
    Add {
        /// Routing prefix and policy name: agents call `/<name>/<path>`.
        name: String,
        #[command(flatten)]
        config: ConfigArg,
        /// Where the proxy forwards to, e.g. `https://api.anthropic.com`.
        #[arg(long, value_name = "URL")]
        base_url: String,
        /// Credential scheme to inject on the way out.
        #[arg(long, value_enum, default_value_t = AuthArg::None)]
        auth: AuthArg,
        /// Credential *reference*: `env:NAME`, `file:/path`, `op://vault/item/field`.
        #[arg(long, value_name = "REF")]
        secret: Option<String>,
        /// Header name for `--auth header`, e.g. `x-api-key`.
        #[arg(long, value_name = "NAME")]
        header: Option<String>,
        /// Value prefix for `--auth header`, when the API wants one.
        #[arg(long, value_name = "PREFIX")]
        prefix: Option<String>,
        /// Username for `--auth basic`.
        #[arg(long)]
        username: Option<String>,
        /// Query parameter for `--auth query`, e.g. `key`.
        #[arg(long, value_name = "NAME")]
        param: Option<String>,
        /// Static header to send upstream, `Name=Value`. Repeatable. Never a
        /// credential — that is what `--secret` is for.
        #[arg(long = "set-header", value_name = "NAME=VALUE")]
        set_headers: Vec<String>,
    },
}

#[derive(Subcommand)]
enum AclCommand {
    /// Append a rule. Appended, not inserted: first match wins, so a new rule
    /// cannot silently shadow one already in the file.
    Add {
        #[command(flatten)]
        config: ConfigArg,
        /// Shown in the audit log and the TUI, so a decision traces to a rule.
        #[arg(long)]
        name: Option<String>,
        /// Agent id or glob. Defaults to every agent.
        #[arg(long, default_value = "*")]
        agent: String,
        /// `http`, `mcp`, or `*`.
        #[arg(long, default_value = "*")]
        kind: String,
        /// Upstream or MCP server name, or `*`.
        #[arg(long, default_value = "*")]
        target: String,
        /// HTTP verbs, or JSON-RPC methods such as `tools/call`. Repeatable.
        #[arg(long = "methods", value_name = "METHOD", default_values_t = [String::from("*")])]
        methods: Vec<String>,
        /// URL paths, or for MCP the tool name. Repeatable.
        #[arg(long = "paths", value_name = "PATH", default_values_t = [String::from("**")])]
        paths: Vec<String>,
        /// `allow`, `deny`, or `ask` to prompt a human in `run --tui`.
        #[arg(long, value_enum, default_value_t = ActionArg::Allow)]
        action: ActionArg,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum AuthArg {
    None,
    Bearer,
    Header,
    Basic,
    Query,
}

#[derive(Copy, Clone, PartialEq, Eq, clap::ValueEnum)]
enum ActionArg {
    Allow,
    Deny,
    Ask,
}

impl ActionArg {
    fn as_str(self) -> &'static str {
        match self {
            ActionArg::Allow => "allow",
            ActionArg::Deny => "deny",
            ActionArg::Ask => "ask",
        }
    }
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Prove the log has not been edited, reordered or truncated.
    Verify { path: PathBuf },
    /// Print the last N entries, one line each.
    Tail {
        path: PathBuf,
        #[arg(short = 'n', long, default_value_t = 20)]
        lines: usize,
        /// Only this agent. One proxy fronts many agents, so the log is
        /// interleaved and "what has bravo been doing" is the usual question.
        #[arg(long, value_name = "ID")]
        agent: Option<String>,
        /// Only this upstream or MCP server.
        #[arg(long, value_name = "NAME")]
        target: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            config,
            agent,
            secret,
            template,
            force,
        } => init_config(&InitOptions {
            path: config.config,
            agent,
            secret,
            template: template.into(),
            force,
        }),
        Command::Run {
            config,
            listen,
            admin_listen,
            tui,
        } => {
            let mut config = Config::load(&config.config)?;

            let overridden = listen.is_some() || admin_listen.is_some();
            if let Some(spec) = &listen {
                config.server.override_listen(spec).context("--listen")?;
            }
            if let Some(spec) = &admin_listen {
                config
                    .server
                    .override_admin_listen(spec)
                    .context("--admin-listen")?;
            }
            if overridden {
                // The file was validated on load; the addresses it was
                // validated with are no longer the ones being bound.
                config
                    .validate()
                    .context("after applying the listen overrides")?;
            }

            init_tracing(tui, &config)?;
            if overridden {
                // Otherwise the file and the socket disagree and nothing says why.
                tracing::info!(
                    listen = %config.server.listen,
                    admin_listen = ?config.server.admin_listen,
                    "listen addresses overridden outside the config file"
                );
            }
            tokio_runtime()?.block_on(run(config, tui))
        }
        Command::Mcp {
            config,
            server,
            token,
            admin_url,
        } => {
            let config = Config::load(&config.config)?;
            // stdout belongs to the JSON-RPC stream; diagnostics go to stderr.
            init_tracing(false, &config)?;
            let admin_url = admin_url
                .or_else(|| {
                    config
                        .server
                        .admin_listen
                        .map(|addr| format!("http://{addr}"))
                })
                .context(
                    "no control-plane address — pass --admin-url or set server.admin_listen",
                )?;
            tokio_runtime()?.block_on(mcp::run(
                config,
                mcp::BridgeOptions {
                    server,
                    agent_token: token,
                    admin_url,
                },
            ))
        }
        Command::List {
            config,
            what,
            agent,
            output,
        } => list_config(
            &config.config,
            &ListOptions {
                what: what.map(What::from).unwrap_or_default(),
                agent,
            },
            output,
        ),
        Command::Check { config } => check(&config.config),
        Command::Agent(AgentCommand::Add {
            id,
            config,
            name,
            targets,
        }) => add_agent(&config.config, &id, name.as_deref(), &targets),
        Command::Upstream(UpstreamCommand::Add {
            name,
            config,
            base_url,
            auth,
            secret,
            header,
            prefix,
            username,
            param,
            set_headers,
        }) => add_upstream(AddUpstream {
            path: config.config,
            name,
            base_url,
            auth,
            secret,
            header,
            prefix,
            username,
            param,
            set_headers,
        }),
        Command::Acl(AclCommand::Add {
            config,
            name,
            agent,
            kind,
            target,
            methods,
            paths,
            action,
        }) => add_rule(
            &config.config,
            name.as_deref(),
            &agent,
            &kind,
            &target,
            &methods,
            &paths,
            action,
        ),
        Command::GenToken { id } => gen_token(&id),
        Command::HashToken { token } => {
            let token = match token {
                Some(token) => token,
                None => {
                    let mut buffer = String::new();
                    std::io::stdin().read_to_string(&mut buffer)?;
                    buffer
                }
            };
            println!("{}", identity::token_hash(&token));
            Ok(())
        }
        Command::Audit(AuditCommand::Verify { path }) => verify_audit(&path),
        Command::Audit(AuditCommand::Tail {
            path,
            lines,
            agent,
            target,
        }) => tail_audit(&path, lines, agent.as_deref(), target.as_deref()),
    }
}

fn tokio_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
}

fn init_tracing(tui: bool, config: &Config) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_env("IAP_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if tui {
        // The terminal is the console's; send diagnostics to a file beside the log.
        let path = config
            .audit
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .join("mcp-iap.log");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("opening `{}`", path.display()))?;
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }
    Ok(())
}

async fn run(config: Config, tui: bool) -> Result<()> {
    let listen = config.server.listen;
    let admin_listen = config.server.admin_listen;
    let audit_path = config.audit.path.clone();
    let audit_to_stderr = config.audit.stderr && !tui;

    let state = AppState::build(config, audit_to_stderr)?;
    state.log_startup()?;

    // The console and the control API are the only things that can answer an
    // `ask`. Without either, `ask` denies rather than hanging.
    state.broker.set_has_approver(tui);

    let proxy_listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding the proxy to {listen}"))?;
    let proxy = axum::serve(
        proxy_listener,
        mcp_iap::proxy::router(Arc::clone(&state))
            .into_make_service_with_connect_info::<SocketAddr>(),
    );

    let admin = match admin_listen {
        Some(addr) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("binding the control plane to {addr}"))?;
            let token_path = write_admin_token(&audit_path, &state.admin_token)?;
            if !tui {
                eprintln!(
                    "control plane on http://{addr} (token in {})",
                    token_path.display()
                );
            }
            Some(axum::serve(
                listener,
                mcp_iap::admin::router(Arc::clone(&state)),
            ))
        }
        None => None,
    };

    if !tui {
        eprintln!(
            "mcp-iap listening on http://{listen} — {} agents, {} rules, default {}",
            state.agents.len(),
            state.acl.rule_count(),
            state.acl.default_action()
        );
        eprintln!("audit log: {}", audit_path.display());
    }

    let console = tui.then(|| {
        let state = Arc::clone(&state);
        tokio::task::spawn_blocking(move || mcp_iap::tui::run(state))
    });

    match (admin, console) {
        (Some(admin), Some(console)) => tokio::select! {
            result = proxy => result?,
            result = admin => result?,
            result = console => result??,
            _ = tokio::signal::ctrl_c() => {}
        },
        (Some(admin), None) => tokio::select! {
            result = proxy => result?,
            result = admin => result?,
            _ = tokio::signal::ctrl_c() => {}
        },
        (None, Some(console)) => tokio::select! {
            result = proxy => result?,
            result = console => result??,
            _ = tokio::signal::ctrl_c() => {}
        },
        (None, None) => tokio::select! {
            result = proxy => result?,
            _ = tokio::signal::ctrl_c() => {}
        },
    }

    Ok(())
}

/// Persist the control-plane token so the TUI and `curl` can find it, owner-only.
fn write_admin_token(audit_path: &Path, token: &str) -> Result<PathBuf> {
    let dir = audit_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).ok();
    let path = dir.join("admin-token");

    // Created 0600 rather than created-then-chmodded: the old order left the
    // token world-readable for however long the chmod took, and discarded the
    // chmod's own failure on top of that.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("creating `{}`", path.display()))?;

    // An existing file keeps its old mode, so tighten it either way.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("restricting `{}` to the current user", path.display()))?;
    }

    use std::io::Write;
    file.write_all(token.as_bytes())
        .with_context(|| format!("writing `{}`", path.display()))?;
    Ok(path)
}

/// `list` reads the policy file and nothing else — no daemon, no network, and
/// no credential resolution, so it answers the same whether the proxy is up or
/// down and cannot turn a reference into a secret on the way.
fn list_config(path: &Path, options: &ListOptions, output: OutputArg) -> Result<()> {
    let config = Config::load(path)?;
    let inventory = Inventory::build(&config, options)?;
    match output {
        OutputArg::Table => print!("{}", inventory.render()),
        OutputArg::Json => println!("{}", serde_json::to_string_pretty(&inventory)?),
    }
    Ok(())
}

fn check(path: &Path) -> Result<()> {
    let config = Config::load(path)?;
    println!("config      {}", path.display());
    println!("proxy       {}", config.server.listen);
    println!(
        "control     {}",
        config
            .server
            .admin_listen
            .map(|a| a.to_string())
            .unwrap_or_else(|| "disabled".into())
    );
    println!("audit log   {}", config.audit.path.display());
    println!(
        "agents      {}",
        config
            .agents
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "upstreams   {}",
        config
            .upstreams
            .iter()
            .map(|u| format!("{} → {}", u.name, u.base_url))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "mcp servers {}",
        config
            .mcp_servers
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "acl         {} rules, default {}",
        config.acl.len(),
        config.acl_default.action
    );
    // Worth a line of its own: whether the data plane takes a standing grant or
    // an hour of one is the single biggest thing this file decides.
    let workload = &config.server.workload_identity;
    println!(
        "identity    agent tokens{}",
        match workload.mode {
            mcp_iap::config::WorkloadMode::Off => String::new(),
            mcp_iap::config::WorkloadMode::Optional => format!(
                ", workload tokens accepted ({}s) — set mode = \"required\" to insist",
                workload.lifetime_secs
            ),
            mcp_iap::config::WorkloadMode::Required => format!(
                " to mint only, workload tokens required ({}s)",
                workload.lifetime_secs
            ),
        }
    );

    let resolver = mcp_iap::secrets::SecretResolver::new(config.server.op_binary.clone());
    let references = config.secret_refs();
    if references.is_empty() {
        println!("secrets     none referenced");
    }
    let mut failed = 0;
    for reference in &references {
        match resolver.resolve(reference) {
            Ok(_) => println!("secrets     ok      {reference}"),
            Err(error) => {
                failed += 1;
                println!("secrets     FAILED  {reference}: {error:#}");
            }
        }
    }
    if failed > 0 {
        anyhow::bail!(
            "{failed} of {} secret references failed to resolve",
            references.len()
        );
    }
    println!("\nconfig is valid.");
    Ok(())
}

/// Write a policy file and tell the operator what is left to do.
///
/// The token is printed rather than stored: only its hash went into the file,
/// so this is the one moment it exists in plaintext.
fn init_config(options: &InitOptions) -> Result<()> {
    let written = init::init(options)?;
    let path = written.path.display();

    let (Some(agent), Some(token)) = (written.agent.as_deref(), written.token.as_deref()) else {
        // The minimal template. Nothing was granted, so the useful thing to
        // print is the shortest path to a proxy that does something.
        println!(
            "Wrote {path}. No agents, no upstreams — the proxy starts and denies everything.\n"
        );
        println!("Add what it should front:");
        println!(
            "  mcp-iap upstream add anthropic --base-url https://api.anthropic.com \\\n             \x20     --auth header --header x-api-key --secret env:ANTHROPIC_API_KEY"
        );
        println!("  mcp-iap acl add --target anthropic --methods POST --paths /v1/messages");
        println!("  mcp-iap agent add claude-code --target anthropic\n");
        println!("Then:");
        println!("  mcp-iap check --config {path}   # resolves every credential reference");
        println!("  mcp-iap run --config {path} --tui");
        return Ok(());
    };

    println!("Wrote {path} for agent `{agent}`.\n");
    println!("The agent's token — shown once, and not any upstream's credential:\n");
    println!("  {token}\n");

    println!("Next:");
    // Only `env:` has a step the operator can act on from here; anything else
    // is somewhere `check` can look for itself.
    if let Some(name) = written
        .secret
        .as_deref()
        .and_then(|reference| reference.strip_prefix("env:"))
    {
        println!("  export {name}=...   # the credential the proxy injects on the way out");
    }
    println!("  mcp-iap check --config {path}   # resolves every credential reference");
    println!("  mcp-iap run --config {path} --tui\n");

    println!("Then point the agent at the proxy:");
    println!(
        "  export ANTHROPIC_BASE_URL=http://{}/anthropic",
        written.listen
    );
    println!("  export ANTHROPIC_AUTH_TOKEN={token}");
    println!("\nAdd another agent with `mcp-iap agent add <id>`.");
    Ok(())
}

fn add_agent(path: &Path, id: &str, name: Option<&str>, targets: &[String]) -> Result<()> {
    let enrolled = enroll::add_agent(path, id, name, targets)?;
    println!("Added agent `{}` to {}.\n", enrolled.id, path.display());
    println!("Its token — shown once, and not any upstream's credential:\n");
    println!("  {}\n", enrolled.token);
    if targets.is_empty() {
        println!("It may address any target, subject to the ACL.");
    } else {
        println!("It may address: {}.", targets.join(", "));
    }
    // An agent with no rule matching it is the quiet failure: the file is
    // valid, the token works, and every call it makes is denied.
    if enroll::rule_count(path)? == 0 {
        println!(
            "\nThere are no `[[acl]]` rules yet, so every request still falls through to \
             `acl_default` and is denied. Add one with `mcp-iap acl add`."
        );
    }
    Ok(())
}

/// Grouped because clap hands back ten flags and `too_many_arguments` is right.
struct AddUpstream {
    path: PathBuf,
    name: String,
    base_url: String,
    auth: AuthArg,
    secret: Option<String>,
    header: Option<String>,
    prefix: Option<String>,
    username: Option<String>,
    param: Option<String>,
    set_headers: Vec<String>,
}

fn add_upstream(options: AddUpstream) -> Result<()> {
    let AddUpstream {
        path,
        name,
        base_url,
        auth,
        secret,
        header,
        prefix,
        username,
        param,
        set_headers,
    } = options;

    // Each scheme needs a different subset of the flags, and silently ignoring
    // one the operator did pass is how a credential ends up not being sent.
    let need_secret = || -> Result<String> {
        secret.clone().context(
            "this `--auth` scheme needs `--secret <REF>` — the credential reference to inject",
        )
    };
    let auth = match auth {
        AuthArg::None => enroll::AuthSpec::None,
        AuthArg::Bearer => enroll::AuthSpec::Bearer {
            secret: need_secret()?,
        },
        AuthArg::Header => enroll::AuthSpec::Header {
            header: header
                .clone()
                .context("`--auth header` needs `--header <NAME>`, e.g. `--header x-api-key`")?,
            secret: need_secret()?,
            prefix: prefix.clone(),
        },
        AuthArg::Basic => enroll::AuthSpec::Basic {
            username: username
                .clone()
                .context("`--auth basic` needs `--username <NAME>`")?,
            secret: need_secret()?,
        },
        AuthArg::Query => enroll::AuthSpec::Query {
            param: param
                .clone()
                .context("`--auth query` needs `--param <NAME>`, e.g. `--param key`")?,
            secret: need_secret()?,
        },
    };
    if matches!(auth, enroll::AuthSpec::None) && secret.is_some() {
        bail!("`--secret` was given but `--auth` is `none`, so nothing would be injected");
    }

    let headers = set_headers
        .iter()
        .map(|raw| {
            raw.split_once('=')
                .map(|(key, value)| (key.trim().to_string(), value.to_string()))
                .with_context(|| format!("`--set-header {raw}` should be `Name=Value`"))
        })
        .collect::<Result<Vec<_>>>()?;

    enroll::add_upstream(&path, &name, &base_url, &auth, &headers)?;
    println!("Added upstream `{name}` to {}.", path.display());
    println!("Agents reach it at `/{name}/<path>`.");
    if enroll::rule_count(&path)? == 0 {
        println!(
            "\nNo `[[acl]]` rules yet, so it is not reachable. Allow something with:\n  \
             mcp-iap acl add --target {name} --methods GET --paths '/**'"
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn add_rule(
    path: &Path,
    name: Option<&str>,
    agent: &str,
    kind: &str,
    target: &str,
    methods: &[String],
    paths: &[String],
    action: ActionArg,
) -> Result<()> {
    enroll::add_rule(
        path,
        name,
        agent,
        kind,
        target,
        methods,
        paths,
        action.as_str(),
    )?;
    let count = enroll::rule_count(path)?;
    println!(
        "Added rule {count} of {count} to {}: {} {} {} on `{target}` for `{agent}`.",
        path.display(),
        action.as_str(),
        methods.join(","),
        paths.join(","),
    );
    // Position is the whole semantics of an ACL, so say it rather than making
    // the operator infer it from the file.
    println!("Rules match in file order and the first match wins, so this one is checked last.");
    Ok(())
}

fn gen_token(id: &str) -> Result<()> {
    let token = identity::generate_token()?;
    let hash = identity::token_hash(&token);
    println!("Give this token to the agent — it is not any upstream credential:\n");
    println!("  {token}\n");
    println!("Add this to your policy file:\n");
    println!("[[agents]]");
    println!("id = \"{id}\"");
    println!("token_sha256 = \"{hash}\"");
    println!("# targets = [\"anthropic\"]   # optional: restrict which upstreams it may address");
    Ok(())
}

fn verify_audit(path: &Path) -> Result<()> {
    let report = audit::verify_file(path)?;
    println!(
        "{} entries verified — the hash chain is intact.",
        report.entries
    );
    if let (Some(first), Some(last)) = (report.first_ts, report.last_ts) {
        println!("covering {first} → {last}");
    }
    Ok(())
}

fn tail_audit(path: &Path, lines: usize, agent: Option<&str>, target: Option<&str>) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading `{}`", path.display()))?;

    let filtered = agent.is_some() || target.is_some();
    let mut rendered: Vec<String> = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<audit::AuditEvent>(line) {
            Ok(event) => {
                if !event.matches(agent, target) {
                    continue;
                }
                rendered.push(format!("{} {}", event.ts, event.oneline()));
            }
            // A line this build cannot parse is still evidence, so it is shown
            // verbatim — but it cannot be matched against a filter, and passing
            // it through a filtered view would misreport it as a hit.
            Err(_) if !filtered => rendered.push(line.to_string()),
            Err(_) => {}
        }
    }

    // Filter first, then take the last N: `-n 20 --agent bravo` means bravo's
    // last twenty, not whatever bravo did inside the log's last twenty.
    for line in rendered.iter().skip(rendered.len().saturating_sub(lines)) {
        println!("{line}");
    }

    if rendered.is_empty() && filtered {
        let what = match (agent, target) {
            (Some(agent), Some(target)) => format!("agent `{agent}` and target `{target}`"),
            (Some(agent), None) => format!("agent `{agent}`"),
            (None, Some(target)) => format!("target `{target}`"),
            (None, None) => unreachable!("filtered implies one of the two is set"),
        };
        eprintln!("no entries for {what}");
    }
    Ok(())
}

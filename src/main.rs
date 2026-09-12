use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mcp_iap::audit;
use mcp_iap::config::Config;
use mcp_iap::identity;
use mcp_iap::init::{self, InitOptions, Template};
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
    /// Write a policy file, agent token and all, ready to run.
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
        /// `starter` is one agent and one upstream; `full` is the annotated
        /// example, with GitHub, MCP and a service account worked out.
        #[arg(long, value_enum, default_value_t = TemplateArg::Starter)]
        template: TemplateArg,
        /// Replace an existing file. Mints a new token, retiring the old one.
        #[arg(short, long)]
        force: bool,
    },
    /// Run the proxy.
    Run {
        #[command(flatten)]
        config: ConfigArg,
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
    /// Validate the policy file and resolve every secret reference in it.
    Check {
        #[command(flatten)]
        config: ConfigArg,
    },
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
enum TemplateArg {
    Starter,
    Full,
}

impl From<TemplateArg> for Template {
    fn from(arg: TemplateArg) -> Self {
        match arg {
            TemplateArg::Starter => Template::Starter,
            TemplateArg::Full => Template::Full,
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
        Command::Run { config, tui } => {
            let config = Config::load(&config.config)?;
            init_tracing(tui, &config)?;
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
        Command::Check { config } => check(&config.config),
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
        Command::Audit(AuditCommand::Tail { path, lines }) => tail_audit(&path, lines),
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

    println!("Wrote {path} for agent `{}`.\n", written.agent);
    println!("The agent's token — shown once, and not any upstream's credential:\n");
    println!("  {}\n", written.token);

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
    println!("  export ANTHROPIC_AUTH_TOKEN={}", written.token);
    println!("\nAdd another agent with `mcp-iap gen-token <id>`.");
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

fn tail_audit(path: &Path, lines: usize) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading `{}`", path.display()))?;
    let all: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    for line in all.iter().skip(all.len().saturating_sub(lines)) {
        match serde_json::from_str::<audit::AuditEvent>(line) {
            Ok(event) => println!("{} {}", event.ts, event.oneline()),
            Err(_) => println!("{line}"),
        }
    }
    Ok(())
}

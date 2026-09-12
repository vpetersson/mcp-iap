//! The MCP bridge.
//!
//! An agent configures `mcp-iap mcp --server github` as its MCP server. This
//! process speaks JSON-RPC to the agent on stdio, asks the running daemon to
//! authorize every call, and only then relays it to the real MCP server — whose
//! credentials it holds and the agent never sees.
//!
//! Policy and audit stay in the daemon. If the daemon is unreachable the bridge
//! refuses to start, and if an authorization call fails the call is denied.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// The agent's stdin/stdout is a single JSON-RPC stream, so every writer has to
/// go through one handle. Two `tokio::io::stdout()` handles buffer separately
/// and can interleave halves of two frames.
type SharedStdout = Arc<Mutex<tokio::io::Stdout>>;

use crate::admin::AuthorizeResult;
use crate::config::{Config, McpServerConfig, McpTransportKind};
use crate::credentials::CredentialInjector;
use crate::secrets::SecretResolver;

/// JSON-RPC error code returned for a call the policy refused.
const BLOCKED_BY_POLICY: i64 = -32001;

/// How long to wait for the real server's last answers after the agent hangs up.
const SHUTDOWN_DRAIN: std::time::Duration = std::time::Duration::from_secs(10);

pub struct BridgeOptions {
    pub server: String,
    pub agent_token: String,
    pub admin_url: String,
}

/// The `(method, name)` pair the ACL matches on, pulled out of one JSON-RPC message.
pub fn call_target(message: &Value) -> Option<(String, String)> {
    let method = message.get("method")?.as_str()?.to_string();
    let params = message.get("params");
    let name = match method.as_str() {
        "tools/call" | "prompts/get" => params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "resources/read" | "resources/subscribe" | "resources/unsubscribe" => params
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .unwrap_or_default(),
        _ => "",
    };
    Some((method, name.to_string()))
}

/// A JSON-RPC error response the agent will understand, or `None` for a notification.
pub fn blocked_response(message: &Value, reason: &str) -> Option<Value> {
    let id = message.get("id")?;
    if id.is_null() {
        return None;
    }
    Some(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": BLOCKED_BY_POLICY,
            "message": format!("blocked by mcp-iap: {reason}"),
        }
    }))
}

struct Authorizer {
    http: reqwest::Client,
    admin_url: String,
    token: String,
    server: String,
}

impl Authorizer {
    async fn authorize(&self, method: &str, name: &str) -> AuthorizeResult {
        let body = json!({
            "kind": "mcp",
            "target": self.server,
            "method": method,
            "path": name,
        });
        let response = self
            .http
            .post(format!("{}/authorize", self.admin_url))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await;

        match response {
            Ok(response) if response.status().is_success() => match response.json().await {
                Ok(result) => result,
                Err(error) => deny(format!("malformed authorization response: {error}")),
            },
            Ok(response) => deny(format!(
                "authorization endpoint returned {}",
                response.status()
            )),
            // Fail closed: no policy authority, no call.
            Err(error) => deny(format!("policy daemon unreachable: {error}")),
        }
    }

    /// Confirm the policy authority is reachable before accepting any message.
    async fn probe(&self) -> Result<()> {
        let response = self
            .http
            .get(format!("{}/health", self.admin_url))
            .send()
            .await
            .with_context(|| {
                format!(
                    "cannot reach the mcp-iap daemon at {} — start `mcp-iap run` first",
                    self.admin_url
                )
            })?;
        if !response.status().is_success() {
            bail!(
                "the mcp-iap daemon at {} answered /health with {}",
                self.admin_url,
                response.status()
            );
        }
        Ok(())
    }

    /// Open the session: authenticates the agent token and checks its `targets`,
    /// and writes the `session_start` record. Any failure is fatal to the bridge.
    async fn start_session(&self) -> Result<()> {
        let response = self
            .http
            .post(format!("{}/event", self.admin_url))
            .bearer_auth(&self.token)
            .json(&json!({
                "kind": "mcp",
                "event": "session_start",
                "target": self.server,
            }))
            .send()
            .await
            .context("opening an MCP session with the daemon")?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            bail!("the agent token was not recognised");
        }
        if status == reqwest::StatusCode::FORBIDDEN {
            bail!(
                "this agent may not address the MCP server `{}`",
                self.server
            );
        }
        if !status.is_success() {
            bail!("the daemon answered the session request with {status}");
        }
        Ok(())
    }

    async fn event(&self, event: &str, error: Option<String>, detail: Option<Value>) {
        let body = json!({
            "kind": "mcp",
            "event": event,
            "target": self.server,
            "error": error,
            "detail": detail,
        });
        let _ = self
            .http
            .post(format!("{}/event", self.admin_url))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await;
    }
}

fn deny(reason: String) -> AuthorizeResult {
    AuthorizeResult {
        allowed: false,
        decision: "deny".into(),
        rule: "<bridge>".into(),
        reason: Some(reason),
    }
}

/// Where authorized messages go once the policy has cleared them.
enum Upstream {
    Stdio(Box<StdioUpstream>),
    Http(Box<HttpUpstream>),
}

struct StdioUpstream {
    /// Taken at shutdown so the child sees EOF and drains cleanly.
    stdin: Mutex<Option<tokio::process::ChildStdin>>,
    /// Kept so the child is killed when the bridge exits.
    _child: Child,
}

struct HttpUpstream {
    http: reqwest::Client,
    url: String,
    server: McpServerConfig,
    injector: CredentialInjector,
    session: Mutex<Option<String>>,
}

pub async fn run(config: Config, options: BridgeOptions) -> Result<()> {
    let server = config
        .mcp_server(&options.server)
        .cloned()
        .with_context(|| format!("`{}` is not a configured MCP server", options.server))?;

    let resolver = Arc::new(SecretResolver::new(config.server.op_binary.clone()));

    // The control plane may be on TLS with a certificate no public root signs,
    // which is the normal case for a loopback listener. The bridge reads the
    // same policy file, so it trusts exactly that certificate and nothing else
    // new — rather than the alternative, which is turning verification off.
    let authorizer = Arc::new(Authorizer {
        http: crate::tls::control_plane_client(config.server.admin_tls_material(), &resolver)?,
        admin_url: options.admin_url.trim_end_matches('/').to_string(),
        token: options.agent_token,
        server: options.server.clone(),
    });

    // Prove the policy authority is up before the agent sends anything. This is
    // a health check rather than a real authorization so the probe never shows
    // up in the audit log as a call the agent did not make.
    authorizer.probe().await?;

    // Then prove *this* agent may address *this* server, before a single secret
    // is resolved. The bridge used to spawn the real server — credentials and
    // all — on the strength of an unauthenticated health check, so an unknown
    // token materialised the key first and was rejected afterwards.
    authorizer
        .start_session()
        .await
        .context("the daemon refused this agent's MCP session")?;

    // No audit log here: the bridge's records go to the daemon, which owns the log.
    let injector = CredentialInjector::new(Arc::clone(&resolver), reqwest::Client::new(), None);

    let stdout: SharedStdout = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut relay = None;
    let upstream = match server.transport {
        McpTransportKind::Stdio => {
            let (upstream, child_stdout) = spawn_stdio(&server, &injector)?;
            // Relay everything the real server says straight back to the agent.
            let out = Arc::clone(&stdout);
            relay = Some(tokio::spawn(async move {
                let mut lines = BufReader::new(child_stdout).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let mut out = out.lock().await;
                    if out
                        .write_all(format!("{line}\n").as_bytes())
                        .await
                        .and(out.flush().await)
                        .is_err()
                    {
                        break;
                    }
                }
            }));
            upstream
        }
        McpTransportKind::Http => Upstream::Http(Box::new(HttpUpstream {
            http: reqwest::Client::new(),
            url: server
                .url
                .clone()
                .expect("validated: http transport has a url"),
            server: server.clone(),
            injector,
            session: Mutex::new(None),
        })),
    };

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            tracing::warn!("dropping a non-JSON line from the agent");
            continue;
        };

        if !authorize_message(&authorizer, &message, &stdout).await? {
            continue;
        }

        match &upstream {
            Upstream::Stdio(stdio) => {
                if let Some(pipe) = stdio.stdin.lock().await.as_mut() {
                    pipe.write_all(format!("{line}\n").as_bytes()).await?;
                    pipe.flush().await?;
                }
            }
            Upstream::Http(http) => {
                if let Err(error) = relay_http(http, &message, &stdout).await {
                    authorizer
                        .event("error", Some(error.to_string()), None)
                        .await;
                    if let Some(response) = blocked_response(&message, &error.to_string()) {
                        write_message(&stdout, &response).await?;
                    }
                }
            }
        }
    }

    // The agent closed its end. Close the child's stdin so it exits, then wait
    // for the relay to flush the answers it already produced — otherwise the
    // last few responses would be lost to the race with process exit.
    if let Upstream::Stdio(stdio) = &upstream {
        stdio.stdin.lock().await.take();
    }
    if let Some(relay) = relay {
        let _ = tokio::time::timeout(SHUTDOWN_DRAIN, relay).await;
    }

    authorizer.event("session_end", None, None).await;
    Ok(())
}

/// Returns `true` when the message may be forwarded. Denials are answered here.
async fn authorize_message(
    authorizer: &Authorizer,
    message: &Value,
    stdout: &SharedStdout,
) -> Result<bool> {
    // A batch is all-or-nothing: partially forwarding one would desynchronise
    // the ids the agent is waiting on.
    if let Some(batch) = message.as_array() {
        for element in batch {
            let Some((method, name)) = call_target(element) else {
                continue;
            };
            let result = authorizer.authorize(&method, &name).await;
            if !result.allowed {
                let reason = result.reason.unwrap_or_else(|| result.decision.clone());
                // One array, not N loose objects: a batch request takes a batch
                // response, and anything else desynchronises the very ids the
                // all-or-nothing rule exists to keep straight.
                let refusals: Vec<Value> = batch
                    .iter()
                    .filter_map(|element| blocked_response(element, &reason))
                    .collect();
                if !refusals.is_empty() {
                    write_message(stdout, &Value::Array(refusals)).await?;
                }
                return Ok(false);
            }
        }
        return Ok(true);
    }

    let Some((method, name)) = call_target(message) else {
        // No `method`: this is a response or an unparseable frame, not a call.
        return Ok(true);
    };

    let result = authorizer.authorize(&method, &name).await;
    if result.allowed {
        return Ok(true);
    }
    let reason = result.reason.unwrap_or_else(|| result.decision.clone());
    if let Some(response) = blocked_response(message, &reason) {
        write_message(stdout, &response).await?;
    }
    Ok(false)
}

async fn write_message(stdout: &SharedStdout, message: &Value) -> Result<()> {
    let line = format!("{}\n", serde_json::to_string(message)?);
    let mut out = stdout.lock().await;
    out.write_all(line.as_bytes()).await?;
    out.flush().await?;
    Ok(())
}

fn spawn_stdio(
    server: &McpServerConfig,
    injector: &CredentialInjector,
) -> Result<(Upstream, tokio::process::ChildStdout)> {
    let command_name = server
        .command
        .clone()
        .expect("validated: stdio transport has a command");

    let mut command = Command::new(&command_name);
    command
        .args(&server.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);

    if let Some(cwd) = &server.cwd {
        command.current_dir(cwd);
    }
    for (key, secret) in injector.resolve_env(&server.env)? {
        command.env(key, secret.expose());
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("spawning MCP server `{command_name}`"))?;
    let stdin = child.stdin.take().expect("stdin was piped");
    let stdout = child.stdout.take().expect("stdout was piped");

    Ok((
        Upstream::Stdio(Box::new(StdioUpstream {
            stdin: Mutex::new(Some(stdin)),
            _child: child,
        })),
        stdout,
    ))
}

async fn relay_http(upstream: &HttpUpstream, message: &Value, stdout: &SharedStdout) -> Result<()> {
    let mut request = reqwest::Request::new(
        http::Method::POST,
        upstream.url.parse().context("parsing the MCP server url")?,
    );
    request.headers_mut().insert(
        http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    request.headers_mut().insert(
        http::header::ACCEPT,
        "application/json, text/event-stream".parse().unwrap(),
    );
    if let Some(session) = upstream.session.lock().await.as_deref() {
        request
            .headers_mut()
            .insert("mcp-session-id", session.parse()?);
    }
    *request.body_mut() = Some(reqwest::Body::from(serde_json::to_vec(message)?));

    upstream
        .injector
        .apply(&upstream.server.name, &upstream.server.auth, &mut request)
        .await?;

    let response = upstream.http.execute(request).await?;

    if let Some(session) = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
    {
        *upstream.session.lock().await = Some(session.to_string());
    }

    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let status = response.status();
    let body = response.text().await?;

    if status == http::StatusCode::ACCEPTED || body.trim().is_empty() {
        // A notification: the server acknowledges with no JSON-RPC payload.
        return Ok(());
    }

    if content_type.starts_with("text/event-stream") {
        for value in parse_sse(&body) {
            write_message(stdout, &value).await?;
        }
    } else {
        let value: Value = serde_json::from_str(&body)
            .with_context(|| format!("MCP server returned {status} with a non-JSON body"))?;
        write_message(stdout, &value).await?;
    }
    Ok(())
}

/// Pull the JSON payloads out of an SSE response body.
pub fn parse_sse(body: &str) -> Vec<Value> {
    body.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .filter(|data| !data.is_empty() && *data != "[DONE]")
        .filter_map(|data| serde_json::from_str(data).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_call_is_matched_by_its_tool_name() {
        let message = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "create_issue", "arguments": { "title": "x" } }
        });
        assert_eq!(
            call_target(&message),
            Some(("tools/call".into(), "create_issue".into()))
        );
    }

    #[test]
    fn a_resource_read_is_matched_by_its_uri() {
        let message = json!({
            "jsonrpc": "2.0", "id": 2, "method": "resources/read",
            "params": { "uri": "file:///etc/passwd" }
        });
        assert_eq!(
            call_target(&message),
            Some(("resources/read".into(), "file:///etc/passwd".into()))
        );
    }

    #[test]
    fn plain_methods_have_an_empty_name() {
        let message = json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" });
        assert_eq!(
            call_target(&message),
            Some(("tools/list".into(), String::new()))
        );
    }

    #[test]
    fn a_response_frame_is_not_a_call() {
        let message = json!({ "jsonrpc": "2.0", "id": 3, "result": {} });
        assert_eq!(call_target(&message), None);
    }

    #[test]
    fn a_blocked_request_gets_a_jsonrpc_error_and_a_notification_gets_nothing() {
        let request = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call" });
        let response = blocked_response(&request, "denied by policy `no-writes`").unwrap();
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["code"], BLOCKED_BY_POLICY);
        assert!(response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("no-writes"));

        let notification = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(blocked_response(&notification, "nope").is_none());
    }

    #[test]
    fn sse_payloads_are_extracted() {
        let body =
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\ndata: [DONE]\n";
        let messages = parse_sse(body);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["id"], 1);
    }

    #[test]
    fn an_unreachable_daemon_denies() {
        let result = deny("policy daemon unreachable: connection refused".into());
        assert!(!result.allowed);
        assert_eq!(result.rule, "<bridge>");
    }
}

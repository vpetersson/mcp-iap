//! End-to-end tests: a real proxy in front of a real (mock) upstream.
//!
//! These cover the property the whole project exists for — the agent gets a
//! result, the upstream gets the real credential, and the agent never sees it.

use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use mcp_iap::audit;
use mcp_iap::config::Config;
use mcp_iap::state::AppState;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;

const AGENT_TOKEN: &str = "iap_agent_token";
const UPSTREAM_KEY: &str = "sk-upstream-real";

/// A stand-in upstream that reports exactly what it was sent.
async fn spawn_upstream() -> SocketAddr {
    async fn echo(request: Request) -> Json<Value> {
        let headers = request.headers().clone();
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Json(serde_json::json!({
            "path": request.uri().path(),
            "query": request.uri().query(),
            "method": request.method().as_str(),
            "x-api-key": header("x-api-key"),
            "authorization": header("authorization"),
            "x-iap-token": header("x-iap-token"),
        }))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(echo)))
            .await
            .unwrap();
    });
    addr
}

struct Harness {
    proxy: SocketAddr,
    admin: SocketAddr,
    admin_token: String,
    audit_path: std::path::PathBuf,
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

async fn spawn_proxy(extra_acl: &str) -> Harness {
    let upstream = spawn_upstream().await;
    build_harness(&format!("http://{upstream}"), DEFAULT_AUTH, extra_acl).await
}

const DEFAULT_AUTH: &str =
    r#"{ type = "header", header = "x-api-key", secret = "literal:sk-upstream-real" }"#;

async fn spawn_proxy_with_upstream(base_url: &str, auth: &str) -> Harness {
    build_harness(base_url, auth, "").await
}

async fn build_harness(upstream: &str, auth: &str, extra_acl: &str) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let config_text = format!(
        r#"
[server]
listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"

[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
name = "Claude Code"
token_sha256 = "{token_hash}"
targets = ["echo", "notes"]

[[upstreams]]
name = "echo"
base_url = "{upstream}"
auth = {auth}

[[mcp_servers]]
name = "notes"
command = "true"

[[acl]]
name = "read-models"
target = "echo"
methods = ["GET"]
paths = ["/v1/models", "/v1/models/*"]
action = "allow"

[[acl]]
name = "send-messages"
target = "echo"
methods = ["POST"]
paths = ["/v1/messages"]
action = "allow"
{extra_acl}
"#,
        audit = audit_path.display(),
        token_hash = mcp_iap::identity::token_hash(AGENT_TOKEN),
        upstream = upstream,
        auth = auth,
    );

    let config: Config = toml::from_str(&config_text).unwrap();
    config.validate().unwrap();
    let state = AppState::build(config, false).unwrap();
    state.log_startup().unwrap();

    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = proxy_listener.local_addr().unwrap();
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            axum::serve(
                proxy_listener,
                mcp_iap::proxy::router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
    }

    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin = admin_listener.local_addr().unwrap();
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            axum::serve(admin_listener, mcp_iap::admin::router(state))
                .await
                .unwrap();
        });
    }

    Harness {
        proxy,
        admin,
        admin_token: state.admin_token.clone(),
        audit_path,
        state,
        _dir: dir,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

#[tokio::test]
async fn an_allowed_call_reaches_the_upstream_with_the_real_credential() {
    let harness = spawn_proxy("").await;

    let response = client()
        .get(format!("http://{}/echo/v1/models?limit=5", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-iap-decision"], "allow");
    let seen: Value = response.json().await.unwrap();

    // The upstream got the real key…
    assert_eq!(seen["x-api-key"], UPSTREAM_KEY);
    // …the path prefix was stripped and the query preserved…
    assert_eq!(seen["path"], "/v1/models");
    assert_eq!(seen["query"], "limit=5");
    // …and the agent's own token stopped at the proxy.
    assert!(
        seen["authorization"].is_null(),
        "the agent token leaked upstream"
    );
    assert!(seen["x-iap-token"].is_null());
}

#[tokio::test]
async fn the_agent_never_learns_the_upstream_credential() {
    let harness = spawn_proxy("").await;

    let response = client()
        .post(format!("http://{}/echo/v1/messages", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .json(&serde_json::json!({ "model": "claude", "messages": [] }))
        .send()
        .await
        .unwrap();

    let headers = format!("{:?}", response.headers());
    let body = response.text().await.unwrap();

    // The echo upstream deliberately reflects what it received; that is the only
    // place the key appears, and it is not reachable through any other route.
    assert!(
        !headers.contains(UPSTREAM_KEY),
        "credential echoed in headers"
    );
    assert!(
        body.contains(UPSTREAM_KEY),
        "sanity: the mock upstream reflects the key"
    );

    // The audit log must never contain it either.
    let log = std::fs::read_to_string(&harness.audit_path).unwrap();
    assert!(
        !log.contains(UPSTREAM_KEY),
        "credential leaked into the audit log"
    );
    assert!(
        !log.contains(AGENT_TOKEN),
        "agent token leaked into the audit log"
    );
}

#[tokio::test]
async fn requests_without_a_valid_token_are_rejected() {
    let harness = spawn_proxy("").await;

    let anonymous = client()
        .get(format!("http://{}/echo/v1/models", harness.proxy))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status(), 401);
    assert_eq!(anonymous.headers()["x-iap-decision"], "missing_credentials");

    let wrong = client()
        .get(format!("http://{}/echo/v1/models", harness.proxy))
        .bearer_auth("iap_not_a_real_token")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    assert_eq!(wrong.headers()["x-iap-decision"], "unknown_agent");
}

#[tokio::test]
async fn anything_the_policy_does_not_allow_is_denied() {
    let harness = spawn_proxy("").await;

    // Right upstream, wrong path: nothing matches, so the default denies.
    let response = client()
        .delete(format!("http://{}/echo/v1/models/opus", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(response.headers()["x-iap-decision"], "policy_denied");

    // An upstream that does not exist.
    let unknown = client()
        .get(format!("http://{}/nope/v1/models", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 404);

    // A path that tries to climb out of the upstream's base path. Sent over a raw
    // socket, because a well-behaved HTTP client normalises `..` away before it
    // ever reaches the proxy — and a hostile one will not.
    let raw = raw_request(harness.proxy, "GET /echo/v1/../../admin HTTP/1.1").await;
    assert!(raw.starts_with("HTTP/1.1 400"), "{raw}");
    assert!(raw.contains("invalid_path"), "{raw}");
}

#[tokio::test]
async fn an_encoded_traversal_cannot_escape_the_path_the_policy_approved() {
    // A deliberately ordinary grant: everything under /v1 is allowed. Before the
    // fix that was enough — the encoded climb matched this rule and then resolved
    // out of /v1 entirely.
    let harness = spawn_proxy(
        r#"
[[acl]]
name = "all-of-v1"
target = "echo"
methods = ["GET"]
paths = ["/v1/**"]
action = "allow"
"#,
    )
    .await;

    // `%2e%2e` is `..` to a URL parser and to nothing else. It once passed the
    // traversal guard, matched `paths = ["/v1/models"]`, and then resolved to
    // `/admin/keys` on the way out — with the credential attached.
    for attempt in [
        "GET /echo/v1/%2e%2e/%2e%2e/admin/keys HTTP/1.1",
        "GET /echo/v1/%2E%2E/admin/keys HTTP/1.1",
        "GET /echo/v1/%2e%2e%2f%2e%2e%2fadmin/keys HTTP/1.1",
        "GET /echo/v1/..%2fadmin/keys HTTP/1.1",
        "GET /echo/v1/%5c..%5cadmin/keys HTTP/1.1",
    ] {
        let raw = raw_request(harness.proxy, attempt).await;
        let status = raw.lines().next().unwrap_or_default().to_string();
        assert!(
            status.starts_with("HTTP/1.1 400"),
            "`{attempt}` was not refused — got `{status}`"
        );
        assert!(
            !raw.contains(UPSTREAM_KEY),
            "`{attempt}` reached the upstream with the credential"
        );
    }

    // The ordinary encoded characters people legitimately send still work.
    let ok = client()
        .get(format!("http://{}/echo/v1/models", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
}

#[tokio::test]
async fn a_query_string_credential_never_reaches_the_audit_log() {
    // The upstream is a closed port, so the request fails and the failure is
    // recorded. reqwest's own error text embeds the post-injection URL.
    let harness = spawn_proxy_with_upstream(
        "http://127.0.0.1:1",
        r#"{ type = "query", param = "key", secret = "literal:sk-query-secret" }"#,
    )
    .await;

    let response = client()
        .get(format!("http://{}/echo/v1/models", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);

    let log = std::fs::read_to_string(&harness.audit_path).unwrap();
    assert!(
        !log.contains("sk-query-secret"),
        "the injected credential was written to the audit log:\n{log}"
    );
    // The failure is still described, just without the request in it.
    assert!(log.contains("could not connect to the upstream"), "{log}");
}

/// Send a request line verbatim, bypassing client-side URL normalisation.
async fn raw_request(addr: SocketAddr, request_line: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "{request_line}\r\nHost: {addr}\r\nAuthorization: Bearer {AGENT_TOKEN}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

#[tokio::test]
async fn an_ask_rule_denies_when_no_one_is_watching() {
    let harness = spawn_proxy(
        r#"
[[acl]]
name = "confirm-deletes"
target = "echo"
methods = ["DELETE"]
paths = ["/v1/**"]
action = "ask"
"#,
    )
    .await;

    let response = client()
        .delete(format!("http://{}/echo/v1/models/opus", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 403);
    assert_eq!(response.headers()["x-iap-decision"], "approval_denied");
    let body: Value = response.json().await.unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("no-approver"));
}

#[tokio::test]
async fn an_ask_rule_lets_a_human_release_the_call() {
    let harness = spawn_proxy(
        r#"
[[acl]]
name = "confirm-deletes"
target = "echo"
methods = ["DELETE"]
paths = ["/v1/**"]
action = "ask"
"#,
    )
    .await;
    harness.state.broker.set_has_approver(true);

    let url = format!("http://{}/echo/v1/models/opus", harness.proxy);
    let call = tokio::spawn(async move {
        client()
            .delete(url)
            .bearer_auth(AGENT_TOKEN)
            .send()
            .await
            .unwrap()
    });

    // Wait for it to show up in the queue, then approve it over the control API.
    let pending_url = format!("http://{}/pending", harness.admin);
    let id = loop {
        let pending: Vec<Value> = client()
            .get(&pending_url)
            .bearer_auth(&harness.admin_token)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if let Some(first) = pending.first() {
            assert_eq!(first["request"]["method"], "DELETE");
            assert_eq!(first["agent_name"], "Claude Code");
            break first["id"].as_str().unwrap().to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };

    let decided = client()
        .post(format!("http://{}/decide", harness.admin))
        .bearer_auth(&harness.admin_token)
        .json(&serde_json::json!({ "id": id, "verdict": "allow" }))
        .send()
        .await
        .unwrap();
    assert_eq!(decided.status(), 200);

    let response = call.await.unwrap();
    assert_eq!(response.status(), 200);
    let seen: Value = response.json().await.unwrap();
    assert_eq!(seen["x-api-key"], UPSTREAM_KEY);
}

#[tokio::test]
async fn the_control_plane_refuses_an_unauthenticated_operator() {
    let harness = spawn_proxy("").await;
    let response = client()
        .get(format!("http://{}/pending", harness.admin))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    let wrong = client()
        .get(format!("http://{}/status", harness.admin))
        .bearer_auth("not-the-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
}

#[tokio::test]
async fn mcp_calls_are_authorized_through_the_same_policy() {
    let harness = spawn_proxy(
        r#"
[[acl]]
name = "mcp-handshake"
kind = "mcp"
target = "notes"
methods = ["initialize", "tools/list", "notifications/*"]
action = "allow"

[[acl]]
name = "mcp-reads"
kind = "mcp"
target = "notes"
methods = ["tools/call"]
paths = ["read_*"]
action = "allow"
"#,
    )
    .await;

    let authorize = |method: &'static str, path: &'static str| {
        let url = format!("http://{}/authorize", harness.admin);
        async move {
            client()
                .post(url)
                .bearer_auth(AGENT_TOKEN)
                .json(&serde_json::json!({
                    "kind": "mcp",
                    "target": "notes",
                    "method": method,
                    "path": path,
                }))
                .send()
                .await
                .unwrap()
                .json::<Value>()
                .await
                .unwrap()
        }
    };

    assert_eq!(authorize("initialize", "").await["allowed"], true);
    assert_eq!(authorize("tools/call", "read_note").await["allowed"], true);

    let blocked = authorize("tools/call", "delete_note").await;
    assert_eq!(blocked["allowed"], false);
    assert_eq!(blocked["rule"], "<default>");

    // An agent scoped to `echo` alone cannot reach a different server's policy.
    let other = client()
        .post(format!("http://{}/authorize", harness.admin))
        .bearer_auth(AGENT_TOKEN)
        .json(&serde_json::json!({
            "kind": "mcp", "target": "somewhere-else", "method": "tools/call", "path": "x"
        }))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(other["allowed"], false);
    assert_eq!(other["rule"], "<agent-targets>");
}

#[tokio::test]
async fn every_decision_lands_in_a_verifiable_audit_log() {
    let harness = spawn_proxy("").await;

    client()
        .get(format!("http://{}/echo/v1/models", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    client()
        .delete(format!("http://{}/echo/v1/models/opus", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    client()
        .get(format!("http://{}/echo/v1/models", harness.proxy))
        .bearer_auth("iap_wrong")
        .send()
        .await
        .unwrap();

    let report = audit::verify_file(&harness.audit_path).unwrap();
    assert!(report.entries >= 4, "startup + three calls");

    let events: Vec<Value> = std::fs::read_to_string(&harness.audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    let allowed = events
        .iter()
        .find(|e| e["decision"] == "allow")
        .expect("the allowed call was recorded");
    assert_eq!(allowed["agent"], "claude");
    assert_eq!(allowed["target"], "echo");
    assert_eq!(allowed["path"], "/v1/models");
    assert_eq!(allowed["rule"], "read-models");
    assert_eq!(allowed["status"], 200);

    let denied = events
        .iter()
        .find(|e| e["decision"] == "deny" && e["method"] == "DELETE")
        .expect("the denied call was recorded");
    assert_eq!(denied["rule"], "<default>");
    assert_eq!(denied["status"], 403);

    let anonymous = events
        .iter()
        .find(|e| e["agent"] == "<unknown>")
        .expect("the rejected token was recorded");
    assert_eq!(anonymous["rule"], "<authentication>");

    // An attempt with no token at all is worth recording too.
    client()
        .get(format!("http://{}/echo/v1/models", harness.proxy))
        .send()
        .await
        .unwrap();
    let events: Vec<Value> = std::fs::read_to_string(&harness.audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(
        events.iter().any(|e| e["agent"] == "<anonymous>"),
        "an unauthenticated attempt must still be logged"
    );
    audit::verify_file(&harness.audit_path).unwrap();
}

/// The control plane authenticates *before* it parses anything.
///
/// Handler-body checks run after axum's extractors, so an anonymous `POST
/// /decide` with a malformed body used to be answered by the JSON extractor —
/// 422, naming the fields it wanted. On a control plane reachable from an agent
/// VLAN that is a free schema description for someone who has proven nothing.
#[tokio::test]
async fn the_control_plane_authenticates_before_it_parses_a_body() {
    let harness = spawn_proxy("").await;

    let malformed = client()
        .post(format!("http://{}/decide", harness.admin))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        malformed.status(),
        401,
        "an unauthenticated caller must not reach the body parser"
    );
    let body = malformed.text().await.unwrap();
    assert!(
        !body.contains("verdict"),
        "the 401 leaked the request schema: {body}"
    );

    // No body at all, and no content-type: still the same answer.
    let bare = client()
        .post(format!("http://{}/decide", harness.admin))
        .send()
        .await
        .unwrap();
    assert_eq!(bare.status(), 401);

    for route in ["status", "pending", "events"] {
        let anonymous = client()
            .get(format!("http://{}/{route}", harness.admin))
            .send()
            .await
            .unwrap();
        assert_eq!(
            anonymous.status(),
            401,
            "/{route} answered an anonymous GET"
        );
    }
}

/// The gate has to still let the operator through, by either header spelling.
#[tokio::test]
async fn the_admin_token_still_opens_the_control_plane() {
    let harness = spawn_proxy("").await;

    let bearer = client()
        .get(format!("http://{}/status", harness.admin))
        .bearer_auth(&harness.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(bearer.status(), 200);

    let header = client()
        .get(format!("http://{}/pending", harness.admin))
        .header("x-iap-token", &harness.admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(header.status(), 200);

    // `/health` is unauthenticated on purpose — the MCP bridge proves the
    // policy authority exists before it accepts a message.
    let health = client()
        .get(format!("http://{}/health", harness.admin))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
}

/// Widening the proxy to a VLAN must not widen the operator surface with it.
#[tokio::test]
async fn overriding_the_proxy_listen_leaves_the_control_plane_where_it_was() {
    let mut config: mcp_iap::config::Config = toml::from_str(
        r#"
[server]
listen = "127.0.0.1:8080"
admin_listen = "127.0.0.1:8081"

[audit]
path = "audit/iap-audit.jsonl"

[acl_default]
action = "deny"
"#,
    )
    .unwrap();

    config.server.override_listen("0.0.0.0:18080").unwrap();

    assert_eq!(config.server.listen.to_string(), "0.0.0.0:18080");
    assert_eq!(
        config.server.admin_listen.map(|a| a.to_string()).as_deref(),
        Some("127.0.0.1:8081"),
        "`--listen` must never move the control plane onto another interface"
    );
}

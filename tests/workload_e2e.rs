//! Workload identity, end to end.
//!
//! The property under test is the one the whole feature exists for: what goes on
//! the data plane is a token that expires, that covers only what this run asked
//! for, and that stops working the moment it is renewed or revoked — while the
//! ACL keeps the last word on all of it.

use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use mcp_iap::config::Config;
use mcp_iap::state::AppState;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;

const AGENT_TOKEN: &str = "iap_agent_token";
const UPSTREAM_KEY: &str = "sk-upstream-real";

async fn spawn_upstream() -> SocketAddr {
    async fn echo(request: Request) -> Json<Value> {
        let headers = request.headers().clone();
        Json(json!({
            "path": request.uri().path(),
            "x-api-key": headers.get("x-api-key").and_then(|v| v.to_str().ok()),
            "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()),
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
    control: SocketAddr,
    audit_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn spawn(mode: &str) -> Harness {
    let upstream = spawn_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");

    let config_text = format!(
        r#"
[server]
listen = "127.0.0.1:0"
admin_listen = "127.0.0.1:0"

[server.workload_identity]
mode = "{mode}"
lifetime_secs = 900

[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
name = "Claude Code"
token_sha256 = "{token_hash}"
targets = ["echo", "notes"]

[[agents]]
id = "other"
token_sha256 = "{other_hash}"
targets = ["notes"]

[[upstreams]]
name = "echo"
base_url = "http://{upstream}"
auth = {{ type = "header", header = "x-api-key", secret = "literal:{key}" }}

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
"#,
        audit = audit_path.display(),
        token_hash = mcp_iap::identity::token_hash(AGENT_TOKEN),
        other_hash = mcp_iap::identity::token_hash("iap_other_token"),
        key = UPSTREAM_KEY,
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

    let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control = control_listener.local_addr().unwrap();
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            axum::serve(control_listener, mcp_iap::admin::router(state))
                .await
                .unwrap();
        });
    }

    Harness {
        proxy,
        control,
        audit_path,
        _dir: dir,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

/// Mint with the agent token, and return the whole response body.
async fn mint_raw(harness: &Harness, body: Value) -> (reqwest::StatusCode, Value) {
    let response = client()
        .post(format!("http://{}/_iap/token", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    (status, response.json().await.unwrap())
}

async fn mint(harness: &Harness, scope: Value) -> Value {
    let (status, body) = mint_raw(harness, json!({ "scope": scope })).await;
    assert_eq!(status, 200, "{body}");
    body
}

/// The scope the happy-path tests use: exactly one call.
fn send_messages() -> Value {
    json!([{ "kind": "http", "target": "echo", "methods": ["POST"], "paths": ["/v1/messages"] }])
}

async fn call(harness: &Harness, token: &str, method: &str, path: &str) -> reqwest::Response {
    client()
        .request(
            method.parse().unwrap(),
            format!("http://{}/echo{path}", harness.proxy),
        )
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
}

fn audit(harness: &Harness) -> Vec<Value> {
    std::fs::read_to_string(&harness.audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn a_workload_token_reaches_the_upstream_and_the_agent_token_never_does() {
    let harness = spawn("required").await;
    let minted = mint(&harness, send_messages()).await;
    let token = minted["token"].as_str().unwrap();

    assert_eq!(minted["token_type"], "Bearer");
    assert_eq!(minted["expires_in"], 900);
    assert_eq!(minted["generation"], 0);

    let response = call(&harness, token, "POST", "/v1/messages").await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-iap-decision"], "allow");
    let seen: Value = response.json().await.unwrap();
    assert_eq!(seen["x-api-key"], UPSTREAM_KEY);
    // The workload token stopped at the proxy along with everything else.
    assert!(seen["authorization"].is_null());

    // And the agent token, which still authenticates, is no longer a key.
    let refused = call(&harness, AGENT_TOKEN, "POST", "/v1/messages").await;
    assert_eq!(refused.status(), 401);
    assert_eq!(
        refused.headers()["x-iap-decision"],
        "workload_token_required"
    );

    // Neither credential is anywhere in the log.
    let log = std::fs::read_to_string(&harness.audit_path).unwrap();
    assert!(!log.contains(AGENT_TOKEN));
    assert!(!log.contains(token));
}

#[tokio::test]
async fn a_scope_narrows_what_the_policy_would_otherwise_allow() {
    let harness = spawn("required").await;
    let token = mint(&harness, send_messages()).await["token"]
        .as_str()
        .unwrap()
        .to_string();

    // `read-models` allows this for the agent. The token did not ask for it, so
    // it does not get it — least privilege the workload opted into.
    let response = call(&harness, &token, "GET", "/v1/models").await;
    assert_eq!(response.status(), 403);
    assert_eq!(response.headers()["x-iap-decision"], "scope_exceeded");

    let denied = audit(&harness)
        .into_iter()
        .find(|record| record["rule"] == "<workload-scope>")
        .expect("the refusal is audited against the scope, not the ACL");
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["agent"], "claude");
}

#[tokio::test]
async fn a_scope_can_never_widen_past_the_acl() {
    let harness = spawn("required").await;
    // Ask for everything on a target the agent may address. The mint succeeds —
    // a scope is a request, not a grant — and the ACL still refuses the call.
    let token = mint(
        &harness,
        json!([{ "kind": "http", "target": "echo", "methods": ["*"], "paths": ["/**"] }]),
    )
    .await["token"]
        .as_str()
        .unwrap()
        .to_string();

    let allowed = call(&harness, &token, "POST", "/v1/messages").await;
    assert_eq!(allowed.status(), 200);

    let denied = call(&harness, &token, "DELETE", "/v1/everything").await;
    assert_eq!(denied.status(), 403);
    assert_eq!(denied.headers()["x-iap-decision"], "policy_denied");
}

#[tokio::test]
async fn renewing_invalidates_the_token_that_renewed_it() {
    let harness = spawn("required").await;
    let first = mint(&harness, send_messages()).await;
    let first_token = first["token"].as_str().unwrap().to_string();

    let renewed: Value = client()
        .post(format!("http://{}/_iap/token/renew", harness.proxy))
        .bearer_auth(&first_token)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(renewed["lineage"], first["lineage"]);
    assert_eq!(renewed["generation"], 1);
    assert_eq!(renewed["replaced"], first["jti"]);
    let second_token = renewed["token"].as_str().unwrap().to_string();

    // The old one is dead on arrival, and taking it out kills the lineage with
    // it: a live copy and a stolen copy look identical from here.
    let replayed = call(&harness, &first_token, "POST", "/v1/messages").await;
    assert_eq!(replayed.status(), 401);
    assert_eq!(
        replayed.headers()["x-iap-decision"],
        "workload_token_replayed"
    );

    let after = call(&harness, &second_token, "POST", "/v1/messages").await;
    assert_eq!(after.status(), 401);
    assert_eq!(after.headers()["x-iap-decision"], "workload_token_revoked");

    // The replay is attributable. "Somebody is holding a copy of one of your
    // tokens" is the one event here worth waking a human for, and the first
    // thing they ask is whose.
    let replay = audit(&harness)
        .into_iter()
        .find(|record| record["rule"] == "<workload-token-replayed>")
        .expect("a replay is a record, not just a status code");
    assert_eq!(replay["agent"], "claude");
    assert_eq!(replay["detail"]["lineage"], first["lineage"]);
    assert_eq!(replay["detail"]["revoked"], "lineage");

    // The agent is not locked out: it still holds the credential that mints.
    let fresh = mint(&harness, send_messages()).await;
    assert_ne!(fresh["lineage"], first["lineage"]);
    assert_eq!(
        call(
            &harness,
            fresh["token"].as_str().unwrap(),
            "POST",
            "/v1/messages"
        )
        .await
        .status(),
        200
    );
}

#[tokio::test]
async fn a_renewal_may_rescope_and_the_new_scope_is_the_one_enforced() {
    let harness = spawn("required").await;
    let first = mint(&harness, send_messages()).await;

    let renewed: Value = client()
        .post(format!("http://{}/_iap/token/renew", harness.proxy))
        .bearer_auth(first["token"].as_str().unwrap())
        .json(&json!({
            "scope": [{ "kind": "http", "target": "echo", "methods": ["GET"], "paths": ["/v1/models"] }],
            "lifetime_secs": 120
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(renewed["expires_in"], 120);
    let token = renewed["token"].as_str().unwrap();
    assert_eq!(
        call(&harness, token, "GET", "/v1/models").await.status(),
        200
    );
    assert_eq!(
        call(&harness, token, "POST", "/v1/messages").await.status(),
        403,
        "the scope it renewed away from is gone"
    );
}

#[tokio::test]
async fn revoking_stops_a_token_before_it_expires() {
    let harness = spawn("required").await;
    let token = mint(&harness, send_messages()).await["token"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(
        call(&harness, &token, "POST", "/v1/messages")
            .await
            .status(),
        200
    );

    let revoked = client()
        .post(format!("http://{}/_iap/token/revoke", harness.proxy))
        .bearer_auth(&token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(revoked.status(), 200);

    let response = call(&harness, &token, "POST", "/v1/messages").await;
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["x-iap-decision"],
        "workload_token_revoked"
    );
}

#[tokio::test]
async fn a_replay_at_the_renew_endpoint_is_caught_and_recorded_too() {
    let harness = spawn("required").await;
    let first = mint(&harness, send_messages()).await;
    let renew = |token: String| async move {
        client()
            .post(format!("http://{}/_iap/token/renew", harness.proxy))
            .bearer_auth(token)
            .json(&json!({}))
            .send()
            .await
            .unwrap()
    };

    assert_eq!(
        renew(first["token"].as_str().unwrap().into())
            .await
            .status(),
        200
    );
    // Two renewals from one generation is exactly the shape of a stolen token
    // being rotated by its thief while the owner carries on.
    let second = renew(first["token"].as_str().unwrap().into()).await;
    assert_eq!(second.status(), 401);
    let body: Value = second.json().await.unwrap();
    assert_eq!(body["error"]["type"], "workload_token_replayed");

    let record = audit(&harness)
        .into_iter()
        .find(|record| record["event"] == "token_renew" && record["decision"] == "deny")
        .expect("a refused renewal is audited even though it identified nobody");
    assert_eq!(record["agent"], "claude");
    assert_eq!(record["rule"], "<workload-token-replayed>");
}

#[tokio::test]
async fn an_unproven_caller_never_gets_the_body_parsed_for_it() {
    let harness = spawn("required").await;

    // The control plane learned this the hard way: a handler-body check runs
    // after the extractors, so a bad body from nobody in particular used to be
    // answered with the field names it should have used.
    let response = client()
        .post(format!("http://{}/_iap/token", harness.proxy))
        .header("content-type", "application/json")
        .body(r#"{"scopes":[]}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
    let body = response.text().await.unwrap();
    assert!(!body.contains("lifetime_secs"), "{body}");
    assert!(!body.contains("unknown field"), "{body}");
}

#[tokio::test]
async fn a_workload_token_cannot_mint_another() {
    let harness = spawn("required").await;
    let token = mint(&harness, send_messages()).await["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Otherwise a leaked token grows itself a second lineage and rotation stops
    // meaning anything.
    let response = client()
        .post(format!("http://{}/_iap/token", harness.proxy))
        .bearer_auth(&token)
        .json(&json!({ "scope": send_messages() }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn a_scope_is_checked_against_the_agents_targets_at_mint_time() {
    let harness = spawn("required").await;

    // Not a configured target at all.
    let (status, body) = mint_raw(&harness, json!({ "scope": [{ "target": "stripe" }] })).await;
    assert_eq!(status, 400);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not a configured upstream"));

    // A kind that contradicts the target can never match anything, so it is a
    // mistake worth catching now rather than an hour of silent 403s later.
    let (status, body) = mint_raw(
        &harness,
        json!({ "scope": [{ "kind": "http", "target": "notes" }] }),
    )
    .await;
    assert_eq!(status, 400);
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("MCP server"));

    // And a scope has to say something.
    let (status, _) = mint_raw(&harness, json!({ "scope": [] })).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn an_agent_that_may_not_address_a_target_cannot_scope_itself_to_it() {
    let harness = spawn("required").await;

    // `other` is confined to `notes`. Scoping is not a way around that, and the
    // refusal lands at mint time rather than on every call for the next hour.
    let response = client()
        .post(format!("http://{}/_iap/token", harness.proxy))
        .bearer_auth("iap_other_token")
        .json(&json!({ "scope": [{ "target": "echo" }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("may not address"));

    let (status, body) = mint_raw(&harness, json!({ "scope": [{ "target": "notes" }] })).await;
    assert_eq!(status, 200, "{body}: `claude` lists `notes` as a target");
}

#[tokio::test]
async fn the_mint_and_the_calls_it_covers_are_both_in_the_log() {
    let harness = spawn("required").await;
    let minted = mint(&harness, send_messages()).await;
    call(
        &harness,
        minted["token"].as_str().unwrap(),
        "POST",
        "/v1/messages",
    )
    .await;

    let records = audit(&harness);
    let mint_record = records
        .iter()
        .find(|record| record["event"] == "token_mint")
        .expect("the mint is a first-class event");
    assert_eq!(mint_record["agent"], "claude");
    assert_eq!(mint_record["decision"], "issued");
    assert_eq!(
        mint_record["detail"]["scope"][0], "http echo POST /v1/messages",
        "the scope is the interesting part of the record"
    );

    // Every call made under the token is attributable to it, not just to the
    // agent: `lineage/generation`, which is the mint record's `workload` too.
    let call_record = records
        .iter()
        .find(|record| record["event"] == "request" && record["status"] == 200)
        .expect("the proxied call is recorded");
    assert_eq!(call_record["workload"], mint_record["workload"]);
    assert_eq!(call_record["decision"], "allow");
    assert_eq!(call_record["rule"], "send-messages");

    // The startup record says which posture this process came up in.
    assert_eq!(
        records[0]["detail"]["workload_identity"], "required",
        "how this process treats identity is evidence"
    );
}

#[tokio::test]
async fn optional_mode_takes_either_credential() {
    let harness = spawn("optional").await;

    // The migration setting: nothing that worked before stops working…
    assert_eq!(
        call(&harness, AGENT_TOKEN, "POST", "/v1/messages")
            .await
            .status(),
        200
    );

    // …and a workload token is accepted alongside it.
    let token = mint(&harness, send_messages()).await["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        call(&harness, &token, "POST", "/v1/messages")
            .await
            .status(),
        200
    );

    // The log tells them apart, which is what makes a migration finishable.
    let records = audit(&harness);
    let requests: Vec<_> = records
        .iter()
        .filter(|record| record["event"] == "request")
        .collect();
    assert!(requests[0]["workload"].is_null());
    assert!(requests[1]["workload"].is_string());
}

#[tokio::test]
async fn off_means_off() {
    let harness = spawn("off").await;

    let (status, _) = mint_raw(&harness, json!({ "scope": send_messages() })).await;
    assert_eq!(status, 403);
    assert_eq!(
        call(&harness, AGENT_TOKEN, "POST", "/v1/messages")
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn the_control_plane_serves_the_same_endpoints_for_the_bridge() {
    let harness = spawn("required").await;

    // The bridge never sees the proxy listener, so `required` would lock it out
    // if the token endpoints lived only there.
    let minted: Value = client()
        .post(format!("http://{}/token", harness.control))
        .bearer_auth(AGENT_TOKEN)
        .json(&json!({
            "workload": "mcp-bridge/notes",
            "scope": [{ "kind": "mcp", "target": "notes" }]
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = minted["token"].as_str().unwrap();

    // And it can ask the policy authority under that token.
    let allowed: Value = client()
        .post(format!("http://{}/authorize", harness.control))
        .bearer_auth(token)
        .json(&json!({ "kind": "mcp", "target": "notes", "method": "tools/call", "path": "delete_everything" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Default deny still decides; the scope just got it that far.
    assert_eq!(allowed["allowed"], false);
    assert_eq!(allowed["rule"], "<default>");

    // A call outside the scope never reaches the ACL.
    let outside: Value = client()
        .post(format!("http://{}/authorize", harness.control))
        .bearer_auth(token)
        .json(
            &json!({ "kind": "http", "target": "echo", "method": "POST", "path": "/v1/messages" }),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(outside["rule"], "<workload-scope>");

    // `/health` tells the bridge to mint in the first place.
    let health: Value = client()
        .get(format!("http://{}/health", harness.control))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["workload_identity"], "required");
}

#[tokio::test]
async fn a_token_says_what_it_covers_when_asked() {
    let harness = spawn("required").await;
    let minted = mint(&harness, send_messages()).await;

    let introspected: Value = client()
        .get(format!("http://{}/_iap/token", harness.proxy))
        .bearer_auth(minted["token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(introspected["agent"], "claude");
    assert_eq!(introspected["jti"], minted["jti"]);
    assert_eq!(introspected["scope"], send_messages());
    assert!(introspected["expires_in"].as_i64().unwrap() > 0);
}

#[tokio::test]
async fn nonsense_at_the_data_plane_is_told_apart_from_a_stale_token() {
    let harness = spawn("optional").await;

    // A token-shaped thing that is not ours is a bad token, not an unknown agent.
    let forged = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjbGF1ZGUifQ.c2ln";
    let response = call(&harness, forged, "POST", "/v1/messages").await;
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["x-iap-decision"],
        "invalid_workload_token"
    );

    // An agent token that is simply wrong still reads as an unknown agent.
    let response = call(&harness, "iap_nope", "POST", "/v1/messages").await;
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["x-iap-decision"], "unknown_agent");
}

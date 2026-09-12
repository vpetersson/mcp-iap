//! The control plane.
//!
//! Two audiences, two credentials. A human operator (the TUI, or curl) uses the
//! admin token to see and answer the approval queue. The MCP bridge uses an
//! *agent* token — or a workload token minted from one, which is what it does
//! when the policy file asks for it — to ask this process, the single policy
//! authority, whether a JSON-RPC call may proceed, so policy and audit never
//! fork across processes.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::acl::{AccessRequest, Kind};
use crate::approval::{PendingView, Verdict};
use crate::audit::AuditRecord;
use crate::config::Action;
use crate::identity::agent_may_address;
use crate::state::AppState;

pub fn router(state: Arc<AppState>) -> Router {
    // Operator routes authenticate in a `route_layer`, not in the handlers.
    // Handler-body checks run *after* axum has already run the extractors, so
    // `POST /decide` with a bad body used to answer an anonymous caller with a
    // deserialization error naming the fields it expected — the body was parsed
    // before anyone asked who was calling. A layer runs first, so an unproven
    // caller gets 401 and nothing else.
    let operator = Router::new()
        .route("/status", get(status))
        .route("/pending", get(pending))
        .route("/decide", post(decide))
        .route("/events", get(events))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_admin,
        ));

    // These two are the MCP bridge's, and authenticate as an *agent*; they do
    // their own check because the credential is a different one.
    let bridge = Router::new()
        .route("/authorize", post(authorize))
        .route("/event", post(record_event))
        // The bridge only ever sees this listener, so the token endpoints have
        // to be reachable here too or `required` mode would lock it out.
        .merge(crate::tokens::routes(
            crate::tokens::CONTROL_PREFIX,
            state.clone(),
        ));

    Router::new()
        .route("/health", get(health))
        .merge(operator)
        .merge(bridge)
        .with_state(state)
}

/// The admin-token gate, as a layer so it precedes every extractor.
async fn require_admin(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if let Some(response) = reject_non_admin(&state, request.headers()) {
        return response;
    }
    next.run(request).await
}

/// Unauthenticated on purpose: it exposes nothing but the fact that we are up,
/// and the MCP bridge must be able to prove the policy authority exists before
/// it accepts a single message from an agent.
async fn health(State(state): State<Arc<AppState>>) -> Response {
    // The mode is here because the MCP bridge probes `/health` before it accepts
    // a message, and that is the moment it needs to know whether to exchange its
    // agent token for a workload one. Cheaper than a second round trip, and it
    // discloses a posture rather than a secret.
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "workload_identity": state.workload.mode().as_str(),
        "workload_lifetime_secs": state.workload.lifetime_secs(),
    }))
    .into_response()
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get("authorization")
        .or_else(|| headers.get("x-iap-token"))?
        .to_str()
        .ok()?;
    Some(
        value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .unwrap_or(value)
            .trim(),
    )
}

/// `Some(response)` means "not an operator" — return it and stop.
fn reject_non_admin(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let presented = bearer(headers).unwrap_or_default();
    // Agent tokens are matched by hash lookup, which gives nothing away. This
    // was the one credential compared byte-for-byte, so compare digests instead:
    // where `==` stops tells an attacker about the hash, not about the token.
    let matches =
        crate::identity::token_hash(presented) == crate::identity::token_hash(&state.admin_token);

    (!matches).then(|| error(StatusCode::UNAUTHORIZED, "admin token required"))
}

fn error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

#[derive(Serialize)]
struct StatusBody {
    version: &'static str,
    listen: String,
    agents: usize,
    upstreams: usize,
    mcp_servers: usize,
    acl_rules: usize,
    acl_default: String,
    pending: usize,
    remembered: usize,
    has_approver: bool,
    workload_identity: &'static str,
    workload_tokens: usize,
}

async fn status(State(state): State<Arc<AppState>>) -> Response {
    Json(StatusBody {
        version: env!("CARGO_PKG_VERSION"),
        listen: state.config.server.listen.to_string(),
        agents: state.agents.len(),
        upstreams: state.config.upstreams.len(),
        mcp_servers: state.config.mcp_servers.len(),
        acl_rules: state.acl.rule_count(),
        acl_default: state.acl.default_action().to_string(),
        pending: state.broker.pending_count(),
        remembered: state.broker.remembered_count(),
        has_approver: state.broker.has_approver(),
        workload_identity: state.workload.mode().as_str(),
        workload_tokens: state.workload.active_count(),
    })
    .into_response()
}

async fn pending(State(state): State<Arc<AppState>>) -> Response {
    // Polling the queue counts as watching it, so `curl` alone is enough to
    // answer an `ask` without running the TUI.
    state.broker.note_poll();
    Json::<Vec<PendingView>>(state.broker.list()).into_response()
}

#[derive(Deserialize)]
struct DecideBody {
    /// Omit to answer whichever request has been waiting longest.
    #[serde(default)]
    id: Option<String>,
    verdict: Verdict,
    #[serde(default)]
    remember: bool,
}

async fn decide(State(state): State<Arc<AppState>>, Json(body): Json<DecideBody>) -> Response {
    let delivered = match &body.id {
        Some(id) => state.broker.decide(id, body.verdict, body.remember),
        None => state.broker.decide_first(body.verdict, body.remember),
    };
    if delivered {
        Json(serde_json::json!({ "ok": true })).into_response()
    } else {
        error(StatusCode::NOT_FOUND, "no such pending request")
    }
}

async fn events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(1000);

    match std::fs::read_to_string(&state.config.audit.path) {
        Ok(text) => {
            let lines: Vec<serde_json::Value> = text
                .lines()
                .rev()
                .take(limit)
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            Json(lines).into_response()
        }
        Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

#[derive(Deserialize)]
pub struct AuthorizeBody {
    pub kind: Kind,
    pub target: String,
    pub method: String,
    #[serde(default)]
    pub path: String,
    /// Free-form context shown to the operator and stored in the audit record.
    #[serde(default)]
    pub detail: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizeResult {
    pub allowed: bool,
    pub decision: String,
    pub rule: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Ask the daemon whether an agent may perform one action. Authenticated with the
/// *agent's* token, so a delegate can only ever ask on its own behalf.
async fn authorize(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AuthorizeBody>,
) -> Response {
    let caller = match bearer(&headers).map(|token| state.authenticate(token)) {
        Some(Ok(caller)) => caller,
        Some(Err(failure)) => return error(StatusCode::UNAUTHORIZED, &failure.message()),
        None => return error(StatusCode::UNAUTHORIZED, "unknown agent token"),
    };
    let agent = caller.agent();

    let access = AccessRequest {
        agent: agent.id.clone(),
        kind: body.kind,
        target: body.target.clone(),
        method: body.method.clone(),
        path: body.path.clone(),
    };

    let mut record = AuditRecord::new(body.kind.as_str(), "request");
    record.agent = agent.id.clone();
    record.agent_name = Some(agent.display_name().to_string());
    record.workload = caller.label();
    record.target = body.target.clone();
    record.method = body.method.clone();
    record.path = body.path.clone();
    record.detail = body.detail.clone();

    // Same order as the proxy: what the credential covers, then what policy
    // allows. A bridge asking about a tool its token was not minted for is
    // refused here, before the ACL and before any credential is resolved.
    if !caller.permits(&access) {
        record.decision = Some("deny".into());
        record.rule = Some("<workload-scope>".into());
        state.audit.write_best_effort(record);
        return Json(AuthorizeResult {
            allowed: false,
            decision: "deny".into(),
            rule: "<workload-scope>".into(),
            reason: Some(format!(
                "the workload token does not cover `{}` on `{}`",
                access.summary(),
                body.target
            )),
        })
        .into_response();
    }

    if !agent_may_address(agent, &body.target) {
        record.decision = Some("deny".into());
        record.rule = Some("<agent-targets>".into());
        state.audit.write_best_effort(record);
        return Json(AuthorizeResult {
            allowed: false,
            decision: "deny".into(),
            rule: "<agent-targets>".into(),
            reason: Some(format!(
                "agent `{}` may not address `{}`",
                agent.id, body.target
            )),
        })
        .into_response();
    }

    let decision = state.acl.evaluate(&access);
    record.rule = Some(decision.rule_label().to_string());

    let result = match decision.action {
        Action::Allow => {
            record.decision = Some("allow".into());
            AuthorizeResult {
                allowed: true,
                decision: "allow".into(),
                rule: decision.rule_label().to_string(),
                reason: None,
            }
        }
        Action::Deny => {
            record.decision = Some("deny".into());
            AuthorizeResult {
                allowed: false,
                decision: "deny".into(),
                rule: decision.rule_label().to_string(),
                reason: Some(format!("denied by policy `{}`", decision.rule_label())),
            }
        }
        Action::Ask => {
            let outcome = state.broker.ask(&access, agent.display_name()).await;
            record.decision = Some(outcome.label().to_string());
            AuthorizeResult {
                allowed: outcome.verdict() == Verdict::Allow,
                decision: outcome.label().to_string(),
                rule: decision.rule_label().to_string(),
                reason: (outcome.verdict() == Verdict::Deny)
                    .then(|| format!("held for approval and not allowed ({})", outcome.label())),
            }
        }
    };

    // Same rule as the proxy: an allow that cannot be recorded is not an allow.
    if let Err(error) = state.audit.write(record) {
        tracing::error!(
            ?error,
            "refusing an authorization that could not be audited"
        );
        if result.allowed {
            return Json(AuthorizeResult {
                allowed: false,
                decision: "audit_unavailable".into(),
                rule: result.rule,
                reason: Some("permitted by policy but not recordable, so refused".into()),
            })
            .into_response();
        }
    }
    Json(result).into_response()
}

#[derive(Deserialize)]
struct EventBody {
    kind: Kind,
    /// One of a small whitelist so a delegate cannot forge decision records.
    event: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    detail: Option<serde_json::Value>,
}

const DELEGATE_EVENTS: &[&str] = &["session_start", "session_end", "error", "response"];

/// Let a delegate (the MCP bridge) contribute non-decision records to the one log.
async fn record_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<EventBody>,
) -> Response {
    let caller = match bearer(&headers).map(|token| state.authenticate(token)) {
        Some(Ok(caller)) => caller,
        Some(Err(failure)) => return error(StatusCode::UNAUTHORIZED, &failure.message()),
        None => return error(StatusCode::UNAUTHORIZED, "unknown agent token"),
    };
    let agent = caller.agent();
    if !DELEGATE_EVENTS.contains(&body.event.as_str()) {
        return error(
            StatusCode::BAD_REQUEST,
            "a delegate may only record session_start, session_end, response or error",
        );
    }
    // The MCP bridge calls this before it resolves any credential, so this is
    // where an agent reaching for a server it was never granted gets stopped —
    // ahead of the key existing in a process the agent controls.
    if !body.target.is_empty() && !agent_may_address(agent, &body.target) {
        return error(
            StatusCode::FORBIDDEN,
            "this agent may not address that target",
        );
    }

    let mut record = AuditRecord::new(body.kind.as_str(), &body.event);
    record.agent = agent.id.clone();
    record.agent_name = Some(agent.display_name().to_string());
    record.workload = caller.label();
    record.target = body.target;
    record.method = body.method;
    record.path = body.path;
    record.error = body.error;
    record.detail = body.detail;
    if state.audit.write_best_effort(record).is_none() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the event could not be written to the audit log",
        );
    }

    Json(serde_json::json!({ "ok": true })).into_response()
}

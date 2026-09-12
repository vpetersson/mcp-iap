//! The token endpoints: mint, renew, revoke, introspect.
//!
//! Mounted on both listeners, because both audiences need them: an agent going
//! through the proxy exchanges its token at `/_iap/token`, and the MCP bridge —
//! which only ever talks to the control plane — does the same at `/token`. Same
//! handlers, same rules, two prefixes.
//!
//! Minting authenticates with the *agent* token and nothing else: a workload
//! token cannot mint, so a leaked one cannot grow itself a fresh lineage. It can
//! only renew, which rotates it rather than adding to it.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::audit::AuditRecord;
use crate::config::AgentConfig;
use crate::identity::agent_may_address;
use crate::state::AppState;
use crate::workload::{Grant, Minted, Scope, Verified, WorkloadError};

/// The proxy's copy, under the `_iap` prefix that keeps it out of the upstream
/// namespace — `/<upstream>/<path>` is every other path on that listener.
pub const PROXY_PREFIX: &str = "/_iap";

/// The control plane's copy, where the MCP bridge finds it.
pub const CONTROL_PREFIX: &str = "";

/// Mount the endpoints under one of the two prefixes. Nesting is deliberately
/// not used: the proxy already routes `/_iap/health` explicitly, and one flat
/// route table is easier to be sure about than a nest overlapping a route.
pub fn routes(prefix: &str, state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route(&format!("{prefix}/token"), post(mint).get(introspect))
        .route(&format!("{prefix}/token/renew"), post(renew))
        .route(&format!("{prefix}/token/revoke"), post(revoke))
        // Authenticate ahead of the extractors, for the reason the control
        // plane already does: a handler-body check runs *after* axum has parsed
        // the JSON, so a malformed body from nobody in particular is answered
        // with the field names it should have used. A layer runs first.
        .route_layer(axum::middleware::from_fn_with_state(state, require_caller))
}

/// A caller worth reading a body for: some agent's token, or something this
/// process signed. Which of the two each endpoint actually wants is the
/// handler's business — this only decides whether to keep listening.
async fn require_caller(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let presented = bearer(request.headers()).unwrap_or_default();
    let known =
        state.agents.authenticate(&presented).is_some() || state.workload.is_ours(&presented);
    if !known {
        return error(
            StatusCode::UNAUTHORIZED,
            "unknown_agent",
            "the token is not recognised".into(),
        );
    }
    next.run(request).await
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MintBody {
    /// What this run calls itself. Audited, never authorising.
    #[serde(default)]
    workload: Option<String>,
    #[serde(default)]
    scope: Vec<Grant>,
    /// Ask for less than the policy's ceiling. Asking for more gets the ceiling.
    #[serde(default)]
    lifetime_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewBody {
    /// Omit to carry the current scope over. Present, it replaces it — a
    /// renewal is a fresh mint that keeps the lineage.
    #[serde(default)]
    scope: Option<Vec<Grant>>,
    #[serde(default)]
    lifetime_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeBody {
    /// Revoking ends the workload by default, not just the current token: a
    /// caller that meant to keep going would have renewed.
    #[serde(default = "yes")]
    lineage: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Serialize)]
struct TokenBody {
    token: String,
    token_type: &'static str,
    expires_in: i64,
    expires_at: String,
    jti: String,
    lineage: String,
    generation: u32,
    scope: Vec<Grant>,
    /// On a renewal, the token that just stopped working.
    #[serde(skip_serializing_if = "Option::is_none")]
    replaced: Option<String>,
}

impl From<Minted> for TokenBody {
    fn from(minted: Minted) -> Self {
        TokenBody {
            token: minted.token,
            token_type: "Bearer",
            expires_in: minted.expires_in,
            expires_at: chrono::DateTime::from_timestamp(minted.expires_at, 0)
                .unwrap_or_default()
                .to_rfc3339(),
            jti: minted.jti,
            lineage: minted.lineage,
            generation: minted.generation,
            scope: minted.scope,
            replaced: minted.replaced,
        }
    }
}

fn error(status: StatusCode, code: &str, message: String) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": { "type": code, "message": message },
            "proxy": "mcp-iap",
        })),
    )
        .into_response()
}

fn refuse(error_: &WorkloadError) -> Response {
    let status = match error_ {
        WorkloadError::BadRequest(_) => StatusCode::BAD_REQUEST,
        WorkloadError::Disabled => StatusCode::FORBIDDEN,
        _ => StatusCode::UNAUTHORIZED,
    };
    error(status, error_.code(), error_.message())
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-iap-token").and_then(|v| v.to_str().ok()) {
        return Some(value.trim().to_string());
    }
    let value = headers.get("authorization")?.to_str().ok()?;
    Some(
        value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
            .unwrap_or(value)
            .trim()
            .to_string(),
    )
}

/// Mint. The agent token is the only credential that works here, in every mode.
async fn mint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<MintBody>>,
) -> Response {
    let Some(agent) = bearer(&headers).and_then(|token| state.agents.authenticate(&token)) else {
        // Specifically the agent registry, not `state.authenticate`: presenting
        // a workload token here is a caller error, and saying so beats handing
        // out a second lineage to whoever is holding the first.
        return error(
            StatusCode::UNAUTHORIZED,
            "unknown_agent",
            "minting a workload token takes the agent token, not a workload token".into(),
        );
    };
    let Json(body) = body.unwrap_or(Json(MintBody {
        workload: None,
        scope: Vec::new(),
        lifetime_secs: None,
    }));

    let scope = match compile_scope(&state, &agent, body.scope) {
        Ok(scope) => scope,
        Err(error_) => return refuse(&error_),
    };

    match state
        .workload
        .mint(&agent.id, body.workload.clone(), scope, body.lifetime_secs)
    {
        Ok(minted) => {
            record(&state, &agent, "token_mint", &minted, None);
            Json(TokenBody::from(minted)).into_response()
        }
        Err(error_) => {
            rejected(&state, "token_mint", &error_);
            refuse(&error_)
        }
    }
}

/// Renew. Takes the workload token being rotated, and retires it.
async fn renew(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<RenewBody>>,
) -> Response {
    let presented = match verify(&state, &headers) {
        Ok(token) => token,
        // A refused renewal is audited even though nobody is identified: a
        // replay caught here is the same signal as one caught on the data
        // plane, and it would otherwise leave no trace at all.
        Err(error_) => {
            rejected(&state, "token_renew", &error_);
            return refuse(&error_);
        }
    };
    let Some(agent) = state.agents.by_id(&presented.agent) else {
        return refuse(&WorkloadError::UnknownAgent(presented.agent.clone()));
    };
    let Json(body) = body.unwrap_or(Json(RenewBody {
        scope: None,
        lifetime_secs: None,
    }));

    // Re-scoping on renewal goes through the same checks a mint does. The agent
    // may have lost a target since the lineage started, and a renewal is not a
    // grandfather clause.
    let scope = match body.scope {
        Some(grants) => match compile_scope(&state, &agent, grants) {
            Ok(scope) => Some(scope),
            Err(error_) => return refuse(&error_),
        },
        None => None,
    };

    match state.workload.renew(&presented, scope, body.lifetime_secs) {
        Ok(minted) => {
            record(&state, &agent, "token_renew", &minted, Some(&presented));
            Json(TokenBody::from(minted)).into_response()
        }
        Err(error_) => {
            rejected(&state, "token_renew", &error_);
            refuse(&error_)
        }
    }
}

/// Hand a token back before it expires. The honest end of a finished workload.
async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<RevokeBody>>,
) -> Response {
    let presented = match verify(&state, &headers) {
        Ok(token) => token,
        Err(error_) => {
            rejected(&state, "token_revoke", &error_);
            return refuse(&error_);
        }
    };
    let Json(body) = body.unwrap_or(Json(RevokeBody { lineage: true }));

    state.workload.revoke(&presented.jti, body.lineage);

    let mut audit = AuditRecord::new("identity", "token_revoke");
    audit.agent = presented.agent.clone();
    audit.workload = Some(presented.label());
    audit.method = "revoke".into();
    audit.decision = Some("revoked".into());
    audit.detail = Some(serde_json::json!({
        "jti": presented.jti,
        "lineage": presented.lineage,
        "whole_lineage": body.lineage,
    }));
    state.audit.write_best_effort(audit);

    Json(serde_json::json!({ "revoked": true, "lineage": body.lineage })).into_response()
}

/// What the token this caller is holding actually covers. Read-only, and it
/// tells the holder nothing it could not decode from the token itself.
async fn introspect(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match verify(&state, &headers) {
        Ok(token) => Json(serde_json::json!({
            "agent": token.agent,
            "workload": token.workload,
            "jti": token.jti,
            "lineage": token.lineage,
            "generation": token.generation,
            "expires_at": chrono::DateTime::from_timestamp(token.expires_at, 0)
                .unwrap_or_default()
                .to_rfc3339(),
            "expires_in": (token.expires_at - chrono::Utc::now().timestamp()).max(0),
            "scope": token.scope.grants(),
        }))
        .into_response(),
        Err(error_) => refuse(&error_),
    }
}

fn verify(state: &AppState, headers: &HeaderMap) -> Result<Verified, WorkloadError> {
    if !state.workload.mode().enabled() {
        return Err(WorkloadError::Disabled);
    }
    let presented = bearer(headers).ok_or(WorkloadError::NotAToken)?;
    state.workload.verify(&presented)
}

/// Turn a requested scope into a compiled one, refusing anything this agent
/// could never use.
///
/// Not an authorisation check — the ACL does that, on every request, for as long
/// as the token lives. This only catches a scope that is *wrong* rather than
/// merely optimistic: a target that does not exist, a target this agent may not
/// address at all, a kind that contradicts the target. Those are worth a 400 at
/// mint time instead of a silent 403 an hour of requests later.
fn compile_scope(
    state: &AppState,
    agent: &AgentConfig,
    grants: Vec<Grant>,
) -> Result<Scope, WorkloadError> {
    for grant in &grants {
        let upstream = state.config.upstream(&grant.target).is_some();
        let mcp = state.config.mcp_server(&grant.target).is_some();
        if !upstream && !mcp {
            return Err(WorkloadError::BadRequest(format!(
                "`{}` is not a configured upstream or MCP server",
                grant.target
            )));
        }
        if !agent_may_address(agent, &grant.target) {
            return Err(WorkloadError::BadRequest(format!(
                "agent `{}` may not address `{}`",
                agent.id, grant.target
            )));
        }
        // A grant whose kind contradicts its target can never match anything.
        // Saying so now beats a token that looks granted and denies everything.
        let contradiction = match grant.kind.as_str() {
            "http" if mcp => Some("an MCP server"),
            "mcp" if upstream => Some("an HTTP upstream"),
            _ => None,
        };
        if let Some(what) = contradiction {
            return Err(WorkloadError::BadRequest(format!(
                "`{}` is {what}; `kind` must be `{}` or `*`",
                grant.target,
                if mcp { "mcp" } else { "http" }
            )));
        }
    }

    Scope::compile(grants).map_err(|error| WorkloadError::BadRequest(format!("{error:#}")))
}

fn record(
    state: &AppState,
    agent: &AgentConfig,
    event: &str,
    minted: &Minted,
    previous: Option<&Verified>,
) {
    let mut audit = AuditRecord::new("identity", event);
    audit.agent = agent.id.clone();
    audit.agent_name = Some(agent.display_name().to_string());
    audit.workload = Some(format!(
        "{}/{}",
        minted.lineage.chars().take(8).collect::<String>(),
        minted.generation
    ));
    audit.method = if previous.is_some() { "renew" } else { "mint" }.into();
    audit.decision = Some("issued".into());
    // The scope is the interesting part of this record: it is the list of things
    // the next hour of this agent's traffic is allowed to be.
    audit.detail = Some(serde_json::json!({
        "jti": minted.jti,
        "lineage": minted.lineage,
        "generation": minted.generation,
        "expires_in": minted.expires_in,
        "scope": minted.scope.iter().map(Grant::summary).collect::<Vec<_>>(),
        "replaces": minted.replaced,
    }));
    state.audit.write_best_effort(audit);
}

fn rejected(state: &AppState, event: &str, error: &WorkloadError) {
    let mut audit = AuditRecord::new("identity", event);
    // Only a replay knows whose token it was; everything else refused here was
    // never proven to belong to anyone.
    audit.agent = match error {
        WorkloadError::Replayed { agent, .. } => agent.clone(),
        _ => "<unknown>".to_string(),
    };
    if let WorkloadError::Replayed { lineage, .. } = error {
        audit.workload = Some(lineage.chars().take(8).collect());
        audit.detail = Some(serde_json::json!({ "lineage": lineage, "revoked": "lineage" }));
    }
    audit.decision = Some("deny".into());
    audit.rule = Some(format!("<{}>", error.code().replace('_', "-")));
    audit.error = Some(error.message());
    state.audit.write_best_effort(audit);
}

//! The data-plane HTTP proxy.
//!
//! The agent points its SDK at `http://127.0.0.1:8080/<upstream>` and
//! authenticates with its *IAP* token. The proxy checks who it is, checks the
//! ACL, writes an audit record, and only then swaps in the real credential.

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use http::{HeaderMap, HeaderName, StatusCode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::acl::AccessRequest;
use crate::approval::Verdict;
use crate::audit::AuditRecord;
use crate::config::{Action, UpstreamConfig};
use crate::identity::agent_may_address;
use crate::state::AppState;

/// Headers that belong to a single hop and must never be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

/// Headers the agent uses to talk to the *proxy*; they stop here.
const IAP_HEADERS: &[&str] = &["authorization", "x-iap-token", "x-iap-upstream", "host"];

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/_iap/health", get(health))
        .fallback(handle)
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn handle(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Response {
    match proxy(state.clone(), peer, request).await {
        Ok(response) => response,
        Err(rejection) => rejection.into_response(state.as_ref()),
    }
}

/// A refusal, carrying everything needed to both answer the agent and audit it.
struct Rejection {
    status: StatusCode,
    code: &'static str,
    message: String,
    record: Option<AuditRecord>,
}

impl Rejection {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Rejection {
            status,
            code,
            message: message.into(),
            record: None,
        }
    }

    fn with_record(mut self, record: AuditRecord) -> Self {
        self.record = Some(record);
        self
    }

    fn into_response(self, state: &AppState) -> Response {
        if let Some(mut record) = self.record {
            record.status = Some(self.status.as_u16());
            if record.error.is_none() {
                record.error = Some(self.message.clone());
            }
            state.audit.write_best_effort(record);
        }
        let body = serde_json::json!({
            "error": { "type": self.code, "message": self.message },
            "proxy": "mcp-iap",
        });
        let mut response = (self.status, axum::Json(body)).into_response();
        response
            .headers_mut()
            .insert("x-iap-decision", self.code.parse().unwrap());
        response
    }
}

async fn proxy(
    state: Arc<AppState>,
    peer: SocketAddr,
    request: Request,
) -> Result<Response, Box<Rejection>> {
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let method = parts.method.clone();
    let full_path = parts.uri.path().to_string();
    let query = parts.uri.query().map(str::to_string);

    // 1. Who is calling? The token is minted for the proxy, not for any upstream.
    let token = extract_token(&parts.headers).ok_or_else(|| {
        let mut record = AuditRecord::new("http", "denied");
        record.agent = "<anonymous>".into();
        record.method = method.to_string();
        record.path = full_path.clone();
        record.decision = Some("deny".into());
        record.rule = Some("<authentication>".into());
        record.client = Some(peer.to_string());
        Rejection::new(
            StatusCode::UNAUTHORIZED,
            "missing_credentials",
            "no agent token — send `Authorization: Bearer <iap-token>` or `X-IAP-Token`",
        )
        .with_record(record)
    })?;

    let agent = state.agents.authenticate(&token).ok_or_else(|| {
        let mut record = AuditRecord::new("http", "denied");
        record.agent = "<unknown>".into();
        record.method = method.to_string();
        record.path = full_path.clone();
        record.decision = Some("deny".into());
        record.rule = Some("<authentication>".into());
        record.client = Some(peer.to_string());
        Rejection::new(
            StatusCode::UNAUTHORIZED,
            "unknown_agent",
            "the agent token is not recognised",
        )
        .with_record(record)
    })?;

    // 2. Which upstream? `X-IAP-Upstream`, else the first path segment.
    let (upstream_name, upstream_path) = route(&parts.headers, &full_path).ok_or_else(|| {
        // Refusals are audited even here: the agent is already identified, and a
        // sweep for valid upstream names should leave a trace like anything else.
        let mut record = AuditRecord::new("http", "denied");
        record.agent = agent.id.clone();
        record.agent_name = Some(agent.display_name().to_string());
        record.method = method.to_string();
        record.path = full_path.clone();
        record.decision = Some("deny".into());
        record.rule = Some("<no-route>".into());
        record.client = Some(peer.to_string());
        Rejection::new(
            StatusCode::NOT_FOUND,
            "no_route",
            "no upstream in the request — use `/<upstream>/<path>` or set `X-IAP-Upstream`",
        )
        .with_record(record)
    })?;

    let mut record = AuditRecord::new("http", "request");
    record.agent = agent.id.clone();
    record.agent_name = Some(agent.display_name().to_string());
    record.target = upstream_name.clone();
    record.method = method.to_string();
    record.path = upstream_path.clone();
    record.client = Some(peer.to_string());

    // A path that climbs out of the upstream's base path would reach an endpoint
    // the ACL never saw — with the real credential attached.
    if let Err(reason) = check_path(&upstream_path) {
        record.decision = Some("deny".into());
        record.rule = Some("<path-traversal>".into());
        return Err(Box::new(
            Rejection::new(StatusCode::BAD_REQUEST, "invalid_path", reason).with_record(record),
        ));
    }

    let upstream: &UpstreamConfig = state.config.upstream(&upstream_name).ok_or_else(|| {
        let mut record = record.clone();
        record.decision = Some("deny".into());
        record.rule = Some("<unknown-upstream>".into());
        Rejection::new(
            StatusCode::NOT_FOUND,
            "unknown_upstream",
            format!("`{upstream_name}` is not a configured upstream"),
        )
        .with_record(record)
    })?;

    if !agent_may_address(&agent, &upstream.name) {
        record.decision = Some("deny".into());
        record.rule = Some("<agent-targets>".into());
        return Err(Box::new(
            Rejection::new(
                StatusCode::FORBIDDEN,
                "target_not_permitted",
                format!("agent `{}` may not address `{}`", agent.id, upstream.name),
            )
            .with_record(record),
        ));
    }

    // 3. What does the policy say?
    let access = AccessRequest::http(&agent.id, &upstream.name, method.as_str(), &upstream_path);
    let decision = state.acl.evaluate(&access);
    record.rule = Some(decision.rule_label().to_string());

    match decision.action {
        Action::Allow => record.decision = Some("allow".into()),
        Action::Deny => {
            record.decision = Some("deny".into());
            return Err(Box::new(
                Rejection::new(
                    StatusCode::FORBIDDEN,
                    "policy_denied",
                    format!(
                        "denied by policy `{}` — {} {} on `{}`",
                        decision.rule_label(),
                        method,
                        upstream_path,
                        upstream.name
                    ),
                )
                .with_record(record),
            ));
        }
        Action::Ask => {
            // Park the request in front of a human. Anything but an explicit
            // "allow" — timeout, no approver, an explicit no — denies.
            let outcome = state.broker.ask(&access, agent.display_name()).await;
            record.decision = Some(outcome.label().to_string());
            if outcome.verdict() == Verdict::Deny {
                return Err(Box::new(
                    Rejection::new(
                        StatusCode::FORBIDDEN,
                        "approval_denied",
                        format!(
                            "held for approval by policy `{}` and not allowed ({})",
                            decision.rule_label(),
                            outcome.label()
                        ),
                    )
                    .with_record(record),
                ));
            }
        }
    }

    // 4. Allowed. Buffer the request body, then swap in the real credential.
    let body_bytes = axum::body::to_bytes(body, state.config.server.max_body_bytes)
        .await
        .map_err(|_| {
            let mut record = record.clone();
            record.error = Some("request body exceeded max_body_bytes".into());
            Rejection::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "body_too_large",
                format!(
                    "request body exceeds max_body_bytes ({})",
                    state.config.server.max_body_bytes
                ),
            )
            .with_record(record)
        })?;
    record.request_bytes = Some(body_bytes.len() as u64);

    if state.audit.log_bodies() && !body_bytes.is_empty() {
        record.detail = Some(serde_json::json!({
            "request_headers": state.audit.redact_headers(&parts.headers),
            "request_body": state.audit.clip_body(&body_bytes),
        }));
    }

    let url = build_url(&upstream.base_url, &upstream_path, query.as_deref()).map_err(|error| {
        let mut record = record.clone();
        record.error = Some(error.to_string());
        Rejection::new(StatusCode::BAD_REQUEST, "invalid_url", error.to_string())
            .with_record(record)
    })?;

    let mut outbound = reqwest::Request::new(method.clone(), url);
    *outbound.headers_mut() = forwarded_request_headers(&parts.headers, upstream);
    *outbound.body_mut() = Some(reqwest::Body::from(body_bytes));

    state
        .injector
        .apply(&upstream.name, &upstream.auth, &mut outbound)
        .await
        .map_err(|error| {
            let mut record = record.clone();
            record.error = Some(error.to_string());
            Rejection::new(
                StatusCode::BAD_GATEWAY,
                "credential_error",
                format!("could not resolve the credential for `{}`", upstream.name),
            )
            .with_record(record)
        })?;

    let response = state.http.execute(outbound).await.map_err(|error| {
        let mut record = record.clone();
        record.error = Some(describe_upstream_error(&error));
        record.duration_ms = Some(started.elapsed().as_millis() as u64);
        Rejection::new(
            StatusCode::BAD_GATEWAY,
            "upstream_error",
            format!("upstream `{}` did not answer", upstream.name),
        )
        .with_record(record)
    })?;

    // A minted token the upstream just rejected is worth nothing; drop it so the
    // next request mints a fresh one rather than repeating the 401 until expiry.
    if matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) && upstream.auth.mints_tokens()
    {
        state.injector.invalidate(&upstream.name);
    }

    // Recorded at response headers, so streamed (SSE) responses are logged when
    // they start rather than being buffered until they finish.
    record.status = Some(response.status().as_u16());
    record.duration_ms = Some(started.elapsed().as_millis() as u64);
    record.response_bytes = response.content_length();
    // We permitted this and cannot record that we did. The agent does not get the
    // response: the log is the product here, and an unrecorded call that the
    // agent can read from is the one outcome worth refusing outright. The call
    // upstream has already happened, so say so rather than pretending otherwise.
    state.audit.write(record).map_err(|error| {
        tracing::error!(?error, "withholding a response that could not be audited");
        Box::new(Rejection::new(
            StatusCode::BAD_GATEWAY,
            "audit_unavailable",
            "the request was permitted and performed, but could not be written to the \
             audit log, so its response was withheld",
        ))
    })?;

    Ok(build_response(response))
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-iap-token").and_then(|v| v.to_str().ok()) {
        return Some(value.trim().to_string());
    }
    let authorization = headers.get("authorization")?.to_str().ok()?;
    let token = authorization
        .strip_prefix("Bearer ")
        .or_else(|| authorization.strip_prefix("bearer "))
        .unwrap_or(authorization);
    Some(token.trim().to_string())
}

/// Returns `(upstream, path-as-the-upstream-sees-it)`.
fn route(headers: &HeaderMap, path: &str) -> Option<(String, String)> {
    if let Some(name) = headers.get("x-iap-upstream").and_then(|v| v.to_str().ok()) {
        let name = name.trim();
        if !name.is_empty() {
            return Some((name.to_string(), path.to_string()));
        }
    }
    let rest = path.strip_prefix('/')?;
    let (name, tail) = match rest.split_once('/') {
        Some((name, tail)) => (name, format!("/{tail}")),
        None => (rest, "/".to_string()),
    };
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), tail))
}

/// Reject any path that could mean one thing to the ACL and another to the URL
/// parser that builds the outbound request.
///
/// `%2e%2e` is `..` to a URL parser and to nobody else, so a guard looking only
/// for a literal `..` is not a guard. Backslashes matter for the same reason:
/// the URL standard folds `\` into `/` for http(s).
fn check_path(path: &str) -> Result<(), &'static str> {
    let decoded = percent_encoding::percent_decode_str(path).decode_utf8_lossy();

    for segment in decoded.split(['/', '\\']) {
        if segment == ".." || segment == "." {
            return Err("the request path contains a `.` or `..` segment, encoded or otherwise");
        }
    }
    if decoded.contains('\0') {
        return Err("the request path contains a NUL byte");
    }
    Ok(())
}

/// Join the upstream's base URL with the proxied path, and refuse if the result
/// is not literally the path the ACL just approved.
///
/// `check_path` catches the encodings we know about; this catches the rest, by
/// comparing what policy authorised against what will actually be requested.
fn build_url(base: &str, path: &str, query: Option<&str>) -> anyhow::Result<url::Url> {
    let base = base.trim_end_matches('/');
    let base_path = url::Url::parse(base)?
        .path()
        .trim_end_matches('/')
        .to_string();
    let approved_path = format!("{base_path}{path}");

    let mut raw = base.to_string();
    raw.push_str(path);
    if let Some(query) = query {
        raw.push('?');
        raw.push_str(query);
    }

    let url = url::Url::parse(&raw)?;
    if url.path() != approved_path {
        anyhow::bail!("the request path does not survive URL normalisation unchanged");
    }
    Ok(url)
}

/// Describe an upstream failure without repeating anything from the request.
///
/// Never `error.to_string()`: reqwest's Display embeds the full outbound URL,
/// which by this point carries the injected credential for `query` auth.
fn describe_upstream_error(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "the upstream did not respond in time".to_string()
    } else if error.is_connect() {
        "could not connect to the upstream".to_string()
    } else if error.is_body() || error.is_decode() {
        "the upstream response could not be read".to_string()
    } else if error.is_redirect() {
        "the upstream redirected too many times".to_string()
    } else {
        "the upstream request failed".to_string()
    }
}

fn forwarded_request_headers(incoming: &HeaderMap, upstream: &UpstreamConfig) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in incoming {
        let key = name.as_str().to_ascii_lowercase();
        if HOP_BY_HOP.contains(&key.as_str())
            || IAP_HEADERS.contains(&key.as_str())
            || key == "content-length"
        {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    for (name, value) in &upstream.headers {
        if let (Ok(name), Ok(value)) = (name.parse::<HeaderName>(), value.parse()) {
            headers.insert(name, value);
        }
    }
    headers
}

fn build_response(response: reqwest::Response) -> Response {
    let status = response.status();
    let mut builder = Response::builder().status(status);
    for (name, value) in response.headers() {
        let key = name.as_str().to_ascii_lowercase();
        // Re-chunked downstream, so the upstream framing headers no longer apply.
        if HOP_BY_HOP.contains(&key.as_str()) || key == "content-length" {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder.header("x-iap-decision", "allow");

    // Streamed straight through: token-by-token responses stay token-by-token.
    builder
        .body(Body::from_stream(response.bytes_stream()))
        .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(name.parse::<HeaderName>().unwrap(), value.parse().unwrap());
        }
        map
    }

    #[test]
    fn token_comes_from_either_header() {
        assert_eq!(
            extract_token(&headers(&[("authorization", "Bearer iap_abc")])).as_deref(),
            Some("iap_abc")
        );
        assert_eq!(
            extract_token(&headers(&[("x-iap-token", "iap_abc")])).as_deref(),
            Some("iap_abc")
        );
        // Some SDKs send a bare token with no scheme.
        assert_eq!(
            extract_token(&headers(&[("authorization", "iap_abc")])).as_deref(),
            Some("iap_abc")
        );
        assert_eq!(extract_token(&HeaderMap::new()), None);
    }

    #[test]
    fn path_prefix_selects_the_upstream_and_is_stripped() {
        assert_eq!(
            route(&HeaderMap::new(), "/anthropic/v1/messages"),
            Some(("anthropic".into(), "/v1/messages".into()))
        );
        assert_eq!(
            route(&HeaderMap::new(), "/anthropic"),
            Some(("anthropic".into(), "/".into()))
        );
        assert_eq!(route(&HeaderMap::new(), "/"), None);
    }

    #[test]
    fn the_header_route_keeps_the_whole_path() {
        assert_eq!(
            route(&headers(&[("x-iap-upstream", "anthropic")]), "/v1/messages"),
            Some(("anthropic".into(), "/v1/messages".into()))
        );
    }

    #[test]
    fn urls_join_without_doubling_or_dropping_a_slash() {
        assert_eq!(
            build_url("https://api.example.com/", "/v1/x", None)
                .unwrap()
                .as_str(),
            "https://api.example.com/v1/x"
        );
        assert_eq!(
            build_url("https://api.example.com/base", "/v1/x", Some("a=1"))
                .unwrap()
                .as_str(),
            "https://api.example.com/base/v1/x?a=1"
        );
    }

    #[test]
    fn the_agents_own_token_never_reaches_the_upstream() {
        let upstream = UpstreamConfig {
            name: "u".into(),
            base_url: "https://example.com".into(),
            auth: crate::config::AuthConfig::None,
            headers: Default::default(),
        };
        let forwarded = forwarded_request_headers(
            &headers(&[
                ("authorization", "Bearer iap_agent_token"),
                ("x-iap-token", "iap_agent_token"),
                ("x-iap-upstream", "u"),
                ("connection", "keep-alive"),
                ("content-type", "application/json"),
            ]),
            &upstream,
        );
        assert!(forwarded.get("authorization").is_none());
        assert!(forwarded.get("x-iap-token").is_none());
        assert!(forwarded.get("x-iap-upstream").is_none());
        assert!(
            forwarded.get("connection").is_none(),
            "hop-by-hop must not be forwarded"
        );
        assert_eq!(forwarded["content-type"], "application/json");
    }
}

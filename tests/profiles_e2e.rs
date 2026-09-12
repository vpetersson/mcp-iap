//! The workflows people actually set this up for, driven end to end.
//!
//! Every test here builds its policy the way an operator would — `profile add`,
//! not a hand-written TOML fixture — and then runs a real proxy in front of a
//! mock upstream. That coupling is the point: a profile whose base URL, scheme
//! or rules are wrong fails here rather than against the vendor, and a change
//! to `enroll` that stops producing what the proxy loads cannot pass.

use axum::extract::Request;
use axum::routing::any;
use axum::{Json, Router};
use mcp_iap::config::Config;
use mcp_iap::profiles::{self, AddOptions};
use mcp_iap::state::AppState;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;

const AGENT_TOKEN: &str = "iap_workflow_agent";

/// An upstream that reports what it was sent, plus a token endpoint for the
/// service-account flow so the Google profiles can be exercised whole.
async fn spawn_upstream() -> SocketAddr {
    async fn handler(request: Request) -> Json<Value> {
        let path = request.uri().path().to_string();
        if path.ends_with("/token") {
            return Json(serde_json::json!({
                "access_token": "ya29.minted-by-the-proxy",
                "expires_in": 3600,
                "token_type": "Bearer",
            }));
        }
        let headers = request.headers().clone();
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        };
        Json(serde_json::json!({
            "path": path,
            "method": request.method().as_str(),
            "authorization": header("authorization"),
            "x-api-key": header("x-api-key"),
            "x-iap-token": header("x-iap-token"),
        }))
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(handler)))
            .await
            .unwrap();
    });
    addr
}

struct Harness {
    proxy: SocketAddr,
    _dir: tempfile::TempDir,
}

/// Build a policy file with `profile add`, repoint it at the mock, and serve it.
///
/// The rewrite is deliberately narrow: only the host of each `base_url` moves.
/// Paths, credential scheme and every ACL rule are exactly what the profile
/// wrote, so what the test exercises is the profile and not a fixture.
async fn harness_from_profiles(specs: &[(&str, AddOptions)], upstream: SocketAddr) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    let audit_path = dir.path().join("audit.jsonl");

    mcp_iap::init::init(&mcp_iap::init::InitOptions {
        path: path.clone(),
        agent: "workflow-agent".into(),
        secret: None,
        template: mcp_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();

    for (id, options) in specs {
        let profile = profiles::get(id).unwrap();
        profiles::add(&path, &profile, options)
            .unwrap_or_else(|error| panic!("profile `{id}`: {error:#}"));
    }

    let text = std::fs::read_to_string(&path).unwrap();
    let mut config: Config = toml::from_str(&text).unwrap();
    for up in &mut config.upstreams {
        let mut url = url::Url::parse(&up.base_url).unwrap();
        url.set_scheme("http").unwrap();
        url.set_host(Some(&upstream.ip().to_string())).unwrap();
        url.set_port(Some(upstream.port())).unwrap();
        up.base_url = url.to_string();
    }
    config.audit.path = audit_path;
    config.audit.stderr = false;
    config.agents = vec![toml::from_str(&format!(
        r#"
id = "workflow-agent"
token_sha256 = "{}"
"#,
        mcp_iap::identity::token_hash(AGENT_TOKEN)
    ))
    .unwrap()];
    config.validate().unwrap();

    let state = AppState::build(config, false).unwrap();
    state.log_startup().unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            mcp_iap::proxy::router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });

    Harness { proxy, _dir: dir }
}

fn options(secret: &str) -> AddOptions {
    AddOptions {
        name: None,
        secret: Some(secret.into()),
        access: None,
        vars: vec![],
        agent: None,
        dry_run: false,
    }
}

async fn call(harness: &Harness, method: &str, path: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            format!("http://{}{path}", harness.proxy),
        )
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.json().await.unwrap_or(Value::Null);
    (status, body)
}

/// A service-account key the proxy can actually sign with, pointed at the mock.
fn service_account_key(dir: &Path, token_url: &str) -> String {
    // Generated per test rather than checked in: a private key in the tree,
    // even a throwaway one, is a thing someone eventually reuses.
    let key = rsa_pkcs8_pem();
    let json = serde_json::json!({
        "type": "service_account",
        "project_id": "test",
        "private_key_id": "test-key-id",
        "private_key": key,
        "client_email": "sa@test.iam.gserviceaccount.com",
        "client_id": "1",
        "token_uri": token_url,
    });
    let path = dir.join("sa.json");
    std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();
    format!("file:{}", path.display())
}

/// Same approach as `service_account_e2e`: shell out to `openssl` for a
/// throwaway key rather than take a Rust RSA crate as a dependency. Generated
/// once per test binary, because 2048-bit keygen is not free.
fn rsa_pkcs8_pem() -> String {
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PEM.get_or_init(|| {
        let output = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("these tests need the `openssl` binary to mint a throwaway key");
        assert!(output.status.success(), "openssl genpkey failed");
        String::from_utf8(output.stdout).unwrap()
    })
    .clone()
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn cloudflare_reads_are_allowed_and_deletes_never_reach_the_network() {
    std::env::set_var("TEST_CF_TOKEN", "cf-real-token");
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_CF_TOKEN");
    opts.access = Some("ask-writes".into());
    let harness = harness_from_profiles(&[("cloudflare", opts)], upstream).await;

    let (status, seen) = call(&harness, "GET", "/cloudflare/zones").await;
    assert_eq!(status, 200);
    // The upstream got the real token, and the agent's own token did not travel.
    assert_eq!(seen["authorization"], "Bearer cf-real-token");
    assert!(seen["x-iap-token"].is_null());

    // `ask-writes` denies DELETE outright, so this must not be a round trip
    // that merely returned an error — the upstream must never have been called.
    let (status, body) = call(&harness, "DELETE", "/cloudflare/zones/abc").await;
    assert_eq!(status, 403);
    assert!(
        body["path"].is_null(),
        "a denied DELETE reached the upstream: {body}"
    );
}

#[tokio::test]
async fn dataforseo_signs_with_the_login_and_holds_back_the_billed_endpoints() {
    std::env::set_var("TEST_DFS_PASSWORD", "dfs-real-password");
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_DFS_PASSWORD");
    opts.vars = vec!["login=seo@example.com".into()];
    let harness = harness_from_profiles(&[("dataforseo", opts)], upstream).await;

    let (status, seen) = call(
        &harness,
        "POST",
        "/dataforseo/v3/serp/google/organic/task_post",
    )
    .await;
    assert_eq!(status, 200);
    let expected = base64_encode("seo@example.com:dfs-real-password");
    assert_eq!(seen["authorization"], format!("Basic {expected}"));

    // The `live` endpoints bill more, so the default level parks them for a
    // human. Nobody is watching this queue, so `ask` resolves to a denial —
    // which is the safe end of that decision, and the assertion that matters.
    let (status, _) = call(
        &harness,
        "POST",
        "/dataforseo/v3/serp/google/organic/live/advanced",
    )
    .await;
    assert_eq!(status, 403, "a billed `live` call was let through unasked");
}

#[tokio::test]
async fn graylog_authenticates_the_token_as_the_user_and_never_writes_it_down() {
    std::env::set_var("TEST_GRAYLOG_TOKEN", "graylog-real-token");
    let upstream = spawn_upstream().await;
    let mut opts = options("env:TEST_GRAYLOG_TOKEN");
    opts.vars = vec!["host=graylog.example.com:9000".into()];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    mcp_iap::init::init(&mcp_iap::init::InitOptions {
        path: path.clone(),
        agent: "a".into(),
        secret: None,
        template: mcp_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();
    let profile = profiles::get("graylog").unwrap();
    profiles::add(&path, &profile, &opts).unwrap();

    // The whole reason `username_secret` exists: the token is a reference in
    // the file, not a value, so the policy file stays committable.
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("username_secret = \"env:TEST_GRAYLOG_TOKEN\""));
    assert!(
        !written.contains("graylog-real-token"),
        "the access token was written into the policy file"
    );

    let harness = harness_from_profiles(&[("graylog", opts)], upstream).await;
    let (status, seen) = call(&harness, "GET", "/graylog/streams").await;
    assert_eq!(status, 200);
    // Graylog's documented scheme is `<token>:token`, token in the user field.
    let expected = base64_encode("graylog-real-token:token");
    assert_eq!(seen["authorization"], format!("Basic {expected}"));
}

#[tokio::test]
async fn a_google_service_account_is_exchanged_for_a_token_the_agent_never_sees() {
    let upstream = spawn_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let key = service_account_key(dir.path(), &format!("http://{upstream}/token"));

    let harness =
        harness_from_profiles(&[("google-search-console", options(&key))], upstream).await;

    // A read that is a GET.
    let (status, seen) = call(
        &harness,
        "GET",
        "/google-search-console/webmasters/v3/sites",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(seen["authorization"], "Bearer ya29.minted-by-the-proxy");

    // …and the read that is a POST. A GET-only "read" level would deny this,
    // and Search Console's actual search-analytics data would be unreachable
    // at the level named for reading it.
    let (status, seen) = call(
        &harness,
        "POST",
        "/google-search-console/webmasters/v3/sites/example.com/searchAnalytics/query",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(seen["authorization"], "Bearer ya29.minted-by-the-proxy");

    // The `read` level does not grant sitemap submission.
    let (status, body) = call(
        &harness,
        "PUT",
        "/google-search-console/webmasters/v3/sites/example.com/sitemaps/x",
    )
    .await;
    assert_eq!(status, 403);
    assert!(body["path"].is_null());
}

#[tokio::test]
async fn one_service_account_fronts_search_console_and_analytics_separately() {
    let upstream = spawn_upstream().await;
    let dir = tempfile::tempdir().unwrap();
    let key = service_account_key(dir.path(), &format!("http://{upstream}/token"));

    let harness = harness_from_profiles(
        &[
            ("google-search-console", options(&key)),
            ("google-analytics-data", options(&key)),
        ],
        upstream,
    )
    .await;

    let (status, _) = call(
        &harness,
        "GET",
        "/google-search-console/webmasters/v3/sites",
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = call(
        &harness,
        "POST",
        "/google-analytics-data/v1beta/properties/1:runReport",
    )
    .await;
    assert_eq!(status, 200);

    // Two upstreams, two scope sets, one key — and the ACL keeps them apart, so
    // a GA4 path is not reachable through the Search Console grant.
    let (status, _) = call(
        &harness,
        "POST",
        "/google-search-console/v1beta/properties/1:runReport",
    )
    .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn two_accounts_of_one_service_are_kept_apart() {
    std::env::set_var("TEST_PH_MAIN", "ph-main-key");
    std::env::set_var("TEST_PH_CLIENT", "ph-client-key");
    let upstream = spawn_upstream().await;

    let mut main = options("env:TEST_PH_MAIN");
    main.name = Some("posthog-main".into());
    let mut client = options("env:TEST_PH_CLIENT");
    client.name = Some("posthog-client".into());

    let harness = harness_from_profiles(&[("posthog", main), ("posthog", client)], upstream).await;

    let (status, seen) = call(&harness, "GET", "/posthog-main/api/projects/").await;
    assert_eq!(status, 200);
    assert_eq!(seen["authorization"], "Bearer ph-main-key");

    let (status, seen) = call(&harness, "GET", "/posthog-client/api/projects/").await;
    assert_eq!(status, 200);
    assert_eq!(
        seen["authorization"], "Bearer ph-client-key",
        "the two accounts share one credential"
    );
}

#[tokio::test]
async fn every_mcp_profile_admits_the_handshake_it_would_otherwise_deny() {
    // `initialize` names no tool, so a tool-scoped rule never matches it. Every
    // MCP profile must therefore write a session rule, or the server it just
    // configured cannot be opened at all.
    for profile in profiles::catalog() {
        if profile.service.kind() != "mcp" {
            continue;
        }
        for level in &profile.access {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("iap.toml");
            mcp_iap::init::init(&mcp_iap::init::InitOptions {
                path: path.clone(),
                agent: "a".into(),
                secret: None,
                template: mcp_iap::init::Template::Minimal,
                force: true,
            })
            .unwrap();

            let mut opts = options("env:UNUSED");
            opts.access = Some(level.name.clone());
            opts.vars = profile
                .vars
                .iter()
                .map(|var| format!("{}=placeholder", var.name))
                .collect();
            profiles::add(&path, &profile, &opts)
                .unwrap_or_else(|error| panic!("{}/{}: {error:#}", profile.id, level.name));

            let config: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            let acl = mcp_iap::acl::Acl::compile(&config).unwrap();
            let request = mcp_iap::acl::AccessRequest {
                agent: "any-agent".into(),
                kind: mcp_iap::acl::Kind::Mcp,
                target: config.mcp_servers[0].name.clone(),
                method: "initialize".into(),
                // `initialize` names no tool, which is exactly why it is the
                // one that falls through a tool-scoped rule.
                path: String::new(),
            };
            assert_eq!(
                acl.evaluate(&request).action,
                mcp_iap::config::Action::Allow,
                "{}/{}: `initialize` is not allowed, so the session never opens",
                profile.id,
                level.name
            );
        }
    }
}

#[test]
fn every_profile_produces_a_policy_file_the_proxy_would_load() {
    // A profile is only useful if what it writes survives the same `validate()`
    // the daemon runs at startup. Broken base URL, unknown auth key, empty rule
    // list — all of it fails here rather than on someone's first run.
    for profile in profiles::catalog() {
        for level in &profile.access {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("iap.toml");
            mcp_iap::init::init(&mcp_iap::init::InitOptions {
                path: path.clone(),
                agent: "a".into(),
                secret: None,
                template: mcp_iap::init::Template::Minimal,
                force: true,
            })
            .unwrap();

            let mut opts = options("op://Vault/Item/field");
            opts.access = Some(level.name.clone());
            opts.vars = profile
                .vars
                .iter()
                .map(|var| format!("{}=placeholder", var.name))
                .collect();
            profiles::add(&path, &profile, &opts)
                .unwrap_or_else(|error| panic!("{}/{}: {error:#}", profile.id, level.name));

            let text = std::fs::read_to_string(&path).unwrap();
            let config: Config = toml::from_str(&text)
                .unwrap_or_else(|error| panic!("{}/{}: {error:#}", profile.id, level.name));
            config
                .validate()
                .unwrap_or_else(|error| panic!("{}/{}: {error:#}", profile.id, level.name));

            // The credential must survive as a *reference*. The only literal
            // any profile may write is a documented scheme constant, and the
            // only one in the catalog is Graylog's password.
            assert!(
                !text.contains("literal:op://"),
                "{}: a reference was wrapped in `literal:`",
                profile.id
            );
            for literal in text.match_indices("literal:") {
                let tail = &text[literal.0..];
                let value = tail
                    .trim_start_matches("literal:")
                    .split('"')
                    .next()
                    .unwrap();
                assert_eq!(
                    value, "token",
                    "{}: wrote an unexpected `literal:` into the policy file",
                    profile.id
                );
            }
        }
    }
}

#[test]
fn a_dry_run_writes_nothing_and_prints_what_it_would_have() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iap.toml");
    mcp_iap::init::init(&mcp_iap::init::InitOptions {
        path: path.clone(),
        agent: "a".into(),
        secret: None,
        template: mcp_iap::init::Template::Minimal,
        force: true,
    })
    .unwrap();
    let before = std::fs::read_to_string(&path).unwrap();

    let profile = profiles::get("cloudflare").unwrap();
    let mut opts = options("op://Vault/Cloudflare/token");
    opts.dry_run = true;
    let added = profiles::add(&path, &profile, &opts).unwrap();

    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    assert_eq!(added.name, "cloudflare");
    assert!(!added.rules.is_empty());
}

fn base64_encode(value: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(value)
}

//! End-to-end: service account in, short-lived token out, agent none the wiser.
//!
//! The mock token endpoint does what Google does — it verifies the assertion's
//! RS256 signature against the service account's public key before issuing
//! anything, so these tests prove the proxy mints a genuinely valid assertion
//! rather than merely a well-shaped one.

use axum::extract::{Request, State};
use axum::routing::{any, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mcp_iap::config::Config;
use mcp_iap::state::AppState;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const AGENT_TOKEN: &str = "iap_agent_token";
const ISSUED_TOKEN: &str = "ya29.mock-short-lived-access-token";

/// A throwaway key, minted once per test run. This repository contains no
/// private keys, and no key-generation crate is pulled in to make one — the
/// only candidate carries an unfixed advisory that `cargo audit` would flag.
struct TestKey {
    private_pem: String,
    public_pkcs1_der: Vec<u8>,
}

fn generate_key() -> TestKey {
    static PEM: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let private_pem = PEM
        .get_or_init(|| {
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
            assert!(
                output.status.success(),
                "openssl genpkey failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        })
        .clone();

    // ring hands back the public key in exactly the DER form its verifier wants.
    let der_body: String = private_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let pkcs8 = base64::engine::general_purpose::STANDARD
        .decode(der_body)
        .unwrap();
    let public_pkcs1_der = ring::signature::RsaKeyPair::from_pkcs8(&pkcs8)
        .unwrap()
        .public()
        .as_ref()
        .to_vec();

    TestKey {
        private_pem,
        public_pkcs1_der,
    }
}

#[derive(Clone)]
struct TokenEndpoint {
    public_key: Arc<Vec<u8>>,
    hits: Arc<AtomicUsize>,
    claims: Arc<parking_lot::Mutex<Vec<Value>>>,
}

/// Stands in for `https://oauth2.googleapis.com/token`.
async fn spawn_token_endpoint(key: &TestKey) -> (SocketAddr, TokenEndpoint) {
    async fn issue(State(state): State<TokenEndpoint>, body: String) -> Json<Value> {
        state.hits.fetch_add(1, Ordering::SeqCst);

        let form: std::collections::HashMap<String, String> =
            form_urlencoded::parse(body.as_bytes())
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();

        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            "the proxy must use the JWT bearer grant"
        );
        let assertion = form.get("assertion").expect("an assertion was sent");

        // Verify exactly as the provider would: signature over `header.claims`.
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();

        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            state.public_key.as_slice(),
        )
        .verify(signing_input.as_bytes(), &signature)
        .expect("the assertion signature must verify against the service account key");

        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        state.claims.lock().push(claims);

        Json(serde_json::json!({
            "access_token": ISSUED_TOKEN,
            "token_type": "Bearer",
            "expires_in": 3599,
        }))
    }

    let state = TokenEndpoint {
        public_key: Arc::new(key.public_pkcs1_der.clone()),
        hits: Arc::new(AtomicUsize::new(0)),
        claims: Arc::new(parking_lot::Mutex::new(Vec::new())),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/token", post(issue))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, state)
}

/// Reports the Authorization header it was handed.
async fn spawn_upstream() -> SocketAddr {
    async fn echo(request: Request) -> Json<Value> {
        Json(serde_json::json!({
            "authorization": request
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok()),
        }))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().fallback(any(echo)))
            .await
            .unwrap()
    });
    addr
}

struct Harness {
    proxy: SocketAddr,
    token_endpoint: TokenEndpoint,
    audit_path: std::path::PathBuf,
    key_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn spawn(subject: Option<&str>) -> Harness {
    let key = generate_key();
    let (token_addr, token_endpoint) = spawn_token_endpoint(&key).await;
    let upstream = spawn_upstream().await;

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.jsonl");
    let key_path = dir.path().join("service-account.json");

    // Written exactly as Google hands it to you.
    std::fs::write(
        &key_path,
        serde_json::json!({
            "type": "service_account",
            "project_id": "demo",
            "private_key_id": "key-1",
            "private_key": key.private_pem,
            "client_email": "iap@demo.iam.gserviceaccount.com",
            "client_id": "1234",
            "token_uri": format!("http://{token_addr}/token"),
        })
        .to_string(),
    )
    .unwrap();

    let subject_line = subject
        .map(|s| format!("subject = \"{s}\"\n"))
        .unwrap_or_default();

    let config: Config = toml::from_str(&format!(
        r#"
[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{token_hash}"

[[upstreams]]
name = "gcs"
base_url = "http://{upstream}"

[upstreams.auth]
type = "service_account_jwt"
key_file = "file:{key_path}"
scopes = ["https://www.googleapis.com/auth/devstorage.read_only"]
{subject_line}
[[acl]]
target = "gcs"
methods = ["GET"]
paths = ["/**"]
action = "allow"
"#,
        audit = audit_path.display(),
        token_hash = mcp_iap::identity::token_hash(AGENT_TOKEN),
        upstream = upstream,
        key_path = key_path.display(),
    ))
    .unwrap();
    config.validate().unwrap();

    let state = AppState::build(config, false).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            mcp_iap::proxy::router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap()
    });

    Harness {
        proxy,
        token_endpoint,
        audit_path,
        key_path,
        _dir: dir,
    }
}

async fn call(harness: &Harness, path: &str) -> Value {
    reqwest::Client::new()
        .get(format!("http://{}/gcs{path}", harness.proxy))
        .bearer_auth(AGENT_TOKEN)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn the_proxy_exchanges_the_service_account_for_a_token_and_uses_it() {
    let harness = spawn(None).await;

    let seen = call(&harness, "/storage/v1/b/bucket/o").await;
    assert_eq!(
        seen["authorization"],
        format!("Bearer {ISSUED_TOKEN}"),
        "the upstream must receive the minted access token"
    );

    assert_eq!(harness.token_endpoint.hits.load(Ordering::SeqCst), 1);
    let claims = harness.token_endpoint.claims.lock()[0].clone();
    assert_eq!(claims["iss"], "iap@demo.iam.gserviceaccount.com");
    assert_eq!(
        claims["scope"],
        "https://www.googleapis.com/auth/devstorage.read_only"
    );
    assert!(claims["exp"].as_i64().unwrap() > claims["iat"].as_i64().unwrap());
    assert!(claims.get("sub").is_none());
}

#[tokio::test]
async fn the_token_is_reused_until_it_is_nearly_expired() {
    let harness = spawn(None).await;
    for _ in 0..5 {
        call(&harness, "/storage/v1/b/bucket/o").await;
    }
    assert_eq!(
        harness.token_endpoint.hits.load(Ordering::SeqCst),
        1,
        "five proxied calls should mint one token, not five"
    );
}

#[tokio::test]
async fn a_burst_on_a_cold_cache_still_mints_only_one_token() {
    let harness = Arc::new(spawn(None).await);

    let calls: Vec<_> = (0..8)
        .map(|_| {
            let harness = Arc::clone(&harness);
            tokio::spawn(async move { call(&harness, "/storage/v1/b/bucket/o").await })
        })
        .collect();
    for call in calls {
        let seen = call.await.unwrap();
        assert_eq!(seen["authorization"], format!("Bearer {ISSUED_TOKEN}"));
    }

    assert_eq!(
        harness.token_endpoint.hits.load(Ordering::SeqCst),
        1,
        "concurrent cold-cache requests must not each mint their own token"
    );
}

#[tokio::test]
async fn domain_wide_delegation_reaches_the_subject_claim() {
    let harness = spawn(Some("person@example.com")).await;
    call(&harness, "/gmail/v1/users/me/messages").await;
    let claims = harness.token_endpoint.claims.lock()[0].clone();
    assert_eq!(claims["sub"], "person@example.com");
}

#[tokio::test]
async fn the_mint_is_audited_and_leaks_neither_the_token_nor_the_key() {
    let harness = spawn(None).await;
    call(&harness, "/storage/v1/b/bucket/o").await;

    let log = std::fs::read_to_string(&harness.audit_path).unwrap();
    let events: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();

    let mint = events
        .iter()
        .find(|e| e["event"] == "token_minted")
        .expect("minting a token is itself a recorded event");
    assert_eq!(mint["target"], "gcs");
    assert_eq!(mint["detail"]["scheme"], "service_account_jwt");
    assert_eq!(mint["detail"]["issuer"], "iap@demo.iam.gserviceaccount.com");
    assert_eq!(mint["detail"]["expires_in_secs"], 3599);
    assert_eq!(
        mint["detail"]["scopes"][0],
        "https://www.googleapis.com/auth/devstorage.read_only"
    );

    assert!(
        !log.contains(ISSUED_TOKEN),
        "the minted token reached the log"
    );
    assert!(!log.contains("PRIVATE KEY"), "key material reached the log");
    assert!(
        !log.contains(AGENT_TOKEN),
        "the agent token reached the log"
    );

    // And the chain still verifies with the extra record in it.
    mcp_iap::audit::verify_file(&harness.audit_path).unwrap();
}

#[tokio::test]
async fn a_broken_key_stops_startup_instead_of_failing_on_the_first_call() {
    let harness = spawn(None).await;
    let config_text = std::fs::read_to_string(&harness.key_path).unwrap();
    let mut key: Value = serde_json::from_str(&config_text).unwrap();
    key["private_key"] = Value::String(
        "-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----".into(),
    );
    std::fs::write(&harness.key_path, key.to_string()).unwrap();

    let config: Config = toml::from_str(&format!(
        r#"
[audit]
path = "{audit}"
stderr = false

[[agents]]
id = "claude"
token_sha256 = "{token_hash}"

[[upstreams]]
name = "gcs"
base_url = "http://127.0.0.1:1"

[upstreams.auth]
type = "service_account_jwt"
key_file = "file:{key_path}"
"#,
        audit = harness.audit_path.display(),
        token_hash = mcp_iap::identity::token_hash(AGENT_TOKEN),
        key_path = harness.key_path.display(),
    ))
    .unwrap();

    let err = match AppState::build(config, false) {
        Err(err) => err,
        Ok(_) => panic!("a service account with an unusable key must not start"),
    };
    let rendered = format!("{err:#}");
    assert!(rendered.contains("service-account key"), "{rendered}");
    assert!(
        !rendered.contains("bm90LWEta2V5"),
        "startup error leaked key bytes"
    );
}

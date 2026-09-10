//! Credential injection.
//!
//! This is where the real key enters the request — on the way *out* of the proxy,
//! after the ACL has already said yes, and never anywhere the agent can observe.

use anyhow::{Context, Result};
use base64::Engine;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::audit::{AuditLog, AuditRecord};
use crate::config::AuthConfig;
use crate::secrets::{Secret, SecretResolver};
use crate::service_account::{ServiceAccount, JWT_BEARER_GRANT};

/// Refresh a minted token this long before it actually expires.
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Assume this lifetime when a provider returns a token without `expires_in`.
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

pub struct CredentialInjector {
    resolver: Arc<SecretResolver>,
    http: reqwest::Client,
    token_cache: Mutex<HashMap<String, (Secret, Instant)>>,
    /// One in-flight token request per target, so a burst of requests on a cold
    /// cache mints one token rather than one each.
    token_gates: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Service-account keys, parsed once at startup.
    service_accounts: Mutex<HashMap<String, Arc<ServiceAccount>>>,
    /// Minting a token is a security event in its own right; when the injector
    /// has a log, every mint is recorded (never the token).
    audit: Option<Arc<AuditLog>>,
}

impl CredentialInjector {
    pub fn new(
        resolver: Arc<SecretResolver>,
        http: reqwest::Client,
        audit: Option<Arc<AuditLog>>,
    ) -> Self {
        CredentialInjector {
            resolver,
            http,
            token_cache: Mutex::new(HashMap::new()),
            token_gates: Mutex::new(HashMap::new()),
            service_accounts: Mutex::new(HashMap::new()),
            audit,
        }
    }

    /// Parse a target's service-account key now, so a malformed key or a locked
    /// vault stops startup instead of surfacing as a 502 on the first request.
    pub fn warm(&self, target: &str, auth: &AuthConfig) -> Result<()> {
        if matches!(auth, AuthConfig::ServiceAccountJwt { .. }) {
            self.service_account(target, auth)?;
        }
        Ok(())
    }

    /// Mutate an outbound request so it carries the upstream's real credential.
    pub async fn apply(
        &self,
        target: &str,
        auth: &AuthConfig,
        request: &mut reqwest::Request,
    ) -> Result<()> {
        match auth {
            AuthConfig::None => {}
            AuthConfig::Bearer { secret } => {
                let value = self.resolve(secret)?;
                set_header(
                    request,
                    "authorization",
                    &format!("Bearer {}", value.expose()),
                )?;
            }
            AuthConfig::Header {
                header,
                secret,
                prefix,
            } => {
                let value = self.resolve(secret)?;
                let rendered = match prefix {
                    Some(prefix) => format!("{prefix}{}", value.expose()),
                    None => value.expose().to_string(),
                };
                set_header(request, header, &rendered)?;
            }
            AuthConfig::Basic { username, secret } => {
                let value = self.resolve(secret)?;
                let encoded = base64::engine::general_purpose::STANDARD
                    .encode(format!("{username}:{}", value.expose()));
                set_header(request, "authorization", &format!("Basic {encoded}"))?;
            }
            AuthConfig::Query { param, secret } => {
                let value = self.resolve(secret)?;
                request
                    .url_mut()
                    .query_pairs_mut()
                    .append_pair(param, value.expose());
            }
            AuthConfig::Oauth2ClientCredentials { .. } | AuthConfig::ServiceAccountJwt { .. } => {
                let token = self.minted_token(target, auth).await?;
                set_header(
                    request,
                    "authorization",
                    &format!("Bearer {}", token.expose()),
                )?;
            }
        }
        Ok(())
    }

    /// Resolve every `env`/`file`/`op://` reference an MCP child process needs.
    pub fn resolve_env(
        &self,
        env: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<(String, Secret)>> {
        env.iter()
            .map(|(key, reference)| {
                let secret = self
                    .resolve(reference)
                    .with_context(|| format!("resolving env `{key}`"))?;
                Ok((key.clone(), secret))
            })
            .collect()
    }

    fn resolve(&self, reference: &str) -> Result<Secret> {
        self.resolver.resolve(reference)
    }

    /// A short-lived token the proxy mints itself, cached until it is nearly due
    /// to expire. Both minting schemes share this path.
    async fn minted_token(&self, target: &str, auth: &AuthConfig) -> Result<Secret> {
        if let Some(token) = self.cached_token(target) {
            return Ok(token);
        }

        // Serialise per target. Whoever gets here first mints; the rest wait and
        // then find the fresh token in the cache.
        let gate = self.gate(target);
        let _held = gate.lock().await;
        if let Some(token) = self.cached_token(target) {
            return Ok(token);
        }

        let (token, lifetime, detail) = match auth {
            AuthConfig::Oauth2ClientCredentials { .. } => {
                self.fetch_client_credentials(target, auth).await?
            }
            AuthConfig::ServiceAccountJwt { .. } => {
                self.fetch_service_account_token(target, auth).await?
            }
            _ => unreachable!("minted_token is only called for token-minting schemes"),
        };
        let token_url = detail
            .get("token_url")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();

        self.token_cache.lock().insert(
            target.to_string(),
            (token.clone(), Instant::now() + lifetime),
        );

        if let Some(audit) = &self.audit {
            let mut record = AuditRecord::new("credential", "token_minted");
            record.agent = "<proxy>".into();
            record.target = target.to_string();
            record.method = "POST".into();
            record.path = token_url;
            record.detail = Some(detail);
            audit.write(record);
        }

        Ok(token)
    }

    fn cached_token(&self, target: &str) -> Option<Secret> {
        let cache = self.token_cache.lock();
        let (token, expires_at) = cache.get(target)?;
        (Instant::now() + TOKEN_REFRESH_MARGIN < *expires_at).then(|| token.clone())
    }

    fn gate(&self, target: &str) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(
            self.token_gates
                .lock()
                .entry(target.to_string())
                .or_default(),
        )
    }

    /// Load (and remember) a target's service-account key.
    fn service_account(&self, target: &str, auth: &AuthConfig) -> Result<Arc<ServiceAccount>> {
        if let Some(account) = self.service_accounts.lock().get(target) {
            return Ok(Arc::clone(account));
        }
        let account = Arc::new(
            ServiceAccount::load(auth, &self.resolver)
                .with_context(|| format!("loading the service-account key for `{target}`"))?,
        );
        self.service_accounts
            .lock()
            .insert(target.to_string(), Arc::clone(&account));
        Ok(account)
    }

    async fn fetch_client_credentials(
        &self,
        target: &str,
        auth: &AuthConfig,
    ) -> Result<(Secret, Duration, serde_json::Value)> {
        let AuthConfig::Oauth2ClientCredentials {
            token_url,
            client_id,
            client_secret,
            scope,
            audience,
        } = auth
        else {
            unreachable!("only called for the client-credentials scheme");
        };

        let secret = self.resolve(client_secret)?;
        let mut form = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", client_id.clone()),
            ("client_secret", secret.expose().to_string()),
        ];
        if let Some(scope) = scope {
            form.push(("scope", scope.clone()));
        }
        if let Some(audience) = audience {
            form.push(("audience", audience.clone()));
        }

        let (token, lifetime) = self.exchange(target, token_url, &form).await?;
        Ok((
            token,
            lifetime,
            serde_json::json!({
                "scheme": "oauth2_client_credentials",
                "token_url": token_url,
                "client_id": client_id,
                "expires_in_secs": lifetime.as_secs(),
            }),
        ))
    }

    /// Sign an assertion with the service-account key and trade it for a token.
    async fn fetch_service_account_token(
        &self,
        target: &str,
        auth: &AuthConfig,
    ) -> Result<(Secret, Duration, serde_json::Value)> {
        let account = self.service_account(target, auth)?;
        let assertion = account
            .assertion()
            .with_context(|| format!("signing a service-account assertion for `{target}`"))?;

        let form = vec![
            ("grant_type", JWT_BEARER_GRANT.to_string()),
            ("assertion", assertion),
        ];

        let (token, lifetime) = self.exchange(target, account.token_url(), &form).await?;
        Ok((
            token,
            lifetime,
            serde_json::json!({
                "scheme": "service_account_jwt",
                "token_url": account.token_url(),
                "issuer": account.issuer(),
                "subject": account.subject(),
                "scopes": account.scopes(),
                "assertion_lifetime_secs": account.lifetime().as_secs(),
                "expires_in_secs": lifetime.as_secs(),
            }),
        ))
    }

    /// POST a token request and read the access token out of the response.
    async fn exchange(
        &self,
        target: &str,
        token_url: &str,
        form: &[(&str, String)],
    ) -> Result<(Secret, Duration)> {
        let response = self
            .http
            .post(token_url)
            .form(form)
            .send()
            .await
            .with_context(|| format!("requesting a token for `{target}`"))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // A failed token request can echo the credential back in its body,
            // and providers put useful-but-sensitive detail in `error_description`.
            anyhow::bail!("token request for `{target}` failed with {status}");
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let parsed: TokenResponse = serde_json::from_str(&body)
            .with_context(|| format!("parsing the token response for `{target}`"))?;

        let lifetime = parsed
            .expires_in
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_TOKEN_LIFETIME);
        Ok((Secret::new(parsed.access_token), lifetime))
    }
}

fn set_header(request: &mut reqwest::Request, name: &str, value: &str) -> Result<()> {
    let name: http::HeaderName = name
        .parse()
        .with_context(|| format!("`{name}` is not a valid header name"))?;
    let mut header: http::HeaderValue = value
        .parse()
        .with_context(|| format!("the credential for `{name}` is not a valid header value"))?;
    header.set_sensitive(true);
    request.headers_mut().insert(name, header);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn injector() -> CredentialInjector {
        let resolver = Arc::new(SecretResolver::new("op"));
        resolver.preset("literal:sk-real", Secret::new("sk-real".into()));
        CredentialInjector::new(resolver, reqwest::Client::new(), None)
    }

    fn request() -> reqwest::Request {
        reqwest::Request::new(
            http::Method::POST,
            "https://api.example.com/v1/messages".parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn bearer_sets_an_authorization_header() {
        let mut req = request();
        injector()
            .apply(
                "u",
                &AuthConfig::Bearer {
                    secret: "literal:sk-real".into(),
                },
                &mut req,
            )
            .await
            .unwrap();
        assert_eq!(req.headers()["authorization"], "Bearer sk-real");
        assert!(
            req.headers()["authorization"].is_sensitive(),
            "credentials must be marked sensitive so they stay out of debug output"
        );
    }

    #[tokio::test]
    async fn custom_header_with_prefix() {
        let mut req = request();
        injector()
            .apply(
                "u",
                &AuthConfig::Header {
                    header: "x-api-key".into(),
                    secret: "literal:sk-real".into(),
                    prefix: None,
                },
                &mut req,
            )
            .await
            .unwrap();
        assert_eq!(req.headers()["x-api-key"], "sk-real");

        let mut req = request();
        injector()
            .apply(
                "u",
                &AuthConfig::Header {
                    header: "x-token".into(),
                    secret: "literal:sk-real".into(),
                    prefix: Some("Token ".into()),
                },
                &mut req,
            )
            .await
            .unwrap();
        assert_eq!(req.headers()["x-token"], "Token sk-real");
    }

    #[tokio::test]
    async fn basic_encodes_username_and_secret() {
        let mut req = request();
        injector()
            .apply(
                "u",
                &AuthConfig::Basic {
                    username: "user".into(),
                    secret: "literal:sk-real".into(),
                },
                &mut req,
            )
            .await
            .unwrap();
        let expected = base64::engine::general_purpose::STANDARD.encode("user:sk-real");
        assert_eq!(req.headers()["authorization"], format!("Basic {expected}"));
    }

    #[tokio::test]
    async fn query_appends_without_dropping_existing_parameters() {
        let mut req = reqwest::Request::new(
            http::Method::GET,
            "https://api.example.com/v1/models?limit=5".parse().unwrap(),
        );
        injector()
            .apply(
                "u",
                &AuthConfig::Query {
                    param: "key".into(),
                    secret: "literal:sk-real".into(),
                },
                &mut req,
            )
            .await
            .unwrap();
        let query = req.url().query().unwrap();
        assert!(query.contains("limit=5"), "{query}");
        assert!(query.contains("key=sk-real"), "{query}");
    }

    #[tokio::test]
    async fn none_leaves_the_request_untouched() {
        let mut req = request();
        injector()
            .apply("u", &AuthConfig::None, &mut req)
            .await
            .unwrap();
        assert!(req.headers().is_empty());
    }

    #[test]
    fn env_resolution_for_an_mcp_child_process() {
        std::env::set_var("LLM_IAP_TEST_MCP_TOKEN", "ghp_real");
        let mut env = std::collections::BTreeMap::new();
        env.insert(
            "GITHUB_TOKEN".to_string(),
            "env:LLM_IAP_TEST_MCP_TOKEN".to_string(),
        );
        let resolved = injector().resolve_env(&env).unwrap();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, "GITHUB_TOKEN");
        assert_eq!(resolved[0].1.expose(), "ghp_real");
    }
}

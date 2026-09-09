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

use crate::config::AuthConfig;
use crate::secrets::{Secret, SecretResolver};

/// Refresh an OAuth token this long before it actually expires.
const OAUTH_REFRESH_MARGIN: Duration = Duration::from_secs(60);

pub struct CredentialInjector {
    resolver: Arc<SecretResolver>,
    http: reqwest::Client,
    oauth_cache: Mutex<HashMap<String, (Secret, Instant)>>,
}

impl CredentialInjector {
    pub fn new(resolver: Arc<SecretResolver>, http: reqwest::Client) -> Self {
        CredentialInjector {
            resolver,
            http,
            oauth_cache: Mutex::new(HashMap::new()),
        }
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
            AuthConfig::Oauth2ClientCredentials { .. } => {
                let token = self.oauth_token(target, auth).await?;
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

    async fn oauth_token(&self, target: &str, auth: &AuthConfig) -> Result<Secret> {
        let AuthConfig::Oauth2ClientCredentials {
            token_url,
            client_id,
            client_secret,
            scope,
            audience,
        } = auth
        else {
            unreachable!("oauth_token is only called for the client-credentials scheme");
        };

        if let Some((token, expires_at)) = self.oauth_cache.lock().get(target) {
            if Instant::now() + OAUTH_REFRESH_MARGIN < *expires_at {
                return Ok(token.clone());
            }
        }

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

        let response = self
            .http
            .post(token_url)
            .form(&form)
            .send()
            .await
            .with_context(|| format!("requesting an OAuth token for `{target}`"))?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // The body of a failed token request can echo the client secret back.
            anyhow::bail!("OAuth token request for `{target}` failed with {status}");
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            expires_in: Option<u64>,
        }
        let parsed: TokenResponse = serde_json::from_str(&body)
            .with_context(|| format!("parsing the OAuth token response for `{target}`"))?;

        let token = Secret::new(parsed.access_token);
        let lifetime = Duration::from_secs(parsed.expires_in.unwrap_or(3600));
        self.oauth_cache.lock().insert(
            target.to_string(),
            (token.clone(), Instant::now() + lifetime),
        );
        Ok(token)
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
        CredentialInjector::new(resolver, reqwest::Client::new())
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

//! Service-account assertions — RFC 7523, the flow Google uses.
//!
//! The operator hands the proxy a service-account key. The agent never sees it,
//! and never sees the access token either: the proxy signs a short-lived JWT
//! with the account's private key, exchanges it for an access token at the
//! provider's token endpoint, and injects that. The token is the only thing
//! that ever leaves this process, it expires on its own, and it is scoped to
//! whatever `scopes` says rather than to everything the key could do.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};
use serde::Deserialize;
use std::time::Duration;

use crate::config::AuthConfig;
use crate::secrets::SecretResolver;

/// The grant type an assertion is exchanged under.
pub const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Google rejects an assertion that claims to live longer than an hour, and
/// there is no reason to ask for more: the proxy re-mints on expiry anyway.
const MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// The subset of a Google service-account JSON key that matters here.
#[derive(Debug, Deserialize)]
struct ServiceAccountKeyFile {
    client_email: String,
    private_key: String,
    #[serde(default)]
    private_key_id: Option<String>,
    #[serde(default)]
    token_uri: Option<String>,
}

/// A loaded service account, ready to mint assertions.
pub struct ServiceAccount {
    issuer: String,
    key_id: Option<String>,
    token_url: String,
    audience: String,
    scopes: Vec<String>,
    subject: Option<String>,
    lifetime: Duration,
    key: RsaKeyPair,
    rng: SystemRandom,
}

impl std::fmt::Debug for ServiceAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAccount")
            .field("issuer", &self.issuer)
            .field("token_url", &self.token_url)
            .field("scopes", &self.scopes)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl ServiceAccount {
    /// Resolve the key material and parse it. Called at startup so a malformed
    /// key or a locked vault stops the process rather than the first request.
    pub fn load(auth: &AuthConfig, resolver: &SecretResolver) -> Result<Self> {
        let AuthConfig::ServiceAccountJwt {
            key_file,
            issuer,
            private_key,
            key_id,
            token_url,
            audience,
            scopes,
            subject,
            lifetime_secs,
        } = auth
        else {
            bail!("not a service-account credential");
        };

        // Two ways in: a Google JSON key, or the pieces spelled out for any
        // other RFC 7523 provider. `validate` has already rejected mixtures.
        let (issuer, pem, key_id, default_token_url) = match key_file {
            Some(reference) => {
                let raw = resolver
                    .resolve(reference)
                    .context("resolving the service-account key file")?;
                let parsed: ServiceAccountKeyFile = serde_json::from_str(raw.expose())
                    .context("parsing the service-account JSON key")?;
                (
                    parsed.client_email,
                    parsed.private_key,
                    parsed.private_key_id,
                    parsed.token_uri,
                )
            }
            None => {
                let reference = private_key
                    .as_deref()
                    .context("service-account credential has no `private_key`")?;
                let pem = resolver
                    .resolve(reference)
                    .context("resolving the service-account private key")?;
                (
                    issuer
                        .clone()
                        .context("service-account credential has no `issuer`")?,
                    pem.expose().to_string(),
                    key_id.clone(),
                    None,
                )
            }
        };

        let token_url = token_url.clone().or(default_token_url).context(
            "service-account credential has no `token_url` and the key file carries no `token_uri`",
        )?;

        let lifetime = lifetime_secs
            .map(Duration::from_secs)
            .unwrap_or(MAX_LIFETIME)
            .min(MAX_LIFETIME);

        Ok(ServiceAccount {
            audience: audience.clone().unwrap_or_else(|| token_url.clone()),
            issuer,
            key_id,
            token_url,
            scopes: scopes.clone(),
            subject: subject.clone(),
            lifetime,
            key: load_rsa_key(&pem)?,
            rng: SystemRandom::new(),
        })
    }

    pub fn token_url(&self) -> &str {
        &self.token_url
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    /// Sign an assertion valid from now.
    pub fn assertion(&self) -> Result<String> {
        self.assertion_at(chrono::Utc::now().timestamp())
    }

    /// Sign an assertion issued at a given instant. Split out so the claim set
    /// can be asserted against a fixed clock in tests.
    pub fn assertion_at(&self, issued_at: i64) -> Result<String> {
        let header = self.header();
        let claims = self.claims_at(issued_at);

        let mut signing_input = URL_SAFE_NO_PAD.encode(header.to_string());
        signing_input.push('.');
        signing_input.push_str(&URL_SAFE_NO_PAD.encode(claims.to_string()));

        let mut signature = vec![0u8; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &self.rng,
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| anyhow::anyhow!("signing the service-account assertion failed"))?;

        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn header(&self) -> serde_json::Value {
        match &self.key_id {
            Some(kid) => serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid }),
            None => serde_json::json!({ "alg": "RS256", "typ": "JWT" }),
        }
    }

    /// The assertion's claim set.
    pub fn claims_at(&self, issued_at: i64) -> serde_json::Value {
        let mut claims = serde_json::Map::new();
        claims.insert("iss".into(), self.issuer.clone().into());
        claims.insert("aud".into(), self.audience.clone().into());
        claims.insert("iat".into(), issued_at.into());
        claims.insert(
            "exp".into(),
            (issued_at + self.lifetime.as_secs() as i64).into(),
        );
        if !self.scopes.is_empty() {
            claims.insert("scope".into(), self.scopes.join(" ").into());
        }
        // Domain-wide delegation: the token acts as this user, not as the
        // service account itself.
        if let Some(subject) = &self.subject {
            claims.insert("sub".into(), subject.clone().into());
        }
        serde_json::Value::Object(claims)
    }
}

/// Parse a PEM private key into something `ring` will sign with.
fn load_rsa_key(pem: &str) -> Result<RsaKeyPair> {
    // A JSON key file carries the PEM with escaped newlines already decoded by
    // serde, but a key pasted into an env var often still has literal `\n`.
    let normalised = pem.replace("\\n", "\n");

    if normalised.contains("BEGIN RSA PRIVATE KEY") {
        bail!(
            "this is a PKCS#1 key; convert it with \
             `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8.pem` and use that"
        );
    }
    if normalised.contains("ENCRYPTED PRIVATE KEY") {
        bail!("the private key is passphrase-encrypted; decrypt it before handing it to the proxy");
    }

    let der = pem_body(&normalised, "PRIVATE KEY")
        .context("the service-account private key is not a PKCS#8 PEM block")?;

    RsaKeyPair::from_pkcs8(&der)
        .map_err(|error| anyhow::anyhow!("the service-account private key was rejected: {error}"))
}

/// Pull the base64 body out of a PEM block, without echoing any of it on error.
fn pem_body(pem: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let start = pem
        .find(&begin)
        .with_context(|| format!("no `{begin}` line"))?
        + begin.len();
    let stop = pem.find(&end).with_context(|| format!("no `{end}` line"))?;
    if stop < start {
        bail!("the PEM block's end marker precedes its begin marker");
    }

    let body: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| anyhow::anyhow!("the PEM block's body is not valid base64"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{Secret, SecretResolver};

    /// A throwaway 2048-bit key, minted once per test run.
    ///
    /// Deliberately not a committed fixture — this repository contains no
    /// private keys — and deliberately not the `rsa` crate, which carries an
    /// unfixed advisory that would have to be silenced in `cargo audit`.
    /// `openssl genpkey` emits PKCS#8, the same form Google issues.
    pub(crate) fn test_key_pem() -> String {
        static KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
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
            String::from_utf8(output.stdout).expect("openssl emitted non-UTF-8 PEM")
        })
        .clone()
    }

    fn google_key_json(pem: &str) -> String {
        serde_json::json!({
            "type": "service_account",
            "project_id": "demo",
            "private_key_id": "key-1",
            "private_key": pem,
            "client_email": "iap@demo.iam.gserviceaccount.com",
            "client_id": "1234",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string()
    }

    fn from_key_file(json: &str, scopes: &[&str], subject: Option<&str>) -> Result<ServiceAccount> {
        let resolver = SecretResolver::new("op");
        resolver.preset("literal:sa", Secret::new(json.to_string()));
        ServiceAccount::load(
            &AuthConfig::ServiceAccountJwt {
                key_file: Some("literal:sa".into()),
                issuer: None,
                private_key: None,
                key_id: None,
                token_url: None,
                audience: None,
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
                subject: subject.map(str::to_string),
                lifetime_secs: None,
            },
            &resolver,
        )
    }

    fn decode_part(part: &str) -> serde_json::Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    }

    #[test]
    fn a_google_key_file_supplies_issuer_key_id_and_token_endpoint() {
        let account = from_key_file(&google_key_json(&test_key_pem()), &[], None).unwrap();
        assert_eq!(account.issuer(), "iap@demo.iam.gserviceaccount.com");
        assert_eq!(account.token_url(), "https://oauth2.googleapis.com/token");
        assert_eq!(account.key_id.as_deref(), Some("key-1"));
        // Google wants the token endpoint itself as the audience.
        assert_eq!(account.audience, "https://oauth2.googleapis.com/token");
    }

    #[test]
    fn the_assertion_carries_the_claims_google_expects() {
        let account = from_key_file(
            &google_key_json(&test_key_pem()),
            &[
                "https://www.googleapis.com/auth/devstorage.read_only",
                "https://www.googleapis.com/auth/cloud-platform.read-only",
            ],
            None,
        )
        .unwrap();

        let assertion = account.assertion_at(1_700_000_000).unwrap();
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWS has three dot-separated parts");

        let header = decode_part(parts[0]);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "key-1");

        let claims = decode_part(parts[1]);
        assert_eq!(claims["iss"], "iap@demo.iam.gserviceaccount.com");
        assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(claims["iat"], 1_700_000_000i64);
        assert_eq!(claims["exp"], 1_700_003_600i64, "one hour by default");
        assert_eq!(
            claims["scope"],
            "https://www.googleapis.com/auth/devstorage.read_only \
             https://www.googleapis.com/auth/cloud-platform.read-only",
            "scopes are space-delimited in a single claim"
        );
        assert!(claims.get("sub").is_none(), "no delegation was configured");

        // The signature is over exactly `header.claims`, and is not empty.
        assert!(!parts[2].is_empty());
        assert_eq!(
            URL_SAFE_NO_PAD.decode(parts[2]).unwrap().len(),
            256,
            "RS256 over a 2048-bit key produces a 256-byte signature"
        );
    }

    #[test]
    fn delegation_sets_the_subject_claim() {
        let account = from_key_file(
            &google_key_json(&test_key_pem()),
            &["https://www.googleapis.com/auth/gmail.readonly"],
            Some("person@example.com"),
        )
        .unwrap();
        let claims = account.claims_at(0);
        assert_eq!(claims["sub"], "person@example.com");
    }

    #[test]
    fn a_lifetime_over_an_hour_is_clamped_rather_than_rejected_by_the_provider() {
        let resolver = SecretResolver::new("op");
        resolver.preset("literal:sa", Secret::new(google_key_json(&test_key_pem())));
        let account = ServiceAccount::load(
            &AuthConfig::ServiceAccountJwt {
                key_file: Some("literal:sa".into()),
                issuer: None,
                private_key: None,
                key_id: None,
                token_url: None,
                audience: None,
                scopes: vec![],
                subject: None,
                lifetime_secs: Some(86_400),
            },
            &resolver,
        )
        .unwrap();
        assert_eq!(account.lifetime(), MAX_LIFETIME);
        assert_eq!(account.claims_at(0)["exp"], 3600);
    }

    #[test]
    fn the_pieces_can_be_spelled_out_for_a_non_google_provider() {
        let resolver = SecretResolver::new("op");
        resolver.preset("literal:pem", Secret::new(test_key_pem()));
        let account = ServiceAccount::load(
            &AuthConfig::ServiceAccountJwt {
                key_file: None,
                issuer: Some("service@example.com".into()),
                private_key: Some("literal:pem".into()),
                key_id: Some("kid-9".into()),
                token_url: Some("https://auth.example.com/oauth/token".into()),
                audience: Some("https://api.example.com".into()),
                scopes: vec!["read".into()],
                subject: None,
                lifetime_secs: Some(300),
            },
            &resolver,
        )
        .unwrap();

        assert_eq!(account.token_url(), "https://auth.example.com/oauth/token");
        let claims = account.claims_at(1_000);
        assert_eq!(claims["iss"], "service@example.com");
        assert_eq!(
            claims["aud"], "https://api.example.com",
            "an explicit audience overrides the token endpoint"
        );
        assert_eq!(claims["exp"], 1_300);
    }

    #[test]
    fn literal_newlines_and_escaped_newlines_both_load() {
        let pem = test_key_pem();
        assert!(load_rsa_key(&pem).is_ok());
        // How a PEM usually survives a trip through an environment variable.
        assert!(load_rsa_key(&pem.replace('\n', "\\n")).is_ok());
    }

    #[test]
    fn a_pkcs1_key_is_named_rather_than_rejected_obscurely() {
        let err =
            load_rsa_key("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")
                .unwrap_err()
                .to_string();
        assert!(err.contains("PKCS#1"), "{err}");
        assert!(err.contains("openssl pkcs8"), "{err}");
    }

    #[test]
    fn an_encrypted_key_is_named_too() {
        let err = load_rsa_key(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("passphrase-encrypted"), "{err}");
    }

    #[test]
    fn a_malformed_key_never_echoes_its_own_bytes() {
        let err = load_rsa_key(
            "-----BEGIN PRIVATE KEY-----\nc2VjcmV0LW1hdGVyaWFs\n-----END PRIVATE KEY-----",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("rejected"), "{err}");
        assert!(
            !err.contains("c2VjcmV0"),
            "error leaked key material: {err}"
        );
        assert!(!err.contains("secret-material"), "{err}");
    }

    #[test]
    fn a_key_file_that_is_not_json_fails_without_printing_its_contents() {
        let err = from_key_file("-----BEGIN PRIVATE KEY-----leaked", &[], None)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("parsing the service-account JSON key"),
            "{err}"
        );
        assert!(!err.contains("leaked"), "{err}");
    }

    #[test]
    fn debug_output_never_carries_key_material() {
        let account = from_key_file(&google_key_json(&test_key_pem()), &[], None).unwrap();
        let rendered = format!("{account:?}");
        assert!(rendered.contains("iap@demo.iam.gserviceaccount.com"));
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
    }
}

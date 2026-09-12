//! Workload identity.
//!
//! The agent token proves *who* is calling. It is long-lived, identical for
//! every call that agent ever makes, and it carries the agent's entire standing
//! grant — so a copy of it, lifted out of a context window or a config file, is
//! the whole grant until somebody notices and rotates it.
//!
//! A workload token answers the other half: *what is this particular run allowed
//! to do, and until when*. The agent presents its agent token once, says which
//! requests it needs, and gets back a JWT this process signed that expires on
//! its own and covers nothing beyond what it asked for. That token is what goes
//! on the data plane.
//!
//! Three properties hold, and they are what make this worth the machinery:
//!
//! - **A scope can only narrow.** The ACL still runs on every request. The token
//!   says what the workload asked for; policy says what it may have; the request
//!   needs both. So a minted token can never grant something the policy does not,
//!   and a policy edit or a revoked rule bites immediately rather than at expiry.
//! - **Renewal rotates.** Renewing supersedes the token that renewed it, in one
//!   atomic step. There is never a moment when two live tokens share a lineage.
//! - **Use of a superseded token kills the lineage.** Either the workload raced
//!   its own renewal or somebody else is holding a copy, and from here those look
//!   identical — so both end the same way, loudly, in the audit log.
//!
//! The signing key is generated per process and never leaves it. Nothing is
//! persisted: a restart invalidates every outstanding token, which is the right
//! failure mode for a credential measured in minutes.

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use globset::GlobMatcher;
use parking_lot::Mutex;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

use crate::acl::{path_matches, AccessRequest, Kind, PathPattern};
use crate::config::{
    WorkloadIdentityConfig, WorkloadMode, MAX_WORKLOAD_LIFETIME_SECS, MIN_WORKLOAD_LIFETIME_SECS,
};

/// `iss`. Constant: `aud` is what actually pins a token to one process.
const ISSUER: &str = "mcp-iap";

/// Tolerated clock skew when checking `nbf`/`iat`. Not applied to `exp`: this
/// process both signs and verifies, so there is no other clock to disagree with,
/// and an expired token staying usable for another minute is not worth it.
const CLOCK_SKEW_SECS: i64 = 60;

/// How long a spent token stays in the ledger past its own expiry. Long enough
/// that a replay is still recognised as a replay rather than mistaken for a
/// token from a previous process, which is a much less interesting audit line.
const TOMBSTONE_SECS: i64 = 3600;

/// One thing a workload asked to be able to do, in the shape the ACL rules use
/// minus the parts a caller does not get to choose: no `agent` (it is the
/// caller) and no `action` (policy decides that, not the applicant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// `http`, `mcp`, or `*`.
    #[serde(default = "star")]
    pub kind: String,
    /// One configured upstream or MCP server. Not a glob: a workload that cannot
    /// name what it is reaching for has not scoped anything.
    pub target: String,
    #[serde(default = "star_vec")]
    pub methods: Vec<String>,
    #[serde(default = "doublestar_vec")]
    pub paths: Vec<String>,
}

fn star() -> String {
    "*".to_string()
}
fn star_vec() -> Vec<String> {
    vec!["*".to_string()]
}
fn doublestar_vec() -> Vec<String> {
    vec!["**".to_string()]
}

impl Grant {
    /// One line for the audit log and for an error a human has to act on.
    pub fn summary(&self) -> String {
        format!(
            "{} {} {} {}",
            self.kind,
            self.target,
            self.methods.join(","),
            self.paths.join(",")
        )
    }
}

struct CompiledGrant {
    kind: Option<Kind>,
    target: String,
    methods: Vec<GlobMatcher>,
    paths: Vec<PathPattern>,
}

impl CompiledGrant {
    fn permits(&self, request: &AccessRequest) -> bool {
        if let Some(kind) = self.kind {
            if kind != request.kind {
                return false;
            }
        }
        self.target == request.target
            && self.methods.iter().any(|m| m.is_match(&request.method))
            && path_matches(&self.paths, &request.path)
    }
}

/// A compiled scope: what the token covers, and the patterns it was written as.
pub struct Scope {
    grants: Vec<Grant>,
    compiled: Vec<CompiledGrant>,
}

impl std::fmt::Debug for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scope")
            .field("grants", &self.grants)
            .finish()
    }
}

impl Scope {
    pub fn compile(grants: Vec<Grant>) -> Result<Self> {
        let mut compiled = Vec::with_capacity(grants.len());
        for grant in &grants {
            let kind = match grant.kind.as_str() {
                "http" => Some(Kind::Http),
                "mcp" => Some(Kind::Mcp),
                "*" => None,
                other => anyhow::bail!("`kind` must be `http`, `mcp` or `*` (got `{other}`)"),
            };
            if grant.methods.is_empty() || grant.paths.is_empty() {
                anyhow::bail!("`methods` and `paths` must not be empty lists");
            }
            compiled.push(CompiledGrant {
                kind,
                target: grant.target.clone(),
                methods: grant
                    .methods
                    .iter()
                    .map(|m| crate::acl::method_glob(m))
                    .collect::<Result<_>>()
                    .context("scope methods")?,
                paths: grant
                    .paths
                    .iter()
                    .map(|p| crate::acl::path_glob(p))
                    .collect::<Result<_>>()
                    .context("scope paths")?,
            });
        }
        Ok(Scope { grants, compiled })
    }

    /// Whether this scope covers one request. Never the last word: the ACL runs
    /// afterwards and can still refuse.
    pub fn permits(&self, request: &AccessRequest) -> bool {
        self.compiled.iter().any(|grant| grant.permits(request))
    }

    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// Every target this scope names, for the `targets` check at mint time.
    pub fn targets(&self) -> impl Iterator<Item = &str> {
        self.grants.iter().map(|grant| grant.target.as_str())
    }

    pub fn summary(&self) -> Vec<String> {
        self.grants.iter().map(Grant::summary).collect()
    }
}

/// The claim set, as it is signed. The ledger is what enforcement reads; this is
/// what the workload can read about itself without asking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    /// The agent this workload belongs to.
    pub sub: String,
    /// This process. A token minted by any other instance fails here first.
    pub aud: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// This token.
    pub jti: String,
    /// This token and every token it is renewed into.
    pub lineage: String,
    /// How many renewals deep. `0` is the minted one.
    pub generation: u32,
    /// What the workload called itself. Free text, audited, never authorising.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    pub scope: Vec<Grant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenState {
    Active,
    /// Renewed away from. Presenting it again is a replay.
    Superseded,
    Revoked,
}

impl TokenState {
    fn as_str(self) -> &'static str {
        match self {
            TokenState::Active => "active",
            TokenState::Superseded => "superseded",
            TokenState::Revoked => "revoked",
        }
    }
}

struct Entry {
    agent: String,
    lineage: String,
    generation: u32,
    workload: Option<String>,
    expires_at: i64,
    state: TokenState,
    scope: Arc<Scope>,
}

/// A token that verified, and everything the request path needs from it.
#[derive(Clone)]
pub struct Verified {
    pub jti: String,
    pub agent: String,
    pub lineage: String,
    pub generation: u32,
    pub workload: Option<String>,
    pub expires_at: i64,
    pub scope: Arc<Scope>,
}

impl std::fmt::Debug for Verified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verified")
            .field("jti", &self.jti)
            .field("agent", &self.agent)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl Verified {
    /// The short form that goes in an audit record: enough to find the mint
    /// record for this token, and to tell two of an agent's workloads apart.
    pub fn label(&self) -> String {
        format!("{}/{}", short(&self.lineage), self.generation)
    }
}

fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

/// A freshly minted token, and the one it replaced.
#[derive(Debug)]
pub struct Minted {
    pub token: String,
    pub jti: String,
    pub lineage: String,
    pub generation: u32,
    pub expires_at: i64,
    pub expires_in: i64,
    pub scope: Vec<Grant>,
    /// The `jti` this one supersedes, on a renewal.
    pub replaced: Option<String>,
}

/// Everything that can go wrong, separated by what the caller should do about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadError {
    /// Not a JWT at all — the caller presented something else, and the agent
    /// registry should have a look at it before anyone reports a failure.
    NotAToken,
    /// Structurally a token, but not one of ours, or tampered with.
    Invalid(&'static str),
    Expired,
    Revoked,
    /// Presented after it was renewed away from. The lineage is dead now, and
    /// the agent comes along for the ride: a replay is the one event here worth
    /// waking somebody for, and "whose" is the first thing they will ask.
    Replayed {
        agent: String,
        lineage: String,
    },
    /// Ours, well-formed, but the agent it names is gone from the config.
    UnknownAgent(String),
    /// Rejected at mint time; the message is for the caller to act on.
    BadRequest(String),
    Disabled,
}

impl WorkloadError {
    /// The machine-readable code, which is also the `x-iap-decision` value.
    pub fn code(&self) -> &'static str {
        match self {
            WorkloadError::NotAToken | WorkloadError::Invalid(_) => "invalid_workload_token",
            WorkloadError::Expired => "workload_token_expired",
            WorkloadError::Revoked => "workload_token_revoked",
            WorkloadError::Replayed { .. } => "workload_token_replayed",
            WorkloadError::UnknownAgent(_) => "unknown_agent",
            WorkloadError::BadRequest(_) => "invalid_scope",
            WorkloadError::Disabled => "workload_identity_disabled",
        }
    }

    pub fn message(&self) -> String {
        match self {
            WorkloadError::NotAToken => "not a workload token".into(),
            WorkloadError::Invalid(why) => format!("the workload token is not valid: {why}"),
            WorkloadError::Expired => {
                "the workload token has expired — renew it, or mint a new one".into()
            }
            WorkloadError::Revoked => "the workload token has been revoked".into(),
            WorkloadError::Replayed { .. } => "this workload token was already renewed away \
                 from; its lineage has been revoked — mint a new one with the agent token"
                .into(),
            WorkloadError::UnknownAgent(agent) => {
                format!("agent `{agent}` is no longer configured")
            }
            WorkloadError::BadRequest(why) => why.clone(),
            WorkloadError::Disabled => {
                "workload identity is off in this proxy's policy file".into()
            }
        }
    }
}

/// The mint, the ledger, and the verifier. One per process.
pub struct WorkloadIssuer {
    mode: WorkloadMode,
    lifetime: u64,
    /// `aud`: random per process, so a token cannot outlive the instance that
    /// signed it even if the key somehow could.
    instance: String,
    kid: String,
    key: Ed25519KeyPair,
    public: Vec<u8>,
    tokens: Mutex<HashMap<String, Entry>>,
}

impl std::fmt::Debug for WorkloadIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorkloadIssuer")
            .field("mode", &self.mode)
            .field("lifetime", &self.lifetime)
            .field("instance", &self.instance)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl WorkloadIssuer {
    /// Generate this process's signing key. Fallible for the same reason
    /// `generate_token` is: a key this process cannot generate securely must
    /// stop it rather than quietly become something weaker.
    pub fn new(config: &WorkloadIdentityConfig) -> Result<Self> {
        let rng = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow::anyhow!("generating the workload signing key failed"))?;
        let key = Ed25519KeyPair::from_pkcs8(document.as_ref())
            .map_err(|_| anyhow::anyhow!("the generated workload signing key did not parse"))?;
        let public = key.public_key().as_ref().to_vec();

        Ok(WorkloadIssuer {
            mode: config.mode,
            lifetime: config
                .lifetime_secs
                .clamp(MIN_WORKLOAD_LIFETIME_SECS, MAX_WORKLOAD_LIFETIME_SECS),
            instance: uuid::Uuid::new_v4().to_string(),
            kid: hex::encode(&Sha256::digest(&public)[..8]),
            key,
            public,
            tokens: Mutex::new(HashMap::new()),
        })
    }

    pub fn mode(&self) -> WorkloadMode {
        self.mode
    }

    pub fn lifetime_secs(&self) -> u64 {
        self.lifetime
    }

    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// How many tokens this process is still accountable for.
    pub fn active_count(&self) -> usize {
        let now = now();
        self.tokens
            .lock()
            .values()
            .filter(|entry| entry.state == TokenState::Active && entry.expires_at > now)
            .count()
    }

    /// Mint a token for an agent. The caller has already proven it is that agent
    /// and has already checked the scope's targets against the agent's `targets`.
    pub fn mint(
        &self,
        agent: &str,
        workload: Option<String>,
        scope: Scope,
        lifetime_secs: Option<u64>,
    ) -> Result<Minted, WorkloadError> {
        if !self.mode.enabled() {
            return Err(WorkloadError::Disabled);
        }
        if scope.grants().is_empty() {
            return Err(WorkloadError::BadRequest(
                "`scope` is empty — a workload token has to say what it is for".into(),
            ));
        }
        let lineage = uuid::Uuid::new_v4().to_string();
        self.issue(
            agent,
            workload,
            Arc::new(scope),
            lifetime_secs,
            lineage,
            0,
            None,
        )
    }

    /// Rotate a token: the new one supersedes the old in the same lock, so the
    /// two are never both live. A renewal may re-scope — it is a fresh mint that
    /// keeps the lineage — but it can no more widen past the ACL than a mint can.
    pub fn renew(
        &self,
        presented: &Verified,
        scope: Option<Scope>,
        lifetime_secs: Option<u64>,
    ) -> Result<Minted, WorkloadError> {
        if !self.mode.enabled() {
            return Err(WorkloadError::Disabled);
        }
        let scope = match scope {
            Some(scope) if scope.grants().is_empty() => {
                return Err(WorkloadError::BadRequest(
                    "`scope` is empty — omit it to keep the current scope".into(),
                ))
            }
            Some(scope) => Arc::new(scope),
            None => Arc::clone(&presented.scope),
        };

        self.issue(
            &presented.agent,
            presented.workload.clone(),
            scope,
            lifetime_secs,
            presented.lineage.clone(),
            presented.generation.saturating_add(1),
            Some(presented.jti.clone()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn issue(
        &self,
        agent: &str,
        workload: Option<String>,
        scope: Arc<Scope>,
        lifetime_secs: Option<u64>,
        lineage: String,
        generation: u32,
        supersedes: Option<String>,
    ) -> Result<Minted, WorkloadError> {
        let lifetime = match lifetime_secs {
            // Asking for less than the policy allows is the whole idea, so it is
            // honoured; asking for more silently gets the policy's answer rather
            // than an error, because the ceiling is not the caller's business.
            Some(asked) => asked.clamp(MIN_WORKLOAD_LIFETIME_SECS, self.lifetime),
            None => self.lifetime,
        };

        let issued_at = now();
        let expires_at = issued_at + lifetime as i64;
        let jti = uuid::Uuid::new_v4().to_string();

        let claims = Claims {
            iss: ISSUER.to_string(),
            sub: agent.to_string(),
            aud: self.instance.clone(),
            iat: issued_at,
            nbf: issued_at,
            exp: expires_at,
            jti: jti.clone(),
            lineage: lineage.clone(),
            generation,
            workload: workload.clone(),
            scope: scope.grants().to_vec(),
        };
        let token = self.sign(&claims)?;

        {
            let mut tokens = self.tokens.lock();
            prune(&mut tokens, issued_at);
            // Supersede inside the same lock as the insert: a renewal that
            // published the new token before retiring the old would leave a
            // window where both are live, which is the property being bought.
            if let Some(previous) = &supersedes {
                if let Some(entry) = tokens.get_mut(previous) {
                    if entry.state == TokenState::Active {
                        entry.state = TokenState::Superseded;
                    }
                }
            }
            tokens.insert(
                jti.clone(),
                Entry {
                    agent: agent.to_string(),
                    lineage: lineage.clone(),
                    generation,
                    workload,
                    expires_at,
                    state: TokenState::Active,
                    scope,
                },
            );
        }

        Ok(Minted {
            token,
            jti,
            lineage,
            generation,
            expires_at,
            expires_in: lifetime as i64,
            scope: claims.scope,
            replaced: supersedes,
        })
    }

    /// Whether this is a token this process signed, without touching the
    /// ledger. Deliberately says nothing about whether it is still good: it
    /// answers "is this caller worth reading a request body for", and a token
    /// that is expired, revoked or replayed still deserves its precise error
    /// rather than a generic 401.
    pub fn is_ours(&self, presented: &str) -> bool {
        match self.verify_signature(presented) {
            Ok(claims) => claims.iss == ISSUER && claims.aud == self.instance,
            Err(_) => false,
        }
    }

    /// Verify a presented token: signature first, then the claims, then the
    /// ledger. Signature first on purpose — nothing about this process's state
    /// is reachable by presenting a token we did not sign.
    pub fn verify(&self, presented: &str) -> Result<Verified, WorkloadError> {
        let claims = self.verify_signature(presented)?;

        let now = now();
        if claims.iss != ISSUER || claims.aud != self.instance {
            return Err(WorkloadError::Invalid("issued by a different proxy"));
        }
        if claims.nbf > now + CLOCK_SKEW_SECS {
            return Err(WorkloadError::Invalid("not valid yet"));
        }
        if claims.exp <= now {
            return Err(WorkloadError::Expired);
        }

        let mut tokens = self.tokens.lock();
        let Some(entry) = tokens.get(&claims.jti) else {
            // We signed it and it has not expired, so the ledger lost it: either
            // it was pruned long after expiry, or this is a token from a lineage
            // this process no longer knows. Unknown means no.
            return Err(WorkloadError::Invalid("unknown token"));
        };

        match entry.state {
            TokenState::Active => {}
            TokenState::Revoked => return Err(WorkloadError::Revoked),
            TokenState::Superseded => {
                // A renewal happened and this copy kept being used. That is a
                // race with itself or a second holder, and the two are not
                // distinguishable from here — so the whole lineage goes.
                let agent = entry.agent.clone();
                let lineage = entry.lineage.clone();
                revoke_lineage(&mut tokens, &lineage);
                return Err(WorkloadError::Replayed { agent, lineage });
            }
        }

        if entry.expires_at <= now {
            return Err(WorkloadError::Expired);
        }

        Ok(Verified {
            jti: claims.jti,
            agent: entry.agent.clone(),
            lineage: entry.lineage.clone(),
            generation: entry.generation,
            workload: entry.workload.clone(),
            expires_at: entry.expires_at,
            // Enforcement reads the ledger's copy, not the claim set. They were
            // written together and cannot disagree, but only one of them is out
            // of reach of whoever is holding the token.
            scope: Arc::clone(&entry.scope),
        })
    }

    /// Revoke one token, or its whole lineage. Returns whether anything changed.
    pub fn revoke(&self, jti: &str, whole_lineage: bool) -> bool {
        let mut tokens = self.tokens.lock();
        let Some(entry) = tokens.get_mut(jti) else {
            return false;
        };
        if whole_lineage {
            let lineage = entry.lineage.clone();
            revoke_lineage(&mut tokens, &lineage);
            return true;
        }
        entry.state = TokenState::Revoked;
        true
    }

    /// Revoke every live token belonging to an agent. What `mcp-iap` reaches for
    /// when an agent is decommissioned mid-flight.
    pub fn revoke_agent(&self, agent: &str) -> usize {
        let mut tokens = self.tokens.lock();
        let mut revoked = 0;
        for entry in tokens.values_mut() {
            if entry.agent == agent && entry.state == TokenState::Active {
                entry.state = TokenState::Revoked;
                revoked += 1;
            }
        }
        revoked
    }

    fn sign(&self, claims: &Claims) -> Result<String, WorkloadError> {
        let header = serde_json::json!({ "alg": "EdDSA", "typ": "JWT", "kid": self.kid });
        let payload = serde_json::to_string(claims)
            .map_err(|_| WorkloadError::Invalid("claims did not serialise"))?;

        let mut signing_input = URL_SAFE_NO_PAD.encode(header.to_string());
        signing_input.push('.');
        signing_input.push_str(&URL_SAFE_NO_PAD.encode(payload));

        let signature = self.key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }

    fn verify_signature(&self, presented: &str) -> Result<Claims, WorkloadError> {
        let presented = presented.trim();
        let mut parts = presented.split('.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(WorkloadError::NotAToken);
        };
        if header.is_empty() || payload.is_empty() || signature.is_empty() {
            return Err(WorkloadError::NotAToken);
        }

        let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
            return Err(WorkloadError::NotAToken);
        };
        let Ok(header_bytes) = URL_SAFE_NO_PAD.decode(header) else {
            return Err(WorkloadError::NotAToken);
        };
        let Ok(header_json) = serde_json::from_slice::<serde_json::Value>(&header_bytes) else {
            return Err(WorkloadError::NotAToken);
        };
        // `alg` is read to reject, never to choose: the verifier uses the one
        // algorithm this process signs with, so `alg: none` and friends are just
        // a header that does not say `EdDSA`.
        if header_json.get("alg").and_then(|v| v.as_str()) != Some("EdDSA") {
            return Err(WorkloadError::Invalid("unexpected signature algorithm"));
        }

        let signing_input = &presented[..header.len() + 1 + payload.len()];
        UnparsedPublicKey::new(&ED25519, &self.public)
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| WorkloadError::Invalid("bad signature"))?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| WorkloadError::Invalid("undecodable claims"))?;
        serde_json::from_slice(&payload).map_err(|_| WorkloadError::Invalid("unreadable claims"))
    }
}

fn revoke_lineage(tokens: &mut HashMap<String, Entry>, lineage: &str) {
    for entry in tokens.values_mut() {
        if entry.lineage == lineage {
            entry.state = TokenState::Revoked;
        }
    }
}

/// Drop entries far enough past expiry that a replay of one is no longer worth
/// distinguishing from a token this process never issued.
fn prune(tokens: &mut HashMap<String, Entry>, now: i64) {
    tokens.retain(|_, entry| entry.expires_at + TOMBSTONE_SECS > now);
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The ledger state of one token, for `/token` introspection and the TUI.
pub fn state_of(issuer: &WorkloadIssuer, jti: &str) -> Option<&'static str> {
    issuer
        .tokens
        .lock()
        .get(jti)
        .map(|entry| entry.state.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issuer(mode: WorkloadMode) -> WorkloadIssuer {
        WorkloadIssuer::new(&WorkloadIdentityConfig {
            mode,
            lifetime_secs: 3600,
        })
        .unwrap()
    }

    fn scope(target: &str, methods: &[&str], paths: &[&str]) -> Scope {
        Scope::compile(vec![Grant {
            kind: "http".into(),
            target: target.into(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
        }])
        .unwrap()
    }

    fn mint(issuer: &WorkloadIssuer) -> Minted {
        issuer
            .mint(
                "claude",
                Some("review-bot".into()),
                scope("echo", &["POST"], &["/v1/messages"]),
                None,
            )
            .unwrap()
    }

    #[test]
    fn a_minted_token_verifies_and_carries_its_agent() {
        let issuer = issuer(WorkloadMode::Required);
        let minted = mint(&issuer);
        let verified = issuer.verify(&minted.token).unwrap();

        assert_eq!(verified.agent, "claude");
        assert_eq!(verified.generation, 0);
        assert_eq!(verified.workload.as_deref(), Some("review-bot"));
        assert_eq!(minted.expires_in, 3600);
    }

    #[test]
    fn a_scope_covers_what_it_names_and_nothing_else() {
        let scope = scope("echo", &["POST"], &["/v1/messages"]);

        assert!(scope.permits(&AccessRequest::http(
            "claude",
            "echo",
            "POST",
            "/v1/messages"
        )));
        // Wrong method, wrong path, wrong target, wrong kind.
        assert!(!scope.permits(&AccessRequest::http(
            "claude",
            "echo",
            "GET",
            "/v1/messages"
        )));
        assert!(!scope.permits(&AccessRequest::http("claude", "echo", "POST", "/v1/admin")));
        assert!(!scope.permits(&AccessRequest::http(
            "claude",
            "other",
            "POST",
            "/v1/messages"
        )));
        assert!(!scope.permits(&AccessRequest::mcp(
            "claude",
            "echo",
            "POST",
            "/v1/messages"
        )));
    }

    #[test]
    fn a_path_wildcard_in_a_scope_stops_at_a_separator_like_everywhere_else() {
        let scope = scope("echo", &["*"], &["/v1/models/*"]);
        assert!(scope.permits(&AccessRequest::http("a", "echo", "GET", "/v1/models/opus")));
        assert!(!scope.permits(&AccessRequest::http(
            "a",
            "echo",
            "GET",
            "/v1/models/opus/versions"
        )));
    }

    #[test]
    fn an_mcp_call_with_no_tool_name_needs_an_unconstrained_scope() {
        let listing = AccessRequest::mcp("claude", "notes", "tools/list", "");
        let named = Scope::compile(vec![Grant {
            kind: "mcp".into(),
            target: "notes".into(),
            methods: vec!["*".into()],
            paths: vec!["create_note".into()],
        }])
        .unwrap();
        let any = Scope::compile(vec![Grant {
            kind: "mcp".into(),
            target: "notes".into(),
            methods: vec!["*".into()],
            paths: vec!["**".into()],
        }])
        .unwrap();

        assert!(!named.permits(&listing));
        assert!(any.permits(&listing));
    }

    #[test]
    fn renewal_supersedes_the_token_that_renewed_it() {
        let issuer = issuer(WorkloadMode::Required);
        let first = mint(&issuer);
        let verified = issuer.verify(&first.token).unwrap();

        let second = issuer.renew(&verified, None, None).unwrap();
        assert_eq!(second.lineage, first.lineage);
        assert_eq!(second.generation, 1);
        assert_eq!(second.replaced.as_deref(), Some(first.jti.as_str()));

        // The new one works…
        assert!(issuer.verify(&second.token).is_ok());
        // …and the old one is gone the moment the new one exists, which is the
        // point: there is never a window where both are live.
        assert!(matches!(
            issuer.verify(&first.token).unwrap_err(),
            WorkloadError::Replayed { .. }
        ));
    }

    #[test]
    fn presenting_a_superseded_token_revokes_the_whole_lineage() {
        let issuer = issuer(WorkloadMode::Required);
        let first = mint(&issuer);
        let second = issuer
            .renew(&issuer.verify(&first.token).unwrap(), None, None)
            .unwrap();

        // Somebody else still has generation 0 and uses it.
        assert!(matches!(
            issuer.verify(&first.token).unwrap_err(),
            WorkloadError::Replayed { agent, .. } if agent == "claude"
        ));

        // The copy that was legitimately in use dies with it. A live token and a
        // stolen one are the same shape from here, so this fails closed.
        assert_eq!(
            issuer.verify(&second.token).unwrap_err(),
            WorkloadError::Revoked
        );
    }

    #[test]
    fn a_renewal_may_rescope_without_leaving_the_lineage() {
        let issuer = issuer(WorkloadMode::Required);
        let first = mint(&issuer);
        let narrowed = issuer
            .renew(
                &issuer.verify(&first.token).unwrap(),
                Some(scope("echo", &["GET"], &["/v1/models"])),
                None,
            )
            .unwrap();

        let verified = issuer.verify(&narrowed.token).unwrap();
        assert_eq!(verified.lineage, first.lineage);
        assert!(verified.scope.permits(&AccessRequest::http(
            "claude",
            "echo",
            "GET",
            "/v1/models"
        )));
        assert!(!verified.scope.permits(&AccessRequest::http(
            "claude",
            "echo",
            "POST",
            "/v1/messages"
        )));
    }

    #[test]
    fn revocation_is_immediate_and_covers_the_lineage_on_request() {
        let issuer = issuer(WorkloadMode::Required);
        let first = mint(&issuer);
        let second = issuer
            .renew(&issuer.verify(&first.token).unwrap(), None, None)
            .unwrap();

        assert!(issuer.revoke(&second.jti, true));
        assert_eq!(
            issuer.verify(&second.token).unwrap_err(),
            WorkloadError::Revoked
        );
        assert_eq!(issuer.active_count(), 0);
    }

    #[test]
    fn decommissioning_an_agent_kills_every_token_it_holds() {
        let issuer = issuer(WorkloadMode::Required);
        let mine = mint(&issuer);
        let theirs = issuer
            .mint("other", None, scope("echo", &["GET"], &["/**"]), None)
            .unwrap();

        assert_eq!(issuer.revoke_agent("claude"), 1);
        assert_eq!(
            issuer.verify(&mine.token).unwrap_err(),
            WorkloadError::Revoked
        );
        assert!(issuer.verify(&theirs.token).is_ok());
    }

    #[test]
    fn a_token_from_another_instance_never_verifies_here() {
        let one = issuer(WorkloadMode::Required);
        let two = issuer(WorkloadMode::Required);
        let minted = mint(&one);

        // Different key and different `aud`; the signature check stops it first.
        assert_eq!(
            two.verify(&minted.token).unwrap_err(),
            WorkloadError::Invalid("bad signature")
        );
    }

    #[test]
    fn a_tampered_scope_does_not_survive_the_signature() {
        let issuer = issuer(WorkloadMode::Required);
        let minted = mint(&issuer);
        let mut parts: Vec<&str> = minted.token.split('.').collect();

        let mut claims: Claims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        claims.scope[0].paths = vec!["/**".into()];
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_string(&claims).unwrap());
        parts[1] = &forged;

        assert_eq!(
            issuer.verify(&parts.join(".")).unwrap_err(),
            WorkloadError::Invalid("bad signature")
        );
    }

    #[test]
    fn an_agent_token_is_not_mistaken_for_a_workload_token() {
        let issuer = issuer(WorkloadMode::Required);
        // The caller needs `NotAToken` specifically: anything else and a plain
        // agent token would be reported as a broken JWT instead of being looked
        // up in the agent registry.
        assert_eq!(
            issuer.verify("iap_deadbeef").unwrap_err(),
            WorkloadError::NotAToken
        );
        assert_eq!(issuer.verify("").unwrap_err(), WorkloadError::NotAToken);
        assert_eq!(issuer.verify("a.b").unwrap_err(), WorkloadError::NotAToken);
    }

    #[test]
    fn alg_none_is_not_a_way_in() {
        let issuer = issuer(WorkloadMode::Required);
        let claims = serde_json::json!({
            "iss": "mcp-iap", "sub": "claude", "aud": issuer.instance,
            "iat": now(), "nbf": now(), "exp": now() + 3600,
            "jti": "forged", "lineage": "forged", "generation": 0,
            "scope": [{ "kind": "*", "target": "echo", "methods": ["*"], "paths": ["**"] }],
        });
        let token = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );

        assert_eq!(issuer.verify(&token).unwrap_err(), WorkloadError::NotAToken);
    }

    #[test]
    fn an_expired_token_is_expired_even_before_the_ledger_is_consulted() {
        let issuer = issuer(WorkloadMode::Required);
        let minted = issuer
            .mint("claude", None, scope("echo", &["*"], &["/**"]), Some(60))
            .unwrap();
        assert_eq!(minted.expires_in, 60);

        // Rewrite the ledger's clock rather than waiting a minute.
        issuer
            .tokens
            .lock()
            .get_mut(&minted.jti)
            .unwrap()
            .expires_at = now() - 1;
        assert_eq!(
            issuer.verify(&minted.token).unwrap_err(),
            WorkloadError::Expired
        );
    }

    #[test]
    fn a_lifetime_is_clamped_to_the_policy_ceiling_not_refused() {
        let issuer = WorkloadIssuer::new(&WorkloadIdentityConfig {
            mode: WorkloadMode::Required,
            lifetime_secs: 900,
        })
        .unwrap();

        let long = issuer
            .mint("claude", None, scope("echo", &["*"], &["/**"]), Some(86400))
            .unwrap();
        assert_eq!(long.expires_in, 900, "the policy ceiling applies");

        let short = issuer
            .mint("claude", None, scope("echo", &["*"], &["/**"]), Some(120))
            .unwrap();
        assert_eq!(short.expires_in, 120, "asking for less is the whole idea");

        let tiny = issuer
            .mint("claude", None, scope("echo", &["*"], &["/**"]), Some(1))
            .unwrap();
        assert_eq!(tiny.expires_in, 60, "below a minute is clock skew");
    }

    #[test]
    fn nothing_is_minted_when_workload_identity_is_off() {
        let issuer = issuer(WorkloadMode::Off);
        assert_eq!(
            issuer
                .mint("claude", None, scope("echo", &["*"], &["/**"]), None)
                .unwrap_err(),
            WorkloadError::Disabled
        );
    }

    #[test]
    fn an_empty_scope_is_refused() {
        let issuer = issuer(WorkloadMode::Required);
        let error = issuer
            .mint("claude", None, Scope::compile(vec![]).unwrap(), None)
            .unwrap_err();
        assert!(matches!(error, WorkloadError::BadRequest(_)));
    }

    #[test]
    fn expired_tokens_are_pruned_but_stay_replay_detectable_for_a_while() {
        let issuer = issuer(WorkloadMode::Required);
        let minted = mint(&issuer);
        issuer
            .tokens
            .lock()
            .get_mut(&minted.jti)
            .unwrap()
            .expires_at = now() - TOMBSTONE_SECS - 10;

        // Any mint prunes; the stale entry goes, and the live one stays.
        let fresh = mint(&issuer);
        let tokens = issuer.tokens.lock();
        assert!(!tokens.contains_key(&minted.jti));
        assert!(tokens.contains_key(&fresh.jti));
    }
}

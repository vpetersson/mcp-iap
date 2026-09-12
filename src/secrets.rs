//! Secret references and resolution.
//!
//! The whole point of the IAP is that the agent never sees the real credential.
//! Credentials therefore live behind a *reference* in the config file — the file
//! itself stays safe to commit — and are resolved inside this process only.

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use zeroize::Zeroize;

/// A resolved credential. Never `Debug`-printed, zeroed when the last handle drops.
#[derive(Clone)]
pub struct Secret(Arc<SecretInner>);

struct SecretInner(String);

impl Drop for SecretInner {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Secret {
    pub fn new(value: String) -> Self {
        Secret(Arc::new(SecretInner(value)))
    }

    pub fn expose(&self) -> &str {
        &self.0 .0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// Where a secret comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// `env:ANTHROPIC_API_KEY`
    Env(String),
    /// `file:/run/secrets/anthropic`
    File(PathBuf),
    /// `op://Private/Anthropic/credential` — resolved with the 1Password CLI.
    OnePassword(String),
    /// `literal:sk-...` — supported for tests and demos, warned about on load.
    Literal(String),
}

impl SecretRef {
    pub fn parse(raw: &str) -> Result<Self> {
        if let Some(rest) = raw.strip_prefix("env:") {
            if rest.is_empty() {
                bail!("`env:` secret reference is missing a variable name");
            }
            Ok(SecretRef::Env(rest.to_string()))
        } else if let Some(rest) = raw.strip_prefix("file:") {
            if rest.is_empty() {
                bail!("`file:` secret reference is missing a path");
            }
            Ok(SecretRef::File(PathBuf::from(rest)))
        } else if raw.starts_with("op://") {
            Ok(SecretRef::OnePassword(raw.to_string()))
        } else if let Some(rest) = raw.strip_prefix("literal:") {
            Ok(SecretRef::Literal(rest.to_string()))
        } else {
            bail!(
                "unrecognised secret reference `{}` — expected `env:NAME`, `file:/path`, \
                 `op://vault/item/field` or `literal:VALUE`",
                redact_for_error(raw)
            )
        }
    }

    /// True for reference kinds that put the plaintext in the config file itself.
    pub fn is_inline(&self) -> bool {
        matches!(self, SecretRef::Literal(_))
    }
}

/// A reference rendered for display. Everything but `literal:` is a *pointer*
/// to a credential and safe to print; `literal:` is the credential itself, so it
/// is masked — `mcp-iap list` must never put a secret on a terminal.
pub fn display_ref(raw: &str) -> String {
    match SecretRef::parse(raw) {
        Ok(SecretRef::Literal(_)) => "literal:***".to_string(),
        Ok(_) => raw.to_string(),
        // Unparseable references never resolve, but a pasted credential is
        // exactly how one gets written, so mask it the way errors do.
        Err(_) => redact_for_error(raw),
    }
}

fn redact_for_error(raw: &str) -> String {
    // Never echo a possible credential back into logs or error strings.
    match raw.split_once(':') {
        Some((scheme, _)) => format!("{scheme}:***"),
        None => "***".to_string(),
    }
}

/// Resolves secret references, caching results so a 1Password lookup happens once.
pub struct SecretResolver {
    cache: Mutex<HashMap<String, Secret>>,
    op_bin: String,
}

impl SecretResolver {
    pub fn new(op_bin: impl Into<String>) -> Self {
        SecretResolver {
            cache: Mutex::new(HashMap::new()),
            op_bin: op_bin.into(),
        }
    }

    /// Seed the cache directly. Used by tests and by `--standalone` bootstrapping.
    pub fn preset(&self, raw: &str, value: Secret) {
        self.cache.lock().insert(raw.to_string(), value);
    }

    /// Resolve a raw reference string. Blocking: 1Password shells out to `op`.
    pub fn resolve(&self, raw: &str) -> Result<Secret> {
        if let Some(hit) = self.cache.lock().get(raw) {
            return Ok(hit.clone());
        }

        let secret = match SecretRef::parse(raw)? {
            SecretRef::Env(name) => {
                let value = std::env::var(&name).with_context(|| {
                    format!("environment variable `{name}` is not set (from `env:{name}`)")
                })?;
                Secret::new(value)
            }
            SecretRef::File(path) => {
                let value = std::fs::read_to_string(&path)
                    .with_context(|| format!("reading secret file `{}`", path.display()))?;
                Secret::new(value.trim_end_matches(['\n', '\r']).to_string())
            }
            SecretRef::OnePassword(reference) => self.resolve_onepassword(&reference)?,
            SecretRef::Literal(value) => Secret::new(value),
        };

        self.cache.lock().insert(raw.to_string(), secret.clone());
        Ok(secret)
    }

    fn resolve_onepassword(&self, reference: &str) -> Result<Secret> {
        let output = Command::new(&self.op_bin)
            .args(["read", "--no-newline", reference])
            .output()
            .with_context(|| {
                format!(
                    "running `{}` — install the 1Password CLI to use `op://` references",
                    self.op_bin
                )
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "`op read {reference}` failed ({}): {}",
                output.status,
                stderr.trim()
            );
        }

        let value = String::from_utf8(output.stdout)
            .context("1Password returned a non-UTF-8 secret")?
            .trim_end_matches(['\n', '\r'])
            .to_string();

        if value.is_empty() {
            bail!("`op read {reference}` returned an empty value");
        }
        Ok(Secret::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_supported_scheme() {
        assert_eq!(
            SecretRef::parse("env:TOKEN").unwrap(),
            SecretRef::Env("TOKEN".into())
        );
        assert_eq!(
            SecretRef::parse("file:/run/secrets/x").unwrap(),
            SecretRef::File(PathBuf::from("/run/secrets/x"))
        );
        assert_eq!(
            SecretRef::parse("op://Private/Anthropic/credential").unwrap(),
            SecretRef::OnePassword("op://Private/Anthropic/credential".into())
        );
        assert_eq!(
            SecretRef::parse("literal:hunter2").unwrap(),
            SecretRef::Literal("hunter2".into())
        );
    }

    #[test]
    fn rejects_bare_values_so_a_pasted_key_is_never_silently_accepted() {
        let err = SecretRef::parse("sk-ant-secret").unwrap_err().to_string();
        assert!(err.contains("unrecognised secret reference"));
        assert!(
            !err.contains("sk-ant-secret"),
            "error leaked the value: {err}"
        );
    }

    #[test]
    fn errors_never_echo_the_value_after_the_scheme() {
        let err = SecretRef::parse("bogus:sk-ant-secret")
            .unwrap_err()
            .to_string();
        assert!(err.contains("bogus:***"));
        assert!(!err.contains("sk-ant-secret"));
    }

    #[test]
    fn debug_never_reveals_the_secret() {
        let s = Secret::new("sk-ant-supersecret".into());
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(s.expose(), "sk-ant-supersecret");
    }

    #[test]
    fn env_and_file_resolve_and_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "from-file\n").unwrap();

        let resolver = SecretResolver::new("op");
        std::env::set_var("LLM_IAP_TEST_SECRET", "from-env");

        assert_eq!(
            resolver
                .resolve("env:LLM_IAP_TEST_SECRET")
                .unwrap()
                .expose(),
            "from-env"
        );
        assert_eq!(
            resolver
                .resolve(&format!("file:{}", path.display()))
                .unwrap()
                .expose(),
            "from-file",
            "trailing newline should be trimmed"
        );

        // Cached: removing the source still resolves.
        std::env::remove_var("LLM_IAP_TEST_SECRET");
        assert_eq!(
            resolver
                .resolve("env:LLM_IAP_TEST_SECRET")
                .unwrap()
                .expose(),
            "from-env"
        );
    }
}

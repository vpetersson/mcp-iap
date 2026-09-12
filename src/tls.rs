//! TLS for the two listeners.
//!
//! The agent's bearer token and the operator's admin token are both on the
//! wire, and this process holds every upstream credential behind them. On one
//! host loopback is enough; the moment an agent is somewhere else, it is not.
//!
//! Everything here happens at startup: the certificate and the key are resolved
//! through the same `SecretResolver` as any other credential, parsed, and
//! checked against each other *before* anything binds. A proxy that comes up
//! and then cannot complete a handshake is worse than one that refused to start.

use anyhow::{anyhow, bail, Context, Result};
use axum::Router;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::{ServerConfig, TlsConfig};
use crate::secrets::SecretResolver;

/// What the listener offers. The upstream client already negotiates h2; the
/// listener is not the thing that forces agents back down to 1.1.
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// A running listener. Both arms resolve to the same thing so `run` can select
/// over them without caring which one it got.
pub type Serving = std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>;

/// The parsed certificates for both listeners, or `None` where the config asked
/// for plain HTTP.
pub struct ServerTls {
    pub proxy: Option<Arc<rustls::ServerConfig>>,
    pub admin: Option<Arc<rustls::ServerConfig>>,
}

impl ServerTls {
    /// Resolve and parse everything the listeners will need. Fails on a missing
    /// file, a locked vault, a malformed PEM, or a key that does not belong to
    /// the certificate.
    pub fn load(server: &ServerConfig, resolver: &SecretResolver) -> Result<Self> {
        let proxy = match &server.tls {
            Some(tls) => Some(load_one(tls, resolver).context("server.tls")?),
            None => None,
        };
        // `admin_tls_material` already decided that an unnamed control plane
        // inherits the proxy's certificate; reuse the parsed one rather than
        // resolving the same reference twice.
        let admin = match (&server.admin_tls, &proxy) {
            (Some(tls), _) => Some(load_one(tls, resolver).context("server.admin_tls")?),
            (None, Some(shared)) => Some(Arc::clone(shared)),
            (None, None) => None,
        };
        Ok(ServerTls { proxy, admin })
    }

    pub fn proxy_scheme(&self) -> &'static str {
        scheme(self.proxy.is_some())
    }

    pub fn admin_scheme(&self) -> &'static str {
        scheme(self.admin.is_some())
    }
}

/// Deliberately hand-written: a certificate is a credential's other half, and
/// nothing about it needs to survive a `{:?}` into a log. The scheme is the only
/// part that is ever useful there.
impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTls")
            .field("proxy", &self.proxy_scheme())
            .field("admin", &self.admin_scheme())
            .finish()
    }
}

pub fn scheme(tls: bool) -> &'static str {
    if tls {
        "https"
    } else {
        "http"
    }
}

fn load_one(tls: &TlsConfig, resolver: &SecretResolver) -> Result<Arc<rustls::ServerConfig>> {
    let cert = resolver.resolve(&tls.cert).context("cert")?;
    let key = resolver.resolve(&tls.key).context("key")?;
    build(cert.expose(), key.expose())
}

/// Turn a PEM chain and a PEM key into a server config.
///
/// Versions and cipher suites are rustls's defaults on purpose. This is a
/// security product; a policy file that can select TLS 1.0 is a liability, so
/// there is no knob for it.
pub fn build(cert_pem: &str, key_pem: &str) -> Result<Arc<rustls::ServerConfig>> {
    // A `file:` reference arrives with its trailing newline trimmed, and PEM
    // wants one after the final `-----END-----`. Chained rather than copied:
    // the key should not gain a second, un-zeroed home on the way through.
    let mut cert_reader = cert_pem.as_bytes().chain(&b"\n"[..]);
    let chain = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parsing the certificate chain")?;
    if chain.is_empty() {
        bail!("the `cert` reference resolved to no PEM certificate — it should be the leaf first, then any intermediates");
    }

    let mut key_reader = key_pem.as_bytes().chain(&b"\n"[..]);
    // The parse error is dropped rather than reported: nothing derived from the
    // key's own bytes belongs in a log line.
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|_| anyhow!("the `key` reference did not resolve to readable PEM"))?
        .context("the `key` reference resolved to no PEM private key (PKCS#8, PKCS#1 or SEC1)")?;

    // The provider is named rather than left to the process default: the same
    // `ring` that the upstream client already uses, chosen here and not by
    // whichever crate happened to install a default first.
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("selecting TLS versions")?
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .map_err(|error| anyhow!("the certificate and the private key do not go together: {error}"))?;

    config.alpn_protocols = ALPN.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Serve `router` on an already-bound listener, over TLS when one was loaded.
///
/// The listener is bound by the caller so the address it actually got — `:0` in
/// the tests — is known before anything is served, and so a bind failure is
/// still a startup failure rather than a task that dies later.
///
/// The TLS arm hands the accept loop to `axum-server`, which completes each
/// handshake on its own task and abandons it after ten seconds. Doing it inline
/// would let one client that opens a connection and then says nothing stall
/// every other agent's accept.
pub fn serve(
    listener: std::net::TcpListener,
    router: Router,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<Serving> {
    listener
        .set_nonblocking(true)
        .context("putting the listener in non-blocking mode")?;
    let service = router.into_make_service_with_connect_info::<SocketAddr>();

    Ok(match tls {
        Some(config) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_config(config);
            Box::pin(axum_server::from_tcp_rustls(listener, config)?.serve(service))
        }
        None => {
            let listener = tokio::net::TcpListener::from_std(listener)
                .context("handing the listener to the async runtime")?;
            Box::pin(std::future::IntoFuture::into_future(axum::serve(
                listener, service,
            )))
        }
    })
}

/// An HTTP client that trusts the control plane's own certificate.
///
/// The MCP bridge reads the same policy file as the daemon, so when the control
/// plane serves a certificate no public root signs — the normal case for a
/// loopback listener — the bridge can trust exactly that one and nothing else
/// new. Public roots stay trusted, so a real certificate needs nothing here.
pub fn control_plane_client(
    material: Option<&TlsConfig>,
    resolver: &SecretResolver,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if let Some(tls) = material {
        let pem = resolver
            .resolve(&tls.cert)
            .context("resolving the control plane's certificate")?;
        let certificates = reqwest::Certificate::from_pem_bundle(pem.expose().as_bytes())
            .context("parsing the control plane's certificate")?;
        for certificate in certificates {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder
        .build()
        .context("building the control-plane HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate for `localhost`, as PEM.
    pub(crate) fn self_signed() -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn a_matching_pair_loads_and_offers_both_protocols() {
        let (cert, key) = self_signed();
        let config = build(&cert, &key).unwrap();
        assert_eq!(
            config.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
    }

    #[test]
    fn a_trailing_newline_is_not_required() {
        // `file:` references arrive trimmed; that must not look like bad PEM.
        let (cert, key) = self_signed();
        build(cert.trim_end(), key.trim_end()).unwrap();
    }

    #[test]
    fn a_key_from_a_different_certificate_is_refused_at_load() {
        let (cert, _) = self_signed();
        let (_, other_key) = self_signed();
        let error = build(&cert, &other_key).unwrap_err().to_string();
        assert!(error.contains("do not go together"), "{error}");
    }

    #[test]
    fn an_empty_or_malformed_pem_names_the_field_that_is_wrong() {
        let (cert, key) = self_signed();

        let error = build("", &key).unwrap_err().to_string();
        assert!(error.contains("`cert`"), "{error}");

        let error = build(&cert, "").unwrap_err().to_string();
        assert!(error.contains("`key`"), "{error}");

        // A certificate pasted into `key` is the likely mistake, and it is the
        // one that would otherwise fail much later.
        let error = build(&cert, &cert).unwrap_err().to_string();
        assert!(error.contains("`key`"), "{error}");
    }

    #[test]
    fn no_error_ever_carries_the_key() {
        let (cert, key) = self_signed();
        // The body of a PEM key, without the armour, is what must not surface.
        let body: String = key
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert!(body.len() > 40, "sanity: the key has a body to leak");

        // A half-copied key, the wrong key, and a key where a certificate
        // belongs: three ways to be handed something this must not repeat.
        for error in [
            build(&cert, &key[..key.len() / 2]).unwrap_err(),
            build(&cert, &self_signed().1).unwrap_err(),
            build(&key, &key).unwrap_err(),
        ] {
            let rendered = format!("{error:#}");
            assert!(
                !rendered.contains(&body[..40]),
                "error leaked the key: {rendered}"
            );
        }
    }

    #[test]
    fn the_control_plane_inherits_the_proxys_certificate_but_can_override_it() {
        let (cert, key) = self_signed();
        let resolver = SecretResolver::new("op");
        let material = TlsConfig {
            cert: format!("literal:{cert}"),
            key: format!("literal:{key}"),
        };

        let mut server = ServerConfig {
            tls: Some(material.clone()),
            ..Default::default()
        };
        assert_eq!(server.admin_tls_material(), Some(&material));
        let loaded = ServerTls::load(&server, &resolver).unwrap();
        assert!(Arc::ptr_eq(
            loaded.proxy.as_ref().unwrap(),
            loaded.admin.as_ref().unwrap()
        ));
        assert_eq!(loaded.proxy_scheme(), "https");
        assert_eq!(loaded.admin_scheme(), "https");

        let (other_cert, other_key) = self_signed();
        let own = TlsConfig {
            cert: format!("literal:{other_cert}"),
            key: format!("literal:{other_key}"),
        };
        server.admin_tls = Some(own.clone());
        assert_eq!(server.admin_tls_material(), Some(&own));
        let loaded = ServerTls::load(&server, &resolver).unwrap();
        assert!(!Arc::ptr_eq(
            loaded.proxy.as_ref().unwrap(),
            loaded.admin.as_ref().unwrap()
        ));
    }

    #[test]
    fn no_tls_section_means_plain_http() {
        let loaded = ServerTls::load(&ServerConfig::default(), &SecretResolver::new("op")).unwrap();
        assert!(loaded.proxy.is_none() && loaded.admin.is_none());
        assert_eq!(loaded.proxy_scheme(), "http");
        assert_eq!(loaded.admin_scheme(), "http");
    }

    #[test]
    fn a_control_plane_certificate_alone_leaves_the_proxy_alone() {
        let (cert, key) = self_signed();
        let server = ServerConfig {
            admin_tls: Some(TlsConfig {
                cert: format!("literal:{cert}"),
                key: format!("literal:{key}"),
            }),
            ..Default::default()
        };
        let loaded = ServerTls::load(&server, &SecretResolver::new("op")).unwrap();
        assert!(loaded.proxy.is_none());
        assert!(loaded.admin.is_some());
    }

    #[test]
    fn the_error_names_which_section_failed() {
        let server = ServerConfig {
            tls: Some(TlsConfig {
                cert: "file:/nonexistent/mcp-iap/cert.pem".into(),
                key: "file:/nonexistent/mcp-iap/key.pem".into(),
            }),
            ..Default::default()
        };
        let error = format!(
            "{:#}",
            ServerTls::load(&server, &SecretResolver::new("op")).unwrap_err()
        );
        assert!(error.contains("server.tls"), "{error}");
        assert!(error.contains("cert"), "{error}");
    }
}

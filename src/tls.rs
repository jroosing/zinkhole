//! TLS for connections zinkhole makes (DNS over HTTPS, lists): rustls with
//! the ring provider, its safe default versions, and Mozilla's root
//! certificates compiled in, so no system certificate store is needed.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};

/// The root certificates of the public web.
#[must_use]
pub fn public_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// A client config that trusts `roots`.
#[must_use]
pub fn client_config(roots: RootCertStore) -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    match ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions() {
        Ok(builder) => builder.with_root_certificates(roots).with_no_client_auth(),
        // The ring provider supports the default versions; should that ever
        // change, trust nothing rather than fail.
        Err(_) => ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    }
}

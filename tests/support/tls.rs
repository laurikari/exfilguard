use std::sync::Arc;

use anyhow::Result;
use rustls::{RootCertStore, client::ClientConfig, crypto::ring};

pub fn build_proxy_tls_configs(
    root_store: RootCertStore,
) -> Result<(Arc<ClientConfig>, Arc<ClientConfig>)> {
    let http1 = build_client_tls(root_store.clone())?;
    let http2 = build_client_tls_h2(root_store)?;
    Ok((http1, http2))
}

pub fn build_client_tls(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    build_client_tls_with_protocols(root_store, vec![b"http/1.1".to_vec()])
}

pub fn build_client_tls_h2(root_store: RootCertStore) -> Result<Arc<ClientConfig>> {
    build_client_tls_with_protocols(root_store, vec![b"h2".to_vec(), b"http/1.1".to_vec()])
}

pub fn build_client_tls_with_protocols(
    root_store: RootCertStore,
    protocols: Vec<Vec<u8>>,
) -> Result<Arc<ClientConfig>> {
    let provider = ring::default_provider();
    let builder = ClientConfig::builder_with_provider(provider.into());
    let builder = builder.with_safe_default_protocol_versions()?;
    let builder = builder.with_root_certificates(Arc::new(root_store));
    let mut config = builder.with_no_client_auth();
    config.alpn_protocols = protocols;
    Ok(Arc::new(config))
}

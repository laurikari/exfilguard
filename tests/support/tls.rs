use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::Result;
use rustls::{
    RootCertStore,
    client::ClientConfig,
    crypto::ring,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use exfilguard::tls::ca::CertificateAuthority;

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

pub fn build_upstream_tls_config(
    ca: &CertificateAuthority,
    host: &str,
) -> Result<Arc<rustls::ServerConfig>> {
    build_upstream_tls_config_with_alpn(ca, host, vec![b"http/1.1".to_vec()])
}

pub fn build_upstream_h2_tls_config(
    ca: &CertificateAuthority,
    host: &str,
) -> Result<Arc<rustls::ServerConfig>> {
    build_upstream_tls_config_with_alpn(ca, host, vec![b"h2".to_vec()])
}

pub fn build_upstream_tls_config_with_alpn(
    ca: &CertificateAuthority,
    host: &str,
    protocols: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ServerConfig>> {
    let minted = ca.mint_leaf(&[host], StdDuration::from_secs(3600))?;
    let provider = ring::default_provider();
    let builder = rustls::ServerConfig::builder_with_provider(provider.into());
    let builder = builder.with_safe_default_protocol_versions()?;
    let builder = builder.with_no_client_auth();
    let chain: Vec<_> = minted
        .chain_der
        .iter()
        .map(|bytes| CertificateDer::from(bytes.clone()))
        .collect();
    let key_der = PrivateKeyDer::try_from(minted.private_key_der.to_vec())
        .map_err(|err| anyhow::anyhow!("invalid upstream private key: {err}"))?;
    let mut config = builder.with_single_cert(chain, key_der)?;
    config.alpn_protocols = protocols;
    Ok(Arc::new(config))
}

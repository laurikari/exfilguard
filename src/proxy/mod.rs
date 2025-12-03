pub mod allow_log;
pub mod cache;
pub mod connect;
pub mod forward_error;
pub mod forward_limits;
pub mod headers;
pub mod http;
pub mod http2;
pub mod listener;
pub mod policy_eval;
pub mod policy_response;
pub mod request;
pub mod request_pipeline;
mod resolver;
pub mod upstream;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::watch;

use crate::{
    policy::matcher::PolicySnapshot,
    settings::Settings,
    tls::{ca::CertificateAuthority, issuer::TlsIssuer},
};
use rustls::client::ClientConfig;

#[derive(Clone)]
pub struct PolicyStore {
    rx: watch::Receiver<PolicySnapshot>,
}

impl PolicyStore {
    pub fn new(rx: watch::Receiver<PolicySnapshot>) -> Self {
        Self { rx }
    }

    pub fn snapshot(&self) -> PolicySnapshot {
        self.rx.borrow().clone()
    }
}

#[derive(Clone)]
pub struct AppContext {
    pub settings: Arc<Settings>,
    pub policies: PolicyStore,
    pub tls: Arc<TlsContext>,
    pub cache: Option<Arc<cache::HttpCache>>,
}

impl AppContext {
    pub fn new(
        settings: Arc<Settings>,
        policies: PolicyStore,
        tls: Arc<TlsContext>,
        cache: Option<Arc<cache::HttpCache>>,
    ) -> Self {
        Self {
            settings,
            policies,
            tls,
            cache,
        }
    }
}

#[derive(Clone)]
pub struct TlsContext {
    pub ca: Arc<CertificateAuthority>,
    pub issuer: Arc<TlsIssuer>,
    pub client_http1: Arc<ClientConfig>,
    pub client_http2: Arc<ClientConfig>,
}

impl TlsContext {
    pub fn new(
        ca: Arc<CertificateAuthority>,
        issuer: Arc<TlsIssuer>,
        client_http1: Arc<ClientConfig>,
        client_http2: Arc<ClientConfig>,
    ) -> Self {
        Self {
            ca,
            issuer,
            client_http1,
            client_http2,
        }
    }
}

pub async fn run(app: AppContext) -> Result<()> {
    listener::start_listener(app).await
}

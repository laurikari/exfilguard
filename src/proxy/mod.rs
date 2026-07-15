mod admission;
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
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

pub(crate) use self::resolver::{
    UpstreamResolver, default_upstream_resolver, permissive_test_upstream_resolver,
};
use crate::{policy::matcher::PolicySnapshot, settings::Settings, tls::issuer::TlsIssuer};
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
    client_connections: Arc<admission::ClientConnectionLimiter>,
    proxy_protocol_pending_connections: Arc<Semaphore>,
    upstream_resolver: Arc<dyn UpstreamResolver>,
}

impl AppContext {
    pub fn new(
        settings: Arc<Settings>,
        policies: PolicyStore,
        tls: Arc<TlsContext>,
        cache: Option<Arc<cache::HttpCache>>,
    ) -> Self {
        let proxy_protocol_pending_connections = Arc::new(Semaphore::new(
            settings.proxy_protocol_max_pending_connections,
        ));
        Self {
            settings,
            policies,
            tls,
            cache,
            client_connections: Arc::new(admission::ClientConnectionLimiter::default()),
            proxy_protocol_pending_connections,
            upstream_resolver: default_upstream_resolver(),
        }
    }

    pub(crate) fn with_upstream_resolver(
        mut self,
        upstream_resolver: Arc<dyn UpstreamResolver>,
    ) -> Self {
        self.upstream_resolver = upstream_resolver;
        self
    }

    #[doc(hidden)]
    pub fn with_permissive_test_upstream_resolver(self) -> Self {
        self.with_upstream_resolver(permissive_test_upstream_resolver())
    }

    pub(crate) fn upstream_resolver(&self) -> &dyn UpstreamResolver {
        self.upstream_resolver.as_ref()
    }

    pub(crate) fn client_connections(&self) -> &Arc<admission::ClientConnectionLimiter> {
        &self.client_connections
    }

    pub(crate) fn try_acquire_proxy_protocol_pending(&self) -> Option<OwnedSemaphorePermit> {
        self.proxy_protocol_pending_connections
            .clone()
            .try_acquire_owned()
            .ok()
    }
}

#[derive(Clone)]
pub struct TlsContext {
    pub issuer: Arc<TlsIssuer>,
    pub client_http1: Arc<ClientConfig>,
    pub client_http2: Arc<ClientConfig>,
}

impl TlsContext {
    pub fn new(
        issuer: Arc<TlsIssuer>,
        client_http1: Arc<ClientConfig>,
        client_http2: Arc<ClientConfig>,
    ) -> Self {
        Self {
            issuer,
            client_http1,
            client_http2,
        }
    }
}

pub async fn run(app: AppContext) -> Result<()> {
    listener::start_listener(app).await
}

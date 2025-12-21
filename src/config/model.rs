use std::net::IpAddr;
use std::sync::Arc;

use http::{Method, StatusCode};
use ipnet::IpNet;

#[derive(Debug, Clone)]
pub struct Config {
    pub clients: Vec<Client>,
    pub policies: Vec<Policy>,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub name: Arc<str>,
    pub selector: ClientSelector,
    pub policies: Arc<[Arc<str>]>,
    pub fallback: bool,
}

#[derive(Debug, Clone)]
pub enum ClientSelector {
    Ip(IpAddr),
    Cidr(IpNet),
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub name: Arc<str>,
    pub rules: Arc<[Rule]>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: Arc<str>,
    pub action: RuleAction,
    pub methods: MethodMatch,
    pub url_pattern: Option<UrlPattern>,
    pub inspect_payload: bool,
    pub allow_private_upstream: bool,
    pub cache: Option<CacheConfig>,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub force_cache_duration: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum RuleAction {
    Allow,
    Deny {
        status: StatusCode,
        reason: Option<Arc<str>>,
        body: Option<Arc<str>>,
    },
}

#[derive(Debug, Clone)]
pub enum MethodMatch {
    Any,
    List(Vec<Method>),
}

#[derive(Debug, Clone)]
pub struct UrlPattern {
    pub scheme: Scheme,
    pub host: Arc<str>,
    pub port: Option<u16>,
    pub path: Option<Arc<str>>,
    pub original: Arc<str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub const fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

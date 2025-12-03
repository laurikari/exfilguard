use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use std::time::Duration;

use globset::GlobMatcher;
use http::Method;
use ipnet::IpNet;
use regex::Regex;

use crate::config::{RuleAction, Scheme};

#[derive(Debug, Clone)]
pub struct CompiledConfig {
    pub clients: Vec<ClientEntry>,
    pub policies: Arc<[Arc<CompiledPolicy>]>,
    pub ip_clients: HashMap<IpAddr, usize>,
    pub cidr_trie: CidrTrie,
    pub default_client: usize,
}

#[derive(Debug, Clone)]
pub struct ClientEntry {
    pub name: Arc<str>,
    pub policies: Arc<[usize]>,
}

#[derive(Debug, Clone)]
pub struct CidrTrie {
    v4: PrefixTrie,
    v6: PrefixTrie,
}

impl CidrTrie {
    pub fn new() -> Self {
        Self {
            v4: PrefixTrie::new(32),
            v6: PrefixTrie::new(128),
        }
    }

    pub fn insert(&mut self, net: IpNet, index: usize) {
        match net {
            IpNet::V4(v4) => {
                let prefix = u32::from(v4.network()) as u128;
                self.v4.insert(prefix, v4.prefix_len(), index);
            }
            IpNet::V6(v6) => {
                let prefix = u128::from(v6.network());
                self.v6.insert(prefix, v6.prefix_len(), index);
            }
        }
    }

    pub fn find(&self, addr: IpAddr) -> Option<usize> {
        match addr {
            IpAddr::V4(v4) => self.v4.find(u32::from(v4) as u128),
            IpAddr::V6(v6) => self.v6.find(u128::from(v6)),
        }
    }
}

impl Default for CidrTrie {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct PrefixTrie {
    nodes: Vec<TrieNode>,
    total_bits: u8,
}

impl PrefixTrie {
    fn new(total_bits: u8) -> Self {
        Self {
            nodes: vec![TrieNode::default()],
            total_bits,
        }
    }

    fn insert(&mut self, prefix: u128, prefix_len: u8, value: usize) {
        let mut node_idx = 0usize;
        for bit in 0..prefix_len {
            let shift = self.total_bits - 1 - bit;
            let direction = ((prefix >> shift) & 1) as usize;
            let next_idx = match self.nodes[node_idx].next[direction] {
                Some(idx) => idx,
                None => {
                    let idx = self.nodes.len();
                    self.nodes.push(TrieNode::default());
                    self.nodes[node_idx].next[direction] = Some(idx);
                    idx
                }
            };
            node_idx = next_idx;
        }
        self.nodes[node_idx].value = Some(value);
    }

    fn find(&self, addr: u128) -> Option<usize> {
        let mut node_idx = 0usize;
        let mut result = self.nodes[node_idx].value;
        for bit in 0..self.total_bits {
            let shift = self.total_bits - 1 - bit;
            let direction = ((addr >> shift) & 1) as usize;
            let Some(next_idx) = self.nodes[node_idx].next[direction] else {
                break;
            };
            node_idx = next_idx;
            if let Some(value) = self.nodes[node_idx].value {
                result = Some(value);
            }
        }
        result
    }
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    next: [Option<usize>; 2],
    value: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub name: Arc<str>,
    pub rules: Arc<[CompiledRule]>,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: Arc<str>,
    pub action: RuleAction,
    pub methods: MethodMask,
    pub url: Option<UrlMatcher>,
    pub inspect_payload: bool,
    pub allow_private_connect: bool,
    pub cache: Option<CompiledCacheConfig>,
}

#[derive(Debug, Clone)]
pub struct CompiledCacheConfig {
    pub force_cache_duration: Option<Duration>,
}

#[derive(Debug, Clone)]
pub struct MethodMask {
    allow_any: bool,
    mask: u32,
    extras: Arc<[Method]>,
}

impl MethodMask {
    pub fn any() -> Self {
        Self {
            allow_any: true,
            mask: 0,
            extras: Arc::from([]),
        }
    }

    pub fn from_methods(methods: &[Method]) -> Self {
        let mut mask = 0u32;
        let mut extras = Vec::new();
        for method in methods {
            if let Some(bit) = method_bit(method) {
                mask |= bit;
            } else if !extras.iter().any(|m: &Method| m == method) {
                extras.push(method.clone());
            }
        }
        Self {
            allow_any: false,
            mask,
            extras: Arc::from(extras.into_boxed_slice()),
        }
    }

    pub fn allows(&self, method: &Method) -> bool {
        if self.allow_any {
            return true;
        }
        if let Some(bit) = method_bit(method) {
            return (self.mask & bit) != 0;
        }
        self.extras.iter().any(|m| m == method)
    }
}

fn method_bit(method: &Method) -> Option<u32> {
    match method.as_str() {
        "GET" => Some(1 << 0),
        "POST" => Some(1 << 1),
        "PUT" => Some(1 << 2),
        "PATCH" => Some(1 << 3),
        "DELETE" => Some(1 << 4),
        "HEAD" => Some(1 << 5),
        "OPTIONS" => Some(1 << 6),
        "TRACE" => Some(1 << 7),
        "CONNECT" => Some(1 << 8),
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct UrlMatcher {
    pub scheme: Scheme,
    pub host: HostMatcher,
    pub port: Option<u16>,
    pub path: Option<PathMatcher>,
    pub original: Arc<str>,
}

impl UrlMatcher {
    pub fn matches(
        &self,
        scheme: Scheme,
        host: &str,
        port: Option<u16>,
        path: &str,
        ignore_path: bool,
    ) -> bool {
        if self.scheme != scheme {
            return false;
        }
        if !self.host.matches(host) {
            return false;
        }
        if let Some(expected) = self.port {
            let actual = port.or_else(|| Some(scheme.default_port()));
            if Some(expected) != actual {
                return false;
            }
        }
        if let Some(path_matcher) = &self.path {
            if ignore_path {
                return true;
            }
            return path_matcher.matches(path);
        }
        true
    }
}

#[derive(Debug, Clone)]
pub enum HostMatcher {
    Any,
    Exact(String),
    Glob(GlobMatcher),
}

impl HostMatcher {
    pub fn matches(&self, host: &str) -> bool {
        match self {
            HostMatcher::Any => true,
            HostMatcher::Exact(expected) => expected == &host.to_ascii_lowercase(),
            HostMatcher::Glob(glob) => glob.is_match(host),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PathMatcher {
    regex: Regex,
    original: Arc<str>,
}

impl PathMatcher {
    pub fn new(regex: Regex, original: Arc<str>) -> Self {
        Self { regex, original }
    }

    pub fn matches(&self, path: &str) -> bool {
        self.regex.is_match(path)
    }

    pub fn original(&self) -> &Arc<str> {
        &self.original
    }
}

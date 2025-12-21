mod loader;
pub mod model;

use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::Deref;

use anyhow::{Result, bail, ensure};
use ipnet::IpNet;

pub use loader::{load_config, load_config_with_dirs};
pub use model::{
    Client, ClientSelector, Config, MethodMatch, Policy, Rule, RuleAction, Scheme, UrlPattern,
};

use crate::util::cidrs_overlap;

/// Ensures that client selectors do not conflict (duplicate IPs or overlapping CIDRs except for the
/// designated fallback). This validation is shared by both the configuration loader and
/// the policy compiler so that hot reloads and programmatic configs get identical guarantees.
pub fn validate_clients(clients: &[Client]) -> Result<()> {
    struct CidrClaim<'a> {
        name: &'a str,
        net: IpNet,
        fallback: bool,
    }

    struct IpClaim<'a> {
        name: &'a str,
        fallback: bool,
    }

    let mut fallback_seen = false;
    let mut ip_claims: HashMap<IpAddr, IpClaim<'_>> = HashMap::new();
    let mut cidr_claims: Vec<CidrClaim<'_>> = Vec::new();

    for client in clients {
        if client.fallback {
            ensure!(
                !fallback_seen,
                "multiple fallback clients defined; exactly one client must set fallback=true"
            );
            fallback_seen = true;
        }

        match &client.selector {
            ClientSelector::Ip(addr) => {
                if let Some(existing) = ip_claims.insert(
                    *addr,
                    IpClaim {
                        name: client.name.as_ref(),
                        fallback: client.fallback,
                    },
                ) {
                    bail!(
                        "client '{}' specifies IP {} which is already claimed by client '{}'",
                        client.name,
                        addr,
                        existing.name
                    );
                }
                for claim in &cidr_claims {
                    if client.fallback || claim.fallback {
                        continue;
                    }
                    if claim.net.contains(addr) {
                        bail!(
                            "client '{}' IP {} overlaps with client '{}' CIDR {}",
                            client.name,
                            addr,
                            claim.name,
                            claim.net
                        );
                    }
                }
            }
            ClientSelector::Cidr(net) => {
                for claim in &cidr_claims {
                    if client.fallback || claim.fallback {
                        continue;
                    }
                    if cidrs_overlap(&claim.net, net) {
                        bail!(
                            "client '{}' CIDR {} overlaps with client '{}' CIDR {}",
                            client.name,
                            net,
                            claim.name,
                            claim.net
                        );
                    }
                }
                for (addr, claim) in &ip_claims {
                    if client.fallback || claim.fallback {
                        continue;
                    }
                    if net.contains(addr) {
                        bail!(
                            "client '{}' CIDR {} overlaps with client '{}' IP {}",
                            client.name,
                            net,
                            claim.name,
                            addr
                        );
                    }
                }
                cidr_claims.push(CidrClaim {
                    name: client.name.as_ref(),
                    net: *net,
                    fallback: client.fallback,
                });
            }
        }
    }

    ensure!(
        fallback_seen,
        "exactly one client must set fallback=true to act as the fallback"
    );

    Ok(())
}

#[derive(Debug, Clone)]
pub struct ValidatedConfig {
    inner: Config,
}

impl ValidatedConfig {
    pub fn new(config: Config) -> Result<Self> {
        validate_clients(&config.clients)?;
        Ok(Self { inner: config })
    }

    pub fn into_inner(self) -> Config {
        self.inner
    }
}

impl AsRef<Config> for ValidatedConfig {
    fn as_ref(&self) -> &Config {
        &self.inner
    }
}

impl Deref for ValidatedConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

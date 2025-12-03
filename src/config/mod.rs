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
/// designated catch-all). This validation is shared by both the configuration loader and
/// the policy compiler so that hot reloads and programmatic configs get identical guarantees.
pub fn validate_clients(clients: &[Client]) -> Result<()> {
    struct CidrClaim<'a> {
        name: &'a str,
        net: IpNet,
        catch_all: bool,
    }

    let mut catch_all_seen = false;
    let mut ip_claims: HashMap<IpAddr, &str> = HashMap::new();
    let mut cidr_claims: Vec<CidrClaim<'_>> = Vec::new();

    for client in clients {
        if client.catch_all {
            ensure!(
                !catch_all_seen,
                "multiple catch-all clients defined; exactly one client must set catch_all=true"
            );
            catch_all_seen = true;
        }

        match &client.selector {
            ClientSelector::Ip(addr) => {
                if let Some(existing) = ip_claims.insert(*addr, client.name.as_ref()) {
                    bail!(
                        "client '{}' specifies IP {} which is already claimed by client '{}'",
                        client.name,
                        addr,
                        existing
                    );
                }
            }
            ClientSelector::Cidr(net) => {
                for claim in &cidr_claims {
                    if client.catch_all || claim.catch_all {
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
                cidr_claims.push(CidrClaim {
                    name: client.name.as_ref(),
                    net: *net,
                    catch_all: client.catch_all,
                });
            }
        }
    }

    ensure!(
        catch_all_seen,
        "exactly one client must set catch_all=true to act as the fallback"
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

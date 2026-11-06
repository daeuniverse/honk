use serde::{Deserialize, Serialize};

use crate::firewall::{FirewallConfig, NatConfig};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    #[default]
    Tc,
    Xdp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectProfile {
    Core,
    Endpoint,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XskMode {
    #[default]
    Copy,
    ZeroCopy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    Lan,
    Wan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpInterface {
    pub name: String,
    pub role: InterfaceRole,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatapathConfig {
    #[serde(default)]
    pub backend: Backend,
    #[serde(default)]
    pub direct: Option<DirectProfile>,
    #[serde(default)]
    pub xsk_mode: Option<XskMode>,
    #[serde(default)]
    pub interfaces: Vec<XdpInterface>,
    #[serde(default)]
    pub firewall: Option<FirewallConfig>,
    #[serde(default)]
    pub nat: NatConfig,
}

impl DatapathConfig {
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        let invalid = |message: &str| crate::ConfigError::Parse(format!("datapath: {message}"));
        let has_nat = !self.nat.prerouting.is_empty() || !self.nat.postrouting.is_empty();
        if self.backend == Backend::Tc {
            if self.direct.is_some()
                || self.xsk_mode.is_some()
                || !self.interfaces.is_empty()
                || self.firewall.is_some()
                || has_nat
            {
                return Err(invalid(
                    "TC does not accept XDP execution, binding mode, interface, firewall or NAT settings",
                ));
            }
            return Ok(());
        }
        if self.direct.is_none() {
            return Err(invalid(
                "XDP requires explicit direct: core or direct: endpoint; native continuation is unavailable",
            ));
        }
        if self.interfaces.is_empty() || self.interfaces.len() > 16 {
            return Err(invalid(
                "XDP requires between one and sixteen explicit interfaces",
            ));
        }
        for (index, interface) in self.interfaces.iter().enumerate() {
            if interface.name.is_empty()
                || interface.name.len() >= 16
                || interface.name == "auto"
                || interface.name == "lo"
                || !interface
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                || self.interfaces[..index]
                    .iter()
                    .any(|earlier| earlier.name == interface.name)
            {
                return Err(invalid(
                    "interfaces must have unique, explicit Ethernet names",
                ));
            }
        }
        if (self.firewall.is_some() || has_nat) && self.direct != Some(DirectProfile::Core) {
            return Err(invalid("firewall and NAT require explicit XDP Core Direct"));
        }
        crate::firewall::validate(self.firewall.as_ref(), &self.nat)
    }

    pub fn effective_xsk_mode(&self) -> XskMode {
        self.xsk_mode.unwrap_or_default()
    }

    pub fn same_device_setup(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.direct == other.direct
            && self.effective_xsk_mode() == other.effective_xsk_mode()
            && self.interfaces == other.interfaces
    }
}

use std::net::Ipv4Addr;

use crate::routing::{RoutingCondition, RoutingNotCondition};
use serde::{Deserialize, Serialize};

fn deserialize_condition<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<RoutingCondition, D::Error> {
    #[derive(Default, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Negated {
        #[serde(flatten)]
        condition: RoutingNotCondition,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Condition {
        #[serde(default)]
        not: Negated,
        #[serde(flatten)]
        condition: RoutingCondition,
    }

    // Security rules reject leftovers without tightening legacy traffic routing.
    let mut input = Condition::deserialize(deserializer)?;
    input.condition.not = input.not.condition;
    Ok(input.condition)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallVerdict {
    Allow,
    #[default]
    Drop,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    #[serde(default)]
    pub ingress: Option<crate::datapath::InterfaceRole>,
    #[serde(deserialize_with = "deserialize_condition")]
    pub condition: RoutingCondition,
    pub verdict: FirewallVerdict,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallChain {
    pub rules: Vec<FirewallRule>,
    pub default: FirewallVerdict,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub original: FirewallChain,
    pub forward: FirewallChain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortPool {
    pub first: u16,
    pub last: u16,
}
impl Default for PortPool {
    fn default() -> Self {
        Self {
            first: 1024,
            last: u16::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationNat {
    pub address: Ipv4Addr,
    pub port: Option<u16>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceNat {
    Snat {
        address: Ipv4Addr,
        ports: Option<PortPool>,
    },
    Masquerade {
        ports: PortPool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnatRule {
    #[serde(deserialize_with = "deserialize_condition")]
    pub condition: RoutingCondition,
    pub action: DestinationNat,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnatRule {
    #[serde(deserialize_with = "deserialize_condition")]
    pub condition: RoutingCondition,
    pub action: SourceNat,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NatConfig {
    pub prerouting: Vec<DnatRule>,
    pub postrouting: Vec<SnatRule>,
}

impl NatConfig {
    pub fn is_empty(&self) -> bool {
        self.prerouting.is_empty() && self.postrouting.is_empty()
    }
}

/// Admission shared by dae and structured configuration consumers.
pub fn validate(
    firewall: Option<&FirewallConfig>,
    nat: &NatConfig,
) -> Result<(), crate::ConfigError> {
    let invalid = |message: &str| crate::ConfigError::Validation(message.into());
    if !nat.is_empty() && firewall.is_none() {
        return Err(invalid("datapath.nat requires an explicit firewall"));
    }
    // Keep the dependency-free config boundary equivalent to honk_netstack::transit::unicast.
    let valid_address = |ip: Ipv4Addr| {
        !ip.is_unspecified()
            && !ip.is_multicast()
            && !ip.is_broadcast()
            && !ip.is_loopback()
            && ip.octets()[0] != 0
            && ip.octets()[0] < 240
    };
    let valid_ports = |ports: PortPool| ports.first != 0 && ports.first <= ports.last;
    for rule in &nat.prerouting {
        if !valid_address(rule.action.address) || rule.action.port == Some(0) {
            return Err(invalid("datapath.nat has an invalid DNAT address or port"));
        }
    }
    for rule in &nat.postrouting {
        let valid = match rule.action {
            SourceNat::Snat { address, ports } => {
                valid_address(address) && ports.is_none_or(valid_ports)
            }
            SourceNat::Masquerade { ports } => valid_ports(ports),
        };
        if !valid {
            return Err(invalid(
                "datapath.nat has an invalid SNAT address or port pool",
            ));
        }
    }
    let conditions = firewall
        .into_iter()
        .flat_map(|fw| {
            fw.original
                .rules
                .iter()
                .chain(&fw.forward.rules)
                .map(|rule| &rule.condition)
        })
        .chain(nat.prerouting.iter().map(|rule| &rule.condition))
        .chain(nat.postrouting.iter().map(|rule| &rule.condition));
    for condition in conditions {
        // No socket/process/domain authority exists for transit packets. Negation must
        // never turn missing authority into an allow rule either.
        if [
            &condition.domain,
            &condition.domain_suffix,
            &condition.domain_keyword,
            &condition.domain_regex,
            &condition.geosite,
            &condition.process_name,
            &condition.mac,
            &condition.not.domain,
            &condition.not.domain_suffix,
            &condition.not.domain_keyword,
            &condition.not.domain_regex,
            &condition.not.geosite,
            &condition.not.process_name,
            &condition.not.mac,
        ]
        .iter()
        .any(|values| !values.is_empty())
        {
            return Err(invalid(
                "datapath firewall/NAT conditions require available packet facts; domain, process and MAC predicates are unsupported",
            ));
        }
        if condition
            .ip
            .iter()
            .chain(&condition.source_ip)
            .chain(&condition.not.ip)
            .chain(&condition.not.source_ip)
            .any(|value| crate::dns::decode_ip_or_cidr(value).is_none())
        {
            return Err(invalid("datapath firewall/NAT has an invalid IP matcher"));
        }
        if condition
            .protocol
            .iter()
            .chain(&condition.not.protocol)
            .any(|value| !value.eq_ignore_ascii_case("tcp") && !value.eq_ignore_ascii_case("udp"))
        {
            return Err(invalid(
                "datapath l4proto accepts the canonical tcp and udp values; use IP conditions for ICMP",
            ));
        }
        if condition
            .ip_version
            .iter()
            .chain(&condition.not.ip_version)
            .any(|value| {
                !matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "4" | "6" | "ipv4" | "ipv6"
                )
            })
        {
            return Err(invalid("datapath firewall/NAT has an invalid IP version"));
        }
        for value in condition
            .port
            .iter()
            .chain(&condition.source_port)
            .chain(&condition.not.port)
            .chain(&condition.not.source_port)
        {
            let (first, last) = value.split_once('-').unwrap_or((value, value));
            if !matches!((first.parse::<u16>(), last.parse::<u16>()), (Ok(first), Ok(last)) if first <= last)
            {
                return Err(invalid("datapath firewall/NAT has an invalid port matcher"));
            }
        }
        for value in condition.dscp.iter().chain(&condition.not.dscp) {
            let value = value.trim();
            let parsed = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .map_or_else(|| value.parse::<u8>(), |hex| u8::from_str_radix(hex, 16));
            if !matches!(parsed, Ok(0..=63)) {
                return Err(invalid("datapath firewall/NAT has an invalid DSCP matcher"));
            }
        }
    }
    Ok(())
}

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use base64::Engine as _;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A decoded WireGuard key. Debug output never exposes credential bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardKey([u8; 32]);

impl WireGuardKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for WireGuardKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WireGuardKey([redacted])")
    }
}

impl FromStr for WireGuardKey {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        decode_base64(value)
            .and_then(|bytes| bytes.try_into().ok())
            .map(Self)
            .ok_or("WireGuard keys must be base64-encoded 32-byte values")
    }
}

impl Serialize for WireGuardKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for WireGuardKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// One userspace tunnel and exactly one remote peer. Endpoint/provenance live on Node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardConfig {
    pub private_key: Option<WireGuardKey>,
    pub public_key: Option<WireGuardKey>,
    pub preshared_key: Option<WireGuardKey>,
    pub local_v4: Option<Ipv4Addr>,
    pub local_v6: Option<Ipv6Addr>,
    pub mtu: u16,
    pub persistent_keepalive: Option<u16>,
    pub reserved: Option<[u8; 3]>,
    pub allowed_ips: Vec<IpNet>,
    pub network: Option<String>,
}

impl Default for WireGuardConfig {
    fn default() -> Self {
        Self {
            private_key: None,
            public_key: None,
            preshared_key: None,
            local_v4: None,
            local_v6: None,
            mtu: 1420,
            persistent_keepalive: None,
            reserved: None,
            allowed_ips: vec![
                "0.0.0.0/0".parse().expect("constant IPv4 network"),
                "::/0".parse().expect("constant IPv6 network"),
            ],
            network: None,
        }
    }
}

impl WireGuardConfig {
    /// Admission guarantees this key exists; runtime consumers need not revalidate.
    pub fn private_key_bytes(&self) -> &[u8; 32] {
        self.private_key
            .as_ref()
            .expect("admitted WireGuard private key")
            .as_bytes()
    }

    /// Admission guarantees this key exists; runtime consumers need not revalidate.
    pub fn public_key_bytes(&self) -> &[u8; 32] {
        self.public_key
            .as_ref()
            .expect("admitted WireGuard peer public key")
            .as_bytes()
    }

    pub fn preshared_key_bytes(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref().map(WireGuardKey::as_bytes)
    }

    /// Collapse wire-equivalent settings before identity and runtime reuse.
    pub fn normalize(&mut self) {
        if self.persistent_keepalive == Some(0) {
            self.persistent_keepalive = None;
        }
        if self.reserved == Some([0; 3]) {
            self.reserved = None;
        }
        if self
            .preshared_key
            .as_ref()
            .is_some_and(|key| key.0 == [0; 32])
        {
            self.preshared_key = None;
        }
        for network in &mut self.allowed_ips {
            *network = network.trunc();
        }
        self.allowed_ips.sort_unstable();
        self.allowed_ips.dedup();
        if let Some(network) = self.network.as_deref()
            && let Ok(udp) = crate::options::vocab::packet_network(network)
        {
            self.network = (udp == Some(false)).then(|| "tcp".into());
        }
    }

    pub fn check(&self) -> Result<(), (&'static str, &'static str)> {
        if self.private_key.is_none() {
            return Err(("wg_private_key", "WireGuard requires a private key"));
        }
        if self.public_key.is_none() {
            return Err(("wg_public_key", "WireGuard requires a peer public key"));
        }
        if self.local_v4.is_none() && self.local_v6.is_none() {
            return Err((
                "wg_addresses",
                "WireGuard requires at least one local tunnel address",
            ));
        }
        if self.mtu < if self.local_v6.is_some() { 1280 } else { 576 } {
            return Err((
                "wg_mtu",
                "WireGuard MTU must be 1280..=65535 with IPv6 or 576..=65535 for IPv4 only",
            ));
        }
        if self.network.as_deref().is_some_and(|network| {
            !matches!(crate::options::vocab::packet_network(network), Ok(Some(_)))
        }) {
            return Err((
                "network",
                "WireGuard packet network must contain only tcp or udp tokens",
            ));
        }
        if self.allowed_ips.is_empty() {
            return Err(("wg_allowed_ips", "WireGuard allowed IPs must not be empty"));
        }
        if self
            .allowed_ips
            .iter()
            .any(|network| *network != network.trunc())
            || self.allowed_ips.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err((
                "wg_allowed_ips",
                "WireGuard allowed IPs must be masked, sorted and nonrepeating",
            ));
        }
        Ok(())
    }

    pub(crate) fn identity_fingerprint(&self) -> String {
        // MTU and keepalive tune this peer; they do not select another authenticated path.
        serde_json::to_string(&(
            &self.private_key,
            &self.public_key,
            self.preshared_key.as_ref().filter(|key| key.0 != [0; 32]),
            self.local_v4,
            self.local_v6,
            self.reserved.filter(|bytes| *bytes != [0; 3]),
            &self.allowed_ips,
            self.network.as_deref().is_none_or(|network| {
                crate::options::vocab::packet_network(network) == Ok(Some(true))
            }),
        ))
        .expect("WireGuard identity serializes")
    }
}

/// Interface prefixes describe the host, not a route; keep its address bits intact.
pub fn parse_wireguard_addresses<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), &'static str> {
    let mut v4 = None;
    let mut v6 = None;
    for value in values.into_iter().flat_map(|value| value.split(',')) {
        let value = value.trim();
        let address = if value.contains('/') {
            value.parse::<IpNet>().map(|network| network.addr()).ok()
        } else {
            value.parse::<IpAddr>().ok()
        }
        .ok_or("WireGuard tunnel address must be an IP address with an optional valid prefix")?;
        let duplicate = match address {
            IpAddr::V4(address) => v4.replace(address).is_some(),
            IpAddr::V6(address) => v6.replace(address).is_some(),
        };
        if duplicate {
            return Err("WireGuard supports at most one local address per IP family");
        }
    }
    Ok((v4, v6))
}

pub fn parse_wireguard_allowed_ips(value: &str) -> Result<Vec<IpNet>, &'static str> {
    let mut networks = value
        .split(',')
        .map(|value| {
            let value = value.trim();
            value
                .parse::<IpNet>()
                .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
                .map(|network| network.trunc())
                .map_err(|_| "WireGuard allowed IPs must be IP addresses or CIDR prefixes")
        })
        .collect::<Result<Vec<_>, _>>()?;
    networks.sort_unstable();
    networks.dedup();
    Ok(networks)
}

pub fn parse_wireguard_reserved(value: &str) -> Result<[u8; 3], &'static str> {
    let value = value.trim();
    let bytes = if value.contains(',') {
        value
            .split(',')
            .map(|byte| byte.trim().parse::<u8>())
            .collect::<Result<Vec<_>, _>>()
            .ok()
    } else {
        decode_base64(value)
    };
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("WireGuard reserved must contain exactly three bytes (decimal list or base64)")
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value))
        .ok()
}

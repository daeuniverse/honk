use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use super::validation::ValidationFailure;
use super::{StreamTransportOptions, TlsOptions};
use crate::options::vocab::packet_network;

const DEFAULT_XRAY_CONCURRENCY: u16 = 8;
const MAX_XRAY_CONCURRENCY: u16 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VlessUdpEncoding {
    #[default]
    Auto,
    Native,
    Xudp,
    UotV2,
}

impl VlessUdpEncoding {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Native => "native",
            Self::Xudp => "xudp",
            Self::UotV2 => "uot-v2",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VlessUdpMux {
    #[default]
    Protocol,
    SharedTcp,
    Separate(NonZeroU16),
}

impl Serialize for VlessUdpMux {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Protocol => serializer.serialize_str("protocol"),
            Self::SharedTcp => serializer.serialize_str("shared-tcp"),
            Self::Separate(limit) => {
                use serde::ser::SerializeMap as _;

                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("separate", &limit.get())?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for VlessUdpMux {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "kebab-case")]
        enum Name {
            Protocol,
            SharedTcp,
        }

        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Separate {
            separate: NonZeroU16,
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Name(Name),
            Separate(Separate),
        }

        match Wire::deserialize(deserializer)? {
            Wire::Name(Name::Protocol) => Ok(Self::Protocol),
            Wire::Name(Name::SharedTcp) => Ok(Self::SharedTcp),
            Wire::Separate(value) => Ok(Self::Separate(value.separate)),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Udp443Policy {
    #[default]
    Reject,
    Skip,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "protocol", rename_all = "lowercase", deny_unknown_fields)]
pub enum VlessMultiplex {
    #[default]
    #[serde(deserialize_with = "deserialize_mux_off")]
    Off,
    H2 {
        #[serde(default)]
        padding: bool,
    },
    Xray {
        #[serde(default)]
        tcp: Option<NonZeroU16>,
        #[serde(default)]
        udp: VlessUdpMux,
        #[serde(default)]
        udp443: Udp443Policy,
    },
}

fn deserialize_mux_off<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    // Serde's internally-tagged unit variant otherwise ignores extra fields.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    Empty::deserialize(deserializer).map(|_| ())
}

impl VlessMultiplex {
    pub fn xray(concurrency: i16, xudp_concurrency: i16, udp443: Udp443Policy) -> Self {
        let tcp = match concurrency {
            ..=-1 => None,
            0 => canonical_limit(DEFAULT_XRAY_CONCURRENCY),
            value => canonical_limit(value as u16),
        };
        let udp = match xudp_concurrency {
            ..=-1 => VlessUdpMux::Protocol,
            0 if tcp.is_some() => VlessUdpMux::SharedTcp,
            0 => VlessUdpMux::Protocol,
            value => VlessUdpMux::Separate(
                canonical_limit(value as u16).expect("positive concurrency is nonzero"),
            ),
        };
        Self::Xray { tcp, udp, udp443 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessTcpPath {
    Direct,
    H2,
    Cool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VlessUdpPath {
    Native,
    Xudp,
    UotV2,
    H2,
    CoolShared,
    CoolSeparate,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VlessConfig {
    pub uuid: Option<String>,
    pub encryption: Option<String>,
    pub udp_encoding: VlessUdpEncoding,
    pub multiplex: VlessMultiplex,
    pub flow: Option<String>,
    pub network: Option<String>,
    pub transport: StreamTransportOptions,
    pub tls: TlsOptions,
}

impl Default for VlessConfig {
    fn default() -> Self {
        Self {
            uuid: None,
            encryption: None,
            udp_encoding: VlessUdpEncoding::Auto,
            multiplex: VlessMultiplex::Off,
            flow: None,
            network: None,
            transport: StreamTransportOptions::default(),
            tls: TlsOptions::default(),
        }
    }
}

impl VlessConfig {
    pub fn udp_enabled(&self) -> bool {
        self.network
            .as_deref()
            .is_none_or(|network| matches!(packet_network(network), Ok(Some(true))))
    }

    pub fn tcp_path(&self) -> VlessTcpPath {
        match self.multiplex {
            VlessMultiplex::Off => VlessTcpPath::Direct,
            VlessMultiplex::H2 { .. } => VlessTcpPath::H2,
            VlessMultiplex::Xray { tcp: Some(_), .. } => VlessTcpPath::Cool,
            VlessMultiplex::Xray { tcp: None, .. } => VlessTcpPath::Direct,
        }
    }

    pub fn udp_path(&self, port: u16) -> Option<VlessUdpPath> {
        if !self.udp_enabled() {
            return None;
        }
        if let VlessMultiplex::Xray { udp443, .. } = self.multiplex
            && port == 443
        {
            match udp443 {
                Udp443Policy::Reject => return None,
                Udp443Policy::Skip => return self.protocol_udp_path(port),
                Udp443Policy::Allow => {}
            }
        }
        match self.multiplex {
            VlessMultiplex::Off => self.protocol_udp_path(port),
            VlessMultiplex::H2 { .. } => Some(VlessUdpPath::H2),
            VlessMultiplex::Xray {
                tcp,
                udp: VlessUdpMux::SharedTcp,
                ..
            } if tcp.is_some() => Some(VlessUdpPath::CoolShared),
            VlessMultiplex::Xray {
                udp: VlessUdpMux::Separate(_),
                ..
            } => Some(VlessUdpPath::CoolSeparate),
            VlessMultiplex::Xray { .. } => self.protocol_udp_path(port),
        }
    }

    pub fn is_vision(&self) -> bool {
        matches!(
            self.flow.as_deref(),
            Some("xtls-rprx-vision" | "xtls-rprx-vision-udp443")
        )
    }

    pub fn is_encrypted(&self) -> bool {
        self.encryption.as_deref().is_some_and(|value| {
            let value = value.trim();
            !value.is_empty() && value != "none"
        })
    }

    pub fn wire_flow(&self) -> Option<&str> {
        match self.flow.as_deref() {
            Some("xtls-rprx-vision-udp443") => Some("xtls-rprx-vision"),
            flow => flow,
        }
    }

    /// Canonicalize only equivalent or unreachable settings so identity and
    /// structural runtime reuse agree without changing any selected path.
    pub fn normalize(&mut self) {
        if let Some(network) = &mut self.network
            && let Ok(enabled) = packet_network(network)
        {
            if enabled == Some(true) {
                self.network = None;
            } else if network != "tcp" {
                network.clear();
                network.push_str("tcp");
            }
        }
        let vision = self.is_vision();
        let vision_blocks_443 = self.flow.as_deref() == Some("xtls-rprx-vision");
        if vision && self.udp_encoding == VlessUdpEncoding::Xudp {
            self.udp_encoding = VlessUdpEncoding::Auto;
        }
        match &mut self.multiplex {
            VlessMultiplex::Off => {}
            VlessMultiplex::H2 { .. } => self.udp_encoding = VlessUdpEncoding::Auto,
            VlessMultiplex::Xray { tcp, udp, udp443 } => {
                *tcp = tcp.and_then(|limit| canonical_limit(limit.get()));
                match udp {
                    VlessUdpMux::SharedTcp if tcp.is_none() => *udp = VlessUdpMux::Protocol,
                    VlessUdpMux::Separate(limit) => {
                        *limit = canonical_limit(limit.get()).expect("nonzero concurrency")
                    }
                    VlessUdpMux::Protocol | VlessUdpMux::SharedTcp => {}
                }
                // Skip and Reject coincide when base Vision denies the only
                // fallback target; without a UDP pool, Skip and Allow coincide.
                if vision_blocks_443 && *udp443 == Udp443Policy::Skip {
                    *udp443 = Udp443Policy::Reject;
                }
                if matches!(udp, VlessUdpMux::Protocol) {
                    if vision_blocks_443 {
                        *udp443 = Udp443Policy::Reject;
                    } else if *udp443 == Udp443Policy::Skip {
                        *udp443 = Udp443Policy::Allow;
                    }
                } else if *udp443 != Udp443Policy::Skip
                    || (!vision && self.udp_encoding == VlessUdpEncoding::Native)
                {
                    // A pooled fallback is reachable only through Skip at :443,
                    // where ordinary Auto and Native select the same protocol.
                    self.udp_encoding = VlessUdpEncoding::Auto;
                }
            }
        }
        if !self.udp_enabled() {
            self.udp_encoding = VlessUdpEncoding::Auto;
            if let VlessMultiplex::Xray { tcp, udp, udp443 } = &mut self.multiplex {
                *udp = VlessUdpMux::Protocol;
                *udp443 = Udp443Policy::Reject;
                if tcp.is_none() {
                    self.multiplex = VlessMultiplex::Off;
                }
            }
        }
    }

    pub fn validate(&self, _name: &str) -> Result<(), crate::ConfigError> {
        self.validate_fields()
            .map_err(ValidationFailure::into_legacy)
    }

    pub(super) fn validate_fields(&self) -> Result<(), ValidationFailure> {
        if let VlessMultiplex::Xray { tcp, udp, .. } = self.multiplex {
            if tcp.is_some_and(|limit| limit.get() > MAX_XRAY_CONCURRENCY)
                || matches!(udp, VlessUdpMux::Separate(limit) if limit.get() > MAX_XRAY_CONCURRENCY)
            {
                return Err(ValidationFailure::new(
                    Some("multiplex"),
                    "VLESS multiplex concurrency must not exceed 128",
                ));
            }
            if matches!(udp, VlessUdpMux::SharedTcp) && tcp.is_none() {
                return Err(ValidationFailure::new(
                    Some("multiplex"),
                    "VLESS shared UDP multiplexing requires TCP multiplexing",
                ));
            }
        }

        let encrypted = self.is_encrypted();
        let paths = [53, 443, 54].map(|port| self.udp_path(port));
        if self.is_vision()
            && (self.tcp_path() != VlessTcpPath::Direct
                || (!encrypted && !matches!(self.transport.transport.as_str(), "" | "tcp"))
                || paths.into_iter().flatten().any(|path| {
                    matches!(
                        path,
                        VlessUdpPath::Native | VlessUdpPath::UotV2 | VlessUdpPath::H2
                    )
                }))
        {
            return Err(ValidationFailure::new(
                Some("flow"),
                "VLESS flow cannot use the selected TCP or UDP path",
            ));
        }
        if encrypted
            && (self.tcp_path() == VlessTcpPath::H2
                || paths
                    .into_iter()
                    .flatten()
                    .any(|path| matches!(path, VlessUdpPath::UotV2 | VlessUdpPath::H2)))
        {
            return Err(ValidationFailure::new(
                Some("encryption"),
                "VLESS Encryption cannot use the selected TCP or UDP path",
            ));
        }

        let has_key = self
            .tls
            .reality_public_key
            .as_deref()
            .is_some_and(|key| !key.trim().is_empty());
        let wants_reality = self.tls.reality_public_key.is_some()
            || self.tls.reality_short_id.is_some()
            || self.tls.reality_spider_x.is_some();
        if wants_reality && !has_key {
            return Err(ValidationFailure::new(
                Some("reality_public_key"),
                "REALITY requires reality_public_key",
            ));
        }
        Ok(())
    }

    pub(super) fn identity_fingerprint(&self) -> String {
        let mut fingerprint = match self.multiplex {
            VlessMultiplex::Xray { tcp: None, .. } if !self.udp_enabled() => "off".to_owned(),
            VlessMultiplex::Off => "off".to_owned(),
            VlessMultiplex::H2 { padding } => format!("h2:{padding}"),
            VlessMultiplex::Xray { tcp, .. } => {
                format!("xray:{}", tcp.map_or(0, NonZeroU16::get))
            }
        };
        if !self.udp_enabled() {
            fingerprint.push_str(":udp-disabled");
            return fingerprint;
        }
        if let VlessMultiplex::Xray {
            udp: VlessUdpMux::Separate(limit),
            ..
        } = self.multiplex
        {
            fingerprint.push_str(":separate-");
            fingerprint.push_str(&limit.get().to_string());
        }
        for port in [53, 443, 54] {
            fingerprint.push(':');
            fingerprint.push_str(match self.udp_path(port) {
                None => "none",
                Some(VlessUdpPath::Native) => "native",
                Some(VlessUdpPath::Xudp) => "xudp",
                Some(VlessUdpPath::UotV2) => "uot-v2",
                Some(VlessUdpPath::H2) => "h2",
                Some(VlessUdpPath::CoolShared) => "cool-shared",
                Some(VlessUdpPath::CoolSeparate) => "cool-separate",
            });
        }
        fingerprint
    }

    fn protocol_udp_path(&self, port: u16) -> Option<VlessUdpPath> {
        if port == 443 && self.flow.as_deref() == Some("xtls-rprx-vision") {
            return None;
        }
        Some(match self.udp_encoding {
            VlessUdpEncoding::Auto if self.is_vision() || !matches!(port, 53 | 443) => {
                VlessUdpPath::Xudp
            }
            VlessUdpEncoding::Auto | VlessUdpEncoding::Native => VlessUdpPath::Native,
            VlessUdpEncoding::Xudp => VlessUdpPath::Xudp,
            VlessUdpEncoding::UotV2 => VlessUdpPath::UotV2,
        })
    }
}

fn canonical_limit(limit: u16) -> Option<NonZeroU16> {
    NonZeroU16::new(limit.min(MAX_XRAY_CONCURRENCY))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xray_signed_controls_normalize_to_canonical_pools() {
        assert_eq!(
            VlessMultiplex::xray(0, 0, Udp443Policy::Reject),
            VlessMultiplex::Xray {
                tcp: NonZeroU16::new(8),
                udp: VlessUdpMux::SharedTcp,
                udp443: Udp443Policy::Reject,
            }
        );
        assert_eq!(
            VlessMultiplex::xray(-1, 0, Udp443Policy::Allow),
            VlessMultiplex::Xray {
                tcp: None,
                udp: VlessUdpMux::Protocol,
                udp443: Udp443Policy::Allow,
            }
        );
        assert_eq!(
            VlessMultiplex::xray(300, 300, Udp443Policy::Skip),
            VlessMultiplex::Xray {
                tcp: NonZeroU16::new(128),
                udp: VlessUdpMux::Separate(NonZeroU16::new(128).unwrap()),
                udp443: Udp443Policy::Skip,
            }
        );
    }

    #[test]
    fn selected_paths_apply_permission_then_udp443_then_pool() {
        let mut config = VlessConfig {
            udp_encoding: VlessUdpEncoding::UotV2,
            multiplex: VlessMultiplex::xray(8, 4, Udp443Policy::Reject),
            ..Default::default()
        };
        assert_eq!(config.tcp_path(), VlessTcpPath::Cool);
        assert_eq!(config.udp_path(53), Some(VlessUdpPath::CoolSeparate));
        assert_eq!(config.udp_path(443), None);

        config.multiplex = VlessMultiplex::xray(8, 4, Udp443Policy::Skip);
        assert_eq!(config.udp_path(443), Some(VlessUdpPath::UotV2));

        config.multiplex = VlessMultiplex::xray(-1, -1, Udp443Policy::Reject);
        assert_eq!(config.udp_path(443), None);
        config.network = Some("tcp".into());
        assert_eq!(config.udp_path(53), None);
    }

    #[test]
    fn normalization_erases_only_inactive_fallback_tuning() {
        let mut pooled = VlessConfig {
            udp_encoding: VlessUdpEncoding::UotV2,
            multiplex: VlessMultiplex::xray(8, 8, Udp443Policy::Allow),
            ..Default::default()
        };
        pooled.normalize();
        assert_eq!(pooled.udp_encoding, VlessUdpEncoding::Auto);

        let mut skipped = VlessConfig {
            udp_encoding: VlessUdpEncoding::UotV2,
            multiplex: VlessMultiplex::xray(8, 8, Udp443Policy::Skip),
            ..Default::default()
        };
        skipped.normalize();
        assert_eq!(skipped.udp_encoding, VlessUdpEncoding::UotV2);
    }

    #[test]
    fn direct_noncanonical_limits_are_rejected() {
        let config = VlessConfig {
            multiplex: VlessMultiplex::Xray {
                tcp: NonZeroU16::new(129),
                udp: VlessUdpMux::Protocol,
                udp443: Udp443Policy::Reject,
            },
            ..Default::default()
        };
        assert!(config.validate("unused").is_err());
    }
}

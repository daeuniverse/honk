use serde::{Deserialize, Serialize};

mod protocol;
mod wire;

pub use protocol::*;

/// Deserialize a group-tag list from either an array (`["hk", "jp"]`) or a
/// single delimited string (`"hk|jp"` / `"hk, jp"`). Entries themselves may
/// also contain `,` or `|` separators.
fn deserialize_group_tags<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum GroupTags {
        List(Vec<String>),
        One(String),
    }
    let raw = GroupTags::deserialize(deserializer)?;
    let parts = match raw {
        GroupTags::List(list) => list,
        GroupTags::One(s) => vec![s],
    };
    Ok(parts
        .iter()
        .flat_map(|s| s.split([',', '|']))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

use crate::types::NodeProtocol;

/// UUID v5 namespace for content-derived node IDs ([`Node::derive_id`]).
/// Fixed arbitrary value; never change it or every persisted node identity
/// breaks.
pub const NODE_ID_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x3d8f2e1a_9b4c_4d57_8f3a_2c6e1d0b9a7f);

/// Normalized multiplexing and packet wire behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum WireMode {
    #[default]
    Legacy,
    UotV2,
    H2mux,
    H2muxPadded,
    Xudp,
    MuxCool,
}
impl WireMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::UotV2 => "uot-v2",
            Self::H2mux => "h2mux",
            Self::H2muxPadded => "h2mux-padded",
            Self::Xudp => "xudp",
            Self::MuxCool => "mux-cool",
        }
    }
}

impl std::str::FromStr for WireMode {
    type Err = crate::ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "legacy" => Ok(Self::Legacy),
            "uot-v2" => Ok(Self::UotV2),
            "h2mux" => Ok(Self::H2mux),
            "h2mux-padded" => Ok(Self::H2muxPadded),
            "xudp" => Ok(Self::Xudp),
            "mux-cool" => Ok(Self::MuxCool),
            _ => Err(crate::ConfigError::Parse(
                "unsupported wire mode (expected legacy/uot-v2/h2mux/h2mux-padded/xudp/mux-cool)"
                    .into(),
            )),
        }
    }
}

/// A proxy node definition. Protocol-specific state lives in [`OutboundConfig`];
/// the outer node carries only identity, endpoint, and provenance shared by all
/// outbounds.
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// Stable identity derived from the node's content by [`Node::derive_id`]
    /// at every construction entry (nil until then — the runtime registry
    /// rejects nil IDs, so a missed entry fails loudly).
    pub id: uuid::Uuid,
    pub name: String,
    pub address: String,
    pub host: String,
    pub port: u16,
    pub outbound: OutboundConfig,
    pub mark: Option<u32>,
    pub tags: Vec<String>,
    pub subscription_id: Option<uuid::Uuid>,
    pub group_id: Option<uuid::Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub(super) fn default_transport() -> String {
    "tcp".to_string()
}

impl Default for Node {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::nil(),
            name: String::new(),
            address: String::new(),
            host: String::new(),
            port: 0,
            outbound: OutboundConfig::default(),
            mark: None,
            tags: Vec::new(),
            subscription_id: None,
            group_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }
}

impl Node {
    pub fn protocol(&self) -> NodeProtocol {
        self.outbound.protocol()
    }

    /// Get the effective host (use host field or parse from address).
    pub fn host(&self) -> &str {
        if self.host.is_empty() {
            self.address.split(':').next().unwrap_or(&self.address)
        } else {
            &self.host
        }
    }

    pub fn shadowsocks(&self) -> Option<&ShadowsocksConfig> {
        match &self.outbound {
            OutboundConfig::Shadowsocks(config) => Some(config),
            _ => None,
        }
    }

    pub fn shadowsocks_mut(&mut self) -> Option<&mut ShadowsocksConfig> {
        match &mut self.outbound {
            OutboundConfig::Shadowsocks(config) => Some(config),
            _ => None,
        }
    }

    pub fn socks5(&self) -> Option<&Socks5Config> {
        match &self.outbound {
            OutboundConfig::Socks5(config) => Some(config),
            _ => None,
        }
    }

    pub fn socks5_mut(&mut self) -> Option<&mut Socks5Config> {
        match &mut self.outbound {
            OutboundConfig::Socks5(config) => Some(config),
            _ => None,
        }
    }

    pub fn trojan(&self) -> Option<&TrojanConfig> {
        match &self.outbound {
            OutboundConfig::Trojan(config) => Some(config),
            _ => None,
        }
    }

    pub fn trojan_mut(&mut self) -> Option<&mut TrojanConfig> {
        match &mut self.outbound {
            OutboundConfig::Trojan(config) => Some(config),
            _ => None,
        }
    }

    pub fn vmess(&self) -> Option<&VmessConfig> {
        match &self.outbound {
            OutboundConfig::Vmess(config) => Some(config),
            _ => None,
        }
    }

    pub fn vmess_mut(&mut self) -> Option<&mut VmessConfig> {
        match &mut self.outbound {
            OutboundConfig::Vmess(config) => Some(config),
            _ => None,
        }
    }

    pub fn vless(&self) -> Option<&VlessConfig> {
        self.outbound.vless()
    }

    pub fn vless_mut(&mut self) -> Option<&mut VlessConfig> {
        self.outbound.vless_mut()
    }

    pub fn hysteria2(&self) -> Option<&Hysteria2Config> {
        match &self.outbound {
            OutboundConfig::Hysteria2(config) => Some(config),
            _ => None,
        }
    }

    pub fn hysteria2_mut(&mut self) -> Option<&mut Hysteria2Config> {
        match &mut self.outbound {
            OutboundConfig::Hysteria2(config) => Some(config),
            _ => None,
        }
    }

    pub fn tuic(&self) -> Option<&TuicConfig> {
        match &self.outbound {
            OutboundConfig::Tuic(config) => Some(config),
            _ => None,
        }
    }

    pub fn tuic_mut(&mut self) -> Option<&mut TuicConfig> {
        match &mut self.outbound {
            OutboundConfig::Tuic(config) => Some(config),
            _ => None,
        }
    }

    pub fn juicity(&self) -> Option<&JuicityConfig> {
        match &self.outbound {
            OutboundConfig::Juicity(config) => Some(config),
            _ => None,
        }
    }

    pub fn juicity_mut(&mut self) -> Option<&mut JuicityConfig> {
        match &mut self.outbound {
            OutboundConfig::Juicity(config) => Some(config),
            _ => None,
        }
    }

    pub fn anytls(&self) -> Option<&AnyTlsConfig> {
        match &self.outbound {
            OutboundConfig::AnyTls(config) => Some(config),
            _ => None,
        }
    }

    pub fn anytls_mut(&mut self) -> Option<&mut AnyTlsConfig> {
        match &mut self.outbound {
            OutboundConfig::AnyTls(config) => Some(config),
            _ => None,
        }
    }

    pub fn tls(&self) -> Option<&TlsOptions> {
        self.outbound.tls()
    }

    pub fn tls_mut(&mut self) -> Option<&mut TlsOptions> {
        self.outbound.tls_mut()
    }

    pub fn transport(&self) -> Option<&StreamTransportOptions> {
        self.outbound.transport()
    }

    pub fn transport_mut(&mut self) -> Option<&mut StreamTransportOptions> {
        self.outbound.transport_mut()
    }

    pub fn network(&self) -> Option<&str> {
        self.outbound.network()
    }

    pub fn validate_protocol(&self) -> Result<(), crate::ConfigError> {
        if let Some(config) = self.vless() {
            config.validate(&self.name)?;
        }
        Ok(())
    }

    /// Content-derived stable identity: UUID v5 over
    /// `protocol|host|port|credential-fingerprint|dial-shape`.
    pub fn derive_id(&self) -> uuid::Uuid {
        let material = format!(
            "{}|{}|{}|{}|{}",
            self.protocol().as_str(),
            self.host(),
            self.port,
            self.outbound.credential_fingerprint(),
            self.outbound.dial_shape_fingerprint()
        );
        uuid::Uuid::new_v5(&NODE_ID_NAMESPACE, material.as_bytes())
    }
}

/// A group of nodes for load balancing / failover.
///
/// Modeled after sing-box's outbound groups, plus the built-in Score policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    #[serde(default = "uuid::Uuid::new_v4")]
    pub id: uuid::Uuid,
    pub name: String,
    /// Group selection policy.
    #[serde(default)]
    pub policy: GroupPolicy,
    /// Node UUIDs that belong to this group.
    #[serde(default)]
    pub nodes: Vec<uuid::Uuid>,
    /// Filter expressions for member resolution.
    #[serde(default)]
    pub filters: Vec<String>,
    /// Tags of nested sub-groups (sing-box style nested outbounds): each
    /// tag names another group whose current selection becomes a member
    /// candidate of this group. Cycles are broken at GroupManager
    /// construction (the cycle-closing edge is dropped with a warning).
    ///
    /// Accepts either an array (`groups = ["hk", "jp"]`) or a single
    /// delimited string (`groups = "hk|jp"` or `"hk, jp"`).
    #[serde(default, deserialize_with = "deserialize_group_tags")]
    pub groups: Vec<String>,
    /// Default node name for Selector policy.
    /// The first alive node is used if empty or the default is dead.
    #[serde(default)]
    pub default: Option<String>,
    /// Fallback outbound name when all nodes in this group are dead.
    /// Can be "direct", "block", another group name, or a node name.
    #[serde(default)]
    pub final_outbound: Option<String>,
    /// URL for health checks (overrides global tcp_check_url).
    #[serde(default)]
    pub check_url: Option<String>,
    /// Health check interval override in seconds.
    #[serde(default)]
    pub check_interval: Option<u64>,
    /// Minimum latency difference (ms) before switching the URLTest selection.
    /// Zero means switch on any improvement. Default: 50 (matches sing-box).
    #[serde(default = "default_tolerance")]
    pub tolerance: u64,
    /// Stop health checks after this many seconds of inactivity.
    /// `None` means never stop. Zero means never stop.
    #[serde(default)]
    pub idle_timeout: Option<u64>,
    /// Interrupt existing connections when the selected node changes.
    #[serde(default)]
    pub interrupt_connections: bool,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Default for Group {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: String::new(),
            policy: GroupPolicy::default(),
            nodes: Vec::new(),
            filters: Vec::new(),
            groups: Vec::new(),
            default: None,
            final_outbound: None,
            check_url: None,
            check_interval: None,
            tolerance: default_tolerance(),
            idle_timeout: None,
            interrupt_connections: false,
            created_at: chrono::Utc::now(),
        }
    }
}

fn default_tolerance() -> u64 {
    50
}

/// Group policy for node selection — matches sing-box's outbound group types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum GroupPolicy {
    /// Manual selection — uses `Group.default` (or first alive node as fallback).
    /// The selected node stays until changed via API or the node dies.
    #[default]
    Selector,
    /// Auto-select lowest-latency node with tolerance (like sing-box urltest).
    /// Keeps separate selections for TCP and UDP (sing-box semantics).
    URLTest,
    /// Round-robin across alive nodes (dae `roundrobin`). Each group keeps an
    /// independent rotation counter.
    #[serde(alias = "roundrobin")]
    LoadBalance,
    /// First alive node in declaration order, pinned until it dies. A
    /// recovered higher-preference node does not immediately win the pin back.
    Fallback,
    /// Reliability-aware automatic selection trained by real connection outcomes.
    Score,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_policy_serde_lowercase() {
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"selector\"").unwrap(),
            GroupPolicy::Selector
        );
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"urltest\"").unwrap(),
            GroupPolicy::URLTest
        );
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"loadbalance\"").unwrap(),
            GroupPolicy::LoadBalance
        );
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"fallback\"").unwrap(),
            GroupPolicy::Fallback
        );
        // dae-style alias for LoadBalance.
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"roundrobin\"").unwrap(),
            GroupPolicy::LoadBalance
        );
        assert_eq!(
            serde_json::to_string(&GroupPolicy::LoadBalance).unwrap(),
            "\"loadbalance\""
        );
        assert_eq!(
            serde_json::to_string(&GroupPolicy::URLTest).unwrap(),
            "\"urltest\""
        );
        assert_eq!(
            serde_json::from_str::<GroupPolicy>("\"score\"").unwrap(),
            GroupPolicy::Score
        );
        assert_eq!(
            serde_json::to_string(&GroupPolicy::Score).unwrap(),
            "\"score\""
        );
    }

    #[test]
    fn test_group_policy_serde_rejects_legacy_honk() {
        assert!(serde_json::from_str::<GroupPolicy>("\"honk\"").is_err());
    }

    #[test]
    fn test_vless_mode_serde_and_default() {
        assert_eq!(Node::default().vless(), None);
        for (value, mode) in [
            ("legacy", WireMode::Legacy),
            ("uot-v2", WireMode::UotV2),
            ("h2mux", WireMode::H2mux),
            ("h2mux-padded", WireMode::H2muxPadded),
            ("xudp", WireMode::Xudp),
            ("mux-cool", WireMode::MuxCool),
        ] {
            assert_eq!(
                serde_json::from_str::<WireMode>(&format!("\"{value}\"")).unwrap(),
                mode
            );
            assert_eq!(
                serde_json::to_string(&mode).unwrap(),
                format!("\"{value}\"")
            );
            assert_eq!(value.parse::<WireMode>().unwrap(), mode);
            assert_eq!(mode.as_str(), value);
        }
        let error = "smux".parse::<WireMode>().unwrap_err().to_string();
        assert!(error.contains("xudp/mux-cool"));
    }

    #[test]
    fn test_protocol_identity_goldens() {
        let cases = [
            (
                "ss",
                "ss://YWVzLTI1Ni1nY206cGFzcw@1.2.3.4:8388#ss",
                "e4a92538-53a2-5f83-85cd-b5d11f90361b",
            ),
            (
                "socks5",
                "socks5://user:pass@1.2.3.4:1080#socks5",
                "4257ffb1-f1ac-5838-b020-fe5c08dc99f8",
            ),
            (
                "trojan",
                "trojan://secret@example.com:443#trojan",
                "6b92dad3-62ea-5dcd-a71f-fd67105ccfe1",
            ),
            (
                "vmess",
                "vmess://eyJwcyI6InZtZXNzIiwiYWRkIjoiZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJzY3kiOiJhdXRvIiwibmV0IjoidGNwIiwidGxzIjoidGxzIn0",
                "263e811a-31e9-572f-bb87-66f1fc63ce98",
            ),
            (
                "vless-legacy",
                "vless://uuid@example.com:443#legacy",
                "d47c73f3-910d-56b4-baa5-d230c76d788b",
            ),
            (
                "vless-uot-v2",
                "vless://uuid@example.com:443?vless_mode=uot-v2#uot-v2",
                "372e7dc7-86a7-5d0d-accc-ba38fd103214",
            ),
            (
                "vless-h2mux",
                "vless://uuid@example.com:443?vless_mode=h2mux#h2mux",
                "258ef463-002a-5fdf-8901-a1c8508ff988",
            ),
            (
                "vless-h2mux-padded",
                "vless://uuid@example.com:443?vless_mode=h2mux-padded#h2mux-padded",
                "7f5ed150-4f89-54e1-b157-4d123d7fbc52",
            ),
            (
                "vless-xudp",
                "vless://uuid@example.com:443?vless_mode=xudp#xudp",
                "85e3e4ce-e4e7-546b-93d5-e1d8a0742f4b",
            ),
            (
                "vless-mux-cool",
                "vless://uuid@example.com:443?vless_mode=mux-cool#mux-cool",
                "4133852f-b86f-5a8f-b8fb-b335023645fe",
            ),
            (
                "hysteria2",
                "hysteria2://secret@example.com:443#hysteria2",
                "f622cf2a-ef2e-5777-abdb-d8c826d11f57",
            ),
            (
                "tuic",
                "tuic://uuid:pass@example.com:443#tuic",
                "e8751061-7db8-5d0d-b2e9-04af9ce55d02",
            ),
            (
                "juicity",
                "juicity://uuid:pass@example.com:443#juicity",
                "26d8181d-9c09-580d-86bc-1bdc22f1d113",
            ),
            (
                "anytls",
                "anytls://secret@example.com:443#anytls",
                "743d15b1-586a-5095-9e49-58c6f444f738",
            ),
        ];

        for (name, link, expected) in cases {
            let node = Node::from_share_link(link).unwrap();
            assert_eq!(node.id.to_string(), expected, "{name}");
        }
    }

    #[test]
    fn test_vless_mode_identity() {
        let legacy = Node::from_share_link("vless://uuid@example.com:443#legacy").unwrap();
        let explicit_legacy =
            Node::from_share_link("vless://uuid@example.com:443?vless_mode=legacy#explicit")
                .unwrap();
        assert_eq!(legacy.id, explicit_legacy.id);

        let ids = ["uot-v2", "h2mux", "h2mux-padded", "xudp", "mux-cool"].map(|mode| {
            Node::from_share_link(&format!(
                "vless://uuid@example.com:443?vless_mode={mode}#{mode}"
            ))
            .unwrap()
            .id
        });
        assert!(ids.iter().all(|id| *id != legacy.id));
        assert_eq!(
            ids.iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            ids.len()
        );
    }

    #[test]
    fn test_derive_id_is_content_derived() {
        let node = Node::from_share_link("trojan://secret@example.com:443#one").unwrap();
        // Same content, different name → same ID.
        let mut renamed = node.clone();
        renamed.name = "two".into();
        assert_eq!(node.derive_id(), renamed.derive_id());
        assert_eq!(node.id, node.derive_id());

        // Credential or endpoint change → different ID.
        let mut other_pw = node.clone();
        other_pw.trojan_mut().unwrap().password = Some("other".into());
        assert_ne!(node.derive_id(), other_pw.derive_id());
        let mut other_port = node.clone();
        other_port.port = 8443;
        assert_ne!(node.derive_id(), other_port.derive_id());
        // Dial shape participates: same server behind a different SNI or
        // transport is a different endpoint (CDN fronting).
        let mut other_sni = node.clone();
        other_sni.tls_mut().unwrap().sni = Some("cdn.example".into());
        assert_ne!(node.derive_id(), other_sni.derive_id());
        let mut other_transport = node.clone();
        other_transport.transport_mut().unwrap().transport = "ws".into();
        assert_ne!(node.derive_id(), other_transport.derive_id());
        // Validation and tuning knobs do not participate.
        let mut other_insecure = node.clone();
        other_insecure.tls_mut().unwrap().skip_cert_verify = true;
        assert_eq!(node.derive_id(), other_insecure.derive_id());
    }
}

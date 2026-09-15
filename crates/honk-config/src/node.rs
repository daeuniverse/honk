use std::borrow::Cow;

use serde::{Deserialize, Serialize};

mod protocol;
mod validation;
mod vless;
mod wire;

pub use protocol::*;
pub use validation::validate_node_collection;
pub use vless::*;
pub use wire::NodeSeed;
pub(crate) use wire::RawNodeSeed;

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

    pub(crate) fn identity_material(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.protocol().as_str(),
            identity_field(self.host()),
            self.port,
            self.outbound.credential_fingerprint(),
            self.outbound.dial_shape_fingerprint()
        )
    }

    /// Content-derived stable identity: UUID v5 over
    /// `protocol|host|port|credential-fingerprint|dial-shape`.
    /// Explicit ALPN derives a child UUID from the legacy ID and an ordered JSON list.
    pub fn derive_id(&self) -> uuid::Uuid {
        let material = self.identity_material();
        let legacy_id = uuid::Uuid::new_v5(&NODE_ID_NAMESPACE, material.as_bytes());
        if let Some(tls) = self.tls().filter(|tls| !tls.alpn.is_empty()) {
            let alpn = serde_json::to_vec(&("tls-alpn", &tls.alpn))
                .expect("TLS ALPN strings are JSON serializable");
            uuid::Uuid::new_v5(&legacy_id, &alpn)
        } else {
            legacy_id
        }
    }
}

/// Escape raw identity fields without changing ordinary nodes' legacy material.
/// Both `|` and `\` must be escaped so different field splits stay distinct (#193).
fn identity_field(value: &str) -> Cow<'_, str> {
    let escapes = value
        .bytes()
        .filter(|byte| matches!(byte, b'|' | b'\\'))
        .count();
    if escapes == 0 {
        return Cow::Borrowed(value);
    }
    let mut escaped = String::with_capacity(value.len() + escapes);
    for character in value.chars() {
        if matches!(character, '|' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    Cow::Owned(escaped)
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
    /// Initial Selector member tag (node or subgroup) when no valid runtime choice exists.
    /// Missing/non-member defaults use the first existing member; health does not replace a choice.
    #[serde(default)]
    pub default: Option<String>,
    /// Explicit fallback for the caller when the group's policy has no available selection.
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
    /// Request tracking removal on selection changes; live relays are not cancelled.
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
    /// Manual selection — valid runtime choice, then valid `Group.default`, then first existing member.
    /// Health never switches TCP or UDP to another member; missing/non-member tags are resolved again.
    /// Same-name nodes resolve to the first matching member in declaration order.
    /// The caller may apply an explicit final, or retry the same sole TCP leaf within this path.
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
                "hysteria2",
                "hysteria2://secret@example.com:443#hysteria2",
                "f622cf2a-ef2e-5777-abdb-d8c826d11f57",
            ),
            (
                "tuic",
                "tuic://00000000-0000-0000-0000-000000000001:pass@example.com:443#tuic",
                "e8751061-7db8-5d0d-b2e9-04af9ce55d02",
            ),
            (
                "juicity",
                "juicity://00000000-0000-0000-0000-000000000001:pass@example.com:443#juicity",
                "26d8181d-9c09-580d-86bc-1bdc22f1d113",
            ),
            (
                "anytls",
                "anytls://secret@example.com:443#anytls",
                "743d15b1-586a-5095-9e49-58c6f444f738",
            ),
        ];

        for (name, link, expected) in cases {
            let mut node = Node::from_share_link(link).unwrap();
            // Admission changed; the historical identity material and hashes did not.
            match &mut node.outbound {
                OutboundConfig::Tuic(config) => config.uuid = Some("uuid".into()),
                OutboundConfig::Juicity(config) => config.uuid = Some("uuid".into()),
                _ => {}
            }
            assert_eq!(node.derive_id().to_string(), expected, "{name}");
        }
    }

    #[test]
    fn test_identity_credential_split() {
        for p in ["socks5", "ss", "tuic", "juicity"] {
            let base =
                Node::from_share_link(&format!("{p}://00000000-0000-0000-0000-000000000001:c@h"))
                    .unwrap();
            let [left, right] = [("a|b", "c"), ("a", "b|c")].map(|(first, second)| {
                let mut node = base.clone();
                let (credential, password) = match &mut node.outbound {
                    OutboundConfig::Socks5(config) => (&mut config.username, &mut config.password),
                    OutboundConfig::Shadowsocks(config) => {
                        (&mut config.encryption, &mut config.password)
                    }
                    OutboundConfig::Tuic(config) => (&mut config.uuid, &mut config.password),
                    OutboundConfig::Juicity(config) => (&mut config.uuid, &mut config.password),
                    _ => unreachable!(),
                };
                *credential = Some(first.into());
                *password = Some(second.into());
                node.derive_id()
            });
            assert_ne!(left, right);
        }
    }

    #[test]
    fn test_identity_vless_credential_arity() {
        let mut left =
            Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443")
                .unwrap();
        let mut right = left.clone();
        left.vless_mut().unwrap().uuid = Some("b".into());
        left.vless_mut().unwrap().encryption = Some("a".into());
        right.vless_mut().unwrap().uuid = Some("a|b".into());
        assert_ne!(left.derive_id(), right.derive_id());
    }

    #[test]
    fn test_identity_dial_shape_split() {
        let mut left =
            Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443?type=ws&sni=a%7Cws&path=%2Fp")
                .unwrap();
        let mut right =
            Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443?type=ws&sni=a&path=ws%7C%2Fp")
                .unwrap();
        left.vless_mut().unwrap().uuid = Some("uuid".into());
        right.vless_mut().unwrap().uuid = Some("uuid".into());
        assert_ne!(left.derive_id(), right.derive_id());
    }

    #[test]
    fn test_identity_effective_host_split() {
        let mut node = Node::from_share_link("socks5://a:b@h:443").unwrap();
        let plain_id = node.derive_id();
        node.host = "h|1080".into();
        assert!(node.identity_material().contains(r"|h\|1080|"));
        assert_ne!(node.derive_id(), plain_id);
    }

    #[test]
    fn test_identity_vless_layout_control() {
        let mut encrypted = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?sni=tcp",
        )
        .unwrap();
        let mut xudp = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=xudp&sni=b",
        )
        .unwrap();
        encrypted.vless_mut().unwrap().uuid = Some("b".into());
        encrypted.vless_mut().unwrap().encryption = Some("a".into());
        xudp.vless_mut().unwrap().uuid = Some("a".into());
        assert_ne!(encrypted.derive_id(), xudp.derive_id());
    }

    #[test]
    fn test_identity_escape_mutation_check() {
        let left = [r"|\", ""].map(identity_field).join("|");
        let right = [r"\", "|"].map(identity_field).join("|");
        assert_ne!(left, right);
    }

    #[test]
    fn test_vless_identity_uses_canonical_effective_settings() {
        let off =
            Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443")
                .unwrap();
        let no_pools = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?mux=xray&concurrency=-1&xudpConcurrency=-1&xudpProxyUDP443=allow",
        )
        .unwrap();
        assert_ne!(off.id, no_pools.id);
        let mut spaced_none = off.clone();
        spaced_none.vless_mut().unwrap().encryption = Some(" none ".into());
        assert_eq!(off.id, spaced_none.derive_id());

        let defaults = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?mux=xray",
        )
        .unwrap();
        let explicit = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?mux=xray&concurrency=8&xudpConcurrency=0",
        )
        .unwrap();
        assert_eq!(defaults.id, explicit.id);

        let pooled_auto = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?mux=xray&xudpConcurrency=8&xudpProxyUDP443=allow",
        )
        .unwrap();
        let pooled_unused_encoding = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=uot-v2&mux=xray&xudpConcurrency=8&xudpProxyUDP443=allow",
        )
        .unwrap();
        assert_eq!(pooled_auto.id, pooled_unused_encoding.id);
    }

    #[test]
    fn test_vless_packet_disable_identity_is_effective() {
        let enabled = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=none",
        )
        .unwrap();
        let disabled = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=none&udp=0",
        )
        .unwrap();
        let mut equivalent = disabled.clone();
        equivalent.vless_mut().unwrap().network = Some(" TCP ".into());
        assert_ne!(enabled.id, disabled.id);
        assert_eq!(disabled.id, equivalent.derive_id());
        for network in ["udp", " TCP, UDP "] {
            let mut equivalent = enabled.clone();
            equivalent.vless_mut().unwrap().network = Some(network.into());
            assert_eq!(enabled.id, equivalent.derive_id());
        }

        let disabled_xudp = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443?packetEncoding=xudp&udp=0",
        )
        .unwrap();
        assert_eq!(disabled.id, disabled_xudp.id);
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

    #[test]
    fn test_tls_alpn_identity_is_ordered_and_framed() {
        let legacy = Node::from_share_link("anytls://secret@example.com:443#anytls").unwrap();
        assert_eq!(
            legacy.id.to_string(),
            "743d15b1-586a-5095-9e49-58c6f444f738"
        );

        let id_with = |protocols: &[&str]| {
            let mut node = legacy.clone();
            node.tls_mut().unwrap().alpn = protocols.iter().map(|value| (*value).into()).collect();
            node.validate_protocol().unwrap();
            node.derive_id()
        };
        assert_eq!(id_with(&[]), legacy.id);
        let ids = [
            id_with(&["h2"]),
            id_with(&["h2", "http/1.1"]),
            id_with(&["http/1.1", "h2"]),
            id_with(&["a,b", "c"]),
            id_with(&["a", "b,c"]),
        ];
        assert_eq!(
            ids.iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            ids.len()
        );
        assert!(ids.iter().all(|id| *id != legacy.id));

        let mut explicit = legacy.clone();
        explicit.anytls_mut().unwrap().password = Some("p".into());
        explicit.tls_mut().unwrap().alpn = vec!["X||tcp||||||||".into()];
        let mut embedded = legacy;
        embedded.anytls_mut().unwrap().password = Some("p||tcp|||||||||tls-alpn:1:14:X".into());
        assert_ne!(explicit.derive_id(), embedded.derive_id());
    }

    #[test]
    fn test_tls_alpn_validation_boundaries_and_context() {
        for protocol in [String::new(), "x".repeat(256), "é".repeat(128)] {
            let tls = TlsOptions {
                alpn: vec![protocol],
                ..Default::default()
            };
            assert!(tls.validate_alpn().is_err());
        }

        let mut tls = TlsOptions {
            alpn: vec!["x".repeat(255); 255],
            ..Default::default()
        };
        tls.alpn.push("x".repeat(252));
        assert!(tls.validate_alpn().is_ok());
        tls.alpn.push("x".into());
        assert!(tls.validate_alpn().is_err());

        let mut raw = Node::from_share_link("trojan://secret@example.com:443").unwrap();
        raw.transport_mut().unwrap().transport.clear();
        raw.tls_mut().unwrap().alpn = vec!["h2".into()];
        assert!(raw.validate_protocol().is_ok());

        let mut disabled = Node::from_share_link("trojan://secret@example.com:443").unwrap();
        disabled.tls_mut().unwrap().enabled = false;
        disabled.tls_mut().unwrap().alpn = vec!["h2".into()];

        let mut wrapped =
            Node::from_share_link("trojan://secret@example.com:443?type=ws&path=%2Fproxy").unwrap();
        wrapped.tls_mut().unwrap().alpn = vec!["h2".into()];

        let mut reality =
            Node::from_share_link("vless://00000000-0000-0000-0000-000000000001@example.com:443?security=reality&pbk=public-key")
                .unwrap();
        reality.tls_mut().unwrap().alpn = vec!["h2".into()];

        let mut quic = Node::from_share_link("hysteria2://secret@example.com:443").unwrap();
        quic.tls_mut().unwrap().alpn = vec!["h3".into()];

        for node in [disabled, wrapped, reality, quic] {
            assert!(node.validate_protocol().is_err(), "{}", node.name);
        }
    }

    #[test]
    fn test_validate_redacts_anytls_alpn_context_name() {
        let mut node = Node::from_share_link("anytls://secret@example.com:443#anytls").unwrap();
        assert!(node.validate().is_ok());

        const CANARY: &str = "node-name-canary-anytls";
        node.name = CANARY.into();
        let tls = node.tls_mut().unwrap();
        tls.enabled = false;
        tls.alpn = vec!["h2".into()];

        let error = node.validate().unwrap_err();
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(CANARY), "{rendered}");
    }

    #[test]
    fn test_validate_redacts_vless_path_context_name() {
        let mut node = Node::from_share_link(
            "vless://00000000-0000-0000-0000-000000000001@example.com:443#vless",
        )
        .unwrap();
        assert!(node.validate().is_ok());

        const CANARY: &str = "node-name-canary-vless";
        node.name = CANARY.into();
        let vless = node.vless_mut().unwrap();
        vless.udp_encoding = VlessUdpEncoding::UotV2;
        vless.flow = Some("xtls-rprx-vision".into());
        vless.tls.enabled = true;

        let error = node.validate().unwrap_err();
        let rendered = format!("{error} {error:?}");
        assert!(!rendered.contains(CANARY), "{rendered}");
    }
}

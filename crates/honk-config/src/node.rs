use serde::{Deserialize, Serialize};

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

/// A proxy node definition.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    /// Stable identity derived from the node's content by [`Node::derive_id`]
    /// at every construction entry (nil until then — the runtime registry
    /// rejects nil IDs, so a missed entry fails loudly).
    #[serde(default)]
    pub id: uuid::Uuid,
    pub name: String,
    pub protocol: NodeProtocol,
    pub address: String,
    #[serde(default)]
    pub host: String,
    pub port: u16,
    /// Username / password / UUID for auth
    #[serde(default)]
    pub username: Option<String>,
    /// Password / UUID for auth
    #[serde(default)]
    pub password: Option<String>,
    /// Protocol encryption/cipher setting (SS, VMess, or VLESS Encryption)
    #[serde(default)]
    pub encryption: Option<String>,
    /// VLESS TCP/UDP multiplexing mode.
    #[serde(default)]
    pub vless_mode: WireMode,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,
    /// Transport protocol (tcp/udp/ws/grpc etc.)
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default)]
    pub tls: bool,
    /// TLS server name (SNI)
    #[serde(default)]
    pub sni: Option<String>,
    /// Skip certificate verification
    #[serde(default)]
    pub skip_cert_verify: bool,
    /// Enable ECH (Encrypted Client Hello) for TLS/QUIC handshakes
    #[serde(default)]
    pub ech_enabled: bool,
    /// Base64-encoded ECHConfigList; implies ech_enabled when set
    #[serde(default)]
    pub ech_config: Option<String>,
    /// Path to a file containing a base64-encoded ECHConfigList
    #[serde(default)]
    pub ech_config_path: Option<String>,
    /// REALITY public key (share-link `pbk`); selects the REALITY handshake
    #[serde(default)]
    pub reality_public_key: Option<String>,
    /// REALITY short id (share-link `sid`)
    #[serde(default)]
    pub reality_short_id: Option<String>,
    /// REALITY spider path (share-link `spx`, share-link default `/`)
    #[serde(default)]
    pub reality_spider_x: Option<String>,
    /// VLESS flow control; only `xtls-rprx-vision` is supported and it
    /// requires REALITY or TLS (enforced by `Config::validate`)
    #[serde(default)]
    pub flow: Option<String>,
    /// Network type for V2Ray (tcp/ws/grpc/h2/quic/kcp)
    #[serde(default)]
    pub network: Option<String>,
    /// WebSocket path
    #[serde(default)]
    pub ws_path: Option<String>,
    /// WebSocket host header
    #[serde(default)]
    pub ws_host: Option<String>,
    /// gRPC service name
    #[serde(default)]
    pub grpc_service: Option<String>,
    /// Hysteria2 authentication
    #[serde(default)]
    pub hy2_auth: Option<String>,
    /// Hysteria2 obfuscation
    #[serde(default)]
    pub hy2_obfs: Option<String>,
    /// Hysteria2 upload bandwidth in Mbps; enables the brutal sender when set
    #[serde(default)]
    pub hy2_up_mbps: Option<u32>,
    /// Hysteria2 download bandwidth in Mbps (advertised via `Hysteria-CC-RX`)
    #[serde(default)]
    pub hy2_down_mbps: Option<u32>,
    /// Hysteria2 port hopping list (`mport`: "20000-30000" or "p1,p2,...")
    #[serde(default)]
    pub hy2_port_hopping: Option<String>,
    /// Hysteria2 port hopping interval in seconds (`mhop`, default 30)
    #[serde(default)]
    pub hy2_hop_interval: Option<u64>,
    /// SHA-256 fingerprint of the peer leaf certificate (hex); replaces PKI
    /// and hostname verification when set (`pinSHA256`)
    #[serde(default)]
    pub tls_pin_sha256: Option<String>,
    /// Hysteria2 initial stream receive window in bytes
    /// (`initStreamReceiveWindow`)
    #[serde(default)]
    pub hy2_init_stream_recv_window: Option<u64>,
    /// Hysteria2 initial connection receive window in bytes
    /// (`initConnReceiveWindow`)
    #[serde(default)]
    pub hy2_init_conn_recv_window: Option<u64>,
    /// Hysteria2: disable QUIC path MTU discovery (`disablePathMTUDiscovery`)
    #[serde(default)]
    pub hy2_disable_mtu_discovery: Option<bool>,
    /// QUIC protocols (hy2/tuic/juicity): UDP **payload** size in bytes
    /// (share-link `mtu=`, valid range 1200..=65527, clamped). Applied to
    /// the send-side initial MTU, the PMTUD upper bound, and the endpoint's
    /// receive advertisement — it is NOT the link/IP MTU (IPv4 payload on
    /// a 1500 link is 1472; on PMTU-unsafe last miles keep the 1252
    /// default).
    #[serde(default)]
    pub quic_mtu: Option<u16>,
    /// TUIC UUID
    #[serde(default)]
    pub tuic_uuid: Option<String>,
    /// TUIC password
    #[serde(default)]
    pub tuic_password: Option<String>,
    /// TUIC congestion control
    #[serde(default)]
    pub tuic_congestion: Option<String>,
    /// TUIC ALPN (share-link `alpn=`; comma-separated for multiple).
    /// Defaults to `tuic` when unset — servers configured with e.g. `h3`
    /// (HTTP/3 camouflage) reject the handshake otherwise.
    #[serde(default)]
    pub tuic_alpn: Option<String>,
    /// TUIC: initial per-stream receive window (`initStreamReceiveWindow`).
    /// quinn's default (1.25MB) caps a stream at ~12.5MB/s per 100ms RTT —
    /// far too small for long-fat links; unset uses honk's larger default.
    #[serde(default)]
    pub tuic_init_stream_recv_window: Option<u64>,
    /// TUIC: initial connection-level receive window (`initConnReceiveWindow`).
    #[serde(default)]
    pub tuic_init_conn_recv_window: Option<u64>,
    /// Juicity UUID
    #[serde(default)]
    pub juicity_uuid: Option<String>,
    /// Juicity password
    #[serde(default)]
    pub juicity_password: Option<String>,
    /// AnyTLS password
    #[serde(default)]
    pub anytls_password: Option<String>,
    /// Minimum idle AnyTLS sessions to maintain per node.
    #[serde(default)]
    pub anytls_min_idle_session: Option<usize>,
    /// Seconds between AnyTLS idle session heartbeat checks.
    #[serde(default)]
    pub anytls_idle_session_check_interval: Option<u64>,
    /// Seconds before an idle AnyTLS session is evicted.
    #[serde(default)]
    pub anytls_idle_session_timeout: Option<u64>,
    /// Outbound mark for routing
    #[serde(default)]
    pub mark: Option<u32>,
    /// Tags for classification
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub subscription_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub group_id: Option<uuid::Uuid>,
    #[serde(default = "chrono::Utc::now")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default = "chrono::Utc::now")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn default_transport() -> String {
    "tcp".to_string()
}

impl Default for Node {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::nil(),
            name: String::new(),
            protocol: NodeProtocol::default(),
            address: String::new(),
            host: String::new(),
            port: 0,
            username: None,
            password: None,
            encryption: None,
            vless_mode: WireMode::default(),
            plugin: None,
            plugin_opts: None,
            transport: default_transport(),
            tls: false,
            sni: None,
            skip_cert_verify: false,
            ech_enabled: false,
            ech_config: None,
            ech_config_path: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_spider_x: None,
            flow: None,
            network: None,
            ws_path: None,
            ws_host: None,
            grpc_service: None,
            hy2_auth: None,
            hy2_obfs: None,
            hy2_up_mbps: None,
            hy2_down_mbps: None,
            hy2_port_hopping: None,
            hy2_hop_interval: None,
            tls_pin_sha256: None,
            hy2_init_stream_recv_window: None,
            hy2_init_conn_recv_window: None,
            hy2_disable_mtu_discovery: None,
            quic_mtu: None,
            tuic_uuid: None,
            tuic_password: None,
            tuic_congestion: None,
            tuic_alpn: None,
            tuic_init_stream_recv_window: None,
            tuic_init_conn_recv_window: None,
            juicity_uuid: None,
            juicity_password: None,
            anytls_password: None,
            anytls_min_idle_session: None,
            anytls_idle_session_check_interval: None,
            anytls_idle_session_timeout: None,
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
    /// Get the effective host (use host field or parse from address).
    pub fn host(&self) -> &str {
        if self.host.is_empty() {
            self.address.split(':').next().unwrap_or(&self.address)
        } else {
            &self.host
        }
    }
    pub fn validate_vless_mode(&self) -> Result<(), crate::ConfigError> {
        if self.vless_mode == WireMode::Legacy {
            return Ok(());
        }
        if self.protocol != NodeProtocol::VLess {
            return Err(crate::ConfigError::Validation(format!(
                "Node '{}' sets a VLESS mode on a non-VLESS protocol",
                self.name
            )));
        }
        if let Some(flow) = self.flow.as_deref().filter(|flow| !flow.is_empty())
            && !(self.vless_mode == WireMode::Xudp && flow == "xtls-rprx-vision")
        {
            return Err(crate::ConfigError::Validation(format!(
                "Node '{}' combines VLESS mode '{}' with flow; this combination is unsupported",
                self.name,
                self.vless_mode.as_str()
            )));
        }
        if self
            .encryption
            .as_deref()
            .is_some_and(|value| !value.is_empty() && value != "none")
        {
            return Err(crate::ConfigError::Validation(format!(
                "Node '{}' combines VLESS mode '{}' with VLESS Encryption; this combination is unsupported",
                self.name,
                self.vless_mode.as_str()
            )));
        }
        Ok(())
    }

    /// Content-derived stable identity: UUID v5 over
    /// `protocol|host|port|credential-fingerprint|dial-shape`. The same
    /// node config keeps its ID across reloads and subscription refreshes
    /// (health state, latency history, and session pools survive); renaming
    /// a node does NOT change the ID — identity is the dialable endpoint,
    /// not the label. Dial shape covers SNI, transport, obfs, the
    /// REALITY/flow handshake shape, and non-legacy VLESS modes;
    /// validation and tuning knobs are excluded.
    pub fn derive_id(&self) -> uuid::Uuid {
        let material = format!(
            "{}|{}|{}|{}|{}",
            self.protocol.as_str(),
            self.host(),
            self.port,
            self.credential_fingerprint(),
            self.dial_shape_fingerprint()
        );
        uuid::Uuid::new_v5(&NODE_ID_NAMESPACE, material.as_bytes())
    }

    fn dial_shape_fingerprint(&self) -> String {
        let mut fingerprint = [
            self.sni.as_deref().unwrap_or(""),
            self.transport.as_str(),
            self.ws_path.as_deref().unwrap_or(""),
            self.ws_host.as_deref().unwrap_or(""),
            self.grpc_service.as_deref().unwrap_or(""),
            self.hy2_obfs.as_deref().unwrap_or(""),
            self.reality_public_key.as_deref().unwrap_or(""),
            self.reality_short_id.as_deref().unwrap_or(""),
            self.reality_spider_x.as_deref().unwrap_or(""),
            self.flow.as_deref().unwrap_or(""),
        ]
        .join("|");
        if self.protocol == NodeProtocol::VLess && self.vless_mode != WireMode::Legacy {
            fingerprint.push('|');
            fingerprint.push_str(self.vless_mode.as_str());
        }
        fingerprint
    }

    /// The protocol's credential identity, resolved the same way the
    /// protocol handlers resolve their auth fields (specific field first,
    /// generic `username`/`password` fallback). Empty for protocols
    /// without credentials (direct/block, unauthenticated socks5).
    fn credential_fingerprint(&self) -> String {
        let user = self.username.as_deref().unwrap_or("");
        let pass = self.password.as_deref().unwrap_or("");
        match self.protocol {
            NodeProtocol::SS => {
                format!("{}|{}", self.encryption.as_deref().unwrap_or(""), pass)
            }
            NodeProtocol::Trojan | NodeProtocol::VMess => pass.to_string(),
            NodeProtocol::VLess
                if self
                    .encryption
                    .as_deref()
                    .is_some_and(|value| !value.is_empty() && value != "none") =>
            {
                format!(
                    "{}|{}",
                    self.encryption.as_deref().unwrap_or_default(),
                    pass
                )
            }
            NodeProtocol::VLess => pass.to_string(),
            NodeProtocol::Socks5 => format!("{user}|{pass}"),
            NodeProtocol::Hysteria2 => self.hy2_auth.as_deref().unwrap_or(pass).to_string(),
            NodeProtocol::Tuic => format!(
                "{}|{}",
                self.tuic_uuid.as_deref().unwrap_or(user),
                self.tuic_password.as_deref().unwrap_or(pass)
            ),
            NodeProtocol::Juicity => format!(
                "{}|{}",
                self.juicity_uuid.as_deref().unwrap_or(user),
                self.juicity_password.as_deref().unwrap_or(pass)
            ),
            NodeProtocol::AnyTLS => self
                .password
                .as_deref()
                .or(self.anytls_password.as_deref())
                .unwrap_or("")
                .to_string(),
            NodeProtocol::Direct | NodeProtocol::Block => String::new(),
        }
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
        assert_eq!(Node::default().vless_mode, WireMode::Legacy);
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
    fn test_vless_mode_identity() {
        let legacy = Node::from_share_link("vless://uuid@example.com:443#legacy").unwrap();
        let explicit_legacy =
            Node::from_share_link("vless://uuid@example.com:443?vless_mode=legacy#explicit")
                .unwrap();
        assert_eq!(legacy.id, explicit_legacy.id);
        assert_eq!(
            legacy.id,
            uuid::Uuid::parse_str("d47c73f3-910d-56b4-baa5-d230c76d788b").unwrap()
        );

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
        other_pw.password = Some("other".into());
        assert_ne!(node.derive_id(), other_pw.derive_id());
        let mut other_port = node.clone();
        other_port.port = 8443;
        assert_ne!(node.derive_id(), other_port.derive_id());
        // Dial shape participates: same server behind a different SNI or
        // transport is a different endpoint (CDN fronting).
        let mut other_sni = node.clone();
        other_sni.sni = Some("cdn.example".into());
        assert_ne!(node.derive_id(), other_sni.derive_id());
        let mut other_transport = node.clone();
        other_transport.transport = "ws".into();
        assert_ne!(node.derive_id(), other_transport.derive_id());
        // Validation and tuning knobs do not participate.
        let mut other_insecure = node.clone();
        other_insecure.skip_cert_verify = true;
        assert_eq!(node.derive_id(), other_insecure.derive_id());
    }
}

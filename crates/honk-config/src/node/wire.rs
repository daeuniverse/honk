use serde::de::Error as _;
use serde::ser::SerializeStruct as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::types::NodeProtocol;

use super::{
    AnyTlsConfig, Hysteria2Config, JuicityConfig, Node, OutboundConfig, QuicOptions,
    ShadowsocksConfig, Socks5Config, StreamTransportOptions, TlsOptions, TrojanConfig, TuicConfig,
    VlessConfig, VmessConfig, WireMode,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct FlatNode {
    #[serde(default)]
    id: uuid::Uuid,
    name: String,
    protocol: NodeProtocol,
    address: String,
    #[serde(default)]
    host: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
    #[serde(default)]
    vless_mode: WireMode,
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    plugin_opts: Option<String>,
    #[serde(default = "super::default_transport")]
    transport: String,
    #[serde(default)]
    tls: bool,
    #[serde(default)]
    sni: Option<String>,
    #[serde(default)]
    skip_cert_verify: bool,
    #[serde(default)]
    ech_enabled: bool,
    #[serde(default)]
    ech_config: Option<String>,
    #[serde(default)]
    ech_config_path: Option<String>,
    #[serde(default)]
    reality_public_key: Option<String>,
    #[serde(default)]
    reality_short_id: Option<String>,
    #[serde(default)]
    reality_spider_x: Option<String>,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    ws_path: Option<String>,
    #[serde(default)]
    ws_host: Option<String>,
    #[serde(default)]
    grpc_service: Option<String>,
    #[serde(default)]
    hy2_auth: Option<String>,
    #[serde(default)]
    hy2_obfs: Option<String>,
    #[serde(default)]
    hy2_up_mbps: Option<u32>,
    #[serde(default)]
    hy2_down_mbps: Option<u32>,
    #[serde(default)]
    hy2_port_hopping: Option<String>,
    #[serde(default)]
    hy2_hop_interval: Option<u64>,
    #[serde(default)]
    tls_pin_sha256: Option<String>,
    #[serde(default)]
    hy2_init_stream_recv_window: Option<u64>,
    #[serde(default)]
    hy2_init_conn_recv_window: Option<u64>,
    #[serde(default)]
    hy2_disable_mtu_discovery: Option<bool>,
    #[serde(default)]
    quic_mtu: Option<u16>,
    #[serde(default)]
    tuic_uuid: Option<String>,
    #[serde(default)]
    tuic_password: Option<String>,
    #[serde(default)]
    tuic_congestion: Option<String>,
    #[serde(default)]
    tuic_alpn: Option<String>,
    #[serde(default)]
    tuic_init_stream_recv_window: Option<u64>,
    #[serde(default)]
    tuic_init_conn_recv_window: Option<u64>,
    #[serde(default)]
    juicity_uuid: Option<String>,
    #[serde(default)]
    juicity_password: Option<String>,
    #[serde(default)]
    anytls_password: Option<String>,
    #[serde(default)]
    anytls_min_idle_session: Option<usize>,
    #[serde(default)]
    anytls_idle_session_check_interval: Option<u64>,
    #[serde(default)]
    anytls_idle_session_timeout: Option<u64>,
    #[serde(default)]
    mark: Option<u32>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    subscription_id: Option<uuid::Uuid>,
    #[serde(default)]
    group_id: Option<uuid::Uuid>,
    #[serde(default = "chrono::Utc::now")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default = "chrono::Utc::now")]
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl FlatNode {
    fn strip_protocol_incompatible_fields(&mut self) {
        let stream = matches!(
            self.protocol,
            NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess
        );
        let tls = matches!(
            self.protocol,
            NodeProtocol::Trojan
                | NodeProtocol::VMess
                | NodeProtocol::VLess
                | NodeProtocol::Hysteria2
                | NodeProtocol::Tuic
                | NodeProtocol::Juicity
                | NodeProtocol::AnyTLS
        );
        let reality = matches!(
            self.protocol,
            NodeProtocol::Trojan | NodeProtocol::VMess | NodeProtocol::VLess
        );
        let unused_username_credential = if self.username.is_some() {
            match self.protocol {
                NodeProtocol::Trojan | NodeProtocol::VLess
                    if self.password.as_deref().is_none_or(str::is_empty) =>
                {
                    Some("password")
                }
                NodeProtocol::Hysteria2
                    if self
                        .hy2_auth
                        .as_deref()
                        .or(self.password.as_deref())
                        .is_none_or(str::is_empty) =>
                {
                    Some("hy2_auth/password")
                }
                NodeProtocol::AnyTLS
                    if self
                        .password
                        .as_deref()
                        .or(self.anytls_password.as_deref())
                        .is_none_or(str::is_empty) =>
                {
                    Some("password/anytls_password")
                }
                _ => None,
            }
        } else {
            None
        };
        let mut dropped = Vec::new();
        macro_rules! strip {
            ($condition:expr, $field:ident) => {
                if $condition {
                    let _ = std::mem::take(&mut self.$field);
                    dropped.push(stringify!($field));
                }
            };
        }

        strip!(
            self.username.is_some()
                && (unused_username_credential.is_some()
                    || !matches!(
                        self.protocol,
                        NodeProtocol::Socks5
                            | NodeProtocol::Trojan
                            | NodeProtocol::VLess
                            | NodeProtocol::Hysteria2
                            | NodeProtocol::Tuic
                            | NodeProtocol::Juicity
                            | NodeProtocol::AnyTLS
                    )),
            username
        );
        strip!(
            self.password.is_some()
                && matches!(self.protocol, NodeProtocol::Direct | NodeProtocol::Block),
            password
        );
        strip!(
            self.encryption.is_some()
                && !matches!(
                    self.protocol,
                    NodeProtocol::SS | NodeProtocol::VMess | NodeProtocol::VLess
                ),
            encryption
        );
        strip!(
            self.vless_mode != WireMode::Legacy && self.protocol != NodeProtocol::VLess,
            vless_mode
        );
        strip!(
            self.plugin.is_some() && self.protocol != NodeProtocol::SS,
            plugin
        );
        strip!(
            self.plugin_opts.is_some() && self.protocol != NodeProtocol::SS,
            plugin_opts
        );
        strip!(self.transport != "tcp" && !stream, transport);
        strip!(self.tls && !tls, tls);
        strip!(self.sni.is_some() && !tls, sni);
        strip!(self.skip_cert_verify && !tls, skip_cert_verify);
        strip!(self.ech_enabled && !tls, ech_enabled);
        strip!(self.ech_config.is_some() && !tls, ech_config);
        strip!(self.ech_config_path.is_some() && !tls, ech_config_path);
        strip!(
            self.reality_public_key.is_some() && !reality,
            reality_public_key
        );
        strip!(
            self.reality_short_id.is_some() && !reality,
            reality_short_id
        );
        strip!(
            self.reality_spider_x.is_some() && !reality,
            reality_spider_x
        );
        strip!(
            self.flow.is_some() && self.protocol != NodeProtocol::VLess,
            flow
        );
        strip!(
            self.network.is_some()
                && !matches!(
                    self.protocol,
                    NodeProtocol::Trojan
                        | NodeProtocol::VMess
                        | NodeProtocol::VLess
                        | NodeProtocol::AnyTLS
                ),
            network
        );
        strip!(self.ws_path.is_some() && !stream, ws_path);
        strip!(self.ws_host.is_some() && !stream, ws_host);
        strip!(self.grpc_service.is_some() && !stream, grpc_service);

        let hy2 = self.protocol == NodeProtocol::Hysteria2;
        strip!(self.hy2_auth.is_some() && !hy2, hy2_auth);
        strip!(self.hy2_obfs.is_some() && !hy2, hy2_obfs);
        strip!(self.hy2_up_mbps.is_some() && !hy2, hy2_up_mbps);
        strip!(self.hy2_down_mbps.is_some() && !hy2, hy2_down_mbps);
        strip!(self.hy2_port_hopping.is_some() && !hy2, hy2_port_hopping);
        strip!(self.hy2_hop_interval.is_some() && !hy2, hy2_hop_interval);
        strip!(
            self.hy2_init_stream_recv_window.is_some() && !hy2,
            hy2_init_stream_recv_window
        );
        strip!(
            self.hy2_init_conn_recv_window.is_some() && !hy2,
            hy2_init_conn_recv_window
        );
        strip!(
            self.hy2_disable_mtu_discovery.is_some() && !hy2,
            hy2_disable_mtu_discovery
        );

        let quic = matches!(
            self.protocol,
            NodeProtocol::Hysteria2 | NodeProtocol::Tuic | NodeProtocol::Juicity
        );
        strip!(self.tls_pin_sha256.is_some() && !tls, tls_pin_sha256);
        strip!(self.quic_mtu.is_some() && !quic, quic_mtu);

        let tuic = self.protocol == NodeProtocol::Tuic;
        strip!(self.tuic_uuid.is_some() && !tuic, tuic_uuid);
        strip!(self.tuic_password.is_some() && !tuic, tuic_password);
        strip!(self.tuic_congestion.is_some() && !tuic, tuic_congestion);
        strip!(self.tuic_alpn.is_some() && !tuic, tuic_alpn);
        strip!(
            self.tuic_init_stream_recv_window.is_some() && !tuic,
            tuic_init_stream_recv_window
        );
        strip!(
            self.tuic_init_conn_recv_window.is_some() && !tuic,
            tuic_init_conn_recv_window
        );

        let juicity = self.protocol == NodeProtocol::Juicity;
        strip!(self.juicity_uuid.is_some() && !juicity, juicity_uuid);
        strip!(
            self.juicity_password.is_some() && !juicity,
            juicity_password
        );

        let anytls = self.protocol == NodeProtocol::AnyTLS;
        strip!(self.anytls_password.is_some() && !anytls, anytls_password);
        strip!(
            self.anytls_min_idle_session.is_some() && !anytls,
            anytls_min_idle_session
        );
        strip!(
            self.anytls_idle_session_check_interval.is_some() && !anytls,
            anytls_idle_session_check_interval
        );
        strip!(
            self.anytls_idle_session_timeout.is_some() && !anytls,
            anytls_idle_session_timeout
        );

        if !dropped.is_empty() {
            if let Some(credential) = unused_username_credential {
                tracing::warn!(
                    node = %self.name,
                    protocol = %self.protocol.as_str(),
                    fields = %dropped.join(", "),
                    "credential field '{}' is empty; 'username' is not used by {}",
                    credential,
                    self.protocol.as_str()
                );
            } else {
                tracing::warn!(
                    node = %self.name,
                    protocol = %self.protocol.as_str(),
                    fields = %dropped.join(", "),
                    "ignoring protocol-incompatible fields"
                );
            }
        }
    }

    fn take_tls(&mut self) -> TlsOptions {
        TlsOptions {
            enabled: self.tls,
            sni: self.sni.take(),
            skip_cert_verify: self.skip_cert_verify,
            ech_enabled: self.ech_enabled,
            ech_config: self.ech_config.take(),
            ech_config_path: self.ech_config_path.take(),
            reality_public_key: self.reality_public_key.take(),
            reality_short_id: self.reality_short_id.take(),
            reality_spider_x: self.reality_spider_x.take(),
            pin_sha256: self.tls_pin_sha256.take(),
        }
    }

    fn take_transport(&mut self) -> StreamTransportOptions {
        StreamTransportOptions {
            transport: std::mem::take(&mut self.transport),
            ws_path: self.ws_path.take(),
            ws_host: self.ws_host.take(),
            grpc_service: self.grpc_service.take(),
        }
    }
}

impl TryFrom<FlatNode> for Node {
    type Error = crate::ConfigError;

    fn try_from(mut flat: FlatNode) -> Result<Self, Self::Error> {
        flat.strip_protocol_incompatible_fields();
        let outbound = match flat.protocol {
            NodeProtocol::SS => OutboundConfig::Shadowsocks(ShadowsocksConfig {
                password: flat.password.take(),
                encryption: flat.encryption.take(),
                plugin: flat.plugin.take(),
                plugin_opts: flat.plugin_opts.take(),
            }),
            NodeProtocol::Trojan => {
                let transport = flat.take_transport();
                let tls = flat.take_tls();
                OutboundConfig::Trojan(TrojanConfig {
                    password: flat.password.take(),
                    network: flat.network.take(),
                    transport,
                    tls,
                })
            }
            NodeProtocol::VMess => {
                let transport = flat.take_transport();
                let tls = flat.take_tls();
                OutboundConfig::Vmess(VmessConfig {
                    uuid: flat.password.take(),
                    encryption: flat.encryption.take(),
                    network: flat.network.take(),
                    transport,
                    tls,
                })
            }
            NodeProtocol::VLess => {
                let transport = flat.take_transport();
                let tls = flat.take_tls();
                OutboundConfig::Vless(VlessConfig {
                    uuid: flat.password.take(),
                    encryption: flat.encryption.take(),
                    mode: flat.vless_mode,
                    flow: flat.flow.take(),
                    network: flat.network.take(),
                    transport,
                    tls,
                })
            }
            NodeProtocol::Socks5 => OutboundConfig::Socks5(Socks5Config {
                username: flat.username.take(),
                password: flat.password.take(),
            }),
            NodeProtocol::Hysteria2 => {
                let tls = flat.take_tls();
                OutboundConfig::Hysteria2(Hysteria2Config {
                    auth: flat.hy2_auth.take().or_else(|| flat.password.take()),
                    obfs: flat.hy2_obfs.take(),
                    up_mbps: flat.hy2_up_mbps,
                    down_mbps: flat.hy2_down_mbps,
                    port_hopping: flat.hy2_port_hopping.take(),
                    hop_interval: flat.hy2_hop_interval,
                    init_stream_recv_window: flat.hy2_init_stream_recv_window,
                    init_conn_recv_window: flat.hy2_init_conn_recv_window,
                    disable_mtu_discovery: flat.hy2_disable_mtu_discovery,
                    quic: QuicOptions {
                        tls,
                        mtu: flat.quic_mtu,
                    },
                })
            }
            NodeProtocol::Tuic => {
                let tls = flat.take_tls();
                OutboundConfig::Tuic(TuicConfig {
                    uuid: flat.tuic_uuid.take().or_else(|| flat.username.take()),
                    password: flat.tuic_password.take().or_else(|| flat.password.take()),
                    congestion: flat.tuic_congestion.take(),
                    alpn: flat.tuic_alpn.take(),
                    init_stream_recv_window: flat.tuic_init_stream_recv_window,
                    init_conn_recv_window: flat.tuic_init_conn_recv_window,
                    quic: QuicOptions {
                        tls,
                        mtu: flat.quic_mtu,
                    },
                })
            }
            NodeProtocol::Juicity => {
                let tls = flat.take_tls();
                OutboundConfig::Juicity(JuicityConfig {
                    uuid: flat.juicity_uuid.take().or_else(|| flat.username.take()),
                    password: flat
                        .juicity_password
                        .take()
                        .or_else(|| flat.password.take()),
                    quic: QuicOptions {
                        tls,
                        mtu: flat.quic_mtu,
                    },
                })
            }
            NodeProtocol::AnyTLS => {
                let tls = flat.take_tls();
                OutboundConfig::AnyTls(AnyTlsConfig {
                    password: flat.password.take().or_else(|| flat.anytls_password.take()),
                    network: flat.network.take(),
                    min_idle_session: flat.anytls_min_idle_session,
                    idle_session_check_interval: flat.anytls_idle_session_check_interval,
                    idle_session_timeout: flat.anytls_idle_session_timeout,
                    tls,
                })
            }
            NodeProtocol::Direct => OutboundConfig::Direct,
            NodeProtocol::Block => OutboundConfig::Block,
        };
        Ok(Node {
            id: flat.id,
            name: flat.name,
            address: flat.address,
            host: flat.host,
            port: flat.port,
            outbound,
            mark: flat.mark,
            tags: flat.tags,
            subscription_id: flat.subscription_id,
            group_id: flat.group_id,
            created_at: flat.created_at,
            updated_at: flat.updated_at,
        })
    }
}

#[derive(Default)]
struct WireOptions<'a> {
    username: Option<&'a str>,
    password: Option<&'a str>,
    encryption: Option<&'a str>,
    vless_mode: WireMode,
    plugin: Option<&'a str>,
    plugin_opts: Option<&'a str>,
    transport: &'a str,
    tls: bool,
    sni: Option<&'a str>,
    skip_cert_verify: bool,
    ech_enabled: bool,
    ech_config: Option<&'a str>,
    ech_config_path: Option<&'a str>,
    reality_public_key: Option<&'a str>,
    reality_short_id: Option<&'a str>,
    reality_spider_x: Option<&'a str>,
    flow: Option<&'a str>,
    network: Option<&'a str>,
    ws_path: Option<&'a str>,
    ws_host: Option<&'a str>,
    grpc_service: Option<&'a str>,
    hy2_auth: Option<&'a str>,
    hy2_obfs: Option<&'a str>,
    hy2_up_mbps: Option<u32>,
    hy2_down_mbps: Option<u32>,
    hy2_port_hopping: Option<&'a str>,
    hy2_hop_interval: Option<u64>,
    tls_pin_sha256: Option<&'a str>,
    hy2_init_stream_recv_window: Option<u64>,
    hy2_init_conn_recv_window: Option<u64>,
    hy2_disable_mtu_discovery: Option<bool>,
    quic_mtu: Option<u16>,
    tuic_uuid: Option<&'a str>,
    tuic_password: Option<&'a str>,
    tuic_congestion: Option<&'a str>,
    tuic_alpn: Option<&'a str>,
    tuic_init_stream_recv_window: Option<u64>,
    tuic_init_conn_recv_window: Option<u64>,
    juicity_uuid: Option<&'a str>,
    juicity_password: Option<&'a str>,
    anytls_password: Option<&'a str>,
    anytls_min_idle_session: Option<usize>,
    anytls_idle_session_check_interval: Option<u64>,
    anytls_idle_session_timeout: Option<u64>,
}

impl<'a> WireOptions<'a> {
    fn set_tls(&mut self, tls: &'a TlsOptions) {
        self.tls = tls.enabled;
        self.sni = tls.sni.as_deref();
        self.skip_cert_verify = tls.skip_cert_verify;
        self.ech_enabled = tls.ech_enabled;
        self.ech_config = tls.ech_config.as_deref();
        self.ech_config_path = tls.ech_config_path.as_deref();
        self.reality_public_key = tls.reality_public_key.as_deref();
        self.reality_short_id = tls.reality_short_id.as_deref();
        self.reality_spider_x = tls.reality_spider_x.as_deref();
        self.tls_pin_sha256 = tls.pin_sha256.as_deref();
    }

    fn set_transport(&mut self, transport: &'a StreamTransportOptions) {
        self.transport = &transport.transport;
        self.ws_path = transport.ws_path.as_deref();
        self.ws_host = transport.ws_host.as_deref();
        self.grpc_service = transport.grpc_service.as_deref();
    }

    fn from_node(node: &'a Node) -> Self {
        let mut wire = Self {
            transport: "tcp",
            ..Self::default()
        };
        match &node.outbound {
            OutboundConfig::Shadowsocks(config) => {
                wire.password = config.password.as_deref();
                wire.encryption = config.encryption.as_deref();
                wire.plugin = config.plugin.as_deref();
                wire.plugin_opts = config.plugin_opts.as_deref();
            }
            OutboundConfig::Trojan(config) => {
                wire.username = config.password.as_deref();
                wire.password = config.password.as_deref();
                wire.network = config.network.as_deref();
                wire.set_transport(&config.transport);
                wire.set_tls(&config.tls);
            }
            OutboundConfig::Vmess(config) => {
                wire.password = config.uuid.as_deref();
                wire.encryption = config.encryption.as_deref();
                wire.network = config.network.as_deref();
                wire.set_transport(&config.transport);
                wire.set_tls(&config.tls);
            }
            OutboundConfig::Vless(config) => {
                wire.username = config.uuid.as_deref();
                wire.password = config.uuid.as_deref();
                wire.encryption = config.encryption.as_deref();
                wire.vless_mode = config.mode;
                wire.flow = config.flow.as_deref();
                wire.network = config.network.as_deref();
                wire.set_transport(&config.transport);
                wire.set_tls(&config.tls);
            }
            OutboundConfig::Socks5(config) => {
                wire.username = config.username.as_deref();
                wire.password = config.password.as_deref();
            }
            OutboundConfig::Hysteria2(config) => {
                wire.username = config.auth.as_deref();
                wire.password = config.auth.as_deref();
                wire.hy2_auth = config.auth.as_deref();
                wire.hy2_obfs = config.obfs.as_deref();
                wire.hy2_up_mbps = config.up_mbps;
                wire.hy2_down_mbps = config.down_mbps;
                wire.hy2_port_hopping = config.port_hopping.as_deref();
                wire.hy2_hop_interval = config.hop_interval;
                wire.hy2_init_stream_recv_window = config.init_stream_recv_window;
                wire.hy2_init_conn_recv_window = config.init_conn_recv_window;
                wire.hy2_disable_mtu_discovery = config.disable_mtu_discovery;
                wire.quic_mtu = config.quic.mtu;
                wire.set_tls(&config.quic.tls);
            }
            OutboundConfig::Tuic(config) => {
                wire.username = config.uuid.as_deref();
                wire.password = config.password.as_deref();
                wire.tuic_uuid = config.uuid.as_deref();
                wire.tuic_password = config.password.as_deref();
                wire.tuic_congestion = config.congestion.as_deref();
                wire.tuic_alpn = config.alpn.as_deref();
                wire.tuic_init_stream_recv_window = config.init_stream_recv_window;
                wire.tuic_init_conn_recv_window = config.init_conn_recv_window;
                wire.quic_mtu = config.quic.mtu;
                wire.set_tls(&config.quic.tls);
            }
            OutboundConfig::Juicity(config) => {
                wire.username = config.uuid.as_deref();
                wire.password = config.password.as_deref();
                wire.juicity_uuid = config.uuid.as_deref();
                wire.juicity_password = config.password.as_deref();
                wire.quic_mtu = config.quic.mtu;
                wire.set_tls(&config.quic.tls);
            }
            OutboundConfig::AnyTls(config) => {
                wire.username = config.password.as_deref();
                wire.password = config.password.as_deref();
                wire.anytls_password = config.password.as_deref();
                wire.network = config.network.as_deref();
                wire.anytls_min_idle_session = config.min_idle_session;
                wire.anytls_idle_session_check_interval = config.idle_session_check_interval;
                wire.anytls_idle_session_timeout = config.idle_session_timeout;
                wire.set_tls(&config.tls);
            }
            OutboundConfig::Direct | OutboundConfig::Block => {}
        }
        wire
    }
}

impl Serialize for Node {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wire = WireOptions::from_node(self);
        let mut state = serializer.serialize_struct("Node", 56)?;
        state.serialize_field("id", &self.id)?;
        state.serialize_field("name", &self.name)?;
        state.serialize_field("protocol", &self.protocol())?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("host", &self.host)?;
        state.serialize_field("port", &self.port)?;
        state.serialize_field("username", &wire.username)?;
        state.serialize_field("password", &wire.password)?;
        state.serialize_field("encryption", &wire.encryption)?;
        state.serialize_field("vless_mode", &wire.vless_mode)?;
        state.serialize_field("plugin", &wire.plugin)?;
        state.serialize_field("plugin_opts", &wire.plugin_opts)?;
        state.serialize_field("transport", wire.transport)?;
        state.serialize_field("tls", &wire.tls)?;
        state.serialize_field("sni", &wire.sni)?;
        state.serialize_field("skip_cert_verify", &wire.skip_cert_verify)?;
        state.serialize_field("ech_enabled", &wire.ech_enabled)?;
        state.serialize_field("ech_config", &wire.ech_config)?;
        state.serialize_field("ech_config_path", &wire.ech_config_path)?;
        state.serialize_field("reality_public_key", &wire.reality_public_key)?;
        state.serialize_field("reality_short_id", &wire.reality_short_id)?;
        state.serialize_field("reality_spider_x", &wire.reality_spider_x)?;
        state.serialize_field("flow", &wire.flow)?;
        state.serialize_field("network", &wire.network)?;
        state.serialize_field("ws_path", &wire.ws_path)?;
        state.serialize_field("ws_host", &wire.ws_host)?;
        state.serialize_field("grpc_service", &wire.grpc_service)?;
        state.serialize_field("hy2_auth", &wire.hy2_auth)?;
        state.serialize_field("hy2_obfs", &wire.hy2_obfs)?;
        state.serialize_field("hy2_up_mbps", &wire.hy2_up_mbps)?;
        state.serialize_field("hy2_down_mbps", &wire.hy2_down_mbps)?;
        state.serialize_field("hy2_port_hopping", &wire.hy2_port_hopping)?;
        state.serialize_field("hy2_hop_interval", &wire.hy2_hop_interval)?;
        state.serialize_field("tls_pin_sha256", &wire.tls_pin_sha256)?;
        state.serialize_field(
            "hy2_init_stream_recv_window",
            &wire.hy2_init_stream_recv_window,
        )?;
        state.serialize_field("hy2_init_conn_recv_window", &wire.hy2_init_conn_recv_window)?;
        state.serialize_field("hy2_disable_mtu_discovery", &wire.hy2_disable_mtu_discovery)?;
        state.serialize_field("quic_mtu", &wire.quic_mtu)?;
        state.serialize_field("tuic_uuid", &wire.tuic_uuid)?;
        state.serialize_field("tuic_password", &wire.tuic_password)?;
        state.serialize_field("tuic_congestion", &wire.tuic_congestion)?;
        state.serialize_field("tuic_alpn", &wire.tuic_alpn)?;
        state.serialize_field(
            "tuic_init_stream_recv_window",
            &wire.tuic_init_stream_recv_window,
        )?;
        state.serialize_field(
            "tuic_init_conn_recv_window",
            &wire.tuic_init_conn_recv_window,
        )?;
        state.serialize_field("juicity_uuid", &wire.juicity_uuid)?;
        state.serialize_field("juicity_password", &wire.juicity_password)?;
        state.serialize_field("anytls_password", &wire.anytls_password)?;
        state.serialize_field("anytls_min_idle_session", &wire.anytls_min_idle_session)?;
        state.serialize_field(
            "anytls_idle_session_check_interval",
            &wire.anytls_idle_session_check_interval,
        )?;
        state.serialize_field(
            "anytls_idle_session_timeout",
            &wire.anytls_idle_session_timeout,
        )?;
        state.serialize_field("mark", &self.mark)?;
        state.serialize_field("tags", &self.tags)?;
        state.serialize_field("subscription_id", &self.subscription_id)?;
        state.serialize_field("group_id", &self.group_id)?;
        state.serialize_field("created_at", &self.created_at)?;
        state.serialize_field("updated_at", &self.updated_at)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        FlatNode::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}

use serde::de::{DeserializeSeed, Error as _};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::validation::ValidationFailure;
use crate::diagnostic::{
    DetailedDiagnostic, DiagnosticSources, SafeValue, SettingPath, SourceRef,
    report_detailed_diagnostics,
};
use crate::options::vocab::{coalesce_equal, optional_flow, packet_network};
use crate::types::NodeProtocol;

use super::{
    AnyTlsConfig, Hysteria2Config, JuicityConfig, Node, OutboundConfig, QuicOptions,
    ShadowsocksConfig, Socks5Config, StreamTransportOptions, TlsOptions, TrojanConfig, TuicConfig,
    VlessConfig, VlessMultiplex, VlessUdpEncoding, VmessConfig,
};
fn semantic_error(
    source: &SourceRef,
    setting: SettingPath,
    message: &'static str,
) -> crate::error::DetailedConfigError {
    crate::error::DetailedConfigError::new(
        crate::error::ErrorCategory::Validation,
        "invalid-config-value",
        source.clone(),
        setting,
        message,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum RawVlessMode {
    #[default]
    Missing,
    Null,
    Legacy,
    Incompatible,
}

impl<'de> Deserialize<'de> for RawVlessMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'value> serde::de::Visitor<'value> for Visitor {
            type Value = RawVlessMode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a legacy VLESS mode string or null")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "legacy" => Ok(RawVlessMode::Legacy),
                    "auto" | "native" | "uot-v2" | "h2mux" | "h2mux-padded" | "xudp"
                    | "mux-cool" => Ok(RawVlessMode::Incompatible),
                    _ => Err(E::unknown_variant(
                        value,
                        &[
                            "legacy",
                            "auto",
                            "native",
                            "uot-v2",
                            "h2mux",
                            "h2mux-padded",
                            "xudp",
                            "mux-cool",
                        ],
                    )),
                }
            }

            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(RawVlessMode::Null)
            }

            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(RawVlessMode::Null)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
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
    vless_mode: RawVlessMode,
    #[serde(default)]
    packet_encoding: Option<VlessUdpEncoding>,
    #[serde(default)]
    multiplex: Option<VlessMultiplex>,
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
    tls_alpn: Vec<String>,
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
    fn resolve_credential_aliases(&mut self) -> Result<(), ValidationFailure> {
        fn resolve(
            field: &'static str,
            dedicated: Option<String>,
            generic: Option<String>,
        ) -> Result<Option<String>, ValidationFailure> {
            coalesce_equal(
                [Ok(dedicated), Ok(generic)],
                "credential aliases must agree",
            )
            .map_err(|message| ValidationFailure::new(Some(field), message))
        }

        match self.protocol {
            NodeProtocol::Hysteria2 => {
                self.hy2_auth = resolve("hy2_auth", self.hy2_auth.take(), self.password.take())?;
            }
            NodeProtocol::Tuic => {
                self.tuic_uuid = resolve("tuic_uuid", self.tuic_uuid.take(), self.username.take())?;
                self.tuic_password = resolve(
                    "tuic_password",
                    self.tuic_password.take(),
                    self.password.take(),
                )?;
            }
            NodeProtocol::Juicity => {
                self.juicity_uuid = resolve(
                    "juicity_uuid",
                    self.juicity_uuid.take(),
                    self.username.take(),
                )?;
                self.juicity_password = resolve(
                    "juicity_password",
                    self.juicity_password.take(),
                    self.password.take(),
                )?;
            }
            NodeProtocol::AnyTLS => {
                self.anytls_password = resolve(
                    "anytls_password",
                    self.anytls_password.take(),
                    self.password.take(),
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    fn strip_protocol_incompatible_fields(
        &mut self,
        diagnostics: &mut Vec<DetailedDiagnostic>,
        source: &SourceRef,
        setting: &SettingPath,
    ) {
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
            self.vless_mode == RawVlessMode::Incompatible && self.protocol != NodeProtocol::VLess,
            vless_mode
        );
        strip!(
            self.protocol != NodeProtocol::VLess
                && self
                    .packet_encoding
                    .is_some_and(|encoding| encoding != VlessUdpEncoding::Auto),
            packet_encoding
        );
        strip!(
            self.protocol != NodeProtocol::VLess
                && self
                    .multiplex
                    .is_some_and(|multiplex| multiplex != VlessMultiplex::Off),
            multiplex
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
            diagnostics.push(DetailedDiagnostic::warning(
                "incompatible-node-fields",
                source.clone(),
                setting.clone(),
                SafeValue::Fields(dropped),
                if unused_username_credential.is_some() {
                    "credential field is empty; username is not used by this protocol"
                } else {
                    "ignoring protocol-incompatible fields"
                },
            ));
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
            alpn: std::mem::take(&mut self.tls_alpn),
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

impl FlatNode {
    fn into_node(
        mut self,
        diagnostics: &mut Vec<DetailedDiagnostic>,
        source: &SourceRef,
        setting: &SettingPath,
    ) -> Result<Node, crate::error::DetailedConfigError> {
        self.resolve_credential_aliases()
            .map_err(|error| error.into_detailed(source.clone(), setting.clone()))?;
        if self.protocol == NodeProtocol::VLess && self.vless_mode != RawVlessMode::Missing {
            return Err(crate::error::DetailedConfigError::new(
                crate::error::ErrorCategory::Validation,
                "removed-vless-mode",
                source.clone(),
                setting.clone().field("vless_mode"),
                "VLESS vless_mode was removed; use packet_encoding and multiplex",
            ));
        }
        self.strip_protocol_incompatible_fields(diagnostics, source, setting);
        if self.protocol == NodeProtocol::VMess {
            self.encryption = crate::options::vocab::vmess_cipher(self.encryption.as_deref())
                .map_err(|_| {
                    semantic_error(
                        source,
                        setting.clone().field("encryption"),
                        "VMess cipher must be auto or aes-128-gcm; aliases must agree",
                    )
                })?
                .map(str::to_owned);
        }
        if let Some(value) = self.network.as_deref()
            && packet_network(value)
                .map_err(|_| {
                    semantic_error(
                        source,
                        setting.clone().field("network"),
                        "packet network must contain only tcp or udp tokens",
                    )
                })?
                .is_none()
        {
            self.network = None;
        }
        if self.protocol == NodeProtocol::VLess
            && optional_flow(self.flow.as_deref())
                .map_err(|_| {
                    semantic_error(
                        source,
                        setting.clone().field("flow"),
                        "VLESS flow must be absent, xtls-rprx-vision, or xtls-rprx-vision-udp443; aliases must agree",
                    )
                })?
                .is_none()
        {
            self.flow = None;
        }
        self.sni = self.sni.take().filter(|value| !value.trim().is_empty());
        let mut flat = self;
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
                let mut config = VlessConfig {
                    uuid: flat.password.take(),
                    encryption: flat.encryption.take(),
                    udp_encoding: flat.packet_encoding.take().unwrap_or_default(),
                    multiplex: flat.multiplex.take().unwrap_or_default(),
                    flow: flat.flow.take(),
                    network: flat.network.take(),
                    transport,
                    tls,
                };
                config.normalize();
                OutboundConfig::Vless(config)
            }
            NodeProtocol::Socks5 => OutboundConfig::Socks5(Socks5Config {
                username: flat.username.take(),
                password: flat.password.take(),
            }),
            NodeProtocol::Hysteria2 => {
                let tls = flat.take_tls();
                OutboundConfig::Hysteria2(Hysteria2Config {
                    auth: flat.hy2_auth.take(),
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
                    uuid: flat.tuic_uuid.take(),
                    password: flat.tuic_password.take(),
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
                    uuid: flat.juicity_uuid.take(),
                    password: flat.juicity_password.take(),
                    quic: QuicOptions {
                        tls,
                        mtu: flat.quic_mtu,
                    },
                })
            }
            NodeProtocol::AnyTLS => {
                let tls = flat.take_tls();
                OutboundConfig::AnyTls(AnyTlsConfig {
                    password: flat.anytls_password.take(),
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
        if !flat.tls_alpn.is_empty() {
            return Err(semantic_error(
                source,
                setting.clone().field("tls_alpn"),
                "TLS ALPN requires a TLS-capable protocol",
            ));
        }
        let node = Node {
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
        };
        node.validate_detailed_at(source, setting)?;
        Ok(node)
    }
}

#[derive(Default, Serialize)]
#[serde(rename = "Node")]
struct WireOptions<'a> {
    id: uuid::Uuid,
    name: &'a str,
    protocol: NodeProtocol,
    address: &'a str,
    host: &'a str,
    port: u16,
    username: Option<&'a str>,
    password: Option<&'a str>,
    encryption: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vless_mode: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet_encoding: Option<VlessUdpEncoding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    multiplex: Option<&'a VlessMultiplex>,
    plugin: Option<&'a str>,
    plugin_opts: Option<&'a str>,
    transport: &'a str,
    tls: bool,
    sni: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_alpn: Option<&'a [String]>,
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
    mark: Option<u32>,
    tags: &'a [String],
    subscription_id: Option<uuid::Uuid>,
    group_id: Option<uuid::Uuid>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl<'a> WireOptions<'a> {
    fn set_tls(&mut self, tls: &'a TlsOptions) {
        self.tls = tls.enabled;
        self.sni = tls.sni.as_deref();
        self.tls_alpn = (!tls.alpn.is_empty()).then_some(tls.alpn.as_slice());
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
            id: node.id,
            name: &node.name,
            protocol: node.protocol(),
            address: &node.address,
            host: &node.host,
            port: node.port,
            vless_mode: (node.protocol() != NodeProtocol::VLess).then_some("legacy"),
            transport: "tcp",
            mark: node.mark,
            tags: &node.tags,
            subscription_id: node.subscription_id,
            group_id: node.group_id,
            created_at: node.created_at,
            updated_at: node.updated_at,
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
                wire.packet_encoding = Some(config.udp_encoding);
                wire.multiplex = Some(&config.multiplex);
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
        WireOptions::from_node(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Node {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut diagnostics = Vec::new();
        let result = NodeSeed {
            diagnostics: &mut diagnostics,
            source: DiagnosticSources::new(None).root(),
            setting: SettingPath::new("nodes"),
        }
        .deserialize(deserializer);
        report_detailed_diagnostics(&diagnostics);
        result
    }
}

/// Data-only serde adapter; the enclosing Config/Node attempt owns terminal reporting.
pub struct NodeSeed<'a> {
    pub diagnostics: &'a mut Vec<DetailedDiagnostic>,
    pub source: SourceRef,
    pub setting: SettingPath,
}

/// Crate-private variant used by the detailed structured loaders. It leaves the
/// decoder error intact until the format-specific owner has captured location
/// metadata and replaced the public error with a redacted terminal.
pub(crate) struct RawNodeSeed<'a> {
    pub diagnostics: &'a mut Vec<DetailedDiagnostic>,
    pub source: SourceRef,
    pub setting: SettingPath,
    pub record_semantic: bool,
}

impl<'de> DeserializeSeed<'de> for NodeSeed<'_> {
    type Value = Node;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Node, D::Error> {
        RawNodeSeed {
            diagnostics: self.diagnostics,
            source: self.source,
            setting: self.setting,
            record_semantic: false,
        }
        .deserialize(deserializer)
        .map_err(|_| D::Error::custom("invalid node fields"))
    }
}

impl<'de> DeserializeSeed<'de> for RawNodeSeed<'_> {
    type Value = Node;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Node, D::Error> {
        let RawNodeSeed {
            diagnostics,
            source,
            setting,
            record_semantic,
        } = self;
        let flat = FlatNode::deserialize(deserializer)?;
        flat.into_node(diagnostics, &source, &setting)
            .map_err(|mut error| {
                if record_semantic {
                    error.diagnostic.entry_index =
                        setting.0.iter().find_map(|segment| match segment {
                            crate::diagnostic::SettingSegment::Index(index) => Some(*index),
                            _ => None,
                        });
                    diagnostics.push(*error.diagnostic);
                }
                D::Error::custom("invalid node fields")
            })
    }
}

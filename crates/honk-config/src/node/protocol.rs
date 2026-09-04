use crate::types::NodeProtocol;

use super::WireMode;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TlsOptions {
    pub enabled: bool,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
    pub ech_enabled: bool,
    pub ech_config: Option<String>,
    pub ech_config_path: Option<String>,
    pub reality_public_key: Option<String>,
    pub reality_short_id: Option<String>,
    pub reality_spider_x: Option<String>,
    pub pin_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StreamTransportOptions {
    pub transport: String,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub grpc_service: Option<String>,
}

impl Default for StreamTransportOptions {
    fn default() -> Self {
        Self {
            transport: "tcp".to_string(),
            ws_path: None,
            ws_host: None,
            grpc_service: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct QuicOptions {
    pub tls: TlsOptions,
    pub mtu: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ShadowsocksConfig {
    pub password: Option<String>,
    pub encryption: Option<String>,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Socks5Config {
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TrojanConfig {
    pub password: Option<String>,
    pub network: Option<String>,
    pub transport: StreamTransportOptions,
    pub tls: TlsOptions,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct VmessConfig {
    pub uuid: Option<String>,
    pub encryption: Option<String>,
    pub network: Option<String>,
    pub transport: StreamTransportOptions,
    pub tls: TlsOptions,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct VlessConfig {
    pub uuid: Option<String>,
    pub encryption: Option<String>,
    pub mode: WireMode,
    pub flow: Option<String>,
    pub network: Option<String>,
    pub transport: StreamTransportOptions,
    pub tls: TlsOptions,
}

impl VlessConfig {
    pub fn validate(&self, name: &str) -> Result<(), crate::ConfigError> {
        if self.mode != WireMode::Legacy {
            if let Some(flow) = self.flow.as_deref().filter(|flow| !flow.is_empty())
                && !(self.mode == WireMode::Xudp && flow == "xtls-rprx-vision")
            {
                return Err(crate::ConfigError::Validation(format!(
                    "Node '{name}' combines VLESS mode '{}' with flow; this combination is unsupported",
                    self.mode.as_str()
                )));
            }
            if self
                .encryption
                .as_deref()
                .is_some_and(|value| !value.is_empty() && value != "none")
            {
                return Err(crate::ConfigError::Validation(format!(
                    "Node '{name}' combines VLESS mode '{}' with VLESS Encryption; this combination is unsupported",
                    self.mode.as_str()
                )));
            }
        }
        // A REALITY node without a usable public key falls back to ordinary TLS with the
        // configured SNI, which is the opposite of what selecting REALITY asked for.
        let has_key = self
            .tls
            .reality_public_key
            .as_deref()
            .is_some_and(|key| !key.trim().is_empty());
        // Presence is the intent, not a non-empty value: an empty short id is documented as
        // valid, and an empty key is exactly what parse_reality_config reads as "no REALITY".
        let wants_reality = self.tls.reality_public_key.is_some()
            || self.tls.reality_short_id.is_some()
            || self.tls.reality_spider_x.is_some();
        if wants_reality && !has_key {
            return Err(crate::ConfigError::Validation(format!(
                "Node '{name}' selects REALITY without reality_public_key"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Hysteria2Config {
    pub auth: Option<String>,
    pub obfs: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub port_hopping: Option<String>,
    pub hop_interval: Option<u64>,
    pub init_stream_recv_window: Option<u64>,
    pub init_conn_recv_window: Option<u64>,
    pub disable_mtu_discovery: Option<bool>,
    pub quic: QuicOptions,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct TuicConfig {
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub congestion: Option<String>,
    pub alpn: Option<String>,
    pub init_stream_recv_window: Option<u64>,
    pub init_conn_recv_window: Option<u64>,
    pub quic: QuicOptions,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct JuicityConfig {
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub quic: QuicOptions,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct AnyTlsConfig {
    pub password: Option<String>,
    pub network: Option<String>,
    pub min_idle_session: Option<usize>,
    pub idle_session_check_interval: Option<u64>,
    pub idle_session_timeout: Option<u64>,
    pub tls: TlsOptions,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutboundConfig {
    Shadowsocks(ShadowsocksConfig),
    Trojan(TrojanConfig),
    Vmess(VmessConfig),
    Vless(VlessConfig),
    Socks5(Socks5Config),
    Hysteria2(Hysteria2Config),
    Tuic(TuicConfig),
    Juicity(JuicityConfig),
    AnyTls(AnyTlsConfig),
    Direct,
    Block,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        Self::Shadowsocks(ShadowsocksConfig::default())
    }
}

impl OutboundConfig {
    pub fn from_protocol(protocol: NodeProtocol) -> Self {
        match protocol {
            NodeProtocol::SS => Self::Shadowsocks(ShadowsocksConfig::default()),
            NodeProtocol::Trojan => Self::Trojan(TrojanConfig::default()),
            NodeProtocol::VMess => Self::Vmess(VmessConfig::default()),
            NodeProtocol::VLess => Self::Vless(VlessConfig::default()),
            NodeProtocol::Socks5 => Self::Socks5(Socks5Config::default()),
            NodeProtocol::Hysteria2 => Self::Hysteria2(Hysteria2Config::default()),
            NodeProtocol::Tuic => Self::Tuic(TuicConfig::default()),
            NodeProtocol::Juicity => Self::Juicity(JuicityConfig::default()),
            NodeProtocol::AnyTLS => Self::AnyTls(AnyTlsConfig::default()),
            NodeProtocol::Direct => Self::Direct,
            NodeProtocol::Block => Self::Block,
        }
    }

    pub fn protocol(&self) -> NodeProtocol {
        match self {
            Self::Shadowsocks(_) => NodeProtocol::SS,
            Self::Trojan(_) => NodeProtocol::Trojan,
            Self::Vmess(_) => NodeProtocol::VMess,
            Self::Vless(_) => NodeProtocol::VLess,
            Self::Socks5(_) => NodeProtocol::Socks5,
            Self::Hysteria2(_) => NodeProtocol::Hysteria2,
            Self::Tuic(_) => NodeProtocol::Tuic,
            Self::Juicity(_) => NodeProtocol::Juicity,
            Self::AnyTls(_) => NodeProtocol::AnyTLS,
            Self::Direct => NodeProtocol::Direct,
            Self::Block => NodeProtocol::Block,
        }
    }

    pub fn tls(&self) -> Option<&TlsOptions> {
        match self {
            Self::Trojan(config) => Some(&config.tls),
            Self::Vmess(config) => Some(&config.tls),
            Self::Vless(config) => Some(&config.tls),
            Self::Hysteria2(config) => Some(&config.quic.tls),
            Self::Tuic(config) => Some(&config.quic.tls),
            Self::Juicity(config) => Some(&config.quic.tls),
            Self::AnyTls(config) => Some(&config.tls),
            Self::Shadowsocks(_) | Self::Socks5(_) | Self::Direct | Self::Block => None,
        }
    }

    pub fn tls_mut(&mut self) -> Option<&mut TlsOptions> {
        match self {
            Self::Trojan(config) => Some(&mut config.tls),
            Self::Vmess(config) => Some(&mut config.tls),
            Self::Vless(config) => Some(&mut config.tls),
            Self::Hysteria2(config) => Some(&mut config.quic.tls),
            Self::Tuic(config) => Some(&mut config.quic.tls),
            Self::Juicity(config) => Some(&mut config.quic.tls),
            Self::AnyTls(config) => Some(&mut config.tls),
            Self::Shadowsocks(_) | Self::Socks5(_) | Self::Direct | Self::Block => None,
        }
    }

    pub fn transport(&self) -> Option<&StreamTransportOptions> {
        match self {
            Self::Trojan(config) => Some(&config.transport),
            Self::Vmess(config) => Some(&config.transport),
            Self::Vless(config) => Some(&config.transport),
            _ => None,
        }
    }

    pub fn transport_mut(&mut self) -> Option<&mut StreamTransportOptions> {
        match self {
            Self::Trojan(config) => Some(&mut config.transport),
            Self::Vmess(config) => Some(&mut config.transport),
            Self::Vless(config) => Some(&mut config.transport),
            _ => None,
        }
    }

    pub fn network(&self) -> Option<&str> {
        match self {
            Self::Trojan(config) => config.network.as_deref(),
            Self::Vmess(config) => config.network.as_deref(),
            Self::Vless(config) => config.network.as_deref(),
            Self::AnyTls(config) => config.network.as_deref(),
            _ => None,
        }
    }

    pub fn vless(&self) -> Option<&VlessConfig> {
        match self {
            Self::Vless(config) => Some(config),
            _ => None,
        }
    }

    pub fn vless_mut(&mut self) -> Option<&mut VlessConfig> {
        match self {
            Self::Vless(config) => Some(config),
            _ => None,
        }
    }

    pub(crate) fn credential_fingerprint(&self) -> String {
        match self {
            Self::Shadowsocks(config) => format!(
                "{}|{}",
                config.encryption.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or("")
            ),
            Self::Trojan(config) => config.password.as_deref().unwrap_or("").to_string(),
            Self::Vmess(config) => config.uuid.as_deref().unwrap_or("").to_string(),
            Self::Vless(config)
                if config
                    .encryption
                    .as_deref()
                    .is_some_and(|value| !value.is_empty() && value != "none") =>
            {
                format!(
                    "{}|{}",
                    config.encryption.as_deref().unwrap_or_default(),
                    config.uuid.as_deref().unwrap_or("")
                )
            }
            Self::Vless(config) => config.uuid.as_deref().unwrap_or("").to_string(),
            Self::Socks5(config) => format!(
                "{}|{}",
                config.username.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or("")
            ),
            Self::Hysteria2(config) => config.auth.as_deref().unwrap_or("").to_string(),
            Self::Tuic(config) => format!(
                "{}|{}",
                config.uuid.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or("")
            ),
            Self::Juicity(config) => format!(
                "{}|{}",
                config.uuid.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or("")
            ),
            Self::AnyTls(config) => config.password.as_deref().unwrap_or("").to_string(),
            Self::Direct | Self::Block => String::new(),
        }
    }

    pub(crate) fn dial_shape_fingerprint(&self) -> String {
        let tls = self.tls();
        let transport = self.transport();
        let mut fingerprint = [
            tls.and_then(|tls| tls.sni.as_deref()).unwrap_or(""),
            transport.map_or("tcp", |transport| transport.transport.as_str()),
            transport
                .and_then(|transport| transport.ws_path.as_deref())
                .unwrap_or(""),
            transport
                .and_then(|transport| transport.ws_host.as_deref())
                .unwrap_or(""),
            transport
                .and_then(|transport| transport.grpc_service.as_deref())
                .unwrap_or(""),
            match self {
                Self::Hysteria2(config) => config.obfs.as_deref().unwrap_or(""),
                _ => "",
            },
            tls.and_then(|tls| tls.reality_public_key.as_deref())
                .unwrap_or(""),
            tls.and_then(|tls| tls.reality_short_id.as_deref())
                .unwrap_or(""),
            tls.and_then(|tls| tls.reality_spider_x.as_deref())
                .unwrap_or(""),
            match self {
                Self::Vless(config) => config.flow.as_deref().unwrap_or(""),
                _ => "",
            },
        ]
        .join("|");
        if let Self::Vless(config) = self
            && config.mode != WireMode::Legacy
        {
            fingerprint.push('|');
            fingerprint.push_str(config.mode.as_str());
        }
        fingerprint
    }
}

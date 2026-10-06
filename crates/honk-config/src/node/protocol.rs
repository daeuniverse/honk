use super::validation::ValidationFailure;
use crate::types::NodeProtocol;

use super::{VlessConfig, identity_field};

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
    pub alpn: Vec<String>,
}

impl TlsOptions {
    /// Resolve key presence without turning incomplete REALITY intent into ordinary TLS.
    /// Decoding the key and short ID belongs to the outbound handshake parser.
    pub fn effective_reality_public_key(&self) -> Result<Option<&str>, &'static str> {
        match self.reality_public_key.as_deref().map(str::trim) {
            Some(key) if !key.is_empty() => Ok(Some(key)),
            None if self.reality_short_id.is_none() && self.reality_spider_x.is_none() => Ok(None),
            _ => Err("REALITY requires reality_public_key"),
        }
    }

    /// True when the dial speaks TLS or authenticated REALITY.
    pub fn is_secure(&self) -> bool {
        self.enabled || matches!(self.effective_reality_public_key(), Ok(Some(_)))
    }

    pub(super) fn check_xhttp_alpn(&self) -> Result<(), &'static str> {
        if self.alpn.iter().all(|protocol| protocol == "h2") {
            Ok(())
        } else {
            Err("XHTTP requires H2-only ALPN")
        }
    }

    pub(super) fn validate_alpn(&self) -> Result<(), ValidationFailure> {
        let mut encoded_len = 0usize;
        for protocol in &self.alpn {
            let len = protocol.len();
            if !(1..=255).contains(&len) {
                return Err(ValidationFailure::new(
                    Some("tls_alpn"),
                    "TLS ALPN protocol names must be 1..=255 bytes",
                ));
            }
            encoded_len += len + 1;
        }
        if encoded_len > 65_533 {
            return Err(ValidationFailure::new(
                Some("tls_alpn"),
                "TLS ALPN protocol list exceeds 65533 encoded bytes",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StreamTransportOptions {
    pub transport: String,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub grpc_service: Option<String>,
    pub xhttp: Option<super::XhttpOptions>,
}

impl Default for StreamTransportOptions {
    fn default() -> Self {
        Self {
            transport: "tcp".to_string(),
            ws_path: None,
            ws_host: None,
            grpc_service: None,
            xhttp: None,
        }
    }
}

impl StreamTransportOptions {
    pub fn is_xhttp(&self) -> bool {
        self.transport == "xhttp"
    }

    pub fn normalize(&mut self) -> Result<(), &'static str> {
        let kind = crate::options::vocab::xhttp_stream_transport(&self.transport)?;
        if kind == "xhttp" {
            self.transport = "xhttp".into();
            self.xhttp
                .get_or_insert_with(Default::default)
                .normalize()?;
        }
        self.check().map_err(|(_, message)| message)
    }

    pub(super) fn check(&self) -> Result<(), (&'static str, &'static str)> {
        let kind = crate::options::vocab::xhttp_stream_transport(&self.transport)
            .map_err(|message| ("transport", message))?;
        if kind == "xhttp" {
            if !self.is_xhttp() {
                return Err((
                    "transport",
                    "XHTTP transport must be normalized before admission",
                ));
            }
            self.xhttp
                .as_ref()
                .ok_or(("xhttp", "XHTTP requires canonical options"))?
                .validate()
                .map_err(|message| ("xhttp", message))?;
            if self.ws_path.is_some() || self.ws_host.is_some() || self.grpc_service.is_some() {
                return Err(("xhttp", "XHTTP cannot use WebSocket or gRPC options"));
            }
        } else if self.xhttp.is_some() {
            return Err(("xhttp", "XHTTP options require XHTTP transport"));
        }
        Ok(())
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
            Self::Shadowsocks(config) => identity_join(&[
                config.encryption.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or(""),
            ]),
            Self::Trojan(config) => identity_join(&[config.password.as_deref().unwrap_or("")]),
            Self::Vmess(config) => identity_join(&[config.uuid.as_deref().unwrap_or("")]),
            Self::Vless(config) if config.is_encrypted() => identity_join(&[
                config.encryption.as_deref().unwrap_or_default(),
                config.uuid.as_deref().unwrap_or(""),
            ]),
            Self::Vless(config) => identity_join(&[config.uuid.as_deref().unwrap_or("")]),
            Self::Socks5(config) => identity_join(&[
                config.username.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or(""),
            ]),
            Self::Hysteria2(config) => identity_join(&[config.auth.as_deref().unwrap_or("")]),
            Self::Tuic(config) => identity_join(&[
                config.uuid.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or(""),
            ]),
            Self::Juicity(config) => identity_join(&[
                config.uuid.as_deref().unwrap_or(""),
                config.password.as_deref().unwrap_or(""),
            ]),
            Self::AnyTls(config) => identity_join(&[config.password.as_deref().unwrap_or("")]),
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
                Self::Vless(config) => config.wire_flow().unwrap_or(""),
                _ => "",
            },
        ]
        .map(identity_field)
        .join("|");
        if let Self::Vless(config) = self {
            fingerprint.push('|');
            fingerprint.push_str(&config.identity_fingerprint());
            // Keep TLS-on IDs stable while separating the plaintext dial path.
            if !config.tls.enabled && config.tls.reality_public_key.is_none() {
                fingerprint.push_str("|tls:0");
            }
        }
        if let Some(options) = transport
            .filter(|transport| transport.is_xhttp())
            .and_then(|transport| transport.xhttp.as_ref())
        {
            fingerprint.push_str("|xhttp:");
            fingerprint.push_str(&serde_json::to_string(options).expect("XHTTP options serialize"));
            fingerprint.push_str(if tls.is_some_and(TlsOptions::is_secure) {
                "|xhttp-tls:1"
            } else {
                "|xhttp-tls:0"
            });
        }
        fingerprint
    }
}

fn identity_join(fields: &[&str]) -> String {
    let capacity =
        fields.iter().map(|field| field.len()).sum::<usize>() + fields.len().saturating_sub(1);
    let mut identity = String::with_capacity(capacity);
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            identity.push('|');
        }
        identity.push_str(&identity_field(field));
    }
    identity
}

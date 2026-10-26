use serde::{Deserialize, Serialize};

/// Supported proxy node protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NodeProtocol {
    #[default]
    SS,
    Trojan,
    VMess,
    VLess,
    Socks5,
    Hysteria2,
    Tuic,
    Juicity,
    AnyTLS,
    WireGuard,
    /// Built-in bypass outbound; reserved, not a configurable protocol.
    Direct,
    /// Built-in reject outbound; reserved, not a configurable protocol.
    Block,
}

impl NodeProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeProtocol::SS => "ss",
            NodeProtocol::Trojan => "trojan",
            NodeProtocol::VMess => "vmess",
            NodeProtocol::VLess => "vless",
            NodeProtocol::Socks5 => "socks5",
            NodeProtocol::Hysteria2 => "hysteria2",
            NodeProtocol::Tuic => "tuic",
            NodeProtocol::Juicity => "juicity",
            NodeProtocol::AnyTLS => "anytls",
            NodeProtocol::WireGuard => "wireguard",
            NodeProtocol::Direct => "direct",
            NodeProtocol::Block => "block",
        }
    }
}

impl std::str::FromStr for NodeProtocol {
    type Err = crate::ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ss" | "shadowsocks" => Ok(NodeProtocol::SS),
            "trojan" => Ok(NodeProtocol::Trojan),
            "vmess" => Ok(NodeProtocol::VMess),
            "vless" => Ok(NodeProtocol::VLess),
            "socks5" => Ok(NodeProtocol::Socks5),
            "hysteria2" => Ok(NodeProtocol::Hysteria2),
            "tuic" => Ok(NodeProtocol::Tuic),
            "juicity" => Ok(NodeProtocol::Juicity),
            "anytls" => Ok(NodeProtocol::AnyTLS),
            "wireguard" | "wg" => Ok(NodeProtocol::WireGuard),
            "direct" => Ok(NodeProtocol::Direct),
            "block" => Ok(NodeProtocol::Block),
            _ => Err(crate::ConfigError::UnknownProtocol(s.to_string())),
        }
    }
}

/// Dial mode for outbound connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DialMode {
    /// IP mode: resolve domain to IP locally, then dial proxy by IP.
    /// Sniffing is disabled in this mode.
    Ip,
    /// Domain mode: verify a sniffed name against the destination, then
    /// re-run routing when verification succeeds; otherwise keep IP routing.
    Domain,
    /// Domain+: use a sniffed domain for dialing but never re-run routing.
    /// Useful when DNS does not go through dae.
    #[serde(rename = "domain+")]
    DomainPlus,
    /// Domain++: use a sniffed domain and always re-run routing.
    #[serde(rename = "domain++")]
    DomainPlusPlus,
}

impl std::str::FromStr for DialMode {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ip" => Ok(Self::Ip),
            "domain" => Ok(Self::Domain),
            "domain+" => Ok(Self::DomainPlus),
            "domain++" => Ok(Self::DomainPlusPlus),
            _ => Err(()),
        }
    }
}

/// Subscription type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionType {
    /// Simple subscription (e.g., base64 encoded node list)
    #[default]
    Simple,
    /// Clash-compatible subscription
    Clash,
    /// SIP008 subscription
    Sip008,
    /// Custom parser
    Custom,
}

/// DNS upstream protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    /// Plain UDP DNS
    #[default]
    Udp,
    /// DNS over TCP
    Tcp,
    /// DNS over TLS (DoT, RFC 7858)
    Tls,
    /// DNS over HTTPS / HTTP/2 (DoH, RFC 8484)
    Https,
    /// DNS over HTTP/3 (DoH3)
    H3,
    /// DNS over QUIC (DoQ, RFC 9250)
    Quic,
}

/// Serde `default = "..."` helper for boolean fields that default to true.
pub fn default_true() -> bool {
    true
}

/// Parse a duration string like `30s`, `1m`, `500ms` or `2h` into seconds.
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(v) = s.strip_suffix("ms") {
        let value = v.parse::<f64>().ok()?;
        if !value.is_finite() || value < 0.0 {
            return None;
        }
        return checked_duration_float((value / 1000.0).ceil());
    }
    if let Some(v) = s.strip_suffix('s') {
        return v.parse().ok();
    }
    if let Some(v) = s.strip_suffix('m') {
        return v.parse::<u64>().ok().and_then(|v| v.checked_mul(60));
    }
    if let Some(v) = s.strip_suffix('h') {
        return v.parse::<u64>().ok().and_then(|v| v.checked_mul(3600));
    }
    s.parse().ok()
}

/// Parse a millisecond duration like `500ms`, `0.5s` or a bare `500`. The
/// minute and hour suffixes `parse_duration_secs` accepts are deliberately
/// not part of this grammar. `as u64` saturates, so a non-finite or negative
/// value is refused rather than becoming `u64::MAX` or zero.
pub fn parse_duration_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(v) = s.strip_suffix("ms") {
        return v.parse().ok();
    }
    if let Some(v) = s.strip_suffix('s') {
        return v
            .parse::<f64>()
            .ok()
            .and_then(|v| checked_duration_float(v * 1000.0));
    }
    s.parse::<f64>().ok().and_then(checked_duration_float)
}

fn checked_duration_float(value: f64) -> Option<u64> {
    // u64::MAX rounds to 2^64 as f64; equality is already out of range.
    (value.is_finite() && value >= 0.0 && value < u64::MAX as f64).then_some(value as u64)
}

#[cfg(test)]
mod tests {
    use super::parse_duration_secs;

    #[test]
    fn second_durations_reject_overflow_at_the_unit_boundary() {
        for (suffix, multiplier) in [('m', 60), ('h', 3600)] {
            let maximum = u64::MAX / multiplier;
            assert_eq!(
                parse_duration_secs(&format!("{maximum}{suffix}")),
                Some(maximum * multiplier)
            );
            assert_eq!(
                parse_duration_secs(&format!("{}{suffix}", maximum + 1)),
                None
            );
        }
    }

    #[test]
    fn c14_float_durations_reject_nonfinite_negative_and_out_of_range() {
        for text in ["NaNms", "infms", "-1ms", "18446744073709551616000ms"] {
            assert_eq!(parse_duration_secs(text), None, "{text}");
        }
        for text in ["NaN", "-1", "18446744073709551616", "18446744073709552s"] {
            assert_eq!(super::parse_duration_ms(text), None, "{text}");
        }
        assert_eq!(parse_duration_secs("0.5ms"), Some(1));
        assert_eq!(super::parse_duration_ms("0.0005s"), Some(0));
        assert_eq!(super::parse_duration_ms("1m"), None);
    }

    #[test]
    fn test_node_protocol_parsing() {
        use super::NodeProtocol;
        use std::str::FromStr;
        assert_eq!(NodeProtocol::from_str("ss").unwrap(), NodeProtocol::SS);
        assert_eq!(NodeProtocol::from_str("SS").unwrap(), NodeProtocol::SS);
        assert_eq!(
            NodeProtocol::from_str("shadowsocks").unwrap(),
            NodeProtocol::SS
        );
        assert_eq!(
            NodeProtocol::from_str("trojan").unwrap(),
            NodeProtocol::Trojan
        );
        assert_eq!(
            NodeProtocol::from_str("vmess").unwrap(),
            NodeProtocol::VMess
        );
        assert_eq!(
            NodeProtocol::from_str("hysteria2").unwrap(),
            NodeProtocol::Hysteria2
        );
        assert_eq!(NodeProtocol::from_str("tuic").unwrap(), NodeProtocol::Tuic);
        assert_eq!(
            NodeProtocol::from_str("juicity").unwrap(),
            NodeProtocol::Juicity
        );
        assert_eq!(
            NodeProtocol::from_str("anytls").unwrap(),
            NodeProtocol::AnyTLS
        );
        assert!(NodeProtocol::from_str("unknown").is_err());
    }
}

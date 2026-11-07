use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};

use crate::firewall::{FirewallConfig, NatConfig};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    #[default]
    Tc,
    Xdp,
    Tun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectProfile {
    Core,
    Endpoint,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XskMode {
    Copy,
    #[default]
    ZeroCopy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PollMode {
    Event,
    #[default]
    Adaptive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationStatus {
    Candidate,
    Qualified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollCalibration {
    pub schema: u16,
    pub counting_revision: u32,
    pub executable_sha256: String,
    pub context_sha256: String,
    pub parameter_sha256: String,
    pub status: CalibrationStatus,
    pub evidence_manifest_sha256: String,
}

impl PollCalibration {
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        if self.schema == 0 || self.counting_revision == 0 {
            return Err(crate::ConfigError::Parse(
                "datapath.busy_poll.calibration: revisions must be positive".into(),
            ));
        }
        for digest in [
            &self.executable_sha256,
            &self.context_sha256,
            &self.parameter_sha256,
            &self.evidence_manifest_sha256,
        ] {
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(crate::ConfigError::Parse(
                    "datapath.busy_poll.calibration: digests require 64 lowercase hex characters"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BusyPollConfig {
    pub pps_enter: u32,
    pub pps_exit: u32,
    pub observation_window_us: u32,
    pub enter_windows: u16,
    pub exit_windows: u16,
    pub max_busy_us: u32,
    pub empty_rounds: u16,
    pub budget_window_us: u32,
    pub budget_us: u32,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub calibration: Option<PollCalibration>,
}

impl BusyPollConfig {
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        let invalid =
            || crate::ConfigError::Parse("datapath.busy_poll: invalid polling bounds".into());
        if self.pps_enter == 0
            || self.pps_exit >= self.pps_enter
            || !(1..=60_000_000).contains(&self.observation_window_us)
            || self.enter_windows < 2
            || self.exit_windows == 0
            || self.empty_rounds == 0
            || !(1..=1_000).contains(&self.max_busy_us)
            || !(1..=60_000_000).contains(&self.budget_window_us)
            || self.budget_us == 0
            || self.budget_us >= self.budget_window_us
            || self.max_busy_us > self.budget_us
        {
            return Err(invalid());
        }
        let window_ns = u64::from(self.observation_window_us)
            .checked_mul(1_000)
            .ok_or_else(invalid)?;
        for dwell in [self.enter_windows, self.exit_windows] {
            window_ns
                .checked_mul(u64::from(dwell))
                .ok_or_else(invalid)?;
        }
        for threshold in [self.pps_enter, self.pps_exit] {
            u128::from(window_ns)
                .checked_mul(u128::from(threshold))
                .ok_or_else(invalid)?;
        }
        for micros in [self.max_busy_us, self.budget_window_us, self.budget_us] {
            u64::from(micros).checked_mul(1_000).ok_or_else(invalid)?;
        }
        if let Some(calibration) = &self.calibration {
            calibration.validate()?;
        }
        Ok(())
    }
}

// Omission is optional; explicit null must not erase a backend-specific claim.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    Lan,
    Wan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XdpInterface {
    pub name: String,
    pub role: InterfaceRole,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    pub name: String,
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,
    #[serde(
        default,
        serialize_with = "serialize_address4",
        deserialize_with = "deserialize_address4"
    )]
    pub address4: Option<Ipv4Addr>,
    #[serde(
        default,
        serialize_with = "serialize_address6",
        deserialize_with = "deserialize_address6"
    )]
    pub address6: Option<Ipv6Addr>,
    pub table: u32,
    pub rule_priority: u32,
    #[serde(deserialize_with = "deserialize_capture")]
    pub capture: Vec<IpNet>,
}

pub(crate) fn default_tun_mtu() -> u16 {
    1500
}

fn invalid_tun(message: &str) -> crate::ConfigError {
    crate::ConfigError::Parse(format!("datapath.tun: {message}"))
}

pub(crate) fn parse_tun_address4(value: &str) -> Result<Ipv4Addr, crate::ConfigError> {
    value
        .strip_suffix("/32")
        .and_then(|address| address.parse().ok())
        .ok_or_else(|| invalid_tun("address4 must be an IPv4 host address with /32"))
}

pub(crate) fn parse_tun_address6(value: &str) -> Result<Ipv6Addr, crate::ConfigError> {
    value
        .strip_suffix("/128")
        .and_then(|address| address.parse().ok())
        .ok_or_else(|| invalid_tun("address6 must be an IPv6 host address with /128"))
}

fn serialize_address4<S: Serializer>(
    address: &Option<Ipv4Addr>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    address.map(Ipv4Net::from).serialize(serializer)
}

fn serialize_address6<S: Serializer>(
    address: &Option<Ipv6Addr>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    address.map(Ipv6Net::from).serialize(serializer)
}

fn deserialize_address4<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Ipv4Addr>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|value| parse_tun_address4(&value).map_err(serde::de::Error::custom))
        .transpose()
}

fn deserialize_address6<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Ipv6Addr>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|value| parse_tun_address6(&value).map_err(serde::de::Error::custom))
        .transpose()
}

pub(crate) fn canonical_tun_capture(
    mut capture: Vec<IpNet>,
) -> Result<Vec<IpNet>, crate::ConfigError> {
    if capture.is_empty() || capture.len() > 64 {
        return Err(invalid_tun("capture requires between one and 64 prefixes"));
    }
    if capture.iter().any(|prefix| *prefix != prefix.trunc()) {
        return Err(invalid_tun("capture prefixes must not contain host bits"));
    }
    capture.sort_unstable();
    capture.dedup();
    Ok(capture)
}

fn deserialize_capture<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<IpNet>, D::Error> {
    canonical_tun_capture(Vec::<IpNet>::deserialize(deserializer)?)
        .map_err(serde::de::Error::custom)
}

fn explicit_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name != "auto"
        && name != "lo"
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

impl TunConfig {
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        if !explicit_interface_name(&self.name) {
            return Err(invalid_tun(
                "name must be an explicit 1..15 byte interface name",
            ));
        }
        if self.mtu < 1280 {
            return Err(invalid_tun("mtu must be between 1280 and 65535"));
        }
        if self.address4.is_none() && self.address6.is_none() {
            return Err(invalid_tun("at least one local address is required"));
        }
        if self.address4.is_some_and(|address| {
            address.is_unspecified()
                || address.is_multicast()
                || address.is_broadcast()
                || address.is_link_local()
        }) || self.address6.is_some_and(|address| {
            address.is_unspecified()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.to_ipv4_mapped().is_some()
        }) {
            return Err(invalid_tun(
                "local addresses must be unicast, non-link-local host addresses",
            ));
        }
        if self.table == 0 || self.table == u32::MAX || (253..=255).contains(&self.table) {
            return Err(invalid_tun(
                "table must be 1..=4294967294 excluding 253..=255",
            ));
        }
        if self.rule_priority == 0
            || self
                .rule_priority
                .checked_add(4)
                .is_none_or(|last| last >= 32766)
        {
            return Err(invalid_tun(
                "rule_priority must reserve five priorities below 32766",
            ));
        }
        if self.capture.is_empty() || self.capture.len() > 64 {
            return Err(invalid_tun("capture requires between one and 64 prefixes"));
        }
        if self.capture.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid_tun(
                "capture prefixes must be sorted and nonrepeating",
            ));
        }
        for (index, prefix) in self.capture.iter().enumerate() {
            if *prefix != prefix.trunc() {
                return Err(invalid_tun("capture prefixes must not contain host bits"));
            }
            if match prefix {
                IpNet::V4(_) => self.address4.is_none(),
                IpNet::V6(_) => self.address6.is_none(),
            } {
                return Err(invalid_tun(
                    "capture prefix family requires a local address",
                ));
            }
            if self.capture[..index]
                .iter()
                .any(|earlier| earlier.contains(prefix) || prefix.contains(earlier))
            {
                return Err(invalid_tun("capture prefixes must not contain one another"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DatapathConfig {
    pub backend: Backend,
    pub direct: Option<DirectProfile>,
    pub xsk_mode: Option<XskMode>,
    pub poll_mode: Option<PollMode>,
    pub busy_poll: Option<BusyPollConfig>,
    pub interfaces: Vec<XdpInterface>,
    pub firewall: Option<FirewallConfig>,
    pub nat: NatConfig,
    pub tun: Option<TunConfig>,
}

impl Serialize for DatapathConfig {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let interfaces = self.backend != Backend::Tun || !self.interfaces.is_empty();
        let xsk_mode = self.backend != Backend::Tun || self.xsk_mode.is_some();
        let firewall = self.backend != Backend::Tun || self.firewall.is_some();
        let fields = 3
            + usize::from(xsk_mode)
            + usize::from(firewall)
            + usize::from(interfaces)
            + usize::from(self.poll_mode.is_some())
            + usize::from(self.busy_poll.is_some())
            + usize::from(self.tun.is_some());
        let mut output = serializer.serialize_struct("DatapathConfig", fields)?;
        output.serialize_field("backend", &self.backend)?;
        output.serialize_field("direct", &self.direct)?;
        if xsk_mode {
            output.serialize_field("xsk_mode", &self.xsk_mode)?;
        }
        if let Some(poll_mode) = &self.poll_mode {
            output.serialize_field("poll_mode", poll_mode)?;
        }
        if let Some(busy_poll) = &self.busy_poll {
            output.serialize_field("busy_poll", busy_poll)?;
        }
        if interfaces {
            output.serialize_field("interfaces", &self.interfaces)?;
        }
        if firewall {
            output.serialize_field("firewall", &self.firewall)?;
        }
        output.serialize_field("nat", &self.nat)?;
        if let Some(tun) = &self.tun {
            output.serialize_field("tun", tun)?;
        }
        output.end()
    }
}

impl<'de> Deserialize<'de> for DatapathConfig {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default)]
            backend: Backend,
            #[serde(default)]
            direct: Option<DirectProfile>,
            #[serde(default, deserialize_with = "present")]
            xsk_mode: Option<Option<XskMode>>,
            #[serde(default, deserialize_with = "present")]
            poll_mode: Option<PollMode>,
            #[serde(default, deserialize_with = "present")]
            busy_poll: Option<BusyPollConfig>,
            #[serde(default, deserialize_with = "present")]
            interfaces: Option<Vec<XdpInterface>>,
            #[serde(default, deserialize_with = "present")]
            firewall: Option<Option<FirewallConfig>>,
            #[serde(default)]
            nat: NatConfig,
            #[serde(default, deserialize_with = "present")]
            tun: Option<TunConfig>,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.backend == Backend::Tun
            && (wire.interfaces.is_some() || wire.xsk_mode.is_some() || wire.firewall.is_some())
        {
            return Err(serde::de::Error::custom(
                "datapath: TUN does not accept interfaces, xsk_mode or firewall fields",
            ));
        }
        Ok(Self {
            backend: wire.backend,
            direct: wire.direct,
            xsk_mode: wire.xsk_mode.flatten(),
            poll_mode: wire.poll_mode,
            busy_poll: wire.busy_poll,
            interfaces: wire.interfaces.unwrap_or_default(),
            firewall: wire.firewall.flatten(),
            nat: wire.nat,
            tun: wire.tun,
        })
    }
}

impl DatapathConfig {
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        let invalid = |message: &str| crate::ConfigError::Parse(format!("datapath: {message}"));
        let has_nat = !self.nat.is_empty();
        match self.backend {
            Backend::Tc => {
                if self.direct.is_some()
                    || self.xsk_mode.is_some()
                    || self.poll_mode.is_some()
                    || self.busy_poll.is_some()
                    || !self.interfaces.is_empty()
                    || self.firewall.is_some()
                    || has_nat
                    || self.tun.is_some()
                {
                    return Err(invalid(
                        "TC does not accept execution, binding mode, polling, interface, firewall, NAT or TUN settings",
                    ));
                }
                Ok(())
            }
            Backend::Xdp => {
                if self.tun.is_some() {
                    return Err(invalid("XDP does not accept TUN settings"));
                }
                if self.direct.is_none() {
                    return Err(invalid(
                        "XDP requires explicit direct: core or direct: endpoint; native continuation is unavailable",
                    ));
                }
                if self.interfaces.is_empty() || self.interfaces.len() > 16 {
                    return Err(invalid(
                        "XDP requires between one and sixteen explicit interfaces",
                    ));
                }
                for (index, interface) in self.interfaces.iter().enumerate() {
                    if !explicit_interface_name(&interface.name)
                        || self.interfaces[..index]
                            .iter()
                            .any(|earlier| earlier.name == interface.name)
                    {
                        return Err(invalid(
                            "interfaces must have unique, explicit Ethernet names",
                        ));
                    }
                }
                if (self.firewall.is_some() || has_nat) && self.direct != Some(DirectProfile::Core)
                {
                    return Err(invalid("firewall and NAT require explicit XDP Core Direct"));
                }
                if let Some(busy_poll) = &self.busy_poll {
                    busy_poll.validate()?;
                }
                crate::firewall::validate(self.firewall.as_ref(), &self.nat)
            }
            Backend::Tun => {
                if self.direct != Some(DirectProfile::Endpoint)
                    || self.xsk_mode.is_some()
                    || self.poll_mode.is_some()
                    || self.busy_poll.is_some()
                    || !self.interfaces.is_empty()
                    || self.firewall.is_some()
                    || has_nat
                {
                    return Err(invalid(
                        "TUN requires direct: endpoint without XDP binding mode, polling, interfaces, firewall or NAT",
                    ));
                }
                self.tun
                    .as_ref()
                    .ok_or_else(|| invalid("TUN requires an explicit tun block"))?
                    .validate()
            }
        }
    }

    pub fn effective_poll_mode(&self) -> PollMode {
        self.poll_mode.unwrap_or_default()
    }

    pub fn effective_xsk_mode(&self) -> XskMode {
        self.xsk_mode.unwrap_or_default()
    }

    pub fn same_device_setup(&self, other: &Self) -> bool {
        self.backend == other.backend
            && self.direct == other.direct
            && self.effective_xsk_mode() == other.effective_xsk_mode()
            && self.interfaces == other.interfaces
            && self.tun == other.tun
    }
}

use serde::{Deserialize, Serialize};

use crate::firewall::{FirewallConfig, NatConfig};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    #[default]
    Tc,
    Xdp,
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

// Omission is optional; explicit null must not erase an XDP-only claim.
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

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatapathConfig {
    #[serde(default)]
    pub backend: Backend,
    #[serde(default)]
    pub direct: Option<DirectProfile>,
    #[serde(default)]
    pub xsk_mode: Option<XskMode>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub poll_mode: Option<PollMode>,
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub busy_poll: Option<BusyPollConfig>,
    #[serde(default)]
    pub interfaces: Vec<XdpInterface>,
    #[serde(default)]
    pub firewall: Option<FirewallConfig>,
    #[serde(default)]
    pub nat: NatConfig,
}

impl DatapathConfig {
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        let invalid = |message: &str| crate::ConfigError::Parse(format!("datapath: {message}"));
        let has_nat = !self.nat.prerouting.is_empty() || !self.nat.postrouting.is_empty();
        if self.backend == Backend::Tc {
            if self.direct.is_some()
                || self.xsk_mode.is_some()
                || self.poll_mode.is_some()
                || self.busy_poll.is_some()
                || !self.interfaces.is_empty()
                || self.firewall.is_some()
                || has_nat
            {
                return Err(invalid(
                    "TC does not accept XDP execution, binding mode, polling, interface, firewall or NAT settings",
                ));
            }
            return Ok(());
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
            if interface.name.is_empty()
                || interface.name.len() >= 16
                || interface.name == "auto"
                || interface.name == "lo"
                || !interface
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                || self.interfaces[..index]
                    .iter()
                    .any(|earlier| earlier.name == interface.name)
            {
                return Err(invalid(
                    "interfaces must have unique, explicit Ethernet names",
                ));
            }
        }
        if (self.firewall.is_some() || has_nat) && self.direct != Some(DirectProfile::Core) {
            return Err(invalid("firewall and NAT require explicit XDP Core Direct"));
        }
        if let Some(busy_poll) = &self.busy_poll {
            busy_poll.validate()?;
        }
        crate::firewall::validate(self.firewall.as_ref(), &self.nat)
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
    }
}

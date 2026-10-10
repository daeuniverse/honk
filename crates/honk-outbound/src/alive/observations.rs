use super::{AliveDialerSet, IpVersion, ProbeDomain, RegisteredNode};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Timing captured at the successful exchange, before retries or cleanup.
#[derive(Debug, Clone, Copy)]
pub struct ProbeMeasurement {
    pub latency: Duration,
    pub observed_at: SystemTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthTransport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthPurpose {
    Data,
    Dns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthMeasurement {
    TcpConnect,
    HttpHeaders,
    DnsRoundTrip,
    QuicHandshake,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthWarmth {
    Cold,
    Warm,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Unavailable,
}

/// One completed probe, independent of routing hysteresis and latency ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthObservation {
    pub transport: HealthTransport,
    pub purpose: HealthPurpose,
    pub measurement: HealthMeasurement,
    pub ip_version: IpVersion,
    pub warmth: HealthWarmth,
    pub state: HealthState,
    pub latency: Option<Duration>,
    pub observed_at: SystemTime,
    pub error: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
pub struct GroupProbeContext {
    pub group_id: Uuid,
    pub member_id: Uuid,
}

/// Registration and group-target identity captured before a native probe starts.
#[derive(Debug, Clone)]
pub struct ProbeTicket {
    node: Uuid,
    registration: Option<Arc<RegisteredNode>>,
    group_epoch: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupHealthObservation {
    pub group_id: Uuid,
    pub member_id: Uuid,
    pub node_id: Uuid,
    pub observation: HealthObservation,
}

pub struct UrlProbeMember {
    pub tag: String,
    pub leaf: Uuid,
    pub native: Option<GroupProbeContext>,
}

/// Healthy-only latency statistics for one retained key; absent while the key is unavailable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HealthAverages {
    /// Halving average `(prev + sample) / 2`, the formula URLTest ranks by.
    pub moving: Option<Duration>,
    /// Arithmetic mean of the newest `AVG_WINDOW` successful probes, fewer while warming up.
    pub avg10: Option<Duration>,
}

const AVG_WINDOW: usize = 10;

/// Fed only by native probe observations, never by the legacy restored/traffic collections.
#[derive(Default)]
pub(super) struct LatencyAverages {
    moving: Option<Duration>,
    recent: [Duration; AVG_WINDOW],
    count: usize,
}

impl LatencyAverages {
    fn fold(&mut self, latency: Duration) {
        self.moving = Some(self.moving.map_or(latency, |moving| (moving + latency) / 2));
        self.recent[self.count % AVG_WINDOW] = latency;
        self.count += 1;
    }

    fn report(&self) -> HealthAverages {
        let filled = self.count.min(AVG_WINDOW);
        HealthAverages {
            moving: self.moving,
            avg10: (filled > 0)
                .then(|| self.recent[..filled].iter().sum::<Duration>() / filled as u32),
        }
    }
}

pub(super) struct RetainedHealth {
    observation: HealthObservation,
    averages: LatencyAverages,
}

#[derive(Default)]
pub(super) struct HealthHistory {
    pub nodes: HashMap<Uuid, Vec<RetainedHealth>>,
    pub groups: VecDeque<GroupHealthObservation>,
    epoch: Option<Uuid>,
}

impl HealthObservation {
    pub fn probe(
        domain: ProbeDomain,
        measurement: HealthMeasurement,
        ip_version: IpVersion,
        latency: Option<Duration>,
        observed_at: SystemTime,
    ) -> Self {
        Self {
            transport: if domain == ProbeDomain::Tcp {
                HealthTransport::Tcp
            } else {
                HealthTransport::Udp
            },
            purpose: if domain == ProbeDomain::DnsUdp {
                HealthPurpose::Dns
            } else {
                HealthPurpose::Data
            },
            measurement,
            ip_version,
            warmth: if measurement == HealthMeasurement::TcpConnect {
                HealthWarmth::Cold
            } else {
                HealthWarmth::Unknown
            },
            state: if latency.is_some() {
                HealthState::Healthy
            } else {
                HealthState::Unavailable
            },
            latency,
            observed_at,
            error: latency.is_none().then_some("probe_failed"),
        }
    }

    fn same_key(&self, other: &Self) -> bool {
        self.transport == other.transport
            && self.purpose == other.purpose
            && self.measurement == other.measurement
            && self.ip_version == other.ip_version
            && self.warmth == other.warmth
    }
}

impl AliveDialerSet {
    /// Allocate retention only for an enabled native listener.
    pub fn enable_health_history(&self) {
        self.health_observations
            .write()
            .get_or_insert_with(|| HealthHistory {
                epoch: Some(Uuid::new_v4()),
                ..Default::default()
            });
    }

    pub fn probe_ticket(&self, node: Uuid) -> ProbeTicket {
        let registered = self.registered.read();
        ProbeTicket {
            node,
            registration: registered.get(&node).cloned(),
            group_epoch: self.health_epoch(),
        }
    }

    /// Retain the exact typed sample, without changing legacy liveness or latency.
    /// All native probes require the captured target epoch to remain current.
    pub fn complete_probe(
        &self,
        ticket: &ProbeTicket,
        context: Option<GroupProbeContext>,
        observation: HealthObservation,
    ) -> bool {
        let Some(epoch) = ticket.group_epoch else {
            return false;
        };
        match context {
            Some(context) => self.record_group_health_observation(
                ticket.node,
                ticket.registration.as_ref(),
                context,
                epoch,
                observation,
            ),
            None => self.retain_health_observation(
                ticket.node,
                ticket.registration.as_ref(),
                Some(epoch),
                observation,
            ),
        }
    }

    /// Read completed global checks only; custom group targets remain separate.
    pub fn health_observations(&self, node: Uuid) -> Vec<HealthObservation> {
        self.health_samples(node)
            .into_iter()
            .map(|(observation, _)| observation)
            .collect()
    }

    /// Like [`Self::health_observations`], with each key's averages while it is healthy.
    pub fn health_samples(&self, node: Uuid) -> Vec<(HealthObservation, HealthAverages)> {
        self.health_observations
            .read()
            .as_ref()
            .and_then(|observations| observations.nodes.get(&node))
            .map_or_else(Vec::new, |retained| {
                retained
                    .iter()
                    .map(|entry| {
                        let averages = if entry.observation.state == HealthState::Healthy {
                            entry.averages.report()
                        } else {
                            HealthAverages::default()
                        };
                        (entry.observation, averages)
                    })
                    .collect()
            })
    }

    pub(super) fn record_health_observation(
        &self,
        node: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        observation: HealthObservation,
    ) {
        self.retain_health_observation(node, registration, None, observation);
    }

    fn retain_health_observation(
        &self,
        node: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        required_epoch: Option<Uuid>,
        observation: HealthObservation,
    ) -> bool {
        let registered = self.registered.read();
        if !Self::same_registration(registered.get(&node), registration)
            || (registration.is_none() && node != honk_config::config::DIRECT_NODE_ID)
        {
            return false;
        }
        let mut retained = self.health_observations.write();
        let Some(retained) = retained.as_mut() else {
            return false;
        };
        if required_epoch.is_some_and(|epoch| retained.epoch != Some(epoch)) {
            return false;
        }
        // The enum-only key bounds retention independently of probe targets.
        let observations = retained.nodes.entry(node).or_default();
        if let Some(previous) = observations
            .iter_mut()
            .find(|old| old.observation.same_key(&observation))
        {
            if observation.observed_at < previous.observation.observed_at {
                return false;
            }
            // A replay at the same instant must not weigh twice.
            if observation.observed_at > previous.observation.observed_at
                && let Some(latency) = observation.latency
            {
                previous.averages.fold(latency);
            }
            previous.observation = observation;
        } else {
            let mut averages = LatencyAverages::default();
            if let Some(latency) = observation.latency {
                averages.fold(latency);
            }
            observations.push(RetainedHealth {
                observation,
                averages,
            });
        }
        true
    }

    pub fn group_health_observations(&self, group: Uuid) -> Vec<GroupHealthObservation> {
        self.health_observations
            .read()
            .as_ref()
            .map_or_else(Vec::new, |retained| {
                retained
                    .groups
                    .iter()
                    .filter(|sample| sample.group_id == group)
                    .copied()
                    .collect()
            })
    }

    pub(super) fn health_epoch(&self) -> Option<Uuid> {
        self.health_observations
            .read()
            .as_ref()
            .and_then(|retained| retained.epoch)
    }

    /// Invalidate at accepted configuration publication, before asynchronous
    /// cleanup can leave old probe targets beside the newly published catalog.
    /// Capture resumes only after `sync_group_check_urls` installs accepted targets.
    pub fn invalidate_group_health_observations(&self) {
        if let Some(retained) = self.health_observations.write().as_mut() {
            retained.epoch = None;
            retained.groups.clear();
        }
    }

    pub(super) fn reset_group_health_observations(&self) {
        if let Some(retained) = self.health_observations.write().as_mut() {
            retained.epoch = Some(Uuid::new_v4());
            retained.groups.clear();
        }
    }

    pub(super) fn advance_probe_epoch(&self) {
        if let Some(retained) = self.health_observations.write().as_mut()
            && retained.epoch.is_some()
        {
            retained.epoch = Some(Uuid::new_v4());
        }
    }

    pub(super) fn record_group_health_observation(
        &self,
        node: Uuid,
        registration: Option<&Arc<RegisteredNode>>,
        context: GroupProbeContext,
        epoch: Uuid,
        observation: HealthObservation,
    ) -> bool {
        let registered = self.registered.read();
        if !Self::same_registration(registered.get(&node), registration)
            || (registration.is_none() && node != honk_config::config::DIRECT_NODE_ID)
        {
            return false;
        }
        let mut retained = self.health_observations.write();
        let Some(retained) = retained
            .as_mut()
            .filter(|retained| retained.epoch == Some(epoch))
        else {
            return false;
        };
        let sample = GroupHealthObservation {
            group_id: context.group_id,
            member_id: context.member_id,
            node_id: node,
            observation,
        };
        // ponytail: at most 4096 fixed-size group tuples; add an index only if probe cost warrants it.
        if let Some(old) = retained.groups.iter_mut().find(|old| {
            old.group_id == context.group_id
                && old.member_id == context.member_id
                && old.observation.same_key(&observation)
        }) {
            if observation.observed_at < old.observation.observed_at {
                return false;
            }
            *old = sample;
        } else {
            if retained.groups.len() == 4096 {
                retained.groups.pop_front();
            }
            retained.groups.push_back(sample);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HealthObservation {
        HealthObservation::probe(
            ProbeDomain::DnsUdp,
            HealthMeasurement::DnsRoundTrip,
            IpVersion::V4,
            Some(Duration::from_millis(1)),
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
        )
    }

    #[test]
    fn averages_follow_healthy_probes_only() {
        let set = AliveDialerSet::new();
        let node = Uuid::from_u128(1);
        set.enable_health_history();
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        let at = |second| SystemTime::UNIX_EPOCH + Duration::from_secs(second);
        let probe = |latency: Option<u64>, second| {
            HealthObservation::probe(
                ProbeDomain::Tcp,
                HealthMeasurement::TcpConnect,
                IpVersion::V4,
                latency.map(Duration::from_millis),
                at(second),
            )
        };
        let record = |observation| {
            let ticket = set.probe_ticket(node);
            assert!(set.complete_probe(&ticket, None, observation));
        };
        let averages = || set.health_samples(node)[0].1;
        let ms = |value| Some(Duration::from_millis(value));

        record(probe(Some(100), 1));
        assert_eq!((averages().moving, averages().avg10), (ms(100), ms(100)));
        record(probe(Some(200), 2));
        assert_eq!((averages().moving, averages().avg10), (ms(150), ms(150)));

        let ticket = set.probe_ticket(node);
        assert!(set.complete_probe(&ticket, None, probe(Some(900), 2)));
        assert_eq!(averages().avg10, ms(150), "same-instant replay weighs once");
        assert!(!set.complete_probe(&ticket, None, probe(Some(900), 1)));

        record(probe(None, 3));
        assert_eq!(
            averages(),
            HealthAverages::default(),
            "unavailable hides averages"
        );
        record(probe(Some(300), 4));
        assert_eq!(
            averages().avg10,
            ms(200),
            "failure leaves the window untouched"
        );

        for second in 5..15 {
            record(probe(Some(10), second));
        }
        assert_eq!(averages().avg10, ms(10), "only the newest ten count");
    }

    #[test]
    fn native_ticket_rejects_missing_removed_and_replaced_registration() {
        let set = AliveDialerSet::new();
        let node = Uuid::from_u128(1);
        set.enable_health_history();
        let missing = set.probe_ticket(node);
        assert!(!set.complete_probe(&missing, None, sample()));
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        assert!(!set.complete_probe(&missing, None, sample()));
        let ticket = set.probe_ticket(node);
        assert!(set.complete_probe(&ticket, None, sample()));
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        let context = GroupProbeContext {
            group_id: Uuid::from_u128(2),
            member_id: node,
        };
        assert!(!set.complete_probe(&ticket, None, sample()));
        assert!(!set.complete_probe(&ticket, Some(context), sample()));
        let replacement = set.probe_ticket(node);
        assert!(set.complete_probe(&replacement, Some(context), sample()));
        set.remove_node(node);
        assert!(!set.complete_probe(&replacement, None, sample()));
        assert!(!set.complete_probe(&replacement, Some(context), sample()));
        assert!(set.health_observations(node).is_empty());
        assert!(set.group_health_observations(context.group_id).is_empty());
    }

    #[test]
    fn native_ticket_rejects_invalidated_group_epoch_and_older_samples() {
        let set = AliveDialerSet::new();
        let node = Uuid::from_u128(1);
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        let disabled = set.probe_ticket(node);
        assert!(!set.complete_probe(&disabled, None, sample()));
        set.enable_health_history();
        let context = GroupProbeContext {
            group_id: Uuid::from_u128(2),
            member_id: node,
        };
        assert!(!set.complete_probe(&disabled, Some(context), sample()));
        let ticket = set.probe_ticket(node);
        assert!(set.complete_probe(&ticket, Some(context), sample()));
        set.invalidate_group_health_observations();
        let invalidated = set.probe_ticket(node);
        assert!(!set.complete_probe(&ticket, Some(context), sample()));
        assert!(!set.complete_probe(&invalidated, Some(context), sample()));
        set.sync_group_check_urls(&[]);
        assert!(!set.complete_probe(&ticket, Some(context), sample()));
        assert!(!set.complete_probe(&invalidated, Some(context), sample()));
        assert!(set.group_health_observations(context.group_id).is_empty());
        let current = set.probe_ticket(node);
        assert!(set.complete_probe(&current, Some(context), sample()));
        assert!(set.complete_probe(&current, None, sample()));
        let older = HealthObservation {
            observed_at: SystemTime::UNIX_EPOCH,
            ..sample()
        };
        assert!(!set.complete_probe(&current, Some(context), older));
        assert!(!set.complete_probe(&current, None, older));
        assert_eq!(set.health_observations(node), [sample()]);
        assert_eq!(
            set.group_health_observations(context.group_id)[0].observation,
            sample()
        );
    }

    #[test]
    fn native_global_ticket_rejects_reloaded_targets_without_changing_periodic_writes() {
        for node in [Uuid::from_u128(1), honk_config::config::DIRECT_NODE_ID] {
            let set = AliveDialerSet::new();
            if node != honk_config::config::DIRECT_NODE_ID {
                set.register_node(node, "node".into(), "127.0.0.1:1".into());
            }
            let disabled = set.probe_ticket(node);
            set.enable_health_history();
            assert!(!set.complete_probe(&disabled, None, sample()));
            let ticket = set.probe_ticket(node);
            assert!(set.complete_probe(&ticket, None, sample()));
            set.invalidate_group_health_observations();
            let invalidated = set.probe_ticket(node);
            let newer = HealthObservation {
                observed_at: sample().observed_at + Duration::from_secs(1),
                ..sample()
            };
            assert!(!set.complete_probe(&ticket, None, newer));
            assert!(!set.complete_probe(&invalidated, None, newer));
            assert_eq!(set.health_observations(node), [sample()]);
            let registration = set.registered.read().get(&node).cloned();
            set.record_health_observation(node, registration.as_ref(), newer);
            assert_eq!(set.health_observations(node), [newer]);
            set.sync_group_check_urls(&[]);
            assert!(!set.complete_probe(&ticket, None, newer));
            assert!(!set.complete_probe(&invalidated, None, newer));
            let current = set.probe_ticket(node);
            assert!(set.complete_probe(&current, None, newer));
        }
    }

    #[test]
    fn native_completion_keeps_typed_keys_out_of_legacy_latency() {
        let set = AliveDialerSet::new();
        let node = Uuid::from_u128(1);
        set.enable_health_history();
        set.register_node(node, "node".into(), "127.0.0.1:1".into());
        let ticket = set.probe_ticket(node);
        let context = GroupProbeContext {
            group_id: Uuid::from_u128(2),
            member_id: node,
        };
        let samples = [
            sample(),
            HealthObservation {
                transport: HealthTransport::Tcp,
                ..sample()
            },
            HealthObservation {
                purpose: HealthPurpose::Data,
                ..sample()
            },
            HealthObservation {
                warmth: HealthWarmth::Warm,
                ..sample()
            },
            HealthObservation::probe(
                ProbeDomain::Tcp,
                HealthMeasurement::TcpConnect,
                IpVersion::V4,
                Some(Duration::ZERO),
                sample().observed_at,
            ),
            HealthObservation::probe(
                ProbeDomain::Tcp,
                HealthMeasurement::HttpHeaders,
                IpVersion::V4,
                Some(Duration::from_millis(2)),
                sample().observed_at,
            ),
        ];
        for observation in samples {
            assert!(set.complete_probe(&ticket, None, observation));
            assert!(set.complete_probe(&ticket, Some(context), observation));
        }
        assert_eq!(set.health_observations(node), samples);
        let retained = set.group_health_observations(context.group_id);
        assert_eq!(
            retained
                .iter()
                .map(|sample| sample.observation)
                .collect::<Vec<_>>(),
            samples
        );
        for domain in [ProbeDomain::Tcp, ProbeDomain::DnsUdp, ProbeDomain::DataUdp] {
            assert_eq!(set.get_last_latency(node, domain, IpVersion::V4), None);
        }
    }

    #[test]
    fn native_direct_completion_preserves_duplicate_member_associations() {
        let set = AliveDialerSet::new();
        set.enable_health_history();
        let node = honk_config::config::DIRECT_NODE_ID;
        let ticket = set.probe_ticket(node);
        let group_id = Uuid::from_u128(1);
        assert!(set.complete_probe(&ticket, None, sample()));
        for member_id in [Uuid::from_u128(2), Uuid::from_u128(3)] {
            let context = GroupProbeContext {
                group_id,
                member_id,
            };
            assert!(set.complete_probe(&ticket, Some(context), sample()));
        }
        let retained = set.group_health_observations(group_id);
        assert_eq!(
            retained
                .iter()
                .map(|sample| sample.member_id)
                .collect::<Vec<_>>(),
            [Uuid::from_u128(2), Uuid::from_u128(3)]
        );
        assert!(retained.iter().all(|sample| sample.node_id == node));
        let block = set.probe_ticket(honk_config::config::BLOCK_NODE_ID);
        assert!(!set.complete_probe(&block, None, sample()));
    }
}

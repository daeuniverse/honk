use std::sync::Weak;

use crate::runtime::OutboundRuntimeRegistry;
use crate::transport_quality::{TransportPressure, TransportQuality};

use super::*;

pub(in crate::group) struct TransportQualitySource {
    node_id: Uuid,
    groups: Vec<String>,
    udp_carried: bool,
    quality: Weak<TransportQuality>,
}

impl GroupManager {
    /// Bind concrete runtime owners before publishing this manager's authority.
    pub fn bind_transport_quality(&self, runtimes: &OutboundRuntimeRegistry) {
        let sources = runtimes
            .values()
            .filter_map(|runtime| {
                let groups: Vec<_> = self
                    .groups
                    .values()
                    .map(|entry| &entry.group)
                    .filter(|group| group.policy == honk_config::group::GroupPolicy::Score)
                    .filter(|group| self.group_reaches_node(&group.name, runtime.node.id))
                    .map(|group| group.name.clone())
                    .collect();
                if groups.is_empty() {
                    return None;
                }
                let quality = runtime.transport_quality();
                quality.enable();
                Some(TransportQualitySource {
                    node_id: runtime.node.id,
                    groups,
                    udp_carried: runtime.udp_capable
                        && matches!(
                            runtime.node.protocol(),
                            honk_config::types::NodeProtocol::Trojan
                                | honk_config::types::NodeProtocol::VLess
                                | honk_config::types::NodeProtocol::AnyTLS
                                | honk_config::types::NodeProtocol::Hysteria2
                                | honk_config::types::NodeProtocol::Tuic
                                | honk_config::types::NodeProtocol::Juicity
                        ),
                    quality: Arc::downgrade(&quality),
                })
            })
            .collect();
        *self.transport_quality.write() = sources;
    }

    /// Consume advisory carrier episodes without crediting or failing a flow.
    pub fn observe_transport_quality(&self) {
        let now = Instant::now();
        for source in self.transport_quality.read().iter() {
            let Some(quality) = source.quality.upgrade() else {
                continue;
            };
            let observations = quality.snapshot();
            self.score_state.observe_carrier_pressure(
                &self.score_authority,
                source.node_id,
                &source.groups,
                source.udp_carried,
                observations,
                now,
            );
        }
    }
}

impl ScorePolicyState {
    pub(super) fn observe_carrier_pressure(
        &self,
        authority: &Arc<ScoreAuthority>,
        node_id: Uuid,
        groups: &[String],
        udp_carried: bool,
        observations: [Option<TransportPressure>; 2],
        now: Instant,
    ) {
        if !observations.iter().flatten().any(|pressure| {
            pressure.observed_at <= now
                && now.duration_since(pressure.observed_at) < CARRIER_PRESSURE_TTL
        }) {
            return;
        }
        let mut inner = self.inner.lock();
        if !inner
            .active_authority
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, authority))
        {
            return;
        }
        let Some(published_at) = inner.published_at else {
            return;
        };
        for group in groups {
            if !inner.valid.contains(&(group.clone(), node_id)) {
                continue;
            }
            for network in [SelectionNetwork::Tcp, SelectionNetwork::Udp] {
                if network == SelectionNetwork::Udp && !udp_carried {
                    continue;
                }
                let key = AggregateKey {
                    group: group.clone(),
                    network,
                    family: None,
                    node_id,
                };
                let Some(stats) = inner.aggregate.peek_mut(&key) else {
                    continue;
                };
                let mut accepted = 0_u64;
                let mut rtt_episodes = 0_u64;
                let mut loss_episodes = 0_u64;
                for (family, observation) in observations.iter().enumerate() {
                    let Some(observation) = observation else {
                        continue;
                    };
                    let at = observation.observed_at;
                    if at <= published_at
                        || at > now
                        || now.duration_since(at) >= CARRIER_PRESSURE_TTL
                        || stats.carrier_pressure[family]
                            .is_some_and(|previous| previous.observed_at >= at)
                    {
                        continue;
                    }
                    stats.carrier_pressure[family] = Some(*observation);
                    accepted += 1;
                    match observation.reason {
                        crate::transport_quality::PressureReason::Rtt => rtt_episodes += 1,
                        crate::transport_quality::PressureReason::Loss => loss_episodes += 1,
                        crate::transport_quality::PressureReason::Both => {
                            rtt_episodes += 1;
                            loss_episodes += 1;
                        }
                    }
                }
                if accepted != 0 {
                    let counts = inner
                        .selection_reasons
                        .entry(SelectionReasonKey::new(group, network))
                        .or_default();
                    counts.carrier_pressure = counts.carrier_pressure.saturating_add(accepted);
                    counts.carrier_rtt_pressure =
                        counts.carrier_rtt_pressure.saturating_add(rtt_episodes);
                    counts.carrier_loss_pressure =
                        counts.carrier_loss_pressure.saturating_add(loss_episodes);
                }
            }
        }
    }
}

use std::net::IpAddr;
use std::sync::Arc;

use honk_ebpf_common::DomainRouting;
use honk_outbound::alive::IpVersion;
use tokio::time::Instant;

use super::{DesiredState, GatewayDnsBank, PacketDomainBitmap, QueryScope, RoutingProjection};

#[derive(Clone, Copy)]
pub(crate) struct GatewayDnsFill {
    pub(crate) query: QueryScope,
    pub(crate) realm: u32,
    pub(crate) epoch: u64,
    ip: IpAddr,
    bitmap: DomainRouting,
    expires_at: Instant,
}

impl DesiredState {
    fn gateway_fill(
        &self,
        query: QueryScope,
        (realm, epoch): (u32, u64),
        ip: IpAddr,
        now: Instant,
    ) -> Option<GatewayDnsFill> {
        let (bitmap, expires_at) = self.gateway_fact(query.fact_scope, ip, now)?;
        Some(GatewayDnsFill {
            query,
            realm,
            epoch,
            ip,
            bitmap,
            expires_at,
        })
    }

    pub(super) fn gateway_packet_fill(
        &self,
        query: QueryScope,
        ip: IpAddr,
        bitmap: Option<DomainRouting>,
    ) -> Option<(Arc<GatewayDnsBank>, GatewayDnsFill)> {
        let bank = self.gateway_bank()?;
        let scope = query.fact_scope;
        let (realm, epoch) = bank.ticket(scope)?;
        let key = super::state::ProjectionIp::new(scope, ip);
        let fact = bitmap.and_then(|bitmap| {
            self.gateway_expiry(key, bitmap, Instant::now())
                .map(|expires_at| GatewayDnsFill {
                    query,
                    realm,
                    epoch,
                    ip,
                    bitmap,
                    expires_at,
                })
        });
        match fact {
            Some(fill) => Some((Arc::clone(bank), fill)),
            None => {
                bank.skip(1);
                None
            }
        }
    }

    pub(super) fn gateway_answer_fills(
        &self,
        query: QueryScope,
        domain: &str,
        family: IpVersion,
        now: Instant,
    ) -> Option<(Arc<GatewayDnsBank>, [Option<GatewayDnsFill>; 16])> {
        let bank = self.gateway_bank()?;
        let scope = query.fact_scope;
        let ticket = bank.ticket(scope)?;
        let owner = self.owners[family as usize]
            .get(&scope.as_u64())?
            .get(domain)?;
        let mut ips = owner.ips.iter();
        let mut accepted = 0;
        let rows = std::array::from_fn(|_| {
            let fill = self.gateway_fill(query, ticket, *ips.next()?, now)?;
            accepted += 1;
            Some(fill)
        });
        if owner.ips.len() > accepted {
            bank.skip(owner.ips.len() - accepted);
        }
        (accepted != 0).then(|| (Arc::clone(bank), rows))
    }

    fn gateway_query_is_current(&self, bank: &Arc<GatewayDnsBank>, query: QueryScope) -> bool {
        self.gateway_bank()
            .is_some_and(|active| Arc::ptr_eq(active, bank))
            && self.query_scope_is_current(query)
    }
}

impl RoutingProjection {
    pub(crate) fn activate_gateway_dns(
        &self,
        bank: Option<Arc<GatewayDnsBank>>,
        generation: u64,
        allowed: impl FnOnce() -> bool,
    ) -> bool {
        let mut state = self.state.lock();
        if state.snapshot.generation() != generation {
            return false;
        }
        let retired = state.close_gateway_dns();
        let bound = state.bind_gateway_dns(bank.as_ref(), allowed);
        drop(state);
        drop(retired);
        self.notify_worker();
        bound
    }

    pub(crate) fn close_gateway_dns(&self) -> Option<(Arc<GatewayDnsBank>, u64)> {
        let mut state = self.state.lock();
        let generation = state.snapshot.generation();
        state.close_gateway_dns().map(|bank| (bank, generation))
    }

    pub(crate) fn hot_fill_packet_domain(&self, facts: PacketDomainBitmap) {
        let Some((bank, fill)) = facts.fill else {
            return;
        };
        let queued = if fill.query.is_shared_host() {
            self.state.try_lock().is_some_and(|state| {
                state.gateway_query_is_current(&bank, fill.query) && bank.queue_fill(fill)
            })
        } else {
            bank.queue_fill(fill)
        };
        if queued {
            self.notify_worker();
        } else {
            bank.skip(1);
        }
    }

    pub(super) fn write_gateway_dns(&self, bank: &Arc<GatewayDnsBank>, fill: GatewayDnsFill) {
        // A surviving port keeps the bank epoch, so Host writes need the source
        // fence through the actual insertion as well as through queue admission.
        let host_state = if fill.query.is_shared_host() {
            let state = self.state.lock();
            if !state.gateway_query_is_current(bank, fill.query) {
                bank.skip(1);
                return;
            }
            Some(state)
        } else {
            None
        };
        if bank.insert(
            fill.realm,
            fill.epoch,
            fill.ip,
            fill.bitmap,
            fill.expires_at,
        ) {
            let renew = |state: &DesiredState| {
                state
                    .gateway_bank()
                    .filter(|active| Arc::ptr_eq(bank, active))
                    .and_then(|_| {
                        state.gateway_fact(fill.query.fact_scope, fill.ip, Instant::now())
                    })
                    .and_then(|(bitmap, until)| {
                        bank.renew(fill.realm, fill.epoch)
                            .map(|epoch| (epoch, bitmap, until))
                    })
            };
            let renewed = match host_state.as_deref() {
                Some(state) => renew(state),
                None => renew(&self.state.lock()),
            };
            if let Some((epoch, bitmap, until)) = renewed {
                bank.insert(fill.realm, epoch, fill.ip, bitmap, until);
            }
        }
        drop(host_state);
        if bank.needs_reclaim() {
            self.notify_worker();
        }
    }
}

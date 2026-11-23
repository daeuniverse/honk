use std::net::IpAddr;
use std::sync::Arc;

use honk_datapath::ScopeId;
use honk_ebpf_common::DomainRouting;
use honk_outbound::alive::IpVersion;
use tokio::time::Instant;

use super::{DesiredState, GatewayDnsBank, PacketDomainBitmap, RoutingProjection};

#[derive(Clone, Copy)]
pub(crate) struct GatewayDnsFill {
    scope: ScopeId,
    pub(crate) realm: u32,
    pub(crate) epoch: u64,
    ip: IpAddr,
    bitmap: DomainRouting,
    expires_at: Instant,
}

impl DesiredState {
    fn gateway_fill(
        &self,
        scope: ScopeId,
        (realm, epoch): (u32, u64),
        ip: IpAddr,
        now: Instant,
    ) -> Option<GatewayDnsFill> {
        let (bitmap, expires_at) = self.gateway_fact(scope, ip, now)?;
        Some(GatewayDnsFill {
            scope,
            realm,
            epoch,
            ip,
            bitmap,
            expires_at,
        })
    }

    pub(super) fn gateway_packet_fill(
        &self,
        scope: ScopeId,
        ip: IpAddr,
        bitmap: Option<DomainRouting>,
    ) -> Option<(Arc<GatewayDnsBank>, GatewayDnsFill)> {
        let bank = self.gateway_bank()?;
        let (realm, epoch) = bank.ticket(scope)?;
        let key = super::state::ProjectionIp::new(scope, ip);
        let fact = bitmap.and_then(|bitmap| {
            self.gateway_expiry(key, bitmap, Instant::now())
                .map(|expires_at| GatewayDnsFill {
                    scope,
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
        scope: ScopeId,
        domain: &str,
        family: IpVersion,
        now: Instant,
    ) -> Option<(Arc<GatewayDnsBank>, [Option<GatewayDnsFill>; 16])> {
        let bank = self.gateway_bank()?;
        let ticket = bank.ticket(scope)?;
        let owner = self.owners[family as usize]
            .get(&scope.as_u64())?
            .get(domain)?;
        let mut ips = owner.ips.iter();
        let mut accepted = 0;
        let rows = std::array::from_fn(|_| {
            let fill = self.gateway_fill(scope, ticket, *ips.next()?, now)?;
            accepted += 1;
            Some(fill)
        });
        if owner.ips.len() > accepted {
            bank.skip(owner.ips.len() - accepted);
        }
        (accepted != 0).then(|| (Arc::clone(bank), rows))
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
        if bank.queue_fill(fill) {
            self.notify_worker();
        } else {
            bank.skip(1);
        }
    }

    pub(super) fn write_gateway_dns(&self, bank: &Arc<GatewayDnsBank>, fill: GatewayDnsFill) {
        if bank.insert(
            fill.realm,
            fill.epoch,
            fill.ip,
            fill.bitmap,
            fill.expires_at,
        ) {
            let renewed = {
                let state = self.state.lock();
                state
                    .gateway_bank()
                    .filter(|active| Arc::ptr_eq(bank, active))
                    .and_then(|_| state.gateway_fact(fill.scope, fill.ip, Instant::now()))
                    .and_then(|(bitmap, until)| {
                        bank.renew(fill.realm, fill.epoch)
                            .map(|epoch| (epoch, bitmap, until))
                    })
            };
            if let Some((epoch, bitmap, until)) = renewed {
                bank.insert(fill.realm, epoch, fill.ip, bitmap, until);
            }
        }
        if bank.needs_reclaim() {
            self.notify_worker();
        }
    }
}

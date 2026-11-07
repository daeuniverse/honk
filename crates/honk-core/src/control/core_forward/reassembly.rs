//! Reassembly timeout control output on the same Core/FIB/policy owner.

use super::{
    Disposition, FirewallVerdict, PolicyGeneration, PolicyRead, Resolution, RoutedCore,
    disposition, mode_decision, route_action,
};
use honk_datapath::{
    firewall::{FragmentLease, Tuple},
    forward::{Ingress, Route, RouteQuery},
};
use honk_netstack::{
    MemoryBudget, MemoryReservation, OwnedPacket,
    transit::{self, Quote},
};
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

pub(super) struct Outputs {
    pending: AtomicUsize,
    _charge: MemoryReservation,
}
impl Outputs {
    pub(super) fn new(budget: &Arc<MemoryBudget>) -> anyhow::Result<Arc<Self>> {
        let charge = budget
            .reserve(size_of::<Self>() + 32)
            .ok_or_else(|| anyhow::anyhow!("reassembly output accounting budget exhausted"))?;
        Ok(Arc::new(Self {
            pending: AtomicUsize::new(0),
            _charge: charge,
        }))
    }
    pub(super) fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }
    fn begin(&self) -> anyhow::Result<()> {
        self.pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("reassembly output ownership exhausted"))?;
        Ok(())
    }
    fn finish(&self) {
        let previous = self.pending.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous != 0, "reassembly output ownership underflow");
    }
}

pub(super) struct Pending {
    ingress: Ingress,
    quote: OwnedPacket,
    deadline: Instant,
    retry_at: Instant,
    fragment: Option<FragmentLease>,
}

/// `out[..len]` was materialized by poll_reassembly_error. Keep its funded byte storage
/// separately until submission, and retain this owner through actual CQ or explicit disposal.
/// The quote/output obligation prevents NAT alias reclamation while this owner is live.
pub struct GeneratedError {
    pub ingress: Ingress,
    pub route: Route,
    pub generation: PolicyGeneration,
    pub len: usize,
    _quote: OwnedPacket,
    _fragment: Option<FragmentLease>,
    outputs: Arc<Outputs>,
}
impl Drop for GeneratedError {
    fn drop(&mut self) {
        self.outputs.finish();
    }
}

impl RoutedCore {
    /// The same clock as receive/retire; a pending neighbor quote keeps its original deadline.
    pub fn poll_reassembly_timeout(&self, now: Instant) -> Option<Instant> {
        let output = match &self.pending_reassembly_error {
            Some(pending) => Some(pending.retry_at.min(pending.deadline)),
            None => self.reassembly_poll_pending.then_some(now),
        };
        self.core
            .poll_reassembly_timeout()
            .into_iter()
            .chain(output)
            .min()
    }

    /// Requires funded control-output storage of at least 1280 bytes. Suppressed/denied
    /// quotes are retired in bounded batches; one unresolved neighbor quote may wait for
    /// two seconds, never renewing its deadline. No conntrack grant is inferred from a quote.
    /// Synchronous under readers of this core's own registration.
    pub fn poll_reassembly_error(
        &mut self,
        read: &PolicyRead<'_>,
        now: Instant,
        out: &mut [u8],
    ) -> anyhow::Result<Option<GeneratedError>> {
        self.check_policy(read)?;
        anyhow::ensure!(
            out.len() >= 1280,
            "reassembly error output requires 1280 bytes"
        );
        let now = now.max(Instant::now());
        self.retire(now);
        self.reassembly_poll_pending = true;
        for _ in 0..64 {
            let pending = match self.pending_reassembly_error.take() {
                Some(pending) => pending,
                None => {
                    let Some((ingress, quote)) = self.core.poll_expired_quote() else {
                        self.reassembly_poll_pending = false;
                        return Ok(None);
                    };
                    let fragment = match transit::quote_metadata(&quote) {
                        Some(metadata) => {
                            match self.firewall.retain_fragment(
                                honk_datapath::forward::FragmentObligation {
                                    ingress,
                                    source: metadata.source,
                                    destination: metadata.destination,
                                    protocol: metadata.protocol,
                                },
                            ) {
                                Ok(fragment) => fragment,
                                Err(error) => {
                                    self.counters.nat(&error);
                                    continue;
                                }
                            }
                        }
                        _ => None,
                    };
                    Pending {
                        fragment,
                        ingress,
                        quote,
                        deadline: now + Duration::from_secs(2),
                        retry_at: now,
                    }
                }
            };
            if !self.authority.admitting() || Instant::now() >= pending.deadline {
                continue;
            }
            if now < pending.retry_at {
                self.pending_reassembly_error = Some(pending);
                return Ok(None);
            }
            let Some(metadata) = transit::quote_metadata(&pending.quote) else {
                continue;
            };
            let Some(query) = timeout_query(pending.ingress, metadata) else {
                continue;
            };
            let generation = {
                let router = &*read.router;
                let config = &*read.config;
                let mode_state = self
                    .authority
                    .0
                    .mode_state
                    .as_ref()
                    .map(|state| state.read());
                let mut generation = self.authority.generation(mode_state.as_deref());
                let bitmap = if router.domain_predicate_count() != 0 {
                    let mut facts = self.authority.0.projection.packet_facts();
                    let Ok((bitmap, stamp)) = self.read_facts(
                        &mut facts,
                        router,
                        pending.ingress,
                        metadata.destination,
                        generation.routing,
                    ) else {
                        continue;
                    };
                    generation.facts = Some(stamp);
                    bitmap
                } else {
                    None
                };
                let Some(action) = route_action(router, query, None, bitmap.as_ref()) else {
                    continue;
                };
                let mode = mode_decision(
                    mode_state.as_deref(),
                    config,
                    #[cfg(feature = "native-api")]
                    self.authority
                        .0
                        .native
                        .as_ref()
                        .map(|native| native.catalog.snapshot())
                        .as_deref(),
                    action.outbound.clone(),
                    action.must,
                );
                let marked =
                    action.outbound == "direct" && mode.name == "direct" && action.mark.is_some();
                if disposition(
                    &mode.name,
                    action.must,
                    marked,
                    query,
                    self.authority.0.execution,
                    self.core.retains(query, now),
                ) != Disposition::Core
                {
                    continue;
                }
                if let Some(policy) = router.firewall_policy() {
                    let (Some((source_port, destination_port)), Some(binding)) = (
                        metadata.ports,
                        self.ingress_bindings
                            .iter()
                            .find(|binding| binding.ingress == pending.ingress),
                    ) else {
                        continue;
                    };
                    let tuple = Tuple {
                        source: metadata.source,
                        destination: metadata.destination,
                        protocol: metadata.protocol,
                        source_port,
                        destination_port,
                    };
                    if policy.original(tuple, metadata.traffic_class, binding.role)
                        != FirewallVerdict::Allow
                    {
                        continue;
                    }
                }
                generation
            };
            if !self.fib.current(self.fib.generation())? {
                self.routes.clear();
                self.fib.synchronize()?;
            }
            // Input route proof also rejects directed broadcast/local input and validates
            // the real source/interface context; output lookup alone is not that proof.
            match self.fib.lookup(query) {
                Ok(Resolution::Forward(_) | Resolution::NeighborPending(_)) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_reassembly_neighbor(pending);
                    return Ok(None);
                }
                Ok(_) => continue,
                Err(error) => return Err(error.into()),
            }
            let route = match self.fib.lookup_error(query) {
                Ok(Resolution::Forward(route)) => route,
                Ok(Resolution::NeighborPending(_)) => {
                    self.wait_reassembly_neighbor(pending);
                    return Ok(None);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_reassembly_neighbor(pending);
                    return Ok(None);
                }
                Ok(_) => continue,
                Err(error) => return Err(error.into()),
            };
            if !self.fib.current(route.generation)? {
                self.wait_reassembly_neighbor(pending);
                return Ok(None);
            }
            let Some(source) = self.fib.error_source(route) else {
                continue;
            };
            let limit = out.len().min(route.mtu as usize);
            let overhead = if source.is_ipv4() { 28 } else { 48 };
            if limit < overhead + metadata.header_len + 8 {
                continue;
            }
            let emitted_at = Instant::now();
            if emitted_at >= pending.deadline || !self.authority.admitting() {
                continue;
            }
            let Some(len) = self.core.reassembly_error(
                pending.ingress,
                emitted_at,
                source,
                &pending.quote,
                &mut out[..limit],
            )?
            else {
                continue;
            };
            self.reassembly_outputs.begin()?;
            return Ok(Some(GeneratedError {
                ingress: pending.ingress,
                route,
                generation,
                len,
                _quote: pending.quote,
                _fragment: pending.fragment,
                outputs: Arc::clone(&self.reassembly_outputs),
            }));
        }
        Ok(None)
    }

    fn wait_reassembly_neighbor(&mut self, mut pending: Pending) {
        let now = Instant::now();
        if now < pending.deadline {
            // ponytail: one funded control wait; separate neighbors only if HOL matters.
            pending.retry_at = now + Duration::from_millis(10);
            self.pending_reassembly_error = Some(pending);
        }
    }
}

fn timeout_query(ingress: Ingress, quote: Quote) -> Option<RouteQuery> {
    if !transit::unicast(quote.source) || !transit::unicast(quote.destination) {
        return None;
    }
    Some(RouteQuery {
        ingress,
        source: quote.source,
        destination: quote.destination,
        traffic_class: quote.traffic_class,
        protocol: quote.protocol,
        ports: quote.ports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reassembly_wait_uses_actual_expiry_then_quote_retry_and_bounded_drain() {
        use honk_netstack::wire;
        use std::os::fd::AsFd;
        let mut config = honk_config::Config::default();
        config.ensure_builtin_nodes();
        config.global.dial_mode = "ip".into();
        config.routing.default_outbound = "block".into();
        let router = crate::routing::Router::from_config(&config.routing).unwrap();
        let plane = crate::control::tests::support::control_plane(config);
        *plane.router.write().await = router;
        let authority = plane
            .core_forward_policy(super::super::Execution::MixedEndpoints)
            .await
            .unwrap();
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        let ingress = Ingress {
            scope: honk_datapath::ScopeId::allocate().unwrap(),
            namespace: super::super::socket_namespace(socket.as_fd()).unwrap(),
            ifindex: 2,
            attachment: 1,
            mark: honk_datapath::forward::MarkProvenance::BeforeSkb,
        };
        // Five quote queues retain 65 outputs, but the shared 64-entry admission needs two expiry waves.
        let inputs: [Ingress; 5] = std::array::from_fn(|index| Ingress {
            ifindex: 2 + index as u32,
            ..ingress
        });
        let budget = MemoryBudget::new(16 << 20);
        let mut core = super::super::tests::unsynchronized_core(authority, &inputs, &budget, None);
        let authority = core.authority();
        let start = Instant::now() - Duration::from_secs(62);
        let mut bytes = [0; 60];
        wire::udp::emit_packet(
            &mut bytes,
            "192.0.2.1:40000".parse().unwrap(),
            "198.51.100.1:41000".parse().unwrap(),
            &[7; 32],
        )
        .unwrap();
        bytes[2..4].copy_from_slice(&36u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        for id in 0..65u16 {
            if id == 64 {
                assert_eq!(
                    core.poll_reassembly_timeout(start),
                    Some(start + Duration::from_secs(30))
                );
                core.retire(start + Duration::from_secs(30));
            }
            bytes[4..6].copy_from_slice(&id.to_be_bytes());
            bytes[10..12].fill(0);
            let checksum = wire::checksum::checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
            let input = inputs[usize::from(id % 5)];
            let received = start + Duration::from_secs(if id == 64 { 31 } else { 0 });
            assert!(
                core.receive(input, received, &bytes[..36])
                    .unwrap()
                    .is_none()
            );
        }
        let now = Instant::now();
        core.retire(now);
        assert_eq!(core.poll_reassembly_timeout(now), Some(now));
        let (input, quote) = core.core.poll_expired_quote().unwrap();
        let deadline = now + Duration::from_secs(120);
        core.wait_reassembly_neighbor(Pending {
            ingress: input,
            quote,
            deadline,
            retry_at: now,
            fragment: None,
        });
        let pending = core.pending_reassembly_error.as_mut().unwrap();
        assert_eq!(pending.deadline, deadline);
        assert!(pending.retry_at > now);
        // Keep wall-clock scheduling out of the retry test; the absolute expiry is unchanged.
        pending.retry_at = now + Duration::from_secs(60);
        let retry = pending.retry_at;
        assert_eq!(core.poll_reassembly_timeout(now), Some(retry));
        let mut output = [0; 1280];
        assert!(
            core.poll_reassembly_error(&authority.read_policy().await, now, &mut output)
                .unwrap()
                .is_none()
        );
        assert_eq!(core.poll_reassembly_timeout(now), Some(retry));
        let pending = core.pending_reassembly_error.as_mut().unwrap();
        pending.retry_at = deadline + Duration::from_secs(1);
        assert_eq!(core.poll_reassembly_timeout(now), Some(deadline));
        core.pending_reassembly_error.as_mut().unwrap().deadline = now - Duration::from_nanos(1);
        assert!(
            core.poll_reassembly_error(&authority.read_policy().await, now, &mut output)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            core.poll_reassembly_timeout(now),
            Some(now),
            "64 disposals must leave the remaining quote runnable"
        );
        assert!(
            core.poll_reassembly_error(&authority.read_policy().await, now, &mut output)
                .unwrap()
                .is_none()
        );
        assert_eq!(core.poll_reassembly_timeout(now), None);
        assert!(core.fragments_quiescent());
    }

    #[test]
    fn timeout_query_uses_retained_first_fragment_context_in_both_families() {
        use honk_netstack::wire;
        let ingress = Ingress {
            scope: honk_datapath::ScopeId::HOST,
            namespace: 19,
            ifindex: 7,
            attachment: 13,
            mark: honk_datapath::forward::MarkProvenance::BeforeSkb,
        };
        for ipv6 in [false, true] {
            let source = if ipv6 {
                "[fd00::1]:40000"
            } else {
                "192.0.2.1:40000"
            }
            .parse()
            .unwrap();
            let destination = if ipv6 {
                "[fd00::2]:41000"
            } else {
                "192.0.2.2:41000"
            }
            .parse()
            .unwrap();
            let mut whole = [0; 128];
            wire::udp::emit_packet(&mut whole, source, destination, &[0x5a; 32]).unwrap();
            let quote = if ipv6 {
                let mut fragment = whole[..40].to_vec();
                fragment[0] = 0x6b;
                fragment[1] = 0x80;
                fragment[6] = 44;
                fragment[4..6].copy_from_slice(&32u16.to_be_bytes());
                fragment.extend_from_slice(&[17, 0, 0, 1, 0, 0, 0, 9]);
                fragment.extend_from_slice(&whole[40..60]);
                fragment
            } else {
                let mut fragment = whole[..40].to_vec();
                fragment[1] = 0xb8;
                fragment[2..4].copy_from_slice(&44u16.to_be_bytes());
                fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
                fragment[10..12].fill(0);
                let checksum = wire::checksum::checksum(&fragment[..20]);
                fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
                fragment
            };
            let metadata = transit::quote_metadata(&quote).unwrap();
            assert_eq!(metadata.header_len, if ipv6 { 48 } else { 20 });
            let query = timeout_query(ingress, metadata).unwrap();
            assert_eq!(query.ingress, ingress);
            assert_eq!(
                (query.source, query.destination),
                (source.ip(), destination.ip())
            );
            assert_eq!(
                (query.traffic_class, query.protocol, query.ports),
                (0xb8, 17, Some((40000, 41000)))
            );
        }
    }

    #[test]
    fn timeout_quote_never_turns_missing_tcp_flags_into_zero() {
        use honk_netstack::{FragmentLimits, wire};
        let now = Instant::now();
        let source = "192.0.2.1".parse().unwrap();
        let destination = "192.0.2.2".parse().unwrap();
        let mut whole = [0; 44];
        wire::emit_ip_header(&mut whole, source, destination, 6, 24).unwrap();
        whole[20..22].copy_from_slice(&40000u16.to_be_bytes());
        whole[22..24].copy_from_slice(&41000u16.to_be_bytes());
        whole[32] = 0x50;
        whole[33] = 4;
        let mut checksum = wire::checksum::Checksum::pseudo(source, destination, 6, 24);
        checksum.add(&whole[20..]);
        whole[36..38].copy_from_slice(&checksum.finish().to_be_bytes());
        assert!(
            transit::quote_metadata(&whole).is_none(),
            "known RST must not elicit a refusal"
        );
        whole[33] = 2;
        assert!(
            transit::quote_metadata(&whole[..28]).is_none(),
            "missing flags are unknown, not non-RST"
        );
        let fragment = |offset: usize, more: bool| {
            let mut bytes = whole[..20].to_vec();
            bytes.extend_from_slice(&whole[20 + offset..28 + offset]);
            bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
            bytes[6..8].copy_from_slice(
                &((offset / 8) as u16 | if more { 0x2000 } else { 0 }).to_be_bytes(),
            );
            bytes[10..12].fill(0);
            let checksum = wire::checksum::checksum(&bytes[..20]);
            bytes[10..12].copy_from_slice(&checksum.to_be_bytes());
            bytes
        };
        let budget = MemoryBudget::new(1 << 20);
        let mut reassembly =
            transit::Transit::new(budget.clone(), FragmentLimits::default()).unwrap();
        assert!(
            reassembly
                .reassemble(now, &fragment(0, true))
                .unwrap()
                .is_none()
        );
        assert!(
            reassembly
                .reassemble(now, &fragment(16, false))
                .unwrap()
                .is_none()
        );
        reassembly.expire(now + Duration::from_secs(31));
        let quote = reassembly.poll_expired_quote().unwrap();
        assert_eq!(
            quote.len(),
            28,
            "do not quote zero-filled bytes from the hole at offset8"
        );
        assert!(transit::quote_metadata(&quote).is_none());
        drop(reassembly);
        assert!(budget.used() > 0);
        drop(quote);
        assert_eq!(budget.used(), 0);
    }
}

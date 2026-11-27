use super::*;

/// Checksum provenance and admission for one ingress packet.
pub struct ReceiveOptions<'a> {
    ingress_at: Instant,
    meta: RxMeta,
    context: Option<SourceContext>,
    service_at: Option<Instant>,
    on_half_open: Option<&'a mut dyn FnMut(IpAddr) -> bool>,
}

impl<'a> ReceiveOptions<'a> {
    pub fn new(ingress_at: Instant, meta: RxMeta) -> Self {
        Self {
            ingress_at,
            meta,
            context: None,
            service_at: None,
            on_half_open: None,
        }
    }

    /// Requires source storage funded by [`Stack::prepare_source_context`].
    pub fn with_context(mut self, context: SourceContext) -> Self {
        self.context = Some(context);
        self
    }

    /// The realm services timers at `service_at` and reserves each new half-open before admission.
    pub fn with_realm(
        mut self,
        service_at: Instant,
        on_half_open: &'a mut dyn FnMut(IpAddr) -> bool,
    ) -> Self {
        self.service_at = Some(service_at);
        self.on_half_open = Some(on_half_open);
        self
    }
}

pub(crate) struct SourceReport<'a, F> {
    source: Option<ValidatedSource>,
    pub(crate) context: Option<SourceContext>,
    source_context: Option<SourceContext>,
    pub(crate) outcome: ReceiveOutcome,
    accept: F,
    pub(crate) half_open: Option<&'a mut dyn FnMut(IpAddr) -> bool>,
    service_at: Option<Instant>,
}

impl<F: FnMut(ValidatedSource, Option<SourceContext>) -> bool> SourceReport<'_, F> {
    fn new(context: Option<SourceContext>, accept: F) -> Self {
        Self {
            source: None,
            context,
            source_context: None,
            outcome: ReceiveOutcome::Unqualified,
            accept,
            half_open: None,
            service_at: None,
        }
    }

    pub(crate) fn record<const REPORT: bool>(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        protocol: u8,
        tcp_flags: Option<u8>,
    ) -> bool {
        if REPORT {
            let source = ValidatedSource {
                src,
                dst,
                protocol,
                tcp_flags,
            };
            self.source = Some(source);
            self.source_context = self.context;
            (self.accept)(source, self.context)
        } else {
            true
        }
    }
}

impl Stack {
    /// Funds fixed contextual flow storage before input, without changing ordinary stacks.
    /// Requires a shared budget and an empty, quiescent table. Unbounded embeddings opt in
    /// to `Config::max_flows` as their slab-slot ceiling; accounted stacks keep their ceiling.
    pub fn prepare_source_context(&mut self) -> Result<(), ConstructionError> {
        let budget = self
            .cfg
            .shared_budget
            .as_ref()
            .ok_or(ConstructionError::MissingBudget)?;
        if !self.is_quiescent() {
            return Err(ConstructionError::InUse);
        }
        self.table
            .prepare_sources(self.cfg.max_flows as usize, budget)
    }

    /// Receives one IP packet with verified checksums and reporting disabled.
    pub fn receive(&mut self, now: Instant, packet: &[u8]) -> Rx {
        self.now = now;
        self.counters.rx_packets += 1;
        self.receive_packet::<false>(
            now,
            packet,
            RxMeta::VERIFY,
            &mut SourceReport::new(None, |_, _| true),
        )
    }

    /// Reports verified source facts before protocol mutation and the resulting TCP/UDP outcome.
    /// A refused source still has a receipt. Reassembled packets and existing TCP flows carry
    /// their original source context. Only transparent stacks accept driver checksum metadata.
    pub fn receive_reported(
        &mut self,
        packet: &[u8],
        options: ReceiveOptions<'_>,
        on_source: impl FnMut(ValidatedSource, Option<SourceContext>) -> bool,
    ) -> (Rx, ReceiveReport) {
        if options.context.is_some() && !self.table.has_sources() {
            return (
                self.drop_packet(DropReason::Capacity),
                ReceiveReport::default(),
            );
        }
        self.now = options.ingress_at;
        self.counters.rx_packets += 1;
        let mut report = SourceReport::new(options.context, on_source);
        report.half_open = options.on_half_open;
        report.service_at = options.service_at;
        let rx = self.receive_packet::<true>(options.ingress_at, packet, options.meta, &mut report);
        if let Some(service_at) = options.service_at {
            self.now = service_at;
        }
        (
            rx,
            ReceiveReport {
                source: report.source,
                source_context: report.source_context,
                outcome: report.outcome,
            },
        )
    }

    /// Established physical TCP receive with a source gate that can defer to ordinary RX.
    /// Reassembly may already hold fragment state when the gate runs. `Err` leaves a complete
    /// TCP input and its accounting untouched, and applies only to stacks without source context.
    pub fn try_receive_realm_tcp<E>(
        &mut self,
        ingress_at: Instant,
        service_at: Instant,
        packet: &[u8],
        mut on_source: impl FnMut(ValidatedSource) -> Result<bool, E>,
    ) -> Result<ReceiveReport, E> {
        let now = self.now;
        let mut deferred = None;
        let (rx, report) = self.receive_reported(
            packet,
            ReceiveOptions::new(ingress_at, RxMeta::VERIFY).with_realm(service_at, &mut |_| false),
            |source, _| {
                on_source(source).unwrap_or_else(|reason| {
                    deferred = Some(reason);
                    false
                })
            },
        );
        if let Some(reason) = deferred
            && matches!(rx, Rx::Dropped(DropReason::NotForUs))
            && !self.table.has_sources()
            && wire::parse_ip(packet).is_ok_and(|ip| ip.proto == wire::PROTO_TCP)
        {
            // Complete TCP source refusal precedes all protocol state mutation.
            self.now = now;
            self.counters.rx_packets -= 1;
            self.counters.drops[DropReason::NotForUs as usize] -= 1;
            return Err(reason);
        }
        Ok(report)
    }

    /// Owner zero reassembles before selecting the completed datagram's transport owner.
    /// Complete bytes remain charged; this method never mutates TCP or UDP state.
    pub fn reassemble_for_dispatch(
        &mut self,
        ingress_at: Instant,
        service_at: Instant,
        packet: &[u8],
    ) -> Result<crate::ReassemblyReport, crate::FragmentError> {
        if !self.transparent() {
            return Err(DropReason::Fragment.into());
        }
        if self
            .shard
            .as_ref()
            .is_some_and(|shard| !shard.reassembly_owner)
        {
            return Err(DropReason::Fragment.into());
        }
        let fragment = wire::frag::parse(packet).map_err(DropReason::from)?;
        if let Some(reason) = self.refuses(fragment.src, fragment.dst) {
            return Err(reason.into());
        }
        self.reasm
            .push_for_dispatch_at(ingress_at, service_at, fragment)
    }

    fn receive_packet<const REPORT: bool>(
        &mut self,
        now: Instant,
        packet: &[u8],
        meta: RxMeta,
        report: &mut SourceReport<'_, impl FnMut(ValidatedSource, Option<SourceContext>) -> bool>,
    ) -> Rx {
        if meta != RxMeta::VERIFY && !self.transparent() {
            return self.drop_packet(DropReason::Unsupported);
        }
        let ip = match wire::parse_ip(packet) {
            Ok(ip) => ip,
            Err(ParseError::Fragment) if self.transparent() => {
                if self
                    .shard
                    .as_ref()
                    .is_some_and(|shard| !shard.reassembly_owner)
                {
                    return self.drop_packet(DropReason::Fragment);
                }
                if meta.gso.is_some() {
                    return self.drop_packet(DropReason::Malformed);
                }
                let fragment = match wire::frag::parse(packet) {
                    Ok(fragment) => fragment,
                    Err(e) => return self.drop_packet(e.into()),
                };
                if let Some(reason) = self.refuses(fragment.src, fragment.dst) {
                    return self.drop_packet(reason);
                }
                let pushed = match report.service_at {
                    Some(service_at) => {
                        self.reasm
                            .push_at(now, service_at, fragment, report.context)
                    }
                    None => self.reasm.push(now, fragment, report.context),
                };
                return match pushed {
                    Push::Pending(_) => Rx::Consumed,
                    Push::Dropped(reason) => self.drop_packet(reason),
                    // The whole datagram goes through the normal checks, destination included,
                    // and its checksum is verified: no fragment's metadata vouches for the rest.
                    Push::Complete(r) => {
                        report.context = r.source;
                        let now = r.packet.completion_ingress();
                        self.now = now;
                        let rx = match wire::parse_ip(&r.packet) {
                            Ok(ip) => self.receive_ip::<REPORT>(
                                now,
                                ip,
                                &r.packet,
                                RxMeta::VERIFY,
                                report,
                            ),
                            Err(e) => self.drop_packet(e.into()),
                        };
                        r.wrap(rx)
                    }
                };
            }
            Err(e) => return self.drop_packet(e.into()),
        };
        self.receive_ip::<REPORT>(now, ip, packet, meta, report)
    }

    fn receive_ip<const REPORT: bool>(
        &mut self,
        now: Instant,
        ip: wire::IpPacket,
        packet: &[u8],
        meta: RxMeta,
        report: &mut SourceReport<'_, impl FnMut(ValidatedSource, Option<SourceContext>) -> bool>,
    ) -> Rx {
        if let Some(reason) = self.refuses(ip.src, ip.dst) {
            return self.drop_packet(reason);
        }
        match ip.proto {
            wire::PROTO_TCP => self.receive_tcp::<REPORT>(now, &ip, packet, meta, report),
            wire::PROTO_UDP if self.transparent() => {
                let rx = crate::udp_t::receive_transparent(self, &ip, packet, meta);
                if let Rx::Transparent { src, dst, .. } | Rx::TransparentSplit { src, dst, .. } =
                    &rx
                {
                    if !report.record::<REPORT>(*src, *dst, wire::PROTO_UDP, None) {
                        return self.drop_packet(DropReason::NotForUs);
                    }
                    if REPORT {
                        report.outcome = ReceiveOutcome::DatagramValidated;
                    }
                }
                rx
            }
            wire::PROTO_UDP => self.receive_udp::<REPORT>(&ip, packet, report),
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 if meta.gso.is_some() => {
                self.drop_packet(DropReason::Malformed)
            }
            wire::PROTO_ICMP | wire::PROTO_ICMPV6 => self.receive_icmp(now, &ip, packet),
            _ => self.drop_packet(DropReason::Unsupported),
        }
    }

    fn receive_tcp<const REPORT: bool>(
        &mut self,
        now: Instant,
        ip: &wire::IpPacket,
        packet: &[u8],
        meta: RxMeta,
        report: &mut SourceReport<'_, impl FnMut(ValidatedSource, Option<SourceContext>) -> bool>,
    ) -> Rx {
        let seg = &packet[ip.payload.clone()];
        let (h, off) = match wire::tcp::parse(seg) {
            Ok(v) => v,
            Err(e) => return self.drop_packet(e.into()),
        };
        let (verify, gso) = match meta.l4(wire::PROTO_TCP, ip.payload.start, 16) {
            Ok(v) => v,
            Err(reason) => return self.drop_packet(reason),
        };
        if verify && !wire::tcp::verify_checksum(ip.src, ip.dst, seg) {
            return self.drop_packet(DropReason::Checksum);
        }
        let tuple = FourTuple {
            local: SocketAddr::new(ip.dst, h.dst_port),
            remote: SocketAddr::new(ip.src, h.src_port),
        };
        let index = self
            .cache
            .filter(|(key, id)| {
                *key == tuple
                    && self.table.slots.get(id.idx as usize).is_some_and(|s| {
                        s.generation == id.generation && matches!(s.flow, Some(Flow::Tcp(_)))
                    })
            })
            .map(|(_, id)| id.idx)
            .or_else(|| self.table.tcp.get(&tuple).copied());
        let reopen = self.timewait_reopen(tuple, &h);
        let owner = index.or_else(|| {
            if reopen.is_none() {
                self.table.timewait.get(&tuple).copied()
            } else {
                None
            }
        });
        let same_source = owner.is_none_or(|index| {
            let original = self.table.source(index);
            let same = original.map(|source| source.lineage)
                == report.context.map(|source| source.lineage);
            if same {
                report.context = original;
            }
            same
        });
        if !report.record::<REPORT>(tuple.remote, tuple.local, wire::PROTO_TCP, Some(h.flags))
            || !same_source
        {
            return self.drop_packet(DropReason::NotForUs);
        }
        if let Some(index) = index {
            let slot = &mut self.table.slots[index as usize];
            let id = FlowId {
                idx: index,
                generation: slot.generation,
            };
            self.cache = Some((tuple, id));
            if let Some(Flow::Tcp(t)) = slot.flow.as_mut() {
                let input = t.input(now, &h, &seg[off..], gso, &mut self.pool);
                if REPORT && input.accepted {
                    report.outcome = ReceiveOutcome::TcpAccepted(id);
                }
                if let Some((seq, ack, flags)) = input.reset {
                    self.control(tuple, seq, ack, flags, Some(id), report.context);
                }
            }
            self.sync(index, now);
            return Rx::Consumed;
        }
        if reopen.is_none()
            && let Some(&index) = self.table.timewait.get(&tuple)
        {
            let slot = &mut self.table.slots[index as usize];
            if let Some(Flow::TimeWait(t)) = slot.flow.as_mut() {
                let args = (
                    seg.len() - off,
                    t.snd_nxt,
                    t.rcv_nxt,
                    t.max_snd_wnd,
                    t.ts_recent,
                );
                let fin =
                    crate::tcp::valid_timewait_fin(&h, args.0, args.1, args.2, args.3, args.4);
                if fin {
                    t.expiry = now + crate::tcp::TIME_WAIT;
                    if t.ts_recent.is_some() {
                        t.ts_recent = h.options.timestamps.map(|v| v.0);
                    }
                }
                let accepted = fin
                    || crate::tcp::valid_timewait_old_data(
                        &h, args.0, args.1, args.2, args.3, args.4,
                    );
                if REPORT && accepted {
                    report.outcome = ReceiveOutcome::TcpAccepted(FlowId {
                        idx: index,
                        generation: t.handle_generation,
                    });
                }
                if accepted && !t.ack_due {
                    t.ack_due = true;
                    self.timewait_ready.push_back(FlowId {
                        idx: index,
                        generation: slot.generation,
                    });
                }
            }
            self.timers.refresh(&mut self.table, index);
            return Rx::Consumed;
        }
        if self.transparent()
            && let Some(rx) = self.passive_open(now, tuple, &h, ip.dscp, reopen, report)
        {
            if REPORT
                && matches!(rx, Rx::Consumed)
                && let Some(&index) = self.table.tcp.get(&tuple)
            {
                report.outcome = ReceiveOutcome::TcpNew(FlowId {
                    idx: index,
                    generation: self.table.slots[index as usize].generation,
                });
            }
            return rx;
        }
        if h.flags & wire::tcp::RST == 0 {
            if h.flags & wire::tcp::ACK != 0 {
                self.control(tuple, h.ack, 0, wire::tcp::RST, None, report.context);
            } else {
                let ack = h.seq.wrapping_add(
                    (seg.len() - off) as u32
                        + u32::from(h.flags & wire::tcp::SYN != 0)
                        + u32::from(h.flags & wire::tcp::FIN != 0),
                );
                self.control(
                    tuple,
                    0,
                    ack,
                    wire::tcp::RST | wire::tcp::ACK,
                    None,
                    report.context,
                );
            }
        }
        self.drop_packet(DropReason::NoFlow)
    }

    /// Why a packet is not ours, if it is not. A transparent stack answers for every unicast
    /// destination except the excluded ones, and refuses mapped IPv6 wire endpoints.
    fn refuses(&self, src: IpAddr, dst: IpAddr) -> Option<DropReason> {
        match &self.cfg.mode {
            Mode::Endpoint => (self.local_for(dst) != Some(dst)).then_some(DropReason::NotForUs),
            Mode::Transparent { exclude } => {
                // Mapped addresses represent IPv4 sockets, not IPv6 wire endpoints.
                if matches!(src, IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some())
                    || matches!(dst, IpAddr::V6(addr) if addr.to_ipv4_mapped().is_some())
                    || !is_unicast(dst)
                {
                    Some(DropReason::Unsupported)
                } else {
                    exclude.contains(dst).then_some(DropReason::NotForUs)
                }
            }
        }
    }

    /// A TIME_WAIT entry that `h`, a plain SYN, may replace: its index and `snd_nxt`.
    fn timewait_reopen(&self, tuple: FourTuple, h: &wire::tcp::Header) -> Option<(u32, u32)> {
        if !self.transparent()
            || h.flags & (wire::tcp::SYN | wire::tcp::ACK | wire::tcp::RST | wire::tcp::FIN)
                != wire::tcp::SYN
        {
            return None;
        }
        let &index = self.table.timewait.get(&tuple)?;
        let Some(Flow::TimeWait(tw)) = &self.table.slots[index as usize].flow else {
            return None;
        };
        tw.syn_reopens(h.seq, h.options.timestamps.map(|v| v.0))
            .then_some((index, tw.snd_nxt))
    }
    pub(crate) fn drop_packet(&mut self, reason: DropReason) -> Rx {
        self.counters.drops[reason as usize] += 1;
        Rx::Dropped(reason)
    }
}

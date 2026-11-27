use super::*;

impl Stack {
    /// Read immediately after a successful pull, before installing the output's sidecar.
    pub fn take_fragment_output(&mut self) -> Option<crate::FragmentInfo> {
        self.shard.as_mut()?.fragment_output.take()
    }

    /// Whether a pull could find queued work in the selected output class.
    /// Stale or currently blocked entries may keep this true. Handle timers separately.
    pub fn may_have_transmit(&self, control_only: bool) -> bool {
        let ready = if control_only {
            self.control_ready.as_ref().unwrap_or(&self.ready)
        } else {
            &self.ready
        };
        !ready.is_empty()
            || !self.controls.is_empty()
            || !self.timewait_ready.is_empty()
            || self.reasm.pending_icmp()
            || (!control_only && self.udp_tx.pending())
    }

    pub fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        self.poll_transmit_with(now, out, TxCaps::NONE)
            .map(|t| t.len)
    }

    /// [`Stack::poll_transmit`] for a driver that can complete TCP checksums or segment a TSO
    /// packet. With the family's `tso4` or `tso6` capability, a TCP flow may emit one packet of up
    /// to 64 KiB of payload with several MSS-sized segments ([`Transmit::gso`]). TSO packets and
    /// single TCP packets with the family's `csum4` or `csum6` capability use [`TxCsum::Partial`].
    /// Other output carries complete checksums. Endpoint mode ignores `caps`.
    ///
    /// How much a packet carries follows the congestion and receive windows, the pacer (a burst is
    /// at most two milliseconds of traffic) and about a millisecond of the pacing rate, as TSO
    /// autosizing; the output buffer bounds it too, so any buffer that holds one MTU-sized packet
    /// works. Every segment keeps its own send descriptor, and a run of lost segments is
    /// retransmitted in one TSO packet too.
    pub fn poll_transmit_with(
        &mut self,
        now: Instant,
        out: &mut [u8],
        caps: TxCaps,
    ) -> Option<Transmit> {
        match self.poll_transmit_filtered(now, out, caps, false, None) {
            AccountedTransmit::Packet(tx) => Some(tx),
            AccountedTransmit::NeedsIcmp
            | AccountedTransmit::BufferTooSmall
            | AccountedTransmit::Idle => None,
        }
    }

    /// Pulls only protocol control output: no TCP payload or UDP datagrams/fragments.
    /// A driver reserves control credit before this call; payload readiness stays queued.
    pub fn poll_control_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<Transmit> {
        self.prepare_control_queue();
        match self.poll_transmit_filtered(now, out, TxCaps::NONE, true, None) {
            AccountedTransmit::Packet(tx) => Some(tx),
            AccountedTransmit::NeedsIcmp
            | AccountedTransmit::BufferTooSmall
            | AccountedTransmit::Idle => None,
        }
    }

    pub(super) fn prepare_control_queue(&mut self) {
        if self.control_ready.is_none() {
            let mut queue = VecDeque::with_capacity(self.ready.len());
            for &id in &self.ready {
                let slot = &mut self.table.slots[id.idx as usize];
                if slot.generation == id.generation
                    && slot.on_tx
                    && matches!(slot.flow, Some(Flow::Tcp(_)))
                {
                    slot.on_control = true;
                    queue.push_back(id);
                }
            }
            self.control_ready = Some(queue);
        }
    }

    /// Retry `NeedsIcmp` under the realm's ICMP lock using the current service time.
    /// No control or limiter state is consumed before that retry.
    pub fn poll_transmit_accounted(
        &mut self,
        now: Instant,
        out: &mut [u8],
        control_only: bool,
        icmp: Option<&mut crate::IcmpState>,
    ) -> AccountedTransmit {
        if control_only {
            self.prepare_control_queue();
        }
        self.poll_transmit_filtered(now, out, TxCaps::NONE, control_only, icmp)
    }

    fn poll_transmit_filtered(
        &mut self,
        now: Instant,
        out: &mut [u8],
        caps: TxCaps,
        control_only: bool,
        mut icmp: Option<&mut crate::IcmpState>,
    ) -> AccountedTransmit {
        self.now = now;
        if let Some(shard) = &mut self.shard {
            shard.fragment_output = None;
        }
        let icmp_retry = self.shard.is_some() && icmp.is_some();
        let retry_class = if icmp_retry {
            let Some(class) = self
                .shard
                .as_mut()
                .and_then(|shard| shard.icmp_class.take())
            else {
                return AccountedTransmit::Idle;
            };
            Some(class)
        } else {
            None
        };
        let caps = if self.transparent() && !control_only {
            caps
        } else {
            TxCaps::NONE
        };
        let mut tx = Transmit::plain(0);
        let first_class = if let Some(class) = retry_class {
            class
        } else if control_only {
            self.control_class
        } else {
            self.class
        };
        let mut saw_too_small = false;
        for step in 0..if icmp_retry { 1 } else { 5 } {
            let class = (first_class + step) % 5;
            let needs_icmp = (class == 0
                && self.controls.front().is_some_and(|c| c.icmp.is_some()))
                || (class == 4 && self.reasm.pending_icmp());
            if icmp.is_none()
                && needs_icmp
                && let Some(shard) = self.shard.as_mut()
            {
                shard.icmp_class = Some(class);
                return AccountedTransmit::NeedsIcmp;
            }
            let result = match class {
                0 => self.emit_control(now, out, caps, &mut tx, &mut icmp),
                1 => self.emit_timewait(now, out, caps, &mut tx),
                2 => self.emit_flow(now, out, caps, &mut tx, control_only),
                3 if !control_only => self.poll_udp_frag(out, &mut tx),
                3 => Output::None,
                _ => match &mut self.shard {
                    Some(shard) => {
                        let (output, fragment) = self.reasm.poll_icmp_with_fragment(
                            now,
                            icmp.as_deref_mut().unwrap_or(&mut self.icmp_out),
                            out,
                            &mut tx,
                        );
                        shard.fragment_output = fragment;
                        output
                    }
                    None => self.reasm.poll_icmp(now, &mut self.icmp_out, out, &mut tx),
                },
            };
            match result {
                Output::Sent(n) => {
                    if control_only {
                        self.control_class = (class + 1) % 5;
                    } else {
                        self.class = (class + 1) % 5;
                    }
                    if class != 3 {
                        // `poll_udp_frag` counts its own packets.
                        self.counters.tx_packets += 1;
                    }
                    tx.len = n;
                    return AccountedTransmit::Packet(tx);
                }
                Output::Blocked => {
                    saw_too_small = true;
                    // The locked retry may touch only ICMP. Resume the unlocked walk past it.
                    if icmp_retry {
                        if control_only {
                            self.control_class = (class + 1) % 5;
                        } else {
                            self.class = (class + 1) % 5;
                        }
                    }
                }
                Output::Deferred | Output::None => {}
            }
        }
        if saw_too_small {
            AccountedTransmit::BufferTooSmall
        } else {
            AccountedTransmit::Idle
        }
    }

    fn emit_control(
        &mut self,
        now: Instant,
        out: &mut [u8],
        caps: TxCaps,
        tx: &mut Transmit,
        icmp: &mut Option<&mut crate::IcmpState>,
    ) -> Output {
        while let Some(c) = self.controls.front().copied() {
            if icmp.is_some() && c.icmp.is_none() {
                return Output::None;
            }
            if let Some(how) = c.icmp {
                match self.emit_refusal(now, &c, how, out, icmp) {
                    Output::None => continue,
                    Output::Sent(n) => {
                        tx.flow = c.flow;
                        tx.source = c.source;
                        return Output::Sent(n);
                    }
                    result => return result,
                }
            }
            let h = c.header();
            return match Self::emit_tcp_control(out, c.tuple, &h, caps, tx) {
                Some(n) => {
                    self.pop_control();
                    tx.flow = c.flow;
                    tx.source = c.source;
                    Output::Sent(n)
                }
                None => Output::Blocked,
            };
        }
        Output::None
    }

    fn emit_timewait(
        &mut self,
        now: Instant,
        out: &mut [u8],
        caps: TxCaps,
        tx: &mut Transmit,
    ) -> Output {
        while let Some(id) = self.timewait_ready.front().copied() {
            let source = self.table.source(id.idx);
            let slot = &mut self.table.slots[id.idx as usize];
            if slot.generation != id.generation || !matches!(slot.flow, Some(Flow::TimeWait(_))) {
                self.timewait_ready.pop_front();
                continue;
            }
            let Some(Flow::TimeWait(t)) = slot.flow.as_mut() else {
                unreachable!()
            };
            if !t.ack_due {
                self.timewait_ready.pop_front();
                continue;
            }
            let h = t.ack_header(now, self.epoch);
            return match Self::emit_tcp_control(out, t.tuple, &h, caps, tx) {
                Some(n) => {
                    tx.flow = Some(FlowId {
                        idx: id.idx,
                        generation: t.handle_generation,
                    });
                    tx.source = source;
                    t.ack_due = false;
                    self.timewait_ready.pop_front();
                    Output::Sent(n)
                }
                None => Output::Blocked,
            };
        }
        Output::None
    }

    pub(super) fn emit_tcp_control(
        out: &mut [u8],
        tuple: FourTuple,
        header: &wire::tcp::Header,
        caps: TxCaps,
        tx: &mut Transmit,
    ) -> Option<usize> {
        let v6 = tuple.local.is_ipv6();
        let partial = caps.csum(v6);
        let len = wire::tcp::emit_header_only(
            out,
            tuple.local.ip(),
            tuple.remote.ip(),
            header,
            0,
            &[],
            partial,
        )?;
        if partial {
            tx.csum = TxCsum::Partial {
                start: wire::ip_header_len(v6) as u16,
                offset: 16,
            };
        }
        Some(len)
    }

    fn emit_flow(
        &mut self,
        now: Instant,
        out: &mut [u8],
        caps: TxCaps,
        tx: &mut Transmit,
        control_only: bool,
    ) -> Output {
        let ready = if control_only {
            self.control_ready.as_ref().unwrap().len()
        } else {
            self.ready.len()
        };
        let mut saw_too_small = false;
        for _ in 0..ready {
            let id = if control_only {
                self.control_ready.as_mut().unwrap().pop_front()
            } else {
                self.ready.pop_front()
            };
            let Some(id) = id else { break };
            let source = self.table.source(id.idx);
            let slot = &mut self.table.slots[id.idx as usize];
            let queued = if control_only {
                slot.on_control
            } else {
                slot.on_tx
            };
            if slot.generation != id.generation || !queued {
                continue;
            }
            if control_only {
                slot.on_control = false;
            } else {
                slot.on_tx = false;
            }
            let Some(Flow::Tcp(t)) = slot.flow.as_mut() else {
                continue;
            };
            let quantum = u32::from(self.cfg.mtu);
            let deficit = slot.deficit;
            if !control_only && slot.deficit < quantum {
                slot.deficit += quantum;
            }
            let result = t.output_with(now, out, &mut self.pool, caps, tx, !control_only);
            match result {
                Output::Sent(n) => {
                    tx.flow = Some(id);
                    tx.source = source;
                    if control_only {
                        slot.on_control = true;
                        self.control_ready.as_mut().unwrap().push_back(id);
                        self.sync_without_tx(id.idx, now);
                    } else {
                        slot.deficit = slot.deficit.saturating_sub(n as u32);
                        slot.on_tx = true;
                        if slot.deficit >= quantum {
                            self.ready.push_front(id);
                        } else {
                            self.ready.push_back(id);
                        }
                        self.sync(id.idx, now);
                    }
                    return Output::Sent(n);
                }
                Output::Blocked | Output::Deferred => {
                    saw_too_small |= matches!(result, Output::Blocked);
                    slot.deficit = deficit;
                    if control_only {
                        slot.on_control = true;
                        self.control_ready.as_mut().unwrap().push_back(id);
                    } else {
                        slot.on_tx = true;
                        self.ready.push_back(id);
                    }
                    self.sync_without_tx(id.idx, now);
                }
                Output::None => self.sync_without_tx(id.idx, now),
            }
        }
        if saw_too_small {
            Output::Blocked
        } else {
            Output::None
        }
    }

    pub(crate) fn control(
        &mut self,
        tuple: FourTuple,
        seq: u32,
        ack: u32,
        flags: u8,
        flow: Option<FlowId>,
        source: Option<SourceContext>,
    ) {
        self.queue_control(Control {
            tuple,
            seq,
            ack,
            flags,
            icmp: None,
            flow,
            source,
        });
    }

    pub(super) fn control_limit(&self) -> usize {
        self.shard
            .as_ref()
            .map_or(CONTROL_LIMIT, |s| s.control_limit)
    }

    pub(crate) fn queue_control(&mut self, c: Control) {
        if self.controls.len() == self.control_limit() {
            self.counters.control_dropped += 1;
            return;
        }
        self.controls.push_back(c);
    }

    pub(crate) fn pop_control(&mut self) {
        if self.controls.pop_front().is_some_and(|c| c.flow.is_some()) {
            self.table.tcp_retention_changed = true;
        }
    }
}

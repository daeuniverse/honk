//! Borrowed packet emission for synchronous devices. Maintenance has its own return
//! boundary so a rejected write cannot publish an earlier candidate's side effects.

use super::*;

#[derive(Debug)]
pub enum IovTransmit {
    Packet(Transmit),
    NeedsIcmp,
    BufferTooSmall,
    Idle,
    /// A bounded housekeeping or storage preparation step; poll again before sleeping.
    Progress,
    /// A flow is waiting for capacity. The scheduler still offers other eligible work.
    Deferred,
}

impl Stack {
    /// Offers one borrowed IP header and up to 18 payload slices for synchronous emission.
    /// `Ok(())` accepts the complete packet. An error leaves the attempted output pending.
    /// A device that accepted a partial record must stop instead of retrying its prefix.
    /// On `NeedsIcmp`, retry with this realm's locked limiter. No slice outlives `emit`.
    pub fn poll_transmit_iov<E>(
        &mut self,
        now: Instant,
        max_len: usize,
        caps: TxCaps,
        control_only: bool,
        mut icmp: Option<&mut crate::IcmpState>,
        mut emit: impl FnMut(&[u8], &[&[u8]], Transmit) -> Result<(), E>,
    ) -> Result<IovTransmit, E> {
        if control_only && self.control_ready.is_none() {
            self.prepare_control_queue();
            return Ok(IovTransmit::Progress);
        }
        let retry = self.shard.is_some() && icmp.is_some();
        let first = if retry {
            let Some(class) = self.shard.as_ref().and_then(|shard| shard.icmp_class) else {
                return Ok(IovTransmit::Idle);
            };
            class
        } else if control_only {
            self.control_class
        } else {
            self.class
        };
        let caps = if self.transparent() {
            caps
        } else {
            TxCaps::NONE
        };
        let mut short = false;
        for step in 0..if retry { 1 } else { 5 } {
            let class = (first + step) % 5;
            let needs_limiter = (class == 0
                && self.controls.front().is_some_and(|c| c.icmp.is_some()))
                || (class == 4 && self.reasm.pending_icmp());
            if icmp.is_none()
                && needs_limiter
                && let Some(shard) = &mut self.shard
            {
                shard.icmp_class = Some(class);
                return Ok(IovTransmit::NeedsIcmp);
            }
            let mut fragment = None;
            let result = match class {
                0 => self.control_iov(now, max_len, caps, &mut icmp, &mut emit)?,
                1 => self.timewait_iov(now, max_len, caps, &mut emit)?,
                2 => self.flow_iov(now, max_len, caps, control_only, &mut emit)?,
                3 if !control_only => self.udp_tx.poll_iov(max_len, &mut emit)?,
                3 => IovTransmit::Idle,
                _ => {
                    let (result, owner) = self.reasm.poll_icmp_iov(
                        now,
                        icmp.as_deref_mut().unwrap_or(&mut self.icmp_out),
                        max_len,
                        &mut emit,
                    )?;
                    fragment = owner;
                    result
                }
            };
            match result {
                IovTransmit::Packet(_) | IovTransmit::Progress => {
                    self.now = now;
                    if let Some(shard) = &mut self.shard {
                        shard.fragment_output = fragment;
                        shard.icmp_class = None;
                    }
                    if matches!(result, IovTransmit::Packet(_)) {
                        self.counters.tx_packets += 1;
                        *self.iov_class(control_only) = (class + 1) % 5;
                    }
                    return Ok(result);
                }
                IovTransmit::BufferTooSmall => short = true,
                IovTransmit::Deferred | IovTransmit::Idle => {}
                IovTransmit::NeedsIcmp => unreachable!("limiter admission precedes selection"),
            }
        }
        self.now = now;
        if let Some(shard) = &mut self.shard {
            shard.fragment_output = None;
            if retry {
                shard.icmp_class = None;
            }
        }
        if retry && short {
            *self.iov_class(control_only) = (first + 1) % 5;
        }
        Ok(if short {
            IovTransmit::BufferTooSmall
        } else {
            IovTransmit::Idle
        })
    }

    fn iov_class(&mut self, control: bool) -> &mut u8 {
        if control {
            &mut self.control_class
        } else {
            &mut self.class
        }
    }

    fn control_iov<E>(
        &mut self,
        now: Instant,
        max_len: usize,
        caps: TxCaps,
        icmp: &mut Option<&mut crate::IcmpState>,
        emit: &mut impl FnMut(&[u8], &[&[u8]], Transmit) -> Result<(), E>,
    ) -> Result<IovTransmit, E> {
        let Some(c) = self.controls.front().copied() else {
            return Ok(IovTransmit::Idle);
        };
        if let Some(how) = c.icmp {
            return self.emit_refusal_iov(now, &c, how, icmp, max_len, emit);
        }
        if icmp.is_some() {
            return Ok(IovTransmit::Idle);
        }
        let result = empty_tcp(c.tuple, &c.header(), c.flow, c.source, max_len, caps, emit)?;
        if matches!(result, IovTransmit::Packet(_)) {
            self.pop_control();
        }
        Ok(result)
    }

    fn timewait_iov<E>(
        &mut self,
        now: Instant,
        max_len: usize,
        caps: TxCaps,
        emit: &mut impl FnMut(&[u8], &[&[u8]], Transmit) -> Result<(), E>,
    ) -> Result<IovTransmit, E> {
        let Some(id) = self.timewait_ready.front().copied() else {
            return Ok(IovTransmit::Idle);
        };
        let source = self.table.source(id.idx);
        let slot = &mut self.table.slots[id.idx as usize];
        let Some(Flow::TimeWait(t)) = &mut slot.flow else {
            self.timewait_ready.pop_front();
            return Ok(IovTransmit::Progress);
        };
        if slot.generation != id.generation || !t.ack_due {
            self.timewait_ready.pop_front();
            return Ok(IovTransmit::Progress);
        }
        let owner = FlowId {
            idx: id.idx,
            generation: t.handle_generation,
        };
        let result = empty_tcp(
            t.tuple,
            &t.ack_header(now, self.epoch),
            Some(owner),
            source,
            max_len,
            caps,
            emit,
        )?;
        if matches!(result, IovTransmit::Packet(_)) {
            t.ack_due = false;
            self.timewait_ready.pop_front();
        }
        Ok(result)
    }

    fn flow_iov<E>(
        &mut self,
        now: Instant,
        max_len: usize,
        caps: TxCaps,
        control_only: bool,
        emit: &mut impl FnMut(&[u8], &[&[u8]], Transmit) -> Result<(), E>,
    ) -> Result<IovTransmit, E> {
        let queue = if control_only {
            self.control_ready.as_mut().expect("control queue prepared")
        } else {
            &mut self.ready
        };
        let mut short = false;
        for at in 0..queue.len() {
            let id = queue[at];
            let source = self.table.source(id.idx);
            let slot = &mut self.table.slots[id.idx as usize];
            let queued = if control_only {
                &mut slot.on_control
            } else {
                &mut slot.on_tx
            };
            if slot.generation != id.generation || !*queued {
                queue.remove(at);
                return Ok(IovTransmit::Progress);
            }
            let Some(Flow::Tcp(t)) = &mut slot.flow else {
                *queued = false;
                queue.remove(at);
                return Ok(IovTransmit::Progress);
            };
            let tx = Transmit {
                flow: Some(id),
                source,
                ..Transmit::plain(0)
            };
            let result =
                t.output_iov(now, max_len, &mut self.pool, caps, !control_only, tx, emit)?;
            match result {
                IovTransmit::Packet(tx) => {
                    queue.rotate_left(at);
                    queue.pop_front();
                    if control_only {
                        queue.push_back(id);
                        self.sync_without_tx(id.idx, now);
                    } else {
                        let quantum = u32::from(self.cfg.mtu);
                        let credit = if slot.deficit < quantum {
                            slot.deficit + quantum
                        } else {
                            slot.deficit
                        };
                        slot.deficit = credit.saturating_sub(tx.len as u32);
                        if slot.deficit >= quantum {
                            queue.push_front(id);
                        } else {
                            queue.push_back(id);
                        }
                        self.sync(id.idx, now);
                    }
                    return Ok(result);
                }
                IovTransmit::Idle => {
                    *queued = false;
                    queue.remove(at);
                    self.sync_without_tx(id.idx, now);
                    return Ok(IovTransmit::Progress);
                }
                IovTransmit::Progress => {
                    self.sync_without_tx(id.idx, now);
                    return Ok(result);
                }
                IovTransmit::Deferred => {}
                IovTransmit::BufferTooSmall => short = true,
                IovTransmit::NeedsIcmp => unreachable!("TCP has no ICMP limiter"),
            }
        }
        Ok(if short {
            IovTransmit::BufferTooSmall
        } else {
            IovTransmit::Idle
        })
    }
}

fn empty_tcp<E>(
    tuple: FourTuple,
    header: &wire::tcp::Header,
    flow: Option<FlowId>,
    source: Option<SourceContext>,
    max_len: usize,
    caps: TxCaps,
    emit: &mut impl FnMut(&[u8], &[&[u8]], Transmit) -> Result<(), E>,
) -> Result<IovTransmit, E> {
    let mut bytes = [0; 128];
    let mut tx = Transmit {
        flow,
        source,
        ..Transmit::plain(0)
    };
    let Some(len) = Stack::emit_tcp_control(&mut bytes, tuple, header, caps, &mut tx) else {
        return Ok(IovTransmit::BufferTooSmall);
    };
    if len > max_len {
        return Ok(IovTransmit::BufferTooSmall);
    }
    tx.len = len;
    emit(&bytes[..len], &[], tx)?;
    Ok(IovTransmit::Packet(tx))
}

impl Control {
    pub(super) fn header(&self) -> wire::tcp::Header {
        wire::tcp::Header {
            src_port: self.tuple.local.port(),
            dst_port: self.tuple.remote.port(),
            seq: self.seq,
            ack: self.ack,
            flags: self.flags,
            window: 0,
            urgent: 0,
            options: wire::tcp::Options::default(),
        }
    }
}

impl TimeWait {
    pub(super) fn ack_header(&self, now: Instant, epoch: Instant) -> wire::tcp::Header {
        let mut options = wire::tcp::Options::default();
        if let Some(recent) = self.ts_recent {
            options.timestamps = Some((
                self.ts_offset
                    .wrapping_add(now.saturating_duration_since(epoch).as_millis() as u32),
                recent,
            ));
        }
        wire::tcp::Header {
            src_port: self.tuple.local.port(),
            dst_port: self.tuple.remote.port(),
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            flags: wire::tcp::ACK,
            window: self.window,
            urgent: 0,
            options,
        }
    }
}

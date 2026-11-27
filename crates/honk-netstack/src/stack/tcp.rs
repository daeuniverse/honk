use super::*;

impl Stack {
    /// A shared budget refund can unblock a queued writer without packet or timer activity on
    /// this Stack. This hint lets an owner schedule a recheck via `handle_timeout` or `poll_event`.
    pub fn has_pending_writers(&self) -> bool {
        !self.writers.is_empty()
    }

    pub fn tcp_connect(
        &mut self,
        now: Instant,
        remote: SocketAddr,
    ) -> Result<FlowId, ConnectError> {
        self.now = now;
        let local_ip = self
            .local_for(remote.ip())
            .ok_or(ConnectError::NoLocalAddress)?;
        if self.table.active >= self.cfg.max_flows {
            return Err(ConnectError::FlowLimit);
        }
        if self.table.tcp_active >= self.floor_cap {
            return Err(ConnectError::Memory);
        }
        let mut port = self.ports.start(&self.cfg.secret, local_ip, remote);
        let offset = flow::ts_offset(&self.cfg.secret, local_ip, remote.ip());
        let stamp =
            offset.wrapping_add(now.saturating_duration_since(self.epoch).as_millis() as u32);
        let mut choice = None;
        for _ in 0..32768 {
            let tuple = FourTuple {
                local: SocketAddr::new(local_ip, port),
                remote,
            };
            let iss = flow::isn(
                &self.cfg.secret,
                tuple,
                now.saturating_duration_since(self.epoch),
            );
            if !self.table.tcp.contains_key(&tuple) {
                if let Some(&index) = self.table.timewait.get(&tuple) {
                    let can_reuse = matches!(&self.table.slots[index as usize].flow, Some(Flow::TimeWait(tw)) if tw.reusable(iss, stamp));
                    if can_reuse && self.table.can_insert(Some(index)) {
                        choice = Some((tuple, iss, Some(index)));
                        break;
                    }
                } else if self.table.can_insert(None) {
                    choice = Some((tuple, iss, None));
                    break;
                }
            }
            port = flow::next_port(port);
        }
        let (tuple, iss, replacing) = choice.ok_or_else(|| {
            if self.table.can_insert(None) {
                ConnectError::AddrInUse
            } else {
                ConnectError::FlowLimit
            }
        })?;
        if !self.pool.admit_floor() {
            return Err(ConnectError::Memory);
        }
        if let Some(index) = replacing {
            self.table.remove(index);
            self.purge_stale();
        }
        let mut t = Tcb::new(tuple, &self.cfg, now, self.epoch, iss, offset);
        t.init_window(&mut self.pool);
        let id = self.table.insert(Flow::Tcp(Box::new(t)));
        self.sync(id.idx, now);
        self.tx_wakeup = true;
        Ok(id)
    }

    pub fn tcp_write(&mut self, id: FlowId, data: &[u8]) -> Result<usize, StreamError> {
        self.tcp_write_with(id, |t, pool| t.write(pool, data), |&n| n != 0)
    }

    /// Lends up to 17 send-ring slices with at most `limit` bytes of spare capacity.
    ///
    /// The callback fills a prefix and returns its length to commit it. Zero, an error or
    /// unwinding leaves the send position intact and releases unused credit. Spare bytes are
    /// unspecified until written. Committed bytes stay owned through graceful close until
    /// cumulatively acknowledged.
    ///
    /// Connection state and send credit determine the outer result. The inner result carries
    /// the callback's I/O result, or `InvalidInput` if it reported more bytes than offered.
    /// A zero limit on an open write half returns `Ok(Ok(0))` without calling the callback.
    pub fn tcp_reserve_tx(
        &mut self,
        id: FlowId,
        limit: usize,
        fill: impl FnOnce(&mut [IoSliceMut<'_>]) -> io::Result<usize>,
    ) -> Result<io::Result<usize>, StreamError> {
        self.tcp_reserve_tx_parts::<{ ring::STREAM_PARTS }>(id, limit, fill)
    }

    /// Like [`Self::tcp_reserve_tx`], with the loan ending at the first chunk boundary.
    /// A partial tail can be borrowed without reserving another chunk.
    pub fn tcp_reserve_tx_chunk(
        &mut self,
        id: FlowId,
        limit: usize,
        fill: impl FnOnce(&mut [IoSliceMut<'_>]) -> io::Result<usize>,
    ) -> Result<io::Result<usize>, StreamError> {
        self.tcp_reserve_tx_parts::<1>(id, limit, fill)
    }

    fn tcp_reserve_tx_parts<const PARTS: usize>(
        &mut self,
        id: FlowId,
        limit: usize,
        fill: impl FnOnce(&mut [IoSliceMut<'_>]) -> io::Result<usize>,
    ) -> Result<io::Result<usize>, StreamError> {
        self.tcp_write_with(
            id,
            |t, pool| t.with_tx_spare::<PARTS>(pool, limit, fill),
            |result| result.as_ref().is_ok_and(|&n| n != 0),
        )
    }

    fn tcp_write_with<T>(
        &mut self,
        id: FlowId,
        write: impl FnOnce(&mut Tcb, &mut Pool) -> Result<T, StreamError>,
        published: impl FnOnce(&T) -> bool,
    ) -> Result<T, StreamError> {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(StreamError::Stale);
        };
        let result = write(t, &mut self.pool);
        if matches!(result, Err(StreamError::WouldBlock)) {
            self.sync_without_tx(id.idx, self.now);
        }
        if result.as_ref().is_ok_and(published) {
            self.tx_wakeup = true;
            self.sync(id.idx, self.now);
        }
        result
    }

    pub fn tcp_read(&mut self, id: FlowId, out: &mut [u8]) -> Result<usize, StreamError> {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(StreamError::Stale);
        };
        let result = t.read(&mut self.pool, out, self.now);
        let ack_due = t.ack_due != 0;
        self.sync_tcp_read(id, ack_due);
        result
    }

    /// Borrows at most `limit` in-order receive bytes in up to 17 ring slices.
    ///
    /// The count is the number of nonempty slices. A drained orderly EOF returns zero slices
    /// and `true`. Buffered bytes precede EOF and sticky errors. An empty live stream or a
    /// zero limit with buffered data returns `WouldBlock`.
    pub fn tcp_peek_rx(
        &self,
        id: FlowId,
        limit: usize,
    ) -> Result<([IoSlice<'_>; ring::STREAM_PARTS], usize, bool), StreamError> {
        let Some(Flow::Tcp(t)) = self.table.get(id) else {
            return Err(StreamError::Stale);
        };
        let available = t.read_len()?;
        if available != 0 && limit == 0 {
            return Err(StreamError::WouldBlock);
        }
        let (parts, count) = t.rx.peek(available.min(limit));
        Ok((parts, count, available == 0))
    }

    /// Consumes `n` bytes of the current contiguous receive prefix and updates receive credit.
    /// A stale handle or an out-of-range count leaves the ring and window unchanged.
    pub fn tcp_consume_rx(&mut self, id: FlowId, n: usize) -> Result<(), TcpConsumeError> {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(TcpConsumeError::Stale);
        };
        if n > t.available() {
            return Err(TcpConsumeError::OutOfRange);
        }
        if n != 0 {
            t.consume_rx(&mut self.pool, n, self.now);
            let ack_due = t.ack_due != 0;
            self.sync_tcp_read(id, ack_due);
        }
        Ok(())
    }

    fn sync_tcp_read(&mut self, id: FlowId, ack_due: bool) {
        if ack_due {
            self.tx_wakeup = true;
        }
        self.sync(id.idx, self.now);
    }

    pub fn tcp_shutdown(&mut self, id: FlowId) -> Result<(), StreamError> {
        let Some(Flow::Tcp(t)) = self.table.get_mut(id) else {
            return Err(StreamError::Stale);
        };
        let result = t.shutdown();
        if result.is_ok() {
            self.tx_wakeup = true;
            self.sync(id.idx, self.now);
        }
        result
    }

    /// Releases the handle immediately. Unread data aborts with RST, as on Linux.
    pub fn tcp_close(&mut self, id: FlowId) {
        if let Some(Flow::Tcp(t)) = self.table.get_mut(id) {
            t.close(self.now);
            self.tx_wakeup = true;
            self.sync(id.idx, self.now);
        }
    }

    pub fn tcp_abort(&mut self, id: FlowId) {
        if let Some(Flow::Tcp(t)) = self.table.get_mut(id) {
            t.abort();
            self.tx_wakeup = true;
            self.sync(id.idx, self.now);
        }
    }

    pub fn tcp_state(&self, id: FlowId) -> Option<TcpState> {
        match self.table.get(id)? {
            Flow::Tcp(t) => Some(t.state),
            _ => None,
        }
    }

    pub fn tcp_stats(&self, id: FlowId) -> Option<TcpStats> {
        match self.table.get(id)? {
            Flow::Tcp(t) => Some(t.stats(self.pool.chunk())),
            _ => None,
        }
    }

    pub(crate) fn sync(&mut self, index: u32, now: Instant) {
        self.collect(index, now, true);
    }
    pub(super) fn sync_without_tx(&mut self, index: u32, now: Instant) {
        self.collect(index, now, false);
    }

    fn collect(&mut self, index: u32, now: Instant, tx: bool) {
        let slot = &mut self.table.slots[index as usize];
        let id = FlowId {
            idx: index,
            generation: slot.generation,
        };
        let mut remove = false;
        let mut compact = None;
        let mut left_half_open = None;
        if let Some(Flow::Tcp(t)) = slot.flow.as_mut() {
            t.check();
            if t.half_open && t.state != TcpState::SynReceived {
                t.half_open = false;
                left_half_open = Some(t.tuple.remote.ip());
            }
            if !t.app_open {
                if t.state == TcpState::Closed && !t.rst_pending {
                    remove = true;
                } else if t.state == TcpState::TimeWait && t.available() == 0 && t.ack_due == 0 {
                    compact = Some(TimeWait::from_tcb(t, now, id.generation));
                }
            }
            if !remove && compact.is_none() {
                if t.write_blocked
                    && let Some(threshold) = t.write_threshold(&self.pool)
                {
                    if t.tx.can_append(&self.pool, threshold) {
                        t.write_blocked = false;
                        t.ready |= Ready::WRITABLE;
                    } else if !t.write_wait_queued {
                        t.write_wait_queued = true;
                        self.writers.push_back(id);
                    }
                }
                let ready = std::mem::take(&mut t.ready);
                if t.app_open && !ready.is_empty() {
                    slot.ready |= ready;
                    if !slot.on_event {
                        slot.on_event = true;
                        self.events.push_back(id);
                    }
                }
                if tx && !slot.on_tx {
                    slot.on_tx = true;
                    self.ready.push_back(id);
                }
                if tx
                    && !slot.on_control
                    && let Some(queue) = &mut self.control_ready
                {
                    slot.on_control = true;
                    queue.push_back(id);
                }
            }
        }
        if let Some(source) = left_half_open {
            self.leave_half_open(source);
            if let Some(shard) = &mut self.shard {
                assert!(shard.half_open_released.len() < shard.release_limit);
                shard.half_open_released.push_back(id);
            }
        }
        let retired = remove || compact.is_some();
        if remove {
            if let Some(Flow::Tcp(mut t)) = self.table.remove(index) {
                t.release(&mut self.pool);
                self.pool.release_floor();
            }
        } else if let Some(tw) = compact {
            if let Some(Flow::Tcp(t)) = self.table.slots[index as usize].flow.as_mut() {
                t.release(&mut self.pool);
                self.pool.release_floor();
            }
            self.table.compact(index, tw);
        }
        if retired {
            self.purge_stale();
        }
        self.timers.mark(&mut self.table, index);
    }

    pub(super) fn wake_writers(&mut self) {
        if self.writers.is_empty() {
            return;
        }
        let epochs = self.pool.release_epochs();
        if epochs == self.seen_release_epochs || self.pool.shared_free() == 0 {
            return;
        }
        self.seen_release_epochs = epochs;
        for _ in 0..self.writers.len() {
            if self.pool.shared_free() == 0 {
                break;
            }
            let Some(id) = self.writers.pop_front() else {
                break;
            };
            #[cfg(test)]
            {
                self.writer_visits += 1;
            }
            let slot = &mut self.table.slots[id.idx as usize];
            if slot.generation != id.generation {
                continue;
            }
            let Some(Flow::Tcp(t)) = slot.flow.as_mut() else {
                continue;
            };
            let threshold = t.write_threshold(&self.pool);
            if !t.write_blocked || threshold.is_none() {
                t.write_wait_queued = false;
            } else if threshold.is_some_and(|bytes| t.tx.can_append(&self.pool, bytes)) {
                t.write_wait_queued = false;
                t.write_blocked = false;
                slot.ready |= Ready::WRITABLE;
                if !slot.on_event {
                    slot.on_event = true;
                    self.events.push_back(id);
                }
            } else {
                self.writers.push_back(id);
            }
        }
    }

    /// Drops queue nodes of removed flows. Every pop already skips them by generation, so this only
    /// bounds growth: a queue is swept once it holds twice what the live slots could, which costs
    /// O(1) amortized per removal where sweeping on each removal made mass teardown quadratic.
    pub(crate) fn purge_stale(&mut self) {
        let limit = 2 * self.table.slots.len().max(16);
        let slots = &self.table.slots;
        for queue in [
            &mut self.events,
            &mut self.ready,
            &mut self.writers,
            &mut self.timewait_ready,
            &mut self.accept_q,
        ]
        .into_iter()
        .chain(self.control_ready.iter_mut())
        {
            if queue.len() > limit {
                #[cfg(test)]
                {
                    self.purge_visits += queue.len();
                }
                queue.retain(|id| slots[id.idx as usize].generation == id.generation);
            }
        }
    }
}

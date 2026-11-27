use super::*;
use std::pin::pin;
use std::task::Waker;

pub(super) struct TurnBudget {
    used: usize,
    limit: usize,
    poll_direct: bool,
}

impl TurnBudget {
    pub(super) fn native() -> Self {
        Self {
            used: 0,
            limit: epoll::MAX_CONSECUTIVE_TURNS,
            poll_direct: true,
        }
    }

    pub(super) fn tokio() -> Self {
        Self {
            used: 0,
            limit: usize::MAX,
            poll_direct: false,
        }
    }

    pub(super) fn charge(&mut self) {
        debug_assert!(self.used < self.limit);
        self.used += 1;
    }

    pub(super) fn exhausted(&self) -> bool {
        self.used == self.limit
    }

    pub(super) fn poll_due(&self, realms: &[Realm]) -> bool {
        self.exhausted() || (self.poll_direct && epoll::direct_epoll_due(self.used, realms))
    }

    pub(super) fn poll_events(
        &self,
        poll: &WorkerEpoll,
        realms: &[Realm],
        events: &mut [libc::epoll_event],
    ) -> io::Result<usize> {
        if self.poll_due(realms) {
            poll.poll_nonblocking(events)
        } else {
            Ok(0)
        }
    }
}

impl Runtime {
    pub(super) fn register_worker_epoll(&mut self) -> io::Result<WorkerEpoll> {
        let watches = 1 + self.devices.iter().map(|d| d.queues.len()).sum::<usize>();
        let poll = WorkerEpoll::new(&self.polling_budget, watches)?;
        poll.add_fd(
            self.topology.get_ref().as_raw_fd(),
            READ_EDGE,
            epoll::TOKEN_TOPOLOGY,
        )?;
        for (index, device) in self.devices.iter().enumerate() {
            for queue in &device.queues {
                queue.io.watch_queue(&poll, index, queue.id as usize)?;
            }
        }
        for (index, realm) in self.realms.iter_mut().enumerate() {
            realm
                .driver
                .bind_worker_epoll(Arc::clone(&poll.fd), index)?;
        }
        Ok(poll)
    }

    fn dispatch_events(&mut self, events: &[libc::epoll_event]) {
        for event in events {
            let token = event.u64;
            if token & epoll::TOKEN_DIRECT_BIT != 0 {
                let index = ((token & !epoll::TOKEN_DIRECT_BIT) >> 56) as usize;
                self.realms[index]
                    .driver
                    .direct_socket_ready(token, event.events);
            } else if token == epoll::TOKEN_TOPOLOGY {
                self.topology_readable = true;
            }
            // XSK events resume the same bounded RX, CQ and custody checks below.
        }
    }

    pub(super) fn sample_owner_pressure(&mut self, now: Instant) {
        if self.pressure.sample(
            now,
            self.core.as_ref(),
            self.waiting.len(),
            self.pending.len(),
            self.workers.peer_count(),
        ) {
            self.sample_queues();
        }
    }

    pub(super) fn service_policy_read(&mut self, read: PolicyRead<'_>) -> anyhow::Result<()> {
        let had_clock = self.polling.last_clock.is_some();
        self.polling.boundary(0, 0);
        let result = if self.polling.clock_requires_policy_recheck(had_clock) {
            self.policy_recheck = true;
            Ok(())
        } else {
            self.resolve(&read)
        };
        drop(read);
        self.observe_polling_round();
        result
    }
}

pub(super) fn run_active_epoll_loop(
    runtime: &mut Runtime,
    owner: &mut PacketEndpointOwner,
    shutdown: &crate::control::ShutdownIntent,
    poll: &WorkerEpoll,
    mut notification: Pin<&mut tokio::sync::futures::OwnedNotified>,
) -> anyhow::Result<Option<EndpointJoin>> {
    let waker = Waker::from(Arc::clone(&poll.wake));
    let cx = &mut Context::from_waker(&waker);
    let mut stop = pin!(shutdown.wait());
    let authority = runtime.core.as_ref().map(RoutedCore::authority);
    let mut reader = pin!(None);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; BATCH];
    loop {
        let mut turns = TurnBudget::native();
        while !turns.exhausted() {
            if poll.wake.is_pending() {
                poll.wake.drain()?;
            }
            if shutdown.requested() {
                return Ok(None);
            }
            let now = Instant::now();
            if !runtime.devices.is_empty() && now >= runtime.link_check_at {
                // Drain topology readiness before verifying link identity, even mid-turn.
                let count = poll.poll_nonblocking(&mut events)?;
                runtime.dispatch_events(&events[..count]);
            }
            runtime.sample_owner_pressure(now);
            if reader.is_none()
                && let Some(authority) = &authority
                && runtime.core_due(now)
            {
                reader.set(Some(authority.read_policy()));
            }
            let mut progress = runtime.service_turn(
                cx,
                shutdown,
                reader.is_some(),
                notification.as_mut(),
                &mut turns,
            )?;
            if let Poll::Ready(joined) = owner.poll_join_plane(cx) {
                return Ok(Some(joined));
            }
            if stop.as_mut().poll(cx).is_ready() {
                return Ok(None);
            }
            if !runtime.policy_recheck
                && let Some(future) = reader.as_mut().as_pin_mut()
                && let Poll::Ready(read) = future.poll(cx)
            {
                reader.set(None);
                runtime.service_policy_read(read)?;
                progress = true;
            }
            if std::mem::take(&mut runtime.policy_recheck) {
                reader.set(None);
                progress = true;
            }
            if !progress && !poll.wake.is_pending() {
                if runtime.polling.poll_change(notification.as_mut(), cx) {
                    runtime.workers.wake_worker(1);
                } else {
                    let now = Instant::now();
                    let count = poll.wait(
                        runtime.next_deadline(now, reader.is_none()),
                        now,
                        &mut events,
                    )?;
                    runtime.dispatch_events(&events[..count]);
                    break;
                }
            }
            let count = turns.poll_events(poll, &runtime.realms, &mut events)?;
            runtime.dispatch_events(&events[..count]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_probes_yield_at_the_epoll_turn_limit() {
        use std::io::Write as _;
        use std::os::unix::net::UnixStream;

        let (read, mut write) = UnixStream::pair().unwrap();
        let poll = WorkerEpoll::new(&MemoryBudget::new(1 << 20), 1).unwrap();
        poll.add_fd(read.as_raw_fd(), READ_EDGE, epoll::TOKEN_TOPOLOGY)
            .unwrap();
        write.write_all(&[1]).unwrap();
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
        let mut turns = TurnBudget::native();
        for _ in 1..epoll::MAX_CONSECUTIVE_TURNS {
            turns.charge();
            assert_eq!(turns.poll_events(&poll, &[], &mut events).unwrap(), 0);
        }
        turns.charge();
        assert!(turns.exhausted());
        assert_eq!(turns.poll_events(&poll, &[], &mut events).unwrap(), 1);
        let token = events[0].u64;
        assert_eq!(token, epoll::TOKEN_TOPOLOGY);
    }

    #[test]
    fn tokio_probes_do_not_inherit_the_native_turn_limit() {
        let mut turns = TurnBudget::tokio();
        assert_eq!(turns.limit, usize::MAX);
        assert!(!turns.poll_direct);
        for _ in 0..=epoll::MAX_CONSECUTIVE_TURNS {
            turns.charge();
            assert!(!turns.poll_due(&[]));
        }
    }
}

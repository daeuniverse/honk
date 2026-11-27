use super::*;
use std::sync::atomic::AtomicU64;

const WORK_CLOSED: usize = 1 << (usize::BITS - 1);

pub(super) struct Auxiliary {
    pub(super) root: Arc<MemoryBudget>,
    #[cfg(target_os = "linux")]
    prepared_mtu: u32,
    // Even stamps admit work. Closing sets the low bit; reopening always uses a new pair.
    stamp: AtomicU64,
    work: AtomicUsize,
    cancelled: Notify,
    pub(super) released: Notify,
    _memory: MemoryReservation,
}

impl Auxiliary {
    pub(super) fn close(&self) {
        self.work.fetch_or(WORK_CLOSED, Ordering::SeqCst);
        if self.stamp.fetch_or(1, Ordering::SeqCst) & 1 == 0 {
            self.cancelled.notify_waiters();
        }
    }
}

/// A queued or executing application operation from one binding. The last owner wakes drain.
#[derive(Debug)]
pub(in crate::control) struct AuxiliaryWork {
    scope: PacketScope,
    stamp: u64,
}

impl AuxiliaryWork {
    pub(in crate::control) fn is_active(&self) -> bool {
        self.scope.binding() == self.stamp
    }

    pub(in crate::control) async fn cancelled(&self) {
        let aux = self
            .scope
            .0
            .auxiliary
            .as_ref()
            .expect("auxiliary operation");
        let cancelled = aux.cancelled.notified();
        if self.is_active() {
            cancelled.await;
        }
    }
}

impl Clone for AuxiliaryWork {
    fn clone(&self) -> Self {
        let aux = self
            .scope
            .0
            .auxiliary
            .as_ref()
            .expect("auxiliary operation");
        aux.work.fetch_add(1, Ordering::SeqCst);
        Self {
            scope: self.scope.clone(),
            stamp: self.stamp,
        }
    }
}

impl Drop for AuxiliaryWork {
    fn drop(&mut self) {
        let aux = self
            .scope
            .0
            .auxiliary
            .as_ref()
            .expect("auxiliary operation");
        if aux.work.fetch_sub(1, Ordering::SeqCst) == WORK_CLOSED + 1 {
            aux.released.notify_one();
        }
    }
}

impl PacketScope {
    pub(in crate::control) fn is_auxiliary(&self) -> bool {
        self.0.auxiliary.is_some()
    }

    pub(crate) fn binding(&self) -> u64 {
        self.0
            .auxiliary
            .as_ref()
            .map_or(0, |aux| aux.stamp.load(Ordering::SeqCst))
    }

    pub(in crate::control) fn auxiliary_active(&self) -> bool {
        self.binding() & 1 == 0
    }

    pub(in crate::control) fn auxiliary_work(&self) -> io::Result<Option<AuxiliaryWork>> {
        let Some(aux) = &self.0.auxiliary else {
            return Ok(None);
        };
        let stamp = self.binding();
        if stamp & 1 != 0 {
            return Err(closed());
        }
        aux.work
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < WORK_CLOSED - 1).then(|| count + 1)
            })
            .map_err(|_| closed())?;
        let work = AuxiliaryWork {
            scope: self.clone(),
            stamp,
        };
        // The increment and this recheck straddle a possible close and even a complete rebind.
        if !work.is_active() {
            return Err(closed());
        }
        Ok(Some(work))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn auxiliary_budget(&self) -> Option<&Arc<MemoryBudget>> {
        self.is_auxiliary().then_some(&self.0.budget)
    }
}

#[cfg(target_os = "linux")]
const LIMITS: RuntimeLimits = RuntimeLimits {
    max_slots: 16,
    control_frames: 2,
    bulk_frames: 6,
    max_waiters: 32,
};

#[cfg(target_os = "linux")]
pub(super) fn config(mtu: u32, budget: &Arc<MemoryBudget>) -> io::Result<Config> {
    let mut cfg = Config::new(rand::random());
    cfg.mtu = u16::try_from(mtu)
        .ok()
        .filter(|&mtu| mtu >= 1280)
        .ok_or_else(|| invalid("auxiliary MTU outside 1280..=65535"))?;
    cfg.mode = Mode::Transparent {
        exclude: Default::default(),
    };
    cfg.max_flows = LIMITS.max_slots as u32;
    cfg.memory_limit = 512 << 10;
    cfg.fragment_limits.max_entries = 8;
    cfg.fragment_limits.max_bytes = 256 << 10;
    cfg.shared_budget = Some(Arc::clone(budget));
    Ok(cfg)
}

#[cfg(target_os = "linux")]
pub(crate) fn auxiliary_scope(
    mtu: u32,
    root: &Arc<MemoryBudget>,
) -> anyhow::Result<(PacketScope, PacketOwner)> {
    let budget = root.child(4 << 20).ok_or_else(capacity)?;
    let memory = budget
        .reserve(size_of::<Auxiliary>() + 2 * size_of::<usize>())
        .ok_or_else(capacity)?;
    let auxiliary = Arc::new(Auxiliary {
        root: Arc::clone(root),
        prepared_mtu: mtu,
        stamp: AtomicU64::new(1),
        work: AtomicUsize::new(WORK_CLOSED),
        cancelled: Notify::new(),
        released: Notify::new(),
        _memory: memory,
    });
    let scope = ScopeId::allocate().ok_or_else(|| invalid("scope identities exhausted"))?;
    Ok(PacketScope::new_partition(
        config(mtu, &budget)?,
        budget,
        LIMITS,
        Instant::now(),
        crate::tun::TX_CAPS,
        crate::tun::MAX_IP_BYTES,
        scope,
        0,
        1,
        None,
        false,
        Some(auxiliary),
    )?)
}

#[cfg(target_os = "linux")]
impl PacketDriver {
    pub(crate) fn is_returned(&self) -> bool {
        // The parked owner may already have reclaimed the returned right.
        let inner = self.scope.0.inner.lock();
        inner.finished && inner.rights != Rights::Driven
    }

    /// Terminal protocol return can precede the final application completion or waiter drop.
    pub(crate) async fn wait_auxiliary_work(&mut self) -> io::Result<()> {
        let shared = &self.scope.0;
        let aux = shared
            .auxiliary
            .as_ref()
            .ok_or_else(|| invalid("ordinary packet scope"))?;
        loop {
            let released = aux.released.notified();
            {
                let inner = shared.inner.lock();
                if !inner.finished || inner.rights == Rights::Driven {
                    return Err(invalid("packet driver has not returned"));
                }
                if inner.binding_drained() && aux.work.load(Ordering::SeqCst) == WORK_CLOSED {
                    break;
                }
            }
            released.await;
        }
        self.release_host_lookup();
        Ok(())
    }

    pub(in crate::control) fn begin_auxiliary_pause(&mut self) -> io::Result<()> {
        let shared = &self.scope.0;
        let aux = shared
            .auxiliary
            .as_ref()
            .ok_or_else(|| invalid("ordinary packet scope"))?;
        let mut inner = shared.inner.lock();
        if inner.closing || inner.rights != Rights::Driven {
            return Err(closed());
        }
        aux.close();
        inner.turn_needs_scan = None;
        inner.abort();
        let mut wakes = Shared::events(&mut inner, None);
        Shared::wake_terminal_waiters(&mut inner, WaitFor::Credit, &mut wakes);
        drop(inner);
        shared.reap();
        self.fallback = None;
        self.deadline = None;
        resume_wake_panic(wakes);
        Ok(())
    }

    pub(in crate::control) async fn drain_auxiliary(&mut self) -> io::Result<()> {
        let aux = Arc::clone(
            self.scope
                .0
                .auxiliary
                .as_ref()
                .ok_or_else(|| invalid("ordinary packet scope"))?,
        );
        loop {
            tokio::select! {
                result = poll_fn(|cx| {
                    self.service_closing(cx, Instant::now());
                    let inner = self.scope.0.inner.lock();
                    if inner.closing || inner.rights != Rights::Driven { return Poll::Ready(Err(closed())); }
                    if !inner.aborted { return Poll::Ready(Err(invalid("active auxiliary scope"))); }
                    if inner.binding_drained() && aux.work.load(Ordering::SeqCst) == WORK_CLOSED {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }) => { result?; break; },
                _ = aux.released.notified() => {},
            }
        }
        self.release_host_lookup();
        Ok(())
    }

    fn release_host_lookup(&self) {
        #[cfg(feature = "packet-ebpf")]
        {
            let mut inner = self.scope.0.inner.lock();
            if inner.finished {
                inner.host_process.take();
            } else if let Some(binding) = &mut inner.host_process {
                binding.release_lookup();
            }
        }
    }

    pub(in crate::control) fn resume_auxiliary(
        &mut self,
        mtu: u32,
        admit: impl FnOnce() -> bool,
    ) -> io::Result<()> {
        let shared = &self.scope.0;
        let aux = shared
            .auxiliary
            .as_ref()
            .ok_or_else(|| invalid("ordinary packet scope"))?;
        let mut inner = shared.inner.lock();
        if inner.closing || inner.rights != Rights::Driven {
            return Err(closed());
        }
        if !inner.aborted
            || !inner.binding_drained()
            || aux.work.load(Ordering::SeqCst) != WORK_CLOSED
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "auxiliary binding still owned",
            ));
        }
        let stamp = aux
            .stamp
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or_else(capacity)?;
        // Only the initially prepared, never-admitted Stack can still exist here.
        // Release it before allocating a different MTU against the same grant.
        let prepared = inner.stack.take().filter(|_| aux.prepared_mtu == mtu);
        let mut stack = match prepared {
            Some(stack) => stack,
            None => Stack::new_accounted(
                config(mtu, &shared.budget)?,
                Instant::now(),
                LIMITS.max_slots,
            )
            .map_err(io::Error::other)?,
        };
        if !admit() {
            return Err(closed());
        }
        stack.set_accepting(true);
        inner.stack = Some(stack);
        inner.pending_closes = 0;
        inner.reap_pending = false;
        inner.next_tx = TxClass::Control;
        inner.aborted = false;
        aux.stamp.store(stamp, Ordering::SeqCst);
        aux.work.store(0, Ordering::SeqCst);
        self.fallback = None;
        self.deadline = None;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Inner {
    pub(super) fn binding_drained(&self) -> bool {
        self.slots.iter().all(Option::is_none)
            && self.source_work.is_empty()
            && self.waiters.iter().all(Option::is_none)
            && self.queued == 0
            && self.ledger.outstanding_tx().next().is_none()
            && self.stack.as_ref().is_none_or(Stack::is_quiescent)
    }
}

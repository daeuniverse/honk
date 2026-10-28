use super::admission::{InitializingEndpoint, ReadyEndpoint};
use super::*;
use crate::control::task_registry::capacity_error;
use honk_netstack::{MemoryBudget, MemoryReservation};

pub(super) const MAP_SHARDS: usize = 16;
pub(super) const RECEIVE_BYTES: usize = 65_536;
pub(super) struct PoolMemory {
    pub(super) budget: Arc<MemoryBudget>,
    pub(super) slots: Arc<Semaphore>,
    pub(super) completed_tasks: Arc<AtomicUsize>,
    pub(super) source_tasks: TaskRegistry,
    pub(super) drivers: TaskRegistry,
    pub(super) slow_tasks: TaskRegistry,
    pub(super) maps: MemoryReservation,
}

impl PoolMemory {
    pub(super) fn new(capacity: usize, budget: Arc<MemoryBudget>) -> io::Result<Self> {
        if capacity == 0 || capacity > MAX_ENDPOINTS {
            return Err(capacity_error());
        }
        // Every shard can retain its independent high-water capacity after churn.
        let keyed = MAP_SHARDS
            * (size_of::<EndpointKey>()
                + size_of::<EndpointEntry>()
                + size_of::<SourceScope>()
                + size_of::<Arc<SourceOwner>>());
        let cached = (MAX_REPLY_SOCKETS_PER_ENDPOINT + 2)
            * (size_of::<ReplySocket>()
                + size_of::<SocketAddr>()
                + size_of::<ScopeId>()
                + size_of::<[usize; 8]>());
        let bytes = capacity
            .checked_mul(16 * (keyed + cached + size_of::<EndpointRemoval>() + 8))
            .and_then(|bytes| {
                bytes.checked_add(2 * MAP_SHARDS * 256 + size_of::<UdpEndpointPool>())
            })
            .ok_or_else(capacity_error)?;
        let maps = budget.reserve(bytes).ok_or_else(capacity_error)?;
        let completed_tasks = Arc::new(AtomicUsize::new(0));
        let source_tasks =
            TaskRegistry::with_completions(capacity, &budget, Some(Arc::clone(&completed_tasks)))?;
        let drivers =
            TaskRegistry::with_completions(capacity, &budget, Some(Arc::clone(&completed_tasks)))?;
        let slow_tasks = TaskRegistry::with_completions(
            capacity + 512,
            &budget,
            Some(Arc::clone(&completed_tasks)),
        )?;
        Ok(Self {
            slots: Arc::new(Semaphore::new(capacity)),
            budget,
            completed_tasks,
            source_tasks,
            drivers,
            slow_tasks,
            maps,
        })
    }
}

pub(super) struct EntryMemory {
    _slot: OwnedSemaphorePermit,
    _bytes: MemoryReservation,
}

impl UdpEndpointPool {
    pub(super) fn reserve_entry_memory(
        &self,
        name_bytes: usize,
    ) -> io::Result<Option<Arc<EntryMemory>>> {
        let Some(budget) = &self.memory_budget else {
            return Ok(None);
        };
        let slot = Arc::clone(self.metadata_slots.as_ref().expect("accounted entry slots"))
            .try_acquire_owned()
            .map_err(|_| capacity_error())?;
        let bytes = size_of::<InitializingEndpoint>()
            + size_of::<ReadyEndpoint>()
            + size_of::<UdpEndpoint>()
            + size_of::<RetirementIo>()
            + (FLOW_QUEUE_CAPACITY + 32) * size_of::<QueuedDatagram>()
            + 8 * (size_of::<EndpointRemoval>() + 64)
            + 16 * size_of::<Semaphore>();
        let bytes = bytes
            .checked_add(name_bytes.checked_mul(8).ok_or_else(capacity_error)?)
            .ok_or_else(capacity_error)?;
        let reservation = budget.reserve(bytes).ok_or_else(capacity_error)?;
        Ok(Some(Arc::new(EntryMemory {
            _slot: slot,
            _bytes: reservation,
        })))
    }

    pub(in crate::control) fn reap_tasks(&self) {
        if self
            .completed_tasks
            .as_ref()
            .is_none_or(|count| count.load(Ordering::Acquire) == 0)
        {
            return;
        }
        for registry in [&self.slow_tasks, &self.drivers, &self.source_tasks] {
            let mut registry = registry.lock();
            while let Some(result) = registry.try_join_next() {
                if let Err(error) = result
                    && !error.is_cancelled()
                {
                    debug!(%error, "UDP owned task failed");
                }
            }
        }
    }
}

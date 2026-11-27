use std::collections::HashMap;
use std::num::NonZeroU64;

use honk_ebpf_common::host::HostSourceFacts;
use honk_ebpf_common::{ROUTING_PROCESS_MAX_LEN, normalize_process_name};
use honk_netstack::SourceContext;

use super::*;

/// Copied, authenticated capture facts; expiry is consumed at scope admission.
#[derive(Clone, Copy, Debug)]
pub struct HostIngress {
    pub facts: HostSourceFacts,
    pub source_horizon: Instant,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SourceKey {
    netns: u64,
    attachment: u64,
    operation_incarnation: u64,
    cookie: u64,
    return_generation: u64,
    output_ifindex: u32,
}

impl From<&HostSourceFacts> for SourceKey {
    fn from(facts: &HostSourceFacts) -> Self {
        Self {
            netns: facts.netns_cookie,
            attachment: facts.attachment,
            cookie: facts.socket_cookie,
            operation_incarnation: facts.operation_incarnation,
            return_generation: facts.return_generation,
            output_ifindex: facts.output_ifindex,
        }
    }
}

struct Lineage {
    id: NonZeroU64,
    cells: usize,
}

struct HostSource {
    facts: HostSourceFacts,
    context: SourceContext,
    work: usize,
    outputs: usize,
}

struct SourceCell {
    generation: u64,
    retained: bool,
    entry: Option<HostSource>,
}

struct HostSources {
    cells: Box<[SourceCell]>,
    index_bits: u32,
    index_mask: u64,
    max_generation: u64,
    snapshots: HashMap<HostSourceFacts, SourceContext>,
    lineages: HashMap<SourceKey, Lineage>,
    next_lineage: u64,
}

enum SourceStorage {
    Plain(Box<[Option<(IpAddr, usize)>]>),
    Host {
        state: Box<HostSources>,
        _memory: MemoryReservation,
    },
}

pub(super) struct Sources {
    storage: SourceStorage,
}

impl Sources {
    pub(super) fn bytes(count: usize) -> Option<usize> {
        count.checked_mul(size_of::<Option<(IpAddr, usize)>>())
    }

    pub(super) fn new(count: usize) -> Self {
        Self {
            storage: SourceStorage::Plain((0..count).map(|_| None).collect()),
        }
    }

    pub(super) fn is_host(&self) -> bool {
        matches!(&self.storage, SourceStorage::Host { .. })
    }

    fn host(&self) -> Option<&HostSources> {
        match &self.storage {
            SourceStorage::Host { state, .. } => Some(state),
            SourceStorage::Plain(_) => None,
        }
    }

    fn host_mut(&mut self) -> Option<&mut HostSources> {
        match &mut self.storage {
            SourceStorage::Host { state, .. } => Some(state),
            SourceStorage::Plain(_) => None,
        }
    }

    fn prepare_host(&mut self, budget: &Arc<MemoryBudget>) -> io::Result<()> {
        let count = match &self.storage {
            SourceStorage::Plain(cells) if cells.iter().all(Option::is_none) => cells.len(),
            _ => return Err(invalid("source kind is already bound")),
        };
        if count == 0 || u32::try_from(count).is_err() {
            return Err(invalid("Host source cell count exceeds token domain"));
        }
        let count_u64 = u64::try_from(count).map_err(|_| capacity())?;
        let index_bits = u64::BITS - (count_u64 - 1).leading_zeros();
        let index_mask = 1u64
            .checked_shl(index_bits)
            .and_then(|bits| bits.checked_sub(1))
            .ok_or_else(capacity)?;
        let max_generation = u64::MAX.checked_shr(index_bits).ok_or_else(capacity)?;
        let index_capacity = count.checked_mul(2).ok_or_else(capacity)?;
        let buckets = index_capacity
            .max(4)
            .checked_next_power_of_two()
            .ok_or_else(capacity)?;
        // At most N live entries in 2N reserved capacity; the existing 3B bound covers cold backing.
        let map_bytes = buckets
            .checked_mul(
                size_of::<(HostSourceFacts, SourceContext)>()
                    + size_of::<(SourceKey, Lineage)>()
                    + 2,
            )
            .and_then(|n| n.checked_add(32))
            .and_then(|n| n.checked_mul(3))
            .ok_or_else(capacity)?;
        let bytes = count
            .checked_mul(size_of::<SourceCell>())
            .and_then(|n| n.checked_mul(2))
            .and_then(|n| n.checked_add(size_of::<HostSources>()))
            .and_then(|n| n.checked_add(map_bytes))
            .filter(|n| *n <= isize::MAX as usize)
            .ok_or_else(capacity)?;
        // The baseline reservation still covers Plain until the replacement frees it.
        let memory = budget.reserve(bytes).ok_or_else(capacity)?;
        let mut snapshots = HashMap::new();
        let mut lineages = HashMap::new();
        snapshots
            .try_reserve(index_capacity)
            .map_err(io::Error::other)?;
        lineages
            .try_reserve(index_capacity)
            .map_err(io::Error::other)?;
        let mut cells = Vec::new();
        cells.try_reserve_exact(count).map_err(io::Error::other)?;
        cells.resize_with(count, || SourceCell {
            generation: 1,
            retained: false,
            entry: None,
        });
        let host = HostSources {
            cells: cells.into_boxed_slice(),
            index_bits,
            index_mask,
            max_generation,
            snapshots,
            lineages,
            next_lineage: 1,
        };
        self.storage = SourceStorage::Host {
            state: Box::new(host),
            _memory: memory,
        };
        Ok(())
    }

    fn index(&self, context: SourceContext) -> Option<usize> {
        self.host()?.index(context)
    }

    fn get_mut(&mut self, context: SourceContext) -> Option<&mut HostSource> {
        self.host_mut()?.get_mut(context)
    }

    pub(super) fn facts(&self, context: SourceContext) -> Option<&HostSourceFacts> {
        self.host()?.get(context).map(|source| &source.facts)
    }

    fn intern(&mut self, facts: &HostSourceFacts) -> io::Result<SourceContext> {
        self.host_mut()
            .ok_or_else(|| invalid("scope has no Host source binding"))?
            .intern(facts)
    }

    fn known(&self, facts: &HostSourceFacts) -> Option<SourceContext> {
        self.host()?.snapshots.get(facts).copied()
    }

    fn has_vacant(&self) -> bool {
        self.host().is_some_and(|host| {
            host.cells
                .iter()
                .any(|cell| cell.entry.is_none() && cell.generation != 0)
        })
    }

    fn retain(&mut self, context: SourceContext) -> io::Result<()> {
        let source = self
            .get_mut(context)
            .ok_or_else(|| invalid("stale Host source"))?;
        source.work = source.work.checked_add(1).ok_or_else(capacity)?;
        Ok(())
    }

    pub(super) fn retain_output(&mut self, context: SourceContext) {
        let source = self.get_mut(context).expect("original emitted source");
        source.outputs = source
            .outputs
            .checked_add(1)
            .expect("bounded source outputs");
    }

    pub(super) fn release_output(&mut self, context: SourceContext) {
        let source = self.get_mut(context).expect("original output source");
        source.outputs = source
            .outputs
            .checked_sub(1)
            .expect("retained source output");
    }

    pub(super) fn retains_address(&self, address: IpAddr) -> bool {
        match &self.storage {
            SourceStorage::Plain(cells) => cells.iter().flatten().any(|(peer, _)| *peer == address),
            SourceStorage::Host { .. } => false,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        match &self.storage {
            SourceStorage::Plain(cells) => cells.iter().all(Option::is_none),
            SourceStorage::Host { state, .. } => {
                state.cells.iter().all(|cell| cell.entry.is_none())
            }
        }
    }

    fn hold_address(&mut self, address: IpAddr) -> io::Result<usize> {
        let SourceStorage::Plain(cells) = &mut self.storage else {
            return Err(invalid("Host source requires captured identity"));
        };
        let index = cells
            .iter()
            .position(|cell| cell.is_some_and(|(peer, _)| peer == address))
            .or_else(|| cells.iter().position(Option::is_none))
            .ok_or_else(capacity)?;
        let (_, work) = cells[index].get_or_insert((address, 0));
        *work = work.checked_add(1).ok_or_else(capacity)?;
        Ok(index)
    }

    fn retain_address(&mut self, index: usize) {
        let SourceStorage::Plain(cells) = &mut self.storage else {
            unreachable!("retained address source kind");
        };
        let (_, work) = cells[index].as_mut().expect("retained address work");
        *work = work.checked_add(1).expect("bounded address work");
    }

    fn release_address(&mut self, index: usize) -> bool {
        let SourceStorage::Plain(cells) = &mut self.storage else {
            unreachable!("retained address source kind");
        };
        let (_, work) = cells[index].as_mut().expect("retained address work");
        *work = work.checked_sub(1).expect("address work count");
        if *work == 0 {
            cells[index] = None;
        }
        cells[index].is_none()
    }

    pub(super) fn reclaim(
        &mut self,
        stack: Option<&Stack>,
        flows: &[Option<FlowSlot>],
    ) -> io::Result<()> {
        match &mut self.storage {
            SourceStorage::Host { state, .. } => state.reclaim(stack, flows),
            SourceStorage::Plain(_) => Ok(()),
        }
    }
}

impl HostSources {
    fn index(&self, context: SourceContext) -> Option<usize> {
        let index = usize::try_from(context.snapshot.get() & self.index_mask).ok()?;
        let cell = self.cells.get(index)?;
        if cell.generation != context.snapshot.get() >> self.index_bits {
            return None;
        }
        cell.entry
            .as_ref()
            .filter(|source| source.context == context)
            .map(|_| index)
    }

    fn get(&self, context: SourceContext) -> Option<&HostSource> {
        self.cells[self.index(context)?].entry.as_ref()
    }

    fn get_mut(&mut self, context: SourceContext) -> Option<&mut HostSource> {
        let index = self.index(context)?;
        self.cells[index].entry.as_mut()
    }

    fn intern(&mut self, facts: &HostSourceFacts) -> io::Result<SourceContext> {
        if let Some(context) = self.snapshots.get(facts) {
            return Ok(*context);
        }
        let index = self
            .cells
            .iter()
            .position(|cell| cell.entry.is_none() && cell.generation != 0)
            .ok_or_else(capacity)?;
        let key = SourceKey::from(facts);
        let lineage = if let Some(lineage) = self.lineages.get(&key) {
            lineage.id
        } else {
            let id = NonZeroU64::new(self.next_lineage).ok_or_else(capacity)?;
            self.next_lineage = self.next_lineage.checked_add(1).unwrap_or(0);
            id
        };
        let generation = self.cells[index].generation;
        if generation > self.max_generation {
            return Err(io::Error::other(
                "Host source generation exceeds token domain",
            ));
        }
        let snapshot = generation
            .checked_shl(self.index_bits)
            .and_then(|high| high.checked_add(index as u64))
            .and_then(NonZeroU64::new)
            .ok_or_else(capacity)?;
        let context = SourceContext { lineage, snapshot };
        self.lineages
            .entry(key)
            .and_modify(|entry| entry.cells += 1)
            .or_insert(Lineage {
                id: lineage,
                cells: 1,
            });
        self.snapshots.insert(*facts, context);
        self.cells[index].entry = Some(HostSource {
            facts: *facts,
            context,
            work: 0,
            outputs: 0,
        });
        Ok(context)
    }

    fn reclaim(&mut self, stack: Option<&Stack>, flows: &[Option<FlowSlot>]) -> io::Result<()> {
        for cell in &mut self.cells {
            cell.retained = false;
        }
        let mut valid = true;
        let mut mark = |context| {
            if let Some(index) = self.index(context) {
                self.cells[index].retained = true;
            } else {
                valid = false;
            }
        };
        if let Some(stack) = stack {
            stack.visit_retained_source_contexts(&mut mark);
        }
        for context in flows.iter().flatten().filter_map(|flow| flow.source) {
            mark(context);
        }
        if !valid {
            return Err(io::Error::other("retained Host source identity is missing"));
        }
        for cell in &mut self.cells {
            let Some(source) = &cell.entry else { continue };
            if cell.retained || source.work != 0 || source.outputs != 0 {
                continue;
            }
            let key = SourceKey::from(&source.facts);
            assert_eq!(self.snapshots.remove(&source.facts), Some(source.context));
            let lineage = self
                .lineages
                .get_mut(&key)
                .expect("retained source lineage");
            lineage.cells -= 1;
            if lineage.cells == 0 {
                self.lineages.remove(&key);
            }
            cell.entry = None;
            cell.generation = if cell.generation == self.max_generation {
                0
            } else {
                cell.generation + 1
            };
        }
        Ok(())
    }
}

impl Inner {
    fn intern_host_source(&mut self, facts: &HostSourceFacts) -> io::Result<SourceContext> {
        if !facts.is_valid() {
            return Err(invalid("incomplete Host source identity"));
        }
        if let Some(context) = self.source_work.known(facts) {
            return Ok(context);
        }
        if !self.source_work.has_vacant() {
            self.source_work.reclaim(self.stack.as_ref(), &self.slots)?;
        }
        self.source_work.intern(facts)
    }
}

impl PacketScope {
    /// Bind and fund authenticated Host intake before handing this scope to Endpoint.
    pub fn prepare_host(&self) -> io::Result<()> {
        self.0.with(|inner| {
            if self.is_auxiliary()
                || inner.endpoint_prepared
                || inner.closing
                || inner.finished
                || !inner.stack.as_ref().is_some_and(Stack::is_quiescent)
                || inner.slots.iter().any(Option::is_some)
                || inner.ledger.outstanding_tx().next().is_some()
            {
                return Err(invalid("Host source binding requires an unused scope"));
            }
            inner
                .stack
                .as_mut()
                .expect("unused scope stack")
                .prepare_source_context()
                .map_err(io::Error::other)?;
            inner.source_work.prepare_host(&self.0.budget)
        })
    }

    pub fn is_host(&self) -> bool {
        self.0.inner.lock().source_work.is_host()
    }

    pub(in crate::control) fn hold_host_source(
        &self,
        facts: &HostSourceFacts,
    ) -> io::Result<SourceWork> {
        let mut inner = self.0.inner.lock();
        if inner.closing || inner.finished {
            return Err(closed());
        }
        let context = inner.intern_host_source(facts)?;
        SourceWork::retained(self, &mut inner.source_work, context)
    }

    pub(in crate::control) fn hold_source(&self, address: IpAddr) -> io::Result<SourceWork> {
        self.0.with(|inner| {
            let work = SourceWork::plain(self, inner, address)?;
            #[cfg(target_os = "linux")]
            if let Some(peer) = inner
                .peers
                .iter()
                .flatten()
                .find(|peer| peer.address() == address)
            {
                return Ok(work.with_peer(peer.clone()));
            }
            Ok(work)
        })
    }

    pub(in crate::control) fn datagram_sender_for(
        &self,
        source: SocketAddr,
        source_work: SourceWork,
    ) -> io::Result<DatagramSender> {
        if !self.same_owner(&source_work.scope) {
            return Err(invalid("reply source belongs to another packet owner"));
        }
        Ok(DatagramSender {
            scope: self.clone(),
            binding: self.binding(),
            source,
            packet_source: Some(source_work),
            realm: None,
        })
    }
}

/// Immutable routing input. Only the TUN source path separately carries a SourceContext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::control) struct ProcessMeta {
    pub(in crate::control) pid: u32,
    pname: [u8; ROUTING_PROCESS_MAX_LEN],
    pname_len: u8,
}

impl Default for ProcessMeta {
    fn default() -> Self {
        Self {
            pid: 0,
            pname: [0; ROUTING_PROCESS_MAX_LEN],
            pname_len: 0,
        }
    }
}

impl ProcessMeta {
    pub(in crate::control) fn from_facts(facts: &HostSourceFacts) -> Self {
        if facts.flags & honk_ebpf_common::host::HOST_PROCESS_PRESENT == 0 {
            return Self::default();
        }
        let mut pname = [0; ROUTING_PROCESS_MAX_LEN];
        let pname_len = normalize_process_name(&facts.pname, &mut pname) as u8;
        Self {
            pid: facts.pid,
            pname,
            pname_len,
        }
    }

    #[cfg(any(test, all(target_os = "linux", feature = "packet-ebpf")))]
    pub(super) fn from_gateway(
        meta: honk_ebpf_common::xdp_gateway::HostFlowMeta,
    ) -> io::Result<Self> {
        let bytes = meta
            .pname
            .get(..usize::from(meta.pname_len))
            .ok_or_else(|| invalid("invalid Host process name length"))?;
        let name =
            std::str::from_utf8(bytes).map_err(|_| invalid("invalid Host process name UTF-8"))?;
        if name.contains('\0') || name.trim() != name {
            return Err(invalid("unnormalized Host process name"));
        }
        Ok(Self {
            pid: meta.pid,
            pname: meta.pname,
            pname_len: meta.pname_len,
        })
    }

    #[cfg(test)]
    pub(in crate::control) fn test_gateway(pid: u32, name: &str) -> Self {
        let mut meta = honk_ebpf_common::xdp_gateway::HostFlowMeta {
            pid,
            pname: [b'X'; ROUTING_PROCESS_MAX_LEN],
            pname_len: u8::try_from(name.len()).unwrap(),
            ..Default::default()
        };
        meta.pname[..name.len()].copy_from_slice(name.as_bytes());
        Self::from_gateway(meta).unwrap()
    }

    pub(in crate::control) fn name(&self) -> Option<String> {
        let bytes = &self.pname[..usize::from(self.pname_len)];
        (!bytes.is_empty()).then(|| {
            std::str::from_utf8(bytes)
                .expect("normalized process name")
                .to_owned()
        })
    }
}

#[derive(Clone, Debug)]
enum SourceOrigin {
    Plain,
    #[cfg(target_os = "linux")]
    Physical(crate::xdp::worker::PeerHold),
    #[cfg(any(test, all(target_os = "linux", feature = "packet-ebpf")))]
    Gateway {
        process: ProcessMeta,
        #[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
        slot: Option<u16>,
    },
}

#[derive(Debug)]
pub(in crate::control) struct SourceWork {
    scope: PacketScope,
    index: usize,
    origin: SourceOrigin,
    context: Option<SourceContext>,
}

impl SourceWork {
    #[cfg(test)]
    pub(in crate::control) fn with_process_input(mut self, process: ProcessMeta) -> Self {
        assert!(matches!(self.origin, SourceOrigin::Plain) && self.context.is_none());
        self.origin = SourceOrigin::Gateway {
            process,
            #[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
            slot: None,
        };
        self
    }

    pub(in crate::control) fn has_gateway_process(&self) -> bool {
        self.gateway_process().is_some()
    }

    fn gateway_process(&self) -> Option<&ProcessMeta> {
        #[cfg(any(test, all(target_os = "linux", feature = "packet-ebpf")))]
        if let SourceOrigin::Gateway { process, .. } = &self.origin {
            return Some(process);
        }
        None
    }

    #[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
    fn host_udp_slot(&self) -> Option<u16> {
        match &self.origin {
            SourceOrigin::Gateway { slot, .. } => *slot,
            _ => None,
        }
    }

    /// Shared reply delivery owns the binding and address. Only views own a Host flow's process.
    pub(in crate::control) fn into_shared_reply_source(mut self) -> Self {
        if !self.has_gateway_process() {
            return self;
        }
        #[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
        if let Some(index) = self.host_udp_slot() {
            self.scope
                .0
                .inner
                .lock()
                .host_process
                .as_mut()
                .expect("owned Host binding")
                .udp
                .release(index);
        }
        self.origin = SourceOrigin::Plain;
        self
    }

    #[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
    pub(in crate::control) fn admit_udp_process(
        &mut self,
        client: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<()> {
        if !self.scope.is_auxiliary() {
            return Ok(());
        }
        let mut inner = self.scope.0.inner.lock();
        let closed_binding = inner.aborted || inner.closing;
        let Some(binding) = &mut inner.host_process else {
            return Ok(());
        };
        if closed_binding {
            return Err(closed());
        }
        if let Some(index) = self.host_udp_slot() {
            return if binding.udp.owns(index, client, destination) {
                Ok(())
            } else {
                Err(invalid("gateway Host UDP input belongs to another tuple"))
            };
        }
        if !matches!(self.origin, SourceOrigin::Plain) || self.context.is_some() {
            return Err(invalid(
                "gateway Host cannot replace an admitted packet source",
            ));
        }
        let (index, process) = binding.udp_input(
            self.scope.binding(),
            client,
            destination,
            &self.scope.0.budget,
        )?;
        self.origin = SourceOrigin::Gateway {
            process,
            slot: Some(index),
        };
        Ok(())
    }

    pub(super) fn plain(
        scope: &PacketScope,
        inner: &mut Inner,
        address: IpAddr,
    ) -> io::Result<Self> {
        if inner.closing || inner.aborted || inner.finished {
            return Err(closed());
        }
        Ok(Self {
            index: inner.source_work.hold_address(address)?,
            origin: SourceOrigin::Plain,
            scope: scope.clone(),
            context: None,
        })
    }

    pub(super) fn retained(
        scope: &PacketScope,
        sources: &mut Sources,
        context: SourceContext,
    ) -> io::Result<Self> {
        sources.retain(context)?;
        Ok(Self {
            scope: scope.clone(),
            index: sources.index(context).expect("retained source"),
            origin: SourceOrigin::Plain,
            context: Some(context),
        })
    }

    pub(in crate::control) fn scope(&self) -> ScopeId {
        self.scope.scope()
    }
    pub(in crate::control) fn owner(&self) -> &PacketScope {
        &self.scope
    }
    #[cfg(feature = "native-api")]
    pub(in crate::control) fn memory_budget(&self) -> &Arc<MemoryBudget> {
        &self.scope.0.budget
    }
    pub(in crate::control) fn optional_context(&self) -> Option<SourceContext> {
        self.context
    }
    pub(in crate::control) fn source_mac(&self) -> Option<[u8; 6]> {
        #[cfg(target_os = "linux")]
        {
            self.peer().map(|peer| peer.original_path().mac)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
    pub(in crate::control) fn plain_address(&self) -> Option<IpAddr> {
        if self.context.is_some() {
            return None;
        }
        #[cfg(target_os = "linux")]
        if let Some(peer) = self.peer() {
            return Some(peer.address());
        }
        let inner = self.scope.0.inner.lock();
        match &inner.source_work.storage {
            SourceStorage::Plain(cells) => cells[self.index].map(|(address, _)| address),
            SourceStorage::Host { .. } => None,
        }
    }
    pub(in crate::control) fn packet_input(&self) -> Option<(ProcessMeta, Option<u32>)> {
        self.gateway_process()
            .map(|process| (*process, None))
            .or_else(|| {
                self.optional_facts()
                    .map(|facts| (ProcessMeta::from_facts(&facts), Some(facts.skb_mark)))
            })
    }

    pub(in crate::control) fn optional_facts(&self) -> Option<HostSourceFacts> {
        self.context.map(|_| self.facts())
    }
    pub(in crate::control) fn identity(&self) -> (usize, usize, Option<SourceContext>) {
        (
            Arc::as_ptr(&self.scope.0) as usize,
            self.index,
            self.context,
        )
    }
    #[cfg(target_os = "linux")]
    pub(in crate::control) fn with_peer(mut self, peer: crate::xdp::worker::PeerHold) -> Self {
        // A peer observation never supersedes previously admitted process or return authority.
        if self.context.is_none() && matches!(self.origin, SourceOrigin::Plain) {
            self.origin = SourceOrigin::Physical(peer);
        }
        self
    }
    #[cfg(target_os = "linux")]
    pub(super) fn peer(&self) -> Option<&crate::xdp::worker::PeerHold> {
        match &self.origin {
            SourceOrigin::Physical(peer) => Some(peer),
            _ => None,
        }
    }
    pub(in crate::control) fn context(&self) -> SourceContext {
        self.context.expect("Host source context")
    }
    pub(in crate::control) fn facts(&self) -> HostSourceFacts {
        *self
            .scope
            .0
            .inner
            .lock()
            .source_work
            .facts(self.context())
            .expect("owned Host facts")
    }
}

impl Clone for SourceWork {
    fn clone(&self) -> Self {
        let mut inner = self.scope.0.inner.lock();
        #[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
        if let Some(index) = self.host_udp_slot() {
            inner
                .host_process
                .as_mut()
                .expect("owned Host binding")
                .udp
                .retain(index);
        }
        if let Some(context) = self.context {
            inner
                .source_work
                .retain(context)
                .expect("bounded retained source work");
        } else {
            inner.source_work.retain_address(self.index);
        }
        Self {
            scope: self.scope.clone(),
            index: self.index,
            context: self.context,
            origin: self.origin.clone(),
        }
    }
}

impl Drop for SourceWork {
    fn drop(&mut self) {
        let device = {
            let mut inner = self.scope.0.inner.lock();
            #[cfg(all(target_os = "linux", feature = "packet-ebpf"))]
            if let Some(index) = self.host_udp_slot() {
                inner
                    .host_process
                    .as_mut()
                    .expect("owned Host binding")
                    .udp
                    .release(index);
            }
            let last = if let Some(context) = self.context {
                let source = inner
                    .source_work
                    .get_mut(context)
                    .expect("retained source work");
                source.work = source.work.checked_sub(1).expect("source work count");
                source.work == 0
            } else {
                inner.source_work.release_address(self.index)
            };
            last.then(|| inner.device_wake())
        };
        if let Some(device) = device {
            self.scope.0.wake_owner(device);
        }
    }
}

impl PacketScope {
    #[cfg(test)]
    pub(in crate::control) fn receive_host_with_source(
        &self,
        input: (&[u8], RxMeta),
        packet_now: Instant,
        ingress: &HostIngress,
        admission: &mut Option<super::super::packet_endpoint::EndpointAdmission>,
        check_output: bool,
        on_source: impl FnMut(
            honk_netstack::ValidatedSource,
            SourceContext,
            &HostSourceFacts,
            bool,
        ) -> bool,
    ) -> io::Result<(
        Rx,
        super::super::packet_endpoint::PacketReceive,
        Option<SourceWork>,
    )> {
        let result = self.receive_host_deferred_with_source(
            input,
            packet_now,
            ingress,
            admission,
            check_output,
            on_source,
        );
        self.after_receive();
        result
    }

    /// The callback holds the scope mutex: it must not re-enter scope/source handles or do I/O.
    pub(in crate::control) fn receive_host_deferred_with_source(
        &self,
        (packet, meta): (&[u8], RxMeta),
        packet_now: Instant,
        ingress: &HostIngress,
        admission: &mut Option<super::super::packet_endpoint::EndpointAdmission>,
        check_output: bool,
        mut on_source: impl FnMut(
            honk_netstack::ValidatedSource,
            SourceContext,
            &HostSourceFacts,
            bool,
        ) -> bool,
    ) -> io::Result<(
        Rx,
        super::super::packet_endpoint::PacketReceive,
        Option<SourceWork>,
    )> {
        self.0.with_silent(|inner| {
            if !inner.source_work.is_host() {
                return Err(invalid("scope does not own Host capture"));
            }
            if inner.finished || inner.aborted || inner.stack.is_none() {
                return Err(closed());
            }
            if Instant::now() >= ingress.source_horizon {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Host capture receipt expired",
                ));
            }
            let context = inner.intern_host_source(&ingress.facts)?;
            let expected = admission
                .as_ref()
                .and_then(|admission| admission.source_context());
            let pending = check_output
                && (inner.stack.as_ref().is_some_and(|stack| {
                    stack.retains_source_output_with_lineage(context.lineage)
                }) || inner.queue.iter().flatten().any(|queued| {
                    queued
                        .tx
                        .source
                        .is_some_and(|source| source.lineage == context.lineage)
                }));
            let sources = &inner.source_work;
            let (rx, report) = inner.stack.as_mut().expect("live scope").receive_reported(
                packet,
                ReceiveOptions::new(packet_now, meta).with_context(context),
                |source, effective| {
                    let effective = effective.expect("contextual input retains its source");
                    expected.is_none_or(|expected| expected == effective)
                        && on_source(
                            source,
                            effective,
                            sources
                                .facts(effective)
                                .expect("retained completed Host facts"),
                            pending,
                        )
                },
            );
            inner.register_tcp_new(&report, admission, None);
            let retained = if matches!(&rx, Rx::TransparentOwned { .. }) {
                Some(SourceWork::retained(
                    self,
                    &mut inner.source_work,
                    report
                        .source_context
                        .expect("completed Host datagram context"),
                )?)
            } else {
                None
            };
            Ok((rx, inner.receive_result(report), retained))
        })
    }

    pub(in crate::control) fn retains_tcp_with_lineage(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        lineage: Option<NonZeroU64>,
    ) -> bool {
        self.0
            .inner
            .lock()
            .retains_tcp_with_lineage(source, destination, lineage)
    }
}

impl Inner {
    pub(super) fn retains_tcp_with_lineage(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        lineage: Option<NonZeroU64>,
    ) -> bool {
        if let Some(retained) = self
            .resources
            .as_ref()
            .and_then(|r| r.retains_tcp_on(self.worker, source, destination))
        {
            return lineage.is_none() && retained;
        }
        self.stack
            .as_ref()
            .is_some_and(|stack| stack.retains_tcp_with_lineage(source, destination, lineage))
            || self.slots.iter().flatten().any(|slot| {
                slot.client == source
                    && slot.destination == destination
                    && slot.source.map(|source| source.lineage) == lineage
            })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod mac_tests {
    use super::*;
    use crate::xdp::routing_input::test_peer;

    #[tokio::test]
    async fn source_mac_uses_retained_peer_and_host_tun_remain_missing() {
        let budget = MemoryBudget::new(CAPTURE_MEMORY);
        let (scope, owner) = capture_scope(1280, 1, 16, &budget).unwrap();
        let work = scope.hold_source("192.0.2.1".parse().unwrap()).unwrap();
        assert_eq!(work.source_mac(), None);
        let work = work.with_peer(test_peer(1, 0, [2; 6], 7));
        let cloned = work.clone();
        assert_eq!(work.source_mac(), Some([2; 6]));
        let changed = scope
            .hold_source("192.0.2.1".parse().unwrap())
            .unwrap()
            .with_peer(test_peer(1, 1, [4; 6], 7));
        assert_eq!(cloned.source_mac(), Some([2; 6]));
        assert_eq!(changed.source_mac(), Some([4; 6]));
        drop((work, cloned, changed));
        owner.shutdown().await;

        let mut config = Config::new([37; 32]);
        config.mode = Mode::Transparent {
            exclude: honk_netstack::ExcludeSet::default(),
        };
        let (scope, owner) =
            PacketScope::new(config, budget, RuntimeLimits::default(), Instant::now()).unwrap();
        scope.prepare_host().unwrap();
        let facts = HostSourceFacts {
            netns_cookie: 7,
            attachment: 11,
            socket_cookie: 29,
            return_generation: 13,
            output_ifindex: 19,
            flags: 1,
            stage: 1,
            family: 2,
            operation_incarnation: 23,
            ..Default::default()
        };
        let work = scope.hold_host_source(&facts).unwrap();
        assert_eq!(work.source_mac(), None);
        drop(work);
        owner.shutdown().await;
    }
}

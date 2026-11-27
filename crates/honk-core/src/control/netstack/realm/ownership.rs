use super::*;
use parking_lot::RwLock;

const END: usize = usize::MAX;
type Tuple = (SocketAddr, SocketAddr);

pub(super) fn canonical(source: SocketAddr, destination: SocketAddr) -> Tuple {
    (
        SocketAddr::new(source.ip().to_canonical(), source.port()),
        SocketAddr::new(destination.ip().to_canonical(), destination.port()),
    )
}

struct Entry {
    tuple: Tuple,
    worker: usize,
    flow: Option<FlowId>,
    claims: usize,
}

struct Cell {
    next: usize,
    entry: Option<Entry>,
}

struct Shard {
    buckets: Box<[usize]>,
    cells: Box<[Cell]>,
    free: usize,
}

impl Shard {
    fn new(count: usize) -> Self {
        let cells = (0..count)
            .map(|index| Cell {
                next: if index + 1 == count { END } else { index + 1 },
                entry: None,
            })
            .collect();
        Self {
            buckets: vec![END; count].into_boxed_slice(),
            cells,
            free: 0,
        }
    }

    fn find(&self, bucket: usize, tuple: Tuple, matches: impl Fn(&Entry) -> bool) -> Option<usize> {
        let mut index = self.buckets[bucket];
        while index != END {
            let cell = &self.cells[index];
            let entry = cell.entry.as_ref().expect("occupied ownership bucket");
            if entry.tuple == tuple && matches(entry) {
                return Some(index);
            }
            index = cell.next;
        }
        None
    }

    fn insert(&mut self, bucket: usize, tuple: Tuple, worker: usize) -> usize {
        let index = self.free;
        let cell = &mut self.cells[index];
        self.free = cell.next;
        cell.next = self.buckets[bucket];
        self.buckets[bucket] = index;
        cell.entry = Some(Entry {
            tuple,
            worker,
            flow: None,
            claims: 0,
        });
        index
    }

    fn remove_if_unused(&mut self, bucket: usize, index: usize) {
        if self.cells[index]
            .entry
            .as_ref()
            .is_some_and(|entry| entry.claims != 0 || entry.flow.is_some())
        {
            return;
        }
        let next = self.cells[index].next;
        let mut previous = self.buckets[bucket];
        if previous == index {
            self.buckets[bucket] = next;
        } else {
            while self.cells[previous].next != index {
                previous = self.cells[previous].next;
            }
            self.cells[previous].next = next;
        }
        self.cells[index] = Cell {
            next: self.free,
            entry: None,
        };
        self.free = index;
    }
}

pub(super) struct OwnershipDir {
    placement: RandomState,
    shards: [RwLock<Shard>; 2],
    per_shard: usize,
    workers: usize,
    full: std::sync::atomic::AtomicU64,
}

impl OwnershipDir {
    pub(super) fn bytes(count: usize) -> Option<usize> {
        count.checked_mul(size_of::<Cell>() + size_of::<usize>())
    }

    pub(super) fn new(count: usize, workers: usize) -> Self {
        assert!((1..=2).contains(&workers) && count.is_multiple_of(workers));
        let per_shard = count / workers;
        Self {
            placement: RandomState::new(),
            shards: std::array::from_fn(|worker| {
                RwLock::new(Shard::new(if worker < workers { per_shard } else { 0 }))
            }),
            per_shard,
            workers,
            full: 0.into(),
        }
    }

    fn location(&self, tuple: Tuple) -> (usize, usize) {
        let hash = self.placement.hash_one(tuple) as usize;
        (hash % self.workers, (hash / self.workers) % self.per_shard)
    }

    fn owner(&self, tuple: Tuple, published: bool) -> Option<usize> {
        let (home, bucket) = self.location(tuple);
        let lookup = |shard: &Shard| {
            let index = shard.find(bucket, tuple, |entry| !published || entry.flow.is_some())?;
            Some(shard.cells[index].entry.as_ref().unwrap().worker)
        };
        let local = lookup(&self.shards[home].read());
        if local.is_some() || self.workers == 1 {
            return local;
        }
        // During TIME_WAIT reuse the replacement can enter the home shard before an
        // overflow incarnation retires. Take a coherent snapshot on the spill path.
        let shards = [self.shards[0].read(), self.shards[1].read()];
        lookup(&shards[home]).or_else(|| lookup(&shards[1 - home]))
    }

    fn retains_source(&self, worker: Option<usize>, address: IpAddr) -> bool {
        let address = address.to_canonical();
        let retains = |shard: &Shard| {
            shard.cells.iter().any(|cell| {
                cell.entry.as_ref().is_some_and(|entry| {
                    entry.flow.is_some()
                        && entry.tuple.0.ip() == address
                        && worker.is_none_or(|worker| entry.worker == worker)
                })
            })
        };
        if self.workers == 1 {
            return retains(&self.shards[0].read());
        }
        let shards = [self.shards[0].read(), self.shards[1].read()];
        shards.iter().any(|shard| retains(shard))
    }

    fn claim(
        &self,
        resources: &Arc<RealmResources>,
        local: usize,
        tuple: Tuple,
        admission: bool,
    ) -> io::Result<(usize, TcpClaim)> {
        let (home, bucket) = self.location(tuple);
        if self.workers == 1 {
            let mut shard = self.shards[0].write();
            if shard.free == END {
                return Err(self.refuse());
            }
            let index = shard.insert(bucket, tuple, 0);
            shard.cells[index].entry.as_mut().unwrap().claims = 1;
            return Ok((
                0,
                TcpClaim {
                    resources: Arc::clone(resources),
                    location: ClaimLocation::Directory { which: 0, bucket },
                    index,
                },
            ));
        }
        // A home bucket can overflow into the other shard. Serialize first reservation
        // and replacement in the same lock order, without reading either worker's Stack.
        let mut shards = [self.shards[0].write(), self.shards[1].write()];
        let mut target = None;
        let mut owner = local;
        for which in [home, 1 - home] {
            let shard = &shards[which];
            if let Some(index) = shard.find(bucket, tuple, |_| true) {
                owner = shard.cells[index].entry.as_ref().unwrap().worker;
                if admission && owner != local {
                    return Err(invalid("TCP admission on foreign worker"));
                }
                if !admission {
                    target = Some((which, index));
                    break;
                }
                if let Some(pending) = shard.find(bucket, tuple, |entry| entry.flow.is_none()) {
                    target = Some((which, pending));
                    break;
                }
            }
        }
        let (which, index) = match target {
            Some(target) => target,
            None => {
                let which = [home, 1 - home]
                    .into_iter()
                    .find(|&which| shards[which].free != END)
                    .ok_or_else(|| self.refuse())?;
                (which, shards[which].insert(bucket, tuple, owner))
            }
        };
        shards[which].cells[index].entry.as_mut().unwrap().claims += 1;
        Ok((
            owner,
            TcpClaim {
                resources: Arc::clone(resources),
                location: ClaimLocation::Directory { which, bucket },
                index,
            },
        ))
    }

    fn refuse(&self) -> io::Error {
        self.full.fetch_add(1, Ordering::Relaxed);
        capacity()
    }

    fn retire(&self, worker: usize, tuple: Tuple, id: FlowId) {
        let (home, bucket) = self.location(tuple);
        for which in [home, 1 - home].into_iter().take(self.workers) {
            let mut shard = self.shards[which].write();
            if let Some(index) = shard.find(bucket, tuple, |entry| {
                entry.worker == worker && entry.flow == Some(id)
            }) {
                shard.cells[index].entry.as_mut().unwrap().flow = None;
                shard.remove_if_unused(bucket, index);
                return;
            }
        }
    }
}

enum ClaimLocation {
    Directory { which: usize, bucket: usize },
    Shared,
}

pub(crate) struct TcpClaim {
    resources: Arc<RealmResources>,
    location: ClaimLocation,
    index: usize,
}

impl TcpClaim {
    pub(in crate::control::netstack) fn publish(self, id: FlowId) {
        let ClaimLocation::Directory { which, .. } = self.location else {
            unreachable!("only local admissions publish")
        };
        let dir = self.resources.directory.as_ref().unwrap();
        let mut shard = dir.shards[which].write();
        let entry = shard.cells[self.index]
            .entry
            .as_mut()
            .expect("live TCP reservation");
        assert!(entry.flow.replace(id).is_none());
    }
}

impl Drop for TcpClaim {
    fn drop(&mut self) {
        let ClaimLocation::Directory { which, bucket } = self.location else {
            let mut state = self.resources.half_open.lock();
            let cell = &mut state.claims[self.index];
            let claim = cell.as_mut().expect("live shared dispatch claim");
            claim.users -= 1;
            if claim.users == 0 {
                *cell = None;
            }
            return;
        };
        let dir = self.resources.directory.as_ref().unwrap();
        let mut shard = dir.shards[which].write();
        let entry = shard.cells[self.index]
            .entry
            .as_mut()
            .expect("live TCP reservation");
        entry.claims -= 1;
        shard.remove_if_unused(bucket, self.index);
    }
}

impl RealmResources {
    pub(in crate::control::netstack) fn tracks_tcp(&self) -> bool {
        self.directory.is_some()
    }

    pub(in crate::control::netstack) fn retains_tcp_source_on(
        &self,
        worker: usize,
        address: IpAddr,
    ) -> bool {
        self.directory
            .as_ref()
            .is_some_and(|dir| dir.retains_source(Some(worker), address))
    }

    pub(in crate::control::netstack) fn retains_tcp_on(
        &self,
        worker: usize,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Option<bool> {
        Some(
            self.directory
                .as_ref()?
                .owner(canonical(source, destination), true)
                == Some(worker),
        )
    }
    pub(in crate::control::netstack) fn reserve_tcp(
        self: &Arc<Self>,
        worker: usize,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<Option<TcpClaim>> {
        self.directory
            .as_ref()
            .map(|dir| {
                dir.claim(self, worker, canonical(source, destination), true)
                    .map(|(_, claim)| claim)
            })
            .transpose()
    }

    pub(in crate::control::netstack) fn retire_tcp(
        &self,
        worker: usize,
        id: FlowId,
        source: SocketAddr,
        destination: SocketAddr,
    ) {
        if let Some(dir) = &self.directory {
            dir.retire(worker, canonical(source, destination), id);
        }
    }
}

impl PacketRealm {
    pub(crate) fn tracks_tcp(&self) -> bool {
        self.0.affinity.as_ref().is_some_and(|r| r.tracks_tcp())
    }

    pub(crate) fn retained_affine_worker(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Option<usize> {
        if self.tracks_tcp() {
            self.tcp_directory_owner(source, destination, true)
        } else {
            self.owners()
                .iter()
                .position(|owner| owner.retains_tcp(source, destination))
        }
    }

    fn shared_dispatch(
        &self,
        resources: &Arc<RealmResources>,
        local: usize,
        tuple: Tuple,
    ) -> io::Result<(usize, Option<TcpClaim>)> {
        let mut state = resources.half_open.lock();
        let index = state
            .claims
            .iter()
            .position(|cell| cell.as_ref().is_some_and(|entry| entry.tuple == tuple))
            .or_else(|| state.claims.iter().position(Option::is_none))
            .ok_or_else(capacity)?;
        let entry = state.claims[index].get_or_insert(SharedClaim {
            tuple,
            preferred: local,
            worker: None,
            users: 0,
        });
        entry.users += 1;
        let claim = TcpClaim {
            resources: Arc::clone(resources),
            location: ClaimLocation::Shared,
            index,
        };
        if let Some(worker) = entry.worker {
            return Ok((worker, Some(claim)));
        }
        let preferred = entry.preferred;
        drop(state);
        // Shared embeddings receive under the scope mutex and then take half_open.
        // This temporary dispatch pin keeps the cell stable across the reverse lookup.
        let worker = if self.owners()[preferred].retains_tcp(tuple.0, tuple.1)
            || !self.owners()[1 - preferred].retains_tcp(tuple.0, tuple.1)
        {
            preferred
        } else {
            1 - preferred
        };
        let mut state = resources.half_open.lock();
        let entry = state.claims[index]
            .as_mut()
            .expect("live shared dispatch claim");
        Ok((*entry.worker.get_or_insert(worker), Some(claim)))
    }
    pub(crate) fn tcp_directory_owner(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        published: bool,
    ) -> Option<usize> {
        self.0
            .affinity
            .as_ref()?
            .directory
            .as_ref()?
            .owner(canonical(source, destination), published)
    }

    pub(crate) fn tcp_directory_retains_source(&self, address: IpAddr) -> bool {
        self.0
            .affinity
            .as_ref()
            .and_then(|r| r.directory.as_ref())
            .is_some_and(|dir| dir.retains_source(None, address))
    }

    pub(crate) fn ownership_dir_full(&self) -> u64 {
        self.0
            .affinity
            .as_ref()
            .and_then(|r| r.directory.as_ref())
            .map_or(0, |dir| dir.full.load(Ordering::Relaxed))
    }

    pub(crate) fn tcp_dispatch(
        &self,
        local: usize,
        source: SocketAddr,
        destination: SocketAddr,
        syn: bool,
    ) -> io::Result<(usize, Option<TcpClaim>)> {
        if self.owners().len() == 1 {
            return Ok((0, None));
        }
        let Some(resources) = &self.0.affinity else {
            return Ok((self.worker_for_tcp(source, destination), None));
        };
        let tuple = canonical(source, destination);
        let Some(dir) = &resources.directory else {
            return self.shared_dispatch(resources, local, tuple);
        };
        if syn {
            dir.claim(resources, local, tuple, false)
                .map(|(worker, claim)| (worker, Some(claim)))
        } else {
            Ok((dir.owner(tuple, false).unwrap_or(local), None))
        }
    }
}

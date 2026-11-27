use super::scan::{Cursor, INITIAL_BATCH};
use super::*;

#[derive(Default)]
enum Table {
    #[default]
    Roots,
    Holds,
    Tcp,
    Fragments,
}

/// Only already-closed bindings share this workspace. Any retiring owner can advance
/// the head of the FIFO, including when its original caller has not yet run again.
#[derive(Default)]
pub(super) struct Cleanup {
    queue: [Option<(HostBindingKey, Arc<AuxDevicePair>)>; MAX_HOST_REALMS],
    table: Table,
    flows: Cursor<GatewayKey, HostFlowOwner>,
    fragments: Cursor<FragmentKey, FragmentVerdict>,
    prepared: bool,
}

impl Cleanup {
    pub(super) fn prepare(&mut self, budget: &Arc<MemoryBudget>) -> io::Result<()> {
        // A hash lookup batch never splits a bucket. Reserve enough for even the largest
        // bucket at capture admission; ordinary turns still request at most INITIAL_BATCH.
        self.flows.resize(HOST_HOLD_ENTRIES as usize, budget)?;
        self.fragments
            .resize(GATEWAY_FRAGMENT_ENTRIES as usize, budget)?;
        self.prepared = true;
        Ok(())
    }

    fn step(
        &mut self,
        maps: &GatewayMaps,
        arb: &GatewayArbitration,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Option<(u32, u64)>> {
        let (key, _) = self.queue[0]
            .as_ref()
            .ok_or_else(|| invalid_data("empty Host cleanup queue"))?;
        let (realm, binding) = (key.realm, key.binding);
        let host = maps.host_flows()?;
        match self.table {
            Table::Roots | Table::Holds | Table::Tcp => {
                if matches!(self.table, Table::Roots) {
                    // Successful map-in-map deletion can wait for RCU. Only the offline FIFO is locked.
                    for map in [&host.gates, &host.devices] {
                        if let Err(error) =
                            bpf(BPF_MAP_DELETE_ELEM, &mut elem(map.as_fd(), key, 0, 0))
                            && error.raw_os_error() != Some(libc::ENOENT)
                        {
                            return Err(error);
                        }
                    }
                    self.table = Table::Holds;
                }
                let tcp = matches!(self.table, Table::Tcp);
                let (fd, capacity) = if tcp {
                    (host.direct_tcp.as_fd(), HOST_DIRECT_TCP_ENTRIES)
                } else {
                    (host.hold.as_fd(), HOST_HOLD_ENTRIES)
                };
                let (_, complete) = self.flows.turn(
                    fd,
                    capacity,
                    budget,
                    INITIAL_BATCH,
                    None,
                    |key, observed| {
                        if key.realm_id != realm {
                            return Ok(false);
                        }
                        if observed.binding != binding {
                            return Err(invalid_data("foreign Host owner at binding retirement"));
                        }
                        arb.with_guard(&GatewayMaps::guard_key(key), || {
                            let Some(current) = lookup::<_, HostFlowOwner>(fd, key)? else {
                                return Ok(false);
                            };
                            if current != observed {
                                return Err(invalid_data(
                                    "Host owner changed during offline cleanup",
                                ));
                            }
                            if !tcp && observed.is_endpoint() {
                                maps.delete_host_meta(key, observed)?;
                            } else if !observed.is_direct()
                                || (tcp && (key.proto != 6 || observed.socket_cookie == 0))
                                || (!tcp && key.proto != 17)
                            {
                                return Err(invalid_data(
                                    "invalid Host owner at binding retirement",
                                ));
                            }
                            bpf(BPF_MAP_DELETE_ELEM, &mut elem(fd, key, 0, 0))?;
                            Ok(true)
                        })?
                        .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))
                    },
                )?;
                if complete {
                    self.table = if tcp { Table::Fragments } else { Table::Tcp };
                }
            }
            Table::Fragments => {
                let fd = maps.fragments.as_fd();
                let (_, complete) = self.fragments.turn(
                    fd,
                    GATEWAY_FRAGMENT_ENTRIES,
                    budget,
                    INITIAL_BATCH,
                    None,
                    |key, _| {
                        if key.realm_id != realm {
                            return Ok(false);
                        }
                        match bpf(BPF_MAP_DELETE_ELEM, &mut elem(fd, key, 0, 0)) {
                            Ok(_) => Ok(true),
                            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
                            Err(error) => Err(error),
                        }
                    },
                )?;
                if complete {
                    let mut slot = host.binding(realm)?;
                    if !matches!(*slot, Binding::Draining(id) if id == binding) {
                        return Err(invalid_data("retired Host binding was replaced"));
                    }
                    *slot = Binding::Offline(binding);
                    drop(slot);
                    self.queue.rotate_left(1);
                    self.queue[MAX_HOST_REALMS - 1] = None;
                    self.table = Table::Roots;
                    return Ok(Some((realm, binding)));
                }
            }
        }
        Ok(None)
    }
}

impl GatewayMaps {
    /// The caller has closed the gates, synchronized writers, discarded old TUN records
    /// and joined the applications. WouldBlock retains the exact binding and scan position.
    pub fn clear_host_binding(
        &self,
        realm: u32,
        binding: u64,
        arbitration: &GatewayArbitration,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<()> {
        let host = self.host_flows()?;
        let mut cleanup = host
            .cleanup
            .lock()
            .map_err(|_| invalid_data("Host cleanup poisoned"))?;
        if !cleanup.prepared {
            return Err(invalid_data("Host cleanup workspace was not admitted"));
        }
        {
            let _capture = self.require_realm_binding(realm, false)?;
            let mut slot = host.binding(realm)?;
            match &*slot {
                Binding::Offline(id) if *id == binding && binding != 0 => return Ok(()),
                Binding::Draining(id) if *id == binding => (),
                Binding::Active { id, pair, .. } if *id == binding => {
                    if lookup::<_, u32>(pair.object_fds()[1], &0u32)? != Some(0) {
                        return Err(invalid_data("gateway Host gate still open at cleanup"));
                    }
                    let entry = cleanup
                        .queue
                        .iter_mut()
                        .find(|entry| entry.is_none())
                        .ok_or_else(|| invalid_data("Host cleanup queue full"))?;
                    let Binding::Active { pair, .. } =
                        std::mem::replace(&mut *slot, Binding::Draining(binding))
                    else {
                        unreachable!("matched active binding");
                    };
                    *entry = Some((
                        HostBindingKey {
                            realm,
                            binding,
                            reserved: 0,
                        },
                        pair,
                    ));
                }
                _ => return Err(invalid_data("foreign gateway Host binding cleanup")),
            }
        }
        if cleanup.step(self, arbitration, budget)? == Some((realm, binding)) {
            Ok(())
        } else {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }
}

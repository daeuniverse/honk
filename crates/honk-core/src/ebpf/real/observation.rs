use super::*;
use crate::ebpf::{
    DatapathAttachment, DatapathCheck, DatapathKind, DatapathObservation, DatapathObservationError,
    DatapathProgram, MAX_DATAPATH_ATTACHMENTS, MAX_DATAPATH_PROGRAMS,
};
use aya::maps::IterableMap;
use aya::programs::{ProgramError, SchedClassifier, TcAttachType, links::FdLink};

impl RealEbpfBackend {
    pub(super) fn observe_backend(&self) -> DatapathObservation {
        let mut result = DatapathObservation::unknown(DatapathKind::Real);
        let Some(bpf) = &self.bpf else {
            result.programs = DatapathCheck::Absent;
            result.hooks = DatapathCheck::Absent;
            result.routing = DatapathCheck::Absent;
            return result;
        };
        result.listeners_published = Some(self.listeners_published);
        result.programs = DatapathCheck::Absent;
        for (index, (name, program)) in bpf.programs().enumerate() {
            if index == MAX_DATAPATH_PROGRAMS {
                result.programs = DatapathCheck::Unknown;
                result.record_error(DatapathObservationError::Limit);
                break;
            }
            match program.info() {
                Ok(info) => {
                    result.loaded_programs.push(DatapathProgram {
                        name: name.to_owned(),
                        id: info.id(),
                    });
                    if result.programs != DatapathCheck::Error {
                        result.programs = DatapathCheck::Verified;
                    }
                }
                Err(ProgramError::NotLoaded) => {}
                Err(_) => {
                    result.programs = DatapathCheck::Error;
                    result.record_error(DatapathObservationError::Programs);
                }
            }
        }
        match self.observed_routing_generation() {
            Ok(Some(generation)) => {
                result.routing = DatapathCheck::Verified;
                result.routing_generation = Some(generation);
            }
            Ok(None) => result.routing = DatapathCheck::Absent,
            Err(_) => {
                result.routing = DatapathCheck::Error;
                result.record_error(DatapathObservationError::Routing);
            }
        }
        match self.array_get::<u32>("DATAPATH_STATE_MAP", 0) {
            Ok(Some(0)) => result.admission = Some(false),
            Ok(Some(1)) => result.admission = Some(true),
            _ => result.record_error(DatapathObservationError::Admission),
        }
        match self
            .hash_map::<TuplesKey, ConnState>("CONN_STATE_MAP")
            .and_then(|map| Ok(map.map().info()?.max_entries()))
        {
            Ok(capacity) => result.conn_state_capacity = Some(capacity),
            Err(_) => result.record_error(DatapathObservationError::Maps),
        }
        // A retained link FD alone does not prove its hook is still installed.
        // TCX queries below check the host interfaces and dae0. aya exposes no
        // query for the cgroup and sk_lookup hooks, and dae0peer sits in daens,
        // so those required hooks stay unchecked and `hooks` stays unknown.
        if self.interface_links.is_empty()
            && self.cgroup_sock_links.is_empty()
            && self.cgroup_sock_addr_links.is_empty()
            && self.dae0_ingress_link.is_none()
            && self.dae0peer_ingress_link.is_none()
            && self.sk_lookup_link.is_none()
        {
            result.hooks = DatapathCheck::Absent;
        }
        // ifindex 0 fails the name lookup below and records the hook error.
        let dae0 = self.dae0_ingress_link.iter().map(|link| {
            (
                nix::net::if_::if_nametoindex("dae0").unwrap_or(0),
                false,
                link,
            )
        });
        let tcx_links = self
            .interface_links
            .iter()
            .map(|(ifindex, egress, link)| (*ifindex, *egress, link))
            .chain(dae0);
        for (ifindex, egress, link) in tcx_links.take(MAX_DATAPATH_ATTACHMENTS) {
            let Ok(interface) = nix::net::if_::if_indextoname(ifindex) else {
                result.record_error(DatapathObservationError::Hooks);
                continue;
            };
            let Ok(interface) = interface.into_string() else {
                result.record_error(DatapathObservationError::Hooks);
                continue;
            };
            match observe_tc_hook(link, &interface, ifindex, egress, &result.loaded_programs) {
                Ok(attachment) => {
                    if attachment.state != DatapathCheck::Verified {
                        result.record_error(DatapathObservationError::Hooks);
                    }
                    result.attachments.push(attachment);
                }
                Err(_) => result.record_error(DatapathObservationError::Hooks),
            }
        }
        let tracked = self.interface_links.len() + usize::from(self.dae0_ingress_link.is_some());
        if tracked > MAX_DATAPATH_ATTACHMENTS {
            result.record_error(DatapathObservationError::Limit);
        }
        // Every hook the real datapath owns is required: the configured TCX
        // hooks, the cgroup hooks when cgroup v2 is present, and dae0_ingress,
        // dae0peer_ingress and tproxy_sk_lookup, which startup always attaches.
        let required = self.interface_links.len()
            + self.cgroup_sock_links.len()
            + self.cgroup_sock_addr_links.len()
            + 3;
        result.verify_required_hooks(required);
        result.checked_at = std::time::SystemTime::now();
        result
    }
}

fn observe_tc_hook(
    link: &aya::programs::tc::SchedClassifierLink,
    interface: &str,
    ifindex: u32,
    egress: bool,
    programs: &[DatapathProgram],
) -> anyhow::Result<DatapathAttachment> {
    let fd: &FdLink = link.try_into()?;
    let info = fd.info()?;
    let program = programs
        .iter()
        .find(|program| program.id == info.program_id())
        .ok_or_else(|| anyhow::anyhow!("hook program is not owned"))?;
    let direction = if egress {
        TcAttachType::Egress
    } else {
        TcAttachType::Ingress
    };
    // Linux TCX chains contain at most 64 programs. This does not enumerate
    // global links/programs or walk any packet-state map.
    let (_, attached) = SchedClassifier::query_tcx(interface, direction)?;
    anyhow::ensure!(
        nix::net::if_::if_nametoindex(interface)? == ifindex,
        "interface identity changed during observation"
    );
    Ok(DatapathAttachment {
        program: program.name.clone(),
        interface: interface.to_owned(),
        egress,
        state: if attached.iter().any(|attached| attached.id() == program.id) {
            DatapathCheck::Verified
        } else {
            DatapathCheck::Absent
        },
    })
}

use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    sync::Arc,
};

use honk_ebpf_common::xdp_gateway::CaptureRealmKey;
use honk_netstack::MemoryBudget;
use honk_xsk::{
    device::DeviceInfo,
    topology::{CaptureWatch, CaptureWatchEvent, capture_layout},
};

pub(crate) struct CaptureRealm {
    pub(crate) realm_id: u32,
    pub(crate) name: String,
    pub(crate) logical_ifindex: u32,
    pub(crate) mtu: u32,
    pub(crate) mac: [u8; 6],
    pub(crate) vlan_count: u32,
    pub(crate) tpid: [u16; 2],
    pub(crate) vid: [u16; 2],
    member_names: Vec<String>,
}

pub(crate) struct CapturePlan {
    realms: Vec<CaptureRealm>,
    members: Vec<CaptureMember>,
}

pub(crate) struct CaptureMember {
    pub(crate) realm_id: u32,
    pub(crate) info: DeviceInfo,
}

impl CapturePlan {
    pub(crate) fn check_gateway_defaults(&self) -> io::Result<()> {
        let captured: Vec<_> = self
            .members
            .iter()
            .map(|member| member.info.ifindex)
            .chain(self.realms.iter().map(|realm| realm.logical_ifindex))
            .collect();
        honk_xsk::topology::check_gateway_defaults(&captured)
    }

    pub(crate) fn memory_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.realms.capacity() * std::mem::size_of::<CaptureRealm>()
            + self.members.capacity() * std::mem::size_of::<CaptureMember>()
            + self
                .realms
                .iter()
                .map(|realm| {
                    realm.name.capacity()
                        + realm.member_names.capacity() * std::mem::size_of::<String>()
                        + realm
                            .member_names
                            .iter()
                            .map(String::capacity)
                            .sum::<usize>()
                })
                .sum::<usize>()
            + self
                .members
                .iter()
                .map(|member| {
                    member.info.name.capacity()
                        + (member.info.queues.capacity() + member.info.upper_ifindices.capacity())
                            * std::mem::size_of::<u32>()
                })
                .sum::<usize>()
    }

    pub(crate) fn discover(interfaces: &[String]) -> io::Result<Self> {
        let realms: Vec<_> = capture_layout(interfaces)?
            .into_iter()
            .map(|realm| CaptureRealm {
                realm_id: realm.realm_id,
                name: realm.name,
                logical_ifindex: realm.logical_ifindex,
                mtu: realm.mtu,
                mac: realm.mac,
                vlan_count: realm.vlan_count,
                tpid: realm.tpid,
                vid: realm.vid,
                member_names: realm.members,
            })
            .collect();
        let mut members = Vec::new();
        for realm in realms.iter().filter(|realm| realm.vlan_count == 0) {
            for name in &realm.member_names {
                let info = DeviceInfo::discover(name)?;
                if members
                    .iter()
                    .any(|member: &CaptureMember| member.info.ifindex == info.ifindex)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "physical capture member belongs to multiple configured roots",
                    ));
                }
                members.push(CaptureMember {
                    realm_id: realm.realm_id,
                    info,
                });
            }
        }
        if members.len() > 64 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "capture exceeds 64 physical members",
            ));
        }
        Ok(Self { realms, members })
    }

    pub(crate) fn realm_keys(&self) -> Vec<(CaptureRealmKey, u32)> {
        self.realms
            .iter()
            .flat_map(|realm| {
                self.members
                    .iter()
                    .filter(move |member| realm.member_names.contains(&member.info.name))
                    .map(move |member| {
                        (
                            CaptureRealmKey {
                                physical_ifindex: member.info.ifindex,
                                vlan_count: realm.vlan_count,
                                tpid: realm.tpid,
                                vid: realm.vid,
                            },
                            realm.realm_id,
                        )
                    })
            })
            .collect()
    }

    pub(crate) fn members(&self) -> &[CaptureMember] {
        &self.members
    }
    pub(crate) fn realms(&self) -> &[CaptureRealm] {
        &self.realms
    }
    pub(crate) fn realm_name(&self, realm_id: u32) -> &str {
        self.realms
            .iter()
            .find(|realm| realm.realm_id == realm_id)
            .map_or("unknown", |realm| realm.name.as_str())
    }
}

pub(crate) struct CaptureTopology {
    watch: CaptureWatch,
}

pub(crate) enum TopologyEvent {
    Quiet,
    AddressDirty,
}

impl CaptureTopology {
    pub(crate) fn admit(plan: &CapturePlan, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let indices: Vec<_> = plan
            .members
            .iter()
            .map(|member| member.info.ifindex)
            .chain(plan.realms.iter().map(|realm| realm.logical_ifindex))
            .collect();
        let watch = CaptureWatch::new(&indices, budget)?;
        let names: Vec<_> = plan
            .realms
            .iter()
            .filter(|realm| realm.vlan_count == 0)
            .map(|realm| realm.name.clone())
            .collect();
        let fresh = capture_layout(&names)?;
        if fresh.len() != plan.realms.len()
            || fresh.iter().zip(&plan.realms).any(|(a, b)| {
                a.realm_id != b.realm_id
                    || a.logical_ifindex != b.logical_ifindex
                    || a.name != b.name
                    || a.mtu != b.mtu
                    || a.mac != b.mac
                    || a.vlan_count != b.vlan_count
                    || a.tpid != b.tpid
                    || a.vid != b.vid
                    || a.members != b.member_names
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "logical capture topology changed during admission",
            ));
        }
        Ok(Self { watch })
    }
    pub(crate) fn ipv4_broadcasts(&self) -> &[std::net::Ipv4Addr] {
        self.watch.ipv4_broadcasts()
    }
    pub(crate) fn expect_program(&mut self, ifindex: u32, program_id: u32) {
        self.watch.expect_program(ifindex, program_id);
    }
    pub(crate) fn check(&mut self) -> io::Result<TopologyEvent> {
        self.watch.check().map(|event| match event {
            CaptureWatchEvent::Quiet => TopologyEvent::Quiet,
            CaptureWatchEvent::AddressDirty => TopologyEvent::AddressDirty,
        })
    }
}

impl AsFd for CaptureTopology {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.watch.as_fd()
    }
}
impl AsRawFd for CaptureTopology {
    fn as_raw_fd(&self) -> RawFd {
        self.watch.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bond_members_map_to_one_logical_vlan_realm() {
        let member = |index: u32, name: &str| CaptureMember {
            realm_id: 1,
            info: DeviceInfo {
                name: name.into(),
                ifindex: index,
                upper_ifindices: vec![10],
                queues: vec![0],
                mtu: 1500,
                mac: [2; 6],
                xdp_features: 3,
                zerocopy_max_segments: 0,
                vlan_metadata: false,
            },
        };
        let realm = |realm_id, vlan_count, vid| CaptureRealm {
            realm_id,
            name: format!("realm{realm_id}"),
            logical_ifindex: realm_id + 9,
            mtu: 1500,
            mac: [2; 6],
            vlan_count,
            tpid: if vlan_count == 0 { [0; 2] } else { [0x8100, 0] },
            vid,
            member_names: vec!["member0".into(), "member1".into()],
        };
        let plan = CapturePlan {
            realms: vec![realm(1, 0, [0; 2]), realm(2, 1, [7, 0])],
            members: vec![member(11, "member0"), member(12, "member1")],
        };
        let keys = plan.realm_keys();
        assert_eq!(keys.len(), 4);
        for (index, physical) in [11, 12].into_iter().enumerate() {
            assert_eq!(keys[index].0.physical_ifindex, physical);
            assert_eq!(keys[index].1, 1);
            assert_eq!(keys[index + 2].0.physical_ifindex, physical);
            assert_eq!(keys[index + 2].0.vid, [7, 0]);
            assert_eq!(keys[index + 2].1, 2);
        }
    }
}

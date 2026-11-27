use std::{
    io,
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
    sync::Arc,
};

use honk_config::datapath::{InterfaceRole, XdpInterface};
use honk_ebpf_common::xdp_gateway::CaptureRealmKey;
use honk_netstack::MemoryBudget;
use honk_xsk::{
    device::DeviceInfo,
    topology::{CaptureWatch, CaptureWatchEvent, capture_layout},
};

pub(crate) struct CaptureRealm {
    pub(crate) realm_id: u32,
    pub(crate) name: String,
    pub(crate) role: InterfaceRole,
    pub(crate) logical_ifindex: u32,
    root_ifindex: u32,
    pub(crate) mtu: u32,
    pub(crate) mac: [u8; 6],
    pub(crate) vlan_count: u32,
    pub(crate) tpid: [u16; 2],
    pub(crate) vid: [u16; 2],
    member_names: Vec<String>,
}

impl CaptureRealm {
    fn from_layout(realm: honk_xsk::topology::CaptureRealm, role: InterfaceRole) -> Self {
        Self {
            realm_id: realm.realm_id,
            name: realm.name,
            role,
            logical_ifindex: realm.logical_ifindex,
            root_ifindex: realm.root_ifindex,
            mtu: realm.mtu,
            mac: realm.mac,
            vlan_count: realm.vlan_count,
            tpid: realm.tpid,
            vid: realm.vid,
            member_names: realm.members,
        }
    }
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

    fn bind_realms(
        layout: Vec<honk_xsk::topology::CaptureRealm>,
        interfaces: &[XdpInterface],
    ) -> io::Result<Vec<CaptureRealm>> {
        // Each admitted root precedes its VLANs in the capture layout.
        let mut root_role = None;
        layout
            .into_iter()
            .map(|realm| {
                if realm.vlan_count == 0 {
                    root_role = interfaces
                        .iter()
                        .find(|interface| interface.name == realm.name)
                        .map(|interface| (realm.logical_ifindex, interface.role));
                }
                let role = root_role
                    .filter(|(ifindex, _)| *ifindex == realm.root_ifindex)
                    .map(|(_, role)| role)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "capture realm root role missing",
                        )
                    })?;
                Ok(CaptureRealm::from_layout(realm, role))
            })
            .collect()
    }

    pub(crate) fn discover(interfaces: &[XdpInterface]) -> io::Result<Self> {
        let names: Vec<_> = interfaces
            .iter()
            .filter(|interface| interface.role != InterfaceRole::L3Lan)
            .map(|interface| interface.name.clone())
            .collect();
        let realms = Self::bind_realms(capture_layout(&names)?, interfaces)?;
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
                    || a.root_ifindex != b.root_ifindex
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
    fn auxiliary_names_are_not_physical_capture_roots() {
        let plan = CapturePlan::discover(&[XdpInterface {
            name: "aux0".into(),
            role: InterfaceRole::L3Lan,
        }])
        .unwrap();
        assert!(plan.realms().is_empty());
        assert!(plan.members().is_empty());
    }

    #[test]
    fn bond_members_map_to_one_logical_vlan_realm() {
        let member = |realm_id, index: u32, name: &str| CaptureMember {
            realm_id,
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
                physical_member: true,
                direct_relay_physical: true,
            },
        };
        let realm = |realm_id, root_ifindex, vlan_count, vid, members: &[&str]| {
            honk_xsk::topology::CaptureRealm {
                realm_id,
                name: format!("realm{realm_id}"),
                logical_ifindex: realm_id + 9,
                root_ifindex,
                mtu: 1500,
                mac: [2; 6],
                vlan_count,
                tpid: if vlan_count == 0 { [0; 2] } else { [0x8100, 0] },
                vid,
                members: members.iter().map(|&name| name.into()).collect(),
            }
        };
        let bond = ["member0", "member1"];
        let wan = ["realm3"];
        let interfaces = [
            XdpInterface {
                name: "realm3".into(),
                role: InterfaceRole::Wan,
            },
            XdpInterface {
                name: "realm1".into(),
                role: InterfaceRole::Lan,
            },
        ];
        let realms = CapturePlan::bind_realms(
            vec![
                realm(1, 10, 0, [0; 2], &bond),
                realm(2, 10, 1, [7, 0], &bond),
                realm(3, 12, 0, [0; 2], &wan),
                realm(4, 12, 1, [7, 0], &wan),
            ],
            &interfaces,
        )
        .unwrap();
        let plan = CapturePlan {
            realms,
            members: vec![
                member(1, 20, "member0"),
                member(1, 21, "member1"),
                member(3, 12, "realm3"),
            ],
        };
        let keys = plan.realm_keys();
        assert_eq!(keys.len(), 6);
        for (index, physical) in [20, 21].into_iter().enumerate() {
            assert_eq!(keys[index].0.physical_ifindex, physical);
            assert_eq!(keys[index].1, 1);
            assert_eq!(keys[index + 2].0.physical_ifindex, physical);
            assert_eq!(keys[index + 2].0.vid, [7, 0]);
            assert_eq!(keys[index + 2].1, 2);
        }
        assert_eq!(keys[4].0.physical_ifindex, 12);
        assert_eq!(keys[4].1, 3);
        assert_eq!(keys[5].0.physical_ifindex, 12);
        assert_eq!(keys[5].0.vid, [7, 0]);
        assert_eq!(keys[5].1, 4);
        let lan_realms: Vec<_> = plan
            .realms()
            .iter()
            .filter(|realm| realm.role == InterfaceRole::Lan)
            .map(|realm| realm.realm_id)
            .collect();
        assert_eq!(lan_realms, [1, 2]);
    }
}

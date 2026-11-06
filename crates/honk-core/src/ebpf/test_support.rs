use std::num::NonZeroU32;

use super::interface::{self, InterfacePlan, Topology};
use crate::netlink::LinkSnapshot;

pub(crate) fn link(ifindex: u32, name: &str) -> LinkSnapshot {
    LinkSnapshot {
        ifindex: NonZeroU32::new(ifindex).unwrap(),
        name: name.into(),
        arphrd: libc::ARPHRD_ETHER,
        flags: 0,
        master: None,
        kind: None,
        mac: Some([2, 0, 0, 0, 0, ifindex as u8]),
    }
}

pub(crate) trait LinkExt {
    fn arphrd(self, arphrd: u16) -> Self;
    fn master(self, master: u32) -> Self;
    fn kind(self, kind: &str) -> Self;
    fn flags(self, flags: u32) -> Self;
}

impl LinkExt for LinkSnapshot {
    fn arphrd(mut self, arphrd: u16) -> Self {
        self.arphrd = arphrd;
        self.mac = None;
        self
    }

    fn master(mut self, master: u32) -> Self {
        self.master = NonZeroU32::new(master);
        self
    }

    fn kind(mut self, kind: &str) -> Self {
        self.kind = Some(kind.into());
        self
    }

    fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }
}

pub(crate) fn planned(lan: &[&str], wan: &[&str], topology: &Topology) -> InterfacePlan {
    let names = |names: &[&str]| {
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>()
    };
    interface::plan(&names(lan), &names(wan), topology)
}

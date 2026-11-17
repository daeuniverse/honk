use crate::xdp::worker::PeerHold;
use honk_netstack::FragmentInfo;
use std::time::Instant;

pub(in crate::control) struct FragmentPeer {
    pub(in crate::control) info: FragmentInfo,
    pub(in crate::control) peer: Option<PeerHold>,
}

impl FragmentPeer {
    pub(in crate::control) fn new(info: FragmentInfo, peer: Option<PeerHold>) -> Self {
        Self { info, peer }
    }

    pub(in crate::control) fn observe(
        &mut self,
        info: FragmentInfo,
        ingress_at: Instant,
        peer: Option<PeerHold>,
    ) {
        if ingress_at < self.info.original_ingress {
            self.peer = peer;
        }
        self.info = info;
    }
}

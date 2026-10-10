//! Inert twin of endpoint observation for builds without `native-api`: the
//! bundle is zero-sized, terminals are uninhabited, and every hook folds away.

use std::sync::Arc;

use honk_outbound::runtime::flow_observation::FlowObserver;

use super::{UdpEndpointPool, UdpTerminal};
use crate::observe::flows::FlowGuard;

#[derive(Clone)]
pub(in crate::control) enum SharedTerminal {}

impl SharedTerminal {
    #[inline]
    pub(in crate::control) fn initializer(&self) -> NativeInitializerGuard {
        match *self {}
    }

    #[inline]
    pub(in crate::control) fn outcome(&self, _outcome: UdpTerminal) {
        match *self {}
    }
}

pub(in crate::control) enum NativeInitializerGuard {}

impl NativeInitializerGuard {
    #[inline]
    pub(in crate::control) fn complete(&mut self) {
        match *self {}
    }
}

#[derive(Default)]
pub(in crate::control) struct EndpointObservation;

const _: () = assert!(size_of::<EndpointObservation>() == 0);
const _: () = assert!(size_of::<Option<SharedTerminal>>() == 0);

impl EndpointObservation {
    #[inline]
    pub(in crate::control) fn set_flow(
        &mut self,
        _flow: Option<Arc<FlowGuard>>,
        _pool: &Arc<UdpEndpointPool>,
        _terminal: Option<SharedTerminal>,
    ) {
    }

    #[inline]
    pub(in crate::control) fn flow(&self) -> Option<&Arc<FlowGuard>> {
        None
    }

    #[inline]
    pub(super) fn observer(&self) -> Option<&FlowObserver> {
        None
    }

    #[inline]
    pub(super) fn dropped(&self, _reason: &'static str, _error: Option<&'static str>) {}

    #[inline]
    pub(super) fn reply_received(&self) {}

    #[inline]
    pub(super) fn finish(&self, _outcome: UdpTerminal) {}
}

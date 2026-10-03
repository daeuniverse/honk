//! Inert twin of connection observation for builds without `native-api`: the
//! recorder is zero-sized and every hook folds away.

use std::{net::SocketAddr, sync::Arc};

use honk_config::{node::Node, types::DialMode};
use honk_outbound::runtime::flow_observation::FlowObserver;

use super::{handoff::HandoffResult, routing::RoutingDecision};
use crate::observe::{Observation, flows::FlowGuard};

#[derive(Clone, Default)]
pub(in crate::control) struct ConnectionObservation;

const _: () = assert!(size_of::<ConnectionObservation>() == 0);

impl ConnectionObservation {
    #[inline]
    pub(in crate::control) fn begin(
        _native: Option<&Observation>,
        _network: crate::observe::vocab::Network,
        _source: SocketAddr,
        _destination: SocketAddr,
    ) -> Self {
        Self
    }

    #[inline]
    pub(in crate::control) fn flow(&self) -> Option<&Arc<FlowGuard>> {
        None
    }

    #[inline]
    pub(in crate::control) fn observer(
        &self,
        _generation: impl FnOnce() -> u64,
        _purpose: &'static str,
    ) -> Option<FlowObserver> {
        None
    }

    #[inline]
    pub(super) fn routing_started(&self) {}

    #[inline]
    pub(super) fn take_flow(&mut self) -> Option<Arc<FlowGuard>> {
        None
    }

    #[inline]
    pub(super) fn handoff(&mut self, _handoff: Option<&HandoffResult>, _expected: bool) {}

    #[inline]
    pub(super) fn tcp_sniffed(
        &self,
        _sniff: &crate::sniffing::SniffResult,
        _handoff: Option<&HandoffResult>,
    ) {
    }

    #[inline]
    pub(super) fn udp_sniffed(&self, _domain: Option<&str>, _handoff: Option<&HandoffResult>) {}

    #[inline]
    pub(super) fn routed(&mut self, _decision: &mut RoutingDecision) {}

    #[inline]
    pub(super) fn mode_applied(&mut self, _outbound: &str) {}

    #[inline]
    pub(super) fn tcp_dial_mode(
        &self,
        _configured: DialMode,
        _sniff: &crate::sniffing::SniffResult,
        _verification: &'static str,
        _candidates: &[Node],
        _domain: Option<&str>,
    ) {
    }

    #[inline]
    pub(super) fn udp_dial_mode(
        &self,
        _configured: DialMode,
        _domain: Option<&str>,
        _verification: &'static str,
        _selected: Option<(&Node, Option<&str>)>,
    ) {
    }

    #[inline]
    pub(in crate::control) fn finish(
        &self,
        _state: crate::observe::vocab::ConnectionState,
        _reason: &'static str,
    ) {
    }

    #[inline]
    pub(super) fn first_response(
        &self,
        previous: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Option<Arc<dyn Fn() + Send + Sync>> {
        previous
    }

    #[inline]
    pub(super) fn udp_preparing(&self) {}
}

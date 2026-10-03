//! Inert twin of the observation contract for builds without `native-api`:
//! uninhabited or zero-sized types keep fields free and every hook folds away,
//! so engine call sites need no feature gates.

#[path = "vocab.rs"]
#[allow(
    dead_code,
    reason = "only the variants engine call sites name are built"
)]
pub(crate) mod vocab;

pub(crate) enum Observation {}

#[derive(Clone, Default)]
pub(crate) struct DnsObserver;

impl DnsObserver {
    #[inline]
    pub(crate) fn operation(&self) -> DnsOperation {
        DnsOperation
    }
}

pub(crate) struct DnsOperation;

impl DnsOperation {
    #[inline]
    pub(crate) fn scope<F: Future>(&self, operation: F) -> F {
        operation
    }
}

macro_rules! scope_pin {
    ($future:ident) => {};
}
pub(crate) use scope_pin;

pub(crate) mod flows {
    pub(crate) enum FlowGuard {}

    impl FlowGuard {
        #[inline]
        pub(crate) fn transition(
            &self,
            _state: crate::observe::vocab::ConnectionState,
            _reason: &'static str,
            _milestone: crate::observe::vocab::ConnectionMilestone,
            _reply_received: Option<bool>,
        ) {
            match *self {}
        }

        #[inline]
        pub(crate) fn attach_connection(&self, _connection_id: &str) {
            match *self {}
        }

        #[inline]
        pub(crate) fn accepted_send(&self) {
            match *self {}
        }
    }

    pub(crate) mod record {
        pub(crate) enum OutboundAttempt {}
    }

    pub(crate) mod dns {
        use std::net::{IpAddr, SocketAddr};

        use honk_config::node::Node;
        use honk_outbound::{alive::IpVersion, group::observation::SelectionObservation};

        use super::record::OutboundAttempt;
        use crate::dns::{
            forwarder::DnsForwardError,
            outcome::DnsOutcome,
            query::{DnsRequestMeta, IngressProfile},
        };
        use crate::routing::{ConnectionInfo, Router};

        #[inline]
        pub(crate) fn scope_purpose<F: Future>(_purpose: &'static str, future: F) -> F {
            future
        }

        #[inline]
        pub(crate) fn outbound_dial_scope<F: Future>(_node: &Node, future: F) -> F {
            future
        }

        #[inline]
        pub(crate) fn client_scope<F: Future>(
            _raw: &[u8],
            _ingress: IngressProfile,
            _metadata: DnsRequestMeta,
            future: F,
        ) -> F {
            future
        }

        #[inline]
        pub(crate) fn exchange_scope<F: Future>(_raw: &[u8], _upstream: &str, future: F) -> F {
            future
        }

        #[inline]
        pub(crate) fn transport_exchange_scope<F: Future>(_raw: &[u8], future: F) -> F {
            future
        }

        #[inline]
        pub(crate) fn outbound_scope<F: Future>(
            _attempt: Option<&OutboundAttempt>,
            future: F,
        ) -> F {
            future
        }

        #[inline]
        pub(crate) fn source(_source: &'static str, _cache: Option<&'static str>) {}

        #[inline]
        pub(crate) fn cache_state(_cache: &'static str) {}

        #[inline]
        pub(crate) fn transport(_upstream: &'static str, _carrier: &'static str) {}

        #[inline]
        pub(crate) fn tcp_fallback() {}

        #[inline]
        pub(crate) fn delivery(_status: &'static str, _error: Option<&'static str>) {}

        #[inline]
        pub(crate) fn reply_delivery<T, E, C>(
            _result: &Result<Result<T, E>, C>,
            _complete: impl FnOnce(&T) -> bool,
            _failure: &'static str,
        ) {
        }

        #[inline]
        pub(crate) fn decision(_status: &'static str, _error: Option<&'static str>) {}

        #[inline]
        pub(crate) fn route_upstream(
            router: &Router,
            input: &ConnectionInfo,
        ) -> (String, Option<String>) {
            (router.route(input).to_owned(), None)
        }

        #[derive(Default)]
        pub(crate) struct SelectionPath;

        #[inline]
        pub(crate) fn selection_evaluated(
            _observation: Option<&SelectionObservation>,
        ) -> SelectionPath {
            SelectionPath
        }

        #[inline]
        pub(crate) fn selection_path(
            _selections: &SelectionPath,
            _chain: &[String],
            _node: &Node,
            _family: IpVersion,
        ) -> SelectionPath {
            SelectionPath
        }

        #[inline]
        pub(crate) fn outbound_evidence(
            _outbound: &str,
            _routing_source: crate::observe::vocab::RoutingSource,
            _evaluation_id: Option<String>,
            _node: Option<&Node>,
            _target: SocketAddr,
            _selection_path: SelectionPath,
        ) -> Option<OutboundAttempt> {
            None
        }

        pub(crate) enum LookupGuard {}

        impl LookupGuard {
            #[inline]
            pub(crate) fn start(
                _raw: &[u8],
                _ingress: IngressProfile,
                _metadata: DnsRequestMeta,
            ) -> Option<Self> {
                None
            }

            #[inline]
            pub(crate) fn scope<F: Future>(&self, _future: F) -> F {
                match *self {}
            }

            #[inline]
            pub(crate) fn outcome(&mut self, _result: &Result<DnsOutcome, DnsForwardError>) {
                match *self {}
            }
        }

        pub(crate) enum RuleCapture {}

        impl RuleCapture {
            #[inline]
            pub(crate) fn request(
                _name: &str,
                _query_type: u16,
                _source_ip: Option<IpAddr>,
            ) -> Option<Self> {
                None
            }

            #[inline]
            pub(crate) fn response(
                _name: &str,
                _query_type: u16,
                _ips: &[IpAddr],
                _from: &str,
            ) -> Option<Self> {
                None
            }

            #[inline]
            pub(crate) fn begin_rule(
                &mut self,
                _index: Option<usize>,
                _conditions: &[honk_config::dns::DnsCond],
            ) {
                match *self {}
            }

            #[inline]
            pub(crate) fn condition(&mut self, _index: usize, _matched: bool) {
                match *self {}
            }

            #[inline]
            pub(crate) fn rule_result(&mut self, _matched: bool) {
                match *self {}
            }

            #[inline]
            pub(crate) fn finish(self, _action: &'static str, _outbound: Option<&str>) {
                match self {}
            }
        }
    }
}

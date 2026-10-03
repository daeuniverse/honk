//! Closed flow vocabularies; shared by the recorder and its inert twin so
//! engine call sites name the same types in every build.

use honk_outbound::wire_enum;

wire_enum! {
    pub(crate) enum Network {
        Tcp => "tcp",
        Udp => "udp",
    }
}

wire_enum! {
    pub(crate) enum ConnectionState {
        Observed => "observed",
        Routing => "routing",
        Dialing => "dialing",
        Active => "active",
        Closed => "closed",
        Blocked => "blocked",
        Failed => "failed",
        Unknown => "unknown",
    }
}

impl ConnectionState {
    pub(crate) const ALL: [Self; 8] = [
        Self::Observed,
        Self::Routing,
        Self::Dialing,
        Self::Active,
        Self::Closed,
        Self::Blocked,
        Self::Failed,
        Self::Unknown,
    ];

    pub(crate) const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Blocked | Self::Failed)
    }
}

wire_enum! {
    pub(crate) enum ConnectionMilestone {
        Unknown => "unknown",
        TransportReady => "transport_ready",
        TargetRequestSent => "target_request_sent",
        TargetConfirmed => "target_confirmed",
        FirstReply => "first_reply",
        Terminal => "terminal",
    }
}

impl From<honk_outbound::runtime::flow_observation::Milestone> for ConnectionMilestone {
    fn from(milestone: honk_outbound::runtime::flow_observation::Milestone) -> Self {
        use honk_outbound::runtime::flow_observation::Milestone;
        match milestone {
            Milestone::TransportReady => Self::TransportReady,
            Milestone::TargetRequestSent => Self::TargetRequestSent,
            Milestone::TargetConfirmed => Self::TargetConfirmed,
        }
    }
}

wire_enum! {
    pub(crate) enum Plane {
        Kernel => "kernel",
        Userspace => "userspace",
    }
}

wire_enum! {
    pub(crate) enum DomainSource {
        TlsSni => "tls_sni",
        HttpHost => "http_host",
        QuicSni => "quic_sni",
        DnsMapping => "dns_mapping",
    }
}

wire_enum! {
    /// Where the routing decision behind an attempt came from.
    pub(crate) enum RoutingSource {
        Kernel => "kernel",
        Evaluation => "evaluation",
        Forced => "forced",
        Builtin => "builtin",
        Unknown => "unknown",
    }
}

wire_enum! {
    /// The summary's rule provenance: a kernel decision or recomputed userspace evidence.
    pub(crate) enum RuleSource {
        Kernel => "kernel",
        Recomputed => "recomputed",
        Unknown => "unknown",
    }
}

impl From<RoutingSource> for RuleSource {
    fn from(source: RoutingSource) -> Self {
        match source {
            RoutingSource::Kernel => Self::Kernel,
            RoutingSource::Evaluation => Self::Recomputed,
            RoutingSource::Forced | RoutingSource::Builtin | RoutingSource::Unknown => {
                Self::Unknown
            }
        }
    }
}

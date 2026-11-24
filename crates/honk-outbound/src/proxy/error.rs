use std::io;
use std::sync::Arc;

/// A proxy's explicit failure to open the requested target, not its carrier.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TargetFailure(#[source] pub anyhow::Error);

/// A failure of the shared proxy carrier or its protocol, not one target.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct NodeFailure(#[source] pub anyhow::Error);

/// A routed dial failure with the location it surfaced at. A locator can
/// refer to a target refusal or a path failure as well as a node failure.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct ChainHopFailure {
    /// Zero-based hop that failed or that a prefix could not reach.
    pub hop: usize,
    pub node: uuid::Uuid,
    #[source]
    pub error: anyhow::Error,
}

/// A UDP entry can fail before a physical connect is attempted. Its locator
/// identifies the executing hop; attribution still requires a typed cause.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct UdpEntrySetupFailure(#[source] pub(super) ChainHopFailure);

/// A target refusal from a hop that was asked to reach the next proxy.
#[derive(Debug, thiserror::Error)]
pub(super) enum IntermediateTargetFailure {
    #[error("chain hop {hop} could not reach the next hop: {cause}")]
    Dial {
        hop: usize,
        #[source]
        cause: anyhow::Error,
    },
    #[error("chain hop {hop} could not reach the next hop: {cause}")]
    Io {
        hop: usize,
        #[source]
        cause: Arc<io::Error>,
    },
}

impl IntermediateTargetFailure {
    fn hop(&self) -> usize {
        match self {
            Self::Dial { hop, .. } | Self::Io { hop, .. } => *hop,
        }
    }

    pub(super) fn dial(hop: usize, error: anyhow::Error) -> anyhow::Error {
        if !is_local_dial_rejection(error.as_ref())
            && target_failure(&error)
            && intermediate_target_hop(error.as_ref()).is_none()
            && hop_io_failure(error.as_ref()).is_none()
        {
            Self::Dial { hop, cause: error }.into()
        } else {
            error
        }
    }

    /// Preserve typed causes while the intermediate boundary owns the I/O error.
    pub(super) fn io(hop: usize, error: io::Error) -> io::Error {
        if is_local_dial_rejection(&error) {
            return error;
        }
        if io_target_failure(&error) {
            Self::attach_io(hop, error)
        } else if let Some(cause) = error.get_ref()
            && !cause.is::<crate::SharedError>()
            && !cause.is::<IntermediateTargetFailure>()
            && !cause.is::<Arc<io::Error>>()
            && io_node_failure(&error)
        {
            // TLS and h2 can only borrow this error before reducing it to text.
            // This copyable wrapper adds no episode to an independent failure.
            io::Error::new(error.kind(), Arc::new(error))
        } else {
            error
        }
    }

    fn attach_io(hop: usize, error: io::Error) -> io::Error {
        io::Error::new(
            error.kind(),
            Self::Io {
                hop,
                cause: Arc::new(error),
            },
        )
    }
}

/// A typed carrier fault located at the hop whose codec produced it.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{cause}")]
pub(super) struct HopIoFailure {
    hop: usize,
    #[source]
    cause: Arc<io::Error>,
}

impl HopIoFailure {
    pub(super) fn io(hop: usize, error: io::Error, targets_next_hop: bool) -> io::Error {
        if is_local_dial_rejection(&error)
            || intermediate_target_hop(&error).is_some()
            || hop_io_failure(&error).is_some()
            || find_cause::<ChainHopFailure>(&error).is_some()
        {
            return error;
        }
        if io_target_failure(&error) {
            return if targets_next_hop {
                IntermediateTargetFailure::attach_io(hop + 1, error)
            } else {
                error
            };
        }
        if !io_node_failure(&error) {
            return error;
        }
        io::Error::new(
            error.kind(),
            Self {
                hop,
                cause: Arc::new(error),
            },
        )
    }
}

/// A protocol or transport whose handshake cannot run over a stream tunneled
/// through an earlier hop.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("{0} cannot run over a tunneled stream")]
pub struct TunnelUnsupported(pub &'static str);

/// Local capability failure. Other candidates can still be tried.
#[derive(Debug, thiserror::Error)]
#[error("No handler for protocol {0:?}")]
pub struct MissingProtocolHandler(pub honk_config::types::NodeProtocol);

fn next_cause<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a (dyn std::error::Error + 'static)> {
    if let Some(error) = error.downcast_ref::<io::Error>()
        && let Some(source) = error.get_ref()
    {
        return Some(source);
    }
    // Arc's Error::source skips the payload, and h2 exposes no I/O cause there.
    if let Some(error) = error.downcast_ref::<Arc<io::Error>>() {
        return Some(error.as_ref());
    }
    if let Some(error) = error.downcast_ref::<h2::Error>()
        && let Some(source) = error.get_io()
    {
        return Some(source);
    }
    error.source()
}

fn find_cause<'a, T: std::error::Error + 'static>(
    mut error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a T> {
    loop {
        if let Some(cause) = error.downcast_ref::<T>() {
            return Some(cause);
        }
        error = next_cause(error)?;
    }
}

/// The innermost shared fan-out carrying this cause, independent of its scope.
pub(crate) fn shared_failure_cause<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a crate::SharedError> {
    std::iter::successors(Some(error), |&error| next_cause(error))
        .filter_map(|cause| cause.downcast_ref::<crate::SharedError>())
        .filter(|cause| cause.episode().is_some())
        .last()
}

fn is_local_dial_rejection(error: &(dyn std::error::Error + 'static)) -> bool {
    find_cause::<PacketRejection>(error).is_some()
        || find_cause::<MissingProtocolHandler>(error).is_some()
        || find_cause::<TunnelUnsupported>(error).is_some()
}

/// Carrier provenance, with the episode of the innermost fanned-out failure delivering it.
/// Recipients of one fanned-out failure must not report separate node failures, while
/// independently constructed failures stay separate however they settle.
pub(crate) fn node_failure_cause<'a>(
    mut error: &'a (dyn std::error::Error + 'static),
) -> Option<Option<&'a crate::SharedError>> {
    let mut episode = None;
    let mut node = None;
    let mut intermediate = false;
    loop {
        // Codecs can add node context before the original shared refusal.
        // Keep its episode when the target was another hop of the chain.
        intermediate |= error.is::<IntermediateTargetFailure>();
        if intermediate && error.is::<TargetFailure>() {
            return Some(episode);
        }
        // A codec can also wrap a lower node marker that owns the actual episode.
        if error.is::<NodeFailure>() {
            node = Some(episode);
        }
        if let Some(fanout) = error
            .downcast_ref::<crate::SharedError>()
            .filter(|cause| cause.episode().is_some())
        {
            episode = Some(fanout);
        }
        let Some(cause) = next_cause(error) else {
            return node;
        };
        error = cause;
    }
}

pub(crate) fn node_failure_episode(
    error: &(dyn std::error::Error + 'static),
) -> Option<Option<u64>> {
    node_failure_cause(error).map(|cause| cause.and_then(crate::SharedError::episode))
}

fn is_target_failure(mut error: &(dyn std::error::Error + 'static)) -> bool {
    loop {
        if error.is::<TargetFailure>() {
            return true;
        }
        if error.is::<IntermediateTargetFailure>() {
            return false;
        }
        let Some(cause) = next_cause(error) else {
            return false;
        };
        error = cause;
    }
}

/// Recover target provenance through anyhow, I/O and shared error wrappers.
pub fn target_failure(error: &anyhow::Error) -> bool {
    is_target_failure(error.as_ref())
}

pub(crate) fn io_target_failure(error: &std::io::Error) -> bool {
    is_target_failure(error)
}

/// The chain hop that failed, through any error wrappers.
pub fn failed_hop(error: &anyhow::Error) -> Option<&ChainHopFailure> {
    find_cause::<ChainHopFailure>(error.as_ref())
}

pub(crate) fn intermediate_target_hop(error: &(dyn std::error::Error + 'static)) -> Option<usize> {
    find_cause::<IntermediateTargetFailure>(error).map(IntermediateTargetFailure::hop)
}

pub(super) fn hop_io_failure(error: &(dyn std::error::Error + 'static)) -> Option<usize> {
    find_cause::<HopIoFailure>(error).map(|failure| failure.hop)
}

/// Failure evidence from setup or relay. Hop indexes are zero-based.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialFailureScope {
    /// An attributable hop fault, including one delivered over a carrier.
    Hop(usize),
    /// An intermediate proxy could not reach this next hop through the prefix.
    Prefix(usize),
    /// The final proxy refused the application target.
    Target,
    /// A local policy, size, admission or cancellation refusal.
    LocalRejection,
    /// The cause cannot identify a failed node or an explicit target refusal.
    Unattributed,
}

/// Classify a dial or relay error through its typed causes.
pub fn dial_failure_scope(error: &(dyn std::error::Error + 'static)) -> DialFailureScope {
    if is_local_dial_rejection(error) {
        DialFailureScope::LocalRejection
    } else if let Some(hop) = intermediate_target_hop(error) {
        DialFailureScope::Prefix(hop)
    } else if let Some(hop) = hop_io_failure(error) {
        DialFailureScope::Hop(hop)
    } else if is_target_failure(error) {
        DialFailureScope::Target
    } else if find_cause::<crate::util::ProxyConnectFailure>(error).is_some() {
        DialFailureScope::Hop(0)
    } else {
        match find_cause::<ChainHopFailure>(error) {
            Some(failure)
                if (failure.hop == 0 && find_cause::<UdpEntrySetupFailure>(error).is_none())
                    || node_failure_episode(error).is_some() =>
            {
                DialFailureScope::Hop(failure.hop)
            }
            _ => DialFailureScope::Unattributed,
        }
    }
}

/// Recover explicit carrier provenance without inferring it from error text.
pub fn node_failure(error: &anyhow::Error) -> bool {
    node_failure_episode(error.as_ref()).is_some()
}

pub(crate) fn io_node_failure(error: &std::io::Error) -> bool {
    node_failure_episode(error).is_some()
}

/// Recover an owned copy of a shareable typed cause from borrowed I/O.
pub(crate) fn retain_typed_io_error(error: &io::Error) -> Option<io::Error> {
    let kind = error.kind();
    let mut source: &(dyn std::error::Error + 'static) = error;
    loop {
        if let Some(cause) = source.downcast_ref::<crate::SharedError>() {
            return Some(io::Error::new(kind, cause.clone()));
        }
        if let Some(cause) = source.downcast_ref::<Arc<io::Error>>()
            && io_node_failure(cause)
        {
            return Some(io::Error::new(kind, Arc::clone(cause)));
        }
        if let Some(IntermediateTargetFailure::Io { hop, cause }) =
            source.downcast_ref::<IntermediateTargetFailure>()
        {
            return Some(io::Error::new(
                kind,
                IntermediateTargetFailure::Io {
                    hop: *hop,
                    cause: Arc::clone(cause),
                },
            ));
        }
        if let Some(failure) = source.downcast_ref::<HopIoFailure>() {
            return Some(io::Error::new(kind, failure.clone()));
        }
        if let Some(rejection) = source.downcast_ref::<PacketRejection>() {
            return Some(io::Error::new(kind, *rejection));
        }
        source = next_cause(source)?;
    }
}

/// Whether any cause of `error`, including one inside an `io::Error`, is a
/// [`TunnelUnsupported`] refusal.
pub fn tunnel_unsupported(error: &anyhow::Error) -> bool {
    find_cause::<TunnelUnsupported>(error.as_ref()).is_some()
}

// Only proxy-owned QUIC carriers may add node provenance. End-to-end QUIC
// (for example DoQ through a packet proxy) belongs to the requested target.
pub(crate) fn quic_carrier_error(error: anyhow::Error) -> anyhow::Error {
    if !node_failure(&error) && find_cause::<quinn::ConnectionError>(error.as_ref()).is_some() {
        NodeFailure(error).into()
    } else {
        error
    }
}

pub(crate) fn quic_carrier_io_error(error: std::io::Error) -> std::io::Error {
    if !io_node_failure(&error) && find_cause::<quinn::ConnectionError>(&error).is_some() {
        std::io::Error::new(error.kind(), NodeFailure(error.into()))
    } else {
        error
    }
}

/// A local packet refusal that must not be treated as transport health.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum PacketRejection {
    #[error("UDP target rejected by policy")]
    Policy,
    #[error("UDP packet size is invalid")]
    InvalidSize,
    #[error("UDP transport capacity is exhausted")]
    Capacity,
    #[error("UDP transport preparation was cancelled")]
    Cancelled,
}

impl From<PacketRejection> for std::io::Error {
    fn from(rejection: PacketRejection) -> Self {
        let kind = match rejection {
            PacketRejection::Policy => std::io::ErrorKind::PermissionDenied,
            PacketRejection::InvalidSize => std::io::ErrorKind::InvalidInput,
            PacketRejection::Capacity => std::io::ErrorKind::WouldBlock,
            PacketRejection::Cancelled => std::io::ErrorKind::ConnectionAborted,
        };
        Self::new(kind, rejection)
    }
}

/// A frame write on a stream shared by every destination of a source was
/// cancelled or failed partway, so the stream holds a partial frame and no
/// further frame may follow it.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("shared stream frame write was interrupted")]
pub struct FrameInterrupted;

impl From<FrameInterrupted> for std::io::Error {
    fn from(interrupted: FrameInterrupted) -> Self {
        Self::new(std::io::ErrorKind::BrokenPipe, interrupted)
    }
}

/// Whether an I/O error reports a stream already torn by an earlier frame.
pub fn is_frame_interrupted(error: &std::io::Error) -> bool {
    find_cause::<FrameInterrupted>(error).is_some()
}

/// Whether an error contains a terminal, health-neutral local refusal.
pub fn is_packet_rejection(error: &anyhow::Error) -> bool {
    packet_rejection(error).is_some()
}

/// Recover local refusal details without losing them through error wrappers.
pub fn packet_rejection(error: &anyhow::Error) -> Option<PacketRejection> {
    find_cause::<PacketRejection>(error.as_ref()).copied()
}

/// Recover a typed packet rejection retained inside an I/O error chain.
pub(crate) fn io_packet_rejection(error: &std::io::Error) -> Option<PacketRejection> {
    find_cause::<PacketRejection>(error).copied()
}

/// A datagram the native UDP send refuses as too large is a local size refusal
/// that must not end a shared association or demote the node.
pub(crate) fn send_size_refusal(error: std::io::Error) -> std::io::Error {
    if error.raw_os_error() == Some(libc::EMSGSIZE) {
        PacketRejection::InvalidSize.into()
    } else {
        error
    }
}

/// Coarse classification for packet-send failures shared with the control plane.
///
/// Congestion is deliberately separate from a dead tunnel: dropping one UDP
/// packet under backpressure must not demote an otherwise live outbound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketErrorClass {
    Congestion,
    Rejected,
    ConnectionDead,
    Other,
}

/// Classify an error returned by a [`super::PacketTransport`] operation.
pub fn packet_error_class(error: &std::io::Error) -> PacketErrorClass {
    if io_packet_rejection(error).is_some() {
        return PacketErrorClass::Rejected;
    }
    if matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
    ) || error.raw_os_error() == Some(libc::ENOBUFS)
    {
        return PacketErrorClass::Congestion;
    }

    if let Some(quic_error) = find_cause::<quinn::SendDatagramError>(error) {
        return match quic_error {
            quinn::SendDatagramError::ConnectionLost(_) => PacketErrorClass::ConnectionDead,
            quinn::SendDatagramError::TooLarge => PacketErrorClass::Congestion,
            quinn::SendDatagramError::UnsupportedByPeer | quinn::SendDatagramError::Disabled => {
                PacketErrorClass::Other
            }
        };
    }

    if matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::AddrNotAvailable
    ) {
        PacketErrorClass::ConnectionDead
    } else {
        PacketErrorClass::Other
    }
}

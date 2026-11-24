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
    pub(super) fn dial(hop: usize, error: anyhow::Error) -> anyhow::Error {
        if !is_packet_rejection(&error) && target_failure(&error) {
            Self::Dial { hop, cause: error }.into()
        } else {
            error
        }
    }

    /// Preserve typed causes while the intermediate boundary owns the I/O error.
    pub(super) fn io(hop: usize, error: io::Error) -> io::Error {
        if io_packet_rejection(&error).is_none() && io_target_failure(&error) {
            io::Error::new(
                error.kind(),
                Self::Io {
                    hop,
                    cause: Arc::new(error),
                },
            )
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
}

/// A protocol or transport whose handshake cannot run over a stream tunneled
/// through an earlier hop.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("{0} cannot run over a tunneled stream")]
pub struct TunnelUnsupported(pub &'static str);

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

/// Carrier provenance, with the episode of the innermost fanned-out failure delivering it.
/// Recipients of one fanned-out failure must not report separate node failures, while
/// independently constructed failures stay separate however they settle.
pub(crate) fn node_failure_episode(
    mut error: &(dyn std::error::Error + 'static),
) -> Option<Option<u64>> {
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
            .and_then(crate::SharedError::episode)
        {
            episode = Some(fanout);
        }
        let Some(cause) = next_cause(error) else {
            return node;
        };
        error = cause;
    }
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

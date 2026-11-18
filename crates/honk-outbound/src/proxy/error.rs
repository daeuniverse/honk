/// A proxy's explicit failure to open the requested target, not its carrier.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TargetFailure(#[source] pub anyhow::Error);

/// A failure of the shared proxy carrier or its protocol, not one target.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct NodeFailure(#[source] pub anyhow::Error);

/// A protocol or transport whose handshake cannot run over a stream tunneled
/// through an earlier hop.
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("{0} cannot run over a tunneled stream")]
pub struct TunnelUnsupported(pub &'static str);

fn next_cause<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a (dyn std::error::Error + 'static)> {
    error
        .downcast_ref::<std::io::Error>()
        .and_then(|error| error.get_ref())
        .map(|source| source as &(dyn std::error::Error + 'static))
        .or_else(|| error.source())
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
    loop {
        if error.is::<NodeFailure>() {
            return Some(episode);
        }
        if let Some(fanout) = error
            .downcast_ref::<crate::SharedError>()
            .and_then(crate::SharedError::episode)
        {
            episode = Some(fanout);
        }
        error = next_cause(error)?;
    }
}

/// Recover target provenance through anyhow, I/O and shared error wrappers.
pub fn target_failure(error: &anyhow::Error) -> bool {
    find_cause::<TargetFailure>(error.as_ref()).is_some()
}

pub(crate) fn io_target_failure(error: &std::io::Error) -> bool {
    find_cause::<TargetFailure>(error).is_some()
}

/// Recover explicit carrier provenance without inferring it from error text.
pub fn node_failure(error: &anyhow::Error) -> bool {
    find_cause::<NodeFailure>(error.as_ref()).is_some()
}

pub(crate) fn io_node_failure(error: &std::io::Error) -> bool {
    find_cause::<NodeFailure>(error).is_some()
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

use super::*;

pub(super) async fn wait_for_close(close: Option<&Arc<CloseSignal>>) {
    match close {
        Some(close) => close.cancelled().await,
        None => std::future::pending().await,
    }
}

pub(super) async fn write_sniff_prefix(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin + ?Sized),
    mut buffered: &[u8],
    mut on_write: impl FnMut(usize),
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    while !buffered.is_empty() {
        let written = stream.write(buffered).await?;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        on_write(written);
        buffered = &buffered[written..];
    }
    Ok(())
}

/// How an observed TCP connection ended.
#[cfg(feature = "native-api")]
#[derive(Clone, Copy)]
pub(super) enum TcpTerminal {
    DnsInterceptCompleted,
    NoAvailableNodes,
    PolicyBlock,
    DialFailed,
    IntentionalRetirement,
    PrefixWriteFailed,
    RelayClosed,
    RelayFailed,
    ConnectionFailed,
}

#[cfg(feature = "native-api")]
impl TcpTerminal {
    pub(super) fn outcome(self) -> (crate::observe::vocab::ConnectionState, &'static str) {
        use crate::observe::vocab::ConnectionState::{Blocked, Closed, Failed};
        match self {
            Self::DnsInterceptCompleted => (Closed, "dns_intercept_completed"),
            Self::NoAvailableNodes => (Failed, "no_available_nodes"),
            Self::PolicyBlock => (Blocked, "policy_block"),
            Self::DialFailed => (Failed, "dial_failed"),
            Self::IntentionalRetirement => (Closed, "intentional_retirement"),
            Self::PrefixWriteFailed => (Failed, "prefix_write_failed"),
            Self::RelayClosed => (Closed, "relay_closed"),
            Self::RelayFailed => (Failed, "relay_failed"),
            Self::ConnectionFailed => (Failed, "connection_failed"),
        }
    }
}

//! Why a DNS exchange failed, for the code that decides what happens next.
//!
//! The retry path used to reset the shared session and try again on every
//! error but a typed packet rejection, so a resolver answering `HTTP 400`
//! or a body that is not a DNS message cost a handshake and a second
//! identical request. The classes here let each consumer act on what the
//! error means rather than on the fact that there was one.

/// What a failed exchange says about the query and the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FailureClass {
    /// The transport refused the query itself (policy, size); no retry.
    Rejected,
    /// The peer answered and the answer is unusable (a 4xx status, a body
    /// that is not a DNS message). The session is healthy and the same
    /// query would get the same answer; no reset, no retry.
    Deterministic,
    /// The session may be dead or the answer was lost (transport error,
    /// timeout, 5xx). Reset the session and try once more.
    SessionSuspect,
}

/// A response the peer sent that cannot be a DNS answer to this query.
#[derive(Debug, thiserror::Error)]
#[error("{transport} {reason}")]
pub(super) struct DeterministicResponse {
    pub(super) transport: &'static str,
    pub(super) reason: String,
}

pub(super) fn classify(error: &anyhow::Error) -> FailureClass {
    if honk_outbound::proxy::is_packet_rejection(error) {
        FailureClass::Rejected
    } else if error.downcast_ref::<DeterministicResponse>().is_some()
        || error
            .downcast_ref::<super::body::DnsMessageTooLarge>()
            .is_some()
    {
        FailureClass::Deterministic
    } else {
        FailureClass::SessionSuspect
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_follow_the_error_type() {
        let rejected: anyhow::Error = honk_outbound::proxy::PacketRejection::Policy.into();
        assert_eq!(classify(&rejected), FailureClass::Rejected);
        let refused: anyhow::Error = DeterministicResponse {
            transport: "DoH",
            reason: "HTTP status 400".into(),
        }
        .into();
        assert_eq!(classify(&refused), FailureClass::Deterministic);
        // Context added on the way up does not hide the class.
        assert_eq!(
            classify(&refused.context("DoH exchange")),
            FailureClass::Deterministic
        );
        let lost = anyhow::anyhow!("DoH response error: connection reset");
        assert_eq!(classify(&lost), FailureClass::SessionSuspect);
    }
}

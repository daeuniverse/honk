//! Encrypted and pooled DNS transports (DoT / DoH / DoQ / DoH3).
//!
//! Design goals (performance-first):
//! - Never TLS/QUIC-handshake per query when a live session exists.
//! - DoT: small idle pool of TLS streams (sequential req/resp per stream).
//! - DoH: long-lived HTTP/2 session (`h2`) multiplexing concurrent queries.
//! - DoQ: one QUIC connection, one bi-stream per query (RFC 9250).
//! - DoH3: one QUIC+H3 session, POST `application/dns-message`.
//! - TCP plain: idle stream pool (same shape as DoT without TLS).
//!
//! All direct dials use the configured bypass mark so eBPF does not re-intercept
//! control-plane DNS. Hostnames resolve via `honk_outbound::bootstrap`.

mod body;
mod dial;
mod doh;
mod doh3;
mod doh_message;
mod doq;
mod dot;
mod framing;
mod idle_pool;
mod lifecycle;
mod owned_task;
mod quic;
mod retry;
mod tcp_pool;
mod udp_pool;

#[cfg(test)]
mod tests_proto;

use body::{DnsMessageBody, doh_content_length};
#[cfg(test)]
use body::{DnsMessageTooLarge, MAX_DNS_MESSAGE_SIZE};
use doh_message::{build_doh_request, check_doh_status, finish_doh_response};
use idle_pool::{IdlePoolState, close_idle_pool, idle_pool_exchange};
use quic::{SharedQuicEndpoint, dns_quic_config, quic_connect_endpoint};
use retry::exchange_with_retry;
fn is_valid_response(query: &[u8], response: &[u8]) -> bool {
    crate::dns::query::QueryContext::parse(query)
        .is_ok_and(|query| crate::dns::response::ResponseTemplate::check(&query, response).is_ok())
}

pub use dial::{DialContext, ProxyDial};
pub use doh::DohClient;
pub use doh3::Doh3Client;
pub use doq::DoqClient;
pub use dot::DotPool;
pub use framing::{exchange_length_prefixed, force_dns_id_zero, restore_dns_id};
pub(crate) use framing::{read_length_prefixed_into, write_length_prefixed};
pub(crate) use lifecycle::LifecycleSlot;
pub use tcp_pool::TcpPool;
pub use udp_pool::UdpPool;

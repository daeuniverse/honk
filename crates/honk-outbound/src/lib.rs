//! Outbound connection management — proxy handlers, alive tracking, group selection.
//!
//! ## Modules
//! - `proxy` — Proxy protocol implementations (SOCKS5, Trojan, Shadowsocks, etc.)
//! - `alive` — Per-protocol-per-IP-version alive detection with exponential backoff
//! - `group` — Node group manager with load balancing policies

mod address_race;

pub mod alive;
pub mod bootstrap;
pub mod descriptor;
pub mod group;
pub mod proxy;
pub mod quic;
pub mod quic_boring;
pub mod reality;
pub mod runtime;
pub(crate) mod session;
pub mod tls;
pub mod urltest;
pub mod util;

pub use proxy::{
    AsyncReadWrite, PacketOutbound, PacketTransport, PreparedUdpTransport, ProbeableOutbound,
    ProtocolEntry, ProxyRegistry, ProxyStream, TcpOutbound, WarmOutcome, WarmRequirement,
    WarmableOutbound,
};
pub use util::{connect_marked, connect_marked_addr, connect_outbound, udp_marked_bind};

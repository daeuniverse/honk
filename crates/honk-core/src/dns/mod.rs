//! Generation-pinned DNS forwarding, caching, routing, and transports.
//!
//! The subsystem is split by invariant rather than protocol call depth:
//!
//! - `query`, `response`, and `wire` validate DNS wire identities.
//! - `engine`, `planner`, `policy`, `routing`, and `outcome` evaluate policy.
//! - `cache`, `singleflight`, and `persist` own response reuse and durability.
//! - `endpoint`, `transport`, and `upstream_pool` own upstream I/O.
//! - `forwarder`, `service`, and `resolver` expose resolution workflows.
//! - `runtime` and `projection` publish coherent reload generations and eBPF
//!   domain-routing state.
//!
//! [`DnsResolver`] is the application-level domain-to-address helper used by
//! the control plane. It resolves through the same current [`DnsForwarder`]
//! generation as intercepted and standalone client requests.

#[cfg(feature = "dns-bench")]
pub mod bench_support;
pub mod cache;
pub(crate) mod ecs;
pub mod endpoint;
pub mod engine;
pub mod forwarder;
pub mod outcome;
pub mod persist;
pub mod planner;
pub mod policy;
pub(crate) mod projection;
pub mod query;
mod resolver;
pub mod response;
pub mod routing;
pub(crate) mod runtime;
mod service;
mod singleflight;
pub mod transport;
pub mod upstream_pool;
pub(crate) mod wire;

pub use resolver::{DnsResolver, ResolvedAddr};
pub use service::DnsService;
#[cfg(feature = "native-api")]
pub(crate) use service::{DiagnosticError, DiagnosticFailure, PinnedNameResolver};

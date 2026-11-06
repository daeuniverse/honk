//! Scoped identities and bounded frame ownership for packet adapters.
//!
//! Capture, policy authority, backend memory and device teardown belong to the adapter;
//! a ledger completion is a resource return, not a peer delivery receipt.

#![forbid(unsafe_code)]

pub mod buffer;
pub mod firewall;
pub mod forward;
mod scope;

pub use scope::ScopeId;

//! Sans-I/O IPv4/IPv6 TCP/UDP stack driven by one owner through `&mut Stack`.
//!
//! The core never performs I/O, reads clocks or takes locks: callers pass every
//! received IP packet as a borrowed slice, pull outgoing packets into their own
//! buffers and supply the current time. Retained bytes are copied into
//! stack-owned rings, so a driver may recycle any buffer as soon as a call returns.

#![forbid(unsafe_code)]

pub mod wire;

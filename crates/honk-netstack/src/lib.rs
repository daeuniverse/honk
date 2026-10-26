//! Sans-I/O IPv4/IPv6 TCP/UDP stack driven by one owner through `&mut Stack`.
//!
//! The core never performs I/O, reads clocks or takes locks: callers pass every
//! received IP packet as a borrowed slice, pull outgoing packets into their own
//! buffers and supply the current time. Retained bytes are copied into
//! stack-owned rings, so a driver may recycle any buffer as soon as a call returns.
//!
//! TCP supports active open (including simultaneous open), SACK/DSACK, timestamps,
//! scaled/autotuned receive windows, CUBIC with HyStart++, RACK-TLP loss detection, PRR,
//! spurious-loss undo (DSACK, Eifel, F-RTO), pacing, delayed ACKs, RTO and zero-window
//! probes. There is no listen API, IP reassembly, ECN, urgent-data API or ICMP emission.
//! Unknown TCP options are ignored; malformed lengths stop option parsing. Incoming IP
//! and transport checksums are always verified before changing a flow.
//!
//! # Driving the stack
//!
//! Pass one ingress timestamp to every packet in a receive batch (at most 64 packets).
//! Drain [`Stack::poll_transmit`] after the batch; each call emits one complete IP packet.
//! A short output buffer preserves the pending packet. Arm [`Stack::poll_timeout`] and
//! call [`Stack::handle_timeout`] when it expires; a stale lazy-heap entry can cause an
//! early wakeup. Drain coalesced [`Ready`] events to wake application streams. After an
//! application read/write/shutdown/close/abort, check [`Stack::take_tx_wakeup`] so a
//! window update or FIN cannot sleep behind an otherwise idle driver.
//!
//! Reads drain buffered data before EOF or a sticky terminal error. Shutdown closes only
//! the write half; close releases the handle immediately and finishes the protocol in
//! the background. Closing with unread data sends RST. TIME_WAIT retains unread data
//! and an open application handle; once both are gone and the final ACK is sent, its
//! compact entry holds no chunk reservations and expires after 60 seconds.
//!
//! # Memory and datagrams
//!
//! Chunk storage is 16 KiB. Admission reserves one TX and one RX chunk plus a minimum
//! send-descriptor capacity per TCP flow; excess chunks and descriptor capacity share
//! the configured budget. Receive windows are committed before advertising space,
//! although physical chunks are allocated lazily. Allocation statistics include cached
//! free chunks, so ACKing all data need not make `memory_allocated` zero. Per-flow buffer
//! maxima are bounded to the modular-sequence safe range and at least one chunk.
//!
//! UDP has no queue: [`Rx::Datagram`] borrows a range of the input packet, and
//! [`Stack::udp_send`] writes straight into the caller's output buffer. Datagram payloads
//! exceeding the configured MTU return [`UdpError::TooLarge`]; fragments are dropped.
//! ICMP packet-too-big and unreachable feedback requires a matching outstanding quoted
//! TCP sequence. Each stack's secret must be supplied by its caller and kept private.

#![forbid(unsafe_code)]

pub mod wire;

mod flow;
mod icmp;
mod stack;
mod tcp;
mod timer;
mod udp;

pub use stack::{
    BindError, Config, ConnectError, DropReason, FlowId, Ready, Rx, Stack, StackStats, StreamError,
    UdpError,
};
pub use tcp::{TcpState, TcpStats};

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
//! probes. In [`Mode::Endpoint`] (the default) there is no listen API, IP reassembly or ICMP
//! emission; ECN and urgent data are never supported. See "Transparent termination" below.
//! Unknown TCP options are ignored; malformed lengths stop option parsing. Incoming IP
//! and transport checksums are verified before changing a flow, except where a transparent
//! driver vouches for them (see "Offload").
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
//! [`Stack::poll_control_transmit`] preserves ordinary readiness, DRR and payload TLP work
//! using a lazy separate queue/cursor and the shared emitter. Reserve control credit first;
//! also offer ordinary pulls for payload progress. Unused control-only queues allocate nothing.
//! RACK bookkeeping pressure defers only its flow; other funded output remains eligible.
//!
//! [`Stack::receive_with_source`] reports a [`ValidatedSource`] only for the current completed,
//! checksum-verified TCP/UDP packet, including shared reassembly completion. Its callback can
//! install reverse delivery facts before protocol state mutation; false refuses the packet.
//! This receipt is not handshake or kernel accepted-child proof. Ordinary receive APIs use a
//! reporting-disabled specialization and retain their behavior without reporting allocation.
//! [`Stack::receive_with_tcp_admission`] returns [`ReceiveReport`]: source validity and actual
//! protocol acceptance, including the exact new passive [`FlowId`] for captured policy binding.
//! Neither a new SYN nor protocol acceptance proves a successful outbound admission.
//! [`Stack::retains_tcp`] classifies existing scoped transport ownership through pending
//! opens, TIME_WAIT and flow-owned controls; adapters must additionally retain their own
//! queued/exported output leases. It neither validates input nor mutates protocol state.
//! [`Stack::retains_source`] also covers stateless controls, UDP fragments and reassembly
//! replies for peer-path reclamation. [`Stack::retains_source_output`] distinguishes
//! pending replies from an idle live flow; exported output remains the adapter's duty.
//!
//! Reads drain buffered data before EOF or a sticky terminal error. Shutdown closes only
//! the write half; close releases the handle immediately and finishes the protocol in
//! the background. Closing with unread data sends RST. TIME_WAIT retains unread data
//! and an open application handle; once both are gone and the final ACK is sent, its
//! compact entry holds no chunk reservations and expires after 60 seconds.
//!
//! [`Stack::tcp_retained`] checks the original handle through application close, compact
//! TIME_WAIT and queued refusal output. Drivers retaining delivery state use
//! [`Stack::poll_transmit_with`] and save [`Transmit::flow`] before consulting that query:
//! returned packets, device completions and cross-owner work have separate lifetimes.
//! A [`FlowId`] is local to its Stack, not a network-scope or kernel incarnation. Its
//! generation never wraps into a new handle; an exhausted slot is not reused.
//!
//! # Transparent termination
//!
//! `Config::mode = Mode::Transparent { exclude }` makes the stack answer for every unicast
//! destination except the excluded ones (a backstop; the classifier in front of the driver is
//! what keeps such traffic out). A flow's local end is the packet's original destination, so
//! replies are sourced from it. Multicast, broadcast and unspecified destinations (the tun's own
//! RS/MLD/DAD) are dropped silently as [`DropReason::Unsupported`].
//! Mapped IPv6 wire endpoints are also rejected before retaining fragment state.
//!
//! A SYN creates a pending flow and sends nothing. [`Stack::poll_accept`] reports it once as a
//! [`SynInfo`]; the application then calls [`Stack::tcp_accept`] (`Now` queues the SYN-ACK,
//! `Deferred` holds it until [`Stack::tcp_complete`] after an upstream dial) or
//! [`Stack::tcp_refuse`] (RST, silent drop, ICMP host unreachable or administratively
//! prohibited). Retransmitted SYNs are absorbed without a second flow or report. A SYN nobody
//! decides on, or a deferred one nobody completes, dies silently 25 s after it arrived
//! ([`MAX_DEFERRED`]); a reported flow then surfaces `ERROR` and must still be closed.
//! `AcceptOpts::max_mss` clamps the connection's MSS in both directions (the client's real egress
//! MTU), `AcceptOpts::keepalive` arms per-flow [`Keepalive`] probing (off by default; a flow whose
//! probes all go unanswered fails with `TimedOut`). Half-open flows are capped in total and per
//! client address ([`Config::half_open_max`], [`Config::half_open_per_source`]); SYNs beyond a
//! cap, or beyond the flow or memory limits, are dropped and counted
//! ([`DropReason::HalfOpen`], [`DropReason::Capacity`]), never answered and never cookied.
//! [`Stack::has_pending_accept`] can skip an empty probe without consuming a candidate;
//! stale queued handles can still make a subsequent `poll_accept` return `None`.
//!
//! The side that closes first keeps TIME_WAIT (RFC 9293 MUST-13), including simultaneous close,
//! with the RFC 6191 reopen check for a new SYN on the same tuple; the side that closes second
//! goes LAST_ACK to CLOSED. A server-side TIME_WAIT is therefore never skipped. The compact
//! TIME_WAIT entry lives inside the stack for 60 s after the last FIN exchange: a driver must keep
//! delivering packets for that tuple to [`Stack::receive`] for that long (the delivery state in
//! front of the stack, such as an eBPF redirect entry, must outlive the flow), or a client's
//! retransmitted FIN reaches the real server instead of the tombstone and is answered with RST.
//!
//! UDP is stateless: [`Rx::Transparent`] carries both addresses, [`Stack::udp_send_from`]
//! answers from any source and fragments oversized replies. [`Rx::Transparent`] and
//! [`Rx::TransparentSplit`] index the borrowed input: consume or copy every datagram before
//! recycling a driver buffer (for AF_XDP, before returning its frame to FILL). Reassembled UDP
//! instead yields [`Rx::TransparentOwned`], whose payload indexes its owned packet. Fragmented
//! packets are reassembled within bounded limits ([`FragmentLimits`]); ICMP errors are rate limited
//! ([`IcmpLimits`]). TCP data has already been copied into the ring when `receive_with` returns.
//!
//! # Offload
//!
//! A transparent driver reading a TUN device with `virtio_net_hdr` hands the stack what the
//! kernel knows, through [`Stack::receive_with`] and [`RxMeta`]. [`Csum::Verify`] (flags 0) is the
//! only provenance [`Stack::receive`] and an endpoint stack know. [`Csum::Valid`]
//! (`DATA_VALID`) says the checksum was verified already; [`Csum::Partial`] (`NEEDS_CSUM`,
//! `CHECKSUM_PARTIAL`) says the field holds only the pseudo-header sum, common for locally
//! generated packets and GRO super-packets, so there is no complete checksum to verify. Both are
//! accepted only in [`Mode::Transparent`]; an endpoint stack (the WireGuard driver) drops any
//! packet that carries offload metadata as [`DropReason::Unsupported`]. The IP header, ICMP and
//! datagrams reassembled from fragments are always verified, and a `Partial` that does not
//! point at the L4 checksum field is [`DropReason::Malformed`]. A TCP super-packet
//! ([`GsoRx`]) is ingested as one contiguous segment; `ceil(len / size)` counts only the
//! full frames of the delayed-ACK cadence (two or more are acknowledged at once, with one ACK),
//! while dupACK, SACK, RACK, PAWS and timestamps see it as the single segment it is. A UDP
//! super-packet is [`Rx::TransparentSplit`]: chunks of `size` bytes are the datagrams.
//!
//! [`Stack::poll_transmit_with`] and [`TxCaps`] let a TCP flow emit one TSO packet of up to 64
//! KiB: one header, MSS-sized segments, the checksum field holding the pseudo-header sum
//! ([`TxCsum::Partial`], the field is not complemented). The packet is as long as the congestion
//! and receive windows, the pacer (a burst is at most two milliseconds of traffic) and about a
//! millisecond of the pacing rate allow, and as the output buffer holds. Each segment keeps its
//! own send descriptor, so SACK and RACK are unchanged, and a run of lost segments is
//! retransmitted as one TSO packet too. [`Stack::udp_send_gso_from`] sends up to 64 equal
//! datagrams as one USO packet (the last may be shorter); without the family's capability, or in
//! endpoint mode, a multi-datagram send returns [`UdpError::Offload`]. `poll_transmit_with` with no
//! capabilities, and every `poll_transmit` call, keep the ordinary single-packet behavior.
//!
//! # Memory and datagrams
//!
//! Chunk storage is 16 KiB in [`Mode::Endpoint`] and 4 KiB in [`Mode::Transparent`]
//! ([`Config::tcp_chunk`] overrides it, 4 to 64 KiB). Admission reserves one TX and one RX chunk
//! plus a minimum send-descriptor capacity per TCP flow; excess chunks and descriptor capacity share
//! the configured budget. The initial window too is committed before its SYN or SYN-ACK advertises
//! it (`tcp_connect` / `tcp_accept` may consume shared space immediately), so admitting an idle flow
//! need not commit only its floor. Physical chunks are allocated lazily. A ring that empties
//! (everything read or acknowledged) returns all its chunks, and descriptor storage is released
//! when nothing is
//! in flight: the floor is a guarantee, not resident memory. Allocation statistics include
//! the pool's cached free chunks (up to 64 while any chunk is in use, one otherwise).
//! [`Config::shared_budget`] lets stacks of one process share an additional limit, charged
//! for floors and commitments and refunded as flows retire and when a stack is dropped.
//! Reassembly storage, queued Time Exceeded quotes and pending UDP fragment datagram capacities
//! share that budget too. Queued storage stays charged across blocked output until sent or dropped.
//! Per-flow buffer maxima are bounded to the modular-sequence safe range and at least one chunk.
//! [`Stack::new_accounted`] also reserves conservative metadata/growth/cache capacity and bounds
//! slab slots before construction. [`Stack::overhead_reserved`] is not resident memory or RSS.
//! [`Stack::set_accepting`] closes new passive admission without disabling existing delivery.
//! Completed reassembly returns [`OwnedPacket`], whose [`MemoryReservation`] remains owned
//! through consumer release, even if the Stack has already been dropped.
//!
//! Endpoint UDP has no queue: [`Rx::Datagram`] borrows a range of the input packet, and
//! [`Stack::udp_send`] writes straight into the caller's output buffer. Datagram payloads
//! exceeding the configured MTU return [`UdpError::TooLarge`]; in endpoint mode fragments are
//! dropped.
//! ICMP packet-too-big and unreachable feedback requires a matching outstanding quoted
//! TCP sequence. Each stack's secret must be supplied by its caller and kept private.

#![forbid(unsafe_code)]

pub mod transit;
pub mod wire;

mod accept;
mod budget;
mod flow;
mod fragment;
mod icmp;
mod icmp_out;
mod mode;
mod offload;
mod stack;
mod tcp;
mod timer;
mod udp;
mod udp_t;

pub use accept::{AcceptOpts, AcceptWhen, Keepalive, MAX_DEFERRED, Refuse, SynInfo};
pub use budget::{MemoryBudget, MemoryReservation};
pub use fragment::{FragmentLimits, OwnedPacket};
pub use icmp_out::IcmpLimits;
pub use mode::{ExcludeSet, Mode};
pub use offload::{Csum, GsoKind, GsoRx, GsoTx, RxMeta, Transmit, TxCaps, TxCsum};
pub use stack::{
    BindError, Config, ConnectError, ConstructionError, DropReason, FlowId, Ready, ReceiveOutcome,
    ReceiveReport, Rx, Stack, StackStats, StreamError, UdpError, ValidatedSource,
};
pub use tcp::{TcpState, TcpStats};
pub use udp_t::UdpRefuse;

/// Property checks behind the `fuzz/` targets and `tests/fuzz_replay.rs`; not part of the API.
#[cfg(feature = "fuzz-checks")]
#[doc(hidden)]
pub mod fuzz_checks;

//! Passive open and keepalive: the parts of a TCB that only terminated flows use.

use std::time::Instant;

use super::cc::Cc;
use super::ring::Pool;
use super::{Tcb, TcpState};
use crate::accept::{AcceptOpts, AcceptWhen, MAX_DEFERRED};
use crate::flow::FourTuple;
use crate::wire::tcp::Header;
use crate::{Config, StreamError};

/// Whether the application has let a passively opened flow answer. Everything but `Open`
/// suppresses all output and ignores all input, so a SYN costs nothing on the wire until the
/// upper layer has decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Active opens and accepted flows.
    Open,
    /// SYN received, not yet reported by `poll_accept`.
    Queued,
    /// Reported; waiting for `tcp_accept` or `tcp_refuse`.
    Pending,
    /// `tcp_accept` with a deferred SYN-ACK; waiting for `tcp_complete` or `tcp_refuse`.
    Held,
}

impl Tcb {
    /// A flow in SYN_RECEIVED for `syn`, with the SYN-ACK withheld. The receive window is not
    /// committed yet: only the funded floor backs the flow until [`Tcb::accept`].
    pub fn new_passive(
        tuple: FourTuple,
        cfg: &Config,
        now: Instant,
        epoch: Instant,
        iss: u32,
        ts_offset: u32,
        syn: &Header,
    ) -> Tcb {
        let mut t = Tcb::new(tuple, cfg, now, epoch, iss, ts_offset);
        t.state = TcpState::SynReceived;
        t.gate = Gate::Queued;
        t.half_open = true;
        t.syn_due = false;
        t.irs = syn.seq;
        t.rcv_nxt = syn.seq.wrapping_add(1);
        t.rx.rd_seq = t.rcv_nxt;
        t.max_adv_right = t.rcv_nxt;
        t.committed_right = t.rcv_nxt;
        t.last_adv_right = t.rcv_nxt;
        t.last_ack_sent = t.rcv_nxt;
        t.peer_mss = syn
            .options
            .mss
            .unwrap_or(if tuple.local.is_ipv6() { 1220 } else { 536 })
            // Linux's `tcp_min_snd_mss`: a hostile client must not buy one packet per byte.
            .max(48);
        t.snd_shift = syn.options.wscale.unwrap_or(0);
        t.wscale = syn.options.wscale.is_some();
        if !t.wscale {
            t.rcv_shift = 0;
        }
        t.sack = syn.options.sack_permitted;
        t.timestamps = syn.options.timestamps.is_some();
        t.ts_recent = syn.options.timestamps.map(|(ts, _)| (ts, now));
        t.cc = Cc::new(t.send_mss());
        t.rcv_mss = t.send_mss().min(536) as usize;
        t.snd_wnd = syn.window.into();
        t.snd_wnd_max = t.snd_wnd;
        t.snd_wl1 = syn.seq;
        t.snd_wl2 = iss;
        t.close_deadline = Some(now + MAX_DEFERRED);
        t
    }

    /// Applies the application's admission: MSS clamp, keepalive, window commitment and the gate.
    pub fn accept(&mut self, opts: &AcceptOpts, now: Instant, pool: &mut Pool) {
        if let Some(max) = opts.max_mss {
            // The connection's segments, in both directions, must fit the client's real path.
            let max = max.max(48);
            self.local_mss = self.local_mss.min(max);
            self.peer_mss = self.peer_mss.min(max);
            self.cc = Cc::new(self.send_mss());
            self.rcv_mss = self.send_mss().min(536) as usize;
        }
        self.keepalive = opts.keepalive;
        self.init_window(pool);
        match opts.when {
            AcceptWhen::Now => self.open_gate(),
            AcceptWhen::Deferred { deadline } => {
                self.gate = Gate::Held;
                // Never later than the undecided deadline set by the SYN: 25 s in total.
                let at = now + deadline.min(MAX_DEFERRED);
                self.close_deadline = Some(self.close_deadline.map_or(at, |d| d.min(at)));
            }
        }
    }

    /// Lets the SYN-ACK go.
    pub fn open_gate(&mut self) {
        self.gate = Gate::Open;
        self.syn_due = true;
        self.close_deadline = None;
    }

    pub fn arm_keepalive(&mut self, now: Instant) {
        self.ka_deadline = self.keepalive.map(|k| now + k.idle);
    }

    /// Probes an idle peer with an empty segment at `snd_una - 1` and fails the flow when
    /// `probes` of them in a row go unanswered. Activity only moves `ka_rx`; an early wakeup
    /// finds the flow busy and re-arms, so the hot path never touches the timer.
    pub(super) fn keepalive_timer(&mut self, now: Instant) {
        if self.ka_deadline.is_none_or(|t| t > now) {
            return;
        }
        let Some(k) = self.keepalive else {
            self.ka_deadline = None;
            return;
        };
        if matches!(
            self.state,
            TcpState::SynSent | TcpState::SynReceived | TcpState::TimeWait | TcpState::Closed
        ) {
            self.ka_deadline = None;
            return;
        }
        // With probes outstanding the deadline is ours and any activity would have reset them.
        let due = self.ka_rx + k.idle;
        if self.ka_probes == 0 && due > now {
            self.ka_deadline = Some(due);
        } else if self.ka_probes >= k.probes.max(1) {
            self.fail(StreamError::TimedOut);
        } else {
            self.ka_probes += 1;
            self.probe_due = true;
            self.ka_deadline = Some(now + k.interval);
        }
    }
}

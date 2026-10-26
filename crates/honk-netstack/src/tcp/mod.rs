//! TCP protocol state. The stack owns scheduling; each TCB owns its reply obligations.

pub(crate) mod cc;
mod cubic;
mod input;
pub(crate) use input::valid_timewait_fin;
pub(crate) mod output;
mod pacing;
mod prr;
mod rack;
pub(crate) mod recovery;
pub(crate) mod passive;
pub(crate) mod ring;
pub(crate) mod rtt;
pub(crate) mod sack;
pub(crate) mod sent;
pub(crate) mod seq;

use std::time::{Duration, Instant};

use crate::flow::FourTuple;
use crate::accept::Keepalive;
use crate::{Config, Ready, StreamError};
use cc::Cc;
use pacing::Pacer;
use recovery::Recovery;
use ring::{CHUNK, Pool, RecvRing, SendRing};
use sack::OooTable;
use sent::Sent;

pub const DATA: u8 = 1;
pub const OOO: u8 = 2;
pub const WINDOW_UPDATE: u8 = 4;
pub const PROBE_RESPONSE: u8 = 8;
pub const CHALLENGE: u8 = 16;
pub const FIN_ACK: u8 = 32;

pub const TIME_WAIT: Duration = Duration::from_secs(60);
const DELAY_ACK: Duration = Duration::from_millis(40);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpStats {
    pub srtt: Option<Duration>,
    pub rto: Duration,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub bytes_in_flight: u32,
    pub outstanding_bytes: u32,
    pub sacked_bytes: u32,
    pub lost_bytes: u32,
    pub retrans_in_flight: u32,
    pub retrans_bytes: u64,
    pub delivery_rate: u64,
    pub retrans_segments: u64,
    pub rto_count: u64,
    pub challenge_acks: u64,
    pub ooo_drops: u64,
    pub pmtu: u16,
    pub send_window: u32,
    pub receive_window: u32,
    pub receive_committed: usize,
    /// Congestion events (fast recoveries and tail-loss-probe discoveries).
    pub loss_events: u64,
    /// Loss episodes later proven spurious (DSACK, timestamp echo or F-RTO).
    pub spurious_recoveries: u64,
    /// Congestion windows restored after a spurious episode.
    pub undo_count: u64,
    pub tlp_probes: u64,
    /// Current RACK reordering window.
    pub reo_wnd: Duration,
}

/// The counters `TcpStats` reports that no other state derives.
#[derive(Default)]
struct Counters {
    delivery_rate: u64,
    retrans_bytes: u64,
    retrans_segments: u32,
    rto_count: u32,
    challenge_acks: u32,
    ooo_drops: u32,
}

pub struct Tcb {
    pub tuple: FourTuple,
    pub state: TcpState,
    pub app_open: bool,
    pub error: Option<StreamError>,
    pub ready: Ready,
    pub iss: u32,
    pub irs: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub(crate) snd_wnd_max: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    pub snd_shift: u8,
    pub rcv_shift: u8,
    pub wscale: bool,
    pub sack: bool,
    pub timestamps: bool,
    pub ts_recent: Option<(u32, Instant)>,
    pub ts_offset: u32,
    pub epoch: Instant,
    pub peer_mss: u16,
    pub local_mss: u16,
    pub pmtu: u16,
    pub rcv_nxt: u32,
    pub max_adv_right: u32,
    pub committed_right: u32,
    last_adv_right: u32,
    last_ack_sent: u32,
    pub rx: RecvRing,
    pub tx: SendRing,
    pub sent: Sent,
    pub ooo: OooTable,
    pub dsack: Option<(u32, u32)>,
    pub ack_due: u8,
    pub ooo_acks: u16,
    full_segments: u8,
    quickack: u8,
    last_rx: Instant,
    challenge_last: Option<Instant>,
    pub delack_deadline: Option<Instant>,
    pub rto_deadline: Option<Instant>,
    pub close_deadline: Option<Instant>,
    pub syn_due: bool,
    pub syn_sent: Option<Instant>,
    pub syn_retries: u8,
    pub rst_pending: bool,
    pub fin_requested: bool,
    pub fin_seq: Option<u32>,
    pub peer_fin: Option<u32>,
    pub peer_fin_seen: bool,
    pub probe_due: bool,
    pub persist: bool,
    pub persist_probes: u8,
    /// Exponent of the probe interval; unlike the retry count, only an opened window resets it.
    persist_backoff: u8,
    pub rtt: rtt::Rtt,
    pub cc: Cc,
    pub recovery: Recovery,
    pub cwnd_limited: bool,
    pacer: Pacer,
    pacing_deadline: Option<Instant>,
    tlp_deadline: Option<Instant>,
    tlp_due: bool,
    /// `delivered` at the time the sender ran out of data with window to spare; rate samples whose
    /// data was sent before it do not measure the path (draft-cheng-iccrg-delivery-rate-estimation).
    app_limited_until: u64,
    pub write_blocked: bool,
    pub write_wait_queued: bool,
    snd_max: usize,
    rcv_max: usize,
    rcv_target: usize,
    rcv_mss: usize,
    rcv_last_size: usize,
    rcv_rtt: Duration,
    rcv_rtt_seq: u32,
    rcv_rtt_time: Instant,
    drs_time: Instant,
    drs_copied: usize,
    pub delivered: u64,
    pub delivered_ts: Instant,
    pub first_tx_ts: Instant,
    /// Last data (new or retransmitted) segment sent; ACKs and probes do not count as activity
    /// for the idle restart (RFC 5681 §4.1).
    last_data_tx: Instant,
    stats: Counters,
    /// Passive open: whether the application has let the SYN-ACK go; see [`passive::Gate`].
    pub(crate) gate: passive::Gate,
    /// Counted against the stack's half-open caps until the handshake completes or the flow dies.
    pub(crate) half_open: bool,
    pub(crate) keepalive: Option<Keepalive>,
    ka_deadline: Option<Instant>,
    /// Last accepted segment from the peer; keepalive idleness is measured from here.
    ka_rx: Instant,
    ka_probes: u8,
}

impl Tcb {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tuple: FourTuple,
        cfg: &Config,
        now: Instant,
        epoch: Instant,
        iss: u32,
        ts_offset: u32,
    ) -> Tcb {
        let local_mss = cfg
            .mtu
            .saturating_sub(if tuple.local.is_ipv6() { 60 } else { 40 })
            .max(1);
        let peer_mss = if tuple.local.is_ipv6() { 1220 } else { 536 };
        let rcv_max = cfg.tcp_rcv_buf_max.clamp(CHUNK, 1 << 30);
        let mut rcv_shift = 0;
        while rcv_shift < 14 && (u16::MAX as usize) << rcv_shift < rcv_max {
            rcv_shift += 1;
        }
        Tcb {
            tuple,
            state: TcpState::SynSent,
            app_open: true,
            error: None,
            ready: Ready::default(),
            iss,
            irs: 0,
            snd_una: iss,
            snd_nxt: iss,
            snd_wnd: u16::MAX.into(),
            snd_wnd_max: u16::MAX.into(),
            snd_wl1: 0,
            snd_wl2: 0,
            snd_shift: 0,
            rcv_shift,
            wscale: false,
            sack: false,
            timestamps: false,
            ts_recent: None,
            ts_offset,
            epoch,
            peer_mss,
            local_mss,
            pmtu: cfg.mtu,
            rcv_nxt: 0,
            max_adv_right: 0,
            committed_right: 0,
            last_adv_right: 0,
            last_ack_sent: 0,
            rx: RecvRing::new(0),
            tx: SendRing::default(),
            sent: Sent::new(iss.wrapping_add(1)),
            ooo: OooTable::default(),
            dsack: None,
            ack_due: 0,
            ooo_acks: 0,
            full_segments: 0,
            quickack: 16,
            last_rx: now,
            challenge_last: None,
            delack_deadline: None,
            rto_deadline: None,
            close_deadline: None,
            syn_due: true,
            syn_sent: None,
            syn_retries: 0,
            rst_pending: false,
            fin_requested: false,
            fin_seq: None,
            peer_fin: None,
            peer_fin_seen: false,
            probe_due: false,
            persist: false,
            persist_probes: 0,
            persist_backoff: 0,
            rtt: rtt::Rtt::default(),
            cc: Cc::new(u32::from(local_mss)),
            recovery: Recovery::new(iss.wrapping_add(1)),
            cwnd_limited: false,
            pacer: Pacer::new(now),
            pacing_deadline: None,
            tlp_deadline: None,
            tlp_due: false,
            app_limited_until: 0,
            write_blocked: false,
            write_wait_queued: false,
            snd_max: cfg.tcp_snd_buf_max.clamp(CHUNK, 1 << 30),
            rcv_max,
            rcv_target: usize::from(u16::MAX).min(rcv_max),
            rcv_mss: usize::from(local_mss.min(536)),
            rcv_last_size: 0,
            rcv_rtt: Duration::from_millis(100),
            rcv_rtt_seq: 0,
            rcv_rtt_time: now,
            drs_time: now,
            drs_copied: 0,
            delivered: 0,
            delivered_ts: now,
            first_tx_ts: now,
            last_data_tx: now,
            stats: Counters::default(),
            gate: passive::Gate::Open,
            half_open: false,
            keepalive: None,
            ka_deadline: None,
            ka_rx: now,
            ka_probes: 0,
        }
    }

    pub fn timestamp(&self, now: Instant) -> u32 {
        self.ts_offset
            .wrapping_add(now.saturating_duration_since(self.epoch).as_millis() as u32)
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        [
            self.rto_deadline,
            self.delack_deadline,
            self.close_deadline,
            self.tlp_deadline,
            self.recovery.reo_deadline(),
            self.pacing_deadline,
            self.ka_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub fn available(&self) -> usize {
        let end = self
            .peer_fin
            .filter(|_| self.peer_fin_seen)
            .unwrap_or(self.rcv_nxt);
        end.wrapping_sub(self.rx.rd_seq) as usize
    }

    pub fn receive_window(&self) -> u32 {
        if self.peer_fin_seen {
            return 0;
        }
        self.max_adv_right.wrapping_sub(self.rcv_nxt)
    }

    fn grow_window(&mut self, pool: &mut Pool) {
        let want = self.rx.rd_seq.wrapping_add(self.rcv_target as u32);
        if !seq::gt(want, self.committed_right) {
            return;
        }
        let candidate = self.rx.limit_right(pool, want);
        if seq::gt(candidate, self.committed_right) && self.rx.grow(pool, candidate) {
            self.committed_right = candidate;
        }
    }

    pub fn write(&mut self, pool: &mut Pool, data: &[u8]) -> Result<usize, StreamError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.fin_requested || matches!(self.state, TcpState::TimeWait | TcpState::Closed) {
            return Err(StreamError::Closed);
        }
        if data.is_empty() {
            return Ok(0);
        }
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            self.write_blocked = true;
            return Err(StreamError::WouldBlock);
        }
        let limit = self.send_limit();
        let n = self.tx.write(
            pool,
            &data[..data.len().min(limit.saturating_sub(self.tx.len()))],
        );
        if n == 0 {
            self.write_blocked = true;
            return Err(StreamError::WouldBlock);
        }
        Ok(n)
    }

    fn send_limit(&self) -> usize {
        (2 * self.cc.cwnd() as usize)
            .max(4 * CHUNK)
            .min(self.snd_max)
    }

    pub fn can_write(&self, pool: &Pool) -> bool {
        let threshold = CHUNK.min(self.send_limit() / 2);
        self.app_open
            && self.error.is_none()
            && !self.fin_requested
            && matches!(self.state, TcpState::Established | TcpState::CloseWait)
            && self.send_limit().saturating_sub(self.tx.len()) >= threshold
            && (pool.shared_free() != 0 || self.tx.tail_room() >= threshold)
    }

    pub fn read(
        &mut self,
        pool: &mut Pool,
        out: &mut [u8],
        now: Instant,
    ) -> Result<usize, StreamError> {
        let avail = self.available();
        if avail != 0 {
            if out.is_empty() {
                return Err(StreamError::WouldBlock);
            }
            let old_window = self.wire_window(false);
            let n = self.rx.read(pool, out, avail);
            self.drs_copied = self.drs_copied.saturating_add(n);
            if now.saturating_duration_since(self.drs_time) >= self.rcv_rtt {
                self.rcv_target = self
                    .rcv_target
                    .max(
                        self.drs_copied
                            .saturating_mul(2)
                            .saturating_add(16 * usize::from(self.local_mss)),
                    )
                    .min(self.rcv_max);
                self.drs_copied = 0;
                self.drs_time = now;
            }
            if self.available() == 0 && self.ooo.is_empty() {
                self.rx.compact(pool, self.committed_right);
            } else {
                self.rx.shrink(pool, self.committed_right);
            }
            if !self.peer_fin_seen {
                self.grow_window(pool);
                let right = self.wire_right(false);
                if (old_window == 0 && self.wire_window(false) != 0)
                    || (seq::gt(right, self.last_adv_right)
                        && right.wrapping_sub(self.last_adv_right) >= 2 * u32::from(self.local_mss))
                {
                    self.ack_due |= WINDOW_UPDATE;
                }
            }
            return Ok(n);
        }
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.peer_fin_seen || self.state == TcpState::Closed {
            return Ok(0);
        }
        Err(StreamError::WouldBlock)
    }

    pub fn shutdown(&mut self) -> Result<(), StreamError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        match self.state {
            TcpState::Established => self.state = TcpState::FinWait1,
            TcpState::CloseWait => self.state = TcpState::LastAck,
            TcpState::SynSent | TcpState::SynReceived => return Err(StreamError::WouldBlock),
            _ => return Ok(()),
        }
        self.fin_requested = true;
        Ok(())
    }

    pub fn close(&mut self, now: Instant) {
        self.app_open = false;
        if self.available() != 0 || !self.ooo.is_empty() {
            self.abort();
        } else if self.state == TcpState::SynSent {
            self.state = TcpState::Closed;
            self.rto_deadline = None;
        } else if self.state == TcpState::SynReceived {
            self.abort();
        } else if self.state == TcpState::FinWait2 {
            self.close_deadline = Some(now + TIME_WAIT);
        } else {
            let _ = self.shutdown();
        }
    }

    pub fn abort(&mut self) {
        self.app_open = false;
        self.rst_pending = self.syn_sent.is_some() && self.state != TcpState::Closed;
        self.state = TcpState::Closed;
        self.rto_deadline = None;
        self.delack_deadline = None;
        self.close_deadline = None;
        self.ack_due = 0;
        self.ka_deadline = None;
    }

    pub fn fail(&mut self, error: StreamError) {
        self.error = Some(error);
        self.state = TcpState::Closed;
        self.rto_deadline = None;
        self.delack_deadline = None;
        self.close_deadline = None;
        self.ack_due = 0;
        self.ka_deadline = None;
        self.ready |= Ready::ERROR | Ready::READABLE | Ready::WRITABLE | Ready::READ_CLOSED;
    }

    fn enter_timewait(&mut self, now: Instant) {
        self.state = TcpState::TimeWait;
        self.close_deadline = Some(now + TIME_WAIT);
        self.rto_deadline = None;
        self.ka_deadline = None;
        self.ready |= Ready::READ_CLOSED;
    }

    fn challenge(&mut self, now: Instant) {
        if self
            .challenge_last
            .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_millis(100))
        {
            self.challenge_last = Some(now);
            self.ack_due |= CHALLENGE;
            self.stats.challenge_acks += 1;
        }
    }

    fn wire_window(&self, syn: bool) -> u16 {
        if self.peer_fin_seen {
            return 0;
        }
        let shift = if syn || !self.wscale {
            0
        } else {
            self.rcv_shift
        };
        (self.committed_right.wrapping_sub(self.rcv_nxt) >> shift).min(u32::from(u16::MAX)) as u16
    }

    fn wire_right(&self, syn: bool) -> u32 {
        let shift = if syn || !self.wscale {
            0
        } else {
            self.rcv_shift
        };
        self.rcv_nxt
            .wrapping_add(u32::from(self.wire_window(syn)) << shift)
    }

    pub fn timer(&mut self, now: Instant) {
        if self.delack_deadline.is_some_and(|t| t <= now) {
            self.delack_deadline = None;
            self.ack_due |= DATA;
        }
        if self.close_deadline.is_some_and(|t| t <= now) {
            self.close_deadline = None;
            if self.state == TcpState::TimeWait {
                if self.ack_due != 0 {
                    self.close_deadline = Some(now + TIME_WAIT);
                } else {
                    self.state = TcpState::Closed;
                }
            } else if self.gate == passive::Gate::Queued {
                // No application ever saw this SYN: forget it silently, the client retries.
                self.abort();
            } else {
                self.fail(StreamError::TimedOut);
            }
        }
        if self.pacing_deadline.is_some_and(|t| t <= now) {
            self.pacing_deadline = None;
        }
        if self.recovery.reo_deadline().is_some_and(|t| t <= now) {
            let mss = self.send_mss();
            self.recovery.reo_timeout(
                &mut self.sent,
                &mut self.cc,
                now,
                self.snd_nxt,
                mss,
                &self.rtt,
            );
        }
        if self.rto_deadline.is_some_and(|t| t <= now) {
            self.rto_expired(now);
        } else if self.tlp_deadline.is_some_and(|t| t <= now) {
            self.tlp_deadline = None;
            self.tlp_due = true;
        }
        self.keepalive_timer(now);
    }

    fn rto_expired(&mut self, now: Instant) {
        self.rto_deadline = None;
        if matches!(self.state, TcpState::SynSent | TcpState::SynReceived) {
            if self.syn_retries >= 6 {
                self.fail(StreamError::TimedOut);
                return;
            }
            self.syn_retries += 1;
            self.rtt.timeout();
            self.syn_due = true;
        } else if self.persist {
            if self.persist_probes >= 15 {
                self.fail(StreamError::TimedOut);
                return;
            }
            self.persist_probes += 1;
            self.persist_backoff = (self.persist_backoff + 1).min(10);
            self.probe_due = true;
            self.rto_deadline = Some(
                now + self
                    .rtt
                    .rto()
                    .saturating_mul(1 << self.persist_backoff)
                    .min(rtt::MAX_RTO),
            );
        } else if self.sent.outstanding != 0 {
            if self.rtt.backoff >= 15 {
                self.fail(StreamError::TimedOut);
                return;
            }
            self.stats.rto_count += 1;
            let mss = self.send_mss();
            self.recovery
                .rto(&mut self.sent, &mut self.cc, self.snd_nxt, mss);
            self.rtt.timeout();
            self.tlp_deadline = None;
            self.tlp_due = false;
        }
    }

    /// Arms the tail loss probe (RFC 8985 §7.2): `2 * SRTT`, plus the peer's ACK delay when a lone
    /// segment is in flight, never later than the retransmission timer.
    pub fn rearm_pto(&mut self, now: Instant) {
        self.tlp_deadline = None;
        if !self.sack
            || self.persist
            || self.recovery.state() != recovery::State::Open
            || self.sent.outstanding == 0
            || self.recovery.rack.tlp.is_some()
            || !self.may_send_new()
        {
            return;
        }
        let Some(srtt) = self.rtt.srtt() else { return };
        let mut pto = 2 * srtt;
        if self.sent.queue.len() <= 1 {
            pto += rack::MAX_ACK_DELAY;
        }
        let rto = self.rto_deadline.unwrap_or(now + self.rtt.rto());
        self.tlp_deadline = Some((now + pto).min(rto));
    }

    pub fn rearm(&mut self, now: Instant) {
        if matches!(
            self.state,
            TcpState::Closed | TcpState::TimeWait | TcpState::SynSent | TcpState::SynReceived
        ) {
            return;
        }
        // A probe replaces the retransmission timer only when nothing is outstanding: with data in
        // flight a zero window must still retransmit the head, or a lost hole stalls forever.
        if self.snd_wnd == 0
            && self.sent.outstanding == 0
            && (self.tx.len() != 0 || (self.fin_requested && self.fin_seq.is_none()))
        {
            self.persist = true;
            if self.rto_deadline.is_none() {
                self.rto_deadline = Some(now + self.rtt.rto());
            }
        } else if self.sent.outstanding != 0 {
            self.persist = false;
            if self.rto_deadline.is_none() {
                self.rto_deadline = Some(now + self.rtt.rto());
            }
        } else {
            self.persist = false;
            self.rto_deadline = None;
        }
    }

    pub fn send_mss(&self) -> u32 {
        let options = if self.timestamps { 12 } else { 0 };
        let ip = if self.tuple.local.is_ipv6() { 40 } else { 20 };
        u32::from(
            self.peer_mss
                .saturating_sub(options)
                .max(1)
                .min(self.pmtu.saturating_sub(ip + 20 + options).max(1)),
        )
    }

    pub fn pmtu(&mut self, mtu: u16) {
        let floor = if self.tuple.local.is_ipv6() { 1280 } else { 68 };
        let mtu = mtu.max(floor);
        if mtu >= self.pmtu {
            return;
        }
        self.pmtu = mtu;
        let opts = if self.timestamps { 12 } else { 0 };
        let cap = u32::from(
            mtu.saturating_sub(if self.tuple.local.is_ipv6() { 60 } else { 40 })
                .saturating_sub(opts),
        )
        .max(1);
        self.sent.pmtu_changed(cap);
    }

    pub fn stats(&self) -> TcpStats {
        TcpStats {
            srtt: self.rtt.srtt(),
            rto: self.rtt.rto(),
            cwnd: self.cc.cwnd(),
            ssthresh: self.cc.ssthresh(),
            bytes_in_flight: self.recovery.pipe(&self.sent, self.sack),
            outstanding_bytes: self.sent.outstanding,
            sacked_bytes: self.sent.sacked,
            lost_bytes: self.sent.lost,
            retrans_in_flight: self.sent.retrans,
            loss_events: u64::from(self.recovery.counters.loss_events),
            spurious_recoveries: u64::from(self.recovery.counters.spurious_recoveries),
            undo_count: u64::from(self.recovery.counters.undo_count),
            tlp_probes: u64::from(self.recovery.counters.tlp_probes),
            reo_wnd: self
                .recovery
                .reo_wnd_now(&self.sent, &self.rtt, self.send_mss()),
            pmtu: self.pmtu,
            send_window: self.snd_wnd,
            receive_window: self.receive_window(),
            receive_committed: (self.rx.charged() + 1) * CHUNK,
            delivery_rate: self.stats.delivery_rate,
            retrans_bytes: self.stats.retrans_bytes,
            retrans_segments: u64::from(self.stats.retrans_segments),
            rto_count: u64::from(self.stats.rto_count),
            challenge_acks: u64::from(self.stats.challenge_acks),
            ooo_drops: u64::from(self.stats.ooo_drops),
        }
    }

    /// Debug-build invariants tying the scoreboard to the sequence variables; `Stack` runs it
    /// after every call that can change this flow.
    pub fn check(&self) {
        // Before the SYN is acknowledged the scoreboard (which starts after it) has no `snd_una`.
        if self.snd_una != self.iss {
            self.sent.check_bounds(self.snd_una, self.snd_nxt);
        }
    }

    /// The slower whole-flow invariants the fuzz targets assert after every operation.
    #[cfg(feature = "fuzz-checks")]
    pub fn check_invariants(&self) {
        self.sent.check();
        assert!(
            self.cc.cwnd() > 0,
            "a zero congestion window stalls the flow"
        );
        assert!(self.rtt.rto() <= rtt::MAX_RTO);
        assert!(
            self.gate == passive::Gate::Open
                || (matches!(self.state, TcpState::SynReceived | TcpState::Closed)
                    && self.syn_sent.is_none()
                    && !self.syn_due),
            "a gated flow has answered or is due to answer"
        );
        assert!(!self.half_open || self.state == TcpState::SynReceived);
        assert!(self.keepalive.is_some() || self.ka_deadline.is_none());
        assert!(self.pmtu >= 68);
        if self.state == TcpState::SynSent {
            return;
        }
        assert!(
            seq::le(self.rcv_nxt, self.max_adv_right)
                && seq::le(self.max_adv_right, self.committed_right),
            "receive window edges: rcv_nxt {} <= max_adv_right {} <= committed_right {}",
            self.rcv_nxt,
            self.max_adv_right,
            self.committed_right
        );
        assert!(seq::le(self.rx.rd_seq, self.rcv_nxt));
        assert!(
            self.snd_una == self.iss || self.sent.outstanding as usize <= self.tx.len() + 1,
            "more unacknowledged sequence space than queued bytes plus a FIN"
        );
    }

    pub fn release(&mut self, pool: &mut Pool) {
        self.tx.clear(pool);
        self.rx.release_all(pool);
        self.sent.release(pool);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_application_reads_do_not_report_false_eof_or_discard_data() {
        let now = Instant::now();
        let tuple = FourTuple {
            local: "192.0.2.1:40000".parse().unwrap(),
            remote: "198.51.100.1:443".parse().unwrap(),
        };
        let mut t = Tcb::new(tuple, &Config::new([1; 32]), now, now, 100, 200);
        let mut pool = Pool::new(0);
        t.state = TcpState::Established;
        assert_eq!(
            t.read(&mut pool, &mut [], now),
            Err(StreamError::WouldBlock)
        );
        t.rx.write_at(&mut pool, 0, b"x");
        t.rcv_nxt = 1;
        t.max_adv_right = CHUNK as u32;
        t.committed_right = CHUNK as u32;
        assert_eq!(
            t.read(&mut pool, &mut [], now),
            Err(StreamError::WouldBlock)
        );
        let mut out = [0; 1];
        assert_eq!(t.read(&mut pool, &mut out, now), Ok(1));
        assert_eq!(out, [b'x']);
        t.peer_fin = Some(1);
        t.peer_fin_seen = true;
        t.rcv_nxt = 2;
        assert_eq!(t.read(&mut pool, &mut [], now), Ok(0));
    }

    #[test]
    fn non_sack_retransmissions_leave_no_rack_bookkeeping() {
        let now = Instant::now();
        let tuple = FourTuple {
            local: "192.0.2.1:40000".parse().unwrap(),
            remote: "198.51.100.1:443".parse().unwrap(),
        };
        let mut t = Tcb::new(tuple, &Config::new([1; 32]), now, now, 100, 200);
        let mut pool = Pool::new(8);
        t.state = TcpState::Established;
        t.snd_una = 101;
        t.snd_nxt = 101;
        assert_eq!(t.write(&mut pool, &[9; 2000]), Ok(2000));
        let mut out = [0u8; 1500];
        while let output::Output::Sent(_) = t.output(now, &mut out, &mut pool) {}
        t.sent.mark_first_lost();
        assert!(matches!(
            t.output(now, &mut out, &mut pool),
            output::Output::Sent(_)
        ));
        assert_eq!(t.stats().retrans_segments, 1);
        assert_eq!(
            t.recovery.rack.pending_retransmits(),
            0,
            "only SACK flows trim this queue, so it must not grow here"
        );
    }
}

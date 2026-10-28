//! Loss recovery state machine: RACK-TLP for SACK peers, NewReno (RFC 6582) otherwise, PRR for
//! the window reduction, and spurious-recovery undo (DSACK, Eifel and F-RTO).

use std::time::{Duration, Instant};

use super::cc::{Cc, Snapshot};
use super::prr::Prr;
use super::rack::{Rack, TlpOutcome};
use super::sent::{Acked, Sent};
use super::seq;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    Recovery,
    Loss,
}

/// F-RTO (RFC 5682) progress after a retransmission timeout.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frto {
    Off,
    /// The first segment was retransmitted; waiting for the ACK that decides what comes next.
    Armed,
    /// Step 2b: new data goes out instead of further retransmissions.
    NewData,
}

/// State that only a loss episode needs, so it is heap-allocated while one lasts and an idle
/// flow pays a pointer: what to restore if the event turns out spurious, and PRR's counters.
struct Episode {
    saved: Snapshot,
    /// Bytes retransmitted in this episode, and how many of them the peer reported as duplicates.
    retrans: u32,
    dsacked: u32,
    /// Timestamp clock reading of the episode's first retransmission (Eifel, RFC 3522).
    stamp: Option<u32>,
    prr: Prr,
}

impl Episode {
    fn new(cc: &Cc) -> Box<Episode> {
        Box::new(Episode {
            saved: cc.snapshot(),
            retrans: 0,
            dsacked: 0,
            stamp: None,
            prr: Prr::default(),
        })
    }

    /// Every retransmission has been reported as a duplicate: the originals had arrived.
    fn all_duplicated(&self) -> bool {
        self.retrans > 0 && self.retrans <= self.dsacked
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    /// Congestion events: fast recoveries and tail-loss-probe discoveries.
    pub loss_events: u32,
    /// Episodes later proven spurious, whether they began with fast recovery or an RTO.
    pub spurious_recoveries: u32,
    /// Congestion-state restorations (one per proven-spurious episode that restored a window).
    pub undo_count: u32,
    pub tlp_probes: u32,
}

pub struct Recovery {
    state: State,
    /// Highest sequence sent when the episode began; ACKing it ends the episode.
    recover: u32,
    dupacks: u32,
    reno_sacked: u32,
    /// NewReno saw a partial ACK: the retransmission timer is no longer restarted (RFC 6582 §4,
    /// "impatient"), so a peer that drops most out-of-order data cannot hold recovery hostage.
    partial_seen: bool,
    keep_rto: bool,
    reducing: bool,
    pub rack: Rack,
    ep: Option<Box<Episode>>,
    frto: Frto,
    pub counters: Counters,
}

pub struct AckCtx<'a> {
    pub now: Instant,
    pub ack: u32,
    /// Bytes the cumulative ACK advanced.
    pub acked: u32,
    /// A pure duplicate ACK (no data, no window change).
    pub dup: bool,
    pub info: &'a Acked,
    /// Bytes of the DSACK block, if the ACK carried one.
    pub dsack: u32,
    /// The ACK echoes a timestamp older than the episode's first retransmission.
    pub eifel: bool,
    pub snd_nxt: u32,
    pub mss: u32,
    pub flight_before: u32,
    pub sack: bool,
    pub srtt: Duration,
    pub min_rtt: Duration,
}

impl Recovery {
    pub(super) fn overhead_bound() -> usize {
        std::mem::size_of::<Episode>()
    }

    pub fn new(seq: u32) -> Recovery {
        Recovery {
            state: State::Open,
            recover: seq,
            dupacks: 0,
            reno_sacked: 0,
            partial_seen: false,
            keep_rto: false,
            reducing: false,
            rack: Rack::new(seq),
            ep: None,
            frto: Frto::Off,
            counters: Counters::default(),
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn in_recovery(&self) -> bool {
        self.state == State::Recovery
    }

    pub fn pipe(&self, sent: &Sent, sack: bool) -> u32 {
        let virtual_sacked = if sack { 0 } else { self.reno_sacked };
        sent.pipe().saturating_sub(virtual_sacked)
    }

    /// Bytes that may be sent now: PRR's allowance while the window is being reduced.
    pub fn budget(&self, pipe: u32, cwnd: u32) -> u32 {
        match &self.ep {
            Some(e) if self.reducing => e.prr.allow(),
            _ => cwnd.saturating_sub(pipe),
        }
    }

    /// F-RTO step 2b: send new data, not more retransmissions.
    pub fn hold_retransmits(&self) -> bool {
        self.frto == Frto::NewData
    }

    /// With no new data to send, step 2b cannot proceed: fall back to conventional loss recovery
    /// (RFC 5682 §3) instead of idling until the next timeout retransmits one segment.
    pub fn end_frto(&mut self) {
        self.frto = Frto::Off;
    }

    /// The ACK just processed must not restart the retransmission timer.
    pub fn keep_rto(&self) -> bool {
        self.keep_rto
    }

    /// The timestamp clock reading of the first retransmission of the current episode.
    pub fn retrans_stamp(&self) -> Option<u32> {
        self.ep.as_ref().and_then(|e| e.stamp)
    }

    /// Accounts `n` bytes sent; `retransmit` ones count towards undo.
    pub fn sent_bytes(&mut self, n: u32, retransmit: bool, ts_now: u32) {
        let reducing = self.reducing;
        if let Some(e) = &mut self.ep {
            if reducing {
                e.prr.sent(n);
            }
            if retransmit {
                e.retrans = e.retrans.saturating_add(n);
                e.stamp.get_or_insert(ts_now);
            }
        }
    }

    pub fn reo_deadline(&self) -> Option<Instant> {
        self.rack.timer
    }

    fn reo_wnd(&self, sent: &Sent, srtt: Duration, min_rtt: Duration, mss: u32) -> Duration {
        self.rack
            .reo_wnd(min_rtt, srtt, self.state != State::Open, sent.sacked, mss)
    }

    pub fn reo_wnd_now(&self, sent: &Sent, rtt: &super::rtt::Rtt, mss: u32) -> Duration {
        let srtt = rtt.srtt().unwrap_or_default();
        self.reo_wnd(sent, srtt, rtt.min_rtt().unwrap_or(srtt), mss)
    }

    fn detect(
        &mut self,
        sent: &mut Sent,
        at: Instant,
        srtt: Duration,
        min_rtt: Duration,
        mss: u32,
    ) -> bool {
        let reo = self.reo_wnd(sent, srtt, min_rtt, mss);
        self.rack.detect(sent, at, reo)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ack(&mut self, sent: &mut Sent, cc: &mut Cc, c: &AckCtx) {
        self.keep_rto = false;
        let advanced = c.acked != 0;
        if advanced && self.state == State::Open {
            self.dupacks = 0;
            self.reno_sacked = 0;
        }
        if c.sack {
            self.rack.on_delivery(
                c.now,
                c.info.newest,
                c.info.reordered,
                c.dsack != 0,
                c.ack,
                c.snd_nxt,
            );
            self.rack.trim(sent.start);
        }
        if c.dsack != 0
            && let Some(e) = &mut self.ep
        {
            e.dsacked = e.dsacked.saturating_add(c.dsack);
        }
        if self.rack.tlp.is_some() {
            let outcome = self
                .rack
                .on_tlp_ack(c.ack, advanced, c.dup && c.info.delivered == 0);
            if outcome == TlpOutcome::Loss && self.state == State::Open {
                // The probe repaired a loss: one congestion event, without a recovery episode.
                cc.on_loss(c.mss);
                self.counters.loss_events += 1;
            }
        }
        match self.state {
            State::Open => self.open_ack(sent, cc, c),
            State::Recovery => self.recovery_ack(sent, cc, c),
            State::Loss => self.loss_ack(sent, cc, c),
        }
        sent.check();
    }

    fn open_ack(&mut self, sent: &mut Sent, cc: &mut Cc, c: &AckCtx) {
        let lost = if c.sack {
            self.detect(sent, c.now, c.srtt, c.min_rtt, c.mss)
        } else {
            if c.dup && sent.outstanding != 0 {
                self.dupacks += 1;
                self.reno_sacked = self
                    .reno_sacked
                    .saturating_add(c.mss)
                    .min(sent.outstanding.saturating_sub(c.mss));
            }
            self.dupacks >= 3
        };
        if lost {
            if !c.sack {
                sent.mark_first_lost();
            }
            self.enter_recovery(sent, cc, c);
        }
    }

    /// The reorder timer fired: RACK may now find losses without any ACK arriving.
    pub fn reo_timeout(
        &mut self,
        sent: &mut Sent,
        cc: &mut Cc,
        now: Instant,
        snd_nxt: u32,
        mss: u32,
        rtt: &super::rtt::Rtt,
    ) {
        let srtt = rtt.srtt().unwrap_or_default();
        let min_rtt = rtt.min_rtt().unwrap_or(srtt);
        let ctx = Acked::new(now, min_rtt);
        let c = AckCtx {
            now,
            ack: sent.start,
            acked: 0,
            dup: false,
            info: &ctx,
            dsack: 0,
            eifel: false,
            snd_nxt,
            mss,
            flight_before: sent.outstanding,
            sack: true,
            srtt,
            min_rtt,
        };
        // Evaluate at each timer's own target time, not at the (possibly later) processing time.
        while let Some(target) = self.rack.timer.filter(|&t| t <= now) {
            let lost = self.detect(sent, target, srtt, min_rtt, mss);
            if lost && self.state == State::Open {
                self.enter_recovery(sent, cc, &c);
            }
        }
        // Segments marked lost lower the pipe; PRR's allowance must see that without waiting for
        // an ACK that may never come.
        if self.reducing {
            self.prr_ack(sent, cc, &c);
        }
    }

    fn enter_recovery(&mut self, sent: &mut Sent, cc: &mut Cc, c: &AckCtx) {
        self.ep = Some(Episode::new(cc));
        self.recover = c.snd_nxt;
        self.state = State::Recovery;
        self.reducing = true;
        self.partial_seen = false;
        cc.on_loss(c.mss);
        if let Some(e) = &mut self.ep {
            e.prr = Prr::new(c.flight_before.max(c.mss), c.mss);
        }
        self.prr_ack(sent, cc, c);
        self.rack.on_recovery();
        self.counters.loss_events += 1;
    }

    fn prr_ack(&mut self, sent: &Sent, cc: &Cc, c: &AckCtx) {
        let delivered = if c.sack {
            c.info.delivered
        } else if c.dup {
            c.mss
        } else {
            c.acked
        };
        let pipe = self.pipe(sent, c.sack);
        if let Some(e) = &mut self.ep {
            e.prr.on_ack(delivered, pipe, cc.ssthresh(), c.mss);
        }
    }

    fn recovery_ack(&mut self, sent: &mut Sent, cc: &mut Cc, c: &AckCtx) {
        let advanced = c.acked != 0;
        if seq::ge(sent.start, self.recover) {
            self.exit(sent, cc, c);
            return;
        }
        if c.sack {
            self.detect(sent, c.now, c.srtt, c.min_rtt, c.mss);
        } else if advanced {
            // Partial ACK (RFC 6582 §3.2 step 3): the next unacknowledged segment is lost too.
            let removed = self.reno_sacked.min(c.acked);
            self.reno_sacked -= removed;
            sent.mark_first_lost();
            self.keep_rto = self.partial_seen;
            self.partial_seen = true;
        } else if c.dup {
            self.dupacks += 1;
            self.reno_sacked = self
                .reno_sacked
                .saturating_add(c.mss)
                .min(sent.outstanding.saturating_sub(c.mss));
        }
        let duplicated = self.ep.as_ref().is_some_and(|e| e.all_duplicated());
        if duplicated || (advanced && c.eifel) {
            self.undo_window(cc);
            self.reducing = false;
            return;
        }
        if self.reducing {
            self.prr_ack(sent, cc, c);
        }
    }

    fn exit(&mut self, sent: &mut Sent, cc: &mut Cc, c: &AckCtx) {
        if self.ep.as_ref().is_some_and(|e| e.retrans <= e.dsacked) || c.eifel {
            self.undo_window(cc);
        }
        self.ep = None;
        self.state = State::Open;
        self.reducing = false;
        self.dupacks = 0;
        self.reno_sacked = 0;
        self.partial_seen = false;
        // Data sent during recovery and lost since is a fresh congestion event (Linux
        // `tcp_time_to_recover`: `lost_out != 0`), not part of the episode that just ended.
        if sent.lost != 0 {
            self.enter_recovery(sent, cc, c);
        }
    }

    /// The loss event never happened: restore the window saved before it.
    fn undo_window(&mut self, cc: &mut Cc) {
        if let Some(e) = self.ep.take() {
            cc.undo(e.saved);
            self.counters.spurious_recoveries += 1;
            self.counters.undo_count += 1;
        }
    }

    pub fn rto(&mut self, sent: &mut Sent, cc: &mut Cc, snd_nxt: u32, mss: u32) {
        let first = self.state == State::Open;
        if self.ep.is_none() {
            self.ep = Some(Episode::new(cc));
        }
        cc.on_rto(mss, first);
        self.state = State::Loss;
        self.recover = snd_nxt;
        self.dupacks = 0;
        self.reno_sacked = 0;
        self.partial_seen = false;
        self.reducing = false;
        self.frto = Frto::Armed;
        self.rack.tlp = None;
        sent.mark_all_lost();
        self.rack.reset_after_rto(sent);
    }

    fn loss_ack(&mut self, sent: &mut Sent, cc: &mut Cc, c: &AckCtx) {
        let advanced = c.acked != 0;
        let recovered = seq::ge(sent.start, self.recover);
        if c.sack {
            self.detect(sent, c.now, c.srtt, c.min_rtt, c.mss);
        }
        let duplicated = self.ep.as_ref().is_some_and(|e| e.all_duplicated());
        if duplicated || (advanced && c.eifel) {
            self.undo_loss(sent, cc);
            return;
        }
        if self.frto != Frto::Off {
            if c.info
                .orig_end
                .is_some_and(|end| seq::le(end, self.recover))
            {
                // Step 3b: data that was never retransmitted has been acknowledged, so the
                // timeout fired on a delayed rather than a lost segment.
                self.undo_loss(sent, cc);
                return;
            }
            let sack_delivered = c.info.delivered > c.acked;
            if seq::gt(c.snd_nxt, self.recover) {
                // Step 3a: new data went out and nothing proves it arrived: the loss was real.
                self.frto = Frto::Off;
            } else if advanced && !recovered && self.frto == Frto::Armed && !sack_delivered {
                self.recover = c.snd_nxt;
                self.frto = Frto::NewData;
            } else {
                self.frto = Frto::Off;
            }
        }
        if recovered && seq::ge(sent.start, self.recover) {
            self.ep = None;
            self.state = State::Open;
            self.frto = Frto::Off;
        }
    }

    /// Spurious timeout: nothing was lost, so nothing is marked lost either.
    fn undo_loss(&mut self, sent: &mut Sent, cc: &mut Cc) {
        self.undo_window(cc);
        self.state = State::Open;
        self.frto = Frto::Off;
        self.reducing = false;
        sent.unmark_lost();
        self.rack.reset(sent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::sent::Descriptor;

    const MSS: u32 = 100;

    struct Rig {
        sent: Sent,
        cc: Cc,
        rec: Recovery,
        t0: Instant,
        snd_nxt: u32,
    }

    impl Rig {
        fn new(segments: u32) -> Rig {
            let t0 = Instant::now();
            let mut sent = Sent::new(1000);
            for i in 0..segments {
                sent.push(Descriptor {
                    end_seq: 1000 + (i + 1) * MSS,
                    xmit_ts: t0 + Duration::from_micros(u64::from(i)),
                    flags: 0,
                    delivered: 0,
                    delivered_ts: t0,
                    first_tx_ts: t0,
                });
            }
            Rig {
                sent,
                cc: Cc::new(MSS),
                rec: Recovery::new(1000),
                t0,
                snd_nxt: 1000 + segments * MSS,
            }
        }

        /// An ACK: cumulative `ack` plus SACK blocks, `ms` after the transmissions.
        fn ack(&mut self, ack: u32, blocks: &[(u32, u32)], dsack: u32, ms: u64, dup: bool) {
            let now = self.t0 + Duration::from_millis(ms);
            let min_rtt = Duration::from_millis(40);
            let mut info = Acked::new(now, min_rtt);
            let flight_before = self.sent.outstanding;
            let acked = ack.wrapping_sub(self.sent.start);
            self.sent.ack(ack, &mut info);
            for &(l, r) in blocks {
                self.sent.sack(l, r, self.snd_nxt, &mut info);
            }
            let c = AckCtx {
                now,
                ack,
                acked,
                dup,
                info: &info,
                dsack,
                eifel: false,
                snd_nxt: self.snd_nxt,
                mss: MSS,
                flight_before,
                sack: true,
                srtt: Duration::from_millis(50),
                min_rtt,
            };
            self.rec.ack(&mut self.sent, &mut self.cc, &c);
        }

        fn retransmit(&mut self, ms: u64) -> u32 {
            let (i, start, len, _) = self.sent.next_retransmit(true).expect("something is lost");
            let now = self.t0 + Duration::from_millis(ms);
            self.sent.split(i, start + len.min(MSS));
            self.sent.retransmitted(
                i,
                now,
                &crate::tcp::sent::Stamp {
                    delivered: 0,
                    delivered_ts: now,
                    first_tx_ts: now,
                    app_limited: false,
                },
            );
            self.rec.rack.on_retransmit(start + len.min(MSS), now);
            self.rec.sent_bytes(MSS, true, ms as u32);
            start
        }
    }

    #[test]
    fn three_sacked_segments_enter_recovery_once_with_an_immediate_fast_retransmit() {
        let mut r = Rig::new(10);
        let cwnd = r.cc.cwnd();
        r.ack(1000, &[(1100, 1200)], 0, 50, true);
        r.ack(1000, &[(1100, 1300)], 0, 50, true);
        assert_eq!(
            r.rec.state(),
            State::Open,
            "two SACKed segments are reordering"
        );
        r.ack(1000, &[(1100, 1400)], 0, 50, true);
        assert_eq!(r.rec.state(), State::Recovery);
        assert_eq!(r.rec.counters.loss_events, 1);
        assert!(r.cc.cwnd() < cwnd);
        assert_eq!(r.sent.lost, MSS, "only the hole below the SACKed data");
        assert_eq!(
            r.rec.budget(r.rec.pipe(&r.sent, true), r.cc.cwnd()),
            MSS.max(1)
        );
        assert_eq!(r.retransmit(50), 1000);
        // More SACKs in the same event never reduce again.
        let reduced = r.cc.cwnd();
        r.ack(1000, &[(1100, 1500)], 0, 51, true);
        r.ack(1000, &[(1100, 1600)], 0, 52, true);
        assert_eq!((r.rec.counters.loss_events, r.cc.cwnd()), (1, reduced));
    }

    #[test]
    fn full_ack_ends_recovery_with_window_at_ssthresh() {
        let mut r = Rig::new(10);
        r.ack(1000, &[(1100, 1400)], 0, 50, true);
        r.retransmit(50);
        r.ack(2000, &[], 0, 100, false);
        assert_eq!(r.rec.state(), State::Open);
        assert_eq!(r.cc.cwnd(), r.cc.ssthresh());
        assert_eq!(
            r.rec.counters.undo_count, 0,
            "a needed retransmission is never undone"
        );
    }

    #[test]
    fn dsack_of_every_retransmission_undoes_the_reduction() {
        let mut r = Rig::new(10);
        let (cwnd, ssthresh) = (r.cc.cwnd(), r.cc.ssthresh());
        r.ack(1000, &[(1100, 1400)], 0, 50, true);
        r.retransmit(50);
        assert!(r.cc.cwnd() < cwnd);
        // The original arrives, the cumulative ACK jumps, and the retransmission is DSACKed.
        r.ack(1400, &[(1000, 1100)], MSS, 90, false);
        assert_eq!(r.rec.counters.spurious_recoveries, 1);
        assert_eq!((r.cc.cwnd(), r.cc.ssthresh()), (cwnd, ssthresh));
    }

    #[test]
    fn partial_dsack_coverage_keeps_the_reduction() {
        let mut r = Rig::new(10);
        let cwnd = r.cc.cwnd();
        r.ack(1000, &[(1100, 1200)], 0, 50, true);
        r.ack(1000, &[(1100, 1300)], 0, 50, true);
        r.ack(1000, &[(1100, 1400), (1500, 1700)], 0, 50, true);
        assert_eq!(r.rec.state(), State::Recovery);
        r.retransmit(50);
        r.retransmit(50);
        r.ack(1400, &[], MSS, 90, false); // only one of two retransmissions duplicated
        assert_eq!(r.rec.counters.undo_count, 0);
        assert!(r.cc.cwnd() < cwnd);
    }

    #[test]
    fn rto_with_original_data_acked_is_spurious_and_restores_the_window() {
        let mut r = Rig::new(10);
        let (cwnd, ssthresh) = (r.cc.cwnd(), r.cc.ssthresh());
        r.rec.rto(&mut r.sent, &mut r.cc, r.snd_nxt, MSS);
        assert_eq!(r.cc.cwnd(), MSS);
        assert_eq!(r.sent.lost, 1000);
        r.retransmit(300);
        // The delayed ACK covers segments that were never retransmitted.
        r.ack(1500, &[], 0, 310, false);
        assert_eq!(r.rec.state(), State::Open);
        assert_eq!((r.cc.cwnd(), r.cc.ssthresh()), (cwnd, ssthresh));
        assert_eq!(r.sent.lost, 0, "loss marks are withdrawn");
        assert_eq!(r.rec.counters.spurious_recoveries, 1);
    }

    #[test]
    fn rto_ack_covering_only_the_retransmission_defers_to_new_data_and_dupack_confirms_loss() {
        let mut r = Rig::new(10);
        r.rec.rto(&mut r.sent, &mut r.cc, r.snd_nxt, MSS);
        r.retransmit(300);
        r.ack(1100, &[], 0, 360, false);
        assert!(
            r.rec.hold_retransmits(),
            "step 2b: new data before more retransmissions"
        );
        // New data is sent; the peer reports a hole instead of progress.
        r.snd_nxt += 2 * MSS;
        r.sent.push(Descriptor {
            end_seq: r.snd_nxt,
            xmit_ts: r.t0 + Duration::from_millis(361),
            flags: 0,
            delivered: 0,
            delivered_ts: r.t0,
            first_tx_ts: r.t0,
        });
        r.ack(1100, &[(2000, 2200)], 0, 420, true);
        assert!(!r.rec.hold_retransmits());
        assert_eq!(r.rec.counters.undo_count, 0);
        assert_eq!(r.rec.state(), State::Loss);
    }

    #[test]
    fn second_timeout_keeps_ssthresh() {
        let mut r = Rig::new(10);
        r.rec.rto(&mut r.sent, &mut r.cc, r.snd_nxt, MSS);
        let ssthresh = r.cc.ssthresh();
        r.rec.rto(&mut r.sent, &mut r.cc, r.snd_nxt, MSS);
        assert_eq!(r.cc.ssthresh(), ssthresh);
    }

    #[test]
    fn loss_beyond_recover_at_exit_starts_a_new_episode() {
        let mut r = Rig::new(10);
        r.ack(1000, &[(1100, 1400)], 0, 50, true);
        assert_eq!(
            (r.rec.state(), r.rec.counters.loss_events),
            (State::Recovery, 1)
        );
        r.retransmit(50);
        // New data sent during the recovery, then SACKed behind one lost segment.
        for i in 0..4 {
            r.snd_nxt += MSS;
            r.sent.push(Descriptor {
                end_seq: r.snd_nxt,
                xmit_ts: r.t0 + Duration::from_millis(60 + i),
                flags: 0,
                delivered: 0,
                delivered_ts: r.t0,
                first_tx_ts: r.t0,
            });
        }
        r.ack(1000, &[(1100, 1400), (2100, 2400)], 0, 80, true);
        assert_eq!(r.rec.state(), State::Recovery);
        // The cumulative ACK reaches `recover`; the data beyond it is still lost.
        r.ack(2000, &[(2100, 2400)], 0, 90, false);
        assert!(r.sent.lost >= MSS);
        assert_eq!(
            (r.rec.state(), r.rec.counters.loss_events),
            (State::Recovery, 2),
            "a loss the first reduction never covered is a new congestion event"
        );
    }

    #[test]
    fn reorder_timer_losses_refresh_the_prr_allowance_without_an_ack() {
        let mut r = Rig::new(10);
        r.ack(1000, &[(1100, 1400)], 0, 50, true);
        r.retransmit(50);
        // Segment 1400 arrives after 1900: reordering, so RACK waits out a reorder window.
        r.ack(1000, &[(1900, 2000), (1400, 1500)], 0, 60, true);
        assert_eq!(r.rec.state(), State::Recovery);
        let budget = |r: &Rig| r.rec.budget(r.rec.pipe(&r.sent, true), r.cc.cwnd());
        let (before, lost) = (budget(&r), r.sent.lost);
        let mut rtt = crate::tcp::rtt::Rtt::default();
        rtt.sample(Duration::from_millis(40));
        let at = r.t0 + Duration::from_millis(71);
        r.rec
            .reo_timeout(&mut r.sent, &mut r.cc, at, r.snd_nxt, MSS, &rtt);
        assert!(r.sent.lost > lost, "the timer found more losses");
        assert!(
            budget(&r) > before,
            "lower pipe must raise the allowance now: {} -> {}",
            before,
            budget(&r)
        );
    }
}

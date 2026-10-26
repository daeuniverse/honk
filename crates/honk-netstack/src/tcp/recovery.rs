//! Base loss-detection seam: NewReno with an RFC 6675 SACK scoreboard.

use super::{cc::Cc, sent::Sent, seq};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    Recovery,
    Loss,
}

pub enum Recovery {
    NewReno(NewReno),
}

pub struct NewReno {
    pub state: State,
    recover: u32,
    dupacks: u32,
    reno_sacked: u32,
    retransmit_credit: bool,
}

impl Recovery {
    pub fn new(seq: u32) -> Recovery {
        Recovery::NewReno(NewReno {
            state: State::Open,
            recover: seq,
            dupacks: 0,
            reno_sacked: 0,
            retransmit_credit: false,
        })
    }

    pub fn state(&self) -> State {
        match self {
            Recovery::NewReno(r) => r.state,
        }
    }
    pub fn in_recovery(&self) -> bool {
        self.state() == State::Recovery
    }

    pub fn pipe(&self, sent: &Sent, sack: bool) -> u32 {
        let virtual_sacked = match self {
            Recovery::NewReno(r) => {
                if sack {
                    0
                } else {
                    r.reno_sacked
                }
            }
        };
        sent.pipe().saturating_sub(virtual_sacked)
    }

    pub fn can_retransmit(&self, pipe: u32, cwnd: u32) -> bool {
        pipe < cwnd
            || match self {
                Recovery::NewReno(r) => r.retransmit_credit,
            }
    }

    pub fn retransmitted(&mut self) {
        match self {
            Recovery::NewReno(r) => r.retransmit_credit = false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ack(
        &mut self,
        sent: &mut Sent,
        cc: &mut Cc,
        acked: u32,
        dup: bool,
        sack: bool,
        snd_nxt: u32,
        mss: u32,
        flight_before: u32,
    ) {
        match self {
            Recovery::NewReno(r) => {
                if acked != 0 {
                    r.dupacks = 0;
                    r.reno_sacked = r.reno_sacked.saturating_sub(acked);
                    if r.state != State::Open && seq::ge(sent.start, r.recover) {
                        if r.state == State::Recovery {
                            cc.exit_recovery(sent.outstanding, mss);
                        }
                        r.state = State::Open;
                        r.reno_sacked = 0;
                        r.retransmit_credit = false;
                    } else if r.state == State::Recovery {
                        // RFC 6582 partial ACK: retransmit the next unacknowledged hole.
                        sent.mark_first_lost();
                        r.retransmit_credit = true;
                    }
                } else if dup && sent.outstanding != 0 {
                    r.dupacks += 1;
                    if !sack {
                        r.reno_sacked = r
                            .reno_sacked
                            .saturating_add(mss)
                            .min(sent.outstanding.saturating_sub(mss));
                    }
                }
                if r.state == State::Open && (r.dupacks >= 3 || (sack && sent.sacked >= 3 * mss)) {
                    r.state = State::Recovery;
                    r.recover = snd_nxt;
                    cc.loss(flight_before, mss);
                    sent.mark_first_lost();
                    r.retransmit_credit = true;
                }
                if sack && r.state != State::Open {
                    sent.mark_sack_losses(mss);
                }
            }
        }
    }

    pub fn rto(&mut self, sent: &mut Sent, cc: &mut Cc, snd_nxt: u32, mss: u32) {
        match self {
            Recovery::NewReno(r) => {
                cc.rto(
                    sent.outstanding.saturating_sub(sent.sacked),
                    mss,
                    r.state != State::Loss,
                );
                r.state = State::Loss;
                r.recover = snd_nxt;
                r.dupacks = 0;
                r.reno_sacked = 0;
                r.retransmit_credit = false;
                sent.mark_all_lost();
            }
        }
    }
}

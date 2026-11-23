use super::*;
use honk_ebpf_common::xdp_gateway::{
    HOLD_MANAGED, HOLD_NATIVE, HOLD_SEQUENCE_MAX, NATIVE_PENDING_CAP,
};

// These slots are dead after the local-address check. CT reuses TUPLE on a lost insertion.
const DNS_EPOCH: i16 = LOCAL;
const PENDING: i16 = LOCAL + 8;
const REDIRECT: i32 = 4;
const JEQ_X: u8 = 0x1d;
const FETCH_ADD: i32 = 1;

pub(super) struct Owner<'a> {
    arb: &'a crate::GatewayArbitration,
    pub(super) bad: Target,
    pub(super) qualified: Target,
    held: Target,
    ct_original: Target,
    ct_reply: Target,
    ct_error: Target,
    conflict: Target,
    unavailable: Target,
    unlock: Target,
}

impl<'a> Owner<'a> {
    pub(super) fn new(b: &mut GatewayBuilder, arb: &'a crate::GatewayArbitration) -> Self {
        Self {
            arb,
            bad: b.target(),
            qualified: b.target(),
            held: b.target(),
            ct_original: b.target(),
            ct_reply: b.target(),
            ct_error: b.target(),
            conflict: b.target(),
            unavailable: b.target(),
            unlock: b.target(),
        }
    }

    fn verdict(&self, b: &mut GatewayBuilder, reason: GatewayReason, verdict: i32) {
        b.word(VERDICT, verdict);
        b.reason(reason, self.unlock);
    }

    fn pending_conflicts(&self, b: &mut GatewayBuilder) {
        b.load(LDX_W, 0, 10, PENDING);
        b.jump(JNE_K, 0, 0, 0, self.conflict);
    }

    fn control(&self, b: &mut GatewayBuilder, unavailable: Target) {
        b.word(INDEX, 0);
        b.lookup(self.arb.control.as_raw_fd(), INDEX);
        b.jump(JEQ_K, 0, 0, 0, unavailable);
        b.mov(8, 0);
    }

    fn acquire(&self, b: &mut GatewayBuilder, maps: &GatewayMaps, drop: Target) {
        let acquired = b.target();
        let unavailable = b.target();
        b.word(INDEX, 1);
        for _ in 0..2 {
            b.update(self.arb.guards.as_raw_fd(), KEY, INDEX, 1);
            b.jump(JEQ_K, 0, 0, 0, acquired);
            b.jump(JNE32_K, 0, 0, -libc::EEXIST, unavailable);
        }
        b.stat(maps, GatewayReason::DropHoldContention);
        b.goto(drop);
        b.bind(unavailable);
        b.stat(maps, GatewayReason::DropHoldUnavailable);
        b.goto(drop);
        b.bind(acquired);
    }

    // Only pointers obtained under our own exact-key guard reach either timestamp write.
    fn read_owner(&self, b: &mut GatewayBuilder, maps: &GatewayMaps) {
        let ct = b.target();
        b.word(PENDING, 0);
        b.lookup(maps.hold.as_raw_fd(), KEY);
        b.jump(JEQ_K, 0, 0, 0, ct);
        b.load(LDX_DW, 1, 0, 0);
        b.emit(RSH_K, 1, 0, 0, HOLD_NATIVE.trailing_zeros() as i32);
        b.jump(JNE_K, 1, 0, 3, self.held);
        b.word(PENDING, 1);
        b.mov(8, 0);
        b.helper(5);
        b.load(LDX_DW, 1, 8, 8);
        b.jump(JLE_X, 0, 1, 0, ct);
        b.store(STX_DW, 8, 8, 0);
        b.bind(ct);
    }

    pub(super) fn observe(
        &self,
        b: &mut GatewayBuilder,
        gateway: &GatewayLoad<'_>,
        data: bool,
        d1: Target,
        pass: Target,
        drop: Target,
    ) {
        let guard = b.target();
        let original = b.target();
        let reply = b.target();
        let error = b.target();
        b.lookup(gateway.maps.hold.as_raw_fd(), KEY);
        b.jump(JNE_K, 0, 0, 0, guard);
        // Established native traffic needs no guard update and no second lookup.
        conntrack(b, gateway.conntrack, guard, error, original, reply);
        b.bind(original);
        b.reason(GatewayReason::PassCtOriginal, pass);
        b.bind(reply);
        b.reason(GatewayReason::PassCtReply, pass);
        b.bind(error);
        b.stat(gateway.maps, GatewayReason::CtLookupError);
        b.goto(drop);

        b.bind(guard);
        self.acquire(b, gateway.maps, drop);
        self.read_owner(b, gateway.maps);
        // The initial miss may straddle another packet's complete pending -> CT handoff.
        let miss = b.target();
        conntrack(
            b,
            gateway.conntrack,
            miss,
            self.ct_error,
            self.ct_original,
            self.ct_reply,
        );
        b.bind(miss);
        if !data || gateway.dns.is_none() {
            self.pending_conflicts(b);
        }
        let ordinary = b.target();
        b.load(LDX_W, 0, 10, IS_QUOTE);
        b.jump(JEQ_K, 0, 0, 0, ordinary);
        self.pending_conflicts(b);
        self.verdict(b, GatewayReason::IcmpQuoteUnresolved, REDIRECT);
        b.bind(ordinary);
        b.load(LDX_B, 0, 10, KEY + 44);
        b.jump(JEQ_K, 0, 0, 17, d1);
        b.load(LDX_W, 0, 10, TCP_FLAGS);
        b.emit(AND_K, 0, 0, 0, 0x17);
        b.jump(JEQ_K, 0, 0, 2, d1);
        self.pending_conflicts(b);
        self.verdict(b, GatewayReason::PassTcpNonSynMiss, XDP_PASS);
    }

    pub(super) fn static_pass(&self, b: &mut GatewayBuilder) {
        self.pending_conflicts(b);
        self.verdict(b, GatewayReason::PassD1, XDP_PASS);
    }

    pub(super) fn finish(
        &self,
        b: &mut GatewayBuilder,
        gateway: &GatewayLoad<'_>,
        data: bool,
        final_pass: Target,
        drop: Target,
    ) {
        if data {
            self.insert(b, gateway);
        } else {
            self.verdict(b, GatewayReason::XskNewFlow, REDIRECT);
        }
        b.bind(self.held);
        let refreshed = b.target();
        refresh_hold(b, refreshed);
        b.bind(refreshed);
        self.verdict(b, GatewayReason::XskEndpointHold, REDIRECT);

        let hit = b.target();
        let pass = b.target();
        let retire_failed = b.target();
        b.bind(self.ct_original);
        b.reason(GatewayReason::PassCtOriginal, hit);
        b.bind(self.ct_reply);
        b.word(REASON, GatewayReason::PassCtReply as i32);
        b.bind(hit);
        b.load(LDX_W, 0, 10, PENDING);
        b.jump(JEQ_K, 0, 0, 0, pass);
        self.control(b, retire_failed);
        delete(b, gateway.maps.hold.as_raw_fd());
        b.jump(JNE_K, 0, 0, 0, retire_failed);
        // No other legitimate refund can consume this deleted row's still-outstanding credit.
        b.load(LDX_DW, 0, 8, 0);
        b.jump(JEQ_K, 0, 0, 0, retire_failed);
        b.jump(JGT_K, 0, 0, NATIVE_PENDING_CAP as i32, retire_failed);
        refund(b);
        b.goto(pass);
        b.bind(retire_failed);
        b.stat(gateway.maps, GatewayReason::HoldRetireFailed);
        b.bind(pass);
        b.word(VERDICT, XDP_PASS);
        b.goto(self.unlock);
        b.bind(self.ct_error);
        self.verdict(b, GatewayReason::CtLookupError, XDP_DROP);
        b.bind(self.bad);
        self.pending_conflicts(b);
        self.verdict(b, GatewayReason::UnclassifiableHeader, XDP_DROP);
        b.bind(self.conflict);
        self.verdict(b, GatewayReason::DropNativePendingConflict, XDP_DROP);
        if data {
            b.bind(self.unavailable);
            self.verdict(b, GatewayReason::DropHoldUnavailable, XDP_DROP);
        }

        b.bind(self.unlock);
        delete(b, self.arb.guards.as_raw_fd());
        let released = b.target();
        b.jump(JEQ_K, 0, 0, 0, released);
        b.stat(gateway.maps, GatewayReason::HoldGuardReleaseFailed);
        b.goto(drop);
        b.bind(released);
        b.load(LDX_W, 0, 10, VERDICT);
        b.jump(JNE_K, 0, 0, XDP_DROP, final_pass);
        b.load(LDX_W, 0, 10, REASON);
        b.store(STX_W, 10, INDEX, 0);
        b.stat_index(gateway.maps.stats.as_raw_fd());
        b.goto(drop);
    }

    fn insert(&self, b: &mut GatewayBuilder, gateway: &GatewayLoad<'_>) {
        let allocate = b.target();
        let endpoint = b.target();
        let raced = b.target();
        let failed = b.target();
        let retry = b.target();
        if gateway.dns.is_some() {
            let unauthorized = b.target();
            b.goto(unauthorized);
            b.bind(self.qualified);
            b.load(LDX_H, 0, 10, KEY + 42);
            b.jump(JEQ_K, 0, 0, u16::from_be(53) as i32, unauthorized);
            b.load(LDX_W, 0, 10, PENDING);
            b.jump(JNE_K, 0, 0, 0, retry);
            b.load(LDX_DW, 0, 10, TUPLE);
            b.store(STX_DW, 10, DNS_EPOCH, 0);
            b.goto(allocate);
            b.bind(unauthorized);
            self.pending_conflicts(b);
            b.emit(ST_DW, 10, 0, DNS_EPOCH, 0);
        }
        b.bind(allocate);
        self.control(b, self.unavailable);
        issue_sequence(b, self.unavailable);
        b.constant(1, HOLD_MANAGED);
        b.emit(ADD_X, 2, 1, 0, 0);
        b.store(STX_DW, 10, VALUE, 2);
        b.helper(5);
        b.store(STX_DW, 10, VALUE + 8, 0);
        if gateway.dns.is_some() {
            let capped = b.target();
            let inserted = b.target();
            b.load(LDX_DW, 0, 10, DNS_EPOCH);
            b.jump(JEQ_K, 0, 0, 0, endpoint);
            increment_below(b, 0, NATIVE_PENDING_CAP, capped, endpoint);
            b.load(LDX_DW, 1, 10, VALUE);
            b.constant(2, HOLD_NATIVE);
            b.emit(ADD_X, 1, 2, 0, 0);
            b.store(STX_DW, 10, VALUE, 1);
            b.update(gateway.maps.hold.as_raw_fd(), KEY, VALUE, 1);
            b.jump(JEQ_K, 0, 0, 0, inserted);
            refund(b);
            b.jump(JEQ32_K, 0, 0, -libc::EEXIST, raced);
            // No row received the allocated sequence, so the Endpoint can use it.
            b.load(LDX_DW, 1, 10, VALUE);
            b.constant(2, HOLD_NATIVE);
            b.emit(SUB_X, 1, 2, 0, 0);
            b.store(STX_DW, 10, VALUE, 1);
            b.goto(endpoint);
            b.bind(inserted);
            self.verdict(b, GatewayReason::PassDnsD1, XDP_PASS);
            b.bind(capped);
            b.jump(JNE_K, 0, 0, NATIVE_PENDING_CAP as i32, self.unavailable);
            b.stat(gateway.maps, GatewayReason::DnsNativePendingCapped);
        }
        b.bind(endpoint);
        b.update(gateway.maps.hold.as_raw_fd(), KEY, VALUE, 1);
        b.jump(JEQ32_K, 0, 0, -libc::EEXIST, raced);
        b.jump(JNE_K, 0, 0, 0, failed);
        self.verdict(b, GatewayReason::XskNewFlow, REDIRECT);

        b.bind(raced);
        self.read_owner(b, gateway.maps);
        let miss = b.target();
        conntrack(
            b,
            gateway.conntrack,
            miss,
            self.ct_error,
            self.ct_original,
            self.ct_reply,
        );
        b.bind(miss);
        b.load(LDX_W, 0, 10, PENDING);
        b.jump(JEQ_K, 0, 0, 0, failed);
        if let Some(dns) = gateway.dns {
            // EEXIST changes the owner. Recheck the same copied proof before a pending retry.
            b.load(LDX_DW, 6, 10, DNS_EPOCH);
            b.jump(JEQ_K, 6, 0, 0, self.conflict);
            b.lookup(dns.epochs.as_raw_fd(), KEY);
            b.jump(JEQ_K, 0, 0, 0, self.conflict);
            b.load(LDX_DW, 0, 0, 0);
            b.jump(JNE_X, 0, 6, 0, self.conflict);
            b.helper(5);
            b.jump(JLE_X, 7, 0, 0, self.conflict);
            b.bind(retry);
            self.verdict(b, GatewayReason::PassDnsD1PendingRetry, XDP_PASS);
        } else {
            b.goto(self.conflict);
        }
        b.bind(failed);
        self.verdict(b, GatewayReason::HoldInsertFailed, XDP_DROP);
    }
}

fn delete(b: &mut GatewayBuilder, fd: RawFd) {
    b.map(1, fd);
    b.address(2, KEY);
    b.helper(3);
}

// R8 is a checked control array pointer. Preserve R0 (the insertion result) across the refund.
fn refund(b: &mut GatewayBuilder) {
    b.imm(1, -1);
    b.emit(ATOMIC_ADD_DW, 8, 1, 0, 0);
}

// Only writers already holding distinct guards can overshoot the logical ceiling. Even a full
// u32-sized guard map leaves the raw u64 far from wraparound; the returned old value gates issue.
fn issue_sequence(b: &mut GatewayBuilder, exhausted: Target) {
    b.constant(3, HOLD_SEQUENCE_MAX);
    b.load(LDX_DW, 0, 8, 8);
    b.jump(JLE_X, 3, 0, 0, exhausted);
    b.imm(2, 1);
    b.emit(ATOMIC_ADD_DW, 8, 2, 8, FETCH_ADD);
    b.jump(JLE_X, 3, 2, 0, exhausted);
    b.add(2, 1);
}

// R2 returns the issued number. A failed CMPXCHG returns the observed value in R0.
fn increment_below(b: &mut GatewayBuilder, offset: i16, limit: u64, full: Target, busy: Target) {
    let issued = b.target();
    b.constant(3, limit);
    b.load(LDX_DW, 0, 8, offset);
    for _ in 0..2 {
        b.jump(JLE_X, 3, 0, 0, full);
        b.mov(1, 0);
        b.mov(2, 0);
        b.add(2, 1);
        b.emit(ATOMIC_ADD_DW, 8, 2, offset, CMPXCHG);
        b.jump(JEQ_X, 0, 1, 0, issued);
    }
    b.jump(JLE_X, 3, 0, 0, full);
    b.goto(busy);
    b.bind(issued);
}

#[cfg(all(test, target_endian = "little"))]
mod tests {
    use super::*;

    fn allocation(mut cell: u64, writes: &[u64]) -> (i32, u64) {
        let mut b = GatewayBuilder::new();
        let full = b.target();
        let busy = b.target();
        increment_below(&mut b, 0, NATIVE_PENDING_CAP, full, busy);
        b.imm(0, 1);
        b.emit(EXIT, 0, 0, 0, 0);
        b.bind(full);
        b.imm(0, 2);
        b.emit(EXIT, 0, 0, 0, 0);
        b.bind(busy);
        b.imm(0, 3);
        b.emit(EXIT, 0, 0, 0, 0);
        let mut writes = writes.iter();
        let result = interpret(&b, &mut cell, &[], |cell| {
            if let Some(&value) = writes.next() {
                *cell = value;
            }
        });
        (result as i32, cell)
    }

    fn interpret(
        b: &GatewayBuilder,
        cell: &mut u64,
        stack: &[u8],
        mut before_atomic: impl FnMut(&mut u64),
    ) -> u64 {
        let mut registers = [0u64; 11];
        let mut pc = 0;
        loop {
            let i = b.program.insns[pc];
            let dst = usize::from(i.regs & 15);
            let src = usize::from(i.regs >> 4);
            let branch = match i.code {
                LD_MAP => {
                    pc += 1;
                    registers[dst] =
                        u64::from(i.imm as u32) | (u64::from(b.program.insns[pc].imm as u32) << 32);
                    false
                }
                LDX_B | LDX_W => {
                    assert_eq!(src, 10);
                    let at = stack.len().checked_add_signed(isize::from(i.off)).unwrap();
                    registers[dst] = if i.code == LDX_B {
                        u64::from(stack[at])
                    } else {
                        u64::from(u32::from_le_bytes(stack[at..at + 4].try_into().unwrap()))
                    };
                    false
                }
                LDX_DW => {
                    assert_eq!(src, 8);
                    registers[dst] = *cell;
                    false
                }
                MOV_K => {
                    registers[dst] = i.imm as u64;
                    false
                }
                MOV_X => {
                    registers[dst] = registers[src];
                    false
                }
                ADD_K => {
                    registers[dst] = registers[dst].wrapping_add_signed(i64::from(i.imm));
                    false
                }
                ATOMIC_ADD_DW => {
                    assert_eq!(dst, 8);
                    before_atomic(cell);
                    let old = *cell;
                    match (i.off, i.imm) {
                        (0, CMPXCHG) => {
                            if old == registers[0] {
                                *cell = registers[src];
                            }
                            registers[0] = old;
                        }
                        (8, FETCH_ADD) => {
                            *cell = old.checked_add(registers[src]).unwrap();
                            registers[src] = old;
                        }
                        _ => panic!("unexpected allocation atomic {i:?}"),
                    }
                    false
                }
                JEQ_K => registers[dst] == i.imm as u64,
                JNE_K => registers[dst] != i.imm as u64,
                JLE_X => registers[dst] <= registers[src],
                JEQ_X => registers[dst] == registers[src],
                JA => true,
                EXIT => return registers[0],
                _ => panic!("unexpected gateway test instruction {i:?}"),
            };
            if branch {
                let target = b.jumps.iter().find(|(at, _)| *at == pc).unwrap().1;
                pc = b.labels[target.0].unwrap();
            } else {
                pc += 1;
            }
        }
    }

    #[test]
    fn only_complete_udp_reaches_dns_arbitration() {
        let mut b = GatewayBuilder::new();
        let miss = b.target();
        skip_incomplete_udp(&mut b, miss);
        b.imm(0, 1);
        b.emit(EXIT, 0, 0, 0, 0);
        b.bind(miss);
        b.imm(0, 0);
        b.emit(EXIT, 0, 0, 0, 0);

        let mut frame = [0u8; 512];
        let flags = frame
            .len()
            .checked_add_signed(isize::from(FRAG_STATE))
            .unwrap();
        let proto = frame
            .len()
            .checked_add_signed(isize::from(KEY + 44))
            .unwrap();
        for (protocol, state, allowed) in [
            (17, 0u32, 1),
            (17, 1, 0),
            (17, 2, 0),
            (17, 4, 1),
            (17, 5, 0),
            (17, 6, 0),
            (6, 0, 1),
            (6, 1, 1),
        ] {
            frame[flags..flags + 4].copy_from_slice(&state.to_le_bytes());
            frame[proto] = protocol;
            assert_eq!(
                interpret(&b, &mut 0, &frame, |_| unreachable!()),
                allowed,
                "{protocol}/{state}"
            );
        }
    }

    #[test]
    fn last_credit_distinguishes_contention_from_capacity() {
        let cap = NATIVE_PENDING_CAP;
        assert_eq!(allocation(cap - 1, &[]), (1, cap));
        assert_eq!(allocation(cap, &[]), (2, cap));
        assert_eq!(allocation(cap - 1, &[cap]), (2, cap));
        assert_eq!(allocation(cap - 2, &[cap - 1, cap]), (2, cap));
        assert_eq!(allocation(0, &[1, 2]), (3, 2));
        assert_eq!(allocation(0, &[1]), (1, 2));
    }

    #[test]
    fn unrelated_stamp_allocations_cannot_displace_an_admissible_ticket() {
        let mut b = GatewayBuilder::new();
        let exhausted = b.target();
        issue_sequence(&mut b, exhausted);
        b.mov(0, 2);
        b.emit(EXIT, 0, 0, 0, 0);
        b.bind(exhausted);
        b.imm(0, 0);
        b.emit(EXIT, 0, 0, 0, 0);

        let mut counter = 0;
        let stamp = interpret(&b, &mut counter, &[], |counter| {
            assert_eq!(interpret(&b, counter, &[], |_| {}), 1);
            assert_eq!(interpret(&b, counter, &[], |_| {}), 2);
        });
        assert_eq!((stamp, counter), (3, 3));

        counter = HOLD_SEQUENCE_MAX - 1;
        let stamp = interpret(&b, &mut counter, &[], |counter| {
            assert_eq!(interpret(&b, counter, &[], |_| {}), HOLD_SEQUENCE_MAX);
        });
        assert_eq!((stamp, counter), (0, HOLD_SEQUENCE_MAX + 1));
        for mut counter in [HOLD_SEQUENCE_MAX, HOLD_SEQUENCE_MAX + 1] {
            let prior = counter;
            assert_eq!(
                interpret(&b, &mut counter, &[], |_| panic!("exhausted RMW")),
                0
            );
            assert_eq!(counter, prior);
        }
    }
}

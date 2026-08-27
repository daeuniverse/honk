//! Routing engine for the eBPF data-plane.
//!
//! Implements the core `route()` function and `RouteCtx` state machine
//! that evaluates MatchSet rules via `bpf_loop`.  Ported 1:1 from Go
//! dae-core's `route_loop_cb` / `route()` in `kern/tproxy.c`.
//!
//! The routing result is encoded as a single `i64`:
//!   bits  0- 7 → outbound index
//!   bits  8-39 → fwmark
//!   bit      40 → must flag
//!   bit      56 → has_routing

use aya_ebpf_cty::c_void;
use core::ffi::c_long;

use aya_ebpf::bindings::__be32;
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf_bindings::helpers::bpf_loop;
use honk_ebpf_common::{
    L4ProtoType, ROUTING_GENERATION_COUNT, ROUTING_MAP_LEN, ROUTING_META_ACTIVE_GENERATION_SLOT,
    redirect_need::MAX_MATCH_SET_LEN,
    route::{
        MatchSet, MatchType, ROUTING_GROUP_BITMAP_WORDS, routing_group_index,
        routing_group_meta_index,
    },
};

use crate::{
    errno::{EFAULT, EINVAL, ENOEXEC},
    maps::{
        DEST_LPM_ROUTING_MAP, DOMAIN_ROUTING_MAP, MAC_LPM_ROUTING_MAP, ROUTE_CTX_SCRATCH_MAP,
        ROUTING_GROUP_META_MAP, ROUTING_MAP, ROUTING_META_MAP, SOURCE_LPM_ROUTING_MAP,
    },
};

pub const OUTBOUND_DIRECT: u8 = 0x0;
pub const OUTBOUND_BLOCK: u8 = 0x1;
pub const OUTBOUND_MUST_RULES: u8 = 0xFC;
pub const OUTBOUND_CONTROL_PLANE_ROUTING: u8 = 0xFD;
pub const OUTBOUND_LOGICAL_OR: u8 = 0xFE;
pub const OUTBOUND_LOGICAL_AND: u8 = 0xFF;
pub const OUTBOUND_LOGICAL_MASK: u8 = 0xFE;

/// `bpf_loop` callback control value: keep iterating.  NOT a TC verdict.
const LOOP_CONTINUE: i32 = 0;
/// `bpf_loop` callback control value: stop iterating (a rule matched or an
/// error was recorded in `RouteCtx::result`).  NOT a TC verdict.
const LOOP_BREAK: i32 = 1;

/// Internal error code for the `eval_match`/`match_*` helpers — NOT a TC
/// verdict; `route_loop_iteration` only checks `is_err()` and turns it into
/// [`LOOP_BREAK`] with `RouteCtx::result` carrying the real errno.
const MATCH_ERR: c_long = 1;

/// Execute routing decision for a packet.
///
/// Parameters map directly to the C `route()` function arguments:
/// - `flag[0]` = L4ProtoType (TCP=1, UDP=2)
/// - `flag[1]` = IpVersionType bit (IPv4=1, IPv6=2)
/// - `flag[2..6]` = Process name (4 × u32, WAN egress only)
/// - `flag[6]` = DSCP value
/// - `flag[7]` = is_wan flag
/// - `h_dport/h_sport` = destination/source ports in host byte order
/// - `saddr/daddr` = source/destination IP as 4 × big-endian u32
/// - `mac` = source MAC encoded as 4 × big-endian u32 (WAN egress uses this)
///
/// Returns: encoded result (outbound | (mark<<8) | (must<<40)), or negative errno.
#[inline(always)]
pub fn route(
    flag: &[u32; 8],
    h_dport: u16,
    h_sport: u16,
    saddr: &[__be32; 4],
    daddr: &[__be32; 4],
    mac: &[__be32; 4],
) -> i64 {
    let ctx_ptr = match ROUTE_CTX_SCRATCH_MAP.get_ptr_mut(0) {
        Some(ctx) => ctx,
        None => return -EFAULT as i64,
    };

    // Zero-init and set up through raw pointer (matching C's __builtin_memset)
    unsafe {
        *ctx_ptr = core::mem::zeroed();
        let ctx = &mut *ctx_ptr;

        ctx.is_wan = flag[7] as u8;
        ctx.mac = *mac;
        ctx.result = -ENOEXEC as i64;

        ctx.l4proto_type = flag[0] as u8;
        ctx.ipversion_type = flag[1] as u8;
        ctx.dscp_cache = flag[6] as u8;
        ctx.pname_cache = [flag[2], flag[3], flag[4], flag[5]];

        // Set up LPM keys with full /128 prefix length (matching C's IPV6_BYTE_LENGTH * 8)
        ctx.lpm_key_saddr = Key::new(128, *saddr);
        ctx.lpm_key_daddr = Key::new(128, *daddr);
        ctx.lpm_key_mac = Key::new(128, *mac);

        ctx.h_dport = h_dport;
        ctx.h_sport = h_sport;

        if h_dport == 53
            && (ctx.l4proto_type == L4ProtoType::Tcp as u8
                || ctx.l4proto_type == L4ProtoType::Udp as u8)
        {
            ctx.route_state |= RouteStateFlags::DnsQuery as u8;
        }

        let active_rules_len = ctx.prepare_generation();

        let ret = ctx.route_loop(active_rules_len);
        if ret < 0 {
            return ret;
        }

        if ctx.result >= 0 {
            return ctx.result;
        }
    }

    // No match_set hits (matching C's -EPERM fallback)
    -1i64
}

#[repr(C)]
pub struct RouteCtx {
    pub is_wan: u8,
    pub mac: [__be32; 4],
    pub h_dport: u16,
    pub h_sport: u16,
    pub result: i64,
    pub lpm_key_saddr: Key<[__be32; 4]>,
    pub lpm_key_daddr: Key<[__be32; 4]>,
    pub lpm_key_mac: Key<[__be32; 4]>,
    pub domain_word_idx: u32,
    pub domain_word_bits: u32,
    pub domain_word_cached: bool,
    pub route_state: u8,
    pub l4proto_type: u8,
    pub ipversion_type: u8,
    pub dscp_cache: u8,
    pub pname_cache: [u32; 4],
    /// Active physical rule bank selected once at route entry.
    pub active_generation: u32,
    /// Bitmap words for the selected generation and flow group.
    pub group_bitmap: [u32; ROUTING_GROUP_BITMAP_WORDS],
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteStateFlags {
    BadRule = 1 << 0,
    GoodSubrule = 1 << 1,
    Must = 1 << 2,
    DnsQuery = 1 << 3,
    /// The flow's destination domain was found in `DOMAIN_ROUTING_MAP`
    /// (DNS-learned), so every domain-set evaluation on this route pass used
    /// a complete bitmap and the decision needs no SNI re-evaluation.
    DomainKnown = 1 << 4,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WanEgressRouteScratch {
    pub flag: [u32; 8],
    pub mac_be: [__be32; 4],
    pub is_wan: u8,
    pub must_val: u8,
    pub mac: [u8; 6],
}

impl RouteCtx {
    /// LPM match: select the DEST/SOURCE/MAC LPM trie according to `match_type`,
    /// then check the bitmap bit for the current `match_set` index and set
    /// GOOD_SUBRULE if it matches.
    ///
    /// Returns `Ok(())` on normal execution (hit or miss), and
    /// `Err(MATCH_ERR)` if a map lookup fails.
    #[inline(always)]
    pub fn match_lpm(
        &mut self,
        lpm_key: &Key<[__be32; 4]>,
        match_type: MatchType,
        index: u32,
    ) -> Result<(), c_long> {
        let lpm = match match_type {
            MatchType::IpSet => DEST_LPM_ROUTING_MAP.get(lpm_key),
            MatchType::SourceIpSet => SOURCE_LPM_ROUTING_MAP.get(lpm_key),
            MatchType::Mac => MAC_LPM_ROUTING_MAP.get(lpm_key),
            _ => return Ok(()),
        };

        if let Some(dr) = lpm {
            let physical_index = index + self.active_generation * MAX_MATCH_SET_LEN as u32;
            let max_index = ROUTING_MAP_LEN as u32 - 1;
            let safe_index = core::hint::black_box(physical_index).min(max_index);
            let word = (safe_index / 32) as usize;
            let bit = safe_index % 32;
            if ((dr.bitmap[word] >> bit) & 1) != 0 {
                self.route_state |= RouteStateFlags::GoodSubrule as u8;
            }
        }

        Ok(())
    }

    /// Domain-set match: look up the bitmap in DOMAIN_ROUTING_MAP.
    ///
    /// Returns `Ok(())` on success, and `Err(MATCH_ERR)` if the index is out
    /// of bounds.
    #[inline(always)]
    pub fn match_domain_set(&mut self, index: u32) -> Result<(), c_long> {
        let physical_index = index + self.active_generation * MAX_MATCH_SET_LEN as u32;
        let safe_index = physical_index.min(ROUTING_MAP_LEN as u32 - 1);
        let bitmap_word_idx = safe_index / 32;
        let max_word_idx = (ROUTING_MAP_LEN as u32 / 32).saturating_sub(1);

        if !self.domain_word_cached || self.domain_word_idx != bitmap_word_idx {
            let key = self.lpm_key_daddr.data;

            self.domain_word_idx = bitmap_word_idx;
            match unsafe { DOMAIN_ROUTING_MAP.get(key) } {
                Some(domain_routing) => {
                    self.route_state |= RouteStateFlags::DomainKnown as u8;
                    let idx = core::hint::black_box(bitmap_word_idx).min(max_word_idx) as usize;
                    self.domain_word_bits = domain_routing.bitmap[idx];
                }
                None => {
                    self.domain_word_bits = 0;
                }
            }
            self.domain_word_cached = true;
        }

        if ((self.domain_word_bits >> (safe_index % 32)) & 1) != 0 {
            self.route_state |= RouteStateFlags::GoodSubrule as u8;
        }

        Ok(())
    }

    /// Core match dispatcher: corresponds to C's `route_eval_match`.
    ///
    /// Returns `Ok(())` when the match logic executed normally, and
    /// `Err(MATCH_ERR)` for internal errors (map failure or invalid type).
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn eval_match(
        &mut self,
        match_set: &MatchSet,
        index: u32,
        l4proto_type: u8,
        ipversion_type: u8,
        pname: &[u32; 4],
        is_wan: u8,
        dscp: u8,
    ) -> Result<(), c_long> {
        let match_type: MatchType = match MatchType::from_u8(match_set.match_type) {
            Some(mt) => mt,
            None => {
                self.result = -EINVAL as i64;
                return Err(MATCH_ERR);
            }
        };

        match match_type {
            MatchType::Mac | MatchType::IpSet | MatchType::SourceIpSet => {
                let lpm_key = match match_type {
                    MatchType::Mac => Key::new(self.lpm_key_mac.prefix_len, self.lpm_key_mac.data),
                    MatchType::IpSet => {
                        Key::new(self.lpm_key_daddr.prefix_len, self.lpm_key_daddr.data)
                    }
                    _ => Key::new(self.lpm_key_saddr.prefix_len, self.lpm_key_saddr.data),
                };
                self.match_lpm(&lpm_key, match_type, index)?;
            }

            MatchType::Port | MatchType::SourcePort => {
                let check_port = if match_type == MatchType::Port {
                    self.h_dport
                } else {
                    self.h_sport
                };
                let port_range = unsafe { match_set.value.port_range };
                if check_port >= port_range.port_start && check_port <= port_range.port_end {
                    self.route_state |= RouteStateFlags::GoodSubrule as u8;
                }
            }

            MatchType::L4Proto | MatchType::IpVersion => {
                let value = if match_type == MatchType::L4Proto {
                    l4proto_type
                } else {
                    ipversion_type
                };
                let mask = if match_type == MatchType::L4Proto {
                    unsafe { match_set.value.l4proto_type as u8 }
                } else {
                    unsafe { match_set.value.ip_version as u8 }
                };
                if (value & mask) != 0 {
                    self.route_state |= RouteStateFlags::GoodSubrule as u8;
                }
            }

            MatchType::DomainSet => {
                self.match_domain_set(index)?;
            }

            MatchType::ProcessName => {
                if is_wan != 0 {
                    let match_pname = unsafe { match_set.value.pname };
                    if match_pname == *pname {
                        self.route_state |= RouteStateFlags::GoodSubrule as u8;
                    }
                }
            }

            MatchType::Dscp => {
                let match_dscp = unsafe { match_set.value.dscp };
                if dscp == match_dscp {
                    self.route_state |= RouteStateFlags::GoodSubrule as u8;
                }
            }

            MatchType::Fallback => {
                self.route_state |= RouteStateFlags::GoodSubrule as u8;
            }

            _ => {
                self.result = -EINVAL as i64;
                return Err(MATCH_ERR);
            }
        }

        Ok(())
    }

    /// Rule finalization: corresponds to C's `route_finalize_match`.
    ///
    /// Returns `LOOP_CONTINUE` to continue to the next `match_set`, and
    /// `LOOP_BREAK` when a rule has matched and `self.result` has been set.
    #[inline(always)]
    pub fn finalize_match(&mut self, match_set: &MatchSet) -> i32 {
        let match_outbound = match_set.outbound;
        let match_not = match_set.not != 0;

        // Sub-rule tail: check whether good_subrule matched.
        if match_outbound != OUTBOUND_LOGICAL_OR {
            let good_subrule = (self.route_state & (RouteStateFlags::GoodSubrule as u8)) != 0;
            if good_subrule == match_not {
                self.route_state |= RouteStateFlags::BadRule as u8;
            }
            self.route_state &= !(RouteStateFlags::GoodSubrule as u8);
        }

        // Rule tail (end of line): decide the final routing result.
        if (match_outbound & OUTBOUND_LOGICAL_MASK) != OUTBOUND_LOGICAL_MASK {
            if (self.route_state & (RouteStateFlags::BadRule as u8)) == 0 {
                if match_outbound == OUTBOUND_MUST_RULES {
                    self.route_state |= RouteStateFlags::Must as u8;
                } else {
                    let must = (self.route_state & (RouteStateFlags::Must as u8)) != 0
                        || match_set.must != 0;

                    // DNS query and not `must`: hand off to the control plane.
                    if !must && (self.route_state & (RouteStateFlags::DnsQuery as u8)) != 0 {
                        self.result = (OUTBOUND_CONTROL_PLANE_ROUTING as i64)
                            | ((match_set.mark as i64) << 8)
                            | ((must as i64) << 40);
                        return LOOP_BREAK;
                    }

                    self.result = (match_outbound as i64)
                        | ((match_set.mark as i64) << 8)
                        | ((must as i64) << 40);
                    return LOOP_BREAK;
                }
            }
            self.route_state &= !(RouteStateFlags::BadRule as u8);
        }

        LOOP_CONTINUE
    }

    /// Select the committed rule bank and load this flow group's packed
    /// count/bitmap metadata with one map lookup.
    #[inline(always)]
    pub fn prepare_generation(&mut self) -> u32 {
        let active_generation = match ROUTING_META_MAP.get(ROUTING_META_ACTIVE_GENERATION_SLOT) {
            Some(generation) if *generation < ROUTING_GENERATION_COUNT as u32 => *generation,
            _ => 0,
        };
        self.active_generation = active_generation;

        let group = routing_group_index(self.l4proto_type, self.ipversion_type);
        let index = routing_group_meta_index(active_generation, group);
        let Some(meta) = ROUTING_GROUP_META_MAP.get(index) else {
            self.group_bitmap = [0; ROUTING_GROUP_BITMAP_WORDS];
            return 0;
        };
        if meta.rule_count > MAX_MATCH_SET_LEN as u32 {
            self.group_bitmap = [0; ROUTING_GROUP_BITMAP_WORDS];
            return 0;
        }
        self.group_bitmap = meta.bitmap;
        meta.rule_count
    }

    #[inline(always)]
    pub fn route_loop_iteration(&mut self, index: u32) -> i32 {
        let l4proto_type = self.l4proto_type;
        let ipversion_type = self.ipversion_type;
        let is_wan = self.is_wan;
        let dscp = self.dscp_cache;

        if index >= MAX_MATCH_SET_LEN as u32 {
            self.result = -EFAULT as i64;
            return LOOP_BREAK;
        }

        // Group pre-filter: skip MatchSets that do not belong to this
        // flow's (l4proto × ipversion) group.  Such a MatchSet can never
        // match — its rule carries an L4Proto/IpVersion condition that
        // fails for this flow — so it is skipped without reading
        // ROUTING_MAP and without running eval_match/finalize_match.
        // Because skipped entries never execute, they cannot touch the
        // LogicalOr/And state machine: GoodSubrule/BadRule only ever flow
        // between in-group entries, and the compiler assigns every
        // MatchSet of a rule chain to the same groups, so a chain is
        // never split across the skip boundary.
        let safe_index = core::hint::black_box(index).min(MAX_MATCH_SET_LEN as u32 - 1);
        let word = (safe_index / 32) as usize;
        let bit = safe_index % 32;
        if ((self.group_bitmap[word] >> bit) & 1) == 0 {
            return LOOP_CONTINUE;
        }

        let k = index + self.active_generation * MAX_MATCH_SET_LEN as u32;

        let match_set = match ROUTING_MAP.get(k) {
            Some(ms) => ms,
            None => {
                self.result = -EFAULT as i64;
                return LOOP_BREAK;
            }
        };

        // Only run eval_match when neither BAD_RULE nor GOOD_SUBRULE is set.
        let has_bad_rule = (self.route_state & (RouteStateFlags::BadRule as u8)) != 0;
        let has_good_subrule = (self.route_state & (RouteStateFlags::GoodSubrule as u8)) != 0;

        if has_bad_rule || has_good_subrule {
        } else {
            let pname = self.pname_cache;
            if self
                .eval_match(
                    match_set,
                    index,
                    l4proto_type,
                    ipversion_type,
                    &pname,
                    is_wan,
                    dscp,
                )
                .is_err()
            {
                // eval_match has already set self.result to the error code.
                return LOOP_BREAK;
            }
        }

        self.finalize_match(match_set)
    }

    /// Outer entry point: start bpf_loop.
    ///
    /// Corresponds to the C call `bpf_loop(nr_loops, route_loop_cb, &loop_ctx, 0)`.
    #[inline(always)]
    pub fn route_loop(&mut self, nr_loops: u32) -> i64 {
        let mut loop_ctx = RouteLoopCtx {
            work: self as *mut _,
        };

        // bpf_loop signature: fn(nr_loops, callback, ctx, flags) -> i32.
        // The callback must be an extern "C" function pointer.
        unsafe {
            bpf_loop(
                nr_loops,
                Self::route_loop_cb as *mut c_void,
                &mut loop_ctx as *mut _ as *mut c_void,
                0,
            )
        }
    }

    /// extern "C" callback wrapper for bpf_loop.
    ///
    /// bpf_loop requires the callback signature:
    /// `fn(index: u32, ctx: *mut c_void) -> i32`.
    extern "C" fn route_loop_cb(index: u32, data: *mut c_void) -> i32 {
        let loop_ctx = unsafe { &mut *(data as *mut RouteLoopCtx) };
        let route_ctx = unsafe { &mut *loop_ctx.work };
        route_ctx.route_loop_iteration(index)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RouteLoopCtx {
    pub work: *mut RouteCtx,
}

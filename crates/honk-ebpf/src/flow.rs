//! Native value-lock boundaries for stable tuple elements.

use aya_ebpf_bindings::helpers::{bpf_spin_lock, bpf_spin_unlock};
use honk_ebpf_common::{
    ConnState, FlowMapValue, RedirectEntry, RedirectTuple, RoutingHandoffEntry, TuplesKey,
};

use crate::maps::{CONN_STATE_MAP, REDIRECT_TRACK, ROUTING_HANDOFF_MAP};

/// Copy only fixed-size, eight-byte-aligned payloads without emitting memcpy under a lock.
#[inline(always)]
pub unsafe fn copy_payload<T: Copy>(dst: *mut T, src: *const T) {
    const {
        assert!(core::mem::size_of::<T>() % 8 == 0);
    }
    const {
        assert!(core::mem::align_of::<T>() >= 8);
    }
    let dst = dst.cast::<u64>();
    let src = src.cast::<u64>();
    let mut i = 0;
    while i < core::mem::size_of::<T>() / 8 {
        unsafe { dst.add(i).write_volatile(src.add(i).read_volatile()) };
        i += 1;
    }
}

/// Zero a fixed-size, eight-byte-aligned payload without emitting memset: the
/// out-of-line memset subprogram costs a 32-byte frame before Linux 6.6.
#[inline(always)]
pub unsafe fn zero_payload<T: Copy>(dst: *mut T) {
    const {
        assert!(core::mem::size_of::<T>() % 8 == 0);
    }
    const {
        assert!(core::mem::align_of::<T>() >= 8);
    }
    let dst = dst.cast::<u64>();
    let mut i = 0;
    while i < core::mem::size_of::<T>() / 8 {
        unsafe { dst.add(i).write_volatile(0) };
        i += 1;
    }
}

/// The projection runs under the value lock: volatile field reads only, no call or helper.
#[inline(always)]
unsafe fn locked_read<T, R>(ptr: *mut FlowMapValue<T>, project: impl FnOnce(*const T) -> R) -> R {
    unsafe {
        bpf_spin_lock(&mut (*ptr).lock);
        let result = project(&raw const (*ptr).value);
        bpf_spin_unlock(&mut (*ptr).lock);
        result
    }
}

#[inline(always)]
unsafe fn snapshot<T: Copy>(ptr: *mut FlowMapValue<T>) -> T {
    let mut result = core::mem::MaybeUninit::<T>::uninit();
    unsafe {
        locked_read(ptr, |value| copy_payload(result.as_mut_ptr(), value));
        result.assume_init()
    }
}

#[inline(always)]
pub fn conn_snapshot(key: &TuplesKey) -> Option<ConnState> {
    Some(unsafe { snapshot(CONN_STATE_MAP.get_ptr_mut(key)?) })
}

#[inline(always)]
pub fn handoff_snapshot(key: &TuplesKey) -> Option<RoutingHandoffEntry> {
    Some(unsafe { snapshot(ROUTING_HANDOFF_MAP.get_ptr_mut(key)?) })
}

#[inline(always)]
pub fn redirect_snapshot(key: &RedirectTuple) -> Option<RedirectEntry> {
    Some(unsafe { snapshot(REDIRECT_TRACK.get_ptr_mut(key)?) })
}

pub struct ConnLifecycle {
    pub incarnation: u64,
    pub last_seen_ns: u64,
    pub state: u8,
}

pub struct AuxiliaryIdentity {
    pub incarnation: u64,
    pub last_seen_ns: u64,
    pub decision_token: u32,
}

#[inline(always)]
pub fn conn_lifecycle(key: &TuplesKey) -> Option<ConnLifecycle> {
    let ptr = CONN_STATE_MAP.get_ptr_mut(key)?;
    Some(unsafe {
        locked_read(ptr, |value| ConnLifecycle {
            incarnation: (&raw const (*value).incarnation).read_volatile(),
            last_seen_ns: (&raw const (*value).last_seen_ns).read_volatile(),
            state: (&raw const (*value).state).read_volatile(),
        })
    })
}

pub struct TcpSynState {
    pub incarnation: u64,
    pub tcp_syn_isn: u32,
    pub tcp_syn_flags: u16,
    pub state: u8,
    pub published: bool,
}

#[inline(always)]
pub fn tcp_syn_state(key: &TuplesKey) -> Option<TcpSynState> {
    let ptr = CONN_STATE_MAP.get_ptr_mut(key)?;
    Some(unsafe {
        locked_read(ptr, |value| TcpSynState {
            incarnation: (&raw const (*value).incarnation).read_volatile(),
            tcp_syn_isn: (&raw const (*value).tcp_syn_isn).read_volatile(),
            tcp_syn_flags: (&raw const (*value).tcp_syn_flags).read_volatile(),
            state: (&raw const (*value).state).read_volatile(),
            published: (&raw const (*value).meta.raw).read_volatile()
                & honk_ebpf_common::ROUTING_META_FLAG_PUBLISHED
                != 0,
        })
    })
}

#[inline(always)]
pub fn redirect_identity(key: &RedirectTuple) -> Option<AuxiliaryIdentity> {
    let ptr = REDIRECT_TRACK.get_ptr_mut(key)?;
    Some(unsafe {
        locked_read(ptr, |value| AuxiliaryIdentity {
            incarnation: (&raw const (*value).incarnation).read_volatile(),
            last_seen_ns: (&raw const (*value).last_seen_ns).read_volatile(),
            decision_token: (&raw const (*value).decision_token).read_volatile(),
        })
    })
}

#[inline(always)]
pub fn handoff_identity(key: &TuplesKey) -> Option<AuxiliaryIdentity> {
    let ptr = ROUTING_HANDOFF_MAP.get_ptr_mut(key)?;
    Some(unsafe {
        locked_read(ptr, |value| AuxiliaryIdentity {
            incarnation: (&raw const (*value).incarnation).read_volatile(),
            last_seen_ns: (&raw const (*value).last_seen_ns).read_volatile(),
            decision_token: (&raw const (*value).result.decision_token).read_volatile(),
        })
    })
}

#[inline(always)]
pub fn conn_incarnation(key: &TuplesKey) -> Option<u64> {
    let ptr = CONN_STATE_MAP.get_ptr_mut(key)?;
    Some(unsafe {
        locked_read(ptr, |value| {
            (&raw const (*value).incarnation).read_volatile()
        })
    })
}

#[inline(always)]
pub fn handoff_incarnation(key: &TuplesKey) -> Option<u64> {
    let ptr = ROUTING_HANDOFF_MAP.get_ptr_mut(key)?;
    Some(unsafe {
        locked_read(ptr, |value| {
            (&raw const (*value).incarnation).read_volatile()
        })
    })
}

#[inline(always)]
pub fn redirect_incarnation(key: &RedirectTuple) -> Option<u64> {
    let ptr = REDIRECT_TRACK.get_ptr_mut(key)?;
    Some(unsafe {
        locked_read(ptr, |value| {
            (&raw const (*value).incarnation).read_volatile()
        })
    })
}

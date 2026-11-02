//! Raw access to the TC context.
//!
//! aya-ebpf keeps the `__sk_buff` pointer private and builds the context from a
//! `NonNull`; these helpers recover the pointer from [`EbpfContext`] and wrap
//! the entry-point argument without `unsafe`.

use aya_ebpf::{EbpfContext, bindings::__sk_buff, programs::TcContext};
use core::ptr::NonNull;

/// The context's `__sk_buff` pointer, for helpers and field access aya does not wrap.
#[inline(always)]
pub fn raw_skb(ctx: &TcContext) -> *mut __sk_buff {
    ctx.as_ptr().cast()
}

/// Wraps the entry-point argument; the kernel never passes null, so `None` is unreachable.
#[inline(always)]
pub fn tc_context(ctx: *mut __sk_buff) -> Option<TcContext> {
    NonNull::new(ctx).map(TcContext::new)
}

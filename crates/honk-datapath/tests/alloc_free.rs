//! Frame ownership hot operations must not allocate after construction and warmup.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

use honk_datapath::buffer::{FrameConfig, FrameLedger, LedgerError, TxClass};
use honk_netstack::MemoryBudget;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
}

struct Counting;

fn count() {
    if COUNTING.get() {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
}

// SAFETY: every method forwards unchanged to `System`; counting touches no allocator state.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

fn allocations_in(f: impl FnOnce()) -> usize {
    COUNTING.set(true);
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    f();
    let after = ALLOCATIONS.load(Ordering::Relaxed);
    COUNTING.set(false);
    after - before
}

fn hot_cycle(ledger: &mut FrameLedger<(u64, u32)>, incarnation: u32) {
    for class in [TxClass::Control, TxClass::Bulk] {
        let unused = ledger.reserve_tx(class).unwrap();
        ledger.cancel_tx(unused).unwrap();
    }
    let bulk = ledger.reserve_tx(TxClass::Bulk).unwrap();
    let control = ledger.reserve_tx(TxClass::Control).unwrap();
    let spare = ledger.reserve_tx(TxClass::Bulk).unwrap();
    assert_eq!(
        ledger.reserve_tx(TxClass::Bulk),
        Err(LedgerError::NoDescriptor)
    );
    assert_eq!(
        ledger.reserve_tx(TxClass::Control),
        Err(LedgerError::NoDescriptor)
    );
    ledger.cancel_tx(spare).unwrap();
    ledger.submit_tx(bulk, 512, (9, incarnation)).unwrap();
    ledger
        .submit_tx(control, control.capacity(), (7, incarnation))
        .unwrap();
    assert_eq!(ledger.outstanding_tx().count(), 2);
    assert_eq!(ledger.complete_tx(control.address()), Ok((7, incarnation)));
    assert_eq!(ledger.release_tx(bulk), Ok((9, incarnation)));

    let unused = ledger.reserve_fill().unwrap();
    ledger.cancel_fill(unused).unwrap();
    let first = ledger.reserve_fill().unwrap();
    let second = ledger.reserve_fill().unwrap();
    ledger.submit_fill(first).unwrap();
    ledger.submit_fill(second).unwrap();
    assert_eq!(ledger.reserve_fill(), Err(LedgerError::NoFillCredit));
    ledger.consume_fill(2).unwrap();
    let rx = ledger.receive_rx(first.address() + 128, 512).unwrap();
    assert_eq!(
        ledger.receive_rx(second.address(), 1),
        Err(LedgerError::NoRxCredit)
    );
    ledger.relinquish_rx(rx).unwrap();
    let rx = ledger
        .receive_rx(second.address() + second.capacity() as u64 - 1, 1)
        .unwrap();
    assert_eq!(rx.capacity(), 1);
    ledger.relinquish_rx(rx).unwrap();
    assert!(ledger.drain_state().is_drained());
}

#[test]
fn warmed_frame_ownership_operations_allocate_nothing() {
    let config = FrameConfig {
        base_address: 4096,
        frame_size: 2048,
        rx_frames: 3,
        control_frames: 2,
        bulk_frames: 3,
        fill_capacity: 2,
        rx_capacity: 1,
        control_descriptors: 1,
        bulk_descriptors: 2,
        tx_capacity: 3,
        completion_capacity: 3,
    };
    let bytes = FrameLedger::<(u64, u32)>::metadata_bytes(config).unwrap();
    let budget = MemoryBudget::new(bytes);
    let mut ledger = FrameLedger::new(config, &budget).unwrap();
    for incarnation in 0..32 {
        hot_cycle(&mut ledger, incarnation);
    }
    let allocations = allocations_in(|| {
        for incarnation in 32..1056 {
            hot_cycle(&mut ledger, incarnation);
            assert_eq!(budget.used(), bytes);
        }
        assert!(ledger.close().is_drained());
        assert_eq!(ledger.reserve_tx(TxClass::Bulk), Err(LedgerError::Closed));
        assert_eq!(ledger.reserve_fill(), Err(LedgerError::Closed));
    });
    assert_eq!(allocations, 0, "FrameLedger hot operations allocated");
    assert_eq!(budget.used(), bytes);
    drop(ledger);
    assert_eq!(budget.used(), 0);
}

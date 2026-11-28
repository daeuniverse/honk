use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

fn config() -> PortConfig {
    PortConfig {
        rx_frames: 2,
        control_frames: 1,
        bulk_frames: 1,
        ring_size: 4,
    }
}

fn fake<L>(config: PortConfig, budget: &Arc<MemoryBudget>) -> Port<L> {
    config.validate().unwrap();
    let bookkeeping =
        reserve(budget, size_of::<Port<L>>() - size_of::<FrameLedger<u32>>()).unwrap();
    let retained_rx = RetainedRxSlots::new(config, budget).unwrap();
    Port {
        socket: None,
        config,
        zerocopy: false,
        mtu: 1500,
        scatter_gather: false,
        metadata_len: METADATA_SIZE,
        umem: Umem::fake(config.umem_bytes().unwrap(), budget),
        rings: Rings::fake(config.ring_size, budget),
        ledger: ManuallyDrop::new(FrameLedger::new(config.frame_config(), budget).unwrap()),
        retained_rx,
        sidecar: Sidecar::new(config, budget).unwrap(),
        rx_consumer: 0,
        tx_producer: 0,
        tx_unpublished: Cell::new(false),
        tx_cached_consumer: Cell::new(0),
        fill_producer: 0,
        fill_consumer: 0,
        cq_consumer: 0,
        tx_free: [config.control_frames, config.bulk_frames],
        closed: Cell::new(false),
        tx_batch_active: false,
        counters: PortCounters::default(),
        _bookkeeping: Some(bookkeeping),
    }
}

fn queue_rx(port: &mut Port<()>, lengths: &[usize], metadata_len: usize) {
    let producer = stage_rx(port, lengths, metadata_len);
    port.rings.rx.publish_producer(producer);
}

fn stage_rx(port: &mut Port<()>, lengths: &[usize], metadata_len: usize) -> u32 {
    let fill = port.rings.fill.consumer();
    let rx = port.rings.rx.producer();
    for (part, &length) in lengths.iter().enumerate() {
        let address =
            port.rings.fill.read(fill.wrapping_add(part as u32)) + 256 + metadata_len as u64;
        if part == 0 && metadata_len != 0 {
            port.umem
                .write_bytes(address - metadata_len as u64, &[0xa5; 128][..metadata_len]);
        }
        port.umem
            .write_bytes(address, &[(part + 1) as u8; FRAME_SIZE][..length]);
        port.rings.rx.write(
            rx.wrapping_add(part as u32),
            Descriptor {
                addr: address,
                len: length as u32,
                options: u32::from(part + 1 != lengths.len()),
            },
        );
    }
    port.rings
        .fill
        .publish_consumer(fill.wrapping_add(lengths.len() as u32));
    rx.wrapping_add(lengths.len() as u32)
}

fn retain_rx(port: &mut Port<()>, metadata_len: usize) -> RetainedRxHandle {
    let mut handle = None;
    assert_eq!(
        port.receive_segments_owned(1, metadata_len, |owned, _, _, tx| {
            assert_eq!(tx.port.retained_rx_count(), 1);
            handle = Some(owned);
            RxDisposition::Retain
        })
        .unwrap(),
        1
    );
    handle.unwrap()
}

#[test]
fn retained_rx_whole_chain_credit_precedes_first_lease() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(
        PortConfig {
            rx_frames: 4,
            control_frames: 4,
            bulk_frames: 4,
            ring_size: 8,
        },
        &budget,
    );
    let mut frames = port.config.frame_config();
    frames.rx_capacity = 2;
    // SAFETY: this fixture has not posted frames or acquired any leases.
    unsafe { ManuallyDrop::drop(&mut port.ledger) };
    port.ledger = ManuallyDrop::new(FrameLedger::new(frames, &budget).unwrap());
    port.mtu = 9000;
    port.scatter_gather = true;
    port.metadata_len = 64;
    port.refill().unwrap();
    queue_rx(&mut port, &[60], 64);
    let first = retain_rx(&mut port, 64);
    queue_rx(&mut port, &[3000, 3000], 64);
    let consumer = port.rings().rx_consumer;
    let fill = port.rings().fill_producer;
    let free = port.retained_rx.free;
    assert_eq!(port.ledger.rx_credit(), 1);
    assert_eq!(
        port.receive_segments(1, 64, |_, _| panic!("half-leased borrowed RX chain"))
            .unwrap(),
        0
    );
    assert_eq!(
        port.receive_segments_owned(1, 64, |_, _, _, _| { panic!("half-leased RX chain") })
            .unwrap(),
        0
    );
    assert_eq!(port.rings().rx_consumer, consumer);
    assert_eq!(port.rings().fill_producer, fill);
    assert_eq!(port.drain_state().rx_leased, 1);
    assert_eq!(port.retained_rx.free, free);
    assert!(!port.drain_state().closed);
    let first_done = port.release_retained_rx(first).unwrap();
    assert_eq!(port.rx_completion_count(), 1);
    let second = retain_rx(&mut port, 64);
    assert_ne!(first.slot, second.slot);
    assert_eq!(port.drain_state().rx_leased, 2);
    port.with_retained_rx(second, |parts, metadata| {
        assert_eq!(parts, &[&[1; 3000][..], &[2; 3000][..]]);
        assert_eq!(metadata, &[0xa5; 64]);
    })
    .unwrap();
    let second_done = port.release_retained_rx(second).unwrap();
    port.complete_retained_rx(second_done).unwrap();
    port.complete_retained_rx(first_done).unwrap();

    let mut port = fake::<()>(config(), &budget);
    port.scatter_gather = true;
    port.refill().unwrap();
    let mut completions = Vec::new();
    for _ in 0..2 {
        queue_rx(&mut port, &[60], 0);
        let handle = retain_rx(&mut port, 0);
        completions.push(port.release_retained_rx(handle).unwrap());
    }
    assert_eq!(port.retained_rx.free, NO_RX_SLOT);
    assert_eq!(port.ledger.rx_credit(), 2);
    queue_rx(&mut port, &[60, 60], 0);
    let consumer = port.rings().rx_consumer;
    assert_eq!(
        port.receive_segments_owned(1, 0, |_, _, _, _| panic!("slot full"))
            .unwrap(),
        0
    );
    assert_eq!(port.rings().rx_consumer, consumer);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.rx_completion_count(), 2);
    port.complete_retained_rx(completions.pop().unwrap())
        .unwrap();
    let handle = retain_rx(&mut port, 0);
    let done = port.release_retained_rx(handle).unwrap();
    queue_rx(&mut port, &[60, 60], 0);
    assert_eq!(
        port.receive_segments(1, 0, |parts, _| assert_eq!(parts.len(), 2))
            .unwrap(),
        1
    );
    assert_eq!(port.rx_completion_count(), 2);
    assert_eq!(port.retained_rx.free, NO_RX_SLOT);
    port.complete_retained_rx(done).unwrap();
    port.complete_retained_rx(completions.pop().unwrap())
        .unwrap();

    let mut port = fake::<()>(
        PortConfig {
            rx_frames: 4,
            control_frames: 2,
            bulk_frames: 2,
            ring_size: 4,
        },
        &budget,
    );
    port.scatter_gather = true;
    port.refill().unwrap();
    queue_rx(&mut port, &[60; 4], 0);
    for index in 0..4 {
        let mut descriptor = port.rings.rx.read(index);
        descriptor.options = u32::from(index == 3);
        port.rings.rx.write(index, descriptor);
    }
    assert_eq!(
        port.receive_segments_owned(4, 0, |_, _, _, _| RxDisposition::Release)
            .unwrap(),
        3
    );
    assert_eq!(port.rings().rx_consumer, 3);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert!(!port.drain_state().closed);
    queue_rx(&mut port, &[60], 0);
    assert_eq!(
        port.receive_segments_owned(1, 0, |_, parts, _, _| {
            assert_eq!(parts.len(), 2);
            RxDisposition::Release
        })
        .unwrap(),
        1
    );
    assert_eq!(port.rings().rx_consumer, 5);
}

#[test]
fn retained_rx_generation_survives_completion_and_callback_panic() {
    for panic_on_borrow in [false, true] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.mtu = 9000;
        port.scatter_gather = true;
        port.metadata_len = 64;
        port.refill().unwrap();
        queue_rx(&mut port, &[3000, 3000], 64);
        let fill = port.rings().fill_producer;
        let mut handle = None;
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            port.receive_segments_owned(1, 64, |owned, parts, metadata, tx| {
                handle = Some(owned);
                assert_eq!(tx.port.retained_rx_count(), 1);
                assert_eq!(tx.port.drain_state().rx_leased, 2);
                assert_eq!(parts.len(), 2);
                assert_eq!(metadata, &[0xa5; 64]);
                if !panic_on_borrow {
                    panic!("RX callback unwind");
                }
                RxDisposition::Retain
            })
            .unwrap();
            port.with_retained_rx(handle.unwrap(), |_, _| panic!("writev unwind"))
                .unwrap();
        }));
        assert!(panic.is_err());
        let handle = handle.unwrap();
        assert!(port.drain_state().closed);
        assert!(!port.tx_credit(TxClass::Bulk));
        assert_eq!(port.rings().rx_consumer, 2);
        assert_eq!(port.rings().fill_producer, fill);
        assert_eq!(port.retained_rx_count(), 1);
        assert_eq!(port.rx_completion_count(), 0);
        port.with_retained_rx(handle, |parts, metadata| {
            assert_eq!(parts, &[&[1; 3000][..], &[2; 3000][..]]);
            assert_eq!(metadata, &[0xa5; 64]);
        })
        .unwrap();
        let completion = port.release_retained_rx(handle).unwrap();
        assert_eq!(completion.handle(), handle);
        assert_eq!(port.retained_rx_count(), 0);
        assert_eq!(port.rx_completion_count(), 1);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert!(!port.close().ready_for_backend_teardown());
        drop(completion);
        let retained = port.umem_bytes()
            + port.ledger.charged_bytes()
            + port.retained_rx.reservation.as_ref().unwrap().bytes()
            + port._bookkeeping.as_ref().unwrap().bytes();
        drop(port);
        assert_eq!(budget.used(), retained);
    }
    {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.refill().unwrap();
        queue_rx(&mut port, &[60], 32);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            port.receive(1, |_| panic!("single-buffer RX unwind"))
                .unwrap();
        }));
        assert!(panic.is_err());
        assert!(port.drain_state().closed);
        assert_eq!(port.retained_rx_count(), 1);
        assert_eq!(port.drain_state().rx_leased, 1);
        assert_eq!(port.rings().rx_consumer, 1);
        assert_eq!(port.rings().fill_producer, 2);
        assert!(!port.close().ready_for_backend_teardown());
    }

    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    port.refill().unwrap();
    queue_rx(&mut port, &[60], 0);
    let handle = retain_rx(&mut port, 0);
    port.rings.fill.set_wakeup();
    assert_eq!(
        port.release_retained_rx(handle).unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(port.retained_rx_count(), 0);
    assert_eq!(port.rx_completion_count(), 1);
    assert!(!port.close().ready_for_backend_teardown());
    assert_eq!(
        port.release_retained_rx(handle).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );

    for invalid in ["borrow", "release", "completion"] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.refill().unwrap();
        queue_rx(&mut port, &[60], 0);
        let first = retain_rx(&mut port, 0);
        let first_done = port.release_retained_rx(first).unwrap();
        assert_eq!(first_done.handle(), first);
        queue_rx(&mut port, &[60], 0);
        let second = retain_rx(&mut port, 0);
        assert_ne!(first.slot, second.slot);
        let second_done = port.release_retained_rx(second).unwrap();
        port.complete_retained_rx(second_done).unwrap();
        port.complete_retained_rx(first_done).unwrap();
        queue_rx(&mut port, &[60], 0);
        let current = retain_rx(&mut port, 0);
        assert_eq!(current.slot, first.slot);
        assert_ne!(current, first);
        assert_eq!(
            current.receipt_identity(),
            RetainedRxIdentity {
                port: current.port,
                port_generation: current.port_generation,
                slot: current.slot,
                slot_generation: current.generation,
            }
        );
        let pending = if invalid == "completion" {
            Some(port.release_retained_rx(current).unwrap())
        } else {
            None
        };
        let error = match invalid {
            "borrow" => port
                .with_retained_rx(first, |_, _| panic!("stale borrow"))
                .unwrap_err(),
            "release" => port.release_retained_rx(first).unwrap_err(),
            "completion" => port
                .complete_retained_rx(RxCompletion { handle: first })
                .unwrap_err(),
            _ => unreachable!(),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(port.drain_state().closed);
        assert_eq!(port.retained_rx_count(), usize::from(pending.is_none()));
        assert_eq!(port.drain_state().rx_leased, usize::from(pending.is_none()));
        let completion = pending.unwrap_or_else(|| port.release_retained_rx(current).unwrap());
        assert_eq!(
            port.release_retained_rx(current).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(port.rx_completion_count(), 1);
        port.complete_retained_rx(completion).unwrap();
        assert_eq!(port.rx_completion_count(), 0);
        assert!(port.close().ready_for_backend_teardown());
    }

    for operation in ["borrow", "release", "completion"] {
        for identity in ["port", "port-generation"] {
            let budget = MemoryBudget::new(1 << 20);
            let mut port = fake::<()>(config(), &budget);
            let mut foreign = fake::<()>(config(), &budget);
            port.refill().unwrap();
            foreign.refill().unwrap();
            queue_rx(&mut port, &[60], 0);
            queue_rx(&mut foreign, &[60], 0);
            let source = retain_rx(&mut port, 0);
            let destination = retain_rx(&mut foreign, 0);
            assert_eq!(source.slot, destination.slot);
            assert_eq!(source.generation, destination.generation);
            assert_eq!(source.port_generation, destination.port_generation);
            assert_ne!(source.port, destination.port);
            let token = if identity == "port" {
                source
            } else {
                RetainedRxHandle {
                    port_generation: destination.port_generation + 1,
                    ..destination
                }
            };
            let completions = if operation == "completion" {
                Some((
                    port.release_retained_rx(source).unwrap(),
                    foreign.release_retained_rx(destination).unwrap(),
                ))
            } else {
                None
            };
            let phase = if completions.is_some() {
                RxPhase::CompletionPending
            } else {
                RxPhase::Held
            };
            assert!(port.retained_rx.slots[source.slot as usize].phase == phase);
            assert!(foreign.retained_rx.slots[destination.slot as usize].phase == phase);
            let error = match operation {
                "borrow" => foreign.with_retained_rx(token, |_, _| ()).unwrap_err(),
                "release" => foreign.release_retained_rx(token).unwrap_err(),
                "completion" => foreign
                    .complete_retained_rx(RxCompletion { handle: token })
                    .unwrap_err(),
                _ => unreachable!(),
            };
            assert_eq!(
                error.kind(),
                io::ErrorKind::InvalidData,
                "{operation}/{identity}"
            );
            assert!(foreign.drain_state().closed);
            assert!(foreign.retained_rx.slots[destination.slot as usize].phase == phase);
            let (source_done, destination_done) = completions.unwrap_or_else(|| {
                (
                    port.release_retained_rx(source).unwrap(),
                    foreign.release_retained_rx(destination).unwrap(),
                )
            });
            port.complete_retained_rx(source_done).unwrap();
            foreign.complete_retained_rx(destination_done).unwrap();
            assert!(port.close().ready_for_backend_teardown());
            assert!(foreign.close().ready_for_backend_teardown());
        }
    }

    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    port.retained_rx.slots[0].generation = u64::MAX;
    port.refill().unwrap();
    queue_rx(&mut port, &[60], 0);
    assert_eq!(
        port.receive_segments_owned(1, 0, |_, _, _, _| panic!("wrapped slot generation"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(port.rings().rx_consumer, 0);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.retained_rx.slots[0].generation, u64::MAX);
    assert!(port.drain_state().closed);
}

#[test]
fn retained_rx_reserves_layout_before_umem() {
    for (rx_frames, ring_size) in [(2, 4), (256, 512), (512, 256)] {
        let config = PortConfig {
            rx_frames,
            ring_size,
            control_frames: 1,
            bulk_frames: 1,
        };
        let count = rx_frames.min(ring_size as usize);
        let bytes = count * 1024;
        assert_eq!(RetainedRxSlots::layout(config).unwrap(), (count, bytes));
        let layout = Layout::array::<RetainedRxSlot>(count).unwrap();
        assert!(layout.size() <= bytes);
        assert_eq!(layout.align(), align_of::<RetainedRxSlot>());
        assert!(size_of::<RetainedRxHandle>() <= 32);
        assert!(size_of::<RxCompletion>() <= 32);
        let budget = MemoryBudget::new(bytes - 1);
        assert_eq!(
            RetainedRxSlots::new(config, &budget).err().unwrap().kind(),
            io::ErrorKind::OutOfMemory
        );
        assert_eq!(budget.used(), 0);
        let budget = MemoryBudget::new(bytes);
        let slots = RetainedRxSlots::new(config, &budget).unwrap();
        assert_eq!(slots.slots.len(), count);
        assert_eq!(budget.used(), bytes);
        assert_eq!(slots.slots.as_ptr() as usize % layout.align(), 0);
        drop(slots);
        assert_eq!(budget.used(), 0);
    }
    // SAFETY: the name is a static NUL-terminated string.
    let ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(ifindex, 0);
    let bytes = size_of::<Port<()>>() - size_of::<FrameLedger<u32>>() + 2 * 1024 - 1;
    let budget = MemoryBudget::new(bytes);
    assert_eq!(
        Port::<()>::open_device(
            ifindex,
            0,
            BindMode::Copy,
            config(),
            1500,
            false,
            64,
            &budget
        )
        .err()
        .unwrap()
        .kind(),
        io::ErrorKind::OutOfMemory
    );
    assert_eq!(budget.used(), 0);
    assert!(
        PortConfig {
            rx_frames: usize::MAX,
            ..config()
        }
        .validate()
        .is_err()
    );
}

#[test]
fn native_metadata64_sg_capacity_rejects_48() {
    assert_eq!(rx_frame_capacity(64).unwrap(), 3776);
    assert_eq!(
        rx_frame_capacity(48).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        (65535usize + 22).div_ceil(rx_frame_capacity(64).unwrap()),
        MAX_SEGMENTS
    );
    let budget = MemoryBudget::new(1 << 20);
    let config = PortConfig {
        rx_frames: 32,
        control_frames: 18,
        bulk_frames: 18,
        ring_size: 64,
    };
    let mut port = fake::<()>(config, &budget);
    port.mtu = 65535;
    port.scatter_gather = true;
    port.metadata_len = 64;
    port.refill().unwrap();
    let mut lengths = [3776; MAX_SEGMENTS];
    lengths[MAX_SEGMENTS - 1] = 65535 + 22 - 3776 * (MAX_SEGMENTS - 1);
    queue_rx(&mut port, &lengths, 64);
    assert_eq!(
        port.receive_segments_owned(1, 48, |_, _, _, _| panic!("legacy metadata"))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(port.rings().rx_consumer, 0);
    let handle = retain_rx(&mut port, 64);
    port.with_retained_rx(handle, |parts, metadata| {
        assert_eq!(parts.len(), MAX_SEGMENTS);
        assert_eq!(parts.iter().map(|part| part.len()).sum::<usize>(), 65557);
        for (part, bytes) in parts.iter().enumerate() {
            assert_eq!(bytes.len(), lengths[part]);
            assert!(bytes.iter().all(|&byte| byte == (part + 1) as u8));
        }
        assert_eq!(metadata, &[0xa5; 64]);
    })
    .unwrap();
    let completion = port.release_retained_rx(handle).unwrap();
    port.complete_retained_rx(completion).unwrap();

    for malformed in ["metadata", "frame", "mtu", "segments", "duplicate", "sg"] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config, &budget);
        port.mtu = 65535;
        port.scatter_gather = true;
        port.metadata_len = 64;
        port.refill().unwrap();
        let lengths = if malformed == "segments" {
            &[60; 19][..]
        } else {
            &[60, 60][..]
        };
        queue_rx(&mut port, lengths, 64);
        let mut first = port.rings.rx.read(0);
        match malformed {
            "metadata" => first.addr = first.addr / FRAME_SIZE as u64 * FRAME_SIZE as u64 + 48,
            "frame" => first.len = 3777,
            "mtu" => {
                port.mtu = 68;
                first.len = 60;
            }
            "segments" => {}
            "duplicate" => {
                let mut second = port.rings.rx.read(1);
                second.addr = first.addr;
                port.rings.rx.write(1, second);
            }
            "sg" => port.scatter_gather = false,
            _ => unreachable!(),
        }
        port.rings.rx.write(0, first);
        assert_eq!(
            port.receive_segments_owned(1, 64, |_, _, _, _| panic!("{malformed} admitted"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.retained_rx_count(), 0);
        assert!(port.drain_state().closed);
    }
}

#[test]
fn packet_count_overflow_never_rolls_back_publication() {
    for writer in [false, true] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.counters.published_packets = u64::MAX;
        if writer {
            port.transmit_with(TxClass::Bulk, 60, (), |_, chunks| {
                chunks[0].fill(0);
                Ok(())
            })
            .unwrap();
        } else {
            port.transmit(TxClass::Bulk, &[0; 14], &[0; 28], ())
                .unwrap();
        }
        assert_eq!(port.rings().tx_producer, 1);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(port.counters().submitted, 1);
        assert_eq!(port.counters().published_packets, u64::MAX);
        assert!(port.counters().publication_count_unavailable);
        port.rings.tx.publish_consumer(1);
        port.rings.cq.write(0, port.rings.tx.read(0).addr);
        port.rings.cq.publish_producer(1);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
        assert!(port.counters().publication_count_unavailable);
        assert!(port.close().ready_for_backend_teardown());
    }
}

struct Retained {
    bytes: [u8; 28],
    drops: Arc<AtomicUsize>,
}

impl Retained {
    fn new(drops: &Arc<AtomicUsize>) -> Self {
        Self {
            bytes: [7; 28],
            drops: Arc::clone(drops),
        }
    }
}

impl AsRef<[u8]> for Retained {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Retained {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn validates_partitions_ring_commitments_and_umem_extent() {
    assert_eq!(config().umem_bytes().unwrap(), 4 * FRAME_SIZE);
    assert_eq!(BindMode::ZeroCopy.as_str(), "zerocopy");
    assert_eq!(BindMode::Copy.as_str(), "copy");
    for invalid in [
        PortConfig {
            rx_frames: 0,
            ..config()
        },
        PortConfig {
            control_frames: 0,
            ..config()
        },
        PortConfig {
            bulk_frames: 0,
            ..config()
        },
        PortConfig {
            ring_size: 0,
            ..config()
        },
        PortConfig {
            ring_size: 3,
            ..config()
        },
        PortConfig {
            ring_size: 1 << 31,
            ..config()
        },
        PortConfig {
            bulk_frames: 4,
            ..config()
        },
        PortConfig {
            rx_frames: usize::MAX,
            ..config()
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn missing_bidirectional_queue_is_refused_before_retaining_umem() {
    // SAFETY: the interface name is a static NUL-terminated string.
    let ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(ifindex, 0);
    let budget = MemoryBudget::new(1 << 20);
    assert!(Port::<()>::open(ifindex, u32::MAX, BindMode::Copy, config(), &budget).is_err());
    assert_eq!(budget.used(), 0);
}

#[test]
fn exact_metadata_lengths_preserve_whole_sg_callback_leases() {
    for metadata_len in [0, 32, 64, 128] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.metadata_len = metadata_len;
        port.mtu = 9000;
        port.scatter_gather = true;
        port.refill().unwrap();
        let first = port.rings.fill.read(0) + 256;
        let second = port.rings.fill.read(1) + 256;
        let expected = [9; 128];
        if metadata_len != 0 {
            port.umem.write_bytes(first, &expected[..metadata_len]);
        }
        port.umem
            .write_bytes(first + metadata_len as u64, &[1; 3000]);
        port.umem
            .write_bytes(second + metadata_len as u64, &[2; 3000]);
        for (index, address) in [first, second].into_iter().enumerate() {
            port.rings.rx.write(
                index as u32,
                Descriptor {
                    addr: address + metadata_len as u64,
                    len: 3000,
                    options: u32::from(index == 0),
                },
            );
        }
        port.rings.rx.publish_producer(2);
        assert_eq!(
            port.receive_segments(1, metadata_len, |_, _| {
                panic!("FILL still owns the complete chain")
            })
            .unwrap(),
            0
        );
        port.rings.fill.publish_consumer(2);
        let mut callbacks = 0;
        assert_eq!(
            port.receive_segments_with(1, metadata_len, |parts, metadata, _| {
                assert_eq!(parts, &[&[1; 3000][..], &[2; 3000][..]]);
                assert_eq!(metadata, &expected[..metadata_len]);
                callbacks += 1;
            })
            .unwrap(),
            1
        );
        assert_eq!(callbacks, 1);
        assert_eq!(port.rings().rx_consumer, 2);
        assert_eq!(port.drain_state().rx_leased, 0);
    }
}

#[test]
fn host_metadata_never_falls_back_to_shorter_headroom() {
    for prefix in [0, 32, 127] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.metadata_len = 128;
        port.refill().unwrap();
        let base = port.rings.fill.read(0);
        port.rings.rx.write(
            0,
            Descriptor {
                addr: base + prefix,
                len: 3,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(1);
        port.rings.fill.publish_consumer(1);
        assert!(
            port.receive_segments(1, 128, |_, _| {
                panic!("missing Host metadata was admitted")
            })
            .is_err()
        );
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert!(port.drain_state().closed);
    }
    for (admitted, requested) in [(0, 32), (32, 128), (128, 32), (128, 127)] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.metadata_len = admitted;
        assert_eq!(
            port.receive_segments(1, requested, |_, _| {
                panic!("wrong metadata contract reached callback")
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(port.rings().rx_consumer, 0);
    }
    for metadata_len in [1, 31, 127, 129, usize::MAX] {
        let budget = MemoryBudget::new(1 << 20);
        assert!(
            Port::<()>::open_device(
                0,
                0,
                BindMode::Copy,
                config(),
                1500,
                false,
                metadata_len,
                &budget,
            )
            .is_err()
        );
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn wire_only_receive_neither_requires_nor_exports_a_metadata_prefix() {
    for prefix in [0, METADATA_SIZE] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.refill().unwrap();
        let base = port.rings.fill.read(0);
        if prefix != 0 {
            port.umem.write_bytes(base, &[0xff; METADATA_SIZE]);
        }
        port.umem.write_bytes(base + prefix as u64, &[1, 2, 3]);
        port.rings.rx.write(
            0,
            Descriptor {
                addr: base + prefix as u64,
                len: 3,
                options: 0,
            },
        );
        port.rings.rx.publish_producer(1);
        assert_eq!(
            port.receive_segments(1, 0, |_, _| panic!("FILL still owns the frame"))
                .unwrap(),
            0
        );
        port.rings.fill.publish_consumer(1);
        assert_eq!(
            port.receive_segments(1, 0, |segments, metadata| {
                assert_eq!(segments.len(), 1);
                assert_eq!(segments[0], &[1, 2, 3]);
                assert!(metadata.is_empty());
            })
            .unwrap(),
            1
        );
        assert_eq!(port.counters().rx, 1);
        assert_eq!(port.drain_state().rx_leased, 0);
    }
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    port.refill().unwrap();
    let base = port.rings.fill.read(0);
    port.umem.write_bytes(base, &[1, 2, 3]);
    port.rings.rx.write(
        0,
        Descriptor {
            addr: base,
            len: 3,
            options: 0,
        },
    );
    port.rings.rx.publish_producer(1);
    port.rings.fill.publish_consumer(1);
    assert!(
        port.receive_segments(1, METADATA_SIZE, |_, _| panic!("missing required metadata"))
            .is_err()
    );
    assert_eq!(port.counters().rx, 0);
    assert_eq!(port.rings().rx_consumer, 0);
    assert!(port.drain_state().closed);
}

#[test]
fn observes_fill_once_and_recycles_actual_rx_offset() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    assert_eq!(port.refill().unwrap(), 2);
    assert_eq!(port.drain_state().fill_queued, 2);
    let base = port.rings.fill.read(0);
    let address = base + 128;
    port.umem.write_bytes(address, &[1, 2, 3]);
    port.rings.fill.publish_consumer(1);
    assert_eq!(port.observe_fill().unwrap(), 1);
    assert_eq!(port.observe_fill().unwrap(), 0);
    assert_eq!(port.drain_state().fill_posted, 2);
    assert_eq!(port.drain_state().fill_queued, 1);
    port.rings.rx.write(
        0,
        Descriptor {
            addr: address,
            len: 3,
            options: 0,
        },
    );
    port.rings.rx.publish_producer(1);
    let mut called = 0;
    assert_eq!(
        port.receive(64, |frame| {
            assert_eq!(frame, &[1, 2, 3]);
            called += 1;
        })
        .unwrap(),
        1
    );
    assert_eq!(called, 1);
    assert_eq!(port.rings().rx_consumer, 1);
    assert_eq!(port.rings().fill_producer, 3);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.drain_state().fill_posted, 2);
    assert_eq!(port.drain_state().fill_queued, 2);
    assert_eq!(port.receive(64, |_| panic!("duplicate RX")).unwrap(), 0);
    assert_eq!(port.counters().rx, 1);
    assert_eq!(port.counters().fill, 3);
}

#[test]
fn receive_defers_rx_until_fill_consumer_publication_and_counts_only_deliveries() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    assert!(!port.needs_service_retry());
    assert_eq!(port.refill().unwrap(), 2);
    assert!(
        !port.needs_service_retry(),
        "posted FILL alone must stay event-driven"
    );
    let first = port.rings.fill.read(0);
    let second = port.rings.fill.read(1);
    port.umem.write_bytes(first + 128, &[1, 2, 3]);
    port.umem.write_bytes(second + 128, &[4, 5, 6]);
    port.rings.rx.write(
        0,
        Descriptor {
            addr: first + 128,
            len: 3,
            options: 0,
        },
    );
    port.rings.rx.write(
        1,
        Descriptor {
            addr: second + 128,
            len: 3,
            options: 0,
        },
    );
    port.rings.rx.publish_producer(2);
    assert_eq!(
        port.receive(2, |_| panic!("FILL consumer not published"))
            .unwrap(),
        0
    );
    assert!(
        port.needs_service_retry(),
        "late FILL publication has no reliable event"
    );
    assert_ne!(port.rings().rx_producer, port.rings().rx_consumer);
    assert_eq!(port.rings().rx_consumer, 0);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.drain_state().fill_queued, 2);
    assert!(!port.drain_state().closed);
    assert_eq!(port.counters().invalid, 0);
    port.transmit(TxClass::Control, &[0; 14], &[7; 28], ())
        .unwrap();
    let tx_address = port.rings.tx.read(0).addr;
    assert!(tx_address >= (config().rx_frames * FRAME_SIZE) as u64);
    port.rings.tx.publish_consumer(1);
    port.rings.cq.write(0, tx_address);
    port.rings.cq.publish_producer(1);
    assert_eq!(port.complete(|_| {}).unwrap(), 1);
    assert!(port.tx_credit(TxClass::Control));
    port.rings.fill.publish_consumer(1);
    let mut delivered = 0;
    assert_eq!(
        port.receive(2, |frame| {
            assert_eq!(frame, &[1, 2, 3]);
            delivered += 1;
        })
        .unwrap(),
        1
    );
    assert_eq!(port.rings().rx_consumer, 1);
    assert_eq!(port.rings().fill_producer, 3);
    assert_eq!(port.rings.fill.read(2), first);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.counters().rx, 1);
    port.rings.fill.publish_consumer(2);
    assert_eq!(
        port.receive(2, |frame| {
            assert_eq!(frame, &[4, 5, 6]);
            delivered += 1;
        })
        .unwrap(),
        1
    );
    assert_eq!(delivered, 2);
    assert_eq!(port.rings().rx_consumer, 2);
    assert_eq!(port.rings().fill_producer, 4);
    assert_eq!(port.rings.fill.read(3), second);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.drain_state().fill_queued, 2);
    assert!(!port.needs_service_retry());
    assert!(!port.drain_state().closed);
    assert_eq!(port.counters().invalid, 0);
    assert_eq!(port.counters().rx, 2);
    assert_eq!(port.counters().fill, 4);
    assert_eq!(port.receive(2, |_| panic!("duplicate RX")).unwrap(), 0);
    assert_eq!(port.rings().fill_producer, 4);
}

#[test]
fn generated_standalone_fatal_kick_retains_actual_bytes_and_owner_credit() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.rings.tx.set_wakeup();
    let error = port
        .transmit_generated(TxClass::Bulk, 80, |frame| {
            frame.fill(0xa5);
            frame[..42].fill(4);
            Ok(Some((42, Retained::new(&drops))))
        })
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    let descriptor = port.rings.tx.read(0);
    assert_eq!(descriptor.len, 60);
    assert_eq!(descriptor.options, 0);
    let frame = port.umem.frame(descriptor.addr, 80).unwrap();
    assert_eq!(&frame[..42], &[4; 42]);
    assert_eq!(&frame[42..60], &[0; 18]);
    assert_eq!(&frame[60..], &[0xa5; 20]);
    assert!(port.drain_state().closed);
    assert_eq!(port.drain_state().bulk_reserved, 0);
    assert_eq!(port.drain_state().bulk_outstanding, 1);
    assert_eq!(port.counters().submitted, 1);
    assert_eq!(port.counters().tx_kicks, 1);
    assert_eq!(port.tx_free, [1, 0]);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    port.rings.tx.publish_consumer(1);
    assert_eq!(
        port.complete(|owners| assert!(owners.is_empty())).unwrap(),
        0
    );
    for errno in [libc::EAGAIN, libc::EBUSY, libc::ENOBUFS, libc::EINTR] {
        port.wakeup_result(Err(io::Error::from_raw_os_error(errno)))
            .unwrap();
    }
    port.close_socket();
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(port.umem.frame(descriptor.addr, 42).unwrap(), &[4; 42]);
    assert_eq!(port.umem.frame(descriptor.addr + 42, 18).unwrap(), &[0; 18]);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    let charge = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
    drop(port);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(budget.used(), charge);
}

#[test]
fn generated_published_prefix_survives_every_unpublished_suffix_failure() {
    for suffix in [
        "none",
        "error",
        "short",
        "long",
        "panic_before",
        "panic_after",
        "close",
    ] {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.rings.tx.set_wakeup();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            port.transmit_batch(|port| {
                assert!(port.transmit_generated(TxClass::Bulk, 60, |frame| {
                    frame.fill(9);
                    let mut owner = Retained::new(&drops);
                    owner.bytes.fill(9);
                    Ok(Some((60, owner)))
                })?);
                if suffix == "close" {
                    port.close();
                    return port.transmit_generated(TxClass::Control, 80, |_| {
                        panic!("closed generator ran")
                    });
                }
                port.transmit_generated(TxClass::Control, 80, |frame| {
                    frame.fill(5);
                    if suffix == "panic_before" {
                        panic!("before suffix owner");
                    }
                    let owner = Retained::new(&drops);
                    match suffix {
                        "none" => Ok(None),
                        "error" => Err(io::Error::other("suffix generation failed")),
                        "short" => Ok(Some((13, owner))),
                        "long" => Ok(Some((81, owner))),
                        "panic_after" => panic!("after suffix owner"),
                        _ => unreachable!(),
                    }
                })
            })
        }));
        if suffix.starts_with("panic") {
            assert!(result.is_err());
            assert_eq!(port.counters().tx_kicks, 0);
        } else {
            let (work, kick) = result.unwrap();
            if suffix == "none" {
                assert!(!work.unwrap());
            } else {
                assert_eq!(
                    work.unwrap_err().kind(),
                    match suffix {
                        "close" => io::ErrorKind::WouldBlock,
                        "error" => io::ErrorKind::Other,
                        _ => io::ErrorKind::InvalidInput,
                    }
                );
            }
            assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
            assert_eq!(port.counters().tx_kicks, 1);
        }
        let disposed = usize::from(!matches!(suffix, "panic_before" | "close"));
        assert_eq!(drops.load(Ordering::Relaxed), disposed);
        assert!(port.drain_state().closed);
        assert!(!port.tx_batch_active);
        assert_eq!(port.drain_state().control_reserved, 0);
        assert_eq!(port.drain_state().bulk_reserved, 0);
        assert_eq!(port.drain_state().bulk_outstanding, 1);
        assert_eq!(port.tx_free, [1, 0]);
        assert_eq!(port.rings().tx_producer, 1);
        assert_eq!(port.counters().submitted, 1);
        assert_eq!(port.sidecar.occupied().count(), 1);
        let prefix = port.rings.tx.read(0);
        assert_eq!(port.umem.frame(prefix.addr, 60).unwrap(), &[9; 60]);
        port.rings.tx.publish_consumer(1);
        assert_eq!(
            port.complete(|owners| assert!(owners.is_empty())).unwrap(),
            0
        );
        port.close_socket();
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), disposed);
        assert_eq!(port.umem.frame(prefix.addr, 60).unwrap(), &[9; 60]);
        port.rings.cq.write(0, prefix.addr);
        port.rings.cq.publish_producer(1);
        assert_eq!(
            port.complete(|owners| {
                assert_eq!(owners.len(), 1);
                assert_eq!(owners[0].as_ref().unwrap().bytes, [9; 28]);
            })
            .unwrap(),
            1
        );
        assert_eq!(drops.load(Ordering::Relaxed), disposed + 1);
        assert_eq!(port.tx_free, [1, 1]);
        assert!(port.drain_state().ready_for_backend_teardown());
    }
}

#[test]
fn generated_mixed_cq_valid_prefix_keeps_partial_sg_and_invalid_suffix_retained() {
    for invalid in ["duplicate", "foreign", "shifted"] {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(
            PortConfig {
                bulk_frames: 5,
                ring_size: 8,
                ..config()
            },
            &budget,
        );
        port.mtu = 9000;
        port.scatter_gather = true;
        assert!(
            port.transmit_generated(TxClass::Bulk, 80, |frame| {
                frame.fill(1);
                let mut owner = Retained::new(&drops);
                owner.bytes.fill(1);
                Ok(Some((80, owner)))
            })
            .unwrap()
        );
        let mut cpu = Retained::new(&drops);
        cpu.bytes.fill(2);
        port.transmit_retained(TxClass::Control, &[2; 14], cpu)
            .unwrap();
        let mut sg = Retained::new(&drops);
        sg.bytes.fill(3);
        port.transmit_with(TxClass::Bulk, 6000, sg, |owner, chunks| {
            for chunk in chunks {
                chunk.fill(owner.bytes[0]);
            }
            Ok(())
        })
        .unwrap();
        assert!(
            port.transmit_generated(TxClass::Bulk, 60, |frame| {
                frame.fill(4);
                let mut owner = Retained::new(&drops);
                owner.bytes.fill(4);
                Ok(Some((60, owner)))
            })
            .unwrap()
        );
        let pending = port.rings.tx.read(4);
        let direct = port.rings.tx.read(0);
        let first = port.rings.tx.read(2);
        let last = port.rings.tx.read(3);
        assert_eq!((first.options, last.options), (1, 0));
        assert_eq!(first.len + last.len, 6000);
        port.rings.tx.publish_consumer(5);
        port.kick().unwrap();
        assert_eq!(
            port.complete(|owners| assert!(owners.is_empty())).unwrap(),
            0
        );
        assert_eq!(port.outstanding().count(), 5);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert_eq!(port.umem.frame(direct.addr, 80).unwrap(), &[1; 80]);
        assert_eq!(port.umem.frame(pending.addr, 60).unwrap(), &[4; 60]);
        assert_eq!(
            port.umem.frame(first.addr, FRAME_SIZE).unwrap(),
            &[3; FRAME_SIZE]
        );
        for (index, descriptor) in [3, 1, 0].into_iter().enumerate() {
            port.rings
                .cq
                .write(index as u32, port.rings.tx.read(descriptor).addr);
        }
        port.rings.cq.write(
            3,
            match invalid {
                "duplicate" => direct.addr,
                "foreign" => 0,
                "shifted" => pending.addr + 1,
                _ => unreachable!(),
            },
        );
        port.rings.cq.write(4, first.addr);
        port.rings.cq.write(5, pending.addr);
        port.rings.cq.publish_producer(6);
        let mut released = Vec::new();
        assert!(
            port.complete(|owners| {
                for owner in owners.iter().flatten() {
                    released.push(owner.bytes[0]);
                }
            })
            .is_err()
        );
        assert_eq!(released, [1, 2]);
        assert_eq!(port.rings().cq_consumer, 3);
        assert_eq!(port.counters().completed, 3);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(port.tx_free, [1, 3]);
        assert_eq!(port.outstanding().count(), 2);
        assert!(port.outstanding().any(|tx| tx.address == first.addr));
        assert!(port.outstanding().any(|tx| tx.address == pending.addr));
        assert_eq!(port.sidecar.occupied().count(), 2);
        let pending_owner = port.sidecar.occupied().last().unwrap();
        assert_eq!(pending_owner.0.bytes, [4; 28]);
        assert_eq!(pending_owner.1, 1);
        let retained = port.sidecar.occupied().next().unwrap();
        assert_eq!(retained.0.bytes, [3; 28]);
        assert_eq!(retained.1, 1);
        assert_eq!(
            port.umem.frame(first.addr, FRAME_SIZE).unwrap(),
            &[3; FRAME_SIZE]
        );
        assert_eq!(port.umem.frame(pending.addr, 60).unwrap(), &[4; 60]);
        assert!(port.complete(|owners| assert!(owners.is_empty())).is_err());
        assert!(
            port.transmit_generated(TxClass::Bulk, 60, |_| panic!("fatal port reused TX"))
                .is_err()
        );
        assert_eq!(port.close().bulk_outstanding, 2);
        port.close_socket();
        assert_eq!(
            port.umem.frame(first.addr, FRAME_SIZE).unwrap(),
            &[3; FRAME_SIZE]
        );
        assert_eq!(port.umem.frame(pending.addr, 60).unwrap(), &[4; 60]);
        let charge = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
        drop(port);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
        assert_eq!(budget.used(), charge);
    }
}

#[test]
fn generated_submit_invariant_failure_transfers_to_fatal_retention() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    let mut prepared = port.reserve_single_tx(TxClass::Bulk).unwrap();
    let address = prepared.lease.address();
    port.umem.write_bytes(address, &[9; 60]);
    prepared.length = FRAME_SIZE as u32 + 1;
    let reservation = TxReservation {
        port: &mut port,
        prepared: Some(prepared),
    };
    assert!(reservation.publish(Retained::new(&drops)).is_err());
    assert!(port.drain_state().closed);
    assert_eq!(port.drain_state().bulk_reserved, 1);
    assert_eq!(port.outstanding().count(), 0);
    assert_eq!(port.rings().tx_producer, 0);
    assert_eq!(port.counters().submitted, 0);
    assert_eq!(port.sidecar.occupied().count(), 1);
    assert_eq!(port.umem.frame(address, 60).unwrap(), &[9; 60]);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(
        port.transmit_generated(TxClass::Bulk, 60, |_| panic!("failed submit reused TX"))
            .is_err()
    );
    let charge = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
    drop(port);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(budget.used(), charge);
}

#[test]
fn generated_publication_survives_future_cancellation_and_close_without_cq() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    let mut future = Box::pin(async {
        let (work, kick) = port.transmit_batch(|port| {
            port.transmit_generated(TxClass::Bulk, 60, |frame| {
                frame.fill(6);
                Ok(Some((60, Retained::new(&drops))))
            })
        });
        assert!(work.unwrap());
        kick.unwrap();
        std::future::pending::<()>().await;
    });
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    drop(future);
    let descriptor = port.rings.tx.read(0);
    assert_eq!(port.umem.frame(descriptor.addr, 60).unwrap(), &[6; 60]);
    port.rings.tx.publish_consumer(1);
    port.kick().unwrap();
    assert_eq!(
        port.complete(|owners| assert!(owners.is_empty())).unwrap(),
        0
    );
    assert_eq!(port.close().bulk_outstanding, 1);
    assert_eq!(port.tx_free, [1, 0]);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    port.close_socket();
    assert_eq!(port.umem.frame(descriptor.addr, 60).unwrap(), &[6; 60]);
    let charge = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
    drop(port);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(budget.used(), charge);
}

#[test]
fn generated_reserve_shortages_preserve_the_original_unsent_packet() {
    for shortage in ["class", "ledger", "descriptor", "sidecar", "ring"] {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(
            PortConfig {
                ring_size: if shortage == "ring" { 2 } else { 4 },
                bulk_frames: if shortage == "descriptor" { 2 } else { 1 },
                ..config()
            },
            &budget,
        );
        if shortage == "descriptor" {
            let mut frames = port.config.frame_config();
            frames.bulk_descriptors = 1;
            // SAFETY: no RX custody exists in this credit-shortage fixture.
            unsafe { ManuallyDrop::drop(&mut port.ledger) };
            port.ledger = ManuallyDrop::new(FrameLedger::new(frames, &budget).unwrap());
        }
        let mut held = None;
        match shortage {
            "class" => port
                .transmit_generated(TxClass::Bulk, 60, |frame| {
                    frame.fill(1);
                    Ok(Some((60, Retained::new(&drops))))
                })
                .map(|sent| assert!(sent))
                .unwrap(),
            "ledger" | "descriptor" => {
                held = Some(port.ledger.reserve_tx(TxClass::Bulk).unwrap());
            }
            "sidecar" => {
                for _ in 0..port.sidecar.slots.len() {
                    port.sidecar.occupy(Retained::new(&drops), 1);
                }
            }
            "ring" => {
                for class in [TxClass::Control, TxClass::Bulk] {
                    port.transmit_generated(class, 60, |frame| {
                        frame.fill(1);
                        Ok(Some((60, Retained::new(&drops))))
                    })
                    .unwrap();
                }
                for index in 0..2 {
                    port.rings.cq.write(index, port.rings.tx.read(index).addr);
                }
                port.rings.cq.publish_producer(2);
                assert_eq!(
                    port.complete(|owners| assert_eq!(owners.len(), 2)).unwrap(),
                    2
                );
                assert_eq!(port.outstanding().count(), 0);
                assert_eq!(port.tx_free, [1, 1]);
            }
            _ => unreachable!(),
        }
        let before = port.counters();
        let mut unsent = Some([0x5a; 60]);
        let error = port
            .transmit_generated(TxClass::Bulk, 60, |frame| {
                frame.copy_from_slice(&unsent.take().expect("original packet"));
                Ok(Some((60, Retained::new(&drops))))
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{shortage}");
        assert_eq!(unsent, Some([0x5a; 60]));
        assert_eq!(port.counters(), before);
        assert!(!port.drain_state().closed);
        match shortage {
            "class" | "ledger" | "descriptor" => {
                assert!(
                    port.transmit_generated(TxClass::Control, 60, |frame| {
                        frame.fill(2);
                        Ok(Some((60, Retained::new(&drops))))
                    })
                    .unwrap()
                );
                if let Some(lease) = held {
                    port.ledger.cancel_tx(lease).unwrap();
                } else {
                    port.rings.cq.write(0, port.rings.tx.read(0).addr);
                    port.rings.cq.publish_producer(1);
                    assert_eq!(
                        port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
                        1
                    );
                    assert_eq!(
                        port.umem.frame(port.rings.tx.read(1).addr, 60).unwrap(),
                        &[2; 60]
                    );
                }
            }
            "sidecar" => port.sidecar.release(0),
            "ring" => port.rings.tx.publish_consumer(1),
            _ => unreachable!(),
        }
        let index = port.tx_producer;
        assert!(
            port.transmit_generated(TxClass::Bulk, 60, |frame| {
                frame.copy_from_slice(&unsent.take().expect("still unsent"));
                Ok(Some((60, Retained::new(&drops))))
            })
            .unwrap()
        );
        assert!(unsent.is_none());
        let descriptor = port.rings.tx.read(index);
        assert_eq!(descriptor.len, 60);
        assert_eq!(descriptor.options, 0);
        assert_eq!(port.umem.frame(descriptor.addr, 60).unwrap(), &[0x5a; 60]);
        assert_eq!(
            port.counters().submitted,
            before.submitted + 1 + u64::from(matches!(shortage, "class" | "ledger" | "descriptor"))
        );
        assert_eq!(port.drain_state().bulk_reserved, 0);
        if shortage == "sidecar" {
            port.sidecar.release(1);
        }
        port.rings.tx.publish_consumer(port.tx_producer);
        let cq = port.cq_consumer;
        let addresses: Vec<_> = port.outstanding().map(|tx| tx.address).collect();
        for (index, address) in addresses.iter().enumerate() {
            port.rings.cq.write(cq + index as u32, *address);
        }
        port.rings.cq.publish_producer(cq + addresses.len() as u32);
        assert_eq!(port.complete(|_| {}).unwrap(), addresses.len());
        assert_eq!(port.outstanding().count(), 0);
        assert_eq!(port.tx_free, [1, port.config.bulk_frames]);
        assert!(port.sidecar.occupied().next().is_none());
    }
}

#[test]
fn generated_closed_corrupt_and_unmapped_reserves_never_call_the_emitter() {
    for failure in ["closed", "ring", "ledger", "extent"] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        match failure {
            "closed" => {
                port.close();
            }
            "ring" => port.rings.tx.publish_consumer(1),
            "ledger" => {
                port.ledger.close();
            }
            "extent" => {
                let mut frames = config().frame_config();
                frames.base_address = port.umem_bytes() as u64;
                // SAFETY: no RX custody exists in this invalid-extent fixture.
                unsafe { ManuallyDrop::drop(&mut port.ledger) };
                port.ledger = ManuallyDrop::new(FrameLedger::new(frames, &budget).unwrap());
            }
            _ => unreachable!(),
        }
        assert!(
            port.transmit_generated(TxClass::Bulk, 60, |_| panic!("{failure} emitter ran"))
                .is_err()
        );
        assert!(port.drain_state().closed);
        assert_eq!(port.drain_state().bulk_reserved, 0);
        assert_eq!(port.rings().tx_producer, 0);
        assert_eq!(port.outstanding().count(), 0);
        assert_eq!(port.tx_free, [1, 1]);
        assert!(port.sidecar.occupied().next().is_none());
        assert_eq!(port.counters().invalid, u64::from(failure != "closed"));
    }
}

#[test]
fn generated_unpublished_none_errors_lengths_and_panics_restore_credit() {
    for outcome in [
        "none",
        "error",
        "zero",
        "short",
        "long",
        "overflow",
        "panic_before",
        "panic_after",
    ] {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        let funded = budget.used();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            port.transmit_generated(TxClass::Bulk, 80, |frame| {
                assert_eq!(frame.len(), 80);
                frame.fill(0xa5);
                if outcome == "panic_before" {
                    panic!("before owner");
                }
                let owner = Retained::new(&drops);
                match outcome {
                    "none" => Ok(None),
                    "error" => Err(io::Error::other("generator failed")),
                    "zero" => Ok(Some((0, owner))),
                    "short" => Ok(Some((13, owner))),
                    "long" => Ok(Some((81, owner))),
                    "overflow" => Ok(Some((usize::MAX, owner))),
                    "panic_after" => panic!("after owner"),
                    _ => unreachable!(),
                }
            })
        }));
        if outcome.starts_with("panic") {
            assert!(result.is_err());
        } else if outcome == "none" {
            assert!(!result.unwrap().unwrap());
        } else {
            let error = result.unwrap().unwrap_err();
            assert_eq!(
                error.kind(),
                if outcome == "error" {
                    io::ErrorKind::Other
                } else {
                    io::ErrorKind::InvalidInput
                }
            );
        }
        let disposed = usize::from(outcome != "panic_before");
        assert_eq!(drops.load(Ordering::Relaxed), disposed);
        assert_eq!(budget.used(), funded);
        assert_eq!(port.rings().tx_producer, 0);
        assert_eq!(port.outstanding().count(), 0);
        assert_eq!(port.drain_state().bulk_reserved, 0);
        assert_eq!(port.tx_free, [1, 1]);
        assert!(port.sidecar.occupied().next().is_none());
        assert!(!port.drain_state().closed);
        assert!(!port.needs_service_retry());
        assert!(
            port.transmit_generated(TxClass::Bulk, 80, |frame| {
                frame[..42].fill(7);
                Ok(Some((42, Retained::new(&drops))))
            })
            .unwrap()
        );
        let descriptor = port.rings.tx.read(0);
        assert_eq!(descriptor.len, 60);
        let frame = port.umem.frame(descriptor.addr, 80).unwrap();
        assert_eq!(&frame[..42], &[7; 42]);
        assert_eq!(&frame[42..60], &[0; 18]);
        assert_eq!(&frame[60..], &[0xa5; 20]);
        port.rings.tx.publish_consumer(1);
        port.rings.cq.write(0, descriptor.addr);
        port.rings.cq.publish_producer(1);
        assert_eq!(
            port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
            1
        );
        assert_eq!(drops.load(Ordering::Relaxed), disposed + 1);
        assert_eq!(port.tx_free, [1, 1]);
    }
}

#[test]
fn generated_all_none_turns_leave_both_classes_reusable_without_publication() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    for _ in 0..8 {
        for class in [TxClass::Control, TxClass::Bulk] {
            assert!(
                !port
                    .transmit_generated(class, 42, |frame| {
                        assert_eq!(frame.len(), 42);
                        frame.fill(9);
                        Ok(None)
                    })
                    .unwrap()
            );
        }
    }
    assert_eq!(port.tx_free, [1, 1]);
    assert_eq!(port.drain_state().control_reserved, 0);
    assert_eq!(port.drain_state().bulk_reserved, 0);
    assert_eq!(port.rings().tx_producer, 0);
    assert_eq!(port.counters().submitted, 0);
    assert!(port.sidecar.occupied().next().is_none());
    for class in [TxClass::Control, TxClass::Bulk] {
        assert!(
            port.transmit_generated(class, 14, |frame| {
                frame.fill(3);
                Ok(Some((14, ())))
            })
            .unwrap()
        );
    }
    assert_eq!(port.outstanding().count(), 2);
    for index in 0..2 {
        let descriptor = port.rings.tx.read(index);
        assert_eq!(descriptor.len, 60);
        let frame = port.umem.frame(descriptor.addr, 60).unwrap();
        assert_eq!(&frame[..14], &[3; 14]);
        assert_eq!(&frame[14..], &[0; 46]);
        port.rings.cq.write(index, descriptor.addr);
    }
    port.rings.tx.publish_consumer(2);
    port.rings.cq.publish_producer(2);
    assert_eq!(
        port.complete(|owners| assert_eq!(owners.len(), 2)).unwrap(),
        2
    );
    assert_eq!(port.tx_free, [1, 1]);
}

#[test]
fn generated_extent_uses_actual_padding_and_the_unshifted_single_frame_base() {
    for actual in [14, 42, 59, 60, 61, FRAME_SIZE] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.mtu = 9000;
        assert!(
            port.transmit_generated(TxClass::Bulk, FRAME_SIZE, |frame| {
                assert_eq!(frame.len(), FRAME_SIZE);
                frame.fill(0xa5);
                frame[..actual].fill(7);
                Ok(Some((actual, ())))
            })
            .unwrap()
        );
        let descriptor = port.rings.tx.read(0);
        assert_eq!(
            descriptor.addr,
            ((config().rx_frames + config().control_frames) * FRAME_SIZE) as u64
        );
        assert_eq!(descriptor.options, 0);
        assert_eq!(descriptor.len as usize, actual.max(60));
        assert_eq!(port.rings().tx_producer, 1);
        assert_eq!(port.counters().submitted, 1);
        let frame = port.umem.frame(descriptor.addr, FRAME_SIZE).unwrap();
        assert!(frame[..actual].iter().all(|&byte| byte == 7));
        assert!(frame[actual..actual.max(60)].iter().all(|&byte| byte == 0));
        assert!(frame[actual.max(60)..].iter().all(|&byte| byte == 0xa5));
        port.rings.tx.publish_consumer(1);
        port.rings.cq.write(0, descriptor.addr);
        port.rings.cq.publish_producer(1);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
    }
    for (mtu, sg, maximum) in [
        (1500, false, 0),
        (1500, false, 13),
        (1500, false, 1523),
        (9000, false, FRAME_SIZE + 1),
        (9000, true, FRAME_SIZE + 1),
        (9000, true, usize::MAX),
    ] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.mtu = mtu;
        port.scatter_gather = sg;
        assert_eq!(
            port.transmit_generated(TxClass::Bulk, maximum, |_| {
                panic!("invalid maximum invoked generator")
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(port.drain_state().bulk_reserved, 0);
        assert_eq!(port.tx_free, [1, 1]);
        assert_eq!(port.rings().tx_producer, 0);
        assert!(!port.drain_state().closed);
    }
}

#[test]
fn retains_class_credit_and_padded_packet_until_real_fake_cq() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    let header = [3; 14];
    port.transmit_retained(TxClass::Bulk, &header, Retained::new(&drops))
        .unwrap();
    assert!(!port.tx_credit(TxClass::Bulk));
    assert!(port.tx_credit(TxClass::Control));
    let bulk = port.rings.tx.read(0);
    assert_eq!(bulk.options, 0);
    assert_eq!(bulk.len, 60);
    let frame = port.umem.frame(bulk.addr, bulk.len as usize).unwrap();
    assert_eq!(&frame[..14], &header);
    assert_eq!(&frame[14..42], &[7; 28]);
    assert_eq!(&frame[42..], &[0; 18]);
    port.transmit(TxClass::Control, &header, &[8; 28], Retained::new(&drops))
        .unwrap();
    let control = port.rings.tx.read(1);
    assert_eq!(port.outstanding().count(), 2);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    port.rings.tx.publish_consumer(2);
    assert_eq!(port.complete(|_| {}).unwrap(), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    port.rings.cq.write(0, bulk.addr);
    port.rings.cq.write(1, control.addr);
    port.rings.cq.publish_producer(2);
    assert_eq!(port.complete(|_| {}).unwrap(), 2);
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    assert_eq!(port.outstanding().count(), 0);
    assert!(port.tx_credit(TxClass::Control));
    assert!(port.tx_credit(TxClass::Bulk));
    let state = port.close();
    assert!(state.ready_for_backend_teardown());
    assert!(!port.tx_credit(TxClass::Control));
    assert_eq!(port.counters().submitted, 2);
    assert_eq!(port.counters().completed, 2);
    assert_eq!(port.counters().published_packets, 2);
    assert!(!port.counters().publication_count_unavailable);
}

#[test]
fn wrapped_cq_lends_each_complete_owner_in_sidecar_order() {
    for order in [[0u32, 1, 2], [2, 0, 1]] {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(
            PortConfig {
                bulk_frames: 3,
                ring_size: 8,
                ..config()
            },
            &budget,
        );
        let start = u32::MAX - 1;
        port.cq_consumer = start;
        port.rings.cq.publish_consumer(start);
        port.rings.cq.publish_producer(start);
        for tag in 0..3 {
            let mut retained = Retained::new(&drops);
            retained.bytes[0] = tag;
            port.transmit_retained(TxClass::Bulk, &[0; 14], retained)
                .unwrap();
        }
        port.rings.tx.publish_consumer(3);
        for (i, sent) in order.into_iter().enumerate() {
            port.rings
                .cq
                .write(start.wrapping_add(i as u32), port.rings.tx.read(sent).addr);
        }
        port.rings.cq.publish_producer(start.wrapping_add(3));
        assert_eq!(
            port.complete(|owners| {
                let tags: Vec<_> = owners
                    .iter()
                    .map(|owner| owner.as_ref().unwrap().bytes[0])
                    .collect();
                assert_eq!(tags, [0, 1, 2]);
            })
            .unwrap(),
            3
        );
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        assert!(port.outstanding().next().is_none());
    }
}

#[test]
fn completes_at_most_sixty_four_cq_entries_per_turn() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let config = PortConfig {
        rx_frames: 1,
        control_frames: 1,
        bulk_frames: 65,
        ring_size: 128,
    };
    let mut port = fake(config, &budget);
    for index in 0..65 {
        port.transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
            .unwrap();
        port.rings.cq.write(index, port.rings.tx.read(index).addr);
    }
    port.rings.tx.publish_consumer(65);
    port.rings.cq.publish_producer(65);
    assert_eq!(
        port.complete(|owners| assert_eq!(owners.len(), 64))
            .unwrap(),
        64
    );
    assert_eq!(drops.load(Ordering::Relaxed), 64);
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(port.rings().cq_consumer, 64);
    assert_eq!(
        port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
        1
    );
    assert_eq!(drops.load(Ordering::Relaxed), 65);
}

#[test]
fn publication_and_drop_keep_sidecar_across_fatal_kick_error() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.rings.tx.set_wakeup();
    let error = port
        .transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    assert_eq!(port.rings().tx_producer, 1);
    assert_eq!(port.counters().submitted, 1);
    assert_eq!(port.counters().completed, 0);
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(port.kick().is_err());
    assert_eq!(port.counters().tx_kicks, 2);
    assert_eq!(port.counters().wakeup_errors, 2);
    assert_eq!(port.counters().published_packets, 1);
    port.close_socket();
    assert_eq!(port.as_raw_fd(), -1);
    assert_eq!(port.outstanding().count(), 1);
    let retained_bytes = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
    drop(port);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(budget.used(), retained_bytes);
}

#[test]
fn retryable_wakeup_errors_never_complete_or_dispose_tx() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
        .unwrap();
    for errno in [libc::EAGAIN, libc::EBUSY, libc::ENOBUFS, libc::EINTR] {
        port.wakeup_result(Err(io::Error::from_raw_os_error(errno)))
            .unwrap();
    }
    assert_eq!(port.counters().wakeup_errors, 4);
    assert_eq!(port.counters().completed, 0);
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    let ((), kick) = port.transmit_batch(|_| ());
    kick.unwrap();
    port.rings.tx.set_wakeup();
    let ((), kick) = port.transmit_batch(|_| ());
    assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
    assert_eq!(port.counters().submitted, 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    let address = port.rings.tx.read(0).addr;
    port.rings.cq.write(0, address);
    port.rings.cq.publish_producer(1);
    assert_eq!(port.complete(|_| {}).unwrap(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn outstanding_tx_kick_follows_cq_debt_and_skips_rx_wakeup() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    for class in [TxClass::Bulk, TxClass::Control] {
        port.transmit_retained(class, &[0; 14], Retained::new(&drops))
            .unwrap();
    }
    port.close();
    port.rings.tx.publish_consumer(2);
    port.rings.cq.write(0, port.rings.tx.read(0).addr);
    port.rings.cq.publish_producer(1);
    assert_eq!(
        port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
        1
    );

    port.rings.fill.set_wakeup();
    port.kick_outstanding_tx().unwrap();
    port.rings.tx.set_wakeup();
    assert_eq!(
        port.kick_outstanding_tx().unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(port.counters().rx_kicks, 0);
    assert_eq!(port.counters().tx_kicks, 1);
    assert_eq!(port.counters().wakeup_errors, 1);
    assert_eq!(port.counters().completed, 1);
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 1);

    port.rings.cq.write(1, port.rings.tx.read(1).addr);
    port.rings.cq.publish_producer(2);
    assert_eq!(
        port.complete(|owners| assert_eq!(owners.len(), 1)).unwrap(),
        1
    );
    let drained = port.counters();
    port.kick_outstanding_tx().unwrap();
    assert_eq!(port.counters(), drained);
    assert_eq!(drops.load(Ordering::Relaxed), 2);
}

#[test]
fn unknown_and_duplicate_cq_entries_are_fatal_not_disposals() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
        .unwrap();
    let address = port.rings.tx.read(0).addr;
    port.rings.cq.write(0, 0);
    port.rings.cq.publish_producer(1);
    assert!(port.complete(|_| {}).is_err());
    assert_eq!(port.counters().invalid, 1);
    assert_eq!(port.rings().cq_consumer, 0);
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    port.rings.cq.write(0, address);
    assert_eq!(port.complete(|_| {}).unwrap(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    port.rings.cq.write(1, address);
    port.rings.cq.publish_producer(2);
    assert!(port.complete(|_| {}).is_err());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(port.counters().completed, 1);
    assert_eq!(port.rings().cq_consumer, 1);
}

#[test]
fn fatal_cq_after_progress_retains_only_unreturned_outputs_and_charge() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(
        PortConfig {
            rx_frames: 1,
            control_frames: 1,
            bulk_frames: 4,
            ring_size: 8,
        },
        &budget,
    );
    port.mtu = 9000;
    port.scatter_gather = true;
    for (class, length, id) in [
        (TxClass::Bulk, 6000, 1),
        (TxClass::Control, 60, 2),
        (TxClass::Bulk, 6000, 3),
    ] {
        let mut owner = Retained::new(&drops);
        owner.bytes.fill(id);
        port.transmit_with(class, length, owner, |owner, chunks| {
            for chunk in chunks {
                chunk.fill(owner.bytes[0]);
            }
            Ok(())
        })
        .unwrap();
    }
    port.rings.tx.publish_consumer(5);
    for (index, descriptor) in [0, 2, 3, 1].into_iter().enumerate() {
        port.rings
            .cq
            .write(index as u32, port.rings.tx.read(descriptor).addr);
    }
    port.rings.cq.write(4, port.rings.tx.read(4).addr + 1);
    port.rings.cq.write(5, port.rings.tx.read(4).addr);
    port.rings.cq.publish_producer(6);
    let mut released = Vec::new();
    assert!(
        port.complete(|owners| {
            for owner in owners.iter().flatten() {
                released.push(owner.bytes[0]);
            }
        })
        .is_err()
    );
    released.sort_unstable();
    assert_eq!(released, [1, 2]);
    assert_eq!(port.rings().cq_consumer, 4);
    assert_eq!(
        (port.counters().submitted, port.counters().completed),
        (5, 4)
    );
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    assert_eq!(port.outstanding().count(), 1);
    assert!(port.complete(|owners| assert!(owners.is_empty())).is_err());
    assert_eq!(port.sidecar.occupied().count(), 1);
    assert_eq!(port.sidecar.occupied().next().unwrap().1, 1);
    let retained = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
    port.close_socket();
    drop(port);
    assert_eq!(drops.load(Ordering::Relaxed), 2);
    assert_eq!(budget.used(), retained);
}

#[test]
fn completion_callback_unwind_disposes_only_proven_owners() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    for class in [TxClass::Control, TxClass::Bulk] {
        port.transmit_retained(class, &[0; 14], Retained::new(&drops))
            .unwrap();
    }
    port.rings.tx.publish_consumer(2);
    port.rings.cq.write(0, port.rings.tx.read(0).addr);
    port.rings.cq.publish_producer(1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        port.complete(|owners| {
            assert_eq!(owners.len(), 1);
            panic!("retirement callback failed");
        })
    }));
    assert!(result.is_err());
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(port.counters().completed, 1);
    assert_eq!(port.rings().cq_consumer, 1);
    assert_eq!(port.outstanding().count(), 1);
    let retained = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
    port.close_socket();
    drop(port);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(budget.used(), retained);
}

#[test]
fn refuses_invalid_rx_geometry_without_publishing_consumer() {
    for descriptor in [
        Descriptor {
            addr: 0,
            len: 1,
            options: 1,
        },
        Descriptor {
            addr: 0,
            len: 0,
            options: 0,
        },
        Descriptor {
            addr: (4 * FRAME_SIZE) as u64,
            len: 1,
            options: 0,
        },
        Descriptor {
            addr: (FRAME_SIZE - 1) as u64,
            len: 2,
            options: 0,
        },
        Descriptor {
            addr: (2 * FRAME_SIZE) as u64,
            len: 1,
            options: 0,
        },
    ] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(config(), &budget);
        port.refill().unwrap();
        port.rings.rx.write(0, descriptor);
        port.rings.rx.publish_producer(1);
        assert!(
            port.receive(64, |_| panic!("invalid RX was borrowed"))
                .is_err()
        );
        assert_eq!(port.counters().invalid, 1);
        assert_eq!(port.counters().rx, 0);
        assert_eq!(port.rings().rx_consumer, 0);
        assert!(!port.tx_credit(TxClass::Control));
    }
}

#[test]
fn rejects_oversize_tx_before_reserving_or_copying() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    assert!(
        port.transmit(TxClass::Bulk, &[0; 14], &[0; 1501], ())
            .is_err()
    );
    assert_eq!(port.outstanding().count(), 0);
    assert_eq!(port.counters().submitted, 0);
    assert!(port.tx_credit(TxClass::Bulk));
    port.transmit(TxClass::Bulk, &[0; 14], &[0; 1500], ())
        .unwrap();
    assert_eq!(port.rings.tx.read(0).len, 1514);
}

#[test]
fn port_indices_wrap_without_repeating_fill_rx_or_cq_ownership() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    let initial = u32::MAX;
    port.fill_producer = initial;
    port.fill_consumer = initial;
    port.rx_consumer = initial;
    port.tx_producer = initial;
    port.cq_consumer = initial;
    port.rings.fill.publish_producer(initial);
    port.rings.fill.publish_consumer(initial);
    port.rings.rx.publish_producer(initial);
    port.rings.rx.publish_consumer(initial);
    port.rings.tx.publish_producer(initial);
    port.rings.tx.publish_consumer(initial);
    port.rings.cq.publish_producer(initial);
    port.rings.cq.publish_consumer(initial);
    assert_eq!(port.refill().unwrap(), 2);
    let rx_address = port.rings.fill.read(initial);
    port.umem.write_bytes(rx_address, &[9]);
    port.rings.fill.publish_consumer(0);
    port.rings.rx.write(
        initial,
        Descriptor {
            addr: rx_address,
            len: 1,
            options: 0,
        },
    );
    port.rings.rx.publish_producer(0);
    assert_eq!(port.receive(1, |frame| assert_eq!(frame, &[9])).unwrap(), 1);
    assert_eq!(port.rings().rx_consumer, 0);
    assert_eq!(port.rings().fill_producer, 2);
    assert_eq!(port.observe_fill().unwrap(), 0);
    port.transmit_retained(TxClass::Control, &[0; 14], Retained::new(&drops))
        .unwrap();
    let tx_address = port.rings.tx.read(initial).addr;
    assert_eq!(port.rings().tx_producer, 0);
    port.rings.tx.publish_consumer(0);
    port.rings.cq.write(initial, tx_address);
    port.rings.cq.publish_producer(0);
    assert_eq!(port.complete(|_| {}).unwrap(), 1);
    assert_eq!(port.rings().cq_consumer, 0);
    assert_eq!(port.complete(|_| {}).unwrap(), 0);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(port.counters().submitted, 1);
    assert_eq!(port.counters().completed, 1);
    assert_eq!(port.counters().rx, 1);
    assert_eq!(port.counters().fill, 3);
}

#[test]
fn sg_receive_defers_the_whole_chain_until_fill_consumer_publication() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(
        PortConfig {
            rx_frames: 4,
            control_frames: 4,
            bulk_frames: 4,
            ring_size: 8,
        },
        &budget,
    );
    port.mtu = 9000;
    port.scatter_gather = true;
    assert_eq!(port.refill().unwrap(), 4);
    let first = port.rings.fill.read(0);
    let second = port.rings.fill.read(1);
    port.umem.write_bytes(first, &[9; METADATA_SIZE]);
    port.umem.write_bytes(first + 32, &[1; 3000]);
    port.umem.write_bytes(second + 32, &[2; 3000]);
    port.rings.rx.write(
        0,
        Descriptor {
            addr: first + 32,
            len: 3000,
            options: 1,
        },
    );
    port.rings.rx.write(
        1,
        Descriptor {
            addr: second + 32,
            len: 3000,
            options: 0,
        },
    );
    port.rings.rx.publish_producer(2);
    assert_eq!(
        port.receive_segments_with(1, METADATA_SIZE, |_, _, _| panic!(
            "FILL consumer not published"
        ))
        .unwrap(),
        0
    );
    assert_ne!(port.rings().rx_producer, port.rings().rx_consumer);
    assert_eq!(port.rings().rx_consumer, 0);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.drain_state().fill_queued, 4);
    assert!(!port.drain_state().closed);
    port.rings.fill.publish_consumer(1);
    assert_eq!(
        port.receive_segments(1, METADATA_SIZE, |_, _| panic!(
            "only part of FILL consumption published"
        ))
        .unwrap(),
        0
    );
    assert_eq!(port.rings().rx_consumer, 0);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.drain_state().fill_queued, 3);
    assert_eq!(port.rings().fill_producer, 4);
    assert_eq!(port.counters().rx, 0);
    assert_eq!(port.counters().invalid, 0);
    assert!(!port.drain_state().closed);
    port.rings.fill.publish_consumer(2);
    let mut delivered = 0;
    assert_eq!(
        port.receive_segments_with(1, METADATA_SIZE, |parts, metadata, tx| {
            assert_eq!(parts.len(), 2);
            assert_eq!(parts[0], &[1; 3000]);
            assert_eq!(parts[1], &[2; 3000]);
            assert_eq!(metadata, &[9; METADATA_SIZE]);
            tx.transmit_segments(TxClass::Bulk, parts, ()).unwrap();
            delivered += 1;
        })
        .unwrap(),
        1
    );
    assert_eq!(delivered, 1);
    assert_eq!(port.rings().rx_consumer, 2);
    assert_eq!(port.rings().fill_producer, 6);
    assert_eq!(
        [port.rings.fill.read(4), port.rings.fill.read(5)],
        [second, first]
    );
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.drain_state().fill_queued, 4);
    assert_eq!(port.counters().rx, 1);
    assert_eq!(port.counters().fill, 6);
    assert_eq!(port.counters().invalid, 0);
    assert!(!port.drain_state().closed);
    assert_eq!(
        port.receive_segments(1, METADATA_SIZE, |_, _| panic!("duplicate RX chain"))
            .unwrap(),
        0
    );
    assert_eq!(port.rings().fill_producer, 6);
    assert_eq!(port.rings().tx_producer, 2);
    for index in 0..2 {
        let address = port.rings.tx.read(index).addr;
        assert!(address >= (port.config().rx_frames * FRAME_SIZE) as u64);
        port.rings.cq.write(index, address);
    }
    port.rings.tx.publish_consumer(2);
    port.rings.cq.publish_producer(2);
    assert_eq!(port.complete(|_| {}).unwrap(), 2);
}

#[test]
fn sg_receive_rejects_invalid_chains_before_waiting_or_leasing() {
    for invalid in 0..8 {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 4,
                control_frames: 4,
                bulk_frames: 4,
                ring_size: 8,
            },
            &budget,
        );
        port.mtu = 9000;
        port.scatter_gather = true;
        port.refill().unwrap();
        let mut first = port.rings.fill.read(0) + 32;
        let second = port.rings.fill.read(1) + 32;
        let descriptor = match invalid {
            0 => Descriptor {
                addr: u64::MAX,
                len: 1,
                options: 0,
            },
            1 => Descriptor {
                addr: (port.config().rx_frames * FRAME_SIZE) as u64 + 32,
                len: 1,
                options: 0,
            },
            2 => Descriptor {
                addr: first + 64,
                len: 1,
                options: 0,
            },
            3 => Descriptor {
                addr: second + FRAME_SIZE as u64 - 33,
                len: 2,
                options: 0,
            },
            4 => {
                port.rings.fill.publish_consumer(1);
                port.observe_fill().unwrap();
                let lease = port.ledger.receive_rx(first, 64).unwrap();
                port.ledger.relinquish_rx(lease).unwrap();
                let free = first;
                first = port.rings.fill.read(2) + 32;
                Descriptor {
                    addr: free,
                    len: 64,
                    options: 0,
                }
            }
            5 => Descriptor {
                addr: second,
                len: 1,
                options: 2,
            },
            6 => Descriptor {
                addr: second,
                len: 0,
                options: 0,
            },
            7 => {
                first -= 1;
                Descriptor {
                    addr: second,
                    len: 1,
                    options: 0,
                }
            }
            _ => unreachable!(),
        };
        port.rings.rx.write(
            0,
            Descriptor {
                addr: first,
                len: 64,
                options: 1,
            },
        );
        port.rings.rx.write(1, descriptor);
        port.rings.rx.publish_producer(2);
        assert!(
            port.receive_segments_with(1, METADATA_SIZE, |_, _, _| panic!(
                "invalid RX chain borrowed"
            ))
            .is_err()
        );
        assert_eq!(port.rings().rx_consumer, 0);
        assert_eq!(port.drain_state().rx_leased, 0);
        assert_eq!(port.counters().rx, 0);
        assert_eq!(port.counters().invalid, 1);
        assert!(port.drain_state().closed);
    }
}

#[test]
fn borrowed_rx_batch_matches_single_packets_across_a_partial_chain() {
    let run = |batch, expected_counts: &[usize]| {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 4,
                ..config()
            },
            &budget,
        );
        port.scatter_gather = true;
        port.refill().unwrap();
        queue_rx(&mut port, &[60], METADATA_SIZE);
        queue_rx(&mut port, &[61], METADATA_SIZE);
        let end = stage_rx(&mut port, &[62, 63], METADATA_SIZE);
        port.rings.rx.publish_producer(end - 1);

        let mut lengths = Vec::new();
        for &expected in expected_counts {
            let before = port.rings();
            let mut descriptors = 0;
            let received = port
                .receive_segments_with(batch, METADATA_SIZE, |parts, metadata, tx| {
                    assert_eq!(tx.port.rings.rx.consumer(), before.rx_consumer);
                    assert_eq!(tx.port.rings.fill.producer(), before.fill_producer);
                    assert_eq!(metadata, &[0xa5; METADATA_SIZE]);
                    if lengths.is_empty() {
                        tx.port.rings.rx.publish_producer(end);
                    }
                    for (index, bytes) in parts.iter().enumerate() {
                        assert!(bytes.iter().all(|&byte| byte == index as u8 + 1));
                    }
                    descriptors += parts.len() as u32;
                    lengths.push(parts.iter().map(|bytes| bytes.len()).collect::<Vec<_>>());
                })
                .unwrap();
            assert_eq!(received, expected);
            assert_eq!(port.rings().rx_consumer, before.rx_consumer + descriptors);
            assert_eq!(
                port.rings().fill_producer,
                before.fill_producer + descriptors
            );
        }
        (lengths, port.rings(), port.counters(), port.drain_state())
    };
    let batch = run(4, &[2, 1, 0]);
    assert_eq!(batch, run(1, &[1, 1, 1, 0]));
    assert_eq!(batch.0, [vec![60], vec![61], vec![62, 63]]);
    assert_eq!(batch.2.rx, 3);
    assert_eq!(batch.3.rx_leased, 0);
}

#[test]
fn borrowed_rx_drops_callback_before_refilling_a_partial_chain() {
    struct PanicOnDrop;

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            std::panic::panic_any("borrowed RX capture dropped");
        }
    }

    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    port.scatter_gather = true;
    port.refill().unwrap();
    let end = stage_rx(&mut port, &[60, 60], 0);
    port.rings.rx.publish_producer(end - 1);
    port.rings.fill.set_wakeup();
    let capture = PanicOnDrop;
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        port.receive_segments(2, 0, move |_, _| {
            std::hint::black_box(&capture);
        })
        .unwrap();
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>(),
        Some(&"borrowed RX capture dropped")
    );
    assert!(port.drain_state().closed);
    assert_eq!(port.rings().rx_consumer, 0);
    assert_eq!(port.counters().rx, 0);
    assert_eq!(port.counters().rx_kicks, 0);
}

#[test]
fn sg_receive_waits_for_terminal_descriptor_and_can_transmit_same_port() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(
        PortConfig {
            rx_frames: 4,
            control_frames: 4,
            bulk_frames: 4,
            ring_size: 8,
        },
        &budget,
    );
    port.mtu = 9000;
    port.scatter_gather = true;
    port.refill().unwrap();
    port.rings.fill.publish_consumer(2);
    let first = port.rings.fill.read(0);
    let second = port.rings.fill.read(1);
    port.umem.write_bytes(first, &[9; METADATA_SIZE]);
    port.umem.write_bytes(first + 32, &[1; 3000]);
    port.umem.write_bytes(second + 32, &[2; 3000]);
    port.rings.rx.write(
        0,
        Descriptor {
            addr: first + 32,
            len: 3000,
            options: 1,
        },
    );
    port.rings.rx.publish_producer(1);
    assert_eq!(
        port.receive_segments(1, METADATA_SIZE, |_, _| panic!("partial RX packet"))
            .unwrap(),
        0
    );
    assert!(
        port.needs_service_retry(),
        "partial RX chains retain a retry obligation"
    );
    assert_eq!(port.rings().rx_consumer, 0);
    port.rings.rx.write(
        1,
        Descriptor {
            addr: second + 32,
            len: 3000,
            options: 0,
        },
    );
    port.rings.rx.publish_producer(2);
    assert_eq!(
        port.receive_segments_with(1, METADATA_SIZE, |parts, metadata, tx| {
            assert_eq!(parts.len(), 2);
            assert_eq!(metadata, &[9; METADATA_SIZE]);
            tx.transmit_segments(TxClass::Bulk, parts, ()).unwrap();
        })
        .unwrap(),
        1
    );
    assert_eq!(port.rings().rx_consumer, 2);
    assert_eq!(port.rings().tx_producer, 2);
    let first = port.rings.tx.read(0);
    let last = port.rings.tx.read(1);
    assert_eq!(first.options, 1);
    assert_eq!(last.options, 0);
    assert_eq!(first.len + last.len, 6000);
    let bytes = port.umem.frame(first.addr, first.len as usize).unwrap();
    assert_eq!(&bytes[..3000], &[1; 3000]);
    assert!(bytes[3000..].iter().all(|&byte| byte == 2));
}

#[test]
fn sg_tx_cancels_writer_failure_and_retains_until_every_completion() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(
        PortConfig {
            rx_frames: 4,
            control_frames: 4,
            bulk_frames: 4,
            ring_size: 8,
        },
        &budget,
    );
    port.mtu = 9000;
    port.scatter_gather = true;
    assert!(port.tx_packet_credit(TxClass::Bulk, 9000));
    assert!(!port.tx_packet_credit(TxClass::Bulk, 13));
    assert!(!port.tx_packet_credit(TxClass::Bulk, 9023));
    assert!(
        port.transmit_with(TxClass::Bulk, 9000, Retained::new(&drops), |owner, _| {
            assert_eq!(owner.as_ref(), &[7; 28]);
            Err(io::Error::other("writer failed"))
        })
        .is_err()
    );
    assert_eq!(port.rings().tx_producer, 0);
    assert_eq!(port.counters().published_packets, 0);
    assert_eq!(port.tx_free[1], 4);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert!(
        !port.needs_service_retry(),
        "unpublished writer failure owes no CQ"
    );
    port.transmit_segments(TxClass::Bulk, &[&[7; 9000]], Retained::new(&drops))
        .unwrap();
    assert!(port.needs_service_retry());
    assert_eq!(port.rings().tx_producer, 3);
    assert_eq!(port.counters().submitted, 3);
    assert_eq!(port.counters().published_packets, 1);
    assert!(port.tx_credit(TxClass::Bulk));
    assert!(!port.tx_packet_credit(TxClass::Bulk, 9000));
    port.rings.tx.publish_consumer(3);
    for (completion, descriptor) in [1, 0, 2].into_iter().enumerate() {
        port.rings
            .cq
            .write(completion as u32, port.rings.tx.read(descriptor).addr);
        port.rings.cq.publish_producer(completion as u32 + 1);
        assert_eq!(
            port.complete(|owners| {
                assert_eq!(owners.len(), usize::from(completion == 2));
            })
            .unwrap(),
            1
        );
        assert_eq!(port.needs_service_retry(), completion != 2);
        assert_eq!(
            drops.load(Ordering::Relaxed),
            if completion == 2 { 2 } else { 1 }
        );
    }
    assert_eq!(port.tx_free[1], 4);
    assert!(port.sidecar.occupied().next().is_none());
    assert!(port.tx_packet_credit(TxClass::Bulk, 9000));
    assert_eq!(port.counters().published_packets, 1);
}

#[test]
fn sg_owner_survives_first_frame_reuse_after_out_of_order_cq() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake(
        PortConfig {
            bulk_frames: 3,
            ..config()
        },
        &budget,
    );
    port.mtu = 9000;
    port.scatter_gather = true;
    port.transmit_segments(TxClass::Bulk, &[&[1; 9000]], 1u8)
        .unwrap();
    let [first, middle, last] = std::array::from_fn(|index| port.rings.tx.read(index as u32).addr);
    port.rings.tx.publish_consumer(3);
    port.rings.cq.write(0, first);
    port.rings.cq.publish_producer(1);
    assert_eq!(
        port.complete(|owners| assert!(owners.is_empty())).unwrap(),
        1
    );

    assert!(
        port.transmit_generated(TxClass::Bulk, 60, |frame| {
            frame.fill(2);
            Ok(Some((60, 2)))
        })
        .unwrap()
    );
    assert_eq!(port.rings.tx.read(3).addr, first);
    port.rings.tx.publish_consumer(4);
    port.rings.cq.write(1, last);
    port.rings.cq.write(2, first);
    port.rings.cq.publish_producer(3);
    assert_eq!(
        port.complete(|owners| assert!(matches!(owners, [Some(v)] if **v == 2)))
            .unwrap(),
        2
    );
    port.rings.cq.write(3, middle);
    port.rings.cq.publish_producer(4);
    assert_eq!(
        port.complete(|owners| assert!(matches!(owners, [Some(v)] if **v == 1)))
            .unwrap(),
        1
    );

    for class in [
        TxClass::Control,
        TxClass::Bulk,
        TxClass::Bulk,
        TxClass::Bulk,
    ] {
        port.transmit_segments(class, &[&[3; 60]], 3).unwrap();
    }
    for index in 4..8 {
        port.rings.cq.write(index, port.rings.tx.read(index).addr);
    }
    port.rings.tx.publish_consumer(8);
    port.rings.cq.publish_producer(8);
    assert_eq!(
        port.complete(|owners| assert_eq!(owners.len(), 4)).unwrap(),
        4
    );
}

#[test]
fn packet_capacity_uses_actual_mtu_class_frames_and_tx_ring_space() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(
        PortConfig {
            rx_frames: 1,
            control_frames: 1,
            bulk_frames: 7,
            ring_size: 8,
        },
        &budget,
    );
    assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 7);
    assert_eq!(port.tx_packet_capacity(TxClass::Control).unwrap(), 1);
    port.mtu = 9000;
    port.scatter_gather = true;
    assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 2);
    assert_eq!(port.tx_packet_capacity(TxClass::Control).unwrap(), 0);
    assert!(port.tx_packet_credit(TxClass::Control, 60));
    port.transmit_segments(TxClass::Control, &[&[1; 60]], ())
        .unwrap();
    for _ in 0..2 {
        port.transmit_segments(TxClass::Bulk, &[&[7; 9022]], ())
            .unwrap();
    }
    assert_eq!(port.counters().submitted, 7);
    assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 0);
    assert_eq!(
        port.transmit_segments(TxClass::Bulk, &[&[7; 9022]], ())
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    for index in 0..7 {
        port.rings.cq.write(index, port.rings.tx.read(index).addr);
    }
    port.rings.cq.publish_producer(7);
    assert_eq!(port.complete(|_| {}).unwrap(), 7);
    assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 0);
    port.rings.tx.publish_consumer(7);
    assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 2);
    port.close();
    assert_eq!(port.tx_packet_capacity(TxClass::Bulk).unwrap(), 0);
    port.rings.tx.publish_consumer(8);
    assert!(port.tx_packet_capacity(TxClass::Bulk).is_err());
    assert_eq!(port.counters().invalid, 1);
}

#[test]
fn returned_cq_still_retries_until_tx_ring_credit_is_visible() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(
        PortConfig {
            ring_size: 2,
            ..config()
        },
        &budget,
    );
    for class in [TxClass::Control, TxClass::Bulk] {
        port.transmit_segments(class, &[&[1; 60]], ()).unwrap();
    }
    for index in 0..2 {
        port.rings.cq.write(index, port.rings.tx.read(index).addr);
    }
    port.rings.cq.publish_producer(2);
    assert_eq!(port.complete(|_| {}).unwrap(), 2);
    assert!(port.outstanding().next().is_none());
    assert!(!port.tx_credit(TxClass::Bulk));
    assert!(port.needs_service_retry());
    port.rings.tx.publish_consumer(2);
    assert!(port.tx_credit(TxClass::Bulk));
    assert!(!port.needs_service_retry());
}

fn transmit_entry(
    port: &mut Port<Retained>,
    entry: usize,
    drops: &Arc<AtomicUsize>,
) -> io::Result<()> {
    let owner = Retained::new(drops);
    match entry {
        0 => port.transmit(TxClass::Bulk, &[3; 14], &[7; 28], owner),
        1 => port.transmit_retained(TxClass::Bulk, &[3; 14], owner),
        2 => port.transmit_segments(TxClass::Bulk, &[&[3; 14], &[7; 28]], owner),
        3 => port.transmit_with(TxClass::Bulk, 42, owner, |_, target| {
            target[0][..14].fill(3);
            target[0][14..].fill(7);
            Ok(())
        }),
        4 => port
            .transmit_generated(TxClass::Bulk, 42, |target| {
                target[..14].fill(3);
                target[14..].copy_from_slice(owner.as_ref());
                Ok(Some((42, owner)))
            })
            .map(|sent| assert!(sent)),
        _ => unreachable!(),
    }
}

#[test]
fn batch_sg_chain_wraps_and_completion_observes_only_whole_packets() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake(
        PortConfig {
            bulk_frames: 5,
            ring_size: 8,
            ..config()
        },
        &budget,
    );
    port.scatter_gather = true;
    port.mtu = 9000;
    let initial = u32::MAX - 1;
    port.tx_producer = initial;
    port.rings.tx.publish_producer(initial);
    port.rings.tx.publish_consumer(initial);
    let ((), kick) = port.transmit_batch(|port| {
        port.transmit_segments(TxClass::Bulk, &[&[1; 9000]], 11)
            .unwrap();
        assert_eq!(port.rings.tx.producer(), initial);
        assert!(
            port.transmit_with(TxClass::Control, 60, 12, |_, _| Err(io::Error::other(
                "materialization refused"
            )))
            .is_err()
        );
        assert_eq!(port.rings.tx.producer(), initial);
        assert_eq!(
            port.complete(|owners| assert!(owners.is_empty())).unwrap(),
            0
        );
        assert_eq!(port.rings.tx.producer(), 1);
        for part in 0..3 {
            let desc = port.rings.tx.read(initial.wrapping_add(part));
            assert_eq!(desc.options, u32::from(part != 2));
            port.rings.cq.write(part, desc.addr);
        }
        port.rings.tx.publish_consumer(1);
        port.rings.cq.publish_producer(3);
        assert_eq!(
            port.complete(|owners| assert_eq!(**owners[0].as_ref().unwrap(), 11))
                .unwrap(),
            3
        );
    });
    kick.unwrap();
}

#[test]
fn batch_refreshes_consumer_when_a_whole_chain_will_not_fit() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(
        PortConfig {
            bulk_frames: 4,
            ring_size: 8,
            ..config()
        },
        &budget,
    );
    port.scatter_gather = true;
    port.mtu = 9000;
    // Six published descriptors precede this turn. The kernel consumes them during it.
    port.tx_producer = 6;
    port.rings.tx.publish_producer(6);
    let (work, kick) = port.transmit_batch(|port| {
        assert!(!port.tx_packet_credit(TxClass::Bulk, 9000));
        port.rings.tx.publish_consumer(6);
        assert!(port.tx_packet_credit(TxClass::Bulk, 60));
        assert_eq!(port.tx_cached_consumer.get(), 0);
        port.transmit_segments(TxClass::Bulk, &[&[1; 9000]], ())?;
        assert_eq!(port.tx_cached_consumer.get(), 6);
        assert_eq!(port.rings.tx.producer(), 6);
        Ok::<_, io::Error>(())
    });
    work.unwrap();
    kick.unwrap();
    assert_eq!(port.rings.tx.producer(), 9);
}

#[test]
fn batch_tx_entries_publish_the_whole_prefix_before_terminal_wakeup() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(
        PortConfig {
            bulk_frames: 5,
            ring_size: 8,
            ..config()
        },
        &budget,
    );
    port.rings.tx.set_wakeup();
    let (work, kick) = port.transmit_batch(|port| {
        for entry in 0..5 {
            transmit_entry(port, entry, &drops)?;
            assert_eq!(port.rings.tx.producer(), 0);
        }
        assert_eq!(port.counters().published_packets, 5);
        assert!(!port.drain_state().closed);
        assert_eq!(port.rings().tx_producer, 5);
        Ok::<_, io::Error>(())
    });
    work.unwrap();
    assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
    assert!(port.drain_state().closed);
    assert!(!port.tx_batch_active);
    assert_eq!(port.outstanding().count(), 5);
    for index in 0..5 {
        let descriptor = port.rings.tx.read(index);
        assert_eq!(descriptor.len, 60);
        assert_eq!(descriptor.options, 0);
        let frame = port.umem.frame(descriptor.addr, 60).unwrap();
        assert_eq!(&frame[..14], &[3; 14]);
        assert_eq!(&frame[14..42], &[7; 28]);
        assert_eq!(&frame[42..], &[0; 18]);
    }
    port.rings.tx.publish_consumer(5);
    assert_eq!(port.complete(|_| {}).unwrap(), 0);
    assert_eq!(port.counters().published_packets, 5);
    assert!(!port.counters().publication_count_unavailable);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    let retained = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
    drop(port);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(budget.used(), retained);
}

#[test]
fn batch_writer_errors_and_credit_pressure_keep_the_final_kick_separate() {
    for suffix in 0..3 {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut port = fake(config(), &budget);
        port.rings.tx.set_wakeup();
        let (work, kick) = port.transmit_batch(|port| {
            transmit_entry(port, 1, &drops)?;
            if suffix == 2 {
                return transmit_entry(port, 2, &drops);
            }
            port.transmit_with(TxClass::Control, 60, Retained::new(&drops), |_, _| {
                Err(io::Error::new(
                    if suffix == 0 {
                        io::ErrorKind::InvalidData
                    } else {
                        io::ErrorKind::WouldBlock
                    },
                    "unpublished writer suffix",
                ))
            })
        });
        assert_eq!(
            work.unwrap_err().kind(),
            if suffix == 0 {
                io::ErrorKind::InvalidData
            } else {
                io::ErrorKind::WouldBlock
            }
        );
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        assert!(port.drain_state().closed);
        assert_eq!(port.drain_state().control_reserved, 0);
        assert_eq!(port.drain_state().bulk_reserved, 0);
        assert_eq!(port.rings().tx_producer, 1);
        assert_eq!(port.counters().published_packets, 1);
        assert_eq!(port.outstanding().count(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        port.rings.cq.write(0, port.rings.tx.read(0).addr);
        port.rings.cq.publish_producer(1);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
        assert_eq!(port.counters().published_packets, 1);
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }
}

#[test]
fn empty_tx_batch_only_wakes_fill_after_the_last_completion() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.transmit_retained(TxClass::Bulk, &[0; 14], Retained::new(&drops))
        .unwrap();
    port.rings.tx.publish_consumer(1);
    port.rings.cq.write(0, port.rings.tx.read(0).addr);
    port.rings.cq.publish_producer(1);
    assert_eq!(port.complete(|_| {}).unwrap(), 1);
    port.rings.tx.set_wakeup();
    port.transmit_batch(|_| ()).1.unwrap();
    port.rings.fill.set_wakeup();
    assert_eq!(
        port.transmit_batch(|_| ()).1.unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!((port.counters().rx_kicks, port.counters().tx_kicks), (1, 0));
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn batch_early_and_pending_returns_reinspect_wakeup_without_new_publication() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    let (pending, kick) = port.transmit_batch(|_| std::task::Poll::<()>::Pending);
    assert!(pending.is_pending());
    kick.unwrap();
    assert!(!port.tx_batch_active);
    port.rings.tx.set_wakeup();
    let (work, kick) = port.transmit_batch(|port| {
        transmit_entry(port, 0, &drops)?;
        if !port.tx_credit(TxClass::Bulk) {
            return Ok::<_, io::Error>(7);
        }
        panic!("one-frame bulk commitment was exceeded");
    });
    assert_eq!(work.unwrap(), 7);
    assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
    let ((), kick) = port.transmit_batch(|_| ());
    assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
    assert_eq!(port.counters().submitted, 1);
    assert_eq!(port.counters().completed, 0);
    assert_eq!(port.counters().published_packets, 1);
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
}

#[test]
fn borrowed_tx_sink_prefix_is_finalized_after_a_later_rx_error() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.refill().unwrap();
    port.rings.fill.publish_consumer(2);
    let rx = port.rings.fill.read(0);
    port.umem.write_bytes(rx, &[7; 60]);
    port.rings.rx.write(
        0,
        Descriptor {
            addr: rx,
            len: 60,
            options: 0,
        },
    );
    port.rings.rx.write(
        1,
        Descriptor {
            addr: port.rings.fill.read(1),
            len: 0,
            options: 0,
        },
    );
    port.rings.rx.publish_producer(2);
    port.rings.tx.set_wakeup();
    let (work, kick) = port.transmit_batch(|port| {
        port.receive_segments_with(2, 0, |parts, _, tx| {
            tx.transmit_segments(TxClass::Bulk, parts, Retained::new(&drops))
                .unwrap();
            tx.transmit_with(TxClass::Control, 60, Retained::new(&drops), |_, target| {
                target[0].copy_from_slice(parts[0]);
                Ok(())
            })
            .unwrap();
        })
    });
    assert!(
        work.unwrap_err()
            .to_string()
            .contains("invalid RX chain descriptor")
    );
    assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
    assert_eq!(port.rings().rx_consumer, 1);
    assert_eq!(port.rings().fill_producer, 2);
    assert_eq!(port.counters().rx, 1);
    assert_eq!(port.counters().invalid, 1);
    assert_eq!(port.drain_state().rx_leased, 0);
    assert_eq!(port.rings().tx_producer, 2);
    assert_eq!(port.outstanding().count(), 2);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    for index in 0..2 {
        let descriptor = port.rings.tx.read(index);
        assert_eq!(port.umem.frame(descriptor.addr, 60).unwrap(), &[7; 60]);
        assert!(descriptor.addr >= (config().rx_frames * FRAME_SIZE) as u64);
    }
}

#[test]
fn borrowed_rx_rejects_a_second_packet_in_the_released_prefix_frame() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(config(), &budget);
    port.refill().unwrap();
    queue_rx(&mut port, &[60], 0);
    queue_rx(&mut port, &[61], 0);
    let mut duplicate = port.rings.rx.read(1);
    duplicate.addr = port.rings.rx.read(0).addr + 1;
    port.rings.rx.write(1, duplicate);
    let error = port
        .receive_segments(2, 0, |parts, _| assert_eq!(parts[0], &[1; 60]))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(port.rings().rx_consumer, 1);
    assert_eq!(port.rings().fill_producer, 2);
    assert_eq!(port.counters().rx, 1);
    let state = port.drain_state();
    assert!(state.closed);
    assert_eq!(state.rx_free, 1);
    assert_eq!(state.rx_leased, 0);
    assert_eq!(state.fill_posted, 1);
}

#[test]
fn retained_rx_stops_on_a_fatal_same_port_tx_kick() {
    for disposition in [RxDisposition::Release, RxDisposition::Retain] {
        let budget = MemoryBudget::new(1 << 20);
        let mut port = fake::<()>(
            PortConfig {
                rx_frames: 3,
                ..config()
            },
            &budget,
        );
        port.refill().unwrap();
        queue_rx(&mut port, &[60], 0);
        queue_rx(&mut port, &[61], 0);
        port.rings.tx.set_wakeup();
        let mut admitted = None;
        let received = port
            .receive_segments_owned(2, 0, |handle, parts, _, tx| {
                assert!(admitted.replace(handle).is_none());
                let error = tx.transmit_segments(TxClass::Bulk, parts, ()).unwrap_err();
                assert_eq!(error.raw_os_error(), Some(libc::EBADF));
                tx.port.rings.fill.publish_consumer(3);
                disposition
            })
            .unwrap();
        assert_eq!(received, 1);
        assert!(port.drain_state().closed);
        assert_eq!(port.rings().rx_consumer, 1);
        assert_eq!(port.rings().fill_producer, 3);
        assert_eq!(port.fill_consumer, 2);
        assert_eq!(port.counters().rx, 1);
        assert_eq!(port.drain_state().bulk_outstanding, 1);
        if disposition == RxDisposition::Retain {
            let completion = port.release_retained_rx(admitted.unwrap()).unwrap();
            port.complete_retained_rx(completion).unwrap();
        }
        assert_eq!(port.retained_rx_count(), 0);
        assert_eq!(port.rx_completion_count(), 0);
        assert_eq!(port.drain_state().rx_leased, 0);
    }
}

#[test]
fn borrowed_rx_callback_panic_keeps_whole_chain_and_tx_prefix() {
    let budget = MemoryBudget::new(1 << 20);
    let mut port = fake::<()>(
        PortConfig {
            rx_frames: 5,
            ring_size: 8,
            ..config()
        },
        &budget,
    );
    port.scatter_gather = true;
    port.refill().unwrap();
    queue_rx(&mut port, &[59], METADATA_SIZE);
    queue_rx(&mut port, &[60, 61], METADATA_SIZE);
    queue_rx(&mut port, &[62], METADATA_SIZE);
    port.rings.fill.set_wakeup();
    port.rings.tx.set_wakeup();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let (work, kick) = port.transmit_batch(|port| {
            port.receive_segments_with(4, METADATA_SIZE, |parts, metadata, tx| {
                assert_eq!(metadata, &[0xa5; METADATA_SIZE]);
                if parts.len() == 1 {
                    assert_eq!(parts[0], &[1; 59]);
                    return;
                }
                assert_eq!(parts, &[&[1; 60][..], &[2; 61][..]]);
                tx.transmit_segments(TxClass::Bulk, parts, ()).unwrap();
                std::panic::panic_any("borrowed RX callback");
            })
        });
        work.unwrap();
        kick.unwrap();
    }))
    .unwrap_err();
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"borrowed RX callback"));
    let state = port.drain_state();
    assert!(state.closed);
    assert!(!state.ready_for_backend_teardown());
    assert_eq!(state.rx_free, 1);
    assert_eq!(state.rx_leased, 2);
    assert_eq!(state.fill_posted, 2);
    assert_eq!(state.fill_queued, 1);
    assert_eq!(port.retained_rx_count(), 0);
    assert_eq!(port.rx_completion_count(), 0);
    assert_eq!(port.rx_consumer, 3);
    assert_eq!(port.rings().rx_consumer, 0);
    assert_eq!(port.rings().fill_producer, 5);
    assert_eq!(port.counters().rx, 2);
    assert_eq!(port.counters().wakeup_errors, 0);
    assert_eq!(port.counters().published_packets, 1);
    assert_eq!(state.bulk_outstanding, 1);
    let descriptor = port.rings.tx.read(0);
    let bytes = port
        .umem
        .frame(descriptor.addr, descriptor.len as usize)
        .unwrap();
    assert_eq!(&bytes[..60], &[1; 60]);
    assert_eq!(&bytes[60..], &[2; 61]);
    // The peer consumed the spare FILL entry after the unwind. Closed admission must
    // leave even this legitimate advance unobserved across every receive entry point.
    port.rings.fill.publish_consumer(5);
    let rings = port.rings();
    let counters = port.counters();
    let charge = budget.used();
    for batch in [0, 4] {
        let counts = [
            port.receive_segments(batch, 0, |_, _| panic!("closed RX admitted"))
                .unwrap(),
            port.receive_segments_with(batch, 0, |_, _, _| panic!("closed sink RX admitted"))
                .unwrap(),
            port.receive_segments_owned(batch, 0, |_, _, _, _| {
                panic!("closed retained RX admitted")
            })
            .unwrap(),
            port.receive(batch, |_| panic!("closed single RX admitted"))
                .unwrap(),
        ];
        assert_eq!(counts, [0; 4]);
        assert_eq!(port.rx_consumer, 3);
        assert_eq!(port.fill_consumer, 4);
        assert_eq!(port.rings(), rings);
        assert_eq!(port.drain_state(), state);
        assert_eq!(port.counters(), counters);
        assert_eq!(port.retained_rx_count(), 0);
        assert_eq!(budget.used(), charge);
    }
    let retained = port.umem_bytes()
        + port.ledger.charged_bytes()
        + port._bookkeeping.as_ref().unwrap().bytes()
        + port.sidecar.reservation.as_ref().unwrap().bytes();
    drop(port);
    assert_eq!(budget.used(), retained);
}

#[test]
fn batch_panic_closes_admission_and_retains_published_and_reserved_ownership() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.rings.tx.set_wakeup();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = port.transmit_batch(|port| {
            transmit_entry(port, 1, &drops).unwrap();
            port.transmit_with(TxClass::Control, 60, Retained::new(&drops), |_, _| {
                panic!("writer unwound after a published prefix")
            })
            .unwrap();
        });
    }));
    assert!(panic.is_err());
    assert_eq!(port.rings.tx.producer(), 1);
    let state = port.drain_state();
    assert!(state.closed);
    assert_eq!(state.control_reserved, 1);
    assert_eq!(state.bulk_outstanding, 1);
    assert!(!state.ready_for_backend_teardown());
    assert!(!port.tx_batch_active);
    assert!(!port.tx_credit(TxClass::Control));
    assert_eq!(port.counters().wakeup_errors, 0);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    let retained = port.umem_bytes() + std::mem::size_of_val(&*port.sidecar.slots);
    drop(port);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(budget.used(), retained);
}

#[test]
fn batch_is_finalized_before_the_owning_future_can_suspend_and_be_cancelled() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.rings.tx.set_wakeup();
    let mut future = Box::pin(async {
        let (work, kick) = port.transmit_batch(|port| transmit_entry(port, 3, &drops));
        work.unwrap();
        assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        std::future::pending::<()>().await;
    });
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    drop(future);
    assert!(port.drain_state().closed);
    assert!(!port.tx_batch_active);
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(port.counters().completed, 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    port.rings.cq.write(0, port.rings.tx.read(0).addr);
    port.rings.cq.publish_producer(1);
    assert_eq!(port.complete(|_| {}).unwrap(), 1);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn distinct_device_scopes_finalize_both_orderings_after_inner_credit_failure() {
    for egress_first in [false, true] {
        let budget = MemoryBudget::new(1 << 20);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut ports = [fake(config(), &budget), fake(config(), &budget)];
        let (first, second) = ports.split_at_mut(1);
        let (current, egress) = if egress_first {
            (&mut second[0], &mut first[0])
        } else {
            (&mut first[0], &mut second[0])
        };
        current.rings.tx.set_wakeup();
        egress.rings.tx.set_wakeup();
        let ((work, egress_kick), current_kick) = current.transmit_batch(|current| {
            transmit_entry(current, 1, &drops).unwrap();
            egress.transmit_batch(|egress| {
                transmit_entry(egress, 2, &drops)?;
                transmit_entry(egress, 3, &drops)
            })
        });
        assert_eq!(work.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        for kick in [egress_kick, current_kick] {
            assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
        }
        for port in &ports {
            assert!(port.drain_state().closed);
            assert!(!port.tx_batch_active);
            assert_eq!(port.outstanding().count(), 1);
            assert_eq!(port.counters().submitted, 1);
            assert_eq!(port.counters().completed, 0);
        }
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn batch_rx_wakeup_failure_does_not_skip_the_published_tx_obligation() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(config(), &budget);
    port.rings.fill.set_wakeup();
    port.rings.tx.set_wakeup();
    let (work, kick) = port.transmit_batch(|port| transmit_entry(port, 1, &drops));
    work.unwrap();
    assert_eq!(kick.unwrap_err().raw_os_error(), Some(libc::EBADF));
    assert_eq!(port.counters().wakeup_errors, 2);
    assert_eq!(port.outstanding().count(), 1);
    assert_eq!(port.counters().completed, 0);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert!(!port.drain_state().ready_for_backend_teardown());
}

#[test]
fn batch_close_and_socket_close_do_not_retire_a_partial_sg_completion() {
    let budget = MemoryBudget::new(1 << 20);
    let drops = Arc::new(AtomicUsize::new(0));
    let mut port = fake(
        PortConfig {
            bulk_frames: 3,
            ring_size: 4,
            ..config()
        },
        &budget,
    );
    port.mtu = 9000;
    port.scatter_gather = true;
    let (work, kick) = port.transmit_batch(|port| {
        port.transmit_segments(TxClass::Bulk, &[&[7; 9000]], Retained::new(&drops))?;
        assert_eq!(port.close().bulk_outstanding, 3);
        port.close_socket();
        Ok::<_, io::Error>(())
    });
    work.unwrap();
    kick.unwrap();
    assert_eq!(port.counters().completed, 0);
    for index in 0..3 {
        port.rings.cq.write(index, port.rings.tx.read(index).addr);
        port.rings.cq.publish_producer(index + 1);
        assert_eq!(port.complete(|_| {}).unwrap(), 1);
        assert_eq!(drops.load(Ordering::Relaxed), usize::from(index == 2));
        assert_eq!(port.drain_state().ready_for_backend_teardown(), index == 2);
    }
}

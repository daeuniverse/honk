use super::{FlowIo, MemoryBudget, MemoryReservation, PacketDriver};
use honk_netstack::wire::tcp;
use std::{cell::Cell, net::SocketAddr, rc::Rc, sync::Arc, time::Instant};

pub(in crate::control) const COPY_BYTES: usize = 73_727;

struct Probe {
    budget: Arc<MemoryBudget>,
    _pressure: MemoryReservation,
    grant: Rc<Cell<Option<usize>>>,
}

thread_local! {
    static COPY_PROBE: Cell<Option<Probe>> = const { Cell::new(None) };
}

// A current-thread fixture parks its packet driver and owns the only copy attempt.
pub(in crate::control) struct CopyPressure(Rc<Cell<Option<usize>>>);

impl CopyPressure {
    pub(in crate::control) fn new(budget: &Arc<MemoryBudget>, headroom: usize) -> Self {
        let grant = Rc::new(Cell::new(None));
        let pressure = budget
            .reserve(budget.limit() - budget.used() - headroom)
            .unwrap();
        let previous = COPY_PROBE.replace(Some(Probe {
            budget: Arc::clone(budget),
            _pressure: pressure,
            grant: Rc::clone(&grant),
        }));
        assert!(previous.is_none());
        Self(grant)
    }

    pub(in crate::control) fn granted(&self) -> Option<usize> {
        self.0.get()
    }
}

impl Drop for CopyPressure {
    fn drop(&mut self) {
        drop(COPY_PROBE.take());
    }
}

pub(in crate::control) fn observe(credit: &MemoryReservation) {
    if let Some(probe) = COPY_PROBE.take() {
        assert_eq!(probe.budget.used(), probe.budget.limit());
        probe.grant.set(Some(credit.bytes()));
        // Give the task or boxed fallback future room only after the actual copy grant.
        drop(probe);
    }
}

pub(in crate::control) fn accept_local_syn(
    driver: &mut PacketDriver,
    destination: SocketAddr,
) -> FlowIo {
    let client: SocketAddr = "192.0.2.1:41000".parse().unwrap();
    let mut packet = [0; 128];
    let length = tcp::emit_packet(
        &mut packet,
        client.ip(),
        destination.ip(),
        &tcp::Header {
            src_port: client.port(),
            dst_port: destination.port(),
            seq: 100,
            ack: 0,
            flags: tcp::SYN,
            window: 4096,
            urgent: 0,
            options: tcp::Options::default(),
        },
        [&[], &[]],
    )
    .unwrap();
    let now = Instant::now();
    let peer = crate::xdp::routing_input::test_peer(1, 0, [2; 6], 7);
    driver
        .receive_realm_timed(&packet[..length], now, now, &mut None, false, |_, _| {
            Some(peer.clone())
        })
        .unwrap();
    driver.poll_accept_local().unwrap().expect("physical SYN").1
}

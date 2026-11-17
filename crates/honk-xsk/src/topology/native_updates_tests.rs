use super::*;
use crate::bpf::XdpUpdateError;
use std::collections::VecDeque;
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Barrier, mpsc};
use std::thread;

type Attribute = (u16, Vec<u8>);
type ReceiveQueue = Arc<Mutex<VecDeque<Receive>>>;

struct Datagram {
    bytes: Vec<u8>,
    length: usize,
    source_port: u32,
    source_family: libc::sa_family_t,
    source_extent: libc::socklen_t,
}

enum Receive {
    Datagram(Datagram),
    Error(i32),
}

impl From<Vec<u8>> for Receive {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Datagram(Datagram {
            length: bytes.len(),
            bytes,
            source_port: 0,
            source_family: libc::AF_NETLINK as libc::sa_family_t,
            source_extent: size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        })
    }
}

struct Fixture {
    topology: Topology,
    updates: NativeXdpUpdates,
    queue: ReceiveQueue,
    _sender: UnixDatagram,
    budget: Arc<MemoryBudget>,
}

fn strict_topology() -> (Topology, UnixDatagram) {
    let (receiver, sender) = UnixDatagram::pair().unwrap();
    (
        Topology {
            fd: receiver.into(),
            watch: WatchState::Strict { invalidated: false },
            ipv4_broadcasts: [Ipv4Addr::UNSPECIFIED; MAX_BROADCASTS],
            broadcast_count: 0,
        },
        sender,
    )
}

fn fixture() -> Fixture {
    let (mut topology, sender) = strict_topology();
    let budget = MemoryBudget::new(1 << 20);
    let updates = topology.enable_native_xdp_updates(&budget).unwrap();
    let queue: ReceiveQueue = Arc::new(Mutex::new(VecDeque::new()));
    let input = queue.clone();
    updates.lock().receive_hook = Some(Box::new(move |buffer| {
        match input.lock().unwrap().pop_front() {
            Some(Receive::Datagram(datagram)) => {
                // The injected queue uses the same source/extent boundary as recvfrom.
                let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
                source.nl_family = datagram.source_family;
                source.nl_pid = datagram.source_port;
                let length = validate_native_receive(
                    datagram.length,
                    buffer.len(),
                    datagram.source_extent,
                    &source,
                )?;
                assert!(length <= datagram.bytes.len());
                buffer[..length].copy_from_slice(&datagram.bytes[..length]);
                Ok(length)
            }
            Some(Receive::Error(error)) => Err(io::Error::from_raw_os_error(error)),
            None => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }));
    Fixture {
        topology,
        updates,
        queue,
        _sender: sender,
        budget,
    }
}

fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = value.len() + 4;
    bytes.extend_from_slice(&(length as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize((bytes.len() + 3) & !3, 0);
}

fn attributes_bytes(attributes: &[Attribute]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (kind, value) in attributes {
        attribute(&mut bytes, *kind, value);
    }
    bytes
}

fn integer(kind: u16, value: u32) -> Attribute {
    (kind, value.to_ne_bytes().to_vec())
}

fn xdp_fields(program: u32) -> Vec<Attribute> {
    vec![(2, vec![1]), integer(4, program), integer(5, program)]
}

fn link_with_xdp(ifindex: u32, attributes: &[Attribute], xdp: &[Attribute]) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[2..4].copy_from_slice(&1u16.to_ne_bytes());
    body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
    body[8..12].copy_from_slice(&0x10041u32.to_ne_bytes());
    body.extend_from_slice(&attributes_bytes(attributes));
    attribute(&mut body, 43 | 0x8000, &attributes_bytes(xdp));
    body
}

fn link(ifindex: u32, program: u32, attributes: &[Attribute]) -> Vec<u8> {
    link_with_xdp(ifindex, attributes, &xdp_fields(program))
}

fn message(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes[..4].copy_from_slice(&((body.len() + 16) as u32).to_ne_bytes());
    bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(body);
    bytes.resize((bytes.len() + 3) & !3, 0);
    bytes
}

fn own(ifindex: u32, program: u32) -> Vec<u8> {
    message(16, &link(ifindex, program, &configuration(false, 0)))
}

fn mib(schema: usize, counter: u64) -> Vec<u8> {
    let mut bytes = (schema as u64).to_ne_bytes().to_vec();
    for index in 1..schema {
        bytes.extend_from_slice(&counter.wrapping_add(index as u64).to_ne_bytes());
    }
    bytes
}

fn ipv6_attributes(counter: u64) -> Vec<Attribute> {
    vec![
        integer(1, 0x80),
        (2, vec![1, 2, 3, 4, 5, 6, 7, 8]),
        (3, mib(38, counter)),
        (4, vec![0; 16]),
        (5, vec![3; 16]),
        (6, mib(7, counter)),
        (7, vec![4; 16]),
        (8, vec![1]),
        integer(9, 1500),
        (100 | 0x8000, attributes_bytes(&[(101, vec![9, 8, 7])])),
    ]
}

fn af_spec(ipv6: &[Attribute]) -> Vec<u8> {
    attributes_bytes(&[
        (2 | 0x8000, attributes_bytes(&[(1, vec![1, 0, 0, 0])])),
        (10 | 0x8000, attributes_bytes(ipv6)),
        (45 | 0x8000, attributes_bytes(&[(1, vec![5, 6, 7])])),
    ])
}

fn configuration(recent: bool, counter: u64) -> Vec<Attribute> {
    let mut attributes = vec![
        (1, vec![0, 1, 2, 3, 4, 5]),
        (2, vec![255; 6]),
        (3, b"capture0\0".to_vec()),
        integer(4, 1500),
        integer(5, 0),
        (6, b"fq_codel\0".to_vec()),
        (7, vec![counter as u8; 96]),
        integer(10, 0),
        integer(13, 1000),
        (14, vec![0; 32]),
        (16, vec![6]),
        (17, vec![0]),
        (18 | 0x8000, attributes_bytes(&[(1, b"veth\0".to_vec())])),
        (20, b"owner\0".to_vec()),
        (23, vec![counter as u8; 200]),
        (26 | 0x8000, af_spec(&ipv6_attributes(counter))),
        integer(27, 0),
        integer(30, 0),
        integer(31, 2),
        integer(32, 2),
        (33, vec![1]),
        (34, vec![1, 2, 3, 4]),
        integer(35, 5),
        (36, vec![5, 6, 7, 8]),
        integer(37, u32::MAX),
        (38, b"p0\0".to_vec()),
        (39, vec![0]),
        integer(40, 64),
        integer(41, 65536),
        (42, Vec::new()),
        (42, Vec::new()),
        integer(47, 3),
        integer(48, 2),
        integer(50, 68),
        integer(51, 65535),
        (
            52 | 0x8000,
            attributes_bytes(&[
                (53, b"alt-capture0\0".to_vec()),
                (53, b"second-capture0\0".to_vec()),
            ]),
        ),
        (54, vec![0, 1, 2, 3, 4, 6]),
        (
            55 | 0x8000,
            attributes_bytes(&[integer(1, 1), integer(2, 0)]),
        ),
        (56, b"parent0\0".to_vec()),
        (57, b"pci\0".to_vec()),
        integer(58, 65536),
        integer(59, 65536),
        integer(60, 64),
        integer(61, 0),
        (62 | 0x8000, attributes_bytes(&[(1, vec![1, 2, 3, 4])])),
        integer(63, 65536),
        integer(64, 65536),
        (65 | 0x8000, attributes_bytes(&[(1, vec![4, 3, 2, 1])])),
        (1000, vec![7, 8, 9]),
        (1001 | 0x8000, attributes_bytes(&[(2, vec![1, 2, 3])])),
    ];
    if recent {
        attributes.extend([
            (66, 1_000_000u64.to_ne_bytes().to_vec()),
            (67, vec![1]),
            integer(68, 32),
            integer(69, 64),
        ]);
    }
    attributes
}

fn replace_attribute(attributes: &mut [Attribute], kind: u16, value: Vec<u8>) {
    attributes
        .iter_mut()
        .find(|(raw, _)| raw & 0x3fff == kind)
        .unwrap()
        .1 = value;
}

fn update(
    fixture: &Fixture,
    (ifindex, old, next): (u32, u32, u32),
    baseline: &[u8],
    notifications: Vec<Receive>,
    terminal: bool,
    transport: Result<(), XdpUpdateError>,
) -> NativeUpdateOutcome {
    let queue = fixture.queue.clone();
    fixture.updates.lock().update_with(
        ifindex,
        old,
        next,
        terminal,
        |projection| native_link_projection(baseline, ifindex, old, projection),
        || {
            queue.lock().unwrap().extend(notifications);
            transport
        },
    )
}

fn successful(outcome: NativeUpdateOutcome) {
    assert!(outcome.transport.is_ok(), "SETLINK must succeed");
    outcome.observation.unwrap();
}

fn assert_sticky(fixture: &mut Fixture) {
    assert!(fixture.updates.lock().invalidated);
    fixture.queue.lock().unwrap().clear();
    for _ in 0..3 {
        assert!(fixture.topology.check_changed().unwrap());
    }
    let called = AtomicBool::new(false);
    let baseline = link(2, 101, &configuration(false, 0));
    let outcome = fixture.updates.lock().update_with(
        2,
        101,
        102,
        false,
        |projection| native_link_projection(&baseline, 2, 101, projection),
        || {
            called.store(true, Ordering::SeqCst);
            Ok(())
        },
    );
    assert!(matches!(
        outcome.transport,
        Err(XdpUpdateError::NotAttempted(_))
    ));
    assert!(outcome.observation.is_err());
    assert!(!called.load(Ordering::SeqCst));
    assert!(fixture.topology.check_changed().unwrap());
}

fn rejects_event(baseline: &[u8], notification: Receive) {
    let mut fixture = fixture();
    let outcome = update(
        &fixture,
        (2, 101, 102),
        baseline,
        vec![notification],
        false,
        Ok(()),
    );
    assert!(outcome.transport.is_ok());
    assert!(outcome.observation.is_err());
    assert_eq!(fixture.updates.consumed_operations(), 0);
    assert_sticky(&mut fixture);
}

#[test]
fn u1_repeated_real_transactions_consume_one_event_and_retain_no_credit() {
    let mut fixture = fixture();
    for (operation, (old, next)) in [(101, 102), (102, 205), (205, 309)].into_iter().enumerate() {
        let baseline = link(2, old, &configuration(false, 0));
        successful(update(
            &fixture,
            (2, old, next),
            &baseline,
            vec![own(2, next).into()],
            false,
            Ok(()),
        ));
        assert_eq!(fixture.updates.consumed_operations(), operation + 1);
        let watch = fixture.updates.lock();
        assert!(watch.baseline.is_empty());
        assert!(watch.observed.is_empty());
        assert!(!watch.invalidated);
        drop(watch);
        assert!(fixture.queue.lock().unwrap().is_empty());
        for _ in 0..3 {
            assert!(!fixture.topology.check_changed().unwrap());
        }
    }
    fixture.queue.lock().unwrap().push_back(own(2, 309).into());
    assert!(fixture.topology.check_changed().is_err());
    assert_eq!(fixture.updates.consumed_operations(), 3);
    assert_sticky(&mut fixture);
}

#[derive(Clone, Copy, Debug)]
enum Foreign {
    Promiscuous,
    AdministrativeDown,
    Mtu,
    Address { family: u8, delete: bool },
    Route { family: u8, delete: bool },
    Rule { family: u8, delete: bool },
    Xdp,
}

fn foreign(kind: Foreign, ifindex: u32) -> Vec<u8> {
    let mut attributes = configuration(false, 0);
    match kind {
        Foreign::Promiscuous | Foreign::AdministrativeDown => {
            let mut body = link(ifindex, 102, &attributes);
            let flags = if matches!(kind, Foreign::Promiscuous) {
                0x10141u32
            } else {
                0x10040
            };
            body[8..12].copy_from_slice(&flags.to_ne_bytes());
            message(16, &body)
        }
        Foreign::Mtu => {
            replace_attribute(&mut attributes, 4, 1400u32.to_ne_bytes().to_vec());
            message(16, &link(ifindex, 102, &attributes))
        }
        Foreign::Xdp => message(16, &link(ifindex, 999, &attributes)),
        Foreign::Address { family, delete } => {
            let mut body = vec![0; 8];
            body[0] = family;
            body[1] = if family == 2 { 32 } else { 128 };
            body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
            attribute(&mut body, 1, &vec![1; if family == 2 { 4 } else { 16 }]);
            message(if delete { 21 } else { 20 }, &body)
        }
        Foreign::Route { family, delete } | Foreign::Rule { family, delete } => {
            let mut body = vec![0; 12];
            body[0] = family;
            body[4] = 200;
            let rule = matches!(kind, Foreign::Rule { .. });
            body[7] = 1;
            attribute(&mut body, if rule { 6 } else { 4 }, &ifindex.to_ne_bytes());
            message(
                if rule {
                    if delete { 33 } else { 32 }
                } else if delete {
                    25
                } else {
                    24
                },
                &body,
            )
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Timing {
    BeforePrecheck,
    DuringQuery,
    ArmedBeforeOwn,
    ArmedInsteadOfOwn,
    AfterOwn,
    AfterAck,
}

#[test]
fn u2_foreign_kind_location_and_timing_table_stays_sticky_after_revert() {
    let mut kinds = vec![
        Foreign::Promiscuous,
        Foreign::AdministrativeDown,
        Foreign::Mtu,
        Foreign::Xdp,
    ];
    for family in [2, 10] {
        for delete in [false, true] {
            kinds.extend([
                Foreign::Address { family, delete },
                Foreign::Route { family, delete },
                Foreign::Rule { family, delete },
            ]);
        }
    }
    for kind in kinds {
        for ifindex in [2, 3, 9] {
            for timing in [
                Timing::BeforePrecheck,
                Timing::DuringQuery,
                Timing::ArmedBeforeOwn,
                Timing::ArmedInsteadOfOwn,
                Timing::AfterOwn,
                Timing::AfterAck,
            ] {
                let mut fixture = fixture();
                let notification = foreign(kind, ifindex);
                let baseline = link(2, 101, &configuration(false, 0));
                if matches!(timing, Timing::BeforePrecheck) {
                    fixture
                        .queue
                        .lock()
                        .unwrap()
                        .push_back(notification.clone().into());
                }
                if matches!(timing, Timing::ArmedBeforeOwn) {
                    let queue = fixture.queue.clone();
                    let event = notification.clone();
                    fixture
                        .updates
                        .before_next_setter(move || queue.lock().unwrap().push_back(event.into()));
                }
                let query_queue = fixture.queue.clone();
                let setter_queue = fixture.queue.clone();
                let setter_called = AtomicBool::new(false);
                let outcome = fixture.updates.lock().update_with(
                    2,
                    101,
                    102,
                    false,
                    |projection| {
                        native_link_projection(&baseline, 2, 101, projection)?;
                        if matches!(timing, Timing::DuringQuery) {
                            query_queue
                                .lock()
                                .unwrap()
                                .push_back(notification.clone().into());
                        }
                        Ok(())
                    },
                    || {
                        setter_called.store(true, Ordering::SeqCst);
                        let mut queue = setter_queue.lock().unwrap();
                        if matches!(timing, Timing::ArmedInsteadOfOwn) {
                            queue.push_back(notification.clone().into());
                        } else {
                            queue.push_back(own(2, 102).into());
                            if matches!(timing, Timing::AfterOwn) {
                                queue.push_back(notification.clone().into());
                            }
                        }
                        Ok(())
                    },
                );
                if matches!(timing, Timing::AfterAck) {
                    successful(outcome);
                    fixture.queue.lock().unwrap().push_back(notification.into());
                    assert!(
                        fixture.topology.check_changed().is_err(),
                        "{kind:?} {ifindex} {timing:?}"
                    );
                } else {
                    assert!(
                        outcome.observation.is_err(),
                        "{kind:?} {ifindex} {timing:?}"
                    );
                    assert_eq!(
                        setter_called.load(Ordering::SeqCst),
                        !matches!(timing, Timing::BeforePrecheck | Timing::DuringQuery)
                    );
                }
                assert_sticky(&mut fixture);
            }
        }
    }
}

#[test]
fn u3_identity_and_unsolicited_historical_replays_are_never_credits() {
    let baseline = link(2, 101, &configuration(false, 0));
    for notification in [own(3, 102), own(2, 101), own(2, 999), own(3, 302)] {
        rejects_event(&baseline, notification.into());
    }
    for program in [101, 102, 205] {
        let mut fixture = fixture();
        fixture
            .queue
            .lock()
            .unwrap()
            .push_back(own(2, program).into());
        assert!(fixture.topology.check_changed().is_err());
        assert_sticky(&mut fixture);
    }
    for (ifindex, old, next) in [(0, 101, 102), (2, 0, 102), (2, 101, 0)] {
        let mut fixture = fixture();
        let called = AtomicBool::new(false);
        let outcome = fixture.updates.lock().update_with(
            ifindex,
            old,
            next,
            false,
            |projection| native_link_projection(&baseline, ifindex, old, projection),
            || {
                called.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(outcome.transport.is_err());
        assert!(outcome.observation.is_err());
        assert!(!called.load(Ordering::SeqCst));
        assert_sticky(&mut fixture);
    }
    let mut fixture = fixture();
    successful(update(
        &fixture,
        (2, 101, 101),
        &baseline,
        vec![own(2, 101).into()],
        false,
        Ok(()),
    ));
    fixture.queue.lock().unwrap().push_back(own(2, 101).into());
    assert!(fixture.topology.check_changed().is_err());
    assert_sticky(&mut fixture);
}

#[test]
fn u3_duplicate_and_every_same_datagram_suffix_are_processed() {
    let baseline = link(2, 101, &configuration(false, 0));
    let exact = own(2, 102);
    let mut fixture = fixture();
    let outcome = update(
        &fixture,
        (2, 101, 102),
        &baseline,
        vec![exact.clone().into(), exact.clone().into()],
        false,
        Ok(()),
    );
    assert!(outcome.transport.is_ok());
    assert!(outcome.observation.is_err());
    assert_sticky(&mut fixture);
    let mut suffixes = vec![
        exact.clone(),
        foreign(Foreign::Mtu, 2),
        message(4, &[]),
        message(2, &[0; 20]),
    ];
    for length in 1..16 {
        suffixes.push(vec![0; length]);
    }
    for suffix in suffixes {
        let mut datagram = exact.clone();
        datagram.extend_from_slice(&suffix);
        rejects_event(&baseline, datagram.into());
    }
}

#[test]
fn u3_generic_header_shape_and_every_short_extent_fail_closed() {
    let baseline = link(2, 101, &configuration(false, 0));
    let exact = own(2, 102);
    for offset in 6..16 {
        let mut changed = exact.clone();
        changed[offset] = 1;
        rejects_event(&baseline, changed.into());
    }
    for offset in [
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ] {
        let mut changed = exact.clone();
        changed[offset] ^= 1;
        rejects_event(&baseline, changed.into());
    }
    for kind in [0, 1, 2, 3, 4, 17, 18, 20, 24, 32] {
        rejects_event(&baseline, message(kind, &exact[16..]).into());
    }
    for length in 0..exact.len() {
        rejects_event(&baseline, exact[..length].to_vec().into());
    }
    for length in [0u32, 1, 15, 16, (exact.len() + 1) as u32, u32::MAX] {
        let mut changed = exact.clone();
        changed[..4].copy_from_slice(&length.to_ne_bytes());
        rejects_event(&baseline, changed.into());
    }
    for body_length in 0..16 {
        rejects_event(&baseline, message(16, &vec![0; body_length]).into());
    }
    for trailing in [
        vec![1],
        vec![1, 0],
        vec![1, 0, 1],
        vec![3, 0, 1, 0],
        vec![8, 0, 1, 0, 1],
    ] {
        let mut body = link(2, 102, &configuration(false, 0));
        body.extend_from_slice(&trailing);
        rejects_event(&baseline, message(16, &body).into());
    }
    // A nonfinal unaligned extent cannot borrow alignment bytes from a suffix.
    for padding in 1..3 {
        let mut changed = message(16, &link(2, 102, &configuration(false, 0)));
        changed.push(1);
        let length = changed.len() as u32;
        changed[..4].copy_from_slice(&length.to_ne_bytes());
        changed.extend(vec![0; padding]);
        rejects_event(&baseline, changed.into());
    }
}

#[test]
fn u3_xdp_singletons_modes_ids_and_nested_extents_are_strict() {
    let attributes = configuration(false, 0);
    let baseline = link(2, 101, &attributes);
    let valid = xdp_fields(102);
    let mut variants = Vec::new();
    for index in 0..valid.len() {
        let mut missing = valid.clone();
        missing.remove(index);
        variants.push(missing);
        let mut duplicate = valid.clone();
        duplicate.push(valid[index].clone());
        variants.push(duplicate);
        for length in [0, 2, 3, 5] {
            if length != valid[index].1.len() {
                let mut changed = valid.clone();
                changed[index].1.resize(length, 0);
                variants.push(changed);
            }
        }
    }
    for kind in [0, 1, 3, 8, 9, 99, 2 | 0x8000, 4 | 0x4000] {
        let mut changed = valid.clone();
        changed.push(integer(kind, 0));
        variants.push(changed);
    }
    for mode in [0, 2, 3, 4, 255] {
        let mut changed = valid.clone();
        changed[0].1[0] = mode;
        variants.push(changed);
    }
    for kind in [4, 5, 6, 7] {
        let mut changed = valid.clone();
        if let Some(field) = changed.iter_mut().find(|field| field.0 == kind) {
            field.1 = 999u32.to_ne_bytes().to_vec();
        } else {
            changed.push(integer(kind, 999));
        }
        variants.push(changed);
    }
    for fields in variants {
        rejects_event(
            &baseline,
            message(16, &link_with_xdp(2, &attributes, &fields)).into(),
        );
    }
    for length in 0..attributes_bytes(&valid).len() {
        let mut body = vec![0; 16];
        body[2..4].copy_from_slice(&1u16.to_ne_bytes());
        body[4..8].copy_from_slice(&2u32.to_ne_bytes());
        body[8..12].copy_from_slice(&0x10041u32.to_ne_bytes());
        body.extend_from_slice(&attributes_bytes(&attributes));
        attribute(&mut body, 43 | 0x8000, &attributes_bytes(&valid)[..length]);
        rejects_event(&baseline, message(16, &body).into());
    }
    let mut missing = link(2, 102, &attributes);
    missing.truncate(missing.len() - 28);
    rejects_event(&baseline, message(16, &missing).into());
    let mut duplicate = link(2, 102, &attributes);
    attribute(&mut duplicate, 43 | 0x8000, &attributes_bytes(&valid));
    rejects_event(&baseline, message(16, &duplicate).into());
}

#[test]
fn u3_raw_receive_source_family_extent_and_truncation_are_validated_in_production() {
    let baseline = link(2, 101, &configuration(false, 0));
    for mutation in 0..8 {
        let Receive::Datagram(mut datagram) = Receive::from(own(2, 102)) else {
            unreachable!()
        };
        match mutation {
            0 => datagram.source_port = 42,
            1 => datagram.source_family = libc::AF_UNIX as libc::sa_family_t,
            2 => datagram.source_extent = 0,
            3 => datagram.source_extent -= 1,
            4 => datagram.source_extent += 1,
            5 => datagram.length = 0,
            6 => {
                datagram.bytes.resize(NATIVE_LINK_CAPACITY + 1, 0);
                datagram.length = datagram.bytes.len();
            }
            _ => datagram.length = usize::MAX,
        }
        rejects_event(&baseline, Receive::Datagram(datagram));
    }
}

#[test]
fn u4_successful_ack_missing_notification_fails_without_late_credit() {
    let mut fixture = fixture();
    let baseline = link(2, 101, &configuration(false, 0));
    let outcome = update(
        &fixture,
        (2, 101, 102),
        &baseline,
        Vec::new(),
        false,
        Ok(()),
    );
    assert!(outcome.transport.is_ok());
    assert!(outcome.observation.is_err());
    assert_eq!(fixture.updates.consumed_operations(), 0);
    fixture.queue.lock().unwrap().push_back(own(2, 102).into());
    assert!(fixture.topology.check_changed().unwrap());
    assert_sticky(&mut fixture);
}

#[test]
fn u4_rejected_ack_is_distinct_from_observation_failure_and_leaves_no_credit() {
    let mut fixture = fixture();
    let baseline = link(2, 101, &configuration(false, 0));
    let outcome = update(
        &fixture,
        (2, 101, 102),
        &baseline,
        Vec::new(),
        false,
        Err(XdpUpdateError::Rejected(io::Error::from_raw_os_error(
            libc::EEXIST,
        ))),
    );
    assert!(matches!(&outcome.transport,
        Err(XdpUpdateError::Rejected(error)) if error.raw_os_error() == Some(libc::EEXIST)));
    outcome.observation.unwrap();
    assert_eq!(fixture.updates.consumed_operations(), 0);
    assert!(!fixture.topology.check_changed().unwrap());
    successful(update(
        &fixture,
        (2, 101, 205),
        &baseline,
        vec![own(2, 205).into()],
        false,
        Ok(()),
    ));
    assert_eq!(fixture.updates.consumed_operations(), 1);
    fixture.queue.lock().unwrap().push_back(own(2, 102).into());
    assert!(fixture.topology.check_changed().is_err());
    assert_sticky(&mut fixture);

    for event in [own(2, 102), foreign(Foreign::Mtu, 2)] {
        let mut fixture = self::fixture();
        let outcome = update(
            &fixture,
            (2, 101, 102),
            &baseline,
            vec![event.into()],
            false,
            Err(XdpUpdateError::Rejected(io::Error::from_raw_os_error(
                libc::EPERM,
            ))),
        );
        assert!(matches!(
            outcome.transport,
            Err(XdpUpdateError::Rejected(_))
        ));
        assert!(outcome.observation.is_err());
        assert_sticky(&mut fixture);
    }
}

#[test]
fn u4_uncertain_ack_is_preserved_and_never_authorizes_a_later_event() {
    let baseline = link(2, 101, &configuration(false, 0));
    for notifications in [Vec::new(), vec![own(2, 102).into()]] {
        let mut fixture = fixture();
        let outcome = update(
            &fixture,
            (2, 101, 102),
            &baseline,
            notifications,
            false,
            Err(XdpUpdateError::Uncertain(io::Error::new(
                io::ErrorKind::TimedOut,
                "missing ACK",
            ))),
        );
        assert!(matches!(&outcome.transport,
            Err(XdpUpdateError::Uncertain(error)) if error.kind() == io::ErrorKind::TimedOut));
        assert!(outcome.observation.is_err());
        assert_eq!(fixture.updates.consumed_operations(), 0);
        fixture.queue.lock().unwrap().push_back(own(2, 102).into());
        assert!(fixture.topology.check_changed().unwrap());
        assert_sticky(&mut fixture);
    }
}

#[test]
fn u4_receive_loss_and_errors_defeat_even_an_exact_match() {
    let baseline = link(2, 101, &configuration(false, 0));
    for error in [libc::ENOBUFS, libc::EIO, libc::ECONNRESET] {
        for after_match in [false, true] {
            let mut fixture = fixture();
            let mut notifications = vec![Receive::Error(error)];
            if after_match {
                notifications.insert(0, own(2, 102).into());
            } else {
                notifications.push(own(2, 102).into());
            }
            let outcome = update(
                &fixture,
                (2, 101, 102),
                &baseline,
                notifications,
                false,
                Ok(()),
            );
            assert!(outcome.transport.is_ok());
            assert_eq!(outcome.observation.unwrap_err().raw_os_error(), Some(error));
            assert_sticky(&mut fixture);
        }
        let mut fixture = fixture();
        fixture
            .queue
            .lock()
            .unwrap()
            .push_back(Receive::Error(error));
        assert_eq!(
            fixture.topology.check_changed().unwrap_err().raw_os_error(),
            Some(error)
        );
        assert_sticky(&mut fixture);
    }
}

#[test]
fn u4_eintr_retries_each_drain_without_spending_extra_credit() {
    let mut fixture = fixture();
    fixture
        .queue
        .lock()
        .unwrap()
        .extend([Receive::Error(libc::EINTR), Receive::Error(libc::EINTR)]);
    let query_queue = fixture.queue.clone();
    let setter_queue = fixture.queue.clone();
    let baseline = link(2, 101, &configuration(false, 0));
    successful(fixture.updates.lock().update_with(
        2,
        101,
        102,
        false,
        |projection| {
            native_link_projection(&baseline, 2, 101, projection)?;
            query_queue
                .lock()
                .unwrap()
                .push_back(Receive::Error(libc::EINTR));
            Ok(())
        },
        || {
            setter_queue.lock().unwrap().extend([
                Receive::Error(libc::EINTR),
                own(2, 102).into(),
                Receive::Error(libc::EINTR),
            ]);
            Ok(())
        },
    ));
    assert_eq!(fixture.updates.consumed_operations(), 1);
    fixture
        .queue
        .lock()
        .unwrap()
        .push_back(Receive::Error(libc::EINTR));
    assert!(!fixture.topology.check_changed().unwrap());
    fixture.queue.lock().unwrap().push_back(own(2, 102).into());
    assert!(fixture.topology.check_changed().is_err());
    assert_sticky(&mut fixture);
}

#[derive(Clone, Copy, Debug)]
enum GuardFailure {
    Predrain,
    QueryIdentity,
    QueryIo,
    DuringQuery,
    AlreadySticky,
    PostAckMissing,
    PostAckLoss,
    PostAckMalformed,
}

fn terminal_update(
    fixture: &Fixture,
    failure: GuardFailure,
    called: &AtomicUsize,
) -> NativeUpdateOutcome {
    let mut watch = fixture.updates.lock();
    if matches!(failure, GuardFailure::Predrain) {
        fixture
            .queue
            .lock()
            .unwrap()
            .push_back(foreign(Foreign::Mtu, 2).into());
    }
    if matches!(failure, GuardFailure::AlreadySticky) {
        watch.invalidated = true;
    }
    let baseline = link(
        2,
        if matches!(failure, GuardFailure::QueryIdentity) {
            999
        } else {
            101
        },
        &configuration(false, 0),
    );
    let query_queue = fixture.queue.clone();
    let setter_queue = fixture.queue.clone();
    watch.update_with(
        2,
        101,
        1,
        true,
        |projection| {
            native_link_projection(&baseline, 2, 101, projection)?;
            if matches!(failure, GuardFailure::QueryIo) {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            if matches!(failure, GuardFailure::DuringQuery) {
                query_queue
                    .lock()
                    .unwrap()
                    .push_back(foreign(Foreign::Mtu, 2).into());
            }
            Ok(())
        },
        || {
            called.fetch_add(1, Ordering::SeqCst);
            let mut queue = setter_queue.lock().unwrap();
            match failure {
                GuardFailure::PostAckMissing => {}
                GuardFailure::PostAckLoss => {
                    queue.extend([own(2, 1).into(), Receive::Error(libc::ENOBUFS)])
                }
                GuardFailure::PostAckMalformed => queue.push_back(vec![0; 7].into()),
                _ => queue.push_back(own(2, 1).into()),
            }
            Ok(())
        },
    )
}

#[test]
fn u4_terminal_guard_is_always_attempted_and_ack_success_survives_observer_failure() {
    for failure in [
        GuardFailure::Predrain,
        GuardFailure::QueryIdentity,
        GuardFailure::QueryIo,
        GuardFailure::DuringQuery,
        GuardFailure::AlreadySticky,
        GuardFailure::PostAckMissing,
        GuardFailure::PostAckLoss,
        GuardFailure::PostAckMalformed,
    ] {
        let mut fixture = fixture();
        let called = AtomicUsize::new(0);
        let outcome = terminal_update(&fixture, failure, &called);
        assert_eq!(called.load(Ordering::SeqCst), 1, "{failure:?}");
        assert!(outcome.transport.is_ok(), "{failure:?}");
        assert!(outcome.observation.is_err(), "{failure:?}");
        assert_eq!(fixture.updates.consumed_operations(), 0);
        assert_sticky(&mut fixture);
    }
}

#[test]
fn u4_terminal_guard_preserves_transport_and_precheck_errors_independently() {
    for uncertain in [false, true] {
        let mut fixture = fixture();
        fixture
            .queue
            .lock()
            .unwrap()
            .push_back(Receive::Error(libc::ENOBUFS));
        let baseline = link(2, 101, &configuration(false, 0));
        let transport = if uncertain {
            XdpUpdateError::Uncertain(io::Error::from_raw_os_error(libc::EIO))
        } else {
            XdpUpdateError::Rejected(io::Error::from_raw_os_error(libc::EPERM))
        };
        let outcome = update(
            &fixture,
            (2, 101, 1),
            &baseline,
            Vec::new(),
            true,
            Err(transport),
        );
        if uncertain {
            assert!(matches!(&outcome.transport,
                Err(XdpUpdateError::Uncertain(error)) if error.raw_os_error() == Some(libc::EIO)));
        } else {
            assert!(matches!(&outcome.transport,
                Err(XdpUpdateError::Rejected(error)) if error.raw_os_error() == Some(libc::EPERM)));
        }
        assert_eq!(
            outcome.observation.unwrap_err().raw_os_error(),
            Some(libc::ENOBUFS)
        );
        assert_sticky(&mut fixture);
    }
}

#[test]
fn u5_check_changed_waits_for_the_whole_transaction_and_sees_its_classification() {
    for fail_observation in [false, true] {
        let fixture = fixture();
        let updates = fixture.updates.clone();
        let queue = fixture.queue.clone();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let setter_entered = entered.clone();
        let setter_release = release.clone();
        let publisher = thread::spawn(move || {
            let baseline = link(2, 101, &configuration(false, 0));
            updates.lock().update_with(
                2,
                101,
                102,
                false,
                |projection| native_link_projection(&baseline, 2, 101, projection),
                || {
                    queue.lock().unwrap().push_back(own(2, 102).into());
                    setter_entered.wait();
                    setter_release.wait();
                    if fail_observation {
                        queue
                            .lock()
                            .unwrap()
                            .push_back(Receive::Error(libc::ENOBUFS));
                    }
                    Ok(())
                },
            )
        });
        entered.wait();
        let (checking_tx, checking_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let check_updates = fixture.updates.clone();
        let mut topology = fixture.topology;
        let checker = thread::spawn(move || {
            assert!(matches!(
                check_updates.0.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            checking_tx.send(()).unwrap();
            let changed = topology.check_changed();
            finished_tx.send(changed).unwrap();
            topology
        });
        checking_rx.recv().unwrap();
        assert!(matches!(
            finished_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release.wait();
        let outcome = publisher.join().unwrap();
        assert!(outcome.transport.is_ok());
        assert_eq!(outcome.observation.is_err(), fail_observation);
        assert_eq!(finished_rx.recv().unwrap().unwrap(), fail_observation);
        let mut topology = checker.join().unwrap();
        assert_eq!(topology.check_changed().unwrap(), fail_observation);
        assert_eq!(
            fixture.updates.consumed_operations(),
            usize::from(!fail_observation)
        );
    }
}

#[test]
fn u5_two_device_updates_share_one_lock_through_query_ack_and_drain() {
    let mut fixture = fixture();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let first_complete = Arc::new(AtomicBool::new(false));
    let second_setter = Arc::new(AtomicBool::new(false));
    let first_updates = fixture.updates.clone();
    let first_queue = fixture.queue.clone();
    let setter_entered = entered.clone();
    let setter_release = release.clone();
    let complete = first_complete.clone();
    let first = thread::spawn(move || {
        let baseline = link(2, 101, &configuration(false, 0));
        let mut watch = first_updates.lock();
        successful(watch.update_with(
            2,
            101,
            102,
            false,
            |projection| native_link_projection(&baseline, 2, 101, projection),
            || {
                first_queue.lock().unwrap().push_back(own(2, 102).into());
                setter_entered.wait();
                setter_release.wait();
                Ok(())
            },
        ));
        complete.store(true, Ordering::SeqCst);
    });
    entered.wait();
    let (attempted_tx, attempted_rx) = mpsc::channel();
    let second_updates = fixture.updates.clone();
    let second_queue = fixture.queue.clone();
    let complete = first_complete.clone();
    let called = second_setter.clone();
    let second = thread::spawn(move || {
        assert!(matches!(
            second_updates.0.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        attempted_tx.send(()).unwrap();
        let baseline = link(3, 301, &configuration(false, 0));
        successful(second_updates.lock().update_with(
            3,
            301,
            302,
            false,
            |projection| {
                assert!(complete.load(Ordering::SeqCst));
                native_link_projection(&baseline, 3, 301, projection)
            },
            || {
                assert!(complete.load(Ordering::SeqCst));
                called.store(true, Ordering::SeqCst);
                second_queue.lock().unwrap().push_back(own(3, 302).into());
                Ok(())
            },
        ));
    });
    attempted_rx.recv().unwrap();
    assert!(!second_setter.load(Ordering::SeqCst));
    release.wait();
    first.join().unwrap();
    second.join().unwrap();
    assert_eq!(fixture.updates.consumed_operations(), 2);
    assert!(fixture.queue.lock().unwrap().is_empty());
    assert!(!fixture.topology.check_changed().unwrap());
    fixture.queue.lock().unwrap().push_back(own(3, 302).into());
    assert!(fixture.topology.check_changed().is_err());
    assert_sticky(&mut fixture);
}

#[test]
fn u5_close_publish_orders_keep_sticky_refusal_and_terminal_guard_progress() {
    for close_first in [false, true] {
        for failure in [
            GuardFailure::Predrain,
            GuardFailure::QueryIdentity,
            GuardFailure::AlreadySticky,
            GuardFailure::PostAckLoss,
        ] {
            let mut fixture = fixture();
            let entered = Arc::new(Barrier::new(2));
            let release = Arc::new(Barrier::new(2));
            let arrived = entered.clone();
            let proceed = release.clone();
            fixture.updates.before_next_setter(move || {
                arrived.wait();
                proceed.wait();
            });
            let (topology, sender) = strict_topology();
            let first_fixture = Fixture {
                topology,
                updates: fixture.updates.clone(),
                queue: fixture.queue.clone(),
                _sender: sender,
                budget: fixture.budget.clone(),
            };
            let first = thread::spawn(move || {
                if close_first {
                    let attempts = AtomicUsize::new(0);
                    let outcome = terminal_update(&first_fixture, failure, &attempts);
                    assert_eq!(attempts.load(Ordering::SeqCst), 1);
                    assert!(outcome.transport.is_ok());
                    assert!(outcome.observation.is_err());
                } else {
                    let baseline = link(2, 101, &configuration(false, 0));
                    successful(update(
                        &first_fixture,
                        (2, 101, 102),
                        &baseline,
                        vec![own(2, 102).into()],
                        false,
                        Ok(()),
                    ));
                }
            });
            entered.wait();
            let (attempted_tx, attempted_rx) = mpsc::channel();
            let updates = fixture.updates.clone();
            let queue = fixture.queue.clone();
            let budget = fixture.budget.clone();
            let second = thread::spawn(move || {
                assert!(matches!(
                    updates.0.try_lock(),
                    Err(std::sync::TryLockError::WouldBlock)
                ));
                attempted_tx.send(()).unwrap();
                let (topology, sender) = strict_topology();
                let fixture = Fixture {
                    topology,
                    updates,
                    queue,
                    _sender: sender,
                    budget,
                };
                if close_first {
                    let baseline = link(2, 1, &configuration(false, 0));
                    let outcome = update(
                        &fixture,
                        (2, 1, 102),
                        &baseline,
                        vec![own(2, 102).into()],
                        false,
                        Ok(()),
                    );
                    assert!(matches!(
                        outcome.transport,
                        Err(XdpUpdateError::NotAttempted(_))
                    ));
                    assert!(outcome.observation.is_err());
                    assert!(fixture.queue.lock().unwrap().is_empty());
                } else {
                    let attempts = AtomicUsize::new(0);
                    let outcome = terminal_update(&fixture, failure, &attempts);
                    assert_eq!(attempts.load(Ordering::SeqCst), 1);
                    assert!(outcome.transport.is_ok());
                    assert!(outcome.observation.is_err());
                }
            });
            attempted_rx.recv().unwrap();
            release.wait();
            first.join().unwrap();
            second.join().unwrap();
            assert_sticky(&mut fixture);
        }
    }
}

fn rejects_configuration(attributes: &[Attribute]) {
    let mut fixture = fixture();
    let baseline = link(2, 101, attributes);
    let event = message(16, &link(2, 102, attributes));
    let called = AtomicBool::new(false);
    let queue = fixture.queue.clone();
    let outcome = fixture.updates.lock().update_with(
        2,
        101,
        102,
        false,
        |projection| native_link_projection(&baseline, 2, 101, projection),
        || {
            called.store(true, Ordering::SeqCst);
            queue.lock().unwrap().push_back(event.into());
            Ok(())
        },
    );
    assert!(matches!(
        outcome.transport,
        Err(XdpUpdateError::NotAttempted(_))
    ));
    assert!(outcome.observation.is_err());
    assert!(!called.load(Ordering::SeqCst));
    assert_sticky(&mut fixture);
}

#[test]
fn u6_both_serializer_shapes_normalize_only_four_counter_payloads_and_padding() {
    for recent in [false, true] {
        let mut fixture = fixture();
        let baseline_attributes = configuration(recent, 0);
        let mut event_attributes = configuration(recent, 233);
        event_attributes.retain(|(kind, _)| *kind != 42);
        event_attributes.push((42, Vec::new()));
        event_attributes.push((42, Vec::new()));
        event_attributes.push((42, Vec::new()));
        let baseline = link(2, 101, &baseline_attributes);
        let mut event = message(16, &link(2, 102, &event_attributes));
        let xdp_start = event.len() - 28;
        event[xdp_start + 9..xdp_start + 12].fill(0xa5);
        successful(update(
            &fixture,
            (2, 101, 102),
            &baseline,
            vec![event.into()],
            false,
            Ok(()),
        ));
        assert_eq!(fixture.updates.consumed_operations(), 1);
        assert!(!fixture.topology.check_changed().unwrap());
    }
}

#[test]
fn u6_every_nonstatistical_attribute_retains_payload_presence_and_raw_type() {
    for recent in [false, true] {
        let attributes = configuration(recent, 0);
        let baseline = link(2, 101, &attributes);
        for index in 0..attributes.len() {
            let (raw_kind, value) = &attributes[index];
            let kind = raw_kind & 0x3fff;
            if matches!(kind, 7 | 23 | 26 | 42) {
                continue;
            }
            let mut changed = attributes.clone();
            changed[index].1[if raw_kind & 0x8000 != 0 { 4 } else { 0 }] ^= 1;
            rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
            let mut missing = attributes.clone();
            missing.remove(index);
            rejects_event(&baseline, message(16, &link(2, 102, &missing)).into());
            let mut changed_type = attributes.clone();
            changed_type[index].0 ^= 0x4000;
            rejects_event(&baseline, message(16, &link(2, 102, &changed_type)).into());
            assert!(!value.is_empty(), "non-PAD configuration payload {kind}");
        }
        for kind in [7, 23, 26] {
            let mut missing = attributes.clone();
            missing.retain(|(raw, _)| raw & 0x3fff != kind);
            rejects_event(&baseline, message(16, &link(2, 102, &missing)).into());
            let missing_baseline = link(2, 101, &missing);
            rejects_event(
                &missing_baseline,
                message(16, &link(2, 102, &attributes)).into(),
            );
        }
        for added in [
            integer(44, 1),
            integer(2000, 1),
            (2001 | 0x8000, attributes_bytes(&[(1, vec![1])])),
        ] {
            let mut changed = attributes.clone();
            changed.push(added);
            rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
        }
    }
}

#[test]
fn u6_af_spec_preserves_every_ipv6_nonstatistical_field_and_unknown_family() {
    let attributes = configuration(false, 0);
    let baseline = link(2, 101, &attributes);
    let ipv6 = ipv6_attributes(0);
    for index in 0..ipv6.len() {
        if matches!(ipv6[index].0, 3 | 6) {
            continue;
        }
        let mut changed_ipv6 = ipv6.clone();
        let offset = if changed_ipv6[index].0 & 0x8000 != 0 {
            4
        } else {
            0
        };
        changed_ipv6[index].1[offset] ^= 1;
        let mut changed = attributes.clone();
        replace_attribute(&mut changed, 26, af_spec(&changed_ipv6));
        rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
        let mut missing_ipv6 = ipv6.clone();
        missing_ipv6.remove(index);
        replace_attribute(&mut changed, 26, af_spec(&missing_ipv6));
        rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
    }
    for family in [2, 10, 45] {
        let mut families = vec![
            (2 | 0x8000, attributes_bytes(&[(1, vec![1, 0, 0, 0])])),
            (10 | 0x8000, attributes_bytes(&ipv6)),
            (45 | 0x8000, attributes_bytes(&[(1, vec![5, 6, 7])])),
        ];
        families.retain(|(raw, _)| raw & 0x3fff != family);
        let mut changed = attributes.clone();
        replace_attribute(&mut changed, 26, attributes_bytes(&families));
        rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
    }
    for family in [2, 45] {
        let families = vec![
            (
                2 | 0x8000,
                attributes_bytes(&[(1, vec![if family == 2 { 2 } else { 1 }, 0, 0, 0])]),
            ),
            (10 | 0x8000, attributes_bytes(&ipv6)),
            (
                45 | 0x8000,
                attributes_bytes(&[(1, vec![if family == 45 { 6 } else { 5 }, 6, 7])]),
            ),
        ];
        let mut changed = attributes.clone();
        replace_attribute(&mut changed, 26, attributes_bytes(&families));
        rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
    }
}

#[test]
fn u6_ipv6_mib_schema_words_and_exact_extents_are_not_traffic_counters() {
    let attributes = configuration(false, 0);
    let baseline = link(2, 101, &attributes);
    for (kind, schema) in [(3, 38usize), (6, 7usize)] {
        for word in [0, 1, schema as u64 - 1, schema as u64 + 1, 128, u64::MAX] {
            let mut ipv6 = ipv6_attributes(233);
            let field = ipv6.iter_mut().find(|field| field.0 == kind).unwrap();
            field.1[..8].copy_from_slice(&word.to_ne_bytes());
            let mut changed = attributes.clone();
            replace_attribute(&mut changed, 26, af_spec(&ipv6));
            rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
            rejects_configuration(&changed);
        }
        for length in [
            0,
            7,
            8,
            schema * 8 - 8,
            schema * 8 - 1,
            schema * 8 + 1,
            schema * 8 + 8,
        ] {
            let mut ipv6 = ipv6_attributes(233);
            ipv6.iter_mut()
                .find(|field| field.0 == kind)
                .unwrap()
                .1
                .resize(length, 0);
            let mut changed = attributes.clone();
            replace_attribute(&mut changed, 26, af_spec(&ipv6));
            rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
            rejects_configuration(&changed);
        }
        let mut ipv6 = ipv6_attributes(233);
        ipv6.retain(|field| field.0 != kind);
        let mut changed = attributes.clone();
        replace_attribute(&mut changed, 26, af_spec(&ipv6));
        rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
    }
    for (kind, extent) in [(7, 96usize), (23, 200usize)] {
        for length in [0, extent - 4, extent - 1, extent + 1, extent + 8] {
            let mut changed = attributes.clone();
            replace_attribute(&mut changed, kind, vec![7; length]);
            rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
            rejects_configuration(&changed);
        }
    }
}

#[test]
fn u6_repeated_pad_and_opaque_altname_lists_preserve_both_names_and_multiplicity() {
    let attributes = configuration(false, 0);
    let baseline = link(2, 101, &attributes);
    let original = vec![
        (53, b"alt-capture0\0".to_vec()),
        (53, b"second-capture0\0".to_vec()),
    ];
    let mut lists = Vec::new();
    for index in 0..2 {
        let mut changed = original.clone();
        changed[index].1[0] ^= 1;
        lists.push(changed);
        let mut missing = original.clone();
        missing.remove(index);
        lists.push(missing);
    }
    let mut duplicate = original.clone();
    duplicate.push(original[0].clone());
    lists.push(duplicate.clone());
    lists.push(Vec::new());
    for names in lists {
        let mut changed = attributes.clone();
        replace_attribute(&mut changed, 52, attributes_bytes(&names));
        rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
    }
    let mut repeated = attributes.clone();
    replace_attribute(&mut repeated, 52, attributes_bytes(&duplicate));
    let repeated_baseline = link(2, 101, &repeated);
    let mut fixture = fixture();
    successful(update(
        &fixture,
        (2, 101, 102),
        &repeated_baseline,
        vec![message(16, &link(2, 102, &repeated)).into()],
        false,
        Ok(()),
    ));
    assert!(!fixture.topology.check_changed().unwrap());
    for payload in [vec![0], vec![1], vec![0; 4]] {
        let mut changed = attributes.clone();
        changed.push((42, payload));
        rejects_event(&baseline, message(16, &link(2, 102, &changed)).into());
        rejects_configuration(&changed);
    }
}

#[test]
fn u6_singleton_duplicates_and_unknown_nested_extents_cannot_hide_in_the_baseline() {
    let attributes = configuration(false, 0);
    for field in attributes.iter().filter(|field| field.0 & 0x3fff != 42) {
        let mut duplicated = attributes.clone();
        duplicated.push(field.clone());
        rejects_configuration(&duplicated);
    }
    for kind in [1, 2, 3, 5, 6, 7, 8, 9] {
        let mut ipv6 = ipv6_attributes(0);
        let duplicate = ipv6.iter().find(|field| field.0 == kind).unwrap().clone();
        ipv6.push(duplicate);
        let mut changed = attributes.clone();
        replace_attribute(&mut changed, 26, af_spec(&ipv6));
        rejects_configuration(&changed);
    }
    for malformed in [
        vec![0],
        vec![0, 0],
        vec![0, 0, 0],
        vec![3, 0, 1, 0],
        vec![8, 0, 1, 0, 1],
        vec![4, 0, 1, 0, 1],
    ] {
        for location in 0..5 {
            let mut changed = attributes.clone();
            match location {
                0 => replace_attribute(&mut changed, 1001, malformed.clone()),
                1 => {
                    let mut ipv6 = ipv6_attributes(0);
                    replace_attribute(&mut ipv6, 100, malformed.clone());
                    replace_attribute(&mut changed, 26, af_spec(&ipv6));
                }
                2 => replace_attribute(
                    &mut changed,
                    26,
                    attributes_bytes(&[
                        (10 | 0x8000, attributes_bytes(&ipv6_attributes(0))),
                        (45 | 0x8000, malformed.clone()),
                    ]),
                ),
                3 => replace_attribute(
                    &mut changed,
                    26,
                    attributes_bytes(&[
                        (10 | 0x8000, attributes_bytes(&ipv6_attributes(0))),
                        (45, malformed.clone()),
                    ]),
                ),
                _ => replace_attribute(&mut changed, 52, malformed.clone()),
            }
            rejects_configuration(&changed);
        }
        let mut changed = attributes.clone();
        replace_attribute(&mut changed, 26, malformed.clone());
        rejects_configuration(&changed);
        replace_attribute(
            &mut changed,
            26,
            attributes_bytes(&[(10 | 0x8000, malformed)]),
        );
        rejects_configuration(&changed);
    }
}

#[test]
fn u6_strict_watchers_invalidate_on_exact_own_events_and_cannot_promote_sticky_authority() {
    let budget = MemoryBudget::new(1 << 20);
    for check_first in [false, true] {
        let (mut topology, sender) = strict_topology();
        sender.send(&own(2, 102)).unwrap();
        if check_first {
            assert!(topology.check_changed().unwrap());
        }
        assert!(topology.enable_native_xdp_updates(&budget).is_err());
        assert!(matches!(
            topology.watch,
            WatchState::Strict { invalidated: true }
        ));
        assert!(topology.check_changed().unwrap());
        assert_eq!(budget.used(), 0);
    }
    let (mut topology, _) = strict_topology();
    topology.watch = WatchState::Strict { invalidated: true };
    assert!(topology.enable_native_xdp_updates(&budget).is_err());
    assert!(topology.check_changed().unwrap());
}

#[test]
fn u6_native_promotion_retains_descriptor_queue_and_budget_until_the_last_handle() {
    let (mut topology, sender) = strict_topology();
    let original_fd = topology.as_raw_fd();
    let budget = MemoryBudget::new(1 << 20);
    let updates = topology.enable_native_xdp_updates(&budget).unwrap();
    let charge = budget.used();
    assert!(charge >= 3 * NATIVE_LINK_CAPACITY);
    assert_eq!(topology.as_raw_fd(), original_fd);
    assert_ne!(updates.lock().fd.as_raw_fd(), original_fd);
    assert!(topology.enable_native_xdp_updates(&budget).is_err());
    assert_eq!(budget.used(), charge);
    sender.send(&own(2, 102)).unwrap();
    // An AF_UNIX sender also exercises the real receive boundary's refusal.
    assert!(topology.check_changed().is_err());
    assert!(updates.lock().invalidated);
    drop(topology);
    assert_eq!(budget.used(), charge);
    let last = updates.clone();
    drop(updates);
    assert_eq!(budget.used(), charge);
    drop(last);
    assert_eq!(budget.used(), 0);

    let (mut topology, _) = strict_topology();
    let insufficient = MemoryBudget::new(3 * NATIVE_LINK_CAPACITY - 1);
    assert!(topology.enable_native_xdp_updates(&insufficient).is_err());
    assert!(matches!(
        topology.watch,
        WatchState::Strict { invalidated: false }
    ));
    assert_eq!(insufficient.used(), 0);
}

#[test]
fn u3_message_and_attribute_alignment_extents_cannot_borrow_missing_padding() {
    let mut baseline = link(2, 101, &configuration(false, 0));
    baseline.extend_from_slice(&[5, 0, 0xb8, 0x0b, 7]);
    let mut event_body = link(2, 102, &configuration(false, 0));
    event_body.extend_from_slice(&[5, 0, 0xb8, 0x0b, 7]);
    let complete = message(16, &event_body);
    let fixture = fixture();
    successful(update(
        &fixture,
        (2, 101, 102),
        &baseline,
        vec![complete.clone().into()],
        false,
        Ok(()),
    ));
    for missing in [1, 2] {
        rejects_event(
            &baseline,
            complete[..complete.len() - missing].to_vec().into(),
        );
    }
    for padding in [1, 2] {
        let mut incomplete = event_body.clone();
        incomplete.extend(vec![0; padding]);
        rejects_event(&baseline, message(16, &incomplete).into());
    }
}

#[test]
fn u4_eintr_work_is_bounded_without_granting_a_credit() {
    for interruptions in [
        NATIVE_DRAIN_DATAGRAMS,
        NATIVE_DRAIN_DATAGRAMS + 1,
        2 * NATIVE_DRAIN_DATAGRAMS,
    ] {
        let mut fixture = fixture();
        fixture
            .queue
            .lock()
            .unwrap()
            .extend((0..interruptions).map(|_| Receive::Error(libc::EINTR)));
        let baseline = link(2, 101, &configuration(false, 0));
        let called = AtomicBool::new(false);
        let outcome = fixture.updates.lock().update_with(
            2,
            101,
            102,
            false,
            |projection| native_link_projection(&baseline, 2, 101, projection),
            || {
                called.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(matches!(
            outcome.transport,
            Err(XdpUpdateError::NotAttempted(_))
        ));
        assert!(outcome.observation.is_err());
        assert!(!called.load(Ordering::SeqCst));
        assert_eq!(fixture.updates.consumed_operations(), 0);
        assert_sticky(&mut fixture);
    }
    let mut fixture = fixture();
    fixture
        .queue
        .lock()
        .unwrap()
        .extend((0..NATIVE_DRAIN_DATAGRAMS - 1).map(|_| Receive::Error(libc::EINTR)));
    let baseline = link(2, 101, &configuration(false, 0));
    successful(update(
        &fixture,
        (2, 101, 102),
        &baseline,
        vec![own(2, 102).into()],
        false,
        Ok(()),
    ));
    assert_eq!(fixture.updates.consumed_operations(), 1);
    assert!(!fixture.topology.check_changed().unwrap());
}

#[test]
fn u5_poisoned_shared_watch_refuses_data_but_still_attempts_the_terminal_guard() {
    let mut fixture = fixture();
    let updates = fixture.updates.clone();
    assert!(
        thread::spawn(move || {
            let _watch = updates.lock();
            panic!("injected failure while holding NativeWatch");
        })
        .join()
        .is_err()
    );
    assert_sticky(&mut fixture);
    let attempts = AtomicUsize::new(0);
    let outcome = terminal_update(&fixture, GuardFailure::AlreadySticky, &attempts);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    assert!(outcome.transport.is_ok());
    assert!(outcome.observation.is_err());
    assert_sticky(&mut fixture);
}

#[test]
fn u6_opaque_nested_framing_has_a_bounded_depth() {
    let mut nested = attributes_bytes(&[(1, vec![7])]);
    for _ in 0..16 {
        nested = attributes_bytes(&[(1 | 0x8000, nested)]);
    }
    let mut attributes = configuration(false, 0);
    replace_attribute(&mut attributes, 1001, nested);
    rejects_configuration(&attributes);
}

fn private_tap_states(recent: bool) -> [Vec<u8>; 3] {
    let mut attributes = configuration(recent, 0);
    let mut pre = link_with_xdp(2, &attributes, &[(2, vec![0])]);
    pre[8..12].copy_from_slice(&0x30141u32.to_ne_bytes());
    replace_attribute(&mut attributes, 16, vec![2]);
    replace_attribute(&mut attributes, 33, vec![0]);
    replace_attribute(&mut attributes, 35, 6u32.to_ne_bytes().to_vec());
    replace_attribute(&mut attributes, 48, 3u32.to_ne_bytes().to_vec());
    let mut down = link_with_xdp(2, &attributes, &[(2, vec![0])]);
    down[8..12].copy_from_slice(&0x100u32.to_ne_bytes());
    down[12..16].copy_from_slice(&0x41u32.to_ne_bytes());
    replace_attribute(&mut attributes, 6, b"noop\0".to_vec());
    replace_attribute(
        &mut attributes,
        26,
        attributes_bytes(&[(45 | 0x8000, attributes_bytes(&[(1, vec![5, 6, 7])]))]),
    );
    let mut delete = link_with_xdp(2, &attributes, &[(2, vec![0])]);
    delete[8..12].copy_from_slice(&0x100u32.to_ne_bytes());
    delete[12..16].copy_from_slice(&u32::MAX.to_ne_bytes());
    [pre, down, delete]
}

fn private_transaction(
    fixture: &Fixture,
    operation: NativeOperation,
    baseline: &[u8],
    notifications: Vec<Receive>,
    transport: Result<(), XdpUpdateError>,
    postcheck: impl FnOnce(&mut Vec<u8>) -> io::Result<()>,
) -> NativeUpdateOutcome {
    let queue = fixture.queue.clone();
    fixture.updates.lock().operation_with(
        2,
        operation,
        false,
        |projection| {
            native_link_projection_state(
                baseline,
                2,
                if matches!(operation, NativeOperation::Detach) {
                    NativeXdp::Present(101)
                } else {
                    NativeXdp::Absent
                },
                0,
                projection,
            )
        },
        || {
            queue.lock().unwrap().extend(notifications);
            transport
        },
        postcheck,
    )
}

fn reject_private_close(pre: &[u8], notifications: Vec<Receive>) {
    let mut fixture = fixture();
    let outcome = private_transaction(
        &fixture,
        NativeOperation::CloseTap,
        pre,
        notifications,
        Ok(()),
        |_| Ok(()),
    );
    assert!(outcome.transport.is_ok());
    assert!(outcome.observation.is_err());
    assert_eq!(fixture.updates.consumed_operations(), 0);
    assert_sticky(&mut fixture);
}

#[test]
fn private_tap_exact_detach_down_delete_preserve_live_shared_authority() {
    for recent in [false, true] {
        for combined in [false, true] {
            let mut fixture = fixture();
            let [pre, down, delete] = private_tap_states(recent);
            assert!(fixture.updates.same_authority(&fixture.updates.clone()));
            assert!(!fixture.updates.same_authority(&self::fixture().updates));
            let mut guarded = pre[..16].to_vec();
            guarded.extend_from_slice(&attributes_bytes(&configuration(recent, 0)));
            attribute(
                &mut guarded,
                43 | 0x8000,
                &attributes_bytes(&xdp_fields(101)),
            );
            successful(private_transaction(
                &fixture,
                NativeOperation::Detach,
                &guarded,
                vec![message(16, &pre).into()],
                Ok(()),
                |_| Ok(()),
            ));
            let notifications = if combined {
                vec![[message(16, &down), message(17, &delete)].concat().into()]
            } else {
                vec![message(16, &down).into(), message(17, &delete).into()]
            };
            successful(private_transaction(
                &fixture,
                NativeOperation::CloseTap,
                &pre,
                notifications,
                Ok(()),
                |_| require_private_tap_absence(Err(io::Error::from_raw_os_error(libc::ENODEV))),
            ));
            assert_eq!(fixture.updates.consumed_operations(), 2);
            assert!(!fixture.topology.check_changed().unwrap());
            fixture.queue.lock().unwrap().push_back(own(7, 300).into());
            assert!(fixture.topology.check_changed().is_err());
            assert_sticky(&mut fixture);
        }
    }
}

#[test]
fn private_detach_absence_requires_only_attached_none_and_unchanged_configuration() {
    let baseline = link(2, 101, &configuration(false, 0));
    for fields in [
        vec![],
        vec![(2, vec![1])],
        vec![(2, vec![0, 0])],
        vec![(2, vec![0]), (2, vec![0])],
        vec![(2, vec![0]), integer(4, 0)],
        vec![(2, vec![0]), integer(3, 0)],
        vec![(2 | 0x8000, vec![0])],
        vec![(2, vec![0]), (8, vec![])],
    ] {
        let mut fixture = fixture();
        let event = message(16, &link_with_xdp(2, &configuration(false, 0), &fields));
        let outcome = private_transaction(
            &fixture,
            NativeOperation::Detach,
            &baseline,
            vec![event.into()],
            Ok(()),
            |_| Ok(()),
        );
        assert!(outcome.transport.is_ok());
        assert!(outcome.observation.is_err());
        assert_sticky(&mut fixture);
    }
    let mut attributes = configuration(false, 0);
    replace_attribute(&mut attributes, 4, 1499u32.to_ne_bytes().to_vec());
    let mut fixture = fixture();
    let outcome = private_transaction(
        &fixture,
        NativeOperation::Detach,
        &baseline,
        vec![message(16, &link_with_xdp(2, &attributes, &[(2, vec![0])])).into()],
        Ok(()),
        |_| Ok(()),
    );
    assert!(outcome.transport.is_ok());
    assert!(outcome.observation.is_err());
    assert_sticky(&mut fixture);
}

#[test]
fn private_tap_close_rejects_competing_configuration_flags_and_af_transformations() {
    let [pre, down, delete] = private_tap_states(false);
    for (phase, original) in [(0, &down), (1, &delete)] {
        let mut cases = Vec::new();
        for (kind, value) in [
            (4, 1499u32.to_ne_bytes().to_vec()),
            (6, b"noqueue\0".to_vec()),
            (16, vec![6]),
            (33, vec![1]),
            (35, 5u32.to_ne_bytes().to_vec()),
            (47, 4u32.to_ne_bytes().to_vec()),
            (48, 2u32.to_ne_bytes().to_vec()),
            (1000, vec![7, 8, 0]),
        ] {
            let mut attrs = configuration(false, 0);
            replace_attribute(&mut attrs, 16, vec![2]);
            replace_attribute(&mut attrs, 33, vec![0]);
            replace_attribute(&mut attrs, 35, 6u32.to_ne_bytes().to_vec());
            replace_attribute(&mut attrs, 48, 3u32.to_ne_bytes().to_vec());
            if phase == 1 {
                replace_attribute(&mut attrs, 6, b"noop\0".to_vec());
                replace_attribute(
                    &mut attrs,
                    26,
                    attributes_bytes(&[(45 | 0x8000, attributes_bytes(&[(1, vec![5, 6, 7])]))]),
                );
            }
            replace_attribute(&mut attrs, kind, value);
            let mut body = original[..16].to_vec();
            body.extend_from_slice(&attributes_bytes(&attrs));
            attribute(&mut body, 43 | 0x8000, &attributes_bytes(&[(2, vec![0])]));
            cases.push(body);
        }
        for (offset, value) in [(4, 3u32), (8, 0x101), (12, 0)] {
            let mut body = original.clone();
            body[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
            cases.push(body);
        }
        // Whole AF removal, retained IP families and deletion of another family
        // are plausible unregister shortcuts, but none is the owned transform.
        for af in [
            vec![],
            af_spec(&ipv6_attributes(0)),
            attributes_bytes(&[(45 | 0x8000, attributes_bytes(&[(1, vec![5, 6, 8])]))]),
        ] {
            let mut body = original[..16].to_vec();
            crate::bpf::raw_attributes(&original[16..], |kind, value| {
                attribute(
                    &mut body,
                    kind,
                    if kind & 0x3fff == 26 { &af } else { value },
                );
                Ok(())
            })
            .unwrap();
            if body != *original {
                cases.push(body);
            }
        }
        for body in cases {
            let (down, delete) = if phase == 0 {
                (&body, &delete)
            } else {
                (&down, &body)
            };
            reject_private_close(
                &pre,
                vec![message(16, down).into(), message(17, delete).into()],
            );
        }
    }
}

#[test]
fn private_tap_close_requires_entire_ordered_sequence_and_every_suffix() {
    let [pre, down, delete] = private_tap_states(false);
    let down = message(16, &down);
    let delete = message(17, &delete);
    for messages in [
        vec![],
        vec![down.clone()],
        vec![delete.clone()],
        vec![delete.clone(), down.clone()],
        vec![down.clone(), down.clone(), delete.clone()],
        vec![down.clone(), delete.clone(), delete.clone()],
        vec![down.clone(), delete.clone(), own(7, 300)],
        vec![down.clone(), message(20, &[]), delete.clone()],
        vec![down.clone(), delete.clone(), vec![0; 15]],
    ] {
        reject_private_close(&pre, messages.iter().cloned().map(Receive::from).collect());
        if !messages.is_empty() {
            reject_private_close(&pre, vec![messages.concat().into()]);
        }
    }
    for error in [libc::ENOBUFS, libc::EIO] {
        reject_private_close(
            &pre,
            vec![
                down.clone().into(),
                delete.clone().into(),
                Receive::Error(error),
            ],
        );
    }
    let Receive::Datagram(mut foreign) = Receive::from(delete.clone()) else {
        unreachable!()
    };
    foreign.source_port = 1;
    reject_private_close(&pre, vec![down.clone().into(), Receive::Datagram(foreign)]);
    let Receive::Datagram(mut truncated) = Receive::from(delete) else {
        unreachable!()
    };
    truncated.length = NATIVE_LINK_CAPACITY + 1;
    reject_private_close(&pre, vec![down.into(), Receive::Datagram(truncated)]);
}

#[test]
fn private_destructive_prechecks_keep_callback_uninvoked_and_fd_owned() {
    let [pre, _, _] = private_tap_states(false);
    for operation in [NativeOperation::Detach, NativeOperation::CloseTap] {
        let failures = if matches!(operation, NativeOperation::Detach) {
            4
        } else {
            8
        };
        for failure in 0..failures {
            let mut fixture = fixture();
            let called = AtomicBool::new(false);
            let mut tap = Some(UnixDatagram::unbound().unwrap());
            let queue = fixture.queue.clone();
            if failure == 0 {
                fixture.queue.lock().unwrap().push_back(own(7, 300).into());
            }
            if failure == 1 {
                fixture.updates.lock().invalidate();
            }
            let outcome = fixture.updates.lock().operation_with(
                2,
                operation,
                true,
                |projection| {
                    if failure == 2 {
                        return Err(io::Error::from_raw_os_error(libc::EIO));
                    }
                    let mut body = pre.clone();
                    if failure == 4 {
                        body[8..12].copy_from_slice(&0u32.to_ne_bytes());
                    }
                    if failure == 5 {
                        let mut attrs = configuration(false, 0);
                        replace_attribute(&mut attrs, 33, vec![0]);
                        body = link_with_xdp(2, &attrs, &[(2, vec![0])]);
                    }
                    if failure == 6 {
                        body = link(2, 101, &configuration(false, 0));
                    }
                    if failure == 7 {
                        body = link_with_xdp(2, &configuration(false, 0), &[]);
                    }
                    if matches!(operation, NativeOperation::Detach) {
                        body = link(2, 101, &configuration(false, 0));
                        native_link_projection(&body, 2, 101, projection)?;
                    } else {
                        native_link_projection_state(&body, 2, NativeXdp::Absent, 0, projection)?;
                    }
                    if failure == 3 {
                        queue.lock().unwrap().push_back(own(7, 300).into());
                    }
                    Ok(())
                },
                || {
                    called.store(true, Ordering::SeqCst);
                    drop(tap.take());
                    Ok(())
                },
                |_| panic!("precheck failure cannot run post-close query"),
            );
            assert!(matches!(
                outcome.transport,
                Err(XdpUpdateError::NotAttempted(_))
            ));
            assert!(outcome.observation.is_err());
            assert!(!called.load(Ordering::SeqCst));
            assert!(
                tap.is_some(),
                "an uninvoked borrowed callback must retain its FD"
            );
            assert_sticky(&mut fixture);
        }
    }
}

#[test]
fn private_tap_consumed_close_error_preserves_postcondition_and_never_retries() {
    let [pre, down, delete] = private_tap_states(false);
    let mut fixture = fixture();
    let called = AtomicUsize::new(0);
    let post = AtomicBool::new(false);
    let queue = fixture.queue.clone();
    let outcome = fixture.updates.lock().operation_with(
        2,
        NativeOperation::CloseTap,
        false,
        |projection| native_link_projection_state(&pre, 2, NativeXdp::Absent, 0, projection),
        || {
            called.fetch_add(1, Ordering::SeqCst);
            queue
                .lock()
                .unwrap()
                .extend([message(16, &down).into(), message(17, &delete).into()]);
            Err(XdpUpdateError::Uncertain(io::Error::from_raw_os_error(
                libc::EINTR,
            )))
        },
        |_| {
            post.store(true, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(libc::EACCES))
        },
    );
    assert!(
        matches!(&outcome.transport, Err(XdpUpdateError::Uncertain(error)) if error.raw_os_error() == Some(libc::EINTR))
    );
    let error = outcome.observation.unwrap_err().to_string();
    assert!(error.contains(&io::Error::from_raw_os_error(libc::EACCES).to_string()));
    assert!(post.load(Ordering::SeqCst));
    let repeated = fixture.updates.lock().operation_with(
        2,
        NativeOperation::CloseTap,
        false,
        |_| Ok(()),
        || {
            called.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        |_| Ok(()),
    );
    assert!(matches!(
        repeated.transport,
        Err(XdpUpdateError::NotAttempted(_))
    ));
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert_sticky(&mut fixture);
}

#[test]
fn private_tap_postclose_requires_exact_ifindex_enodev_and_live_late_checks() {
    let mut request = [0u8; 32];
    request[..4].copy_from_slice(&32u32.to_ne_bytes());
    request[4..6].copy_from_slice(&18u16.to_ne_bytes());
    request[6..8].copy_from_slice(&1u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[20..24].copy_from_slice(&2u32.to_ne_bytes());
    let mut body = (-libc::ENODEV).to_ne_bytes().to_vec();
    body.extend_from_slice(&request);
    let mut absent = message(2, &body);
    absent[8..12].copy_from_slice(&1u32.to_ne_bytes());
    let mut projection = Vec::new();
    require_private_tap_absence(
        parse_native_link_reply(&absent, &request, NativeXdp::Absent, &mut projection).map(|_| ()),
    )
    .unwrap();
    for offset in [8, 20, 40] {
        let mut wrong = absent.clone();
        wrong[offset] ^= 1;
        assert!(
            require_private_tap_absence(
                parse_native_link_reply(&wrong, &request, NativeXdp::Absent, &mut projection)
                    .map(|_| ())
            )
            .is_err()
        );
    }
    assert!(
        require_private_tap_absence(
            parse_native_link_reply(
                &[absent.clone(), absent].concat(),
                &request,
                NativeXdp::Absent,
                &mut projection
            )
            .map(|_| ())
        )
        .is_err()
    );
    let [pre, down, delete] = private_tap_states(false);
    for result in [Ok(()), Err(io::Error::from_raw_os_error(libc::EIO))] {
        let mut fixture = fixture();
        let outcome = private_transaction(
            &fixture,
            NativeOperation::CloseTap,
            &pre,
            vec![message(16, &down).into(), message(17, &delete).into()],
            Ok(()),
            |_| require_private_tap_absence(result),
        );
        assert!(outcome.transport.is_ok());
        assert!(outcome.observation.is_err());
        assert_sticky(&mut fixture);
    }
}

#[test]
fn private_tap_close_preserves_attribute_order_singletons_and_af_container() {
    let [pre, down, delete] = private_tap_states(false);
    for (phase, original) in [(0, &down), (1, &delete)] {
        for mutation in 0..8 {
            let mut attrs = Vec::new();
            crate::bpf::raw_attributes(&original[16..], |kind, value| {
                attrs.push((kind, value.to_vec()));
                Ok(())
            })
            .unwrap();
            match mutation {
                0 => attrs.swap(0, 1),
                1 => attrs.push(
                    attrs
                        .iter()
                        .find(|(kind, _)| kind & 0x3fff == 33)
                        .unwrap()
                        .clone(),
                ),
                2 => attrs.retain(|(kind, _)| kind & 0x3fff != 26),
                3 => replace_attribute(
                    &mut attrs,
                    26,
                    attributes_bytes(&[
                        (2 | 0x8000, attributes_bytes(&[(1, vec![1, 0, 0, 0])])),
                        (45 | 0x8000, attributes_bytes(&[(1, vec![5, 6, 7])])),
                    ]),
                ),
                4 => replace_attribute(
                    &mut attrs,
                    26,
                    attributes_bytes(&[
                        (10 | 0x8000, attributes_bytes(&ipv6_attributes(0))),
                        (45 | 0x8000, attributes_bytes(&[(1, vec![5, 6, 7])])),
                    ]),
                ),
                5 => replace_attribute(&mut attrs, 43, attributes_bytes(&xdp_fields(101))),
                6 => attrs.retain(|(kind, _)| kind & 0x3fff != 43),
                7 => replace_attribute(&mut attrs, 26, vec![]),
                _ => unreachable!(),
            }
            let mut body = original[..16].to_vec();
            body.extend_from_slice(&attributes_bytes(&attrs));
            let (down, delete) = if phase == 0 {
                (&body, &delete)
            } else {
                (&down, &body)
            };
            reject_private_close(
                &pre,
                vec![message(16, down).into(), message(17, delete).into()],
            );
        }
    }
}

#[test]
fn private_tap_delete_rewrites_short_qdisc_and_keeps_empty_af_container() {
    let [pre, down, delete] = private_tap_states(false);
    let mut states = [pre, down, delete];
    for (phase, body) in states.iter_mut().enumerate() {
        let mut changed = body[..16].to_vec();
        crate::bpf::raw_attributes(&body[16..], |kind, value| {
            if kind & 0x3fff == 26 {
                let mut families = Vec::new();
                crate::bpf::raw_attributes(value, |family, subtree| {
                    if family & 0x3fff != 45 {
                        attribute(&mut families, family, subtree);
                    }
                    Ok(())
                })?;
                attribute(&mut changed, kind, &families);
            } else {
                attribute(
                    &mut changed,
                    kind,
                    if phase < 2 && kind & 0x3fff == 6 {
                        b"sfb\0"
                    } else {
                        value
                    },
                );
            }
            Ok(())
        })
        .unwrap();
        *body = changed;
    }
    let fixture = fixture();
    successful(private_transaction(
        &fixture,
        NativeOperation::CloseTap,
        &states[0],
        vec![
            message(16, &states[1]).into(),
            message(17, &states[2]).into(),
        ],
        Ok(()),
        |_| Ok(()),
    ));
    assert_eq!(fixture.updates.consumed_operations(), 1);
}

#[test]
fn private_tap_consumed_close_keeps_receive_loss_separate_from_close_error() {
    let [pre, down, delete] = private_tap_states(false);
    let mut fixture = fixture();
    let outcome = private_transaction(
        &fixture,
        NativeOperation::CloseTap,
        &pre,
        vec![
            message(16, &down).into(),
            message(17, &delete).into(),
            Receive::Error(libc::ENOBUFS),
        ],
        Err(XdpUpdateError::Uncertain(io::Error::from_raw_os_error(
            libc::EINTR,
        ))),
        |_| require_private_tap_absence(Err(io::Error::from_raw_os_error(libc::ENODEV))),
    );
    assert!(
        matches!(&outcome.transport, Err(XdpUpdateError::Uncertain(error)) if error.raw_os_error() == Some(libc::EINTR))
    );
    assert_eq!(
        outcome.observation.unwrap_err().raw_os_error(),
        Some(libc::ENOBUFS)
    );
    assert_eq!(fixture.updates.consumed_operations(), 0);
    assert_sticky(&mut fixture);
}

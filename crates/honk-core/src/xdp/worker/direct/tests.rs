mod download;
mod readiness;

use super::*;
use crate::relay::RelayProgress;
use honk_netstack::{AcceptOpts, Config, ExcludeSet, MemoryBudget, Mode, StreamError, TcpState};
use std::future::poll_fn;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::os::fd::RawFd;
use std::sync::atomic::Ordering;

fn client() -> Stack {
    let mut config = Config::new([17; 32]);
    config.local_v4 = Some([192, 0, 2, 1].into());
    Stack::new(config, Instant::now())
}

fn connect(stack: &mut Stack) -> FlowId {
    stack
        .tcp_connect(Instant::now(), "198.51.100.2:443".parse().unwrap())
        .unwrap()
}

fn new_reactor(max_slots: usize, budget: &Arc<MemoryBudget>) -> DirectReactor {
    DirectReactor::new(max_slots, |bytes| budget.reserve(bytes)).unwrap()
}

fn attach_flow(
    reactor: &mut DirectReactor,
    id: FlowId,
    attach: DirectAttach,
    now: Instant,
) -> DirectHandle {
    reactor
        .attach(id, attach, now)
        .unwrap_or_else(|_| panic!("Direct fixture attachment refused"))
}

fn attach(budget: &Arc<MemoryBudget>) -> (DirectAttach, DirectObserver, TcpStream, RelayProgress) {
    attach_with_live_observation(budget, true)
}

fn attach_with_live_observation(
    budget: &Arc<MemoryBudget>,
    observe_live: bool,
) -> (DirectAttach, DirectObserver, TcpStream, RelayProgress) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    attach_to(&listener, budget, observe_live)
}

fn attach_to(
    listener: &TcpListener,
    budget: &Arc<MemoryBudget>,
    observe_live: bool,
) -> (DirectAttach, DirectObserver, TcpStream, RelayProgress) {
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let peer = listener.accept().unwrap().0;
    socket.set_nonblocking(true).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let progress = RelayProgress {
        upload: Arc::default(),
        download: Arc::default(),
        outbound: Some(Arc::default()),
        first_response: Some(Arc::new(|| panic!("worker ran shared observer"))),
        on_transfer: Some(Arc::new(|_, _| panic!("worker ran shared observer"))),
    };
    let (attach, observer) = DirectAttach::new(
        socket,
        &progress,
        DirectAttach::credit(|bytes| budget.reserve(bytes)).unwrap(),
        observe_live,
    );
    (attach, observer, peer, progress)
}

fn wait_for_fd(fd: RawFd, event: libc::c_short) {
    let mut descriptor = libc::pollfd {
        fd,
        events: event,
        revents: 0,
    };
    // SAFETY: the caller holds the fd open and the single pollfd is writable.
    assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 2000) }, 1);
    assert_ne!(descriptor.revents & event, 0);
}

fn expect_update(observer: &mut DirectObserver) -> (DirectSnapshot, Option<DirectOutcome>) {
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    let Poll::Ready(update) = observer.poll_update(&mut cx) else {
        panic!("expected Direct observation revision");
    };
    update
}

fn owned_notification(reactor: &DirectReactor) -> &AsyncFd<OwnedFd> {
    let ReactorEpoll::Owned {
        notification: Some(notification),
        ..
    } = &reactor.epoll
    else {
        panic!("expected a registered standalone epoll");
    };
    notification
}

fn owned_kernel_ready(reactor: &DirectReactor) -> bool {
    matches!(
        reactor.epoll,
        ReactorEpoll::Owned {
            kernel_ready: true,
            ..
        }
    )
}

#[test]
fn stale_epoll_ready_and_abort_do_not_schedule_a_reused_slot() {
    let (mut client, old_client, mut stack, old, mut now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(1, &budget);
    let (attachment, mut first, mut peer, _) = attach(&budget);
    let stale = attach_flow(&mut reactor, old, attachment, now);
    let token = reactor
        .epoll
        .token(reactor.slots[stale.index].watch_generation, stale.index);
    reactor.abort(stale);
    assert_eq!(reactor.live_index(stale), None);
    assert_eq!(reactor.epoll_waiters, 0);
    assert!(!owned_kernel_ready(&reactor));
    assert!(matches!(
        expect_update(&mut first).1,
        Some(DirectOutcome::Cancelled)
    ));
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);

    client.tcp_abort(old_client);
    now += Duration::from_millis(10);
    transfer(&mut client, &mut stack, now);
    stack.tcp_close(old);
    assert!(!stack.tcp_retained(old));
    let new_client = client
        .tcp_connect(now, "198.51.100.2:443".parse().unwrap())
        .unwrap();
    now += Duration::from_millis(10);
    transfer(&mut client, &mut stack, now);
    let new = stack.poll_accept().unwrap().id;
    assert_eq!(new.index(), old.index());
    assert_ne!(new, old);
    stack.tcp_accept(new, AcceptOpts::default()).unwrap();
    transfer(&mut stack, &mut client, now);
    transfer(&mut client, &mut stack, now);
    assert_eq!(stack.tcp_state(new), Some(TcpState::Established));

    let (attachment, mut successor, mut peer, _) = attach(&budget);
    let current = attach_flow(&mut reactor, new, attachment, now);
    assert_eq!(current.index, stale.index);
    assert!(expect_update(&mut successor).0.attached);
    reactor.service(&mut stack, now).unwrap();
    assert!(reactor.ready.is_empty());
    assert_eq!(reactor.live_index(stale), None);
    assert_eq!(reactor.live_index(current), Some(current.index));
    assert!(reactor.watched_pump(token).is_none());
    reactor.socket_ready(token, libc::EPOLLIN as u32);
    reactor.mark_ready(stale);
    reactor.abort(stale);
    assert!(reactor.ready.is_empty());
    assert_eq!(reactor.epoll_waiters, 1);
    assert_eq!(reactor.live_index(current), Some(current.index));

    assert_eq!(client.tcp_write(new_client, b"new"), Ok(3));
    now += Duration::from_millis(10);
    deliver_client_turn(&mut client, &mut stack, &mut reactor, (new, current), now);
    let mut received = [0; 3];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"new");
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(first.poll_update(&mut cx).is_pending());
    reactor.close();
    assert_eq!(reactor.epoll_waiters, 0);
    assert!(!reactor.has_pending_work());
    assert!(matches!(
        expect_update(&mut successor).1,
        Some(DirectOutcome::Cancelled)
    ));
}

#[test]
fn exhausted_software_generation_retires_the_slot() {
    let mut stack = client();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(2, &budget);
    let now = Instant::now();
    reactor.slots[0].generation = u64::MAX - 1;
    let (attachment, _, _, _) = attach(&budget);
    let last = attach_flow(&mut reactor, connect(&mut stack), attachment, now);
    assert_eq!(last.index, 0);
    assert_eq!(last.generation, u64::MAX);
    assert_eq!(reactor.live_index(last), Some(0));
    reactor.abort(last);
    assert_eq!(reactor.live_index(last), None);
    assert_eq!(reactor.free, [1]);

    let (attachment, _, _, _) = attach(&budget);
    let next = attach_flow(&mut reactor, connect(&mut stack), attachment, now);
    assert_eq!(next.index, 1);
    assert_eq!(next.generation, 1);
    assert_eq!(reactor.live_index(next), Some(1));
}

#[test]
fn close_discards_ready_entries_and_cancels_the_remaining_pump() {
    let mut stack = client();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(2, &budget);
    let now = Instant::now();
    let old = connect(&mut stack);
    let (first, _, _first_peer, _) = attach(&budget);
    let handle = attach_flow(&mut reactor, old, first, now);

    let (second, mut observer, mut peer, _) = attach(&budget);
    assert!(reactor.attach(connect(&mut stack), second, now).is_ok());
    reactor.abort(handle);
    assert!(expect_update(&mut observer).0.attached);
    assert!(reactor.has_pending_work());
    reactor.close();
    assert!(!reactor.has_pending_work());
    assert!(reactor.slots.iter().all(|slot| !slot.queued));
    assert!(matches!(
        expect_update(&mut observer).1,
        Some(DirectOutcome::Cancelled)
    ));
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

fn transfer(from: &mut Stack, to: &mut Stack, now: Instant) {
    let mut packet = [0; 2048];
    from.handle_timeout(now);
    while let Some(len) = from.poll_transmit(now, &mut packet) {
        let _ = to.receive(now, &packet[..len]);
    }
}

fn connected() -> (Stack, FlowId, Stack, FlowId, Instant) {
    let mut now = Instant::now();
    let mut client = client();
    let mut cfg = Config::new([19; 32]);
    cfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    cfg.tcp_chunk = Some(4096);
    cfg.tcp_snd_buf_max = 4096;
    let mut server = Stack::new(cfg, now);
    let client_id = connect(&mut client);
    now += Duration::from_millis(1);
    transfer(&mut client, &mut server, now);
    let id = server.poll_accept().unwrap().id;
    server.tcp_accept(id, AcceptOpts::default()).unwrap();
    transfer(&mut server, &mut client, now);
    transfer(&mut client, &mut server, now);
    assert_eq!(server.tcp_state(id), Some(TcpState::Established));
    (client, client_id, server, id, now)
}

fn deliver_client(
    client: &mut Stack,
    server: &mut Stack,
    reactor: &mut DirectReactor,
    binding: (FlowId, DirectHandle),
    now: &mut Instant,
) {
    for _ in 0..8 {
        *now += Duration::from_millis(10);
        deliver_client_turn(client, server, reactor, binding, *now);
    }
}

fn deliver_client_turn(
    client: &mut Stack,
    server: &mut Stack,
    reactor: &mut DirectReactor,
    binding: (FlowId, DirectHandle),
    now: Instant,
) {
    transfer(client, server, now);
    mark_stack_events(server, reactor, binding);
    reactor.service(server, now).unwrap();
    transfer(server, client, now);
}

fn mark_stack_events(
    server: &mut Stack,
    reactor: &mut DirectReactor,
    (flow, handle): (FlowId, DirectHandle),
) {
    while let Some((id, _)) = server.poll_event() {
        if id == flow {
            reactor.mark_ready(handle);
        }
    }
}

#[tokio::test]
async fn half_closed_client_receives_every_byte_across_partial_ring_credits() {
    let (mut client, client_id, mut server, id, mut now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(1, &budget);
    let (a, mut observer, mut peer, counters) = attach(&budget);
    let handle = attach_flow(&mut reactor, id, a, now);
    let request = b"complete request before FIN";
    assert_eq!(client.tcp_write(client_id, request).unwrap(), request.len());
    client.tcp_shutdown(client_id).unwrap();
    deliver_client(
        &mut client,
        &mut server,
        &mut reactor,
        (id, handle),
        &mut now,
    );
    let mut received = Vec::new();
    peer.read_to_end(&mut received).unwrap();
    assert_eq!(received, request);
    assert!(reactor.deadline().is_some());

    let response = (0..(24 << 10)).map(|i| (i % 193) as u8).collect::<Vec<_>>();
    // Arm the real aggregate AsyncFd before the upstream supplies any response.
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    reactor.poll_ready(&mut cx).unwrap();
    peer.write_all(&response).unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| {
            while reactor.poll_ready(cx).unwrap() {
                reactor.service(&mut server, now).unwrap();
                if counters.download.load(Ordering::Relaxed) > 0 {
                    return Poll::Ready(());
                }
            }
            Poll::Pending
        }),
    )
    .await
    .unwrap();
    let accepted = counters.download.load(Ordering::Relaxed) as usize;
    assert!(accepted > 0 && accepted <= 4096 && accepted < response.len());
    let mut received = Vec::new();
    let mut eof = false;
    for _ in 0..256 {
        now += Duration::from_millis(10);
        transfer(&mut server, &mut client, now);
        let mut chunk = [0; 1200];
        loop {
            match client.tcp_read(client_id, &mut chunk) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(StreamError::WouldBlock) => break,
                Err(error) => panic!("client read: {error:?}"),
            }
        }
        transfer(&mut client, &mut server, now);
        mark_stack_events(&mut server, &mut reactor, (id, handle));
        reactor.poll_ready(&mut cx).unwrap();
        reactor.service(&mut server, now).unwrap();
        if eof {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(eof);
    assert_eq!(received, response);
    let (snapshot, terminal) = poll_fn(|cx| observer.poll_update(cx)).await;
    assert_eq!(snapshot.upload, request.len() as u64);
    assert_eq!(snapshot.download, response.len() as u64);
    assert!(snapshot.first_response >= snapshot.first_upload);
    assert!(
        matches!(terminal, Some(DirectOutcome::Finished(Ok(stats))) if stats.total_bytes == snapshot.upload + snapshot.download)
    );
    assert!(reactor.deadline().is_none());
}

#[tokio::test]
async fn upstream_fin_allows_client_to_finish_its_request() {
    let (mut client, client_id, mut server, id, mut now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(1, &budget);
    let (a, mut observer, mut peer, _) = attach(&budget);
    peer.shutdown(Shutdown::Write).unwrap();
    let handle = attach_flow(&mut reactor, id, a, now);
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| {
            while reactor.poll_ready(cx).unwrap() {
                reactor.service(&mut server, now).unwrap();
                if reactor.deadline().is_some() {
                    return Poll::Ready(());
                }
            }
            Poll::Pending
        }),
    )
    .await
    .unwrap();
    transfer(&mut server, &mut client, now);
    assert_eq!(client.tcp_read(client_id, &mut [0]), Ok(0));
    assert!(reactor.deadline().is_some());
    let request = b"late request";
    assert_eq!(client.tcp_write(client_id, request).unwrap(), request.len());
    client.tcp_shutdown(client_id).unwrap();
    deliver_client(
        &mut client,
        &mut server,
        &mut reactor,
        (id, handle),
        &mut now,
    );
    let mut bytes = Vec::new();
    peer.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, request);
    let (snapshot, terminal) = poll_fn(|cx| observer.poll_update(cx)).await;
    assert!(matches!(terminal, Some(DirectOutcome::Finished(Ok(_)))));
    assert_eq!(snapshot.upload, request.len() as u64);
    assert!(snapshot.first_response.is_none());
}

#[tokio::test]
async fn preconsumption_refusal_returns_the_same_connected_socket() {
    let mut stack = client();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(1, &budget);
    let (active, _active_observer, _active_peer, _) = attach(&budget);
    let now = Instant::now();
    assert!(reactor.attach(connect(&mut stack), active, now).is_ok());
    let (second, mut observer, mut peer, counters) = attach(&budget);
    let fd = second.socket.as_raw_fd();
    peer.write_all(b"early").unwrap();
    let refused = reactor
        .attach(connect(&mut stack), second, now)
        .unwrap_err();
    refused.reject();
    let (snapshot, outcome) = poll_fn(|cx| observer.poll_update(cx)).await;
    let Some(DirectOutcome::Fallback(mut socket)) = outcome else {
        panic!("socket lost");
    };
    assert!(!snapshot.attached);
    assert_eq!(counters.download.load(Ordering::Relaxed), 0);
    assert_eq!(socket.as_raw_fd(), fd);
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = [0; 5];
    socket.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"early");
}

#[tokio::test]
async fn reset_retains_original_error_and_socket_side() {
    for client_reset in [true, false] {
        let (mut client, client_id, mut server, id, mut now) = connected();
        let budget = MemoryBudget::new(1 << 20);
        let mut reactor = new_reactor(1, &budget);
        let (a, mut observer, peer, _) = attach(&budget);
        let handle = attach_flow(&mut reactor, id, a, now);
        if client_reset {
            client.tcp_abort(client_id);
            deliver_client(
                &mut client,
                &mut server,
                &mut reactor,
                (id, handle),
                &mut now,
            );
        } else {
            socket2::SockRef::from(&peer)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(peer);
        }
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                while reactor.poll_ready(cx).unwrap() {
                    reactor.service(&mut server, now).unwrap();
                }
                loop {
                    match observer.poll_update(cx) {
                        Poll::Ready((_, Some(outcome))) => return Poll::Ready(outcome),
                        Poll::Ready((_, None)) => {}
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }),
        )
        .await
        .unwrap();
        let DirectOutcome::Finished(Err(error)) = outcome else {
            panic!("lost reset");
        };
        assert_eq!(error.is::<crate::relay::ClientIoError>(), client_reset);
        let error = error.downcast_ref::<io::Error>().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        if client_reset {
            assert_eq!(
                error
                    .get_ref()
                    .and_then(|error| error.downcast_ref::<StreamError>()),
                Some(&StreamError::Reset)
            );
        } else {
            assert_eq!(error.raw_os_error(), Some(libc::ECONNRESET));
        }
    }
}

#[test]
fn quiet_flow_reports_accepted_bytes_and_an_idle_half_close_expires() {
    for observe_live in [false, true] {
        let (mut client, client_id, mut server, id, stack_now) = connected();
        let budget = MemoryBudget::new(1 << 20);
        let mut reactor = new_reactor(1, &budget);
        let (attach, mut observer, mut peer, counters) =
            attach_with_live_observation(&budget, observe_live);
        let started = stack_now.max(Instant::now());
        let handle = attach_flow(&mut reactor, id, attach, started);
        let (accepted, outcome) = expect_update(&mut observer);
        assert!(accepted.attached && outcome.is_none());
        assert_eq!(accepted.upload, 0);

        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let first_at = started + Duration::from_millis(10);
        assert_eq!(client.tcp_write(client_id, b"a"), Ok(1));
        deliver_client_turn(
            &mut client,
            &mut server,
            &mut reactor,
            (id, handle),
            first_at,
        );
        assert_eq!(counters.upload.load(Ordering::Relaxed), 1);
        if observe_live {
            let (first, outcome) = expect_update(&mut observer);
            assert_eq!(first.upload, 1);
            assert_eq!(first.first_upload, Some(first_at));
            assert!(outcome.is_none());
        } else {
            assert!(observer.poll_update(&mut cx).is_pending());
        }
        assert!(reactor.deadline().is_none());

        let second_at = first_at + Duration::from_millis(10);
        assert_eq!(client.tcp_write(client_id, b"b"), Ok(1));
        deliver_client_turn(
            &mut client,
            &mut server,
            &mut reactor,
            (id, handle),
            second_at,
        );
        let outbound = &counters.outbound.as_ref().unwrap().tx_bytes;
        assert_eq!(counters.upload.load(Ordering::Relaxed), 2);
        assert_eq!(outbound.load(Ordering::Relaxed), 2);
        let report_at = second_at + REPORT_INTERVAL;
        assert_eq!(reactor.deadline(), observe_live.then_some(report_at));
        reactor
            .service(&mut server, report_at - Duration::from_nanos(1))
            .unwrap();
        assert!(observer.poll_update(&mut cx).is_pending());
        reactor.service(&mut server, report_at).unwrap();
        if observe_live {
            let (updated, outcome) = expect_update(&mut observer);
            assert_eq!(updated.upload, 2);
            assert_eq!(updated.first_upload, Some(first_at));
            assert_eq!(updated.last_upload, Some(second_at));
            assert!(outcome.is_none());
        } else {
            assert!(observer.poll_update(&mut cx).is_pending());
        }
        assert!(reactor.deadline().is_none());

        let fin_at = report_at + Duration::from_millis(10);
        assert_eq!(client.tcp_write(client_id, b"c"), Ok(1));
        client.tcp_shutdown(client_id).unwrap();
        let earliest_drain = fin_at.max(Instant::now()) + DRAIN_DEADLINE;
        deliver_client_turn(&mut client, &mut server, &mut reactor, (id, handle), fin_at);
        let latest_drain = fin_at.max(Instant::now()) + DRAIN_DEADLINE;
        let mut request = Vec::new();
        peer.read_to_end(&mut request).unwrap();
        assert_eq!(request, b"abc");
        assert!(observer.poll_update(&mut cx).is_pending());

        let drain_at = reactor.slots[handle.index].timers[DRAIN].deadline.unwrap();
        assert!((earliest_drain..=latest_drain).contains(&drain_at));
        reactor.service(&mut server, drain_at).unwrap();
        let (snapshot, outcome) = expect_update(&mut observer);
        let Some(DirectOutcome::Finished(Ok(stats))) = outcome else {
            panic!("expected the idle download half to expire");
        };
        assert_eq!(stats.total_bytes, 3);
        assert_eq!(stats.duration_ms, (drain_at - started).as_millis() as u64);
        assert_eq!(snapshot.upload, 3);
        assert_eq!(snapshot.first_upload, Some(first_at));
        assert_eq!(snapshot.last_upload, Some(fin_at));
        assert_eq!(counters.upload.load(Ordering::Relaxed), 3);
        assert_eq!(outbound.load(Ordering::Relaxed), 3);
        assert!(observer.poll_update(&mut cx).is_pending());
        assert!(reactor.deadline().is_none());
        transfer(&mut server, &mut client, drain_at);
        assert_eq!(client.tcp_read(client_id, &mut [0]), Ok(0));
    }
}

#[test]
fn drain_arm_and_renewal_allow_full_idle_time_after_an_old_turn() {
    let (mut client, client_id, mut server, id, mut stack_now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(1, &budget);
    let (attach, mut observer, mut peer, _) = attach_with_live_observation(&budget, false);
    let old_turn = Instant::now() - Duration::from_secs(1);
    peer.shutdown(Shutdown::Write).unwrap();
    wait_for_fd(attach.socket.as_raw_fd(), libc::POLLRDHUP);
    let handle = attach_flow(&mut reactor, id, attach, old_turn);
    assert!(expect_update(&mut observer).0.attached);

    let before_fin = Instant::now();
    reactor.service(&mut server, old_turn).unwrap();
    let after_fin = Instant::now();
    let first_deadline = reactor.deadline().expect("draining after upstream FIN");
    assert!((before_fin + DRAIN_DEADLINE..=after_fin + DRAIN_DEADLINE).contains(&first_deadline));

    stack_now += Duration::from_millis(10);
    transfer(&mut server, &mut client, stack_now);
    assert_eq!(client.tcp_read(client_id, &mut [0]), Ok(0));
    assert_eq!(client.tcp_write(client_id, b"survivor"), Ok(8));
    stack_now += Duration::from_millis(10);
    transfer(&mut client, &mut server, stack_now);
    reactor.mark_ready(handle);

    let before_upload = Instant::now();
    reactor.service(&mut server, old_turn).unwrap();
    let after_upload = Instant::now();
    let renewed = reactor.deadline().expect("draining after surviving upload");
    assert!((before_upload + DRAIN_DEADLINE..=after_upload + DRAIN_DEADLINE).contains(&renewed));
    assert!(renewed > first_deadline);
    let mut request = [0; 8];
    peer.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"survivor");

    reactor.service(&mut server, first_deadline).unwrap();
    assert_eq!(reactor.deadline(), Some(renewed));
    reactor.service(&mut server, renewed).unwrap();
    let (snapshot, outcome) = expect_update(&mut observer);
    assert_eq!(snapshot.upload, 8);
    assert!(matches!(outcome, Some(DirectOutcome::Finished(Ok(stats))) if stats.total_bytes == 8));
}

#[tokio::test]
async fn upstream_reset_while_client_fin_and_stack_credit_held() {
    for release_credit in [false, true] {
        let (mut client, client_id, mut server, id, mut now) = connected();
        let budget = MemoryBudget::new(1 << 20);
        let mut reactor = new_reactor(1, &budget);
        let (attach, mut observer, mut peer, counters) = attach(&budget);
        let handle = attach_flow(&mut reactor, id, attach, now);
        client.tcp_shutdown(client_id).unwrap();
        deliver_client(
            &mut client,
            &mut server,
            &mut reactor,
            (id, handle),
            &mut now,
        );
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);

        // The first chunk fits the Stack. Leave the extra byte buffered in the socket.
        let response = [0x5a; 4097];
        peer.write_all(&response).unwrap();
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                while reactor.poll_ready(cx).unwrap() {
                    reactor.service(&mut server, now).unwrap();
                    if counters.download.load(Ordering::Relaxed) == 4096 {
                        return Poll::Ready(());
                    }
                }
                Poll::Pending
            }),
        )
        .await
        .unwrap();
        assert!(matches!(
            server.tcp_reserve_tx(id, 1, |_| panic!("Stack must be full")),
            Err(StreamError::WouldBlock)
        ));
        let index = handle.index;
        let pump = reactor.slots[index].pump.as_ref().unwrap();
        let mut tail = [0];
        assert_eq!(pump.socket.peek(&mut tail).unwrap(), 1);
        assert_eq!(tail, [0x5a]);
        socket2::SockRef::from(&peer)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(peer);
        // Wait for the real error without clearing SO_ERROR or touching the buffered byte.
        wait_for_fd(pump.socket.as_raw_fd(), libc::POLLERR);
        {
            // Retain the real outer readiness while no pump can use a socket event.
            let notifier = owned_notification(&reactor);
            let _ready = tokio::time::timeout(Duration::from_secs(2), notifier.readable())
                .await
                .unwrap()
                .unwrap();
        }
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        assert!(!reactor.poll_ready(&mut cx).unwrap());
        assert!(!reactor.service(&mut server, now).unwrap());
        wait_for_fd(reactor.epoll.as_raw_fd(), libc::POLLIN);
        assert!(
            reactor.live_index(handle).is_some(),
            "credit pressure must preserve the buffered byte"
        );
        if release_credit {
            // A real client ACK restores credit. readv must deliver the tail before the reset.
            deliver_client(
                &mut client,
                &mut server,
                &mut reactor,
                (id, handle),
                &mut now,
            );
        } else {
            // Expire the drain deadline while withholding every client ACK.
            now = reactor.slots[index].timers[DRAIN].deadline.unwrap();
            reactor.service(&mut server, now).unwrap();
        }
        let (snapshot, outcome) = tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| observer.poll_update(cx)),
        )
        .await
        .unwrap();
        let Some(DirectOutcome::Finished(Err(error))) = outcome else {
            panic!("lost upstream reset");
        };
        assert!(!error.is::<crate::relay::ClientIoError>());
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
            Some(libc::ECONNRESET)
        );
        let expected = if release_credit { 4097 } else { 4096 };
        assert_eq!(snapshot.download, expected);
        assert_eq!(counters.download.load(Ordering::Relaxed), expected);
        assert_eq!(snapshot.upload, 0);
        assert_eq!(reactor.live_index(handle), None);
        assert!(
            observer
                .poll_update(&mut Context::from_waker(futures::task::noop_waker_ref()))
                .is_pending()
        );
    }
}

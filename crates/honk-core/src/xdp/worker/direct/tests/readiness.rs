use super::*;
use crate::xdp::worker::epoll::{TOKEN_TOPOLOGY, WorkerEpoll};
use std::sync::atomic::AtomicBool;
use std::task::{Wake, Waker};

const FULL_CREDIT: [u8; 4096] = [0x7e; 4096];

fn wait_for_direct_event(worker: &WorkerEpoll, token: u64, flag: u32, missing: &str) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; BATCH];
    loop {
        let now = Instant::now();
        let count = worker.wait(Some(deadline), now, &mut events).unwrap();
        for event in &events[..count] {
            if event.u64 == token && event.events & flag != 0 {
                return event.events;
            }
        }
        assert!(count != 0 && now < deadline, "{missing}");
    }
}

fn constrained_socket(
    budget: &Arc<MemoryBudget>,
) -> (DirectAttach, DirectObserver, TcpStream, RelayProgress) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(FULL_CREDIT.len())
        .unwrap();
    let pair = attach_to(&listener, budget, false);
    socket2::SockRef::from(&pair.0.socket)
        .set_send_buffer_size(FULL_CREDIT.len())
        .unwrap();
    pair
}

fn drive_until_write_wait(
    reactor: &mut DirectReactor,
    client: &mut Stack,
    server: &mut Stack,
    handle: DirectHandle,
    now: &mut Instant,
    mut on_finish: impl FnMut(&mut Stack, FlowId),
) {
    for _ in 0..BATCH {
        *now += Duration::from_millis(10);
        transfer(client, server, *now);
        reactor.mark_ready(handle);
        reactor
            .service_with_finish(server, *now, &mut on_finish)
            .unwrap();
        if reactor.slots[handle.index]
            .pump
            .as_ref()
            .is_none_or(Pump::wants_write_epoll)
        {
            return;
        }
        transfer(server, client, *now);
    }
    panic!("loopback fixture did not exhaust the peer's receive window");
}

#[test]
fn queued_input_reaches_client_on_first_waiter_with_a_pre_origin_turn() {
    for observe_live in [false, true] {
        let (mut client, client_id, mut server, id, now) = connected();
        let budget = MemoryBudget::new(1 << 20);
        let mut reactor = new_reactor(1, &budget);
        let before_origin = Instant::now();
        let (attach, mut observer, mut peer, counters) =
            attach_with_live_observation(&budget, observe_live);
        let after_origin = Instant::now();
        let turn = before_origin - Duration::from_secs(1);
        peer.write_all(b"r").unwrap();
        wait_for_fd(attach.socket.as_raw_fd(), libc::POLLIN);

        let handle = attach_flow(&mut reactor, id, attach, turn);
        let (accepted, outcome) = expect_update(&mut observer);
        assert!(accepted.attached && outcome.is_none());
        assert_eq!(accepted.download, 0);
        wait_for_fd(reactor.epoll.as_raw_fd(), libc::POLLIN);
        // The first waiter must drain the inner fd before the outer driver is polled.
        reactor.service(&mut server, turn).unwrap();
        transfer(&mut server, &mut client, now + Duration::from_millis(10));
        let mut response = [0];
        assert_eq!(client.tcp_read(client_id, &mut response), Ok(1));
        assert_eq!(&response, b"r");
        assert_eq!(counters.download.load(Ordering::Relaxed), 1);
        assert_eq!(
            counters.outbound.unwrap().rx_bytes.load(Ordering::Relaxed),
            1
        );

        let check_times = |snapshot: DirectSnapshot| {
            let first = snapshot.first_response.expect("response time");
            assert!((before_origin..=after_origin).contains(&first));
            assert_eq!(snapshot.last_download, Some(first));
            assert_eq!(snapshot.download, 1);
        };
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        if observe_live {
            let (snapshot, outcome) = expect_update(&mut observer);
            assert!(outcome.is_none());
            check_times(snapshot);
        } else {
            assert!(observer.poll_update(&mut cx).is_pending());
        }
        assert!(reactor.deadline().is_none());
        reactor.abort(handle);
        let (snapshot, outcome) = expect_update(&mut observer);
        check_times(snapshot);
        assert!(matches!(outcome, Some(DirectOutcome::Cancelled)));
        assert!(observer.poll_update(&mut cx).is_pending());
    }
}

async fn hold_download_credit(
    reactor: &mut DirectReactor,
    stack: &mut Stack,
    id: FlowId,
    attach: DirectAttach,
    peer: &mut TcpStream,
    now: Instant,
) -> (RawFd, DirectHandle) {
    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(!reactor.poll_ready(&mut cx).unwrap());
    let socket = attach.socket.as_raw_fd();
    assert_eq!(stack.tcp_write(id, &FULL_CREDIT), Ok(FULL_CREDIT.len()));
    peer.write_all(b"r").unwrap();
    wait_for_fd(socket, libc::POLLIN);
    let handle = attach_flow(reactor, id, attach, now);
    {
        // Drive the fixture with a real outer edge before testing the forced drain.
        let _ready = tokio::time::timeout(
            Duration::from_secs(2),
            owned_notification(reactor).readable(),
        )
        .await
        .unwrap()
        .unwrap();
    }
    assert!(reactor.poll_ready(&mut cx).unwrap());
    reactor.service(stack, now).unwrap();
    assert_eq!(reactor.epoll_waiters, 0);
    assert!(!reactor.has_pending_work());
    (socket, handle)
}

#[tokio::test]
async fn queued_output_resumes_an_upload_without_an_outer_poll() {
    let (mut client, client_id, mut server, id, mut now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(1, &budget);
    let (attach, _, mut peer, counters) = constrained_socket(&budget);
    let (socket, handle) =
        hold_download_credit(&mut reactor, &mut server, id, attach, &mut peer, now).await;
    peer.write_all(b"s").unwrap();
    wait_for_fd(reactor.epoll.as_raw_fd(), libc::POLLIN);

    // Leave the peer unread to exhaust its window. Keep the Stack send ring full
    // as ACKs return credit so only the upload can become a waiter.
    let request: Vec<u8> = (0..(64 << 10)).map(|i| (i % 251) as u8).collect();
    assert_eq!(client.tcp_write(client_id, &request), Ok(request.len()));
    for _ in 0..BATCH {
        now += Duration::from_millis(10);
        transfer(&mut client, &mut server, now);
        reactor.mark_ready(handle);
        reactor.service(&mut server, now).unwrap();
        if reactor.epoll_waiters != 0 {
            break;
        }
        transfer(&mut server, &mut client, now);
        transfer(&mut client, &mut server, now);
        assert!(matches!(
            server.tcp_write(id, &FULL_CREDIT),
            Ok(_) | Err(StreamError::WouldBlock)
        ));
    }
    assert_eq!(reactor.epoll_waiters, 1);
    assert_eq!(counters.download.load(Ordering::Relaxed), 0);
    assert!(
        server
            .tcp_peek_rx(id, 1)
            .is_ok_and(|(_, count, _)| count == 1)
    );
    let sent = counters.upload.load(Ordering::Relaxed) as usize;
    assert!(sent > 0 && sent < request.len());
    let mut received = vec![0; sent + 1];
    peer.read_exact(&mut received[..sent]).unwrap();
    wait_for_fd(socket, libc::POLLOUT);
    wait_for_fd(reactor.epoll.as_raw_fd(), libc::POLLIN);
    reactor.service(&mut server, now).unwrap();
    peer.read_exact(&mut received[sent..]).unwrap();
    assert_eq!(received.as_slice(), &request[..sent + 1]);
}

#[tokio::test]
async fn queued_error_after_forwarded_fin_reaches_terminal_observer() {
    let (mut client, client_id, mut server, id, mut now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(1, &budget);
    let (attach, mut observer, mut peer, _) = attach(&budget);
    let (socket, handle) =
        hold_download_credit(&mut reactor, &mut server, id, attach, &mut peer, now).await;

    peer.shutdown(Shutdown::Write).unwrap();
    wait_for_fd(socket, libc::POLLRDHUP);
    wait_for_fd(reactor.epoll.as_raw_fd(), libc::POLLIN);
    assert!(!reactor.service(&mut server, now).unwrap());
    // ACK the full Stack send ring without servicing the reactor's pending FIN.
    for _ in 0..8 {
        now += Duration::from_millis(10);
        transfer(&mut server, &mut client, now);
        transfer(&mut client, &mut server, now);
    }
    let mut received = [0; FULL_CREDIT.len()];
    assert_eq!(
        client.tcp_read(client_id, &mut received),
        Ok(FULL_CREDIT.len())
    );
    assert_eq!(received, FULL_CREDIT);
    reactor.mark_ready(handle);
    reactor.service(&mut server, now).unwrap();

    now += Duration::from_millis(10);
    transfer(&mut server, &mut client, now);
    let mut response = [0];
    assert_eq!(client.tcp_read(client_id, &mut response), Ok(1));
    assert_eq!(&response, b"r");
    assert_eq!(client.tcp_read(client_id, &mut response), Ok(0));
    let (before_reset, outcome) = expect_update(&mut observer);
    assert_eq!(before_reset.download, 1);
    assert!(outcome.is_none());

    socket2::SockRef::from(&peer)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(peer);
    wait_for_fd(socket, libc::POLLERR);
    wait_for_fd(reactor.epoll.as_raw_fd(), libc::POLLIN);
    reactor.service(&mut server, now).unwrap();
    let (snapshot, outcome) = expect_update(&mut observer);
    let Some(DirectOutcome::Finished(Err(error))) = outcome else {
        panic!("lost the reset after upstream FIN");
    };
    assert!(!error.is::<crate::relay::ClientIoError>());
    // Linux tcp_reset sets SO_ERROR to EPIPE after the peer FIN entered CLOSE_WAIT.
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(libc::EPIPE)
    );
    assert_eq!(snapshot.download, 1);
    assert!(!reactor.has_pending_work());
    assert!(reactor.deadline().is_none());
}

#[test]
fn full_batches_keep_draining_until_the_last_waiter_is_satisfied() {
    let mut stack = client();
    let budget = MemoryBudget::new(1 << 20);
    let mut reactor = new_reactor(2 * BATCH, &budget);
    let mut peers = Vec::with_capacity(2 * BATCH);
    for _ in 0..2 * BATCH {
        let (attach, _, mut peer, _) = attach(&budget);
        peer.write_all(b"r").unwrap();
        wait_for_fd(attach.socket.as_raw_fd(), libc::POLLIN);
        assert!(
            reactor
                .attach(connect(&mut stack), attach, Instant::now())
                .is_ok()
        );
        peers.push(peer);
    }
    assert_eq!(reactor.collect_events().unwrap(), BATCH);
    assert!(owned_kernel_ready(&reactor));
    assert_eq!(reactor.epoll_waiters, BATCH);
    assert_eq!(reactor.collect_events().unwrap(), BATCH);
    assert_eq!(reactor.epoll_waiters, 0);
    assert!(!owned_kernel_ready(&reactor));
    assert!(reactor.has_pending_work());
    assert_eq!(reactor.collect_events().unwrap(), 0);
}

#[test]
fn shared_dispatch_preserves_other_sources_and_rejects_stale_tokens() {
    let (mut left_client, left_client_id, mut left_stack, left_id, now) = connected();
    let (mut right_client, right_client_id, mut right_stack, right_id, _) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let worker = WorkerEpoll::new(&budget, 1).unwrap();
    let mut left = new_reactor(1, &budget);
    let mut right = new_reactor(1, &budget);
    left.bind_worker_epoll(Arc::clone(&worker.fd), 3).unwrap();
    right
        .bind_worker_epoll(Arc::clone(&worker.fd), 127)
        .unwrap();
    let left_tag = TOKEN_DIRECT_BIT | (3 << 56);
    let right_tag = TOKEN_DIRECT_BIT | (127 << 56);

    let (old, _, mut old_peer, _) = attach_with_live_observation(&budget, false);
    old_peer.write_all(b"x").unwrap();
    let old_handle = attach_flow(&mut left, left_id, old, now);
    let old_token = left_tag | (1 << 32);
    let old_events = wait_for_direct_event(
        &worker,
        old_token,
        libc::EPOLLIN as u32,
        "old Direct socket did not report its read edge",
    );
    left.abort(old_handle);

    let (attach, _, mut left_peer, left_counts) = attach_with_live_observation(&budget, false);
    let left_socket = attach.socket.as_raw_fd();
    assert!(left.attach(left_id, attach, now).is_ok());
    let (attach, _, mut right_peer, right_counts) = attach_with_live_observation(&budget, false);
    let right_socket = attach.socket.as_raw_fd();
    assert!(right.attach(right_id, attach, now).is_ok());
    left_peer.write_all(b"l").unwrap();
    right_peer.write_all(b"r").unwrap();
    wait_for_fd(left_socket, libc::POLLIN);
    wait_for_fd(right_socket, libc::POLLIN);
    let (watch, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    worker
        .add_fd(
            watch.as_raw_fd(),
            (libc::EPOLLIN | libc::EPOLLET) as u32,
            TOKEN_TOPOLOGY,
        )
        .unwrap();
    drop(writer);
    Waker::from(Arc::clone(&worker.wake)).wake();

    let mut cx = Context::from_waker(futures::task::noop_waker_ref());
    assert!(left.poll_ready(&mut cx).unwrap());
    assert!(left.service(&mut left_stack, now).unwrap());
    assert!(!left.poll_ready(&mut cx).unwrap());
    assert!(!left.service(&mut left_stack, now).unwrap());
    assert!(right.service(&mut right_stack, now).unwrap());
    assert!(left.watched_pump(old_token).is_none());
    assert!(right.watched_pump(old_token).is_none());
    left.socket_ready(old_token, old_events);
    right.socket_ready(old_token, old_events);
    assert!(!left.has_pending_work());
    assert!(!right.has_pending_work());
    assert_eq!(left_counts.download.load(Ordering::Relaxed), 0);
    assert_eq!(right_counts.download.load(Ordering::Relaxed), 0);
    assert_eq!(left.epoll_waiters(), 1);
    assert_eq!(right.epoll_waiters(), 1);
    assert!(
        worker.wake.is_pending(),
        "Shared Direct consumed a running worker wake"
    );
    worker.wake.drain().unwrap();

    let left_token = left_tag | (2 << 32);
    let right_token = right_tag | (1 << 32);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 3];
    let mut saw_topology = false;
    for _ in 0..3 {
        let count = worker
            .wait(Some(deadline), Instant::now(), &mut events)
            .unwrap();
        assert_ne!(count, 0, "Shared Direct consumed a worker source");
        for event in &events[..count] {
            let token = event.u64;
            match token {
                TOKEN_TOPOLOGY => {
                    assert_ne!(event.events & libc::EPOLLIN as u32, 0);
                    saw_topology = true;
                }
                token if token == left_token => left.socket_ready(token, event.events),
                token if token == right_token => right.socket_ready(token, event.events),
                _ => panic!("unexpected worker token {token:#x}"),
            }
        }
        if saw_topology && left.has_pending_work() && right.has_pending_work() {
            break;
        }
    }
    assert!(saw_topology);
    assert_eq!(left.epoll_waiters(), 0);
    assert_eq!(right.epoll_waiters(), 0);
    assert!(left.service(&mut left_stack, now).unwrap());
    assert!(right.service(&mut right_stack, now).unwrap());
    let ack_at = now + Duration::from_millis(10);
    transfer(&mut left_stack, &mut left_client, ack_at);
    transfer(&mut right_stack, &mut right_client, ack_at);
    let mut bytes = [0];
    assert_eq!(left_client.tcp_read(left_client_id, &mut bytes), Ok(1));
    assert_eq!(&bytes, b"l");
    assert_eq!(right_client.tcp_read(right_client_id, &mut bytes), Ok(1));
    assert_eq!(&bytes, b"r");
}

#[test]
fn shared_watch_generation_wraps_after_proven_removal() {
    let (_, _, mut stack, id, now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let worker = WorkerEpoll::new(&budget, 0).unwrap();
    let mut reactor = new_reactor(1, &budget);
    assert_eq!(
        reactor
            .bind_worker_epoll(Arc::clone(&worker.fd), 128)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    reactor
        .bind_worker_epoll(Arc::clone(&worker.fd), 0)
        .unwrap();
    reactor.slots[0].watch_generation = POISONED_WATCH_GENERATION - 2;

    let (attach, _, mut peer, _) = attach_with_live_observation(&budget, false);
    peer.write_all(b"x").unwrap();
    let old_handle = attach_flow(&mut reactor, id, attach, now);
    let old_token = TOKEN_DIRECT_BIT | (u64::from(POISONED_WATCH_GENERATION - 1) << 32);
    let old_events = wait_for_direct_event(
        &worker,
        old_token,
        libc::EPOLLIN as u32,
        "last valid Direct generation was not registered",
    );
    reactor.abort(old_handle);

    let (attach, _, mut peer, _) = attach_with_live_observation(&budget, false);
    let mut duplicate = attach.socket.try_clone().unwrap();
    let new_handle = attach_flow(&mut reactor, id, attach, now);
    assert_eq!(new_handle.index, old_handle.index);
    assert_eq!(new_handle.generation, old_handle.generation + 1);
    assert_eq!(reactor.live_index(old_handle), None);
    assert_eq!(reactor.live_index(new_handle), Some(new_handle.index));
    reactor.service(&mut stack, now).unwrap();
    assert!(reactor.watched_pump(old_token).is_none());
    reactor.socket_ready(old_token, old_events);
    assert!(!reactor.has_pending_work());

    peer.write_all(b"y").unwrap();
    let new_events = wait_for_direct_event(
        &worker,
        TOKEN_DIRECT_BIT | (1 << 32),
        libc::EPOLLIN as u32,
        "Direct generation did not wrap to one",
    );
    reactor.socket_ready(TOKEN_DIRECT_BIT | (1 << 32), new_events);
    assert!(reactor.has_pending_work());
    let mut byte = [0];
    duplicate.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"y");
    drop(reactor);
    peer.write_all(b"z").unwrap();
    wait_for_fd(duplicate.as_raw_fd(), libc::POLLIN);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }];
    assert_eq!(worker.poll_nonblocking(&mut events).unwrap(), 0);
}

#[test]
fn shared_unblocked_upload_leaves_epollout_unarmed() {
    let (mut client, client_id, mut server, id, now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let worker = WorkerEpoll::new(&budget, 0).unwrap();
    let mut reactor = new_reactor(1, &budget);
    reactor
        .bind_worker_epoll(Arc::clone(&worker.fd), 0)
        .unwrap();
    let (attach, _, mut peer, _) = attach_with_live_observation(&budget, false);
    let socket = attach.socket.as_raw_fd();
    wait_for_fd(socket, libc::POLLOUT);
    let handle = attach_flow(&mut reactor, id, attach, now);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }];
    assert_eq!(worker.poll_nonblocking(&mut events).unwrap(), 0);

    assert_eq!(client.tcp_write(client_id, b"request"), Ok(7));
    deliver_client_turn(
        &mut client,
        &mut server,
        &mut reactor,
        (id, handle),
        now + Duration::from_millis(10),
    );
    let mut received = [0; 7];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"request");
    assert!(!reactor.slots[0].epoll_out_armed);
    assert_eq!(worker.poll_nonblocking(&mut events).unwrap(), 0);
}

#[test]
fn shared_second_mod_preserves_epollout_and_resumes_upload() {
    let (mut client, client_id, mut server, id, mut now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let worker = WorkerEpoll::new(&budget, 0).unwrap();
    let mut reactor = new_reactor(1, &budget);
    reactor
        .bind_worker_epoll(Arc::clone(&worker.fd), 19)
        .unwrap();
    let (attach, mut observer, mut peer, counters) = constrained_socket(&budget);
    let socket = attach.socket.as_raw_fd();
    let handle = attach_flow(&mut reactor, id, attach, now);
    let request: Vec<u8> = (0..(64 << 10)).map(|i| (i % 251) as u8).collect();
    assert_eq!(client.tcp_write(client_id, &request), Ok(request.len()));
    drive_until_write_wait(
        &mut reactor,
        &mut client,
        &mut server,
        handle,
        &mut now,
        |_, _| {
            panic!("Direct upload ended before the peer opened its window");
        },
    );
    assert!(reactor.slots[0].epoll_out_armed);
    assert!(reactor.slots[0].epoll_et);
    // The second MOD must keep existing writable interest without a new request.
    reactor.slots[0]
        .modify_watch(&reactor.epoll, 0, false)
        .unwrap();
    assert!(reactor.slots[0].epoll_out_armed);
    assert!(!reactor.has_pending_work());
    assert!(
        server
            .tcp_peek_rx(id, 1)
            .is_ok_and(|(_, count, _)| count == 1)
    );
    let sent_before_drain = counters.upload.load(Ordering::Relaxed) as usize;
    assert!(sent_before_drain > 0 && sent_before_drain < request.len());

    let token = TOKEN_DIRECT_BIT | (19 << 56) | (1 << 32);
    let mut received = vec![0; request.len()];
    let mut received_len = sent_before_drain;
    peer.read_exact(&mut received[..received_len]).unwrap();
    for _ in 0..BATCH {
        if reactor.slots[0].pump.as_ref().unwrap().wants_write_epoll() {
            wait_for_fd(socket, libc::POLLOUT);
            let ready = wait_for_direct_event(
                &worker,
                token,
                libc::EPOLLOUT as u32,
                "blocked Direct upload did not receive EPOLLOUT after peer drain",
            );
            reactor.socket_ready(token, ready);
        }
        reactor.service(&mut server, now).unwrap();
        let sent = counters.upload.load(Ordering::Relaxed) as usize;
        assert!(sent > sent_before_drain, "EPOLLOUT did not resume upload");
        peer.read_exact(&mut received[received_len..sent]).unwrap();
        received_len = sent;
        if received_len == request.len() {
            break;
        }
        now += Duration::from_millis(10);
        transfer(&mut server, &mut client, now);
        transfer(&mut client, &mut server, now);
        reactor.mark_ready(handle);
    }
    assert_eq!(received_len, request.len());
    assert_eq!(received, request);

    client.tcp_shutdown(client_id).unwrap();
    deliver_client(
        &mut client,
        &mut server,
        &mut reactor,
        (id, handle),
        &mut now,
    );
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    peer.shutdown(Shutdown::Write).unwrap();
    let ready = wait_for_direct_event(
        &worker,
        token,
        libc::EPOLLRDHUP as u32,
        "Direct socket did not receive the peer's FIN after upload",
    );
    reactor.socket_ready(token, ready);
    reactor.service(&mut server, now).unwrap();
    let (snapshot, outcome) = expect_update(&mut observer);
    assert_eq!(snapshot.upload, request.len() as u64);
    assert!(matches!(outcome, Some(DirectOutcome::Finished(Ok(_)))));
    assert_eq!(reactor.epoll_waiters(), 0);
}

#[test]
fn shared_mod_failure_finishes_and_releases_the_absent_watch() {
    let (mut client, client_id, mut server, id, mut now) = connected();
    let budget = MemoryBudget::new(1 << 20);
    let worker = WorkerEpoll::new(&budget, 0).unwrap();
    let mut reactor = new_reactor(1, &budget);
    reactor
        .bind_worker_epoll(Arc::clone(&worker.fd), 0)
        .unwrap();
    let (attach, mut observer, _peer, _) = constrained_socket(&budget);
    let handle = attach_flow(&mut reactor, id, attach, now);
    let socket = &reactor.slots[0].pump.as_ref().unwrap().socket;
    reactor
        .epoll
        .control(libc::EPOLL_CTL_DEL, socket, None)
        .unwrap();
    let request = [0x5a; 64 << 10];
    assert_eq!(client.tcp_write(client_id, &request), Ok(request.len()));
    let slot = &mut reactor.slots[0];
    assert_eq!(
        slot.modify_watch(&reactor.epoll, 0, true)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOENT)
    );
    assert!(!slot.epoll_out_armed && !slot.epoll_et);
    let mut closed = None;
    drive_until_write_wait(
        &mut reactor,
        &mut client,
        &mut server,
        handle,
        &mut now,
        |stack, id| {
            assert!(closed.replace(id).is_none());
            stack.tcp_close(id);
        },
    );

    assert_eq!(closed, Some(id));
    let (_, outcome) = expect_update(&mut observer);
    let Some(DirectOutcome::Finished(Err(error))) = outcome else {
        panic!("Direct MOD failure did not reach the terminal observer");
    };
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
        Some(libc::ENOENT)
    );
    assert_eq!(reactor.epoll_waiters(), 0);
    assert!(!reactor.has_pending_work());
    assert_eq!(&reactor.free, &[0]);
}

#[derive(Default)]
struct TerminalWake {
    closed: AtomicBool,
    woken: AtomicBool,
}

impl Wake for TerminalWake {
    fn wake(self: Arc<Self>) {
        assert!(
            self.closed.load(Ordering::Acquire),
            "Direct woke before close"
        );
        self.woken.store(true, Ordering::Release);
    }
}

#[test]
fn finish_callback_precedes_observer_wake_on_success_error_and_drain() {
    for (reset, peer_fin) in [(false, true), (true, false), (false, false)] {
        let (mut client, client_id, mut server, id, mut now) = connected();
        let budget = MemoryBudget::new(1 << 20);
        let worker = WorkerEpoll::new(&budget, 0).unwrap();
        let mut reactor = new_reactor(1, &budget);
        reactor
            .bind_worker_epoll(Arc::clone(&worker.fd), 0)
            .unwrap();
        let (attach, mut observer, peer, _) = attach_with_live_observation(&budget, false);
        let handle = attach_flow(&mut reactor, id, attach, now);
        assert!(expect_update(&mut observer).0.attached);
        let signal = Arc::new(TerminalWake::default());
        let waker = Waker::from(Arc::clone(&signal));
        let mut cx = Context::from_waker(&waker);
        assert!(observer.poll_update(&mut cx).is_pending());

        if reset {
            client.tcp_abort(client_id);
        } else {
            client.tcp_shutdown(client_id).unwrap();
        }
        now += Duration::from_millis(10);
        transfer(&mut client, &mut server, now);
        reactor.mark_ready(handle);
        if peer_fin {
            peer.shutdown(Shutdown::Write).unwrap();
            let token = TOKEN_DIRECT_BIT | (1 << 32);
            let ready = wait_for_direct_event(
                &worker,
                token,
                libc::EPOLLRDHUP as u32,
                "Direct socket did not report the peer's FIN",
            );
            reactor.socket_ready(token, ready);
        } else if !reset {
            reactor
                .service_with_finish(&mut server, now, |_, _| panic!("Direct drained early"))
                .unwrap();
            now = reactor.deadline().expect("Direct half-close deadline");
        }
        let mut turn = reactor.begin_service().unwrap();
        let (flow, publish) = reactor.next_finished(&mut server, now, &mut turn).unwrap();
        assert_eq!(flow, id);
        assert_eq!(reactor.live_index(handle), None);
        assert!(!signal.woken.load(Ordering::Acquire));
        server.tcp_close(flow);
        assert!(!signal.closed.swap(true, Ordering::AcqRel));
        publish();

        assert!(signal.woken.load(Ordering::Acquire));
        let (_, outcome) = expect_update(&mut observer);
        let Some(DirectOutcome::Finished(result)) = outcome else {
            panic!("expected terminal Direct observer outcome");
        };
        assert_eq!(result.is_err(), reset);
        assert_eq!(reactor.epoll_waiters(), 0);
    }
}

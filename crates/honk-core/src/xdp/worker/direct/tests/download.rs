use super::*;
use honk_netstack::Rx;

#[test]
fn socket_receive_prefix_reaches_client_before_eof_or_reset() {
    const RESPONSE: &[u8] = b"response before terminal state";
    for reset in [false, true] {
        let (mut client, client_id, mut server, id, mut now) = connected();
        let budget = MemoryBudget::new(1 << 20);
        let mut reactor = new_reactor(1, &budget);
        let (attach, mut observer, mut peer, counters) = attach(&budget);
        let socket = attach.socket.as_raw_fd();
        peer.write_all(RESPONSE).unwrap();
        wait_for_fd(socket, libc::POLLIN);
        now = (now + Duration::from_millis(10)).max(Instant::now());
        if reset {
            socket2::SockRef::from(&peer)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(peer);
            wait_for_fd(socket, libc::POLLERR);
        } else {
            peer.shutdown(Shutdown::Write).unwrap();
            wait_for_fd(socket, libc::POLLRDHUP);
            client.tcp_shutdown(client_id).unwrap();
            transfer(&mut client, &mut server, now);
        }
        assert!(reactor.attach(id, attach, now).is_ok());
        let mut closed = None;
        reactor
            .service_with_finish(&mut server, now, |stack, id| {
                assert!(closed.replace(id).is_none());
                stack.tcp_close(id);
            })
            .unwrap();
        assert_eq!(closed, Some(id));
        assert_eq!(
            counters.download.load(Ordering::Relaxed),
            RESPONSE.len() as u64
        );

        transfer(&mut server, &mut client, now);
        let mut received = [0; RESPONSE.len()];
        assert_eq!(
            client.tcp_read(client_id, &mut received),
            Ok(RESPONSE.len())
        );
        assert_eq!(&received, RESPONSE);
        assert_eq!(client.tcp_read(client_id, &mut [0]), Ok(0));

        let (snapshot, outcome) = expect_update(&mut observer);
        assert_eq!(snapshot.download, RESPONSE.len() as u64);
        assert_eq!(snapshot.first_response, Some(now));
        match (reset, outcome) {
            (false, Some(DirectOutcome::Finished(Ok(stats)))) => {
                assert_eq!(stats.proxy_to_client, RESPONSE.len() as u64);
            }
            (true, Some(DirectOutcome::Finished(Err(error)))) => {
                assert!(!error.is::<crate::relay::ClientIoError>());
                assert_eq!(
                    error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                    Some(libc::ECONNRESET)
                );
            }
            _ => panic!("lost Direct socket terminal outcome"),
        }
        assert!(!reactor.has_pending_work());
        assert!(reactor.deadline().is_none());
    }
}

#[tokio::test]
async fn bulk_download_uses_partial_credit_before_ack() {
    const CHUNK: usize = 4 << 10;
    let budget = MemoryBudget::new(8 << 20);
    let mut now = Instant::now();
    let mut cfg = Config::new([29; 32]);
    cfg.local_v4 = Some([192, 0, 2, 1].into());
    cfg.mtu = 32 << 10;
    cfg.max_flows = 1;
    cfg.memory_limit = 512 << 10;
    cfg.tcp_chunk = Some(CHUNK);
    cfg.tcp_rcv_buf_max = 96 << 10;
    cfg.tcp_snd_buf_max = 128 << 10;
    let mut client = Stack::new(cfg.clone(), now);
    connect(&mut client);
    cfg.mode = Mode::Transparent {
        exclude: ExcludeSet::default(),
    };
    cfg.shared_budget = Some(Arc::clone(&budget));
    let mut server = Stack::new_accounted(cfg, now, 1).unwrap();
    now += Duration::from_millis(1);
    transfer(&mut client, &mut server, now);
    let id = server.poll_accept().unwrap().id;
    server.tcp_accept(id, AcceptOpts::default()).unwrap();
    transfer(&mut server, &mut client, now);
    transfer(&mut client, &mut server, now);
    assert_eq!(server.tcp_state(id), Some(TcpState::Established));

    // Leave one segment in flight with only 8 KiB of application TX room.
    let queued = [0x5a; 120 << 10];
    assert_eq!(server.tcp_write(id, &queued), Ok(queued.len()));
    let mut packet = [0; 32 << 10];
    let len = server.poll_transmit(now, &mut packet).unwrap();
    assert_eq!(client.receive(now, &packet[..len]), Rx::Consumed);

    let mut reactor = new_reactor(1, &budget);
    let (attach, _, mut peer, counters) = attach(&budget);
    peer.write_all(&[0xa5; CHUNK + 1]).unwrap();
    wait_for_fd(attach.socket.as_raw_fd(), libc::POLLIN);
    assert!(reactor.attach(id, attach, now).is_ok());
    tokio::time::timeout(
        Duration::from_secs(2),
        poll_fn(|cx| {
            while reactor.poll_ready(cx).unwrap() {
                reactor.service(&mut server, now).unwrap();
                if counters.download.load(Ordering::Relaxed) == CHUNK as u64 + 1 {
                    return Poll::Ready(());
                }
            }
            Poll::Pending
        }),
    )
    .await
    .unwrap();
}

use super::*;

fn assert_accounted_heap(budget: &MemoryBudget) {
    assert_eq!(
        UNFUNDED_HEAP.get(),
        None,
        "allocation exceeds contemporaneous funding (live heap, charged budget)"
    );
    assert!(
        LIVE_BYTES.get() <= budget.used(),
        "retained allocation exceeds its funding"
    );
}

pub(super) fn stress() {
    let budget = MemoryBudget::new(32 * 1024 * 1024);
    LIVE_BYTES.set(0);
    UNFUNDED_HEAP.set(None);
    HEAP_BUDGET.with(|tracked| *tracked.borrow_mut() = Some(budget.clone()));
    HEAP_COUNTING.set(true);
    {
        let mut f = Flow::configured(Some(budget.clone()));
        assert_accounted_heap(&budget);
        f.grow(256);
        assert_accounted_heap(&budget);
        let data = vec![0xa5; 128 * MSS];
        for _ in 0..32 {
            assert_eq!(f.stack.tcp_write(f.id, &data), Ok(data.len()));
            assert!(f.stack.poll_control_transmit(f.now, &mut f.out).is_none());
            f.send(128);
            f.now += 10 * MS;
            // Retain one segment: ring and scoreboard capacity must stay funded after draining.
            let ack = f.encode(&f.header(f.snd_nxt.wrapping_sub(MSS as u32)), &[]);
            assert_eq!(f.stack.receive(f.now, &ack), Rx::Consumed);
            assert_accounted_heap(&budget);
        }
        let ack = f.ack_all();
        assert_eq!(f.stack.receive(f.now, &ack), Rx::Consumed);
        let start = f.snd_nxt;
        assert_eq!(f.stack.tcp_write(f.id, &data), Ok(data.len()));
        f.send(128);
        f.now += 10 * MS;
        let mut header = f.header(start);
        header
            .options
            .sack
            .push(start.wrapping_add((64 * MSS) as u32), f.snd_nxt);
        let sack = f.encode(&header, &[]);
        assert_eq!(f.stack.receive(f.now, &sack), Rx::Consumed);
        for _ in 0..256 {
            if f.stack.poll_transmit(f.now, &mut f.out).is_none() {
                match f.stack.poll_timeout() {
                    Some(at) if at.saturating_duration_since(f.now) <= 5 * MS => {
                        f.now = at.max(f.now);
                        f.stack.handle_timeout(f.now);
                    }
                    _ => break,
                }
            }
            assert_accounted_heap(&budget);
        }
        assert!(
            f.stack.tcp_stats(f.id).unwrap().retrans_segments > 16,
            "exercise retained RACK FIFO capacity beyond its fixed floor"
        );
        let ack = f.ack_all();
        assert_eq!(f.stack.receive(f.now, &ack), Rx::Consumed);
        for _ in 0..32 {
            let mut header = f.header(f.snd_nxt);
            header.seq = f.peer_next.wrapping_add(20_000);
            let ooo = f.encode(&header, &[7; MSS]);
            assert_eq!(f.stack.receive(f.now, &ooo), Rx::Consumed);
            for _ in 0..20 {
                let packet = f.data_packet(&[8; 1000]);
                assert_eq!(f.stack.receive(f.now, &packet), Rx::Consumed);
            }
            f.peer_next = f.peer_next.wrapping_add(MSS as u32);
            let mut read = [0; 20_000];
            assert_eq!(f.stack.tcp_read(f.id, &mut read), Ok(read.len()));
            assert_accounted_heap(&budget);
            assert_eq!(f.stack.tcp_read(f.id, &mut read), Ok(MSS));
            while f.stack.poll_control_transmit(f.now, &mut f.out).is_some() {}
            f.now += 10 * MS;
        }
        for _ in 0..1000 {
            let pending = f.stack.tcp_connect(f.now, remote()).unwrap();
            f.stack.tcp_close(pending);
        }
        assert_accounted_heap(&budget);
        f.stack.tcp_close(f.id);
        let n = f.stack.poll_transmit(f.now, &mut f.out).expect("FIN");
        let ip = wire::parse_ip(&f.out[..n]).unwrap();
        let (fin, _) = tcp::parse(&f.out[ip.payload]).unwrap();
        assert_ne!(fin.flags & tcp::FIN, 0);
        let mut header = f.header(fin.seq.wrapping_add(1));
        header.flags |= tcp::FIN;
        let packet = f.encode(&header, &[]);
        assert_eq!(f.stack.receive(f.now, &packet), Rx::Consumed);
        while f.stack.poll_control_transmit(f.now, &mut f.out).is_some() {}
        assert_eq!(f.stack.stats().timewait_entries, 1);
        assert_accounted_heap(&budget);

        let mut cfg = Config::new([0x59; 32]);
        cfg.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
        cfg.mtu = 1280;
        cfg.max_flows = 32;
        cfg.memory_limit = 512 * 1024;
        cfg.fragment_limits.max_entries = 32;
        cfg.icmp_limits.burst = 1000;
        cfg.shared_budget = Some(budget.clone());
        let mut stack = Stack::new_accounted(cfg, f.now, 64).unwrap();
        let src: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:40000".parse().unwrap();
        let mut output = [0; 2000];
        let mut queued = 0;
        loop {
            match stack.udp_send_from(src, dst, &[3; 1233], &mut output) {
                Ok(_) => queued += 1,
                Err(UdpError::Busy) => break,
                other => panic!("unexpected fragment queue result: {other:?}"),
            }
            assert_accounted_heap(&budget);
        }
        assert!(
            queued > 400,
            "exercise geometric Pending metadata high water"
        );
        let mut packet = [0; 2000];
        let local: IpAddr = "203.0.113.1".parse().unwrap();
        for index in 0..256u16 {
            let peer = std::net::Ipv4Addr::new(198, 51, 100, (index % 250 + 1) as u8);
            let n = wire::udp::emit_packet(
                &mut packet,
                SocketAddr::new(peer.into(), 40000),
                SocketAddr::new(local, 53),
                b"quote",
            )
            .unwrap();
            stack
                .udp_refuse(f.now, UdpRefuse::PortUnreachable, &packet[..n], &mut output)
                .unwrap();
            let h = wire::ipv4::emit(
                &mut packet,
                peer,
                "203.0.113.1".parse().unwrap(),
                wire::PROTO_UDP,
                8,
            )
            .unwrap();
            packet[4..6].copy_from_slice(&index.to_be_bytes());
            packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
            packet[10..12].fill(0);
            let checksum = wire::checksum::checksum(&packet[..h]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            packet[h..h + 8].fill(0);
            assert_eq!(stack.receive(f.now, &packet[..h + 8]), Rx::Consumed);
            assert_accounted_heap(&budget);
        }
        f.now += Duration::from_secs(31);
        stack.handle_timeout(f.now);
        assert_accounted_heap(&budget);
        for port in 40000..41000 {
            let header = tcp::Header {
                src_port: port,
                dst_port: 443,
                seq: 100,
                ack: 0,
                flags: tcp::SYN,
                window: 65535,
                urgent: 0,
                options: tcp::Options::default(),
            };
            let n = tcp::emit_packet(
                &mut packet,
                "198.51.100.2".parse().unwrap(),
                local,
                &header,
                [&[], &[]],
            )
            .unwrap();
            assert_eq!(stack.receive(f.now, &packet[..n]), Rx::Consumed);
            let id = stack.poll_accept().unwrap().id;
            stack.tcp_refuse(id, Refuse::Rst);
            assert_accounted_heap(&budget);
        }
        while stack.poll_transmit(f.now, &mut output).is_some() {}
        assert_accounted_heap(&budget);
    }
    assert_accounted_heap(&budget);
    assert_eq!(
        LIVE_BYTES.get(),
        0,
        "all measured allocation owners were dropped"
    );
    assert_eq!(budget.used(), 0);
    HEAP_COUNTING.set(false);
    HEAP_BUDGET.with(|tracked| *tracked.borrow_mut() = None);
}

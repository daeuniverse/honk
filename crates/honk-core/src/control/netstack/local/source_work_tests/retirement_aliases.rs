use super::*;
use std::pin::pin;
use tokio::io::AsyncReadExt;

fn control_output(driver: &mut PacketDriver, now: Instant) -> (OutputOwner, tcp::Header) {
    let mut packet = [0; 1280];
    let MaterializedOutput::Packet(output) = driver
        .materialize_into(now, TxClass::Control, &mut packet)
        .unwrap()
    else {
        panic!("expected original TCP control output");
    };
    let ip = wire::parse_ip(&packet[..output.owner.len()]).unwrap();
    let (header, _) = tcp::parse(&packet[ip.payload]).unwrap();
    (output.owner, header)
}

#[tokio::test]
async fn time_wait_and_output_return_fence_reused_flow_slots() {
    for cq_first in [false, true] {
        let (scope, owner, mut driver) = super::super::tests::physical();
        let shared = scope.0.local.get().unwrap();
        let authority = PeerAuthority::new(Arc::new(true.into()), &scope.0.budget).unwrap();
        let client = "192.0.2.1:45001".parse().unwrap();
        let destination = "203.0.113.2:443".parse().unwrap();
        let now = Instant::now();
        let mut cx = Context::from_waker(Waker::noop());
        let (mut flow, ack) = accept(&mut driver, &authority, client, destination, now);
        let id = flow.flow_id();
        let stale = flow.local().unwrap().clone();
        let callbacks = Arc::new(AtomicUsize::new(0));
        let fired = Arc::clone(&callbacks);
        flow.set_retirement_callback(move || {
            fired.fetch_add(1, Ordering::Relaxed);
        })
        .unwrap();
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, ack, tcp::ACK, b""),
            now,
        );
        driver.finish_turn(&mut cx, now);
        drop(flow);
        let now = now + Duration::from_millis(1);
        driver.finish_turn(&mut cx, now);
        let (mut fin, header) = control_output(&mut driver, now);
        assert_eq!(fin.flow_id(), Some(id));
        assert_ne!(header.flags & tcp::FIN, 0);
        let end = header.seq.wrapping_add(1);
        if cq_first {
            assert!(driver.complete_local(&mut fin));
        }

        let closed = now + Duration::from_millis(2);
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, end, tcp::ACK, b""),
            closed - Duration::from_millis(1),
        );
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, end, tcp::ACK | tcp::FIN, b""),
            closed,
        );
        let (mut ack_owner, header) = control_output(&mut driver, closed);
        assert_eq!(ack_owner.flow_id(), Some(id));
        assert_eq!((header.flags, header.ack), (tcp::ACK, 102));
        assert!(driver.complete_local(&mut ack_owner));
        driver.finish_turn(&mut cx, closed);
        shared.deliver_callbacks();
        assert_eq!(scope.stats().unwrap().timewait_entries, 1);
        assert!(scope.retains_tcp(client, destination));
        assert_eq!(callbacks.load(Ordering::Relaxed), 0);

        let now = closed + Duration::from_secs(61);
        driver.finish_turn(&mut cx, now);
        shared.deliver_callbacks();
        assert!(!driver.local_retains_tcp(client, destination));
        assert_eq!(scope.retains_tcp(client, destination), !cq_first);
        assert_eq!(callbacks.load(Ordering::Relaxed), usize::from(cq_first));
        let (mut next, next_ack) = accept(&mut driver, &authority, client, destination, now);
        let replacement = next.flow_id();
        assert_eq!(id.index(), replacement.index());
        assert_ne!(id, replacement);
        {
            let local = driver.local.as_ref().unwrap();
            let slots = local.inner.local_slots.as_ref().unwrap();
            assert!(slots.active(&id).is_none());
            assert!(slots.active(&replacement).is_some());
            assert_eq!(slots.retiring_aliases.contains_key(&id), !cq_first);
            assert_eq!(slots.get(&id).is_some(), !cq_first);
            assert_ne!(slots.get(&id), slots.get(&replacement));
        }
        stale.abort();
        if !cq_first {
            assert!(driver.complete_local(&mut fin));
        }
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, next_ack, tcp::ACK, b""),
            now,
        );
        driver.finish_turn(&mut cx, now);
        shared.deliver_callbacks();
        assert_eq!(callbacks.load(Ordering::Relaxed), 1);
        assert!(scope.retains_tcp(client, destination));
        assert!(matches!(
            pin!(stale.wait()).poll(&mut cx),
            Poll::Ready(Ok(()))
        ));
        {
            let mut attach = pin!(next.attach_remote());
            assert!(attach.as_mut().poll(&mut cx).is_pending());
            driver.finish_turn(&mut cx, now);
            assert!(matches!(attach.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        let data = b"successor";
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, next_ack, tcp::ACK, data),
            now,
        );
        driver.finish_turn(&mut cx, now);
        let mut read = [0; 9];
        assert!(matches!(
            pin!(next.read_exact(&mut read)).poll(&mut cx),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(&read, data);

        drop(next);
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(owner.reclaim().await);
        owner.run().await;
        assert_eq!(callbacks.load(Ordering::Relaxed), 1);
    }
}

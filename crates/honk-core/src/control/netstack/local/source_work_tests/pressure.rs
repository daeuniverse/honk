use super::*;
use std::io::IoSlice;
use std::pin::pin;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn local_tcp_admission_reclaims_idle_chunks_once() {
    for before_syn in [false, true] {
        let (scope, owner, mut driver) = super::super::tests::physical();
        let shared = scope.0.local.get().unwrap();
        let budget = &scope.0.budget;
        let authority = PeerAuthority::new(Arc::new(true.into()));
        let now = Instant::now();
        let client = "192.0.2.1:45001".parse().unwrap();
        let next = "192.0.2.2:45002".parse().unwrap();
        let destination = "203.0.113.2:443".parse().unwrap();
        let (mut flow, ack) = accept(&mut driver, &authority, client, destination, now);
        let id = flow.flow_id();
        receive(
            &mut driver,
            &authority,
            &input(client, destination, 101, ack, tcp::ACK, b""),
            now,
        );
        let mut cx = Context::from_waker(Waker::noop());
        driver.finish_turn(&mut cx, now);
        {
            let mut attach = pin!(flow.attach_remote());
            assert!(attach.as_mut().poll(&mut cx).is_pending());
            driver.finish_turn(&mut cx, now);
            assert!(matches!(attach.poll(&mut cx), Poll::Ready(Ok(()))));
        }
        let idle = budget.used();
        // The first chunk uses the small-flow size. Only the six full bulk chunks cache.
        let seed = vec![7; 6 * remote::BULK_CHUNK + (4 << 10)];
        let remote = driver
            .local
            .as_mut()
            .unwrap()
            .flows
            .get_mut(&id)
            .unwrap()
            .remote
            .as_mut()
            .unwrap();
        assert_eq!(remote.push_rx(&[IoSlice::new(&seed)]), seed.len());
        let mut read = vec![0; seed.len()];
        flow.read_exact(&mut read).await.unwrap();
        assert_eq!(read, seed);
        assert!(budget.used() >= idle + 6 * remote::BULK_CHUNK);

        let drains = shared.pool.drains();
        let syn = input(next, destination, 100, 0, tcp::SYN, b"");
        if !before_syn {
            assert!(receive(&mut driver, &authority, &syn, now).taken_over);
        }
        let occupied = budget
            .reserve(budget.limit().saturating_sub(budget.used()))
            .unwrap();
        assert_eq!(budget.limit().saturating_sub(budget.used()), 0);
        if before_syn {
            assert!(receive(&mut driver, &authority, &syn, now).taken_over);
        }
        let (syn, admitted) = driver
            .poll_accept_local()
            .unwrap()
            .expect("funded original SYN");
        assert_eq!(admitted.peer_addr(), next);
        assert_eq!(shared.pool.drains(), drains + 1);
        let mut bytes = [0; 1280];
        let MaterializedOutput::Packet(mut output) = driver
            .materialize_into(now, TxClass::Control, &mut bytes)
            .unwrap()
        else {
            panic!("admitted flow owes a SYN-ACK");
        };
        assert_eq!(output.owner.flow_id(), Some(syn.id));
        assert!(driver.complete_local(&mut output.owner));

        drop((occupied, admitted, flow));
        scope.shutdown(true);
        driver.service_closing(&mut cx, now);
        assert!(owner.reclaim().await);
        owner.run().await;
    }
}

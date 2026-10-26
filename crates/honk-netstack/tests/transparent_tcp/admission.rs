use super::*;
use honk_netstack::MemoryBudget;

#[test]
fn duplicate_syn_output_cannot_postpone_passive_handshake_timeout() {
    let t0 = Instant::now();
    let budget = MemoryBudget::new(128 * 1024);
    let mut cfg = transparent();
    cfg.shared_budget = Some(budget.clone());
    let mut stack = Stack::new(cfg, t0);
    let peer = Peer::new(CLIENT, DST, 1000);
    assert_eq!(peer.syn(&mut stack, t0, 1460), Rx::Consumed);
    let info = info_of(&mut stack);
    stack.tcp_accept(info.id, AcceptOpts::default()).unwrap();
    assert_eq!(drain(&mut stack, t0).len(), 1);
    for tick in 1..=400 {
        let now = t0 + Duration::from_millis(tick * 500);
        while let Some(at) = stack.poll_timeout().filter(|&at| at <= now) {
            stack.handle_timeout(at);
            drain(&mut stack, at);
        }
        if stack.tcp_state(info.id) == Some(TcpState::Closed) {
            break;
        }
        assert_eq!(peer.syn(&mut stack, now, 1460), Rx::Consumed);
        assert_eq!(drain(&mut stack, now).len(), 1);
        assert!(stack.poll_accept().is_none());
    }
    assert_eq!(
        stack.tcp_read(info.id, &mut [0; 1]),
        Err(StreamError::TimedOut)
    );
    assert_eq!(stack.stats().half_open, 0);
    stack.tcp_close(info.id);
    assert_eq!(stack.stats().flows, 0);
    assert_eq!(budget.used(), 0);
}

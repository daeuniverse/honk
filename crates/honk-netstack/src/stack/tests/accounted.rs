use super::*;
use std::time::Duration;

fn bounded(slots: usize) -> (Stack, Arc<MemoryBudget>) {
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut cfg = Config::new([71; 32]);
    cfg.local_v4 = Some("192.0.2.1".parse().unwrap());
    cfg.memory_limit = 512 * 1024;
    cfg.max_flows = 4;
    cfg.shared_budget = Some(budget.clone());
    (
        Stack::new_accounted(cfg, Instant::now(), slots).unwrap(),
        budget,
    )
}

fn reusable_tombstone(stack: &mut Stack, exhausted: bool, now: Instant) -> FlowId {
    let local_ip = stack.cfg.local_v4.unwrap().into();
    let remote = "198.51.100.1:443".parse().unwrap();
    let port = Ports::new(&stack.cfg.secret).start(&stack.cfg.secret, local_ip, remote);
    let tuple = FourTuple {
        local: SocketAddr::new(local_ip, port),
        remote,
    };
    let offset = flow::ts_offset(&stack.cfg.secret, local_ip, remote.ip());
    let stamp = offset.wrapping_add(now.duration_since(stack.epoch).as_millis() as u32);
    let iss = flow::isn(&stack.cfg.secret, tuple, now.duration_since(stack.epoch));
    let id = stack.table.insert(Flow::TimeWait(TimeWait {
        tuple,
        handle_generation: 1,
        snd_nxt: iss.wrapping_sub(1),
        rcv_nxt: 200,
        max_snd_wnd: u16::MAX.into(),
        ts_recent: Some(1),
        ts_offset: offset,
        ts_last: stamp.wrapping_sub(1),
        window: 1,
        expiry: now + Duration::from_secs(60),
        ack_due: true,
    }));
    if exhausted {
        stack.table.slots[id.idx as usize].generation = 0;
    }
    id
}

#[test]
fn failed_active_floor_admission_does_not_erase_a_reusable_time_wait() {
    let (mut stack, budget) = bounded(1);
    let now = stack.epoch + Duration::from_secs(1);
    let id = reusable_tombstone(&mut stack, false, now);
    let held = budget.reserve(budget.limit() - budget.used()).unwrap();
    assert_eq!(
        stack.tcp_connect(now, "198.51.100.1:443".parse().unwrap()),
        Err(ConnectError::Memory)
    );
    assert!(stack.tcp_retained(id));
    assert_eq!(stack.table.timewait.len(), 1);
    assert!(
        matches!(&stack.table.slots[id.idx as usize].flow, Some(Flow::TimeWait(tw)) if tw.ack_due)
    );
    drop(held);
    stack.ports = Ports::new(&stack.cfg.secret);
    let next = stack
        .tcp_connect(now, "198.51.100.1:443".parse().unwrap())
        .unwrap();
    assert_eq!(next.idx, id.idx);
    assert_ne!(next.generation, id.generation);
    assert!(!stack.tcp_retained(id));
}

#[test]
fn exhausted_replacement_requires_another_funded_slot() {
    for slots in [1, 2] {
        let (mut stack, budget) = bounded(slots);
        let now = stack.epoch + Duration::from_secs(1);
        let id = reusable_tombstone(&mut stack, true, now);
        let result = stack.tcp_connect(now, "198.51.100.1:443".parse().unwrap());
        if slots == 1 {
            assert_eq!(result, Err(ConnectError::FlowLimit));
            assert!(stack.tcp_retained(id));
            assert_eq!(stack.table.timewait.len(), 1);
        } else {
            let next = result.unwrap();
            assert_ne!(next.idx, id.idx);
            assert!(!stack.tcp_retained(id));
            assert_eq!(stack.table.slots.len(), 2);
        }
        drop(stack);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn exhausted_empty_slots_count_against_the_slab_bound() {
    let (mut stack, budget) = bounded(1);
    let id = stack.udp_bind(Some(9000)).unwrap();
    stack.table.slots[id.idx as usize].generation = u32::MAX;
    stack.udp_close(FlowId {
        generation: u32::MAX,
        ..id
    });
    assert_eq!(stack.table.slots[0].generation, 0);
    assert_eq!(stack.udp_bind(Some(9001)), Err(BindError::FlowLimit));
    assert_eq!(
        stack.tcp_connect(stack.now, "198.51.100.1:443".parse().unwrap()),
        Err(ConnectError::FlowLimit)
    );
    assert_eq!(stack.table.slots.len(), 1);
    drop(stack);
    assert_eq!(budget.used(), 0);
}

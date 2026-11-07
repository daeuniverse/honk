//! The binding owner on kernels without TCX (before Linux 6.6): every hook is
//! a clsact filter at honk's priority. Each case checks the kernel's filter
//! dump, not the owner's records.

use super::*;
use crate::netlink::tc::{TC_PARENT_EGRESS, TC_PARENT_INGRESS, TcFilterEntry};
use TcProgram::*;

fn clsact_netns(test: impl FnOnce() + Send + 'static) {
    if owner::tcx_supported() {
        eprintln!("skipped: TCX kernels bind links, not clsact filters");
        return;
    }
    private_netns(test);
}

fn parent(direction: Direction) -> u32 {
    match direction {
        Direction::Ingress => TC_PARENT_INGRESS,
        Direction::Egress => TC_PARENT_EGRESS,
    }
}

fn filters(ifindex: u32, direction: Direction) -> Vec<TcFilterEntry> {
    NlSock::new()
        .unwrap()
        .dump_filters(ifindex, parent(direction))
        .unwrap()
}

fn honk_filters(ifindex: u32, direction: Direction) -> Vec<(u32, Option<u32>)> {
    filters(ifindex, direction)
        .into_iter()
        .filter(|entry| entry.priority == owner::FILTER_PRIORITY)
        .map(|entry| (entry.handle, entry.program_id))
        .collect()
}

/// `r0 = 0; exit`: a classifier another tool could install.
fn foreign_program() -> OwnedFd {
    let insns: [u8; 16] = [0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
    let mut load: bpf_attr = unsafe { core::mem::zeroed() };
    load.__bindgen_anon_3.prog_type = bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS as u32;
    load.__bindgen_anon_3.insn_cnt = 2;
    load.__bindgen_anon_3.insns = insns.as_ptr() as u64;
    load.__bindgen_anon_3.license = c"GPL".as_ptr() as u64;
    let program = unsafe { syscall::bpf_syscall(bpf_cmd::BPF_PROG_LOAD as _, &mut load) }
        .expect("load a trivial classifier");
    unsafe { OwnedFd::from_raw_fd(program as i32) }
}

fn foreign_filter(ifindex: u32, direction: Direction, priority: u16, handle: u32) -> OwnedFd {
    let program = foreign_program();
    let mut netlink = NlSock::new().unwrap();
    netlink.add_clsact(ifindex).unwrap();
    netlink
        .set_bpf_filter(
            ifindex,
            parent(direction),
            priority,
            handle,
            program.as_raw_fd(),
            "foreign",
            true,
        )
        .unwrap();
    program
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn filters_follow_bind_reprogram_and_release_and_leave_foreign_ones() {
    clsact_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbc_a", "hbc_ap");
        let _other = foreign_filter(ifindex, Direction::Ingress, 1, 7);

        assert!(lab.round(&["hbc_a"], &[]).settled());
        let owned = lab.owned();
        for direction in [Direction::Ingress, Direction::Egress] {
            let (program, handle) = owned[&(ifindex, direction)];
            assert_eq!(
                honk_filters(ifindex, direction),
                [(handle, Some(lab.program_id(program)))],
                "{direction:?}"
            );
        }

        let round = lab.round(&[], &["hbc_a"]);
        assert!(round.settled() && round.added.is_empty(), "{round:?}");
        let rebound = lab.owned();
        for direction in [Direction::Ingress, Direction::Egress] {
            let (program, handle) = rebound[&(ifindex, direction)];
            assert_eq!(handle, owned[&(ifindex, direction)].1, "changed in place");
            assert_eq!(
                honk_filters(ifindex, direction),
                [(handle, Some(lab.program_id(program)))]
            );
        }
        assert_eq!(rebound[&(ifindex, Direction::Ingress)].0, WanIngressL2);

        assert!(lab.round(&[], &[]).settled());
        for direction in [Direction::Ingress, Direction::Egress] {
            assert!(honk_filters(ifindex, direction).is_empty(), "{direction:?}");
        }
        let left = filters(ifindex, Direction::Ingress);
        assert_eq!(left.len(), 1, "the foreign filter stays: {left:?}");
        assert_eq!((left[0].priority, left[0].handle), (1, 7));
    });
}

#[test]
#[ignore = "requires root; run via just test-netns"]
fn a_dead_instances_filter_is_replaced_and_a_stale_hook_deletes_only_itself() {
    clsact_netns(|| {
        let mut lab = Lab::new();
        let ifindex = lab.veth("hbd_a", "hbd_ap");
        let _stale = foreign_filter(ifindex, Direction::Ingress, owner::FILTER_PRIORITY, 0x7777);

        assert!(lab.round(&["hbd_a"], &[]).settled());
        let (program, handle) = lab.owned()[&(ifindex, Direction::Ingress)];
        assert_eq!(
            honk_filters(ifindex, Direction::Ingress),
            [(handle, Some(lab.program_id(program)))],
            "the filter a dead instance left at honk's priority is gone"
        );

        // A snapshot taken now still shares the filter; the owner re-creates
        // the binding under a new handle once the old filter vanished.
        let stale = lab.snapshot();
        NlSock::new()
            .unwrap()
            .del_filter(ifindex, TC_PARENT_INGRESS, owner::FILTER_PRIORITY, handle)
            .unwrap();
        let round = lab.round(&["hbd_a"], &[]);
        assert!(round.settled(), "{round:?}");
        let (_, renewed) = lab.owned()[&(ifindex, Direction::Ingress)];
        assert_ne!(renewed, handle);
        drop(stale);
        assert_eq!(
            honk_filters(ifindex, Direction::Ingress),
            [(renewed, Some(lab.program_id(program)))],
            "dropping the stale hook left the replacement"
        );
    });
}

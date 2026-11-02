use super::raw_bpf::{ADD64_IMM, CALL, EXIT, MOV64_IMM, MOV64_REG, insn, load_program};
use super::*;
use anyhow::Context as _;
use aya::programs::Program;
use aya_obj::generated::{bpf_attr, bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, bpf_prog_info, bpf_prog_type};

const MANDATORY_PROGRAMS: [&str; 16] = [
    "lan_ingress_l2",
    "lan_ingress_l3",
    "lan_egress_l2",
    "lan_egress_l3",
    "wan_ingress_l2",
    "wan_ingress_l3",
    "wan_egress_l2",
    "wan_egress_l3",
    "dae0peer_ingress",
    "dae0_ingress",
    "tproxy_wan_cg_sock_create_comm",
    "tproxy_wan_cg_connect4_comm",
    "tproxy_wan_cg_connect6_comm",
    "tproxy_wan_cg_sendmsg4_comm",
    "tproxy_wan_cg_sendmsg6_comm",
    "honk_tcp_passive",
];

const BPF_PROBE_READ: i32 = 4;
const BPF_PROBE_READ_KERNEL: i32 = 113;
const BPF_PROBE_READ_KERNEL_STR: i32 = 115;

fn program_info(fd: RawFd, info: &mut bpf_prog_info) -> anyhow::Result<()> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.info.bpf_fd = fd as u32;
    attr.info.info_len = core::mem::size_of::<bpf_prog_info>() as u32;
    attr.info.info = info as *mut bpf_prog_info as u64;
    unsafe { syscall::bpf_syscall(BPF_OBJ_GET_INFO_BY_FD as _, &mut attr) }
        .map(|_| ())
        .map_err(|errno| anyhow::anyhow!("BPF_OBJ_GET_INFO_BY_FD failed with errno {errno}"))
}

/// Verifier-rewritten instructions; a call's `imm` is then the helper's address relative
/// to `__bpf_call_base`, not its id, and is zeroed unless raw dumps are permitted.
fn xlated_instructions(fd: RawFd) -> anyhow::Result<Vec<[u8; 8]>> {
    let mut info: bpf_prog_info = unsafe { core::mem::zeroed() };
    program_info(fd, &mut info)?;
    let mut insns = vec![[0u8; 8]; info.xlated_prog_len as usize / 8];
    let mut info: bpf_prog_info = unsafe { core::mem::zeroed() };
    info.xlated_prog_len = (insns.len() * 8) as u32;
    info.xlated_prog_insns = insns.as_mut_ptr() as u64;
    program_info(fd, &mut info)?;
    anyhow::ensure!(
        info.xlated_prog_len as usize == insns.len() * 8,
        "program changed between xlated length and dump"
    );
    Ok(insns)
}

fn helper_call_offsets(insns: &[[u8; 8]]) -> impl Iterator<Item = i32> + '_ {
    // src_reg 0 selects a helper call; pseudo calls (subprograms, kfuncs) carry other imms.
    insns
        .iter()
        .filter(|raw| raw[0] == CALL && raw[1] >> 4 == 0)
        .map(|raw| i32::from_ne_bytes(raw[4..].try_into().unwrap()))
}

fn helper_call_offset(helper: i32) -> anyhow::Result<i32> {
    let program = load_program(
        bpf_prog_type::BPF_PROG_TYPE_KPROBE,
        &[
            insn(MOV64_REG, 1, 10, 0, 0),
            insn(ADD64_IMM, 1, 0, 0, -8),
            insn(MOV64_IMM, 2, 0, 0, 8),
            insn(MOV64_IMM, 3, 0, 0, 0),
            insn(CALL, 0, 0, 0, helper),
            insn(MOV64_IMM, 0, 0, 0, 0),
            insn(EXIT, 0, 0, 0, 0),
        ],
    )?;
    let insns = xlated_instructions(program.as_raw_fd())?;
    let offset = helper_call_offsets(&insns)
        .next()
        .context("reference program lost its helper call")?;
    anyhow::ensure!(offset != 0, "kernel withheld raw xlated call targets");
    Ok(offset)
}

fn load_mandatory(program: &mut Program) -> anyhow::Result<RawFd> {
    match program {
        Program::SchedClassifier(program) => program.load()?,
        Program::CgroupSock(program) => program.load()?,
        Program::CgroupSockAddr(program) => program.load()?,
        Program::SockOps(program) => program.load()?,
        _ => anyhow::bail!("unexpected mandatory program type"),
    }
    Ok(program.fd()?.as_fd().as_raw_fd())
}

// VM kernels have CONFIG_BPF_EVENTS, so loading cannot reproduce a kernel without it (OpenWrt
// FTRACE=n): only the absence of the probe-read helper calls in the verified programs can.
#[test]
#[ignore = "requires root and an eBPF build; run in the isolated VM gate"]
fn mandatory_programs_call_no_probe_read_helper() -> anyhow::Result<()> {
    // bpf_probe_read (id 4) is rejected for non-tracing program types on some kernels; then no
    // mandatory program can contain it and there is nothing to compare against.
    let mut forbidden = Vec::new();
    for (helper, required) in [
        (BPF_PROBE_READ, false),
        (BPF_PROBE_READ_KERNEL, true),
        (BPF_PROBE_READ_KERNEL_STR, true),
    ] {
        match helper_call_offset(helper) {
            Ok(offset) => forbidden.push(offset),
            Err(error) if required => {
                return Err(error.context(format!("reference program for helper {helper}")));
            }
            Err(_) => {}
        }
    }
    let (_, kernel_btf) = btf::load_kernel()?;
    let param = DaeParam {
        has_bpf_get_current_task: 0,
        tcp_daens_netns_id: 0,
        ..Default::default()
    };
    let mut bpf = EbpfLoader::new()
        .btf(&kernel_btf)
        .override_global("PARAM", &param, true)
        .override_global("IPV6_SOCKETS_AVAILABLE", &1u8, true)
        // A zero cookie is frozen read-only data: the verifier prunes the whole callback body.
        .override_global("TCP_DAENS_NETNS_COOKIE", &1u64, true)
        .load(crate::DEFAULT_BPF_OBJECT)?;
    for name in MANDATORY_PROGRAMS {
        let program = bpf
            .program_mut(name)
            .with_context(|| format!("mandatory program {name} missing from the object"))?;
        let fd = load_mandatory(program).with_context(|| format!("load {name}"))?;
        let insns = xlated_instructions(fd)?;
        let calls: Vec<i32> = helper_call_offsets(&insns).collect();
        anyhow::ensure!(
            !calls.is_empty(),
            "{name} dumped without any helper call; raw dump unavailable"
        );
        anyhow::ensure!(
            !calls.iter().any(|call| forbidden.contains(call)),
            "{name} calls a probe-read helper that kernels without BPF_EVENTS lack"
        );
    }
    Ok(())
}

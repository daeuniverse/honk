use super::btf::Btf;
use aya::EbpfLoader;
use aya::programs::{CgroupSock, CgroupSockAddr};
use honk_ebpf_common::DaeParam;
use std::convert::TryInto;

pub(super) const VMLINUX_BTF_PATHS: [&str; 2] =
    ["/sys/kernel/btf/vmlinux", "/usr/lib/debug/boot/vmlinux"];
pub(super) const VMLINUX_BTF_ENV: &str = "HONK_VMLINUX_BTF";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PnameCaptureMode {
    Argv0,
    Comm,
}

/// Select a mode by loading the actual cgroup programs, not by trusting a
/// helper probe. Some kernels recognize helpers globally but reject them for
/// cgroup programs during verification.
pub(super) fn select_capture_mode(
    obj: &[u8],
    offsets: Option<ProcessNameOffsets>,
) -> PnameCaptureMode {
    if offsets.is_some()
        && probe_pair(
            obj,
            offsets,
            "tproxy_wan_cg_sock_create",
            "tproxy_wan_cg_connect4",
        )
    {
        return PnameCaptureMode::Argv0;
    }
    PnameCaptureMode::Comm
}

fn probe_pair(
    obj: &[u8],
    offsets: Option<ProcessNameOffsets>,
    sock_name: &str,
    sock_addr_name: &str,
) -> bool {
    let param = DaeParam {
        has_bpf_get_current_task: 1,
        ..Default::default()
    };
    let task_mm_offset = offsets.map(|value| value.task_mm).unwrap_or_default();
    let mm_arg_start_offset = offsets.map(|value| value.mm_arg_start).unwrap_or_default();
    let mut loader = EbpfLoader::new();
    loader
        .override_global("PARAM", &param, true)
        .override_global("TASK_MM_OFFSET", &task_mm_offset, true)
        .override_global("MM_ARG_START_OFFSET", &mm_arg_start_offset, true);
    let mut bpf = match loader.load(obj) {
        Ok(bpf) => bpf,
        Err(_) => return false,
    };
    let sock_ok = bpf
        .program_mut(sock_name)
        .and_then(|program| {
            let program: &mut CgroupSock = program.try_into().ok()?;
            program.load().ok()
        })
        .is_some();
    if !sock_ok {
        return false;
    }
    bpf.program_mut(sock_addr_name)
        .and_then(|program| {
            let program: &mut CgroupSockAddr = program.try_into().ok()?;
            program.load().ok()
        })
        .is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProcessNameOffsets {
    pub task_mm: u32,
    pub mm_arg_start: u32,
}

pub(super) fn detect() -> Option<ProcessNameOffsets> {
    if let Some(path) = std::env::var_os(VMLINUX_BTF_ENV) {
        return find_offsets(&std::fs::read(path).ok()?);
    }
    VMLINUX_BTF_PATHS.iter().find_map(|path| {
        let data = std::fs::read(path).ok()?;
        find_offsets(&data)
    })
}

fn find_offsets(data: &[u8]) -> Option<ProcessNameOffsets> {
    let btf = Btf::parse(data)?;
    Some(ProcessNameOffsets {
        task_mm: btf.member_offset("task_struct", "mm")?,
        mm_arg_start: btf.member_offset("mm_struct", "arg_start")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::real::btf::BTF_HEADER_LEN;

    #[test]
    fn finds_process_argv_offsets() {
        let mut strings = vec![0];
        let mut add_name = |value: &[u8]| {
            let offset = strings.len() as u32;
            strings.extend_from_slice(value);
            strings.push(0);
            offset
        };
        let task = add_name(b"task_struct");
        let mm = add_name(b"mm_struct");
        let task_mm = add_name(b"mm");
        let arg_start = add_name(b"arg_start");

        let mut types = Vec::new();
        let mut add_struct = |name: u32, size: u32, members: &[(u32, u32, u32)]| {
            types.extend_from_slice(&name.to_le_bytes());
            types.extend_from_slice(&((4u32 << 24) | members.len() as u32).to_le_bytes());
            types.extend_from_slice(&size.to_le_bytes());
            for &(member_name, member_type, byte_offset) in members {
                types.extend_from_slice(&member_name.to_le_bytes());
                types.extend_from_slice(&member_type.to_le_bytes());
                types.extend_from_slice(&(byte_offset * 8).to_le_bytes());
            }
        };
        add_struct(0, 256, &[(arg_start, 0, 80)]);
        add_struct(task, 128, &[(task_mm, 0, 24)]);
        add_struct(mm, 256, &[(0, 1, 0)]);

        let mut data = Vec::new();
        data.extend_from_slice(&0xeb9fu16.to_le_bytes());
        data.extend_from_slice(&[1, 0]);
        data.extend_from_slice(&(BTF_HEADER_LEN as u32).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(types.len() as u32).to_le_bytes());
        data.extend_from_slice(&(types.len() as u32).to_le_bytes());
        data.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        data.extend_from_slice(&types);
        data.extend_from_slice(&strings);

        assert_eq!(
            find_offsets(&data),
            Some(ProcessNameOffsets {
                task_mm: 24,
                mm_arg_start: 80,
            })
        );
    }
}

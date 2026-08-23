use crate::maps::PARAM;
use aya_ebpf::Global;
use aya_ebpf_bindings::helpers::{
    bpf_get_current_task, bpf_loop, bpf_probe_read_kernel, bpf_probe_read_user_str,
};
use aya_ebpf_cty::c_void;
use core::mem;
use honk_ebpf_common::TASK_COMM_LEN;

const MAX_ARG_LEN: usize = 128;

#[unsafe(no_mangle)]
pub static TASK_MM_OFFSET: Global<u32> = Global::new(0);

#[unsafe(no_mangle)]
pub static MM_ARG_START_OFFSET: Global<u32> = Global::new(0);

#[repr(C)]
struct BasenameScan {
    argv0: [u8; MAX_ARG_LEN],
    start: u32,
}

extern "C" fn find_basename(index: u32, data: *mut c_void) -> i32 {
    if index >= MAX_ARG_LEN as u32 {
        return 1;
    }
    let scan = unsafe { &mut *(data as *mut BasenameScan) };
    let byte = scan.argv0[index as usize];
    if byte == 0 {
        return 1;
    }
    if byte == b'/' {
        scan.start = index + 1;
    }
    0
}

#[inline(always)]
pub fn read_argv0_basename(pname: &mut [u8; TASK_COMM_LEN]) -> bool {
    if PARAM.load().has_bpf_get_current_task == 0 {
        return false;
    }

    let task = unsafe { bpf_get_current_task() } as usize;
    if task == 0 {
        return false;
    }

    let mut mm = 0usize;
    if unsafe {
        bpf_probe_read_kernel(
            &mut mm as *mut _ as *mut c_void,
            mem::size_of::<usize>() as u32,
            task.wrapping_add(TASK_MM_OFFSET.load() as usize) as *const c_void,
        )
    } < 0
        || mm == 0
    {
        return false;
    }

    let mut arg_start = 0usize;
    if unsafe {
        bpf_probe_read_kernel(
            &mut arg_start as *mut _ as *mut c_void,
            mem::size_of::<usize>() as u32,
            mm.wrapping_add(MM_ARG_START_OFFSET.load() as usize) as *const c_void,
        )
    } < 0
        || arg_start == 0
    {
        return false;
    }

    let mut scan = BasenameScan {
        argv0: [0; MAX_ARG_LEN],
        start: 0,
    };
    let read = unsafe {
        bpf_probe_read_user_str(
            scan.argv0.as_mut_ptr() as *mut c_void,
            MAX_ARG_LEN as u32,
            arg_start as *const c_void,
        )
    };
    if read <= 1 || read as usize >= MAX_ARG_LEN {
        return false;
    }

    if unsafe {
        bpf_loop(
            MAX_ARG_LEN as u32,
            find_basename as *mut c_void,
            &mut scan as *mut _ as *mut c_void,
            0,
        )
    } < 0
    {
        return false;
    }

    if scan.start >= MAX_ARG_LEN as u32 {
        return false;
    }
    (unsafe {
        bpf_probe_read_user_str(
            pname.as_mut_ptr() as *mut c_void,
            TASK_COMM_LEN as u32,
            arg_start.wrapping_add(scan.start as usize) as *const c_void,
        )
    }) > 1
}

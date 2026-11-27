use aya_ebpf::Global;

mod capture;
pub(crate) use capture::capture;
#[unsafe(no_mangle)]
pub static TASK_MM_OFFSET: Global<u32> = Global::new(0);

#[unsafe(no_mangle)]
pub static MM_ARG_START_OFFSET: Global<u32> = Global::new(0);

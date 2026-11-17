#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod cgroup;
mod ctx;
mod host_connect;
mod host_identity;
mod host_kernel;
mod host_maps;
mod process_name;

use host_identity as socket_identity;

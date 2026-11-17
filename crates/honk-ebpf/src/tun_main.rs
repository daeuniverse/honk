#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod cgroup;
#[path = "tun_connect.rs"]
mod host_connect;
mod host_identity;
mod host_kernel;
#[path = "tun_maps.rs"]
mod host_maps;
mod process_name;

use host_identity as socket_identity;

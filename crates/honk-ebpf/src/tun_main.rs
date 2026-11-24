#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

mod cgroup;
#[path = "tun_connect.rs"]
mod host_connect;
#[path = "tun_identity.rs"]
mod host_identity;
#[path = "tun_kernel.rs"]
mod host_kernel;
#[path = "tun_maps.rs"]
mod host_maps;
mod process_name;

use host_identity as socket_identity;

#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[path = "process_name/capture.rs"]
mod process_name;
mod host_connect;
mod host_maps;

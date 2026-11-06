#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub mod action;
mod auxiliary;
pub mod cgroup;
pub mod contrack;
pub mod ctx;
pub mod egress;
pub mod errno;
pub mod event;
pub mod flow;
pub mod fragment;
pub mod ingress;
pub mod log_shim;
pub mod maps;
pub mod new_flow_limit;
#[cfg(feature = "routing-test")]
mod preparing_claim_test;
pub mod process_name;
mod receive_trace;
pub mod route;
pub mod routing;
pub mod sk;
pub mod sk_lookup;
mod socket_identity;
#[cfg(feature = "routing-test")]
mod stable_flow_test;
pub mod stats;
mod tcp_binding;
pub mod transport;

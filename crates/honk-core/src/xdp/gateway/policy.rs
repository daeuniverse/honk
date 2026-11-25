use crate::control::routing_matcher::{
    RoutingPushPlan,
    codegen::{GatewayBytecode, RoutingMapFds, emit_gateway_routing_program},
};
use honk_ebpf_common::{DomainRouting, LpmKey};
use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const FACT_CAPACITY: u32 = 2_048_000;

#[cfg(all(test, feature = "ebpf"))]
mod tests;

pub(crate) struct GatewayPolicy {
    pub(crate) bytecode: GatewayBytecode,
    pub(crate) host_bytecode: Option<GatewayBytecode>,
    facts: [OwnedFd; 5],
}

#[repr(C)]
struct MapCreate {
    kind: u32,
    key_size: u32,
    value_size: u32,
    capacity: u32,
    flags: u32,
    inner: u32,
    numa: u32,
    name: [u8; 16],
}

#[repr(C)]
struct MapElement {
    fd: u32,
    reserved: u32,
    key: u64,
    value: u64,
    flags: u64,
}

fn syscall<T>(command: u32, attr: &mut T) -> io::Result<i32> {
    // SAFETY: callers supply command-specific C layouts; pointers outlive the syscall.
    let result = unsafe { libc::syscall(libc::SYS_bpf, command, attr as *mut T, size_of::<T>()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        i32::try_from(result).map_err(|_| io::Error::other("gateway BPF descriptor overflow"))
    }
}

fn fact_map(entries: &[(LpmKey, DomainRouting)]) -> io::Result<OwnedFd> {
    if entries.len() > FACT_CAPACITY as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "gateway routing fact capacity exceeded",
        ));
    }
    let fd = syscall(
        0,
        &mut MapCreate {
            kind: 11,
            key_size: size_of::<LpmKey>() as u32,
            value_size: size_of::<DomainRouting>() as u32,
            capacity: FACT_CAPACITY,
            flags: 1,
            inner: 0,
            numa: 0,
            name: [0; 16],
        },
    )?;
    // SAFETY: BPF_MAP_CREATE returned a fresh descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    for (key, value) in entries {
        syscall(
            2,
            &mut MapElement {
                fd: fd.as_raw_fd() as u32,
                reserved: 0,
                key: key as *const LpmKey as u64,
                value: value as *const DomainRouting as u64,
                flags: 0,
            },
        )?;
    }
    syscall(22, &mut (fd.as_raw_fd() as u32))?;
    Ok(fd)
}

impl GatewayPolicy {
    pub(crate) fn prepare(
        plan: &RoutingPushPlan,
        lan_dns_shadow: bool,
        host_dns_shadow: Option<bool>,
    ) -> io::Result<Self> {
        let facts = [
            fact_map(&plan.facts.destination_v4)?,
            fact_map(&plan.facts.destination_v6)?,
            fact_map(&plan.facts.source_v4)?,
            fact_map(&plan.facts.source_v6)?,
            fact_map(&plan.facts.mac)?,
        ];
        let fds = RoutingMapFds {
            destination_v4: facts[0].as_raw_fd(),
            destination_v6: facts[1].as_raw_fd(),
            source_v4: facts[2].as_raw_fd(),
            source_v6: facts[3].as_raw_fd(),
            mac: facts[4].as_raw_fd(),
            domain: -1,
        };
        let bytecode = emit_gateway_routing_program(plan, fds, lan_dns_shadow, false)?;
        let host_bytecode = host_dns_shadow
            .map(|dns_shadow| emit_gateway_routing_program(plan, fds, dns_shadow, true))
            .transpose()?;
        Ok(Self {
            bytecode,
            host_bytecode,
            facts,
        })
    }

    pub(crate) fn fact_fds(&self) -> impl Iterator<Item = std::os::fd::BorrowedFd<'_>> {
        use std::os::fd::AsFd;
        self.facts.iter().map(AsFd::as_fd)
    }
}

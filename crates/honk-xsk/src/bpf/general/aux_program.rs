use super::*;
use aya_obj::generated::{bpf_attach_type, bpf_prog_type};
use honk_ebpf_common::xdp_gateway::GATEWAY_REALM_CAPACITY;

pub struct HostGatewayLoad<'a> {
    pub binding: u64,
    pub is_l2: bool,
    pub bypass_mark: u32,
    pub honk_pid: Option<u32>,
    pub identity: BorrowedFd<'a>,
    pub decision: BorrowedFd<'a>,
    pub dns_realm: u32,
    pub ct: &'a crate::HostConntrack,
}

/// One policy generation for the outer ingress of a private L3 auxiliary binding.
pub struct AuxGatewayProgram {
    fd: OwnedFd,
    id: u32,
    _pair: Arc<crate::AuxDevicePair>,
}

impl AuxGatewayProgram {
    pub fn load(
        pair: &Arc<crate::AuxDevicePair>,
        realm: u32,
        ipv4_broadcasts: &[Ipv4Addr],
        gateway: GatewayLoad<'_>,
        ct: &SkbConntrackKfuncs,
    ) -> io::Result<Self> {
        if !(1..=GATEWAY_REALM_CAPACITY).contains(&realm) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid auxiliary gateway realm",
            ));
        }
        let _routing_fds = gateway.validate_routing()?;
        let mut program = gateway::build_auxiliary(pair, realm, ipv4_broadcasts, &gateway, ct)?;
        program.kfunc_btf = ct.0.btf.as_ref().map(OwnedFd::try_clone).transpose()?;
        Self::load_tcx(
            pair,
            program,
            gateway.dns,
            b"honk_aux_gw",
            bpf_attach_type::BPF_TCX_INGRESS,
        )
    }

    pub fn load_host(
        pair: &Arc<crate::AuxDevicePair>,
        realm: u32,
        gateway: GatewayLoad<'_>,
        host: HostGatewayLoad<'_>,
    ) -> io::Result<Self> {
        if host.binding == 0
            || host.bypass_mark == 0
            || host.bypass_mark & 0xc800_0000 != 0
            || host.honk_pid == Some(0)
            || !(1..=GATEWAY_REALM_CAPACITY).contains(&host.dns_realm)
            || host.dns_realm == realm
            || !gateway.maps.host_realms().contains(&realm)
        {
            return Err(invalid_data("invalid Host gateway authority"));
        }
        let _routing_fds = gateway.validate_routing()?;
        let mut program = gateway::build_host(pair, realm, &gateway, &host)?;
        program.kfunc_btf = host
            .ct
            .lookup
            .0
            .btf
            .as_ref()
            .map(OwnedFd::try_clone)
            .transpose()?;
        Self::load_tcx(
            pair,
            program,
            gateway.dns,
            b"honk_host_gw",
            bpf_attach_type::BPF_TCX_EGRESS,
        )
    }

    fn load_tcx(
        pair: &Arc<crate::AuxDevicePair>,
        mut program: Program,
        dns: Option<&crate::GatewayDnsMaps>,
        name: &[u8],
        direction: bpf_attach_type,
    ) -> io::Result<Self> {
        program.dns_shadow = dns.is_some();
        let kind = bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS as u32;
        let (fd, id) = load_typed_program(
            &program,
            name,
            &mut vec![0; 1 << 20],
            kind,
            direction as u32,
        )?;
        if let Some(dns) = dns {
            dns.validate_typed_program(fd.as_fd(), id, kind)?;
        }
        Ok(Self {
            fd,
            id,
            _pair: Arc::clone(pair),
        })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn object_fds(&self) -> [BorrowedFd<'_>; 1] {
        [self.as_fd()]
    }
}

impl AsFd for AuxGatewayProgram {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

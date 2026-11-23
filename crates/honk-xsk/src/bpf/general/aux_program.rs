use super::*;
use aya_obj::generated::{bpf_attach_type, bpf_prog_type};
use honk_ebpf_common::xdp_gateway::GATEWAY_REALM_CAPACITY;

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
        program.dns_shadow = gateway.dns.is_some();
        let kind = bpf_prog_type::BPF_PROG_TYPE_SCHED_CLS as u32;
        let (fd, id) = load_typed_program(
            &program,
            b"honk_aux_gw",
            &mut vec![0; 1 << 20],
            kind,
            bpf_attach_type::BPF_TCX_INGRESS as u32,
        )?;
        if let Some(dns) = gateway.dns {
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

use super::*;
use crate::ebpf::DomainRouteWriteError;
use crate::ebpf::maps::DOMAIN_MAP_CAPACITY;
use aya::maps::{ArrayOfMaps as AyaArrayOfMaps, IterableMap};
use aya::programs::{ProgramError, ProgramFd, SchedClassifier};
#[cfg(test)]
use aya::programs::{TestRun, TestRunOptions};
use aya_obj::btf::{Btf, BtfKind};
use aya_obj::generated::{
    bpf_attr, bpf_btf_info, bpf_cmd, bpf_func_info, bpf_line_info, bpf_prog_type,
};
use std::io;
use std::mem::size_of;
use std::os::fd::{FromRawFd, OwnedFd};

const ROUTING_TARGETS: [&str; 4] = [
    "lan_ingress_l2",
    "lan_ingress_l3",
    "wan_egress_l2",
    "wan_egress_l3",
];
const FACT_MAP_CAPACITY: u32 = 2_048_000;
const BPF_F_NO_PREALLOC: u32 = 1;
const VERIFIER_LOG_SIZE: usize = 1 << 20;

type RoutingLpm = AyaLpmTrie<AyaMapData, [u32; 4], DomainRouting>;
type RoutingDomain = AyaHashMap<AyaMapData, [u32; 4], DomainRouting>;
type RoutingDescriptor = AyaArray<AyaMapData, RoutingPolicyDescriptor>;

pub(super) struct RoutingGeneration {
    pub(super) domain: RoutingDomain,
    _destination_v4: RoutingLpm,
    _destination_v6: RoutingLpm,
    _source_v4: RoutingLpm,
    _source_v6: RoutingLpm,
    _mac: RoutingLpm,
    _descriptor: RoutingDescriptor,
    _btf: OwnedFd,
    _program: OwnedFd,
    _links: Vec<OwnedFd>,
}

struct RoutingMaps {
    destination_v4: RoutingLpm,
    destination_v6: RoutingLpm,
    source_v4: RoutingLpm,
    source_v6: RoutingLpm,
    mac: RoutingLpm,
    domain: RoutingDomain,
}

struct Target {
    fd: ProgramFd,
    function_id: u32,
    btf: Btf,
}

fn bpf_syscall(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i64> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_uint,
            attr as *mut bpf_attr,
            size_of::<bpf_attr>(),
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result as i64)
    }
}

fn bpf_fd(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<OwnedFd> {
    let fd = bpf_syscall(cmd, attr)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn verifier_text(log: &[u8]) -> String {
    let end = log.iter().position(|byte| *byte == 0).unwrap_or(log.len());
    String::from_utf8_lossy(&log[..end]).into_owned()
}

fn btf_fd_by_id(id: u32) -> anyhow::Result<OwnedFd> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_6.__bindgen_anon_1.btf_id = id;
    bpf_fd(bpf_cmd::BPF_BTF_GET_FD_BY_ID, &mut attr)
        .map_err(|error| anyhow::anyhow!("BPF_BTF_GET_FD_BY_ID({id}): {error}"))
}

fn btf_bytes(fd: &OwnedFd) -> anyhow::Result<Vec<u8>> {
    let mut bytes = vec![0u8; 4096];
    loop {
        let mut info: bpf_btf_info = unsafe { core::mem::zeroed() };
        info.btf = bytes.as_mut_ptr() as u64;
        info.btf_size = bytes.len() as u32;
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.info.bpf_fd = fd.as_raw_fd() as u32;
        attr.info.info_len = size_of::<bpf_btf_info>() as u32;
        attr.info.info = (&mut info as *mut bpf_btf_info) as u64;
        bpf_syscall(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr)
            .map_err(|error| anyhow::anyhow!("BPF_OBJ_GET_INFO_BY_FD(BTF): {error}"))?;
        if info.btf_size as usize > bytes.len() {
            bytes.resize(info.btf_size as usize, 0);
            continue;
        }
        bytes.truncate(info.btf_size as usize);
        return Ok(bytes);
    }
}

fn load_btf(bytes: &[u8]) -> anyhow::Result<OwnedFd> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_7.btf = bytes.as_ptr() as u64;
    attr.__bindgen_anon_7.btf_size = bytes.len() as u32;
    let first_error = match bpf_fd(bpf_cmd::BPF_BTF_LOAD, &mut attr) {
        Ok(fd) => return Ok(fd),
        Err(error) => error,
    };
    let mut log = vec![0u8; VERIFIER_LOG_SIZE];
    attr.__bindgen_anon_7.btf_log_buf = log.as_mut_ptr() as u64;
    attr.__bindgen_anon_7.btf_log_size = log.len() as u32;
    attr.__bindgen_anon_7.btf_log_level = 1;
    bpf_fd(bpf_cmd::BPF_BTF_LOAD, &mut attr).map_err(|error| {
        anyhow::anyhow!(
            "BPF_BTF_LOAD: {first_error}; diagnostic retry: {error}\n{}",
            verifier_text(&log)
        )
    })
}

fn line_info(
    btf: &mut Btf,
    bytecode: &crate::control::routing_matcher::codegen::RoutingBytecode,
) -> anyhow::Result<Vec<bpf_line_info>> {
    let file_name_off = btf.add_string("honk-routing.generated");
    let mut records = Vec::with_capacity(bytecode.lines.len().max(1));
    if bytecode.lines.is_empty() {
        records.push(bpf_line_info {
            insn_off: 0,
            file_name_off,
            line_off: btf.add_string("generated routing policy"),
            line_col: 1 << 10,
        });
        return Ok(records);
    }
    for line in &bytecode.lines {
        anyhow::ensure!(
            (line.insn_offset as usize) < bytecode.insns.len(),
            "generated source offset {} exceeds {} instructions",
            line.insn_offset,
            bytecode.insns.len()
        );
        anyhow::ensure!(line.line < (1 << 22), "generated source line is too large");
        records.push(bpf_line_info {
            insn_off: line.insn_offset,
            file_name_off,
            line_off: btf.add_string(&line.text),
            line_col: (line.line << 10) | 1,
        });
    }
    records.sort_by_key(|record| record.insn_off);
    records.dedup_by_key(|record| record.insn_off);
    Ok(records)
}

fn load_extension(
    target: &Target,
    slot_name: &str,
    bytecode: &crate::control::routing_matcher::codegen::RoutingBytecode,
) -> anyhow::Result<(OwnedFd, OwnedFd)> {
    anyhow::ensure!(
        !bytecode.insns.is_empty(),
        "generated routing program is empty"
    );
    let mut btf = target.btf.clone();
    let function_id = btf.id_by_type_name_kind(slot_name, BtfKind::Func)?;
    let lines = line_info(&mut btf, bytecode)?;
    let btf_fd = load_btf(&btf.to_bytes())?;
    let functions = [bpf_func_info {
        insn_off: 0,
        type_id: function_id,
    }];
    let license = b"GPL\0";
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.__bindgen_anon_3.prog_type = bpf_prog_type::BPF_PROG_TYPE_EXT as u32;
    attr.__bindgen_anon_3.insn_cnt = bytecode.insns.len() as u32;
    attr.__bindgen_anon_3.insns = bytecode.insns.as_ptr() as u64;
    attr.__bindgen_anon_3.license = license.as_ptr() as u64;
    attr.__bindgen_anon_3.prog_name = b"honk_route\0\0\0\0\0\0".map(|byte| byte as libc::c_char);
    attr.__bindgen_anon_3.prog_btf_fd = btf_fd.as_raw_fd() as u32;
    attr.__bindgen_anon_3.func_info_rec_size = size_of::<bpf_func_info>() as u32;
    attr.__bindgen_anon_3.func_info = functions.as_ptr() as u64;
    attr.__bindgen_anon_3.func_info_cnt = functions.len() as u32;
    attr.__bindgen_anon_3.line_info_rec_size = size_of::<bpf_line_info>() as u32;
    attr.__bindgen_anon_3.line_info = lines.as_ptr() as u64;
    attr.__bindgen_anon_3.line_info_cnt = lines.len() as u32;
    attr.__bindgen_anon_3.attach_btf_id = target.function_id;
    attr.__bindgen_anon_3.__bindgen_anon_1.attach_prog_fd = target.fd.as_fd().as_raw_fd() as u32;
    let program = match bpf_fd(bpf_cmd::BPF_PROG_LOAD, &mut attr) {
        Ok(program) => program,
        Err(first_error) => {
            let mut log = vec![0u8; VERIFIER_LOG_SIZE];
            attr.__bindgen_anon_3.log_level = 1;
            attr.__bindgen_anon_3.log_size = log.len() as u32;
            attr.__bindgen_anon_3.log_buf = log.as_mut_ptr() as u64;
            bpf_fd(bpf_cmd::BPF_PROG_LOAD, &mut attr).map_err(|error| {
                anyhow::anyhow!(
                    "BPF_PROG_LOAD EXT for {slot_name}: {first_error}; diagnostic retry: {error}; log bytes={}\n{}",
                    unsafe { attr.__bindgen_anon_3.log_true_size },
                    verifier_text(&log)
                )
            })?
        }
    };
    Ok((btf_fd, program))
}

fn attach_extension(program: &OwnedFd, target: &Target) -> anyhow::Result<OwnedFd> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.link_create.__bindgen_anon_1.prog_fd = program.as_raw_fd() as u32;
    attr.link_create.__bindgen_anon_2.target_fd = target.fd.as_fd().as_raw_fd() as u32;
    attr.link_create.__bindgen_anon_3.target_btf_id = target.function_id;
    attr.link_create.attach_type = 0;
    bpf_fd(bpf_cmd::BPF_LINK_CREATE, &mut attr).map_err(|error| {
        anyhow::anyhow!(
            "BPF_LINK_CREATE EXT target btf {}: {error}",
            target.function_id
        )
    })
}

fn create_lpm(entries: &[(LpmKey, DomainRouting)]) -> anyhow::Result<RoutingLpm> {
    let mut map = RoutingLpm::create(FACT_MAP_CAPACITY, BPF_F_NO_PREALLOC)?;
    for (key, value) in entries {
        map.insert(&AyaLpmKey::new(key.prefix_len, key.data), value, 0)?;
    }
    Ok(map)
}

fn create_maps(
    facts: &crate::control::routing_matcher::RoutingFactMaps,
    domain_entries: &[(LpmKey, DomainRouting)],
) -> anyhow::Result<RoutingMaps> {
    let mut domain = RoutingDomain::create(DOMAIN_MAP_CAPACITY, BPF_F_NO_PREALLOC)?;
    for (key, value) in domain_entries {
        domain.insert(key.data, value, 0)?;
    }
    Ok(RoutingMaps {
        destination_v4: create_lpm(&facts.destination_v4)?,
        destination_v6: create_lpm(&facts.destination_v6)?,
        source_v4: create_lpm(&facts.source_v4)?,
        source_v6: create_lpm(&facts.source_v6)?,
        mac: create_lpm(&facts.mac)?,
        domain,
    })
}

impl RoutingMaps {
    fn fds(&self) -> crate::control::routing_matcher::codegen::RoutingMapFds {
        crate::control::routing_matcher::codegen::RoutingMapFds {
            destination_v4: lpm_fd(&self.destination_v4),
            destination_v6: lpm_fd(&self.destination_v6),
            source_v4: lpm_fd(&self.source_v4),
            source_v6: lpm_fd(&self.source_v6),
            mac: lpm_fd(&self.mac),
            domain: map_fd(&self.domain),
        }
    }
}

fn map_fd<K: Pod, V: Pod>(map: &AyaHashMap<AyaMapData, K, V>) -> RawFd {
    map.map().fd().as_fd().as_raw_fd()
}

fn lpm_fd(map: &RoutingLpm) -> RawFd {
    map.map().fd().as_fd().as_raw_fd()
}

impl RealEbpfBackend {
    fn routing_targets(&mut self, slot_name: &str) -> anyhow::Result<Vec<Target>> {
        let bpf = self.bpf_mut()?;
        let mut names = ROUTING_TARGETS.to_vec();
        if bpf.program("routing_test").is_some() {
            names.push("routing_test");
        }
        let mut result = Vec::with_capacity(names.len());
        for name in names {
            let program: &mut SchedClassifier = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("routing target '{name}' not found"))?
                .try_into()?;
            match program.load() {
                Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
                Err(error) => return Err(anyhow::anyhow!("load routing target '{name}': {error}")),
            }
            let info = program.info()?;
            let btf_id = info
                .btf_id()
                .ok_or_else(|| anyhow::anyhow!("routing target '{name}' has no BTF"))?;
            let fd = program.fd()?.try_clone()?;
            let kernel_btf = btf_fd_by_id(btf_id)?;
            let btf = Btf::parse(&btf_bytes(&kernel_btf)?, Default::default())?;
            let function_id = btf.id_by_type_name_kind(slot_name, BtfKind::Func)?;
            result.push(Target {
                fd,
                function_id,
                btf,
            });
        }
        Ok(result)
    }

    pub(super) fn publish_compiled_routing(
        &mut self,
        plan: &crate::control::routing_matcher::RoutingPushPlan,
        learned_domains: &[(LpmKey, DomainRouting)],
    ) -> anyhow::Result<()> {
        let active = self.routing_slot;
        anyhow::ensure!(
            active < ROUTING_SLOT_NAMES.len() as u32,
            "invalid active routing slot {active}"
        );
        let slot = active ^ 1;
        let slot_name = ROUTING_SLOT_NAMES[slot as usize];
        let targets = self.routing_targets(slot_name)?;
        let maps = create_maps(&plan.facts, learned_domains)?;
        let bytecode =
            crate::control::routing_matcher::codegen::emit_routing_program(plan, maps.fds())?;
        let (btf, program) = load_extension(&targets[0], slot_name, &bytecode)?;
        let mut links = Vec::with_capacity(targets.len());
        for target in &targets {
            links.push(attach_extension(&program, target)?);
        }

        let domain_map_id = maps.domain.map().info()?.id();
        let generation = self
            .routing_generation_counter
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("routing generation counter exhausted"))?;
        let descriptor_value = RoutingPolicyDescriptor {
            slot,
            features: plan.features,
            generation,
            domain_map_id,
            reserved: 0,
        };
        let mut descriptor = RoutingDescriptor::create(1, 0)?;
        descriptor.set(0, descriptor_value, 0)?;
        {
            let root = self
                .bpf_mut()?
                .map_mut(ROUTING_POLICY_ROOT_NAME)
                .ok_or_else(|| anyhow::anyhow!("map '{ROUTING_POLICY_ROOT_NAME}' not found"))?;
            let mut root = AyaArrayOfMaps::<_, RoutingDescriptor>::try_from(root)?;
            root.set(0, &descriptor, 0)?;
        }

        let candidate = RoutingGeneration {
            domain: maps.domain,
            _destination_v4: maps.destination_v4,
            _destination_v6: maps.destination_v6,
            _source_v4: maps.source_v4,
            _source_v6: maps.source_v6,
            _mac: maps.mac,
            _descriptor: descriptor,
            _btf: btf,
            _program: program,
            _links: links,
        };
        let previous = self.routing_generation.replace(candidate);
        self.routing_slot = slot;
        self.routing_generation_counter = generation;
        // Successful map-in-map replacement already waited out old non-sleepable TC readers.
        drop(previous);
        Ok(())
    }

    pub(super) fn active_domain_mut(
        &mut self,
    ) -> Result<&mut RoutingDomain, DomainRouteWriteError> {
        self.routing_generation
            .as_mut()
            .map(|generation| &mut generation.domain)
            .ok_or_else(|| {
                DomainRouteWriteError::Other(anyhow::anyhow!("no active routing generation"))
            })
    }
}

#[cfg(test)]
impl RealEbpfBackend {
    /// Load the production object without attaching any network or cgroup hook.
    /// The resulting backend can publish a real generated policy and exercise
    /// the optional `routing_test` classifier with `BPF_PROG_TEST_RUN`.
    pub(crate) fn load_routing_test_fixture(obj: &[u8]) -> anyhow::Result<Self> {
        let version =
            kernel_version().ok_or_else(|| anyhow::anyhow!("cannot determine kernel version"))?;
        anyhow::ensure!(
            version >= (6, 12, 0),
            "routing tests require Linux 6.12 or newer"
        );
        let bpf = EbpfLoader::new().load(obj)?;
        Ok(Self {
            bpf: Some(bpf),
            pin_root: PathBuf::new(),
            pinned_maps: Vec::new(),
            interface_links: Vec::new(),
            cgroup_sock_links: Vec::new(),
            cgroup_sock_addr_links: Vec::new(),
            dae0_ingress_link: None,
            dae0peer_ingress_link: None,
            sk_lookup_link: None,
            listeners_published: false,
            log_flush_handle: None,
            event_flush_handle: None,
            cap_lookup_and_delete: BatchCapability::new(),
            cap_lookup_batch: BatchCapability::new(),
            routing_generation: None,
            routing_slot: 0,
            routing_generation_counter: 0,
        })
    }

    pub(crate) fn run_routing_test(
        &mut self,
        input: &RoutingInput,
    ) -> anyhow::Result<RoutingTestResult> {
        self.array_set("ROUTING_TEST_INPUT", 0, input)?;
        let packet = [0u8; 64];
        {
            let program: &SchedClassifier = self
                .bpf()?
                .program("routing_test")
                .ok_or_else(|| anyhow::anyhow!("routing-test program is absent"))?
                .try_into()?;
            program.test_run(TestRunOptions {
                data_in: Some(&packet),
                ..Default::default()
            })?;
        }
        self.array_get("ROUTING_TEST_OUTPUT", 0)?
            .ok_or_else(|| anyhow::anyhow!("routing test produced no output"))
    }
}

#[cfg(test)]
mod tests;

use super::*;
use std::io::Read as _;

const BTF_LIMIT: usize = 256 << 20;
const VMLINUX: &str = "/sys/kernel/btf/vmlinux";
const CONNTRACK: &str = "/sys/kernel/btf/nf_conntrack";

struct Bounds {
    base: usize,
    module: Option<usize>,
}

impl Bounds {
    fn read() -> io::Result<Self> {
        let base = admitted_size(std::fs::metadata(VMLINUX)?.len())?;
        let module = match std::fs::metadata(CONNTRACK) {
            Ok(metadata) => Some(admitted_size(metadata.len())?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        if base
            .checked_add(module.unwrap_or(0))
            .is_none_or(|size| size > BTF_LIMIT)
        {
            return Err(invalid_data(
                "native combined kernel BTF exceeds construction bound",
            ));
        }
        Ok(Self { base, module })
    }

    fn memory_bytes(&self) -> io::Result<usize> {
        self.base
            .checked_add(self.module.unwrap_or(0))
            .and_then(|size| size.checked_mul(12))
            .and_then(|size| size.checked_add(2 << 20))
            .and_then(|size| size.checked_add(CLOSED_COUNTER_PREPARATION_BYTES))
            .ok_or_else(|| invalid_data("native BTF preparation reservation overflow"))
    }
}

fn admitted_size(size: u64) -> io::Result<usize> {
    usize::try_from(size)
        .ok()
        .filter(|size| (24..=BTF_LIMIT).contains(size))
        .ok_or_else(|| invalid_data("native kernel BTF size outside construction bound"))
}

fn read_bounded(path: &str, admitted: usize) -> io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    if admitted_size(file.metadata()?.len())? != admitted {
        return Err(invalid_data(
            "native kernel BTF size changed after admission",
        ));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(admitted)
        .map_err(io::Error::other)?;
    bytes.resize(admitted, 0);
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0u8; 1])? != 0 || file.metadata()?.len() != admitted as u64 {
        return Err(invalid_data("native kernel BTF grew beyond admitted read"));
    }
    Ok(bytes)
}

pub(in crate::bpf) fn preparation_memory_bytes() -> io::Result<usize> {
    Bounds::read()?.memory_bytes()
}

#[repr(C)]
pub(super) struct CtOptions {
    pub netns_id: i32,
    pub error: i32,
    pub l4proto: u8,
    pub dir: u8,
    pub ct_zone_id: u16,
    pub ct_zone_dir: u8,
    pub reserved: [u8; 3],
}

const CT_OPTIONS_FIELDS: [(&str, u32, i16); 7] = [
    (
        "netns_id",
        4,
        std::mem::offset_of!(CtOptions, netns_id) as i16,
    ),
    ("error", 4, std::mem::offset_of!(CtOptions, error) as i16),
    (
        "l4proto",
        1,
        std::mem::offset_of!(CtOptions, l4proto) as i16,
    ),
    ("dir", 1, std::mem::offset_of!(CtOptions, dir) as i16),
    (
        "ct_zone_id",
        2,
        std::mem::offset_of!(CtOptions, ct_zone_id) as i16,
    ),
    (
        "ct_zone_dir",
        1,
        std::mem::offset_of!(CtOptions, ct_zone_dir) as i16,
    ),
    (
        "reserved",
        3,
        std::mem::offset_of!(CtOptions, reserved) as i16,
    ),
];

pub(super) struct Layout {
    pub lookup: u32,
    pub release: u32,
    pub lookup_offset: i16,
    pub release_offset: i16,
    pub btf: Option<OwnedFd>,
    pub vlan: Option<u32>,
    pub src: i16,
    pub dst: i16,
    pub sport: i16,
    pub dport: i16,
    pub family: i16,
    pub proto: i16,
    pub zone: i16,
    pub socket_remote4: i16,
    pub socket_local4: i16,
    pub socket_remote6: i16,
    pub socket_local6: i16,
    pub socket_remote_port: i16,
    pub socket_local_port: i16,
}

struct Types {
    bytes: Vec<u8>,
    records: Vec<usize>,
    strings: usize,
    strings_end: usize,
}

impl Types {
    fn word(&self, at: usize) -> io::Result<u32> {
        let bytes = self
            .bytes
            .get(at..at + 4)
            .ok_or_else(|| invalid_data("short native kernel BTF"))?;
        Ok(u32::from_ne_bytes(bytes.try_into().unwrap()))
    }

    fn name(&self, offset: u32) -> io::Result<&str> {
        let start = self
            .strings
            .checked_add(offset as usize)
            .ok_or_else(|| invalid_data("BTF string overflow"))?;
        let bytes = self
            .bytes
            .get(start..self.strings_end)
            .ok_or_else(|| invalid_data("BTF string outside section"))?;
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| invalid_data("unterminated BTF string"))?;
        std::str::from_utf8(&bytes[..end]).map_err(|_| invalid_data("invalid BTF name"))
    }

    fn record(&self, id: u32) -> io::Result<usize> {
        self.records
            .get(id as usize)
            .copied()
            .filter(|at| *at != usize::MAX)
            .ok_or_else(|| invalid_data("invalid BTF type reference"))
    }

    fn resolve(&self, mut id: u32) -> io::Result<usize> {
        for _ in 0..32 {
            let at = self.record(id)?;
            match self.word(at + 4)? >> 24 & 31 {
                8..=11 | 18 => id = self.word(at + 8)?,
                _ => return Ok(at),
            }
        }
        Err(invalid_data("cyclic BTF qualifiers"))
    }

    fn named(&self, name: &str, kind: u32) -> io::Result<(u32, usize)> {
        for (id, &at) in self.records.iter().enumerate().skip(1) {
            if self.word(at + 4)? >> 24 & 31 == kind && self.name(self.word(at)?)? == name {
                return Ok((id as u32, at));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("native requires vmlinux BTF {name}"),
        ))
    }

    fn member(&self, at: usize, name: &str, depth: usize) -> io::Result<Option<(u32, u32)>> {
        if depth == 8 {
            return Err(invalid_data("nested BTF member depth"));
        }
        let info = self.word(at + 4)?;
        if !matches!(info >> 24 & 31, 4 | 5) {
            return Err(invalid_data("native BTF member is not aggregate"));
        }
        let mut result = None;
        for index in 0..info & 0xffff {
            let member = at + 12 + index as usize * 12;
            let member_name = self.name(self.word(member)?)?;
            let bits = self.word(member + 8)?;
            if bits & 7 != 0 || (info >> 31 != 0 && bits >> 24 != 0) {
                continue;
            }
            let offset = (bits & 0xffffff) / 8;
            let ty = self.word(member + 4)?;
            let found = if member_name == name {
                Some((offset, ty))
            } else if member_name.is_empty() {
                self.member(self.resolve(ty)?, name, depth + 1)?
                    .map(|(inner, ty)| (offset + inner, ty))
            } else {
                None
            };
            if let Some(found) = found
                && result.replace(found).is_some()
            {
                return Err(invalid_data("ambiguous native BTF member"));
            }
        }
        Ok(result)
    }

    fn field(&self, root: &str, path: &[&str], size: u32) -> io::Result<i16> {
        let (_, mut at) = self.named(root, 4)?;
        let mut offset = 0u32;
        for (index, name) in path.iter().enumerate() {
            let (part, ty) = self
                .member(at, name, 0)?
                .ok_or_else(|| invalid_data("missing native CT member"))?;
            offset = offset
                .checked_add(part)
                .ok_or_else(|| invalid_data("native CT member overflow"))?;
            at = self.resolve(ty)?;
            if index + 1 == path.len() {
                let kind = self.word(at + 4)? >> 24 & 31;
                let actual_size = if kind == 3 {
                    let element = self.resolve(self.word(at + 12)?)?;
                    let element_size = if self.word(element + 4)? >> 24 & 31 == 2 {
                        8
                    } else {
                        self.word(element + 8)?
                    };
                    element_size
                        .checked_mul(self.word(at + 20)?)
                        .ok_or_else(|| invalid_data("BTF array extent overflow"))?
                } else if kind == 2 {
                    8
                } else {
                    self.word(at + 8)?
                };
                if actual_size != size {
                    return Err(invalid_data("native CT leaf size mismatch"));
                }
            } else if self.word(at + 4)? >> 24 & 31 == 3 {
                at = self.resolve(self.word(at + 12)?)?;
            }
        }
        i16::try_from(offset).map_err(|_| invalid_data("native CT member exceeds BPF offset"))
    }

    fn pointer(&self, id: u32, name: &str) -> io::Result<()> {
        let pointer = self.resolve(id)?;
        if self.word(pointer + 4)? >> 24 & 31 != 2 {
            return Err(invalid_data("native kfunc argument is not pointer"));
        }
        let target = self.resolve(self.word(pointer + 8)?)?;
        if self.name(self.word(target)?)? != name {
            return Err(invalid_data("native kfunc pointee type mismatch"));
        }
        Ok(())
    }

    fn function(&self, name: &str, parameters: usize) -> io::Result<u32> {
        let (id, at) = self.named(name, 12)?;
        let proto = self.resolve(self.word(at + 8)?)?;
        let info = self.word(proto + 4)?;
        if info >> 24 & 31 != 13 || info & 0xffff != parameters as u32 {
            return Err(invalid_data("native CT kfunc prototype mismatch"));
        }
        if parameters == 5 {
            self.pointer(self.word(proto + 8)?, "nf_conn")?;
            self.pointer(
                self.word(proto + 16)?,
                if name == "bpf_skb_ct_lookup" {
                    "__sk_buff"
                } else {
                    "xdp_md"
                },
            )?;
            self.pointer(self.word(proto + 24)?, "bpf_sock_tuple")?;
            self.pointer(self.word(proto + 40)?, "bpf_ct_opts")?;
            for parameter in [2, 4] {
                let integer = self.resolve(self.word(proto + 16 + parameter * 8)?)?;
                if self.word(integer + 4)? >> 24 & 31 != 1 || self.word(integer + 8)? != 4 {
                    return Err(invalid_data("native kfunc length argument mismatch"));
                }
            }
        } else {
            if self.word(proto + 8)? != 0 {
                return Err(invalid_data("native CT release return mismatch"));
            }
            self.pointer(self.word(proto + 16)?, "nf_conn")?;
        }
        Ok(id)
    }

    fn parse(bytes: Vec<u8>) -> io::Result<Self> {
        let mut result = Self {
            bytes,
            records: vec![usize::MAX],
            strings: 0,
            strings_end: 0,
        };
        if result.bytes.get(..4) != Some(&[0x9f, 0xeb, 1, 0]) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native requires little-endian BTF v1",
            ));
        }
        let header = result.word(4)? as usize;
        let mut at = header
            .checked_add(result.word(8)? as usize)
            .ok_or_else(|| invalid_data("BTF type section overflow"))?;
        let end = at
            .checked_add(result.word(12)? as usize)
            .ok_or_else(|| invalid_data("BTF type section overflow"))?;
        result.strings = header
            .checked_add(result.word(16)? as usize)
            .ok_or_else(|| invalid_data("BTF strings overflow"))?;
        result.strings_end = result
            .strings
            .checked_add(result.word(20)? as usize)
            .ok_or_else(|| invalid_data("BTF strings overflow"))?;
        if header < 24 || end > result.strings || result.strings_end > result.bytes.len() {
            return Err(invalid_data("BTF section exceeds file or overlaps strings"));
        }
        while at < end {
            result.records.push(at);
            let info = result.word(at + 4)?;
            let count = (info & 0xffff) as usize;
            let extra = match info >> 24 & 31 {
                1 | 14 | 17 => 4,
                3 => 12,
                4 | 5 | 15 | 19 => count * 12,
                6 | 13 => count * 8,
                2 | 7..=12 | 16 | 18 => 0,
                _ => return Err(invalid_data("unsupported native BTF type kind")),
            };
            at = at
                .checked_add(12 + extra)
                .ok_or_else(|| invalid_data("BTF type extent overflow"))?;
        }
        if at != end {
            return Err(invalid_data("BTF type section boundary mismatch"));
        }
        Ok(result)
    }

    fn read(admitted: usize) -> io::Result<Self> {
        Self::parse(read_bounded(VMLINUX, admitted)?)
    }

    fn with_conntrack(self, admitted: Option<usize>) -> io::Result<(Self, Option<OwnedFd>, u32)> {
        let base_types = u32::try_from(self.records.len() - 1)
            .map_err(|_| invalid_data("native BTF type count overflow"))?;
        if self.named("bpf_xdp_ct_lookup", 12).is_ok()
            && self.named("bpf_skb_ct_lookup", 12).is_ok()
            && self.named("bpf_ct_release", 12).is_ok()
        {
            return Ok((self, None, base_types));
        }
        self.with_module(admitted, CONNTRACK, b"nf_conntrack")
    }

    fn with_module(
        self,
        admitted: Option<usize>,
        path: &str,
        name: &[u8],
    ) -> io::Result<(Self, Option<OwnedFd>, u32)> {
        let base_types = u32::try_from(self.records.len() - 1)
            .map_err(|_| invalid_data("native BTF type count overflow"))?;
        let admitted = admitted.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "native nf_conntrack module BTF was not admitted",
            )
        })?;
        let module = read_bounded(path, admitted)?;
        let fd = module_fd(&module, name)?;
        let word = |at: usize| -> io::Result<usize> {
            Ok(u32::from_ne_bytes(
                module
                    .get(at..at + 4)
                    .ok_or_else(|| invalid_data("short split native BTF"))?
                    .try_into()
                    .unwrap(),
            ) as usize)
        };
        if module.get(..4) != Some(&[0x9f, 0xeb, 1, 0]) {
            return Err(invalid_data("invalid split native BTF header"));
        }
        let header = word(4)?;
        let mt = header
            .checked_add(word(8)?)
            .ok_or_else(|| invalid_data("split BTF extent overflow"))?;
        let me = mt
            .checked_add(word(12)?)
            .ok_or_else(|| invalid_data("split BTF extent overflow"))?;
        let ms = header
            .checked_add(word(16)?)
            .ok_or_else(|| invalid_data("split BTF extent overflow"))?;
        let mse = ms
            .checked_add(word(20)?)
            .ok_or_else(|| invalid_data("split BTF extent overflow"))?;
        if header < 24 || me > ms || mse > module.len() {
            return Err(invalid_data("split BTF sections overlap or exceed file"));
        }
        let module_types = module
            .get(mt..me)
            .ok_or_else(|| invalid_data("split BTF types exceed section"))?;
        let module_strings = module
            .get(ms..mse)
            .ok_or_else(|| invalid_data("split BTF strings exceed section"))?;
        let base_header = self.word(4)? as usize;
        let bt = base_header + self.word(8)? as usize;
        let be = bt + self.word(12)? as usize;
        let base_types_bytes = &self.bytes[bt..be];
        let base_strings = &self.bytes[self.strings..self.strings_end];
        let types_len = base_types_bytes
            .len()
            .checked_add(module_types.len())
            .ok_or_else(|| invalid_data("split BTF types overflow"))?;
        let strings_len = base_strings
            .len()
            .checked_add(module_strings.len())
            .ok_or_else(|| invalid_data("split BTF strings overflow"))?;
        let extent = 24usize
            .checked_add(types_len)
            .and_then(|x| x.checked_add(strings_len))
            .ok_or_else(|| invalid_data("split BTF extent overflow"))?;
        let mut merged = Vec::new();
        merged.try_reserve_exact(extent).map_err(io::Error::other)?;
        merged.extend_from_slice(&self.bytes[..24]);
        for (offset, value) in [
            (4, 24),
            (8, 0),
            (12, types_len),
            (16, types_len),
            (20, strings_len),
        ] {
            merged[offset..offset + 4].copy_from_slice(
                &u32::try_from(value)
                    .map_err(|_| invalid_data("split BTF section exceeds u32"))?
                    .to_ne_bytes(),
            );
        }
        merged.extend_from_slice(base_types_bytes);
        merged.extend_from_slice(module_types);
        merged.extend_from_slice(base_strings);
        merged.extend_from_slice(module_strings);
        Ok((Self::parse(merged)?, Some(fd), base_types))
    }
}

impl Layout {
    pub(super) fn read(tc: bool, vlan: bool, preparation_bytes: usize) -> io::Result<Self> {
        let bounds = Bounds::read()?;
        if bounds.memory_bytes()? > preparation_bytes {
            return Err(invalid_data(
                "native BTF preparation exceeds reserved memory",
            ));
        }
        let (btf, module, base_types) = Types::read(bounds.base)?.with_conntrack(bounds.module)?;
        let (_, opts) = btf.named("bpf_ct_opts", 4)?;
        if btf.word(opts + 8)? as usize != size_of::<CtOptions>() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native requires 16-byte bpf_ct_opts",
            ));
        }
        for (name, size, expected) in CT_OPTIONS_FIELDS {
            if btf.field("bpf_ct_opts", &[name], size)? != expected {
                return Err(invalid_data("native conntrack options layout mismatch"));
            }
        }
        Ok(Self {
            lookup: btf.function(
                if tc {
                    "bpf_skb_ct_lookup"
                } else {
                    "bpf_xdp_ct_lookup"
                },
                5,
            )?,
            release: btf.function("bpf_ct_release", 1)?,
            lookup_offset: if btf.function(
                if tc {
                    "bpf_skb_ct_lookup"
                } else {
                    "bpf_xdp_ct_lookup"
                },
                5,
            )? > base_types
            {
                1
            } else {
                0
            },
            release_offset: if btf.function("bpf_ct_release", 1)? > base_types {
                1
            } else {
                0
            },
            btf: module,
            vlan: if !tc && vlan {
                Some(btf.named("bpf_xdp_metadata_rx_vlan_tag", 12)?.0)
            } else {
                None
            },
            src: btf.field("nf_conn", &["tuplehash", "tuple", "src", "u3"], 16)?,
            dst: btf.field("nf_conn", &["tuplehash", "tuple", "dst", "u3"], 16)?,
            sport: btf.field("nf_conn", &["tuplehash", "tuple", "src", "u"], 2)?,
            dport: btf.field("nf_conn", &["tuplehash", "tuple", "dst", "u"], 2)?,
            family: btf.field("nf_conn", &["tuplehash", "tuple", "src", "l3num"], 2)?,
            proto: btf.field("nf_conn", &["tuplehash", "tuple", "dst", "protonum"], 1)?,
            zone: btf.field("nf_conn", &["zone", "id"], 2)?,
            socket_remote4: btf.field("bpf_sock", &["dst_ip4"], 4)?,
            socket_local4: btf.field("bpf_sock", &["src_ip4"], 4)?,
            socket_remote6: btf.field("bpf_sock", &["dst_ip6"], 16)?,
            socket_local6: btf.field("bpf_sock", &["src_ip6"], 16)?,
            socket_remote_port: btf.field("bpf_sock", &["dst_port"], 2)?,
            socket_local_port: btf.field("bpf_sock", &["src_port"], 4)?,
        })
    }
}

#[cfg(feature = "host")]
impl crate::bpf::source::native::HostNativeLayoutAdmission {
    pub fn preparation_memory_bytes() -> io::Result<usize> {
        preparation_memory_bytes()
    }

    /// Read the current base/module BTF under the caller's preparation reservation.
    pub fn read(preparation_bytes: usize, producer_callback: u64) -> io::Result<Self> {
        use crate::bpf::source::native::HostNativeLayout;
        let bounds = Bounds::read()?;
        if bounds.memory_bytes()? > preparation_bytes || producer_callback == 0 {
            return Err(invalid_data(
                "Host Native layout is not funded or callback is absent",
            ));
        }
        let (btf, module, _) = Types::read(bounds.base)?.with_conntrack(bounds.module)?;
        let field = |root, names: &[&str], bytes| {
            u32::try_from(btf.field(root, names, bytes)?)
                .map_err(|_| invalid_data("negative Host Native field offset"))
        };
        let (_, hook) = btf.named("nf_hook_entry", 4)?;
        let layout = HostNativeLayout {
            cast: btf.named("bpf_cast_to_kern_ctx", 12)?.0,
            sock_cookie: field("sock", &["__sk_common", "skc_cookie", "counter"], 8)?,
            sock_family: field("sock", &["__sk_common", "skc_family"], 2)?,
            sock_state: field("sock", &["__sk_common", "skc_state"], 1)?,
            sock_type: field("sock", &["sk_type"], 2)?,
            sock_protocol: field("sock", &["sk_protocol"], 2)?,
            sock_mark: field("sock", &["sk_mark"], 4)?,
            skb_len: field("sk_buff", &["len"], 4)?,
            skb_data_len: field("sk_buff", &["data_len"], 4)?,
            skb_data: field("sk_buff", &["data"], 8)?,
            skb_protocol: field("sk_buff", &["protocol"], 2)?,
            skb_mark: field("sk_buff", &["mark"], 4)?,
            skb_refdst: field("sk_buff", &["_skb_refdst"], 8)?,
            skb_nfct: field("sk_buff", &["_nfct"], 8)?,
            dst_dev: field("dst_entry", &["dev"], 8)?,
            dev_ifindex: field("net_device", &["ifindex"], 4)?,
            dev_net: field("net_device", &["nd_net", "net"], 8)?,
            state_net: field("nf_hook_state", &["net"], 8)?,
            state_out: field("nf_hook_state", &["out"], 8)?,
            state_hook: field("nf_hook_state", &["hook"], 1)?,
            state_pf: field("nf_hook_state", &["pf"], 1)?,
            ct_net: field("nf_conn", &["ct_net", "net"], 8)?,
            ct_status: field("nf_conn", &["status"], 8)?,
            ct_zone_id: field("nf_conn", &["zone", "id"], 2)?,
            ct_zone_dir: field("nf_conn", &["zone", "dir"], 1)?,
            ct_zone_flags: field("nf_conn", &["zone", "flags"], 1)?,
            ct_src: field("nf_conn", &["tuplehash", "tuple", "src", "u3"], 16)?,
            ct_dst: field("nf_conn", &["tuplehash", "tuple", "dst", "u3"], 16)?,
            ct_sport: field("nf_conn", &["tuplehash", "tuple", "src", "u"], 2)?,
            ct_dport: field("nf_conn", &["tuplehash", "tuple", "dst", "u"], 2)?,
            ct_family: field("nf_conn", &["tuplehash", "tuple", "src", "l3num"], 2)?,
            ct_protocol: field("nf_conn", &["tuplehash", "tuple", "dst", "protonum"], 1)?,
            net_hooks_ipv4: field("net", &["nf", "hooks_ipv4"], 5 * 8)?,
            net_hooks_ipv6: field("net", &["nf", "hooks_ipv6"], 5 * 8)?,
            hooks_count: field("nf_hook_entries", &["num_hook_entries"], 2)?,
            hooks_entries: field("nf_hook_entries", &["hooks"], 0)?,
            hook_stride: btf.word(hook + 8)?,
            hook_callback: field("nf_hook_entry", &["hook"], 8)?,
            hook_private: field("nf_hook_entry", &["priv"], 8)?,
            prog_aux: field("bpf_prog", &["aux"], 8)?,
            aux_id: field("bpf_prog_aux", &["id"], 4)?,
            producer_callback,
        };
        Ok(Self::from_admitted(layout, module))
    }
}

fn module_fd(expected: &[u8], expected_name: &[u8]) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct Id {
        start: u32,
        next: u32,
        flags: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct Info {
        data: u64,
        size: u32,
        id: u32,
        name: u64,
        name_len: u32,
        kernel: u32,
    }
    let mut start = 0;
    for _ in 0..4096 {
        let mut id = Id {
            start,
            next: 0,
            flags: 0,
        };
        match bpf(23, &mut id) {
            Ok(_) => {}
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => break,
            Err(error) => return Err(error),
        }
        if id.next <= start {
            return Err(invalid_data("native BTF inventory failed to advance"));
        }
        start = id.next;
        let fd = match bpf_fd(
            19,
            &mut Id {
                start,
                next: 0,
                flags: 0,
            },
        ) {
            Ok(fd) => fd,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(error) => return Err(error),
        };
        let mut name = [0u8; 256];
        let mut info = Info {
            name: name.as_mut_ptr() as u64,
            name_len: name.len() as u32,
            ..Info::default()
        };
        object_info(fd.as_fd(), &mut info)?;
        let len = name
            .iter()
            .position(|x| *x == 0)
            .ok_or_else(|| invalid_data("unterminated native module BTF name"))?;
        if &name[..len] != expected_name {
            continue;
        }
        if info.id != start || info.kernel != 1 || info.size as usize != expected.len() {
            return Err(invalid_data(
                "native BTF descriptor is not running nf_conntrack module",
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected.len())
            .map_err(io::Error::other)?;
        bytes.resize(expected.len(), 0);
        let mut verify = Info {
            data: bytes.as_mut_ptr() as u64,
            size: bytes.len() as u32,
            ..Info::default()
        };
        object_info(fd.as_fd(), &mut verify)?;
        if verify.kernel != 1
            || verify.id != start
            || verify.size as usize != expected.len()
            || bytes != expected
        {
            return Err(invalid_data(
                "native module BTF descriptor differs from sysfs",
            ));
        }
        return Ok(fd);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "running nf_conntrack module BTF descriptor unavailable",
    ))
}

const TUN_BTF_LIMIT: usize = 4 << 20;
const CAPTURED_COLD_OBJECTS: [(&str, usize); 8] = [
    ("net_device", 64 << 10),
    ("tun_struct", 64 << 10),
    ("tun_file", 64 << 10),
    ("netdev_queue", 4096),
    ("netdev_rx_queue", 4096),
    ("file", 4096),
    ("dentry", 4096),
    ("inode", 4096),
];
const CAPTURED_PERCPU_OBJECTS: [(&str, usize); 2] =
    [("pcpu_sw_netstats", 256), ("net_device_core_stats", 128)];

pub(super) fn captured_preparation_bounds() -> io::Result<(usize, usize)> {
    let base = admitted_size(std::fs::metadata(VMLINUX)?.len())?;
    let scratch = Bounds {
        base,
        module: Some(TUN_BTF_LIMIT),
    }
    .memory_bytes()?;
    if base
        .checked_add(TUN_BTF_LIMIT)
        .is_none_or(|size| size > BTF_LIMIT)
    {
        return Err(invalid_data(
            "captured combined BTF exceeds funded construction bound",
        ));
    }
    let cpus = possible_cpu_count(&std::fs::read_to_string(
        "/sys/devices/system/cpu/possible",
    )?)?;
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|size| size.is_power_of_two())
        .ok_or_else(|| invalid_data("invalid captured page size"))?;
    let mut cold = 500 * size_of::<usize>();
    for (_, size) in CAPTURED_COLD_OBJECTS {
        cold = cold
            .checked_add(
                size.checked_add(page - 1)
                    .map(|size| size & !(page - 1))
                    .ok_or_else(|| invalid_data("captured cold ceiling overflow"))?,
            )
            .ok_or_else(|| invalid_data("captured cold ceiling overflow"))?;
    }
    for (_, size) in CAPTURED_PERCPU_OBJECTS {
        cold = cold
            .checked_add(
                size.checked_add(127)
                    .and_then(|size| (size & !127).checked_mul(cpus))
                    .ok_or_else(|| invalid_data("captured perCPU ceiling overflow"))?,
            )
            .ok_or_else(|| invalid_data("captured perCPU ceiling overflow"))?;
    }
    Ok((scratch, cold))
}

#[derive(Clone, Debug)]
pub(super) struct CapturedLayout {
    pub entry: u32,
    pub skb_dev: i16,
    pub skb_cb: i16,
    pub cb_data: i16,
    pub ctx_cb: i16,
    pub dev_ifindex: i16,
    pub dev_net: i16,
    pub net_cookie: i16,
    pub cold_bytes: usize,
    pub tcx_link_bytes: usize,
    pub trace_link_bytes: usize,
}

impl Types {
    fn aggregate_size(&self, name: &str) -> io::Result<usize> {
        let (_, at) = self.named(name, 4)?;
        let size = self.word(at + 8)? as usize;
        if size == 0 || size > 1 << 20 {
            return Err(invalid_data("captured BTF allocation size outside bound"));
        }
        Ok(size)
    }

    fn pointer_field(&self, root: &str, path: &[&str], target: &str) -> io::Result<i16> {
        let (_, mut at) = self.named(root, 4)?;
        for (index, name) in path.iter().enumerate() {
            let (_, ty) = self
                .member(at, name, 0)?
                .ok_or_else(|| invalid_data("missing captured BTF pointer member"))?;
            if index + 1 == path.len() {
                self.pointer(ty, target)?;
            } else {
                at = self.resolve(ty)?;
            }
        }
        self.field(root, path, 8)
    }

    fn captured_entry(&self) -> io::Result<u32> {
        let (id, at) = self.named("__netif_receive_skb_one_core", 12)?;
        let proto = self.resolve(self.word(at + 8)?)?;
        if self.word(proto + 4)? != (13 << 24 | 2) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "captured target entry prototype changed",
            ));
        }
        self.pointer(self.word(proto + 16)?, "sk_buff")?;
        for (ty, width) in [(self.word(proto + 8)?, 4), (self.word(proto + 24)?, 1)] {
            let at = self.resolve(ty)?;
            if self.word(at + 4)? >> 24 & 31 != 1 || self.word(at + 8)? != width {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "captured target entry scalar changed",
                ));
            }
        }
        Ok(id)
    }
}

impl CapturedLayout {
    pub(super) fn read() -> io::Result<Self> {
        if !cfg!(all(target_arch = "x86_64", target_endian = "little")) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "captured return requires x86-64 little endian",
            ));
        }
        let base = admitted_size(std::fs::metadata(VMLINUX)?.len())?;
        let (reserved_scratch, _) = captured_preparation_bounds()?;
        if (Bounds {
            base,
            module: Some(TUN_BTF_LIMIT),
        })
        .memory_bytes()?
            > reserved_scratch
        {
            return Err(invalid_data(
                "captured BTF changed beyond its funded construction bound",
            ));
        }
        let types = Types::read(base)?;
        let cb_data = types.field("qdisc_skb_cb", &["data"], 20)?;
        let skb_cb = types.field("sk_buff", &["cb"], 48)?;
        if cb_data < 0 || usize::try_from(cb_data).unwrap() + 20 > 48 || cb_data % 4 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "captured qdisc scratch extent changed",
            ));
        }
        let mut result = Self {
            entry: types.captured_entry()?,
            skb_dev: types.pointer_field("sk_buff", &["dev"], "net_device")?,
            skb_cb,
            cb_data,
            ctx_cb: types.field("__sk_buff", &["cb"], 20)?,
            dev_ifindex: types.field("net_device", &["ifindex"], 4)?,
            dev_net: types.pointer_field("net_device", &["nd_net", "net"], "net")?,
            net_cookie: types.field("net", &["net_cookie"], 8)?,
            cold_bytes: 0,
            tcx_link_bytes: types.aggregate_size("tcx_link")?,
            trace_link_bytes: types.aggregate_size("bpf_tracing_link")?,
        };
        if result.tcx_link_bytes > 4096 || result.trace_link_bytes > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "captured link layout exceeds funded source ceiling",
            ));
        }
        types.pointer_field("net_device", &["phydev"], "phy_device")?;
        let (_, dev) = types.named("net_device", 4)?;
        if types.member(dev, "hwprov", 0)?.is_some() {
            types.pointer_field("net_device", &["hwprov"], "hwtstamp_provider")?;
        }
        let (types, _module, _) = if types.named("tun_struct", 4).is_ok() {
            (types, None, 0)
        } else {
            let size = admitted_size(std::fs::metadata("/sys/kernel/btf/tun")?.len())?;
            if size > TUN_BTF_LIMIT {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "tun BTF exceeds funded captured construction ceiling",
                ));
            }
            types.with_module(Some(size), "/sys/kernel/btf/tun", b"tun")?
        };
        for (name, path, size) in [
            ("tun_struct", &["rx_batched"][..], 4),
            ("tun_struct", &["numqueues"][..], 4),
            ("tun_struct", &["numdisabled"][..], 4),
            ("tun_file", &["napi_enabled"][..], 1),
            ("tun_file", &["napi_frags_enabled"][..], 1),
        ] {
            types.field(name, path, size)?;
        }
        let cpus = possible_cpu_count(&std::fs::read_to_string(
            "/sys/devices/system/cpu/possible",
        )?)?;
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page = usize::try_from(page)
            .ok()
            .filter(|size| size.is_power_of_two())
            .ok_or_else(|| invalid_data("invalid captured allocation page size"))?;
        // alloc_netdev_mqs, sk_alloc(tun_proto), single RX/TX queues and TUN_READQ_SIZE=500.
        let mut cold = 500usize
            .checked_mul(size_of::<usize>())
            .ok_or_else(|| invalid_data("captured ring allocation overflow"))?;
        for (name, ceiling) in CAPTURED_COLD_OBJECTS {
            let size = types.aggregate_size(name)?;
            if size > ceiling {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "captured cold type exceeds funded source ceiling",
                ));
            }
            cold = cold
                .checked_add(
                    size.checked_add(page - 1)
                        .map(|n| n & !(page - 1))
                        .ok_or_else(|| invalid_data("captured slab round overflow"))?,
                )
                .ok_or_else(|| invalid_data("captured cold allocation overflow"))?;
        }
        for (name, ceiling) in CAPTURED_PERCPU_OBJECTS {
            let size = types.aggregate_size(name)?;
            if size > ceiling {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "captured perCPU type exceeds funded source ceiling",
                ));
            }
            cold = cold
                .checked_add(
                    size.checked_add(127)
                        .and_then(|size| (size & !127).checked_mul(cpus))
                        .ok_or_else(|| invalid_data("captured perCPU allocation overflow"))?,
                )
                .ok_or_else(|| invalid_data("captured cold allocation overflow"))?;
        }
        result.cold_bytes = cold;
        Ok(result)
    }
}

fn possible_cpu_count(text: &str) -> io::Result<usize> {
    let mut count = 0usize;
    let mut previous = None;
    for part in text.trim().split(',') {
        let mut range = part.split('-');
        let first = range
            .next()
            .unwrap_or("")
            .parse::<usize>()
            .map_err(|_| invalid_data("invalid possible CPU range"))?;
        let last = range
            .next()
            .map(str::parse::<usize>)
            .transpose()
            .map_err(|_| invalid_data("invalid possible CPU range"))?
            .unwrap_or(first);
        if range.next().is_some()
            || last < first
            || previous.is_some_and(|old| first <= old)
            || last >= 65536
        {
            return Err(invalid_data("overlapping or unbounded possible CPUs"));
        }
        count = count
            .checked_add(last - first + 1)
            .ok_or_else(|| invalid_data("possible CPU count overflow"))?;
        previous = Some(last);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_array_field_uses_pointer_width_not_pointee_id() {
        let words = [
            1u32,
            1 << 24,
            4,
            32,
            0,
            2 << 24,
            1,
            0,
            3 << 24,
            0,
            2,
            1,
            5,
            5,
            (4 << 24) | 1,
            40,
            10,
            3,
            0,
        ];
        let strings = b"\0u32\0Root\0hooks\0";
        let type_bytes = (words.len() * 4) as u32;
        let mut bytes = vec![0x9f, 0xeb, 1, 0];
        for word in [24, 0, type_bytes, type_bytes, strings.len() as u32] {
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        for word in words {
            bytes.extend_from_slice(&word.to_ne_bytes());
        }
        bytes.extend_from_slice(strings);
        let types = Types::parse(bytes).unwrap();
        assert_eq!(types.field("Root", &["hooks"], 40).unwrap(), 0);
        assert!(types.field("Root", &["hooks"], 5).is_err());
        assert!(types.field("Root", &["hooks"], 20).is_err());
    }

    #[test]
    fn captured_possible_cpu_ranges_are_exact_and_bounded() {
        assert_eq!(possible_cpu_count("0-3,8-9\n").unwrap(), 6);
        for invalid in ["", "1-0", "0-1,1-2", "0-65536", "0-1-2", "0,,1"] {
            assert!(possible_cpu_count(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn native_preparation_includes_closed_counter_emission_and_map_admission() {
        let bounds = Bounds {
            base: 24,
            module: Some(48),
        };
        assert_eq!(
            bounds.memory_bytes().unwrap(),
            72 * 12 + (2 << 20) + CLOSED_COUNTER_PREPARATION_BYTES
        );
    }

    #[test]
    fn conntrack_options_match_stock_kernel_abi() {
        assert_eq!(size_of::<CtOptions>(), 16);
        assert_eq!(
            CT_OPTIONS_FIELDS,
            [
                ("netns_id", 4, 0),
                ("error", 4, 4),
                ("l4proto", 1, 8),
                ("dir", 1, 9),
                ("ct_zone_id", 2, 10),
                ("ct_zone_dir", 1, 12),
                ("reserved", 3, 13),
            ]
        );
    }
}

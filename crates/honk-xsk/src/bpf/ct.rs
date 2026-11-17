use super::{bpf, bpf_fd, invalid_data, object_info};
use std::io::{self, Read as _};
use std::mem::size_of;
use std::os::fd::{AsFd, OwnedFd};

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
                "combined kernel BTF exceeds construction bound",
            ));
        }
        Ok(Self { base, module })
    }
}

fn admitted_size(size: u64) -> io::Result<usize> {
    usize::try_from(size)
        .ok()
        .filter(|size| (24..=BTF_LIMIT).contains(size))
        .ok_or_else(|| invalid_data("kernel BTF size outside construction bound"))
}

fn read_bounded(path: &str, admitted: usize) -> io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    if admitted_size(file.metadata()?.len())? != admitted {
        return Err(invalid_data("kernel BTF size changed after admission"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(admitted)
        .map_err(io::Error::other)?;
    bytes.resize(admitted, 0);
    file.read_exact(&mut bytes)?;
    if file.read(&mut [0u8; 1])? != 0 || file.metadata()?.len() != admitted as u64 {
        return Err(invalid_data("kernel BTF grew beyond admitted read"));
    }
    Ok(bytes)
}

#[repr(C)]
struct CtOptions {
    netns_id: i32,
    error: i32,
    l4proto: u8,
    dir: u8,
    ct_zone_id: u16,
    ct_zone_dir: u8,
    reserved: [u8; 3],
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

/// Conntrack kfunc IDs and their independently selected BTF FD-array indices.
pub struct ConntrackKfuncs {
    pub lookup: u32,
    pub release: u32,
    /// Zero selects vmlinux; one selects the module FD in `btf`.
    pub lookup_offset: i16,
    /// Zero selects vmlinux; one selects the module FD in `btf`.
    pub release_offset: i16,
    /// Keeps split-module BTF alive while programs using its IDs are loaded.
    pub btf: Option<OwnedFd>,
}

impl ConntrackKfuncs {
    /// Resolve the running kernel's XDP conntrack lookup and release ABI.
    pub fn read() -> io::Result<Self> {
        let bounds = Bounds::read()?;
        let (btf, module, base_types) =
            Types::parse(read_bounded(VMLINUX, bounds.base)?)?.with_conntrack(bounds.module)?;
        let (_, opts) = btf.named("bpf_ct_opts", 4)?;
        if btf.word(opts + 8)? as usize != size_of::<CtOptions>() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "conntrack requires 16-byte bpf_ct_opts",
            ));
        }
        for (name, size, expected) in CT_OPTIONS_FIELDS {
            if btf.field(opts, name, size)? != expected as u32 {
                return Err(invalid_data("conntrack options layout mismatch"));
            }
        }
        let lookup = btf.function("bpf_xdp_ct_lookup", 5)?;
        let release = btf.function("bpf_ct_release", 1)?;
        Ok(Self {
            lookup,
            release,
            lookup_offset: i16::from(lookup > base_types),
            release_offset: i16::from(release > base_types),
            btf: module,
        })
    }
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
            .ok_or_else(|| invalid_data("short kernel BTF"))?;
        Ok(u32::from_ne_bytes(
            bytes
                .try_into()
                .map_err(|_| invalid_data("short kernel BTF word"))?,
        ))
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
            format!("conntrack requires kernel BTF {name}"),
        ))
    }

    fn member(&self, at: usize, name: &str, depth: usize) -> io::Result<Option<(u32, u32)>> {
        if depth == 8 {
            return Err(invalid_data("nested BTF member depth"));
        }
        let info = self.word(at + 4)?;
        if !matches!(info >> 24 & 31, 4 | 5) {
            return Err(invalid_data("BTF member is not aggregate"));
        }
        let mut result = None;
        for index in 0..info & 0xffff {
            let member = at + 12 + index as usize * 12;
            let member_name = self.name(self.word(member)?)?;
            let bits = self.word(member + 8)?;
            if bits & 7 != 0 || (info >> 31 != 0 && bits >> 24 != 0) {
                continue;
            }
            let offset = if info >> 31 != 0 {
                bits & 0xffffff
            } else {
                bits
            } / 8;
            let ty = self.word(member + 4)?;
            let found = if member_name == name {
                Some((offset, ty))
            } else if member_name.is_empty() {
                self.member(self.resolve(ty)?, name, depth + 1)?
                    .map(|(inner, ty)| {
                        offset
                            .checked_add(inner)
                            .map(|offset| (offset, ty))
                            .ok_or_else(|| invalid_data("BTF member overflow"))
                    })
                    .transpose()?
            } else {
                None
            };
            if let Some(found) = found
                && result.replace(found).is_some()
            {
                return Err(invalid_data("ambiguous BTF member"));
            }
        }
        Ok(result)
    }

    fn field(&self, root: usize, name: &str, size: u32) -> io::Result<u32> {
        let (offset, ty) = self
            .member(root, name, 0)?
            .ok_or_else(|| invalid_data("missing conntrack options member"))?;
        let at = self.resolve(ty)?;
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
            return Err(invalid_data("conntrack options member size mismatch"));
        }
        Ok(offset)
    }

    fn pointer(&self, id: u32, name: &str, kind: u32) -> io::Result<()> {
        let pointer = self.resolve(id)?;
        if self.word(pointer + 4)? >> 24 & 31 != 2 {
            return Err(invalid_data("conntrack kfunc argument is not pointer"));
        }
        let target = self.resolve(self.word(pointer + 8)?)?;
        if self.word(target + 4)? >> 24 & 31 != kind || self.name(self.word(target)?)? != name {
            return Err(invalid_data("conntrack kfunc pointee type mismatch"));
        }
        Ok(())
    }

    fn function(&self, name: &str, parameters: usize) -> io::Result<u32> {
        let (id, at) = self.named(name, 12)?;
        let proto = self.resolve(self.word(at + 8)?)?;
        let info = self.word(proto + 4)?;
        if info >> 24 & 31 != 13 || info & 0xffff != parameters as u32 {
            return Err(invalid_data("conntrack kfunc prototype mismatch"));
        }
        if parameters == 5 {
            self.pointer(self.word(proto + 8)?, "nf_conn", 4)?;
            self.pointer(self.word(proto + 16)?, "xdp_md", 4)?;
            self.pointer(self.word(proto + 24)?, "bpf_sock_tuple", 4)?;
            self.pointer(self.word(proto + 40)?, "bpf_ct_opts", 4)?;
            for parameter in [2, 4] {
                let integer = self.resolve(self.word(proto + 16 + parameter * 8)?)?;
                if self.word(integer + 4)? >> 24 & 31 != 1 || self.word(integer + 8)? != 4 {
                    return Err(invalid_data("conntrack kfunc length argument mismatch"));
                }
            }
        } else {
            if self.word(proto + 8)? != 0 {
                return Err(invalid_data("conntrack release return mismatch"));
            }
            self.pointer(self.word(proto + 16)?, "nf_conn", 4)?;
        }
        Ok(id)
    }

    fn parse(bytes: Vec<u8>) -> io::Result<Self> {
        admitted_size(bytes.len() as u64)?;
        let mut result = Self {
            bytes,
            records: vec![usize::MAX],
            strings: 0,
            strings_end: 0,
        };
        if result.bytes.get(..4) != Some(&[0x9f, 0xeb, 1, 0]) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "conntrack requires little-endian BTF v1",
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
            if end - at < 12 {
                return Err(invalid_data("short BTF type record"));
            }
            result.records.push(at);
            let info = result.word(at + 4)?;
            let count = (info & 0xffff) as usize;
            let extra = match info >> 24 & 31 {
                1 | 14 | 17 => 4,
                3 => 12,
                4 | 5 | 15 | 19 => count * 12,
                6 | 13 => count * 8,
                2 | 7..=12 | 16 | 18 => 0,
                _ => return Err(invalid_data("unsupported BTF type kind")),
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

    fn with_conntrack(self, admitted: Option<usize>) -> io::Result<(Self, Option<OwnedFd>, u32)> {
        let base_types = u32::try_from(self.records.len() - 1)
            .map_err(|_| invalid_data("BTF type count overflow"))?;
        if self.named("bpf_xdp_ct_lookup", 12).is_ok() && self.named("bpf_ct_release", 12).is_ok() {
            return Ok((self, None, base_types));
        }
        let admitted = admitted.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "nf_conntrack module BTF was not admitted",
            )
        })?;
        let module = read_bounded(CONNTRACK, admitted)?;
        let fd = module_fd(&module)?;
        let word = |at: usize| -> io::Result<usize> {
            Ok(u32::from_ne_bytes(
                module
                    .get(at..at + 4)
                    .ok_or_else(|| invalid_data("short split BTF"))?
                    .try_into()
                    .map_err(|_| invalid_data("short split BTF word"))?,
            ) as usize)
        };
        if module.get(..4) != Some(&[0x9f, 0xeb, 1, 0]) {
            return Err(invalid_data("invalid split BTF header"));
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
        admitted_size(extent as u64)?;
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

fn module_fd(expected: &[u8]) -> io::Result<OwnedFd> {
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
            return Err(invalid_data("BTF inventory failed to advance"));
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
            .ok_or_else(|| invalid_data("unterminated module BTF name"))?;
        if &name[..len] != b"nf_conntrack" {
            continue;
        }
        if info.id != start || info.kernel != 1 || info.size as usize != expected.len() {
            return Err(invalid_data(
                "BTF descriptor is not running nf_conntrack module",
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
            return Err(invalid_data("module BTF descriptor differs from sysfs"));
        }
        return Ok(fd);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "running nf_conntrack module BTF descriptor unavailable",
    ))
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
        let (_, root) = types.named("Root", 4).unwrap();
        assert_eq!(types.field(root, "hooks", 40).unwrap(), 0);
        assert!(types.field(root, "hooks", 5).is_err());
        assert!(types.field(root, "hooks", 20).is_err());
        assert!(types.resolve(0).is_err());
        assert!(types.resolve(types.records.len() as u32).is_err());
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

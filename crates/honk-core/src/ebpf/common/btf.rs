//! Raw BTF reader for the few kernel and object layouts aya does not expose.

use anyhow::{Context, ensure};
use honk_netstack::{MemoryBudget, MemoryReservation};
use std::io::Read as _;
use std::ops::Range;
use std::sync::Arc;

pub(in crate::ebpf) const BTF_HEADER_LEN: usize = 24;

// Only raw BTF parses here; an ELF debug vmlinux needs HONK_VMLINUX_BTF pointed at its extracted `.BTF`.
const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
// OpenWrt's vmlinux-btf package installs a detached raw BTF blob here for kernels built without BTF.
const VMLINUX_BTF_FALLBACK_PATH: &str = "/usr/lib/debug/boot/vmlinux";
const VMLINUX_BTF_ENV: &str = "HONK_VMLINUX_BTF";

pub(crate) fn load_kernel() -> anyhow::Result<(Vec<u8>, aya::Btf)> {
    let data = if let Some(path) = std::env::var_os(VMLINUX_BTF_ENV) {
        std::fs::read(&path).with_context(|| {
            format!(
                "reading kernel BTF from {VMLINUX_BTF_ENV}={}",
                std::path::Path::new(&path).display()
            )
        })?
    } else {
        std::fs::read(VMLINUX_BTF_PATH)
            .or_else(|_| std::fs::read(VMLINUX_BTF_FALLBACK_PATH))
            .with_context(|| {
                format!(
                    "reading kernel BTF from {VMLINUX_BTF_PATH} or {VMLINUX_BTF_FALLBACK_PATH}; set {VMLINUX_BTF_ENV}"
                )
            })?
    };
    let btf = aya::Btf::parse(&data, Default::default()).context("parsing selected kernel BTF")?;
    Ok((data, btf))
}

pub(crate) struct RawKernelBtf {
    pub(crate) data: Vec<u8>,
    _memory: MemoryReservation,
}

pub(crate) fn read_kernel_accounted_file(
    path: &std::path::Path,
    budget: &Arc<MemoryBudget>,
) -> anyhow::Result<RawKernelBtf> {
    let mut file = std::fs::File::open(path)?;
    // sysfs has no reliable size. Derive the exact maximum section end first.
    let mut header = [0u8; BTF_HEADER_LEN];
    read_btf_exact(&mut file, &mut header)?;
    anyhow::ensure!(
        u16::from_ne_bytes([header[0], header[1]]) == 0xeb9f,
        "Host kernel BTF endianness differs from the running target"
    );
    let extent = declared_extent(&header).context("invalid Host kernel BTF header")?;
    let raw_bytes = extent
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(core::mem::size_of::<Vec<u8>>()))
        .context("Host raw BTF charge overflow")?;
    let raw = budget
        .reserve(raw_bytes)
        .context("Host raw kernel BTF memory capacity")?;
    let mut data = Vec::new();
    data.try_reserve_exact(extent)
        .context("allocating charged Host kernel BTF")?;
    data.resize(extent, 0);
    data[..BTF_HEADER_LEN].copy_from_slice(&header);
    for chunk in data[BTF_HEADER_LEN..].chunks_mut(8192) {
        read_btf_exact(&mut file, chunk)?;
    }
    anyhow::ensure!(
        file.read(&mut header[..1])? == 0,
        "Host kernel BTF has undeclared trailing bytes"
    );
    Ok(RawKernelBtf { data, _memory: raw })
}

fn read_btf_exact(file: &mut std::fs::File, output: &mut [u8]) -> anyhow::Result<()> {
    match file.read_exact(output) {
        Ok(()) => Ok(()),
        // EOF is a successful short read in fs::read, then a BTF parse error;
        // it must not change canonical file-selection fallback semantics.
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            anyhow::bail!("truncated Host kernel BTF")
        }
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn declared_extent(header: &[u8; BTF_HEADER_LEN]) -> Option<usize> {
    let endian = match u16::from_le_bytes(header[..2].try_into().ok()?) {
        0xeb9f => Endian::Little,
        0x9feb => Endian::Big,
        _ => return None,
    };
    let header_len = read_u32(header, 4, endian)? as usize;
    if header_len < BTF_HEADER_LEN {
        return None;
    }
    let type_end = (read_u32(header, 8, endian)? as usize)
        .checked_add(read_u32(header, 12, endian)? as usize)?;
    let string_end = (read_u32(header, 16, endian)? as usize)
        .checked_add(read_u32(header, 20, endian)? as usize)?;
    header_len
        .checked_add(type_end.max(string_end))
        .filter(|&bytes| bytes <= isize::MAX as usize)
}

fn vector_peak(elements: usize, width: usize) -> Option<usize> {
    if elements == 0 {
        return Some(0);
    }
    // The pinned Vec growth retains an old and doubled new backing. Three
    // power-of-two capacities also cover exact-size collect/to_vec paths.
    elements
        .max(4)
        .checked_next_power_of_two()?
        .checked_mul(width)?
        .checked_mul(3)
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}

pub(crate) struct Btf<'a> {
    data: &'a [u8],
    types: Range<usize>,
    strings: Range<usize>,
    endian: Endian,
}

impl<'a> Btf<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < BTF_HEADER_LEN {
            return None;
        }
        let endian = match u16::from_le_bytes(data[..2].try_into().ok()?) {
            0xeb9f => Endian::Little,
            0x9feb => Endian::Big,
            _ => return None,
        };
        let header_len = read_u32(data, 4, endian)? as usize;
        if !(BTF_HEADER_LEN..=data.len()).contains(&header_len) {
            return None;
        }
        let range = |offset: usize, len: usize| {
            let start = header_len.checked_add(offset)?;
            let end = start.checked_add(len)?;
            (end <= data.len()).then_some(start..end)
        };
        let types = range(
            read_u32(data, 8, endian)? as usize,
            read_u32(data, 12, endian)? as usize,
        )?;
        let strings = range(
            read_u32(data, 16, endian)? as usize,
            read_u32(data, 20, endian)? as usize,
        )?;
        Some(Self {
            data,
            types,
            strings,
            endian,
        })
    }

    /// Word at an absolute record offset; reads past the type section fail
    /// instead of decoding string-table bytes as type records.
    pub(crate) fn u32_at(&self, offset: usize) -> Option<u32> {
        if offset.checked_add(4)? > self.types.end {
            return None;
        }
        read_u32(self.data, offset, self.endian)
    }

    pub(crate) fn kind(&self, cursor: usize) -> Option<u32> {
        Some((read_u32(self.data, cursor.checked_add(4)?, self.endian)? >> 24) & 0x1f)
    }

    pub(crate) fn string(&self, offset: u32) -> Option<&str> {
        let start = self.strings.start.checked_add(offset as usize)?;
        if start >= self.strings.end {
            return None;
        }
        let end = self.data[start..self.strings.end]
            .iter()
            .position(|&byte| byte == 0)?
            .checked_add(start)?;
        std::str::from_utf8(&self.data[start..end]).ok()
    }

    pub(crate) fn aya_parse_allocation_bound(&self) -> Option<usize> {
        // aya-obj 0.6 owns strings and a growing Vec<BtfType>. BtfType::read
        // additionally allocates only the arrays of wire-width entries below
        // and a temporary three-word header Vec, released after each record.
        let mut cursor = self.types.start;
        let mut records = 0usize;
        let mut arrays = 0usize;
        while cursor < self.types.end {
            let info = self.u32_at(cursor.checked_add(4)?)?;
            let kind = (info >> 24) & 0x1f;
            let vlen = info & 0xffff;
            let next = cursor
                .checked_add(12)?
                .checked_add(type_extra_len(kind, vlen)?)?;
            if next > self.types.end {
                return None;
            }
            let width = match kind {
                4 | 5 | 15 | 19 => 12,
                6 | 13 => 8,
                _ => 0,
            };
            if width != 0 {
                arrays = arrays.checked_add(vector_peak(vlen as usize, width)?)?;
            }
            records = records.checked_add(1)?;
            cursor = next;
        }
        vector_peak(
            records.checked_add(1)?,
            core::mem::size_of::<aya_obj::btf::BtfType>(),
        )?
        .checked_add(vector_peak(self.strings.len(), 1)?)?
        .checked_add(arrays)?
        .checked_add(vector_peak(3, core::mem::size_of::<u32>())?)?
        .checked_add(core::mem::size_of::<aya::Btf>())
    }

    /// Cursor of the first type of `kind` named `name`.
    pub(crate) fn find_type(&self, kind: u32, name: &str) -> Option<usize> {
        let mut cursor = self.types.start;
        while cursor < self.types.end {
            let name_offset = read_u32(self.data, cursor, self.endian)?;
            let info = read_u32(self.data, cursor.checked_add(4)?, self.endian)?;
            let payload = cursor.checked_add(12)?;
            let next = payload.checked_add(type_extra_len((info >> 24) & 0x1f, info & 0xffff)?)?;
            if next > self.types.end {
                return None;
            }
            if (info >> 24) & 0x1f == kind && self.string(name_offset) == Some(name) {
                return Some(cursor);
            }
            cursor = next;
        }
        None
    }

    pub(in crate::ebpf) fn unsigned_integer_width(&self, type_id: u32, width: u32) -> bool {
        let Some(cursor) = self.resolve_modifiers(type_id) else {
            return false;
        };
        self.kind(cursor) == Some(1)
            && self.u32_at(cursor + 8) == Some(width)
            && self.u32_at(cursor + 12) == width.checked_mul(8)
    }

    pub(in crate::ebpf) fn member_offset(&self, type_name: &str, member_name: &str) -> Option<u32> {
        self.composite_member_offset(self.find_type(4, type_name)?, member_name, 0, None)
    }

    /// Offset of a complete, non-bitfield member of exactly `width` bytes.
    pub(crate) fn sized_member_offset(
        &self,
        type_name: &str,
        member_name: &str,
        width: u32,
    ) -> Option<u32> {
        self.composite_member_offset(self.find_type(4, type_name)?, member_name, 0, Some(width))
    }

    /// Direct, non-bitfield member: its type id and byte offset.
    pub(crate) fn direct_member(&self, cursor: usize, name: &str) -> Option<(u32, u32)> {
        let info = self.u32_at(cursor.checked_add(4)?)?;
        if self.kind(cursor)? != 4 || info >> 31 != 0 {
            return None;
        }
        for index in 0..(info & 0xffff) as usize {
            let member = cursor
                .checked_add(12)?
                .checked_add(index.checked_mul(12)?)?;
            if self.string(self.u32_at(member)?) == Some(name) {
                let bits = self.u32_at(member.checked_add(8)?)?;
                if bits % 8 != 0 {
                    return None;
                }
                return Some((self.u32_at(member.checked_add(4)?)?, bits / 8));
            }
        }
        None
    }

    fn composite_member_offset(
        &self,
        cursor: usize,
        member_name: &str,
        depth: u8,
        width: Option<u32>,
    ) -> Option<u32> {
        if depth == 8 {
            return None;
        }
        let info = read_u32(self.data, cursor.checked_add(4)?, self.endian)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = info & 0xffff;
        if !matches!(kind, 4 | 5) {
            return None;
        }
        let payload = cursor.checked_add(12)?;
        if payload.checked_add(type_extra_len(kind, vlen)?)? > self.types.end {
            return None;
        }
        for index in 0..vlen as usize {
            let member = payload.checked_add(index.checked_mul(12)?)?;
            let name_offset = read_u32(self.data, member, self.endian)?;
            let raw_offset = read_u32(self.data, member.checked_add(8)?, self.endian)?;
            let bit_offset = if info >> 31 == 1 {
                raw_offset & 0x00ff_ffff
            } else {
                raw_offset
            };
            if bit_offset % 8 != 0 || (info >> 31 == 1 && raw_offset >> 24 != 0) {
                continue;
            }
            let byte_offset = bit_offset / 8;
            if self.string(name_offset) == Some(member_name) {
                if let Some(width) = width {
                    let size = read_u32(self.data, cursor.checked_add(8)?, self.endian)?;
                    let type_id = read_u32(self.data, member.checked_add(4)?, self.endian)?;
                    if byte_offset.checked_add(width)? > size || self.type_size(type_id)? != width {
                        return None;
                    }
                }
                return Some(byte_offset);
            }
            if name_offset == 0 {
                let type_id = read_u32(self.data, member.checked_add(4)?, self.endian)?;
                if let Some(nested) = self.resolve_composite(type_id)
                    && let Some(offset) =
                        self.composite_member_offset(nested, member_name, depth + 1, width)
                {
                    let offset = byte_offset.checked_add(offset)?;
                    if let Some(width) = width {
                        let size = read_u32(self.data, cursor.checked_add(8)?, self.endian)?;
                        if offset.checked_add(width)? > size {
                            return None;
                        }
                    }
                    return Some(offset);
                }
            }
        }
        None
    }

    pub(crate) fn type_size(&self, mut type_id: u32) -> Option<u32> {
        let mut elements = 1u32;
        for _ in 0..8 {
            let cursor = self.type_by_id(type_id)?;
            let info = self.u32_at(cursor.checked_add(4)?)?;
            let size = self.u32_at(cursor.checked_add(8)?)?;
            match (info >> 24) & 0x1f {
                1 | 4 | 5 | 6 | 16 | 19 => return size.checked_mul(elements),
                2 => return 8u32.checked_mul(elements),
                3 => {
                    elements = elements.checked_mul(self.u32_at(cursor.checked_add(20)?)?)?;
                    type_id = self.u32_at(cursor.checked_add(12)?)?;
                }
                8..=11 | 18 => type_id = size,
                _ => return None,
            }
        }
        None
    }

    pub(crate) fn resolve_composite(&self, type_id: u32) -> Option<usize> {
        let cursor = self.resolve_modifiers(type_id)?;
        matches!(self.kind(cursor)?, 4 | 5).then_some(cursor)
    }

    /// Follow a bounded typedef/qualifier/type-tag chain to the underlying type.
    pub(crate) fn resolve_modifiers(&self, mut type_id: u32) -> Option<usize> {
        for _ in 0..8 {
            let cursor = self.type_by_id(type_id)?;
            if !matches!(self.kind(cursor)?, 8..=11 | 18) {
                return Some(cursor);
            }
            type_id = read_u32(self.data, cursor.checked_add(8)?, self.endian)?;
        }
        None
    }

    pub(crate) fn type_by_id(&self, type_id: u32) -> Option<usize> {
        if type_id == 0 {
            return None;
        }
        let mut cursor = self.types.start;
        for _ in 1..type_id {
            let info = read_u32(self.data, cursor.checked_add(4)?, self.endian)?;
            cursor = cursor
                .checked_add(12)?
                .checked_add(type_extra_len((info >> 24) & 0x1f, info & 0xffff)?)?;
            if cursor >= self.types.end {
                return None;
            }
        }
        Some(cursor)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Leaf {
    Integer(u32),
    Pointer(&'static str),
    Function,
}

// Kernel BTF can nest the named field in anonymous structs and unions.
fn member(btf: &Btf<'_>, owner: usize, name: &str, depth: u8) -> Option<(u32, u32)> {
    if depth == 8 || !matches!(btf.kind(owner)?, 4 | 5) {
        return None;
    }
    let info = btf.u32_at(owner + 4)?;
    let owner_size = btf.u32_at(owner + 8)?;
    let mut found = None;
    for index in 0..info & 0xffff {
        let at = owner.checked_add(12 + index as usize * 12)?;
        let member_name = btf.string(btf.u32_at(at)?)?;
        let ty = btf.u32_at(at + 4)?;
        let bits = btf.u32_at(at + 8)?;
        if info >> 31 != 0 && bits >> 24 != 0 {
            continue;
        }
        let bits = if info >> 31 != 0 {
            bits & 0xffffff
        } else {
            bits
        };
        if bits % 8 != 0 {
            continue;
        }
        let offset = bits / 8;
        if offset.checked_add(btf.type_size(ty)?)? > owner_size {
            return None;
        }
        let candidate = if member_name == name {
            Some((ty, offset))
        } else if member_name.is_empty() {
            member(btf, btf.resolve_composite(ty)?, name, depth + 1)
                .and_then(|(ty, inner)| Some((ty, offset.checked_add(inner)?)))
        } else {
            None
        };
        if let Some(candidate) = candidate {
            if found.is_some() {
                return None;
            }
            found = Some(candidate);
        }
    }
    found
}

pub(crate) fn field(btf: &Btf<'_>, root: &str, names: &[&str], leaf: Leaf) -> anyhow::Result<u32> {
    let mut owner = btf
        .find_type(4, root)
        .with_context(|| format!("Host BTF struct {root}"))?;
    let mut offset = 0u32;
    let mut terminal = None;
    for (index, name) in names.iter().enumerate() {
        let (ty, part) = member(btf, owner, name, 0)
            .with_context(|| format!("Host BTF {root}.{}", names.join(".")))?;
        offset = offset
            .checked_add(part)
            .context("Host BTF offset overflow")?;
        let cursor = btf.resolve_modifiers(ty).context("Host BTF member type")?;
        if index + 1 == names.len() {
            terminal = Some((ty, cursor));
        } else {
            owner = btf
                .resolve_composite(ty)
                .context("Host BTF non-composite member chain")?;
        }
    }
    let (ty, cursor) = terminal.context("empty Host BTF member chain")?;
    let width = match leaf {
        Leaf::Integer(width) => {
            ensure!(
                btf.kind(cursor) == Some(1) && btf.type_size(ty) == Some(width),
                "Host BTF integer width"
            );
            let encoding = btf
                .u32_at(cursor + 12)
                .context("Host BTF integer encoding")?;
            ensure!(
                encoding & 0x00ff_ffff == width * 8,
                "Host BTF partial integer"
            );
            width
        }
        Leaf::Pointer(target) => {
            ensure!(btf.kind(cursor) == Some(2), "Host BTF pointer required");
            let target = btf
                .find_type(4, target)
                .context("Host BTF pointer target")?;
            let pointee =
                btf.resolve_modifiers(btf.u32_at(cursor + 8).context("Host BTF pointer type")?);
            ensure!(pointee == Some(target), "Host BTF pointer target mismatch");
            8
        }
        Leaf::Function => {
            ensure!(
                btf.kind(cursor) == Some(2),
                "Host BTF function pointer required"
            );
            let pointee = btf
                .resolve_modifiers(
                    btf.u32_at(cursor + 8)
                        .context("Host BTF function pointer type")?,
                )
                .context("Host BTF function pointer target")?;
            ensure!(
                btf.kind(pointee) == Some(13),
                "Host BTF function prototype required"
            );
            8
        }
    };
    ensure!(
        offset.is_multiple_of(width) && offset <= i32::MAX as u32 - width,
        "Host BTF unaligned/out-of-range field"
    );
    Ok(offset)
}

fn read_u32(data: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    Some(endian.u32(data.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}

pub(crate) fn type_extra_len(kind: u32, vlen: u32) -> Option<usize> {
    let (size, repeated): (usize, bool) = match kind {
        0 | 2 | 7..=12 | 16 | 18 => (0, false),
        1 => (4, false),
        3 => (12, false),
        4 | 5 => (12, true),
        6 | 13 => (8, true),
        14 | 17 => (4, false),
        15 | 19 => (12, true),
        _ => return None,
    };
    if repeated {
        size.checked_mul(vlen as usize)
    } else {
        Some(size)
    }
}

#[cfg(test)]
mod tests {
    use super::Btf;

    #[test]
    fn aya_allocation_preflight_accounts_payloads_and_rejects_truncated_records() {
        let fixture = |declared_members: u32, actual_members: u32| {
            let mut types = Vec::new();
            for value in [0u32, (4 << 24) | declared_members, 16] {
                types.extend_from_slice(&value.to_ne_bytes());
            }
            for _ in 0..actual_members {
                for value in [0u32, 0, 0] {
                    types.extend_from_slice(&value.to_ne_bytes());
                }
            }
            let mut data = Vec::from(0xeb9fu16.to_ne_bytes());
            data.extend_from_slice(&[1, 0]);
            for value in [24u32, 0, types.len() as u32, types.len() as u32, 1] {
                data.extend_from_slice(&value.to_ne_bytes());
            }
            data.extend_from_slice(&types);
            data.push(0);
            data
        };
        let one = fixture(1, 1);
        let many = fixture(8, 8);
        let one_bound = Btf::parse(&one)
            .unwrap()
            .aya_parse_allocation_bound()
            .unwrap();
        let many_bound = Btf::parse(&many)
            .unwrap()
            .aya_parse_allocation_bound()
            .unwrap();
        assert!(many_bound > one_bound);
        assert!(many_bound >= 8 * 12 + 2 * core::mem::size_of::<aya_obj::btf::BtfType>());
        assert!(aya::Btf::parse(&one, Default::default()).is_ok());
        assert!(aya::Btf::parse(&many, Default::default()).is_ok());
        let truncated = fixture(9, 8);
        assert!(
            Btf::parse(&truncated)
                .unwrap()
                .aya_parse_allocation_bound()
                .is_none()
        );
        let header: &[u8; super::BTF_HEADER_LEN] = many[..24].try_into().unwrap();
        assert_eq!(super::declared_extent(header), Some(many.len()));
    }

    #[test]
    fn array_members_require_exact_bounded_nonoverflowing_width() {
        let strings = b"\0holder\0padding\0u8\0";
        let make = |count: u32, element: u32| {
            let types: Vec<u8> = [
                1,
                (4 << 24) | 1,
                3,
                8,
                3,
                0,
                16,
                1 << 24,
                1,
                8,
                0,
                3 << 24,
                0,
                element,
                2,
                count,
            ]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
            let mut data = Vec::from([0x9f, 0xeb, 1, 0]);
            for value in [
                24,
                0,
                types.len() as u32,
                types.len() as u32,
                strings.len() as u32,
            ] {
                data.extend_from_slice(&value.to_le_bytes());
            }
            data.extend_from_slice(&types);
            data.extend_from_slice(strings);
            data
        };
        let data = make(3, 2);
        let btf = Btf::parse(&data).unwrap();
        assert_eq!(btf.sized_member_offset("holder", "padding", 3), Some(0));
        assert_eq!(btf.sized_member_offset("holder", "padding", 2), None);
        let outside = make(4, 2);
        assert_eq!(
            Btf::parse(&outside)
                .unwrap()
                .sized_member_offset("holder", "padding", 3),
            None
        );
        let recursive = make(2, 3);
        assert_eq!(Btf::parse(&recursive).unwrap().type_size(3), None);
        let overflow = make(u32::MAX, 1);
        assert_eq!(Btf::parse(&overflow).unwrap().type_size(3), None);
    }

    #[test]
    fn receive_fields_require_complete_sized_non_bitfield_members() {
        let strings = b"\0holder\0priority\0u32\0";
        let types: Vec<u8> = [1u32, (4 << 24) | 1, 8, 8, 2, 32, 17, 1 << 24, 4, 32]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let mut data = Vec::from(0xeb9fu16.to_le_bytes());
        data.extend_from_slice(&[1, 0]);
        for value in [
            24u32,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        data.extend_from_slice(&types);
        data.extend_from_slice(strings);
        let btf = Btf::parse(&data).unwrap();
        assert_eq!(btf.sized_member_offset("holder", "priority", 4), Some(4));
        assert_eq!(btf.sized_member_offset("holder", "priority", 8), None);
        let mut outside = data.clone();
        outside[44..48].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(
            Btf::parse(&outside)
                .unwrap()
                .sized_member_offset("holder", "priority", 4),
            None
        );
        let mut bitfield = data.clone();
        bitfield[28..32].copy_from_slice(&((1u32 << 31) | (4 << 24) | 1).to_le_bytes());
        bitfield[44..48].copy_from_slice(&((1u32 << 24) | 32).to_le_bytes());
        assert_eq!(
            Btf::parse(&bitfield)
                .unwrap()
                .sized_member_offset("holder", "priority", 4),
            None
        );
        data[44..48].copy_from_slice(&33u32.to_le_bytes());
        assert_eq!(
            Btf::parse(&data)
                .unwrap()
                .sized_member_offset("holder", "priority", 4),
            None
        );
    }
}

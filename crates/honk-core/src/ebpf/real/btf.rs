//! Raw BTF reader for the few kernel and object layouts aya does not expose.

use std::ops::Range;

pub(super) const BTF_HEADER_LEN: usize = 24;

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

pub(super) struct Btf<'a> {
    data: &'a [u8],
    types: Range<usize>,
    strings: Range<usize>,
    endian: Endian,
}

impl<'a> Btf<'a> {
    pub(super) fn parse(data: &'a [u8]) -> Option<Self> {
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
    pub(super) fn u32_at(&self, offset: usize) -> Option<u32> {
        if offset.checked_add(4)? > self.types.end {
            return None;
        }
        read_u32(self.data, offset, self.endian)
    }

    pub(super) fn kind(&self, cursor: usize) -> Option<u32> {
        Some((read_u32(self.data, cursor.checked_add(4)?, self.endian)? >> 24) & 0x1f)
    }

    pub(super) fn string(&self, offset: u32) -> Option<&str> {
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

    /// Cursor of the first type of `kind` named `name`.
    pub(super) fn find_type(&self, kind: u32, name: &str) -> Option<usize> {
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

    pub(super) fn member_offset(&self, type_name: &str, member_name: &str) -> Option<u32> {
        self.composite_member_offset(self.find_type(4, type_name)?, member_name, 0, None)
    }

    /// Offset of a complete, non-bitfield member of exactly `width` bytes.
    pub(super) fn sized_member_offset(
        &self,
        type_name: &str,
        member_name: &str,
        width: u32,
    ) -> Option<u32> {
        self.composite_member_offset(self.find_type(4, type_name)?, member_name, 0, Some(width))
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

    fn type_size(&self, mut type_id: u32) -> Option<u32> {
        for _ in 0..8 {
            let cursor = self.type_by_id(type_id)?;
            let info = read_u32(self.data, cursor.checked_add(4)?, self.endian)?;
            let size = read_u32(self.data, cursor.checked_add(8)?, self.endian)?;
            match (info >> 24) & 0x1f {
                1 | 4 | 5 | 6 | 16 | 19 => return Some(size),
                8..=11 | 18 => type_id = size,
                _ => return None,
            }
        }
        None
    }

    pub(super) fn resolve_composite(&self, type_id: u32) -> Option<usize> {
        let cursor = self.resolve_modifiers(type_id)?;
        matches!(self.kind(cursor)?, 4 | 5).then_some(cursor)
    }

    /// Follow a bounded typedef/qualifier/type-tag chain to the underlying type.
    pub(super) fn resolve_modifiers(&self, mut type_id: u32) -> Option<usize> {
        for _ in 0..8 {
            let cursor = self.type_by_id(type_id)?;
            if !matches!(self.kind(cursor)?, 8..=11 | 18) {
                return Some(cursor);
            }
            type_id = read_u32(self.data, cursor.checked_add(8)?, self.endian)?;
        }
        None
    }

    pub(super) fn type_by_id(&self, type_id: u32) -> Option<usize> {
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

fn read_u32(data: &[u8], offset: usize, endian: Endian) -> Option<u32> {
    Some(endian.u32(data.get(offset..offset.checked_add(4)?)?.try_into().ok()?))
}

fn type_extra_len(kind: u32, vlen: u32) -> Option<usize> {
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

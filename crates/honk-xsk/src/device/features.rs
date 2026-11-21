use super::*;

const MAX_FEATURES: usize = 4096;
pub(super) const NAMED_FEATURES: [&[u8]; 10] = [
    b"rx-vlan-hw-parse",
    b"rx-vlan-stag-hw-parse",
    b"rx-gro",
    b"rx-lro",
    b"tx-generic-segmentation",
    b"tx-tcp-segmentation",
    b"tx-tcp6-segmentation",
    b"rx-checksum",
    b"tx-checksum-ip-generic",
    b"rx-gro-hw",
];
const CONTEXT_HEADER: usize = 8 + 160 + 2 + 4 + NAMED_FEATURES.len() * 4;

/// Select Auto per device; explicit requests remain strict.
pub fn select_xsk_mode(
    info: &DeviceInfo,
    requested: Option<BindMode>,
    config: PortConfig,
    metadata_len: usize,
) -> io::Result<BindMode> {
    if info.xdp_features & 3 != 3 {
        return Err(unsupported("native XDP basic/redirect support unavailable"));
    }
    match requested {
        Some(mode) => {
            info.validate_port_config(mode, config, metadata_len)?;
            Ok(mode)
        }
        None => {
            info.validate_port_config(BindMode::Copy, config, metadata_len)?;
            if info
                .validate_port_config(BindMode::ZeroCopy, config, metadata_len)
                .is_ok()
            {
                Ok(BindMode::ZeroCopy)
            } else {
                Ok(BindMode::Copy)
            }
        }
    }
}

/// Restores only RX VLAN feature bits changed by this process.
pub struct VlanOffload {
    fd: OwnedFd,
    name: [libc::c_char; libc::IFNAMSIZ],
    ifindex: u32,
    count: usize,
    words: Vec<u32>,
    changed: [Option<usize>; 2],
    restore_allowed: bool,
    _reservation: MemoryReservation,
}

/// Call after read-only admission and before constructing the FeatureQuery baseline.
pub fn prepare_vlan_offload(
    info: &DeviceInfo,
    budget: &Arc<MemoryBudget>,
) -> io::Result<VlanOffload> {
    let bookkeeping = budget
        .reserve(size_of::<VlanOffload>())
        .ok_or_else(|| io::Error::other("VLAN feature owner memory budget exhausted"))?;
    let name = interface_name(&info.name)?;
    // SAFETY: interface_name returns a terminated name; no resource is changed here.
    if unsafe { libc::if_nametoindex(name.as_ptr()) } != info.ifindex {
        return Err(unsupported(
            "device identity changed before VLAN preparation",
        ));
    }
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let count = feature_count(&fd, &name)?;
    let retained = (4 + count.div_ceil(32) * 6) * size_of::<u32>();
    let reservation = budget
        .reserve(size_of::<VlanOffload>() + retained)
        .ok_or_else(|| io::Error::other("VLAN feature owner memory budget exhausted"))?;
    drop(bookkeeping);
    let _scratch = budget
        .reserve(
            (3 + count * 8) * 4
                + 2 * MAX_UPPER_INTERFACES * (size_of::<String>() + libc::IFNAMSIZ + 8)
                + 4096,
        )
        .ok_or_else(|| io::Error::other("VLAN feature scratch memory budget exhausted"))?;
    let mut names = vec![0; 3 + count * 8];
    read_feature_names(&fd, &name, count, &mut names)?;
    let mut words = vec![0; 2 + count.div_ceil(32) * 4];
    read_features(&fd, &name, count, &mut words)?;
    let mut indices = [None; 2];
    for index in 0..count {
        let bytes = string_bytes(&names[3 + index * 8..3 + (index + 1) * 8]);
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(32);
        for (slot, feature) in NAMED_FEATURES[..2].iter().enumerate() {
            if &bytes[..end] == *feature && indices[slot].replace(index).is_some() {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
    }
    if !info.vlan_metadata && indices.iter().any(Option::is_none) {
        return Err(unsupported("RX VLAN stripping facts unavailable"));
    }
    let has_vlan_upper = vlan_upper(&info.name, &info.upper_ifindices)?;
    let mut guard = VlanOffload {
        fd,
        name,
        ifindex: info.ifindex,
        count,
        words,
        changed: [None; 2],
        restore_allowed: true,
        _reservation: reservation,
    };
    for (slot, index) in indices.into_iter().enumerate() {
        let Some(index) = index else { continue };
        let block = index / 32;
        let bit = 1u32 << (index % 32);
        if guard.words[4 + block * 4] & bit == 0 {
            continue;
        }
        if has_vlan_upper {
            if !info.vlan_metadata {
                return Err(unsupported(
                    "VLAN upper requires authoritative RX VLAN metadata",
                ));
            }
            continue;
        }
        if guard.words[2 + block * 4] & bit == 0 || guard.words[5 + block * 4] & bit != 0 {
            return Err(unsupported("active RX VLAN stripping cannot be disabled"));
        }
        guard.changed[slot] = Some(index);
    }
    guard.set_changed(false)?;
    Ok(guard)
}

fn vlan_upper(name: &str, expected: &[u32]) -> io::Result<bool> {
    let root = Path::new("/sys/class/net").join(name);
    let root_index = fs::read_to_string(root.join("ifindex"))?
        .trim()
        .parse::<u32>()
        .map_err(|_| unsupported("invalid device identity"))?;
    if upper_ifindices(&root, root_index)? != expected {
        return Err(unsupported(
            "upper interfaces changed before VLAN admission",
        ));
    }
    let mut pending = Vec::with_capacity(MAX_UPPER_INTERFACES);
    pending.push(name.to_owned());
    let mut seen = Vec::with_capacity(MAX_UPPER_INTERFACES);
    seen.push(root_index);
    let mut vlan = false;
    while let Some(name) = pending.pop() {
        for entry in fs::read_dir(Path::new("/sys/class/net").join(name))? {
            let entry = entry?;
            let entry_name = entry.file_name();
            let Some(name) = entry_name.to_str().and_then(|s| s.strip_prefix("upper_")) else {
                continue;
            };
            interface_name(name)?;
            let upper = entry.path();
            let index = fs::read_to_string(upper.join("ifindex"))?
                .trim()
                .parse::<u32>()
                .map_err(|_| unsupported("invalid upper interface identity"))?;
            if seen.contains(&index) {
                continue;
            }
            if seen.len() == MAX_UPPER_INTERFACES {
                return Err(unsupported("VLAN upper graph exceeds bounded capacity"));
            }
            seen.push(index);
            vlan |= fs::read_to_string(upper.join("uevent"))?
                .lines()
                .any(|line| line == "DEVTYPE=vlan");
            pending.push(name.to_owned());
        }
    }
    Ok(vlan)
}

impl VlanOffload {
    fn set_changed(&mut self, enabled: bool) -> io::Result<()> {
        change_vlan_features(
            self.count,
            &self.changed,
            enabled,
            &mut self.words,
            |words| query_named(&self.fd, &self.name, words),
        )
    }

    /// Disable restoration after identity change or lost topology authority.
    pub fn abandon(&mut self) {
        self.restore_allowed = false;
    }

    pub fn restore(&mut self) -> io::Result<()> {
        if !self.restore_allowed || self.changed.iter().all(Option::is_none) {
            return Ok(());
        }
        self.restore_allowed = false;
        // SAFETY: interface_name produces a NUL-terminated name.
        if unsafe { libc::if_nametoindex(self.name.as_ptr()) } != self.ifindex {
            return Err(unsupported(
                "device identity changed before VLAN restoration",
            ));
        }
        restore_vlan_features(self.count, &mut self.changed, &mut self.words, |words| {
            query_named(&self.fd, &self.name, words)
        })?;
        Ok(())
    }
}

impl Drop for VlanOffload {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("failed to restore RX VLAN features: {error}");
        }
    }
}

fn query_vlan_features(
    count: usize,
    words: &mut [u32],
    query: &mut impl FnMut(&mut [u32]) -> io::Result<()>,
) -> io::Result<()> {
    words.fill(0);
    words[0] = 0x3a;
    words[1] = count.div_ceil(32) as u32;
    query(words)?;
    validate_features(count, words)
}

fn change_vlan_features(
    count: usize,
    changed: &[Option<usize>; 2],
    enabled: bool,
    words: &mut [u32],
    mut query: impl FnMut(&mut [u32]) -> io::Result<()>,
) -> io::Result<()> {
    let blocks = count.div_ceil(32);
    let mut request = vec![0u32; 2 + blocks * 2];
    request[0] = 0x3b;
    request[1] = blocks as u32;
    for &index in changed.iter().flatten() {
        let bit = 1u32 << (index % 32);
        request[2 + index / 32 * 2] |= bit;
        if enabled {
            request[3 + index / 32 * 2] |= bit;
        }
    }
    if changed.iter().any(Option::is_some) {
        query(&mut request)?;
    }
    query_vlan_features(count, words, &mut query)?;
    if changed
        .iter()
        .flatten()
        .any(|&index| (words[4 + index / 32 * 4] & (1 << (index % 32)) != 0) != enabled)
    {
        return Err(unsupported("RX VLAN feature change readback failed"));
    }
    Ok(())
}

fn restore_vlan_features(
    count: usize,
    changed: &mut [Option<usize>; 2],
    words: &mut [u32],
    mut query: impl FnMut(&mut [u32]) -> io::Result<()>,
) -> io::Result<()> {
    query_vlan_features(count, words, &mut query)?;
    for slot in changed.iter_mut() {
        if let Some(index) = *slot
            && words[4 + index / 32 * 4] & (1 << (index % 32)) != 0
        {
            *slot = None;
        }
    }
    change_vlan_features(count, changed, true, words, query)?;
    *changed = [None; 2];
    Ok(())
}

/// Cold-funded ethtool state. Runtime checks never rediscover a device or allocate.
pub struct FeatureQuery {
    fd: OwnedFd,
    name: [libc::c_char; libc::IFNAMSIZ],
    count: usize,
    words: Vec<u32>,
    baseline: Vec<u32>,
    context: Vec<u8>,
    _reservation: MemoryReservation,
}

impl FeatureQuery {
    pub fn new(info: &DeviceInfo, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let name = interface_name(&info.name)?;
        let bookkeeping = budget
            .reserve(size_of::<Self>())
            .ok_or_else(|| io::Error::other("feature query memory budget exhausted"))?;
        let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
        let count = feature_count(&fd, &name)?;
        let blocks = count.div_ceil(32);
        let context_len = CONTEXT_HEADER + count * 32 + blocks * 4;
        // Fund both retained storage and cold dictionary scratch before allocating either.
        let scratch = budget
            .reserve((3 + count * 8) * 4)
            .ok_or_else(|| io::Error::other("feature dictionary memory budget exhausted"))?;
        let reservation = budget
            .reserve(size_of::<Self>() + (2 + blocks * 5) * 4 + context_len)
            .ok_or_else(|| io::Error::other("feature query memory budget exhausted"))?;
        drop(bookkeeping);
        let mut driver = [0u32; 49];
        driver[0] = 3;
        query_named(&fd, &name, &mut driver)?;
        let mut names = vec![0; 3 + count * 8];
        read_feature_names(&fd, &name, count, &mut names)?;
        let mut result = Self {
            fd,
            name,
            count,
            words: vec![0; 2 + blocks * 4],
            baseline: vec![0; blocks],
            context: vec![0; context_len],
            _reservation: reservation,
        };
        encode_feature_context(&driver, count, &names, &mut result.context)?;
        read_features(&result.fd, &result.name, count, &mut result.words)?;
        for (block, active) in result.baseline.iter_mut().enumerate() {
            *active = result.words[4 + block * 4];
        }
        result.observe()?;
        drop(names);
        drop(scratch);
        Ok(result)
    }

    /// Version 1: magic, five driver strings, firmware/bus applicability tags,
    /// LE feature count, named indices (u32::MAX = not advertised), dictionary,
    /// and latest observed LE active words. No ephemeral ifindex is encoded.
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    /// True only when the valid current active bits equal the cold admission baseline.
    /// False retains the newly observed bits without rebinding that baseline. Errors
    /// preserve the last valid context and must disable optional polling at the caller.
    pub fn check(&mut self) -> io::Result<bool> {
        read_features(&self.fd, &self.name, self.count, &mut self.words)?;
        self.observe()
    }

    fn observe(&mut self) -> io::Result<bool> {
        validate_features(self.count, &self.words)?;
        let offset = CONTEXT_HEADER + self.count * 32;
        let mut unchanged = true;
        for (block, &baseline) in self.baseline.iter().enumerate() {
            let active = self.words[4 + block * 4];
            unchanged &= active == baseline;
            self.context[offset + block * 4..offset + (block + 1) * 4]
                .copy_from_slice(&active.to_le_bytes());
        }
        Ok(unchanged)
    }
}

pub(super) fn feature_count(
    fd: &OwnedFd,
    name: &[libc::c_char; libc::IFNAMSIZ],
) -> io::Result<usize> {
    let mask = (1u64 << 4).to_ne_bytes();
    let low = u32::from_ne_bytes(mask[..4].try_into().unwrap());
    let high = u32::from_ne_bytes(mask[4..].try_into().unwrap());
    let mut info = [0x37, 0, low, high, 0, 0];
    query_named(fd, name, &mut info)?;
    if info[0] != 0x37
        || info[2] != low
        || info[3] != high
        || !(1..=MAX_FEATURES).contains(&(info[4] as usize))
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(info[4] as usize)
}

pub(super) fn read_feature_names(
    fd: &OwnedFd,
    name: &[libc::c_char; libc::IFNAMSIZ],
    count: usize,
    names: &mut [u32],
) -> io::Result<()> {
    if !(1..=MAX_FEATURES).contains(&count) || names.len() != 3 + count * 8 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    names.fill(0);
    names[..3].copy_from_slice(&[0x1b, 4, count as u32]);
    query_named(fd, name, names)?;
    if names[..3] != [0x1b, 4, count as u32] {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

pub(super) fn read_features(
    fd: &OwnedFd,
    name: &[libc::c_char; libc::IFNAMSIZ],
    count: usize,
    words: &mut [u32],
) -> io::Result<()> {
    if !(1..=MAX_FEATURES).contains(&count) || words.len() != 2 + count.div_ceil(32) * 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    words.fill(0);
    words[0] = 0x3a;
    words[1] = count.div_ceil(32) as u32;
    query_named(fd, name, words)?;
    validate_features(count, words)
}

pub(super) fn validate_features(count: usize, words: &[u32]) -> io::Result<()> {
    if !(1..=MAX_FEATURES).contains(&count)
        || words.len() != 2 + count.div_ceil(32) * 4
        || words[0] != 0x3a
        || words[1] as usize != count.div_ceil(32)
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    if !count.is_multiple_of(32) {
        let outside = !((1u32 << (count % 32)) - 1);
        if words[words.len() - 4..]
            .iter()
            .any(|word| word & outside != 0)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(())
}

pub(super) fn string_bytes(words: &[u32]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_ne_bytes());
    }
    if let Some(end) = bytes.iter().position(|&byte| byte == 0) {
        bytes[end..].fill(0);
    }
    bytes
}

pub(super) fn encode_feature_context(
    driver: &[u32; 49],
    count: usize,
    names: &[u32],
    out: &mut [u8],
) -> io::Result<()> {
    if driver[0] != 3
        || !(1..=MAX_FEATURES).contains(&count)
        || names.len() != 3 + count * 8
        || names[..3] != [0x1b, 4, count as u32]
        || out.len() != CONTEXT_HEADER + count * 32 + count.div_ceil(32) * 4
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    out[..8].copy_from_slice(b"HXFEAT\0\x01");
    for index in 0..5 {
        out[8 + index * 32..8 + (index + 1) * 32]
            .copy_from_slice(&string_bytes(&driver[1 + index * 8..1 + (index + 1) * 8]));
    }
    let veth = &out[8..13] == b"veth\0";
    if out[8] == 0 || out[40] == 0 {
        return Err(io::ErrorKind::Unsupported.into());
    }
    // 1 = applicable/present, 2 = verified NotApplicable; unavailable is an error.
    for (tag, field) in [(168, 72), (169, 104)] {
        out[tag] = if veth {
            2
        } else if out[field] != 0 {
            1
        } else {
            return Err(io::ErrorKind::Unsupported.into());
        };
    }
    out[170..174].copy_from_slice(&(count as u32).to_le_bytes());
    out[174..CONTEXT_HEADER].fill(0xff);
    for index in 0..count {
        let bytes = string_bytes(&names[3 + index * 8..3 + (index + 1) * 8]);
        let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(32);
        out[CONTEXT_HEADER + index * 32..CONTEXT_HEADER + (index + 1) * 32].copy_from_slice(&bytes);
        for (named, wanted) in NAMED_FEATURES.iter().enumerate() {
            if &bytes[..end] == *wanted {
                let slot = &mut out[174 + named * 4..178 + named * 4];
                if slot != [0xff; 4] {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                slot.copy_from_slice(&(index as u32).to_le_bytes());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver_fixture(veth: bool) -> [u32; 49] {
        let mut driver = [0; 49];
        driver[0] = 3;
        for (field, text) in [
            (
                0,
                if veth {
                    b"veth".as_slice()
                } else {
                    b"ixgbe".as_slice()
                },
            ),
            (1, b"6.12".as_slice()),
            (
                2,
                if veth {
                    b"".as_slice()
                } else {
                    b"firmware-1".as_slice()
                },
            ),
            (
                3,
                if veth {
                    b"".as_slice()
                } else {
                    b"0000:01:00.0".as_slice()
                },
            ),
        ] {
            let mut bytes = [0; 32];
            bytes[..text.len()].copy_from_slice(text);
            for (word, chunk) in driver[1 + field * 8..1 + (field + 1) * 8]
                .iter_mut()
                .zip(bytes.as_chunks::<4>().0)
            {
                *word = u32::from_ne_bytes(*chunk);
            }
        }
        driver
    }

    fn dictionary_fixture(count: usize) -> Vec<u32> {
        let mut names = vec![0; 3 + count * 8];
        names[..3].copy_from_slice(&[0x1b, 4, count as u32]);
        for (index, name) in NAMED_FEATURES.iter().take(count).enumerate() {
            let mut bytes = [0; 32];
            bytes[..name.len()].copy_from_slice(name);
            for (word, chunk) in names[3 + index * 8..3 + (index + 1) * 8]
                .iter_mut()
                .zip(bytes.as_chunks::<4>().0)
            {
                *word = u32::from_ne_bytes(*chunk);
            }
        }
        names
    }

    #[test]
    fn feature_context_distinguishes_not_advertised_inapplicable_and_unavailable() {
        let names = dictionary_fixture(2);
        let mut out = vec![0; CONTEXT_HEADER + 64 + 4];
        encode_feature_context(&driver_fixture(true), 2, &names, &mut out).unwrap();
        assert_eq!(&out[..8], b"HXFEAT\0\x01");
        assert_eq!(&out[168..170], &[2, 2]);
        assert_eq!(&out[174..178], &0u32.to_le_bytes());
        assert_eq!(&out[178..182], &1u32.to_le_bytes());
        assert_eq!(&out[182..186], &u32::MAX.to_le_bytes());
        let veth = out.clone();
        let mut physical = driver_fixture(false);
        encode_feature_context(&physical, 2, &names, &mut out).unwrap();
        assert_eq!(&out[168..170], &[1, 1]);
        assert_ne!(out, veth);
        physical[17..25].fill(0);
        assert_eq!(
            encode_feature_context(&physical, 2, &names, &mut out)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        physical = driver_fixture(false);
        physical[25..33].fill(0);
        assert!(encode_feature_context(&physical, 2, &names, &mut out).is_err());
        let mut duplicate = names.clone();
        duplicate[11..19].copy_from_slice(&names[3..11]);
        assert!(encode_feature_context(&driver_fixture(true), 2, &duplicate, &mut out).is_err());
    }

    #[test]
    fn fixed_feature_shape_and_observed_changes_preserve_admission_baseline() {
        for count in [1usize, 32, 33, MAX_FEATURES] {
            let blocks = count.div_ceil(32);
            let mut words = vec![0; 2 + blocks * 4];
            words[..2].copy_from_slice(&[0x3a, blocks as u32]);
            validate_features(count, &words).unwrap();
            words[1] += 1;
            assert!(validate_features(count, &words).is_err());
            words[1] -= 1;
            assert!(validate_features(count, &words[..words.len() - 1]).is_err());
            if count % 32 != 0 {
                words[4 + (blocks - 1) * 4] = 1 << (count % 32);
                assert!(validate_features(count, &words).is_err());
            }
        }
        assert!(validate_features(0, &[]).is_err());
        assert!(validate_features(MAX_FEATURES + 1, &[]).is_err());
        let budget = MemoryBudget::new(1 << 20);
        let mut query = FeatureQuery {
            fd: fs::File::open("/dev/null").unwrap().into(),
            name: interface_name("fixture0").unwrap(),
            count: 2,
            words: vec![0x3a, 1, 3, 0, 1, 0],
            baseline: vec![1],
            context: vec![0; CONTEXT_HEADER + 64 + 4],
            _reservation: budget.reserve(4096).unwrap(),
        };
        encode_feature_context(
            &driver_fixture(true),
            2,
            &dictionary_fixture(2),
            &mut query.context,
        )
        .unwrap();
        assert!(query.observe().unwrap());
        let admitted = query.context().to_vec();
        query.words[4] = 2;
        assert!(!query.observe().unwrap());
        assert!(!query.observe().unwrap());
        assert_eq!(query.baseline, [1]);
        assert_eq!(&query.context()[CONTEXT_HEADER + 64..], &2u32.to_le_bytes());
        assert_ne!(query.context(), admitted);
        let changed = query.context().to_vec();
        query.words[1] = 2;
        assert!(query.observe().is_err());
        assert_eq!(query.context(), changed);
        assert!(query.check().is_err());
        assert_eq!(query.context(), changed);
        query.words.copy_from_slice(&[0x3a, 1, 3, 0, 1, 0]);
        assert!(query.observe().unwrap());
        assert_eq!(query.context(), admitted);
        drop(query);
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(test)]
mod gateway_tests {
    use super::*;

    fn device() -> DeviceInfo {
        DeviceInfo {
            name: "fixture0".into(),
            ifindex: 1,
            upper_ifindices: vec![],
            queues: vec![0],
            mtu: 9000,
            mac: [2; 6],
            xdp_features: 3 | 8 | 32,
            zerocopy_max_segments: 8,
            vlan_metadata: false,
            direct_relay_physical: true,
        }
    }

    #[test]
    fn auto_selects_copy_only_for_insufficient_zerocopy_capability() {
        let mut info = device();
        let config = PortConfig {
            rx_frames: 256,
            control_frames: 32,
            bulk_frames: 224,
            ring_size: 256,
        };
        assert_eq!(
            select_xsk_mode(&info, None, config, 0).unwrap(),
            BindMode::ZeroCopy
        );
        info.zerocopy_max_segments = 1;
        assert_eq!(
            select_xsk_mode(&info, None, config, 0).unwrap(),
            BindMode::Copy
        );
        assert!(select_xsk_mode(&info, Some(BindMode::ZeroCopy), config, 0).is_err());
        info.xdp_features &= !8;
        assert_eq!(
            select_xsk_mode(&info, None, config, 0).unwrap(),
            BindMode::Copy
        );
        assert_eq!(
            select_xsk_mode(&info, Some(BindMode::Copy), config, 0).unwrap(),
            BindMode::Copy
        );
        info.xdp_features &= !32;
        assert!(select_xsk_mode(&info, None, config, 0).is_err());
        info.mtu = 1500;
        assert_eq!(
            select_xsk_mode(&info, None, config, 0).unwrap(),
            BindMode::Copy
        );
        info.xdp_features &= !1;
        assert!(select_xsk_mode(&info, None, config, 0).is_err());
    }

    #[test]
    fn vlan_disable_and_restore_touch_only_owned_bits_and_verify_readback() {
        let mut active = 0b111u32;
        let mut writes = Vec::new();
        let mut words = [0u32; 6];
        let mut changed = [Some(0), Some(1)];
        let mut query = |request: &mut [u32]| -> io::Result<()> {
            match request[0] {
                0x3b => {
                    writes.push((request[2], request[3]));
                    active = (active & !request[2]) | (request[3] & request[2]);
                }
                0x3a => {
                    request[2] = 7;
                    request[4] = active;
                }
                _ => panic!("unexpected ethtool command"),
            }
            Ok(())
        };
        change_vlan_features(3, &changed, false, &mut words, &mut query).unwrap();
        assert_eq!(words[4], 0b100);
        restore_vlan_features(3, &mut changed, &mut words, &mut query).unwrap();
        assert_eq!(words[4], 0b111);
        assert_eq!(changed, [None; 2]);
        assert_eq!(writes, [(3, 0), (3, 3)]);

        let mut changed = [Some(0), Some(1)];
        let mut writes = Vec::new();
        // An external writer already enabled bit 0; restoration must not write it.
        let mut active = 0b101;
        restore_vlan_features(3, &mut changed, &mut words, |request| {
            if request[0] == 0x3b {
                writes.push((request[2], request[3]));
                active |= request[3];
            } else {
                request[2] = 7;
                request[4] = active;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(writes, [(2, 2)]);
        assert_eq!(words[4], 0b111);

        assert!(
            change_vlan_features(3, &[Some(0), Some(1)], false, &mut words, |request| {
                if request[0] == 0x3a {
                    request[2] = 7;
                    request[4] = 7;
                }
                Ok(())
            })
            .is_err()
        );
    }
}

#[cfg(test)]
mod kernel_vlan_tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::os::unix::fs::MetadataExt;
    use std::process::{Child, Command, Stdio};

    struct ChildOwner(Child);
    impl Drop for ChildOwner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "requires disposable virtme guest private netns and HONK_XDP_VLAN_TEST_DEVICE with both writable RX VLAN bits enabled"]
    fn kernel_vlan_no_upper_normal_failure_and_sigkill_boundaries() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert!(
            fs::read_to_string("/proc/cmdline")
                .unwrap()
                .contains("virtme.")
        );
        assert_ne!(
            fs::metadata("/proc/self/ns/net").unwrap().ino(),
            fs::metadata("/proc/1/ns/net").unwrap().ino()
        );
        let name = std::env::var("HONK_XDP_VLAN_TEST_DEVICE")
            .expect("requires a VLAN-offload capable disposable fixture");
        let info = DeviceInfo::discover(&name).unwrap();
        assert!(!vlan_upper(&name, &info.upper_ifindices).unwrap());
        let budget = MemoryBudget::new(4 << 20);
        if std::env::var_os("HONK_TEST_VLAN_KILL_CHILD").is_some() {
            let owner = prepare_vlan_offload(&info, &budget).unwrap();
            assert!(owner.changed.iter().all(Option::is_some));
            println!("VLAN_OFFLOAD_DISABLED");
            std::io::stdout().flush().unwrap();
            loop {
                std::thread::park();
            }
        }
        let mut owner = prepare_vlan_offload(&info, &budget).unwrap();
        let changed = owner.changed;
        assert!(changed.iter().all(Option::is_some));
        let mut baseline = FeatureQuery::new(&info, &budget).unwrap();
        assert!(baseline.check().unwrap());
        owner.restore().unwrap();
        assert!(!baseline.check().unwrap());
        drop(baseline);
        let failed = (|| -> io::Result<()> {
            let _owner = prepare_vlan_offload(&info, &budget)?;
            Err(io::Error::other("injected subsequent startup failure"))
        })();
        assert!(failed.is_err());
        let mut after_failure = prepare_vlan_offload(&info, &budget).unwrap();
        assert_eq!(after_failure.changed, changed);
        after_failure.restore().unwrap();
        drop(after_failure);
        // The parent owns cleanup of this test's deliberately killed child.
        owner.changed = changed;
        owner.restore_allowed = true;
        let mut child = ChildOwner(Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "device::features::kernel_vlan_tests::kernel_vlan_no_upper_normal_failure_and_sigkill_boundaries", "--ignored", "--nocapture"])
            .env("HONK_TEST_VLAN_KILL_CHILD", "1").stdout(Stdio::piped()).spawn().unwrap());
        let mut output = std::io::BufReader::new(child.0.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert_ne!(
                output.read_line(&mut line).unwrap(),
                0,
                "child exited before disabling VLAN offload"
            );
            if line.contains("VLAN_OFFLOAD_DISABLED") {
                break;
            }
        }
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        read_features(&owner.fd, &owner.name, owner.count, &mut owner.words).unwrap();
        for index in changed.into_iter().flatten() {
            assert_eq!(owner.words[4 + index / 32 * 4] & (1 << (index % 32)), 0);
        }
        owner.restore().unwrap();
        drop(owner);
        assert_eq!(budget.used(), 0);
    }
}

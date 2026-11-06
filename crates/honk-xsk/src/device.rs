//! Fail-closed Ethernet root discovery; upper interfaces require canonical FIB admission.

use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use crate::port::{BindMode, FRAME_SIZE, MAX_SEGMENTS, METADATA_SIZE, Port, PortConfig};
use honk_netstack::MemoryBudget;

const MAX_UPPER_INTERFACES: usize = 4096;
// Attaching our guard may publish these NDO-XMIT flags; AF_XDP TX does not use them.
const NDO_XMIT_FEATURES: u64 = 4 | 64;

#[derive(Debug)]
pub struct DeviceInfo {
    pub name: String,
    pub ifindex: u32,
    /// Direct sysfs uppers, not proof that any descendant is safe to capture.
    pub upper_ifindices: Vec<u32>,
    pub queues: Vec<u32>,
    pub mtu: u32,
    pub mac: [u8; 6],
    pub xdp_features: u64,
    pub zerocopy_max_segments: u32,
    pub vlan_metadata: bool,
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

impl DeviceInfo {
    pub fn discover(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() >= libc::IFNAMSIZ
            || name.contains('/')
            || name.as_bytes().contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid interface name",
            ));
        }
        let path = Path::new("/sys/class/net").join(name);
        let number = |file: &str| -> io::Result<u32> {
            fs::read_to_string(path.join(file))?
                .trim()
                .parse()
                .map_err(|_| unsupported(format!("invalid {file}")))
        };
        let ifindex = number("ifindex")?;
        let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
        let mut driver = [0u32; 49];
        driver[0] = 3; // ETHTOOL_GDRVINFO
        query(&fd, name, &mut driver)?;
        let veth = driver[1].to_ne_bytes() == *b"veth" && driver[2].to_ne_bytes()[0] == 0;
        let physical = path.join("device").try_exists()? && number("iflink")? == ifindex;
        if number("type")? != 1 || !(physical || veth) {
            return Err(unsupported(
                "only standalone physical Ethernet or proven veth topology is admitted",
            ));
        }
        let upper_ifindices = upper_ifindices(&path, ifindex)?;
        let mtu = number("mtu")?;
        if !(68..=65535).contains(&mtu) {
            return Err(unsupported("unsupported device MTU"));
        }
        let queues = bidirectional_queues(&path.join("queues"))?;
        let address = fs::read_to_string(path.join("address"))?;
        let mut mac = [0; 6];
        let octets: Vec<_> = address.trim().split(':').collect();
        if octets.len() != 6 {
            return Err(unsupported("invalid Ethernet address"));
        }
        for (out, text) in mac.iter_mut().zip(octets) {
            *out = u8::from_str_radix(text, 16)
                .map_err(|_| unsupported("invalid Ethernet address"))?;
        }
        let (xdp_features, zerocopy_max_segments, rx_metadata) = xdp_capabilities(ifindex)?;
        let vlan_metadata = rx_metadata & 4 != 0;
        if veth && !vlan_metadata {
            return Err(unsupported("veth requires authoritative RX VLAN metadata"));
        }
        if !vlan_metadata {
            reject_vlan_stripping(name)?;
        }
        if xdp_features & 3 != 3 {
            return Err(unsupported("native XDP basic/redirect support unavailable"));
        }
        let required = (mtu as usize + 22).div_ceil(FRAME_SIZE - 256 - METADATA_SIZE);
        if required > 1 && xdp_features & 32 == 0 {
            return Err(unsupported(
                "MTU requires advertised native XDP RX scatter/gather",
            ));
        }
        Ok(Self {
            name: name.into(),
            ifindex,
            upper_ifindices,
            queues,
            mtu,
            mac,
            xdp_features,
            zerocopy_max_segments,
            vlan_metadata,
        })
    }

    /// Check commitments without allocating UMEM; return the required RX chain length.
    pub fn validate_port_config(&self, mode: BindMode, config: PortConfig) -> io::Result<usize> {
        config.validate()?;
        let required = (self.mtu as usize + 22).div_ceil(FRAME_SIZE - 256 - METADATA_SIZE);
        if required > MAX_SEGMENTS
            || config.rx_frames < required
            || config.control_frames < required
            || config.bulk_frames < required
        {
            return Err(unsupported(
                "whole-packet frame commitments cannot cover device MTU",
            ));
        }
        if mode == BindMode::ZeroCopy
            && (self.xdp_features & 8 == 0
                || (required > 1 && self.zerocopy_max_segments < required as u32))
        {
            return Err(unsupported("zero-copy segment capability unavailable"));
        }
        Ok(required)
    }

    /// Recheck immutable admission facts, including the wire-only stripping-off proof.
    pub fn validate_current(&self) -> io::Result<()> {
        let fresh = Self::discover(&self.name)?;
        if fresh.ifindex != self.ifindex
            || fresh.upper_ifindices != self.upper_ifindices
            || fresh.queues != self.queues
            || fresh.mtu != self.mtu
            || fresh.mac != self.mac
            || fresh.xdp_features & !NDO_XMIT_FEATURES != self.xdp_features & !NDO_XMIT_FEATURES
            || fresh.zerocopy_max_segments != self.zerocopy_max_segments
            || fresh.vlan_metadata != self.vlan_metadata
        {
            return Err(unsupported("device facts changed before capture admission"));
        }
        Ok(())
    }

    pub fn open_ports<L>(
        &self,
        mode: BindMode,
        config: PortConfig,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Vec<Port<L>>> {
        self.validate_current()?;
        let required = self.validate_port_config(mode, config)?;
        self.queues
            .iter()
            .map(|&queue| {
                Port::open_device(
                    self.ifindex,
                    queue,
                    mode,
                    config,
                    self.mtu,
                    required > 1,
                    budget,
                )
            })
            .collect()
    }
}

fn bidirectional_queues(path: &Path) -> io::Result<Vec<u32>> {
    let mut queues = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        if let Some(queue) = entry.file_name().to_string_lossy().strip_prefix("rx-") {
            let queue = queue
                .parse::<u32>()
                .map_err(|_| unsupported("invalid RX queue identity"))?;
            if queue >= 256 || queues.len() == 256 {
                return Err(unsupported("RX queue count must be 1..=256"));
            }
            require_queue_pair(path, queue)?;
            queues.push(queue);
        }
    }
    queues.sort_unstable();
    if queues.is_empty() || queues.iter().copied().ne(0..queues.len() as u32) {
        return Err(unsupported("RX queues must be nonempty and contiguous"));
    }
    Ok(queues)
}

fn require_queue_pair(path: &Path, queue: u32) -> io::Result<()> {
    for direction in ["rx", "tx"] {
        if !path.join(format!("{direction}-{queue}")).try_exists()? {
            return Err(unsupported("AF_XDP queue requires both RX and TX"));
        }
    }
    Ok(())
}

pub(crate) fn validate_queue(ifindex: u32, queue: u32) -> io::Result<()> {
    let mut name = [0; libc::IFNAMSIZ];
    // SAFETY: name has IFNAMSIZ bytes, as required by if_indextoname.
    if unsafe { libc::if_indextoname(ifindex, name.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful if_indextoname returned a NUL-terminated name in this buffer.
    let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) };
    let path = Path::new("/sys/class/net").join(std::ffi::OsStr::from_bytes(name.to_bytes()));
    let actual = fs::read_to_string(path.join("ifindex"))?;
    if actual.trim().parse::<u32>().ok() != Some(ifindex) {
        return Err(unsupported("AF_XDP interface identity changed before bind"));
    }
    require_queue_pair(&path.join("queues"), queue)
}

fn upper_ifindices(path: &Path, root: u32) -> io::Result<Vec<u32>> {
    let mut uppers = Vec::new();
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "master" || name == "bridge" || name == "bonding" || name.starts_with("lower_") {
            return Err(unsupported(
                "stacked, bridged, bonded or enslaved XDP root topology",
            ));
        }
        if name.starts_with("upper_") {
            if uppers.len() == MAX_UPPER_INTERFACES {
                return Err(unsupported(
                    "direct upper interfaces exceed bounded capacity",
                ));
            }
            let index = fs::read_to_string(entry.path().join("ifindex"))?
                .trim()
                .parse::<u32>()
                .map_err(|_| unsupported("invalid upper interface identity"))?;
            if index == 0 || index == root {
                return Err(unsupported("invalid upper interface identity"));
            }
            uppers.push(index);
        }
    }
    uppers.sort_unstable();
    if uppers.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(unsupported("duplicate upper interface identity"));
    }
    Ok(uppers)
}

fn socket(domain: i32, kind: i32, protocol: i32) -> io::Result<OwnedFd> {
    // SAFETY: no pointer arguments; returned descriptor is wrapped exactly once.
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn query(fd: &OwnedFd, name: &str, words: &mut [u32]) -> io::Result<()> {
    // SAFETY: zeroed ifreq is valid; name is validated and the ioctl buffer remains live.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (out, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *out = byte as libc::c_char;
    }
    request.ifr_ifru.ifru_data = words.as_mut_ptr().cast();
    if unsafe { libc::ioctl(fd.as_raw_fd(), 0x8946, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn reject_vlan_stripping(name: &str) -> io::Result<()> {
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    // ETHTOOL_GSSET_INFO, ETH_SS_FEATURES; preserve native u64 mask byte order.
    let mask = (1u64 << 4).to_ne_bytes();
    let mut info = [
        0x37,
        0,
        u32::from_ne_bytes(mask[..4].try_into().unwrap()),
        u32::from_ne_bytes(mask[4..].try_into().unwrap()),
        0,
        0,
    ];
    query(&fd, name, &mut info)?;
    let count = info[4] as usize;
    if info[2] != u32::from_ne_bytes(mask[..4].try_into().unwrap())
        || info[3] != u32::from_ne_bytes(mask[4..].try_into().unwrap())
        || count == 0
        || count > 4096
    {
        return Err(unsupported("ethtool feature facts unavailable"));
    }
    let mut names = vec![0u32; 3 + count * 8];
    names[0] = 0x1b;
    names[1] = 4;
    names[2] = count as u32;
    query(&fd, name, &mut names)?;
    let blocks = count.div_ceil(32);
    let mut features = vec![0u32; 2 + blocks * 4];
    features[0] = 0x3a;
    features[1] = blocks as u32;
    query(&fd, name, &mut features)?;
    if names[2] as usize != count || features[1] as usize != blocks {
        return Err(unsupported("ethtool features changed during discovery"));
    }
    let mut found_vlan = 0;
    for index in 0..count {
        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(&names[3 + index * 8..3 + (index + 1) * 8])
        {
            chunk.copy_from_slice(&word.to_ne_bytes());
        }
        let feature = &bytes[..bytes.iter().position(|&byte| byte == 0).unwrap_or(32)];
        if feature == b"rx-vlan-hw-parse" || feature == b"rx-vlan-stag-hw-parse" {
            found_vlan |= if feature == b"rx-vlan-hw-parse" { 1 } else { 2 };
            if features[2 + index / 32 * 4 + 2] & (1 << (index % 32)) != 0 {
                return Err(unsupported(
                    "active RX VLAN stripping has no admitted metadata recovery",
                ));
            }
        }
    }
    if found_vlan != 3 {
        return Err(unsupported("RX VLAN stripping facts unavailable"));
    }
    Ok(())
}

fn attributes(mut bytes: &[u8], mut f: impl FnMut(u16, &[u8]) -> io::Result<()>) -> io::Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(unsupported("truncated netlink attribute"));
        }
        let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        if length < 4 || length > bytes.len() {
            return Err(unsupported("invalid netlink attribute extent"));
        }
        f(kind, &bytes[4..length])?;
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            return Err(unsupported("truncated netlink attribute padding"));
        }
        bytes = &bytes[aligned..];
    }
    Ok(())
}

fn xdp_capabilities(ifindex: u32) -> io::Result<(u64, u32, u64)> {
    let fd = socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_GENERIC)?;
    // SAFETY: initialized sockaddr_nl identifies the kernel, not another userspace peer.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            size_of::<libc::sockaddr_nl>() as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: timeval is the exact socket option payload.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::from_ref(&timeout).cast(),
            size_of::<libc::timeval>() as _,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    fn request(
        fd: &OwnedFd,
        family: u16,
        command: u8,
        kind: u16,
        value: &[u8],
        sequence: u32,
    ) -> io::Result<Vec<u8>> {
        let attr_len = value.len() + 4;
        let mut bytes = vec![0u8; 20 + ((attr_len + 3) & !3)];
        let length = bytes.len() as u32;
        bytes[0..4].copy_from_slice(&length.to_ne_bytes());
        bytes[4..6].copy_from_slice(&family.to_ne_bytes());
        bytes[6..8].copy_from_slice(&1u16.to_ne_bytes());
        bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
        bytes[16] = command;
        bytes[17] = 1;
        bytes[20..22].copy_from_slice(&(attr_len as u16).to_ne_bytes());
        bytes[22..24].copy_from_slice(&kind.to_ne_bytes());
        bytes[24..24 + value.len()].copy_from_slice(value);
        // SAFETY: both syscall buffers have their stated extents and remain live.
        if unsafe { libc::send(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len(), 0) }
            != bytes.len() as isize
        {
            return Err(io::Error::last_os_error());
        }
        let mut response = vec![0u8; 65536];
        let received = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                response.as_mut_ptr().cast(),
                response.len(),
                libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        if received < 20 || received as usize > response.len() {
            return Err(unsupported("invalid netdev reply size"));
        }
        response.truncate(received as usize);
        let size = u32::from_ne_bytes(response[0..4].try_into().unwrap()) as usize;
        let reply = u16::from_ne_bytes(response[4..6].try_into().unwrap());
        if u32::from_ne_bytes(response[8..12].try_into().unwrap()) != sequence
            || size != response.len()
        {
            return Err(unsupported("unexpected netdev reply identity"));
        }
        if reply == 2 {
            let code = i32::from_ne_bytes(response[16..20].try_into().unwrap());
            return Err(if code < 0 {
                io::Error::from_raw_os_error(-code)
            } else {
                unsupported("netdev returned no facts")
            });
        }
        if reply != family {
            return Err(unsupported("unexpected netdev reply family"));
        }
        Ok(response)
    }
    let family_name = CString::new("netdev").unwrap();
    let response = request(&fd, 0x10, 3, 2, family_name.as_bytes_with_nul(), 1)?;
    let mut family = None;
    attributes(&response[20..], |kind, value| {
        if kind == 1 && value.len() == 2 {
            family = Some(u16::from_ne_bytes(value.try_into().unwrap()));
        }
        Ok(())
    })?;
    let response = request(
        &fd,
        family.ok_or_else(|| unsupported("netdev generic family unavailable"))?,
        1,
        1,
        &ifindex.to_ne_bytes(),
        2,
    )?;
    let mut index = None;
    let mut features = None;
    let mut maximum = 0;
    let mut rx_metadata = 0;
    attributes(&response[20..], |kind, value| {
        match (kind, value.len()) {
            (1, 4) => index = Some(u32::from_ne_bytes(value.try_into().unwrap())),
            (3, 8) => features = Some(u64::from_ne_bytes(value.try_into().unwrap())),
            (4, 4) => maximum = u32::from_ne_bytes(value.try_into().unwrap()),
            (5, 8) => rx_metadata = u64::from_ne_bytes(value.try_into().unwrap()),
            _ => {}
        }
        Ok(())
    })?;
    if index != Some(ifindex) {
        return Err(unsupported("netdev interface identity mismatch"));
    }
    Ok((
        features.ok_or_else(|| unsupported("XDP feature advertisement unavailable"))?,
        maximum,
        rx_metadata,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_preflight_requires_real_zero_copy_and_complete_chains() {
        let mut device = DeviceInfo {
            name: "test0".into(),
            ifindex: 2,
            upper_ifindices: vec![],
            queues: vec![0, 1],
            mtu: 1500,
            mac: [2, 0, 0, 0, 0, 1],
            xdp_features: 3 | 32,
            zerocopy_max_segments: 0,
            vlan_metadata: false,
        };
        let config = PortConfig {
            rx_frames: 4,
            control_frames: 4,
            bulk_frames: 4,
            ring_size: 8,
        };
        assert_eq!(
            device.validate_port_config(BindMode::Copy, config).unwrap(),
            1
        );
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        device.xdp_features |= 8;
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config)
                .unwrap(),
            1
        );
        device.mtu = 9000;
        assert_eq!(
            device.validate_port_config(BindMode::Copy, config).unwrap(),
            3
        );
        device.zerocopy_max_segments = 2;
        assert!(
            device
                .validate_port_config(BindMode::ZeroCopy, config)
                .is_err()
        );
        device.zerocopy_max_segments = 3;
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config)
                .unwrap(),
            3
        );
        for insufficient in [
            PortConfig {
                rx_frames: 2,
                ..config
            },
            PortConfig {
                control_frames: 2,
                ..config
            },
            PortConfig {
                bulk_frames: 2,
                ..config
            },
            PortConfig {
                ring_size: 7,
                ..config
            },
        ] {
            assert!(
                device
                    .validate_port_config(BindMode::Copy, insufficient)
                    .is_err()
            );
            assert!(
                device
                    .validate_port_config(BindMode::ZeroCopy, insufficient)
                    .is_err()
            );
        }
    }

    struct SysfsFixture(std::path::PathBuf);

    impl SysfsFixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("honk-xsk-device-{}-{id}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn upper(&self, name: &str, index: &str) {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("ifindex"), index).unwrap();
        }
    }

    impl Drop for SysfsFixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn every_discovered_rx_queue_requires_a_transmit_peer() {
        let fixture = SysfsFixture::new();
        for queue in ["rx-0", "tx-0", "rx-1"] {
            fs::create_dir(fixture.0.join(queue)).unwrap();
        }
        assert_eq!(
            bidirectional_queues(&fixture.0).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        fs::create_dir(fixture.0.join("tx-1")).unwrap();
        assert_eq!(bidirectional_queues(&fixture.0).unwrap(), [0, 1]);
        fs::remove_dir(fixture.0.join("rx-1")).unwrap();
        assert_eq!(bidirectional_queues(&fixture.0).unwrap(), [0]);
        assert!(require_queue_pair(&fixture.0, 1).is_err());
        fs::remove_dir(fixture.0.join("rx-0")).unwrap();
        assert!(bidirectional_queues(&fixture.0).is_err());
        fs::create_dir(fixture.0.join("rx-1")).unwrap();
        assert!(bidirectional_queues(&fixture.0).is_err());
    }

    #[test]
    fn direct_uppers_are_sorted_facts_without_relaxing_root_guards() {
        let fixture = SysfsFixture::new();
        fixture.upper("upper_a", "20\n");
        fixture.upper("upper_b", "4\n");
        fixture.upper("upper_b/upper_nested", "99\n");
        assert_eq!(upper_ifindices(&fixture.0, 2).unwrap(), [4, 20]);
        for guard in ["master", "bridge", "bonding", "lower_eth0"] {
            fs::write(fixture.0.join(guard), "").unwrap();
            assert!(upper_ifindices(&fixture.0, 2).is_err());
            fs::remove_file(fixture.0.join(guard)).unwrap();
        }
        for invalid in ["0", "2", "20", "not-an-ifindex"] {
            fs::write(fixture.0.join("upper_b/ifindex"), invalid).unwrap();
            assert!(upper_ifindices(&fixture.0, 2).is_err());
        }
        fs::remove_file(fixture.0.join("upper_b/ifindex")).unwrap();
        assert!(upper_ifindices(&fixture.0, 2).is_err());
    }

    #[test]
    fn upper_discovery_is_bounded_before_growing_past_capacity() {
        let fixture = SysfsFixture::new();
        fixture.upper("target", "4");
        for index in 0..=MAX_UPPER_INTERFACES {
            std::os::unix::fs::symlink("target", fixture.0.join(format!("upper_{index}"))).unwrap();
        }
        assert_eq!(
            upper_ifindices(&fixture.0, 2).unwrap_err().to_string(),
            "direct upper interfaces exceed bounded capacity"
        );
    }

    #[test]
    fn attribute_extents_fail_closed() {
        assert!(attributes(&[3, 0, 1, 0], |_, _| Ok(())).is_err());
        assert!(attributes(&[8, 0, 1, 0, 0], |_, _| Ok(())).is_err());
        let mut seen = false;
        attributes(&[8, 0, 1, 0, 7, 0, 0, 0], |kind, bytes| {
            assert_eq!(kind, 1);
            assert_eq!(bytes, &[7, 0, 0, 0]);
            seen = true;
            Ok(())
        })
        .unwrap();
        assert!(seen);
    }
}

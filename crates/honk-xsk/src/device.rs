//! Read-only physical Ethernet/veth discovery; logical roots are admitted by topology.

use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

use crate::port::{BindMode, MAX_SEGMENTS, Port, PortConfig, rx_frame_capacity};
use honk_netstack::{MemoryBudget, MemoryReservation};
mod features;
pub use features::{FeatureQuery, VlanOffload, prepare_vlan_offload, select_xsk_mode};

const MAX_UPPER_INTERFACES: usize = 4096;
// Attaching our guard may publish these NDO-XMIT flags; AF_XDP TX does not use them.
const NDO_XMIT_FEATURES: u64 = 4 | 64;

#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub name: String,
    pub ifindex: u32,
    /// Direct sysfs uppers, not proof that any descendant is safe to capture.
    pub upper_ifindices: Vec<u32>,
    pub queues: Vec<u32>,
    /// A device-backed Ethernet member, not the veth capture test profile.
    pub physical_member: bool,
    pub mtu: u32,
    pub mac: [u8; 6],
    pub xdp_features: u64,
    pub zerocopy_max_segments: u32,
    pub vlan_metadata: bool,
    /// Discovery found the i40e PCI physical-function profile measured for Direct relay.
    pub direct_relay_physical: bool,
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
        let ifindex = device_number(&path, "ifindex")?;
        let driver = driver_info(name)?;
        let veth = driver[1].to_ne_bytes() == *b"veth" && driver[2].to_ne_bytes()[0] == 0;
        let physical =
            path.join("device").try_exists()? && device_number(&path, "iflink")? == ifindex;
        if device_number(&path, "type")? != 1 || !(physical || veth) {
            return Err(unsupported(
                "only physical Ethernet or proven veth capture members are admitted",
            ));
        }
        let upper_ifindices = upper_ifindices(&path, ifindex)?;
        let mtu = device_number(&path, "mtu")?;
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
        if xdp_features & 3 != 3 {
            return Err(unsupported("native XDP basic/redirect support unavailable"));
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
            physical_member: physical,
            direct_relay_physical: physical && i40e_physical_function(&path, &driver),
        })
    }

    /// Check commitments with exact RX metadata headroom; return the required RX chain length.
    pub fn validate_port_config(
        &self,
        mode: BindMode,
        config: PortConfig,
        metadata_len: usize,
    ) -> io::Result<usize> {
        let capacity = rx_frame_capacity(metadata_len)?;
        config.validate()?;
        let required = (self.mtu as usize + 22).div_ceil(capacity);
        if required > MAX_SEGMENTS
            || config.rx_frames < required
            || config.control_frames < required
            || config.bulk_frames < required
            || (config.ring_size as usize) < required
        {
            return Err(unsupported(
                "whole-packet frame commitments cannot cover device MTU",
            ));
        }
        if required > 1 && self.xdp_features & 32 == 0 {
            return Err(unsupported("native XDP RX scatter/gather unavailable"));
        }
        if mode == BindMode::ZeroCopy
            && (self.xdp_features & 8 == 0
                || (required > 1 && self.zerocopy_max_segments < required as u32))
        {
            return Err(unsupported("zero-copy segment capability unavailable"));
        }
        Ok(required)
    }

    /// Recheck device identity and capabilities before opening capture queues.
    pub fn validate_current(&self) -> io::Result<()> {
        self.validate_recheck(&Self::discover(&self.name)?)
    }

    /// Recheck the optional Direct relay hardware proof immediately before publication.
    pub fn supports_direct_relay_now(&self) -> bool {
        if !self.direct_relay_physical {
            return false;
        }
        let path = Path::new("/sys/class/net").join(&self.name);
        device_number(&path, "ifindex").is_ok_and(|ifindex| ifindex == self.ifindex)
            && device_number(&path, "iflink").is_ok_and(|iflink| iflink == self.ifindex)
            && driver_info(&self.name).is_ok_and(|driver| i40e_physical_function(&path, &driver))
    }

    fn validate_recheck(&self, fresh: &Self) -> io::Result<()> {
        if fresh.ifindex != self.ifindex
            || fresh.upper_ifindices != self.upper_ifindices
            || fresh.queues != self.queues
            || fresh.physical_member != self.physical_member
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
        metadata_len: usize,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Vec<Port<L>>> {
        self.validate_current()?;
        let required = self.validate_port_config(mode, config, metadata_len)?;
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
                    metadata_len,
                    budget,
                )
            })
            .collect()
    }
}

fn device_number(path: &Path, file: &str) -> io::Result<u32> {
    fs::read_to_string(path.join(file))?
        .trim()
        .parse()
        .map_err(|_| unsupported(format!("invalid {file}")))
}

fn driver_info(name: &str) -> io::Result<[u32; 49]> {
    let fd = socket(libc::AF_INET, libc::SOCK_DGRAM, 0)?;
    let mut driver = [0u32; 49];
    driver[0] = 3; // ETHTOOL_GDRVINFO
    query(&fd, name, &mut driver)?;
    Ok(driver)
}

fn i40e_physical_function(path: &Path, driver: &[u32; 49]) -> bool {
    if driver[1].to_ne_bytes() != *b"i40e" || driver[2].to_ne_bytes()[0] != 0 {
        return false;
    }
    let bus = features::string_bytes(&driver[25..33]);
    let Ok(bus) = CStr::from_bytes_until_nul(&bus) else {
        return false;
    };
    let device = path.join("device");
    let bus_matches = fs::read_link(&device).is_ok_and(|target| {
        target
            .file_name()
            .is_some_and(|name| name.as_bytes() == bus.to_bytes())
    });
    bus_matches
        && fs::read_link(device.join("subsystem")).is_ok_and(|target| target.ends_with("bus/pci"))
        && fs::symlink_metadata(device.join("physfn"))
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        && fs::read_to_string(device.join("vendor")).is_ok_and(|vendor| vendor.trim() == "0x8086")
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
        if name == "master" {
            if !entry.path().join("bonding").is_dir() {
                return Err(unsupported("XDP member has a non-bond master"));
            }
            continue;
        }
        if name == "bridge" || name == "bonding" || name.starts_with("lower_") {
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

fn interface_name(name: &str) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    if name.is_empty()
        || name.len() >= libc::IFNAMSIZ
        || name.contains('/')
        || name.as_bytes().contains(&0)
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut bytes = [0; libc::IFNAMSIZ];
    for (out, byte) in bytes.iter_mut().zip(name.bytes()) {
        *out = byte as libc::c_char;
    }
    Ok(bytes)
}

fn query(fd: &OwnedFd, name: &str, words: &mut [u32]) -> io::Result<()> {
    query_named(fd, &interface_name(name)?, words)
}

fn query_named(
    fd: &OwnedFd,
    name: &[libc::c_char; libc::IFNAMSIZ],
    words: &mut [u32],
) -> io::Result<()> {
    // SAFETY: the fixed name is terminated and the ioctl buffer remains live.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name = *name;
    request.ifr_ifru.ifru_data = words.as_mut_ptr().cast();
    if unsafe { libc::ioctl(fd.as_raw_fd(), 0x8946, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
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
    use crate::port::METADATA_SIZE;

    fn device() -> DeviceInfo {
        DeviceInfo {
            name: "test0".into(),
            ifindex: 2,
            upper_ifindices: vec![],
            queues: vec![0, 1],
            mtu: 1500,
            mac: [2, 0, 0, 0, 0, 1],
            xdp_features: 3 | 32,
            zerocopy_max_segments: 0,
            vlan_metadata: false,
            physical_member: true,
            direct_relay_physical: true,
        }
    }

    #[test]
    fn optional_direct_relay_proof_does_not_change_capture_recheck() {
        let candidate = device();
        let unproven = DeviceInfo {
            direct_relay_physical: false,
            ..candidate.clone()
        };
        assert!(candidate.validate_recheck(&unproven).is_ok());
        assert!(!unproven.supports_direct_relay_now());

        let virtual_member = DeviceInfo {
            physical_member: false,
            ..unproven
        };
        assert_eq!(
            candidate
                .validate_recheck(&virtual_member)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }

    #[test]
    fn binding_preflight_requires_real_zero_copy_and_complete_chains() {
        let mut device = device();
        let config = PortConfig {
            rx_frames: 4,
            control_frames: 4,
            bulk_frames: 4,
            ring_size: 8,
        };
        assert_eq!(
            device
                .validate_port_config(BindMode::Copy, config, METADATA_SIZE)
                .unwrap(),
            1
        );
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config, METADATA_SIZE)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
        device.xdp_features |= 8;
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config, METADATA_SIZE)
                .unwrap(),
            1
        );
        device.mtu = 9000;
        assert_eq!(
            device
                .validate_port_config(BindMode::Copy, config, METADATA_SIZE)
                .unwrap(),
            3
        );
        device.zerocopy_max_segments = 2;
        assert!(
            device
                .validate_port_config(BindMode::ZeroCopy, config, METADATA_SIZE)
                .is_err()
        );
        device.zerocopy_max_segments = 3;
        assert_eq!(
            device
                .validate_port_config(BindMode::ZeroCopy, config, METADATA_SIZE)
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
                    .validate_port_config(BindMode::Copy, insufficient, METADATA_SIZE)
                    .is_err()
            );
            assert!(
                device
                    .validate_port_config(BindMode::ZeroCopy, insufficient, METADATA_SIZE)
                    .is_err()
            );
        }
        device.mtu = 3700;
        for (metadata_len, required) in [(0, 1), (32, 1), (64, 1), (128, 2)] {
            assert_eq!(
                device
                    .validate_port_config(BindMode::Copy, config, metadata_len)
                    .unwrap(),
                required,
            );
        }
        device.xdp_features &= !32;
        assert!(
            device
                .validate_port_config(BindMode::Copy, config, 32)
                .is_ok()
        );
        assert!(
            device
                .validate_port_config(BindMode::Copy, config, 128)
                .is_err()
        );
        device.xdp_features |= 32;
        device.zerocopy_max_segments = 1;
        assert!(
            device
                .validate_port_config(BindMode::ZeroCopy, config, 32)
                .is_ok()
        );
        assert!(
            device
                .validate_port_config(BindMode::ZeroCopy, config, 128)
                .is_err()
        );
        for metadata_len in [1, 31, 48, 63, 65, 127, 129, usize::MAX] {
            assert_eq!(
                device
                    .validate_port_config(BindMode::Copy, config, metadata_len)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput,
            );
        }
        device.mtu = 65535;
        let full = PortConfig {
            rx_frames: MAX_SEGMENTS,
            control_frames: MAX_SEGMENTS,
            bulk_frames: MAX_SEGMENTS,
            ring_size: 64,
        };
        assert_eq!(rx_frame_capacity(64).unwrap(), 3776);
        assert_eq!(
            device
                .validate_port_config(BindMode::Copy, full, 64)
                .unwrap(),
            MAX_SEGMENTS,
        );
        assert_eq!(
            device
                .validate_port_config(BindMode::Copy, full, 128)
                .unwrap(),
            MAX_SEGMENTS,
        );
        assert!(
            device
                .validate_port_config(
                    BindMode::Copy,
                    PortConfig {
                        rx_frames: MAX_SEGMENTS - 1,
                        ..full
                    },
                    128
                )
                .is_err()
        );
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
    fn direct_relay_requires_the_i40e_pci_physical_function_proof() {
        use std::os::unix::fs::symlink;

        let fixture = SysfsFixture::new();
        let bdf = "0000:02:00.1";
        let device = fixture.0.join(bdf);
        fs::create_dir(&device).unwrap();
        symlink(bdf, fixture.0.join("device")).unwrap();
        symlink("../../../bus/pci", device.join("subsystem")).unwrap();
        fs::write(device.join("vendor"), "0x8086\n").unwrap();

        let driver_info = |name: &[u8], bus: &[u8]| {
            let mut driver = [0; 49];
            driver[0] = 3;
            for (start, text) in [(1, name), (25, bus)] {
                let mut bytes = [0; 32];
                bytes[..text.len()].copy_from_slice(text);
                for (word, chunk) in driver[start..start + 8]
                    .iter_mut()
                    .zip(bytes.as_chunks::<4>().0)
                {
                    *word = u32::from_ne_bytes(*chunk);
                }
            }
            driver
        };
        let pf = driver_info(b"i40e", bdf.as_bytes());
        assert!(i40e_physical_function(&fixture.0, &pf));
        for driver in [b"virtio_net".as_slice(), b"iavf", b"veth", b"i40evf"] {
            assert!(!i40e_physical_function(
                &fixture.0,
                &driver_info(driver, bdf.as_bytes())
            ));
        }
        assert!(!i40e_physical_function(
            &fixture.0,
            &driver_info(b"i40e", b"0000:02:00.0")
        ));

        let physfn = device.join("physfn");
        symlink("../0000:02:00.0", &physfn).unwrap();
        assert!(!i40e_physical_function(&fixture.0, &pf));
        fs::remove_file(physfn).unwrap();
        let subsystem = device.join("subsystem");
        fs::remove_file(&subsystem).unwrap();
        symlink("../../../bus/virtio", &subsystem).unwrap();
        assert!(!i40e_physical_function(&fixture.0, &pf));
        fs::remove_file(&subsystem).unwrap();
        symlink("../../../bus/pci", &subsystem).unwrap();
        fs::remove_file(device.join("vendor")).unwrap();
        assert!(!i40e_physical_function(&fixture.0, &pf));
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
    fn bond_master_is_allowed_but_other_masters_are_rejected() {
        let fixture = SysfsFixture::new();
        fs::create_dir(fixture.0.join("master")).unwrap();
        assert!(upper_ifindices(&fixture.0, 2).is_err());
        fs::create_dir(fixture.0.join("master/bonding")).unwrap();
        assert_eq!(upper_ifindices(&fixture.0, 2).unwrap(), []);
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

//! Bounded socket-cookie registrations, synchronously armed and drained by the receive owner.

use std::io;
use std::os::fd::{AsFd, BorrowedFd, RawFd};
use std::sync::Arc;

use anyhow::Context as _;
use aya::maps::{HashMap, IterableMap, Map, MapData};
use aya::programs::{FEntry, FExit, fentry::FEntryLink, fexit::FExitLink};
use aya::{Btf, Ebpf, EbpfLoader};
use honk_ebpf_common::receive_trace::{
    RECEIVE_TRACE_BATCH_SIZE, RECEIVE_TRACE_VALID, ReceiveTraceBatch, ReceiveTracePacket,
};

use super::btf::Btf as OffsetBtf;

#[derive(Clone, Copy, Debug)]
pub(super) struct ReceiveTraceOffsets {
    cookie: u32,
    priority: u32,
    mark: u32,
    owner: u32,
}

impl ReceiveTraceOffsets {
    pub(super) fn configure<'a>(&'a self, loader: &mut EbpfLoader<'a>) {
        loader
            .override_global("RECEIVE_SOCK_COOKIE_OFFSET", &self.cookie, true)
            .override_global("RECEIVE_SKB_PRIORITY_OFFSET", &self.priority, true)
            .override_global("RECEIVE_SKB_MARK_OFFSET", &self.mark, true)
            .override_global("RECEIVE_OWNER_TGID", &self.owner, true);
    }
}

pub(super) fn detect(data: &[u8]) -> Option<ReceiveTraceOffsets> {
    let btf = OffsetBtf::parse(data)?;
    let common = btf.member_offset("sock", "__sk_common")?;
    let cookie = common.checked_add(btf.sized_member_offset("sock_common", "skc_cookie", 8)?)?;
    Some(ReceiveTraceOffsets {
        cookie,
        priority: btf.sized_member_offset("sk_buff", "priority", 4)?,
        mark: btf.sized_member_offset("sk_buff", "mark", 4)?,
        // The hooks see host TGIDs; like `control_plane_pid`, this assumes the host PID namespace.
        owner: std::process::id(),
    })
}

pub struct ReceiveTrace {
    map: HashMap<MapData, u64, ReceiveTraceBatch>,
    ipv4: Option<(FEntryLink, FExitLink)>,
    ipv6: Option<(FEntryLink, FExitLink)>,
    _candidate: FExitLink,
}

// Each registration owns its handle so concurrent listeners never serialize map updates.
fn handle(map: &MapData) -> io::Result<HashMap<MapData, u64, ReceiveTraceBatch>> {
    let map = MapData::from_fd(map.fd().as_fd().try_clone_to_owned()?).map_err(io::Error::other)?;
    HashMap::try_from(Map::HashMap(map)).map_err(io::Error::other)
}

fn attach_exit(bpf: &mut Ebpf, btf: &Btf, name: &str, target: &str) -> anyhow::Result<FExitLink> {
    let program: &mut FExit = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow::anyhow!("missing receive program {name}"))?
        .try_into()?;
    program
        .load(target, btf)
        .with_context(|| format!("load {name} on {target}"))?;
    let link = program
        .attach()
        .with_context(|| format!("attach {name} on {target}"))?;
    Ok(program.take_link(link)?)
}

fn attach_family(
    bpf: &mut Ebpf,
    btf: &Btf,
    enter: &str,
    exit: &str,
    target: &str,
) -> anyhow::Result<(FEntryLink, FExitLink)> {
    let program: &mut FEntry = bpf
        .program_mut(enter)
        .ok_or_else(|| anyhow::anyhow!("missing receive program {enter}"))?
        .try_into()?;
    program
        .load(target, btf)
        .with_context(|| format!("load {enter} on {target}"))?;
    let link = program
        .attach()
        .with_context(|| format!("attach {enter} on {target}"))?;
    let entry = program.take_link(link)?;
    // A failed exit must detach the entry too; an incomplete pair cannot produce evidence.
    let exit = attach_exit(bpf, btf, exit, target)?;
    Ok((entry, exit))
}

impl ReceiveTrace {
    #[cfg(test)]
    fn load_unattached_for_test() -> anyhow::Result<(Ebpf, Vec<u8>, Btf)> {
        let (data, kernel_btf) = super::btf::load_kernel()?;
        let offsets = detect(&data)
            .ok_or_else(|| anyhow::anyhow!("receive trace BTF offsets unavailable"))?;
        let mut loader = EbpfLoader::new();
        loader.btf(&kernel_btf);
        offsets.configure(&mut loader);
        let bpf = loader.load(crate::DEFAULT_BPF_OBJECT)?;
        drop(loader);
        Ok((bpf, data, kernel_btf))
    }

    #[cfg(test)]
    pub(crate) fn load_for_test() -> anyhow::Result<(Ebpf, Arc<Self>)> {
        let (mut bpf, _, kernel_btf) = Self::load_unattached_for_test()?;
        let trace = Self::attach(&mut bpf, &kernel_btf)?;
        Ok((bpf, trace))
    }

    pub(super) fn attach(bpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<Arc<Self>> {
        // Both recvmsg paths consume the candidate from this shared helper.
        let candidate = attach_exit(bpf, btf, "honk_udp_receive_candidate", "__skb_recv_udp")?;
        let ipv4 = attach_family(
            bpf,
            btf,
            "honk_udp_receive_enter",
            "honk_udp_receive_exit",
            "udp_recvmsg",
        );
        let ipv6 = attach_family(
            bpf,
            btf,
            "honk_udp6_receive_enter",
            "honk_udp6_receive_exit",
            "udpv6_recvmsg",
        );
        if let (Err(ipv4), Err(ipv6)) = (&ipv4, &ipv6) {
            anyhow::bail!("UDP receive hooks unavailable: IPv4: {ipv4:#}; IPv6: {ipv6:#}");
        }
        for (family, result) in [("ipv4", &ipv4), ("ipv6", &ipv6)] {
            if let Err(error) = result {
                tracing::warn!(
                    family,
                    error = %format_args!("{error:#}"),
                    "kernel UDP trace attach unavailable"
                );
            }
        }
        let Some(Map::HashMap(map)) = bpf.map("RECEIVE_TRACE") else {
            anyhow::bail!("missing RECEIVE_TRACE hash map");
        };
        Ok(Arc::new(Self {
            map: handle(map)?,
            ipv4: ipv4.ok(),
            ipv6: ipv6.ok(),
            _candidate: candidate,
        }))
    }

    pub(crate) fn register(self: &Arc<Self>, fd: RawFd) -> io::Result<ReceiveRegistration> {
        // Listeners are family-specific (IPv6-only for AF_INET6), so require that family's pair.
        let socket = unsafe { BorrowedFd::borrow_raw(fd) };
        let domain = socket2::SockRef::from(&socket).domain()?;
        let available = (domain == socket2::Domain::IPV4 && self.ipv4.is_some())
            || (domain == socket2::Domain::IPV6 && self.ipv6.is_some());
        if !available {
            return Err(io::Error::other(
                "UDP receive trace unavailable for socket family",
            ));
        }
        let mut cookie = 0u64;
        let mut size = std::mem::size_of_val(&cookie) as libc::socklen_t;
        // SO_COOKIE initializes the exact field subsequently read by the hooks.
        let status = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&mut cookie as *mut u64).cast(),
                &mut size,
            )
        };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        if size as usize != std::mem::size_of::<u64>() || cookie == 0 {
            return Err(io::Error::other("invalid owned UDP socket cookie"));
        }
        let mut map = handle(self.map.map())?;
        map.insert(&cookie, &ReceiveTraceBatch::default(), 1)
            .map_err(io::Error::other)?;
        Ok(ReceiveRegistration {
            _trace: self.clone(),
            map,
            fd,
            cookie,
            epoch: 0,
            armed: false,
        })
    }
}

pub(crate) struct ReceiveRegistration {
    _trace: Arc<ReceiveTrace>,
    map: HashMap<MapData, u64, ReceiveTraceBatch>,
    fd: RawFd,
    cookie: u64,
    epoch: u64,
    armed: bool,
}

impl ReceiveRegistration {
    /// A receive that consumed nothing leaves the armed batch as the hooks
    /// found it, so the owner may skip `finish` and reuse it without a syscall.
    pub(crate) fn begin(&mut self, fd: RawFd) -> bool {
        fd == self.fd && (self.armed || self.arm())
    }

    fn arm(&mut self) -> bool {
        let Some(epoch) = self.epoch.checked_add(1) else {
            self.armed = false;
            return false;
        };
        self.epoch = epoch;
        self.armed = self
            .map
            .insert(
                &self.cookie,
                &ReceiveTraceBatch {
                    epoch,
                    active: 1,
                    ..Default::default()
                },
                2,
            )
            .is_ok();
        self.armed
    }

    pub(crate) fn finish(
        &mut self,
        count: usize,
    ) -> Option<[ReceiveTracePacket; RECEIVE_TRACE_BATCH_SIZE]> {
        let epoch = self.epoch;
        let batch = self.map.get(&self.cookie, 0).ok();
        // Even an errored syscall or failed read must replace the drained batch;
        // rearming does so and spares the next receive its own update.
        let rearmed = self.arm();
        let batch = batch?;
        if !rearmed
            || batch.epoch != epoch
            || batch.active != 1
            || batch.count as usize != count
            || batch.depth != 0
            || batch.lost != 0
            || count > RECEIVE_TRACE_BATCH_SIZE
        {
            return None;
        }
        Some(batch.packets)
    }
}

impl Drop for ReceiveRegistration {
    fn drop(&mut self) {
        let _ = self.map.remove(&self.cookie);
    }
}

pub(crate) fn packet_priority(
    packet: ReceiveTracePacket,
    length: u32,
    mark: Option<u32>,
) -> Option<u32> {
    (packet.valid == RECEIVE_TRACE_VALID && packet.length == length && mark == Some(packet.mark))
        .then_some(packet.priority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn without_target(mut data: Vec<u8>, target: &str) -> anyhow::Result<Btf> {
        let name = format!("\0{target}\0");
        let offset = data
            .windows(name.len())
            .position(|window| window == name.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("test requires {target} in kernel BTF"))?;
        // Keep type IDs/signatures intact; only Aya's lookup of this target must fail.
        data[offset + 1] = b'x';
        Ok(Btf::parse(&data, Default::default())?)
    }

    #[test]
    #[ignore = "requires Linux 6.12+ and root; run in the eBPF VM"]
    fn receive_trace_family_failure_is_isolated() -> anyhow::Result<()> {
        for (target, enter, exit, unavailable, available) in [
            (
                "udp_recvmsg",
                "honk_udp_receive_enter",
                "honk_udp_receive_exit",
                "127.0.0.1:0",
                "[::1]:0",
            ),
            (
                "udpv6_recvmsg",
                "honk_udp6_receive_enter",
                "honk_udp6_receive_exit",
                "[::1]:0",
                "127.0.0.1:0",
            ),
        ] {
            for fail_exit in [false, true] {
                let (mut bpf, data, kernel_btf) = ReceiveTrace::load_unattached_for_test()?;
                let missing_btf;
                let attach_btf = if fail_exit {
                    // Force the second hook to fail after the family's entry has attached.
                    let program: &mut FExit = bpf.program_mut(exit).unwrap().try_into()?;
                    program.load(target, &kernel_btf)?;
                    &kernel_btf
                } else {
                    missing_btf = without_target(data, target)?;
                    &missing_btf
                };
                let trace = ReceiveTrace::attach(&mut bpf, attach_btf)
                    .expect("one family must survive a sibling hook failure");
                if fail_exit {
                    let failed_entry_id = bpf.program(enter).unwrap().info()?.id();
                    for link in aya::programs::loaded_links() {
                        assert_ne!(
                            link?.program_id(),
                            failed_entry_id,
                            "failed family's entry remained attached"
                        );
                    }
                }
                let untraced = std::net::UdpSocket::bind(unavailable)?;
                assert!(trace.register(untraced.as_raw_fd()).is_err());

                let receiver = std::net::UdpSocket::bind(available)?;
                receiver.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
                let sender = std::net::UdpSocket::bind(available)?;
                let mut registration = trace.register(receiver.as_raw_fd())?;
                sender.send_to(b"live", receiver.local_addr()?)?;
                assert!(registration.begin(receiver.as_raw_fd()));
                let mut buffer = [0u8; 8];
                let length = receiver.recv(&mut buffer)?;
                assert_eq!(&buffer[..length], b"live");
                let packets = registration.finish(1).expect("surviving family is traced");
                assert_eq!(packets[0].valid, RECEIVE_TRACE_VALID);
                assert_eq!(packets[0].length, length as u32);
            }
        }
        let (mut bpf, data, _) = ReceiveTrace::load_unattached_for_test()?;
        let missing_btf = without_target(data, "__skb_recv_udp")?;
        assert!(ReceiveTrace::attach(&mut bpf, &missing_btf).is_err());
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux 6.12+ and root; run in the eBPF VM"]
    fn receive_trace_registration_loss_and_successful_zero_byte() -> anyhow::Result<()> {
        let (bpf, trace) = ReceiveTrace::load_for_test()?;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
        receiver.set_nonblocking(true)?;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let mut registration = trace.register(receiver.as_raw_fd())?;
        assert!(trace.register(receiver.as_raw_fd()).is_err());
        let cookie = registration.cookie;

        // Hooks and maps are owned by the registration, not the loader/backend.
        drop(bpf);
        drop(trace);
        let mut buffer = [0u8; 8];
        for (payload, flags, success, evidence) in [
            (Some(&b"peek"[..]), libc::MSG_PEEK, true, false),
            (None, 0, true, true),
            (Some(&b""[..]), 0, true, true),
            (None, 0, false, true),
            (Some(&b"after"[..]), 0, true, true),
            (None, libc::MSG_ERRQUEUE, false, false),
        ] {
            if let Some(payload) = payload {
                sender.send_to(payload, receiver.local_addr()?)?;
            }
            assert!(registration.begin(receiver.as_raw_fd()));
            let length = unsafe {
                libc::recv(
                    receiver.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    flags | libc::MSG_DONTWAIT,
                )
            };
            assert_eq!(length >= 0, success);
            let metadata = registration.finish(usize::from(success));
            assert_eq!(metadata.is_some(), evidence);
            if success && evidence {
                let packet = metadata.unwrap()[0];
                assert_eq!(packet.valid, RECEIVE_TRACE_VALID);
                assert_eq!(packet.length, length as u32);
            }
        }

        for loss in 0..5 {
            assert!(registration.begin(receiver.as_raw_fd()));
            let mut batch = ReceiveTraceBatch {
                epoch: registration.epoch,
                active: 1,
                count: 3,
                ..Default::default()
            };
            for (index, packet) in batch.packets[..3].iter_mut().enumerate() {
                *packet = ReceiveTracePacket {
                    priority: index as u32 + 100,
                    mark: 77,
                    length: 1,
                    valid: RECEIVE_TRACE_VALID,
                };
            }
            match loss {
                0 => batch.packets[1].valid = 0,
                1 => batch.count = 2,
                2 => batch.epoch -= 1,
                3 => batch.depth = 1,
                _ => batch.lost = 1,
            }
            registration.map.insert(&cookie, &batch, 2)?;
            let result = registration.finish(3);
            if loss == 0 {
                let packets = result.expect("located candidate hole retains other slots");
                assert_eq!(packet_priority(packets[0], 1, Some(77)), Some(100));
                assert_eq!(packet_priority(packets[1], 1, Some(77)), None);
                assert_eq!(packet_priority(packets[2], 1, Some(77)), Some(102));
                assert_eq!(packet_priority(packets[2], 1, Some(78)), None);
                assert_eq!(packet_priority(packets[2], 2, Some(77)), None);
            } else {
                assert!(result.is_none(), "unlocated loss must invalidate the batch");
            }
        }

        let trace = registration._trace.clone();
        drop(registration);
        assert!(trace.map.get(&cookie, 0).is_err());
        let mut registration = trace.register(receiver.as_raw_fd())?;
        assert!(registration.begin(receiver.as_raw_fd()));
        assert!(registration.finish(0).is_some());
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux 6.12+ and root; run in the eBPF VM"]
    fn receive_trace_stays_armed_between_receives() -> anyhow::Result<()> {
        let (_bpf, trace) = ReceiveTrace::load_for_test()?;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
        receiver.set_nonblocking(true)?;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let mut registration = trace.register(receiver.as_raw_fd())?;
        let cookie = registration.cookie;
        let mut buffer = [0u8; 8];

        assert!(registration.begin(receiver.as_raw_fd()));
        let mut marked = trace.map.get(&cookie, 0)?;
        marked.packets[RECEIVE_TRACE_BATCH_SIZE - 1].priority = 99;
        registration.map.insert(&cookie, &marked, 2)?;
        // Would-block receives skip `finish`; neither they nor `begin` may touch the map.
        for _ in 0..2 {
            assert!(registration.begin(receiver.as_raw_fd()));
            let length = unsafe {
                libc::recv(
                    receiver.as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            assert_eq!(length, -1);
        }
        let batch = trace.map.get(&cookie, 0)?;
        assert_eq!(batch.packets[RECEIVE_TRACE_BATCH_SIZE - 1].priority, 99);
        assert_eq!(
            (batch.epoch, batch.active, batch.count, batch.lost),
            (registration.epoch, 1, 0, 0)
        );

        sender.send_to(b"x", receiver.local_addr()?)?;
        assert!(registration.begin(receiver.as_raw_fd()));
        let length = unsafe {
            libc::recv(
                receiver.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        assert_eq!(length, 1);
        assert_eq!(registration.finish(1).expect("armed receive")[0].length, 1);
        let batch = trace.map.get(&cookie, 0)?;
        assert_eq!(
            (batch.epoch, batch.active, batch.count),
            (registration.epoch, 1, 0)
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires Linux 6.12+ and root; run in the eBPF VM"]
    fn receive_trace_ignores_other_processes() -> anyhow::Result<()> {
        let (_bpf, trace) = ReceiveTrace::load_for_test()?;
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let sender = std::net::UdpSocket::bind("127.0.0.1:0")?;
        let mut registration = trace.register(receiver.as_raw_fd())?;
        let mut buffer = [0u8; 8];
        let mut receive = || unsafe {
            libc::recv(
                receiver.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
            )
        };

        sender.send_to(b"child", receiver.local_addr()?)?;
        assert!(registration.begin(receiver.as_raw_fd()));
        // The child shares the registered socket; only async-signal-safe calls follow fork.
        match unsafe { libc::fork() } {
            0 => unsafe { libc::_exit(i32::from(receive() != 5)) },
            -1 => return Err(io::Error::last_os_error().into()),
            child => {
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
            }
        }
        assert!(
            registration.finish(0).is_some(),
            "another process's receive was traced"
        );

        sender.send_to(b"owner", receiver.local_addr()?)?;
        assert!(registration.begin(receiver.as_raw_fd()));
        assert_eq!(receive(), 5);
        let packets = registration
            .finish(1)
            .expect("the owner's receive is traced");
        assert_eq!(packets[0].valid, RECEIVE_TRACE_VALID);
        Ok(())
    }
}

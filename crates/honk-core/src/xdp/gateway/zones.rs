use honk_netstack::{MemoryBudget, MemoryReservation};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::Arc;

const XT_CT_NOTRACK_FLAGS: usize = 0x03;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn attrs<'a>(
    mut bytes: &'a [u8],
    mut visit: impl FnMut(u16, &'a [u8]) -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(invalid("truncated netlink attribute"));
        }
        let len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        if len < 4 || len > bytes.len() {
            return Err(invalid("invalid netlink attribute length"));
        }
        visit(kind, &bytes[4..len])?;
        let aligned = (len + 3) & !3;
        if aligned > bytes.len() {
            return Err(invalid("truncated netlink attribute padding"));
        }
        bytes = &bytes[aligned..];
    }
    Ok(())
}

fn zone(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() != 2 {
        return Err(invalid("invalid conntrack zone"));
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != 0 {
        return Err(invalid("nonzero conntrack zone"));
    }
    Ok(())
}

fn tuple_zone(bytes: &[u8]) -> io::Result<()> {
    attrs(bytes, |kind, value| {
        if kind == 3 {
            zone(value)?;
        }
        Ok(())
    })
}

fn conntrack_zones(bytes: &[u8], expectation: bool) -> io::Result<()> {
    attrs(bytes, |kind, value| {
        if expectation {
            match kind {
                1..=3 => tuple_zone(value)?,
                7 => zone(value)?,
                10 => attrs(value, |kind, value| {
                    if kind == 2 {
                        tuple_zone(value)?;
                    }
                    Ok(())
                })?,
                _ => {}
            }
        } else {
            match kind {
                1 | 2 | 14 => tuple_zone(value)?,
                18 => zone(value)?,
                _ => {}
            }
        }
        Ok(())
    })
}

fn native_u16(bytes: &[u8], offset: usize) -> io::Result<usize> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| invalid("truncated xtables entry"))?;
    Ok(u16::from_ne_bytes([value[0], value[1]]) as usize)
}

fn xt_ct_notrack(revision: u32, info: &[u8], legacy: bool) -> io::Result<bool> {
    // Revision 2 reuses xt_ct_target_info_v1. Legacy entries include the aligned kernel
    // pointer slot after the userspace fields, which the nft compat payload can omit.
    let usersize = match revision {
        0 => 32,
        1 | 2 => 64,
        _ => return Err(invalid("unknown xt CT target revision")),
    };
    let minimum = usersize + if legacy { 8 } else { 0 };
    if info.len() < minimum {
        return Err(invalid("truncated xt CT target info"));
    }
    let flags = native_u16(info, 0)?;
    if flags & 16 != 0 || native_u16(info, 2)? != 0 {
        return Err(invalid("nonzero or dynamic xt CT target zone"));
    }
    Ok(flags & XT_CT_NOTRACK_FLAGS != 0)
}

fn legacy_entries(mut bytes: &[u8], ipv6: bool, expected: u32) -> io::Result<bool> {
    // ip6t_ip6 is 136 bytes; nfcache precedes offsets, counters align to eight.
    let (target_field, entry_size) = if ipv6 { (140, 168) } else { (88, 112) };
    let mut count = 0u32;
    let mut notrack_seen = false;
    while !bytes.is_empty() {
        if bytes.len() < entry_size {
            return Err(invalid("truncated xtables entry"));
        }
        let target = native_u16(bytes, target_field)?;
        let next = native_u16(bytes, target_field + 2)?;
        if target < entry_size || next < target + 32 || next > bytes.len() {
            return Err(invalid("invalid xtables entry offsets"));
        }
        let entry = &bytes[target..next];
        let size = native_u16(entry, 0)?;
        if size < 32 || size != entry.len() {
            return Err(invalid("invalid xtables target size"));
        }
        let name = &entry[2..31];
        let end = name
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| invalid("invalid xtables target name"))?;
        match &name[..end] {
            b"CT" => notrack_seen |= xt_ct_notrack(u32::from(entry[31]), &entry[32..], true)?,
            b"NOTRACK" => notrack_seen = true,
            _ => {}
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("too many xtables entries"))?;
        bytes = &bytes[next..];
    }
    if count != expected {
        return Err(invalid("xtables entry count mismatch"));
    }
    Ok(notrack_seen)
}

fn attr_value(bytes: &[u8], wanted: u16) -> io::Result<Option<&[u8]>> {
    let mut found = None;
    attrs(bytes, |kind, value| {
        if kind == wanted && found.replace(value).is_some() {
            return Err(invalid("duplicate netlink attribute"));
        }
        Ok(())
    })?;
    Ok(found)
}

fn required(bytes: &[u8], kind: u16) -> io::Result<&[u8]> {
    attr_value(bytes, kind)?.ok_or_else(|| invalid("missing netlink attribute"))
}

fn be32(bytes: &[u8]) -> io::Result<u32> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| invalid("invalid netlink integer"))?;
    Ok(u32::from_be_bytes(bytes))
}

fn register(value: &[u8]) -> io::Result<usize> {
    match be32(value)? {
        1..=4 => Ok(8 + (be32(value)? as usize - 1) * 4),
        8..=23 => Ok(be32(value)? as usize),
        _ => Err(invalid("invalid nft register")),
    }
}

fn nft_string(bytes: &[u8]) -> io::Result<&[u8]> {
    let Some((&0, value)) = bytes.split_last() else {
        return Err(invalid("invalid nft string"));
    };
    if value.contains(&0) {
        return Err(invalid("invalid nft string"));
    }
    Ok(value)
}

fn nft_rule(bytes: &[u8], mut check_set: impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<bool> {
    let expressions = required(bytes, 4)?;
    let mut known_zero = [false; 24];
    let mut sets: [Option<&[u8]>; 24] = [None; 24];
    let mut notrack_seen = false;
    attrs(expressions, |kind, expression| {
        if kind != 1 {
            return Err(invalid("invalid nft expression list"));
        }
        let name = nft_string(required(expression, 1)?)?;
        let data = attr_value(expression, 2)?.unwrap_or(&[]);
        match name {
            b"immediate" => {
                let destination = required(data, 1)?;
                if be32(destination)? == 0 {
                    required(required(data, 2)?, 2)?;
                } else {
                    let reg = register(destination)?;
                    let value = required(required(data, 2)?, 1)?;
                    let width = value.len().div_ceil(4);
                    if width == 0 || reg + width > known_zero.len() {
                        return Err(invalid("invalid nft immediate width"));
                    }
                    for index in 0..width {
                        let end = (index * 4 + 4).min(value.len());
                        known_zero[reg + index] = end - index * 4 >= 2
                            && value[index * 4..end].iter().all(|&byte| byte == 0);
                        sets[reg + index] = None;
                    }
                }
            }
            b"lookup" => {
                if let Some(dreg) = attr_value(data, 3)? {
                    let reg = register(dreg)?;
                    known_zero.fill(false);
                    sets.fill(None);
                    sets[reg] = Some(nft_string(required(data, 1)?)?);
                }
            }
            b"ct" => {
                if be32(required(data, 2)?)? == 17
                    && let Some(sreg) = attr_value(data, 4)?
                {
                    let reg = register(sreg)?;
                    if let Some(set) = sets[reg] {
                        check_set(set)?;
                    } else if !known_zero[reg] {
                        return Err(invalid("nonzero or unproven nft CT zone"));
                    }
                }
                if attr_value(data, 1)?.is_some() {
                    known_zero.fill(false);
                    sets.fill(None);
                }
            }
            b"target" => {
                match nft_string(required(data, 1)?)? {
                    b"CT" => {
                        let revision = be32(required(data, 2)?)?;
                        notrack_seen |= xt_ct_notrack(revision, required(data, 3)?, false)?;
                    }
                    b"NOTRACK" => notrack_seen = true,
                    _ => {}
                }
                known_zero.fill(false);
                sets.fill(None);
            }
            _ => {
                notrack_seen |= name == b"notrack";
                known_zero.fill(false);
                sets.fill(None);
            }
        }
        Ok(())
    })?;
    Ok(notrack_seen)
}

fn nft_set_elements(bytes: &[u8]) -> io::Result<()> {
    attrs(required(bytes, 3)?, |kind, element| {
        if kind != 1 {
            return Err(invalid("invalid nft set element list"));
        }
        if let Some(flags) = attr_value(element, 3)?
            && be32(flags)? & 1 != 0
        {
            return Ok(());
        }
        let data = required(element, 2)?;
        let value = required(data, 1)?;
        if value.is_empty() || value.iter().any(|&byte| byte != 0) {
            return Err(invalid("nonzero or unproven nft set zone"));
        }
        Ok(())
    })
}

fn legacy_table(ipv6: bool, budget: &Arc<MemoryBudget>) -> io::Result<bool> {
    let family = if ipv6 { libc::AF_INET6 } else { libc::AF_INET };
    let level = if ipv6 {
        libc::IPPROTO_IPV6
    } else {
        libc::IPPROTO_IP
    };
    // SAFETY: socket takes integer arguments and returns a new descriptor.
    let raw = unsafe {
        libc::socket(
            family,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly created, valid descriptor owned only here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut info = [0u8; 84];
    info[..4].copy_from_slice(b"raw\0");
    let mut len = info.len() as libc::socklen_t;
    // SAFETY: info and len are writable for the exact lengths passed.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            64,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        // ENOPROTOOPT is nf_sockopt_find's result when no legacy handler exists.
        if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ENOPROTOOPT)) {
            return Ok(false);
        }
        return Err(error);
    }
    if len as usize != info.len() {
        return Err(invalid("invalid legacy table info"));
    }
    let count = u32::from_ne_bytes([info[76], info[77], info[78], info[79]]);
    let size = u32::from_ne_bytes([info[80], info[81], info[82], info[83]]) as usize;
    if size > 32 * 1024 * 1024 {
        return Err(invalid("legacy table too large"));
    }
    let _memory = reserve_scan(budget, 40 + size)?;
    let mut entries = vec![0u8; 40 + size];
    entries[..4].copy_from_slice(b"raw\0");
    entries[32..36].copy_from_slice(&(size as u32).to_ne_bytes());
    let mut len = entries.len() as libc::socklen_t;
    // SAFETY: entries and len are writable for the exact lengths passed.
    let result = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            level,
            65,
            entries.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != entries.len() {
        return Err(invalid("truncated legacy table"));
    }
    legacy_entries(&entries[40..], ipv6, count)
}

fn netfilter_socket(groups: u32, nonblocking: bool) -> io::Result<OwnedFd> {
    let flags =
        libc::SOCK_RAW | libc::SOCK_CLOEXEC | if nonblocking { libc::SOCK_NONBLOCK } else { 0 };
    // SAFETY: socket takes integer arguments and returns a new descriptor.
    let raw = unsafe { libc::socket(libc::AF_NETLINK, flags, 12) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is a newly created, valid descriptor owned only here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: zero is valid for sockaddr_nl, including its reserved bytes.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as u16;
    addr.nl_groups = groups;
    // SAFETY: addr is initialized and readable for its supplied size.
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&addr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: timeout is initialized and readable for its supplied size.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of_val(&timeout) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn receive(fd: &OwnedFd, nonblocking: bool) -> io::Result<Option<Vec<u8>>> {
    let mut bytes = vec![0u8; 1024 * 1024];
    // SAFETY: zero is valid for sockaddr_nl, including its reserved bytes.
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: zero initializes absent ancillary fields and null pointers.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = (&mut addr as *mut libc::sockaddr_nl).cast();
    msg.msg_namelen = std::mem::size_of_val(&addr) as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: msg points to live, writable addr, iov and bytes storage.
    let n = unsafe {
        libc::recvmsg(
            fd.as_raw_fd(),
            &mut msg,
            if nonblocking { libc::MSG_DONTWAIT } else { 0 },
        )
    };
    if n < 0 {
        let error = io::Error::last_os_error();
        if nonblocking && error.kind() == io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(error);
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 || addr.nl_pid != 0 || n == 0 {
        return Err(invalid("lost or invalid netfilter datagram"));
    }
    bytes.truncate(n as usize);
    Ok(Some(bytes))
}

fn messages(
    mut bytes: &[u8],
    mut visit: impl FnMut(u16, u16, u32, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 16 {
            return Err(invalid("truncated netlink message"));
        }
        let len = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if len < 16 || len > bytes.len() {
            return Err(invalid("invalid netlink message length"));
        }
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        let flags = u16::from_ne_bytes([bytes[6], bytes[7]]);
        let seq = u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        visit(kind, flags, seq, &bytes[16..len])?;
        let aligned = (len + 3) & !3;
        if aligned > bytes.len() {
            return Err(invalid("truncated netlink message padding"));
        }
        bytes = &bytes[aligned..];
    }
    Ok(())
}

fn put_attr(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = value.len() + 4;
    bytes.extend_from_slice(&(len as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize((bytes.len() + 3) & !3, 0);
}

fn reserve_scan(budget: &Arc<MemoryBudget>, bytes: usize) -> io::Result<MemoryReservation> {
    budget
        .reserve(bytes)
        .ok_or_else(|| io::Error::other("zone scan memory capacity"))
}

struct NetfilterReplies {
    entries: Vec<(u8, Vec<u8>, MemoryReservation)>,
    _memory: Option<MemoryReservation>,
}

impl NetfilterReplies {
    fn push(&mut self, budget: &Arc<MemoryBudget>, family: u8, bytes: &[u8]) -> io::Result<()> {
        let memory = reserve_scan(budget, bytes.len())?;
        if self.entries.len() == self.entries.capacity() {
            let capacity = self.entries.capacity().max(4) * 2;
            let storage = reserve_scan(
                budget,
                capacity * std::mem::size_of::<(u8, Vec<u8>, MemoryReservation)>(),
            )?;
            self.entries
                .try_reserve_exact(capacity - self.entries.len())
                .map_err(io::Error::other)?;
            self._memory = Some(storage);
        }
        self.entries.push((family, bytes.to_vec(), memory));
        Ok(())
    }
}

struct Netfilter {
    fd: OwnedFd,
    sequence: u32,
    budget: Arc<MemoryBudget>,
}

impl Netfilter {
    fn open(budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        Ok(Self {
            fd: netfilter_socket(0, false)?,
            sequence: 0,
            budget: Arc::clone(budget),
        })
    }

    fn request(
        &mut self,
        kind: u16,
        family: u8,
        dump: bool,
        attributes: &[(u16, &[u8])],
    ) -> io::Result<NetfilterReplies> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("netfilter sequence exhausted"))?;
        let request_len = 20
            + attributes
                .iter()
                .map(|(_, value)| (value.len() + 7) & !3)
                .sum::<usize>();
        let _request_memory = reserve_scan(&self.budget, request_len)?;
        let mut request = Vec::with_capacity(request_len);
        request.resize(20, 0);
        request[4..6].copy_from_slice(&kind.to_ne_bytes());
        request[6..8].copy_from_slice(&(1u16 | if dump { 0x300 } else { 0 }).to_ne_bytes());
        request[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        request[16] = family;
        for &(kind, value) in attributes {
            put_attr(&mut request, kind, value);
        }
        let len = request.len() as u32;
        request[..4].copy_from_slice(&len.to_ne_bytes());
        // SAFETY: zero is valid for sockaddr_nl, including its reserved bytes.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: request and addr are initialized and readable for their lengths.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                (&addr as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&addr) as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if sent as usize != request.len() {
            return Err(invalid("short netfilter request"));
        }
        let mut out = NetfilterReplies {
            entries: Vec::new(),
            _memory: None,
        };
        let mut total = 0usize;
        let mut done = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !done {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "netfilter dump deadline",
                ));
            }
            let bytes =
                receive(&self.fd, false)?.ok_or_else(|| invalid("missing netfilter reply"))?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| invalid("netfilter dump too large"))?;
            if total > 32 * 1024 * 1024 {
                return Err(invalid("netfilter dump too large"));
            }
            messages(&bytes, |msg_type, flags, seq, payload| {
                if seq != self.sequence || done {
                    return Err(invalid("unexpected netfilter reply"));
                }
                if flags & 0x10 != 0 {
                    return Err(invalid("interrupted netfilter dump"));
                }
                match msg_type {
                    2 => {
                        if payload.len() < 4 {
                            return Err(invalid("short netfilter error"));
                        }
                        let error =
                            i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        if error != 0 {
                            return Err(io::Error::from_raw_os_error(-error));
                        }
                        done = true;
                    }
                    3 => {
                        if payload.len() >= 4 {
                            let error = i32::from_ne_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]);
                            if error != 0 {
                                return Err(io::Error::from_raw_os_error(-error));
                            }
                        }
                        done = true;
                    }
                    _ => {
                        if payload.len() < 4 || msg_type >> 8 != kind >> 8 {
                            return Err(invalid("invalid netfilter reply"));
                        }
                        out.push(&self.budget, payload[0], &payload[4..])?;
                        if !dump && flags & 2 == 0 {
                            done = true;
                        }
                    }
                }
                Ok(())
            })?;
        }
        Ok(out)
    }
}

fn generation(net: &mut Netfilter) -> io::Result<u32> {
    let replies = net.request((10 << 8) | 16, 0, false, &[])?;
    if replies.entries.len() != 1 {
        return Err(invalid("invalid nft generation reply"));
    }
    be32(required(&replies.entries[0].1, 1)?)
}

fn nft_inventory(net: &mut Netfilter) -> io::Result<bool> {
    let mut notrack_seen = false;
    for _ in 0..3 {
        let before = generation(net)?;
        for operation in [1u16, 4, 10] {
            let replies = net.request((10 << 8) | operation, 0, true, &[])?;
            for (_, item, _) in &replies.entries {
                attrs(item, |_, _| Ok(()))?;
            }
        }
        let rules = net.request((10 << 8) | 7, 0, true, &[])?;
        for (family, rule, _) in &rules.entries {
            let table = required(rule, 1)?;
            nft_string(table)?;
            notrack_seen |= nft_rule(rule, |set| {
                let _name_memory = reserve_scan(&net.budget, set.len() + 1)?;
                let mut name = Vec::with_capacity(set.len() + 1);
                name.extend_from_slice(set);
                name.push(0);
                let definitions =
                    net.request((10 << 8) | 10, *family, false, &[(1, table), (2, &name)])?;
                if definitions.entries.len() != 1 {
                    return Err(invalid("missing referenced nft set"));
                }
                let definition = &definitions.entries[0].1;
                if be32(required(definition, 3)?)? & 0x120 != 0 {
                    return Err(invalid("packet-updated nft zone map is not provably zero"));
                }
                if be32(required(definition, 7)?)? != 2 {
                    return Err(invalid("nft zone map has unexpected value width"));
                }
                let elements =
                    net.request((10 << 8) | 13, *family, true, &[(1, table), (2, &name)])?;
                for (_, elements, _) in &elements.entries {
                    nft_set_elements(elements)?;
                }
                Ok(())
            })?;
        }
        if before == generation(net)? {
            return Ok(notrack_seen);
        }
    }
    Err(invalid("nft ruleset changed during zone inventory"))
}

pub(crate) struct ZoneAdmission {
    notifications: OwnedFd,
    observe_notrack: bool,
    notrack_seen: bool,
}

impl ZoneAdmission {
    pub(crate) fn read(budget: &Arc<MemoryBudget>, observe_notrack: bool) -> io::Result<Self> {
        let _receive_memory = reserve_scan(budget, 1024 * 1024)?;
        let notifications = netfilter_socket(1 << 6, true)?;
        let mut net = Netfilter::open(budget)?;
        for (subsystem, expectation) in [(1u16, false), (2u16, true)] {
            let entries = net.request((subsystem << 8) | 1, 0, true, &[])?;
            for (_, entry, _) in &entries.entries {
                conntrack_zones(entry, expectation)?;
            }
        }
        let notrack_seen =
            legacy_table(false, budget)? | legacy_table(true, budget)? | nft_inventory(&mut net)?;
        Ok(Self {
            notifications,
            observe_notrack,
            notrack_seen: observe_notrack && notrack_seen,
        })
    }

    pub(crate) fn revalidate(&mut self, budget: &Arc<MemoryBudget>) -> io::Result<()> {
        let _receive_memory = reserve_scan(budget, 1024 * 1024)?;
        let mut total = 0usize;
        while let Some(bytes) = receive(&self.notifications, true)? {
            total += bytes.len();
            if total > 32 * 1024 * 1024 {
                return Err(invalid("nft notification backlog too large"));
            }
            messages(&bytes, |kind, _, _, payload| {
                if kind >> 8 != 10 || payload.len() < 4 {
                    return Err(invalid("invalid nft notification"));
                }
                let attributes = &payload[4..];
                attrs(attributes, |_, _| Ok(()))?;
                if self.observe_notrack && !self.notrack_seen && kind == (10 << 8) | 6 {
                    // A committed new rule may have been removed before the inventory dump.
                    // Only the current inventory can reject the gateway on its zone checks.
                    self.notrack_seen = nft_rule(attributes, |_| Ok(())).unwrap_or(true);
                }
                Ok(())
            })?;
        }
        let nft_notrack = nft_inventory(&mut Netfilter::open(budget)?)?;
        if self.observe_notrack && !self.notrack_seen {
            // Legacy tables have no nft notifications. Runtime failures here leave DNS
            // without an absence proof. Legacy zone validation is mandatory at startup.
            self.notrack_seen = nft_notrack
                || legacy_table(false, budget).unwrap_or(true)
                || legacy_table(true, budget).unwrap_or(true);
        }
        Ok(())
    }

    pub(crate) fn notrack_seen(&self) -> bool {
        self.notrack_seen
    }
}

impl AsFd for ZoneAdmission {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.notifications.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_dump_memory_is_charged_until_replies_drop() {
        let storage = 8 * std::mem::size_of::<(u8, Vec<u8>, MemoryReservation)>();
        let budget = MemoryBudget::new(storage + 3);
        let mut replies = NetfilterReplies {
            entries: Vec::new(),
            _memory: None,
        };
        replies.push(&budget, 2, b"abc").unwrap();
        assert_eq!(budget.used(), storage + 3);
        assert!(replies.push(&budget, 2, b"x").is_err());
        drop(replies);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn zone_scan_rejects_missing_receive_budget() {
        let budget = MemoryBudget::new(0);
        assert_eq!(
            ZoneAdmission::read(&budget, true)
                .err()
                .unwrap()
                .to_string(),
            "zone scan memory capacity"
        );
        let mut admission = ZoneAdmission {
            notifications: std::fs::File::open("/dev/null").unwrap().into(),
            observe_notrack: true,
            notrack_seen: false,
        };
        assert_eq!(
            admission.revalidate(&budget).unwrap_err().to_string(),
            "zone scan memory capacity"
        );
        assert_eq!(budget.used(), 0);
    }

    fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() + 4;
        let mut result = Vec::new();
        result.extend_from_slice(&(len as u16).to_ne_bytes());
        result.extend_from_slice(&kind.to_ne_bytes());
        result.extend_from_slice(payload);
        result.resize((len + 3) & !3, 0);
        result
    }

    #[test]
    fn conntrack_and_expectation_reject_nonzero_zone() {
        assert!(conntrack_zones(&attr(18, &[0, 0]), false).is_ok());
        assert!(conntrack_zones(&attr(18, &[0, 1]), false).is_err());
        assert!(conntrack_zones(&attr(2, &attr(3, &[0, 1])), false).is_err());
        assert!(conntrack_zones(&attr(7, &[0, 1]), true).is_err());
        assert!(conntrack_zones(&attr(1, &attr(3, &[0, 1])), true).is_err());
    }

    fn expression(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut named = name.to_vec();
        named.push(0);
        let mut expression = attr(1, &named);
        expression.extend(attr(2, data));
        attr(1, &expression)
    }

    fn rule(zone: u8) -> Vec<u8> {
        let mut immediate = attr(1, &1u32.to_be_bytes());
        immediate.extend(attr(2, &attr(1, &[0, zone])));
        let mut ct = attr(2, &17u32.to_be_bytes());
        ct.extend(attr(4, &1u32.to_be_bytes()));
        let mut expressions = expression(b"immediate", &immediate);
        expressions.extend(expression(b"ct", &ct));
        attr(4, &expressions)
    }

    #[test]
    fn nft_zone_constants_and_map_values_are_checked() {
        assert!(!nft_rule(&rule(0), |_| Ok(())).unwrap());
        assert!(nft_rule(&rule(1), |_| Ok(())).is_err());
        let element = |zone| attr(3, &attr(1, &attr(2, &attr(1, &[0, zone]))));
        assert!(nft_set_elements(&element(0)).is_ok());
        assert!(nft_set_elements(&element(1)).is_err());
    }

    #[test]
    fn nft_notrack_is_reported_without_masking_zone_errors() {
        let native = attr(1, &attr(1, b"notrack\0"));
        let xt_ct = |revision: u32, size: usize, flags: u16, zone: u16| {
            let mut data = attr(1, b"CT\0");
            data.extend(attr(2, &revision.to_be_bytes()));
            let mut info = [0; 72];
            info[..2].copy_from_slice(&flags.to_ne_bytes());
            info[2..4].copy_from_slice(&zone.to_ne_bytes());
            data.extend(attr(3, &info[..size]));
            expression(b"target", &data)
        };
        for expr in [
            native.clone(),
            expression(b"notrack", &[]),
            expression(b"target", &attr(1, b"NOTRACK\0")),
            xt_ct(0, 40, 1, 0),
            xt_ct(1, 72, 2, 0),
            xt_ct(2, 72, 3, 0),
            xt_ct(2, 64, 3, 0),
        ] {
            assert!(nft_rule(&attr(4, &expr), |_| Ok(())).unwrap());
        }
        assert!(!nft_rule(&attr(4, &xt_ct(2, 72, 0, 0)), |_| Ok(())).unwrap());
        for (expr, expected) in [
            (xt_ct(2, 72, 3, 7), "nonzero or dynamic xt CT target zone"),
            (
                xt_ct(2, 72, 0x13, 0),
                "nonzero or dynamic xt CT target zone",
            ),
            (xt_ct(3, 72, 3, 0), "unknown xt CT target revision"),
            (xt_ct(2, 63, 3, 0), "truncated xt CT target info"),
        ] {
            assert_eq!(
                nft_rule(&attr(4, &expr), |_| Ok(()))
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
        let mut expressions = native.clone();
        expressions.extend(required(&rule(7), 4).unwrap());
        assert_eq!(
            nft_rule(&attr(4, &expressions), |_| Ok(()))
                .unwrap_err()
                .to_string(),
            "nonzero or unproven nft CT zone"
        );
        let mut expressions = native;
        expressions.extend(attr(2, &[]));
        assert_eq!(
            nft_rule(&attr(4, &expressions), |_| Ok(()))
                .unwrap_err()
                .to_string(),
            "invalid nft expression list"
        );
    }

    #[test]
    fn nft_short_immediate_is_allowed_unless_used_as_zone() {
        let mut immediate = attr(1, &1u32.to_be_bytes());
        immediate.extend(attr(2, &attr(1, &[0])));
        let mut expressions = expression(b"immediate", &immediate);
        assert!(nft_rule(&attr(4, &expressions), |_| Ok(())).is_ok());
        let mut ct = attr(2, &17u32.to_be_bytes());
        ct.extend(attr(4, &1u32.to_be_bytes()));
        expressions.extend(expression(b"ct", &ct));
        assert!(nft_rule(&attr(4, &expressions), |_| Ok(())).is_err());
    }

    #[test]
    fn nft_zone_map_is_resolved_and_unknown_source_rejected() {
        let mut lookup = attr(1, b"zones\0");
        lookup.extend(attr(2, &1u32.to_be_bytes()));
        lookup.extend(attr(3, &1u32.to_be_bytes()));
        let mut ct = attr(2, &17u32.to_be_bytes());
        ct.extend(attr(4, &1u32.to_be_bytes()));
        let mut expressions = expression(b"lookup", &lookup);
        expressions.extend(expression(b"ct", &ct));
        let rule = attr(4, &expressions);
        let mut resolved = false;
        assert!(
            nft_rule(&rule, |name| {
                assert_eq!(name, b"zones");
                resolved = true;
                Ok(())
            })
            .is_ok()
        );
        assert!(resolved);
        assert!(nft_rule(&rule, |_| Err(invalid("nonzero set element"))).is_err());
        assert!(nft_rule(&attr(4, &expression(b"ct", &ct)), |_| Ok(())).is_err());
    }

    #[test]
    fn legacy_ct_zone_and_mark_are_rejected() {
        for (ipv6, field, size) in [(false, 88, 112), (true, 140, 168)] {
            let entry = |target_size: u16, revision, name: &[u8]| {
                let next = (size as u16 + target_size).to_ne_bytes();
                let mut entry = vec![0; size + usize::from(target_size)];
                entry[field..field + 2].copy_from_slice(&(size as u16).to_ne_bytes());
                entry[field + 2..field + 4].copy_from_slice(&next);
                entry[size..size + 2].copy_from_slice(&target_size.to_ne_bytes());
                entry[size + 2..size + 2 + name.len()].copy_from_slice(name);
                entry[size + 31] = revision;
                entry
            };
            let notrack = entry(32, 0, b"NOTRACK");
            assert!(legacy_entries(&notrack, ipv6, 1).unwrap());

            for (revision, target_size) in [(0, 72), (1, 104), (2, 104)] {
                let mut ct = entry(target_size, revision, b"CT");
                assert!(!legacy_entries(&ct, ipv6, 1).unwrap());
                for flags in [1u16, 2, 3] {
                    ct[size + 32..size + 34].copy_from_slice(&flags.to_ne_bytes());
                    assert!(legacy_entries(&ct, ipv6, 1).unwrap());
                }
                ct[size + 34..size + 36].copy_from_slice(&1u16.to_ne_bytes());
                assert_eq!(
                    legacy_entries(&ct, ipv6, 1).unwrap_err().to_string(),
                    "nonzero or dynamic xt CT target zone"
                );
                let mut rules = notrack.clone();
                rules.extend_from_slice(&ct);
                assert!(legacy_entries(&rules, ipv6, 2).is_err());
                ct[size + 34..size + 36].fill(0);
                ct[size + 32..size + 34].copy_from_slice(&0x13u16.to_ne_bytes());
                assert_eq!(
                    legacy_entries(&ct, ipv6, 1).unwrap_err().to_string(),
                    "nonzero or dynamic xt CT target zone"
                );
            }
            assert_eq!(
                legacy_entries(&entry(104, 3, b"CT"), ipv6, 1)
                    .unwrap_err()
                    .to_string(),
                "unknown xt CT target revision"
            );
            assert_eq!(
                legacy_entries(&entry(103, 2, b"CT"), ipv6, 1)
                    .unwrap_err()
                    .to_string(),
                "truncated xt CT target info"
            );
        }
    }

    fn fixture_command(program: &str, arguments: &[&str]) -> io::Result<()> {
        let output = std::process::Command::new(program)
            .args(arguments)
            .output()
            .map_err(|error| {
                io::Error::other(format!(
                    "NOT_EXERCISED: {program} fixture unavailable: {error}"
                ))
            })?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "NOT_EXERCISED: {program} {arguments:?}: {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr),
            )));
        }
        Ok(())
    }

    struct ZoneFixture {
        table: String,
        nft: bool,
        legacy_chain: bool,
        legacy_jump: bool,
    }

    impl ZoneFixture {
        fn remove_nft(&mut self) -> io::Result<()> {
            if self.nft {
                fixture_command("nft", &["delete", "table", "inet", &self.table])?;
                self.nft = false;
            }
            Ok(())
        }

        fn cleanup(&mut self) -> io::Result<()> {
            self.remove_nft()?;
            if self.legacy_jump {
                fixture_command(
                    "iptables-legacy",
                    &[
                        "-w",
                        "2",
                        "-t",
                        "raw",
                        "-D",
                        "PREROUTING",
                        "-j",
                        "HONK_ZONE_TEST",
                    ],
                )?;
                self.legacy_jump = false;
            }
            if self.legacy_chain {
                fixture_command(
                    "iptables-legacy",
                    &["-w", "2", "-t", "raw", "-F", "HONK_ZONE_TEST"],
                )?;
                fixture_command(
                    "iptables-legacy",
                    &["-w", "2", "-t", "raw", "-X", "HONK_ZONE_TEST"],
                )?;
                self.legacy_chain = false;
            }
            Ok(())
        }
    }

    impl Drop for ZoneFixture {
        fn drop(&mut self) {
            // The private network namespace also dies with this fixture's thread.
            if let Err(error) = self.cleanup() {
                eprintln!("zone fixture cleanup failed: {error}");
            }
        }
    }

    #[test]
    #[ignore = "requires disposable kernel VM, root, nft and iptables-legacy"]
    fn kernel_gateway_zone_startup_refuses_nft_and_legacy() -> io::Result<()> {
        let expected = std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap_or_default();
        // SAFETY: geteuid has no arguments or memory preconditions.
        let root = unsafe { libc::geteuid() } == 0;
        assert!(
            std::env::var_os("HONK_CI_VM_LANE").is_some()
                && !expected.is_empty()
                && std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim() == expected
                && root,
            "NOT_EXERCISED: zone fixture requires the disposable kernel VM gate and root",
        );
        std::thread::spawn(|| -> io::Result<()> {
            let original = std::fs::read_link("/proc/thread-self/ns/net")?;
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).map_err(|error| {
                io::Error::other(format!("NOT_EXERCISED: private netns: {error}"))
            })?;
            assert_ne!(
                original,
                std::fs::read_link("/proc/thread-self/ns/net")?,
                "NOT_EXERCISED: private netns not established"
            );
            fixture_command("nft", &["--version"])?;
            fixture_command("iptables-legacy", &["--version"])?;
            let mut fixture = ZoneFixture {
                table: format!("honk_zone_test_{}", std::process::id()),
                nft: false,
                legacy_chain: false,
                legacy_jump: false,
            };
            let budget = MemoryBudget::new(128 * 1024 * 1024);
            let mut admission = ZoneAdmission::read(&budget, true).map_err(|error| {
                io::Error::other(format!("NOT_EXERCISED: clean zone admission: {error}"))
            })?;
            assert!(!admission.notrack_seen());
            fixture_command("nft", &["add", "table", "inet", &fixture.table])?;
            fixture.nft = true;
            fixture_command(
                "nft",
                &[
                    "add",
                    "chain",
                    "inet",
                    &fixture.table,
                    "raw",
                    "{ type filter hook prerouting priority -300; policy accept; }",
                ],
            )?;
            fixture_command(
                "nft",
                &["add", "rule", "inet", &fixture.table, "raw", "notrack"],
            )?;
            assert!(ZoneAdmission::read(&budget, true)?.notrack_seen());
            assert!(!ZoneAdmission::read(&budget, false)?.notrack_seen());
            fixture_command("nft", &["flush", "chain", "inet", &fixture.table, "raw"])?;
            admission.revalidate(&budget)?;
            assert!(admission.notrack_seen());
            fixture_command(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    &fixture.table,
                    "raw",
                    "ct",
                    "zone",
                    "set",
                    "7",
                ],
            )?;
            assert!(
                ZoneAdmission::read(&budget, true).is_err(),
                "startup admitted nft zone 7"
            );
            assert!(
                admission.revalidate(&budget).is_err(),
                "runtime admitted nft zone 7"
            );
            fixture.remove_nft()?;
            admission.revalidate(&budget)?;
            let mut admission = ZoneAdmission::read(&budget, true)?;
            assert!(!admission.notrack_seen());
            fixture_command(
                "iptables-legacy",
                &["-w", "2", "-t", "raw", "-N", "HONK_ZONE_TEST"],
            )?;
            fixture.legacy_chain = true;
            fixture_command(
                "iptables-legacy",
                &[
                    "-w",
                    "2",
                    "-t",
                    "raw",
                    "-A",
                    "PREROUTING",
                    "-j",
                    "HONK_ZONE_TEST",
                ],
            )?;
            fixture.legacy_jump = true;
            fixture_command(
                "iptables-legacy",
                &[
                    "-w",
                    "2",
                    "-t",
                    "raw",
                    "-A",
                    "HONK_ZONE_TEST",
                    "-j",
                    "CT",
                    "--zone",
                    "7",
                ],
            )?;
            assert!(
                ZoneAdmission::read(&budget, true).is_err(),
                "startup admitted legacy zone 7"
            );
            admission
                .revalidate(&budget)
                .expect("legacy runtime edits must not trigger nft rejection");
            assert!(admission.notrack_seen());
            fixture_command(
                "iptables-legacy",
                &["-w", "2", "-t", "raw", "-F", "HONK_ZONE_TEST"],
            )?;
            admission.revalidate(&budget)?;
            assert!(admission.notrack_seen());
            let mut admission = ZoneAdmission::read(&budget, true)?;
            assert!(!admission.notrack_seen());
            fixture_command(
                "iptables-legacy",
                &[
                    "-w",
                    "2",
                    "-t",
                    "raw",
                    "-A",
                    "HONK_ZONE_TEST",
                    "-j",
                    "CT",
                    "--notrack",
                ],
            )?;
            assert!(ZoneAdmission::read(&budget, true)?.notrack_seen());
            admission.revalidate(&budget)?;
            assert!(admission.notrack_seen());
            fixture.cleanup()?;
            admission.revalidate(&budget)?;
            assert!(admission.notrack_seen());
            let clean = ZoneAdmission::read(&budget, true).map_err(|error| {
                io::Error::other(format!(
                    "zone fixture cleanup left failed admission: {error}"
                ))
            })?;
            assert!(!clean.notrack_seen());
            Ok(())
        })
        .join()
        .map_err(|_| io::Error::other("zone admission fixture thread panicked"))?
    }
}

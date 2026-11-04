//! Owner `comm` of a host-originated socket, the TPROXY stand-in for the eBPF
//! datapath's socket-creation capture.
//!
//! `/proc/net/{tcp,udp}{,6}` names the socket inode and owner uid; only
//! processes of that uid are searched for the inode. A LAN client has no
//! local socket, so its lookup ends after the table scan.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::MetadataExt as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SocketEntry {
    pub(crate) uid: u32,
    pub(crate) inode: u64,
}

fn parse_address(text: &str) -> Option<SocketAddr> {
    let (ip, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    // The kernel prints each 32-bit word of the network-order address natively.
    let word = |chunk: &str| u32::from_str_radix(chunk, 16).map(u32::to_ne_bytes).ok();
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(ip)?)),
        32 => {
            let mut octets = [0u8; 16];
            for (index, bytes) in octets.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                *bytes = word(&ip[index * 8..index * 8 + 8])?;
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip.to_canonical(), port))
}

/// The table entry bound to `local` (or its wildcard) and, when given,
/// connected to `peer`.
pub(crate) fn find_entry(
    table: &str,
    local: SocketAddr,
    peer: Option<SocketAddr>,
) -> Option<SocketEntry> {
    let local = SocketAddr::new(local.ip().to_canonical(), local.port());
    let peer = peer.map(|peer| SocketAddr::new(peer.ip().to_canonical(), peer.port()));
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            return None;
        }
        let bound = parse_address(fields[1])?;
        // A wildcard-bound UDP socket sends from any local address.
        if bound.port() != local.port()
            || !(bound.ip() == local.ip() || bound.ip().is_unspecified())
        {
            return None;
        }
        if let Some(peer) = peer
            && parse_address(fields[2])? != peer
        {
            return None;
        }
        let inode = fields[9].parse().ok().filter(|inode| *inode != 0)?;
        Some(SocketEntry {
            uid: fields[7].parse().ok()?,
            inode,
        })
    })
}

fn owner_comm(entry: SocketEntry) -> Option<String> {
    let target = format!("socket:[{}]", entry.inode);
    for process in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = process.file_name();
        if !name
            .to_str()
            .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        {
            continue;
        }
        let path = process.path();
        if !std::fs::metadata(&path).is_ok_and(|metadata| metadata.uid() == entry.uid) {
            continue;
        }
        let Ok(descriptors) = std::fs::read_dir(path.join("fd")) else {
            continue;
        };
        let owns = descriptors.flatten().any(|descriptor| {
            std::fs::read_link(descriptor.path())
                .is_ok_and(|link| link.as_os_str() == target.as_str())
        });
        if owns {
            let comm = std::fs::read_to_string(path.join("comm")).ok()?;
            return Some(comm.trim_end_matches('\n').to_owned());
        }
    }
    None
}

/// `comm` of the local process owning the client socket, if it is local.
pub(crate) fn owner_name(protocol: &str, client: SocketAddr, server: SocketAddr) -> Option<String> {
    let (tables, peer) = match protocol {
        "tcp" => (["/proc/net/tcp", "/proc/net/tcp6"], Some(server)),
        // Unconnected UDP sockets have no peer in the table.
        "udp" => (["/proc/net/udp", "/proc/net/udp6"], None),
        _ => return None,
    };
    let entry = tables
        .iter()
        .find_map(|table| find_entry(&std::fs::read_to_string(table).ok()?, client, peer))?;
    owner_comm(entry)
}

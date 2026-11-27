use super::*;

#[test]
fn attr_alignment() {
    let mut buf = Vec::new();
    put_attr(&mut buf, IFLA_IFNAME, &Attr::Str("dae0".into()));
    // header 4 + payload 5 (with NUL) = 9 → aligned to 12
    assert_eq!(buf.len(), 12);
    assert_eq!(u16::from_ne_bytes([buf[0], buf[1]]), 9);
    assert_eq!(&buf[4..9], b"dae0\0");

    let mut buf = Vec::new();
    put_attr(&mut buf, RTA_OIF, &Attr::U32(7));
    assert_eq!(buf.len(), 8);
    assert_eq!(u32::from_ne_bytes([buf[4], buf[5], buf[6], buf[7]]), 7);
}

#[test]
fn nested_attr() {
    let mut buf = Vec::new();
    put_attr(
        &mut buf,
        IFLA_LINKINFO,
        &Attr::Nested(vec![
            (IFLA_INFO_KIND, Attr::Str("veth".into())),
            (IFLA_INFO_DATA, Attr::Bytes(vec![1, 2, 3])),
        ]),
    );
    let outer = u16::from_ne_bytes([buf[0], buf[1]]) as usize;
    assert_eq!(buf.len(), align(outer));
    assert!(outer > 4);
}

#[test]
fn netkit_fallback_is_only_for_missing_driver() {
    assert!(netkit_unavailable(&io::Error::from_raw_os_error(
        libc::EOPNOTSUPP
    )));
    assert!(!netkit_unavailable(&io::Error::from_raw_os_error(
        libc::EINVAL
    )));
    assert!(!netkit_unavailable(&io::Error::from_raw_os_error(
        libc::EPERM
    )));
}

#[test]
fn sock_open_close() {
    let _ = NlSock::new().expect("netlink socket");
}

#[test]
fn tproxy_mark_default_matches_datapath() {
    assert_eq!(
        honk_config::config::DEFAULT_TPROXY_MARK,
        honk_ebpf_common::TPROXY_MARK
    );
}

#[test]
fn get_link_lo() {
    let mut nl = NlSock::new().unwrap();
    let (idx, _mac) = nl.get_link("lo").expect("lo must exist");
    assert_eq!(idx, 1);
}

/// Whether daens is unavailable or the switch succeeds, the calling
/// thread must come back in its original namespace (P1a regression).
#[test]
fn netns_with_daens_restores_namespace() {
    let before = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
    let _ = crate::daens::with_daens_netns("test", || Ok(()));
    let after = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
    assert_eq!(before, after);
}

const RTM_GETRULE: u16 = 34;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_DONE: u16 = 3;

/// Dump (fwmark, fwmask, table) of every rule in the current namespace.
fn rule_dump(nl: &mut NlSock) -> io::Result<Vec<(u32, u32, u32)>> {
    nl.seq += 1;
    let seq = nl.seq;
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(&RTM_GETRULE.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&[0u8; 12]); // fib_rule_hdr
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
    nl.send_datagram(&buf)?;
    let mut out = Vec::new();
    let mut resp = vec![0u8; 8192];
    'outer: loop {
        let n = nl.recv_one(&mut resp)?;
        let mut off = 0usize;
        while off + 16 <= n {
            let hlen = u32::from_ne_bytes(resp[off..off + 4].try_into().unwrap()) as usize;
            let htype = u16::from_ne_bytes(resp[off + 4..off + 6].try_into().unwrap());
            let hflags = u16::from_ne_bytes(resp[off + 6..off + 8].try_into().unwrap());
            let hseq = u32::from_ne_bytes(resp[off + 8..off + 12].try_into().unwrap());
            if hlen < 16 || off + hlen > n {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "malformed netlink message header",
                ));
            }
            if hseq == seq {
                if hflags & NLM_F_DUMP_INTR != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "rule dump interrupted by table change",
                    ));
                }
                match htype {
                    NLMSG_DONE => break 'outer,
                    NLMSG_ERROR => {
                        if hlen < 20 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "short NLMSG_ERROR",
                            ));
                        }
                        let err = i32::from_ne_bytes(resp[off + 16..off + 20].try_into().unwrap());
                        if err != 0 {
                            return Err(io::Error::from_raw_os_error(-err));
                        }
                        break 'outer;
                    }
                    RTM_NEWRULE if hlen >= 16 + 12 => {
                        let hdr = &resp[off + 16..off + hlen];
                        let mut table = u32::from(hdr[4]);
                        let mut mark = 0u32;
                        let mut mask = 0u32;
                        let mut aoff = 12;
                        while aoff + 4 <= hdr.len() {
                            let alen = u16::from_ne_bytes(hdr[aoff..aoff + 2].try_into().unwrap())
                                as usize;
                            let atype =
                                u16::from_ne_bytes(hdr[aoff + 2..aoff + 4].try_into().unwrap());
                            if alen < 4 || aoff + alen > hdr.len() {
                                break;
                            }
                            let payload = &hdr[aoff + 4..aoff + alen];
                            if payload.len() == 4 {
                                let v = u32::from_ne_bytes(payload.try_into().unwrap());
                                match atype {
                                    FRA_FWMARK => mark = v,
                                    FRA_FWMASK => mask = v,
                                    FRA_TABLE => table = v,
                                    _ => {}
                                }
                            }
                            aoff += align(alen);
                        }
                        out.push((mark, mask, table));
                    }
                    _ => {}
                }
            }
            let next = align(hlen);
            if next == 0 {
                break;
            }
            off += next;
        }
    }
    Ok(out)
}

/// Root-only roundtrip over every NlSock op the engine uses. Run with:
/// `just test-netns`.
#[test]
#[ignore = "requires root; run via just test-netns"]
fn netns_link_addr_route_rule_neigh_roundtrip() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: requires root");
        return;
    }
    const MARK: u32 = 0x0800_0099;
    const TABLE: u32 = 100;
    const DNS_MASK: u32 = !honk_ebpf_common::DNS_ROUTE_MARK_MASK;
    let mut nl = NlSock::new().unwrap();
    // Idempotent start: drop leftovers from an interrupted earlier run.
    let _ = nl.del_rule_fwmark(FAM_V4, MARK, u32::MAX, TABLE);
    let _ = nl.del_rule_fwmark(FAM_V4, MARK, DNS_MASK, TABLE);
    if let Ok((idx, _)) = nl.get_link("honkt0") {
        let _ = nl.del_link(idx);
    }
    let peer_ns = std::thread::spawn(|| -> io::Result<OwnedFd> {
        nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET).map_err(io::Error::from)?;
        std::fs::File::open("/proc/thread-self/ns/net").map(OwnedFd::from)
    })
    .join()
    .unwrap()
    .unwrap();

    let result = (|| -> io::Result<()> {
        let kind = nl.add_link_pair("honkt0", "honkt1")?;
        eprintln!("created {kind:?} link pair");
        let (idx, _mac) = nl.get_link("honkt0")?;
        nl.set_link_up(idx, true)?;
        let (peer_idx, _) = nl.get_link("honkt1")?;
        nl.set_link_up(peer_idx, true)?;
        nl.set_link_netns_fd(peer_idx, &peer_ns)?;
        nl.addr_op(true, idx, FAM_V4, &[10, 254, 99, 1], 32)?;
        nl.add_route(
            FAM_V4,
            TABLE,
            ROUTE_UNICAST,
            SCOPE_LINK,
            PROTO_STATIC,
            Some((&[198, 51, 100, 0], 24)),
            None,
            Some(idx),
        )?;
        nl.add_rule_fwmark(FAM_V4, MARK, u32::MAX, TABLE)?;
        let rules = rule_dump(&mut nl)?;
        assert!(
            rules.contains(&(MARK, u32::MAX, TABLE)),
            "fwmark rule with full mask missing from dump: {rules:?}"
        );
        nl.add_rule_fwmark(FAM_V4, MARK, DNS_MASK, TABLE)?;
        assert!(rule_dump(&mut nl)?.contains(&(MARK, DNS_MASK, TABLE)));
        nl.del_rule_fwmark(FAM_V4, MARK, DNS_MASK, TABLE)?;
        let rules = rule_dump(&mut nl)?;
        assert!(rules.contains(&(MARK, u32::MAX, TABLE)));
        assert!(!rules.contains(&(MARK, DNS_MASK, TABLE)));
        nl.neigh_replace(idx, FAM_V4, &[198, 51, 100, 1], &[0x02, 0, 0, 0, 0, 1])?;
        Ok(())
    })();

    let _ = nl.del_rule_fwmark(FAM_V4, MARK, u32::MAX, TABLE);
    let _ = nl.del_rule_fwmark(FAM_V4, MARK, DNS_MASK, TABLE);
    if let Ok((idx, _)) = nl.get_link("honkt0") {
        let _ = nl.del_link(idx);
    }
    result.unwrap();
}

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

fn nla(ty: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align(out.len()), 0);
    out
}

fn nlmsg(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(body);
    out.resize(align(out.len()), 0);
    out
}

fn newlink(seq: u32, flags: u16, index: i32, arphrd: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&arphrd.to_ne_bytes());
    body.extend_from_slice(&index.to_ne_bytes());
    body.extend_from_slice(&0x1003u32.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    for attr in attrs {
        body.extend_from_slice(attr);
    }
    nlmsg(RTM_NEWLINK, flags, seq, &body)
}

fn cstr(text: &str) -> Vec<u8> {
    let mut bytes = text.as_bytes().to_vec();
    bytes.push(0);
    bytes
}

fn parse_all(buf: &[u8], seq: u32) -> io::Result<(bool, Vec<LinkSnapshot>)> {
    let mut links = Vec::new();
    parse_link_datagram(buf, seq, &mut links).map(|done| (done, links))
}

#[test]
fn link_dump_keeps_l3_link_without_mac() {
    let mut buf = newlink(7, 2, 5, 0xfffe, &[nla(IFLA_IFNAME, &cstr("wg0"))]);
    buf.extend(nlmsg(NLMSG_DONE, 2, 7, &0u32.to_ne_bytes()));
    let (done, links) = parse_all(&buf, 7).unwrap();
    assert!(done);
    assert_eq!(
        links,
        [LinkSnapshot {
            ifindex: NonZeroU32::new(5).unwrap(),
            name: "wg0".into(),
            arphrd: 0xfffe,
            flags: 0x1003,
            master: None,
            kind: None,
            mac: None,
        }]
    );
}

#[test]
fn link_dump_parses_master_kind_and_exact_mac() {
    let linkinfo = nla(IFLA_LINKINFO, &nla(IFLA_INFO_KIND, &cstr("bond")));
    let buf = newlink(
        3,
        2,
        9,
        ARPHRD_ETHER,
        &[
            nla(IFLA_IFNAME, &cstr("eth1")),
            nla(IFLA_MASTER, &4u32.to_ne_bytes()),
            nla(IFLA_ADDRESS, &[2, 0, 0, 0, 0, 1]),
            linkinfo,
        ],
    );
    let link = parse_all(&buf, 3).unwrap().1.remove(0);
    assert_eq!(link.master, NonZeroU32::new(4));
    assert_eq!(link.kind.as_deref(), Some("bond"));
    assert_eq!(link.mac, Some([2, 0, 0, 0, 0, 1]));

    // An IFLA_ADDRESS that is not 6 bytes (e.g. 8-byte tunnel address) is no MAC.
    let buf = newlink(
        3,
        2,
        9,
        ARPHRD_ETHER,
        &[nla(IFLA_IFNAME, &cstr("gre1")), nla(IFLA_ADDRESS, &[0; 4])],
    );
    assert_eq!(parse_all(&buf, 3).unwrap().1[0].mac, None);
}

#[test]
fn link_dump_interrupt_is_interrupted() {
    let buf = newlink(
        3,
        2 | NLM_F_DUMP_INTR,
        9,
        ARPHRD_ETHER,
        &[nla(IFLA_IFNAME, &cstr("eth0"))],
    );
    assert_eq!(
        parse_all(&buf, 3).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
    let done = nlmsg(NLMSG_DONE, 2 | NLM_F_DUMP_INTR, 3, &0u32.to_ne_bytes());
    assert_eq!(
        parse_all(&done, 3).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );
}

#[test]
fn link_dump_ignores_stale_sequence() {
    let buf = newlink(
        2,
        2 | NLM_F_DUMP_INTR,
        9,
        ARPHRD_ETHER,
        &[nla(IFLA_IFNAME, &cstr("eth0"))],
    );
    assert_eq!(parse_all(&buf, 3).unwrap(), (false, Vec::new()));
}

#[test]
fn link_dump_rejects_malformed_messages() {
    let name = nla(IFLA_IFNAME, &cstr("eth0"));
    let invalid = |buf: Vec<u8>| {
        assert_eq!(
            parse_all(&buf, 1).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        )
    };
    // attribute length overruns the message
    let mut truncated = name.clone();
    truncated[0..2].copy_from_slice(&40u16.to_ne_bytes());
    invalid(newlink(1, 2, 2, ARPHRD_ETHER, &[truncated]));
    // nested IFLA_INFO_KIND overruns IFLA_LINKINFO
    let mut kind = nla(IFLA_INFO_KIND, &cstr("bond"));
    kind[0..2].copy_from_slice(&40u16.to_ne_bytes());
    invalid(newlink(
        1,
        2,
        2,
        ARPHRD_ETHER,
        &[name.clone(), nla(IFLA_LINKINFO, &kind)],
    ));
    // wrong IFLA_MASTER width
    invalid(newlink(
        1,
        2,
        2,
        ARPHRD_ETHER,
        &[name.clone(), nla(IFLA_MASTER, &[1, 0])],
    ));
    // missing name, zero and negative index
    invalid(newlink(1, 2, 2, ARPHRD_ETHER, &[]));
    invalid(newlink(1, 2, 0, ARPHRD_ETHER, std::slice::from_ref(&name)));
    invalid(newlink(1, 2, -1, ARPHRD_ETHER, std::slice::from_ref(&name)));
    // ifinfomsg shorter than 16 bytes, and a header longer than the datagram
    invalid(nlmsg(RTM_NEWLINK, 2, 1, &[0; 8]));
    let mut long = newlink(1, 2, 2, ARPHRD_ETHER, &[name]);
    long.truncate(long.len() - 4);
    invalid(long);
}

#[test]
fn link_dump_kernel_error_is_os_error() {
    let buf = nlmsg(
        NLMSG_ERROR,
        0,
        1,
        &[(-libc::EPERM).to_ne_bytes(), [0; 4]].concat(),
    );
    assert_eq!(
        parse_all(&buf, 1).unwrap_err().raw_os_error(),
        Some(libc::EPERM)
    );
}

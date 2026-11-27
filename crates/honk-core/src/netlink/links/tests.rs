use super::*;

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

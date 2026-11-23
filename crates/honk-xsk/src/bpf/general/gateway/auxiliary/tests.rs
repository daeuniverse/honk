use super::*;

fn builder() -> GatewayBuilder {
    let mut b = GatewayBuilder::new();
    b.auxiliary = Some(Ingress {
        devices: -1,
        gate: -1,
        realms: -1,
        scratch: -1,
        realm: 1,
    });
    b
}

fn emit_quote(cursor: i32, available: i32) -> GatewayBuilder {
    let mut b = builder();
    let bad = b.target();
    let done = b.target();
    b.load(LDX_W, 7, 9, SKB_DATA_END);
    b.load(LDX_W, 0, 9, SKB_LEN);
    b.store(STX_W, 10, FULL_LEN, 0);
    b.imm(0, cursor);
    b.rebase_cursor(bad);
    b.word(QUOTE_AVAILABLE, available);
    parse_ip(
        &mut b,
        true,
        true,
        &[],
        &ParseTargets {
            bad,
            later: bad,
            done,
            pass: bad,
            drop: bad,
        },
    );
    b.bind(done);
    b.prefix(4, INNER_REMAIN, bad);
    b.load(LDX_H, 0, 6, 0);
    b.emit(BE16, 0, 0, 0, 16);
    b.emit(EXIT, 0, 0, 0, 0);
    b.bind(bad);
    b.imm(0, -1);
    b.emit(EXIT, 0, 0, 0, 0);
    b
}

fn run(
    b: &GatewayBuilder,
    packet: &[u8],
    mut linear: usize,
    extend: bool,
    gso_size: u32,
) -> (i32, Vec<usize>) {
    let mut frame = [0; 512];
    let mut registers = [0; 11];
    registers[10] = frame.len() as u64;
    registers[9] = 9;
    let mut base = 1024;
    let mut pulls = Vec::new();
    let mut pc = 0;
    loop {
        let i = b.program.insns[pc];
        let dst = usize::from(i.regs & 15);
        let src = usize::from(i.regs >> 4);
        let x = registers[dst];
        let y = registers[src];
        let k = i.imm as u64;
        let jump = match i.code {
            LDX_B | LDX_H | LDX_W => {
                registers[dst] = if src == 9 {
                    match i.off {
                        SKB_LEN => packet.len() as u64,
                        SKB_DATA => base,
                        SKB_DATA_END => base + linear as u64,
                        SKB_GSO_SIZE => u64::from(gso_size),
                        _ => panic!("unexpected skb read {i:?}"),
                    }
                } else {
                    let addr = y.checked_add_signed(i64::from(i.off)).unwrap();
                    let bytes = if src == 10 {
                        &frame[addr as usize..]
                    } else {
                        let at = addr.checked_sub(base).expect("invalidated packet pointer");
                        &packet[at as usize..linear]
                    };
                    match i.code {
                        LDX_B => u64::from(bytes[0]),
                        LDX_H => u64::from(u16::from_le_bytes(bytes[..2].try_into().unwrap())),
                        LDX_W => u64::from(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
                        _ => unreachable!(),
                    }
                };
                false
            }
            ST_DW => {
                assert_eq!(dst, 10);
                let at = x.checked_add_signed(i64::from(i.off)).unwrap() as usize;
                frame[at..at + 8].copy_from_slice(&k.to_le_bytes());
                false
            }
            ST_W | STX_W => {
                assert_eq!(dst, 10);
                let at = x.checked_add_signed(i64::from(i.off)).unwrap() as usize;
                let word = (if i.code == ST_W { k } else { y }) as u32;
                frame[at..at + 4].copy_from_slice(&word.to_le_bytes());
                false
            }
            CALL => {
                assert_eq!(i.imm, SKB_PULL_DATA);
                assert_eq!(registers[1], registers[9]);
                let needed = registers[2] as usize;
                assert!(needed > linear && needed <= packet.len());
                pulls.push(needed);
                if extend {
                    linear = needed;
                }
                base += 1024;
                registers[1..=5].fill(u64::MAX);
                registers[0] = 0;
                false
            }
            JEQ_K => x == k,
            JEQ32_K => x as u32 == k as u32,
            JNE_K => x != k,
            JGT_K => x > k,
            JGE_K => x >= k,
            JLT_K => x < k,
            JSET_K => x & k != 0,
            JNE_X => x != y,
            JGT_X => x > y,
            JLE_X => x <= y,
            JLT_X => x < y,
            JA => true,
            EXIT => return (registers[0] as i32, pulls),
            _ => {
                registers[dst] = match i.code {
                    MOV_K => k,
                    MOV_X => y,
                    ADD_K => x.wrapping_add(k),
                    AND_K => x & k,
                    LSH_K => x << k,
                    RSH_K => x >> k,
                    ADD_X => x + y,
                    SUB_X => x - y,
                    BE16 => u64::from((x as u16).to_be()),
                    _ => panic!("unexpected gateway test instruction {i:?}"),
                };
                false
            }
        };
        if jump {
            let target = b.jumps.iter().find(|(at, _)| *at == pc).unwrap().1;
            pc = b.labels[target.0].unwrap();
        } else {
            pc += 1;
        }
    }
}

#[test]
fn nonlinear_quote_pulls_only_required_ipv6_extension_and_port_prefixes() {
    let mut packet = [0u8; 116];
    let quote = &mut packet[64..];
    quote[0] = 0x60;
    quote[4..6].copy_from_slice(&1024u16.to_be_bytes());
    quote[40] = 17;
    quote[48..50].copy_from_slice(&443u16.to_be_bytes());
    let valid = emit_quote(64, 52);
    assert_eq!(run(&valid, &packet, 116, true, 0), (443, vec![]));
    assert_eq!(run(&valid, &packet, 104, true, 0), (443, vec![106, 116]));
    assert_eq!(run(&valid, &packet, 104, false, 0), (-1, vec![106]));
    assert_eq!(run(&valid, &packet[..115], 104, true, 0), (-1, vec![106]));
    let short_quote = emit_quote(64, 51);
    assert_eq!(run(&short_quote, &packet, 104, true, 0), (-1, vec![106]));
}

fn emit_ipv4(broadcasts: &[Ipv4Addr], verdict: i32) -> GatewayBuilder {
    let mut b = builder();
    let bad = b.target();
    let classified = b.target();
    let native = b.target();
    b.word(L2_LEN, 0);
    b.word(IS_QUOTE, 0);
    b.load(LDX_W, 7, 9, SKB_DATA_END);
    b.load(LDX_W, 0, 9, SKB_LEN);
    b.store(STX_W, 10, FULL_LEN, 0);
    parse_ip(
        &mut b,
        false,
        false,
        broadcasts,
        &ParseTargets {
            bad,
            later: classified,
            done: classified,
            pass: native,
            drop: bad,
        },
    );
    b.bind(classified);
    b.word(VERDICT, verdict);
    check_endpoint_gso(&mut b, bad);
    b.imm(0, verdict);
    b.emit(EXIT, 0, 0, 0, 0);
    b.bind(native);
    b.imm(0, VERDICT_PASS);
    b.emit(EXIT, 0, 0, 0, 0);
    b.bind(bad);
    b.imm(0, VERDICT_DROP);
    b.emit(EXIT, 0, 0, 0, 0);
    b
}

fn udp_ip(destination: [u8; 4]) -> [u8; 44] {
    let mut packet = [0; 44];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&44u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[198, 51, 100, 4]);
    packet[16..20].copy_from_slice(&destination);
    packet[24..26].copy_from_slice(&24u16.to_be_bytes());
    packet
}

#[test]
fn aux_udp_gso_uses_endpoint_representation_checks_only_for_endpoint() {
    let mut packet = udp_ip([192, 0, 2, 9]);
    let endpoint = emit_ipv4(&[], VERDICT_ENDPOINT);
    let native = emit_ipv4(&[], VERDICT_PASS);
    let len = packet.len();
    assert_eq!(run(&endpoint, &packet, len, true, 8).0, VERDICT_ENDPOINT);
    assert_eq!(run(&native, &packet, len, true, 8).0, VERDICT_PASS);
    assert_eq!(
        run(&endpoint, &packet, len, true, u32::from(u16::MAX)).0,
        VERDICT_DROP,
    );

    for fragment in [0x2000u16, 1] {
        packet[6..8].copy_from_slice(&fragment.to_be_bytes());
        assert_eq!(run(&endpoint, &packet, len, true, 8).0, VERDICT_DROP);
        assert_eq!(run(&native, &packet, len, true, 8).0, VERDICT_PASS);
        assert_eq!(run(&endpoint, &packet, len, true, 0).0, VERDICT_ENDPOINT);
    }
}

#[test]
fn aux_directed_broadcasts_use_the_supplied_snapshot() {
    let destination = [192, 0, 2, 63];
    let exact = emit_ipv4(&[destination.into()], VERDICT_ENDPOINT);
    let empty = emit_ipv4(&[], VERDICT_ENDPOINT);
    let packet = udp_ip(destination);
    assert_eq!(run(&exact, &packet, packet.len(), true, 0).0, VERDICT_PASS);
    assert_eq!(
        run(&empty, &packet, packet.len(), true, 0).0,
        VERDICT_ENDPOINT,
    );
    let packet = udp_ip([192, 0, 2, 255]);
    assert_eq!(
        run(&exact, &packet, packet.len(), true, 0).0,
        VERDICT_ENDPOINT,
    );
}

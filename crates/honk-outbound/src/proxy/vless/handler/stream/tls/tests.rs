use super::*;

fn record(record_type: u8, content: &[u8]) -> Vec<u8> {
    let mut record = vec![record_type, 3, 3];
    record.extend_from_slice(&(content.len() as u16).to_be_bytes());
    record.extend_from_slice(content);
    record
}

fn client_hello() -> Vec<u8> {
    let mut body = vec![HANDSHAKE_CLIENT_HELLO, 0, 0, 40];
    body.extend_from_slice(&[0x5a; 40]);
    record(RECORD_HANDSHAKE, &body)
}

fn server_hello(random: [u8; 32], cipher: u16, tls13: bool) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&[7; 32]);
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0);
    let mut extensions = vec![0x00, 0x33, 0x00, 0x04, 1, 2, 3, 4];
    if tls13 {
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 3, 4]);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let mut message = vec![HANDSHAKE_SERVER_HELLO, 0];
    message.extend_from_slice(&(body.len() as u16).to_be_bytes());
    message.extend_from_slice(&body);
    message
}

/// Drives `plan_uplink` the way the writer does: one frame per call.
fn frames(tls: &mut InnerTls, stream: &[u8], chunk: usize) -> Vec<UplinkFrame> {
    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < stream.len() {
        let end = (offset + chunk).min(stream.len());
        let frame = tls.plan_uplink(&stream[offset..end], true);
        assert!(frame.take > 0);
        offset += frame.take;
        frames.push(frame);
        if frame.terminal != Terminal::Continue {
            break;
        }
    }
    frames
}

fn observe_in_chunks(tls: &mut InnerTls, data: &[u8], chunk: usize) {
    for piece in data.chunks(chunk) {
        tls.observe_downlink(piece);
    }
}

#[test]
fn uplink_switches_exactly_at_the_first_application_record_end() {
    let mut uplink = client_hello();
    uplink.extend(record(20, &[1]));
    uplink.extend(record(RECORD_APPLICATION_DATA, &[0x33; 16_384]));
    let switch_at = uplink.len();
    uplink.extend(record(RECORD_APPLICATION_DATA, &[0x44; 40]));
    let downlink = record(RECORD_HANDSHAKE, &server_hello([1; 32], 0x1301, true));

    for chunk in [1, 3, 5, 8171, 16_384, 65_535] {
        let mut tls = InnerTls::default();
        observe_in_chunks(&mut tls, &downlink, chunk);
        let frames = frames(&mut tls, &uplink, chunk);
        let last = frames.last().unwrap();
        assert_eq!(last.terminal, Terminal::Direct, "chunk={chunk}");
        assert!(last.long_padding);
        assert_eq!(
            frames.iter().map(|frame| frame.take).sum::<usize>(),
            switch_at,
            "chunk={chunk}"
        );
        assert!(frames.iter().all(|frame| frame.take <= MAX_FRAME_CONTENT));
        // Padding stays short until the ClientHello's first content byte.
        assert!(
            frames[..frames.len() - 1]
                .iter()
                .skip_while(|frame| !frame.long_padding)
                .all(|frame| frame.long_padding)
        );
        assert!(frames.iter().filter(|frame| !frame.long_padding).count() <= 5);
    }
}

#[test]
fn uplink_ends_without_direct_when_the_server_is_not_xtls() {
    let mut uplink = client_hello();
    uplink.extend(record(RECORD_APPLICATION_DATA, &[0x33; 64]));
    for (downlink, capable) in [
        (server_hello([1; 32], 0x1305, true), true),
        (server_hello([1; 32], 0x1301, false), true),
        (server_hello([1; 32], 0x1301, true), false),
    ] {
        let mut tls = InnerTls::default();
        tls.observe_downlink(&record(RECORD_HANDSHAKE, &downlink));
        let mut offset = 0;
        let mut last = None;
        while offset < uplink.len() {
            let frame = tls.plan_uplink(&uplink[offset..], capable);
            offset += frame.take;
            last = Some(frame);
            if frame.terminal != Terminal::Continue {
                break;
            }
        }
        assert_eq!(last.unwrap().terminal, Terminal::End);
        assert_eq!(offset, uplink.len());
    }
}

#[test]
fn early_application_data_before_server_hello_ends_padding() {
    let mut uplink = client_hello();
    uplink.extend(record(RECORD_APPLICATION_DATA, &[0x33; 64]));
    let mut tls = InnerTls::default();
    let frames = frames(&mut tls, &uplink, uplink.len());
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].terminal, Terminal::End);
}

#[test]
fn non_tls_uplink_ends_on_its_first_frame_with_short_padding() {
    for data in [&b"GET / HTTP/1.1\r\n\r\n"[..], &[0x17, 3, 3, 0, 1, 0][..]] {
        let mut tls = InnerTls::default();
        let frame = tls.plan_uplink(data, true);
        assert_eq!(
            frame,
            UplinkFrame {
                take: data.len(),
                terminal: Terminal::End,
                long_padding: false,
            }
        );
    }
}

#[test]
fn undecided_prefix_keeps_padding_until_the_first_content_byte() {
    let hello = client_hello();
    let mut tls = InnerTls::default();
    let first = tls.plan_uplink(&hello[..5], true);
    assert_eq!(first.terminal, Terminal::Continue);
    assert!(!first.long_padding);
    let second = tls.plan_uplink(&hello[5..], true);
    assert_eq!(second.terminal, Terminal::Continue);
    assert!(second.long_padding);
}

#[test]
fn malformed_record_after_client_hello_ends_with_long_padding() {
    let mut uplink = client_hello();
    uplink.extend_from_slice(b"GET / HTTP/1.1\r\n");
    let mut tls = InnerTls::default();
    let frame = tls.plan_uplink(&uplink, true);
    assert_eq!(
        frame,
        UplinkFrame {
            take: uplink.len(),
            terminal: Terminal::End,
            long_padding: true,
        }
    );
    // Nothing later can reopen padding or authorize Direct.
    let after = tls.plan_uplink(&record(RECORD_APPLICATION_DATA, &[1]), true);
    assert_eq!(after.terminal, Terminal::End);
}

#[test]
fn padding_ends_after_the_inspection_budget() {
    let mut uplink = client_hello();
    for _ in 0..8 {
        uplink.extend(record(RECORD_HANDSHAKE, &[0; 16_000]));
    }
    let mut tls = InnerTls::default();
    let frames = frames(&mut tls, &uplink, MAX_FRAME_CONTENT);
    let last = frames.last().unwrap();
    assert_eq!(last.terminal, Terminal::End);
    assert!(frames.iter().map(|frame| frame.take).sum::<usize>() >= INSPECT_LIMIT);
}

#[test]
fn server_hello_verdict_survives_fragmentation_and_retry() {
    let hello = server_hello([9; 32], 0x1302, true);
    let mut split = record(RECORD_HANDSHAKE, &hello[..10]);
    split.extend(record(RECORD_HANDSHAKE, &hello[10..]));
    let mut retry = record(
        RECORD_HANDSHAKE,
        &server_hello(HELLO_RETRY_RANDOM, 0x1301, true),
    );
    retry.extend(record(RECORD_CHANGE_CIPHER_SPEC, &[1]));
    retry.extend(record(RECORD_HANDSHAKE, &hello));
    for downlink in [split, retry] {
        for chunk in [1, 4, 7, downlink.len()] {
            let mut tls = InnerTls::default();
            observe_in_chunks(&mut tls, &downlink, chunk);
            assert_eq!(tls.server.verdict, Verdict::Xtls, "chunk={chunk}");
            assert!(tls.server.message.capacity() == 0);
        }
    }
}

#[test]
fn server_hello_rejects_non_tls_and_oversized_messages() {
    let mut oversized = vec![HANDSHAKE_SERVER_HELLO, 0, 0x20, 0];
    oversized.extend_from_slice(&[0; 64]);
    for downlink in [
        b"HTTP/1.1 200 OK\r\n\r\n".to_vec(),
        record(RECORD_APPLICATION_DATA, &[1; 32]),
        record(RECORD_HANDSHAKE, &oversized),
        record(
            RECORD_HANDSHAKE,
            &[HANDSHAKE_SERVER_HELLO, 0, 0, 3, 3, 3, 1],
        ),
    ] {
        let mut tls = InnerTls::default();
        tls.observe_downlink(&downlink);
        assert_eq!(tls.server.verdict, Verdict::Ineligible);
    }
}

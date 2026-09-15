use super::*;

#[test]
fn documented_xudp_new_vector_is_exact() {
    let frame = udp_frame(
        1,
        true,
        udp_target(),
        None,
        [1, 2, 3, 4, 5, 6, 7, 8],
        b"abc",
    )
    .unwrap();
    assert_eq!(
        &frame[..],
        &[
            0x00, 0x14, 0x00, 0x01, 0x01, 0x01, 0x02, 0x00, 0x35, 0x01, 0x01, 0x02, 0x03, 0x04,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x03, b'a', b'b', b'c',
        ]
    );
}

#[tokio::test]
async fn configured_active_limit_is_a_hard_semaphore() {
    let (client, _wire) = tokio::io::duplex(1024);
    let session = connect(Box::new(client), 1);
    let first = session.try_reserve().expect("first active child");
    assert!(session.try_reserve().is_none());
    drop(first);
    assert!(session.try_reserve().is_some());
    session.close();
}

#[test]
fn xudp_packet_caps_match_carrier_modes() {
    let rejected = |result: io::Result<Bytes>| {
        let error = anyhow::Error::new(result.unwrap_err());
        crate::proxy::is_packet_rejection(&error)
    };
    assert!(rejected(udp_frame(
        0,
        true,
        udp_target(),
        None,
        [0; 8],
        &[],
    )));
    assert!(rejected(udp_frame(
        0,
        true,
        udp_target(),
        None,
        [0; 8],
        &vec![0; MAX_SINGLE_XUDP_PACKET_SIZE + 1],
    )));
    assert!(
        udp_frame(
            1,
            true,
            udp_target(),
            None,
            [0; 8],
            &vec![0; MAX_MUX_XUDP_PACKET_SIZE],
        )
        .is_ok()
    );
    assert!(rejected(udp_frame(
        1,
        true,
        udp_target(),
        None,
        [0; 8],
        &vec![0; MAX_MUX_XUDP_PACKET_SIZE + 1],
    )));
}

#[tokio::test]
async fn reader_accepts_payloads_larger_than_xray_writer_chunks() {
    let (mut wire, mut reader) = tokio::io::duplex(1 << 14);
    let payload = vec![0x5a; 8192];
    wire.write_all(&response_frame(
        1,
        STATUS_KEEP,
        OPTION_DATA,
        None,
        Some(&payload),
    ))
    .await
    .unwrap();
    assert_eq!(
        read_wire_frame(&mut reader).await.payload.unwrap().len(),
        8192
    );
}

#[tokio::test]
async fn missing_writer_ack_is_conservatively_committed() {
    let (tx, mut rx) = mpsc::channel(1);
    let writer = CarrierWriter { tx };
    let pending =
        tokio::spawn(async move { writer.send(Bytes::from_static(b"frame"), true).await });
    let command = rx.recv().await.unwrap();
    drop(command.done);

    let error = pending.await.unwrap().unwrap_err();
    assert!(error.committed, "ambiguous writes must never be replayed");
}

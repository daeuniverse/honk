use super::*;
use crate::proxy::request_observation_support::{milestones, observed};
use crate::runtime::flow_observation::{Milestone, request_write};

enum Finish {
    Reset,
    Refuse,
    Drop,
    Deliver,
    FinalFlush { succeeds: bool },
}

async fn zero_window(finish: Finish, payload: &[u8]) {
    let (client, mut server) = tokio::io::duplex(8192);
    let control = Arc::new(IoControl::default());
    let stream = wrap_grpc(
        &grpc_node(),
        Box::new(ControlledIo {
            inner: client,
            control: control.clone(),
            dribble: false,
        }),
    )
    .await
    .unwrap();
    read_request(&mut server).await;
    server.write_all(&frame(SETTINGS, 0, 0, &[])).await.unwrap();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (observer, events) = observed();
    let sent = || milestones(&events.lock(), Milestone::TargetRequestSent);

    // No application flush: only the other half will run the H2 driver from here.
    observer
        .scope(request_write(std::pin::pin!(writer.write_all(payload))))
        .await
        .unwrap();
    assert_eq!(sent(), 0, "queue admission published delivery");
    let mut wire = frame(SETTINGS, 0, 0, &[0, 4, 0, 0, 0, 0]);
    wire.extend(frame(6, 0, 0, b"wnd-zero"));
    server.write_all(&wire).await.unwrap();
    let mut byte = [0];
    assert!(futures_util::poll!(std::pin::pin!(reader.read(&mut byte))).is_pending());
    loop {
        let (kind, flags, id, body) = read_frame(&mut server).await;
        assert_ne!(kind, DATA, "DATA escaped the zero window");
        if kind == 6 {
            assert_eq!((flags, id, body.as_slice()), (1, 0, &b"wnd-zero"[..]));
            break;
        }
    }
    assert_eq!(sent(), 0, "a control-only flush published delivery");

    match finish {
        Finish::Reset => {
            server
                .write_all(&frame(RESET, 0, 1, &8u32.to_be_bytes()))
                .await
                .unwrap();
            assert_eq!(
                reader.read(&mut byte).await.unwrap_err().kind(),
                std::io::ErrorKind::ConnectionReset
            );
        }
        Finish::Refuse => {
            // Indexed HPACK :status 404, without resetting the request's send side.
            server
                .write_all(&frame(HEADERS, END_HEADERS, 1, &[0x8d]))
                .await
                .unwrap();
            assert_eq!(
                reader.read(&mut byte).await.unwrap_err().kind(),
                std::io::ErrorKind::ConnectionRefused
            );
        }
        Finish::Drop => {}
        Finish::Deliver | Finish::FinalFlush { .. } => {
            control.mode.store(3, Ordering::Release);
            server
                .write_all(&frame(8, 0, 1, &65_535u32.to_be_bytes()))
                .await
                .unwrap();
            assert!(futures_util::poll!(std::pin::pin!(reader.read(&mut byte))).is_pending());
            let (kind, _, id, body) = read_frame(&mut server).await;
            assert_eq!((kind, id, body), (DATA, 1, gun_message(payload)));
            assert_eq!(sent(), 0, "DATA was not flushed at the carrier");
            if let Finish::FinalFlush { succeeds } = finish {
                server.shutdown().await.unwrap();
                control
                    .mode
                    .store(if succeeds { 0 } else { 4 }, Ordering::Release);
                control.waker.wake();
                // No response headers: the read fails even when the final DATA flush succeeds.
                reader.read(&mut byte).await.unwrap_err();
                assert_eq!(sent(), usize::from(succeeds));
            } else {
                control.mode.store(0, Ordering::Release);
                control.waker.wake();
                assert!(futures_util::poll!(std::pin::pin!(reader.read(&mut byte))).is_pending());
                assert_eq!(sent(), 1, "reader flushed DATA without another writer poll");
            }
        }
    }
    drop(writer);
    drop(reader);
    assert!(control.dropped.load(Ordering::Acquire));
    assert_eq!(
        sent(),
        usize::from(matches!(
            finish,
            Finish::Deliver | Finish::FinalFlush { succeeds: true }
        ))
    );
}

#[tokio::test]
async fn grpc_reset_refusal_or_drop_before_window_update_does_not_publish() {
    tokio::time::timeout(Duration::from_secs(3), async {
        zero_window(Finish::Reset, b"not sent").await;
        zero_window(Finish::Refuse, b"not sent").await;
        zero_window(Finish::Drop, b"not sent").await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grpc_reader_seals_copied_and_chained_data_only_after_carrier_flush() {
    tokio::time::timeout(Duration::from_secs(3), async {
        zero_window(Finish::Deliver, b"small").await;
        zero_window(Finish::Deliver, &[0x5a; 2048]).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grpc_reader_settles_last_data_flush_on_peer_half_close() {
    tokio::time::timeout(Duration::from_secs(3), async {
        for succeeds in [true, false] {
            zero_window(Finish::FinalFlush { succeeds }, b"last DATA").await;
        }
    })
    .await
    .unwrap();
}

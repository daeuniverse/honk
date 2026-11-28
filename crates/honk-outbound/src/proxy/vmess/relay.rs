use super::{BodyChunks, CHUNK_MAX_LEN, GCM_TAG_LEN, RelayFence, Session, read_response_header};
use crate::proxy::{AsyncReadWrite, transport};
use futures_util::FutureExt;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(super) async fn run(
    server: Box<dyn AsyncReadWrite>,
    client: &mut tokio::io::DuplexStream,
    (header_wire, session): (Vec<u8>, Session),
    pipe: &transport::relay_upload::Reader,
    uploaded: &mut Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>,
    tail: &mut Vec<u8>,
    fence: Option<&RelayFence>,
) -> anyhow::Result<()> {
    let peer_end = transport::WsPeerEnd::for_stream(server.as_ref());
    let omitted = AtomicBool::new(false);
    let (mut server_read, mut server_write) = tokio::io::split(server);
    let (mut client_read, mut client_write) = tokio::io::split(client);

    let upload = async {
        if fence.is_some() {
            server_write.write_all(&header_wire).await?;
            server_write.flush().await?;
        } else {
            transport::write_request(&mut server_write, &header_wire).await?;
        }

        let mut body = BodyChunks::new(&session.req_key, &session.req_iv)?;
        let mut buf = vec![0u8; CHUNK_MAX_LEN];
        let mut relayed = 0u64;
        loop {
            let n = match client_read.read(&mut buf).now_or_never() {
                Some(read) => read?,
                None => {
                    server_write.flush().await?;
                    if let Some(fence) = fence {
                        fence.advance(relayed);
                    }
                    client_read.read(&mut buf).await?
                }
            };
            if n == 0 {
                break;
            }
            relayed += n as u64;
            let chunk = body.seal_chunk(&buf[..n])?;
            let writer = &mut server_write;
            let bytes = &chunk;
            pipe.forward(relayed, |flush| async move {
                writer.write_all(bytes).await?;
                if flush {
                    writer.flush().await?;
                    if let Some(fence) = fence {
                        fence.advance(relayed);
                    }
                }
                Ok::<_, std::io::Error>(())
            })
            .await?;
        }
        let term = body.seal_chunk(&[])?;
        let mut remaining = term.as_slice();
        let result = transport::relay_upload::scope(async {
            server_write.write_all_buf(&mut remaining).await?;
            server_write.flush().await
        })
        .await;
        if let Err(error) = result {
            if peer_end
                .as_ref()
                .is_some_and(|proof| proof.omitted(&error, term.len() - remaining.len()))
            {
                return Ok(true);
            }
            return Err(error.into());
        }
        if let Some(fence) = fence {
            fence.advance(relayed);
        }
        if let Some(uploaded) = uploaded.take() {
            let _ = uploaded.send(Ok(()));
        }
        Ok::<bool, anyhow::Error>(false)
    };

    let download = async {
        let complete_header = read_response_header(&mut server_read, &session).await?;

        let mut body = BodyChunks::new(&session.resp_key, &session.resp_iv)?;
        let marker = loop {
            let mut len_buf = [0u8; 2];
            match server_read.read(&mut len_buf).await? {
                0 => break None,
                1 => {
                    server_read.read_exact(&mut len_buf[1..]).await?;
                }
                _ => {}
            }
            let chunk_len = body.decode_len(len_buf) as usize;
            // size == AEAD overhead is the server's termination chunk
            // (AuthenticationReader.readInternal).
            if chunk_len == GCM_TAG_LEN {
                break peer_end.is_some().then_some(body);
            }
            if !(chunk_len > GCM_TAG_LEN && chunk_len <= CHUNK_MAX_LEN + GCM_TAG_LEN) {
                return Err(crate::proxy::NodeFailure(
                    anyhow::anyhow!("invalid VMess chunk size {chunk_len}")
                        .context("VMess response body"),
                )
                .into());
            }
            let chunk = body.read_chunk(&mut server_read, chunk_len).await?;
            let mut remaining = chunk.as_slice();
            while tail.is_empty() && !remaining.is_empty() {
                let write = std::future::poll_fn(|cx| {
                    match Pin::new(&mut client_write).poll_write(cx, remaining) {
                        Poll::Pending if omitted.load(Ordering::Relaxed) => Poll::Ready(None),
                        result => result.map(Some),
                    }
                })
                .await;
                let Some(write) = write else {
                    // Only the current record and the closed WS duplex can remain.
                    tail.reserve_exact(remaining.len() + 65536);
                    break;
                };
                let written = write?;
                if written == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                }
                remaining = &remaining[written..];
            }
            tail.extend_from_slice(remaining);
        };
        if !omitted.load(Ordering::Relaxed) {
            client_write.shutdown().await?;
        }
        Ok::<_, anyhow::Error>((complete_header, marker))
    };

    let (peer_ended, (complete_header, marker)) = {
        let mut upload = std::pin::pin!(upload);
        let mut download = std::pin::pin!(download);
        tokio::select! {
            result = &mut upload => {
                let peer_ended = result?;
                if peer_ended {
                    omitted.store(true, Ordering::Relaxed);
                }
                // Repoll even if download last waited for space in the application duplex.
                (peer_ended, download.await?)
            }
            result = &mut download => {
                let response = result?;
                (upload.await?, response)
            }
        }
    };
    if peer_ended {
        if !complete_header {
            return Err(crate::proxy::NodeFailure(anyhow::anyhow!(
                "invalid VMess response header command length"
            ))
            .into());
        }
        if let Some(body) = marker {
            // Ordinary VMess readers accept the length alone as EOF. Only the
            // peer-close exception needs proof of the entire empty record.
            let (nonce, cipher) = body.into_terminator()?;
            let mut tag = [0u8; GCM_TAG_LEN];
            server_read.read_exact(&mut tag).await?;
            cipher
                .open_in_place(&nonce, &mut [], &tag, b"")
                .map_err(|error| {
                    crate::proxy::NodeFailure(anyhow::anyhow!(
                        "VMess response terminator decrypt failed: {error}"
                    ))
                })?;
        }
    }
    Ok(())
}

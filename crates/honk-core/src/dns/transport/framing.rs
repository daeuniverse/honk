//! Shared DNS stream framing helpers (RFC 7766 length-prefix).

use honk_outbound::group::ScoreReporter;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
pub async fn exchange_length_prefixed<S>(
    stream: &mut S,
    raw_query: &[u8],
    query_timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_length_prefixed_reported(stream, raw_query, query_timeout, None, None).await
}

pub(super) async fn exchange_length_prefixed_reported<S>(
    stream: &mut S,
    raw_query: &[u8],
    query_timeout: Duration,
    reporter: Option<&ScoreReporter>,
    routed_id: Option<u16>,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(query_timeout, async {
        if let Some(id) = routed_id {
            let len = u16::try_from(raw_query.len())
                .map_err(|_| anyhow::anyhow!("DNS message too large for stream framing"))?;
            let payload = raw_query
                .get(2..)
                .ok_or_else(|| anyhow::anyhow!("missing DNS ID"))?;
            let mut header = [0; 4];
            header[..2].copy_from_slice(&len.to_be_bytes());
            header[2..].copy_from_slice(&id.to_be_bytes());
            stream.write_all(&header).await?;
            stream.write_all(payload).await?;
            stream.flush().await?;
        } else {
            write_length_prefixed(stream, raw_query).await?;
        }
        if let Some(reporter) = reporter {
            reporter.tx(raw_query.len() as u64);
        }
        let mut response = Vec::new();
        read_length_prefixed_into(stream, &mut response, None).await?;
        if let Some(id) = routed_id {
            anyhow::ensure!(
                response.get(..2) == Some(id.to_be_bytes().as_slice()),
                "DNS stream response ID does not match the query"
            );
            response[..2].copy_from_slice(&raw_query[..2]);
        }
        if let Some(reporter) = reporter
            && super::is_valid_response(raw_query, &response)
        {
            reporter.first_response();
            reporter.rx(response.len() as u64);
        }
        Ok::<_, anyhow::Error>(response)
    })
    .await
    .map_err(|_| anyhow::anyhow!("DNS stream exchange timed out after {query_timeout:?}"))?
}

pub(crate) async fn write_length_prefixed<S>(stream: &mut S, raw_query: &[u8]) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let len = u16::try_from(raw_query.len())
        .map_err(|_| anyhow::anyhow!("DNS message too large for stream framing"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(raw_query).await?;
    stream.flush().await?;
    Ok(())
}

pub(super) async fn read_length_prefixed<S>(
    stream: &mut S,
    query_timeout: Duration,
) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();
    read_length_prefixed_into(stream, &mut buffer, Some(query_timeout)).await?;
    Ok(buffer)
}

/// Read one RFC 7766 frame into reusable storage.
///
/// Upstream callers pass a timeout, which is applied independently to the
/// length and body stages. Server-side callers pass `None` to retain their
/// existing connection-lifetime behavior without an idle timeout.
pub(crate) async fn read_length_prefixed_into<S>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    query_timeout: Option<Duration>,
) -> anyhow::Result<()>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    read_exact_stage(
        stream,
        &mut len_buf,
        query_timeout,
        "DNS stream read length timed out",
    )
    .await?;
    let message_len = usize::from(u16::from_be_bytes(len_buf));
    if message_len == 0 {
        anyhow::bail!("invalid DNS stream message length {message_len}");
    }
    buffer.resize(message_len, 0);
    read_exact_stage(
        stream,
        buffer,
        query_timeout,
        "DNS stream read body timed out",
    )
    .await
}

async fn read_exact_stage<S>(
    stream: &mut S,
    buffer: &mut [u8],
    stage_timeout: Option<Duration>,
    timeout_message: &'static str,
) -> anyhow::Result<()>
where
    S: AsyncRead + Unpin,
{
    if let Some(duration) = stage_timeout {
        timeout(duration, stream.read_exact(buffer))
            .await
            .map_err(|_| anyhow::anyhow!(timeout_message))??;
    } else {
        stream.read_exact(buffer).await?;
    }
    Ok(())
}

/// Force DNS message ID to 0 (DoH/DoQ cache-friendly / RFC 9250 §4.2.1).
#[inline]
pub fn force_dns_id_zero(msg: &mut [u8]) -> u16 {
    if msg.len() < 2 {
        return 0;
    }
    let orig = u16::from_be_bytes([msg[0], msg[1]]);
    msg[0] = 0;
    msg[1] = 0;
    orig
}

/// Restore a previously saved DNS message ID.
#[inline]
pub fn restore_dns_id(msg: &mut [u8], id: u16) {
    if msg.len() < 2 {
        return;
    }
    let bytes = id.to_be_bytes();
    msg[0] = bytes[0];
    msg[1] = bytes[1];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_zero_roundtrip() {
        let mut msg = vec![0x12, 0x34, 0x01, 0x00];
        let orig = force_dns_id_zero(&mut msg);
        assert_eq!(orig, 0x1234);
        assert_eq!(&msg[..2], &[0, 0]);
        restore_dns_id(&mut msg, orig);
        assert_eq!(&msg[..2], &[0x12, 0x34]);
    }

    #[tokio::test]
    async fn length_prefix_exchange() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);
        let query = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01];
        let response = vec![0xAB, 0xCD, 0x81, 0x80, 0x00, 0x00];

        let server_resp = response.clone();
        let expected_query = query.clone();
        let server_task = tokio::spawn(async move {
            let mut len = [0u8; 2];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut len)
                .await
                .unwrap();
            let n = u16::from_be_bytes(len) as usize;
            let mut buf = vec![0u8; n];
            tokio::io::AsyncReadExt::read_exact(&mut server, &mut buf)
                .await
                .unwrap();
            assert_eq!(buf, expected_query);
            let len = (server_resp.len() as u16).to_be_bytes();
            tokio::io::AsyncWriteExt::write_all(&mut server, &len)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(&mut server, &server_resp)
                .await
                .unwrap();
        });

        let got = exchange_length_prefixed(&mut client, &query, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(got, response);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_deadline_covers_a_stalled_request_write() {
        use tokio::io::duplex;

        let (mut client, _server) = duplex(1);
        let error = exchange_length_prefixed(&mut client, &[0; 512], Duration::from_millis(20))
            .await
            .expect_err("stalled request write must expire");

        assert!(error.to_string().contains("exchange timed out"));
    }

    #[tokio::test]
    async fn exchange_deadline_is_shared_across_response_stages() {
        use tokio::io::duplex;

        let (mut client, mut server) = duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut request = [0_u8; 14];
            server.read_exact(&mut request).await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
            server.write_all(&2_u16.to_be_bytes()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
            let _ = server.write_all(&[0, 0]).await;
        });

        let error = exchange_length_prefixed(&mut client, &[0; 12], Duration::from_millis(60))
            .await
            .expect_err("staged slow response must exceed one deadline");

        assert!(error.to_string().contains("exchange timed out"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn read_into_reuses_capacity_across_frames() {
        use tokio::io::duplex;

        let (mut reader, mut writer) = duplex(4096);
        let first = vec![0x11; 512];
        let second = vec![0x22; 12];
        let expected_first = first.clone();
        let expected_second = second.clone();
        let writer_task = tokio::spawn(async move {
            write_length_prefixed(&mut writer, &first).await.unwrap();
            write_length_prefixed(&mut writer, &second).await.unwrap();
        });

        let mut buffer = Vec::new();
        read_length_prefixed_into(&mut reader, &mut buffer, None)
            .await
            .unwrap();
        assert_eq!(buffer, expected_first);
        let first_capacity = buffer.capacity();

        read_length_prefixed_into(&mut reader, &mut buffer, None)
            .await
            .unwrap();
        assert_eq!(buffer, expected_second);
        assert_eq!(buffer.capacity(), first_capacity);
        writer_task.await.unwrap();
    }
}

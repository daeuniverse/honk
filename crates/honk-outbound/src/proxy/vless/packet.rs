use super::*;

struct VlessPacketReader {
    stream: tokio::io::ReadHalf<Box<dyn AsyncReadWrite>>,
    decoder: crate::proxy::uot::Decoder,
}

struct VlessPacketWriter {
    stream: tokio::io::WriteHalf<Box<dyn AsyncReadWrite>>,
    setup: Option<bytes::Bytes>,
    pending: bool,
}

pub(super) struct VlessConnectedTransport {
    reader: tokio::sync::Mutex<VlessPacketReader>,
    writer: tokio::sync::Mutex<VlessPacketWriter>,
    target: SocketAddr,
    native: bool,
}

impl VlessConnectedTransport {
    pub(super) fn new(
        stream: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        setup: Option<bytes::Bytes>,
    ) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        let native = setup.is_none();
        Self {
            reader: tokio::sync::Mutex::new(VlessPacketReader {
                stream: reader,
                decoder: crate::proxy::uot::Decoder::default(),
            }),
            writer: tokio::sync::Mutex::new(VlessPacketWriter {
                stream: writer,
                setup,
                pending: false,
            }),
            target,
            native,
        }
    }

    async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        if self.native && (data.is_empty() || data.len() > MAX_NATIVE_PACKET_SIZE) {
            return Err(crate::proxy::PacketRejection::InvalidSize.into());
        }
        let packet = crate::proxy::uot::encode_packet(data, crate::proxy::uot::MAX_PACKET_SIZE)?;
        let mut writer = self.writer.lock().await;
        if writer.pending {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "VLESS packet write was interrupted",
            ));
        }
        let frame = if let Some(setup) = writer.setup.as_ref() {
            let mut frame = bytes::BytesMut::with_capacity(setup.len() + packet.len());
            frame.extend_from_slice(setup);
            frame.extend_from_slice(&packet);
            frame.freeze()
        } else {
            packet
        };
        writer.pending = true;
        writer.stream.write_all(&frame).await?;
        writer.stream.flush().await?;
        writer.setup = None;
        writer.pending = false;
        Ok(())
    }
}

impl std::fmt::Debug for VlessConnectedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessConnectedTransport")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PacketTransport for VlessConnectedTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }

    async fn send_packet(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> std::io::Result<()> {
        self.send(data).await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        let mut reader = self.reader.lock().await;
        loop {
            if let Some(size) = reader.decoder.next_packet(output)? {
                return Ok((size, self.target));
            }
            let mut chunk = [0; 16 * 1024];
            let size = reader.stream.read(&mut chunk).await?;
            if size == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "VLESS packet stream closed",
                ));
            }
            reader.decoder.push(&chunk[..size])?;
        }
    }
}

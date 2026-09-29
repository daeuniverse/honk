//! Codec fixtures for Vision tests in `handler`, which cannot reach this
//! module's private AEAD and XOR state yet must see which uplink bytes are
//! framed and which are raw.

use super::*;

/// The server end of a ready client [`EncryptedStream`].
pub(in crate::proxy::vless) struct ScriptedServer {
    io: tokio::io::DuplexStream,
    recv: StreamAead,
    send: StreamAead,
    recv_xor: Option<AesCtr>,
    send_xor: Option<AesCtr>,
}

/// `random_xor_iv` selects random mode: header XOR keystreams whose IVs the
/// server would have announced.
pub(in crate::proxy::vless) fn scripted_pair(
    random_xor_iv: Option<[u8; IV_LEN]>,
) -> (EncryptedStream, ScriptedServer) {
    let key = vec![31_u8; 96];
    // The downlink keystream must differ from the uplink one.
    let downlink_iv = random_xor_iv.map(|iv| iv.map(|byte| byte ^ 0xff));
    let xor = |iv: Option<[u8; IV_LEN]>| iv.map(|iv| AesCtr::new(&key, &iv));
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let client = EncryptedStream::new(
        Box::new(client_io),
        key.clone(),
        true,
        StreamAead::new(b"client", &key, true).unwrap(),
        Some(StreamAead::new(b"server", &key, true).unwrap()),
        xor(random_xor_iv),
        xor(downlink_iv),
        None,
        PeerInit::Ready,
        None,
        random_xor_iv.is_some(),
    );
    let server = ScriptedServer {
        io: server_io,
        recv: StreamAead::new(b"client", &key, true).unwrap(),
        send: StreamAead::new(b"server", &key, true).unwrap(),
        recv_xor: xor(random_xor_iv),
        send_xor: xor(downlink_iv),
    };
    (client, server)
}

impl ScriptedServer {
    /// One authenticated client frame's plaintext.
    pub(in crate::proxy::vless) async fn read_frame(&mut self) -> Vec<u8> {
        let mut header = [0; FRAME_HEADER_LEN];
        self.io.read_exact(&mut header).await.unwrap();
        if let Some(xor) = self.recv_xor.as_mut() {
            xor.apply(&mut header);
        }
        assert_eq!(header[..3], [23, 3, 3], "not an Encryption frame header");
        let mut body = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
        self.io.read_exact(&mut body).await.unwrap();
        let length = self.recv.open(&mut body, &header).unwrap();
        body.truncate(length);
        body
    }

    pub(in crate::proxy::vless) async fn write_frame(&mut self, plaintext: &[u8]) {
        let mut header = [23, 3, 3, 0, 0];
        header[3..].copy_from_slice(&encode_length(plaintext.len() + TAG_LEN));
        let mut body = Vec::new();
        self.send.seal(plaintext, &header, &mut body).unwrap();
        if let Some(xor) = self.send_xor.as_mut() {
            xor.apply(&mut header);
        }
        self.io.write_all(&header).await.unwrap();
        self.io.write_all(&body).await.unwrap();
    }

    /// Reads `count` TLS-shaped records the client sent after its Direct
    /// command and returns `(wire, decoded)`. As in Xray `XorConn`, only each
    /// record's 5-byte header is XORed, continuing the keystream where the
    /// last framed header left it; bodies travel untouched.
    pub(in crate::proxy::vless) async fn read_direct_records(
        &mut self,
        count: usize,
    ) -> (Vec<u8>, Vec<u8>) {
        let (mut wire, mut decoded) = (Vec::new(), Vec::new());
        for _ in 0..count {
            let mut header = [0; FRAME_HEADER_LEN];
            self.io.read_exact(&mut header).await.unwrap();
            wire.extend_from_slice(&header);
            if let Some(xor) = self.recv_xor.as_mut() {
                xor.apply(&mut header);
            }
            assert_eq!(header[..3], [23, 3, 3], "Direct bytes must be raw records");
            let mut body = vec![0; usize::from(u16::from_be_bytes([header[3], header[4]]))];
            self.io.read_exact(&mut body).await.unwrap();
            wire.extend_from_slice(&body);
            decoded.extend_from_slice(&header);
            decoded.extend_from_slice(&body);
        }
        (wire, decoded)
    }
}

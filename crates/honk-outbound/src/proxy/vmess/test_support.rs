use super::Session;
#[cfg(feature = "flow-observation")]
use super::{AsyncReadWrite, BodyChunks, CHUNK_MAX_LEN, GCM_TAG_LEN, VmessStream};
#[cfg(feature = "flow-observation")]
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// VMess request header vector from Xray-core/sing-vmess.
pub(super) const HEADER_WIRE: &str = "7997d3314952dc37e0b284331b6bb2e71a963074b6c9f5cd7c0825ace93c69df311f0102030405060708301fcaedd9021cf0eaab9deb25afab08b13d78f0b0ff69acfc123dd0ba0d9b6c24d5edbfbcd20d23d7fd0a9f3d59a64835ccd0253af09feb22cc2affb2942c159c5acdc2";
pub(super) const RESP_KEY: &str = "b8f12ea8c9a95d4b4641b03d9fa5a71a";
pub(super) const RESP_IV: &str = "3dc30fbac8417f76943e9c10e15eeacb";

pub(super) fn fixed_session() -> Session {
    Session {
        req_key: [0x11; 16],
        req_iv: [0x22; 16],
        resp_key: hex(RESP_KEY).try_into().unwrap(),
        resp_iv: hex(RESP_IV).try_into().unwrap(),
        resp_header: 0x5a,
        ambiguous_header_io: false,
    }
}

#[cfg(feature = "flow-observation")]
pub(in crate::proxy) struct UploadPeer(BodyChunks);

#[cfg(feature = "flow-observation")]
impl UploadPeer {
    pub(in crate::proxy) const CHUNK_LEN: usize = CHUNK_MAX_LEN;
    pub(in crate::proxy) const FULL_WIRE_LEN: usize = CHUNK_MAX_LEN + 2 + GCM_TAG_LEN;

    pub(in crate::proxy) fn header() -> Vec<u8> {
        hex(HEADER_WIRE)
    }

    pub(in crate::proxy) fn start(carrier: Box<dyn AsyncReadWrite>) -> (impl AsyncReadWrite, Self) {
        let session = fixed_session();
        let peer = Self(BodyChunks::new(&session.req_key, &session.req_iv).unwrap());
        let stream = VmessStream::start(carrier, Self::header(), session).unwrap();
        (stream, peer)
    }

    pub(in crate::proxy) async fn read_chunk(
        &mut self,
        wire: &mut (impl AsyncRead + Unpin),
    ) -> Vec<u8> {
        let mut len = [0; 2];
        wire.read_exact(&mut len).await.unwrap();
        let mut chunk = vec![0; self.0.decode_len(len) as usize];
        wire.read_exact(&mut chunk).await.unwrap();
        let len = self.0.open_chunk(&mut chunk).unwrap();
        chunk.truncate(len);
        chunk
    }
}

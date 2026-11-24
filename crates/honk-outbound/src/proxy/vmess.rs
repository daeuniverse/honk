//! VMess AEAD outbound handler (alterId = 0).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use async_trait::async_trait;
use futures_util::FutureExt;
use honk_config::node::Node;
use md5::{Digest, Md5};
use rand::Rng;
use rand::RngExt;
use sha2::Sha256;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::addr::{self, SocksAddr};
use super::{
    AsyncReadWrite, ProbeableOutbound, ProxyStream, TcpOutbound, TunnelDialOptions,
    WarmRequirement, WarmableOutbound,
};

/// VMess protocol version byte.
const VMESS_VERSION: u8 = 0x01;
/// Request options: ChunkStream | ChunkMasking — what Xray's outbound sets
/// for AES-128-GCM security (`proxy/vmess/outbound/outbound.go`).
const REQUEST_OPTION: u8 = 0x01 | 0x04;
/// Security nibble: AES-128-GCM (`SecurityType_AES128_GCM`, what "auto"
/// resolves to on any AES-capable host).
const SECURITY_AES128_GCM: u8 = 0x03;
/// Request command: TCP.
const CMD_TCP: u8 = 0x01;
/// Suffix for cmd_key derivation (`vmess.Account.ID.CmdKey`).
const CMD_KEY_SUFFIX: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
/// Seed of the chained KDF (`aead/kdf.go` KDFSaltConstVMessAEADKDF).
const KDF_SALT_SEED: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";
/// AES-GCM tag length in bytes.
const GCM_TAG_LEN: usize = 16;
/// Maximum plaintext per body chunk (Xray `buf.Size` - tag - size field,
/// no global padding).
const CHUNK_MAX_LEN: usize = 16384 - GCM_TAG_LEN - 2;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac = <hmac::Hmac<Sha256>>::new_from_slice(key).expect("HMAC key length is free");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// HMAC block pads for a key that fits the 64-byte block (every KDF path
/// element does, so the >64-byte pre-hash branch never applies).
fn hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    debug_assert!(key.len() <= 64);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, &b) in key.iter().enumerate() {
        ipad[i] ^= b;
        opad[i] ^= b;
    }
    (ipad, opad)
}

/// The chained hash of `aead/kdf.go`: `chain[0]` is the innermost HMAC key
/// (the salt seed); each further element wraps the previous hash as an HMAC
/// whose "hash function" is the previous level — `H_k(m) = H_{k-1}(opad_k
/// || H_{k-1}(ipad_k || m))`. Verified byte-identical to both Xray-core's
/// `KDF` and sing-vmess's `KDF` against their Go sources.
fn chain_hash(chain: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    if let &[seed] = chain {
        return hmac_sha256(seed, msg);
    }
    let (rest, last) = chain.split_at(chain.len() - 1);
    let (ipad, opad) = hmac_pads(last[0]);
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner = chain_hash(rest, &inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner);
    chain_hash(rest, &outer)
}

fn kdf(key: &[u8], salt: &[u8], extra: &[&[u8]]) -> [u8; 32] {
    let mut chain: Vec<&[u8]> = Vec::with_capacity(2 + extra.len());
    chain.push(KDF_SALT_SEED);
    chain.push(salt);
    chain.extend_from_slice(extra);
    chain_hash(&chain, key)
}

fn kdf16(key: &[u8], salt: &[u8], extra: &[&[u8]]) -> [u8; 16] {
    kdf(key, salt, extra)[..16]
        .try_into()
        .expect("slice length")
}

fn kdf12(key: &[u8], salt: &[u8], extra: &[&[u8]]) -> [u8; 12] {
    kdf(key, salt, extra)[..12]
        .try_into()
        .expect("slice length")
}

/// CRC-32 IEEE (gzip polynomial), used by the auth ID
/// (`crc32.ChecksumIEEE` in `aead/authid.go`).
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// FNV-1a 32 (`hash/fnv` in `EncodeRequestHeader`; Go's `Sum` appends
/// big-endian).
fn fnv1a32(data: &[u8]) -> u32 {
    let mut h = 0x811C_9DC5u32;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// VMess AEAD proxy handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct VmessHandler;

tokio::task_local! {
    pub(super) static ROUTED_CARRIER: ();
}

/// Per-connection session material (`encoding.NewClientSession`).
struct Session {
    req_key: [u8; 16],
    req_iv: [u8; 16],
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_header: u8,
    ambiguous_header_io: bool,
}

impl Session {
    fn new(ambiguous_header_io: bool) -> Self {
        let mut rng = rand::rng();
        let mut req_key = [0u8; 16];
        let mut req_iv = [0u8; 16];
        rng.fill_bytes(&mut req_key);
        rng.fill_bytes(&mut req_iv);
        // Response body keys derive from the request keys
        // (encoding/client.go NewClientSession).
        let resp_key: [u8; 16] = Sha256::digest(req_key)[..16]
            .try_into()
            .expect("sha256 > 16");
        let resp_iv: [u8; 16] = Sha256::digest(req_iv)[..16]
            .try_into()
            .expect("sha256 > 16");
        Self {
            req_key,
            req_iv,
            resp_key,
            resp_iv,
            resp_header: rng.random(),
            ambiguous_header_io,
        }
    }
}

/// The terminal relay failure, surfaced after any buffered application data.
type RelayFailure = std::sync::Arc<std::sync::OnceLock<(std::io::ErrorKind, crate::SharedError)>>;

struct VmessStream {
    _relay: super::transport::RelayTask,
    inner: tokio::io::DuplexStream,
    failure: RelayFailure,
    pipe: super::transport::relay_upload::Writer,
    upload_done: super::transport::UploadEnd,
}

impl VmessStream {
    fn start(
        stream: Box<dyn AsyncReadWrite>,
        header_wire: Vec<u8>,
        session: Session,
    ) -> anyhow::Result<Self> {
        let (inner, server) = tokio::io::duplex(65536);
        let failure = RelayFailure::default();
        let (pipe, reader) = super::transport::relay_upload::pipe();
        let (uploaded, upload_done) = super::transport::UploadEnd::channel();
        let relay = vmess_relay_recorded(
            stream,
            server,
            header_wire,
            session,
            failure.clone(),
            reader,
            uploaded,
        );
        let relay = crate::runtime::flow_observation::scope(
            crate::runtime::flow_observation::current(),
            relay,
        );
        Ok(Self {
            _relay: super::transport::RelayTask::spawn(relay)?,
            inner,
            failure,
            pipe,
            upload_done,
        })
    }

    fn relay_error(&self) -> Option<std::io::Error> {
        self.failure
            .get()
            .map(|(kind, message)| std::io::Error::new(*kind, message.clone()))
    }
}

/// The failure is recorded before the duplex half closes, so the owner sees it
/// on the poll that would otherwise be EOF.
async fn vmess_relay_recorded(
    server: Box<dyn AsyncReadWrite>,
    mut client: tokio::io::DuplexStream,
    header_wire: Vec<u8>,
    session: Session,
    failure: RelayFailure,
    pipe: super::transport::relay_upload::Reader,
    uploaded: tokio::sync::oneshot::Sender<std::io::Result<()>>,
) {
    let mut uploaded = Some(uploaded);
    let mut tail = Vec::new();
    if let Err(error) = vmess_relay(
        server,
        &mut client,
        header_wire,
        session,
        &pipe,
        &mut uploaded,
        &mut tail,
    )
    .await
    {
        let kind = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .map(std::io::Error::kind)
            .unwrap_or(std::io::ErrorKind::InvalidData);
        let _ = failure.set((
            kind,
            crate::SharedError::new(error.context("VMess relay failed")),
        ));
    }
    if let Some(uploaded) = uploaded {
        let result = match failure.get() {
            Some((kind, cause)) => Err(std::io::Error::new(*kind, cause.clone())),
            None => Ok(()),
        };
        let _ = uploaded.send(result);
    }
    drop(pipe);
    if !tail.is_empty() {
        // Shutdown can now return even if the application has yet to read.
        let _ = client.write_all(&tail).await;
    }
}

impl std::fmt::Debug for VmessStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmessStream").finish_non_exhaustive()
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() == before => match self.relay_error() {
                Some(error) => Poll::Ready(Err(error)),
                None => Poll::Ready(Ok(())),
            },
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.relay_error().unwrap_or(error))),
            other => other,
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let inner = &mut this.inner;
        match this
            .pipe
            .poll_write(cx, |cx| Pin::new(inner).poll_write(cx, buf))
        {
            Poll::Ready(Err(error)) => Poll::Ready(Err(this.relay_error().unwrap_or(error))),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if std::task::ready!(self.pipe.poll_flush(cx)).is_err() {
            std::task::ready!(self.upload_done.poll(cx))
                .map_err(|error| self.relay_error().unwrap_or(error))?;
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.relay_error().unwrap_or(error))),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        std::task::ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        self.upload_done
            .poll(cx)
            .map_err(|error| self.relay_error().unwrap_or(error))
    }
}

impl VmessHandler {
    pub fn new() -> Self {
        Self
    }

    /// Derive the command key: `MD5(uuid || CMD_KEY_SUFFIX)`.
    fn derive_cmd_key(uuid: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(uuid);
        h.update(CMD_KEY_SUFFIX);
        h.finalize().into()
    }

    /// `CreateAuthID`: AES-128 single-block encryption of
    /// `ts(8 BE) | rand(4) | crc32(ts|rand)(4 BE)` under the auth-ID key.
    fn create_auth_id(cmd_key: &[u8; 16], ts: u64, rand4: [u8; 4]) -> [u8; 16] {
        use aes_gcm::aes::cipher::BlockCipherEncrypt;
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&ts.to_be_bytes());
        block[8..12].copy_from_slice(&rand4);
        let crc = crc32_ieee(&block[..12]);
        block[12..].copy_from_slice(&crc.to_be_bytes());
        let key = kdf16(cmd_key, KDF_SALT_AUTH_ID, &[]);
        let cipher = aes_gcm::aes::Aes128::new_from_slice(&key).expect("key length");
        cipher.encrypt_block((&mut block).into());
        block
    }

    /// Header plaintext per `EncodeRequestHeader` (fnv checksum included).
    fn build_header_plain(
        session: &Session,
        padding_len: u8,
        padding: &[u8],
        target: SocketAddr,
        target_domain: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        debug_assert_eq!(padding_len as usize, padding.len());
        let addr = SocksAddr::new(target, target_domain)?;
        let mut plain = Vec::with_capacity(41 + addr.encoded_len() + padding.len() + 4);
        plain.push(VMESS_VERSION);
        plain.extend_from_slice(&session.req_iv);
        plain.extend_from_slice(&session.req_key);
        plain.push(session.resp_header);
        plain.push(REQUEST_OPTION);
        plain.push((padding_len << 4) | SECURITY_AES128_GCM);
        plain.push(0);
        plain.push(CMD_TCP);
        plain.extend_from_slice(&target.port().to_be_bytes());
        // V2Ray writes port first, then ATYP + address
        // (protocol.AddressSerializer with PortThenAddress).
        match &addr {
            SocksAddr::V4(v4) => {
                plain.push(addr::ATYP_VMESS.ipv4);
                plain.extend_from_slice(&v4.ip().octets());
            }
            SocksAddr::V6(v6) => {
                plain.push(addr::ATYP_VMESS.ipv6);
                plain.extend_from_slice(&v6.ip().octets());
            }
            SocksAddr::Domain(domain, _) => {
                plain.push(addr::ATYP_VMESS.domain);
                plain.push(domain.len() as u8);
                plain.extend_from_slice(domain.as_bytes());
            }
        }
        plain.extend_from_slice(padding);
        plain.extend_from_slice(&fnv1a32(&plain).to_be_bytes());
        Ok(plain)
    }

    /// `SealVMessAEADHeader`: auth_id | enc_len | conn_nonce | enc_header,
    /// both AEAD blocks authenticated with auth_id as AAD.
    fn seal_request_header(
        cmd_key: &[u8; 16],
        auth_id: &[u8; 16],
        conn_nonce: &[u8; 8],
        plain: &[u8],
    ) -> Vec<u8> {
        let extra: [&[u8]; 2] = [auth_id, conn_nonce];
        let len_key = kdf16(cmd_key, KDF_SALT_HEADER_LEN_KEY, &extra);
        let len_nonce = kdf12(cmd_key, KDF_SALT_HEADER_LEN_IV, &extra);
        let hdr_key = kdf16(cmd_key, KDF_SALT_HEADER_KEY, &extra);
        let hdr_nonce = kdf12(cmd_key, KDF_SALT_HEADER_IV, &extra);

        let mut out = Vec::with_capacity(16 + 18 + 8 + plain.len() + GCM_TAG_LEN);
        out.extend_from_slice(auth_id);
        out.extend_from_slice(&Self::seal_aad(
            &len_key,
            &len_nonce,
            &(plain.len() as u16).to_be_bytes(),
            auth_id,
        ));
        out.extend_from_slice(conn_nonce);
        out.extend_from_slice(&Self::seal_aad(&hdr_key, &hdr_nonce, plain, auth_id));
        out
    }

    fn seal_aad(key: &[u8; 16], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("valid key length");
        cipher
            .encrypt(
                <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                    .expect("nonce size"),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("seal")
    }

    fn open(
        key: &[u8; 16],
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("valid key length");
        cipher.decrypt(
            <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                .expect("nonce size"),
            ciphertext,
        )
    }

    #[cfg(test)]
    fn open_aad(
        key: &[u8; 16],
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, aes_gcm::aead::Error> {
        let cipher = aes_gcm::Aes128Gcm::new_from_slice(key).expect("valid key length");
        cipher.decrypt(
            <&aes_gcm::aead::Nonce<aes_gcm::Aes128Gcm>>::try_from(nonce.as_slice())
                .expect("nonce size"),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
    }

    /// Build the request header and return a proxy stream backed by a
    /// duplex pipe + background relay task.
    fn perform_handshake(
        uuid_bytes: &[u8],
        stream: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        ambiguous_header_io: bool,
    ) -> anyhow::Result<ProxyStream> {
        let cmd_key = Self::derive_cmd_key(uuid_bytes);
        let session = Session::new(ambiguous_header_io);

        let mut rng = rand::rng();
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let auth_id = Self::create_auth_id(&cmd_key, ts, rng.random());
        let conn_nonce: [u8; 8] = rng.random();
        // dice.Roll(16): 0..=15 — the length lives in the high nibble.
        let padding_len: u8 = rng.random_range(0..16);
        let mut padding = vec![0u8; padding_len as usize];
        rng.fill_bytes(&mut padding);

        let plain =
            Self::build_header_plain(&session, padding_len, &padding, target, target_domain)?;
        let header_wire = Self::seal_request_header(&cmd_key, &auth_id, &conn_nonce, &plain);

        Ok(ProxyStream {
            stream: Box::new(VmessStream::start(stream, header_wire, session)?),
            target_addr: target,
            target_domain: target_domain.map(|s| s.to_string()),
        })
    }
}

fn uuid(node: &Node) -> anyhow::Result<uuid::Uuid> {
    uuid::Uuid::parse_str(node.vmess().unwrap().uuid.as_deref().unwrap_or(""))
        .map_err(|error| anyhow::anyhow!("invalid VMess UUID: {}", error))
}

#[async_trait]
impl TcpOutbound for VmessHandler {
    async fn dial(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let uuid = uuid(node)?;

        let stream = super::transport::wrap_transport(node, None, connect_timeout).await?;
        Self::perform_handshake(uuid.as_bytes(), stream, target, target_domain, false)
    }

    async fn dial_with_tcp(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: TcpStream,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let uuid = uuid(node)?;

        let stream = super::transport::wrap_transport(node, Some(tcp), connect_timeout).await?;
        Self::perform_handshake(uuid.as_bytes(), stream, target, target_domain, false)
    }

    async fn dial_runtime(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let uuid = uuid(&runtime.node)?;
        let stream =
            super::transport::wrap_transport_runtime(&runtime, None, connect_timeout).await?;
        Self::perform_handshake(uuid.as_bytes(), stream, target, target_domain, false)
    }

    async fn dial_over(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        carrier: Box<dyn AsyncReadWrite>,
        target: SocketAddr,
        target_domain: Option<&str>,
        options: TunnelDialOptions,
    ) -> anyhow::Result<ProxyStream> {
        let uuid = uuid(&runtime.node)?;
        let stream = super::transport::wrap_tunnel(&runtime.node, carrier, options).await?;
        // Capture the route context before spawning the relay that reads the header.
        let ambiguous_header_io = ROUTED_CARRIER.try_with(|_| ()).is_ok();
        Self::perform_handshake(
            uuid.as_bytes(),
            stream,
            target,
            target_domain,
            ambiguous_header_io,
        )
    }
}

#[async_trait]
impl WarmableOutbound for VmessHandler {
    async fn warm(
        &self,
        runtime: Arc<crate::runtime::NodeRuntime>,
        connect_timeout: std::time::Duration,
        _requirement: WarmRequirement,
    ) -> anyhow::Result<()> {
        super::transport::xhttp::XhttpRuntime::warm(&runtime, connect_timeout).await
    }
}

#[async_trait]
impl ProbeableOutbound for VmessHandler {}

/// `ShakeSizeParser` (encoding/auth.go): a SHAKE128 stream over the body IV
/// yielding the 2-byte XOR mask for each chunk's length field, in order.
struct ShakeSizeParser(shake::ShakeReader<168>);

impl ShakeSizeParser {
    fn new(iv: &[u8; 16]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut h = shake::Shake128::default();
        h.update(iv);
        Self(h.finalize_xof())
    }

    fn next_mask(&mut self) -> [u8; 2] {
        use sha3::digest::XofReader;
        let mut mask = [0u8; 2];
        self.0.read(&mut mask);
        mask
    }

    fn encode_len(&mut self, size: u16) -> [u8; 2] {
        let mask = self.next_mask();
        let [a, b] = size.to_be_bytes();
        [a ^ mask[0], b ^ mask[1]]
    }

    fn decode_len(&mut self, encoded: [u8; 2]) -> u16 {
        let mask = self.next_mask();
        u16::from_be_bytes([encoded[0] ^ mask[0], encoded[1] ^ mask[1]])
    }
}

/// `GenerateChunkNonce`: the 12-byte nonce is the body IV's first 12 bytes
/// with the first two replaced by the big-endian chunk counter.
fn chunk_nonce(iv: &[u8; 16], count: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

/// Per-direction body chunk coder: SHAKE128 length masking + AES-128-GCM.
/// The AEAD runs on BoringSSL (`AeadCtx`): RustCrypto's aes-gcm measured
/// ~0.4 GB/s single-core vs BoringSSL's multi-GB/s on AES-NI
/// (benches/ss_aead.rs, same finding as the Shadowsocks `AeadCipher`),
/// which made the VMess relay single-core-bound. The header AEAD and the
/// auth-ID block stay on RustCrypto — two AEAD ops and one AES block per
/// connection are not hot.
struct BodyChunks {
    ctx: boring::aead::AeadCtx,
    iv: [u8; 16],
    size: ShakeSizeParser,
    count: u16,
}

impl BodyChunks {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> anyhow::Result<Self> {
        Ok(Self {
            ctx: boring::aead::AeadCtx::new_default_tag(
                &boring::aead::Algorithm::aes_128_gcm(),
                key,
            )?,
            iv: *iv,
            size: ShakeSizeParser::new(iv),
            count: 0,
        })
    }

    /// Seal one chunk: masked length field + AEAD(payload). An empty
    /// payload is the request-body termination chunk (Xray's outbound
    /// writes an empty MultiBuffer on upload EOF; without it the server
    /// keeps waiting for more request data).
    fn seal_chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        debug_assert!(payload.len() <= CHUNK_MAX_LEN);
        let mut out = Vec::with_capacity(2 + payload.len() + GCM_TAG_LEN);
        out.extend_from_slice(&self.size.encode_len((payload.len() + GCM_TAG_LEN) as u16));
        out.extend_from_slice(payload);
        out.resize(out.len() + GCM_TAG_LEN, 0);
        let (body, tag) = out[2..].split_at_mut(payload.len());
        self.ctx
            .seal_in_place(&chunk_nonce(&self.iv, self.count), body, tag, b"")
            .expect("AES-128-GCM seal");
        self.count = self.count.wrapping_add(1);
        out
    }

    fn decode_len(&mut self, encoded: [u8; 2]) -> u16 {
        self.size.decode_len(encoded)
    }

    /// Decrypt a chunk in place (ciphertext+tag → plaintext prefix) and
    /// return the plaintext length.
    fn open_chunk(&mut self, ct: &mut [u8]) -> anyhow::Result<usize> {
        anyhow::ensure!(ct.len() >= GCM_TAG_LEN, "short VMess chunk");
        let (body, tag) = ct.split_at_mut(ct.len() - GCM_TAG_LEN);
        self.ctx
            .open_in_place(&chunk_nonce(&self.iv, self.count), body, tag, b"")
            .map_err(|e| anyhow::anyhow!("VMess response chunk decrypt failed: {e}"))?;
        self.count = self.count.wrapping_add(1);
        Ok(body.len())
    }
}

/// Background task that encrypts client→server data and decrypts
/// server→client data using the VMess AEAD chunking format.
async fn vmess_relay(
    server: Box<dyn AsyncReadWrite>,
    client: &mut tokio::io::DuplexStream,
    header_wire: Vec<u8>,
    session: Session,
    pipe: &super::transport::relay_upload::Reader,
    uploaded: &mut Option<tokio::sync::oneshot::Sender<std::io::Result<()>>>,
    tail: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let peer_end = super::transport::WsPeerEnd::for_stream(server.as_ref());
    let omitted = AtomicBool::new(false);
    let (mut server_read, mut server_write) = tokio::io::split(server);
    let (mut client_read, mut client_write) = tokio::io::split(client);

    let upload = async {
        super::transport::write_request(&mut server_write, &header_wire).await?;

        let mut body = BodyChunks::new(&session.req_key, &session.req_iv)?;
        let mut buf = vec![0u8; CHUNK_MAX_LEN];
        let mut relayed = 0u64;
        loop {
            let n = match client_read.read(&mut buf).now_or_never() {
                Some(read) => read?,
                None => {
                    server_write.flush().await?;
                    client_read.read(&mut buf).await?
                }
            };
            if n == 0 {
                break;
            }
            relayed += n as u64;
            let chunk = body.seal_chunk(&buf[..n]);
            let writer = &mut server_write;
            let bytes = &chunk;
            pipe.forward(relayed, |flush| async move {
                writer.write_all(bytes).await?;
                if flush {
                    writer.flush().await?;
                }
                Ok::<_, std::io::Error>(())
            })
            .await?;
        }
        let term = body.seal_chunk(&[]);
        let mut remaining = term.as_slice();
        let result = super::transport::relay_upload::scope(async {
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
                break peer_end
                    .as_ref()
                    .map(|_| (chunk_nonce(&body.iv, body.count), body.ctx));
            }
            if !(chunk_len > GCM_TAG_LEN && chunk_len <= CHUNK_MAX_LEN + GCM_TAG_LEN) {
                return Err(crate::proxy::NodeFailure(
                    anyhow::anyhow!("invalid VMess chunk size {chunk_len}")
                        .context("VMess response body"),
                )
                .into());
            }
            let mut ct = vec![0u8; chunk_len];
            server_read.read_exact(&mut ct).await?;
            let n = body
                .open_chunk(&mut ct)
                .map_err(|error| crate::proxy::NodeFailure(error.context("VMess response body")))?;
            let mut remaining = &ct[..n];
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
        if let Some((nonce, cipher)) = marker {
            // Ordinary VMess readers accept the length alone as EOF. Only the
            // peer-close exception needs proof of the entire empty record.
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

fn response_header_fault(error: anyhow::Error) -> anyhow::Error {
    crate::proxy::NodeFailure(error.context("VMess response header")).into()
}

fn header_read_error(error: io::Error, ambiguous_header_io: bool) -> anyhow::Error {
    if ambiguous_header_io {
        // A raw carrier error can come from any preceding hop.
        error.into()
    } else {
        response_header_fault(error.into())
    }
}

async fn read_response_header_tail(
    reader: &mut (impl AsyncRead + Unpin),
    mut tail: &mut [u8],
    ambiguous_header_io: bool,
) -> anyhow::Result<()> {
    while !tail.is_empty() {
        let n = reader
            .read(tail)
            .await
            .map_err(|error| header_read_error(error, ambiguous_header_io))?;
        if n == 0 {
            let error = io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated VMess response header",
            );
            return Err(header_read_error(error, ambiguous_header_io));
        }
        tail = &mut tail[n..];
    }
    Ok(())
}

/// `DecodeResponseHeader`: AEAD-sealed length then AEAD-sealed payload,
/// keyed from the response body key/IV with no AAD.
async fn read_response_header<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    session: &Session,
) -> anyhow::Result<bool> {
    let mut len_ct = [0u8; 2 + GCM_TAG_LEN];
    let received = reader
        .read(&mut len_ct)
        .await
        .map_err(|error| header_read_error(error, session.ambiguous_header_io))?;
    // sing-vmess writes its response header lazily with the first target data;
    // no response bytes cannot distinguish target closure from a carrier fault.
    if received == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
    }
    read_response_header_tail(reader, &mut len_ct[received..], session.ambiguous_header_io).await?;
    let len_plain = VmessHandler::open(
        &kdf16(&session.resp_key, KDF_SALT_RESP_LEN_KEY, &[]),
        &kdf12(&session.resp_iv, KDF_SALT_RESP_LEN_IV, &[]),
        &len_ct,
    )
    .map_err(|e| {
        response_header_fault(anyhow::anyhow!(
            "VMess response header length decrypt failed: {e:?}"
        ))
    })?;
    let hdr_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    if !(4..=256).contains(&hdr_len) {
        return Err(response_header_fault(anyhow::anyhow!(
            "invalid VMess response header length {hdr_len}"
        )));
    }

    let mut hdr_ct = vec![0u8; hdr_len + GCM_TAG_LEN];
    read_response_header_tail(reader, &mut hdr_ct, session.ambiguous_header_io).await?;
    let hdr = VmessHandler::open(
        &kdf16(&session.resp_key, KDF_SALT_RESP_KEY, &[]),
        &kdf12(&session.resp_iv, KDF_SALT_RESP_IV, &[]),
        &hdr_ct,
    )
    .map_err(|e| {
        response_header_fault(anyhow::anyhow!(
            "VMess response header decrypt failed: {e:?}"
        ))
    })?;
    if hdr[0] != session.resp_header {
        return Err(response_header_fault(anyhow::anyhow!(
            "unexpected VMess response header byte {:#x}, expected {:#x}",
            hdr[0],
            session.resp_header
        )));
    }
    // hdr[1] option, hdr[2] command id, hdr[3] command data length; the
    // command data rides inside the same header block and carries nothing
    // a plain TCP outbound needs.
    Ok(hdr[2] == 0 || hdr.len() >= 4 + usize::from(hdr[3]))
}

#[cfg(test)]
pub(super) mod test_support;

#[cfg(test)]
mod tests;

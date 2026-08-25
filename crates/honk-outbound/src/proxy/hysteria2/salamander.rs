use std::time::Instant;

use parking_lot::Mutex;
use rand::{Rng, RngExt};

use super::*;

// BLAKE2b-256 (RFC 7693) — salamander obfuscation key derivation.

pub(super) const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

pub(super) const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[allow(clippy::many_single_char_names)]
pub(super) fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, chunk) in block.as_chunks::<8>().0.iter().enumerate() {
        m[i] = u64::from_le_bytes(*chunk);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    for round in &BLAKE2B_SIGMA {
        #[inline(always)]
        fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
            v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
            v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]);
            v[b] = (v[b] ^ v[c]).rotate_right(63);
        }
        g(&mut v, 0, 4, 8, 12, m[round[0]], m[round[1]]);
        g(&mut v, 1, 5, 9, 13, m[round[2]], m[round[3]]);
        g(&mut v, 2, 6, 10, 14, m[round[4]], m[round[5]]);
        g(&mut v, 3, 7, 11, 15, m[round[6]], m[round[7]]);
        g(&mut v, 0, 5, 10, 15, m[round[8]], m[round[9]]);
        g(&mut v, 1, 6, 11, 12, m[round[10]], m[round[11]]);
        g(&mut v, 2, 7, 8, 13, m[round[12]], m[round[13]]);
        g(&mut v, 3, 4, 9, 14, m[round[14]], m[round[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b with a 32-byte digest and no key (what Go's `blake2b.Sum256`
/// computes, `salamander.go:50`).
pub(super) fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = BLAKE2B_IV;
    // Parameter block: digest length 32, key length 0, fanout 1, depth 1.
    h[0] ^= 0x0101_0000 ^ 32;
    let mut t = 0u128;
    // Compress all full 128-byte blocks except the trailing chunk, which is
    // zero-padded into the final block and gets the finalization flag.
    let full_blocks = data.len() / 128;
    let head_len = if data.len().is_multiple_of(128) && full_blocks > 0 {
        (full_blocks - 1) * 128
    } else {
        full_blocks * 128
    };
    let (head, tail) = data.split_at(head_len);
    for chunk in head.as_chunks::<128>().0 {
        t += 128;
        blake2b_compress(&mut h, chunk, t, false);
    }
    let mut last_block = [0u8; 128];
    last_block[..tail.len()].copy_from_slice(tail);
    t += tail.len() as u128;
    blake2b_compress(&mut h, &last_block, t, true);
    let mut out = [0u8; 32];
    for (i, word) in h[..4].iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// Salamander obfuscation (sing-quic hysteria2/salamander.go).

pub(super) const SALAMANDER_SALT_LEN: usize = 8;
pub(super) const SALAMANDER_MIN_PSK_LEN: usize = 4;

#[inline]
fn salamander_key(password: &[u8], salt: &[u8; SALAMANDER_SALT_LEN]) -> [u8; 32] {
    // Hysteria passwords are normally short. Keep the common key derivation
    // allocation-free; retain the heap fallback for unusually long secrets.
    const STACK_INPUT_LEN: usize = 128;
    if password.len() <= STACK_INPUT_LEN - SALAMANDER_SALT_LEN {
        let mut input = [0u8; STACK_INPUT_LEN];
        input[..password.len()].copy_from_slice(password);
        input[password.len()..password.len() + SALAMANDER_SALT_LEN].copy_from_slice(salt);
        return blake2b256(&input[..password.len() + SALAMANDER_SALT_LEN]);
    }
    let mut input = Vec::with_capacity(password.len() + SALAMANDER_SALT_LEN);
    input.extend_from_slice(password);
    input.extend_from_slice(salt);
    blake2b256(&input)
}

fn salamander_seal_into(password: &[u8], data: &[u8], out: &mut Vec<u8>) {
    out.resize(SALAMANDER_SALT_LEN + data.len(), 0);
    rand::rng().fill_bytes(&mut out[..SALAMANDER_SALT_LEN]);
    let salt: [u8; SALAMANDER_SALT_LEN] = out[..SALAMANDER_SALT_LEN]
        .try_into()
        .expect("fixed salt length");
    let key = salamander_key(password, &salt);
    for (index, byte) in data.iter().enumerate() {
        out[SALAMANDER_SALT_LEN + index] = byte ^ key[index % 32];
    }
}

/// Encrypt one datagram: 8-byte random salt, then payload XORed with
/// BLAKE2b-256(password ++ salt) cycled (`salamander.go:57-70`).
#[cfg(test)]
pub(super) fn salamander_seal(password: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SALAMANDER_SALT_LEN + data.len());
    salamander_seal_into(password, data, &mut out);
    out
}

/// Decrypt a datagram in place, returning the payload length (the salt is
/// compacted away), or `None` for malformed packets (`salamander.go:42-55`).
pub(super) fn salamander_open(password: &[u8], buf: &mut [u8]) -> Option<usize> {
    if buf.len() <= SALAMANDER_SALT_LEN {
        return None;
    }
    let salt: [u8; SALAMANDER_SALT_LEN] = buf[..SALAMANDER_SALT_LEN].try_into().ok()?;
    let key = salamander_key(password, &salt);
    let len = buf.len() - SALAMANDER_SALT_LEN;
    for i in 0..len {
        buf[i] = buf[i + SALAMANDER_SALT_LEN] ^ key[i % 32];
    }
    Some(len)
}

/// quinn `AsyncUdpSocket` for hysteria2 with optional salamander
/// obfuscation and optional client-side port hopping (`mport`/`mhop`).
///
/// Built directly on a tokio socket (no GSO/GRO segmentation), so every
/// `Transmit`/`RecvMeta` carries exactly one datagram to (de)obfuscate.
#[derive(Debug)]
pub(super) struct Hy2UdpSocket {
    socket: Arc<tokio::net::UdpSocket>,
    obfs: Option<Arc<[u8]>>,
    obfs_send: Option<Mutex<Vec<u8>>>,
    hop: Mutex<Option<HopState>>,
}

impl Hy2UdpSocket {
    fn new(
        ipv6: bool,
        obfs: Option<Arc<[u8]>>,
        hop: Option<(Vec<u16>, Duration)>,
    ) -> io::Result<Self> {
        let socket = tokio::net::UdpSocket::from_std(crate::quic::marked_udp_socket(ipv6)?)?;
        Ok(Self::from_socket(socket, obfs, hop))
    }

    pub(super) fn from_socket(
        socket: tokio::net::UdpSocket,
        obfs: Option<Arc<[u8]>>,
        hop: Option<(Vec<u16>, Duration)>,
    ) -> Self {
        let obfs_send = obfs.as_ref().map(|_| Mutex::new(Vec::with_capacity(2048)));
        Self {
            socket: Arc::new(socket),
            obfs,
            obfs_send,
            hop: Mutex::new(hop.map(|(ports, interval)| HopState::new(ports, interval))),
        }
    }
}

/// Client-side port hopping state: every `interval` the next outbound
/// datagram goes to a random different port from the hopping list (the
/// official client's `hopLoop`; the server side is expected to DNAT the
/// whole range onto its listen port).
#[derive(Debug)]
pub(super) struct HopState {
    ports: Vec<u16>,
    interval: Duration,
    pub(super) last_hop: Instant,
    current: Option<u16>,
    /// The connection's nominal remote port (learned from the first send).
    /// Received packets have their source port rewritten to it: with
    /// server-side DNAT, reply sources are rewritten to the hop port by
    /// conntrack, and QUIC must see a stable peer address (sing-quic's
    /// hopping conn does the same substitution).
    base: Option<u16>,
}

impl HopState {
    pub(super) fn new(ports: Vec<u16>, interval: Duration) -> Self {
        Self {
            ports,
            interval,
            last_hop: Instant::now(),
            current: None,
            base: None,
        }
    }

    /// Destination port for the next outbound datagram. The very first call
    /// already hops, so the connection never mixes the base port with the
    /// redirected range.
    pub(super) fn port(&mut self, base: u16) -> u16 {
        if self.ports.is_empty() {
            return base;
        }
        self.base.get_or_insert(base);
        if let Some(current) = self.current
            && self.last_hop.elapsed() < self.interval
        {
            return current;
        }
        let next = if self.ports.len() == 1 {
            self.ports[0]
        } else {
            let mut rng = rand::rng();
            loop {
                let port = self.ports[rng.random_range(0..self.ports.len())];
                if Some(port) != self.current {
                    break port;
                }
            }
        };
        self.current = Some(next);
        self.last_hop = Instant::now();
        next
    }

    /// Nominal remote port for receive-side source rewriting (see above).
    pub(super) fn base_port(&self) -> Option<u16> {
        self.base
    }
}

/// Parse an `mport` list (`20000-30000` / `8080,8888-8890`) into ports.
pub(super) fn parse_port_hopping(spec: &str) -> Option<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((lo, hi)) => {
                let lo: u16 = lo.trim().parse().ok()?;
                let hi: u16 = hi.trim().parse().ok()?;
                if lo == 0 || hi < lo {
                    return None;
                }
                ports.extend(lo..=hi);
            }
            None => {
                let port: u16 = part.parse().ok()?;
                if port == 0 {
                    return None;
                }
                ports.push(port);
            }
        }
    }
    (!ports.is_empty()).then_some(ports)
}

#[derive(Debug)]
pub(super) struct Hy2UdpPoller {
    socket: Arc<tokio::net::UdpSocket>,
}

impl UdpPoller for Hy2UdpPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

impl AsyncUdpSocket for Hy2UdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Hy2UdpPoller {
            socket: Arc::clone(&self.socket),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let destination = match &mut *self.hop.lock() {
            Some(hop) => SocketAddr::new(
                transmit.destination.ip(),
                hop.port(transmit.destination.port()),
            ),
            None => transmit.destination,
        };
        match (&self.obfs, &self.obfs_send) {
            (Some(password), Some(send_buffer)) => {
                let mut packet = send_buffer.lock();
                salamander_seal_into(password, transmit.contents, &mut packet);
                self.socket.try_send_to(&packet, destination)?;
            }
            _ => {
                self.socket.try_send_to(transmit.contents, destination)?;
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let base_port = self.hop.lock().as_ref().and_then(HopState::base_port);
        let mut count = 0;
        for (buf, meta_slot) in bufs.iter_mut().zip(meta.iter_mut()) {
            let mut read_buf = ReadBuf::new(&mut buf[..]);
            match self.socket.poll_recv_from(cx, &mut read_buf) {
                Poll::Ready(Ok(addr)) => {
                    let len = match &self.obfs {
                        Some(password) => salamander_open(password, read_buf.filled_mut()),
                        None => Some(read_buf.filled().len()),
                    };
                    if let Some(len) = len {
                        let addr = match base_port {
                            Some(port) => SocketAddr::new(addr.ip(), port),
                            None => addr,
                        };
                        *meta_slot = quinn::udp::RecvMeta {
                            addr,
                            len,
                            stride: len,
                            ecn: None,
                            dst_ip: None,
                        };
                        count += 1;
                    }
                }
                Poll::Ready(Err(error)) => {
                    return if count == 0 {
                        Poll::Ready(Err(error))
                    } else {
                        Poll::Ready(Ok(count))
                    };
                }
                Poll::Pending => {
                    return if count == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(count))
                    };
                }
            }
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    /// Salamander adds eight wire bytes, and quic-go can send 1280-byte
    /// handshake packets despite a smaller advertised peer maximum. Giving
    /// Quinn two receive segments enlarges its buffer without raising that
    /// advertised steady-state MTU; each `RecvMeta` still describes one packet.
    fn max_receive_segments(&self) -> usize {
        2
    }

    /// The tokio socket does not set DONTFRAG; reporting `true` also keeps
    /// quinn's MTU discovery off the obfuscated path (the +8 byte salt would
    /// otherwise skew probe sizes).
    fn may_fragment(&self) -> bool {
        true
    }
}

/// Endpoint factory for hysteria2 QUIC connections with optional salamander
/// obfuscation and/or port hopping (`client.go:275-277`).
pub(super) fn hy2_endpoint_factory(
    obfs: Option<Arc<[u8]>>,
    hop: Option<(Vec<u16>, Duration)>,
    mtu: u16,
) -> impl Fn(bool) -> io::Result<Endpoint> + Send + Sync {
    move |ipv6| {
        let socket = Arc::new(Hy2UdpSocket::new(ipv6, obfs.clone(), hop.clone())?);
        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::other("no async runtime available for QUIC"))?;
        Endpoint::new_with_abstract_socket(
            crate::quic::endpoint_config_with_mtu(mtu)?,
            None,
            socket,
            runtime,
        )
    }
}

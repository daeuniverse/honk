//! Loopback servers for the shared-source protocols (Shadowsocks AEAD, SOCKS5
//! UDP ASSOCIATE, plaintext Trojan). Each maps one client association to ONE
//! unconnected egress socket, exactly like the Hy2/TUIC fixture in
//! `control/tests/support.rs`, so a destination that was never contacted can
//! reach the client through the association's mapped address. Wire formats are
//! spelled out here and never reuse the production codecs.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use anyhow::{Context, ensure};
use honk_config::node::{Node, OutboundConfig};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::{JoinHandle, JoinSet};

const PASSWORD: &str = "shared-source-test-password";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::control::tests) enum SharedUdpMode {
    Shadowsocks,
    Socks5,
    Trojan,
}

/// One client datagram as the server relayed it to its destination.
#[derive(Debug)]
pub(in crate::control::tests) struct SharedUdpPacket {
    /// Serial of the client association (UDP source for SS, control TCP
    /// connection for SOCKS5/Trojan): equal values mean one association.
    pub(in crate::control::tests) association: u64,
    pub(in crate::control::tests) target: SocketAddr,
    /// The association's single egress socket, the address peers see.
    pub(in crate::control::tests) mapping: SocketAddr,
    pub(in crate::control::tests) payload: Vec<u8>,
}

pub(in crate::control::tests) struct SharedUdpPeer {
    pub(in crate::control::tests) node: Node,
    pub(in crate::control::tests) packets: UnboundedReceiver<SharedUdpPacket>,
    task: JoinHandle<anyhow::Result<()>>,
}

impl SharedUdpPeer {
    pub(in crate::control::tests) async fn start(
        mode: SharedUdpMode,
        bind: SocketAddr,
    ) -> anyhow::Result<Self> {
        let (events, packets) = unbounded_channel();
        let (address, task) = match mode {
            SharedUdpMode::Shadowsocks => {
                let server = UdpSocket::bind(bind).await?;
                let address = server.local_addr()?;
                let task = tokio::spawn(run_shadowsocks(server, address.ip(), events));
                (address, task)
            }
            SharedUdpMode::Socks5 | SharedUdpMode::Trojan => {
                let listener = TcpListener::bind(bind).await?;
                let address = listener.local_addr()?;
                let task = tokio::spawn(run_stream(mode, listener, address.ip(), events));
                (address, task)
            }
        };
        let outbound = match mode {
            SharedUdpMode::Shadowsocks => {
                OutboundConfig::Shadowsocks(honk_config::node::ShadowsocksConfig {
                    password: Some(PASSWORD.into()),
                    encryption: Some("aes-128-gcm".into()),
                    ..Default::default()
                })
            }
            SharedUdpMode::Socks5 => OutboundConfig::Socks5(Default::default()),
            // `tls.enabled` defaults to false: the Trojan stream is plaintext.
            SharedUdpMode::Trojan => OutboundConfig::Trojan(honk_config::node::TrojanConfig {
                password: Some(PASSWORD.into()),
                ..Default::default()
            }),
        };
        let mut node = Node {
            name: format!("shared-{mode:?}"),
            host: address.ip().to_string(),
            address: address.to_string(),
            port: address.port(),
            outbound,
            ..Default::default()
        };
        node.id = node.derive_id();
        Ok(Self {
            node,
            packets,
            task,
        })
    }

    /// A peer failure (bad frame, auth mismatch) surfaces here instead of as a
    /// silent hang; a healthy peer is simply stopped.
    pub(in crate::control::tests) async fn close(self) -> anyhow::Result<()> {
        if self.task.is_finished() {
            return self.task.await?;
        }
        self.task.abort();
        let _ = self.task.await;
        Ok(())
    }
}

fn put_addr(out: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
}

fn take_addr(wire: &[u8]) -> anyhow::Result<(SocketAddr, &[u8])> {
    let (ip, rest): (IpAddr, _) = match wire.split_first() {
        Some((1, rest)) if rest.len() >= 6 => (<[u8; 4]>::try_from(&rest[..4])?.into(), &rest[4..]),
        Some((4, rest)) if rest.len() >= 18 => {
            (<[u8; 16]>::try_from(&rest[..16])?.into(), &rest[16..])
        }
        _ => anyhow::bail!("fixture expects a numeric target"),
    };
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Ok((SocketAddr::new(ip, port), &rest[2..]))
}

async fn read_addr<R: AsyncReadExt + Unpin>(stream: &mut R) -> anyhow::Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    let mut wire = [0u8; 19];
    wire[0] = atyp[0];
    let len = match atyp[0] {
        1 => 6,
        4 => 18,
        other => anyhow::bail!("fixture expects a numeric target, got ATYP {other}"),
    };
    stream.read_exact(&mut wire[1..=len]).await?;
    Ok(take_addr(&wire[..=len])?.0)
}

async fn egress(bind: IpAddr) -> anyhow::Result<Arc<UdpSocket>> {
    // Marked like the Hy2/TUIC fixture so honk's own datapath ignores it.
    Ok(Arc::new(
        honk_outbound::util::udp_marked_bind(SocketAddr::new(bind, 0)).await?,
    ))
}

/// Forward everything the egress socket receives together with its real source.
fn spawn_egress_reader<T: Clone + Send + Sync + 'static>(
    tasks: &mut JoinSet<anyhow::Result<()>>,
    socket: Arc<UdpSocket>,
    tag: T,
    replies: UnboundedSender<(T, SocketAddr, Vec<u8>)>,
) {
    tasks.spawn(async move {
        let mut buffer = vec![0u8; 65536];
        loop {
            let (size, source) = socket.recv_from(&mut buffer).await?;
            replies.send((tag.clone(), source, buffer[..size].to_vec()))?;
        }
    });
}

// ---- Shadowsocks AEAD (aes-128-gcm), one datagram = salt | AEAD(addr|payload) ----

fn ss_master_key() -> [u8; 16] {
    // EVP_BytesToKey(MD5, no salt, one round) per shadowsocks.org/doc/aead.html.
    use md5::{Digest, Md5};
    let (mut key, mut previous) = (Vec::new(), Vec::new());
    while key.len() < 16 {
        previous.extend_from_slice(PASSWORD.as_bytes());
        previous = Md5::digest(&previous).to_vec();
        key.extend_from_slice(&previous);
    }
    key[..16].try_into().unwrap()
}

fn ss_cipher(master: &[u8; 16], salt: &[u8]) -> Aes128Gcm {
    let mut subkey = [0u8; 16];
    hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), master)
        .expand(b"ss-subkey", &mut subkey)
        .unwrap();
    Aes128Gcm::new_from_slice(&subkey).unwrap()
}

fn ss_open(master: &[u8; 16], packet: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(packet.len() >= 16 + 16, "short Shadowsocks datagram");
    let (salt, sealed) = packet.split_at(16);
    ss_cipher(master, salt)
        .decrypt(&Nonce::from([0u8; 12]), sealed)
        .map_err(|_| anyhow::anyhow!("Shadowsocks datagram authentication failed"))
}

fn ss_seal(master: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    let mut packet = salt.to_vec();
    packet.extend(
        ss_cipher(master, &salt)
            .encrypt(&Nonce::from([0u8; 12]), plain)
            .unwrap(),
    );
    packet
}

async fn run_shadowsocks(
    server: UdpSocket,
    bind: IpAddr,
    events: UnboundedSender<SharedUdpPacket>,
) -> anyhow::Result<()> {
    let master = ss_master_key();
    let mut clients = HashMap::<SocketAddr, (u64, Arc<UdpSocket>)>::new();
    let (reply_tx, mut reply_rx) = unbounded_channel();
    let mut tasks = JoinSet::<anyhow::Result<()>>::new();
    let mut buffer = vec![0u8; 65536];
    loop {
        tokio::select! {
            received = server.recv_from(&mut buffer) => {
                let (size, client) = received?;
                let body = ss_open(&master, &buffer[..size])?;
                let (target, payload) = take_addr(&body)?;
                let serial = clients.len() as u64 + 1;
                if let std::collections::hash_map::Entry::Vacant(entry) = clients.entry(client) {
                    let socket = egress(bind).await?;
                    spawn_egress_reader(&mut tasks, Arc::clone(&socket), client, reply_tx.clone());
                    entry.insert((serial, socket));
                }
                let (association, socket) = &clients[&client];
                socket.send_to(payload, target).await?;
                events.send(SharedUdpPacket {
                    association: *association,
                    target,
                    mapping: socket.local_addr()?,
                    payload: payload.to_vec(),
                })?;
            }
            Some((client, source, payload)) = reply_rx.recv() => {
                let mut plain = Vec::new();
                put_addr(&mut plain, source);
                plain.extend_from_slice(&payload);
                server.send_to(&ss_seal(&master, &plain), client).await?;
            }
            result = tasks.join_next(), if !tasks.is_empty() => result.unwrap()??,
        }
    }
}

// ---- SOCKS5 UDP ASSOCIATE (RFC 1928) and plaintext Trojan, one TCP control stream per association ----

async fn run_stream(
    mode: SharedUdpMode,
    listener: TcpListener,
    bind: IpAddr,
    events: UnboundedSender<SharedUdpPacket>,
) -> anyhow::Result<()> {
    let mut associations = JoinSet::<anyhow::Result<()>>::new();
    let mut serial = 0;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                serial += 1;
                let events = events.clone();
                associations.spawn(async move {
                    let result = match mode {
                        SharedUdpMode::Socks5 => socks5_association(stream, bind, serial, events).await,
                        _ => trojan_association(stream, bind, serial, events).await,
                    };
                    // honk opens a bare connection ahead of use and may drop it
                    // unused; one that dies before its request is no association.
                    match result {
                        Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(
                            |error| error.kind() == std::io::ErrorKind::UnexpectedEof,
                        ) => Ok(()),
                        result => result,
                    }
                });
            }
            result = associations.join_next(), if !associations.is_empty() => result.unwrap()??,
        }
    }
}

async fn socks5_association(
    mut control: tokio::net::TcpStream,
    bind: IpAddr,
    serial: u64,
    events: UnboundedSender<SharedUdpPacket>,
) -> anyhow::Result<()> {
    let mut head = [0u8; 2];
    control.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    control.read_exact(&mut methods).await?;
    ensure!(head[0] == 5 && methods.contains(&0), "SOCKS5 greeting");
    control.write_all(&[5, 0]).await?;
    let mut request = [0u8; 3];
    control.read_exact(&mut request).await?;
    ensure!(request == [5, 3, 0], "expected SOCKS5 UDP ASSOCIATE");
    read_addr(&mut control).await?;
    // One relay socket per association identifies it without trusting a client port.
    let relay = UdpSocket::bind(SocketAddr::new(bind, 0)).await?;
    let mut reply = vec![5, 0, 0];
    put_addr(&mut reply, relay.local_addr()?);
    control.write_all(&reply).await?;

    let socket = egress(bind).await?;
    let mapping = socket.local_addr()?;
    let mut client = None;
    let mut inbound = vec![0u8; 65536];
    let mut outbound = vec![0u8; 65536];
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            received = relay.recv_from(&mut inbound) => {
                let (size, source) = received?;
                client = Some(source);
                ensure!(size >= 4 && inbound[..3] == [0, 0, 0], "SOCKS5 UDP header");
                let (target, payload) = take_addr(&inbound[3..size])?;
                socket.send_to(payload, target).await?;
                events.send(SharedUdpPacket {
                    association: serial,
                    target,
                    mapping,
                    payload: payload.to_vec(),
                })?;
            }
            received = socket.recv_from(&mut outbound) => {
                let (size, source) = received?;
                let client = client.context("reply before the first client datagram")?;
                let mut wire = vec![0, 0, 0];
                put_addr(&mut wire, source);
                wire.extend_from_slice(&outbound[..size]);
                relay.send_to(&wire, client).await?;
            }
            closed = control.read(&mut probe) => {
                // The association lives exactly as long as its control stream.
                ensure!(closed? == 0, "unexpected SOCKS5 control bytes");
                return Ok(());
            }
        }
    }
}

async fn trojan_association(
    stream: tokio::net::TcpStream,
    bind: IpAddr,
    serial: u64,
    events: UnboundedSender<SharedUdpPacket>,
) -> anyhow::Result<()> {
    use sha2::{Digest, Sha224};
    let (mut reader, mut writer) = stream.into_split();
    let mut credential = [0u8; 56 + 2 + 1];
    reader.read_exact(&mut credential).await?;
    let expected: String = Sha224::digest(PASSWORD.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    ensure!(
        credential[..56] == *expected.as_bytes() && credential[56..58] == *b"\r\n",
        "Trojan credential"
    );
    ensure!(credential[58] == 3, "expected Trojan UDP command");
    read_addr(&mut reader).await?;
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).await?;
    ensure!(crlf == *b"\r\n", "Trojan request terminator");

    let socket = egress(bind).await?;
    let mapping = socket.local_addr()?;
    let mut tasks = JoinSet::<anyhow::Result<()>>::new();
    let (reply_tx, mut reply_rx) = unbounded_channel();
    spawn_egress_reader(&mut tasks, Arc::clone(&socket), (), reply_tx);
    tasks.spawn(async move {
        while let Some(((), source, payload)) = reply_rx.recv().await {
            let mut frame = Vec::new();
            put_addr(&mut frame, source);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            frame.extend_from_slice(b"\r\n");
            frame.extend_from_slice(&payload);
            writer.write_all(&frame).await?;
        }
        Ok(())
    });
    loop {
        let mut probe = [0u8; 1];
        if reader.read(&mut probe).await? == 0 {
            return Ok(());
        }
        // Put the peeked ATYP back in front of the address decoder.
        let mut chained = (&probe[..]).chain(&mut reader);
        let target = read_addr(&mut chained).await?;
        let mut head = [0u8; 4];
        reader.read_exact(&mut head).await?;
        ensure!(head[2..] == *b"\r\n", "Trojan frame terminator");
        let mut payload = vec![0u8; usize::from(u16::from_be_bytes([head[0], head[1]]))];
        reader.read_exact(&mut payload).await?;
        socket.send_to(&payload, target).await?;
        events.send(SharedUdpPacket {
            association: serial,
            target,
            mapping,
            payload,
        })?;
    }
}

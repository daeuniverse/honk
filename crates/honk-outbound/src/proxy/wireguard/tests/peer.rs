//! The far side of a tunnel, in process: a boringtun `Tunn` on a loopback UDP socket with a
//! smoltcp interface behind it hosting TCP/UDP services. Independent of the code under test.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use honk_config::node::{Node, OutboundConfig, WireGuardConfig, WireGuardKey};
use rand::RngExt as _;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const PEER_IP2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
/// Owned by the peer's interface but outside the client's allowed IPs.
pub const SPOOF_IP: Ipv4Addr = Ipv4Addr::new(10, 9, 9, 9);
pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

pub const ECHO: u16 = 7;
/// Counts received bytes, replies `done:<n>` after the client's FIN and closes.
pub const SUM: u16 = 9;
/// Accepts, reads one byte, then aborts the connection (RST).
pub const ABORT: u16 = 10;
/// Accepts and never reads.
pub const STALL: u16 = 11;
pub const UDP_ECHO: u16 = 53;
/// Replies from an address outside the client's allowed IPs.
pub const UDP_SPOOF: u16 = 54;

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Echo,
    Sum,
    Abort,
    Stall,
}

struct Service {
    handle: SocketHandle,
    kind: Kind,
    port: u16,
    count: u64,
    replied: bool,
}

#[derive(Default)]
pub struct Control {
    /// Drop every datagram in both directions (a dead path).
    pub mute: AtomicBool,
    /// Drop inner TCP packets after decryption, keep the tunnel and UDP alive.
    pub drop_tcp: AtomicBool,
    pub inner_tcp_dropped: AtomicU64,
    pub handshakes: AtomicU64,
    /// Silently drop this many incoming handshake initiations (a lossy path), then answer.
    pub drop_inits: AtomicU64,
}

pub struct Peer {
    pub addr: SocketAddr,
    pub secret: [u8; 32],
    pub public: [u8; 32],
    pub control: Arc<Control>,
    /// First four bytes of every datagram the peer received.
    pub wire: Arc<parking_lot::Mutex<Vec<[u8; 4]>>>,
    commands: mpsc::UnboundedSender<Command>,
    task: tokio::task::JoinHandle<()>,
}

enum Command {
    Garbage(usize),
    Forged(usize),
}

pub fn key_pair() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    rand::rng().fill(&mut secret);
    let public = PublicKey::from(&StaticSecret::from(secret));
    (secret, *public.as_bytes())
}

pub fn wg_key(bytes: &[u8; 32]) -> WireGuardKey {
    base64::engine::general_purpose::STANDARD
        .encode(bytes)
        .parse()
        .unwrap()
}

struct IpDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct In(Vec<u8>);
struct Out<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for In {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Out<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut data = vec![0; len];
        let result = f(&mut data);
        self.0.push_back(data);
        result
    }
}

impl Device for IpDevice {
    type RxToken<'a> = In;
    type TxToken<'a> = Out<'a>;

    fn receive(&mut self, _: SmolInstant) -> Option<(In, Out<'_>)> {
        let data = self.rx.pop_front()?;
        Some((In(data), Out(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<Out<'_>> {
        Some(Out(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1420;
        caps
    }
}

impl Peer {
    pub async fn spawn(client_public: [u8; 32], reserved: Option<[u8; 3]>) -> Peer {
        Self::spawn_with(key_pair().0, client_public, reserved).await
    }

    pub async fn spawn_with(
        secret: [u8; 32],
        client_public: [u8; 32],
        reserved: Option<[u8; 3]>,
    ) -> Peer {
        let public = *PublicKey::from(&StaticSecret::from(secret)).as_bytes();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let control = Arc::new(Control::default());
        let wire = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let (commands, command_rx) = mpsc::unbounded_channel();
        let tunn = Tunn::new(
            StaticSecret::from(secret),
            PublicKey::from(client_public),
            None,
            None,
            rand::rng().random::<u32>() >> 8,
            None,
        );
        let task = tokio::spawn(run(
            socket,
            tunn,
            client_public,
            reserved,
            Arc::clone(&control),
            Arc::clone(&wire),
            command_rx,
        ));
        Peer {
            addr,
            secret,
            public,
            control,
            wire,
            commands,
            task,
        }
    }

    /// Datagrams of data-message shape that fail authentication, sent from the peer's endpoint.
    pub fn send_garbage(&self, count: usize) {
        self.commands.send(Command::Garbage(count)).unwrap();
    }

    /// Mac1-valid forged initiations from a foreign address (cookie replies when under load).
    pub fn send_forged_initiations(&self, count: usize) {
        self.commands.send(Command::Forged(count)).unwrap();
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn smol_now(epoch: Instant) -> SmolInstant {
    SmolInstant::from_micros(epoch.elapsed().as_micros() as i64)
}

async fn run(
    socket: UdpSocket,
    mut tunn: Tunn,
    client_public: [u8; 32],
    reserved: Option<[u8; 3]>,
    control: Arc<Control>,
    wire: Arc<parking_lot::Mutex<Vec<[u8; 4]>>>,
    mut commands: mpsc::UnboundedReceiver<Command>,
) {
    let epoch = Instant::now();
    let mut device = IpDevice {
        rx: VecDeque::new(),
        tx: VecDeque::new(),
    };
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut device,
        smol_now(epoch),
    );
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(PEER_IP), 24))
            .unwrap();
        addrs
            .push(IpCidr::new(IpAddress::Ipv4(PEER_IP2), 24))
            .unwrap();
    });
    let mut sockets = SocketSet::new(vec![]);
    let mut services = Vec::new();
    for (kind, port) in [
        (Kind::Echo, ECHO),
        (Kind::Sum, SUM),
        (Kind::Abort, ABORT),
        (Kind::Stall, STALL),
    ] {
        for _ in 0..8 {
            let handle = sockets.add(tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 64 * 1024]),
                tcp::SocketBuffer::new(vec![0; 64 * 1024]),
            ));
            services.push(Service {
                handle,
                kind,
                port,
                count: 0,
                replied: false,
            });
        }
    }
    let udp_socket = |sockets: &mut SocketSet<'static>, port: u16| {
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 32 * 2048]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 32 * 2048]),
        );
        socket.bind(IpListenEndpoint::from(port)).unwrap();
        sockets.add(socket)
    };
    let udp_echo = udp_socket(&mut sockets, UDP_ECHO);
    let udp_spoof = udp_socket(&mut sockets, UDP_SPOOF);

    let mut client: Option<SocketAddr> = None;
    let mut rx = vec![0u8; 65_536];
    let mut out = vec![0u8; 65_536 + 64];
    let mut timers = tokio::time::interval(Duration::from_millis(20));
    let mut sends: Vec<Vec<u8>> = Vec::new();
    loop {
        tokio::select! {
            received = socket.recv_from(&mut rx) => {
                let Ok((n, from)) = received else { continue };
                if control.mute.load(Ordering::Relaxed) {
                    continue;
                }
                let mut first = [0u8; 4];
                first[..n.min(4)].copy_from_slice(&rx[..n.min(4)]);
                wire.lock().push(first);
                if rx[0] == 1
                    && control
                        .drop_inits
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |left| left.checked_sub(1))
                        .is_ok()
                {
                    continue;
                }
                if reserved.is_some() && n > 3 {
                    rx[1..4].fill(0);
                }
                client = Some(from);
                if rx[0] == 1 {
                    control.handshakes.fetch_add(1, Ordering::Relaxed);
                }
                let mut result = tunn.decapsulate(Some(from.ip()), &rx[..n], &mut out);
                loop {
                    match result {
                        TunnResult::WriteToNetwork(packet) => {
                            sends.push(packet.to_vec());
                            result = tunn.decapsulate(None, &[], &mut out);
                        }
                        TunnResult::WriteToTunnelV4(packet, _) => {
                            if control.drop_tcp.load(Ordering::Relaxed) && packet[9] == 6 {
                                control.inner_tcp_dropped.fetch_add(1, Ordering::Relaxed);
                            } else {
                                device.rx.push_back(packet.to_vec());
                            }
                            break;
                        }
                        _ => break,
                    }
                }
            }
            Some(command) = commands.recv() => match command {
                Command::Garbage(count) => {
                    if let Some(to) = client {
                        for _ in 0..count {
                            let mut junk = [0u8; 64];
                            rand::rng().fill(&mut junk);
                            junk[..4].copy_from_slice(&[4, 0, 0, 0]);
                            let _ = socket.send_to(&junk, to).await;
                        }
                    }
                }
                Command::Forged(count) => {
                    // Handshake initiations with a valid mac1 (it only needs the client's public
                    // key) from an address that is not the peer's, from a key the client does not know.
                    if let Some(to) = client {
                        let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                        let mut secret = [0u8; 32];
                        rand::rng().fill(&mut secret);
                        let mut forger = Tunn::new(
                            StaticSecret::from(secret),
                            PublicKey::from(client_public),
                            None,
                            None,
                            1,
                            None,
                        );
                        for _ in 0..count {
                            if let TunnResult::WriteToNetwork(packet) =
                                forger.format_handshake_initiation(&mut out, true)
                            {
                                let _ = attacker.send_to(packet, to).await;
                            }
                        }
                    }
                }
            },
            _ = timers.tick() => {
                if !control.mute.load(Ordering::Relaxed)
                    && let TunnResult::WriteToNetwork(packet) = tunn.update_timers(&mut out)
                {
                    sends.push(packet.to_vec());
                }
            }
        }
        let now = smol_now(epoch);
        for _ in 0..2 {
            iface.poll(now, &mut device, &mut sockets);
            serve(&mut sockets, &mut services, udp_echo, udp_spoof);
        }
        while let Some(packet) = device.tx.pop_front() {
            if let TunnResult::WriteToNetwork(cipher) = tunn.encapsulate(&packet, &mut out) {
                sends.push(cipher.to_vec());
            }
        }
        if let Some(to) = client
            && !control.mute.load(Ordering::Relaxed)
        {
            for mut packet in sends.drain(..) {
                if let Some(reserved) = reserved {
                    packet[1..4].copy_from_slice(&reserved);
                }
                let _ = socket.send_to(&packet, to).await;
            }
        }
        sends.clear();
    }
}

fn serve(
    sockets: &mut SocketSet<'static>,
    services: &mut [Service],
    udp_echo: SocketHandle,
    udp_spoof: SocketHandle,
) {
    for service in services {
        let socket = sockets.get_mut::<tcp::Socket>(service.handle);
        if socket.state() == tcp::State::Closed {
            *service = Service {
                handle: service.handle,
                kind: service.kind,
                port: service.port,
                count: 0,
                replied: false,
            };
            socket.listen(service.port).unwrap();
            continue;
        }
        let mut buf = [0u8; 4096];
        match service.kind {
            Kind::Echo => {
                while socket.can_recv() && socket.send_capacity() > socket.send_queue() {
                    let free = socket.send_capacity() - socket.send_queue();
                    let n = socket.recv_slice(&mut buf[..free.min(4096)]).unwrap();
                    socket.send_slice(&buf[..n]).unwrap();
                }
                if !socket.may_recv() && socket.may_send() && !socket.can_recv() {
                    socket.close();
                }
            }
            Kind::Sum => {
                while socket.can_recv() {
                    service.count += socket.recv_slice(&mut buf).unwrap() as u64;
                }
                if !socket.may_recv() && socket.may_send() && !service.replied {
                    service.replied = true;
                    let reply = format!("done:{}", service.count);
                    socket.send_slice(reply.as_bytes()).unwrap();
                    socket.close();
                }
            }
            Kind::Abort => {
                if socket.can_recv() {
                    socket.abort();
                }
            }
            Kind::Stall => {}
        }
    }
    let mut datagrams = Vec::new();
    for (handle, spoof) in [(udp_echo, false), (udp_spoof, true)] {
        let socket = sockets.get_mut::<udp::Socket>(handle);
        while let Ok((data, meta)) = socket.recv() {
            datagrams.push((handle, spoof, data.to_vec(), meta));
        }
    }
    for (handle, spoof, data, mut meta) in datagrams {
        if spoof {
            meta.local_address = Some(IpAddress::Ipv4(SPOOF_IP));
        }
        let _ = sockets
            .get_mut::<udp::Socket>(handle)
            .send_slice(&data, meta);
    }
}

/// A client node whose tunnel runs to `peer`, allowing 10.0.0.0/24.
pub struct Fixture {
    pub peer: Peer,
    pub node: Node,
}

impl Fixture {
    pub async fn new() -> Self {
        Self::with(None, |_| {}).await
    }

    pub async fn with(reserved: Option<[u8; 3]>, tune: impl FnOnce(&mut WireGuardConfig)) -> Self {
        let (secret, public) = key_pair();
        let peer = Peer::spawn(public, reserved).await;
        let mut config = WireGuardConfig {
            private_key: Some(wg_key(&secret)),
            public_key: Some(wg_key(&peer.public)),
            local_v4: Some(CLIENT_IP),
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            reserved,
            ..WireGuardConfig::default()
        };
        tune(&mut config);
        let mut node = Node {
            name: "wg-test".into(),
            address: peer.addr.to_string(),
            host: peer.addr.ip().to_string(),
            port: peer.addr.port(),
            outbound: OutboundConfig::WireGuard(config),
            ..Node::default()
        };
        node.normalize_wireguard();
        node.id = node.derive_id();
        Fixture { peer, node }
    }

    /// A second peer with the same server key pair on another port, and the node that dials it:
    /// same keys, different endpoint (a WARP-style list).
    pub async fn sibling(&self) -> Fixture {
        let wg = self.node.wireguard().unwrap();
        let client_public = PublicKey::from(&StaticSecret::from(*wg.private_key_bytes()));
        let peer = Peer::spawn_with(self.peer.secret, *client_public.as_bytes(), wg.reserved).await;
        let mut node = self.node.clone();
        node.host = peer.addr.ip().to_string();
        node.port = peer.addr.port();
        node.address = peer.addr.to_string();
        node.normalize_wireguard();
        node.id = node.derive_id();
        Fixture { peer, node }
    }

    /// Same keys and endpoint with different tunnel settings (a conflicting config).
    pub fn variant(&self, tune: impl FnOnce(&mut WireGuardConfig)) -> Node {
        let mut node = self.node.clone();
        tune(node.wireguard_mut().unwrap());
        node.normalize_wireguard();
        node.id = node.derive_id();
        node
    }
}

pub fn endpoint(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(ip.into(), port)
}

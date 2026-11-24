//! Configured TCP chains against pinned, independent loopback peers.

#![cfg(all(target_os = "linux", feature = "rprx"))]

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose};
use honk_config::parser::{parse_dae_config_file, resolve_group_filters};
use honk_outbound::bootstrap::{NodeHostLookup, NodeHostResolver, set_node_host_resolver};
use honk_outbound::group::GroupManager;
use honk_outbound::proxy::ProxyRegistry;
use honk_outbound::runtime::OutboundRuntimeRegistry;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

const STARTUP: Duration = Duration::from_secs(5);
const EXCHANGE: Duration = Duration::from_secs(10);
const UUID: &str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
const PASSWORD: &str = "chain-fixture";
const SS2022_KEY: &str = "AAECAwQFBgcICQoLDA0ODw==";
const SS2022_HOST: &str = "chain-ss.invalid";
const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Socks,
    Ss,
    Ss2022,
    Trojan,
    VmessWs,
    VlessGrpc,
    VlessReality,
    VlessMux,
    VlessXhttp,
    Hy2,
    Tuic,
    AnyTls,
    Juicity,
}

impl Protocol {
    fn name(self) -> &'static str {
        match self {
            Self::Socks => "socks",
            Self::Ss => "ss",
            Self::Ss2022 => "ss2022",
            Self::Trojan => "trojan",
            Self::VmessWs => "vmess-ws",
            Self::VlessGrpc => "vless-grpc",
            Self::VlessReality => "vless-reality",
            Self::VlessMux => "vless-h2mux",
            Self::VlessXhttp => "vless-xhttp",
            Self::Hy2 => "hy2",
            Self::Tuic => "tuic",
            Self::AnyTls => "anytls",
            Self::Juicity => "juicity",
        }
    }

    fn udp_listener(self) -> bool {
        matches!(self, Self::Hy2 | Self::Tuic | Self::Juicity)
    }
}

struct PeerBinaries {
    sing_box: PathBuf,
    xray: PathBuf,
    juicity: PathBuf,
}

fn executable(variable: &str) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    let path = std::env::var_os(variable).with_context(|| format!("set {variable}"))?;
    let path = fs::canonicalize(path).with_context(|| format!("resolve {variable}"))?;
    let metadata = fs::metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        "{variable} must name an executable file"
    );
    Ok(path)
}

struct Directory(PathBuf);

impl Directory {
    fn new() -> Result<Self> {
        let path = std::env::temp_dir().join(format!("honk-chain-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path)?;
        let mut directory = Self(path);
        directory.0 = fs::canonicalize(&directory.0)?;
        Ok(directory)
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Credentials {
    cert: PathBuf,
    key: PathBuf,
    pin: String,
    reality_private: String,
    reality_public: String,
}

impl Credentials {
    fn new(directory: &Path) -> Result<Self> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let mut pin = String::with_capacity(64);
        for byte in Sha256::digest(cert.der().as_ref()) {
            write!(pin, "{byte:02x}")?;
        }
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        fs::write(&cert_path, cert.pem())?;
        fs::write(&key_path, signing_key.serialize_pem())?;
        let key = boring::pkey::PKey::generate(boring::pkey::Id::X25519)?;
        let mut raw = [0; 32];
        Ok(Self {
            cert: cert_path,
            key: key_path,
            pin,
            reality_private: general_purpose::URL_SAFE_NO_PAD
                .encode(key.raw_private_key(&mut raw)?),
            reality_public: general_purpose::URL_SAFE_NO_PAD.encode(key.raw_public_key(&mut raw)?),
        })
    }

    fn sing_box_tls(&self) -> Value {
        json!({
            "enabled": true, "server_name": "localhost",
            "certificate_path": self.cert, "key_path": self.key
        })
    }

    fn xray_tls(&self) -> Value {
        json!({
            "alpn": ["h2"], "minVersion": "1.3", "maxVersion": "1.3",
            "certificates": [{ "certificateFile": self.cert, "keyFile": self.key }]
        })
    }
}

fn bind(address: SocketAddr, udp: bool) -> io::Result<Socket> {
    let kind = if udp { Type::DGRAM } else { Type::STREAM };
    let socket = Socket::new(Domain::for_address(address), kind, None)?;
    socket.bind(&address.into())?;
    if !udp {
        socket.listen(1)?;
    }
    Ok(socket)
}

struct Server {
    child: Child,
    log: PathBuf,
}

impl Server {
    fn start(bin: &Path, directory: &Path, name: &str, config: Value) -> Result<Self> {
        let config_path = directory.join(format!("{name}.json"));
        fs::write(&config_path, config.to_string())?;
        let log = directory.join(format!("{name}.log"));
        let file = File::create(&log)?;
        let child = Command::new(bin)
            .current_dir(directory)
            .args(["run", "-c"])
            .arg(config_path)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(file.try_clone()?)
            .stderr(file)
            .spawn()
            .with_context(|| format!("start {name} ({})", bin.display()))?;
        Ok(Self { child, log })
    }

    fn diagnostics(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn assert_alive(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            anyhow::bail!(
                "{} exited with {status}\n{}",
                self.log.display(),
                self.diagnostics()
            );
        }
        Ok(())
    }

    async fn wait_bound(&mut self, address: SocketAddr, udp_log: Option<&str>) -> Result<()> {
        let ready_message = udp_log.map(|prefix| format!("{prefix}{address}"));
        timeout(STARTUP, async {
            loop {
                self.assert_alive()?;
                let ready = match &ready_message {
                    Some(message) => self.diagnostics().contains(message),
                    None => TcpStream::connect(address).await.is_ok(),
                };
                if ready {
                    return self.assert_alive();
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .with_context(|| format!("listener {address} did not start\n{}", self.diagnostics()))?
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone, Copy)]
struct Destination {
    addr: SocketAddr,
    domain: Option<&'static str>,
}

struct Hop {
    protocol: Protocol,
    listen: Destination,
    source: IpAddr,
    egress: IpAddr,
}

impl Hop {
    fn share_link(&self, credentials: &Credentials) -> String {
        use Protocol::*;
        let addr = self.listen.addr;
        let endpoint = self.listen.domain.map_or_else(
            || addr.to_string(),
            |domain| format!("{domain}:{}", addr.port()),
        );
        let pin = &credentials.pin;
        let tls = format!("sni=localhost&pinSHA256={pin}");
        match self.protocol {
            Socks => format!("socks5://{endpoint}"),
            Ss | Ss2022 => {
                let auth = if matches!(self.protocol, Ss) {
                    format!("aes-128-gcm:{PASSWORD}")
                } else {
                    format!("2022-blake3-aes-128-gcm:{SS2022_KEY}")
                };
                let auth = general_purpose::URL_SAFE_NO_PAD.encode(auth);
                format!("ss://{auth}@{endpoint}")
            }
            Trojan => format!("trojan://{PASSWORD}@{endpoint}?{tls}"),
            VmessWs => {
                let vmess = json!({
                    "v": "2", "ps": "vmess-ws", "add": addr.ip().to_string(), "port": addr.port(),
                    "id": UUID, "aid": "0", "scy": "aes-128-gcm", "net": "ws", "path": "/chain-ws"
                });
                format!(
                    "vmess://{}",
                    general_purpose::STANDARD.encode(vmess.to_string())
                )
            }
            VlessGrpc => format!(
                "vless://{UUID}@{endpoint}?security=tls&{tls}&type=grpc&serviceName=chain-grpc"
            ),
            VlessReality => format!(
                "vless://{UUID}@{endpoint}?security=reality&sni=localhost&pbk={}&sid=a1b2",
                credentials.reality_public
            ),
            VlessMux => format!("vless://{UUID}@{endpoint}?security=none&mux=h2mux"),
            VlessXhttp => format!(
                "vless://{UUID}@{endpoint}?security=tls&{tls}&type=xhttp&path=%2Fchain-xhttp%2F&mode=stream-one"
            ),
            Hy2 => format!("hysteria2://{PASSWORD}@{endpoint}?{tls}"),
            Tuic => format!("tuic://{UUID}:{PASSWORD}@{endpoint}?{tls}&alpn=h3"),
            AnyTls => format!("anytls://{PASSWORD}@{endpoint}?{tls}"),
            Juicity => format!("juicity://{UUID}:{PASSWORD}@{endpoint}?{tls}"),
        }
    }

    fn sing_box(&self, next: Destination, credentials: &Credentials) -> Value {
        use Protocol::*;
        let mut inbound = match self.protocol {
            Socks => json!({ "type": "socks", "users": [] }),
            Ss => json!({
                "type": "shadowsocks", "network": "tcp",
                "method": "aes-128-gcm", "password": PASSWORD
            }),
            Ss2022 => json!({
                "type": "shadowsocks", "network": "tcp",
                "method": "2022-blake3-aes-128-gcm", "password": SS2022_KEY
            }),
            Trojan | AnyTls | Hy2 | Tuic => {
                let mut tls = credentials.sing_box_tls();
                let (kind, users) = match self.protocol {
                    Trojan => ("trojan", json!([{ "password": PASSWORD }])),
                    AnyTls => ("anytls", json!([{ "password": PASSWORD }])),
                    Hy2 => ("hysteria2", json!([{ "password": PASSWORD }])),
                    Tuic => {
                        tls["alpn"] = json!(["h3"]);
                        ("tuic", json!([{ "uuid": UUID, "password": PASSWORD }]))
                    }
                    _ => unreachable!(),
                };
                json!({ "type": kind, "users": users, "tls": tls })
            }
            VmessWs => json!({
                "type": "vmess", "users": [{ "uuid": UUID, "alterId": 0 }],
                "transport": { "type": "ws", "path": "/chain-ws" }
            }),
            VlessMux => json!({
                "type": "vless", "users": [{ "uuid": UUID }], "multiplex": { "enabled": true }
            }),
            _ => unreachable!(),
        };
        inbound["tag"] = json!(self.protocol.name());
        inbound["listen"] = json!(self.listen.addr.ip());
        inbound["listen_port"] = json!(self.listen.addr.port());
        let mut allow = json!({
            "inbound": [self.protocol.name()], "network": "tcp", "port": [next.addr.port()],
            "source_ip_cidr": [host_prefix(self.source)], "action": "route", "outbound": "next"
        });
        if let Some(domain) = next.domain {
            allow["domain"] = json!([domain]);
            allow["override_address"] = json!(next.addr.ip());
        } else {
            allow["ip_cidr"] = json!([host_prefix(next.addr.ip())]);
        }
        json!({
            "log": { "level": "info" },
            "inbounds": [inbound],
            "outbounds": [{ "type": "direct", "tag": "next", "inet4_bind_address": self.egress }],
            "route": { "rules": [allow, { "action": "reject" }] }
        })
    }

    fn xray(
        &self,
        next: Destination,
        credentials: &Credentials,
        mask: Option<SocketAddr>,
    ) -> Value {
        let tag = self.protocol.name();
        let settings = json!({ "clients": [{ "id": UUID }], "decryption": "none" });
        let inbound = |tag: &str, addr: SocketAddr, stream: Value| {
            json!({
                "tag": tag, "listen": addr.ip(), "port": addr.port(), "protocol": "vless",
                "settings": settings, "streamSettings": stream
            })
        };
        let tls = credentials.xray_tls();
        let stream = match self.protocol {
            Protocol::VlessGrpc => json!({
                "network": "grpc", "security": "tls", "tlsSettings": tls,
                "grpcSettings": { "serviceName": "chain-grpc" }
            }),
            Protocol::VlessXhttp => json!({
                "network": "xhttp", "security": "tls", "tlsSettings": tls,
                "xhttpSettings": { "path": "/chain-xhttp/", "mode": "stream-one" }
            }),
            Protocol::VlessReality => json!({
                "network": "raw", "security": "reality", "realitySettings": {
                    "target": mask.unwrap().to_string(), "serverNames": ["localhost"],
                    "privateKey": credentials.reality_private, "shortIds": ["a1b2"]
                }
            }),
            _ => unreachable!(),
        };
        let mut inbounds = vec![inbound(tag, self.listen.addr, stream)];
        if let Some(addr) = mask {
            inbounds.push(inbound(
                "local-mask",
                addr,
                json!({ "network": "raw", "security": "tls", "tlsSettings": tls }),
            ));
        }
        assert!(next.domain.is_none());
        json!({
            "log": { "loglevel": "info" },
            "inbounds": inbounds,
            "outbounds": [
                { "protocol": "blackhole", "tag": "reject" },
                { "protocol": "freedom", "tag": "next", "sendThrough": self.egress,
                  "settings": { "finalRules": [
                    { "action": "allow", "network": "tcp", "ip": [host_prefix(next.addr.ip())],
                      "port": next.addr.port() },
                    { "action": "block", "blockDelay": "0" }
                  ] } }
            ],
            "routing": { "rules": [{
                "type": "field", "inboundTag": [tag], "sourceIP": [host_prefix(self.source)],
                "network": "tcp", "ip": [host_prefix(next.addr.ip())], "port": next.addr.port(),
                "outboundTag": "next"
            }] }
        })
    }

    fn juicity(&self, credentials: &Credentials) -> Value {
        json!({
            "listen": self.listen.addr.to_string(), "users": { (UUID): PASSWORD },
            "certificate": credentials.cert, "private_key": credentials.key,
            "congestion_control": "cubic", "log_level": "info", "send_through": self.egress
        })
    }
}

fn host_prefix(ip: IpAddr) -> String {
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    format!("{ip}/{bits}")
}

struct RefuseLocalNames;

impl NodeHostResolver for RefuseLocalNames {
    fn lookup(&self, host: &str) -> Option<NodeHostLookup> {
        let message = format!("unexpected local resolution of {host}");
        Some(Box::pin(async move {
            Err(io::Error::new(ErrorKind::NotFound, message))
        }))
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    send: &[u8],
    expect: &[u8],
) -> Result<S> {
    stream.write_all(send).await?;
    stream.flush().await?;
    let mut received = vec![0; expect.len()];
    stream.read_exact(&mut received).await?;
    ensure!(
        received == expect,
        "payload differs ({} bytes)",
        received.len()
    );
    // Dropping a mux stream can cancel queued data before the other peer reads it.
    Ok(stream)
}

async fn roundtrip(
    listener: TcpListener,
    exit_ip: IpAddr,
    dial: impl Future<Output = Result<impl AsyncRead + AsyncWrite + Unpin>>,
) -> Result<()> {
    let up = b"client-to-destination\x00\xff".repeat(137);
    let down = b"destination-to-client\xff\x00".repeat(263);
    timeout(EXCHANGE, async {
        tokio::try_join!(
            async { exchange(dial.await?, &up, &down).await.context("client") },
            async {
                let (stream, peer) = listener.accept().await?;
                ensure!(
                    peer.ip() == exit_ip,
                    "destination saw {peer}, expected exit {exit_ip}"
                );
                exchange(stream, &down, &up).await.context("destination")
            },
        )
    })
    .await
    .context("TCP exchange timed out")??;
    Ok(())
}

async fn route(
    protocols: &[Protocol],
    first_ip: IpAddr,
    bins: &PeerBinaries,
    registry: &ProxyRegistry,
) -> Result<()> {
    let directory = Directory::new()?;
    let credentials = Credentials::new(&directory.0)?;
    let listener = TcpListener::bind((V4, 0)).await?;
    let target = listener.local_addr()?;
    let mut next = Destination {
        addr: target,
        domain: None,
    };
    let mut source = first_ip;
    let mut hops = Vec::new();
    let mut reservations = Vec::new();
    for (index, &protocol) in protocols.iter().enumerate() {
        let ip = if index == 0 { first_ip } else { V4 };
        let socket = bind(SocketAddr::new(ip, 0), protocol.udp_listener())?;
        let listen = Destination {
            addr: socket.local_addr()?.as_socket().unwrap(),
            domain: matches!(protocol, Protocol::Ss2022).then_some(SS2022_HOST),
        };
        // Linux reserves all of 127/8 for loopback. A different source for each
        // proxy lets the next peer reject connections that skip the preceding hop.
        let egress = Ipv4Addr::new(127, 0, 0, 101 + index as u8).into();
        hops.push(Hop {
            protocol,
            listen,
            source,
            egress,
        });
        reservations.push(socket);
        source = egress;
    }
    let mut dae = String::from("node {\n");
    let route = if let [only] = protocols {
        only.name()
    } else {
        let names: Vec<_> = protocols.iter().map(|protocol| protocol.name()).collect();
        dae.push_str(&format!("  via: {}\n", names.join(" -> ")));
        "via"
    };
    for hop in &hops {
        dae.push_str(&format!(
            "  {}: '{}'\n",
            hop.protocol.name(),
            hop.share_link(&credentials)
        ));
    }
    dae.push_str(&format!(
        "}}\ngroup {{\n  test-route {{\n    filter: name('{route}')\n    policy: fixed(0)\n  }}\n}}\n\
         routing {{\n  fallback: test-route\n}}\n"
    ));
    let dae_file = directory.0.join("chain.dae");
    fs::write(&dae_file, dae)?;
    let config = parse_dae_config_file(dae_file)?.assemble(resolve_group_filters)?;
    let groups = GroupManager::new(&config.groups, &config.nodes);
    let selected = groups
        .select_node(&config.routing.default_outbound)
        .context("select configured route")?;
    ensure!(selected.name == route, "unexpected leaf {}", selected.name);
    let generation = Arc::new(OutboundRuntimeRegistry::build(&config.nodes)?);

    let mut servers = Vec::new();
    for (hop, reservation) in hops.iter().zip(reservations).rev() {
        let mask_socket = matches!(hop.protocol, Protocol::VlessReality)
            .then(|| bind(SocketAddr::new(V4, 0), false))
            .transpose()?;
        let mask = mask_socket
            .as_ref()
            .map(|socket| socket.local_addr().unwrap().as_socket().unwrap());
        let (bin, config) = match hop.protocol {
            Protocol::VlessGrpc | Protocol::VlessReality | Protocol::VlessXhttp => {
                (&bins.xray, hop.xray(next, &credentials, mask))
            }
            Protocol::Juicity => (&bins.juicity, hop.juicity(&credentials)),
            _ => (&bins.sing_box, hop.sing_box(next, &credentials)),
        };
        drop((reservation, mask_socket));
        let mut server = Server::start(bin, &directory.0, hop.protocol.name(), config)?;
        let udp_log = match hop.protocol {
            Protocol::Hy2 | Protocol::Tuic => Some("udp server started at "),
            Protocol::Juicity => Some("Juicity server listening on "),
            _ => None,
        };
        server.wait_bound(hop.listen.addr, udp_log).await?;
        if let Some(mask) = mask {
            server.wait_bound(mask, None).await?;
        }
        servers.push(server);
        next = hop.listen;
    }

    let dial = async {
        let stream = registry
            .dial_runtime(Arc::clone(&generation), selected.id, target, None, STARTUP)
            .await
            .context("dial configured route")?;
        ensure!(
            stream.target_addr == target,
            "unexpected stream target {}",
            stream.target_addr
        );
        Ok(stream.stream)
    };
    let result = roundtrip(listener, source, dial).await;
    if result.is_err() {
        for server in servers.iter().rev() {
            eprintln!("{}\n{}", server.log.display(), server.diagnostics());
        }
    }
    timeout(STARTUP, generation.shutdown())
        .await
        .context("shut down outbound generation")?;
    result?;
    for server in &mut servers {
        server.assert_alive()?;
    }
    let endpoints: Vec<_> = hops
        .iter()
        .map(|hop| format!("{}@{}", hop.protocol.name(), hop.listen.addr))
        .collect();
    eprintln!(
        "{} delivered both payloads to {target} from {source}",
        endpoints.join(" -> ")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit pinned sing-box, Xray and juicity-server executables"]
async fn official_peers_carry_configured_tcp_chains() -> Result<()> {
    use Protocol::*;

    let bins = PeerBinaries {
        sing_box: executable("HONK_SING_BOX_BIN")?,
        xray: executable("HONK_XRAY_BIN")?,
        juicity: executable("HONK_JUICITY_SERVER_BIN")?,
    };
    // This executable owns bootstrap state. Local resolution must fail so the
    // preceding proxy has to receive and resolve the alias.
    set_node_host_resolver(Some(Arc::new(RefuseLocalNames)));
    let registry = ProxyRegistry::default_resolver()?;
    let direct = TcpListener::bind((V6, 0)).await?;
    let address = direct.local_addr()?;
    roundtrip(direct, V6, async { Ok(TcpStream::connect(address).await?) }).await?;
    for (hops, first_ip) in [
        (&[Socks][..], V6),
        (&[Hy2, Ss2022, VmessWs, VlessGrpc][..], V4),
        (&[Tuic, Trojan, VlessReality][..], V4),
        (&[AnyTls, Socks][..], V6),
        (&[Juicity, Ss][..], V4),
        (&[VlessMux, Socks][..], V4),
        (&[VlessXhttp, Socks][..], V4),
    ] {
        route(hops, first_ip, &bins, &registry)
            .await
            .with_context(|| format!("{hops:?}"))?;
    }
    Ok(())
}

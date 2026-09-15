#![cfg(feature = "rprx")]

#[path = "vless_udp/reality.rs"]
mod reality;

use honk_config::node::{Node, VlessTcpPath, VlessUdpEncoding, VlessUdpPath};
use honk_outbound::ProxyRegistry;
use honk_outbound::proxy::{
    PacketErrorClass, PacketRejection, is_packet_rejection, packet_error_class,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UUID: &str = "b5bc10a6-5c72-4fd0-9f62-15c2b9f8a7d3";
const CASE_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_TIMEOUT: Duration = Duration::from_secs(5);
const NATIVE_MAX: usize = 8190;
const XUDP_MAX: usize = 7526;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "honk-vless-udp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is before the Unix epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&path).expect("create VLESS UDP fixture directory");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Server {
    name: &'static str,
    child: Child,
    log: PathBuf,
}

impl Server {
    fn spawn(name: &'static str, mut command: Command, log: PathBuf) -> Self {
        let output = std::fs::File::create(&log).expect("create server log");
        command
            .stdout(Stdio::from(output.try_clone().expect("clone server log")))
            .stderr(Stdio::from(output));
        let child = command
            .spawn()
            .unwrap_or_else(|error| panic!("start {name}: {error}"));
        Self { name, child, log }
    }

    fn diagnostics(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_else(|error| format!("<read log: {error}>"))
    }

    fn assert_alive(&mut self) {
        if let Some(status) = self.child.try_wait().expect("query server status") {
            panic!(
                "{} exited with {status}:\n{}",
                self.name,
                self.diagnostics()
            );
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{} fixture log:\n{}", self.name, self.diagnostics());
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct EchoTasks(Vec<tokio::task::JoinHandle<()>>);

impl Drop for EchoTasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

struct Echoes {
    tcp: SocketAddr,
    tls_tcp: SocketAddr,
    tls_root: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
    native_v4_53: SocketAddr,
    native_v6_443: SocketAddr,
    domain: SocketAddr,
    tls_tasks: tokio::sync::mpsc::UnboundedReceiver<tokio::task::JoinHandle<()>>,
    _tasks: EchoTasks,
}

impl Echoes {
    async fn start() -> Self {
        let tcp = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind TCP echo");
        let tcp_addr = tcp.local_addr().expect("TCP echo address");

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
                .expect("generate inner TLS certificate");
        let tls_root = cert.der().clone();
        let tls_config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("select inner TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![tls_root.clone()],
            tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                signing_key.serialize_der().into(),
            ),
        )
        .expect("build inner TLS server");
        let tls_acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));
        let tls_tcp = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind inner TLS echo");
        let tls_tcp_addr = tls_tcp.local_addr().expect("inner TLS echo address");

        let native_v4 = tokio::net::UdpSocket::bind((Ipv4Addr::new(127, 77, 0, 1), 53))
            .await
            .expect("bind isolated loopback UDP/53 echo");
        let native_v4_53 = native_v4.local_addr().expect("UDP/53 echo address");

        let native_v6 = tokio::net::UdpSocket::bind("[::1]:443")
            .await
            .expect("bind IPv6 loopback UDP/443 echo");
        let native_v6_443 = native_v6.local_addr().expect("UDP/443 echo address");

        let domain_v4 = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind domain IPv4 UDP echo");
        let domain = domain_v4.local_addr().expect("domain UDP echo address");
        let domain_v6 = tokio::net::UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, domain.port()))
            .await
            .expect("bind domain IPv6 UDP echo");

        let mut tasks = vec![tokio::spawn(async move {
            loop {
                let (mut stream, _) = tcp.accept().await.expect("accept TCP echo");
                tokio::spawn(async move {
                    let mut buffer = [0; 16 * 1024];
                    loop {
                        let size = stream.read(&mut buffer).await.expect("read TCP echo");
                        if size == 0 {
                            break;
                        }
                        stream
                            .write_all(&buffer[..size])
                            .await
                            .expect("write TCP echo");
                    }
                });
            }
        })];
        let (tls_results, tls_tasks) = tokio::sync::mpsc::unbounded_channel();
        let tls_task = tokio::spawn(async move {
            loop {
                let (stream, _) = tls_tcp.accept().await.expect("accept inner TLS echo");
                let acceptor = tls_acceptor.clone();
                let handler = tokio::spawn(async move {
                    let mut stream = acceptor.accept(stream).await.expect("accept inner TLS");
                    assert_eq!(
                        stream.get_ref().1.protocol_version(),
                        Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
                    );
                    let mut buffer = [0; 16 * 1024];
                    loop {
                        let size = stream.read(&mut buffer).await.expect("read inner TLS echo");
                        if size == 0 {
                            break;
                        }
                        stream
                            .write_all(&buffer[..size])
                            .await
                            .expect("write inner TLS echo");
                    }
                });
                tls_results.send(handler).expect("track inner TLS handler");
            }
        });
        tasks.push(tls_task);
        for socket in [native_v4, native_v6, domain_v4, domain_v6] {
            tasks.push(tokio::spawn(async move {
                let mut buffer = [0; u16::MAX as usize];
                loop {
                    let (size, peer) = socket
                        .recv_from(&mut buffer)
                        .await
                        .expect("receive UDP echo");
                    socket
                        .send_to(&buffer[..size], peer)
                        .await
                        .expect("send UDP echo");
                }
            }));
        }

        Self {
            tcp: tcp_addr,
            tls_tcp: tls_tcp_addr,
            tls_root,
            native_v4_53,
            native_v6_443,
            domain,
            tls_tasks,
            _tasks: EchoTasks(tasks),
        }
    }

    async fn finish(mut self) {
        for task in std::mem::take(&mut self._tasks.0) {
            task.abort();
            if let Err(error) = task.await {
                assert!(error.is_cancelled(), "echo listener failed: {error}");
            }
        }
        while let Some(task) = self.tls_tasks.recv().await {
            task.await.expect("inner TLS echo handler failed");
        }
    }
}

fn required_executable(variable: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let supplied = std::env::var_os(variable).unwrap_or_else(|| panic!("{variable} must be set"));
    let path = std::fs::canonicalize(&supplied).unwrap_or_else(|error| {
        panic!("{variable}={supplied:?} is not an executable path: {error}")
    });
    let metadata = std::fs::metadata(&path).expect("read executable metadata");
    assert!(metadata.is_file(), "{variable} must name a file");
    assert_ne!(
        metadata.permissions().mode() & 0o111,
        0,
        "{variable} must name an executable file"
    );
    path
}

async fn bounded<T>(name: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(CASE_TIMEOUT, future)
        .await
        .unwrap_or_else(|_| panic!("{name} timed out after {CASE_TIMEOUT:?}"))
}

async fn wait_ready(server: &mut Server, ports: &[u16]) {
    let ready = tokio::time::timeout(SERVER_TIMEOUT, async {
        loop {
            server.assert_alive();
            let mut all_bound = true;
            for port in ports {
                if tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, *port))
                    .await
                    .is_err()
                {
                    all_bound = false;
                    break;
                }
            }
            if all_bound {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if ready.is_err() {
        panic!(
            "{} did not bind {ports:?} within {SERVER_TIMEOUT:?}:\n{}",
            server.name,
            server.diagnostics()
        );
    }
}

fn reserve_ports(count: usize) -> (Vec<u16>, Vec<std::net::TcpListener>) {
    let listeners: Vec<_> = (0..count)
        .map(|_| std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve TCP port"))
        .collect();
    let ports = listeners
        .iter()
        .map(|listener| listener.local_addr().expect("reserved port address").port())
        .collect();
    (ports, listeners)
}

async fn xray_encryption_pair(xray: &Path) -> (String, String) {
    let output = bounded("xray vlessenc", async {
        let mut command = tokio::process::Command::new(xray);
        command.arg("vlessenc").kill_on_drop(true);
        command.output().await.expect("run xray vlessenc")
    })
    .await;
    assert!(
        output.status.success(),
        "xray vlessenc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("xray vlessenc output is UTF-8");
    let value = |field: &str| {
        let prefix = format!("\"{field}\": \"");
        stdout
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix(&prefix)
                    .and_then(|value| value.strip_suffix('"'))
            })
            .unwrap_or_else(|| panic!("xray vlessenc omitted {field}"))
            .to_owned()
    };
    (value("decryption"), value("encryption"))
}

fn canonical_node(server_port: u16, name: &str, options: &str) -> Node {
    Node::from_share_link(&format!(
        "vless://{UUID}@127.0.0.1:{server_port}?udp=1{options}#{name}"
    ))
    .unwrap_or_else(|error| panic!("parse {name}: {error}"))
}

fn encrypted_node(
    server_port: u16,
    name: &str,
    udp_encoding: VlessUdpEncoding,
    encryption: &str,
) -> Node {
    let packet_encoding = match udp_encoding {
        VlessUdpEncoding::Native => "none",
        encoding => encoding.as_str(),
    };
    let option = format!("&security=none&packetEncoding={packet_encoding}");
    let mut node = canonical_node(server_port, name, &option);
    node.vless_mut().expect("VLESS config").encryption = Some(encryption.to_owned());
    node.id = node.derive_id();
    node.validate()
        .unwrap_or_else(|error| panic!("validate {name}: {error}"));
    node
}

fn payload(size: usize, salt: u8) -> Vec<u8> {
    (0..size)
        .map(|offset| salt.wrapping_add((offset % 251) as u8))
        .collect()
}

async fn tcp_echo(registry: &ProxyRegistry, name: &str, node: &Node, target: SocketAddr) {
    bounded(name, async {
        let message = format!("tcp-{name}");
        let mut stream = registry
            .dial(node, target, None, Duration::from_secs(3))
            .await
            .unwrap_or_else(|error| panic!("dial {name}: {error:#}"));
        stream
            .stream
            .write_all(message.as_bytes())
            .await
            .expect("send TCP echo");
        stream.stream.flush().await.expect("flush TCP echo");

        let mut echoed = vec![0; message.len()];
        stream
            .stream
            .read_exact(&mut echoed)
            .await
            .expect("receive TCP echo");
        assert_eq!(echoed, message.as_bytes(), "{name}");
    })
    .await;
}
async fn tls_tcp_echo(
    registry: &ProxyRegistry,
    name: &str,
    node: &Node,
    target: SocketAddr,
    root: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
) {
    bounded(name, async {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots
            .add(root)
            .expect("trust inner TLS fixture certificate");
        let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(
            tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("select inner TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let proxy = registry
            .dial(node, target, None, Duration::from_secs(3))
            .await
            .unwrap_or_else(|error| panic!("dial {name}: {error:#}"));
        let mut stream = connector
            .connect(
                tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                proxy.stream,
            )
            .await
            .expect("complete inner TLS handshake through VLESS");
        assert_eq!(
            stream.get_ref().1.protocol_version(),
            Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3)
        );
        let message = format!("tls-{name}");
        stream
            .write_all(message.as_bytes())
            .await
            .expect("send inner TLS echo");
        stream.flush().await.expect("flush inner TLS echo");
        let mut echoed = vec![0; message.len()];
        stream
            .read_exact(&mut echoed)
            .await
            .expect("receive inner TLS echo");
        assert_eq!(echoed, message.as_bytes());
        stream.shutdown().await.expect("close inner TLS echo");
    })
    .await;
}

async fn udp_echo(
    registry: &ProxyRegistry,
    name: &str,
    node: &Node,
    target: SocketAddr,
    target_domain: Option<&str>,
    size: usize,
) {
    bounded(name, async {
        let transport = registry
            .dial_udp_transport(node, target, target_domain, Duration::from_secs(3))
            .await
            .unwrap_or_else(|error| panic!("dial {name}: {error:#}"));
        let sent = payload(size, name.bytes().fold(0, u8::wrapping_add));
        transport
            .send_packet_confirmed(&sent)
            .await
            .unwrap_or_else(|error| panic!("send {name}: {error}"));
        let mut echoed = vec![0; size];
        let (received, peer) = transport
            .recv_packet(&mut echoed)
            .await
            .unwrap_or_else(|error| panic!("receive {name}: {error}"));
        assert_eq!(received, sent.len(), "{name}");
        assert_eq!(echoed, sent, "{name}");
        assert!(
            peer.ip().is_loopback(),
            "{name} returned non-loopback peer {peer}"
        );
        assert_eq!(peer.port(), target.port(), "{name}");
    })
    .await;
}

async fn udp_size_contract(
    registry: &ProxyRegistry,
    name: &str,
    node: &Node,
    target: SocketAddr,
    target_domain: Option<&str>,
    maximum: usize,
) {
    bounded(name, async {
        let transport = registry
            .dial_udp_transport(node, target, target_domain, Duration::from_secs(3))
            .await
            .unwrap_or_else(|error| panic!("dial {name}: {error:#}"));

        for (size, salt) in [(1, 0x31), (maximum, 0x79)] {
            let sent = payload(size, salt);
            transport
                .send_packet_confirmed(&sent)
                .await
                .unwrap_or_else(|error| panic!("send {name} size {size}: {error}"));
            let mut echoed = vec![0; size];
            let (received, peer) = transport
                .recv_packet(&mut echoed)
                .await
                .unwrap_or_else(|error| panic!("receive {name} size {size}: {error}"));
            assert_eq!(received, size, "{name}");
            assert_eq!(echoed, sent, "{name}");
            assert!(
                peer.ip().is_loopback(),
                "{name} returned non-loopback peer {peer}"
            );
            assert_eq!(peer.port(), target.port(), "{name}");
        }

        for rejected in [Vec::new(), vec![0; maximum + 1]] {
            let error = transport
                .send_packet_confirmed(&rejected)
                .await
                .expect_err("out-of-contract packet size must be rejected locally");
            assert_eq!(packet_error_class(&error), PacketErrorClass::Rejected);
        }

        let sent = b"after-local-size-rejection";
        transport
            .send_packet_confirmed(sent)
            .await
            .expect("local size rejection must not retire the transport");
        let mut echoed = vec![0; sent.len()];
        let (received, _) = transport
            .recv_packet(&mut echoed)
            .await
            .expect("transport must remain usable after local size rejection");
        assert_eq!(&echoed[..received], sent);
    })
    .await;
}

/// Run with absolute paths to pinned official executables:
/// `HONK_XRAY_BIN=/path/to/xray HONK_SING_BOX_BIN=/path/to/sing-box cargo test -p honk-outbound --features rprx --test vless_udp -- --ignored --nocapture`
///
/// The host must permit binds to isolated loopback UDP ports 53 and 443, and
/// those addresses must be free. Every configured listener and relay target is
/// loopback; the fixture does not use the maintainer lab or any public endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires explicit HONK_XRAY_BIN and HONK_SING_BOX_BIN official executables"]
async fn official_xray_and_sing_box_vless_udp_loopback_interop() {
    let xray_bin = required_executable("HONK_XRAY_BIN");
    let sing_box_bin = required_executable("HONK_SING_BOX_BIN");
    let temp = TempDir::new();
    let echoes = Echoes::start().await;
    let (decryption, encryption_0rtt) = xray_encryption_pair(&xray_bin).await;
    let encryption_1rtt = encryption_0rtt.replacen(".0rtt.", ".1rtt.", 1);
    assert_ne!(
        encryption_1rtt, encryption_0rtt,
        "xray vlessenc returned no 0rtt client field"
    );

    let (ports, reservations) = reserve_ports(5);
    let [
        xray_plain_port,
        xray_vision_port,
        xray_encrypted_port,
        xray_encrypted_vision_port,
        sing_box_port,
    ]: [u16; 5] = ports.try_into().expect("five reserved ports");

    let key = rcgen::KeyPair::generate().expect("generate TLS key");
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
        .expect("build TLS certificate parameters")
        .self_signed(&key)
        .expect("generate TLS certificate");
    let cert_path = temp.join("cert.pem");
    let key_path = temp.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).expect("write TLS certificate");
    std::fs::write(&key_path, key.serialize_pem()).expect("write TLS key");

    let xray_config = temp.join("xray.json");
    std::fs::write(
        &xray_config,
        format!(
            r#"{{
  "log": {{ "loglevel": "info" }},
  "inbounds": [
    {{
      "tag": "vless-plain",
      "listen": "127.0.0.1",
      "port": {xray_plain_port},
      "protocol": "vless",
      "settings": {{ "clients": [{{ "id": "{UUID}" }}], "decryption": "none" }},
      "streamSettings": {{ "network": "tcp", "security": "none" }}
    }},
    {{
      "tag": "vless-vision",
      "listen": "127.0.0.1",
      "port": {xray_vision_port},
      "protocol": "vless",
      "settings": {{ "clients": [{{ "id": "{UUID}", "flow": "xtls-rprx-vision" }}], "decryption": "none" }},
      "streamSettings": {{ "network": "tcp", "security": "tls", "tlsSettings": {{ "certificates": [{{ "certificateFile": "{}", "keyFile": "{}" }}] }} }}
    }},
    {{
      "tag": "vless-encrypted",
      "listen": "127.0.0.1",
      "port": {xray_encrypted_port},
      "protocol": "vless",
      "settings": {{ "clients": [{{ "id": "{UUID}" }}], "decryption": "{decryption}" }},
      "streamSettings": {{ "network": "tcp", "security": "none" }}
    }},
    {{
      "tag": "vless-encrypted-vision",
      "listen": "127.0.0.1",
      "port": {xray_encrypted_vision_port},
      "protocol": "vless",
      "settings": {{ "clients": [{{ "id": "{UUID}", "flow": "xtls-rprx-vision" }}], "decryption": "{decryption}" }},
      "streamSettings": {{ "network": "tcp", "security": "tls", "tlsSettings": {{ "certificates": [{{ "certificateFile": "{}", "keyFile": "{}" }}] }} }}
    }}
  ],
  "outbounds": [{{ "tag": "direct", "protocol": "freedom", "settings": {{ "finalRules": [
    {{ "action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": {tcp_echo_port} }},
    {{ "action": "allow", "network": "tcp", "ip": ["127.0.0.1"], "port": {tls_echo_port} }},
    {{ "action": "allow", "network": "udp", "ip": ["127.77.0.1"], "port": 53 }},
    {{ "action": "allow", "network": "udp", "ip": ["::1"], "port": 443 }},
    {{ "action": "allow", "network": "udp", "ip": ["127.0.0.1", "::1"], "port": {domain_echo_port} }},
    {{ "action": "block", "blockDelay": "0" }}
  ] }} }}]
}}"#,
            cert_path.display(),
            key_path.display(),
            cert_path.display(),
            key_path.display(),
            tcp_echo_port = echoes.tcp.port(),
            tls_echo_port = echoes.tls_tcp.port(),
            domain_echo_port = echoes.domain.port(),
        ),
    )
    .expect("write Xray config");

    let sing_box_config = temp.join("sing-box.json");
    std::fs::write(
        &sing_box_config,
        format!(
            r#"{{
  "log": {{ "level": "warn" }},
  "inbounds": [{{
    "type": "vless",
    "tag": "vless",
    "listen": "127.0.0.1",
    "listen_port": {sing_box_port},
    "users": [{{ "uuid": "{UUID}" }}],
    "multiplex": {{ "enabled": true }}
  }}],
  "outbounds": [{{ "type": "direct", "tag": "direct" }}],
  "route": {{ "final": "direct" }}
}}"#
        ),
    )
    .expect("write sing-box config");
    drop(reservations);

    let mut xray_command = Command::new(&xray_bin);
    xray_command
        .current_dir(&temp.0)
        .args(["run", "-c"])
        .arg(&xray_config);
    let mut xray = Server::spawn("Xray", xray_command, temp.join("xray.log"));

    let mut sing_box_command = Command::new(&sing_box_bin);
    sing_box_command
        .current_dir(&temp.0)
        .args(["run", "--disable-color", "-c"])
        .arg(&sing_box_config);
    let mut sing_box = Server::spawn("sing-box", sing_box_command, temp.join("sing-box.log"));

    wait_ready(
        &mut xray,
        &[
            xray_plain_port,
            xray_vision_port,
            xray_encrypted_port,
            xray_encrypted_vision_port,
        ],
    )
    .await;
    wait_ready(&mut sing_box, &[sing_box_port]).await;

    let registry = ProxyRegistry::default_resolver().expect("build public proxy registry");
    for (server, port) in [("xray", xray_plain_port), ("sing-box", sing_box_port)] {
        let auto = canonical_node(port, &format!("{server}-auto"), "&security=none");

        tcp_echo(&registry, &format!("{server}-auto-tcp"), &auto, echoes.tcp).await;
        udp_echo(
            &registry,
            &format!("{server}-auto-native-ipv4-53"),
            &auto,
            echoes.native_v4_53,
            None,
            NATIVE_MAX,
        )
        .await;
        udp_echo(
            &registry,
            &format!("{server}-auto-native-ipv6-443"),
            &auto,
            echoes.native_v6_443,
            None,
            NATIVE_MAX,
        )
        .await;
        udp_size_contract(
            &registry,
            &format!("{server}-auto-xudp-domain"),
            &auto,
            echoes.domain,
            Some("localhost"),
            XUDP_MAX,
        )
        .await;

        let native = canonical_node(
            port,
            &format!("{server}-explicit-native"),
            "&security=none&packetEncoding=none",
        );
        udp_size_contract(
            &registry,
            &format!("{server}-explicit-native-domain"),
            &native,
            echoes.domain,
            Some("localhost"),
            NATIVE_MAX,
        )
        .await;
    }

    for (name, options) in [
        ("uot-v2", "packetEncoding=uot-v2"),
        ("h2mux", "mux=h2mux"),
        ("h2mux-padded", "mux=h2mux&padding=true"),
    ] {
        let node = canonical_node(sing_box_port, name, &format!("&security=none&{options}"));
        tcp_echo(&registry, name, &node, echoes.tcp).await;
        udp_echo(
            &registry,
            name,
            &node,
            echoes.domain,
            Some("localhost"),
            512,
        )
        .await;
    }
    let cool = canonical_node(
        xray_plain_port,
        "shared-cool",
        "&security=none&mux=xray&concurrency=8&xudpConcurrency=0&xudpProxyUDP443=allow",
    );
    tcp_echo(&registry, "shared-cool-tcp", &cool, echoes.tcp).await;
    udp_echo(
        &registry,
        "shared-cool-udp",
        &cool,
        echoes.domain,
        Some("localhost"),
        512,
    )
    .await;

    let mut vision_base = canonical_node(
        xray_vision_port,
        "xray-vision-base",
        "&security=tls&sni=localhost&flow=xtls-rprx-vision",
    );
    vision_base
        .tls_mut()
        .expect("VLESS TLS config")
        .skip_cert_verify = true;
    vision_base.id = vision_base.derive_id();
    let denial = bounded("xray-vision-base-udp443-denied", async {
        registry
            .dial_udp_transport(
                &vision_base,
                echoes.native_v6_443,
                None,
                Duration::from_secs(3),
            )
            .await
            .expect_err("base Vision flow must deny UDP/443")
    })
    .await;
    assert!(is_packet_rejection(&denial));
    assert!(denial.chain().any(|cause| matches!(
        cause.downcast_ref::<PacketRejection>(),
        Some(PacketRejection::Policy)
    )));

    let mut vision_suffix = canonical_node(
        xray_vision_port,
        "xray-vision-udp443",
        "&security=tls&sni=localhost&flow=xtls-rprx-vision-udp443",
    );
    vision_suffix
        .tls_mut()
        .expect("VLESS TLS config")
        .skip_cert_verify = true;
    vision_suffix.id = vision_suffix.derive_id();
    udp_echo(
        &registry,
        "xray-vision-suffix-xudp-443",
        &vision_suffix,
        echoes.native_v6_443,
        None,
        512,
    )
    .await;

    for (udp_encoding, target, domain) in [
        (VlessUdpEncoding::Native, echoes.domain, Some("localhost")),
        (VlessUdpEncoding::Xudp, echoes.domain, Some("localhost")),
    ] {
        let mode_name = udp_encoding.as_str();
        let one_rtt = encrypted_node(
            xray_encrypted_port,
            &format!("xray-encrypted-{mode_name}-1rtt"),
            udp_encoding,
            &encryption_1rtt,
        );
        udp_echo(
            &registry,
            &format!("xray-encrypted-{mode_name}-1rtt"),
            &one_rtt,
            target,
            domain,
            512,
        )
        .await;

        let zero_rtt = encrypted_node(
            xray_encrypted_port,
            &format!("xray-encrypted-{mode_name}-0rtt"),
            udp_encoding,
            &encryption_0rtt,
        );
        // The repeated connection reuses honk's public registry/handler and the same
        // 0-RTT-capable node. Echo proves both connections interoperate, but this
        // black-box fixture does not claim to observe which ticket path Xray accepted.
        for attempt in ["cold", "repeat"] {
            udp_echo(
                &registry,
                &format!("xray-encrypted-{mode_name}-0rtt-{attempt}"),
                &zero_rtt,
                target,
                domain,
                512,
            )
            .await;
        }
    }

    let mut encrypted_vision = canonical_node(
        xray_encrypted_vision_port,
        "xray-encrypted-vision",
        "&security=tls&sni=localhost&flow=xtls-rprx-vision-udp443&packetEncoding=auto&mux=xray&concurrency=-1&xudpConcurrency=4&xudpProxyUDP443=allow",
    );
    {
        let vless = encrypted_vision.vless_mut().expect("VLESS config");
        vless.encryption = Some(encryption_1rtt.clone());
        assert_eq!(vless.tcp_path(), VlessTcpPath::Direct);
        assert_eq!(vless.udp_path(443), Some(VlessUdpPath::CoolSeparate));
    }
    encrypted_vision
        .tls_mut()
        .expect("VLESS TLS config")
        .skip_cert_verify = true;
    encrypted_vision.id = encrypted_vision.derive_id();
    encrypted_vision
        .validate()
        .expect("encrypted Vision mux node validates");
    tls_tcp_echo(
        &registry,
        "xray-encrypted-vision-direct-tls13",
        &encrypted_vision,
        echoes.tls_tcp,
        echoes.tls_root.clone(),
    )
    .await;
    udp_echo(
        &registry,
        "xray-encrypted-vision-xudp-443",
        &encrypted_vision,
        echoes.native_v6_443,
        None,
        512,
    )
    .await;
    xray.assert_alive();
    sing_box.assert_alive();
    bounded("echo fixture shutdown", echoes.finish()).await;
}

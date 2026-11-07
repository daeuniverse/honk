use super::*;
use crate::control::core_forward::PolicyRead;
use std::{os::unix::fs::MetadataExt, path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
};

const PEER: &str = r#"
import contextlib, os, socket, struct, sys

home = os.open('/proc/self/ns/net', os.O_RDONLY)
@contextlib.contextmanager
def namespace(name):
    target = os.open('/run/netns/' + name, os.O_RDONLY)
    try:
        os.setns(target, 0)
        yield
    finally:
        os.setns(home, 0)
        os.close(target)

with namespace('client'):
    client = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    client.bind(('c0', 0))
with namespace('server'):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('198.51.100.2', 18084))
    listener.listen(2)
    transit = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    transit.bind(('s0', 0))
for sock in (client, listener, transit):
    sock.settimeout(8)
os.close(home)

def checksum(data):
    data += b'\0' * (len(data) % 2)
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def send(protocol, body, source='192.0.2.99'):
    source, destination = socket.inet_aton(source), socket.inet_aton('198.51.100.2')
    pseudo = source + destination + struct.pack('!BBH', 0, protocol, len(body))
    offset = 16 if protocol == 6 else 6
    body = body[:offset] + struct.pack('!H', checksum(pseudo + body) or 65535) + body[offset + 2:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), 1234, 0, 64, protocol, 0, source, destination)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    client.send(bytes.fromhex('0200000000100200000000200800') + ip + body)

def receive(sock, protocol, source, destination):
    while True:
        packet, peer = sock.recvfrom(65535)
        if peer[2] == 4 or packet[12:14] != b'\x08\x00':
            continue
        ip = packet[14:]
        if len(ip) < 20 or ip[9] != protocol or ip[12:16] != socket.inet_aton(source) or ip[16:20] != socket.inet_aton(destination):
            continue
        length, = struct.unpack_from('!H', ip, 2)
        header = (ip[0] & 15) * 4
        assert checksum(ip[:header]) == 0
        body = ip[header:length]
        assert checksum(ip[12:20] + struct.pack('!BBH', 0, protocol, len(body)) + body) == 0
        return ip[:length], body

def tcp(flags, payload=b''):
    send(6, struct.pack('!HHIIBBHHH', port, 18084, sequence, acknowledgment, 5 << 4, flags, 60000, 0, 0) + payload)

def reply():
    while True:
        _, body = receive(client, 6, '198.51.100.2', '192.0.2.99')
        source, destination, seq, ack, offset, flags, _, _, _ = struct.unpack('!HHIIBBHHH', body[:20])
        if (source, destination) != (18084, port):
            continue
        assert not flags & 4, ('unexpected reset', flags)
        return seq, ack, flags, body[(offset >> 4) * 4:]

def exact(sock, expected):
    received = b''
    while len(received) < len(expected):
        chunk = sock.recv(len(expected) - len(received))
        assert chunk, ('early application EOF', received, expected)
        received += chunk
    assert received == expected, (received, expected)

print('READY', flush=True)
connection = None
for line in sys.stdin:
    command, label = line.strip().split()
    if command == 'CONNECT':
        port = 41084 if label == 'router' else 41085
        sequence, acknowledgment = 100 if label == 'router' else 10000, 0
        tcp(2)
        seq, ack, flags, payload = reply()
        assert (ack, flags, payload) == (sequence + 1, 18, b'')
        sequence += 1
        acknowledgment = (seq + 1) & 0xffffffff
        tcp(16)
        connection, address = listener.accept()
        connection.settimeout(8)
        assert address[0] == '10.77.0.1', ('not the actual Endpoint dial', address)
        warm = ('prime/' + label).encode()
        connection.sendall(warm)
        while True:
            seq, ack, flags, payload = reply()
            if payload:
                break
        assert seq == acknowledgment and ack == sequence and payload == warm
        acknowledgment = (seq + len(warm)) & 0xffffffff
        tcp(16)
        print('CONNECTED ' + label, flush=True)
    elif command == 'COLD':
        payload = ('cold/' + label).encode()
        send(17, struct.pack('!HHHH', port + 10, 18085, 8 + len(payload), 0) + payload, '192.0.2.2')
        print('COLD ' + label, flush=True)
    elif command == 'APP':
        request, response = ('request/' + label).encode(), ('response/' + label).encode()
        tcp(24, request)
        sequence += len(request)
        exact(connection, request)
        connection.sendall(response)
        while True:
            first = reply()
            if first[3]:
                break
        assert first[0] == acknowledgment and first[1] == sequence and first[3] == response, first
        print('APP ' + label, flush=True)
    elif command == 'RETRANSMIT':
        while True:
            repeated = reply()
            if repeated[3]:
                break
        assert repeated == first, ('not the identical unacknowledged response', first, repeated)
        acknowledgment = (first[0] + len(first[3])) & 0xffffffff
        tcp(16)
        print('RETRANSMITTED ' + label, flush=True)
    elif command == 'CLOSE':
        connection.shutdown(socket.SHUT_WR)
        while True:
            seq, ack, flags, payload = reply()
            if flags & 1:
                break
        assert seq == acknowledgment and ack == sequence and not payload
        acknowledgment = (seq + 1) & 0xffffffff
        tcp(17)
        sequence += 1
        while True:
            _, ack, flags, payload = reply()
            if ack == sequence:
                break
        assert flags == 16 and not payload
        assert connection.recv(1) == b'', 'client FIN did not reach the real application'
        connection.close()
        connection = None
        print('CLOSED ' + label, flush=True)
    elif command == 'FORWARDED':
        while True:
            ip, body = receive(transit, 17, '192.0.2.2', '198.51.100.2')
            if body[8:] == ('cold/' + label).encode():
                break
        assert struct.unpack('!HH', body[:4]) == (port + 10, 18085) and ip[8] == 63
        print('FORWARDED ' + label, flush=True)
    elif command == 'STOP':
        assert connection is None
        for sock in (client, listener, transit):
            sock.close()
        print('STOPPED ' + label, flush=True)
        break
    else:
        raise AssertionError(command)
else:
    raise AssertionError('peer owner disappeared before STOP')
"#;

struct Peer {
    child: Child,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
}

impl Peer {
    fn spawn() -> anyhow::Result<Self> {
        let mut child = Command::new("python3")
            .args(["-u", "-c", PEER])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap()).lines();
        Ok(Self {
            child,
            input,
            output,
        })
    }

    async fn command(&mut self, command: &str, label: &str) -> anyhow::Result<()> {
        self.input
            .write_all(format!("{command} {label}\n").as_bytes())
            .await?;
        Ok(())
    }

    async fn expect(&mut self, expected: &str) -> anyhow::Result<()> {
        let actual = self.output.next_line().await?;
        ensure!(
            actual.as_deref() == Some(expected),
            "peer expected {expected:?}, got {actual:?}"
        );
        Ok(())
    }
}

fn guarded_pin_root() -> PathBuf {
    assert!(
        std::fs::read_to_string("/proc/cmdline")
            .unwrap()
            .contains("virtme.")
    );
    let current = std::fs::metadata("/proc/self/ns/net").unwrap().ino();
    assert_ne!(current, std::fs::metadata("/proc/1/ns/net").unwrap().ino());
    assert_ne!(
        current.to_string(),
        std::env::var("HONK_XDP_PARENT_NETNS").unwrap()
    );
    assert_eq!(current, std::fs::metadata("/run/netns/dut").unwrap().ino());
    for (name, mac) in [("dut0", "02:00:00:00:00:10"), ("dut1", "02:00:00:00:00:11")] {
        assert_eq!(
            std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
                .unwrap()
                .trim(),
            mac
        );
    }
    PathBuf::from(std::env::var_os("HONK_XDP_PIN_ROOT").unwrap()).join("driven-runtime")
}

async fn start_runtime(
    plane: ControlPlane,
    config: &Config,
    pins: &Path,
    artifacts: &Path,
    admission: Arc<AtomicBool>,
) -> anyhow::Result<(Runtime, PacketEndpointOwner)> {
    let (devices, topology, plans, scopes, core, memory, staging, mut links) =
        prepare(&plane, config, pins).await?;
    let (endpoints, mut owner, mut drivers) = PacketEndpoints::start_driven(plane, scopes, 64)?;
    let realms = plans
        .into_iter()
        .map(|(ingress, device, link, scope)| {
            let index = drivers
                .iter()
                .position(|driver| driver.scope() == scope)
                .unwrap();
            Realm {
                ingress,
                device,
                link,
                driver: drivers.swap_remove(index),
                pending: [None, None],
            }
        })
        .collect();
    assert!(drivers.is_empty());
    let mut runtime = Runtime {
        devices,
        topology,
        admission,
        realms,
        endpoints,
        core,
        waiting: VecDeque::with_capacity(PENDING),
        pending: VecDeque::with_capacity(PENDING),
        peers: Vec::with_capacity(PEERS),
        staging,
        closing: false,
        pressure: Pressure::new(Instant::now()),
        core_maintenance_checked: Instant::now(),
        _memory: memory,
    };
    let timer = None;
    tokio::pin!(timer);
    loop {
        tokio::select! {
            ready = poll_fn(|cx| owner.poll_ready(cx)) => { ready?; break; }
            () = poll_fn(|cx| runtime.poll_scopes(cx, timer.as_mut())) => tokio::task::yield_now().await,
        }
    }
    for device in &mut runtime.devices {
        std::fs::write(
            artifacts.join(format!("driven-runtime.{}.guard-id", device.info.name)),
            device.programs.discover_prog_id().to_string(),
        )?;
        device.attachment.replace(&device.programs)?;
        device.active = true;
    }
    let indices: Vec<_> = runtime
        .devices
        .iter()
        .map(|device| device.info.ifindex)
        .collect();
    let logical: Vec<_> = runtime
        .realms
        .iter()
        .map(|realm| realm.ingress.ifindex)
        .collect();
    let topology = Topology::admit(&indices, &logical, config.global.effective_so_mark())?;
    ensure!(topology.ipv4_broadcasts() == runtime.topology.get_ref().ipv4_broadcasts());
    // SAFETY: this is the same owned, stable Topology descriptor used by production run.
    runtime.topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
    links.synchronize()?;
    links.validate_capture(&indices)?;
    assert_eq!(
        links
            .logical_links()
            .filter(|link| indices.contains(&link.path.physical_ifindex))
            .count(),
        runtime.realms.len()
    );
    for realm in &runtime.realms {
        assert!(links.logical_links().any(|link| link == realm.link));
    }
    for device in &runtime.devices {
        device.info.validate_current()?;
        assert!(
            device
                .queues
                .iter()
                .all(|queue| !queue.io.get_ref().zerocopy())
        );
    }
    ensure!(!runtime.topology.get_mut().check_changed()?);
    runtime.admission.store(true, Ordering::Release);
    runtime.endpoints.capture_ready()?;
    Ok((runtime, owner))
}

struct PolicyWait<'a, R> {
    reader: Pin<&'a mut Option<R>>,
    timer: Pin<&'a mut Option<tokio::time::Sleep>>,
    started: u64,
    blocked: Option<u64>,
    resumed: Option<u64>,
}

async fn drive_until<'policy, T, R>(
    runtime: &mut Runtime,
    owner: &mut PacketEndpointOwner,
    policy: &mut PolicyWait<'_, R>,
    acquire: impl Fn() -> R,
    shutdown: &crate::control::ShutdownIntent,
    event: impl Future<Output = anyhow::Result<T>>,
    held_publication: bool,
) -> anyhow::Result<T>
where
    R: Future<Output = PolicyRead<'policy>>,
{
    tokio::pin!(event);
    let mut output = None;
    let mut pending_reader = false;
    let mut armed_driver_timer = false;
    loop {
        if output.is_some() && (held_publication || policy.reader.is_none()) {
            if held_publication {
                assert!(
                    pending_reader,
                    "the real Core reader must contend during stream work"
                );
                assert!(
                    armed_driver_timer,
                    "a drained real port must sleep on the live stream timer"
                );
                assert!(
                    policy.reader.is_some(),
                    "the queued reader remains pinned until writer release"
                );
            }
            return Ok(output.take().unwrap());
        }
        if output.is_none() && policy.reader.is_none() && runtime.core_due(Instant::now()) {
            policy.reader.set(Some(acquire()));
            policy.started += 1;
        }
        if held_publication && let Some(read) = policy.reader.as_mut().as_pin_mut() {
            assert!(
                futures::poll!(read).is_pending(),
                "actual publication reader escaped its writer"
            );
            if pending_reader {
                assert_eq!(policy.blocked, Some(policy.started));
            } else {
                policy.blocked = Some(policy.started);
            }
            pending_reader = true;
        }
        tokio::select! {
            result = &mut event, if output.is_none() => output = Some(result?),
            turned = turn(
                policy.reader.as_mut(),
                |cx| owner.poll_join_plane(cx),
                |cx, reading| {
                    let result = runtime.poll_service(cx, shutdown, policy.timer.as_mut(), reading);
                    if held_publication && reading && result.is_pending() {
                        let now = Instant::now();
                        let due = runtime.realms.iter().filter_map(|realm| realm.driver.deadline()).min();
                        let idle_ports = runtime.devices.iter().flat_map(|device| &device.queues).all(|queue| {
                            let port = queue.io.get_ref();
                            port.counters().submitted == port.counters().completed && !port.needs_service_retry()
                        });
                        if let Some(due) = due
                            && due > now
                            && idle_ports
                            && runtime.realms.iter().all(|realm| realm.pending.iter().all(Option::is_none))
                            && runtime.devices.iter().all(|device| !device.capture.vlan_metadata || due < device.metadata_checked + Duration::from_secs(1))
                        {
                            assert_eq!(runtime.next_deadline(now, false), Some(due), "the actual driver deadline wins without Core readers or a CQ retry");
                            assert_eq!(policy.timer.as_ref().get_ref().as_ref().map(|sleep| sleep.deadline()), Some(tokio::time::Instant::from_std(due)), "poll_service must arm that same driver deadline");
                            armed_driver_timer = true;
                        }
                    }
                    result
                },
                shutdown,
            ) => match turned {
                Turn::Read(read) => {
                    assert!(!held_publication, "the real writer is still held");
                    if policy.blocked == Some(policy.started) {
                        assert_eq!(runtime.waiting.len(), 1, "the original blocked reader resumes the retained Core packet");
                        policy.resumed = Some(policy.started);
                    }
                    runtime.resolve(&read)?;
                }
                Turn::Serviced(result) => result?,
                Turn::Joined(_) => anyhow::bail!("real endpoint supervisor ended before capture close"),
                Turn::Shutdown => anyhow::bail!("real endpoint runtime shut down before the peer finished"),
            }
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespace and real AF_XDP"]
async fn policy_publication_keeps_real_endpoint_app_timer_and_close_owned() -> anyhow::Result<()> {
    let pins = guarded_pin_root();
    let artifacts = PathBuf::from(std::env::var_os("HONK_XDP_ARTIFACT_ROOT").unwrap());
    let mut peer = Peer::spawn()?;
    let result = tokio::time::timeout(Duration::from_secs(45), async {
        peer.expect("READY").await?;
        let mut config = honk_config::parser::parse_dae_config(
            "global { dial_mode: ip\n nfqueue_enable: false\n so_mark_from_dae: 0x100 }\n\
             dns { bind: '' }\n\
             datapath { backend: xdp\n direct: core\n xsk_mode: copy\n interface { dut0: lan\n dut1: wan } }\n\
             routing { dport(18084) -> packet-proof\n fallback: direct }",
        )?;
        config.ensure_builtin_nodes();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = vec!["127.0.0.1:9".into()];
        config.global.preconnect_node_count = 0;
        config.global.udp_warm_node_count = 0;
        config.global.store_subscribe = false;
        config.global.check_interval_secs = 3600;
        config.groups.push(honk_config::group::Group {
            name: "packet-proof".into(),
            nodes: vec![honk_config::config::DIRECT_NODE_ID],
            ..Default::default()
        });
        config.validate_assembled()?;
        let resolver = crate::dns::DnsResolver::new(&config.dns)?;
        let forwarder = resolver.forwarder();
        let admission = Arc::new(AtomicBool::new(false));
        let mut plane = ControlPlane::new(
            config.clone(),
            Box::new(crate::ebpf::userspace::UserspaceBackend::new(Arc::clone(&admission))),
            crate::routing::Router::from_config(&config.routing)?,
            Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver()?),
            resolver,
            forwarder,
        )?;
        plane.set_mode_state(Arc::new(parking_lot::RwLock::new(crate::mode::ModeState::new("Rule", "direct"))));
        plane.start_datapath_flags_coordinator()?;
        let router = plane.traffic_router();
        let publication = plane.config_handle();
        let backend = plane.policy_backend_handle();
        let shutdown = plane.shutdown_intent();
        let (mut runtime, mut owner) = start_runtime(plane, &config, &pins, &artifacts, admission).await?;
        let authority = runtime.core.as_ref().unwrap().authority();
        let acquire = || authority.read_policy();
        let reader = None;
        let timer = None;
        tokio::pin!(reader, timer);
        {
        let mut policy = PolicyWait {
            reader: reader.as_mut(),
            timer: timer.as_mut(),
            started: 0,
            blocked: None,
            resumed: None,
        };
        for label in ["router", "config"] {
            peer.command("CONNECT", label).await?;
            drive_until(&mut runtime, &mut owner, &mut policy, &acquire, &shutdown, peer.expect(&format!("CONNECTED {label}")), false).await?;
            let client = format!("192.0.2.99:{}", if label == "router" { 41084 } else { 41085 }).parse().unwrap();
            let destination = "198.51.100.2:18084".parse().unwrap();
            assert!(runtime.realms.iter().any(|realm| runtime.endpoints.retains(realm.driver.scope(), client, destination, 6)), "real captured TCP belongs to Endpoint, not native/Core forwarding");
            let router_writer = if label == "router" { Some(router.write().await) } else { None };
            let config_writer = if label == "config" { Some(publication.write().await) } else { None };
            let active = async {
                peer.command("COLD", label).await?;
                peer.expect(&format!("COLD {label}")).await?;
                peer.command("APP", label).await?;
                peer.expect(&format!("APP {label}")).await?;
                peer.command("RETRANSMIT", label).await?;
                peer.expect(&format!("RETRANSMITTED {label}")).await?;
                peer.command("CLOSE", label).await?;
                peer.expect(&format!("CLOSED {label}")).await
            };
            drive_until(&mut runtime, &mut owner, &mut policy, &acquire, &shutdown, active, true).await?;
            assert_eq!(runtime.waiting.len(), 1, "the captured cold Core packet remains behind publication while the stream finishes");
            let queued = policy.blocked.expect("the publication writer queued a real reader");
            assert_eq!(policy.started, queued);
            assert!(policy.reader.is_some());
            assert_ne!(policy.resumed, Some(queued));
            drop((router_writer, config_writer));
            peer.command("FORWARDED", label).await?;
            drive_until(&mut runtime, &mut owner, &mut policy, &acquire, &shutdown, peer.expect(&format!("FORWARDED {label}")), false).await?;
            assert_eq!(policy.resumed, Some(queued), "the original queued acquisition completed after writer release, not a replacement reader");
            assert!(runtime.waiting.is_empty() && runtime.pending.is_empty(), "the same Core owner resumes after its real writer releases");
        }
        }
        reader.set(None);
        timer.set(None);
        runtime.close_capture()?;
        peer.command("STOP", "owned").await?;
        peer.expect("STOPPED owned").await?;
        let mut warned = false;
        let (_plane, result) = join_endpoints(
            &mut owner,
            |cx| runtime.poll_service(cx, &shutdown, timer.as_mut(), false),
            Instant::now(),
            &mut warned,
        ).await??;
        result?;
        drain_transmit(
            || {
                let mut pending = false;
                for device in &mut runtime.devices {
                    for queue in &mut device.queues {
                        let port = queue.io.get_mut();
                        port.complete(release_completed)?;
                        port.kick()?;
                        pending |= port.counters().submitted != port.counters().completed;
                    }
                }
                Ok(pending)
            },
            Instant::now(),
            &mut warned,
        ).await?;
        for device in &mut runtime.devices {
            assert_eq!(honk_xsk::xdp_state(device.info.ifindex)?.prog_id, device.programs.discover_prog_id());
            for queue in device.queues.drain(..) {
                let mut port = queue.io.into_inner();
                assert_eq!(port.counters().submitted, port.counters().completed);
                assert!(port.close().ready_for_backend_teardown());
                port.close_socket();
            }
        }
        backend.write().await.cleanup().await?;
        println!("real AF_XDP Endpoint app bytes, identical timer retransmission, close and Core publication recovery: router/config PASS");
        Ok::<(), anyhow::Error>(())
    }).await;
    if !result.as_ref().is_ok_and(|result| result.is_ok()) {
        let _ = peer.child.kill().await;
    }
    let status = peer.child.wait().await?;
    result.context("real AF_XDP app/timer/close work starved behind policy publication")??;
    ensure!(status.success(), "the owned real peer failed");
    Ok(())
}

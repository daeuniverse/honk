use super::*;
use crate::control::core_forward::PolicyRead;
use std::{os::unix::fs::MetadataExt, path::PathBuf, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
};

mod adaptive;
pub(super) mod gateway;

const PEER: &str = r#"
import contextlib, ctypes, os, socket, struct, sys, time

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
    # The UDP pump must not fill the TCP witness queue with local transmissions.
    client.setsockopt(263, 23, 1)
    # Nor with incoming pump replies: keep only IPv4 TCP from 198.51.100.2, the only frames reply() reads.
    witness = ctypes.create_string_buffer(b''.join(struct.pack('HBBI', *insn) for insn in (
        (0x28, 0, 0, 12), (0x15, 0, 5, 0x0800), (0x30, 0, 0, 23), (0x15, 0, 3, 6),
        (0x20, 0, 0, 26), (0x15, 0, 1, 0xc6336402), (0x06, 0, 0, 0x40000), (0x06, 0, 0, 0))))
    client.setsockopt(socket.SOL_SOCKET, 26, struct.pack('HL', 8, ctypes.addressof(witness)))
with namespace('server'):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('198.51.100.2', 18084))
    listener.listen(2)
    transit = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    transit.bind(('s0', 0))
    transit.setsockopt(263, 23, 1) # PACKET_IGNORE_OUTGOING: the independent WAN pump is not this peer.
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

def backlog_drops():
    with open('/proc/net/softnet_stat') as stat:
        return sum(int(line.split()[1], 16) for line in stat)

def receive(sock, protocol, source, destination, deadline=None):
    deadline = time.monotonic() + 8 if deadline is None else deadline
    observed = 0
    backlog = backlog_drops()
    while True:
        try:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError('matching packet deadline')
            sock.settimeout(left)
            packet, peer = sock.recvfrom(65535)
            observed += 1
        except TimeoutError as error:
            packets, dropped = struct.unpack('=II', sock.getsockopt(263, 6, 8))
            raise RuntimeError(('packet witness timeout', protocol, source, destination,
                                'observed', observed, 'socket_packets', packets,
                                'socket_drops', dropped, 'backlog_drops', backlog_drops() - backlog)) from error
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
    deadline = time.monotonic() + 8
    while True:
        _, body = receive(client, 6, '198.51.100.2', '192.0.2.99', deadline)
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
connections = 0
selected_ports = {}
for line in sys.stdin:
    command, label = line.strip().split()
    if command == 'PORT':
        name, number = label.split(':')
        selected_ports[name] = int(number)
        print('PORT ' + label, flush=True)
        continue
    if command == 'CONNECT':
        connections += 1
        port = 41084 if label == 'router' else 41085 if label == 'config' else 42000 + connections
        port = selected_ports.get(label, port)
        sequence, acknowledgment = 100 if label == 'router' else 10000 if label == 'config' else connections * 20000, 0
        tcp(2)
        print(label + ': SYN sent', file=sys.stderr, flush=True)
        seq, ack, flags, payload = reply()
        assert (ack, flags, payload) == (sequence + 1, 18, b'')
        print(label + ': SYN-ACK received', file=sys.stderr, flush=True)
        sequence += 1
        acknowledgment = (seq + 1) & 0xffffffff
        tcp(16)
        connection, address = listener.accept()
        connection.settimeout(8)
        assert address[0] == '10.77.0.1', ('not the actual Endpoint dial', address)
        print(label + ': upstream accepted', file=sys.stderr, flush=True)
        warm = ('prime/' + label).encode()
        connection.sendall(warm)
        print(label + ': warm payload sent', file=sys.stderr, flush=True)
        while True:
            seq, ack, flags, payload = reply()
            if payload:
                break
        assert seq == acknowledgment and ack == sequence and payload == warm
        acknowledgment = (seq + len(warm)) & 0xffffffff
        tcp(16)
        print('CONNECTED ' + label, flush=True)
    elif command == 'COLD':
        # No cold packet exists yet; discard old unrelated traffic before its observation window.
        transit.setblocking(False)
        try:
            for _ in range(4096):
                try:
                    transit.recvfrom(65535)
                except BlockingIOError:
                    break
            else:
                raise AssertionError('transit observer did not drain before cold send')
        finally:
            transit.settimeout(8)
        transit.getsockopt(263, 6, 8) # Reset PACKET_STATISTICS at the actual window boundary.
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
        _, drops = struct.unpack('=II', transit.getsockopt(263, 6, 8))
        assert drops == 0, ('cold-packet observer lost wire evidence', drops)
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
    pname_support: crate::ebpf::PnameSupportCell,
) -> anyhow::Result<(Runtime, PacketEndpointOwner)> {
    let (polling_publication, process_polling) =
        plane.polling_runtime().expect("explicit XDP fixture");
    let shutdown = plane.shutdown_intent();
    let backend = plane.policy_backend_handle();
    let active_plan = plane.active_routing_plan_handle();
    let prepared = prepare(&plane, config, pins, Arc::clone(&admission)).await?;
    #[cfg(feature = "ebpf")]
    let host = prepared.host;
    let PreparedRuntime {
        devices,
        topology,
        capture_plan,
        gateway,
        gateway_maps,
        zones,
        local_addresses,
        local_memory,
        kernel_memory,
        realm_scopes,
        plan_memory,
        realms: plans,
        scope_pairs: scopes,
        workers,
        inboxes,
        core,
        memory,
        staging,
        links,
        polling_prefix,
        polling_budget,
        diagnostics,
        ..
    } = prepared;
    plane.stats_handle().install_xdp(Arc::clone(&diagnostics));
    let (endpoints, mut owner, mut drivers) =
        PacketEndpoints::start_driven(plane, scopes, 64, None, ScopeId::HOST).await?;
    let mut realms = Vec::with_capacity(plans.len());
    let mut remote_realms = Vec::with_capacity(plans.len());
    for (ingress, device, link, scope) in plans {
        for worker_index in 0..usize::from(workers.workers) {
            let Some(index) = drivers
                .iter()
                .position(|driver| driver.scope() == scope && driver.worker() == worker_index)
            else {
                continue;
            };
            let members: Vec<usize> = workers
                .placements
                .lock()
                .iter()
                .filter(|placement| placement.realm.scope() == scope)
                .map(|placement| placement.device)
                .collect();
            let generated = (members.len() == 1)
                .then(|| generated_layout(link))
                .flatten();
            let realm = Realm {
                realm_id: *realm_scopes
                    .iter()
                    .find(|(_, value)| **value == scope)
                    .expect("prepared scope realm")
                    .0,
                members,
                ingress,
                device,
                link,
                generated,
                driver: drivers.swap_remove(index),
                pending: [None, None],
            };
            if worker_index == 0 {
                realms.push(realm);
            } else {
                remote_realms.push(realm);
            }
        }
    }
    #[cfg(feature = "ebpf")]
    let host = host.map(|host| host.start(&mut drivers));
    assert!(drivers.is_empty());
    let [inbox, remote_inbox] = inboxes;
    let mut runtime = Runtime {
        devices,
        topology,
        capture_plan: Some(capture_plan),
        capture_plan_memory: Some(plan_memory),
        topology_lost: false,
        gateway,
        gateway_maps,
        zones,
        links,
        local_addresses,
        local_memory,
        _kernel_memory: kernel_memory,
        realm_scopes,
        hold_collector: HoldCollector,
        #[cfg(feature = "ebpf")]
        host,
        admission,
        pname_support,
        realms,
        workers,
        worker: None,
        inbox,
        endpoints,
        core,
        waiting: VecDeque::with_capacity(PENDING),
        pending: VecDeque::with_capacity(PENDING),
        staging,
        closing: false,
        finished: false,
        pressure: Pressure::new(Instant::now()),
        diagnostics,
        core_maintenance_checked: Instant::now(),
        link_check_at: Instant::now() + LINK_CHECK_INTERVAL,
        polling: AdaptivePoll::new(polling_publication, process_polling),
        polling_prefix,
        polling_budget,
        polling_affinity: None,
        qualified_rx: 0,
        qualification_unavailable: false,
        rx_device: 0,
        rx_queue: 0,
        tx_realm: 0,
        tx_class: 0,
        round_cut_short: false,
        policy_recheck: false,
        context_recheck: false,
        context_revision: 0,
        _memory: Some(memory),
    };
    if runtime.workers.workers == 2 {
        runtime.worker = Some(worker::Worker::start(
            Arc::clone(&runtime.workers),
            &mut runtime.devices,
            remote_realms,
            runtime.endpoints.clone(),
            remote_inbox,
            runtime.core.is_some(),
            runtime.polling.participant(),
            Arc::clone(&runtime.polling_budget),
            shutdown,
        )?);
    }
    runtime.workers.ready(0);
    let readiness = Arc::clone(&runtime.workers);
    let timer = None;
    tokio::pin!(timer);
    loop {
        tokio::select! {
            ready = async {
                poll_fn(|cx| owner.poll_ready(cx)).await?;
                poll_fn(|cx| readiness.all_ready(cx)).await
            } => { ready?; break; }
            () = poll_fn(|cx| runtime.poll_scopes(cx, timer.as_mut())) => tokio::task::yield_now().await,
        }
    }
    for device in &mut runtime.devices {
        std::fs::write(
            artifacts.join(format!("driven-runtime.{}.data-id", device.info.name)),
            device.programs.data_prog_id().to_string(),
        )?;
        device
            .attachment
            .as_ref()
            .context("owned XDP link")?
            .replace(device.programs.discover_fd(), device.programs.data_fd())?;
        if let Some(publisher) = &runtime.gateway {
            publisher.register(
                device.info.ifindex,
                device.attachment.take().context("owned XDP link")?,
                Arc::clone(&device.programs),
                GatewayReload {
                    capture: device.capture.clone(),
                    queues: device.info.queues.last().copied().context("RX queues")? + 1,
                    ipv4_broadcasts: runtime.topology.get_ref().ipv4_broadcasts().to_vec(),
                },
            )?;
        }
        device.active = true;
    }
    runtime.diagnostics.lifecycle(Lifecycle::Active);
    let topology = runtime.admit_final_topology()?;
    ensure!(topology.ipv4_broadcasts() == runtime.topology.get_ref().ipv4_broadcasts());
    // SAFETY: production and the fixture retain the watcher's stable descriptor.
    runtime.topology = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
    for device in &runtime.devices {
        runtime
            .topology
            .get_mut()
            .expect_program(device.info.ifindex, device.programs.data_prog_id());
    }
    if let Some(publisher) = &runtime.gateway {
        let mut backend = backend.write().await;
        let plan = active_plan.read().clone();
        if plan.policy_fingerprint != publisher.fingerprint() {
            publisher.publish(&plan)?;
        }
        backend
            .userspace_mut()?
            .install_gateway(Some(Arc::clone(publisher)))?;
        publisher.commit();
    }
    let zero_copy = config
        .datapath
        .as_ref()
        .context("XDP configuration missing")?
        .effective_xsk_mode()
        == XskMode::ZeroCopy;
    for device in &runtime.devices {
        device.info.validate_current()?;
        for queue in &device.queues {
            assert_eq!(
                queue.io.get_ref().zerocopy(),
                zero_copy,
                "actual AF_XDP mode differs from configuration on {} queue {}",
                device.info.name,
                queue.id
            );
        }
    }
    current_topology(
        &mut runtime.topology,
        runtime.gateway.as_deref(),
        &runtime.devices,
        &mut runtime.topology_lost,
    )?;
    runtime.capture_plan.take();
    runtime.capture_plan_memory.take();
    runtime.rebuild_polling_context();
    #[cfg(feature = "ebpf")]
    if let Some(host) = &mut runtime.host {
        if let Some(publisher) = &runtime.gateway {
            host.capture.set_gateway(Arc::clone(publisher))?;
        }
        host.admit(&runtime.pname_support)?;
    }
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

#[derive(Clone, Copy, PartialEq)]
enum Hold {
    Released,
    /// The writer is held and the cold packet was just sent: its ingress may still be in
    /// flight or in the worker handoff, so keep driving until the real reader is pending.
    Contend,
    /// Contention is established; stream work must neither resolve nor replace the reader.
    Held,
}

async fn drive_until<'policy, T, R>(
    runtime: &mut Runtime,
    owner: &mut PacketEndpointOwner,
    policy: &mut PolicyWait<'_, R>,
    acquire: impl Fn() -> R,
    shutdown: &crate::control::ShutdownIntent,
    event: impl Future<Output = anyhow::Result<T>>,
    hold: Hold,
) -> anyhow::Result<T>
where
    R: Future<Output = PolicyRead<'policy>>,
{
    tokio::pin!(event);
    let notification = runtime.polling.notification();
    tokio::pin!(notification);
    let mut output = None;
    let mut pending_reader = false;
    let mut armed_driver_timer = false;
    let control = runtime.polling.test_control();
    if hold != Hold::Released {
        control.clear_pending();
    }
    loop {
        if let Some(wait) = control.pending_wait()
            && wait.reading
            && wait.idle_ports
            && !wait.pending_outputs
            && let Some(due) = wait.driver_deadline
            && wait.armed_deadline == Some(tokio::time::Instant::from_std(due))
        {
            armed_driver_timer = true;
        }
        let finished = match hold {
            Hold::Released => policy.reader.is_none(),
            Hold::Contend => false,
            Hold::Held => true,
        };
        if output.is_some() && finished {
            if hold == Hold::Held {
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
        if hold != Hold::Released
            && let Some(read) = policy.reader.as_mut().as_pin_mut()
        {
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
        if hold == Hold::Contend && pending_reader && output.is_some() {
            return Ok(output.take().unwrap());
        }
        let retained_core = runtime.waiting.len();
        let started = std::cell::Cell::new(policy.started);
        tokio::select! {
            result = &mut event, if output.is_none() => output = Some(result?),
            joined = owner_step(
                runtime,
                owner,
                policy.reader.as_mut(),
                || { started.set(started.get() + 1); Some(acquire()) },
                shutdown,
                policy.timer.as_mut(),
                notification.as_mut(),
            ) => {
                if joined?.is_some() {
                    anyhow::bail!("real endpoint supervisor ended before capture close");
                }
            }
            // A turn that acquired the reader awaits it or new device work; with the writer
            // held and no stream traffic yet, neither arrives, so re-check from outside.
            () = tokio::time::sleep(Duration::from_millis(1)), if hold == Hold::Contend && output.is_some() => {}
        }
        policy.started = started.get();
        if policy.blocked == Some(policy.started)
            && retained_core == 1
            && runtime.waiting.is_empty()
            && policy.reader.is_none()
        {
            assert!(hold == Hold::Released, "the real writer is still held");
            policy.resumed = Some(policy.started);
        }
    }
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespace and real AF_XDP"]
async fn policy_publication_keeps_real_endpoint_app_timer_and_close_owned() -> anyhow::Result<()> {
    publication_owned_case(1).await
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespace, two physical RX queues and two allowed CPUs"]
async fn two_worker_publication_keeps_real_endpoint_app_timer_and_close_owned() -> anyhow::Result<()>
{
    publication_owned_case(2).await
}

async fn publication_owned_case(workers: u8) -> anyhow::Result<()> {
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
        config.datapath.as_mut().unwrap().workers = Some(workers);
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
        let pname_support = Arc::new(parking_lot::RwLock::new(crate::ebpf::PnameSupport::Unavailable));
        let mut plane = ControlPlane::new(
            config.clone(),
            Box::new(crate::ebpf::userspace::UserspaceBackend::new(
                Arc::clone(&admission), Arc::clone(&pname_support),
            )),
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
        let (mut runtime, mut owner) = start_runtime(plane, &config, &pins, &artifacts, admission, pname_support).await?;
        let mut selected_ports = [41084u16, 41085];
        if workers == 2 {
            let scope = runtime.realms.iter().find(|realm| realm.link.path.physical_ifindex == runtime.devices[0].info.ifindex).unwrap().driver.scope();
            let realm = runtime.workers.placement(scope)?.realm;
            for (worker, selected) in selected_ports.iter_mut().enumerate() {
                *selected = (41084..60000).find(|port| realm.worker_for_tcp(
                    format!("192.0.2.99:{port}").parse().unwrap(), "198.51.100.2:18084".parse().unwrap()) == worker).unwrap();
                let request = format!("{}:{}", ["router", "config"][worker], selected);
                peer.command("PORT", &request).await?;
                peer.expect(&format!("PORT {request}")).await?;
            }
        }
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
            drive_until(&mut runtime, &mut owner, &mut policy, &acquire, &shutdown, peer.expect(&format!("CONNECTED {label}")), Hold::Released).await?;
            let client = format!("192.0.2.99:{}", selected_ports[usize::from(label == "config")]).parse().unwrap();
            let destination = "198.51.100.2:18084".parse().unwrap();
            assert!(runtime.realms.iter().any(|realm| runtime.endpoints.retains(realm.driver.scope(), client, destination, 6)), "real captured TCP belongs to Endpoint, not native/Core forwarding");
            let router_writer = if label == "router" { Some(router.write().await) } else { None };
            let config_writer = if label == "config" { Some(publication.write().await) } else { None };
            let cold = async {
                peer.command("COLD", label).await?;
                peer.expect(&format!("COLD {label}")).await
            };
            tokio::time::timeout(
                Duration::from_secs(8),
                drive_until(&mut runtime, &mut owner, &mut policy, &acquire, &shutdown, cold, Hold::Contend),
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "the cold Core packet never reached the held policy reader: waiting={} pending={} reader={} pressure={:?}",
                    runtime.waiting.len(),
                    runtime.pending.len(),
                    policy.reader.is_some(),
                    runtime.pressure.counters,
                )
            })??;
            let active = async {
                peer.command("APP", label).await?;
                peer.expect(&format!("APP {label}")).await?;
                peer.command("RETRANSMIT", label).await?;
                peer.expect(&format!("RETRANSMITTED {label}")).await?;
                peer.command("CLOSE", label).await?;
                peer.expect(&format!("CLOSED {label}")).await
            };
            drive_until(&mut runtime, &mut owner, &mut policy, &acquire, &shutdown, active, Hold::Held).await?;
            assert_eq!(runtime.waiting.len(), 1, "the captured cold Core packet remains behind publication while the stream finishes");
            let queued = policy.blocked.expect("the publication writer queued a real reader");
            assert_eq!(policy.started, queued);
            assert!(policy.reader.is_some());
            assert_ne!(policy.resumed, Some(queued));
            drop((router_writer, config_writer));
            peer.command("FORWARDED", label).await?;
            drive_until(&mut runtime, &mut owner, &mut policy, &acquire, &shutdown, peer.expect(&format!("FORWARDED {label}")), Hold::Released).await?;
            assert_eq!(policy.resumed, Some(queued), "the original queued acquisition completed after writer release, not a replacement reader");
        }
        }
        reader.set(None);
        timer.set(None);
        runtime.close_capture(&backend).await?;
        let wakeups = |runtime: &Runtime| runtime.devices.iter().flat_map(|device| &device.queues).map(|queue| {
            let counters = queue.io.get_ref().counters();
            (counters.rx_kicks, counters.tx_kicks)
        }).collect::<Vec<_>>();
        let after_detach = wakeups(&runtime);
        peer.command("STOP", "owned").await?;
        peer.expect("STOPPED owned").await?;
        let mut warned = false;
        let notification = runtime.polling.notification();
        tokio::pin!(notification);
        let (_plane, result) = join_endpoints(
            &mut owner,
            |cx| runtime.poll_service(cx, &shutdown, timer.as_mut(), false, notification.as_mut()),
            Instant::now(),
            &mut warned,
        ).await??;
        result?;
        drain_transmit(
            || runtime.complete_transmit(),
            Instant::now(),
            &mut warned,
        ).await?;
        if let Some(worker) = &mut runtime.worker { worker.join().await?; }
        assert_eq!(wakeups(&runtime), after_detach, "physical wakeup after detach");
        for device in &mut runtime.devices {
            assert!(honk_xsk::xdp_absent(device.info.ifindex)?);
            for queue in device.queues.drain(..) {
                let mut port = queue.io.into_inner();
                assert_eq!(port.counters().submitted, port.counters().completed);
                assert!(port.close().ready_for_backend_teardown());
                port.close_socket();
            }
            device.vlan_offload.restore()?;
        }
        #[cfg(feature = "ebpf")]
        if let Some(host) = runtime.host.take() {
            host.finish()?;
        }
        backend.write().await.cleanup().await?;
        runtime.finished = true;
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

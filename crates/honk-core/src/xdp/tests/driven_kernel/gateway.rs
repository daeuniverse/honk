use super::*;

pub(in crate::xdp::tests) fn guard() {
    // SAFETY: geteuid has no arguments or memory preconditions.
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let lane = std::env::var("HONK_CI_VM_LANE").unwrap();
    assert!(matches!(lane.as_str(), "floor" | "recent"));
    let expected = std::env::var("HONK_CI_EXPECTED_KERNEL").unwrap();
    assert_eq!(
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap()
            .trim(),
        expected,
    );
    let _ = guarded_pin_root();
}

fn timestamp() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

struct Fixture {
    runtime: Runtime,
    owner: PacketEndpointOwner,
    config: Config,
    commands: tokio::sync::mpsc::Sender<crate::control::ControlCommand>,
    diagnostics: crate::config_diagnostics::SharedDiagnostics,
    backend: Arc<tokio::sync::RwLock<Box<dyn crate::ebpf::PolicyBackend>>>,
    authority: crate::control::core_forward::RoutingAuthority,
    shutdown: Arc<crate::control::ShutdownIntent>,
}

impl Fixture {
    async fn start() -> anyhow::Result<Self> {
        guard();
        let pins = guarded_pin_root();
        let artifacts = PathBuf::from(std::env::var_os("HONK_XDP_ARTIFACT_ROOT").unwrap());
        let mut config = honk_config::parser::parse_dae_config(
            "global { dial_mode: ip\n nfqueue_enable: false\n so_mark_from_dae: 0x100 }\n\
             dns { bind: '' }\n\
             datapath { backend: xdp\n direct: endpoint\n xsk_mode: copy\n interface { dut0: lan\n dut1: wan } }\n\
             routing { fallback: direct }",
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
        let pname = Arc::new(parking_lot::RwLock::new(
            crate::ebpf::PnameSupport::Unavailable,
        ));
        let mut plane = ControlPlane::new(
            config.clone(),
            Box::new(crate::ebpf::userspace::UserspaceBackend::new(
                Arc::clone(&admission),
                Arc::clone(&pname),
            )),
            crate::routing::Router::from_config(&config.routing)?,
            Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver()?),
            resolver,
            forwarder,
        )?;
        plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
            crate::mode::ModeState::new("Rule", "direct"),
        )));
        plane.start_datapath_flags_coordinator()?;
        let commands = plane.command_sender();
        let diagnostics = plane.diagnostics_handle();
        let backend = plane.policy_backend_handle();
        let shutdown = plane.shutdown_intent();
        let authority = plane.core_forward_policy(Execution::MixedEndpoints).await?;
        let (runtime, owner) =
            start_runtime(plane, &config, &pins, &artifacts, admission, pname).await?;
        ensure!(
            runtime.gateway.is_some(),
            "Endpoint gateway publisher missing"
        );
        ensure!(
            runtime.core.is_none(),
            "gateway fixture requires Endpoint Direct"
        );
        Ok(Self {
            runtime,
            owner,
            config,
            commands,
            diagnostics,
            backend,
            authority,
            shutdown,
        })
    }

    async fn drive<T>(
        &mut self,
        event: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<T> {
        let reader = None;
        let timer = None;
        tokio::pin!(reader, timer);
        let mut policy = PolicyWait {
            reader: reader.as_mut(),
            timer: timer.as_mut(),
            started: 0,
            blocked: None,
            resumed: None,
        };
        drive_until(
            &mut self.runtime,
            &mut self.owner,
            &mut policy,
            || self.authority.read_policy(),
            &self.shutdown,
            event,
            Hold::Released,
        )
        .await
    }

    async fn finish(mut self) -> anyhow::Result<()> {
        self.runtime.close_capture()?;
        let timer = None;
        tokio::pin!(timer);
        let notification = self.runtime.polling.notification();
        tokio::pin!(notification);
        let mut warned = false;
        let (_plane, result) = join_endpoints(
            &mut self.owner,
            |cx| {
                self.runtime.poll_service(
                    cx,
                    &self.shutdown,
                    timer.as_mut(),
                    false,
                    notification.as_mut(),
                )
            },
            Instant::now(),
            &mut warned,
        )
        .await??;
        result?;
        drain_transmit(
            || self.runtime.complete_transmit(),
            Instant::now(),
            &mut warned,
        )
        .await?;
        if let Some(worker) = &mut self.runtime.worker {
            worker.join().await?;
        }
        for device in &mut self.runtime.devices {
            assert!(honk_xsk::xdp_absent(device.info.ifindex)?);
            for queue in device.queues.drain(..) {
                let mut port = queue.io.into_inner();
                assert_eq!(port.counters().submitted, port.counters().completed);
                assert!(port.close().ready_for_backend_teardown());
                port.close_socket();
            }
            device.vlan_offload.restore()?;
        }
        self.backend.write().await.cleanup().await?;
        self.runtime.finished = true;
        Ok(())
    }
}

const PUBLICATION_PEER: &str = r#"
import contextlib, json, os, select, socket, struct, sys, threading, time
home = os.open('/proc/self/ns/net', os.O_RDONLY)
@contextlib.contextmanager
def namespace(name):
    fd = os.open('/run/netns/' + name, os.O_RDONLY)
    try:
        os.setns(fd, 0)
        yield
    finally:
        os.setns(home, 0)
        os.close(fd)
with namespace('client'):
    sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sender.bind(('c0', 0))
with namespace('server'):
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(('198.51.100.2', 18098))
os.close(home)
def checksum(data):
    data += b'\0' * (len(data) % 2)
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535
sent = {}
def send(order):
    payload = ('G08/%06d' % order).encode()
    src, dst = socket.inet_aton('192.0.2.2'), socket.inet_aton('198.51.100.2')
    udp = struct.pack('!HHHH', 41098, 18098, 8 + len(payload), 0) + payload
    udp = udp[:6] + struct.pack('!H', checksum(src + dst + struct.pack('!BBH', 0, 17, len(udp)) + udp) or 65535) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), order, 0, 64, 17, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    sent[order] = time.time_ns()
    sender.send(bytes.fromhex('0200000000100200000000200800') + ip + udp)
def receive(deadline):
    result = []
    while time.monotonic() < deadline:
        if not select.select([receiver], [], [], min(0.01, max(0, deadline - time.monotonic())))[0]:
            continue
        payload, source = receiver.recvfrom(65535)
        if not payload.startswith(b'G08/'):
            continue
        order = int(payload[4:])
        result.append(dict(order=order, sent_ns=sent[order], received_ns=time.time_ns(), source=source))
    return result
print('READY', flush=True)
assert sys.stdin.readline().strip() == 'GO'
send(0)
first = receive(time.monotonic() + 0.1)
assert any(item['order'] == 0 and item['source'][0] == '192.0.2.2' for item in first), first
print('BASELINE ' + json.dumps(first), flush=True)
def pump():
    for order in range(1, 201):
        send(order)
        time.sleep(0.005)
thread = threading.Thread(target=pump)
thread.start()
observed = receive(time.monotonic() + 1.5)
thread.join()
print('OBSERVATIONS ' + json.dumps(observed), flush=True)
assert sys.stdin.readline().strip() == 'FOLLOW'
send(201)
following = receive(time.monotonic() + 0.5)
print('FOLLOWING ' + json.dumps(following), flush=True)
sender.close()
receiver.close()
"#;

struct Notrack(String);

impl Notrack {
    fn install() -> anyhow::Result<Self> {
        let name = format!("honk_g08_{}", std::process::id());
        let created = std::process::Command::new("nft")
            .args(["create", "table", "inet", &name])
            .output()?;
        ensure!(
            created.status.success(),
            "G08 NOTRACK table: {}",
            String::from_utf8_lossy(&created.stderr)
        );
        let table = Self(name);
        for args in [
            vec![
                "add",
                "chain",
                "inet",
                &table.0,
                "raw",
                "{ type filter hook prerouting priority -300; policy accept; }",
            ],
            vec![
                "add",
                "rule",
                "inet",
                &table.0,
                "raw",
                "ip",
                "saddr",
                "192.0.2.2",
                "udp",
                "sport",
                "41098",
                "udp",
                "dport",
                "18098",
                "notrack",
            ],
        ] {
            let output = std::process::Command::new("nft").args(args).output()?;
            ensure!(
                output.status.success(),
                "G08 NOTRACK setup: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(table)
    }
}

impl Drop for Notrack {
    fn drop(&mut self) {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", &self.0])
            .output();
    }
}

async fn observations(
    output: &mut Lines<BufReader<ChildStdout>>,
    prefix: &str,
) -> anyhow::Result<Vec<serde_json::Value>> {
    let line = output.next_line().await?.context("G08 peer disappeared")?;
    let json = line
        .strip_prefix(prefix)
        .context("unexpected G08 peer event")?;
    Ok(serde_json::from_str(json)?)
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces and real Endpoint AF_XDP"]
async fn gateway_g08_real_publication_observes_packet_and_generation_windows() -> anyhow::Result<()>
{
    tokio::time::timeout(Duration::from_secs(45), async {
        let mut fixture = Fixture::start().await?;
        let _notrack = Notrack::install()?;
        let device = fixture.runtime.devices.iter().find(|device| device.info.name == "dut0").context("dut0")?;
        let ifindex = device.info.ifindex;
        let old_program = honk_xsk::xdp_state(ifindex)?.prog_id;
        let old_generation = fixture.diagnostics.read().generation;
        let baseline_time = timestamp();
        let mut child = Command::new("python3")
            .args(["-u", "-c", PUBLICATION_PEER])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap()).lines();
        ensure!(output.next_line().await?.as_deref() == Some("READY"));
        input.write_all(b"GO\n").await?;
        let mut packets = fixture.drive(observations(&mut output, "BASELINE ")).await?;
        let diagnostics = Arc::clone(&fixture.diagnostics);
        let sampling = Arc::new(AtomicBool::new(true));
        let running = Arc::clone(&sampling);
        let sampler = std::thread::spawn(move || {
            let mut samples = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(10);
            while running.load(Ordering::Acquire) && Instant::now() < deadline {
                let before_ns = timestamp();
                let before_generation = diagnostics.read().generation;
                let state = honk_xsk::xdp_state(ifindex);
                let after_generation = diagnostics.read().generation;
                let after_ns = timestamp();
                if let Ok(state) = state {
                    samples.push((before_ns, after_ns, state.prog_id, before_generation, after_generation));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            samples
        });
        let mut next = fixture.config.clone();
        next.routing.rules = honk_config::parser::parse_dae_config(
            "routing { dport(18098) -> packet-proof\n fallback: direct }",
        )?.routing.rules;
        let (send, reply) = tokio::sync::oneshot::channel();
        fixture.commands.send(crate::control::ControlCommand::ReloadConfig {
            request_id: 8,
            config: Box::new(next),
            diagnostics: Vec::new(),
            #[cfg(feature = "native-api")]
            sources: None,
            #[cfg(feature = "native-api")]
            expected_group_revision: None,
            result: send,
        }).await?;
        let result = fixture.drive(async { Ok(reply.await?) }).await;
        sampling.store(false, Ordering::Release);
        let mut samples = vec![(baseline_time, baseline_time, old_program, old_generation, old_generation)];
        samples.extend(sampler.join().map_err(|_| anyhow::anyhow!("G08 sampler panicked"))?);
        let reply = result?;
        ensure!(matches!(reply.outcome, crate::control::ReloadOutcome::Committed { .. }), "real policy publication failed: {:?}", reply.outcome);
        let new_program = honk_xsk::xdp_state(ifindex)?.prog_id;
        let new_generation = fixture.diagnostics.read().generation;
        let committed_time = timestamp();
        samples.push((committed_time, committed_time, new_program, new_generation, new_generation));
        packets.extend(fixture.drive(observations(&mut output, "OBSERVATIONS ")).await?);
        input.write_all(b"FOLLOW\n").await?;
        packets.extend(fixture.drive(observations(&mut output, "FOLLOWING ")).await?);
        ensure!(child.wait().await?.success(), "G08 peer failed");
        assert_ne!(old_program, new_program);
        assert_ne!(old_generation, new_generation);
        ensure!(packets.iter().any(|packet| packet["order"] == 201 && packet["source"][0] == "10.77.0.1"), "post-publication packet did not traverse the actual Endpoint socket");
        for packet in &packets {
            let time = u128::from(packet["sent_ns"].as_u64().context("packet send time")?);
            let sample = samples.iter().rev().find(|sample| sample.1 <= time).context("packet predates fixture baseline")?;
            println!("G08 packet tuple=192.0.2.2:41098->198.51.100.2:18098/udp device=dut0 ifindex={ifindex} order={} position={} sent_ns={} received_ns={} executor={} sampled_program_id={} sampled_software_generation={}..{} sample_time_ns={}..{} attribution=sampled_not_reader_identity", packet["order"], if packet["order"] == 0 { "first" } else { "following" }, packet["sent_ns"], packet["received_ns"], if packet["source"][0] == "192.0.2.2" { "kernel" } else { "Endpoint" }, sample.2, sample.3, sample.4, sample.0, sample.1);
        }
        println!("G08 publication device=dut0 ifindex={ifindex} program={old_program}->{new_program} software_generation={old_generation}->{new_generation} clock=realtime_ns");
        for sample in samples.iter().filter(|sample| sample.2 == new_program && sample.3 == old_generation && sample.4 == old_generation) {
            println!("G08 xdp_software_sample tuple=192.0.2.2:41098->198.51.100.2:18098/udp device=dut0 ifindex={ifindex} time_ns={}..{} program={} software_generation={} packet_order=unassociated", sample.0, sample.1, sample.2, sample.3);
        }
        println!("NOT_RUN: G08 old_reader_pass_new_reader_xsk: bounded single-member run cannot attribute an in-flight packet to a reader program; dual active bond-member wire correlation belongs to smoke");
        println!("NOT_RUN: G08 xdp_software_commit_gap: program/generation samples do not identify a packet executed inside the commit gap");
        println!("NOT_RUN: G08 rollback: fixture has no reliable real later-link update failure after an observed earlier successful update");
        println!("NOT_RUN: G08 collector: public owner APIs do not expose the last-read/refresh/delete causal order for a real packet");
        fixture.finish().await
    }).await.context("G08 bounded real-publication fixture")?
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces, real veth AF_XDP transmit and CQ"]
async fn gateway_g17_real_veth_transmit_cq_and_early_release() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut fixture = Fixture::start().await?;
        let device = fixture
            .runtime
            .devices
            .iter_mut()
            .find(|device| device.info.name == "dut0")
            .context("dut0")?;
        let (endpoints, owner) = super::super::retention::gateway_g17_port_outputs(
            device.queues[0].io.get_mut(),
            device.info.ifindex,
        )
        .await?;
        fixture.finish().await?;
        endpoints.shutdown().await?;
        owner.run().await
    })
    .await
    .context("G17 bounded real-veth fixture")?
}

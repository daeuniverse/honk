use super::*;

mod dns;
mod dns_reload;

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
    router: Arc<tokio::sync::RwLock<crate::routing::Router>>,
    shutdown: Arc<crate::control::ShutdownIntent>,
}

impl Fixture {
    async fn start(direct: DirectProfile) -> anyhow::Result<Self> {
        let profile = match direct {
            DirectProfile::Core => "core",
            DirectProfile::Endpoint => "endpoint",
        };
        let config = honk_config::parser::parse_dae_config(&format!(
            "global {{ dial_mode: ip\n nfqueue_enable: false\n so_mark_from_dae: 0x100 }}\n\
             dns {{ bind: '' }}\n\
             datapath {{ backend: xdp\n direct: {profile}\n xsk_mode: copy\n interface {{ dut0: lan\n dut1: wan }} }}\n\
             routing {{ fallback: direct }}",
        ))?;
        Self::start_config(config).await
    }

    async fn start_config(config: Config) -> anyhow::Result<Self> {
        Self::start_config_inner(config, false).await
    }

    async fn start_config_inner(mut config: Config, defer_gateway: bool) -> anyhow::Result<Self> {
        guard();
        let artifacts = PathBuf::from(std::env::var_os("HONK_XDP_ARTIFACT_ROOT").unwrap());
        let direct = config
            .datapath
            .as_ref()
            .and_then(|d| d.direct)
            .context("fixture requires a Direct profile")?;
        config.ensure_builtin_nodes();
        config.global.tcp_check_url.clear();
        config.global.udp_check_dns = Some(vec!["127.0.0.1:9".into()]);
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
        let router = plane.traffic_router();
        let authority = plane.core_forward_policy(Execution::MixedEndpoints).await?;
        let (runtime, owner) =
            start_runtime(plane, &config, &artifacts, admission, pname, defer_gateway).await?;
        ensure!(runtime.gateway.is_some() == (direct == DirectProfile::Endpoint));
        ensure!(runtime.core.is_some() == (direct == DirectProfile::Core));
        Ok(Self {
            runtime,
            owner,
            config,
            commands,
            diagnostics,
            backend,
            authority,
            router,
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
        self.runtime.close_capture(&self.backend).await?;
        self.finish_after_capture_close().await
    }

    async fn finish_after_capture_close(&mut self) -> anyhow::Result<()> {
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
        if let Some(tasks) = self.runtime.workers.auxiliary.get() {
            tasks.join().await?;
        }
        result?;
        drain_transmit(
            || self.runtime.complete_physical_tx(None),
            Instant::now(),
            &mut warned,
        )
        .await?;
        if let Some(worker) = &mut self.runtime.worker {
            worker.join().await?;
        }
        ensure!(
            self.runtime.ports_ready_for_backend_teardown(),
            "XDP queues still own buffers at fixture teardown"
        );
        for device in &mut self.runtime.devices {
            assert!(honk_xsk::xdp_absent(device.info.ifindex)?);
            for queue in device.queues.drain(..) {
                let mut port = queue.io.into_inner();
                assert_eq!(port.counters().submitted, port.counters().completed);
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
        let mut fixture = Fixture::start(DirectProfile::Endpoint).await?;
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
        let mut fixture = Fixture::start(DirectProfile::Endpoint).await?;
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

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces and real Endpoint AF_XDP"]
async fn gateway_close_detaches_links_after_backend_unregister_timeout() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        // If terminal ownership cannot be proven, retain the fixture until the test process exits.
        let mut owned = std::mem::ManuallyDrop::new(Fixture::start(DirectProfile::Endpoint).await?);
        let fixture = &mut *owned;
        ensure!(
            fixture.runtime.devices.len() == 2,
            "expected both DUT devices"
        );
        for device in &fixture.runtime.devices {
            let state = honk_xsk::xdp_state(device.info.ifindex)
                .with_context(|| format!("reading {} XDP state before close", device.info.name))?;
            let expected = fixture_program_id(fixture.runtime.gateway.as_deref(), device)?;
            ensure!(
                expected != 0 && state.prog_id == expected,
                "{} XDP program before close: expected {expected}, got {state:?}",
                device.info.name
            );
        }

        {
            let mut writer = fixture.backend.write().await;
            let started = Instant::now();
            let error = fixture
                .runtime
                .close_capture(&fixture.backend)
                .await
                .expect_err("capture close succeeded with the backend writer held");
            let elapsed = started.elapsed();
            ensure!(
                error
                    .downcast_ref::<tokio::time::error::Elapsed>()
                    .is_some(),
                "expected the gateway unregister timeout, got {error:#}"
            );
            ensure!(
                elapsed >= Duration::from_millis(100),
                "gateway unregister timed out after only {elapsed:?}"
            );
            for device in &fixture.runtime.devices {
                let absent = honk_xsk::xdp_absent(device.info.ifindex).with_context(|| {
                    format!("reading {} XDP state after close", device.info.name)
                })?;
                ensure!(
                    absent,
                    "{} XDP link survived capture close",
                    device.info.name
                );
            }

            // The deadline prevented unregistering the now-detached publisher.
            writer.install_gateway(None)?;
        }
        fixture.finish_after_capture_close().await?;
        drop(std::mem::ManuallyDrop::into_inner(owned));
        Ok(())
    })
    .await
    .context("bounded gateway unregister timeout fixture")?
}

fn fixture_program_id(publisher: Option<&GatewayPublisher>, device: &Device) -> io::Result<u32> {
    match publisher {
        Some(publisher) => publisher.validate_programs(|members| {
            members
                .iter()
                .find(|(idx, _)| *idx == device.info.ifindex)
                .map(|(_, prog)| *prog)
                .ok_or_else(|| io::Error::other("fixture gateway member missing"))
        }),
        None => Ok(device.unpublished_programs()?.data_prog_id()),
    }
}

// Use the fixture's own link, independently of where Gateway or Core stores its FD.
fn revoke_fixture_link(
    publisher: Option<&GatewayPublisher>,
    device: &Device,
) -> anyhow::Result<()> {
    let ifindex = format!("ifindex:\t{}", device.info.ifindex);
    let program = format!("prog_id:\t{}", fixture_program_id(publisher, device)?);
    let mut owned = None;
    for entry in std::fs::read_dir("/proc/self/fdinfo")? {
        let entry = entry?;
        let info = match std::fs::read_to_string(entry.path()) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            result => result?,
        };
        if ["link_type:\txdp", &ifindex, &program]
            .iter()
            .all(|field| info.lines().any(|line| line == *field))
        {
            ensure!(owned.is_none(), "ambiguous fixture link FD");
            owned = Some(entry.file_name().to_string_lossy().parse::<u32>()?);
        }
    }
    let fd = owned.context("no fixture link FD")?;
    // SAFETY: the fixture holds this exact XDP link across the synchronous syscall;
    // the BPF_LINK_DETACH attribute is one initialized u32 and never closes the FD.
    if unsafe {
        libc::syscall(
            libc::SYS_bpf,
            aya_obj::generated::bpf_cmd::BPF_LINK_DETACH as u32,
            &fd,
            size_of_val(&fd),
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }
    ensure!(honk_xsk::xdp_absent(device.info.ifindex)?);
    Ok(())
}

async fn quiet_link_loss(direct: DirectProfile) -> anyhow::Result<()> {
    let mut f = Fixture::start(direct).await?;
    let secondary = {
        // Leave only this fixture's link multicast group so RTM_NEWLINK cannot mask a missing timer.
        let group: libc::c_int = 1; // RTNLGRP_LINK
        // SAFETY: the fixture owns this subscribed socket and group is a live integer.
        if unsafe {
            libc::setsockopt(
                f.runtime.topology.get_ref().as_raw_fd(),
                libc::SOL_NETLINK,
                libc::NETLINK_DROP_MEMBERSHIP,
                (&group as *const libc::c_int).cast(),
                size_of_val(&group) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }
        let _writer = f.router.write().await;
        let reader = (direct == DirectProfile::Core).then(|| f.authority.read_policy());
        let timer = None;
        let notification = f.runtime.polling.notification();
        tokio::pin!(reader, timer, notification);
        if let Some(read) = reader.as_mut().as_pin_mut() {
            assert!(futures::poll!(read).is_pending());
        }
        let initial = f.runtime.link_check_at;
        tokio::time::timeout(
            Duration::from_secs(4),
            poll_fn(|cx| {
                match f.runtime.poll_service(
                    cx,
                    &f.shutdown,
                    timer.as_mut(),
                    reader.is_some(),
                    notification.as_mut(),
                ) {
                    Poll::Ready(result) => {
                        result?;
                        cx.waker().wake_by_ref();
                    }
                    Poll::Pending
                        if f.runtime.link_check_at > initial
                            && f.runtime
                                .devices
                                .iter()
                                .flat_map(|d| &d.queues)
                                .all(|q| !q.io.get_ref().needs_service_retry()) =>
                    {
                        return Poll::Ready(Ok::<_, anyhow::Error>(()));
                    }
                    Poll::Pending => {}
                }
                Poll::Pending
            }),
        )
        .await
        .context("quiet owner did not rearm its link check")??;
        let due = f.runtime.link_check_at;
        let armed = timer
            .as_ref()
            .as_pin_ref()
            .context("quiet owner parked without a timer")?;
        ensure!(
            armed.deadline().into_std() <= due,
            "parked past physical link deadline"
        );
        let device = f
            .runtime
            .devices
            .iter()
            .find(|d| d.info.name == "dut0")
            .context("dut0")?;
        revoke_fixture_link(f.runtime.gateway.as_deref(), device)?;
        let error = tokio::time::timeout_at((due + Duration::from_secs(1)).into(), async {
            loop {
                match owner_step(
                    &mut f.runtime,
                    &mut f.owner,
                    reader.as_mut(),
                    || None,
                    &f.shutdown,
                    timer.as_mut(),
                    notification.as_mut(),
                )
                .await
                {
                    Err(error) => return Ok(error),
                    Ok(Some(_)) => {
                        anyhow::bail!("endpoint owner ended before link loss was reported")
                    }
                    Ok(None) => {}
                }
            }
        })
        .await
        .context("owner missed revoked physical link")??;
        ensure!(
            f.runtime.topology_lost
                && error.downcast_ref::<&str>().copied() == Some(STANDBY_LINK_CHECK)
                && error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::InvalidData),
            "unexpected owner outcome: {error:#}"
        );
        if direct == DirectProfile::Core {
            assert!(futures::poll!(reader.as_mut().as_pin_mut().unwrap()).is_pending());
        }
        println!("{direct:?} revoked link detected by the standby FD check");
        (direct == DirectProfile::Core)
            .then(|| error.downcast_ref::<io::Error>().unwrap().to_string())
    };
    let close = f
        .runtime
        .close_capture(&f.backend)
        .await
        .expect_err("lost capture authority");
    // Non-gateway close rechecks each physical link, including the one just revoked.
    ensure!(
        close.chain().count() == 1 + usize::from(secondary.is_some())
            && secondary.is_none_or(|expected| close.to_string().ends_with(&expected)),
        "unexpected additional capture close failure: {close:#}"
    );
    f.finish_after_capture_close().await
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM interfaces"]
async fn quiet_core_detects_revoked_link_with_a_blocked_reader() -> anyhow::Result<()> {
    quiet_link_loss(DirectProfile::Core).await
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM interfaces"]
async fn quiet_gateway_detects_revoked_link() -> anyhow::Result<()> {
    quiet_link_loss(DirectProfile::Endpoint).await
}

#[cfg(feature = "packet-ebpf")]
#[tokio::test]
#[ignore = "requires the guarded auxiliary WireGuard and native XDP disposable-VM fixture"]
async fn kernel_gateway_auxiliary_mixed_rollback() -> anyhow::Result<()> {
    guard();
    let config = honk_config::parser::parse_dae_config(
        "global { dial_mode: ip\n nfqueue_enable: false\n so_mark_from_dae: 0x100 }
         dns { bind: '' }
         datapath { backend: xdp\n direct: endpoint\n xsk_mode: copy\n dns_projection: false\n interface { dut0: lan\n wg0: l3_lan } }
         routing { fallback: direct }",
    )?;
    let fixture = Fixture::start_config(config).await?;
    let publisher = fixture.runtime.gateway.as_ref().context("gateway")?;
    let physical = fixture
        .runtime
        .devices
        .first()
        .context("physical interface")?
        .info
        .ifindex;
    let outer: u32 = std::fs::read_to_string("/sys/class/net/wg0/ifindex")?
        .trim()
        .parse()?;
    let old_tcx = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(id) = publisher.auxiliary_program(outer)? {
                return Ok::<_, io::Error>(id);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let attached = || -> anyhow::Result<(u32, u32)> {
        Ok((
            honk_xsk::xdp_state(physical)?.prog_id,
            publisher
                .auxiliary_program(outer)?
                .context("attached TCX program")?,
        ))
    };
    let old = attached()?;
    assert_ne!(old.0, 0);
    assert_eq!(old.1, old_tcx);
    publisher.check_unhealthy_auxiliary_retry()?;
    let old_fingerprint = publisher.fingerprint();
    let mut next = fixture.config.clone();
    next.routing.rules = honk_config::parser::parse_dae_config(
        "routing { dport(18098) -> packet-proof\n fallback: direct }",
    )?
    .routing
    .rules;
    let plan = ControlPlane::compile_routing_plan(
        &next,
        &crate::routing::Router::from_config(&next.routing)?,
    )?;
    assert_ne!(plan.fingerprint, old_fingerprint);
    publisher.publish(&plan)?;
    let staged = attached()?;
    assert_ne!(staged.0, old.0);
    assert_ne!(staged.1, old.1);
    let shared_maps = |id: u32| -> anyhow::Result<std::collections::BTreeMap<String, u32>> {
        let program = aya::programs::loaded_programs()
            .filter_map(Result::ok)
            .find(|p| p.id() == id)
            .context("installed program ID")?;
        let mut maps = std::collections::BTreeMap::new();
        for map_id in program.map_ids()?.context("installed program map IDs")? {
            let info = aya::maps::MapInfo::from_id(map_id)?;
            if let Some(name @ ("honk_gw_hold" | "honk_gw_frag" | "honk_gw_mode")) =
                info.name_as_str()
            {
                maps.insert(name.to_owned(), map_id);
            }
        }
        Ok(maps)
    };
    let maps = shared_maps(staged.0)?;
    assert_eq!(maps.len(), 3);
    assert_eq!(shared_maps(staged.1)?, maps);
    assert_eq!(publisher.fingerprint(), plan.fingerprint);
    publisher.rollback()?;
    assert_eq!(attached()?, old);
    assert_eq!(publisher.fingerprint(), old_fingerprint);

    // Commit a real configuration, then change the program ID on the owned TCX FD during the final readback.
    let before = fixture.diagnostics.read().generation;
    publisher
        .replace_tcx_before_final
        .store(true, Ordering::Release);
    let (result, reply) = tokio::sync::oneshot::channel();
    fixture
        .commands
        .send(crate::control::ControlCommand::ReloadConfig {
            request_id: 9,
            config: Box::new(next),
            diagnostics: Vec::new(),
            #[cfg(feature = "native-api")]
            sources: None,
            #[cfg(feature = "native-api")]
            expected_group_revision: None,
            result,
        })
        .await?;
    let reply = tokio::time::timeout(Duration::from_secs(30), reply).await??;
    assert_eq!(
        reply.outcome,
        crate::control::ReloadOutcome::CommittedDegraded {
            generation: before + 1
        }
    );
    assert_eq!(fixture.diagnostics.read().generation, before + 1);
    assert_eq!(
        publisher
            .capture_error()
            .context("missing final TCX readback failure")?
            .to_string(),
        "auxiliary TCX link identity changed"
    );
    assert!(!fixture.runtime.admission.load(Ordering::Acquire));
    fixture.finish().await
}

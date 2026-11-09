//! One-shot X0 Endpoint consumer. The supervisor must stop the upstream before releasing
//! its duplicate native-link fd. Socket close is not a UMEM/DMA release acknowledgement.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("xsk_endpoint requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    tokio::task::LocalSet::new().run_until(linux::main()).await;
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context as _, bail, ensure};
    use honk_core::{
        control::{
            ControlPlane,
            netstack::{OutputLease, PacketScope, RuntimeLimits},
            packet_endpoint::PacketEndpoints,
        },
        dns,
        ebpf::mock::MockEbpfBackend,
        routing::Router,
    };
    use honk_datapath::buffer::{DrainState, TxClass};
    use honk_netstack::{ExcludeSet, MemoryBudget, MemoryReservation, Mode};
    use honk_xsk::{
        Attachment, BindMode, Capture, CaptureCounters, FRAME_SIZE, Port, PortConfig, Programs,
        Protocol, Reject, SocketStats,
    };
    use serde::Deserialize;
    use serde_json::{Value, json};
    use std::{
        fs,
        future::poll_fn,
        io::{self, Read, Write},
        net::{Ipv4Addr, SocketAddrV4},
        os::{
            fd::{AsFd, AsRawFd},
            unix::fs::MetadataExt,
        },
        sync::Arc,
        task::{Context, Poll},
        time::{Duration, Instant},
    };
    use tokio::{
        io::{AsyncBufReadExt, BufReader, unix::AsyncFd},
        sync::{mpsc, oneshot},
        task::JoinHandle,
    };

    const BATCH: usize = 64;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RunConfig {
        schema_version: u32,
        attachment_id: u64,
        config_generation: u64,
        ifname: String,
        ifindex: u32,
        mac: String,
        peer_mac: String,
        protocol: String,
        client: SocketAddrV4,
        service: SocketAddrV4,
        bind_mode: String,
        root_netns_inode: u64,
        discovery_min: u32,
        discovery_deadline_ms: u64,
        drain_deadline_ms: u64,
        budget_bytes: usize,
        rx_frames: usize,
        control_frames: usize,
        bulk_frames: usize,
        ring_size: u32,
    }

    impl RunConfig {
        fn capture(&self) -> anyhow::Result<Capture> {
            ensure!(
                self.schema_version == 1 && self.config_generation == 1,
                "unsupported schema/generation"
            );
            ensure!(
                self.attachment_id != 0 && self.root_netns_inode != 0,
                "zero attachment/namespace identity"
            );
            // Copy mode exists only for disposable-VM veth smoke; PF0 is always forced zero-copy.
            ensure!(
                self.ifindex != 0
                    && matches!(
                        (self.ifname.as_str(), self.bind_mode()?),
                        ("enp2s0f0np0", BindMode::ZeroCopy) | ("dut0", BindMode::Copy)
                    ),
                "requires PF0 zero-copy or the dut0 copy-mode VM fixture"
            );
            ensure!(
                *self.client.ip() == Ipv4Addr::new(10, 10, 10, 251),
                "wrong client address"
            );
            ensure!(
                *self.service.ip() == Ipv4Addr::new(10, 10, 10, 252),
                "wrong service address"
            );
            ensure!(
                self.client.port() != 0 && self.service.port() != 0 && self.service.port() != 53,
                "unsupported port"
            );
            let protocol = match self.protocol.as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                _ => bail!("unsupported protocol"),
            };
            ensure!(
                self.discovery_min == if protocol == Protocol::Udp { 3 } else { 1 },
                "wrong discovery threshold"
            );
            ensure!(
                self.discovery_deadline_ms != 0 && self.drain_deadline_ms != 0,
                "zero deadline"
            );
            deadline(self.discovery_deadline_ms)?;
            deadline(self.drain_deadline_ms)?;
            self.port_config().validate()?;
            self.bind_mode()?;
            let own_mac = parse_mac(&self.mac)?;
            ensure!(
                own_mac == [0x58, 0x47, 0xca, 0x74, 0xec, 0x9d],
                "wrong DUT MAC"
            );
            let peer_mac = parse_mac(&self.peer_mac)?;
            ensure!(
                peer_mac[0] & 1 == 0 && peer_mac != [0; 6] && peer_mac != own_mac,
                "invalid peer MAC"
            );
            Ok(Capture {
                protocol,
                client: self.client,
                service: self.service,
                own_mac,
                peer_mac,
            })
        }

        fn port_config(&self) -> PortConfig {
            PortConfig {
                rx_frames: self.rx_frames,
                control_frames: self.control_frames,
                bulk_frames: self.bulk_frames,
                ring_size: self.ring_size,
            }
        }

        fn bind_mode(&self) -> anyhow::Result<BindMode> {
            match self.bind_mode.as_str() {
                "zerocopy" => Ok(BindMode::ZeroCopy),
                "copy" => Ok(BindMode::Copy),
                _ => bail!("unsupported bind mode (no fallback)"),
            }
        }
    }

    fn parse_mac(text: &str) -> anyhow::Result<[u8; 6]> {
        let mut mac = [0; 6];
        let mut parts = text.split(':');
        for byte in &mut mac {
            let part = parts.next().context("short MAC")?;
            ensure!(part.len() == 2, "invalid MAC component");
            *byte = u8::from_str_radix(part, 16)?;
        }
        ensure!(parts.next().is_none(), "long MAC");
        Ok(mac)
    }

    fn deadline(milliseconds: u64) -> anyhow::Result<Instant> {
        Instant::now()
            .checked_add(Duration::from_millis(milliseconds))
            .context("deadline overflow")
    }

    fn emit(event: Value) -> io::Result<()> {
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, &event)?;
        output.write_all(b"\n")?;
        output.flush()
    }

    struct Commands(BufReader<tokio::io::Stdin>);

    impl Commands {
        async fn next(&mut self) -> anyhow::Result<Option<String>> {
            let mut line = [0; 256];
            let mut length = 0;
            loop {
                let buffer = self.0.fill_buf().await?;
                if buffer.is_empty() {
                    ensure!(length == 0, "EOF inside command");
                    return Ok(None);
                }
                let count = buffer
                    .iter()
                    .position(|&byte| byte == b'\n')
                    .map_or(buffer.len(), |at| at + 1);
                ensure!(count <= line.len() - length, "command exceeds 256 bytes");
                line[length..length + count].copy_from_slice(&buffer[..count]);
                length += count;
                self.0.consume(count);
                if line[length - 1] == b'\n' {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Command {
                        command: String,
                    }
                    let command: Command = serde_json::from_slice(&line[..length])?;
                    return Ok(Some(command.command));
                }
            }
        }
    }

    enum DeviceCommand {
        Snapshot(&'static str, oneshot::Sender<io::Result<()>>),
        Stop(Instant),
    }

    struct Device {
        io: AsyncFd<Port<OutputLease>>,
        capture: Capture,
        scope: PacketScope,
        endpoints: Option<PacketEndpoints>,
        rejects: Box<[u64]>,
        udp_ingress_drops: u64,
        tx_control: u64,
        tx_bulk: u64,
        stats_sequence: u64,
        last_stats: SocketStats,
        started: Instant,
        stopping: Option<Instant>,
        retry_wakeup: bool,
        _memory: MemoryReservation,
    }

    struct DeviceTask {
        commands: mpsc::Sender<DeviceCommand>,
        join: JoinHandle<(Device, io::Result<()>)>,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("{work}; TX wakeup also failed: {kick}")]
    struct TransmitFailure {
        #[source]
        work: io::Error,
        kick: io::Error,
    }

    fn finish_transmit(work: io::Result<usize>, kick: io::Result<()>) -> io::Result<usize> {
        match (work, kick) {
            (Ok(progress), Ok(())) => Ok(progress),
            (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
            (Err(work), Err(kick)) => Err(io::Error::other(TransmitFailure { work, kick })),
        }
    }

    impl Device {
        fn new(
            port: Port<OutputLease>,
            capture: Capture,
            scope: PacketScope,
            budget: &Arc<MemoryBudget>,
            started: Instant,
        ) -> anyhow::Result<Self> {
            let bytes = size_of::<Self>()
                + Reject::ALL.len() * size_of::<u64>()
                + 4 * size_of::<DeviceCommand>();
            let memory = budget.reserve(bytes).context("device bookkeeping budget")?;
            // SAFETY: Port retains this OwnedFd unchanged; close_socket is called only
            // after into_inner deregisters it. No mutable access replaces the Port.
            let io =
                unsafe { AsyncFd::register_with_interest(port, tokio::io::Interest::READABLE) }
                    .map_err(io::Error::from)?;
            Ok(Self {
                io,
                capture,
                scope,
                endpoints: None,
                rejects: vec![0; Reject::ALL.len()].into_boxed_slice(),
                udp_ingress_drops: 0,
                tx_control: 0,
                tx_bulk: 0,
                stats_sequence: 0,
                last_stats: SocketStats::default(),
                started,
                stopping: None,
                retry_wakeup: false,
                _memory: memory,
            })
        }

        fn turn(&mut self, cx: &mut Context<'_>) -> io::Result<usize> {
            let Self {
                io,
                capture,
                scope,
                endpoints,
                rejects,
                udp_ingress_drops,
                tx_control,
                tx_bulk,
                stopping,
                retry_wakeup,
                ..
            } = self;
            let port = io.get_mut();
            let wakeup_errors = port.counters().wakeup_errors;
            let (work, kick) = port.transmit_batch(|port| {
                let mut progress = port.complete(OutputLease::release_batch)?;
                port.observe_fill()?;
                if stopping.is_none() {
                    let now = Instant::now();
                    let mut failure = None;
                    progress += port.receive(BATCH, |frame| match capture.rx_ip(frame) {
                        Ok(ip) => {
                            if let Err(error) = endpoints
                                .as_ref()
                                .expect("core ready before device start")
                                .receive(scope.scope(), ip, now)
                            {
                                if capture.protocol == Protocol::Udp
                                    && matches!(
                                        error.kind(),
                                        io::ErrorKind::WouldBlock
                                            | io::ErrorKind::OutOfMemory
                                            | io::ErrorKind::BrokenPipe
                                    )
                                {
                                    *udp_ingress_drops += 1;
                                } else {
                                    failure.get_or_insert(error);
                                }
                            }
                        }
                        Err(reason) => rejects[reason.index()] += 1,
                    })?;
                    if let Some(error) = failure {
                        return Err(error);
                    }
                    port.refill()?;
                    let header = capture.eth_header();
                    let mut outputs: [Option<OutputLease>; BATCH] = std::array::from_fn(|_| None);
                    for class in [TxClass::Control, TxClass::Bulk] {
                        let mut considered = 0;
                        while considered < BATCH {
                            let capacity = port.tx_packet_capacity(class)?.min(BATCH - considered);
                            if capacity == 0 {
                                break;
                            }
                            let Poll::Ready(Some(count)) =
                                scope.poll_outputs_class(cx, class, &mut outputs[..capacity])
                            else {
                                break;
                            };
                            considered += count;
                            for output in &mut outputs[..count] {
                                let output = output.take().expect("selected Endpoint output");
                                if output.scope() != scope.scope() || output.class() != class {
                                    return Err(io::Error::other("foreign output scope/class"));
                                }
                                let submitted = port.counters().submitted;
                                let result = port.transmit_retained(class, &header, output);
                                if port.counters().submitted != submitted {
                                    match class {
                                        TxClass::Control => *tx_control += 1,
                                        TxClass::Bulk => *tx_bulk += 1,
                                    }
                                }
                                result?;
                                progress += 1;
                            }
                        }
                    }
                }
                Ok(progress)
            });
            *retry_wakeup = port.counters().wakeup_errors != wakeup_errors;
            finish_transmit(work, kick)
        }

        fn poll_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let was_retrying = self.retry_wakeup;
            if self.stopping.is_none() {
                // A cached Ready installs no reader waker: clear until Pending stores this task's.
                while let Poll::Ready(ready) = self.io.poll_read_ready(cx) {
                    ready?.clear_ready();
                }
            }
            match self.turn(cx) {
                Err(error) => Poll::Ready(Err(error)),
                Ok(progress) if progress != 0 || (self.retry_wakeup && !was_retrying) => {
                    Poll::Ready(Ok(()))
                }
                _ => Poll::Pending,
            }
        }

        async fn run(
            mut self,
            mut commands: mpsc::Receiver<DeviceCommand>,
            ready: oneshot::Sender<Result<(), String>>,
        ) -> (Self, io::Result<()>) {
            let initial = poll_fn(|cx| Poll::Ready(self.turn(cx))).await;
            let result = match initial {
                Err(error) => {
                    let _ = ready.send(Err(error.to_string()));
                    Err(error)
                }
                Ok(_) => {
                    let _ = ready.send(Ok(()));
                    self.service(&mut commands).await
                }
            };
            (self, result)
        }

        async fn service(
            &mut self,
            commands: &mut mpsc::Receiver<DeviceCommand>,
        ) -> io::Result<()> {
            loop {
                if let Some(until) = self.stopping {
                    if self.io.get_ref().outstanding().next().is_none() {
                        return Ok(());
                    }
                    if Instant::now() >= until {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "TX completion drain expired",
                        ));
                    }
                }
                let repoll = self.retry_wakeup
                    || self.stopping.is_some()
                    || self.io.get_ref().outstanding().next().is_some();
                tokio::select! {
                    command = commands.recv() => match command {
                        Some(DeviceCommand::Snapshot(stage, reply)) => {
                            let result = self.snapshot(stage);
                            let failure = result.as_ref().err().map(ToString::to_string);
                            let _ = reply.send(result);
                            if let Some(error) = failure { return Err(io::Error::other(error)); }
                        }
                        Some(DeviceCommand::Stop(until)) => self.stopping = Some(until),
                        None => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "device command owner closed")),
                    },
                    result = poll_fn(|cx| self.poll_io(cx)) => result?,
                    _ = tokio::time::sleep(Duration::from_millis(1)), if repoll => {},
                }
                tokio::task::yield_now().await;
            }
        }

        fn snapshot(&mut self, stage: &'static str) -> io::Result<()> {
            let port = self.io.get_ref();
            let stats = port.stats()?;
            let values = stats_values(stats);
            let monotonic = values
                .iter()
                .zip(stats_values(self.last_stats))
                .all(|(&new, old)| new >= old);
            let rings = port.rings();
            let counters = port.counters();
            self.stats_sequence += 1;
            emit(json!({
                "event":"socket_stats", "stage":stage, "sequence":self.stats_sequence,
                "monotonic_ns":self.started.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64,
                "monotonic":monotonic, "rx_count":counters.rx, "tx_count":counters.submitted, "cq_count":counters.completed,
                "stats":{
                    "rx_dropped":stats.rx_dropped, "rx_invalid_descs":stats.rx_invalid_descs,
                    "tx_invalid_descs":stats.tx_invalid_descs, "rx_ring_full":stats.rx_ring_full,
                    "rx_fill_ring_empty_descs":stats.rx_fill_ring_empty_descs, "tx_ring_empty_descs":stats.tx_ring_empty_descs,
                },
                "rings":{
                    "rx_producer":rings.rx_producer, "rx_consumer":rings.rx_consumer,
                    "tx_producer":rings.tx_producer, "tx_consumer":rings.tx_consumer,
                    "fill_producer":rings.fill_producer, "fill_consumer":rings.fill_consumer,
                    "cq_producer":rings.cq_producer, "cq_consumer":rings.cq_consumer,
                },
            }))?;
            self.last_stats = stats;
            if !monotonic || stats.rx_invalid_descs != 0 || stats.tx_invalid_descs != 0 {
                return Err(io::Error::other(
                    "invalid/nonmonotonic XDP socket statistics",
                ));
            }
            Ok(())
        }

        fn counters(&self, capture: &CaptureCounters) -> Value {
            let counters = self.io.get_ref().counters();
            let rejects: serde_json::Map<_, _> = Reject::ALL
                .iter()
                .map(|&reason| {
                    (
                        reason.as_str().to_owned(),
                        json!(self.rejects[reason.index()]),
                    )
                })
                .collect();
            json!({
                "rx_frames":counters.rx, "fill_submitted":counters.fill, "invalid_descriptors":counters.invalid,
                "tx_control":self.tx_control, "tx_bulk":self.tx_bulk, "cq_completions":counters.completed,
                "udp_ingress_drops":self.udp_ingress_drops, "rx_kicks":counters.rx_kicks,
                "tx_kicks":counters.tx_kicks, "wakeup_errors":counters.wakeup_errors,
                "rx_rejects":rejects, "capture":capture_json(capture),
            })
        }
    }

    fn stats_values(stats: SocketStats) -> [u64; 6] {
        [
            stats.rx_dropped,
            stats.rx_invalid_descs,
            stats.tx_invalid_descs,
            stats.rx_ring_full,
            stats.rx_fill_ring_empty_descs,
            stats.tx_ring_empty_descs,
        ]
    }

    struct Session {
        config: RunConfig,
        commands: Commands,
        programs: Option<Programs>,
        attachment: Option<Attachment>,
        queue: Option<u32>,
        endpoints: Option<PacketEndpoints>,
        core: Option<JoinHandle<anyhow::Result<()>>>,
        driver: Option<DeviceTask>,
        device: Option<Device>,
        closed_port: Option<Port<OutputLease>>,
        stage: &'static str,
        started: Instant,
        device_started: bool,
    }

    impl Session {
        async fn wait_command(&mut self, expected: &str) -> anyhow::Result<()> {
            let command = if let Some(driver) = self.driver.as_mut() {
                tokio::select! {
                    command = self.commands.next() => command?,
                    result = &mut driver.join => return self.device_ended(result),
                    result = await_core(&mut self.core) => return self.core_ended(result),
                }
            } else {
                self.commands.next().await?
            };
            ensure!(
                command.as_deref() == Some(expected),
                "expected command {expected}, got {command:?}"
            );
            Ok(())
        }

        fn device_ended<T>(
            &mut self,
            result: Result<(Device, io::Result<()>), tokio::task::JoinError>,
        ) -> anyhow::Result<T> {
            self.driver = None;
            let (device, result) = result.context("device owner panicked")?;
            self.device = Some(device);
            result?;
            bail!("device owner exited before stop")
        }

        fn core_ended<T>(
            &mut self,
            result: Result<anyhow::Result<()>, tokio::task::JoinError>,
        ) -> anyhow::Result<T> {
            self.core = None;
            result.context("core owner panicked")??;
            bail!("core owner exited before shutdown")
        }

        async fn supervise<T>(
            &mut self,
            operation: impl Future<Output = anyhow::Result<T>>,
        ) -> anyhow::Result<T> {
            let driver = self.driver.as_mut().context("missing device owner")?;
            tokio::select! {
                result = operation => result,
                result = &mut driver.join => self.device_ended(result),
                result = await_core(&mut self.core) => self.core_ended(result),
            }
        }

        async fn snapshot(&mut self, stage: &'static str) -> anyhow::Result<()> {
            let (reply, result) = oneshot::channel();
            self.driver
                .as_ref()
                .context("missing device")?
                .commands
                .send(DeviceCommand::Snapshot(stage, reply))
                .await
                .context("device command send")?;
            self.supervise(async {
                result.await.context("device snapshot owner")??;
                Ok(())
            })
            .await
        }

        async fn stop_device(&mut self) -> anyhow::Result<()> {
            let Some(driver) = self.driver.take() else {
                return Ok(());
            };
            let _ = driver
                .commands
                .send(DeviceCommand::Stop(deadline(
                    self.config.drain_deadline_ms,
                )?))
                .await;
            let (device, result) = driver.join.await.context("device owner panicked")?;
            self.device = Some(device);
            result?;
            Ok(())
        }

        fn outstanding(&self) -> Value {
            let port = self
                .device
                .as_ref()
                .map(|device| device.io.get_ref())
                .or(self.closed_port.as_ref());
            match port {
                Some(port) => Value::Array(port.outstanding().map(|item| json!({"address":item.address,"class":class_name(item.class),"owner":item.owner})).collect()),
                None if !self.device_started => json!([]),
                None => Value::Null,
            }
        }

        async fn run(&mut self) -> anyhow::Result<()> {
            let capture = self.config.capture()?;
            let mode = self.config.bind_mode()?;
            let budget = MemoryBudget::new(self.config.budget_bytes);
            honk_outbound::util::init_dae_socket_mark(0x100, false)?;
            let (netns_inode, uid, queues) = guards(&self.config)?;
            let mut cfg = honk_config::Config::default();
            cfg.ensure_builtin_nodes();
            cfg.global.dial_mode = "ip".into();
            cfg.global.so_mark_from_dae = 0x100;
            cfg.global.tcp_check_url.clear();
            cfg.global.udp_check_dns = vec!["127.0.0.1:9".into()];
            cfg.global.preconnect_node_count = 0;
            cfg.global.udp_warm_node_count = 0;
            cfg.routing.default_outbound = "direct".into();
            let resolver = dns::DnsResolver::new(&cfg.dns)?;
            let forwarder = resolver.forwarder();
            let router = Router::from_config(&cfg.routing)?;
            let plane = ControlPlane::new(
                cfg,
                Box::new(MockEbpfBackend::new()),
                router,
                Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver()?),
                resolver,
                forwarder,
            )?;
            let health = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            plane
                .alive_set()
                .set_direct_check_addr(health.local_addr()?.to_string());
            // This frozen direct-only fixture has no probe/warm workload beside the real relay.
            for id in plane.alive_set().registered_nodes().keys() {
                plane.alive_set().remove_node(*id);
            }
            let mut stack = honk_netstack::Config::new(rand::random());
            stack.mode = Mode::Transparent {
                exclude: ExcludeSet::default(),
            };
            stack.mtu = 1500;
            stack.max_flows = 8;
            // Stack reserves allocation peaks as well as live bytes; leave room for device/core owners.
            stack.memory_limit = self.config.budget_bytes / 4;
            let pair = PacketScope::new(
                stack,
                Arc::clone(&budget),
                RuntimeLimits {
                    max_slots: 8,
                    control_frames: self.config.control_frames,
                    bulk_frames: self.config.bulk_frames,
                    max_waiters: 8,
                },
                Instant::now(),
            )?;
            let scope = pair.0.clone();
            emit(
                json!({"event":"prepared","pid":std::process::id(),"netns_inode":netns_inode,"ifindex":self.config.ifindex,"mac":self.config.mac,"mtu":1500,"xdp_absent":true,"uid":uid}),
            )?;
            self.stage = "attach";
            self.programs = Some(Programs::load(&capture, queues)?);
            self.attachment = Some(Attachment::create(
                self.config.ifindex,
                self.programs.as_ref().unwrap(),
            )?);
            let attachment = self.attachment.as_ref().unwrap();
            let programs = self.programs.as_ref().unwrap();
            let state = honk_xsk::xdp_state(self.config.ifindex)?;
            emit(
                json!({"event":"attached","link_fd":attachment.as_raw_fd(),"link_id":attachment.id(),"discover_prog_id":programs.discover_prog_id(),"data_prog_id":programs.data_prog_id(),"xdp_mode":"drv","prog_id":state.prog_id}),
            )?;
            self.wait_command("continue").await?;
            self.stage = "discovery";
            emit(json!({"event":"discover_ready"}))?;
            let until = deadline(self.config.discovery_deadline_ms)?;
            let (queue, observed) = loop {
                let observed = self.programs.as_ref().unwrap().counters()?;
                if let Some(queue) = discovery_queue(&observed, self.config.discovery_min)? {
                    break (queue, observed);
                }
                ensure!(Instant::now() < until, "queue discovery deadline expired");
                tokio::select! {
                    command = self.commands.next() => bail!("discovery cancelled by stdin: {:?}", command?),
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {},
                }
            };
            self.queue = Some(queue);
            emit(
                json!({"event":"discovered","queue":queue,"per_queue_nonzero":nonzero_queues(&observed),"fragments":observed.fragments,"options":observed.options,"malformed":observed.malformed}),
            )?;
            self.stage = "socket_setup";
            let port = Port::open(
                self.config.ifindex,
                queue,
                mode,
                self.config.port_config(),
                &budget,
            )?;
            self.device_started = true;
            let zerocopy = port.zerocopy();
            self.device = Some(Device::new(
                port,
                capture,
                scope.clone(),
                &budget,
                self.started,
            )?);
            let device = self.device.as_mut().unwrap();
            device.snapshot("post_bind_before_fill")?;
            device.io.get_mut().refill()?;
            device.snapshot("after_fill")?;
            self.programs
                .as_ref()
                .unwrap()
                .insert_xsk(queue, device.io.get_ref().as_fd())?;
            let (endpoints, owner) = PacketEndpoints::new(plane, vec![pair], 8).await?;
            self.endpoints = Some(endpoints.clone());
            self.core = Some(tokio::spawn(owner.run()));
            self.device.as_mut().unwrap().endpoints = Some(endpoints);
            let (commands, receiver) = mpsc::channel(2);
            let (ready, started) = oneshot::channel();
            let device = self.device.take().unwrap();
            self.driver = Some(DeviceTask {
                commands,
                join: tokio::task::spawn_local(device.run(receiver, ready)),
            });
            self.supervise(async {
                started
                    .await
                    .context("device readiness owner")?
                    .map_err(anyhow::Error::msg)
            })
            .await?;
            self.stage = "publication";
            self.attachment
                .as_ref()
                .unwrap()
                .replace(self.programs.as_ref().unwrap())?;
            let programs = self.programs.as_ref().unwrap();
            let attachment = self.attachment.as_ref().unwrap();
            emit(json!({
                "event":"data_ready","attachment_id":self.config.attachment_id,"scope":scope.scope().as_u64(),"config_generation":self.config.config_generation,
                "protocol":self.config.protocol,"client":self.config.client,"service":self.config.service,"queue":queue,
                "link_id":attachment.id(),"data_prog_id":programs.data_prog_id(),"bind_mode":mode.as_str(),"zerocopy":zerocopy,
                "umem_bytes":self.config.port_config().umem_bytes()?,"frame_size":FRAME_SIZE,
                "ring_sizes":{"rx":self.config.ring_size,"tx":self.config.ring_size,"fill":self.config.ring_size,"cq":self.config.ring_size},
                "partitions":{"rx_frames":self.config.rx_frames,"control_frames":self.config.control_frames,"bulk_frames":self.config.bulk_frames,"control_descriptors":self.config.control_frames,"bulk_descriptors":self.config.bulk_frames},
            }))?;
            self.snapshot("data_begin").await?;
            self.stage = "data";
            self.wait_command("close").await?;
            self.stage = "quiescence";
            self.snapshot("data_end").await?;
            scope.close_admission();
            let until = deadline(self.config.drain_deadline_ms)?;
            let graceful = self
                .supervise(async {
                    while !scope.is_protocol_quiescent() && Instant::now() < until {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    Ok(scope.is_protocol_quiescent())
                })
                .await?;
            emit(json!({"event":"quiescent","graceful":graceful}))?;
            self.stage = "core_shutdown";
            let endpoints = self.endpoints.as_ref().unwrap().clone();
            let core = self.core.take().unwrap();
            let join_deadline = Duration::from_millis(self.config.drain_deadline_ms);
            let closed = self
                .supervise(async {
                    tokio::time::timeout(join_deadline, async {
                        let (closed, joined) = tokio::join!(endpoints.shutdown(), core);
                        closed?;
                        joined.context("core owner panicked")??;
                        Ok(())
                    })
                    .await
                    .context("core close deadline expired while retaining exported outputs")?
                })
                .await;
            emit(json!({"event":"core_closed","ok":closed.is_ok(),"explicit_abort":!graceful}))?;
            closed?;
            self.stage = "tx_drain";
            self.programs.as_ref().unwrap().delete_xsk(queue)?;
            self.stop_device().await?;
            let device = self.device.as_mut().unwrap();
            let drain = device.io.get_mut().close();
            ensure!(
                drain.ready_for_backend_teardown(),
                "device ownership did not drain"
            );
            let observed = self.programs.as_ref().unwrap().counters()?;
            ensure!(
                observed.fragments == 0
                    && observed.options == 0
                    && observed.malformed == 0
                    && observed
                        .per_queue
                        .iter()
                        .enumerate()
                        .all(|(index, &hits)| index == queue as usize || hits == 0),
                "capture domain changed: {}",
                capture_json(&observed)
            );
            device.snapshot("final")?;
            let counters = device.io.get_ref().counters();
            ensure!(
                counters.submitted == counters.completed,
                "incomplete TX ledger"
            );
            let closed_counters = device.counters(&observed);
            let device = self.device.take().unwrap();
            let mut port = device.io.into_inner();
            port.close_socket();
            self.closed_port = Some(port);
            emit(
                json!({"event":"closed","drain_state":drain_json(drain),"submitted":counters.submitted,"completed":counters.completed,"umem_release":"retained_until_process_exit","counters":closed_counters}),
            )?;
            drop(health);
            self.stage = "exit";
            Ok(())
        }

        async fn fail(&mut self, error: anyhow::Error) {
            let mut errors = format!("{error:#}");
            if let (Some(programs), Some(queue)) = (&self.programs, self.queue)
                && let Err(error) = programs.delete_xsk(queue)
            {
                errors.push_str(&format!("; XSK deletion: {error}"));
            }
            if let Some(endpoints) = &self.endpoints {
                endpoints.close();
            }
            if let Err(error) = self.stop_device().await {
                errors.push_str(&format!("; device: {error:#}"));
            }
            if let Some(device) = &mut self.device {
                device.io.get_mut().close();
                let _ = device.snapshot("aborted");
            }
            eprintln!("{}: {errors}", self.stage);
            let _ = emit(
                json!({"event":"failed","stage":self.stage,"error":errors,"outstanding":self.outstanding()}),
            );
        }
    }

    async fn await_core(
        core: &mut Option<JoinHandle<anyhow::Result<()>>>,
    ) -> Result<anyhow::Result<()>, tokio::task::JoinError> {
        match core.as_mut() {
            Some(core) => core.await,
            None => std::future::pending().await,
        }
    }

    fn class_name(class: TxClass) -> &'static str {
        match class {
            TxClass::Control => "control",
            TxClass::Bulk => "bulk",
        }
    }

    fn capture_json(counters: &CaptureCounters) -> Value {
        json!({"per_queue":counters.per_queue,"fragments":counters.fragments,"options":counters.options,"malformed":counters.malformed})
    }

    fn nonzero_queues(counters: &CaptureCounters) -> Vec<(u32, u64)> {
        counters
            .per_queue
            .iter()
            .enumerate()
            .filter(|(_, hits)| **hits != 0)
            .map(|(queue, &hits)| (queue as u32, hits))
            .collect()
    }

    fn discovery_queue(counters: &CaptureCounters, minimum: u32) -> anyhow::Result<Option<u32>> {
        ensure!(
            counters.fragments == 0 && counters.options == 0 && counters.malformed == 0,
            "unsupported discovery domain: {}",
            capture_json(counters)
        );
        let mut observed = counters
            .per_queue
            .iter()
            .enumerate()
            .filter(|(_, hits)| **hits != 0);
        let first = observed.next();
        ensure!(
            observed.next().is_none(),
            "multiple discovery queues: {}",
            capture_json(counters)
        );
        Ok(first
            .filter(|(_, hits)| **hits >= u64::from(minimum))
            .map(|(queue, _)| queue as u32))
    }

    fn drain_json(state: DrainState) -> Value {
        json!({
            "closed":state.closed,"rx_free":state.rx_free,"fill_reserved":state.fill_reserved,"fill_posted":state.fill_posted,"fill_queued":state.fill_queued,"rx_leased":state.rx_leased,
            "control_free":state.control_free,"control_reserved":state.control_reserved,"control_outstanding":state.control_outstanding,
            "bulk_free":state.bulk_free,"bulk_reserved":state.bulk_reserved,"bulk_outstanding":state.bulk_outstanding,"exhausted_frames":state.exhausted_frames,"ready_for_backend_teardown":state.ready_for_backend_teardown(),
        })
    }

    fn guards(config: &RunConfig) -> anyhow::Result<(u64, u32, u32)> {
        let netns = fs::metadata("/proc/self/ns/net")?.ino();
        ensure!(
            netns != config.root_netns_inode,
            "refusing root network namespace"
        );
        let status = fs::read_to_string("/proc/self/status")?;
        let uid: u32 = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .context("missing uid")?
            .split_whitespace()
            .nth(1)
            .context("missing effective uid")?
            .parse()?;
        ensure!(uid == 0, "requires uid 0");
        let sysfs = std::path::Path::new("/sys/class/net").join(&config.ifname);
        if config.bind_mode()? == BindMode::Copy {
            ensure!(
                fs::read_to_string("/proc/cmdline")?
                    .split_whitespace()
                    .any(|arg| arg.starts_with("virtme."))
                    && fs::canonicalize(&sysfs)?.starts_with("/sys/devices/virtual/net"),
                "copy mode requires a virtual interface in the virtme guest"
            );
        }
        let ifindex: u32 = fs::read_to_string(sysfs.join("ifindex"))?.trim().parse()?;
        let mtu: u32 = fs::read_to_string(sysfs.join("mtu"))?.trim().parse()?;
        let mac = fs::read_to_string(sysfs.join("address"))?;
        ensure!(
            ifindex == config.ifindex
                && mtu == 1500
                && parse_mac(mac.trim())? == parse_mac(&config.mac)?,
            "interface identity/MTU mismatch"
        );
        ensure!(
            honk_xsk::xdp_absent(ifindex)?,
            "pre-existing XDP attachment"
        );
        let mut rx_queues = [false; 256];
        let mut count = 0;
        for entry in fs::read_dir(sysfs.join("queues"))? {
            let name = entry?.file_name();
            let name = name.to_str().context("non-UTF8 queue name")?;
            if let Some(number) = name.strip_prefix("rx-") {
                let number: usize = number.parse()?;
                ensure!(
                    number < rx_queues.len() && !rx_queues[number],
                    "unsupported RX queue index"
                );
                rx_queues[number] = true;
                count += 1;
            }
        }
        ensure!(
            count != 0 && rx_queues[..count].iter().all(|&present| present),
            "missing/sparse RX queues"
        );
        Ok((netns, uid, count as u32))
    }

    pub async fn main() {
        let loaded = (|| -> anyhow::Result<RunConfig> {
            let mut args = std::env::args_os().skip(1);
            let path = args
                .next()
                .context("usage: xsk_endpoint <run-config.json>")?;
            ensure!(
                args.next().is_none(),
                "usage: xsk_endpoint <run-config.json>"
            );
            let mut bytes = Vec::new();
            fs::File::open(path)?
                .take(16 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 16 * 1024, "run config exceeds 16 KiB");
            Ok(serde_json::from_slice(&bytes)?)
        })();
        let config = match loaded {
            Ok(config) => config,
            Err(error) => {
                eprintln!("prepare: {error:#}");
                let _ = emit(
                    json!({"event":"failed","stage":"prepare","error":format!("{error:#}"),"outstanding":[]}),
                );
                std::process::exit(1);
            }
        };
        let mut session = Session {
            config,
            commands: Commands(BufReader::new(tokio::io::stdin())),
            programs: None,
            attachment: None,
            queue: None,
            endpoints: None,
            core: None,
            driver: None,
            device: None,
            closed_port: None,
            stage: "prepare",
            started: Instant::now(),
            device_started: false,
        };
        let failed = match session.run().await {
            Ok(()) => false,
            Err(error) => {
                session.fail(error).await;
                true
            }
        };
        if !failed {
            match session.wait_command("exit").await {
                Ok(()) => std::process::exit(0),
                Err(error) => session.fail(error).await,
            }
        }
        loop {
            match session.commands.next().await {
                Ok(Some(command)) if command == "exit" => break,
                Ok(None) => break,
                Ok(Some(command)) => {
                    eprintln!("ignoring terminal command {command:?}; expected exit");
                }
                Err(error) => {
                    eprintln!("terminal stdin: {error:#}");
                    break;
                }
            }
        }
        // No in-process teardown claims a deferred UMEM release fence.
        std::process::exit(1);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn copy_fixture_cannot_select_another_physical_interface() {
            let mut config: RunConfig = serde_json::from_value(json!({
                "schema_version":1, "attachment_id":1, "config_generation":1,
                "ifname":"enp2s0f1np1", "ifindex":2,
                "mac":"58:47:ca:74:ec:9d", "peer_mac":"02:00:00:00:00:01",
                "protocol":"udp", "client":"10.10.10.251:54632",
                "service":"10.10.10.252:54631", "bind_mode":"copy",
                "root_netns_inode":1, "discovery_min":3,
                "discovery_deadline_ms":1000, "drain_deadline_ms":1000,
                "budget_bytes":67108864, "rx_frames":128,
                "control_frames":8, "bulk_frames":24, "ring_size":128
            }))
            .unwrap();
            assert!(config.capture().is_err());
            config.ifname = "dut0".into();
            assert!(config.capture().is_ok());
            config.bind_mode = "zerocopy".into();
            assert!(config.capture().is_err());
            config.ifname = "enp2s0f0np0".into();
            assert!(config.capture().is_ok());
            config.bind_mode = "copy".into();
            assert!(config.capture().is_err());
        }

        #[test]
        fn discovery_requires_one_clean_queue_at_threshold() {
            let mut counters = CaptureCounters {
                per_queue: vec![0, 2, 0],
                fragments: 0,
                options: 0,
                malformed: 0,
            };
            assert_eq!(discovery_queue(&counters, 3).unwrap(), None);
            counters.per_queue[1] = 3;
            assert_eq!(discovery_queue(&counters, 3).unwrap(), Some(1));
            counters.per_queue[2] = 1;
            assert!(discovery_queue(&counters, 3).is_err());
            counters.per_queue[2] = 0;
            counters.fragments = 1;
            assert!(discovery_queue(&counters, 3).is_err());
            counters.fragments = 0;
            counters.options = 1;
            assert!(discovery_queue(&counters, 3).is_err());
            counters.options = 0;
            counters.malformed = 1;
            assert!(discovery_queue(&counters, 3).is_err());
        }

        #[test]
        fn fatal_batch_kick_cannot_be_reported_as_would_block() {
            let error = finish_transmit(
                Err(io::Error::new(io::ErrorKind::WouldBlock, "writer pressure")),
                Err(io::Error::from_raw_os_error(libc::EBADF)),
            )
            .unwrap_err();
            assert_ne!(error.kind(), io::ErrorKind::WouldBlock);
            let causes = error
                .get_ref()
                .unwrap()
                .downcast_ref::<TransmitFailure>()
                .unwrap();
            assert_eq!(causes.work.kind(), io::ErrorKind::WouldBlock);
            assert_eq!(causes.kick.raw_os_error(), Some(libc::EBADF));
            assert!(error.to_string().contains("writer pressure"));
            let error =
                finish_transmit(Ok(1), Err(io::Error::from_raw_os_error(libc::EBADF))).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EBADF));
            let error = finish_transmit(Err(io::Error::from_raw_os_error(libc::EAGAIN)), Ok(()))
                .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EAGAIN));
            assert_eq!(finish_transmit(Ok(1), Ok(())).unwrap(), 1);
        }
    }
}

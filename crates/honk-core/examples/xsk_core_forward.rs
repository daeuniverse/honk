//! Isolated-VM routed-only XSK consumer, two single-queue Ethernet interfaces.
//! External supervisor owns namespace/topology and retains duplicate link FDs until sources stop.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("xsk_core_forward requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = linux::run().await {
        eprintln!("CoreForward failed closed: {error:#}");
        // Attachment guards retain kernel links on failure. The supervisor first stops
        // both external peers, then sends exit (or destroys the disposable namespace).
        let mut commands = linux::commands();
        while let Ok(Some(command)) = commands.next_line().await {
            if command == "exit" {
                break;
            }
        }
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, ensure};
    use honk_core::{
        control::{
            ControlPlane,
            core_forward::{Decision, Execution, Requirements, RoutedCore, socket_namespace},
        },
        dns,
        ebpf::mock::MockEbpfBackend,
        routing::Router,
    };
    use honk_datapath::{
        ScopeId,
        buffer::TxClass,
        forward::{ForwardLease, ForwardPacket, Ingress, MarkProvenance, Packet, Prepared, Route},
    };
    use honk_netstack::{MemoryBudget, MemoryReservation};
    use honk_xsk::{Attachment, BindMode, Capture, Port, PortConfig, Programs, Protocol};
    use serde::Deserialize;
    use serde_json::json;
    use std::{
        collections::VecDeque,
        fs,
        io::{self, Read, Write},
        net::SocketAddrV4,
        os::{
            fd::{AsFd, AsRawFd},
            unix::fs::MetadataExt,
        },
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Device {
        ifname: String,
        ifindex: u32,
        mac: [u8; 6],
        peer_mac: [u8; 6],
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        requirements: Requirements,
        policy: String,
        root_netns_inode: u64,
        devices: [Device; 2],
        client: SocketAddrV4,
        service: SocketAddrV4,
        protocol: String,
        budget_bytes: usize,
    }

    struct Link(Option<Attachment>);
    impl Drop for Link {
        fn drop(&mut self) {
            // Failure must not expose this selected tuple to native forwarding. The VM
            // supervisor holds its duplicate before data admission, including process death.
            if let Some(link) = self.0.take() {
                std::mem::forget(link);
            }
        }
    }

    enum Lease {
        Forward {
            _owner: ForwardLease,
        },
        Error {
            _binding: Option<honk_datapath::firewall::BindingLease>,
        },
    }
    struct Pending {
        output: ForwardPacket,
        generation: honk_core::control::core_forward::PolicyGeneration,
    }
    struct Waiting {
        owner: usize,
        packet: Packet,
        retry: Instant,
    }

    pub struct Commands {
        input: BufReader<tokio::io::Stdin>,
        bytes: [u8; 256],
        len: usize,
    }
    pub fn commands() -> Commands {
        Commands {
            input: BufReader::new(tokio::io::stdin()),
            bytes: [0; 256],
            len: 0,
        }
    }
    impl Commands {
        pub async fn next_line(&mut self) -> io::Result<Option<String>> {
            loop {
                let input = self.input.fill_buf().await?;
                if input.is_empty() {
                    return if self.len == 0 {
                        Ok(None)
                    } else {
                        Err(io::Error::other("EOF inside supervisor command"))
                    };
                }
                let count = input
                    .iter()
                    .position(|byte| *byte == b'\n')
                    .map_or(input.len(), |at| at + 1);
                if count > self.bytes.len() - self.len {
                    return Err(io::Error::other("supervisor command exceeds 256 bytes"));
                }
                self.bytes[self.len..self.len + count].copy_from_slice(&input[..count]);
                self.len += count;
                self.input.consume(count);
                if self.bytes[self.len - 1] == b'\n' {
                    let line = std::str::from_utf8(&self.bytes[..self.len - 1])
                        .map_err(io::Error::other)?
                        .to_owned();
                    self.len = 0;
                    return Ok(Some(line));
                }
            }
        }
    }
    fn emit(value: serde_json::Value) -> anyhow::Result<()> {
        let mut output = io::stdout().lock();
        serde_json::to_writer(&mut output, &value)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    }
    fn guard(config: &Config) -> anyhow::Result<()> {
        ensure!(
            config.requirements.execution == Execution::RoutedOnly,
            "this fixture selects routed-only execution"
        );
        ensure!(
            config.root_netns_inode != 0
                && fs::metadata("/proc/self/ns/net")?.ino() != config.root_netns_inode,
            "refusing root network namespace"
        );
        ensure!(
            fs::read_to_string("/proc/cmdline")?
                .split_whitespace()
                .any(|word| word.starts_with("virtme.")),
            "this copy-mode smoke entry requires the disposable virtme VM"
        );
        ensure!(
            config.devices[0].ifindex != config.devices[1].ifindex,
            "interfaces must be distinct"
        );
        for (index, device) in config.devices.iter().enumerate() {
            ensure!(
                device.ifname == format!("dut{index}"),
                "requires explicit dut0/dut1 fixture"
            );
            let path = std::path::Path::new("/sys/class/net").join(&device.ifname);
            ensure!(
                fs::canonicalize(&path)?.starts_with("/sys/devices/virtual/net"),
                "requires virtual interfaces"
            );
            ensure!(
                fs::read_to_string(path.join("ifindex"))?
                    .trim()
                    .parse::<u32>()?
                    == device.ifindex,
                "interface incarnation changed"
            );
            ensure!(
                fs::read_to_string(path.join("mtu"))?
                    .trim()
                    .parse::<u32>()?
                    == 1500,
                "XSK fixture requires MTU 1500"
            );
            let mut queues = Vec::new();
            for entry in fs::read_dir(path.join("queues"))? {
                let name = entry?.file_name();
                if name.to_string_lossy().starts_with("rx-") {
                    queues.push(name);
                }
            }
            ensure!(
                queues.len() == 1 && queues[0] == "rx-0",
                "requires exactly RX queue zero"
            );
            ensure!(
                honk_xsk::xdp_absent(device.ifindex)?,
                "foreign XDP attachment"
            );
            let observed = fs::read_to_string(path.join("address"))?;
            let expected = device.mac.map(|byte| format!("{byte:02x}")).join(":");
            ensure!(observed.trim() == expected, "capture MAC mismatch");
        }
        Ok(())
    }

    pub async fn run() -> anyhow::Result<()> {
        let mut args = std::env::args_os().skip(1);
        let path = args.next().context("usage: xsk_core_forward run.json")?;
        ensure!(args.next().is_none(), "unexpected arguments");
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(16385).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16384, "run config exceeds 16 KiB");
        let config: Config = serde_json::from_slice(&bytes)?;
        guard(&config)?;
        let protocol = match config.protocol.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => anyhow::bail!("requires tcp or udp"),
        };
        let mut policy = honk_config::Config::from_file(&config.policy)?;
        policy.ensure_builtin_nodes();
        let resolver = dns::DnsResolver::new(&policy.dns)?;
        let forwarder = resolver.forwarder();
        let router = Router::from_config(&policy.routing)?;
        let plane = Arc::new(ControlPlane::new(
            policy,
            Box::new(MockEbpfBackend::new()),
            router,
            Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver()?),
            resolver,
            forwarder,
        )?);
        // No ControlPlane run(), socket relay, PacketEndpoints, TUN or TC is started.
        let budget = MemoryBudget::new(config.budget_bytes);
        let _queues: MemoryReservation = budget
            .reserve(64 * (size_of::<Waiting>() + size_of::<Pending>()) + 2 * 1500)
            .context("queue budget exhausted")?;
        let captures = [
            Capture {
                protocol,
                client: config.client,
                service: config.service,
                own_mac: config.devices[0].mac,
                peer_mac: config.devices[0].peer_mac,
            },
            Capture {
                protocol,
                client: config.service,
                service: config.client,
                own_mac: config.devices[1].mac,
                peer_mac: config.devices[1].peer_mac,
            },
        ];
        let mut programs = Vec::with_capacity(2);
        let mut links = Vec::with_capacity(2);
        let mut ports = Vec::<Port<Lease>>::with_capacity(2);
        let mut ingresses = Vec::with_capacity(2);
        let scope = ScopeId::allocate().context("scope exhausted")?;
        let authority = plane.core_forward_policy(Execution::RoutedOnly).await?;
        let mut commands = commands();
        for (index, capture) in captures.iter().enumerate() {
            let program = Programs::load(capture, 1)?;
            let attachment = Attachment::create(config.devices[index].ifindex, &program)?;
            emit(
                json!({"event":"attached","device":index,"pid":std::process::id(),"link_fd":attachment.as_raw_fd(),"link_id":attachment.id()}),
            )?;
            links.push(Link(Some(attachment)));
            programs.push(program);
        }
        ensure!(
            commands.next_line().await?.as_deref() == Some("armed"),
            "supervisor must duplicate both link FDs before armed"
        );
        for index in 0..2 {
            let mut port = Port::open(
                config.devices[index].ifindex,
                0,
                BindMode::Copy,
                PortConfig {
                    rx_frames: 128,
                    control_frames: 32,
                    bulk_frames: 96,
                    ring_size: 128,
                },
                &budget,
            )?;
            let ingress = Ingress {
                scope,
                namespace: socket_namespace(port.as_fd())?,
                ifindex: config.devices[index].ifindex,
                attachment: u64::from(links[index].0.as_ref().unwrap().id()),
                mark: MarkProvenance::BeforeSkb,
            };
            ingresses.push(ingress);
            port.refill()?;
            programs[index].insert_xsk(0, port.as_fd())?;
            ports.push(port);
        }
        let mut core = RoutedCore::new(
            authority,
            &ingresses,
            config.requirements.clone(),
            Arc::clone(&budget),
        )?;
        // Readers are acquired per decision/publication and dropped before the next await.
        let authority = core.authority();
        for index in 0..2 {
            links[index].0.as_ref().unwrap().replace(&programs[index])?;
        }
        emit(
            json!({"event":"ready","execution":"routed-only","devices":2,"native_fallback":false}),
        )?;
        let mut waiting = VecDeque::<Waiting>::with_capacity(64);
        let mut pending = VecDeque::<Pending>::with_capacity(64);
        let macs = config
            .devices
            .each_ref()
            .map(|device| device.peer_mac.map(|byte| format!("{byte:02x}")).join(":"));
        let mut transmitted = 0u64;
        let mut dropped = 0u64;
        let mut errors = 0u64;
        let mut out = [0; 1500];
        loop {
            tokio::select! {
                command = commands.next_line() => {
                    ensure!(command?.as_deref() == Some("close"), "expected close after both peer generators stop");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
            let now = Instant::now();
            for index in 0..2 {
                ports[index].complete(|_| {})?;
                ports[index].kick()?;
                ports[index].receive(32, |frame| {
                    if waiting.len() == 64 {
                        dropped += 1;
                        return;
                    }
                    match captures[index]
                        .rx_ip(frame)
                        .ok()
                        .and_then(|ip| core.receive(ingresses[index], now, ip).ok().flatten())
                    {
                        Some(packet) => waiting.push_back(Waiting {
                            owner: index,
                            packet,
                            retry: now,
                        }),
                        None => dropped += 1,
                    }
                })?;
            }
            for _ in 0..waiting.len() {
                let work = waiting.pop_front().unwrap();
                if Instant::now() >= work.packet.deadline() {
                    dropped += 1;
                    continue;
                }
                if now < work.retry {
                    waiting.push_back(work);
                    continue;
                }
                let decision = core.decide(
                    &authority.read_policy().await,
                    work.packet,
                    Some(&macs[work.owner]),
                    now,
                )?;
                match decision {
                    Decision::Wait(packet) => waiting.push_back(Waiting {
                        packet,
                        retry: now + Duration::from_millis(10),
                        owner: work.owner,
                    }),
                    Decision::Drop | Decision::LocalInput => dropped += 1,
                    Decision::Endpoint(..) => {
                        anyhow::bail!("routed-only consumer received Endpoint disposition")
                    }
                    Decision::Forward(Prepared::Forward(output), generation) => {
                        if pending.len() == 64 {
                            dropped += 1;
                        } else {
                            pending.push_back(Pending { output, generation });
                        }
                    }
                    Decision::Forward(Prepared::Error { packet, error }, generation) => {
                        let route = match core.error_route(&packet) {
                            Ok(route) => route,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                            Err(error) => return Err(error.into()),
                        };
                        if let Some(route) = route
                            && let Some(device) = device_for(&config, route)
                            && ports[device].tx_credit(TxClass::Control)
                            && let Some(length) =
                                core.error(now, &packet, error, route, &mut out)?
                        {
                            let header = route.ethernet_header(packet.ip().src.is_ipv6())?;
                            if core
                                .submit(&authority.read_policy().await, route, generation, || {
                                    if !packet.is_current(Instant::now()) {
                                        return Ok(None);
                                    }
                                    ports[device]
                                        .transmit_segments(
                                            TxClass::Control,
                                            &[&header, &out[..length]],
                                            Lease::Error {
                                                _binding: packet.into_binding(),
                                            },
                                        )
                                        .map(Some)
                                })?
                                .is_some()
                            {
                                errors += 1;
                            }
                        }
                    }
                }
            }
            for _ in 0..pending.len() {
                let mut work = pending.pop_front().unwrap();
                if Instant::now() >= work.output.deadline() {
                    dropped += 1;
                    continue;
                }
                let route = work.output.route();
                let Some(device) = device_for(&config, route) else {
                    dropped += 1;
                    continue;
                };
                if !ports[device].tx_credit(TxClass::Bulk) {
                    pending.push_back(work);
                    continue;
                }
                let Some((length, lease)) = work.output.write_next(&mut out) else {
                    dropped += 1;
                    continue;
                };
                let header = route.ethernet_header(out[0] >> 4 == 6)?;
                if core
                    .submit(
                        &authority.read_policy().await,
                        route,
                        work.generation,
                        || {
                            if !lease
                                .retained_packet()
                                .expect("owned forwarding cursor")
                                .is_current(Instant::now())
                            {
                                return Ok(None);
                            }
                            ports[device]
                                .transmit_segments(
                                    TxClass::Bulk,
                                    &[&header, &out[..length]],
                                    Lease::Forward { _owner: lease },
                                )
                                .map(Some)
                        },
                    )?
                    .is_some()
                {
                    transmitted += 1;
                    if !work.output.is_complete() {
                        pending.push_back(work);
                    }
                } else {
                    dropped += 1;
                }
            }
            core.retire(now);
        }
        for program in &programs {
            program.delete_xsk(0)?;
        }
        waiting.clear();
        pending.clear();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            for port in &mut ports {
                port.complete(|_| {})?;
                port.kick()?;
            }
            if ports
                .iter()
                .all(|port| port.counters().submitted == port.counters().completed)
            {
                break;
            }
            ensure!(Instant::now() < deadline, "TX ownership did not drain");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        for port in &mut ports {
            ensure!(
                port.close().ready_for_backend_teardown(),
                "backend ownership did not drain"
            );
            port.close_socket();
        }
        let counts: Vec<_> = ports.iter().map(|port| {
            let counters = port.counters();
            json!({"rx":counters.rx,"submitted":counters.submitted,"completed":counters.completed})
        }).collect();
        emit(
            json!({"event":"closed","forwarded":transmitted,"icmp":errors,"dropped":dropped,"ports":counts,"umem_release":"retained_until_process_exit"}),
        )?;
        ensure!(
            commands.next_line().await?.as_deref() == Some("exit"),
            "expected exit after supervisor has stopped peers"
        );
        for link in &mut links {
            drop(link.0.take());
        }
        Ok(())
    }

    fn device_for(config: &Config, route: Route) -> Option<usize> {
        config.devices.iter().position(|device| {
            device.ifindex == route.l2.physical_ifindex && device.mac == route.source_mac
        })
    }
}

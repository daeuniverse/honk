//! Combined real-consumer coverage; never run outside the guarded disposable-VM window.

use super::*;
use crate::control::poll_budget::{PollBudgetBinding, PollBudgetSnapshot, ProcessPollBudget};
use crate::control::{ControlCommand, ReloadReply};
use crate::xdp::polling::testing::{ClockFault, Control, Snapshot};
use honk_config::datapath::{
    BusyPollConfig, CalibrationStatus, PollCalibration, PollMode, XskMode,
};
use std::{io::Write as _, os::fd::AsRawFd, sync::atomic::AtomicU64};
use tokio::sync::{mpsc, oneshot, watch};

mod clocks;
mod shared;

const WINDOW: Duration = Duration::from_secs(45);

#[derive(Clone, Copy, Debug, Default)]
struct Attempts {
    started: u64,
    completed: u64,
    canceled: u64,
}

#[derive(Default)]
struct ReaderAttempts {
    started: AtomicU64,
    completed: AtomicU64,
    canceled: AtomicU64,
}

struct ReaderTicket {
    attempts: Arc<ReaderAttempts>,
    id: u64,
    completed: bool,
}

impl Drop for ReaderTicket {
    fn drop(&mut self) {
        if !self.completed {
            self.attempts.canceled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl ReaderAttempts {
    fn snapshot(&self) -> Attempts {
        Attempts {
            started: self.started.load(Ordering::SeqCst),
            completed: self.completed.load(Ordering::SeqCst),
            canceled: self.canceled.load(Ordering::SeqCst),
        }
    }
}

#[derive(Clone, Debug)]
struct State {
    polling: Snapshot,
    attempts: Attempts,
    fair_turns: u64,
    owner_thread: std::thread::ThreadId,
    fair_thread: Option<std::thread::ThreadId>,
    clock_events: polling::testing::ClockEvents,
}

struct Retired {
    plane: Option<ControlPlane>,
    state: State,
    ledger: PollBudgetSnapshot,
    terminal: Terminal,
    failure: Option<anyhow::Error>,
}

/// Exact persistent guards a joined owner leaves installed. `serve` never detaches or
/// unpins; only `Retired::release` may, after real producer quiescence.
struct Terminal {
    namespace: OwnedNamespace,
    source: &'static str,
    guards: Vec<(u32, &'static str, u32)>,
    pins: PathBuf,
    custody: Arc<std::sync::Mutex<Option<NamespaceCustody>>>,
    released: bool,
}

impl Drop for Terminal {
    fn drop(&mut self) {
        if !self.released {
            // Unreleased guards/pins keep their nsfs/mount custody until process exit.
            std::mem::forget(Arc::clone(&self.custody));
            std::mem::forget(Arc::clone(&self.namespace.net));
        }
    }
}

/// Minted only by an observed TCP-peer STOP reply and successful child exit.
struct TcpExited(());

impl Retired {
    /// The controller's sole teardown frontier. Any error leaves every unreleased guard,
    /// pin and namespace custody in place, and the joined marker is never written.
    async fn release(&mut self, pump: &mut Pump, tcp: Option<&TcpExited>) -> anyhow::Result<()> {
        let terminal = &mut self.terminal;
        ensure!(!terminal.released, "terminal bundle released twice");
        ensure!(
            terminal.source == "b" || tcp.is_some(),
            "A guard teardown requires the actual TCP peer exit"
        );
        // A's real STOP reply covers both LAN and WAN streams.
        pump.set(terminal.source, false).await?;
        let namespace = &terminal.namespace;
        let mut names = Vec::new();
        for &(ifindex, mac, guard) in &terminal.guards {
            let directory = terminal.pins.join(format!("xdp-{ifindex}"));
            let (name, _) = owned_link(namespace, ifindex, mac).await?;
            exact_guard(namespace, ifindex, guard, &directory).await?;
            owned_command(
                namespace,
                &["ip", "link", "set", "dev", name.as_str(), "down"],
            )
            .await?;
            let (down, up) = owned_link(namespace, ifindex, mac).await?;
            ensure!(
                down == name && !up,
                "owned capture device {name} did not read back administratively down"
            );
            exact_guard(namespace, ifindex, guard, &directory).await?;
            names.push((name, ifindex, directory));
        }
        // Every device is quiesced and still guarded; only now detach and unpin.
        for (name, ifindex, directory) in names {
            owned_command(
                namespace,
                &["ip", "link", "set", "dev", name.as_str(), "xdp", "off"],
            )
            .await?;
            let state = guard_state(namespace, ifindex).await?;
            ensure!(
                state.attached == 0
                    && state.prog_id == 0
                    && state.drv_prog_id == 0
                    && state.skb_prog_id == 0
                    && state.hw_prog_id == 0,
                "exact owned guard survived detach: {state:?}"
            );
            for file in ["guard", "data"] {
                std::fs::remove_file(directory.join(file))?;
            }
            std::fs::remove_dir(directory)?;
        }
        std::fs::remove_dir(&terminal.pins)?;
        terminal.released = true;
        Ok(())
    }
}

/// Exact owned device identity by retained ifindex: current name and administrative UP.
async fn owned_link(
    namespace: &OwnedNamespace,
    ifindex: u32,
    mac: &str,
) -> anyhow::Result<(String, bool)> {
    let output = owned_command(namespace, &["ip", "-j", "link", "show"]).await?;
    let links: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let link = links
        .as_array()
        .and_then(|links| {
            links
                .iter()
                .find(|link| link["ifindex"].as_u64() == Some(u64::from(ifindex)))
        })
        .context("owned device vanished before exact attachment teardown")?;
    ensure!(
        link["address"] == mac,
        "owned device identity changed before teardown: {link}"
    );
    let name = link["ifname"]
        .as_str()
        .context("owned device has no name")?
        .to_owned();
    let up = link["flags"]
        .as_array()
        .context("owned device has no flags")?
        .iter()
        .any(|flag| flag == "UP");
    Ok((name, up))
}

async fn exact_guard(
    namespace: &OwnedNamespace,
    ifindex: u32,
    guard: u32,
    pins: &Path,
) -> anyhow::Result<()> {
    let state = guard_state(namespace, ifindex).await?;
    ensure!(
        state.attached == 1
            && state.prog_id == guard
            && state.drv_prog_id == guard
            && state.skb_prog_id == 0
            && state.hw_prog_id == 0,
        "exact owned native guard changed before teardown: {state:?}"
    );
    for file in ["guard", "data"] {
        ensure!(
            std::fs::symlink_metadata(pins.join(file))?.is_file(),
            "owned {file} pin changed before teardown"
        );
    }
    Ok(())
}

/// Real netlink readback inside the retained namespace, on a thread owning nothing else.
async fn guard_state(
    namespace: &OwnedNamespace,
    ifindex: u32,
) -> anyhow::Result<honk_xsk::XdpState> {
    ensure!(
        Instant::now() < namespace.deadline,
        "guard readback started after the original fixture deadline"
    );
    let net = Arc::clone(&namespace.net);
    let (send, receive) = oneshot::channel();
    let thread = std::thread::Builder::new()
        .name("e4-guard-readback".into())
        .spawn(move || {
            // SAFETY: this short-lived thread holds no executor, socket or mount state.
            let result = if unsafe { libc::setns(net.as_raw_fd(), libc::CLONE_NEWNET) } == 0 {
                honk_xsk::xdp_state(ifindex)
            } else {
                Err(io::Error::last_os_error())
            };
            let _ = send.send(result);
        })?;
    let state = within(namespace.deadline, "owned guard readback", async {
        let state = receive
            .await
            .context("owned guard readback thread ended")??;
        while !thread.is_finished() {
            tokio::task::yield_now().await;
        }
        Ok(state)
    })
    .await?;
    thread
        .join()
        .map_err(|_| anyhow::anyhow!("owned guard readback thread panicked"))?;
    ensure!(
        Instant::now() < namespace.deadline,
        "guard readback joined after the original fixture deadline"
    );
    Ok(state)
}

/// Every fixture exchange shares the one original absolute deadline.
async fn within<T>(
    deadline: Instant,
    what: &str,
    work: impl Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    ensure!(
        Instant::now() < deadline,
        "{what} started after the original fixture deadline"
    );
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), work)
        .await
        .map_err(|_| anyhow::anyhow!("{what} exceeded the original fixture deadline"))?
}

enum Request {
    State(oneshot::Sender<State>),
    Gap(Duration, oneshot::Sender<()>),
}

struct Ready {
    requests: mpsc::Sender<Request>,
    commands: mpsc::Sender<ControlCommand>,
    router: Arc<tokio::sync::RwLock<crate::routing::Router>>,
    publication: Arc<tokio::sync::RwLock<Arc<Config>>>,
    control: Arc<Control>,
    fairness: watch::Sender<bool>,
}

struct Owner {
    ready: Ready,
    config: Config,
    deadline: Instant,
    finished: oneshot::Receiver<anyhow::Result<Retired>>,
    thread: Option<std::thread::JoinHandle<()>>,
    custody: Arc<std::sync::Mutex<Option<NamespaceCustody>>>,
}

impl Owner {
    async fn start(
        config: Config,
        binding: PollBudgetBinding,
        namespace: OwnedNamespace,
        pins: PathBuf,
        artifacts: PathBuf,
        deadline: Instant,
    ) -> anyhow::Result<Self> {
        let (started, ready) = oneshot::channel();
        let (finished, mut done) = oneshot::channel();
        let owner_config = config.clone();
        let custody = Arc::new(std::sync::Mutex::new(None));
        let thread_custody = Arc::clone(&custody);
        let thread = std::thread::Builder::new()
            .name(format!("e4-{}", namespace.name))
            .spawn(move || {
                let result = (|| -> anyhow::Result<_> {
                    let entered = enter_owned_namespace(&namespace)?;
                    let net_inode = entered.net.metadata()?.ino();
                    let mount_inode = entered.mount.metadata()?.ino();
                    *thread_custody.lock().unwrap() = Some(entered);
                    let worker_starts = Arc::new(AtomicU64::new(0));
                    let worker_stops = Arc::new(AtomicU64::new(0));
                    let starts = Arc::clone(&worker_starts);
                    let stops = Arc::clone(&worker_stops);
                    let executor = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .on_thread_start(move || {
                            assert_eq!(
                                std::fs::metadata("/proc/thread-self/ns/net").unwrap().ino(),
                                net_inode
                            );
                            assert_eq!(
                                std::fs::metadata("/proc/thread-self/ns/mnt").unwrap().ino(),
                                mount_inode
                            );
                            starts.fetch_add(1, Ordering::SeqCst);
                        })
                        .on_thread_stop(move || {
                            stops.fetch_add(1, Ordering::SeqCst);
                        })
                        .build()?;
                    // Both tasks share this LocalSet and OS thread, not another worker.
                    let retired = executor.block_on(tokio::task::LocalSet::new().run_until(serve(
                        owner_config,
                        binding,
                        namespace,
                        pins,
                        artifacts,
                        started,
                        Arc::clone(&thread_custody),
                    )));
                    drop(executor); // Actual worker join precedes namespace/mount release.
                    ensure!(
                        worker_starts.load(Ordering::SeqCst) >= 2
                            && worker_starts.load(Ordering::SeqCst)
                                == worker_stops.load(Ordering::SeqCst),
                        "owned executor workers did not all join"
                    );
                    retired
                })();
                let _ = finished.send(result);
            })?;
        let ready = match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), ready)
            .await
        {
            Ok(Ok(ready)) => ready,
            _ => {
                let mut error = anyhow::anyhow!(
                    "real owner startup did not complete before its deadline/channel ended"
                );
                match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), &mut done)
                    .await
                {
                    Ok(outcome) => {
                        let cause = match outcome {
                            Ok(Err(cause)) => Some(cause),
                            Ok(Ok(mut retired)) => retired.failure.take(),
                            Err(_) => None,
                        };
                        if let Some(cause) = cause {
                            error = cause.context("real owner startup failed");
                        }
                        if thread.join().is_err() {
                            error = error.context("actual owner startup thread panicked");
                        }
                    }
                    Err(_) => {
                        // A still-running owner, its mounts and nsfs remain in custody.
                        // The VM-only terminal custodian retains names/pins at teardown.
                        std::mem::forget(Arc::clone(&custody));
                    }
                }
                return Err(error);
            }
        };
        Ok(Self {
            ready,
            config,
            deadline,
            finished: done,
            thread: Some(thread),
            custody,
        })
    }

    async fn state(&self) -> anyhow::Result<State> {
        let (send, receive) = oneshot::channel();
        within(self.deadline, "actual owner observation", async {
            self.ready
                .requests
                .send(Request::State(send))
                .await
                .map_err(|_| anyhow::anyhow!("actual owner ended before state observation"))?;
            receive.await.context("actual owner observation closed")
        })
        .await
    }

    async fn wait_for(&self, predicate: impl Fn(&State) -> bool) -> anyhow::Result<State> {
        loop {
            let state = self.state().await?;
            if predicate(&state) {
                return Ok(state);
            }
            ensure!(
                Instant::now() < self.deadline,
                "actual owner condition exceeded fixture deadline: {state:?}"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    async fn gap(&self, duration: Duration) -> anyhow::Result<()> {
        let (send, receive) = oneshot::channel();
        within(self.deadline, "actual owner gap", async {
            self.ready
                .requests
                .send(Request::Gap(duration, send))
                .await
                .map_err(|_| anyhow::anyhow!("actual owner ended before gap"))?;
            receive.await.context("actual owner gap closed")
        })
        .await
    }

    async fn reload(&mut self, config: Config) -> anyhow::Result<ReloadReply> {
        let (result, receive) = oneshot::channel();
        let command = ControlCommand::ReloadConfig {
            request_id: 1,
            config: Box::new(config.clone()),
            diagnostics: Vec::new(),
            #[cfg(feature = "native-api")]
            sources: None,
            #[cfg(feature = "native-api")]
            expected_group_revision: None,
            result,
        };
        let reply = within(self.deadline, "real configuration reply", async {
            self.ready.commands.send(command).await.map_err(|_| {
                anyhow::anyhow!("actual owner ended before configuration publication")
            })?;
            receive.await.context("real configuration reply closed")
        })
        .await?;
        ensure!(
            reply.outcome.accepted(),
            "real configuration publication rejected: {:?}",
            reply.outcome
        );
        self.config = config;
        Ok(reply)
    }

    async fn calibrate(&mut self, artifacts: &Path, label: &str) -> anyhow::Result<State> {
        let state = self.state().await?;
        let metadata = &state.polling;
        let executable = metadata
            .executable_sha256
            .clone()
            .context("actual executable identity unavailable")?;
        let context = metadata
            .context_sha256
            .clone()
            .context("actual device context unavailable")?;
        let parameter = metadata
            .parameter_sha256
            .clone()
            .context("actual parameter identity unavailable")?;
        let declaration = serde_json::json!({
            "purpose": "owned-VM real-consumer regression; not platform calibration or performance evidence",
            "schema": polling::CALIBRATION_SCHEMA,
            "counting_revision": polling::COUNTING_REVISION,
            "executable_sha256": executable,
            "context_sha256": context,
            "parameter_sha256": parameter,
            "parameters": self.config.datapath.as_ref().unwrap().busy_poll,
        });
        let bytes = serde_json::to_vec(&declaration)?;
        std::fs::write(
            artifacts.join(format!("adaptive-{label}.candidate.json")),
            &bytes,
        )?;
        use sha2::{Digest as _, Sha256};
        let evidence = crate::configuration::encode_digest(&Sha256::digest(&bytes));
        let mut config = self.config.clone();
        config
            .datapath
            .as_mut()
            .unwrap()
            .busy_poll
            .as_mut()
            .unwrap()
            .calibration = Some(PollCalibration {
            schema: polling::CALIBRATION_SCHEMA,
            counting_revision: polling::COUNTING_REVISION,
            executable_sha256: executable,
            context_sha256: context,
            parameter_sha256: parameter,
            status: CalibrationStatus::Candidate,
            evidence_manifest_sha256: evidence,
        });
        let revision = state.polling.local_revision;
        self.reload(config).await?;
        self.wait_for(|state| state.polling.local_revision > revision)
            .await
    }

    async fn stop(self) -> anyhow::Result<Retired> {
        let _ = within(self.deadline, "actual owner shutdown request", async {
            self.ready
                .commands
                .send(ControlCommand::Shutdown)
                .await
                .map_err(|_| anyhow::anyhow!("owner already ended"))
        })
        .await;
        self.join().await
    }

    /// Retired custody is handed out only after the actual OS-thread join.
    async fn join(mut self) -> anyhow::Result<Retired> {
        let retired = within(self.deadline, "actual close/join/CQ drain", async {
            (&mut self.finished)
                .await
                .context("actual owner ended without retirement")?
        })
        .await?;
        self.thread
            .take()
            .unwrap()
            .join()
            .map_err(|_| anyhow::anyhow!("actual owner thread panicked"))?;
        Ok(retired)
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        // The independent owner has the same absolute deadline even if its controller fails.
        let _ = self.ready.commands.try_send(ControlCommand::Shutdown);
        if self.thread.is_some() {
            // No unobserved join authorizes releasing namespace/mount custody.
            std::mem::forget(Arc::clone(&self.custody));
        }
    }
}

#[derive(Clone)]
struct OwnedNamespace {
    name: String,
    net: Arc<std::fs::File>,
    inode: u64,
    devices: Vec<(&'static str, &'static str)>,
    deadline: Instant,
}

impl OwnedNamespace {
    fn open(
        name: String,
        inode: u64,
        devices: Vec<(&'static str, &'static str)>,
        deadline: Instant,
    ) -> anyhow::Result<Self> {
        ensure!(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "invalid owned namespace name"
        );
        let net = Arc::new(std::fs::File::open(format!("/run/netns/{name}"))?);
        ensure!(
            net.metadata()?.ino() == inode,
            "run-owned namespace identity changed"
        );
        Ok(Self {
            name,
            net,
            inode,
            devices,
            deadline,
        })
    }

    fn b(deadline: Instant) -> anyhow::Result<Self> {
        let name = std::env::var("HONK_XDP_ADAPTIVE_B_NS")?;
        ensure!(name.starts_with("hv7-b-"), "B namespace is not run-owned");
        Self::open(
            name,
            std::env::var("HONK_XDP_ADAPTIVE_B_INODE")?.parse()?,
            vec![("dut2", "02:00:00:00:00:12")],
            deadline,
        )
    }
}

struct NamespaceCustody {
    net: std::fs::File,
    mount: std::fs::File,
}

fn enter_owned_namespace(namespace: &OwnedNamespace) -> anyhow::Result<NamespaceCustody> {
    let original_mount = std::fs::metadata("/proc/thread-self/ns/mnt")?.ino();
    // SAFETY: this is a dedicated OS thread, before any executor, worker or socket.
    ensure!(
        unsafe { libc::unshare(libc::CLONE_FS | libc::CLONE_NEWNS) } == 0,
        "isolating owned FS/mount namespace: {}",
        io::Error::last_os_error()
    );
    ensure!(
        unsafe {
            libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            )
        } == 0,
        "privatizing owned mount namespace: {}",
        io::Error::last_os_error()
    );
    ensure!(
        unsafe { libc::setns(namespace.net.as_raw_fd(), libc::CLONE_NEWNET) } == 0,
        "entering retained owned netns: {}",
        io::Error::last_os_error()
    );
    // The inherited sysfs may already belong to this netns. Replace it only in
    // this private mount namespace, as ip netns exec does; pins live outside /sys.
    ensure!(
        unsafe { libc::umount2(c"/sys".as_ptr(), libc::MNT_DETACH) } == 0,
        "detaching inherited private sysfs: {}",
        io::Error::last_os_error()
    );
    ensure!(
        unsafe {
            libc::mount(
                c"sysfs".as_ptr(),
                c"/sys".as_ptr(),
                c"sysfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        } == 0,
        "mounting owned namespace sysfs: {}",
        io::Error::last_os_error()
    );
    let net = std::fs::File::open("/proc/thread-self/ns/net")?;
    let mount = std::fs::File::open("/proc/thread-self/ns/mnt")?;
    ensure!(
        net.metadata()?.ino() == namespace.inode && mount.metadata()?.ino() != original_mount,
        "actual owner thread namespace identities do not match custody"
    );
    for &(device, mac) in &namespace.devices {
        ensure!(
            std::fs::read_to_string(format!("/sys/class/net/{device}/address"))?.trim() == mac,
            "private sysfs does not describe the owned {device}"
        );
    }
    Ok(NamespaceCustody { net, mount })
}

fn record_bindings(
    runtime: &Runtime,
    config: &Config,
    namespace: &OwnedNamespace,
    artifacts: &Path,
) -> anyhow::Result<()> {
    let namespace_inode = std::fs::metadata("/proc/thread-self/ns/net")?.ino();
    ensure!(
        namespace_inode == namespace.inode,
        "binding receipt is outside the retained owner namespace"
    );
    let xsk_mode = config
        .datapath
        .as_ref()
        .context("XDP configuration missing")?
        .effective_xsk_mode();
    let startup_id = runtime
        .devices
        .first()
        .context("binding receipt has no captured device")?
        .capture
        .authority
        .attachment_generation;
    let mut devices = Vec::with_capacity(runtime.devices.len());
    for device in &runtime.devices {
        let context = device
            .features
            .as_ref()
            .context("binding receipt has no actual retained driver context")?
            .context();
        ensure!(
            context.starts_with(b"HXFEAT\0\x01"),
            "binding receipt has an unsupported retained feature context"
        );
        let field = context
            .get(8..40)
            .context("retained driver field is truncated")?;
        let end = field
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(field.len());
        let driver = std::str::from_utf8(&field[..end])?;
        ensure!(
            device
                .queues
                .iter()
                .map(|queue| queue.id)
                .eq(device.info.queues.iter().copied()),
            "actual bound queues differ from device readback on {}",
            device.info.name
        );
        if xsk_mode == XskMode::ZeroCopy {
            ensure!(
                driver == "igb",
                "adaptive ZeroCopy fixture requires actual igb: {driver}"
            );
            ensure!(
                device.info.queues == [0, 1],
                "adaptive ZeroCopy fixture requires exact queues [0, 1] on {}: {:?}",
                device.info.name,
                device.info.queues
            );
        }
        let queues: Vec<_> = device
            .queues
            .iter()
            .map(|queue| {
                serde_json::json!({
                    "queue_id": queue.id,
                    "zero_copy": queue.io.get_ref().zerocopy(),
                })
            })
            .collect();
        devices.push(serde_json::json!({
            "device": device.info.name,
            "ifindex": device.info.ifindex,
            "driver": driver,
            "queues": queues,
        }));
    }
    let record = serde_json::json!({
        "schema": 1,
        "startup_id": startup_id,
        "namespace": namespace.name,
        "namespace_inode": namespace_inode,
        "xsk_mode": xsk_mode,
        "devices": devices,
    });
    let line = format!("{record}\n");
    std::fs::OpenOptions::new()
        .append(true)
        .open(artifacts.join("adaptive-runtime.bindings.jsonl"))?
        .write_all(line.as_bytes())?;
    print!("adaptive-runtime.binding {line}");
    Ok(())
}

async fn serve(
    config: Config,
    binding: PollBudgetBinding,
    namespace: OwnedNamespace,
    pins: PathBuf,
    artifacts: PathBuf,
    started: oneshot::Sender<Ready>,
    custody: Arc<std::sync::Mutex<Option<NamespaceCustody>>>,
) -> anyhow::Result<Retired> {
    let deadline = namespace.deadline;
    let admission = Arc::new(AtomicBool::new(false));
    let resolver = crate::dns::DnsResolver::new(&config.dns)?;
    let forwarder = resolver.forwarder();
    let mut plane = ControlPlane::new(
        config.clone(),
        Box::new(crate::ebpf::userspace::UserspaceBackend::new(Arc::clone(
            &admission,
        ))),
        crate::routing::Router::from_config(&config.routing)?,
        Arc::new(honk_outbound::proxy::ProxyRegistry::default_resolver()?),
        resolver,
        forwarder,
    )?
    .with_process_polling(binding)?;
    plane.set_mode_state(Arc::new(parking_lot::RwLock::new(
        crate::mode::ModeState::new("Rule", "direct"),
    )));
    plane.start_datapath_flags_coordinator()?;
    let commands = plane.command_sender();
    let router = plane.traffic_router();
    let publication = plane.config_handle();
    let shutdown = plane.shutdown_intent();
    let backend = plane.policy_backend_handle();
    let (mut runtime, mut owner) =
        start_runtime(plane, &config, &pins, &artifacts, admission).await?;
    let binding_failure = record_bindings(&runtime, &config, &namespace, &artifacts).err();
    let control = runtime.polling.test_control();
    let budget = runtime.polling.budget.as_ref().unwrap().clone();
    let (requests, mut receive) = mpsc::channel(4);
    let (fairness, mut fair_enabled) = watch::channel(false);
    let fair_turns = Arc::new(AtomicU64::new(0));
    let fair_thread = Arc::new(std::sync::Mutex::new(None));
    let fair_count = Arc::clone(&fair_turns);
    let fair_identity = Arc::clone(&fair_thread);
    let fair_task = tokio::task::spawn_local(async move {
        loop {
            if Instant::now() >= deadline {
                break;
            }
            if !*fair_enabled.borrow() {
                if fair_enabled.changed().await.is_err() {
                    break;
                }
                continue;
            }
            tokio::task::yield_now().await;
            *fair_identity.lock().unwrap() = Some(std::thread::current().id());
            fair_count.fetch_add(1, Ordering::SeqCst);
        }
    });
    let controller_left = if binding_failure.is_none() {
        started
            .send(Ready {
                requests,
                commands,
                router,
                publication,
                control: Arc::clone(&control),
                fairness,
            })
            .is_err()
    } else {
        drop(started);
        true
    };
    let attempts = Arc::new(ReaderAttempts::default());
    let authority = runtime.core.as_ref().map(RoutedCore::authority);
    let acquire = || {
        authority.as_ref().map(|authority| {
            let id = attempts.started.fetch_add(1, Ordering::SeqCst) + 1;
            let mut ticket = ReaderTicket {
                attempts: Arc::clone(&attempts),
                id,
                completed: false,
            };
            async move {
                let read = authority.read_policy().await;
                ticket.completed = true;
                ticket.attempts.completed.store(ticket.id, Ordering::SeqCst);
                read
            }
        })
    };
    let reader = None;
    let timer = None;
    let notification = runtime.polling.notification();
    tokio::pin!(reader, timer, notification);
    let watchdog = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(watchdog);
    let mut failure = binding_failure.or_else(|| {
        controller_left
            .then(|| anyhow::anyhow!("fixture controller disappeared during real startup"))
    });
    let mut joined_plane = None;
    loop {
        if Instant::now() >= deadline {
            failure.get_or_insert_with(|| {
                anyhow::anyhow!("actual owner exceeded its independent fixture deadline")
            });
        }
        if (failure.is_some() || shutdown.requested()) && !runtime.closing {
            reader.set(None);
            if let Err(error) = runtime.close_capture() {
                failure.get_or_insert(error);
            }
        }
        if runtime.closing {
            break;
        }
        tokio::select! {
            _ = watchdog.as_mut() => {
                failure.get_or_insert_with(|| anyhow::anyhow!("actual owner exceeded its independent fixture deadline"));
            },
            request = receive.recv() => match request {
                Some(Request::State(reply)) => {
                    let _ = reply.send(State {
                        polling: runtime.polling_test_snapshot(), attempts: attempts.snapshot(),
                        fair_turns: fair_turns.load(Ordering::SeqCst),
                        owner_thread: std::thread::current().id(), fair_thread: *fair_thread.lock().unwrap(),
                        clock_events: control.clock_events(),
                    });
                }
                Some(Request::Gap(duration, reply)) => {
                    let until = Instant::now().checked_add(duration).context("fixture gap overflow")?;
                    ensure!(until < deadline, "fixture gap exceeds the owned window");
                    tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
                    let _ = reply.send(());
                }
                None => {
                    failure.get_or_insert_with(|| anyhow::anyhow!("fixture controller left an active owner"));
                }
            },
            joined = owner_step(&mut runtime, &mut owner, reader.as_mut(), &acquire, &shutdown,
                timer.as_mut(), notification.as_mut()) => {
                match joined {
                    Ok(Some(joined)) => {
                        reader.set(None);
                        if let Err(error) = runtime.close_capture() { failure.get_or_insert(error); }
                        joined_plane = Some(joined);
                        break;
                    }
                    Ok(None) => {}
                    Err(error) => { failure.get_or_insert(error); }
                }
            }
        }
    }
    fair_task.abort();
    let _ = fair_task.await;
    reader.set(None);
    timer.set(None);
    let mut warned = false;
    let joined = match joined_plane {
        Some(joined) => joined,
        None => match join_endpoints(
            &mut owner,
            |cx| runtime.poll_service(cx, &shutdown, timer.as_mut(), false, notification.as_mut()),
            Instant::now(),
            &mut warned,
        )
        .await
        {
            Ok(joined) => joined,
            Err(error) => {
                std::mem::forget((runtime, owner));
                return Err(error);
            }
        },
    };
    let (plane, result) = match joined {
        Ok(joined) => joined,
        Err(error) => {
            std::mem::forget((runtime, owner));
            return Err(error);
        }
    };
    if let Err(error) = result {
        failure.get_or_insert(error);
    }
    if let Err(error) = drain_transmit(
        || {
            let mut outstanding = false;
            for device in &mut runtime.devices {
                for queue in &mut device.queues {
                    let port = queue.io.get_mut();
                    port.complete(release_completed)?;
                    port.kick()?;
                    outstanding |= port.counters().submitted != port.counters().completed;
                }
            }
            Ok(outstanding)
        },
        Instant::now(),
        &mut warned,
    )
    .await
    {
        std::mem::forget((runtime, owner, plane));
        return Err(error.into());
    }
    let state = State {
        polling: runtime.polling_test_snapshot(),
        attempts: attempts.snapshot(),
        fair_turns: fair_turns.load(Ordering::SeqCst),
        owner_thread: std::thread::current().id(),
        fair_thread: *fair_thread.lock().unwrap(),
        clock_events: control.clock_events(),
    };
    // Autonomous closure only drains local owners; exact guards and pins stay installed.
    let source = if runtime.core.is_some() { "a" } else { "b" };
    let mut guards = Vec::new();
    for device in &mut runtime.devices {
        let guard = device.programs.discover_prog_id();
        ensure!(
            honk_xsk::xdp_state(device.info.ifindex)?.prog_id == guard,
            "owned guard identity changed before retirement"
        );
        for queue in device.queues.drain(..) {
            let mut port = queue.io.into_inner();
            ensure!(
                port.counters().submitted == port.counters().completed,
                "real CQ did not drain"
            );
            ensure!(
                port.close().ready_for_backend_teardown(),
                "real packet owners survived close"
            );
            port.close_socket();
        }
        let &(_, mac) = namespace
            .devices
            .iter()
            .find(|(name, _)| *name == device.info.name)
            .context("owner captured an unowned device")?;
        guards.push((device.info.ifindex, mac, guard));
    }
    backend.write().await.cleanup().await?;
    Ok(Retired {
        plane: Some(plane),
        state,
        ledger: budget.snapshot(),
        terminal: Terminal {
            namespace,
            source,
            guards,
            pins,
            custody,
            released: false,
        },
        failure,
    })
}

fn configuration(core: bool, xsk_mode: XskMode) -> anyhow::Result<Config> {
    let interfaces = if core {
        "dut0: lan\n dut1: wan"
    } else {
        "dut2: lan"
    };
    let profile = if core { "core" } else { "endpoint" };
    let mut config = honk_config::parser::parse_dae_config(&format!(
        "global {{ dial_mode: ip\n nfqueue_enable: false\n so_mark_from_dae: 0x100 }}\n\
         dns {{ bind: '' }}\n\
         datapath {{ backend: xdp\n direct: {profile}\n interface {{ {interfaces} }} }}\n\
         routing {{ dport(18084) -> packet-proof\n dport(18086) -> packet-proof\n fallback: direct }}"
    ))?;
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
    config.datapath.as_mut().unwrap().xsk_mode = Some(xsk_mode);
    config.datapath.as_mut().unwrap().busy_poll = Some(BusyPollConfig {
        // Same small correctness-fixture parameters as the real daemon candidate profile.
        pps_enter: 1,
        pps_exit: 0,
        observation_window_us: 20_000,
        enter_windows: 2,
        exit_windows: 1,
        max_busy_us: 1_000,
        empty_rounds: 2,
        budget_window_us: 10_000,
        budget_us: 2_000,
        calibration: None,
    });
    config.validate_assembled()?;
    Ok(config)
}

struct Rig {
    a: Option<Owner>,
    b: Option<Owner>,
    budget: ProcessPollBudget,
    tcp: Option<TcpPeer>,
    pump: Pump,
    pins: PathBuf,
    artifacts: PathBuf,
    deadline: Instant,
    b_namespace: OwnedNamespace,
}

impl Rig {
    fn a(&self) -> &Owner {
        self.a.as_ref().unwrap()
    }
    fn b(&self) -> &Owner {
        self.b.as_ref().unwrap()
    }
    fn a_mut(&mut self) -> &mut Owner {
        self.a.as_mut().unwrap()
    }
    fn b_mut(&mut self) -> &mut Owner {
        self.b.as_mut().unwrap()
    }
    fn tcp(&mut self) -> &mut TcpPeer {
        self.tcp.as_mut().unwrap()
    }

    /// Retire B through the controller frontier, then cold-restart it while its Pump stays stopped.
    async fn rebuild_b(&mut self) -> anyhow::Result<(Retired, State)> {
        let config = self.b().config.clone();
        let mut retired = self.b.take().unwrap().stop().await?;
        ensure!(
            retired.failure.is_none(),
            "participant retirement failed: {:?}",
            retired.failure
        );
        retired.release(&mut self.pump, None).await?;
        self.restore_b_link().await?;
        let owner = Owner::start(
            config,
            PollBudgetBinding::Participant(self.budget.clone()),
            self.b_namespace.clone(),
            self.pins.join("b"),
            self.artifacts.clone(),
            self.deadline,
        )
        .await?;
        let state = owner.state().await?;
        self.b = Some(owner);
        Ok((retired, state))
    }

    /// Re-enable only the owned B capture link the frontier brought down, before fresh capture.
    async fn restore_b_link(&self) -> anyhow::Result<()> {
        owned_command(
            &self.b_namespace,
            &["ip", "link", "set", "dev", "dut2", "up"],
        )
        .await?;
        Ok(())
    }
}

async fn owned_command(
    namespace: &OwnedNamespace,
    args: &[&str],
) -> anyhow::Result<std::process::Output> {
    use std::os::unix::process::CommandExt as _;
    ensure!(
        matches!(args.first(), Some(&"ip" | &"ethtool")),
        "unowned fixture command"
    );
    ensure!(
        namespace.net.metadata()?.ino() == namespace.inode,
        "retained namespace identity changed"
    );
    let net = Arc::clone(&namespace.net);
    let mut command = Command::new(args[0]);
    command.args(&args[1..]).kill_on_drop(true);
    // SAFETY: only raw namespace/mount syscalls run in the fork child before exec.
    // The controller's executor and every existing worker remain untouched.
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if libc::unshare(libc::CLONE_FS | libc::CLONE_NEWNS) != 0
                || libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
                || libc::setns(net.as_raw_fd(), libc::CLONE_NEWNET) != 0
                || libc::umount2(c"/sys".as_ptr(), libc::MNT_DETACH) != 0
                || libc::mount(
                    c"sysfs".as_ptr(),
                    c"/sys".as_ptr(),
                    c"sysfs".as_ptr(),
                    0,
                    std::ptr::null(),
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = within(namespace.deadline, "owned VM command", async {
        Ok(command.output().await?)
    })
    .await?;
    ensure!(
        output.status.success(),
        "owned VM command {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

const UDP_PEER: &str = r#"
import contextlib, json, os, selectors, socket, struct, sys, time
names = json.loads(sys.argv[1])
deadline = time.monotonic() + float(sys.argv[2])
home = os.open('/proc/thread-self/ns/net', os.O_RDONLY)
@contextlib.contextmanager
def namespace(label):
    identity = names[label]
    target = os.open('/run/netns/' + identity['name'], os.O_RDONLY)
    assert os.fstat(target).st_ino == identity['inode'], ('namespace replaced', label)
    try:
        os.setns(target, 0)
        yield
    finally:
        os.setns(home, 0)
        os.close(target)

def checksum(data):
    data += b'\0' * (len(data) % 2)
    value = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

select = selectors.DefaultSelector()
select.register(sys.stdin, selectors.EVENT_READ, 'command')
owners = {}
for label, dev, source, mac in [('a', 'c0', '192.0.2.98', '0200000000100200000000200800'),
                                ('w', 's0', '198.51.100.98', '0200000000110200000000210800'),
                                ('b', 'c1', '192.0.3.98', '0200000000120200000000220800')]:
    with namespace('server' if label == 'w' else label):
        receive = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        receive.bind((dev, 0))
        receive.setsockopt(263, 23, 1) # PACKET_IGNORE_OUTGOING
        receive.setblocking(False)
        transmit = []
        for priority in [0, 1]:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            sock.bind((dev, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY, priority)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
            transmit.append(sock)
    owners[label] = {'receive': receive, 'transmit': transmit, 'source': socket.inet_aton(source),
                     'ethernet': bytes.fromhex(mac), 'running': False, 'sequence': 0,
                     'sent': 0, 'received': 0, 'upstream': 0}
    select.register(receive, selectors.EVENT_READ, label)
with namespace('server'):
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(('198.51.100.2', 18086))
    server.setblocking(False)
select.register(server, selectors.EVENT_READ, 'server')
os.close(home)
destination = socket.inet_aton('198.51.100.2')

def send(label, state):
    state['sequence'] += 1
    sequence = state['sequence']
    payload = b'v7e4/' + label.encode() + b'/' + struct.pack('!I', sequence) + bytes(range(48))
    body = struct.pack('!HHHH', 43000 + sequence % 64, 18086, 8 + len(payload), 0) + payload
    pseudo = state['source'] + destination + struct.pack('!BBH', 0, 17, len(body))
    body = body[:6] + struct.pack('!H', checksum(pseudo + body) or 65535) + body[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), sequence % 65536, 0, 64, 17, 0, state['source'], destination)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    state['transmit'][sequence % 2].send(state['ethernet'] + ip + body)
    state['sent'] += 1

def low(label, state):
    # Fully valid, unmatched RST input has no admitted flow and elicits no RST.
    # Real RX rounds can close zero-qualified-packet windows without an idle timer.
    state['sequence'] += 1
    sequence = state['sequence']
    body = struct.pack('!HHIIBBHHH', 47000 + sequence % 64, 18084, sequence, 0, 5 << 4, 4, 0, 0, 0)
    pseudo = state['source'] + destination + struct.pack('!BBH', 0, 6, len(body))
    body = body[:16] + struct.pack('!H', checksum(pseudo + body)) + body[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), sequence % 65536, 0, 64, 6, 0, state['source'], destination)
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    state['transmit'][sequence % 2].send(state['ethernet'] + ip + body)
    state['sent'] += 1

print('READY', flush=True)
next_send = time.monotonic()
running = True
while running:
    now = time.monotonic()
    assert now < deadline, 'UDP peer exceeded owned fixture deadline'
    if now >= next_send:
        for label, state in owners.items():
            if state['running'] == 'low':
                low(label, state)
            elif state['running']:
                for _ in range(64):
                    send(label, state)
        next_send = time.monotonic() + 0.002
    for key, _ in select.select(min(0.002, max(0, next_send - time.monotonic()))):
        label = key.data
        if label == 'command':
            line = sys.stdin.readline()
            assert line, 'UDP controller vanished before QUIT'
            command, target = line.strip().split()
            if command in ['RUN', 'STOP', 'LOW']:
                for name in (['a', 'w'] if target == 'a' else [target]):
                    owners[name]['running'] = 'low' if command == 'LOW' else command == 'RUN'
                print(command + ' ' + target, flush=True)
            elif command == 'STATUS':
                counts = {name: {field: state[field] for field in ['sent', 'received', 'upstream']}
                          for name, state in owners.items()}
                counts['a'] = {field: counts['a'][field] + counts['w'][field] for field in counts['a']}
                print('STATUS ' + json.dumps(counts, sort_keys=True), flush=True)
            elif command == 'QUIT':
                running = False
                print('STOPPED all', flush=True)
                break
            else:
                raise AssertionError(command)
        elif label == 'server':
            for _ in range(256):
                try:
                    payload, address = server.recvfrom(65535)
                except BlockingIOError:
                    break
                assert len(payload) == 59 and payload[:5] == b'v7e4/' and payload[6:7] == b'/'
                owner = payload[5:6].decode()
                assert owner in owners
                expected = '10.78.0.1' if owner == 'b' else '10.77.0.1'
                assert address[0] == expected, ('not the actual Endpoint dial', owner, address)
                owners[owner]['upstream'] += 1
                assert server.sendto(payload, address) == len(payload)
        else:
            state = owners[label]
            for _ in range(256):
                try:
                    packet, address = state['receive'].recvfrom(65535)
                except BlockingIOError:
                    break
                if address[2] == 4 or len(packet) < 42 or packet[12:14] != b'\x08\x00':
                    continue
                ip = packet[14:]
                if ip[9] != 17 or ip[12:16] != destination or ip[16:20] != state['source']:
                    continue
                length, = struct.unpack_from('!H', ip, 2)
                header = (ip[0] & 15) * 4
                assert header >= 20 and length <= len(ip) and checksum(ip[:header]) == 0
                body = ip[header:length]
                assert checksum(ip[12:20] + struct.pack('!BBH', 0, 17, len(body)) + body) == 0
                source, port, udp_length, _ = struct.unpack('!HHHH', body[:8])
                payload = body[8:]
                assert source == 18086 and udp_length == len(body)
                assert payload[:7] == b'v7e4/' + label.encode() + b'/' and payload[11:] == bytes(range(48))
                sequence, = struct.unpack('!I', payload[7:11])
                assert 0 < sequence <= state['sequence'] and port == 43000 + sequence % 64
                state['received'] += 1
for state in owners.values():
    for sock in [state['receive']] + state['transmit']:
        sock.close()
server.close()
select.close()
"#;

struct Pump {
    child: Child,
    input: ChildStdin,
    output: Lines<BufReader<ChildStdout>>,
    deadline: Instant,
    _namespaces: Vec<std::fs::File>,
}

impl Pump {
    async fn spawn(deadline: Instant) -> anyhow::Result<Self> {
        let b = std::env::var("HONK_XDP_ADAPTIVE_CLIENT_NS")?;
        ensure!(
            b.starts_with("hv7-c-"),
            "client B namespace is not run-owned"
        );
        let expected_b: u64 = std::env::var("HONK_XDP_ADAPTIVE_CLIENT_INODE")?.parse()?;
        let mut retained = Vec::new();
        let mut identities = serde_json::Map::new();
        for (label, name) in [
            ("a", "client".to_owned()),
            ("b", b),
            ("server", "server".to_owned()),
        ] {
            let namespace = std::fs::File::open(format!("/run/netns/{name}"))?;
            let inode = namespace.metadata()?.ino();
            if label == "b" {
                ensure!(inode == expected_b, "client B namespace identity changed");
            }
            identities.insert(
                label.into(),
                serde_json::json!({"name": name, "inode": inode}),
            );
            retained.push(namespace);
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("UDP startup exceeded fixture window")?;
        let mut child = Command::new("python3")
            .args(["-u", "-c", UDP_PEER])
            .arg(serde_json::Value::Object(identities).to_string())
            .arg(remaining.as_secs_f64().to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut pump = Self {
            child,
            input,
            output,
            deadline,
            _namespaces: retained,
        };
        let ready = pump.line().await?;
        ensure!(ready == "READY", "actual UDP peer failed startup: {ready}");
        Ok(pump)
    }

    async fn line(&mut self) -> anyhow::Result<String> {
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            self.output.next_line(),
        )
        .await
        .context("actual UDP peer reply deadline")??
        .context("actual UDP peer exited")
    }

    async fn set(&mut self, label: &str, running: bool) -> anyhow::Result<()> {
        ensure!(matches!(label, "a" | "b"), "unknown actual UDP owner");
        let command = format!("{} {label}", if running { "RUN" } else { "STOP" });
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            self.input.write_all(format!("{command}\n").as_bytes()),
        )
        .await
        .context("actual UDP peer command deadline")??;
        let reply = self.line().await?;
        ensure!(
            reply == command,
            "actual UDP peer command mismatch: {reply}"
        );
        Ok(())
    }

    async fn low(&mut self, label: &str) -> anyhow::Result<()> {
        ensure!(
            matches!(label, "a" | "b"),
            "unknown actual unadmitted-input owner"
        );
        let command = format!("LOW {label}");
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            self.input.write_all(format!("{command}\n").as_bytes()),
        )
        .await
        .context("actual unadmitted-input command deadline")??;
        ensure!(
            self.line().await? == command,
            "actual unadmitted-input peer command mismatch"
        );
        Ok(())
    }

    async fn status(&mut self) -> anyhow::Result<serde_json::Value> {
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            self.input.write_all(b"STATUS all\n"),
        )
        .await
        .context("actual UDP status command deadline")??;
        let reply = self.line().await?;
        serde_json::from_str(
            reply
                .strip_prefix("STATUS ")
                .context("actual UDP peer status missing")?,
        )
        .map_err(Into::into)
    }

    async fn stop(mut self) -> anyhow::Result<()> {
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            self.input.write_all(b"QUIT all\n"),
        )
        .await
        .context("actual UDP stop command deadline")??;
        ensure!(
            self.line().await? == "STOPPED all",
            "actual UDP peer did not stop"
        );
        let status = tokio::time::timeout_at(
            tokio::time::Instant::from_std(self.deadline),
            self.child.wait(),
        )
        .await
        .context("actual UDP peer join deadline")??;
        ensure!(status.success(), "actual UDP peer failed");
        Ok(())
    }
}

/// The original real TCP peer, with READY, every exchange, STOP and exit inside the original deadline.
struct TcpPeer {
    peer: Peer,
    deadline: Instant,
}

impl TcpPeer {
    async fn spawn(deadline: Instant) -> anyhow::Result<Self> {
        let mut tcp = Self {
            peer: Peer::spawn()?,
            deadline,
        };
        let ready = within(deadline, "actual TCP peer READY", tcp.peer.expect("READY")).await;
        match ready {
            Ok(()) => Ok(tcp),
            Err(error) => Err(tcp.abort(error).await),
        }
    }

    async fn step(&mut self, command: &str, label: &str, expected: &str) -> anyhow::Result<()> {
        within(self.deadline, "real TCP wire exchange", async {
            self.peer.command(command, label).await?;
            self.peer.expect(&format!("{expected} {label}")).await
        })
        .await
        .with_context(|| format!("TCP peer {command} {label} awaiting {expected}"))
    }

    async fn join(mut self) -> anyhow::Result<TcpExited> {
        if let Err(error) = self.step("STOP", "adaptive", "STOPPED").await {
            return Err(self.abort(error).await);
        }
        let status = within(self.deadline, "actual TCP peer join", async {
            Ok(self.peer.child.wait().await?)
        })
        .await?;
        ensure!(status.success(), "actual TCP peer failed: {status}");
        Ok(TcpExited(()))
    }

    /// Nonblocking kill plus an exit wait under the same deadline; never a success receipt.
    async fn abort(mut self, error: anyhow::Error) -> anyhow::Error {
        let _ = self.peer.child.start_kill();
        match within(self.deadline, "actual TCP peer abort", async {
            Ok(self.peer.child.wait().await?)
        })
        .await
        {
            Ok(_) => error,
            Err(unobserved) => {
                error.context(format!("actual TCP peer exit unobserved: {unobserved:#}"))
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires the owned adaptive disposable-VM window, real AF_XDP and run-owned B namespaces"]
async fn actual_owner_clock_budget_fairness_and_live_features() -> anyhow::Result<()> {
    actual_owner_fixture(XskMode::Copy).await
}

#[tokio::test]
#[ignore = "requires the owned recent-kernel igb adaptive-ZeroCopy VM window and run-owned B namespaces"]
async fn actual_zerocopy_owner_clock_budget_fairness_and_live_features() -> anyhow::Result<()> {
    actual_owner_fixture(XskMode::ZeroCopy).await
}

async fn actual_owner_fixture(xsk_mode: XskMode) -> anyhow::Result<()> {
    let deadline = Instant::now() + WINDOW;
    let pins = guarded_pin_root().join("adaptive");
    let artifacts = PathBuf::from(std::env::var_os("HONK_XDP_ARTIFACT_ROOT").unwrap());
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(artifacts.join("adaptive-runtime.bindings.jsonl"))?;
    let b_namespace = OwnedNamespace::b(deadline)?;
    let a_namespace = OwnedNamespace::open(
        "dut".into(),
        std::fs::metadata("/run/netns/dut")?.ino(),
        vec![("dut0", "02:00:00:00:00:10"), ("dut1", "02:00:00:00:00:11")],
        deadline,
    )?;
    ensure!(
        a_namespace.inode != b_namespace.inode,
        "actual owners must have independent topology watches"
    );
    let publisher = ProcessPollBudget::initialize_process(true)?;
    let budget = publisher.participant_handle();
    let a = Owner::start(
        configuration(true, xsk_mode)?,
        PollBudgetBinding::Publisher(publisher),
        a_namespace,
        pins.join("a"),
        artifacts.clone(),
        deadline,
    )
    .await?;
    let b = Owner::start(
        configuration(false, xsk_mode)?,
        PollBudgetBinding::Participant(budget.clone()),
        b_namespace.clone(),
        pins.join("b"),
        artifacts.clone(),
        deadline,
    )
    .await?;
    let tcp = TcpPeer::spawn(deadline).await?;
    let pump = match Pump::spawn(deadline).await {
        Ok(pump) => pump,
        Err(error) => return Err(tcp.abort(error).await),
    };
    let mut rig = Rig {
        a: Some(a),
        b: Some(b),
        budget,
        tcp: Some(tcp),
        pump,
        pins,
        artifacts,
        deadline,
        b_namespace,
    };
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
        let artifacts = rig.artifacts.clone();
        for owner in [rig.a(), rig.b()] {
            let state = owner.state().await?;
            ensure!(
                !state.polling.high
                    && state.polling.busy_entries == 0
                    && state.polling.probe_rounds == 0,
                "no fake initial qualification: {state:?}"
            );
        }
        rig.a_mut().calibrate(&artifacts, "a-start").await?;
        rig.b_mut().calibrate(&artifacts, "b-start").await?;
        rig.pump.set("a", true).await?;
        let a = rig
            .a()
            .wait_for(|state| state.polling.high && state.polling.probe_rounds > 0)
            .await?;
        ensure!(
            (a.polling.rx_high_windows >= 2 || a.polling.tx_high_windows >= 2)
                && a.polling.qualified_rx > 0
                && a.polling.published_tx > 0,
            "actual directional dwell/counting did not qualify A: {a:?}"
        );
        rig.pump.set("a", false).await?;
        rig.pump.set("b", true).await?;
        let b = rig
            .b()
            .wait_for(|state| state.polling.high && state.polling.probe_rounds > 0)
            .await?;
        ensure!(
            (b.polling.rx_high_windows >= 2 || b.polling.tx_high_windows >= 2)
                && b.polling.qualified_rx > 0
                && b.polling.published_tx > 0,
            "actual directional dwell/counting did not qualify B: {b:?}"
        );
        rig.pump.set("a", true).await?;
        clocks::run(&mut rig).await?;
        shared::run(&mut rig).await?;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .unwrap_or_else(|error| {
        Err(anyhow::Error::new(error).context("combined actual-owner fixture window"))
    });
    if result.is_err() {
        for (label, owner) in [("a", rig.a.as_ref()), ("b", rig.b.as_ref())] {
            if let Some(owner) = owner
                && Instant::now() < deadline
            {
                eprintln!(
                    "{label}: actual owner at peer failure: {:?}",
                    owner.state().await
                );
            }
        }
    }
    // Successful scenarios released every owner at its own frontier. Anything left only
    // drains: its exact guards, pins and namespace custody stay retained, with no marker.
    let Rig {
        a,
        b,
        tcp,
        pump,
        pins,
        artifacts,
        ..
    } = rig;
    let mut cleanup_error = pump.stop().await.err();
    if let Some(tcp) = tcp {
        cleanup_error.get_or_insert(
            tcp.abort(anyhow::anyhow!("actual TCP peer outlived its A frontier"))
                .await,
        );
    }
    for owner in [a, b].into_iter().flatten() {
        let error = match owner.stop().await {
            Ok(retired) => anyhow::anyhow!(
                "actual owner outlived its controller frontier: {:?}",
                retired.failure
            ),
            Err(error) => error,
        };
        cleanup_error.get_or_insert(error);
    }
    result?;
    if let Some(error) = cleanup_error {
        return Err(error);
    }
    std::fs::remove_dir(&pins)?;
    std::fs::remove_dir(pins.parent().unwrap())?;
    std::fs::write(
        artifacts.join("adaptive-runtime.joined"),
        "all real scope/CQ owners, peers, workers and OS threads joined\n",
    )?;
    Ok(())
}

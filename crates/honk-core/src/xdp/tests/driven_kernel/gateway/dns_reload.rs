#![cfg(feature = "packet-ebpf")]

mod batch_udp;
mod pending;
mod quic_udp;

use super::{Config, ControlPlane, Fixture};
use crate::{
    control::{ControlCommand, ReloadOutcome, ReloadReply, routing_matcher::RoutingPushPlan},
    ebpf::{PolicyBackend, userspace::GatewayReload},
    routing::Router,
};
use anyhow::{Context, ensure};
use aya::maps::{Array, HashMap as BpfHashMap, Map, MapData, MapError, MapInfo};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use honk_ebpf_common::xdp_gateway::{GatewayDnsKey, GatewayDnsValue};
use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    os::fd::{AsFd, AsRawFd},
    time::Duration,
};
use tokio::{
    process::Command,
    sync::{RwLock, oneshot},
    time::{sleep, timeout},
};

const NAME: &str = "shadow-reload.test";
const OLD_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const NEW_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 99);
const LIMIT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct FactKey(GatewayDnsKey);

#[derive(Clone, Copy)]
#[repr(transparent)]
struct FactValue(GatewayDnsValue);

// SAFETY: the shared repr(C) layouts contain only integers and byte arrays,
// and the shared ABI assertions cover their complete sizes and field offsets.
unsafe impl aya::Pod for FactKey {}
unsafe impl aya::Pod for FactValue {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BankMaps {
    epochs: u32,
    facts: u32,
}

impl BankMaps {
    fn epoch(self, realm: u32) -> anyhow::Result<u64> {
        let epochs = Array::<_, [u64; 8]>::try_from(Map::Array(MapData::from_id(self.epochs)?))?;
        Ok(epochs.get(&realm, 0)?[0])
    }

    fn fact(self, realm: u32, epoch: u64, ip: Ipv4Addr) -> anyhow::Result<Option<GatewayDnsValue>> {
        let map = Map::HashMap(MapData::from_id(self.facts)?);
        let facts = BpfHashMap::<_, FactKey, FactValue>::try_from(map)?;
        let key = FactKey(GatewayDnsKey {
            export_epoch: epoch,
            realm_id: realm,
            reserved: 0,
            canonical_dst: ip.to_ipv6_mapped().octets(),
        });
        match facts.get(&key, 0) {
            Ok(FactValue(value)) => Ok(Some(value)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn retired(self) -> anyhow::Result<bool> {
        maps_retired(&[self.epochs, self.facts])
    }
}

fn maps_retired(ids: &[u32]) -> anyhow::Result<bool> {
    for &id in ids {
        match MapInfo::from_id(id) {
            Ok(_) => return Ok(false),
            Err(MapError::SyscallError(error))
                if error.io_error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}

#[derive(Debug, PartialEq, Eq)]
struct Attached {
    programs: [u32; 2],
    bank: Option<BankMaps>,
    arbitration: Option<(u32, u32)>,
    mode: u32,
}

impl Attached {
    fn read(fixture: &Fixture) -> anyhow::Result<Self> {
        let mut programs = [0; 2];
        let mut members = [(None, None, 0); 2];
        for ((slot, maps), name) in programs.iter_mut().zip(&mut members).zip(["dut0", "dut1"]) {
            let device = fixture
                .runtime
                .devices
                .iter()
                .find(|device| device.info.name == name)
                .context("fixture member")?;
            *slot = honk_xsk::xdp_state(device.info.ifindex)?.prog_id;
            let program = aya::programs::loaded_programs()
                .filter_map(Result::ok)
                .find(|program| program.id() == *slot)
                .context("attached XDP program")?;
            let mut facts = None;
            let mut epochs = None;
            let mut guards = None;
            let mut control = None;
            let mut mode = None;
            for id in program.map_ids()?.context("attached program map IDs")? {
                match MapInfo::from_id(id)?.name_as_str() {
                    Some("dns_facts") => facts = Some(id),
                    Some("dns_epochs") => epochs = Some(id),
                    Some("honk_gw_guards") => guards = Some(id),
                    Some("honk_gw_ctl") => control = Some(id),
                    Some("honk_gw_mode") => mode = Some(id),
                    _ => {}
                }
            }
            ensure!(
                facts.is_some() == epochs.is_some(),
                "partial DNS bank on {name}"
            );
            ensure!(
                guards.is_some() == control.is_some(),
                "partial arbitration on {name}"
            );
            ensure!(
                facts.is_none() || guards.is_some(),
                "DNS bank without arbitration on {name}"
            );
            let bank = epochs
                .zip(facts)
                .map(|(epochs, facts)| BankMaps { epochs, facts });
            *maps = (bank, guards.zip(control), mode.context("gateway mode map")?);
        }
        assert_eq!(
            members[0], members[1],
            "gateway members disagree on map identity"
        );
        let (bank, arbitration, mode) = members[0];
        Ok(Self {
            programs,
            bank,
            arbitration,
            mode,
        })
    }

    fn last_issued(&self) -> anyhow::Result<u64> {
        let (_, control) = self.arbitration.context("attached arbitration maps")?;
        let control = Array::<_, [u64; 8]>::try_from(Map::Array(MapData::from_id(control)?))?;
        Ok(control.get(&0, 0)?[1])
    }
}

fn realm(fixture: &Fixture, name: &str) -> anyhow::Result<u32> {
    fixture
        .runtime
        .realms
        .iter()
        .find(|realm| fixture.runtime.devices[realm.device].info.name == name)
        .map(|realm| realm.realm_id)
        .context("fixture realm")
}

fn config(hosts: &tempfile::NamedTempFile) -> anyhow::Result<Config> {
    let mut config = honk_config::parser::parse_dae_config(
        "global { dial_mode: ip\n nfqueue_enable: false\n so_mark_from_dae: 0x100 }
         dns { bind: '' }
         datapath { backend: xdp\n direct: endpoint\n xsk_mode: copy\n interface { dut0: lan\n dut1: wan } }
         routing { domain(full: shadow-reload.test) -> direct(must)\n dip(198.51.100.99/32) && dport(53) -> direct\n fallback: block }",
    )?;
    config.dns.hosts = vec![hosts.path().to_str().context("hosts path encoding")?.into()];
    Ok(config)
}

fn write_hosts(hosts: &tempfile::NamedTempFile, ip: Ipv4Addr) -> io::Result<()> {
    std::fs::write(hosts.path(), format!("full:{NAME} {ip}\n"))
}

async fn query(fixture: &mut Fixture, ip: Ipv4Addr) -> anyhow::Result<()> {
    let query = crate::dns::forwarder::build_dns_query(NAME, 1);
    let encoded = STANDARD.encode(&query);
    let output = fixture
        .drive(async {
            Ok(Command::new("ip")
                .args(["netns", "exec", "client", "python3", "-c"])
                .arg(
                    r#"
import base64, socket, sys
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind(('192.0.2.2', 0))
    s.connect(('198.51.100.99', 53))
    s.settimeout(4)
    s.send(base64.b64decode(sys.argv[1]))
    sys.stdout.buffer.write(s.recv(4096))
"#,
                )
                .arg(encoded)
                .kill_on_drop(true)
                .output()
                .await?)
        })
        .await?;
    ensure!(
        output.status.success(),
        "client DNS exchange failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout.get(..2), query.get(..2));
    assert_eq!(
        crate::dns::forwarder::extract_answer_ips(&output.stdout),
        [IpAddr::V4(ip)]
    );
    Ok(())
}

async fn begin_reload(
    fixture: &Fixture,
    config: Config,
) -> anyhow::Result<oneshot::Receiver<ReloadReply>> {
    let (result, reply) = oneshot::channel();
    let request_id = fixture.diagnostics.read().generation + 1;
    fixture
        .commands
        .send(ControlCommand::ReloadConfig {
            request_id,
            config: Box::new(config),
            diagnostics: Vec::new(),
            #[cfg(feature = "native-api")]
            sources: None,
            #[cfg(feature = "native-api")]
            expected_group_revision: None,
            result,
        })
        .await?;
    Ok(reply)
}

async fn reload(fixture: &mut Fixture, config: Config) -> anyhow::Result<()> {
    let generation = fixture.diagnostics.read().generation;
    let reply = begin_reload(fixture, config).await?;
    let outcome = fixture.drive(async { Ok(reply.await?.outcome) }).await?;
    assert_eq!(
        outcome,
        ReloadOutcome::Committed {
            generation: generation + 1
        }
    );
    assert_eq!(fixture.diagnostics.read().generation, generation + 1);
    Ok(())
}

async fn assert_fact(
    fixture: &mut Fixture,
    bank: BankMaps,
    lan: u32,
    ip: Ipv4Addr,
) -> anyhow::Result<u64> {
    query(fixture, ip).await?;
    let epoch = bank.epoch(lan)?;
    ensure!(
        epoch != 0,
        "LAN bank is closed after an accepted DNS answer"
    );
    let fact = bank
        .fact(lan, epoch, ip)?
        .context("accepted DNS answer missing from the live kernel epoch")?;
    assert_ne!(fact.bitmap, Default::default());
    Ok(epoch)
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces and real Endpoint AF_XDP"]
async fn shadow_hosts_reload_keeps_kernel_bank_and_rebinds_generation() -> anyhow::Result<()> {
    timeout(LIMIT, async {
        let hosts = tempfile::NamedTempFile::new()?;
        write_hosts(&hosts, OLD_IP)?;
        let mut fixture = Fixture::start_config(config(&hosts)?).await?;
        let lan = realm(&fixture, "dut0")?;
        let wan = realm(&fixture, "dut1")?;
        let before = Attached::read(&fixture)?;
        let bank = before.bank.context("startup must attach a shadow bank")?;
        let publisher = fixture.runtime.gateway.as_ref().context("gateway")?.clone();
        let plan = ControlPlane::compile_routing_plan(
            &fixture.config,
            &Router::from_config(&fixture.config.routing)?,
        )?;
        assert_eq!(publisher.fingerprint(), plan.fingerprint);
        assert_eq!(bank.epoch(wan)?, 0);
        let epoch = assert_fact(&mut fixture, bank, lan, OLD_IP).await?;

        // The only changed input is the content of the already configured hosts source.
        write_hosts(&hosts, NEW_IP)?;
        let same_config = fixture.config.clone();
        reload(&mut fixture, same_config).await?;
        assert_eq!(Attached::read(&fixture)?, before);
        assert_eq!(publisher.fingerprint(), plan.fingerprint);
        let reloaded = bank.epoch(lan)?;
        assert!(reloaded > epoch);
        assert_eq!(bank.epoch(wan)?, 0);
        assert_eq!(bank.fact(lan, reloaded, OLD_IP)?, None);
        let written = assert_fact(&mut fixture, bank, lan, NEW_IP).await?;
        assert!(written >= reloaded);
        assert_eq!(bank.fact(lan, written, OLD_IP)?, None);

        fixture.finish().await
    })
    .await
    .context("bounded hosts-only shadow publication")?
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces and real Endpoint AF_XDP"]
async fn shadow_staged_rollback_retires_memory_and_reopens_fresh_epoch() -> anyhow::Result<()> {
    timeout(LIMIT, async {
        let hosts = tempfile::NamedTempFile::new()?;
        write_hosts(&hosts, OLD_IP)?;
        let domain = config(&hosts)?;
        let mut static_config = domain.clone();
        static_config.routing.rules.clear();
        let mut fixture = Fixture::start_config(static_config).await?;
        let baseline = fixture.config.clone();
        let lan = realm(&fixture, "dut0")?;
        let wan = realm(&fixture, "dut1")?;
        let budget = fixture.runtime.polling_budget.clone();
        let pristine = Attached::read(&fixture)?;
        assert_eq!((pristine.bank, pristine.arbitration), (None, None));
        fixture.runtime.endpoints.reap_completed_udp_tasks();
        let static_used = budget.used();
        let mut domain_config = baseline.clone();
        domain_config.routing = domain.routing;
        reload(&mut fixture, domain_config.clone()).await?;
        let publisher = fixture.runtime.gateway.as_ref().context("gateway")?.clone();
        let old = Attached::read(&fixture)?;
        let old_bank = old
            .bank
            .context("domain reload must attach a shadow bank")?;
        let old_epoch = assert_fact(&mut fixture, old_bank, lan, OLD_IP).await?;
        let old_generation = fixture.diagnostics.read().generation;
        let old_fingerprint = publisher.fingerprint();
        let old_plan = ControlPlane::compile_routing_plan(
            &domain_config,
            &Router::from_config(&domain_config.routing)?,
        )?;
        assert_eq!(old_fingerprint, old_plan.fingerprint);

        let mut candidate = domain_config;
        candidate
            .groups
            .iter_mut()
            .find(|group| group.name == "packet-proof")
            .context("fixture group")?
            .name = "renamed-packet-proof".into();
        let next = ControlPlane::compile_routing_plan(
            &candidate,
            &Router::from_config(&candidate.routing)?,
        )?;
        assert_eq!(next.policy_fingerprint, old_plan.policy_fingerprint);
        assert_ne!(next.fingerprint, old_fingerprint);
        let backend = fixture.backend.write().await;
        let old_used = budget.used();

        // Exercise the real link-update and rollback entry points. A malformed
        // ControlPlane candidate would be rejected before it reached either.
        publisher.publish(&next)?;
        let staged = Attached::read(&fixture)?;
        let staged_bank = staged.bank.context("candidate must attach a shadow bank")?;
        assert_eq!(staged.arbitration, old.arbitration);
        assert_ne!(staged.programs, old.programs);
        assert_ne!(staged_bank.epochs, old_bank.epochs);
        assert_ne!(staged_bank.facts, old_bank.facts);
        assert_eq!(publisher.fingerprint(), next.fingerprint);
        assert_eq!(fixture.diagnostics.read().generation, old_generation);
        assert_eq!(old_bank.epoch(lan)?, 0);
        assert_eq!(staged_bank.epoch(lan)?, 0);
        assert_eq!(staged_bank.epoch(wan)?, 0);
        assert!(
            budget.used() > old_used,
            "overlapping generations must both be charged"
        );

        publisher.rollback()?;
        assert_eq!(Attached::read(&fixture)?, old);
        assert_eq!(publisher.fingerprint(), old_fingerprint);
        assert_eq!(fixture.diagnostics.read().generation, old_generation);
        assert_eq!(
            budget.used(),
            old_used,
            "discarded candidate retained capture memory"
        );
        let restored = old_bank.epoch(lan)?;
        assert!(restored > old_epoch, "rollback resurrected an old epoch");
        assert_eq!(old_bank.fact(lan, restored, OLD_IP)?, None);
        drop(backend);
        assert!(assert_fact(&mut fixture, old_bank, lan, OLD_IP).await? >= restored);

        reload(&mut fixture, candidate).await?;
        let committed = Attached::read(&fixture)?;
        let new_bank = committed
            .bank
            .context("committed fingerprint must attach a shadow bank")?;
        assert_ne!(committed.programs, old.programs);
        assert_ne!(new_bank.epochs, old_bank.epochs);
        assert_ne!(new_bank.facts, old_bank.facts);
        assert_eq!(publisher.fingerprint(), next.fingerprint);
        assert_eq!(new_bank.epoch(wan)?, 0);
        assert_fact(&mut fixture, new_bank, lan, OLD_IP).await?;
        assert_eq!(committed.arbitration, old.arbitration);
        let last_issued = committed.last_issued()?;
        ensure!(last_issued > 0, "DNS query did not establish a managed Endpoint hold");

        reload(&mut fixture, baseline).await?;
        let pristine = Attached::read(&fixture)?;
        assert_eq!((pristine.bank, pristine.arbitration), (None, None));
        // A delivered DNS reply can leave its completed task charged until the next ingress joins it.
        let before_join = budget.used();
        fixture.runtime.endpoints.reap_completed_udp_tasks();
        let after_join = budget.used();
        println!("static capture budget: original={static_used} before_udp_join={before_join} after_udp_join={after_join}");
        assert_eq!(
            after_join,
            static_used,
            "retired static or shadow generations retained capture memory"
        );
        timeout(Duration::from_secs(5), async {
            while !(staged_bank.retired()? && old_bank.retired()? && new_bank.retired()?) {
                sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("retired generations still hold kernel maps")??;
        {
            let _backend = fixture.backend.write().await;
            publisher.publish(&next)?;
            let staged = Attached::read(&fixture)?;
            assert_ne!(staged.arbitration, committed.arbitration);
            assert!(staged.last_issued()? >= last_issued);
            assert_eq!(staged.bank.context("restaged bank")?.epoch(lan)?, 0);
            publisher.rollback()?;
            assert_eq!(Attached::read(&fixture)?, pristine);
            assert_eq!(budget.used(), static_used);
        }
        fixture.finish().await
    })
    .await
    .context("bounded staged shadow rollback and recovery")?
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces and real Endpoint AF_XDP"]
async fn native_pending_survives_static_downshift_until_idle_retirement() -> anyhow::Result<()> {
    timeout(Duration::from_secs(100), pending::downshift())
        .await
        .context("bounded pending downshift and real idle sweep")?
}

#[tokio::test]
#[ignore = "requires the disposable gateway guest with both real UDP peer paths"]
async fn udp_quic_early_native_and_revoke() -> anyhow::Result<()> {
    super::guard();
    timeout(Duration::from_secs(120), quic_udp::run())
        .await
        .context("bounded QUIC early-data and DNS revocation cases")?
}

#[tokio::test]
#[ignore = "requires the disposable gateway guest, DUT NAPI tracing and the real attached owner maps"]
async fn udp_native_one_queue_batch_and_quota_delivery() -> anyhow::Result<()> {
    super::guard();
    timeout(Duration::from_secs(140), batch_udp::run())
        .await
        .context("bounded UDP batch and Endpoint delivery at capacity")?
}

fn freeze_mode_map(id: u32) -> anyhow::Result<()> {
    let map = MapData::from_id(id)?;
    let fd = map.fd().as_fd().as_raw_fd() as u32;
    // SAFETY: the attribute is an initialized map FD held by `map`. The
    // attached program IDs scoped this map to the fixture-owned gateway.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            aya_obj::generated::bpf_cmd::BPF_MAP_FREEZE as u32,
            &fd,
            size_of_val(&fd),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error()).context("freeze fixture gateway mode map");
    }
    Ok(())
}

async fn wait_for_queued_writer<T>(
    lock: &RwLock<T>,
    reply: &mut oneshot::Receiver<ReloadReply>,
) -> anyhow::Result<()> {
    while lock.try_read().is_ok() {
        tokio::select! {
            result = &mut *reply => {
                anyhow::bail!("reload ended before its publication barrier: {:?}", result?.outcome);
            }
            () = sleep(Duration::from_millis(1)) => {}
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces and real Endpoint AF_XDP"]
async fn shadow_committed_degraded_closes_kernel_bank() -> anyhow::Result<()> {
    timeout(LIMIT, async {
        let hosts = tempfile::NamedTempFile::new()?;
        write_hosts(&hosts, OLD_IP)?;
        let mut fixture = Fixture::start_config(config(&hosts)?).await?;
        let lan = realm(&fixture, "dut0")?;
        let wan = realm(&fixture, "dut1")?;
        let before = Attached::read(&fixture)?;
        let bank = before.bank.context("startup must attach a shadow bank")?;
        assert_fact(&mut fixture, bank, lan, OLD_IP).await?;
        let generation = fixture.diagnostics.read().generation;

        // Freezing before the queued router writer would reject preflight.
        let router = fixture.router.clone();
        let backend = fixture.backend.clone();
        let router_read = router.read().await;
        let diagnostics = fixture.diagnostics.clone();
        write_hosts(&hosts, NEW_IP)?;
        let mut reply = begin_reload(&fixture, fixture.config.clone()).await?;
        let outcome = fixture
            .drive(async {
                wait_for_queued_writer(&router, &mut reply).await?;
                freeze_mode_map(before.mode)?;
                let precommit = backend.read().await;
                drop(router_read);
                wait_for_queued_writer(&backend, &mut reply).await?;

                // Queue behind the commit writer so the failed late write
                // cannot hide a transiently open epoch.
                let postcommit = backend.read();
                tokio::pin!(postcommit);
                assert!(futures::poll!(postcommit.as_mut()).is_pending());
                drop(precommit);
                let postcommit = postcommit.await;
                assert_eq!(diagnostics.read().generation, generation + 1);
                assert_eq!(bank.epoch(lan)?, 0);
                drop(postcommit);
                Ok(reply.await?.outcome)
            })
            .await?;
        assert_eq!(
            outcome,
            ReloadOutcome::CommittedDegraded {
                generation: generation + 1
            }
        );
        assert_eq!(fixture.diagnostics.read().generation, generation + 1);
        assert_eq!(Attached::read(&fixture)?, before);
        assert_eq!(bank.epoch(lan)?, 0);
        assert_eq!(bank.epoch(wan)?, 0);
        fixture.finish().await
    })
    .await
    .context("bounded real mode-map publication failure")?
}

fn compile(config: &Config) -> anyhow::Result<RoutingPushPlan> {
    ControlPlane::compile_routing_plan(config, &Router::from_config(&config.routing)?)
}

fn activate_capture(
    fixture: &Fixture,
    backend: &mut dyn PolicyBackend,
    plan: &RoutingPushPlan,
    generation: u64,
) -> anyhow::Result<()> {
    let publisher = fixture.runtime.gateway.as_ref().context("gateway")?;
    fixture.runtime.activate_capture(
        &fixture.shutdown,
        fixture
            .config
            .datapath
            .as_ref()
            .and_then(|datapath| datapath.direct),
    )?;
    backend.activate_gateway_start(publisher, plan.fingerprint, generation)?;
    fixture
        .runtime
        .diagnostics
        .lifecycle(crate::stats::xdp::Lifecycle::Active);
    Ok(())
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces and real Endpoint AF_XDP"]
async fn shadow_late_gateway_registration_waits_for_final_flags() -> anyhow::Result<()> {
    for (flags_fail, capture_first, stop_before_flags) in [
        (false, true, false),
        (false, false, false),
        (true, true, false),
        (false, true, true),
    ] {
        timeout(LIMIT, async {
            let hosts = tempfile::NamedTempFile::new()?;
            write_hosts(&hosts, OLD_IP)?;
            let fixture = Fixture::start_config_inner(config(&hosts)?, true).await?;
            let lan = realm(&fixture, "dut0")?;
            let wan = realm(&fixture, "dut1")?;
            let publisher = fixture.runtime.gateway.as_ref().context("gateway")?;
            let plan = compile(&fixture.config)?;
            let generation = fixture.diagnostics.read().generation + 1;

            let router_read = fixture.router.read().await;
            write_hosts(&hosts, NEW_IP)?;
            let mut reply = begin_reload(&fixture, fixture.config.clone()).await?;
            wait_for_queued_writer(&fixture.router, &mut reply).await?;
            let precommit = fixture.backend.read().await;
            drop(router_read);
            wait_for_queued_writer(&fixture.backend, &mut reply).await?;

            // Queue registration between canonical commit and the final flags write.
            let mut writer = {
                let postcommit = fixture.backend.write();
                tokio::pin!(postcommit);
                assert!(futures::poll!(postcommit.as_mut()).is_pending());
                drop(precommit);
                postcommit.await
            };
            assert!(writer.userspace_mut()?.gateway().is_none());
            assert_eq!(fixture.diagnostics.read().generation, generation);
            publisher.prepare_start(&plan)?;
            writer.install_gateway(Some(publisher.clone()))?;
            publisher.commit();
            let attached = Attached::read(&fixture)?;
            let bank = attached
                .bank
                .context("late startup must attach a shadow bank")?;
            assert_eq!(bank.epoch(lan)?, 0);
            if flags_fail {
                freeze_mode_map(attached.mode)?;
            }
            if capture_first {
                activate_capture(&fixture, writer.as_mut(), &plan, generation)?;
                assert_eq!(bank.epoch(lan)?, 0, "startup preceded final flags");
            }
            if stop_before_flags {
                fixture.shutdown.request();
                publisher.stop_dns();
            }
            drop(writer);

            let outcome = reply.await?.outcome;
            if flags_fail {
                assert_eq!(outcome, ReloadOutcome::CommittedDegraded { generation });
                assert_eq!(bank.epoch(lan)?, 0);
                assert_eq!(
                    fixture.runtime.diagnostics.json(false)["dns_projection_reason"],
                    "committed_degraded"
                );
            } else {
                assert_eq!(outcome, ReloadOutcome::Committed { generation });
                if !capture_first {
                    assert_eq!(bank.epoch(lan)?, 0, "final flags preceded capture");
                    let mut writer = fixture.backend.write().await;
                    activate_capture(&fixture, writer.as_mut(), &plan, generation)?;
                }
                assert_eq!(bank.epoch(lan)? != 0, !stop_before_flags);
            }
            let epoch = bank.epoch(lan)?;
            {
                let mut writer = fixture.backend.write().await;
                let backend = writer.userspace_mut()?;
                backend.finish_gateway_dns_reload(generation - 1, plan.fingerprint)?;
                backend.finish_gateway_dns_reload(generation, plan.fingerprint)?;
                writer.activate_gateway_start(publisher, plan.fingerprint, generation)?;
            }
            assert_eq!(bank.epoch(lan)?, epoch, "settled generation reopened");
            assert_eq!(bank.epoch(wan)?, 0);
            fixture.finish().await
        })
        .await
        .context("bounded late gateway registration")??;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires the daemon smoke's private disposable-VM namespaces and real Endpoint AF_XDP"]
async fn shadow_optional_preparation_retains_complete_static_policy() -> anyhow::Result<()> {
    timeout(LIMIT, async {
        let hosts = tempfile::NamedTempFile::new()?;
        write_hosts(&hosts, OLD_IP)?;
        let mut config = config(&hosts)?;
        // Static D1 stops at the domain barrier. Shadow must emit the later rule,
        // whose port ranges exceed the assembler's 16-bit jump distance.
        let mut long_rule = config.routing.rules[0].clone();
        long_rule.priority = config.routing.rules.last().unwrap().priority + 1;
        long_rule.condition = honk_config::routing::RoutingCondition {
            port: (1000..10000).map(|port| port.to_string()).collect(),
            ..Default::default()
        };
        let long_rule_index = config.routing.rules.len();
        config.routing.rules.push(long_rule);
        let mut fixture = Fixture::start_config_inner(config, true).await?;
        let initial = compile(&fixture.config)?;
        let publisher = fixture.runtime.gateway.as_ref().context("gateway")?.clone();
        let early = Attached::read(&fixture)?;
        assert_eq!(early.bank, None);
        {
            let mut writer = fixture.backend.write().await;
            publisher.prepare_start(&initial)?;
            writer.install_gateway(Some(publisher.clone()))?;
            publisher.commit();
            activate_capture(
                &fixture,
                writer.as_mut(),
                &initial,
                fixture.diagnostics.read().generation,
            )?;
        }
        assert_eq!(
            Attached::read(&fixture)?,
            early,
            "startup replaced working static links"
        );
        assert_eq!(
            fixture.runtime.diagnostics.json(false)["dns_projection_reason"],
            "policy_prepare"
        );

        let mut candidate = fixture.config.clone();
        candidate.routing.rules[long_rule_index].condition.port[0] = "10000".into();
        let next = compile(&candidate)?;
        assert_ne!(next.fingerprint, initial.fingerprint);
        reload(&mut fixture, candidate.clone()).await?;
        let reloaded = Attached::read(&fixture)?;
        assert_eq!(reloaded.bank, None);
        assert_ne!(reloaded.programs, early.programs);
        assert_eq!(publisher.fingerprint(), next.fingerprint);
        assert_eq!(
            fixture.runtime.diagnostics.json(false)["dns_projection_reason"],
            "policy_prepare"
        );

        // The same rule now precedes the domain barrier and is required in static D1.
        candidate.routing.rules[long_rule_index].priority = candidate.routing.rules[0].priority;
        candidate.routing.rules.swap(0, long_rule_index);
        let generation = fixture.diagnostics.read().generation;
        let reply = begin_reload(&fixture, candidate).await?;
        assert_eq!(
            fixture.drive(async { Ok(reply.await?.outcome) }).await?,
            ReloadOutcome::Rejected
        );
        assert_eq!(fixture.diagnostics.read().generation, generation);
        assert_eq!(Attached::read(&fixture)?, reloaded);
        assert_eq!(publisher.fingerprint(), next.fingerprint);
        fixture.finish().await
    })
    .await
    .context("bounded static fallback for optional preparation failure")?
}

use super::*;
use honk_ebpf_common::xdp_gateway::{GatewayKey, GatewayReason, HOLD_SEQUENCE_MAX};
use std::{net::SocketAddrV4, process::Command};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const SPORT: u16 = 41984;
const DPORT: u16 = 18984;

struct SynDrop(String);

impl SynDrop {
    fn install() -> anyhow::Result<Self> {
        let name = format!("honk_pending_{}", std::process::id());
        let commands = format!(
            "create table inet {name}\n\
             add chain inet {name} raw {{ type filter hook prerouting priority -300; policy accept; }}\n\
             add counter inet {name} syn_packets\n\
             add rule inet {name} raw iifname dut0 ip saddr {CLIENT} ip daddr {OLD_IP} tcp sport {SPORT} tcp dport {DPORT} tcp flags & (fin | syn | rst | ack) == syn counter name syn_packets drop"
        );
        let output = Command::new("nft").arg(commands).output()?;
        ensure!(
            output.status.success(),
            "install pre-CT SYN drop: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(Self(name))
    }

    fn packets(&self) -> anyhow::Result<u64> {
        let output = Command::new("nft")
            .args(["-j", "list", "counter", "inet", &self.0, "syn_packets"])
            .output()?;
        ensure!(
            output.status.success(),
            "read pre-CT SYN counter: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let counters: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        counters["nftables"]
            .as_array()
            .context("nft counters")?
            .iter()
            .find(|entry| entry["counter"]["name"] == "syn_packets")
            .and_then(|entry| entry["counter"]["packets"].as_u64())
            .context("fixture SYN counter")
    }
}

impl Drop for SynDrop {
    fn drop(&mut self) {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", &self.0])
            .output();
    }
}

fn emit_client_syn() -> anyhow::Result<()> {
    // The namespace switch ends with this thread. Close before TCP's first retry.
    std::thread::spawn(|| -> anyhow::Result<()> {
        let client = std::fs::File::open("/run/netns/client")?;
        nix::sched::setns(client, nix::sched::CloneFlags::CLONE_NEWNET)?;
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.bind(&SocketAddrV4::new(CLIENT, SPORT).into())?;
        let error = socket
            .connect_timeout(
                &SocketAddrV4::new(OLD_IP, DPORT).into(),
                Duration::from_millis(200),
            )
            .expect_err("fixture SYN should be dropped before conntrack");
        ensure!(
            error.kind() == io::ErrorKind::TimedOut,
            "unexpected client socket error: {error}"
        );
        Ok(())
    })
    .join()
    .map_err(|_| anyhow::anyhow!("client SYN sender panicked"))?
}

pub(super) async fn downshift() -> anyhow::Result<()> {
    let hosts = tempfile::NamedTempFile::new()?;
    write_hosts(&hosts, OLD_IP)?;
    let mut static_config = config(&hosts)?;
    let domain_rules = std::mem::take(&mut static_config.routing.rules);
    let mut fixture = Fixture::start_config(static_config).await?;
    let syn_drop = SynDrop::install()?;
    let budget = fixture.runtime.polling_budget.clone();
    fixture.runtime.endpoints.reap_completed_udp_tasks();
    let static_used = budget.used();
    let baseline = fixture.config.clone();
    let mut domain = baseline.clone();
    domain.routing.rules = domain_rules;
    let plan = compile(&domain)?;
    reload(&mut fixture, domain).await?;
    let lan = realm(&fixture, "dut0")?;
    let active = Attached::read(&fixture)?;
    let bank = active.bank.context("active DNS bank")?;
    let (guards, control_id) = active.arbitration.context("active arbitration")?;
    let control = Array::<_, [u64; 8]>::try_from(Map::Array(MapData::from_id(control_id)?))?;
    assert_fact(&mut fixture, bank, lan, OLD_IP).await?;
    assert_eq!(control.get(&0, 0)?[0], 0);
    let maps = fixture
        .runtime
        .gateway_maps
        .clone()
        .context("gateway maps")?;
    let key = GatewayKey {
        realm_id: lan,
        family: 4,
        src: CLIENT.to_ipv6_mapped().octets(),
        dst: OLD_IP.to_ipv6_mapped().octets(),
        sport: SPORT.to_be(),
        dport: DPORT.to_be(),
        proto: libc::IPPROTO_TCP as u8,
        reserved: [0; 3],
    };
    assert_eq!(maps.lookup_hold(&key)?, None);
    let passes = maps.reason_count(GatewayReason::PassDnsD1)?;
    let sent = std::time::Instant::now();
    emit_client_syn()?;
    assert_eq!(syn_drop.packets()?, 1);
    assert_eq!(maps.reason_count(GatewayReason::PassDnsD1)?, passes + 1);
    let pending = maps
        .lookup_hold(&key)?
        .context("DNS SYN did not acquire its tuple")?;
    assert!(pending.is_native_pending());
    assert_eq!(control.get(&0, 0)?[0], 1);

    reload(&mut fixture, baseline).await?;
    let draining = Attached::read(&fixture)?;
    assert_eq!(draining.bank, None);
    assert_eq!(draining.arbitration, active.arbitration);
    assert_eq!(control.get(&0, 0)?[0], 1);
    assert_eq!(maps.lookup_hold(&key)?, Some(pending));
    fixture
        .drive(async {
            while maps.lookup_hold(&key)?.is_some() || !maps_retired(&[guards])? {
                sleep(Duration::from_millis(100)).await;
            }
            Ok(())
        })
        .await?;
    assert!(sent.elapsed() >= crate::xdp::gateway::hold::HOLD_IDLE);
    assert_eq!(syn_drop.packets()?, 1);
    let final_control = control.get(&0, 0)?;
    assert_eq!(final_control[0], 0);
    assert!(final_control[1] >= (pending.stamp & HOLD_SEQUENCE_MAX));
    drop(control);
    let pristine = Attached::read(&fixture)?;
    assert_eq!((pristine.bank, pristine.arbitration), (None, None));
    while !maps_retired(&[guards, control_id])? {
        sleep(Duration::from_millis(10)).await;
    }
    fixture.runtime.endpoints.reap_completed_udp_tasks();
    assert_eq!(budget.used(), static_used);
    {
        let _backend = fixture.backend.write().await;
        let publisher = fixture.runtime.gateway.as_ref().context("gateway")?;
        publisher.publish(&plan)?;
        let next = Attached::read(&fixture)?;
        assert_ne!(next.arbitration, active.arbitration);
        assert!(next.last_issued()? >= final_control[1]);
        publisher.rollback()?;
        assert_eq!(Attached::read(&fixture)?, pristine);
        assert_eq!(budget.used(), static_used);
    }
    drop(syn_drop);
    fixture.finish().await
}

use super::*;
use crate::ebpf::real::{btf::Btf, syscall::bpf_syscall};
use aya_obj::generated::{bpf_attr, bpf_cmd::BPF_PROG_TEST_RUN};
use honk_ebpf_common::xdp_gateway::{
    GatewayKey, GatewayReason, HOLD_MANAGED, HOLD_SEQUENCE_MAX, NATIVE_PENDING_CAP,
};
use std::{collections::BTreeMap, net::SocketAddr, os::fd::BorrowedFd, path::PathBuf};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const PORT: u16 = 18275;
const QUOTA_CLIENT: u16 = 42064;

fn peer(mode: &str, program: u32, sport: u16) -> anyhow::Result<std::process::Command> {
    let path = PathBuf::from(std::env::var_os("HONK_XDP_DNS_PROBE").context("guest DNS probe")?)
        .with_file_name("xdp_dns_udp_batch.py");
    let mut command = std::process::Command::new("python3");
    command.arg(path).args([
        mode,
        &program.to_string(),
        &sport.to_string(),
        &PORT.to_string(),
    ]);
    Ok(command)
}

fn batch(attached: &Attached) -> anyhow::Result<()> {
    // These are the only kernel fields the private trace events dereference. Resolve
    // each against this guest's actual BTF before registering any probe.
    let raw = std::fs::read("/sys/kernel/btf/vmlinux")?;
    let btf = Btf::parse(&raw).context("running kernel BTF")?;
    let mut offsets = std::collections::BTreeMap::new();
    for (ty, field, size) in [
        ("napi_struct", "dev", 8),
        ("napi_struct", "napi_id", 4),
        ("xdp_buff", "data", 8),
        ("xdp_buff", "data_end", 8),
        ("xdp_buff", "rxq", 8),
        ("xdp_rxq_info", "dev", 8),
        ("xdp_rxq_info", "queue_index", 4),
        ("net_device", "ifindex", 4),
        ("net_device", "name", libc::IFNAMSIZ as u32),
        ("sk_buff", "data", 8),
        ("sk_buff", "dev", 8),
        ("sk_buff", "len", 4),
        ("sk_buff", "data_len", 4),
    ] {
        let offset = btf
            .sized_member_offset(ty, field, size)
            .with_context(|| format!("missing {ty}.{field} ({size} bytes)"))?;
        offsets.insert(format!("{ty}.{field}"), offset);
    }
    // The original-source exchange must complete entirely through the kernel. A
    // synchronous child also keeps its trace cleanup joined on socket or trace failure.
    let status = peer("batch", attached.programs[0], QUOTA_CLIENT - 1)?
        .arg(serde_json::to_string(&offsets)?)
        .status()?;
    ensure!(
        status.success(),
        "guest one-queue poll/GRO observation failed: {status}"
    );
    Ok(())
}

fn decision_maps(program: u32) -> anyhow::Result<BTreeMap<u32, String>> {
    let info = aya::programs::loaded_programs()
        .filter_map(Result::ok)
        .find(|item| item.id() == program)
        .context("quota data program ID")?;
    ensure!(
        info.name_as_str() == Some("honk_gw_data"),
        "unexpected quota program {program}"
    );
    let mut maps = BTreeMap::new();
    for id in info.map_ids()?.context("quota data program map IDs")? {
        let info = MapInfo::from_id(id)?;
        let name = info.name_as_str().context("kernel map name encoding")?;
        // The detached loader owns its queue-local maps. All other IDs, including
        // unnamed policy LPM maps, must agree with the attached data program.
        if !matches!(name, "honk_xdp_count" | "honk_xdp_xsks") {
            maps.insert(id, name.to_owned());
        }
    }
    for required in [
        "honk_gw_hold",
        "honk_gw_guards",
        "honk_gw_ctl",
        "dns_facts",
        "dns_epochs",
        "honk_gw_realms",
        "honk_gw_stats",
        "honk_gw_mode",
    ] {
        ensure!(
            maps.values().any(|name| name == required),
            "{program} lacks {required}"
        );
    }
    Ok(maps)
}

fn fill(program: BorrowedFd<'_>, ifindex: u32) -> anyhow::Result<()> {
    let mut frame = [0u8; 60];
    frame[..14].copy_from_slice(&[2, 0, 0, 0, 0, 16, 2, 0, 0, 0, 0, 32, 8, 0]);
    let context = [0u32, frame.len() as u32, 0, ifindex, 0, 0];
    let destination = SocketAddr::from((OLD_IP, PORT));
    for offset in 0..u16::try_from(NATIVE_PENDING_CAP)? {
        let source = SocketAddr::from((CLIENT, 20_000 + offset));
        honk_netstack::wire::udp::emit_packet(&mut frame[14..], source, destination, &[1])
            .context("fixture UDP packet extent")?;
        // SAFETY: all unused bpf_attr fields are zero. TEST_RUN reads only the
        // live frame and xdp_md for this synchronous call. No live-frame flag.
        let mut attr: bpf_attr = unsafe { std::mem::zeroed() };
        attr.test.prog_fd = program.as_raw_fd() as u32;
        attr.test.data_size_in = frame.len() as u32;
        attr.test.data_in = frame.as_ptr() as u64;
        attr.test.ctx_size_in = size_of_val(&context) as u32;
        attr.test.ctx_in = context.as_ptr() as u64;
        attr.test.repeat = 1;
        let action = unsafe {
            bpf_syscall(BPF_PROG_TEST_RUN as _, &mut attr)
                .map_err(|errno| io::Error::from_raw_os_error(errno as i32))?;
            attr.test.retval
        };
        ensure!(
            action == 2,
            "non-live datagram {offset} returned XDP action {action}"
        );
    }
    Ok(())
}

async fn quota(fixture: &mut Fixture, attached: &Attached, lan: u32) -> anyhow::Result<()> {
    let (_, control) = attached.arbitration.context("attached LAN arbitration")?;
    let control = Array::<_, [u64; 8]>::try_from(Map::Array(MapData::from_id(control)?))?;
    let pending = || -> anyhow::Result<u64> { Ok(control.get(&0, 0)?[0]) };
    let maps = fixture
        .runtime
        .gateway_maps
        .clone()
        .context("gateway maps")?;
    let native = maps.reason_count(GatewayReason::PassDnsD1)?;
    let capped = maps.reason_count(GatewayReason::DnsNativePendingCapped)?;
    let overflow = GatewayKey {
        realm_id: lan,
        family: 4,
        src: CLIENT.to_ipv6_mapped().octets(),
        dst: OLD_IP.to_ipv6_mapped().octets(),
        sport: QUOTA_CLIENT.to_be(),
        dport: PORT.to_be(),
        proto: libc::IPPROTO_UDP as u8,
        reserved: [0; 3],
    };
    ensure!(
        pending()? == 0 && maps.lookup_hold(&overflow)?.is_none(),
        "quota baseline"
    );
    let ifindex = nix::net::if_::if_nametoindex("dut0")?;
    let live = attached.programs[0];
    let bank = attached.bank.context("attached LAN DNS bank")?;
    let epoch = bank.epoch(lan)?;
    ensure!(epoch != 0, "LAN DNS epoch is closed");
    let publisher = fixture
        .runtime
        .gateway
        .as_ref()
        .context("gateway publisher")?;
    let probe = publisher.unbound_quota_programs(ifindex, live)?;
    let unbound = probe.0.data_prog_id();
    ensure!(
        unbound != live,
        "non-live quota probe is the attached program"
    );
    let shared = decision_maps(live)?;
    ensure!(
        decision_maps(unbound)? == shared,
        "quota wrapper has different decision maps"
    );
    fill(probe.0.data_fd(), ifindex)?;
    drop(probe);
    ensure!(
        Attached::read(fixture)? == *attached && bank.epoch(lan)? == epoch,
        "gateway attachment or DNS epoch changed during the non-live quota fill"
    );
    let full = native + NATIVE_PENDING_CAP;
    ensure!(
        pending()? == NATIVE_PENDING_CAP && maps.reason_count(GatewayReason::PassDnsD1)? == full,
        "8,192 non-live single-datagram flows did not acquire their credits"
    );
    ensure!(
        maps.reason_count(GatewayReason::DnsNativePendingCapped)? == capped,
        "early quota refusal"
    );
    let issued_before_echo = attached.last_issued()?;
    ensure!(
        maps.lookup_hold(&overflow)?.is_none(),
        "actual echo tuple already has an owner"
    );
    let mut command = Command::from(peer("quota", attached.programs[0], QUOTA_CLIENT)?);
    let status = fixture
        .drive(async { Ok(command.kill_on_drop(true).status().await?) })
        .await?;
    ensure!(
        status.success(),
        "real at-capacity Endpoint exchange failed: {status}"
    );
    let owner = maps
        .lookup_hold(&overflow)?
        .context("missing real overflow flow")?;
    ensure!(
        owner.stamp & HOLD_MANAGED != 0
            && !owner.is_native_pending()
            && (owner.stamp & HOLD_SEQUENCE_MAX) > issued_before_echo,
        "overflow did not acquire a fresh Endpoint incarnation"
    );
    let after = maps.reason_count(GatewayReason::DnsNativePendingCapped)?;
    ensure!(
        pending()? == NATIVE_PENDING_CAP
            && maps.reason_count(GatewayReason::PassDnsD1)? == full
            && after == capped + 1
            && bank.epoch(lan)? == epoch,
        "overflow did not preserve native capacity and charge exactly one cap refusal"
    );
    println!(
        "UDP Endpoint echo at native capacity: attached={live} non_live={unbound} shared_maps={shared:?} realm={lan} epoch={epoch} native={NATIVE_PENDING_CAP} capped={capped}->{after} owner={owner:?}"
    );
    Ok(())
}

async fn observation(at_capacity: bool) -> anyhow::Result<()> {
    use futures::FutureExt as _;
    use std::panic::AssertUnwindSafe;

    let hosts = tempfile::NamedTempFile::new()?;
    write_hosts(&hosts, OLD_IP)?;
    let mut policy = config(&hosts)?;
    // At capacity, a fresh Endpoint may dial even if it has no userspace name.
    // Only the learned domain rule grants terminal native forwarding.
    policy.routing.default_outbound = "direct".into();
    let mut fixture = Fixture::start_config(policy).await?;
    let observed = AssertUnwindSafe(async {
        let attached = Attached::read(&fixture)?;
        let lan = realm(&fixture, "dut0")?;
        let bank = attached.bank.context("attached DNS bank")?;
        assert_fact(&mut fixture, bank, lan, OLD_IP).await?;
        if at_capacity {
            quota(&mut fixture, &attached, lan).await?;
        } else {
            let maps = fixture
                .runtime
                .gateway_maps
                .clone()
                .context("gateway maps")?;
            let native = maps.reason_count(GatewayReason::PassDnsD1)?;
            batch(&attached)?;
            ensure!(
                maps.reason_count(GatewayReason::PassDnsD1)? == native + 1,
                "fresh batch socket did not acquire one DNS-native owner"
            );
        }
        ensure!(
            Attached::read(&fixture)? == attached,
            "gateway attachment changed during observation"
        );
        anyhow::Ok(())
    })
    .catch_unwind()
    .await
    .map_err(|panic| {
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("fixture panic");
        anyhow::anyhow!("{message}")
    })
    .and_then(|result| result);
    let cleanup = fixture.finish().await;
    ensure!(
        observed.is_ok() && cleanup.is_ok(),
        "observation={observed:?}, fixture teardown={cleanup:?}"
    );
    Ok(())
}

pub(super) async fn run() -> anyhow::Result<()> {
    let batch = observation(false).await;
    let quota = observation(true).await;
    ensure!(
        batch.is_ok() && quota.is_ok(),
        "one-queue batch={batch:?}, Endpoint at capacity={quota:?}"
    );
    Ok(())
}

//! Netfilter TPROXY datapath for kernels or platforms without the eBPF one.
//!
//! iptables `mangle` rules divert configured LAN ingress with TPROXY and
//! re-mark host-originated traffic so one fwmark rule and a local default
//! route loop it back through PREROUTING. Transparent listeners stay in the
//! host netns. No kernel routing state exists: every flow reaches userspace,
//! where the ordinary `Router` decides, and direct flows are relayed rather
//! than offloaded. Every honk transparent socket keeps the bypass mark so its
//! own replies are never diverted again.

use std::io::Write as _;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context as _;
use tracing::{debug, info, warn};

pub(crate) mod process;
#[cfg(test)]
mod tests;

static HOST_TRANSPARENT: AtomicBool = AtomicBool::new(false);

/// Whether transparent listeners and reply sockets live in the host netns.
pub(crate) fn host_transparent() -> bool {
    HOST_TRANSPARENT.load(Ordering::Acquire)
}

/// Select host-netns transparent sockets; set before any listener binds.
pub(crate) fn enable_host_transparent() {
    HOST_TRANSPARENT.store(true, Ordering::Release);
}

/// Policy-routing table holding the local default route (`"ho"`).
pub(crate) const ROUTE_TABLE: u32 = 0x686f;
/// Below every Android netd rule (6000+) and the Linux main table (32766).
pub(crate) const RULE_PRIORITY: u32 = 5000;

const PREROUTING_CHAIN: &str = "HONK_PREROUTING";
const OUTPUT_CHAIN: &str = "HONK_OUTPUT";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    V4,
    V6,
}

impl Family {
    fn restore(self) -> &'static str {
        match self {
            Self::V4 => "iptables-restore",
            Self::V6 => "ip6tables-restore",
        }
    }

    fn iptables(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    fn netlink(self) -> u8 {
        match self {
            Self::V4 => libc::AF_INET as u8,
            Self::V6 => libc::AF_INET6 as u8,
        }
    }

    /// Never diverted: link-local, multicast and limited broadcast.
    fn special(self) -> &'static [&'static str] {
        match self {
            Self::V4 => &["169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"],
            Self::V6 => &["fe80::/10", "ff00::/8"],
        }
    }

    fn contains(self, address: IpAddr) -> bool {
        matches!(
            (self, address),
            (Self::V4, IpAddr::V4(_)) | (Self::V6, IpAddr::V6(_))
        )
    }

    fn host_prefix(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

/// How LAN packets to the gateway's own addresses are recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocalDestinations {
    /// `xt_addrtype`, which tracks address changes.
    Addrtype,
    /// Addresses present at install time, for kernels without `xt_addrtype`
    /// (Android's included): later addresses are diverted and relayed.
    Addresses(Vec<IpAddr>),
}

impl LocalDestinations {
    fn current() -> anyhow::Result<Self> {
        let mut addresses: Vec<IpAddr> = nix::ifaddrs::getifaddrs()
            .context("list interface addresses")?
            .filter_map(|interface| {
                let address = interface.address?;
                if let Some(v4) = address.as_sockaddr_in() {
                    Some(IpAddr::V4(v4.ip()))
                } else {
                    address.as_sockaddr_in6().map(|v6| IpAddr::V6(v6.ip()))
                }
            })
            .collect();
        addresses.sort();
        addresses.dedup();
        Ok(Self::Addresses(addresses))
    }
}

/// Where host traffic is diverted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostScope {
    /// No `wan_interface`: host-originated traffic is left alone.
    None,
    /// An `auto` entry: every output interface.
    All,
    Interfaces(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Settings {
    pub(crate) port: u16,
    pub(crate) tproxy_mark: u32,
    pub(crate) bypass_mark: u32,
    pub(crate) lan: Vec<String>,
    pub(crate) host: HostScope,
}

impl Settings {
    pub(crate) fn from_config(global: &honk_config::config::GlobalConfig) -> Self {
        let mut lan = Vec::new();
        for entry in &global.lan_interface {
            if honk_config::config::is_auto_interface(entry) {
                match honk_config::config::default_route_interface() {
                    Some(name) => lan.push(name),
                    None => warn!("lan_interface auto has no default-route interface yet"),
                }
            } else {
                lan.push(entry.trim().to_owned());
            }
        }
        lan.sort();
        lan.dedup();
        let host = if global.wan_interface.is_empty() {
            HostScope::None
        } else if global
            .wan_interface
            .iter()
            .any(|entry| honk_config::config::is_auto_interface(entry))
        {
            HostScope::All
        } else {
            let mut names: Vec<String> = global
                .wan_interface
                .iter()
                .map(|entry| entry.trim().to_owned())
                .collect();
            names.sort();
            names.dedup();
            HostScope::Interfaces(names)
        };
        Self {
            port: global.tproxy_port,
            tproxy_mark: global.tproxy_mark,
            bypass_mark: global.effective_so_mark(),
            lan,
            host,
        }
    }
}

/// `iptables-restore --noflush` input that creates and hooks the honk chains.
pub(crate) fn restore_script(
    settings: &Settings,
    family: Family,
    local: &LocalDestinations,
) -> String {
    let mark = settings.tproxy_mark;
    let classified = honk_ebpf_common::CLASSIFIED_MARK;
    let mut lines = vec![
        "*mangle".to_owned(),
        format!(":{PREROUTING_CHAIN} - [0:0]"),
        format!(":{OUTPUT_CHAIN} - [0:0]"),
    ];
    let bypass = settings.bypass_mark;
    // netd ORs network and permission bits into every Android socket mark.
    let bypass = if cfg!(target_os = "android") {
        format!("{bypass:#x}/{bypass:#x}")
    } else {
        format!("{bypass:#x}")
    };
    for chain in [PREROUTING_CHAIN, OUTPUT_CHAIN] {
        lines.push(format!("-A {chain} -m mark --mark {bypass} -j RETURN"));
        lines.push(format!(
            "-A {chain} -m mark --mark {classified:#x}/{classified:#x} -j RETURN"
        ));
    }
    // LAN DNS keeps honk's port-53 policy even when the router serves DNS itself.
    for protocol in ["udp", "tcp"] {
        lines.push(format!(
            "-A {PREROUTING_CHAIN} -p {protocol} --dport 53 -j TPROXY --on-port {} --tproxy-mark {mark:#x}/{mark:#x}",
            settings.port
        ));
    }
    for kind in ["broadcast", "multicast"] {
        lines.push(format!(
            "-A {PREROUTING_CHAIN} -m pkttype --pkt-type {kind} -j RETURN"
        ));
    }
    match local {
        LocalDestinations::Addrtype => {
            for (chain, kind) in [
                (PREROUTING_CHAIN, "LOCAL"),
                (PREROUTING_CHAIN, "BROADCAST"),
                (OUTPUT_CHAIN, "BROADCAST"),
            ] {
                lines.push(format!(
                    "-A {chain} -m addrtype --dst-type {kind} -j RETURN"
                ));
            }
        }
        LocalDestinations::Addresses(addresses) => {
            for address in addresses
                .iter()
                .filter(|address| family.contains(**address))
            {
                lines.push(format!(
                    "-A {PREROUTING_CHAIN} -d {address}/{} -j RETURN",
                    family.host_prefix()
                ));
            }
        }
    }
    // Packets to the host's own addresses route through lo.
    lines.push(format!("-A {OUTPUT_CHAIN} -o lo -j RETURN"));
    for chain in [PREROUTING_CHAIN, OUTPUT_CHAIN] {
        for network in family.special() {
            lines.push(format!("-A {chain} -d {network} -j RETURN"));
        }
    }
    for protocol in ["tcp", "udp"] {
        lines.push(format!(
            "-A {PREROUTING_CHAIN} -p {protocol} -j TPROXY --on-port {} --tproxy-mark {mark:#x}/{mark:#x}",
            settings.port
        ));
        lines.push(format!(
            "-A {OUTPUT_CHAIN} -p {protocol} -j MARK --set-mark {mark:#x}/{mark:#x}"
        ));
    }
    for interface in &settings.lan {
        lines.push(format!(
            "-I PREROUTING -i {interface} -j {PREROUTING_CHAIN}"
        ));
    }
    match &settings.host {
        HostScope::None => {}
        HostScope::All => lines.push(format!("-I OUTPUT -j {OUTPUT_CHAIN}")),
        HostScope::Interfaces(interfaces) => {
            for interface in interfaces {
                lines.push(format!("-I OUTPUT -o {interface} -j {OUTPUT_CHAIN}"));
            }
        }
    }
    if settings.host != HostScope::None {
        lines.push(format!(
            "-I PREROUTING -i lo -m mark --mark {mark:#x}/{mark:#x} -j {PREROUTING_CHAIN}"
        ));
    }
    lines.push("COMMIT".to_owned());
    let mut script = lines.join("\n");
    script.push('\n');
    script
}

/// Builtin-chain rules that jump to a honk chain, rewritten as `-D` arguments.
pub(crate) fn jump_deletions(listing: &str) -> Vec<Vec<String>> {
    listing
        .lines()
        .filter(|line| {
            line.starts_with("-A ")
                && (line.ends_with(&format!("-j {PREROUTING_CHAIN}"))
                    || line.ends_with(&format!("-j {OUTPUT_CHAIN}")))
        })
        .map(|line| {
            let mut arguments: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
            arguments[0] = "-D".to_owned();
            arguments
        })
        .collect()
}

fn run(program: &str, arguments: &[&str], input: Option<&str>) -> anyhow::Result<String> {
    let mut command = Command::new(program);
    command
        .args(arguments)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().with_context(|| format!("run {program}"))?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input.as_bytes())
            .with_context(|| format!("write {program} input"))?;
    }
    let output = child
        .wait_with_output()
        .with_context(|| format!("wait for {program}"))?;
    anyhow::ensure!(
        output.status.success(),
        "{program} {} failed ({}): {}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Remove honk's chains and jumps for one family; absent state is success.
fn remove_rules(family: Family) -> anyhow::Result<()> {
    let iptables = family.iptables();
    for builtin in ["PREROUTING", "OUTPUT"] {
        let listing = run(iptables, &["-w", "-t", "mangle", "-S", builtin], None)?;
        for deletion in jump_deletions(&listing) {
            let mut arguments = vec!["-w", "-t", "mangle"];
            arguments.extend(deletion.iter().map(String::as_str));
            run(iptables, &arguments, None)?;
        }
    }
    for chain in [PREROUTING_CHAIN, OUTPUT_CHAIN] {
        if run(iptables, &["-w", "-t", "mangle", "-S", chain], None).is_ok() {
            run(iptables, &["-w", "-t", "mangle", "-F", chain], None)?;
            run(iptables, &["-w", "-t", "mangle", "-X", chain], None)?;
        }
    }
    Ok(())
}

fn install_rules(settings: &Settings, family: Family) -> anyhow::Result<()> {
    let restore = |local: &LocalDestinations| {
        let script = restore_script(settings, family, local);
        debug!(?family, %script, "installing TPROXY rules");
        run(family.restore(), &["-w", "--noflush"], Some(&script))
    };
    // A rejected restore commits nothing, so the fallback starts clean.
    if let Err(error) = restore(&LocalDestinations::Addrtype) {
        info!(?family, %error, "addrtype unavailable; matching current local addresses");
        restore(&LocalDestinations::current()?).with_context(|| {
            format!(
                "install {} TPROXY rules (needs the mangle table and the TPROXY, MARK, mark and pkttype extensions)",
                family.iptables()
            )
        })?;
    }
    Ok(())
}

fn add_route(family: Family, mark: u32) -> anyhow::Result<()> {
    let mut netlink = crate::netlink::NlSock::new().context("netlink socket")?;
    let lo = crate::netlink::ifindex_of("lo").context("loopback interface")?;
    netlink
        .add_route(
            family.netlink(),
            ROUTE_TABLE,
            crate::netlink::ROUTE_LOCAL,
            crate::netlink::SCOPE_HOST,
            crate::netlink::PROTO_STATIC,
            None,
            None,
            Some(lo),
        )
        .with_context(|| format!("add {family:?} local default route to table {ROUTE_TABLE}"))?;
    match netlink.add_rule_fwmark_priority(family.netlink(), mark, mark, ROUTE_TABLE, RULE_PRIORITY)
    {
        Err(error) if error.raw_os_error() != Some(libc::EEXIST) => {
            Err(error).with_context(|| format!("add {family:?} fwmark rule"))
        }
        _ => Ok(()),
    }
}

fn remove_route(family: Family, mark: u32) {
    let Ok(mut netlink) = crate::netlink::NlSock::new() else {
        return;
    };
    // Repeat: a crashed predecessor may have left duplicate rules.
    while netlink
        .del_rule_fwmark_priority(family.netlink(), mark, mark, ROUTE_TABLE, RULE_PRIORITY)
        .is_ok()
    {}
    let _ = netlink.del_route(
        family.netlink(),
        ROUTE_TABLE,
        crate::netlink::ROUTE_LOCAL,
        None,
    );
}

/// Installed interception; [`TproxyDatapath::remove`] or drop restores the host.
pub(crate) struct TproxyDatapath {
    settings: Settings,
    families: Vec<Family>,
}

impl TproxyDatapath {
    /// Replace any leftover honk state, then route and divert both families.
    pub(crate) fn install(settings: Settings) -> anyhow::Result<Self> {
        let mut families = vec![Family::V4];
        if crate::netlink::ipv6_socket_available().context("probe IPv6 socket family")? {
            families.push(Family::V6);
        }
        for &family in &families {
            remove_route(family, settings.tproxy_mark);
            remove_rules(family).with_context(|| format!("clear stale {family:?} TPROXY rules"))?;
        }
        let mut installed = Self {
            settings,
            families: Vec::new(),
        };
        for family in families {
            // Routes first: a marked packet must never meet rules without them.
            add_route(family, installed.settings.tproxy_mark)?;
            installed.families.push(family);
            install_rules(&installed.settings, family)?;
        }
        info!(
            port = installed.settings.port,
            lan = ?installed.settings.lan,
            host = ?installed.settings.host,
            "TPROXY datapath installed"
        );
        Ok(installed)
    }

    /// Divert nothing more, then drop the routes; reports the first failure.
    pub(crate) fn remove(mut self) -> anyhow::Result<()> {
        self.teardown()
    }

    fn teardown(&mut self) -> anyhow::Result<()> {
        let mut first = None;
        for family in std::mem::take(&mut self.families) {
            if let Err(error) = remove_rules(family) {
                warn!(?family, %error, "removing TPROXY rules failed");
                first.get_or_insert(error);
            }
            remove_route(family, self.settings.tproxy_mark);
        }
        first.map_or(Ok(()), Err)
    }
}

impl Drop for TproxyDatapath {
    fn drop(&mut self) {
        let _ = self.teardown();
    }
}

//! Sysctl writes with a command fallback for restricted procfs mounts.

fn proc_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

pub(crate) fn set_sysctl(key: &str, value: &str) -> anyhow::Result<()> {
    set_sysctl_at(key, value, &proc_path(key))
}

fn set_sysctl_at(key: &str, value: &str, path: &str) -> anyhow::Result<()> {
    // Prefer /proc/sys because the standalone `sysctl` binary may not be on
    // PATH in minimal environments (e.g. NixOS containers).
    if let Err(e) = std::fs::write(path, format!("{}\n", value)) {
        let output = std::process::Command::new("sysctl")
            .args(["-w", &format!("{}={}", key, value)])
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "sysctl -w {}={} failed: {} (proc write also failed: {})",
                key,
                value,
                String::from_utf8_lossy(&output.stderr),
                e
            );
        }
    }
    Ok(())
}

/// Slash-form key and /proc path for a per-device sysctl. The interface name
/// is a single path segment taken verbatim: a name like `eth0.100` must not be
/// split on its dot (the dotted form, and `proc_path`, would turn it into
/// `eth0/100`). The slash key also keeps `sysctl -w` from splitting it.
#[cfg(feature = "ebpf")]
fn device_sysctl_target(family: &str, ifname: &str, key: &str) -> anyhow::Result<(String, String)> {
    anyhow::ensure!(
        !ifname.is_empty() && ifname != "." && ifname != ".." && !ifname.contains(['/', '\0']),
        "invalid interface name {ifname:?} for sysctl path"
    );
    let key = format!("net/{family}/conf/{ifname}/{key}");
    let path = format!("/proc/sys/{key}");
    Ok((key, path))
}

/// Write `net/<family>/conf/<ifname>/<key>`; `family` is `ipv4` or `ipv6`.
#[cfg(feature = "ebpf")]
pub(crate) fn set_device_sysctl(
    family: &str,
    ifname: &str,
    key: &str,
    value: &str,
) -> anyhow::Result<()> {
    let (key, path) = device_sysctl_target(family, ifname, key)?;
    set_sysctl_at(&key, value, &path)
}

#[cfg(feature = "ebpf")]
pub(crate) fn require_off(key: &str, optional: bool) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let path = proc_path(key);
    if optional
        && !std::path::Path::new(&path)
            .try_exists()
            .with_context(|| format!("inspect {key} in daens"))?
    {
        return Ok(());
    }
    set_sysctl_at(key, "0", &path).with_context(|| format!("disable {key} in daens"))?;
    let actual =
        std::fs::read_to_string(&path).with_context(|| format!("verify {key} in daens"))?;
    anyhow::ensure!(actual.trim() == "0", "{key} remains enabled in daens");
    Ok(())
}

/// Keep RA reception alive on a WAN interface across the datapath's
/// all.forwarding=1 pin: with the stock accept_ra=1 the kernel drops RAs
/// once forwarding is on, and networkd's userspace RA disables itself the
/// same way — either path lets the SLAAC default route expire (#46).
#[cfg(feature = "ebpf")]
pub(crate) fn enable_wan_accept_ra(ifname: &str) -> anyhow::Result<()> {
    set_device_sysctl("ipv6", ifname, "accept_ra", "2")
}

/// Disable reverse-path filtering on the first existing, non-refused resolved LAN name.
#[cfg(feature = "ebpf")]
pub(crate) fn disable_rp_filter(ifname: &str) -> anyhow::Result<()> {
    set_device_sysctl("ipv4", ifname, "rp_filter", "0")
}

#[cfg(all(test, feature = "ebpf"))]
mod tests {
    use super::device_sysctl_target;

    #[test]
    fn dotted_interface_name_stays_one_path_segment() {
        assert_eq!(
            device_sysctl_target("ipv6", "eth0.100", "accept_ra").unwrap(),
            (
                "net/ipv6/conf/eth0.100/accept_ra".to_string(),
                "/proc/sys/net/ipv6/conf/eth0.100/accept_ra".to_string(),
            )
        );
        for bad in ["", ".", "..", "a/b", "../all"] {
            assert!(
                device_sysctl_target("ipv4", bad, "rp_filter").is_err(),
                "{bad:?}"
            );
        }
    }
}

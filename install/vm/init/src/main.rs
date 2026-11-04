//! PID 1 of the honk VM image. The image ships no shell: this program mounts
//! the kernel filesystems, installs the configuration, brings up `eth0` with a
//! static IPv4 address, runs `honk-core` and powers off when it exits.

use std::ffi::CString;
use std::fs;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const FW_CFG: &str = "/sys/firmware/qemu_fw_cfg/by_name/opt/honk";
const NINEP_DIR: &str = "/mnt/cfg";
const CONFIG: &str = "/etc/honk/config.dae";
const DEFAULT_CONFIG: &str = "/etc/honk/default.dae";
const HONK: &str = "/bin/honk-core";
// QEMU user networking defaults.
const DEFAULT_IP: &str = "10.0.2.15/24";
const DEFAULT_GW: &str = "10.0.2.2";
const DEFAULT_DNS: &str = "10.0.2.3";

macro_rules! log {
    ($($arg:tt)*) => { println!("[init] {}", format_args!($($arg)*)) };
}

fn main() {
    for (source, target, fstype) in [
        ("proc", "/proc", "proc"),
        ("sysfs", "/sys", "sysfs"),
        ("devtmpfs", "/dev", "devtmpfs"),
        ("tmpfs", "/run", "tmpfs"),
        ("tmpfs", "/tmp", "tmpfs"),
        ("bpf", "/sys/fs/bpf", "bpf"),
        ("cgroup2", "/sys/fs/cgroup", "cgroup2"),
        ("tracefs", "/sys/kernel/tracing", "tracefs"),
    ] {
        if let Err(error) = mount(source, target, fstype, None) {
            log!("mount {target}: {error}");
        }
    }
    if let Err(error) = fs::create_dir_all("/var/lib/honk") {
        log!("/var/lib/honk: {error}");
    }

    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let config = install_config(&cmdline).unwrap_or_else(|error| {
        log!("configuration: {error}");
        CONFIG.into()
    });
    let ip = setting("ip", &cmdline).unwrap_or_else(|| DEFAULT_IP.into());
    let gw = setting("gw", &cmdline).unwrap_or_else(|| DEFAULT_GW.into());
    let dns = setting("dns", &cmdline).unwrap_or_else(|| DEFAULT_DNS.into());
    match network(&ip, &gw) {
        Ok(()) => log!("eth0 {ip} via {gw}, dns {dns}"),
        Err(error) => log!("network eth0 {ip} via {gw}: {error}"),
    }
    if let Err(error) = fs::write("/etc/resolv.conf", format!("nameserver {dns}\n")) {
        log!("resolv.conf: {error}");
    }

    let status = supervise(&config);
    log!("honk-core exited: {status}");
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
}

fn mount(source: &str, target: &str, fstype: &str, data: Option<&str>) -> io::Result<()> {
    fs::create_dir_all(target)?;
    let flags = if fstype == "devtmpfs" {
        libc::MS_NOSUID
    } else {
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC
    };
    let [source, target, fstype] = [source, target, fstype].map(|s| CString::new(s).unwrap());
    let data = data.map(|data| CString::new(data).unwrap());
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data.as_ref()
                .map_or(std::ptr::null(), |data| data.as_ptr().cast()),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Returns the configuration path, first match wins: fw_cfg `opt/honk/config`
/// (with every `opt/honk/conf.d/<name>` as an include), kernel command line
/// `honk.cfg_b64=`, `config.dae` on the virtio-9p share tagged `honkcfg`
/// (used in place, so API edits persist), then the built-in default.
fn install_config(cmdline: &str) -> io::Result<String> {
    fs::create_dir_all("/etc/honk/conf.d")?;
    let main = Path::new(FW_CFG).join("config/raw");
    let inline = cmdline
        .split_whitespace()
        .find_map(|arg| arg.strip_prefix("honk.cfg_b64="));
    if main.exists() {
        fs::copy(&main, CONFIG)?;
        log!("config from fw_cfg ({} bytes)", fs::metadata(CONFIG)?.len());
        if let Ok(entries) = fs::read_dir(Path::new(FW_CFG).join("conf.d")) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                fs::copy(
                    entry.path().join("raw"),
                    Path::new("/etc/honk/conf.d").join(&name),
                )?;
                log!("include conf.d/{}", name.to_string_lossy());
            }
        }
    } else if let Some(inline) = inline {
        let decoded = base64_decode(inline)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad honk.cfg_b64"))?;
        fs::write(CONFIG, decoded)?;
        log!("config from the kernel command line");
    } else if mount(
        "honkcfg",
        NINEP_DIR,
        "9p",
        Some("trans=virtio,version=9p2000.L"),
    )
    .is_ok()
        && Path::new(NINEP_DIR).join("config.dae").exists()
    {
        log!("config from 9p (writable)");
        return Ok(format!("{NINEP_DIR}/config.dae"));
    } else {
        fs::copy(DEFAULT_CONFIG, CONFIG)?;
        log!("WARNING: no configuration supplied, using the built-in default");
    }
    fs::set_permissions(CONFIG, fs::Permissions::from_mode(0o600))?;
    Ok(CONFIG.into())
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let (mut bits, mut count) = (0u32, 0);
    for byte in input.bytes().take_while(|byte| *byte != b'=') {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        bits = bits << 6 | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    Some(out)
}

/// fw_cfg `opt/honk/<key>` wins over the kernel command line `honk.<key>=`.
fn setting(key: &str, cmdline: &str) -> Option<String> {
    let from_fw_cfg = fs::read_to_string(Path::new(FW_CFG).join(key).join("raw"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    from_fw_cfg.or_else(|| {
        let prefix = format!("honk.{key}=");
        cmdline
            .split_whitespace()
            .find_map(|arg| arg.strip_prefix(&prefix).map(str::to_string))
    })
}

fn network(ip: &str, gw: &str) -> io::Result<()> {
    let invalid = |what: &str| io::Error::new(io::ErrorKind::InvalidInput, what.to_string());
    let (address, prefix) = ip.split_once('/').unwrap_or((ip, "24"));
    let address: Ipv4Addr = address.parse().map_err(|_| invalid("bad address"))?;
    let prefix: u32 = prefix
        .parse()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| invalid("bad prefix"))?;
    let netmask = Ipv4Addr::from(u32::MAX.checked_shl(32 - prefix).unwrap_or(0));
    let gw: Ipv4Addr = gw.parse().map_err(|_| invalid("bad gateway"))?;

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        up(fd, "lo")?;
        ioctl(fd, libc::SIOCSIFADDR as _, &mut ifreq_addr("eth0", address))?;
        ioctl(
            fd,
            libc::SIOCSIFNETMASK as _,
            &mut ifreq_addr("eth0", netmask),
        )?;
        up(fd, "eth0")?;
        let mut route: libc::rtentry = unsafe { zeroed() };
        route.rt_dst = sockaddr(Ipv4Addr::UNSPECIFIED);
        route.rt_genmask = sockaddr(Ipv4Addr::UNSPECIFIED);
        route.rt_gateway = sockaddr(gw);
        route.rt_flags = (libc::RTF_UP | libc::RTF_GATEWAY) as _;
        ioctl(fd, libc::SIOCADDRT as _, &mut route)
    })();
    unsafe { libc::close(fd) };
    result
}

fn up(fd: libc::c_int, name: &str) -> io::Result<()> {
    let mut request = ifreq(name);
    ioctl(fd, libc::SIOCGIFFLAGS as _, &mut request)?;
    unsafe { request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short };
    ioctl(fd, libc::SIOCSIFFLAGS as _, &mut request)
}

fn ifreq(name: &str) -> libc::ifreq {
    let mut request: libc::ifreq = unsafe { zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *slot = byte as libc::c_char;
    }
    request
}

fn ifreq_addr(name: &str, address: Ipv4Addr) -> libc::ifreq {
    let mut request = ifreq(name);
    request.ifr_ifru.ifru_addr = sockaddr(address);
    request
}

fn sockaddr(address: Ipv4Addr) -> libc::sockaddr {
    const _: () = assert!(size_of::<libc::sockaddr_in>() == size_of::<libc::sockaddr>());
    let inet = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(address).to_be(),
        },
        sin_zero: [0; 8],
    };
    unsafe { std::mem::transmute(inet) }
}

fn ioctl<T>(fd: libc::c_int, request: libc::Ioctl, arg: &mut T) -> io::Result<()> {
    if unsafe { libc::ioctl(fd, request, arg as *mut T) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Run honk-core with SIGHUP/SIGTERM/SIGINT forwarded, reaping every child,
/// until honk-core itself exits.
fn supervise(config: &str) -> String {
    let mut signals: libc::sigset_t = unsafe { zeroed() };
    unsafe {
        libc::sigemptyset(&mut signals);
        for signal in [libc::SIGCHLD, libc::SIGHUP, libc::SIGTERM, libc::SIGINT] {
            libc::sigaddset(&mut signals, signal);
        }
        libc::sigprocmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut());
    }
    let mut command = Command::new(HONK);
    command
        .args(["--config", config, "--disable-timestamp"])
        .env_clear()
        .stdin(std::process::Stdio::null());
    // The child must not inherit the mask that lets PID 1 wait for signals.
    unsafe {
        command.pre_exec(|| {
            let mut empty: libc::sigset_t = zeroed();
            libc::sigemptyset(&mut empty);
            libc::sigprocmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            Ok(())
        });
    }
    let child = match command.spawn() {
        Ok(child) => child.id() as libc::pid_t,
        Err(error) => return format!("spawn {HONK}: {error}"),
    };
    loop {
        let signal = unsafe { libc::sigwaitinfo(&signals, std::ptr::null_mut()) };
        match signal {
            libc::SIGHUP | libc::SIGTERM | libc::SIGINT => unsafe {
                libc::kill(child, signal);
            },
            libc::SIGCHLD => loop {
                let mut status = 0;
                let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                if pid <= 0 {
                    break;
                }
                if pid == child {
                    return if libc::WIFEXITED(status) {
                        format!("exit code {}", libc::WEXITSTATUS(status))
                    } else {
                        format!("signal {}", libc::WTERMSIG(status))
                    };
                }
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_decodes_padded_and_url_safe_input() {
        assert_eq!(super::base64_decode("aG9uaw==").unwrap(), b"honk");
        assert_eq!(super::base64_decode("Pz8-").unwrap(), b"??>");
        assert!(super::base64_decode("a b").is_none());
    }
}

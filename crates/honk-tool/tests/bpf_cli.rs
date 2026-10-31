#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, ensure};
use aya::EbpfLoader;
use aya::maps::{Array, Map};
use aya::programs::{SchedClassifier, TcAttachType};
use honk_ebpf_common::wan_diagnostic::{FILTER_MAP, SAMPLE_MAP};
use honk_ebpf_common::{DAE_BYPASS_MARK, DaeParam};

const WAIT: Duration = Duration::from_secs(10);
const OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy)]
enum Case {
    Capture,
    Disable,
    CleanupFailure,
}

struct ChildGuard {
    child: Child,
    reaped: bool,
}

impl ChildGuard {
    fn status(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    fn alive(&mut self) -> anyhow::Result<()> {
        ensure!(
            self.status()?.is_none(),
            "collector exited before the output checkpoint"
        );
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let deadline = Instant::now() + WAIT;
            while Instant::now() < deadline {
                if self.status().is_ok_and(|status| status.is_some()) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn flags(fd: RawFd, value: Option<i32>) -> io::Result<i32> {
    let result = unsafe {
        match value {
            Some(value) => libc::fcntl(fd, libc::F_SETFL, value),
            None => libc::fcntl(fd, libc::F_GETFL),
        }
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    flags(fd, Some(flags(fd, None)? | libc::O_NONBLOCK)).map(|_| ())
}

fn pipe() -> anyhow::Result<(File, File, usize)> {
    let mut descriptors = [0i32; 2];
    ensure!(
        unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } == 0,
        "pipe2: {}",
        io::Error::last_os_error()
    );
    let reader = unsafe { File::from_raw_fd(descriptors[0]) };
    let writer = unsafe { File::from_raw_fd(descriptors[1]) };
    let capacity = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) };
    ensure!(capacity > 0, "pipe size: {}", io::Error::last_os_error());
    Ok((reader, writer, capacity as usize))
}

fn fill(writer: &mut File, capacity: usize) -> anyhow::Result<()> {
    let original_flags = flags(writer.as_raw_fd(), None)?;
    nonblocking(writer.as_raw_fd())?;
    writer.write_all(&vec![b'X'; capacity])?;
    flags(writer.as_raw_fd(), Some(original_flags))?;
    Ok(())
}

fn drain(input: &mut impl Read, bytes: &mut Vec<u8>) -> anyhow::Result<bool> {
    let mut buffer = [0u8; 4096];
    loop {
        match input.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(count) => {
                ensure!(
                    bytes.len() + count <= OUTPUT_LIMIT,
                    "collector output exceeded test bound"
                );
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn wait_until(mut ready: impl FnMut() -> anyhow::Result<bool>) -> anyhow::Result<()> {
    let deadline = Instant::now() + WAIT;
    loop {
        if ready()? {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "deadline exceeded");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[repr(C)]
#[derive(Default)]
struct Query {
    ifindex: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    program_ids: u64,
    count: u32,
    padding: u32,
    program_flags: u64,
    link_ids: u64,
    link_flags: u64,
    revision: u64,
}

fn hook_count(ifindex: u32) -> io::Result<u32> {
    let mut query = Query {
        ifindex,
        attach_type: 47,
        ..Default::default()
    };
    let result = unsafe { libc::syscall(libc::SYS_bpf, 16, &mut query, size_of::<Query>()) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(query.count)
    }
}

fn map_alive(id: u32) -> io::Result<bool> {
    let mut attr = [id, 0u32, 0u32];
    let result = unsafe { libc::syscall(libc::SYS_bpf, 14, attr.as_mut_ptr(), size_of_val(&attr)) };
    if result >= 0 {
        drop(unsafe { OwnedFd::from_raw_fd(result as i32) });
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(error)
    }
}

fn blocked_write(pid: u32, fd: u32) -> anyhow::Result<bool> {
    let syscall = std::fs::read_to_string(format!("/proc/{pid}/syscall"))?;
    let mut fields = syscall.split_whitespace();
    let number = fields
        .next()
        .and_then(|number| number.parse::<libc::c_long>().ok());
    let output = fields
        .next()
        .and_then(|value| value.strip_prefix("0x"))
        .and_then(|value| u32::from_str_radix(value, 16).ok());
    Ok(output == Some(fd) && matches!(number, Some(libc::SYS_write | libc::SYS_writev)))
}

fn private_tun() -> anyhow::Result<File> {
    ensure!(
        unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0,
        "unshare: {}",
        io::Error::last_os_error()
    );
    let tun = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (byte, value) in request.ifr_name.iter_mut().zip(b"wan-diag") {
        *byte = *value as libc::c_char;
    }
    request.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    ensure!(
        unsafe { libc::ioctl(tun.as_raw_fd(), libc::TUNSETIFF, &request) } == 0,
        "TUNSETIFF: {}",
        io::Error::last_os_error()
    );
    Ok(tun)
}

fn output_case(case: Case) -> anyhow::Result<()> {
    let disable = matches!(case, Case::Disable);
    let fail_stop = matches!(case, Case::CleanupFailure);
    let output_fd = if fail_stop { 2 } else { 1 };
    ensure!(unsafe { libc::geteuid() } == 0, "requires root");
    let object = std::env::var_os("HONK_TEST_BPF_OBJECT")
        .context("set HONK_TEST_BPF_OBJECT to the matching production eBPF object")?;
    let tool = std::env::var_os("HONK_TEST_TOOL").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_honk-tool")),
        PathBuf::from,
    );
    let _tun = private_tun()?;
    let ifindex = unsafe { libc::if_nametoindex(c"wan-diag".as_ptr()) };
    ensure!(ifindex != 0, "private TUN missing");
    let pins = tempfile::Builder::new()
        .prefix("honk-tool-output-")
        .tempdir_in("/sys/fs/bpf")?;
    let parameter = DaeParam {
        tproxy_port: 12345u16.to_be() as u32,
        dae0_ifindex: 1,
        wan_ifindex: ifindex,
        dae0peer_mac: [2, 0, 0, 0, 0, 2],
        dae_socket_mark: DAE_BYPASS_MARK,
        tcp_daens_netns_id: 0,
        ..Default::default()
    };
    let mut loader = EbpfLoader::new();
    loader
        .override_global("PARAM", &parameter, true)
        .override_global("WAN_IFINDEX", &ifindex, true)
        .override_global("DAE0PEER_IFINDEX", &1u32, true)
        .override_global("TASK_MM_OFFSET", &0u32, true)
        .override_global("MM_ARG_START_OFFSET", &0u32, true);
    let mut bpf = loader.load_file(object)?;
    for name in [FILTER_MAP, SAMPLE_MAP] {
        bpf.map(name)
            .context("missing diagnostic map")?
            .pin(pins.path().join(name))?;
    }
    let production_id = match bpf
        .map("CONN_STATE_MAP")
        .context("missing production map")?
    {
        Map::HashMap(data) => data.info()?.id(),
        _ => anyhow::bail!("unexpected connection map type"),
    };
    let filter_id = match bpf.map(FILTER_MAP).unwrap() {
        Map::Array(data) => data.info()?.id(),
        _ => anyhow::bail!("unexpected filter map type"),
    };
    {
        let program: &mut SchedClassifier = bpf
            .program_mut("wan_egress_l3")
            .context("missing WAN program")?
            .try_into()?;
        program.load()?;
        program.attach("wan-diag", TcAttachType::Egress)?;
    }
    ensure!(
        hook_count(ifindex)? == 1 && map_alive(production_id)?,
        "fixture ownership missing"
    );
    if disable {
        Array::<_, [u32; 2]>::try_from(bpf.map_mut(FILTER_MAP).unwrap())?.set(
            0,
            [ifindex, 41500],
            0,
        )?;
        ensure!(
            Array::<_, [u32; 2]>::try_from(bpf.map(FILTER_MAP).unwrap())?.get(&0, 0)?
                == [ifindex, 41500],
            "filter not armed"
        );
    }
    let (read_fd, mut writer, capacity) = pipe()?;
    let (error_fd, mut error_writer, error_capacity) = pipe()?;
    if !fail_stop {
        fill(&mut writer, capacity)?;
    }
    let mut command = Command::new(tool);
    command
        .args(["bpf", "wan-diag", "--interface", "wan-diag", "--pin-root"])
        .arg(pins.path())
        .env("PATH", "/nonexistent")
        .env("RUST_LOG", "off")
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(error_writer.try_clone()?));
    if disable {
        command.arg("--disable");
    } else {
        command.args(["--source-port", "41500", "--seconds", "30"]);
    }
    let mut child = ChildGuard {
        child: command.spawn()?,
        reaped: false,
    };
    drop(command);
    // These read ends close before the child guard kills/reaps on an error.
    let mut reader = read_fd;
    let mut errors = error_fd;
    nonblocking(reader.as_raw_fd())?;
    nonblocking(errors.as_raw_fd())?;
    let pid = child.child.id();
    let mut stderr = Vec::new();
    let mut error_prefix = 0;
    if !disable {
        wait_until(|| {
            drain(&mut errors, &mut stderr)?;
            child.alive()?;
            Ok(stderr.starts_with(b"WAN diagnostic sampling ready:") && stderr.ends_with(b"\n"))
        })
        .with_context(|| format!("readiness: {}", String::from_utf8_lossy(&stderr)))?;
        ensure!(
            Array::<_, [u32; 2]>::try_from(bpf.map(FILTER_MAP).unwrap())?.get(&0, 0)?
                == [ifindex, 41500],
            "capture was not armed"
        );
        if fail_stop {
            error_prefix = stderr.len();
            fill(&mut error_writer, error_capacity)?;
            let mut fd = match bpf.map(FILTER_MAP).unwrap() {
                Map::Array(data) => data.fd().as_fd().as_raw_fd() as u32,
                _ => unreachable!(),
            };
            ensure!(
                unsafe { libc::syscall(libc::SYS_bpf, 22, &mut fd, size_of::<u32>()) } == 0,
                "freeze diagnostic filter: {}",
                io::Error::last_os_error()
            );
        }
        ensure!(
            unsafe { libc::kill(pid as i32, libc::SIGTERM) } == 0,
            "signal collector: {}",
            io::Error::last_os_error()
        );
    }
    drop(error_writer);
    wait_until(|| {
        if !fail_stop {
            drain(&mut errors, &mut stderr)?;
        }
        child.alive()?;
        let filter = Array::<_, [u32; 2]>::try_from(bpf.map(FILTER_MAP).unwrap())?.get(&0, 0)?;
        let expected = if fail_stop { [ifindex, 41500] } else { [0, 0] };
        Ok(filter == expected && blocked_write(pid, output_fd)?)
    })
    .context("collector did not reach the expected blocked output checkpoint")?;
    println!(
        "collector blocked on fd {output_fd}; production map {production_id}; disable_failed={fail_stop}"
    );
    drop(bpf);
    pins.close()?;
    ensure!(
        hook_count(ifindex)? == 0,
        "fixture TCX link survived teardown"
    );
    wait_until(|| {
        if !fail_stop {
            drain(&mut errors, &mut stderr)?;
        }
        child.alive()?;
        ensure!(
            blocked_write(pid, output_fd)?,
            "collector stopped blocking before release check"
        );
        Ok(!map_alive(production_id)?)
    })
    .with_context(|| {
        format!("production map {production_id} remained alive while fd {output_fd} was blocked")
    })?;
    println!("production map {production_id}: ENOENT while collector remains blocked");
    let mut stdout = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status = None;
    wait_until(|| {
        stderr_eof |= drain(&mut errors, &mut stderr)?;
        stdout_eof |= drain(&mut reader, &mut stdout)?;
        if status.is_none() {
            status = child.status()?;
        }
        Ok(stdout_eof && stderr_eof && status.is_some())
    })
    .context("collector did not finish after output drain")?;
    if fail_stop {
        ensure!(
            !status.unwrap().success() && stdout.is_empty(),
            "failed cleanup reported success"
        );
        ensure!(
            stderr.len() >= error_prefix + error_capacity
                && stderr[error_prefix..error_prefix + error_capacity]
                    .iter()
                    .all(|byte| *byte == b'X'),
            "stderr filler changed"
        );
        let error = std::str::from_utf8(&stderr[error_prefix + error_capacity..])?;
        ensure!(
            error.contains("disable WAN diagnostics failed")
                && error.contains("sampling may remain enabled"),
            "cleanup failure was not reported: {error}"
        );
        return Ok(());
    }
    ensure!(
        status.unwrap().success(),
        "collector failed: {}",
        String::from_utf8_lossy(&stderr)
    );
    ensure!(
        stdout.len() >= capacity && stdout[..capacity].iter().all(|byte| *byte == b'X'),
        "stdout filler changed"
    );
    let report: serde_json::Value = serde_json::from_slice(&stdout[capacity..])?;
    ensure!(
        report["filter_map_id"] == filter_id,
        "wrong filter identity in report"
    );
    if disable {
        ensure!(report["disabled"] == true, "missing disable result");
    } else {
        ensure!(
            report["end_reason"] == "SIGTERM"
                && report["source_port"] == 41500
                && report["ifindex"] == ifindex,
            "wrong capture result"
        );
        ensure!(
            report["before"].is_array() && report["after"].is_array(),
            "missing snapshots"
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires root, bpffs, TUN and production BPF object; private TCX only"]
fn capture_releases_kernel_owners_before_output() -> anyhow::Result<()> {
    std::thread::spawn(|| output_case(Case::Capture))
        .join()
        .expect("fixture thread panicked")
}

#[test]
#[ignore = "requires root, bpffs, TUN and production BPF object; private TCX only"]
fn disable_releases_kernel_owners_before_output() -> anyhow::Result<()> {
    std::thread::spawn(|| output_case(Case::Disable))
        .join()
        .expect("fixture thread panicked")
}

#[test]
#[ignore = "requires root, bpffs, TUN and production BPF object; private TCX only"]
fn cleanup_failure_releases_kernel_owners_before_error_output() -> anyhow::Result<()> {
    std::thread::spawn(|| output_case(Case::CleanupFailure))
        .join()
        .expect("fixture thread panicked")
}

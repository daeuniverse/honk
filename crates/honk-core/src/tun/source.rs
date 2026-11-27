//! Socket/process provenance for the sole owned TUN reader.
mod kernel;
mod object;
mod reader;
mod receipt;
mod sys;

use crate::control::netstack::HostIngress;
use crate::ebpf::PnameSupport;
use anyhow::{Context as _, ensure};
use honk_config::Config;
use honk_netstack::{MemoryBudget, MemoryReservation};
use object::Object;
use reader::Reader;
pub(super) use reader::is_expired;
use receipt::Receipt;
use std::os::fd::{AsRawFd as _, RawFd};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sys::{Cgroups, Grace};

const SOURCE_BYTES: usize = 32 << 20;
const LOADER_BYTES: usize = 32 << 20;
const KERNEL_BYTES: usize = 12 << 20;

pub(super) struct Read {
    pub len: usize,
    pub host: Option<HostIngress>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Prepared,
    Bound,
    Active,
    Closed,
    Finished,
}

pub(super) struct Source {
    object: Object,
    layout: Option<kernel::KernelLayout>,
    reader: Reader,
    netns_cookie: u64,
    owner_epoch: u64,
    ifindex: u32,
    attachment: u64,
    bypass_mark: u32,
    pins: PathBuf,
    receipt: Receipt,
    cgroups: Option<Cgroups>,
    grace: Grace,
    memory: Option<MemoryReservation>,
    loader: Option<MemoryReservation>,
    state: State,
}

impl Source {
    pub(super) fn prepare(
        config: &Config,
        budget: &Arc<MemoryBudget>,
        pin_root: &Path,
    ) -> anyhow::Result<Self> {
        kernel::zero_monotonic_namespace()?;
        let memory = budget
            .reserve(SOURCE_BYTES)
            .context("TUN source persistent memory budget exhausted")?;
        let loader = budget
            .reserve(LOADER_BYTES)
            .context("TUN source loader memory budget exhausted")?;
        let layout = kernel::KernelLayout::probe(budget)?;
        let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
        let netns_cookie = crate::netlink::fib::namespace_cookie(socket.as_raw_fd())?;
        let owner_epoch = honk_datapath::ScopeId::allocate()
            .context("TUN source owner incarnation exhausted")?
            .as_u64();
        let pins = pin_root.join(format!("host-{netns_cookie}"));
        std::fs::create_dir_all(pin_root)?;
        let mut receipt = Receipt::create(
            Path::new(&config.global.data_dir),
            netns_cookie,
            owner_epoch,
            &pins,
        )?;
        let intent = receipt.intent("pin_directory", serde_json::json!({"path":pins}))?;
        std::fs::DirBuilder::new().mode(0o700).create(&pins)?;
        let metadata = std::fs::metadata(&pins)?;
        receipt.acknowledge(
            intent,
            serde_json::json!({"dev":metadata.dev(),"inode":metadata.ino()}),
        )?;
        // Pins and their charge remain owned even if a later load cannot be rolled back.
        let memory = std::mem::ManuallyDrop::new(memory);
        let bypass_mark = config.global.effective_so_mark();
        let mut object = Object::load(
            include_bytes!(env!("HONK_TUN_EBPF_OBJECT")),
            &layout,
            netns_cookie,
            bypass_mark,
        )?;
        let active_lsm = Object::active_lsm()?;
        object.attach(&layout, &pins, &mut receipt, &active_lsm)?;
        let reader = Reader::new(object.map("TUN_READ_WINDOW")?, object.map("TUN_OWNER")?)?;
        let grace = Grace::new()?;
        let memory = std::mem::ManuallyDrop::into_inner(memory);
        let mut source = Self {
            object,
            layout: Some(layout),
            reader,
            netns_cookie,
            owner_epoch,
            ifindex: 0,
            attachment: 0,
            bypass_mark,
            pins,
            receipt,
            cgroups: None,
            grace,
            memory: Some(memory),
            loader: Some(loader),
            state: State::Prepared,
        };
        source.check_kernel_memory()?;
        source.receipt.phase("prepared")?;
        Ok(source)
    }

    pub(super) fn bind(&mut self, fd: RawFd, ifindex: u32, attachment: u64) -> anyhow::Result<()> {
        ensure!(
            self.state == State::Prepared && ifindex != 0 && attachment != 0,
            "TUN source rebound or invalid attachment"
        );
        let layout = self
            .layout
            .as_ref()
            .context("TUN source missing admitted layout")?;
        self.object.bind(
            layout,
            fd,
            object::TunProgramConfig {
                owner_epoch: self.owner_epoch,
                attachment,
                netns_cookie: self.netns_cookie,
                ifindex,
                bypass_mark: self.bypass_mark,
                owner_tgid: std::process::id(),
            },
            &self.pins,
            &mut self.receipt,
        )?;
        self.ifindex = ifindex;
        self.attachment = attachment;
        self.reader
            .bind(self.owner_epoch, attachment, self.netns_cookie, ifindex)?;
        let mut buffer = [0u8; 11];
        match self.reader.read(fd, &mut buffer, true) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error).context("TUN source empty-read binding canary"),
            Ok(_) => anyhow::bail!("TUN source binding canary consumed an unexpected record"),
        }
        self.cgroups = Some(Cgroups::capture(
            &self.object.cgroup,
            &self.object.hooks,
            &mut self.receipt,
        )?);
        self.check_kernel_memory()?;
        drop(self.layout.take());
        drop(self.loader.take());
        self.receipt.phase("bound")?;
        self.state = State::Bound;
        Ok(())
    }

    pub(super) fn activate(&mut self) -> anyhow::Result<()> {
        ensure!(
            self.state == State::Bound,
            "TUN source activation outside bound state"
        );
        self.cgroups
            .as_ref()
            .context("TUN source cgroup coverage was not bound")?
            .check()?;
        self.grace.barrier()?;
        self.object.gate(1)?;
        self.receipt.phase("open")?;
        self.state = State::Active;
        Ok(())
    }

    pub(super) fn pname_support(&self) -> PnameSupport {
        if self.state == State::Active {
            self.object.pname_support()
        } else {
            PnameSupport::Unavailable
        }
    }

    pub(super) fn read(&mut self, fd: RawFd, buffer: &mut [u8]) -> std::io::Result<Read> {
        if self.state != State::Active {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "TUN source admission is closed",
            ));
        }
        let result = self.reader.read(fd, buffer, false);
        if result.as_ref().is_err_and(|error| {
            !is_expired(error)
                && !matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                )
        }) {
            let close = self.close();
            if let Err(error) = close {
                return Err(std::io::Error::other(format!(
                    "TUN source read failed: {}; close failed: {error:#}",
                    result.as_ref().err().expect("read failed")
                )));
            }
        }
        result
    }

    pub(super) fn close(&mut self) -> anyhow::Result<()> {
        if matches!(self.state, State::Closed | State::Finished) {
            return Ok(());
        }
        self.object.gate(0)?;
        self.state = State::Closed;
        let reader = self.reader.close();
        let grace = self.grace.barrier();
        let receipt = self.receipt.phase("closed");
        reader.with_context(|| {
            format!("TUN read close failed; reader grace={grace:?}; receipt={receipt:?}")
        })?;
        grace?;
        receipt?;
        Ok(())
    }

    pub(super) fn finish(mut self) -> anyhow::Result<()> {
        let result = self.finish_inner();
        if result.is_err() {
            let _ = self.receipt.phase("guarded-retained");
            std::mem::forget(self);
        }
        result
    }

    fn finish_inner(&mut self) -> anyhow::Result<()> {
        self.object.gate(0)?;
        self.grace.barrier()?;
        if self.ifindex != 0 {
            self.reader.finish()?;
        }
        self.reader.close_after_release();
        self.receipt.retire_pins(&self.pins)?;
        self.object.links.clear();
        self.receipt.finish()?;
        self.state = State::Finished;
        // Deferred kernel release is not a synchronous allocation refund.
        if let Some(memory) = self.memory.take() {
            std::mem::forget(memory);
        }
        Ok(())
    }

    fn check_kernel_memory(&self) -> anyhow::Result<()> {
        let bytes = self
            .object
            .memory_bytes()?
            .checked_add(self.grace.memory_bytes()?)
            .context("TUN source kernel memory accounting overflow")?;
        ensure!(
            bytes <= KERNEL_BYTES,
            "TUN source kernel allocation {bytes} exceeds {KERNEL_BYTES}"
        );
        Ok(())
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        if self.state != State::Finished {
            let _ = self.close();
            if let Some(memory) = self.memory.take() {
                std::mem::forget(memory);
            }
        }
    }
}

//! Single owner of the TCX links on configured interfaces.
//!
//! Kernels before Linux 6.6 have no TCX; there each binding is a clsact
//! direct-action filter at honk's own priority instead, with a fresh handle
//! standing in for the link ID. Return codes mean the same in both: TCX_NEXT
//! is TC_ACT_UNSPEC (continue to the next filter) and TCX_PASS is TC_ACT_OK.
//!
//! The backend holds the eight preloaded TC program FDs and one owned link per
//! `(ifindex, direction)`. [`apply`] turns one validated [`InterfacePlan`] into
//! a [`BindingCommit`] without any lock held: it creates links by interface
//! index, updates a link in place when the program changes, and proves a
//! retained link is still on the namespace-local chain with `BPF_PROG_QUERY`
//! (a link FD alone survives its device being deleted or moved). Aya's
//! `attach_to_link` neither checks the expected old program nor preserves the
//! old link on failure. Every `unsafe` syscall of the module is here.

use std::collections::HashMap;
use std::ffi::c_long;
use std::io;
use std::mem::size_of;
use std::num::NonZeroU32;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::Context as _;
use aya::Ebpf;
use aya::programs::{ProgramError, SchedClassifier};
use aya_obj::generated::{
    BPF_F_AFTER, BPF_F_REPLACE, bpf_attach_type, bpf_attr, bpf_cmd, bpf_link_info,
};

use super::syscall::bpf_syscall;
use crate::ebpf::interface::{
    ApplyReport, Binding, BindingCommit, BindingSnapshot, Direction, Hook, InterfacePlan,
    TcProgram, Topology,
};
use crate::netlink::{LinkSnapshot, NlSock};

#[cfg(test)]
mod tests;

/// Kernel mprog chains hold at most 64 programs.
const CHAIN_CAPACITY: usize = 64;

type Key = (NonZeroU32, Direction);

/// clsact priority of every honk filter: the highest, so it runs last, as
/// a TCX link appended with `BPF_F_AFTER` does.
pub(crate) const FILTER_PRIORITY: u16 = 0xfffe;

/// TCX arrived in Linux 6.6. Tests can force the clsact path on any kernel
/// with `HONK_TEST_CLSACT=1`.
pub(crate) fn tcx_supported() -> bool {
    static TCX: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *TCX.get_or_init(|| {
        #[cfg(test)]
        if std::env::var_os("HONK_TEST_CLSACT").is_some() {
            return false;
        }
        super::kernel_version().is_some_and(|version| version >= (6, 6, 0))
    })
}

fn filter_parent(direction: Direction) -> u32 {
    match direction {
        Direction::Ingress => crate::netlink::tc::TC_PARENT_INGRESS,
        Direction::Egress => crate::netlink::tc::TC_PARENT_EGRESS,
    }
}

/// Handles are never reused within a process, so a released filter can only
/// ever delete itself, never a replacement at the same priority.
fn next_filter_handle() -> u32 {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// A clsact filter honk installed. The netlink socket is bound to the
/// namespace the filter lives in, whichever thread drops it.
pub struct TcFilter {
    ifindex: u32,
    direction: Direction,
    handle: u32,
    socket: parking_lot::Mutex<NlSock>,
    /// IDs of every honk TC program: only a filter still running one of them
    /// is deleted, so a recycled ifindex keeps its own filters.
    programs: std::sync::Arc<[u32]>,
}

impl std::fmt::Debug for TcFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcFilter")
            .field("ifindex", &self.ifindex)
            .field("direction", &self.direction)
            .field("handle", &self.handle)
            .finish_non_exhaustive()
    }
}

impl TcFilter {
    pub(crate) fn handle(&self) -> u32 {
        self.handle
    }

    /// The program this filter runs, if it is still on its device.
    pub(crate) fn program_id(&self) -> io::Result<Option<u32>> {
        Ok(self
            .socket
            .lock()
            .dump_filters(self.ifindex, filter_parent(self.direction))?
            .into_iter()
            .find(|entry| entry.priority == FILTER_PRIORITY && entry.handle == self.handle)
            .and_then(|entry| entry.program_id))
    }
}

impl Drop for TcFilter {
    fn drop(&mut self) {
        let owned = self
            .program_id()
            .ok()
            .flatten()
            .is_some_and(|id| self.programs.contains(&id));
        if owned {
            let _ = self.socket.get_mut().del_filter(
                self.ifindex,
                filter_parent(self.direction),
                FILTER_PRIORITY,
                self.handle,
            );
        }
    }
}

#[derive(Default)]
pub(crate) struct InterfaceBindings {
    programs: Vec<(TcProgram, OwnedFd)>,
    owned: Vec<(Binding, u32, Hook)>,
}

impl InterfaceBindings {
    /// Load every TC variant and keep a dup of its program FD, so no
    /// `BPF_PROG_LOAD` (and no verifier run) happens while reconciling. Must
    /// run before `EbpfLogger::init`, which takes a map FD the loads need.
    pub(super) fn preload(bpf: &mut Ebpf) -> anyhow::Result<Self> {
        let mut programs = Vec::with_capacity(TcProgram::ALL.len());
        for program in TcProgram::ALL {
            let name = program.name();
            let classifier: &mut SchedClassifier = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("TC program '{name}' not found"))?
                .try_into()?;
            match classifier.load() {
                Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
                Err(error) => anyhow::bail!("load TC program '{name}': {error}"),
            }
            let fd = classifier
                .fd()?
                .as_fd()
                .try_clone_to_owned()
                .with_context(|| format!("duplicate TC program '{name}' fd"))?;
            programs.push((program, fd));
        }
        Ok(Self {
            programs,
            owned: Vec::new(),
        })
    }

    pub(super) fn owned(&self) -> &[(Binding, u32, Hook)] {
        &self.owned
    }

    #[cfg(test)]
    pub(super) fn programs(&self) -> &[(TcProgram, OwnedFd)] {
        &self.programs
    }

    pub(super) fn snapshot(&self) -> anyhow::Result<BindingSnapshot> {
        Ok(BindingSnapshot {
            programs: self
                .programs
                .iter()
                .map(|(program, fd)| {
                    Ok((*program, fd.try_clone().context("duplicate TC program fd")?))
                })
                .collect::<anyhow::Result<_>>()?,
            owned: self
                .owned
                .iter()
                .map(|(binding, id, hook)| {
                    Ok((
                        binding.clone(),
                        *id,
                        hook.try_clone().context("duplicate hook")?,
                    ))
                })
                .collect::<anyhow::Result<_>>()?,
        })
    }

    pub(super) fn commit(&mut self, commit: BindingCommit) -> Vec<Hook> {
        commit.apply_to(&mut self.owned)
    }

    /// Drops every link (detach). Program FDs stay.
    pub(super) fn release(&mut self) {
        self.owned.clear();
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Held {
    key: Key,
    program: TcProgram,
    link_id: u32,
    interface: String,
}

#[derive(Debug, PartialEq, Eq)]
enum Step<'a> {
    Remove(Key),
    Create(&'a Binding),
    /// Same key, other program: update in place once the link is proven live.
    Reprogram {
        to: &'a Binding,
        from: TcProgram,
        link_id: u32,
    },
    /// Same key and program; only emitted when verifying.
    Check {
        binding: &'a Binding,
        link_id: u32,
    },
    /// Same key, the device has another name now. Bookkeeping only; may come
    /// with a `Reprogram` or `Check` of the same key.
    Rename(&'a Binding),
}

/// The whole diff between what is held and what the plan wants, by
/// `(ifindex, direction)`. Unchanged keys cost nothing unless `verify`.
fn diff<'a>(held: &[Held], wanted: &'a [Binding], verify: bool) -> Vec<Step<'a>> {
    let mut steps: Vec<Step> = held
        .iter()
        .filter(|h| !wanted.iter().any(|b| b.key() == h.key))
        .map(|h| Step::Remove(h.key))
        .collect();
    for binding in wanted {
        let Some(h) = held.iter().find(|h| h.key == binding.key()) else {
            steps.push(Step::Create(binding));
            continue;
        };
        if h.interface != binding.interface {
            steps.push(Step::Rename(binding));
        }
        if h.program != binding.program {
            steps.push(Step::Reprogram {
                to: binding,
                from: h.program,
                link_id: h.link_id,
            });
        } else if verify {
            steps.push(Step::Check {
                binding,
                link_id: h.link_id,
            });
        }
    }
    steps
}

/// What identifies a device for the plan: not its flags or addresses.
fn same_device(a: &LinkSnapshot, b: &LinkSnapshot) -> bool {
    a.name == b.name && a.arphrd == b.arphrd && a.master == b.master && a.kind == b.kind
}

/// Blocking, no lock held. Applies `plan` against the snapshot and returns the
/// commit for the owner plus whatever could not be bound. Partial results are
/// reported as they are; one failure never clears an unrelated binding.
pub(crate) fn apply(
    snapshot: BindingSnapshot,
    plan: &InterfacePlan,
    topology: &Topology,
    verify: bool,
) -> ApplyReport {
    let BindingSnapshot { programs, owned } = snapshot;
    let held: Vec<Held> = owned
        .iter()
        .map(|(binding, link_id, _)| Held {
            key: binding.key(),
            program: binding.program,
            link_id: *link_id,
            interface: binding.interface.clone(),
        })
        .collect();
    let links: HashMap<Key, Hook> = owned
        .into_iter()
        .map(|(binding, _, fd)| (binding.key(), fd))
        .collect();

    let mut report = ApplyReport::default();
    // Created or updated this round; confirmed against a fresh dump below.
    let mut created: Vec<(Binding, u32, Hook)> = Vec::new();
    let mut updated: Vec<(&Binding, u32, TcProgram)> = Vec::new();

    for step in diff(&held, &plan.bindings, verify) {
        match step {
            Step::Remove(key) => report.commit.remove.push(key),
            Step::Rename(binding) => report.commit.rename.push((
                binding.ifindex,
                binding.direction,
                binding.interface.clone(),
            )),
            Step::Create(binding) => {
                create_into(&programs, binding, &mut created, &mut report);
            }
            Step::Check { binding, link_id } => {
                match chain_has(binding, link_id) {
                    Ok(true) => {}
                    // The device went away or moved: the old link is dead.
                    Ok(false) => replace_dead(&programs, binding, &mut created, &mut report),
                    // Not proof of absence: keep the binding, never recreate.
                    Err(error) => report.failed.push((binding.clone(), error)),
                }
            }
            Step::Reprogram { to, from, link_id } => match chain_has(to, link_id) {
                Ok(true) => match update(&programs, &links, to, from) {
                    Ok(()) => updated.push((to, link_id, from)),
                    // The old owner and program stay as they were.
                    Err(error) => report.failed.push((to.clone(), error)),
                },
                Ok(false) => replace_dead(&programs, to, &mut created, &mut report),
                Err(error) => report.failed.push((to.clone(), error)),
            },
        }
    }

    if !created.is_empty() || !updated.is_empty() {
        let fresh = crate::ebpf::interface::dump_links();
        for (binding, link_id, fd) in created {
            match confirm(&binding, link_id, &fresh, topology) {
                Ok(true) => report.commit.add.push((binding, link_id, fd)),
                confirmation => {
                    // Drop the new FD and forget any dead owner it would have
                    // replaced. Other healthy keys are untouched.
                    if links.contains_key(&binding.key()) {
                        report.commit.remove.push(binding.key());
                    }
                    match confirmation {
                        Ok(false) => report.topology_changed = true,
                        Err(error) => report.failed.push((binding, error)),
                        Ok(true) => unreachable!(),
                    }
                }
            }
        }
        for (binding, link_id, from) in updated {
            match confirm(binding, link_id, &fresh, topology) {
                Ok(true) => report.commit.reprogram.push((
                    binding.ifindex,
                    binding.direction,
                    binding.program,
                )),
                confirmation => {
                    match confirmation {
                        Ok(false) => report.topology_changed = true,
                        Err(error) => report.failed.push((binding.clone(), error)),
                        Ok(true) => unreachable!(),
                    }
                    // Restore the previous program before keeping the old owner.
                    let mut previous = binding.clone();
                    previous.program = from;
                    if let Err(error) = update(&programs, &links, &previous, binding.program) {
                        // Even a failed rollback must leave the owner truthful.
                        report.commit.reprogram.push((
                            binding.ifindex,
                            binding.direction,
                            binding.program,
                        ));
                        report.failed.push((
                            binding.clone(),
                            error.context("restore program after topology changed"),
                        ));
                    }
                }
            }
        }
    }
    report
}

fn program_fd(programs: &[(TcProgram, OwnedFd)], program: TcProgram) -> anyhow::Result<&OwnedFd> {
    programs
        .iter()
        .find(|(p, _)| *p == program)
        .map(|(_, fd)| fd)
        .ok_or_else(|| anyhow::anyhow!("TC program {} is not preloaded", program.name()))
}

fn create_into(
    programs: &[(TcProgram, OwnedFd)],
    binding: &Binding,
    created: &mut Vec<(Binding, u32, Hook)>,
    report: &mut ApplyReport,
) -> bool {
    match create(programs, binding) {
        Ok((link_id, fd)) => {
            created.push((binding.clone(), link_id, fd));
            true
        }
        // The device vanished between the dump and the attach: not a failure
        // of the attach, the next dump simply no longer has it.
        Err(error) if device_gone(&error) => {
            report.topology_changed = true;
            false
        }
        Err(error) => {
            report.failed.push((binding.clone(), error));
            false
        }
    }
}

fn device_gone(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|io| io.raw_os_error() == Some(libc::ENODEV))
    })
}

/// The held link is gone from this namespace's chain. Release that owner even
/// if creating or confirming the replacement fails.
fn replace_dead(
    programs: &[(TcProgram, OwnedFd)],
    binding: &Binding,
    created: &mut Vec<(Binding, u32, Hook)>,
    report: &mut ApplyReport,
) {
    if !create_into(programs, binding, created, report) {
        report.commit.remove.push(binding.key());
    }
}

fn create(programs: &[(TcProgram, OwnedFd)], binding: &Binding) -> anyhow::Result<(u32, Hook)> {
    let program = program_fd(programs, binding.program)?;
    let context = || {
        format!(
            "attach {} to {} (ifindex {}, {:?})",
            binding.program.name(),
            binding.interface,
            binding.ifindex,
            binding.direction
        )
    };
    if !tcx_supported() {
        let filter = create_filter(programs, program, binding).with_context(context)?;
        return Ok((filter.handle, Hook::Filter(std::sync::Arc::new(filter))));
    }
    let fd =
        link_create(program, binding.ifindex.get(), binding.direction).with_context(context)?;
    let info = link_info(fd.as_raw_fd()).context("read the new TCX link")?;
    Ok((info.id, Hook::Link(fd)))
}

/// A filter at honk's priority that runs none of this process's programs was
/// left by an instance that died without detaching: remove it first.
fn create_filter(
    programs: &[(TcProgram, OwnedFd)],
    program: &OwnedFd,
    binding: &Binding,
) -> anyhow::Result<TcFilter> {
    let ids: std::sync::Arc<[u32]> = programs
        .iter()
        .map(|(_, fd)| program_id(fd.as_raw_fd()))
        .collect::<io::Result<Vec<_>>>()
        .context("read TC program IDs")?
        .into();
    let (ifindex, parent) = (binding.ifindex.get(), filter_parent(binding.direction));
    let mut socket = NlSock::new().context("netlink socket")?;
    socket.add_clsact(ifindex).context("add clsact qdisc")?;
    for stale in socket
        .dump_filters(ifindex, parent)
        .context("list filters")?
    {
        if stale.priority == FILTER_PRIORITY
            && !stale.program_id.is_some_and(|id| ids.contains(&id))
        {
            socket
                .del_filter(ifindex, parent, FILTER_PRIORITY, stale.handle)
                .context("remove a stale honk filter")?;
        }
    }
    let handle = next_filter_handle();
    socket
        .set_bpf_filter(
            ifindex,
            parent,
            FILTER_PRIORITY,
            handle,
            program.as_raw_fd(),
            binding.program.name(),
            true,
        )
        .context("add clsact filter")?;
    Ok(TcFilter {
        ifindex,
        direction: binding.direction,
        handle,
        socket: parking_lot::Mutex::new(socket),
        programs: ids,
    })
}

fn update(
    programs: &[(TcProgram, OwnedFd)],
    links: &HashMap<Key, Hook>,
    to: &Binding,
    from: TcProgram,
) -> anyhow::Result<()> {
    let new = program_fd(programs, to.program)?;
    let old = program_fd(programs, from)?;
    let hook = links
        .get(&to.key())
        .ok_or_else(|| anyhow::anyhow!("owned link is missing from the snapshot"))?;
    let result = match hook {
        Hook::Link(link) => link_update(link.as_raw_fd(), new.as_raw_fd(), old.as_raw_fd()),
        Hook::Filter(filter) => filter_update(filter, new, old, to.program.name()),
    };
    result.with_context(|| {
        format!(
            "replace {} with {} on {} (ifindex {}, {:?})",
            from.name(),
            to.program.name(),
            to.interface,
            to.ifindex,
            to.direction
        )
    })
}

/// clsact has no compare-and-swap: the expected program is checked first,
/// then the filter is changed in place, which never leaves a gap.
fn filter_update(filter: &TcFilter, new: &OwnedFd, old: &OwnedFd, name: &str) -> io::Result<()> {
    let expected = program_id(old.as_raw_fd())?;
    if filter.program_id()? != Some(expected) {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    filter.socket.lock().set_bpf_filter(
        filter.ifindex,
        filter_parent(filter.direction),
        FILTER_PRIORITY,
        filter.handle,
        new.as_raw_fd(),
        name,
        false,
    )
}

/// `BPF_OBJ_GET_INFO_BY_FD` on a program.
pub(super) fn program_id(program: RawFd) -> io::Result<u32> {
    let mut info: aya_obj::generated::bpf_prog_info = unsafe { core::mem::zeroed() };
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.info.bpf_fd = program as u32;
    attr.info.info_len = size_of::<aya_obj::generated::bpf_prog_info>() as u32;
    attr.info.info = (&mut info as *mut aya_obj::generated::bpf_prog_info) as u64;
    unsafe { bpf_syscall(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as c_long, &mut attr) }.map_err(errno)?;
    Ok(info.id)
}

/// Is `link_id` on the chain of the calling thread's network namespace?
fn chain_has(binding: &Binding, link_id: u32) -> anyhow::Result<bool> {
    if !tcx_supported() {
        return filter_chain(binding.ifindex.get(), binding.direction)
            .map(|chain| chain.contains_link(link_id))
            .with_context(|| {
                format!(
                    "verify {} (ifindex {}, {:?}): list clsact filters",
                    binding.interface, binding.ifindex, binding.direction
                )
            });
    }
    let chain = query_chain(binding.ifindex.get(), binding.direction).with_context(|| {
        format!(
            "verify {} (ifindex {}, {:?}): query TCX chain",
            binding.interface, binding.ifindex, binding.direction
        )
    })?;
    Ok(chain.contains_link(link_id))
}

/// After a create or update: the device must still be the planned one and the
/// link must be on its chain. `Ok(false)` means the topology moved on.
fn confirm(
    binding: &Binding,
    link_id: u32,
    fresh: &io::Result<Vec<LinkSnapshot>>,
    planned: &Topology,
) -> anyhow::Result<bool> {
    let fresh = fresh
        .as_ref()
        .map_err(|error| anyhow::anyhow!("re-read links after attach: {error}"))?;
    let before = planned
        .links
        .iter()
        .find(|link| link.ifindex == binding.ifindex);
    let after = fresh.iter().find(|link| link.ifindex == binding.ifindex);
    match (before, after) {
        (Some(before), Some(after)) if same_device(before, after) => {}
        _ => return Ok(false),
    }
    chain_has(binding, link_id)
}

/// Handles of honk-priority filters, as a chain whose "link IDs" are handles.
pub(super) fn filter_chain(ifindex: u32, direction: Direction) -> io::Result<Chain> {
    let links = NlSock::new()?
        .dump_filters(ifindex, filter_parent(direction))?
        .into_iter()
        .filter(|entry| entry.priority == FILTER_PRIORITY && entry.program_id.is_some())
        .map(|entry| entry.handle)
        .collect();
    Ok(Chain { links })
}

/// Link IDs on one chain, in order; 0 marks a legacy (non-link) attachment.
#[derive(Debug, Default)]
pub(super) struct Chain {
    pub links: Vec<u32>,
}

impl Chain {
    pub(super) fn contains_link(&self, link_id: u32) -> bool {
        link_id != 0 && self.links.contains(&link_id)
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct LinkInfo {
    pub id: u32,
    pub program_id: u32,
    pub ifindex: u32,
    pub attach_type: u32,
}

fn errno(code: c_long) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

pub(super) fn tcx_attach_type(direction: Direction) -> u32 {
    (match direction {
        Direction::Ingress => bpf_attach_type::BPF_TCX_INGRESS,
        Direction::Egress => bpf_attach_type::BPF_TCX_EGRESS,
    }) as u32
}

/// `BPF_LINK_CREATE` on an interface index, appended last (`BPF_F_AFTER` with
/// relative fd 0: the order `SchedClassifier::attach` uses).
fn link_create(program: &OwnedFd, ifindex: u32, direction: Direction) -> io::Result<OwnedFd> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.link_create.__bindgen_anon_1.prog_fd = program.as_raw_fd() as u32;
    attr.link_create.__bindgen_anon_2.target_ifindex = ifindex;
    attr.link_create.attach_type = tcx_attach_type(direction);
    attr.link_create.flags = BPF_F_AFTER;
    let fd =
        unsafe { bpf_syscall(bpf_cmd::BPF_LINK_CREATE as c_long, &mut attr) }.map_err(errno)?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// `BPF_LINK_UPDATE` that fails unless the link still runs `old`.
fn link_update(link: RawFd, new: RawFd, old: RawFd) -> io::Result<()> {
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.link_update.link_fd = link as u32;
    attr.link_update.__bindgen_anon_1.new_prog_fd = new as u32;
    attr.link_update.flags = BPF_F_REPLACE;
    attr.link_update.__bindgen_anon_2.old_prog_fd = old as u32;
    unsafe { bpf_syscall(bpf_cmd::BPF_LINK_UPDATE as c_long, &mut attr) }
        .map(|_| ())
        .map_err(errno)
}

pub(super) fn link_info(link: RawFd) -> io::Result<LinkInfo> {
    let mut info: bpf_link_info = unsafe { core::mem::zeroed() };
    let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
    attr.info.bpf_fd = link as u32;
    attr.info.info_len = size_of::<bpf_link_info>() as u32;
    attr.info.info = (&mut info as *mut bpf_link_info) as u64;
    unsafe { bpf_syscall(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD as c_long, &mut attr) }.map_err(errno)?;
    let tcx = unsafe { info.__bindgen_anon_1.tcx };
    Ok(LinkInfo {
        id: info.id,
        program_id: info.prog_id,
        ifindex: tcx.ifindex,
        attach_type: tcx.attach_type,
    })
}

/// `BPF_PROG_QUERY` by interface index. Both ID buffers are required: without
/// `prog_ids` the kernel returns before filling `link_ids`. `ENOSPC` carries
/// the real count, so one retry with that size is exact.
pub(super) fn query_chain(ifindex: u32, direction: Direction) -> io::Result<Chain> {
    let mut capacity = CHAIN_CAPACITY;
    for attempt in 0..2 {
        let mut programs = vec![0u32; capacity];
        let mut links = vec![0u32; capacity];
        let mut attr: bpf_attr = unsafe { core::mem::zeroed() };
        attr.query.__bindgen_anon_1.target_ifindex = ifindex;
        attr.query.attach_type = tcx_attach_type(direction);
        attr.query.__bindgen_anon_2.prog_cnt = capacity as u32;
        attr.query.prog_ids = programs.as_mut_ptr() as u64;
        attr.query.link_ids = links.as_mut_ptr() as u64;
        let result = unsafe { bpf_syscall(bpf_cmd::BPF_PROG_QUERY as c_long, &mut attr) };
        let count = unsafe { attr.query.__bindgen_anon_2.prog_cnt } as usize;
        match result {
            Ok(_) => {
                links.truncate(count);
                return Ok(Chain { links });
            }
            Err(code) if code == libc::ENOSPC as c_long && attempt == 0 && count > capacity => {
                capacity = count;
            }
            Err(code) => return Err(errno(code)),
        }
    }
    unreachable!("the second attempt returns")
}

impl super::RealEbpfBackend {
    /// Startup bind, before the backend is shared, using the watcher's apply.
    pub(crate) fn bind_interfaces(
        &mut self,
        plan: &InterfacePlan,
        topology: &Topology,
    ) -> ApplyReport {
        let snapshot = match self.bindings.snapshot() {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return ApplyReport {
                    failed: plan
                        .bindings
                        .iter()
                        .map(|binding| {
                            (
                                binding.clone(),
                                anyhow::anyhow!("snapshot interface bindings: {error:#}"),
                            )
                        })
                        .collect(),
                    ..ApplyReport::default()
                };
            }
        };
        let mut report = apply(snapshot, plan, topology, false);
        drop(self.bindings.commit(std::mem::take(&mut report.commit)));
        report
    }

    pub(crate) fn owned_bindings(&self) -> impl Iterator<Item = &Binding> {
        self.bindings.owned().iter().map(|(binding, ..)| binding)
    }
}

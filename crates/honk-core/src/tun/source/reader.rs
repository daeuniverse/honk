use super::Read;
use crate::control::netstack::HostIngress;
use honk_ebpf_common::host::{HOST_CAPTURE_HORIZON_NS, HOST_ID_MAX, HOST_STAGE_TUN_EGRESS};
use honk_ebpf_common::tun::*;
use std::io;
use std::os::fd::{AsRawFd as _, BorrowedFd, RawFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

struct Mapping {
    address: NonNull<u8>,
    length: usize,
}

// The sole Source moves between workers only outside its synchronous read window.
unsafe impl Send for Mapping {}

impl Mapping {
    fn new(fd: BorrowedFd<'_>, extent: usize) -> io::Result<Self> {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page <= 0 {
            return Err(io::Error::last_os_error());
        }
        let length = extent
            .checked_next_multiple_of(page as usize)
            .ok_or_else(|| invalid("TUN map mapping extent overflow"))?;
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            address: NonNull::new(address.cast()).expect("non-null mmap"),
            length,
        })
    }

    fn at<T>(&self) -> *mut T {
        self.address.as_ptr().cast()
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.address.as_ptr().cast(), self.length);
        }
    }
}

pub(super) struct Reader {
    window: Mapping,
    owner: Mapping,
    read_id: u64,
    owner_epoch: u64,
    attachment: u64,
    netns_cookie: u64,
    ifindex: u32,
    closed: bool,
}

#[derive(Debug)]
struct Expired;
impl std::fmt::Display for Expired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authenticated TUN Host source expired")
    }
}
impl std::error::Error for Expired {}

pub(crate) fn is_expired(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|cause| cause.is::<Expired>())
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

unsafe fn atomic<'a>(field: *mut u64) -> &'a AtomicU64 {
    unsafe { AtomicU64::from_ptr(field) }
}

impl Reader {
    pub(super) fn new(window: BorrowedFd<'_>, owner: BorrowedFd<'_>) -> io::Result<Self> {
        Ok(Self {
            window: Mapping::new(window, TUN_WINDOW_EXTENT)?,
            owner: Mapping::new(owner, TUN_OWNER_EXTENT)?,
            read_id: 0,
            owner_epoch: 0,
            attachment: 0,
            netns_cookie: 0,
            ifindex: 0,
            closed: false,
        })
    }

    pub(super) fn bind(
        &mut self,
        owner_epoch: u64,
        attachment: u64,
        netns_cookie: u64,
        ifindex: u32,
    ) -> io::Result<()> {
        if self.owner_epoch != 0 {
            return Err(invalid("TUN read owner rebound"));
        }
        self.owner_epoch = owner_epoch;
        self.attachment = attachment;
        self.netns_cookie = netns_cookie;
        self.ifindex = ifindex;
        let owner = self.owner.at::<TunOwnerV1>();
        unsafe {
            let actual = owner.read_volatile();
            if actual.magic != TUN_ABI_MAGIC
                || actual.version != TUN_ABI_VERSION
                || actual.extent as usize != TUN_OWNER_EXTENT
                || actual.fatal != 0
                || actual.gate != 0
            {
                return Err(invalid("TUN owner schema/state mismatch"));
            }
            (&raw mut (*owner).owner_epoch).write_volatile(owner_epoch);
            (&raw mut (*owner).attachment).write_volatile(attachment);
            (&raw mut (*owner).netns_cookie).write_volatile(netns_cookie);
            (&raw mut (*owner).output_ifindex).write_volatile(ifindex);
            (&raw mut (*owner).owner_tgid).write_volatile(std::process::id());
            self.window
                .at::<TunReadWindowV1>()
                .write_volatile(TunReadWindowV1::default());
        }
        Ok(())
    }

    pub(super) fn read(&mut self, fd: RawFd, buffer: &mut [u8], binding: bool) -> io::Result<Read> {
        if self.closed {
            return Err(invalid("TUN read owner closed after unresolved completion"));
        }
        let result = self.read_inner(fd, buffer, binding);
        if result.as_ref().is_err_and(|error| {
            !is_expired(error)
                && !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                )
        }) {
            self.closed = true;
        }
        result
    }

    fn read_inner(&mut self, fd: RawFd, buffer: &mut [u8], binding: bool) -> io::Result<Read> {
        let owner = self.owner.at::<TunOwnerV1>();
        let window = self.window.at::<TunReadWindowV1>();
        let previous = unsafe { atomic(&raw mut (*window).phase).load(Ordering::Acquire) };
        let fatal = unsafe {
            atomic(&raw mut (*window).fatal).load(Ordering::Acquire)
                | atomic(&raw mut (*owner).fatal).load(Ordering::Acquire)
        };
        if fatal != 0 || !matches!(previous, TUN_PHASE_IDLE | TUN_PHASE_COMPLETE) {
            return Err(invalid(format!(
                "TUN source unresolved window phase={previous} fatal={fatal}"
            )));
        }
        let read_id = self
            .read_id
            .checked_add(1)
            .filter(|id| *id <= HOST_ID_MAX)
            .ok_or_else(|| invalid("TUN read incarnation exhausted"))?;
        let reader_tid = u32::try_from(unsafe { libc::syscall(libc::SYS_gettid) })
            .map_err(|_| invalid("invalid TUN reader tid"))?;
        let request = TunReadWindowV1 {
            owner_epoch: self.owner_epoch,
            attachment: self.attachment,
            netns_cookie: self.netns_cookie,
            read_id,
            requested_extent: buffer.len() as u64,
            output_ifindex: self.ifindex,
            reader_tid,
            owner_tgid: std::process::id(),
            acknowledged_read_id: self.read_id,
            ..TunReadWindowV1::default()
        };
        unsafe {
            window.write_volatile(request);
            atomic(&raw mut (*window).phase).store(TUN_PHASE_ARMED, Ordering::Release);
        }
        self.read_id = read_id;
        let returned = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        let error = (returned < 0).then(io::Error::last_os_error);
        let phase = unsafe { atomic(&raw mut (*window).phase).load(Ordering::Acquire) };
        if phase != TUN_PHASE_COMPLETE {
            return Err(invalid(format!(
                "TUN read {read_id} returned {returned}, errno={:?}, missing outer completion phase={phase}",
                error.as_ref().and_then(io::Error::raw_os_error)
            )));
        }
        let completion = unsafe { window.read_volatile() };
        let actual_result = if returned < 0 {
            -i64::from(
                error
                    .as_ref()
                    .and_then(io::Error::raw_os_error)
                    .unwrap_or(libc::EIO),
            )
        } else {
            returned as i64
        };
        let result = self.reconcile(&request, &completion, actual_result, binding);
        unsafe {
            (&raw mut (*window).acknowledged_read_id).write_volatile(read_id);
        }
        result?;
        if let Some(error) = error {
            return Err(error);
        }
        let len = usize::try_from(returned).map_err(|_| invalid("negative TUN successful read"))?;
        let host = match completion.source_kind {
            TUN_SOURCE_PLAIN => None,
            TUN_SOURCE_HOST => {
                let source_horizon = horizon(completion.captured_ns, completion.expires_ns)?;
                Some(HostIngress {
                    facts: completion.source,
                    source_horizon,
                })
            }
            _ => return Err(invalid("unknown TUN source outcome")),
        };
        Ok(Read { len, host })
    }

    fn reconcile(
        &self,
        request: &TunReadWindowV1,
        completion: &TunReadWindowV1,
        actual_result: i64,
        binding: bool,
    ) -> io::Result<()> {
        if completion.magic != TUN_ABI_MAGIC
            || completion.version != TUN_ABI_VERSION
            || completion.extent as usize != TUN_WINDOW_EXTENT
            || completion.owner_epoch != request.owner_epoch
            || completion.attachment != request.attachment
            || completion.netns_cookie != request.netns_cookie
            || completion.output_ifindex != request.output_ifindex
            || completion.read_id != request.read_id
            || completion.reader_tid != request.reader_tid
            || completion.owner_tgid != request.owner_tgid
            || completion.requested_extent != request.requested_extent
            || completion.acknowledged_read_id != request.acknowledged_read_id
            || completion.outer_result != actual_result
            || completion.fatal != 0
            || completion.actual_task_address == 0
            || completion.actual_task_start_boottime == 0
            || completion.actual_leader_start_boottime == 0
            || completion.actual_file_address == 0
            || completion.actual_tfile_address == 0
            || completion.actual_tun_address == 0
            || completion.actual_iocb_address == 0
            || completion.actual_iter_address == 0
            || completion.outer_entry_count != request.requested_extent
        {
            return Err(invalid(format!(
                "TUN read {} source mismatch: syscall={actual_result}, outer={}, status={}, fatal={:#x}, witnesses={:#x}, counts={}/{}/{}/{}, copy={}/{}/{}, read_id={}/{}, ack={}/{}, tid={}/{}, tgid={}/{}",
                request.read_id,
                completion.outer_result,
                completion.status,
                completion.fatal,
                completion.witnesses,
                completion.outer_entry_count,
                completion.copy_entry_count,
                completion.copy_exit_count,
                completion.outer_exit_count,
                completion.copy_offset,
                completion.copy_length,
                completion.copy_result,
                completion.read_id,
                request.read_id,
                completion.acknowledged_read_id,
                request.acknowledged_read_id,
                completion.reader_tid,
                request.reader_tid,
                completion.owner_tgid,
                request.owner_tgid
            )));
        }
        if completion.status == TUN_STATUS_NO_RECORD {
            let expected = TUN_WITNESS_OUTER_ENTRY | TUN_WITNESS_OUTER_EXIT;
            if completion.witnesses != expected
                || !matches!(actual_result, value if value == -i64::from(libc::EAGAIN) || value == -i64::from(libc::EINTR))
                || completion.outer_exit_count != completion.outer_entry_count
                || completion.packet_id != 0
                || completion.copy_length != 0
                || completion.original_skb_address != 0
            {
                return Err(invalid(
                    "TUN no-record completion consumed or failed to witness its read",
                ));
            }
            return Ok(());
        }
        if binding
            || completion.status != TUN_STATUS_COMPLETE_RECORD
            || completion.witnesses != TUN_WITNESS_ALL
            || actual_result <= 10
            || actual_result as u64 >= request.requested_extent
            || completion.original_record_len as u64 + 10 != actual_result as u64
            || completion.copy_offset != 0
            || completion.copy_length != completion.original_record_len
            || completion.copy_result != 0
            || completion.packet_id == 0
            || completion.packet_id > HOST_ID_MAX
            || completion.packet_cell >= TUN_PACKET_CELLS
            || completion.original_skb_address == 0
            || completion
                .copy_entry_count
                .checked_sub(completion.copy_exit_count)
                != Some(completion.copy_length as u64)
            || completion
                .outer_entry_count
                .checked_sub(completion.outer_exit_count)
                != Some(actual_result as u64)
        {
            return Err(invalid(format!(
                "TUN read {} incomplete real-copy completion (actual result {actual_result})",
                request.read_id
            )));
        }
        match completion.source_kind {
            TUN_SOURCE_PLAIN if completion.source == Default::default() => Ok(()),
            TUN_SOURCE_HOST
                if completion.source.is_valid()
                    && completion.source.stage == HOST_STAGE_TUN_EGRESS
                    && completion.source.netns_cookie == self.netns_cookie
                    && completion.source.attachment == self.attachment
                    && completion.source.return_generation == self.attachment
                    && completion.source.output_ifindex == self.ifindex
                    && completion.expires_ns.checked_sub(completion.captured_ns)
                        == Some(HOST_CAPTURE_HORIZON_NS) =>
            {
                Ok(())
            }
            _ => Err(invalid(
                "TUN completion has invalid or cross-stage source facts",
            )),
        }
    }

    pub(super) fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        let window = self.window.at::<TunReadWindowV1>();
        let phase = unsafe { atomic(&raw mut (*window).phase).load(Ordering::Acquire) };
        if matches!(phase, TUN_PHASE_ARMED | TUN_PHASE_ENTERED) {
            return Err(invalid("TUN source close retains unresolved read window"));
        }
        unsafe {
            atomic(&raw mut (*window).phase).store(TUN_PHASE_CLOSED, Ordering::Release);
        }
        Ok(())
    }

    pub(super) fn finish(&self) -> io::Result<()> {
        let owner = self.owner.at::<TunOwnerV1>();
        let completed = unsafe { atomic(&raw mut (*owner).close_exit).load(Ordering::Acquire) };
        let value = unsafe { owner.read_volatile() };
        if completed != 1
            || value.close_enter != 1
            || value.close_file_address != value.bound_file_address
            || value.close_tfile_address != value.bound_tfile_address
            || value.close_tun_address != value.bound_tun_address
            || value.bound_file_address == 0
            || value.close_task_address == 0
            || value.gate != 0
            || value.owner_epoch != self.owner_epoch
            || value.attachment != self.attachment
        {
            return Err(invalid(
                "TUN final owned file detach/purge was not witnessed; retaining source custody",
            ));
        }
        Ok(())
    }

    pub(super) fn close_after_release(&mut self) {
        self.closed = true;
        let window = self.window.at::<TunReadWindowV1>();
        unsafe {
            (&raw mut (*window).acknowledged_read_id).write_volatile(self.read_id);
            atomic(&raw mut (*window).phase).store(TUN_PHASE_CLOSED, Ordering::Release);
        }
    }
}

fn horizon(captured_ns: u64, expires_ns: u64) -> io::Result<Instant> {
    if expires_ns.checked_sub(captured_ns) != Some(HOST_CAPTURE_HORIZON_NS) {
        return Err(invalid("invalid TUN source capture interval"));
    }
    let earlier = Instant::now();
    let mut time: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let sampled = u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| seconds.checked_add(time.tv_nsec as u64))
        .ok_or_else(|| invalid("TUN monotonic clock overflow"))?;
    if captured_ns > sampled {
        return Err(invalid("future TUN capture timestamp"));
    }
    let remaining = expires_ns
        .checked_sub(sampled)
        .filter(|remaining| *remaining != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, Expired))?;
    earlier
        .checked_add(Duration::from_nanos(remaining))
        .ok_or_else(|| invalid("TUN source horizon overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_authenticated_expiry_is_packet_local() {
        assert!(is_expired(&io::Error::new(
            io::ErrorKind::TimedOut,
            Expired
        )));
        assert!(!is_expired(&io::Error::new(
            io::ErrorKind::TimedOut,
            "read timed out"
        )));
        assert!(horizon(10, 9).is_err());
        assert!(horizon(u64::MAX - HOST_CAPTURE_HORIZON_NS, u64::MAX).is_err());
    }

    #[test]
    fn completion_requires_same_read_and_real_copy_delta() {
        use std::os::fd::AsFd as _;
        let backing = tempfile::tempfile().unwrap();
        backing.set_len(4096).unwrap();
        let mut reader = Reader::new(backing.as_fd(), backing.as_fd()).unwrap();
        reader.owner_epoch = 1;
        reader.attachment = 2;
        reader.netns_cookie = 3;
        reader.ifindex = 4;
        let request = TunReadWindowV1 {
            owner_epoch: 1,
            attachment: 2,
            netns_cookie: 3,
            output_ifindex: 4,
            read_id: 5,
            requested_extent: 100,
            reader_tid: 6,
            owner_tgid: 7,
            acknowledged_read_id: 4,
            ..TunReadWindowV1::default()
        };
        let completion = TunReadWindowV1 {
            phase: TUN_PHASE_COMPLETE,
            actual_task_address: 1,
            actual_task_start_boottime: 1,
            actual_leader_start_boottime: 1,
            actual_file_address: 1,
            actual_tfile_address: 1,
            actual_tun_address: 1,
            actual_iocb_address: 1,
            actual_iter_address: 1,
            outer_entry_count: 100,
            copy_entry_count: 90,
            copy_exit_count: 70,
            outer_exit_count: 70,
            packet_id: 8,
            original_skb_address: 9,
            original_record_len: 20,
            copy_length: 20,
            outer_result: 30,
            witnesses: TUN_WITNESS_ALL,
            status: TUN_STATUS_COMPLETE_RECORD,
            ..request
        };
        assert!(reader.reconcile(&request, &completion, 30, false).is_ok());
        for bad in [
            TunReadWindowV1 {
                read_id: 4,
                ..completion
            },
            TunReadWindowV1 {
                witnesses: TUN_WITNESS_ALL ^ TUN_WITNESS_OUTER_EXIT,
                ..completion
            },
            TunReadWindowV1 {
                copy_exit_count: 71,
                ..completion
            },
            TunReadWindowV1 {
                outer_exit_count: 71,
                ..completion
            },
            TunReadWindowV1 {
                copy_result: -14,
                ..completion
            },
            TunReadWindowV1 {
                source_kind: TUN_SOURCE_HOST,
                ..completion
            },
        ] {
            assert!(reader.reconcile(&request, &bad, 30, false).is_err());
        }
        assert!(reader.reconcile(&request, &completion, 31, false).is_err());
        let empty = TunReadWindowV1 {
            status: TUN_STATUS_NO_RECORD,
            witnesses: TUN_WITNESS_OUTER_ENTRY | TUN_WITNESS_OUTER_EXIT,
            outer_result: -i64::from(libc::EAGAIN),
            outer_exit_count: 100,
            packet_id: 0,
            original_skb_address: 0,
            original_record_len: 0,
            copy_length: 0,
            copy_entry_count: 0,
            copy_exit_count: 0,
            ..completion
        };
        assert!(
            reader
                .reconcile(&request, &empty, -i64::from(libc::EAGAIN), true)
                .is_ok()
        );
        assert!(
            reader
                .reconcile(
                    &request,
                    &TunReadWindowV1 {
                        copy_length: 1,
                        ..empty
                    },
                    -i64::from(libc::EAGAIN),
                    false
                )
                .is_err()
        );
        assert!(
            reader
                .reconcile(
                    &request,
                    &TunReadWindowV1 {
                        outer_exit_count: 99,
                        ..empty
                    },
                    -i64::from(libc::EAGAIN),
                    false
                )
                .is_err()
        );
        assert!(
            reader
                .reconcile(
                    &request,
                    &TunReadWindowV1 {
                        outer_result: -i64::from(libc::EIO),
                        ..empty
                    },
                    -i64::from(libc::EIO),
                    false
                )
                .is_err()
        );
    }

    #[test]
    fn final_release_requires_the_bound_file_lifetime() {
        use std::os::fd::AsFd as _;
        let backing = tempfile::tempfile().unwrap();
        backing.set_len(4096).unwrap();
        let mut reader = Reader::new(backing.as_fd(), backing.as_fd()).unwrap();
        reader.owner_epoch = 1;
        reader.attachment = 2;
        let owner = reader.owner.at::<TunOwnerV1>();
        let released = TunOwnerV1 {
            owner_epoch: 1,
            attachment: 2,
            bound_file_address: 11,
            bound_tfile_address: 12,
            bound_tun_address: 13,
            close_enter: 1,
            close_exit: 1,
            close_file_address: 11,
            close_tfile_address: 12,
            close_tun_address: 13,
            close_task_address: 14,
            ..TunOwnerV1::default()
        };
        unsafe {
            owner.write_volatile(released);
        }
        assert!(reader.finish().is_ok());
        unsafe {
            owner.write_volatile(TunOwnerV1 {
                close_file_address: 15,
                ..released
            });
        }
        assert!(reader.finish().is_err());
        unsafe {
            owner.write_volatile(TunOwnerV1 {
                close_exit: 0,
                ..released
            });
        }
        assert!(reader.finish().is_err());
    }
}

use std::alloc::Layout;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use honk_netstack::{MemoryBudget, MemoryReservation};

use super::{BindMode, FRAME_SIZE, PortConfig, RingSnapshot, SocketStats};

pub(super) type Descriptor = libc::xdp_desc;

// No supported DMA-release fence exists, so fresh budgets cannot bypass this ceiling.
pub(super) const RETAINED_UMEM_LIMIT: usize = 512 * 1024 * 1024;
static RETAINED_UMEM_BYTES: AtomicUsize = AtomicUsize::new(0);

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn reserve(budget: &Arc<MemoryBudget>, bytes: usize) -> io::Result<MemoryReservation> {
    budget
        .reserve(bytes)
        .ok_or_else(|| io::Error::other("AF_XDP memory budget exhausted"))
}

fn page_size() -> io::Result<usize> {
    // SAFETY: sysconf has no pointer arguments or side effects on ownership.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(page)
        .ok()
        .filter(|page| page.is_power_of_two())
        .ok_or_else(|| invalid("invalid system page size"))
}

fn page_extent(bytes: usize, page: usize) -> io::Result<usize> {
    bytes
        .checked_add(page - 1)
        .map(|n| n & !(page - 1))
        .filter(|&n| n != 0 && n <= isize::MAX as usize)
        .ok_or_else(|| invalid("mapping extent overflow"))
}

/// B-UMEM-RELEASE is unresolved: neither the mapping nor its charge is released in-process.
pub(super) struct Umem {
    pointer: NonNull<u8>,
    bytes: usize,
    _reservation: ManuallyDrop<MemoryReservation>,
    #[cfg(test)]
    _heap: Option<ManuallyDrop<Box<[u8]>>>,
}

// SAFETY: moving the sole userspace owner does not move the mapping. Access to a frame is
// serialized by Port's ledger, including the interval in which the kernel owns that frame.
unsafe impl Send for Umem {}

impl Umem {
    pub(super) fn map(bytes: usize, budget: &Arc<MemoryBudget>) -> io::Result<Self> {
        let page = page_size()?;
        let extent = page_extent(bytes, page)?;
        let reservation = reserve(budget, extent)?;
        RETAINED_UMEM_BYTES
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(extent)
                    .filter(|&next| next <= RETAINED_UMEM_LIMIT)
            })
            .map_err(|_| io::Error::other("process retained UMEM ceiling exhausted"))?;
        // SAFETY: extent is nonzero, page-rounded, and within isize::MAX; no address is fixed.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                extent,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            RETAINED_UMEM_BYTES.fetch_sub(extent, Ordering::AcqRel);
            return Err(io::Error::last_os_error());
        }
        let reservation = ManuallyDrop::new(reservation);
        let pointer = NonNull::new(mapping.cast::<u8>())
            .filter(|pointer| (pointer.as_ptr() as usize).is_multiple_of(page))
            .ok_or_else(|| invalid("UMEM mapping is null or not page aligned"))?;
        Ok(Self {
            pointer,
            bytes,
            #[cfg(test)]
            _heap: None,
            _reservation: reservation,
        })
    }

    pub(super) fn bytes(&self) -> usize {
        self.bytes
    }

    fn extent(&self, address: u64, length: usize) -> io::Result<usize> {
        let offset = usize::try_from(address).map_err(|_| invalid("UMEM address overflow"))?;
        let end = offset
            .checked_add(length)
            .filter(|&end| end <= self.bytes)
            .ok_or_else(|| invalid("descriptor escapes UMEM"))?;
        if length == 0 || length > FRAME_SIZE - offset % FRAME_SIZE || end > isize::MAX as usize {
            return Err(invalid("descriptor is empty or crosses a UMEM chunk"));
        }
        Ok(offset)
    }

    pub(super) fn frame(&self, address: u64, length: usize) -> io::Result<&[u8]> {
        let offset = self.extent(address, length)?;
        // SAFETY: extent checked the complete slice, and Port acquired this frame from the
        // backend before borrowing it. The borrow ends before the frame returns to FILL.
        Ok(unsafe { std::slice::from_raw_parts(self.pointer.as_ptr().add(offset), length) })
    }

    pub(super) fn write_frame(
        &mut self,
        address: u64,
        header: &[u8; 14],
        l3: &[u8],
    ) -> io::Result<u32> {
        let packet_len = header
            .len()
            .checked_add(l3.len())
            .filter(|&n| n <= 1514)
            .ok_or_else(|| invalid("TX frame exceeds Ethernet MTU 1500"))?;
        let length = packet_len.max(60);
        let offset = self.extent(address, length)?;
        if !offset.is_multiple_of(FRAME_SIZE) {
            return Err(invalid("TX address is not a UMEM chunk base"));
        }
        // SAFETY: extent checked the slice, and Port holds an unpublished TX reservation.
        let frame =
            unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr().add(offset), length) };
        frame[..14].copy_from_slice(header);
        frame[14..packet_len].copy_from_slice(l3);
        frame[packet_len..].fill(0);
        Ok(length as u32)
    }

    pub(super) fn frame_pointer(&self, address: u64, length: usize) -> io::Result<*mut u8> {
        let offset = self.extent(address, length)?;
        // SAFETY: extent checked this allocation; Port proves ownership before dereferencing.
        Ok(unsafe { self.pointer.as_ptr().add(offset) })
    }

    #[cfg(test)]
    pub(super) fn fake(bytes: usize, budget: &Arc<MemoryBudget>) -> Self {
        let reservation = reserve(budget, bytes).unwrap();
        let mut heap = vec![0; bytes].into_boxed_slice();
        Self {
            pointer: NonNull::new(heap.as_mut_ptr()).unwrap(),
            bytes,
            _reservation: ManuallyDrop::new(reservation),
            _heap: Some(ManuallyDrop::new(heap)),
        }
    }

    #[cfg(test)]
    pub(super) fn write_bytes(&mut self, address: u64, bytes: &[u8]) {
        let offset = self.extent(address, bytes.len()).unwrap();
        // SAFETY: heap-backed tests own the full mapping and checked this slice's extent.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                self.pointer.as_ptr().add(offset),
                bytes.len(),
            );
        }
    }
}

#[derive(Clone, Copy)]
struct RingLayout {
    producer: usize,
    consumer: usize,
    flags: usize,
    descriptors: usize,
    bytes: usize,
}

impl RingLayout {
    fn new<T>(offset: &libc::xdp_ring_offset, entries: u32) -> io::Result<Self> {
        if !entries.is_power_of_two()
            || entries > i32::MAX as u32
            || size_of::<T>() == 0
            || align_of::<T>() > align_of::<u64>()
        {
            return Err(invalid("invalid ring capacity or descriptor layout"));
        }
        let producer =
            usize::try_from(offset.producer).map_err(|_| invalid("producer offset overflow"))?;
        let consumer =
            usize::try_from(offset.consumer).map_err(|_| invalid("consumer offset overflow"))?;
        let flags = usize::try_from(offset.flags).map_err(|_| invalid("flags offset overflow"))?;
        let descriptors =
            usize::try_from(offset.desc).map_err(|_| invalid("descriptor offset overflow"))?;
        if !descriptors.is_multiple_of(align_of::<T>()) {
            return Err(invalid("unaligned ring descriptors"));
        }
        let fields = [producer, consumer, flags];
        for (index, &field) in fields.iter().enumerate() {
            let end = field
                .checked_add(size_of::<AtomicU32>())
                .filter(|&end| end <= descriptors)
                .ok_or_else(|| invalid("ring index escapes its header"))?;
            if !field.is_multiple_of(align_of::<AtomicU32>())
                || fields[..index]
                    .iter()
                    .any(|&other| field < other + size_of::<AtomicU32>() && other < end)
            {
                return Err(invalid("ring indices overlap or are unaligned"));
            }
        }
        let descriptor_bytes = Layout::array::<T>(entries as usize)
            .map_err(|_| invalid("ring descriptor extent overflow"))?
            .size();
        let bytes = descriptors
            .checked_add(descriptor_bytes)
            .filter(|&n| n <= isize::MAX as usize)
            .ok_or_else(|| invalid("ring mapping extent overflow"))?;
        Ok(Self {
            producer,
            consumer,
            flags,
            descriptors,
            bytes,
        })
    }
}

struct RingMapping {
    pointer: NonNull<u8>,
    bytes: usize,
    #[cfg(test)]
    heap: Option<Box<[u64]>>,
    reservation: Option<MemoryReservation>,
}

impl Drop for RingMapping {
    fn drop(&mut self) {
        #[cfg(test)]
        if self.heap.is_some() {
            return;
        }
        // SAFETY: this is the original live ring mapping and its mmap length; the socket
        // owns the kernel ring independently. UMEM is deliberately not a RingMapping.
        if unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.bytes) } != 0 {
            std::mem::forget(self.reservation.take());
        }
    }
}

pub(super) struct Ring<T> {
    _mapping: RingMapping,
    producer: NonNull<AtomicU32>,
    consumer: NonNull<AtomicU32>,
    flags: NonNull<AtomicU32>,
    descriptors: NonNull<T>,
    mask: u32,
}

// SAFETY: the mapping is stable and Ring is not Sync. One userspace owner moves with it;
// acquire/release indices fence descriptor access against the kernel's SPSC peer.
unsafe impl<T: Send> Send for Ring<T> {}

impl<T: Copy> Ring<T> {
    fn from_mapping(mapping: RingMapping, layout: RingLayout, entries: u32) -> Self {
        let pointer = mapping.pointer.as_ptr();
        // SAFETY: RingLayout checked every field's alignment, disjointness, and complete
        // extent before allocation/mmap. The mapping base is aligned for these UAPI types.
        unsafe {
            Self {
                producer: NonNull::new_unchecked(pointer.add(layout.producer).cast()),
                consumer: NonNull::new_unchecked(pointer.add(layout.consumer).cast()),
                flags: NonNull::new_unchecked(pointer.add(layout.flags).cast()),
                descriptors: NonNull::new_unchecked(pointer.add(layout.descriptors).cast()),
                mask: entries - 1,
                _mapping: mapping,
            }
        }
    }

    fn map(
        fd: BorrowedFd<'_>,
        layout: RingLayout,
        page_offset: u64,
        entries: u32,
        budget: &Arc<MemoryBudget>,
    ) -> io::Result<Self> {
        let page = page_size()?;
        let bytes = page_extent(layout.bytes, page)?;
        let page_offset =
            libc::off_t::try_from(page_offset).map_err(|_| invalid("ring mmap offset overflow"))?;
        if !(page_offset as u64).is_multiple_of(page as u64) {
            return Err(invalid("unaligned ring mmap offset"));
        }
        let reservation = reserve(budget, bytes)?;
        // SAFETY: the checked ring extent is page-rounded and the fd remains borrowed.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                page_offset,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(pointer) = NonNull::new(pointer.cast::<u8>()) else {
            // SAFETY: mmap succeeded at address zero, which Rust cannot reference.
            if unsafe { libc::munmap(pointer, bytes) } != 0 {
                std::mem::forget(reservation);
            }
            return Err(invalid("ring mapping is null"));
        };
        let mapping = RingMapping {
            pointer,
            bytes,
            #[cfg(test)]
            heap: None,
            reservation: Some(reservation),
        };
        if !(pointer.as_ptr() as usize).is_multiple_of(page) {
            return Err(invalid("ring mapping is not page aligned"));
        }
        Ok(Self::from_mapping(mapping, layout, entries))
    }

    pub(super) fn producer(&self) -> u32 {
        // SAFETY: this disjoint atomic field stays aligned and mapped for self's lifetime.
        unsafe { self.producer.as_ref() }.load(Ordering::Acquire)
    }

    pub(super) fn consumer(&self) -> u32 {
        // SAFETY: this disjoint atomic field stays aligned and mapped for self's lifetime.
        unsafe { self.consumer.as_ref() }.load(Ordering::Acquire)
    }

    pub(super) fn needs_wakeup(&self) -> bool {
        // SAFETY: this disjoint atomic field stays aligned and mapped for self's lifetime.
        unsafe { self.flags.as_ref() }.load(Ordering::Acquire) & libc::XDP_RING_NEED_WAKEUP != 0
    }

    pub(super) fn publish_producer(&mut self, producer: u32) {
        // SAFETY: Port is the sole userspace producer and has finished descriptor writes.
        unsafe { self.producer.as_ref() }.store(producer, Ordering::Release);
    }

    pub(super) fn publish_consumer(&mut self, consumer: u32) {
        // SAFETY: Port is the sole userspace consumer and has finished descriptor reads.
        unsafe { self.consumer.as_ref() }.store(consumer, Ordering::Release);
    }

    pub(super) fn read(&self, index: u32) -> T {
        // SAFETY: masking stays within the checked descriptor array. Port acquires the
        // producer and validates the available count before reading kernel-owned entries.
        unsafe {
            self.descriptors
                .as_ptr()
                .add((index & self.mask) as usize)
                .read_volatile()
        }
    }

    pub(super) fn write(&mut self, index: u32, value: T) {
        // SAFETY: masking stays within the checked descriptor array. Port acquires the
        // consumer and checks credit before writing an entry, then release-publishes it.
        unsafe {
            self.descriptors
                .as_ptr()
                .add((index & self.mask) as usize)
                .write_volatile(value)
        }
    }

    #[cfg(test)]
    pub(super) fn fake(entries: u32, initial: u32, budget: &Arc<MemoryBudget>) -> Self {
        let offsets = libc::xdp_ring_offset {
            producer: 0,
            consumer: 4,
            flags: 8,
            desc: 16,
        };
        let layout = RingLayout::new::<T>(&offsets, entries).unwrap();
        let bytes = layout.bytes.div_ceil(size_of::<u64>()) * size_of::<u64>();
        let reservation = reserve(budget, bytes).unwrap();
        let mut heap = vec![0_u64; bytes / size_of::<u64>()].into_boxed_slice();
        let mapping = RingMapping {
            pointer: NonNull::new(heap.as_mut_ptr().cast()).unwrap(),
            bytes,
            heap: Some(heap),
            reservation: Some(reservation),
        };
        let mut ring = Self::from_mapping(mapping, layout, entries);
        ring.publish_producer(initial);
        ring.publish_consumer(initial);
        ring
    }

    #[cfg(test)]
    pub(super) fn set_wakeup(&mut self) {
        // SAFETY: the test is also the sole fake-kernel owner of this atomic flags field.
        unsafe { self.flags.as_ref() }.store(libc::XDP_RING_NEED_WAKEUP, Ordering::Release);
    }
}

pub(super) fn distance(producer: u32, consumer: u32, capacity: u32) -> io::Result<u32> {
    let used = producer.wrapping_sub(consumer);
    if used > capacity {
        return Err(invalid("AF_XDP ring index escaped its capacity"));
    }
    Ok(used)
}

pub(super) struct Rings {
    pub(super) rx: Ring<Descriptor>,
    pub(super) tx: Ring<Descriptor>,
    pub(super) fill: Ring<u64>,
    pub(super) cq: Ring<u64>,
}

impl Rings {
    pub(super) fn snapshot(&self) -> RingSnapshot {
        RingSnapshot {
            rx_producer: self.rx.producer(),
            rx_consumer: self.rx.consumer(),
            tx_producer: self.tx.producer(),
            tx_consumer: self.tx.consumer(),
            fill_producer: self.fill.producer(),
            fill_consumer: self.fill.consumer(),
            cq_producer: self.cq.producer(),
            cq_consumer: self.cq.consumer(),
        }
    }

    #[cfg(test)]
    pub(super) fn fake(entries: u32, budget: &Arc<MemoryBudget>) -> Self {
        Self {
            rx: Ring::fake(entries, 0, budget),
            tx: Ring::fake(entries, 0, budget),
            fill: Ring::fake(entries, 0, budget),
            cq: Ring::fake(entries, 0, budget),
        }
    }
}

fn set_option<T>(fd: BorrowedFd<'_>, name: libc::c_int, value: &T) -> io::Result<()> {
    let length = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| invalid("socket option size overflow"))?;
    // SAFETY: all callers supply the matching initialized integer-only AF_XDP UAPI value.
    if unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_XDP,
            name,
            std::ptr::from_ref(value).cast(),
            length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_option<T>(fd: BorrowedFd<'_>, name: libc::c_int, value: &mut T) -> io::Result<()> {
    let expected = libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| invalid("socket option size overflow"))?;
    let mut length = expected;
    // SAFETY: all callers provide writable integer-only UAPI structs for this exact option.
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_XDP,
            name,
            std::ptr::from_mut(value).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if length != expected {
        return Err(invalid("unexpected AF_XDP socket option size"));
    }
    Ok(())
}

pub(super) fn open(
    ifindex: u32,
    queue: u32,
    mode: BindMode,
    config: PortConfig,
    scatter_gather: bool,
    umem: &Umem,
    budget: &Arc<MemoryBudget>,
) -> io::Result<(OwnedFd, Rings, bool)> {
    use std::os::fd::AsFd;

    // SAFETY: socket has no pointer arguments. There is no implicit bind-mode fallback.
    let raw_fd = unsafe {
        libc::socket(
            libc::AF_XDP,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socket returned a new nonnegative fd and this is its only owning wrapper.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    for option in [libc::XDP_RX_RING, libc::XDP_TX_RING] {
        set_option(fd.as_fd(), option, &config.ring_size)?;
    }
    let registration = libc::xdp_umem_reg {
        addr: u64::try_from(umem.pointer.as_ptr() as usize)
            .map_err(|_| invalid("UMEM pointer overflow"))?,
        len: u64::try_from(umem.bytes).map_err(|_| invalid("UMEM length overflow"))?,
        chunk_size: FRAME_SIZE as u32,
        headroom: super::METADATA_SIZE as u32,
        flags: 0,
        tx_metadata_len: 0,
    };
    set_option(fd.as_fd(), libc::XDP_UMEM_REG, &registration)?;
    for option in [libc::XDP_UMEM_FILL_RING, libc::XDP_UMEM_COMPLETION_RING] {
        set_option(fd.as_fd(), option, &config.ring_size)?;
    }
    // SAFETY: every bit pattern of this integer-only UAPI struct is valid.
    let mut offsets: libc::xdp_mmap_offsets = unsafe { std::mem::zeroed() };
    get_option(fd.as_fd(), libc::XDP_MMAP_OFFSETS, &mut offsets)?;
    let rx_layout = RingLayout::new::<Descriptor>(&offsets.rx, config.ring_size)?;
    let tx_layout = RingLayout::new::<Descriptor>(&offsets.tx, config.ring_size)?;
    let fill_layout = RingLayout::new::<u64>(&offsets.fr, config.ring_size)?;
    let cq_layout = RingLayout::new::<u64>(&offsets.cr, config.ring_size)?;
    let rings = Rings {
        rx: Ring::map(fd.as_fd(), rx_layout, 0, config.ring_size, budget)?,
        tx: Ring::map(fd.as_fd(), tx_layout, 0x8000_0000, config.ring_size, budget)?,
        fill: Ring::map(
            fd.as_fd(),
            fill_layout,
            libc::XDP_UMEM_PGOFF_FILL_RING,
            config.ring_size,
            budget,
        )?,
        cq: Ring::map(
            fd.as_fd(),
            cq_layout,
            libc::XDP_UMEM_PGOFF_COMPLETION_RING,
            config.ring_size,
            budget,
        )?,
    };
    let address = libc::sockaddr_xdp {
        sxdp_family: libc::AF_XDP as u16,
        sxdp_flags: libc::XDP_USE_NEED_WAKEUP
            | if scatter_gather { 1 << 4 } else { 0 }
            | match mode {
                BindMode::ZeroCopy => libc::XDP_ZEROCOPY,
                BindMode::Copy => libc::XDP_COPY,
            },
        sxdp_ifindex: ifindex,
        sxdp_queue_id: queue,
        sxdp_shared_umem_fd: 0,
    };
    crate::device::validate_queue(ifindex, queue)?;
    // SAFETY: sockaddr_xdp is the initialized AF_XDP address and length for this socket.
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::from_ref(&address).cast(),
            size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut options = libc::xdp_options { flags: 0 };
    get_option(fd.as_fd(), libc::XDP_OPTIONS, &mut options)?;
    let zerocopy = options.flags & libc::XDP_OPTIONS_ZEROCOPY != 0;
    if zerocopy != (mode == BindMode::ZeroCopy) {
        return Err(invalid("AF_XDP bind mode readback mismatch"));
    }
    if rings.snapshot() != RingSnapshot::default() {
        return Err(invalid("new AF_XDP rings are not empty"));
    }
    Ok((fd, rings, zerocopy))
}

pub(super) fn stats(fd: BorrowedFd<'_>) -> io::Result<SocketStats> {
    let mut stats = SocketStats::default();
    get_option(fd, libc::XDP_STATISTICS, &mut stats)?;
    Ok(stats)
}

pub(super) fn kick_rx(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll receives one initialized, writable pollfd and cannot block (timeout 0).
    if unsafe { libc::poll(&mut poll, 1, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if poll.revents & libc::POLLNVAL != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    if poll.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
        return Err(io::Error::other(
            "AF_XDP RX wakeup reported socket error/hangup",
        ));
    }
    Ok(())
}

pub(super) fn kick_tx(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: a zero-length sendto with no data/address is the AF_XDP TX wakeup API.
    if unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            std::ptr::null(),
            0,
            libc::MSG_DONTWAIT,
            std::ptr::null(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_umem_retention_cannot_be_reset_with_a_fresh_budget() {
        const CHILD: &str = "HONK_XSK_UMEM_LIMIT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "port::ring::tests::real_umem_retention_cannot_be_reset_with_a_fresh_budget",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed"));
            return;
        }
        let page = page_size().unwrap();
        RETAINED_UMEM_BYTES.store(RETAINED_UMEM_LIMIT - 2 * page, Ordering::Release);
        let first_budget = MemoryBudget::new(2 * page);
        {
            let first = Umem::map(1, &first_budget).unwrap();
            assert_eq!(first.bytes(), 1);
        }
        assert_eq!(first_budget.used(), page);
        assert_eq!(
            RETAINED_UMEM_BYTES.load(Ordering::Acquire),
            RETAINED_UMEM_LIMIT - page
        );
        let second_budget = MemoryBudget::new(2 * page);
        {
            let _second = Umem::map(page, &second_budget).unwrap();
        }
        assert_eq!(second_budget.used(), page);
        assert_eq!(
            RETAINED_UMEM_BYTES.load(Ordering::Acquire),
            RETAINED_UMEM_LIMIT
        );
        for budget in [first_budget, second_budget, MemoryBudget::new(2 * page)] {
            let used = budget.used();
            assert!(Umem::map(1, &budget).is_err());
            assert_eq!(budget.used(), used);
            assert_eq!(
                RETAINED_UMEM_BYTES.load(Ordering::Acquire),
                RETAINED_UMEM_LIMIT
            );
        }
        RETAINED_UMEM_BYTES.store(0, Ordering::Release);
        let budget = MemoryBudget::new(page);
        // An impossible address-space limit makes the real mmap fail without huge allocations.
        let mut original = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: the output is a writable rlimit; only this child changes its soft limit.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) },
            0
        );
        let limit = libc::rlimit {
            rlim_cur: 0,
            ..original
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limit) }, 0);
        let result = Umem::map(page, &budget);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &original) }, 0);
        assert!(result.is_err());
        assert_eq!(budget.used(), 0);
        assert_eq!(RETAINED_UMEM_BYTES.load(Ordering::Acquire), 0);
    }

    #[test]
    fn heap_ring_wraps_indices_at_u32_boundary() {
        let budget = MemoryBudget::new(4096);
        let initial = u32::MAX - 1;
        let mut ring = Ring::<u64>::fake(4, initial, &budget);
        for n in 0..4_u32 {
            ring.write(initial.wrapping_add(n), 100 + u64::from(n));
        }
        ring.publish_producer(initial.wrapping_add(4));
        assert_eq!(distance(ring.producer(), ring.consumer(), 4).unwrap(), 4);
        for n in 0..4_u32 {
            assert_eq!(ring.read(initial.wrapping_add(n)), 100 + u64::from(n));
        }
        ring.publish_consumer(initial.wrapping_add(4));
        assert_eq!(distance(ring.producer(), ring.consumer(), 4).unwrap(), 0);
        ring.write(ring.producer(), 999);
        ring.publish_producer(ring.producer().wrapping_add(1));
        assert_eq!(ring.read(ring.consumer()), 999);
        assert!(distance(3, u32::MAX - 1, 4).is_err());
        drop(ring);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn rejects_offsets_before_constructing_ring_pointers() {
        let good = libc::xdp_ring_offset {
            producer: 0,
            consumer: 4,
            flags: 8,
            desc: 16,
        };
        assert!(RingLayout::new::<Descriptor>(&good, 4).is_ok());
        for offsets in [
            libc::xdp_ring_offset {
                producer: 1,
                ..good
            },
            libc::xdp_ring_offset {
                consumer: 0,
                ..good
            },
            libc::xdp_ring_offset { flags: 16, ..good },
            libc::xdp_ring_offset { desc: 17, ..good },
            libc::xdp_ring_offset {
                producer: u64::MAX,
                ..good
            },
            libc::xdp_ring_offset {
                desc: u64::MAX - 7,
                ..good
            },
        ] {
            assert!(RingLayout::new::<Descriptor>(&offsets, 4).is_err());
        }
        for entries in [0, 3, 1 << 31] {
            assert!(RingLayout::new::<Descriptor>(&good, entries).is_err());
        }
    }
}

//! Owned LOCAL_OUT route chains for the original Host skb. The caller must hold
//! its closed Native publication through mutation, readback and reader grace.
//! Dropping this owner closes descriptors; it never removes persistent rules.

use std::cell::Cell;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use bytes::Bytes;

use crate::netlink::{self, Attribute, Message};
use crate::rules::{put_ct_state_load, put_expression};

pub const CHAIN_NAME: &str = "native_output";
pub const CHAIN_PRIORITY: i32 = -451;
pub const MAX_ACTIONS: usize = 257;
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_READBACK_BYTES: usize = 512 * 1024;
// Includes allocator rounding, compat info/ops, rule expressions, both chain
// blobs and transaction records; BPF allocations are charged by their owner.
pub const KERNEL_FIXED_BYTES: usize = 64 * 1024;
pub const KERNEL_BYTES_PER_RULE: usize = 8192;
// Stock x86_64 notifications allocate NLMSG_GOODSIZE (one 4KiB head),
// plus the skb descriptor. ACKs for our <=2KiB messages fit the same 8KiB
// envelope, even without successful netlink_trim or a capped error ACK.
const REPLY_SKB_BYTES: usize = 8192;
const MAX_CONTROL_MESSAGE_BYTES: usize = 2048;
const READBACK_DATAGRAM_BYTES: usize = 64 * 1024;
const MIN_RECEIVE_BYTES: usize = 32 * 1024;
const MIN_SEND_BYTES: usize = 8192;
const XT_BPF_USERSIZE: usize = 520;
const XT_BPF_MATCHSIZE: usize = 528;
const CREATE_EXCL: u16 = 0x400 | 0x200;
const APPEND: u16 = 0x800;
const DUMP: u16 = 0x300;
const DUMP_INTR: u16 = 0x10;
const NEWTABLE: u16 = 0;
const GETTABLE: u16 = 1;
const DELTABLE: u16 = 2;
const NEWCHAIN: u16 = 3;
const GETCHAIN: u16 = 4;
const NEWRULE: u16 = 6;
const GETRULE: u16 = 7;
const DELRULE: u16 = 8;
const NEWGEN: u16 = 15;
const GETGEN: u16 = 16;

pub struct NativeAction<'a> {
    pub matcher: BorrowedFd<'a>,
    pub mark: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRuleReceipt {
    pub handle: Option<u64>,
    pub userdata: Vec<u8>,
    pub matcher_program_id: u32,
    pub matcher_tag: [u8; 8],
    pub matcher_fd: i32,
    pub mark: Option<u32>,
    pub candidate_scope: bool,
    pub conntrack_anchor: bool,
    pub expressions: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeGenerationReceipt {
    pub generation: u64,
    pub mutation_acked: bool,
    pub rules: Vec<NativeRuleReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeReceipt {
    pub table: String,
    pub chain: String,
    pub family: u8,
    pub owner: [u8; 16],
    pub table_handle: Option<u64>,
    pub chain_handle: Option<u64>,
    pub table_create_acked: bool,
    pub install_attempted: bool,
    pub removing: bool,
    pub remove_acked: bool,
    pub removed: bool,
    pub active: Option<NativeGenerationReceipt>,
    pub pending: Option<NativeGenerationReceipt>,
    pub socket_receive_bytes: usize,
    pub socket_send_bytes: usize,
}

struct Generation {
    receipt: NativeGenerationReceipt,
    matchers: Vec<OwnedFd>,
}

/// A prepared owner must be retained by the caller before `install` is called.
/// An error preserves at most one accepted and one attempted generation. A
/// failed mutation cannot be retried as a new publication; inspect/remove it
/// while admission stays closed. No preexisting table is adopted.
pub struct NativeRoutes {
    socket: OwnedFd,
    sequence: Cell<u32>,
    receipt: NativeReceipt,
    active: Option<Vec<OwnedFd>>,
    pending: Option<Vec<OwnedFd>>,
}

impl NativeRoutes {
    pub fn prepare(name: &str, owner: &[u8; 16], family: u8) -> io::Result<Self> {
        if !cfg!(all(target_arch = "x86_64", target_endian = "little")) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Native xt_bpf ABI requires x86_64 little endian",
            ));
        }
        if !matches!(family as i32, libc::AF_INET | libc::AF_INET6)
            || name.is_empty()
            || name.len() > 255
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || *owner == [0; 16]
        {
            return Err(input("invalid Native table name, family or instance owner"));
        }
        let socket = netlink::open_socket(false)?;
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&timeout as *const libc::timeval).cast(),
                    std::mem::size_of_val(&timeout) as libc::socklen_t,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let buffers = SocketBuffers {
            receive: MIN_RECEIVE_BYTES,
            send: MIN_SEND_BYTES,
        };
        apply_socket_buffers(socket.as_raw_fd(), buffers)?;
        Ok(Self {
            socket,
            sequence: Cell::new(1),
            active: None,
            pending: None,
            receipt: NativeReceipt {
                table: name.into(),
                chain: CHAIN_NAME.into(),
                family,
                owner: *owner,
                table_handle: None,
                chain_handle: None,
                table_create_acked: false,
                install_attempted: false,
                removing: false,
                remove_acked: false,
                removed: false,
                active: None,
                socket_receive_bytes: buffers.receive,
                socket_send_bytes: buffers.send,
                pending: None,
            },
        })
    }

    pub fn receipt(&self) -> &NativeReceipt {
        &self.receipt
    }

    /// Reserve for each retained generation. Old plus candidate reservations
    /// cover one socket's replacement burst, including verified send/receive
    /// limits and skb allocation overhead; BPF and durable receipts are separate.
    pub fn kernel_memory_bound(action_count: usize) -> io::Result<usize> {
        if action_count > MAX_ACTIONS {
            return Err(input("too many Native actions"));
        }
        Ok(KERNEL_FIXED_BYTES
            + (action_count + 2) * KERNEL_BYTES_PER_RULE
            + Self::socket_memory_bound(action_count)?)
    }

    /// One generation contributes its install ACK/ECHO burst and bounded send
    /// allocation. Old plus new contributions also bound an atomic replacement.
    pub fn socket_memory_bound(action_count: usize) -> io::Result<usize> {
        if action_count > MAX_ACTIONS {
            return Err(input("too many Native actions"));
        }
        let receive = (2 * action_count + 10) * REPLY_SKB_BYTES;
        let send = ((action_count + 6) * MAX_CONTROL_MESSAGE_BYTES).min(MAX_REQUEST_BYTES) + 32;
        Ok(receive + send.max(MIN_SEND_BYTES) + 2 * READBACK_DATAGRAM_BYTES + 2 * REPLY_SKB_BYTES)
    }

    /// Each family retains at most two such generations. Transport staging is
    /// bounded separately by MAX_REQUEST_BYTES and MAX_READBACK_BYTES.
    pub fn userspace_memory_bound(action_count: usize) -> io::Result<usize> {
        if action_count > MAX_ACTIONS {
            return Err(input("too many Native actions"));
        }
        Ok(4096
            + (action_count + 2)
                * (768
                    + 32
                    + std::mem::size_of::<NativeRuleReceipt>()
                    + std::mem::size_of::<OwnedFd>()))
    }

    pub fn install(
        &mut self,
        actions: &[NativeAction<'_>],
        candidate_scope: BorrowedFd<'_>,
    ) -> io::Result<()> {
        if self.receipt.install_attempted {
            return Err(input("Native table installation already attempted"));
        }
        let candidate = prepare_generation(&self.receipt.owner, 1, actions, candidate_scope)?;
        let sequence = self.next_sequence()?;
        let request = Bytes::from(self.install_batch(sequence, &candidate)?);
        let capacity = transaction_capacity(request.clone())?;
        self.configure_capacity(capacity.buffers, Self::socket_memory_bound(actions.len())?)?;
        self.receipt.install_attempted = true;
        self.receipt.pending = Some(candidate.receipt);
        self.pending = Some(candidate.matchers);
        self.mutate(&request, sequence, capacity)?;
        self.receipt.table_create_acked = true;
        self.receipt
            .pending
            .as_mut()
            .expect("pending")
            .mutation_acked = true;
        self.accept_pending()
    }

    pub fn replace(
        &mut self,
        actions: &[NativeAction<'_>],
        candidate_scope: BorrowedFd<'_>,
    ) -> io::Result<()> {
        if self.pending.is_some() || self.receipt.removing || self.receipt.removed {
            return Err(input(
                "Native ownership is retained after an unfinished mutation",
            ));
        }
        let active = self
            .receipt
            .active
            .as_ref()
            .ok_or_else(|| input("Native table is not installed"))?;
        let generation = active
            .generation
            .checked_add(1)
            .ok_or_else(|| input("Native generation exhausted"))?;
        let mut candidate =
            prepare_generation(&self.receipt.owner, generation, actions, candidate_scope)?;
        let snapshot = self.inspect(active)?;
        candidate.receipt.rules[0].handle = active.rules[0].handle;
        let sequence = self.next_sequence()?;
        let mut request = self.batch_begin(sequence, Some(snapshot.generation));
        for rule in active.rules.iter().skip(1) {
            let start = self.header(&mut request, DELRULE, 0, sequence);
            self.rule_location(&mut request);
            put_be64(
                &mut request,
                3,
                rule.handle
                    .ok_or_else(|| invalid("missing owned rule handle"))?,
            );
            netlink::seal_message(&mut request, start);
        }
        self.put_rules(&mut request, sequence, &candidate.receipt.rules[1..]);
        batch_end(&mut request, sequence);
        bound_request(&request)?;
        let request = Bytes::from(request);
        let capacity = transaction_capacity(request.clone())?;
        let socket_budget = Self::socket_memory_bound(active.rules.len() - 2)?
            + Self::socket_memory_bound(actions.len())?;
        self.configure_capacity(capacity.buffers, socket_budget)?;
        self.receipt.pending = Some(candidate.receipt);
        self.pending = Some(candidate.matchers);
        self.mutate(&request, sequence, capacity)?;
        self.receipt
            .pending
            .as_mut()
            .expect("pending")
            .mutation_acked = true;
        self.accept_pending()
    }

    pub fn check(&self) -> io::Result<()> {
        if self.receipt.removed {
            return self.verify_absent();
        }
        if self.pending.is_some() || self.receipt.removing {
            return Err(invalid("Native mutation has not completed exact readback"));
        }
        let active = self
            .receipt
            .active
            .as_ref()
            .ok_or_else(|| invalid("Native ownership is not accepted"))?;
        self.inspect(active).map(|_| ())
    }

    pub fn remove(&mut self) -> io::Result<()> {
        if self.receipt.removed {
            return Ok(());
        }
        if !self.receipt.install_attempted {
            return Ok(());
        }
        if self.receipt.remove_acked {
            self.verify_absent()?;
            self.receipt.removed = true;
            return Ok(());
        }
        // A lost CREATE ACK is intent, not ownership, even if userdata matches.
        if !self.receipt.table_create_acked {
            return Err(invalid(
                "Native table CREATE was not acknowledged; retaining intent without adoption",
            ));
        }
        let snapshot = if let Some(pending) = &self.receipt.pending {
            if pending.mutation_acked {
                self.inspect(pending)?
            } else if let Some(active) = &self.receipt.active {
                self.inspect(active)?
            } else {
                return Err(invalid("Native mutation outcome is unknown"));
            }
        } else {
            self.inspect(
                self.receipt
                    .active
                    .as_ref()
                    .ok_or_else(|| invalid("missing Native generation"))?,
            )?
        };
        self.receipt.table_handle = Some(snapshot.table);
        self.receipt.chain_handle = Some(snapshot.chain);
        let sequence = self.next_sequence()?;
        let mut request = self.batch_begin(sequence, Some(snapshot.generation));
        let start = self.header(&mut request, DELTABLE, 0, sequence);
        // The kernel resolves HANDLE preferentially; GENID closes the gap after
        // exact userdata/content verification, including concurrent replacement.
        put_be64(&mut request, 4, snapshot.table);
        netlink::seal_message(&mut request, start);
        batch_end(&mut request, sequence);
        let request = Bytes::from(request);
        let capacity = transaction_capacity(request.clone())?;
        let mut socket_budget = 0usize;
        for generation in self
            .receipt
            .active
            .iter()
            .chain(self.receipt.pending.iter())
        {
            socket_budget += Self::socket_memory_bound(generation.rules.len() - 2)?;
        }
        self.configure_capacity(capacity.buffers, socket_budget)?;
        self.receipt.removing = true;
        self.mutate(&request, sequence, capacity)?;
        self.receipt.remove_acked = true;
        self.verify_absent()?;
        self.receipt.removed = true;
        Ok(())
    }

    fn accept_pending(&mut self) -> io::Result<()> {
        let pending = self.receipt.pending.as_ref().expect("pending generation");
        self.inspect(pending)?;
        self.receipt.active = self.receipt.pending.take();
        self.active = self.pending.take();
        Ok(())
    }

    fn next_sequence(&self) -> io::Result<u32> {
        let sequence = self.sequence.get();
        self.sequence.set(
            sequence
                .checked_add(1)
                .ok_or_else(|| input("Native netlink sequence exhausted"))?,
        );
        Ok(sequence)
    }

    fn header(&self, buffer: &mut Vec<u8>, kind: u16, flags: u16, sequence: u32) -> usize {
        let echo = if matches!(kind, NEWTABLE | NEWCHAIN | NEWRULE) {
            8
        } else {
            0
        };
        netlink::put_message_header(
            buffer,
            nft_type(kind),
            netlink::NLM_F_REQUEST | netlink::NLM_F_ACK | flags | echo,
            sequence,
            self.receipt.family,
            netlink::NFNL_SUBSYS_NFTABLES,
        )
    }

    fn batch_begin(&self, sequence: u32, generation: Option<u32>) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(MAX_REQUEST_BYTES);
        let start = netlink::put_message_header(
            &mut buffer,
            netlink::NFNL_MSG_BATCH_BEGIN,
            netlink::NLM_F_REQUEST,
            sequence,
            0,
            netlink::NFNL_BATCH_RES_ID,
        );
        if let Some(generation) = generation {
            netlink::put_attribute_be32(&mut buffer, 1, generation);
        }
        netlink::seal_message(&mut buffer, start);
        buffer
    }

    fn rule_location(&self, buffer: &mut Vec<u8>) {
        netlink::put_attribute_string(buffer, 1, &self.receipt.table);
        netlink::put_attribute_string(buffer, 2, CHAIN_NAME);
    }

    fn install_batch(&self, sequence: u32, candidate: &Generation) -> io::Result<Vec<u8>> {
        let mut buffer = self.batch_begin(sequence, None);
        let table = self.header(&mut buffer, NEWTABLE, CREATE_EXCL, sequence);
        netlink::put_attribute_string(&mut buffer, 1, &self.receipt.table);
        netlink::put_attribute_be32(&mut buffer, 2, 0);
        netlink::put_attribute(&mut buffer, 6, &self.receipt.owner);
        netlink::seal_message(&mut buffer, table);
        let chain = self.header(&mut buffer, NEWCHAIN, CREATE_EXCL, sequence);
        netlink::put_attribute_string(&mut buffer, 1, &self.receipt.table);
        netlink::put_attribute_string(&mut buffer, 3, CHAIN_NAME);
        let hook = netlink::begin_nested(&mut buffer, 4);
        netlink::put_attribute_be32(&mut buffer, 1, 3); // NF_INET_LOCAL_OUT
        netlink::put_attribute_be32(&mut buffer, 2, CHAIN_PRIORITY as u32);
        netlink::seal_nested(&mut buffer, hook);
        netlink::put_attribute_be32(&mut buffer, 5, 1); // NF_ACCEPT
        netlink::put_attribute_string(&mut buffer, 7, "route");
        netlink::put_attribute(&mut buffer, 12, &self.receipt.owner);
        netlink::seal_message(&mut buffer, chain);
        self.put_rules(&mut buffer, sequence, &candidate.receipt.rules);
        batch_end(&mut buffer, sequence);
        bound_request(&buffer)?;
        Ok(buffer)
    }

    fn put_rules(&self, buffer: &mut Vec<u8>, sequence: u32, rules: &[NativeRuleReceipt]) {
        for rule in rules {
            let start = self.header(buffer, NEWRULE, CREATE_EXCL | APPEND, sequence);
            self.rule_location(buffer);
            netlink::put_attribute(buffer, 4 | netlink::NLA_F_NESTED, &rule.expressions);
            netlink::put_attribute(buffer, 7, &rule.userdata);
            netlink::seal_message(buffer, start);
        }
    }

    fn configure_capacity(&mut self, buffers: SocketBuffers, budget: usize) -> io::Result<()> {
        if buffers.memory_bound() > budget {
            return Err(input(
                "Native transaction socket exceeds retained memory budget",
            ));
        }
        let previous = read_socket_buffers(self.socket.as_raw_fd())?;
        if let Err(error) = apply_socket_buffers(self.socket.as_raw_fd(), buffers) {
            let restored = apply_socket_buffers(self.socket.as_raw_fd(), previous);
            let actual = read_socket_buffers(self.socket.as_raw_fd())?;
            self.receipt.socket_receive_bytes = actual.receive;
            self.receipt.socket_send_bytes = actual.send;
            return match restored {
                Ok(()) => Err(error),
                Err(restore) => Err(io::Error::new(
                    error.kind(),
                    format!(
                        "Native socket capacity: {error}; restoring previous limits: {restore}"
                    ),
                )),
            };
        }
        let actual = read_socket_buffers(self.socket.as_raw_fd())?;
        self.receipt.socket_receive_bytes = actual.receive;
        self.receipt.socket_send_bytes = actual.send;
        Ok(())
    }

    fn mutate(
        &mut self,
        request: &[u8],
        sequence: u32,
        capacity: TransactionCapacity,
    ) -> io::Result<()> {
        let fd = self.socket.as_raw_fd();
        netlink::send_and_acks_bounded(
            fd,
            request,
            sequence,
            capacity.acknowledgements,
            MAX_READBACK_BYTES,
            capacity.echoes,
            |message| record_echo(&mut self.receipt, message),
        )
    }

    fn query(
        &self,
        kind: u16,
        dump: bool,
        location: impl FnOnce(&mut Vec<u8>),
    ) -> io::Result<Vec<Message>> {
        let sequence = self.next_sequence()?;
        let mut request = Vec::with_capacity(512);
        let start = netlink::put_message_header(
            &mut request,
            nft_type(kind),
            netlink::NLM_F_REQUEST | if dump { DUMP } else { 0 },
            sequence,
            if kind == GETGEN {
                0
            } else {
                self.receipt.family
            },
            netlink::NFNL_SUBSYS_NFTABLES,
        );
        location(&mut request);
        netlink::seal_message(&mut request, start);
        netlink::send(self.socket.as_raw_fd(), &request)?;
        let mut result = Vec::new();
        let mut total = 0usize;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Native readback deadline exceeded",
                ));
            }
            let datagram =
                netlink::recv_kernel_datagram(self.socket.as_raw_fd(), READBACK_DATAGRAM_BYTES)?;
            total = total
                .checked_add(datagram.len())
                .ok_or_else(|| invalid("readback overflow"))?;
            if total > MAX_READBACK_BYTES {
                return Err(invalid("Native readback exceeds byte budget"));
            }
            for message in netlink::messages(datagram) {
                let message = message.map_err(invalid_decode)?;
                if message.sequence != sequence {
                    continue;
                }
                if message.flags & DUMP_INTR != 0 {
                    return Err(invalid("Native nft dump interrupted"));
                }
                if message.message_type == netlink::NLMSG_ERROR {
                    let code = ack_code(&message.body)?;
                    if code != 0 {
                        return Err(io::Error::from_raw_os_error(-code));
                    }
                    continue;
                }
                if message.message_type == 3 {
                    if message.body.len() >= 4 && ack_code(&message.body)? != 0 {
                        return Err(invalid("Native nft dump failed"));
                    }
                    return Ok(result);
                }
                let expected = match kind {
                    GETTABLE => NEWTABLE,
                    GETCHAIN => NEWCHAIN,
                    GETRULE => NEWRULE,
                    GETGEN => NEWGEN,
                    _ => unreachable!(),
                };
                if message.message_type != nft_type(expected) {
                    return Err(invalid("unexpected Native nft reply"));
                }
                if result.len() >= MAX_ACTIONS + 2 {
                    return Err(invalid("Native readback exceeds object budget"));
                }
                result.push(message);
                if !dump {
                    return Ok(result);
                }
            }
        }
    }

    fn generation(&self) -> io::Result<u32> {
        let reply = self.query(GETGEN, false, |_| {})?;
        let fields = message_fields(&reply[0], 0)?;
        let generation = be32(required(&fields, 1)?)?;
        if generation == 0 {
            return Err(invalid("zero nft generation"));
        }
        Ok(generation)
    }

    fn verify_absent(&self) -> io::Result<()> {
        match self.query(GETTABLE, false, |buffer| {
            netlink::put_attribute_string(buffer, 1, &self.receipt.table)
        }) {
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(invalid(
                "Native table name still exists; retaining removal state",
            )),
        }
    }

    fn inspect(&self, expected: &NativeGenerationReceipt) -> io::Result<Snapshot> {
        let generation = self.generation()?;
        let table = self.query(GETTABLE, false, |buffer| {
            netlink::put_attribute_string(buffer, 1, &self.receipt.table)
        })?;
        let fields = message_fields(&table[0], self.receipt.family)?;
        allow(&fields, &[1, 2, 3, 4, 5, 6])?;
        same_string(required(&fields, 1)?, &self.receipt.table)?;
        same(required(&fields, 6)?, &self.receipt.owner)?;
        if be32(required(&fields, 2)?)? != 0 || be32(required(&fields, 3)?)? != 1 {
            return Err(invalid("Native table flags or object count changed"));
        }
        let table_handle = handle(required(&fields, 4)?)?;
        if self
            .receipt
            .table_handle
            .is_some_and(|owned| owned != table_handle)
        {
            return Err(invalid("Native table handle changed"));
        }
        let chain = self.query(GETCHAIN, false, |buffer| {
            netlink::put_attribute_string(buffer, 1, &self.receipt.table);
            netlink::put_attribute_string(buffer, 3, CHAIN_NAME);
        })?;
        let fields = message_fields(&chain[0], self.receipt.family)?;
        allow(&fields, &[1, 2, 3, 4, 5, 6, 7, 9, 10, 12])?;
        same_string(required(&fields, 1)?, &self.receipt.table)?;
        same_string(required(&fields, 3)?, CHAIN_NAME)?;
        same_string(required(&fields, 7)?, "route")?;
        same(required(&fields, 12)?, &self.receipt.owner)?;
        if be32(required(&fields, 5)?)? != 1
            || be32(required(&fields, 10)?)? != 1
            || be32(required(&fields, 6)?)? as usize != expected.rules.len()
        {
            return Err(invalid("Native chain policy, flags or rule count changed"));
        }
        let hook = fields_of(required(&fields, 4)?.clone())?;
        allow(&hook, &[1, 2])?;
        if be32(required(&hook, 1)?)? != 3 || be32(required(&hook, 2)?)? != CHAIN_PRIORITY as u32 {
            return Err(invalid("Native route hook changed"));
        }
        let chain_handle = handle(required(&fields, 2)?)?;
        if self
            .receipt
            .chain_handle
            .is_some_and(|owned| owned != chain_handle)
        {
            return Err(invalid("Native chain handle changed"));
        }
        let rules = self.query(GETRULE, true, |buffer| self.rule_location(buffer))?;
        if rules.len() != expected.rules.len() {
            return Err(invalid("Native rule set size changed"));
        }
        let mut handles = Vec::with_capacity(rules.len());
        for (actual, expected) in rules.iter().zip(&expected.rules) {
            let fields = message_fields(actual, self.receipt.family)?;
            allow(&fields, &[1, 2, 3, 4, 6, 7, 8])?;
            same_string(required(&fields, 1)?, &self.receipt.table)?;
            same_string(required(&fields, 2)?, CHAIN_NAME)?;
            same(required(&fields, 7)?, &expected.userdata)?;
            let actual_handle = handle(required(&fields, 3)?)?;
            if expected.handle != Some(actual_handle) {
                return Err(invalid("Native rule handle changed"));
            }
            if let Some(position) = optional(&fields, 6) {
                if handles.last().copied() != Some(handle(position)?) {
                    return Err(invalid("Native rule order changed"));
                }
            } else if !handles.is_empty() {
                return Err(invalid("missing Native rule position"));
            }
            if handles.contains(&actual_handle) {
                return Err(invalid("duplicate Native rule handle"));
            }
            compare_expressions(
                required(&fields, 4)?.clone(),
                Bytes::copy_from_slice(&expected.expressions),
            )?;
            handles.push(actual_handle);
        }
        let owned_generation = if self
            .receipt
            .pending
            .as_ref()
            .is_some_and(|pending| pending.generation == expected.generation)
        {
            self.pending.as_ref()
        } else {
            self.active.as_ref()
        }
        .ok_or_else(|| invalid("missing Native matcher custody"))?;
        if owned_generation.len() + 1 != expected.rules.len() {
            return Err(invalid("Native matcher custody count changed"));
        }
        for (fd, rule) in owned_generation.iter().zip(expected.rules.iter().skip(1)) {
            let (id, tag) = program_identity(fd.as_fd())?;
            if id != rule.matcher_program_id || tag != rule.matcher_tag {
                return Err(invalid("Native matcher program identity changed"));
            }
        }
        if self.generation()? != generation {
            return Err(invalid("Native rules changed during exact readback"));
        }
        Ok(Snapshot {
            table: table_handle,
            chain: chain_handle,
            generation,
        })
    }
}

fn record_echo(receipt: &mut NativeReceipt, message: &Message) -> io::Result<()> {
    let fields = message_fields(message, receipt.family)?;
    match message.message_type {
        kind if kind == nft_type(NEWTABLE) => {
            same_string(required(&fields, 1)?, &receipt.table)?;
            same(required(&fields, 6)?, &receipt.owner)?;
            if receipt.table_handle.is_some() {
                return Err(invalid("duplicate Native table echo"));
            }
            receipt.table_handle = Some(handle(required(&fields, 4)?)?);
        }
        kind if kind == nft_type(NEWCHAIN) => {
            same_string(required(&fields, 1)?, &receipt.table)?;
            same_string(required(&fields, 3)?, CHAIN_NAME)?;
            same(required(&fields, 12)?, &receipt.owner)?;
            if receipt.chain_handle.is_some() {
                return Err(invalid("duplicate Native chain echo"));
            }
            receipt.chain_handle = Some(handle(required(&fields, 2)?)?);
        }
        kind if kind == nft_type(NEWRULE) => {
            same_string(required(&fields, 1)?, &receipt.table)?;
            same_string(required(&fields, 2)?, CHAIN_NAME)?;
            let userdata = required(&fields, 7)?;
            let rule = receipt
                .pending
                .as_mut()
                .ok_or_else(|| invalid("Native rule echo without intent"))?
                .rules
                .iter_mut()
                .find(|rule| rule.userdata.as_slice() == userdata.as_ref())
                .ok_or_else(|| invalid("Native rule echo does not match intent"))?;
            if rule.handle.is_some() {
                return Err(invalid("duplicate Native rule echo"));
            }
            compare_expressions(
                required(&fields, 4)?.clone(),
                Bytes::copy_from_slice(&rule.expressions),
            )?;
            rule.handle = Some(handle(required(&fields, 3)?)?);
        }
        _ => return Err(invalid("unexpected Native mutation echo")),
    }
    Ok(())
}
struct Snapshot {
    table: u64,
    chain: u64,
    generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketBuffers {
    receive: usize,
    send: usize,
}

impl SocketBuffers {
    fn memory_bound(self) -> usize {
        // A query can cross its rcvbuf watermark by one dump skb. Its head
        // rounds up after shared-info padding; reserve twice the datagram plus
        // descriptor space and the outbound request's allocation overhead.
        self.receive + self.send + 2 * READBACK_DATAGRAM_BYTES + 2 * REPLY_SKB_BYTES
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransactionCapacity {
    acknowledgements: usize,
    echoes: usize,
    buffers: SocketBuffers,
}

fn transaction_capacity(request: Bytes) -> io::Result<TransactionCapacity> {
    bound_request(&request)?;
    let mut acknowledgements = 0usize;
    let mut echoes = 0usize;
    let request_bytes = request.len();
    for message in netlink::messages(request) {
        let message = message.map_err(invalid_decode)?;
        if message.body.len() < netlink::NFGENMSG_LEN
            || message.body.len() + netlink::NLMSG_HDRLEN > MAX_CONTROL_MESSAGE_BYTES
        {
            return Err(input(
                "Native control message exceeds admitted skb envelope",
            ));
        }
        acknowledgements += usize::from(message.flags & netlink::NLM_F_ACK != 0);
        echoes += usize::from(message.flags & 8 != 0);
    }
    if acknowledgements == 0 {
        return Err(input("Native transaction has no ACK frontier"));
    }
    // send() processes the batch synchronously: the complete reply burst can
    // already be queued before the first recv(). One extra envelope covers a
    // batch-level error in place of individual transaction acknowledgements.
    let receive = ((acknowledgements + echoes + 1) * REPLY_SKB_BYTES).max(MIN_RECEIVE_BYTES);
    let send = netlink::align4(request_bytes + 32).max(MIN_SEND_BYTES);
    Ok(TransactionCapacity {
        acknowledgements,
        echoes,
        buffers: SocketBuffers { receive, send },
    })
}

fn read_socket_buffer(fd: i32, option: libc::c_int) -> io::Result<usize> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&value) || value <= 0 {
        return Err(invalid("invalid Native socket buffer readback"));
    }
    Ok(value as usize)
}

fn read_socket_buffers(fd: i32) -> io::Result<SocketBuffers> {
    Ok(SocketBuffers {
        receive: read_socket_buffer(fd, libc::SO_RCVBUF)?,
        send: read_socket_buffer(fd, libc::SO_SNDBUF)?,
    })
}

fn verify_socket_buffer(actual: usize, expected: usize) -> io::Result<()> {
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("Native socket effective buffer {actual} does not equal reserved {expected}"),
        ));
    }
    Ok(())
}

fn set_socket_buffer(
    fd: i32,
    option: libc::c_int,
    force: libc::c_int,
    expected: usize,
) -> io::Result<()> {
    // Linux doubles the requested value. Charge and compare the effective
    // GETSOCKOPT value, rather than mistaking the requested payload for memory.
    let requested = libc::c_int::try_from(expected.div_ceil(2))
        .map_err(|_| input("Native socket buffer size exceeds Linux option range"))?;
    let set = |option| -> io::Result<()> {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&requested as *const libc::c_int).cast(),
                std::mem::size_of_val(&requested) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    };
    set(option)?;
    if read_socket_buffer(fd, option)? < expected {
        // FORCE is attempted only for a capped ordinary option. The kernel
        // requires CAP_NET_ADMIN; refusal remains a pre-mutation error.
        set(force)?;
    }
    verify_socket_buffer(read_socket_buffer(fd, option)?, expected)
}

fn apply_socket_buffers(fd: i32, buffers: SocketBuffers) -> io::Result<()> {
    set_socket_buffer(fd, libc::SO_SNDBUF, libc::SO_SNDBUFFORCE, buffers.send)?;
    set_socket_buffer(fd, libc::SO_RCVBUF, libc::SO_RCVBUFFORCE, buffers.receive)?;
    let actual = read_socket_buffers(fd)?;
    verify_socket_buffer(actual.send, buffers.send)?;
    verify_socket_buffer(actual.receive, buffers.receive)
}

fn conntrack_anchor_rule(owner: &[u8; 16]) -> NativeRuleReceipt {
    let mut userdata = Vec::with_capacity(32);
    userdata.extend_from_slice(owner);
    userdata.extend_from_slice(&0u64.to_be_bytes());
    userdata.extend_from_slice(&0u32.to_be_bytes());
    userdata.extend_from_slice(&2u32.to_be_bytes());
    let mut expressions = Vec::with_capacity(64);
    // nft_ct init/destroy holds the actual family netns/defrag reference;
    // the unused register value grants no routing or conntrack authority.
    put_ct_state_load(&mut expressions);
    NativeRuleReceipt {
        handle: None,
        userdata,
        matcher_program_id: 0,
        matcher_tag: [0; 8],
        matcher_fd: -1,
        mark: None,
        candidate_scope: false,
        conntrack_anchor: true,
        expressions,
    }
}

fn prepare_generation(
    owner: &[u8; 16],
    generation: u64,
    actions: &[NativeAction<'_>],
    scope: BorrowedFd<'_>,
) -> io::Result<Generation> {
    if actions.len() > MAX_ACTIONS {
        return Err(input("Native action count exceeds 257"));
    }
    for (index, action) in actions.iter().enumerate() {
        if actions[..index]
            .iter()
            .any(|other| other.mark == action.mark)
        {
            return Err(input("duplicate Native Keep/Set action"));
        }
    }
    if actions
        .iter()
        .filter(|action| action.mark.is_some())
        .count()
        > 256
    {
        return Err(input("Native Set action count exceeds 256"));
    }
    let mut matchers = Vec::with_capacity(actions.len() + 1);
    let mut rules = Vec::with_capacity(actions.len() + 2);
    rules.push(conntrack_anchor_rule(owner));
    for (index, (fd, mark, candidate_scope)) in actions
        .iter()
        .map(|action| (action.matcher, action.mark, false))
        .chain(std::iter::once((scope, None, true)))
        .enumerate()
    {
        let fd = fd.try_clone_to_owned()?;
        let (matcher_program_id, matcher_tag) = program_identity(fd.as_fd())?;
        let mut userdata = Vec::with_capacity(32);
        userdata.extend_from_slice(owner);
        userdata.extend_from_slice(&generation.to_be_bytes());
        userdata.extend_from_slice(&(index as u32).to_be_bytes());
        userdata.extend_from_slice(&u32::from(candidate_scope).to_be_bytes());
        rules.push(NativeRuleReceipt {
            handle: None,
            userdata,
            matcher_program_id,
            matcher_tag,
            matcher_fd: fd.as_raw_fd(),
            mark,
            candidate_scope,
            conntrack_anchor: false,
            expressions: rule_expressions(fd.as_raw_fd(), mark, candidate_scope),
        });
        matchers.push(fd);
    }
    Ok(Generation {
        receipt: NativeGenerationReceipt {
            generation,
            mutation_acked: false,
            rules,
        },
        matchers,
    })
}

fn program_identity(fd: BorrowedFd<'_>) -> io::Result<(u32, [u8; 8])> {
    #[repr(C)]
    struct InfoAttr {
        fd: u32,
        length: u32,
        info: u64,
    }
    let mut info = [0u8; 16];
    let mut attr = InfoAttr {
        fd: fd.as_raw_fd() as u32,
        length: info.len() as u32,
        info: info.as_mut_ptr() as u64,
    };
    if unsafe {
        libc::syscall(
            libc::SYS_bpf,
            15,
            &mut attr as *mut InfoAttr,
            std::mem::size_of::<InfoAttr>(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let kind = u32::from_ne_bytes(info[..4].try_into().expect("type"));
    let id = u32::from_ne_bytes(info[4..8].try_into().expect("id"));
    if kind != 1 || id == 0 {
        return Err(input(
            "Native matcher must be an actual SOCKET_FILTER program",
        ));
    }
    Ok((id, info[8..16].try_into().expect("tag")))
}

fn xt_bpf_info(fd: i32) -> [u8; XT_BPF_MATCHSIZE] {
    // Linux xt_bpf.h: mode:u16, count:u16, fd:s32, union[512],
    // filter pointer aligned(8). nft_compat needs matchsize, not usersize;
    // its dump copies usersize=520 and zeros the private pointer to 528.
    let mut info = [0u8; XT_BPF_MATCHSIZE];
    info[..2].copy_from_slice(&2u16.to_ne_bytes()); // XT_BPF_MODE_FD_ELF
    info[4..8].copy_from_slice(&fd.to_ne_bytes());
    info[XT_BPF_USERSIZE..].fill(0);
    info
}

fn rule_expressions(fd: i32, mark: Option<u32>, drop_scope: bool) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(768);
    put_expression(&mut buffer, "match", |buffer| {
        netlink::put_attribute_string(buffer, 1, "bpf");
        netlink::put_attribute_be32(buffer, 2, 1);
        netlink::put_attribute(buffer, 3, &xt_bpf_info(fd));
    });
    if let Some(mark) = mark {
        put_expression(&mut buffer, "immediate", |buffer| {
            netlink::put_attribute_be32(buffer, 1, 1);
            let data = netlink::begin_nested(buffer, 2);
            netlink::put_attribute(buffer, 1, &mark.to_ne_bytes());
            netlink::seal_nested(buffer, data);
        });
        put_expression(&mut buffer, "meta", |buffer| {
            netlink::put_attribute_be32(buffer, 2, 3); // NFT_META_MARK
            netlink::put_attribute_be32(buffer, 3, 1); // NFTA_META_SREG
        });
    }
    put_expression(&mut buffer, "immediate", |buffer| {
        netlink::put_attribute_be32(buffer, 1, 0); // NFT_REG_VERDICT
        let data = netlink::begin_nested(buffer, 2);
        let verdict = netlink::begin_nested(buffer, 2);
        netlink::put_attribute_be32(buffer, 1, u32::from(!drop_scope));
        netlink::seal_nested(buffer, verdict);
        netlink::seal_nested(buffer, data);
    });
    buffer
}

fn batch_end(buffer: &mut Vec<u8>, sequence: u32) {
    let start = netlink::put_message_header(
        buffer,
        netlink::NFNL_MSG_BATCH_END,
        netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
        sequence,
        0,
        netlink::NFNL_BATCH_RES_ID,
    );
    netlink::seal_message(buffer, start);
}
fn nft_type(kind: u16) -> u16 {
    (netlink::NFNL_SUBSYS_NFTABLES << 8) | kind
}
fn put_be64(buffer: &mut Vec<u8>, kind: u16, value: u64) {
    netlink::put_attribute(buffer, kind, &value.to_be_bytes());
}
fn bound_request(request: &[u8]) -> io::Result<()> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(input("Native nft batch exceeds staging budget"));
    }
    Ok(())
}
fn ack_code(bytes: &[u8]) -> io::Result<i32> {
    Ok(i32::from_ne_bytes(
        bytes
            .get(..4)
            .ok_or_else(|| invalid("truncated netlink error"))?
            .try_into()
            .expect("four bytes"),
    ))
}
fn message_fields(message: &Message, family: u8) -> io::Result<Vec<Attribute>> {
    if message.body.len() < 4 || message.body[0] != family || message.body[1] != 0 {
        return Err(invalid("Native nft family or nfgen version mismatch"));
    }
    fields_of(message.body.slice(4..))
}
fn bounded_attributes(bytes: Bytes, limit: usize) -> io::Result<Vec<Attribute>> {
    if bytes.len() > 4096 {
        return Err(invalid("Native attribute byte budget exceeded"));
    }
    let mut fields = Vec::with_capacity(limit);
    for field in netlink::attributes(bytes) {
        if fields.len() == limit {
            return Err(invalid("Native attribute count budget exceeded"));
        }
        fields.push(field.map_err(invalid_decode)?);
    }
    Ok(fields)
}
fn fields_of(bytes: Bytes) -> io::Result<Vec<Attribute>> {
    let mut fields = bounded_attributes(bytes, 16)?;
    fields.sort_by_key(|field| field.kind);
    if fields.windows(2).any(|pair| pair[0].kind == pair[1].kind) {
        return Err(invalid("duplicate nft attribute"));
    }
    Ok(fields)
}
fn allow(fields: &[Attribute], allowed: &[u16]) -> io::Result<()> {
    if fields.iter().any(|field| !allowed.contains(&field.kind)) {
        return Err(invalid("unexpected owned nft attribute"));
    }
    Ok(())
}
fn optional(fields: &[Attribute], kind: u16) -> Option<&Bytes> {
    fields
        .iter()
        .find(|field| field.kind == kind)
        .map(|field| &field.payload)
}
fn required(fields: &[Attribute], kind: u16) -> io::Result<&Bytes> {
    optional(fields, kind).ok_or_else(|| invalid("missing owned nft attribute"))
}
fn be32(bytes: &[u8]) -> io::Result<u32> {
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| invalid("invalid nft u32"))?,
    ))
}
fn handle(bytes: &[u8]) -> io::Result<u64> {
    let handle = u64::from_be_bytes(
        bytes
            .try_into()
            .map_err(|_| invalid("invalid nft handle"))?,
    );
    if handle == 0 {
        return Err(invalid("zero nft handle"));
    }
    Ok(handle)
}
fn same(actual: &[u8], expected: &[u8]) -> io::Result<()> {
    if actual != expected {
        return Err(invalid("owned nft content changed"));
    }
    Ok(())
}
fn same_string(actual: &[u8], expected: &str) -> io::Result<()> {
    if actual.last() != Some(&0) || &actual[..actual.len() - 1] != expected.as_bytes() {
        return Err(invalid("owned nft name changed"));
    }
    Ok(())
}
fn compare_expressions(actual: Bytes, expected: Bytes) -> io::Result<()> {
    let actual = bounded_attributes(actual, 4)?;
    let expected = bounded_attributes(expected, 4)?;
    if actual.len() != expected.len() {
        return Err(invalid("Native expression count changed"));
    }
    for (actual, expected) in actual.iter().zip(expected.iter()) {
        if actual.kind != 1 || expected.kind != 1 {
            return Err(invalid("invalid nft expression list"));
        }
        let actual = fields_of(actual.payload.clone())?;
        let expected = fields_of(expected.payload.clone())?;
        allow(&actual, &[1, 2])?;
        same(required(&actual, 1)?, required(&expected, 1)?)?;
        let name = required(&expected, 1)?;
        let actual = fields_of(required(&actual, 2)?.clone())?;
        let expected = fields_of(required(&expected, 2)?.clone())?;
        if name.as_ref() == b"immediate\0" {
            allow(&actual, &[1, 2])?;
            same(required(&actual, 1)?, required(&expected, 1)?)?;
            let actual = fields_of(required(&actual, 2)?.clone())?;
            let expected = fields_of(required(&expected, 2)?.clone())?;
            if actual.len() != 1 || expected.len() != 1 || actual[0].kind != expected[0].kind {
                return Err(invalid("Native immediate changed"));
            }
            if expected[0].kind == 2 {
                if fields_of(actual[0].payload.clone())? != fields_of(expected[0].payload.clone())?
                {
                    return Err(invalid("Native verdict changed"));
                }
            } else {
                same(&actual[0].payload, &expected[0].payload)?;
            }
        } else if actual != expected {
            return Err(invalid("Native match or mark setter changed"));
        }
    }
    Ok(())
}
fn input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn invalid_decode(error: netlink::DecodeError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xt_bpf_revision_one_uses_full_aligned_matchsize() {
        let info = xt_bpf_info(0x1234_5678);
        assert_eq!(info.len(), 528);
        assert_eq!(XT_BPF_USERSIZE, 520);
        assert_eq!(&info[..8], &[2, 0, 0, 0, 0x78, 0x56, 0x34, 0x12]);
        assert!(info[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn full_mark_set_and_keep_have_distinct_exact_expressions() {
        let keep = rule_expressions(7, None, false);
        for mark in [0, 1, 0x8000_0000, u32::MAX] {
            let set = rule_expressions(7, Some(mark), false);
            assert!(
                compare_expressions(Bytes::from(keep.clone()), Bytes::from(set.clone())).is_err()
            );
            let expressions = netlink::attributes(Bytes::from(set.clone()))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            assert_eq!(expressions.len(), 4);
            let immediate = fields_of(expressions[1].payload.clone()).unwrap();
            let data = fields_of(required(&immediate, 2).unwrap().clone()).unwrap();
            let value = fields_of(required(&data, 2).unwrap().clone()).unwrap();
            assert_eq!(required(&value, 1).unwrap().as_ref(), &mark.to_ne_bytes());
            compare_expressions(Bytes::from(set.clone()), Bytes::from(set)).unwrap();
        }
        assert_eq!(netlink::attributes(Bytes::from(keep.clone())).count(), 2);
        assert!(
            compare_expressions(
                Bytes::from(keep),
                Bytes::from(rule_expressions(7, None, true))
            )
            .is_err()
        );
    }

    #[test]
    fn readback_rejects_private_pointer_and_matcher_or_action_changes() {
        let expected = rule_expressions(7, Some(0), false);
        for changed in [
            rule_expressions(8, Some(0), false),
            rule_expressions(7, Some(u32::MAX), false),
            rule_expressions(7, Some(0), true),
        ] {
            assert!(
                compare_expressions(Bytes::from(changed), Bytes::from(expected.clone())).is_err()
            );
        }
        let mut changed = expected.clone();
        let info = changed
            .windows(8)
            .position(|bytes| bytes == [2, 0, 0, 0, 7, 0, 0, 0])
            .unwrap();
        changed[info + XT_BPF_USERSIZE] = 1;
        assert!(compare_expressions(Bytes::from(changed), Bytes::from(expected)).is_err());
    }

    #[test]
    fn action_limits_fail_before_bpf_or_netlink_mutation() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let duplicate = [
            NativeAction {
                matcher: file.as_fd(),
                mark: None,
            },
            NativeAction {
                matcher: file.as_fd(),
                mark: None,
            },
        ];
        assert_eq!(
            prepare_generation(&[1; 16], 1, &duplicate, file.as_fd())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let too_many: Vec<_> = (0..257)
            .map(|mark| NativeAction {
                matcher: file.as_fd(),
                mark: Some(mark),
            })
            .collect();
        assert_eq!(
            prepare_generation(&[1; 16], 1, &too_many, file.as_fd())
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(NativeRoutes::kernel_memory_bound(MAX_ACTIONS + 1).is_err());
    }

    #[test]
    fn reply_capacity_covers_full_replacement_burst_and_linux_buffer_accounting() {
        for (old_actions, new_actions) in [(0, 0), (257, 0), (0, 257), (257, 257)] {
            let mut request = Vec::new();
            for _ in 0..old_actions + 1 {
                let start = netlink::put_message_header(
                    &mut request,
                    nft_type(DELRULE),
                    netlink::NLM_F_REQUEST | netlink::NLM_F_ACK,
                    1,
                    2,
                    netlink::NFNL_SUBSYS_NFTABLES,
                );
                netlink::seal_message(&mut request, start);
            }
            for _ in 0..new_actions + 1 {
                let start = netlink::put_message_header(
                    &mut request,
                    nft_type(NEWRULE),
                    netlink::NLM_F_REQUEST | netlink::NLM_F_ACK | 8,
                    1,
                    2,
                    netlink::NFNL_SUBSYS_NFTABLES,
                );
                netlink::seal_message(&mut request, start);
            }
            batch_end(&mut request, 1);
            let capacity = transaction_capacity(Bytes::from(request)).unwrap();
            assert_eq!(capacity.acknowledgements, old_actions + new_actions + 3);
            assert_eq!(capacity.echoes, new_actions + 1);
            assert_eq!(
                capacity.buffers.receive,
                (old_actions + 2 * new_actions + 5) * REPLY_SKB_BYTES
            );
            assert!(
                capacity.buffers.memory_bound()
                    <= NativeRoutes::socket_memory_bound(old_actions).unwrap()
                        + NativeRoutes::socket_memory_bound(new_actions).unwrap()
            );
        }
        assert!(verify_socket_buffer(212_992, 4_000_000).is_err());
        assert!(verify_socket_buffer(2 * MIN_SEND_BYTES, MIN_SEND_BYTES).is_err());
        verify_socket_buffer(MIN_RECEIVE_BYTES, MIN_RECEIVE_BYTES).unwrap();
    }

    #[test]
    fn capacity_refusal_leaves_prepared_receipt_and_socket_limits_unchanged() {
        let mut routes =
            NativeRoutes::prepare("honk_native_capacity", &[1; 16], libc::AF_INET as u8).unwrap();
        let before = routes.receipt().clone();
        let buffers = SocketBuffers {
            receive: MIN_RECEIVE_BYTES,
            send: MIN_SEND_BYTES,
        };
        assert!(
            routes
                .configure_capacity(buffers, buffers.memory_bound() - 1)
                .is_err()
        );
        assert_eq!(routes.receipt(), &before);
        assert_eq!(
            read_socket_buffers(routes.socket.as_raw_fd()).unwrap(),
            buffers
        );
        assert!(!routes.receipt().install_attempted);
        assert!(routes.receipt().pending.is_none());
    }

    #[test]
    fn oversized_control_message_is_refused_before_reply_skb_budgeting() {
        let mut request = Vec::new();
        let start = netlink::put_message_header(
            &mut request,
            nft_type(NEWRULE),
            netlink::NLM_F_REQUEST | netlink::NLM_F_ACK | 8,
            1,
            2,
            netlink::NFNL_SUBSYS_NFTABLES,
        );
        request.resize(MAX_CONTROL_MESSAGE_BYTES + 4, 0);
        netlink::seal_message(&mut request, start);
        assert!(transaction_capacity(Bytes::from(request)).is_err());
    }

    #[test]
    fn duplicate_attributes_and_nested_action_changes_are_refused() {
        let mut attributes = Vec::new();
        netlink::put_attribute_be32(&mut attributes, 1, 1);
        netlink::put_attribute_be32(&mut attributes, 1, 1);
        assert!(fields_of(Bytes::from(attributes)).is_err());
        let expected = rule_expressions(7, Some(0), false);
        let mut changed = expected.clone();
        changed.extend_from_slice(&expected);
        assert!(compare_expressions(Bytes::from(changed), Bytes::from(expected)).is_err());
    }

    #[test]
    fn conntrack_anchor_only_loads_state_without_policy_or_matcher() {
        let anchor = conntrack_anchor_rule(&[1; 16]);
        assert!(anchor.conntrack_anchor);
        assert!(!anchor.candidate_scope);
        assert_eq!(anchor.matcher_program_id, 0);
        assert_eq!(anchor.matcher_tag, [0; 8]);
        assert_eq!(anchor.matcher_fd, -1);
        assert_eq!(anchor.mark, None);
        let expressions = bounded_attributes(Bytes::from(anchor.expressions.clone()), 1).unwrap();
        assert_eq!(expressions.len(), 1);
        let expression = fields_of(expressions[0].payload.clone()).unwrap();
        assert_eq!(required(&expression, 1).unwrap().as_ref(), b"ct\0");
        let data = fields_of(required(&expression, 2).unwrap().clone()).unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(be32(required(&data, 1).unwrap()).unwrap(), 1);
        assert_eq!(be32(required(&data, 2).unwrap()).unwrap(), 0);
        compare_expressions(
            Bytes::from(anchor.expressions.clone()),
            Bytes::from(anchor.expressions.clone()),
        )
        .unwrap();
        let mut altered = anchor.expressions.clone();
        put_expression(&mut altered, "immediate", |buffer| {
            netlink::put_attribute_be32(buffer, 1, 0);
        });
        assert!(
            compare_expressions(Bytes::from(altered), Bytes::from(anchor.expressions)).is_err()
        );
        assert_eq!(
            NativeRoutes::kernel_memory_bound(0).unwrap(),
            KERNEL_FIXED_BYTES
                + 2 * KERNEL_BYTES_PER_RULE
                + NativeRoutes::socket_memory_bound(0).unwrap()
        );
    }

    #[test]
    #[ignore = "requires disposable VM root, nft route, nft_compat and xt_bpf revision 1"]
    fn native_routes_isolated_netns_kernel_roundtrip() {
        std::thread::spawn(|| {
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) },
                0,
                "unshare: {}",
                io::Error::last_os_error()
            );
            let matcher = load_socket_filter();
            for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
                let actions = [
                    NativeAction {
                        matcher: matcher.as_fd(),
                        mark: None,
                    },
                    NativeAction {
                        matcher: matcher.as_fd(),
                        mark: Some(0),
                    },
                    NativeAction {
                        matcher: matcher.as_fd(),
                        mark: Some(u32::MAX),
                    },
                ];
                let mut routes =
                    NativeRoutes::prepare("honk_native_roundtrip", &[1; 16], family).unwrap();
                routes.install(&actions, matcher.as_fd()).unwrap();
                routes.check().unwrap();
                let original = routes.receipt().clone();
                assert_eq!(
                    original.socket_receive_bytes,
                    (2 * actions.len() + 10) * REPLY_SKB_BYTES
                );
                assert!(original.socket_send_bytes >= MIN_SEND_BYTES);
                let socket_memory = SocketBuffers {
                    receive: original.socket_receive_bytes,
                    send: original.socket_send_bytes,
                };
                assert!(
                    socket_memory.memory_bound()
                        <= NativeRoutes::socket_memory_bound(actions.len()).unwrap()
                );
                assert!(original.table_handle.is_some());
                assert!(original.chain_handle.is_some());
                let original_rules = &original.active.as_ref().unwrap().rules;
                assert_eq!(original_rules.len(), actions.len() + 2);
                assert_eq!(
                    original_rules
                        .iter()
                        .filter(|rule| rule.conntrack_anchor)
                        .count(),
                    1
                );
                assert!(original_rules[0].conntrack_anchor);
                assert!(
                    original
                        .active
                        .as_ref()
                        .unwrap()
                        .rules
                        .iter()
                        .all(|rule| rule.handle.is_some()
                            && (rule.conntrack_anchor || rule.matcher_program_id != 0))
                );
                let mut collision =
                    NativeRoutes::prepare("honk_native_roundtrip", &[2; 16], family).unwrap();
                assert_eq!(
                    collision
                        .install(&actions, matcher.as_fd())
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EEXIST)
                );
                assert!(collision.remove().is_err());
                assert!(!collision.receipt().table_create_acked);
                routes.check().unwrap();
                let duplicate = [
                    NativeAction {
                        matcher: matcher.as_fd(),
                        mark: None,
                    },
                    NativeAction {
                        matcher: matcher.as_fd(),
                        mark: None,
                    },
                ];
                assert!(routes.replace(&duplicate, matcher.as_fd()).is_err());
                assert_eq!(&original, routes.receipt());
                routes.replace(&actions[1..2], matcher.as_fd()).unwrap();
                routes.check().unwrap();
                assert_eq!(routes.receipt().table_handle, original.table_handle);
                assert_eq!(routes.receipt().chain_handle, original.chain_handle);
                assert_eq!(routes.receipt().active.as_ref().unwrap().generation, 2);
                let replaced_rules = &routes.receipt().active.as_ref().unwrap().rules;
                assert_eq!(replaced_rules.len(), 3);
                assert_eq!(&replaced_rules[0], &original_rules[0]);
                routes.remove().unwrap();
                routes.check().unwrap();
                assert!(routes.receipt().removed);
            }
        })
        .join()
        .unwrap();
    }

    fn load_socket_filter() -> OwnedFd {
        use std::os::fd::FromRawFd;
        // A false matcher exercises real FD/type validation and compat rule
        // lifetime without granting packet permission in this ownership test.
        let instructions: [u8; 16] = [0xb7, 0, 0, 0, 0, 0, 0, 0, 0x95, 0, 0, 0, 0, 0, 0, 0];
        let license = b"GPL\0";
        let mut attributes = [0u8; 72];
        attributes[..4].copy_from_slice(&1u32.to_ne_bytes());
        attributes[4..8].copy_from_slice(&2u32.to_ne_bytes());
        attributes[8..16].copy_from_slice(&(instructions.as_ptr() as u64).to_ne_bytes());
        attributes[16..24].copy_from_slice(&(license.as_ptr() as u64).to_ne_bytes());
        let fd = unsafe { libc::syscall(libc::SYS_bpf, 5, attributes.as_ptr(), attributes.len()) };
        assert!(fd >= 0, "BPF_PROG_LOAD: {}", io::Error::last_os_error());
        unsafe { OwnedFd::from_raw_fd(fd as i32) }
    }
}

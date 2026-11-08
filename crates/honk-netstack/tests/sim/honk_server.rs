//! honk-netstack as a transparent terminator: accepts whatever the client dials (`10.0.0.2:8000+i`)
//! and plays the server side of the plan. Flow `i` is identified by the destination port; with
//! `ServerOpts::per_source` it is `source index * per_source + port - 8000`, where the source index
//! is the last two octets of the client address `10.1.hi.lo` (see `source_addr`).

use super::app::{Driver, Plan, Role, StreamError, StreamIo};
use super::engine::{Host, epoch};
use super::smol::Family;
use honk_netstack::wire::{self, tcp};
use honk_netstack::{
    AcceptOpts, AcceptWhen, Config, ExcludeSet, FlowId, Mode, Stack, StreamError as NsError,
    TcpState,
};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The address of client source `k` in a multi-source run.
pub fn source_addr(k: usize) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 1, (k >> 8) as u8, k as u8))
}

pub type ConfigHook = Box<dyn FnOnce(&mut Config)>;

#[derive(Default)]
pub struct ServerOpts {
    /// Several client sources with this many flows each (see the module comment).
    pub per_source: Option<usize>,
    /// Close the application handle of a flow as soon as the server side of the plan completed
    /// (the compact TIME_WAIT entry then outlives the handle).
    pub close_when_done: bool,
    /// Adjusts the stack configuration (budget, limits).
    pub config: Option<ConfigHook>,
}

/// What the terminator emitted: the transparency check ("a reply is sourced from the original
/// destination") and the resets it sent.
#[derive(Debug, Default)]
pub struct Audit {
    pub tcp_packets: u64,
    pub rsts: u64,
    /// Packets whose source was not the original destination of an accepted flow.
    pub foreign: u64,
    /// FINs delivered when every full flow is gone and only compact TIME_WAIT entries remain.
    pub tombstone_fins: u64,
}

pub struct HonkServerIo {
    pub stack: Stack,
    ids: Vec<Option<FlowId>>,
    app_indices: HashMap<FlowId, usize>,
    /// When each flow was reported by `poll_accept`.
    pub admitted: Vec<Option<Instant>>,
    closed: Vec<bool>,
    /// Deferred flows waiting for their (simulated) upstream dial.
    held: Vec<(FlowId, Instant)>,
    defer: Option<Duration>,
    per_source: Option<usize>,
    close_when_done: bool,
    tuples: HashSet<(SocketAddr, SocketAddr)>,
    pub audit: Audit,
}

impl HonkServerIo {
    pub fn close_all(&mut self) {
        for id in self.ids.iter().flatten() {
            self.stack.tcp_close(*id);
        }
    }

    pub fn id(&self, i: usize) -> Option<FlowId> {
        self.ids[i]
    }

    fn index_of(&self, client: IpAddr, dst_port: u16) -> usize {
        let port = usize::from(dst_port - 8000);
        match (self.per_source, client) {
            (Some(per), IpAddr::V4(a)) => {
                let o = a.octets();
                assert_eq!(&o[..2], &[10, 1], "unexpected client {a}");
                (usize::from(o[2]) << 8 | usize::from(o[3])) * per + port
            }
            _ => port,
        }
    }
}

impl StreamIo for HonkServerIo {
    type Id = usize;

    fn connected(&self, i: usize) -> bool {
        self.ids[i].is_some_and(|id| {
            !matches!(
                self.stack.tcp_state(id),
                None | Some(TcpState::SynSent | TcpState::SynReceived)
            )
        })
    }

    fn read(&mut self, i: usize, out: &mut [u8]) -> Result<usize, StreamError> {
        match self.ids[i] {
            Some(id) if !self.closed[i] => self.stack.tcp_read(id, out).map_err(map_err),
            _ => Err(StreamError::WouldBlock),
        }
    }

    fn write(&mut self, i: usize, data: &[u8]) -> Result<usize, StreamError> {
        match self.ids[i] {
            Some(id) if !self.closed[i] => self.stack.tcp_write(id, data).map_err(map_err),
            _ => Err(StreamError::WouldBlock),
        }
    }

    fn shutdown(&mut self, i: usize) -> Result<(), StreamError> {
        match self.ids[i] {
            Some(id) => self.stack.tcp_shutdown(id).map_err(map_err),
            None => Err(StreamError::WouldBlock),
        }
    }
}

fn map_err(e: NsError) -> StreamError {
    match e {
        NsError::WouldBlock => StreamError::WouldBlock,
        NsError::Closed => StreamError::Closed,
        _ => StreamError::Reset,
    }
}

pub struct HonkServerHost {
    pub io: HonkServerIo,
    pub app: Driver<usize>,
}

impl HonkServerHost {
    /// `defer`: hold every SYN-ACK this long (a simulated upstream dial) before completing.
    pub fn new(family: Family, buffer: usize, plan: Plan, defer: Option<Duration>) -> Self {
        Self::with(family, buffer, plan, defer, ServerOpts::default())
    }

    pub fn with(
        _family: Family,
        buffer: usize,
        plan: Plan,
        defer: Option<Duration>,
        opts: ServerOpts,
    ) -> Self {
        let mut cfg = Config::new([8; 32]);
        cfg.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
        cfg.tcp_rcv_buf_max = buffer;
        cfg.tcp_snd_buf_max = buffer;
        if let Some(f) = opts.config {
            f(&mut cfg);
        }
        let flows = plan.flows;
        let io = HonkServerIo {
            stack: Stack::new(cfg, epoch()),
            ids: vec![None; flows],
            app_indices: HashMap::with_capacity(flows),
            admitted: vec![None; flows],
            closed: vec![false; flows],
            held: Vec::with_capacity(flows),
            defer,
            per_source: opts.per_source,
            close_when_done: opts.close_when_done,
            tuples: HashSet::with_capacity(flows),
            audit: Audit::default(),
        };
        HonkServerHost {
            io,
            app: Driver::new(plan, Role::Server, 0..flows, epoch()),
        }
    }
}

impl Host for HonkServerHost {
    fn receive(&mut self, now: Instant, packet: &[u8]) {
        let s = self.io.stack.stats();
        if s.flows == 0
            && s.timewait_entries > 0
            && let Ok(ip) = wire::parse_ip(packet)
            && ip.proto == wire::PROTO_TCP
            && let Ok((h, _)) = tcp::parse(&packet[ip.payload])
            && h.flags & tcp::FIN != 0
        {
            self.io.audit.tombstone_fins += 1;
        }
        self.io.stack.receive(now, packet);
    }

    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        let n = self.io.stack.poll_transmit(now, out)?;
        let ip = wire::parse_ip(&out[..n]).expect("the terminator emits valid IP");
        if ip.proto == wire::PROTO_TCP {
            let (h, _) = tcp::parse(&out[ip.payload.clone()]).expect("valid TCP");
            let audit = &mut self.io.audit;
            audit.tcp_packets += 1;
            audit.rsts += u64::from(h.flags & tcp::RST != 0);
            audit.foreign += u64::from(!self.io.tuples.contains(&(
                SocketAddr::new(ip.src, h.src_port),
                SocketAddr::new(ip.dst, h.dst_port),
            )));
        }
        Some(n)
    }

    fn poll_timeout(&self) -> Option<Instant> {
        let held = self.io.held.iter().map(|&(_, at)| at).min();
        [self.io.stack.poll_timeout(), held]
            .into_iter()
            .flatten()
            .min()
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.io.stack.handle_timeout(now);
    }

    fn poll_app(&mut self, now: Instant) {
        let io = &mut self.io;
        while let Some(info) = io.stack.poll_accept() {
            let i = io.index_of(info.client.ip(), info.original_dst.port());
            assert!(io.ids[i].is_none(), "flow {i} reported twice");
            io.ids[i] = Some(info.id);
            io.app_indices.insert(info.id, i);
            io.admitted[i] = Some(now);
            io.tuples.insert((info.original_dst, info.client));
            let when = match io.defer {
                Some(d) => {
                    io.held.push((info.id, now + d));
                    AcceptWhen::Deferred {
                        deadline: Duration::from_secs(20),
                    }
                }
                None => AcceptWhen::Now,
            };
            io.stack
                .tcp_accept(
                    info.id,
                    AcceptOpts {
                        when,
                        ..AcceptOpts::default()
                    },
                )
                .expect("accept");
        }
        io.held.retain(|&(id, at)| {
            if at > now {
                return true;
            }
            io.stack.tcp_complete(id).expect("complete");
            false
        });
        while let Some((id, _ready)) = io.stack.poll_event() {
            let i = io.app_indices[&id];
            self.app.poll_flow(i, io, now);
            if io.close_when_done && self.app.flows[i].completed.is_some() && !io.closed[i] {
                io.closed[i] = true;
                io.stack.tcp_close(id);
            }
        }
        io.stack.take_tx_wakeup();
    }
}

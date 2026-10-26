//! honk-netstack as a transparent terminator: accepts whatever the client dials (`10.0.0.2:8000+i`)
//! and plays the server side of the plan. Flow `i` is identified by the destination port.

use super::app::{Driver, Plan, Role, StreamError, StreamIo};
use super::engine::{Host, epoch};
use super::smol::Family;
use honk_netstack::{
    AcceptOpts, AcceptWhen, Config, ExcludeSet, FlowId, Mode, Stack, StreamError as NsError,
    TcpState,
};
use std::time::{Duration, Instant};

pub struct HonkServerIo {
    pub stack: Stack,
    ids: Vec<Option<FlowId>>,
    /// Deferred flows waiting for their (simulated) upstream dial.
    held: Vec<(FlowId, Instant)>,
    defer: Option<Duration>,
}

impl HonkServerIo {
    pub fn close_all(&mut self) {
        for id in self.ids.iter().flatten() {
            self.stack.tcp_close(*id);
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
            Some(id) => self.stack.tcp_read(id, out).map_err(map_err),
            None => Err(StreamError::WouldBlock),
        }
    }

    fn write(&mut self, i: usize, data: &[u8]) -> Result<usize, StreamError> {
        match self.ids[i] {
            Some(id) => self.stack.tcp_write(id, data).map_err(map_err),
            None => Err(StreamError::WouldBlock),
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
    pub fn new(_family: Family, buffer: usize, plan: Plan, defer: Option<Duration>) -> Self {
        let mut cfg = Config::new([8; 32]);
        cfg.mode = Mode::Transparent {
            exclude: ExcludeSet::default(),
        };
        cfg.tcp_rcv_buf_max = buffer;
        cfg.tcp_snd_buf_max = buffer;
        let flows = plan.flows;
        let io = HonkServerIo {
            stack: Stack::new(cfg, epoch()),
            ids: vec![None; flows],
            held: Vec::new(),
            defer,
        };
        HonkServerHost {
            io,
            app: Driver::new(plan, Role::Server, 0..flows, epoch()),
        }
    }
}

impl Host for HonkServerHost {
    fn receive(&mut self, now: Instant, packet: &[u8]) {
        self.io.stack.receive(now, packet);
    }

    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        self.io.stack.poll_transmit(now, out)
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
            let i = usize::from(info.original_dst.port() - 8000);
            assert!(io.ids[i].is_none(), "flow {i} reported twice");
            io.ids[i] = Some(info.id);
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
        let (due, later): (Vec<_>, Vec<_>) = io.held.drain(..).partition(|&(_, at)| at <= now);
        io.held = later;
        for (id, _) in due {
            io.stack.tcp_complete(id).expect("complete");
        }
        while io.stack.poll_event().is_some() {}
        self.app.poll(&mut self.io, now);
        self.io.stack.take_tx_wakeup();
    }
}

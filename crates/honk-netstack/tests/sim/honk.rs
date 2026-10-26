//! honk-netstack host. honk is always the active opener; a smoltcp listener plays the server.

use super::app::{Driver, Plan, Role, StreamError, StreamIo};
use super::engine::{Host, epoch};
use super::smol::Family;
use honk_netstack::{Config, FlowId, Stack, StreamError as NsError, TcpState};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

pub struct HonkTcp {
    pub stack: Stack,
}

impl HonkTcp {
    pub fn new(family: Family, buffer: usize) -> Self {
        let mut cfg = Config::new([7; 32]);
        match family.address(Role::Client).into() {
            IpAddr::V4(a) => cfg.local_v4 = Some(a),
            IpAddr::V6(a) => cfg.local_v6 = Some(a),
        }
        cfg.tcp_rcv_buf_max = buffer;
        cfg.tcp_snd_buf_max = buffer;
        HonkTcp {
            stack: Stack::new(cfg, epoch()),
        }
    }
}

impl StreamIo for HonkTcp {
    type Id = FlowId;

    fn connected(&self, id: FlowId) -> bool {
        !matches!(
            self.stack.tcp_state(id),
            None | Some(TcpState::SynSent | TcpState::SynReceived)
        )
    }

    fn read(&mut self, id: FlowId, out: &mut [u8]) -> Result<usize, StreamError> {
        self.stack.tcp_read(id, out).map_err(map_err)
    }

    fn write(&mut self, id: FlowId, data: &[u8]) -> Result<usize, StreamError> {
        self.stack.tcp_write(id, data).map_err(map_err)
    }

    fn shutdown(&mut self, id: FlowId) -> Result<(), StreamError> {
        self.stack.tcp_shutdown(id).map_err(map_err)
    }
}

fn map_err(e: NsError) -> StreamError {
    match e {
        NsError::WouldBlock => StreamError::WouldBlock,
        NsError::Closed => StreamError::Closed,
        _ => StreamError::Reset,
    }
}

pub struct HonkHost {
    pub io: HonkTcp,
    pub app: Driver<FlowId>,
}

impl HonkHost {
    pub fn new(family: Family, buffer: usize, plan: Plan) -> Self {
        let mut io = HonkTcp::new(family, buffer);
        let server: IpAddr = family.address(Role::Server).into();
        let ids: Vec<_> = (0..plan.flows)
            .map(|i| {
                let remote = SocketAddr::new(server, 8000 + u16::try_from(i).unwrap());
                io.stack.tcp_connect(epoch(), remote).expect("connect")
            })
            .collect();
        let app = Driver::new(plan, Role::Client, ids, epoch());
        HonkHost { io, app }
    }
}

impl Host for HonkHost {
    fn receive(&mut self, now: Instant, packet: &[u8]) {
        self.io.stack.receive(now, packet);
    }

    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        self.io.stack.poll_transmit(now, out)
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.io.stack.poll_timeout()
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.io.stack.handle_timeout(now);
    }

    fn poll_app(&mut self, now: Instant) {
        // The driver reads/writes every flow each wakeup, so readiness only needs draining here.
        while self.io.stack.poll_event().is_some() {}
        self.app.poll(&mut self.io, now);
        self.io.stack.take_tx_wakeup();
    }
}

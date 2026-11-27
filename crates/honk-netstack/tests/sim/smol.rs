//! smoltcp 0.14.0 reference host. A one-packet egress device makes each `poll_transmit` materialize
//! at most one packet; ingress-generated responses are retained until the caller pulls them.

use super::app::{Driver, Plan, Role, StreamError, StreamIo};
use super::engine::{Host, epoch};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn address(self, role: Role) -> IpAddress {
        let last = match role {
            Role::Client => 1,
            Role::Server => 2,
        };
        match self {
            Family::V4 => Ipv4Address::new(10, 0, 0, last).into(),
            Family::V6 => Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(last)).into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SmolConfig {
    pub family: Family,
    pub mtu: usize,
    pub rx_bytes: usize,
    pub tx_bytes: usize,
    pub ack_delay: Option<Duration>,
}

impl SmolConfig {
    pub fn buffers(bytes: usize) -> Self {
        SmolConfig {
            family: Family::V4,
            mtu: 1420,
            rx_bytes: bytes,
            tx_bytes: bytes,
            ack_delay: Some(Duration::from_millis(10)),
        }
    }
}

struct IpDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct InToken(Vec<u8>);
struct OutToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for InToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl TxToken for OutToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut data = vec![0; len];
        let r = f(&mut data);
        self.0.push_back(data);
        r
    }
}

impl Device for IpDevice {
    type RxToken<'a> = InToken;
    type TxToken<'a> = OutToken<'a>;

    fn receive(&mut self, _now: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let data = self.rx.pop_front()?;
        Some((InToken(data), OutToken(&mut self.tx)))
    }

    fn transmit(&mut self, _now: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx.is_empty() {
            Some(OutToken(&mut self.tx))
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

pub struct SmolTcp {
    iface: Interface,
    device: IpDevice,
    sockets: SocketSet<'static>,
    ids: Vec<SocketHandle>,
    timeout: Option<Instant>,
}

impl SmolTcp {
    fn new(cfg: &SmolConfig, role: Role, flows: usize) -> Self {
        let mut device = IpDevice {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu: cfg.mtu,
        };
        let mut iface_cfg = InterfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = match role {
            Role::Client => 1,
            Role::Server => 2,
        };
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            let prefix = match cfg.family {
                Family::V4 => 24,
                Family::V6 => 64,
            };
            addrs
                .push(IpCidr::new(cfg.family.address(role), prefix))
                .unwrap();
        });
        let mut sockets = SocketSet::new(vec![]);
        let mut ids = Vec::with_capacity(flows);
        for i in 0..flows {
            let mut sock = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; cfg.rx_bytes]),
                tcp::SocketBuffer::new(vec![0; cfg.tx_bytes]),
            );
            sock.set_congestion_control(tcp::CongestionControl::Cubic);
            sock.set_ack_delay(
                cfg.ack_delay
                    .map(|d| SmolDuration::from_micros(d.as_micros() as u64)),
            );
            sock.set_nagle_enabled(false);
            // One listener per flow keeps payload identity tied to a destination port even if
            // connect completion order changes under loss. It is not a listen-backlog benchmark.
            let port = 8000 + u16::try_from(i).unwrap();
            match role {
                Role::Server => sock.listen((cfg.family.address(role), port)).unwrap(),
                Role::Client => sock
                    .connect(
                        iface.context(),
                        (cfg.family.address(Role::Server), port),
                        (cfg.family.address(role), 16000 + u16::try_from(i).unwrap()),
                    )
                    .unwrap(),
            }
            ids.push(sockets.add(sock));
        }
        let mut s = SmolTcp {
            iface,
            device,
            sockets,
            ids,
            timeout: None,
        };
        s.refresh_timeout(epoch());
        s
    }

    fn time(now: Instant) -> SmolInstant {
        SmolInstant::from_micros((now - epoch()).as_micros() as i64)
    }

    fn refresh_timeout(&mut self, now: Instant) {
        self.timeout = if !self.device.tx.is_empty() {
            Some(now)
        } else {
            self.iface
                .poll_at(Self::time(now), &self.sockets)
                .map(|t| epoch() + Duration::from_micros(t.total_micros().max(0) as u64))
        };
    }

    fn socket(&self, id: usize) -> &tcp::Socket<'static> {
        self.sockets.get(self.ids[id])
    }

    fn socket_mut(&mut self, id: usize) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut(self.ids[id])
    }
}

impl StreamIo for SmolTcp {
    type Id = usize;

    fn connected(&self, id: usize) -> bool {
        !matches!(
            self.socket(id).state(),
            tcp::State::Closed | tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
        )
    }

    fn write(&mut self, id: usize, data: &[u8]) -> Result<usize, StreamError> {
        let s = self.socket_mut(id);
        if data.is_empty() {
            return Ok(0);
        }
        match s.send_slice(data) {
            Ok(0) => Err(StreamError::WouldBlock),
            Ok(n) => Ok(n),
            Err(tcp::SendError::InvalidState) => Err(StreamError::Closed),
        }
    }

    fn read(&mut self, id: usize, out: &mut [u8]) -> Result<usize, StreamError> {
        let s = self.socket_mut(id);
        match s.recv_slice(out) {
            Ok(0) => Err(StreamError::WouldBlock),
            Ok(n) => Ok(n),
            Err(tcp::RecvError::Finished) => Ok(0),
            Err(tcp::RecvError::InvalidState) => Err(StreamError::Reset),
        }
    }

    fn shutdown(&mut self, id: usize) -> Result<(), StreamError> {
        self.socket_mut(id).close();
        Ok(())
    }
}

pub struct SmolHost {
    pub io: SmolTcp,
    pub app: Driver<usize>,
}

impl SmolHost {
    pub fn new(cfg: &SmolConfig, plan: Plan, role: Role) -> Self {
        let io = SmolTcp::new(cfg, role, plan.flows);
        let app = Driver::new(plan, role, 0..io.ids.len(), epoch());
        SmolHost { io, app }
    }
}

impl Host for SmolHost {
    fn receive(&mut self, now: Instant, packet: &[u8]) {
        self.io.device.rx.push_back(packet.to_vec());
        self.io.iface.poll_ingress_single(
            Self::smol_time(now),
            &mut self.io.device,
            &mut self.io.sockets,
        );
        self.io.refresh_timeout(now);
    }

    fn poll_transmit(&mut self, now: Instant, out: &mut [u8]) -> Option<usize> {
        if self.io.device.tx.is_empty() {
            self.io.iface.poll_egress(
                Self::smol_time(now),
                &mut self.io.device,
                &mut self.io.sockets,
            );
        }
        let len = self.io.device.tx.front().map(Vec::len);
        let n = len.filter(|&n| n <= out.len());
        if let Some(n) = n {
            out[..n].copy_from_slice(&self.io.device.tx.pop_front().unwrap());
        }
        self.io.refresh_timeout(now);
        n
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.io.timeout
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.io.iface.poll_maintenance(Self::smol_time(now));
        self.io.refresh_timeout(now);
    }

    fn poll_app(&mut self, now: Instant) {
        self.app.poll(&mut self.io, now);
        self.io.refresh_timeout(now);
    }
}

impl SmolHost {
    fn smol_time(now: Instant) -> SmolInstant {
        SmolTcp::time(now)
    }
}

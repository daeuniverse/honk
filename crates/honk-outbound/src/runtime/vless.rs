use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use honk_config::node::{VlessConfig, VlessMultiplex, VlessTcpPath, VlessUdpMux, VlessUdpPath};

use super::WarmRetention;
use crate::proxy::WarmRequirement;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PoolKind {
    H2,
    SharedCool,
    SeparateCool,
}

#[derive(Debug)]
pub struct VlessRuntime {
    h2: Option<Arc<crate::proxy::vless_mux::VlessMuxPool>>,
    shared_cool: Option<Arc<crate::proxy::vless_cool::VlessCoolPool>>,
    separate_cool: Option<Arc<crate::proxy::vless_cool::VlessCoolPool>>,
    tcp_warm: Option<PoolKind>,
    udp_warm: Option<PoolKind>,
    source_key: OnceLock<[u8; 32]>,
}

impl VlessRuntime {
    pub(super) fn new(config: &VlessConfig) -> Self {
        let (h2, shared_cool, separate_cool) = match &config.multiplex {
            VlessMultiplex::Off => (None, None, None),
            VlessMultiplex::H2 { .. } => (
                Some(Arc::new(crate::session::SessionPool::new(
                    crate::proxy::vless_mux::session_pool_config(),
                ))),
                None,
                None,
            ),
            VlessMultiplex::Xray { tcp, udp, .. } => (
                None,
                tcp.map(|limit| {
                    Arc::new(crate::session::SessionPool::new(
                        crate::proxy::vless_cool::session_pool_config(limit.get() as usize),
                    ))
                }),
                match udp {
                    VlessUdpMux::Separate(limit) => {
                        Some(Arc::new(crate::session::SessionPool::new(
                            crate::proxy::vless_cool::session_pool_config(limit.get() as usize),
                        )))
                    }
                    VlessUdpMux::Protocol | VlessUdpMux::SharedTcp => None,
                },
            ),
        };
        let tcp_warm = match config.tcp_path() {
            VlessTcpPath::Direct => None,
            VlessTcpPath::H2 => Some(PoolKind::H2),
            VlessTcpPath::Cool => Some(PoolKind::SharedCool),
        };
        let udp_warm = match config.udp_path(0) {
            Some(VlessUdpPath::H2) => Some(PoolKind::H2),
            Some(VlessUdpPath::CoolShared) => Some(PoolKind::SharedCool),
            Some(VlessUdpPath::CoolSeparate) => Some(PoolKind::SeparateCool),
            Some(VlessUdpPath::Native | VlessUdpPath::Xudp | VlessUdpPath::UotV2) | None => None,
        };
        Self {
            h2,
            shared_cool,
            separate_cool,
            tcp_warm,
            udp_warm,
            source_key: OnceLock::new(),
        }
    }

    pub(crate) fn h2_pool(&self) -> anyhow::Result<Arc<crate::proxy::vless_mux::VlessMuxPool>> {
        self.h2
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| anyhow::anyhow!("VLESS H2 path has no runtime pool"))
    }

    pub(crate) fn shared_cool_pool(
        &self,
    ) -> anyhow::Result<Arc<crate::proxy::vless_cool::VlessCoolPool>> {
        self.shared_cool
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| anyhow::anyhow!("VLESS shared Cool path has no runtime pool"))
    }

    pub(crate) fn separate_cool_pool(
        &self,
    ) -> anyhow::Result<Arc<crate::proxy::vless_cool::VlessCoolPool>> {
        self.separate_cool
            .as_ref()
            .map(Arc::clone)
            .ok_or_else(|| anyhow::anyhow!("VLESS separate Cool path has no runtime pool"))
    }

    pub(super) fn sync_warm_retention(&self, retention: u8) {
        let retained = |kind| {
            (retention & WarmRetention::Selector.bit() != 0 && self.tcp_warm == Some(kind))
                || (retention & WarmRetention::Udp.bit() != 0 && self.udp_warm == Some(kind))
        };
        if let Some(pool) = &self.h2 {
            pool.set_warm_retained(retained(PoolKind::H2));
        }
        if let Some(pool) = &self.shared_cool {
            pool.set_warm_retained(retained(PoolKind::SharedCool));
        }
        if let Some(pool) = &self.separate_cool {
            pool.set_warm_retained(retained(PoolKind::SeparateCool));
        }
    }

    pub(super) fn shutdown(&self) {
        if let Some(pool) = &self.h2 {
            pool.shutdown();
        }
        if let Some(pool) = &self.shared_cool {
            pool.shutdown();
        }
        if let Some(pool) = &self.separate_cool {
            pool.shutdown();
        }
    }

    pub(super) fn retire(&self) {
        if let Some(pool) = &self.h2 {
            pool.retire();
        }
        if let Some(pool) = &self.shared_cool {
            pool.retire();
        }
        if let Some(pool) = &self.separate_cool {
            pool.retire();
        }
    }

    pub(super) fn is_warm_or_stateless_for(&self, requirement: WarmRequirement) -> bool {
        match requirement {
            WarmRequirement::Session => self.tcp_warm,
            WarmRequirement::Udp => self.udp_warm,
        }
        .is_none_or(|kind| self.pool_has_usable_session(kind))
    }

    pub(super) fn reap_unretained_idle(&self) -> usize {
        self.h2
            .iter()
            .map(|pool| pool.reap_unretained_idle())
            .chain(
                self.shared_cool
                    .iter()
                    .map(|pool| pool.reap_unretained_idle()),
            )
            .chain(
                self.separate_cool
                    .iter()
                    .map(|pool| pool.reap_unretained_idle()),
            )
            .sum()
    }

    fn pool_has_usable_session(&self, kind: PoolKind) -> bool {
        match kind {
            PoolKind::H2 => self
                .h2
                .as_ref()
                .is_some_and(|pool| pool.has_usable_session()),
            PoolKind::SharedCool => self
                .shared_cool
                .as_ref()
                .is_some_and(|pool| pool.has_usable_session()),
            PoolKind::SeparateCool => self
                .separate_cool
                .as_ref()
                .is_some_and(|pool| pool.has_usable_session()),
        }
    }

    pub(super) fn live_session_count(&self) -> usize {
        self.h2
            .iter()
            .map(|pool| pool.live_session_count())
            .chain(
                self.shared_cool
                    .iter()
                    .map(|pool| pool.live_session_count()),
            )
            .chain(
                self.separate_cool
                    .iter()
                    .map(|pool| pool.live_session_count()),
            )
            .sum()
    }

    #[cfg(test)]
    pub(super) fn pool_is_warm_retained(&self, kind: VlessUdpPath) -> bool {
        match kind {
            VlessUdpPath::H2 => self.h2.as_ref().is_some_and(|pool| pool.is_warm_retained()),
            VlessUdpPath::CoolShared => self
                .shared_cool
                .as_ref()
                .is_some_and(|pool| pool.is_warm_retained()),
            VlessUdpPath::CoolSeparate => self
                .separate_cool
                .as_ref()
                .is_some_and(|pool| pool.is_warm_retained()),
            VlessUdpPath::Native | VlessUdpPath::Xudp | VlessUdpPath::UotV2 => false,
        }
    }

    pub(super) fn source_id(
        &self,
        client: SocketAddr,
        path: VlessUdpPath,
        reply_destination: Option<SocketAddr>,
    ) -> [u8; 8] {
        let key = self.source_key.get_or_init(rand::random);
        let mut hash = blake3::Hasher::new_keyed(key);
        hash.update(b"honk-vless-xudp-source-v1");
        hash_socket(&mut hash, normalize_socket(client));
        hash.update(&[match path {
            VlessUdpPath::Native => 1,
            VlessUdpPath::Xudp => 2,
            VlessUdpPath::UotV2 => 3,
            VlessUdpPath::H2 => 4,
            VlessUdpPath::CoolShared => 5,
            VlessUdpPath::CoolSeparate => 6,
        }]);
        match reply_destination {
            None => {
                hash.update(&[0]);
            }
            Some(destination) => {
                hash.update(&[1]);
                hash_socket(&mut hash, normalize_socket(destination));
            }
        };
        let mut id = [0; 8];
        id.copy_from_slice(&hash.finalize().as_bytes()[..8]);
        if id == [0; 8] {
            id[7] = 1;
        }
        id
    }
}

fn normalize_socket(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(address) => address
            .ip()
            .to_ipv4_mapped()
            .map_or(SocketAddr::V6(address), |ip| {
                SocketAddr::new(IpAddr::V4(ip), address.port())
            }),
        address => address,
    }
}

fn hash_socket(hash: &mut blake3::Hasher, address: SocketAddr) {
    match address.ip() {
        IpAddr::V4(ip) => {
            hash.update(&[4]);
            hash.update(&ip.octets());
        }
        IpAddr::V6(ip) => {
            hash.update(&[6]);
            hash.update(&ip.octets());
        }
    }
    hash.update(&address.port().to_be_bytes());
}

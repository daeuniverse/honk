use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(in crate::control) enum SourcePath {
    #[cfg(feature = "rprx")]
    Vless(VlessUdpPath),
    Hysteria2,
    Tuic,
    /// Protocols whose registry entry has a shared-source slot.
    Shared,
}

pub(in crate::control) enum PreparedSourceTransport {
    #[cfg(feature = "rprx")]
    Vless(PreparedUdpTransport<VlessXudpTransport>),
    Hysteria2(PreparedUdpTransport<Hy2UdpTransport>),
    Tuic(PreparedUdpTransport<TuicUdpTransport>),
    Shared(PreparedUdpTransport<dyn MultiTargetTransport>),
}

impl PreparedSourceTransport {
    pub(super) async fn commit(self) -> anyhow::Result<SourceTransport> {
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(prepared) => prepared.commit().await.map(SourceTransport::Vless),
            Self::Hysteria2(prepared) => prepared.commit().await.map(SourceTransport::Hysteria2),
            Self::Tuic(prepared) => prepared.commit().await.map(SourceTransport::Tuic),
            Self::Shared(prepared) => prepared.commit().await.map(SourceTransport::Shared),
        }
    }
}

pub(super) enum SourceTransport {
    #[cfg(feature = "rprx")]
    Vless(Arc<VlessXudpTransport>),
    Hysteria2(Arc<Hy2UdpTransport>),
    Tuic(Arc<TuicUdpTransport>),
    Shared(Arc<dyn MultiTargetTransport>),
}

impl SourceTransport {
    pub(super) fn packet_transport(&self) -> &dyn PacketTransport {
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(transport) => transport.as_ref(),
            Self::Hysteria2(transport) => transport.as_ref(),
            Self::Tuic(transport) => transport.as_ref(),
            Self::Shared(transport) => transport.as_ref(),
        }
    }

    pub(super) fn observe_reuse(&self) {
        use honk_outbound::runtime::flow_observation::{self, FlowEvent, ResolutionLocation};

        let Some(observer) = flow_observation::current() else {
            return;
        };
        let server_addr = match self {
            #[cfg(feature = "rprx")]
            Self::Vless(_) => return,
            Self::Hysteria2(transport) => Some(transport.server_addr()),
            Self::Tuic(transport) => Some(transport.server_addr()),
            Self::Shared(transport) => transport.carrier_addr(),
        };
        observer.publish(FlowEvent::TransportAttached {
            server_addr,
            resolution_location: ResolutionLocation::Reused,
        });
    }

    /// VLESS refuses an empty datagram before anything was sent; Hy2, TUIC and
    /// the shared carriers send zero-length datagrams.
    pub(super) fn rejects_empty_first_datagram(&self) -> bool {
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(_) => true,
            Self::Hysteria2(_) | Self::Tuic(_) | Self::Shared(_) => false,
        }
    }

    /// Whether `error` echoes a frame write that one of this source's views
    /// cancelled, rather than reporting a fault of the carrier.
    pub(super) fn is_interruption(&self, error: &io::Error) -> bool {
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(_) => {
                honk_outbound::proxy::vless::is_vless_source_post_admission_cancel(error)
            }
            Self::Hysteria2(_) | Self::Tuic(_) => false,
            Self::Shared(_) => honk_outbound::proxy::is_frame_interrupted(error),
        }
    }

    pub(super) async fn send_to(
        &self,
        target: SocketAddr,
        target_domain: Option<&str>,
        data: &[u8],
        confirmed: bool,
        admitted: Option<&AtomicBool>,
        current: Option<&(dyn Fn() -> bool + Send + Sync)>,
    ) -> io::Result<()> {
        if let Some(current) = current {
            return match self {
                #[cfg(feature = "rprx")]
                Self::Vless(transport) => {
                    transport
                        .send_to_checked(target, target_domain, data, admitted, current)
                        .await
                }
                Self::Shared(transport) => {
                    transport
                        .send_to_checked(target, target_domain, data, admitted, current)
                        .await
                }
                Self::Hysteria2(_) | Self::Tuic(_) => {
                    Err(honk_outbound::proxy::PacketRejection::Policy.into())
                }
            };
        }
        match self {
            #[cfg(feature = "rprx")]
            Self::Vless(transport) => {
                transport
                    .send_to(target, target_domain, data, admitted)
                    .await
            }
            Self::Hysteria2(transport) => {
                transport
                    .send_to(target, target_domain, data, admitted)
                    .await
            }
            Self::Tuic(transport) => {
                transport
                    .send_to(target, target_domain, data, admitted)
                    .await
            }
            Self::Shared(transport) => {
                transport
                    .send_to(target, target_domain, data, confirmed, admitted)
                    .await
            }
        }
    }
}

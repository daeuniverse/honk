use super::DnsController;
use crate::dns::projection::QueryScope;
use crate::dns::query::{DnsRequestMeta, IngressProfile, ValidatedDnsQuery, is_exact_dns_query};
use crate::dns::response::build_dns_refused;
use crate::dns::transport::{read_length_prefixed_into, write_length_prefixed};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

pub(super) const TCP_DNS_IO_TIMEOUT: Duration = Duration::from_secs(30);

pub(in crate::control) enum DnsUdpReply<'a> {
    Kernel,
    Packet(&'a crate::control::netstack::DatagramSender),
}

#[derive(Debug, thiserror::Error)]
#[error("packet DNS scope retired")]
pub(in crate::control) struct PacketDnsScopeRetired;

impl DnsController {
    fn retired_dns_delivery(&self, scope: QueryScope) -> bool {
        if self.routing_projection.query_scope_is_current(scope) {
            return false;
        }
        crate::observe::flows::dns::delivery("cancelled", Some("intentional_retirement"));
        true
    }

    pub(in crate::control) async fn handle_udp_dns_admitted(
        &self,
        admission: &super::AdmittedDnsQuery,
        data: &[u8],
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        validated: ValidatedDnsQuery,
        reply: DnsUdpReply<'_>,
    ) {
        let operation = self.handle_udp_dns_admitted_inner(
            admission,
            data,
            client_addr,
            original_dst,
            validated,
            reply,
        );
        crate::observe::scope_pin!(operation);
        let operation = crate::observe::flows::dns::client_scope(
            data,
            validated.ingress(),
            DnsRequestMeta::new(Some(client_addr.ip()), Some(original_dst)),
            operation,
        );
        operation.await;
    }

    async fn handle_udp_dns_admitted_inner(
        &self,
        admission: &super::AdmittedDnsQuery,
        data: &[u8],
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        validated: ValidatedDnsQuery,
        reply: DnsUdpReply<'_>,
    ) {
        #[cfg(feature = "native-api")]
        let started = std::time::Instant::now();
        debug!(%client_addr, "DNS controller (UDP): forwarding query");
        let response = self
            .answer_query(
                admission,
                data,
                DnsRequestMeta::new(Some(client_addr.ip()), Some(original_dst)),
                validated.ingress(),
            )
            .await;
        let delivery = admission
            .run_reply(async {
                match reply {
                    DnsUdpReply::Kernel => {
                        super::super::send_udp_reply_from_orig_dst(
                            response.wire(),
                            client_addr,
                            original_dst,
                        )
                        .await
                    }
                    DnsUdpReply::Packet(sender) => {
                        sender.send_to(response.wire(), client_addr).await
                    }
                }
            })
            .await;
        if matches!(delivery, Ok(Err(_))) && self.retired_dns_delivery(admission.projection_scope) {
            return;
        }
        crate::observe::flows::dns::reply_delivery(
            &delivery,
            |length| *length == response.wire().len(),
            "client_send_failed",
        );
        #[cfg(feature = "native-api")]
        self.dns_service.observer.observe_client(
            data,
            validated.ingress(),
            Some(client_addr),
            response.outcome(),
            response.wire(),
            started.elapsed(),
        );
    }

    /// Handle a transparent DNS-over-TCP stream after traffic-policy admission.
    pub async fn handle_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }
        stream.set_nodelay(true)?;
        self.serve_tcp_frames(stream, client_addr, Some(original_dst), QueryScope::HOST)
            .await
    }

    pub(in crate::control) async fn handle_packet_tcp_dns(
        &self,
        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        scope: honk_datapath::ScopeId,
    ) -> anyhow::Result<bool> {
        let scope = self
            .routing_projection
            .packet_query_scope(scope)
            .ok_or_else(|| {
                if self.routing_projection.owns_packet_scope(scope) {
                    PacketDnsScopeRetired.into()
                } else {
                    anyhow::anyhow!("packet DNS scope is unavailable")
                }
            })?;
        self.serve_tcp_frames(stream, client_addr, Some(original_dst), scope)
            .await
    }

    /// Serve a standalone DNS-over-TCP connection in the host namespace.
    pub(crate) async fn serve_bound_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        fact_scope: QueryScope,
    ) -> anyhow::Result<()> {
        stream.set_nodelay(true)?;
        if let Err(error) = self
            .serve_tcp_frames(stream, client_addr, None, fact_scope)
            .await
            && !error.is::<PacketDnsScopeRetired>()
        {
            return Err(error);
        }
        Ok(())
    }

    /// Sequential RFC 7766 request loop shared by transparent and bound TCP.
    /// Port 53 belongs to DNS once intercepted; malformed, idle, or partial
    /// frames close the connection rather than falling through after consuming bytes.
    async fn serve_tcp_frames(
        &self,
        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        client_addr: SocketAddr,
        original_dst: Option<SocketAddr>,
        scope: QueryScope,
    ) -> anyhow::Result<bool> {
        let metadata = DnsRequestMeta::new(Some(client_addr.ip()), original_dst);
        let mut query = Vec::new();
        let mut served = false;
        loop {
            if !self.routing_projection.query_scope_is_current(scope) {
                return Err(PacketDnsScopeRetired.into());
            }
            if !read_tcp_dns_query(stream, &mut query, Some(TCP_DNS_IO_TIMEOUT)).await {
                if !self.routing_projection.query_scope_is_current(scope) {
                    return Err(PacketDnsScopeRetired.into());
                }
                return Ok(served || original_dst.is_some());
            }
            if !served {
                debug!(%client_addr, "DNS controller (TCP): forwarding query");
            }
            self.process_tcp_query(stream, &query, client_addr, metadata, scope)
                .await?;
            served = true;
        }
    }

    async fn process_tcp_query(
        &self,
        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        query: &[u8],
        client_addr: SocketAddr,
        metadata: DnsRequestMeta,
        scope: QueryScope,
    ) -> anyhow::Result<()> {
        let operation = self.process_tcp_query_inner(stream, query, client_addr, metadata, scope);
        crate::observe::scope_pin!(operation);
        let operation = crate::observe::flows::dns::client_scope(
            query,
            IngressProfile::Tcp,
            metadata,
            operation,
        );
        operation.await
    }

    async fn process_tcp_query_inner(
        &self,
        stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
        query: &[u8],
        client_addr: SocketAddr,
        metadata: DnsRequestMeta,
        scope: QueryScope,
    ) -> anyhow::Result<()> {
        #[cfg(feature = "native-api")]
        let started = std::time::Instant::now();
        #[cfg(not(feature = "native-api"))]
        let _ = client_addr;
        // Each persistent frame gets the current generation independently.
        let admission = match self.try_admit_bound_query(false, Some(scope)) {
            Ok(admission) => admission,
            Err(_) => {
                if self.retired_dns_delivery(scope) {
                    return Err(PacketDnsScopeRetired.into());
                }
                crate::observe::flows::dns::decision("rejected", Some("admission_refused"));
                let response = build_dns_refused(query);
                let result = write_tcp_dns_response(stream, &response, TCP_DNS_IO_TIMEOUT).await;
                if result.is_err() && self.retired_dns_delivery(scope) {
                    return Err(PacketDnsScopeRetired.into());
                }
                crate::observe::flows::dns::delivery(
                    if result.is_ok() {
                        "delivered"
                    } else {
                        "delivery_failed"
                    },
                    if result.is_ok() {
                        None
                    } else {
                        Some("client_write_failed")
                    },
                );
                #[cfg(feature = "native-api")]
                self.dns_service.observer.observe_client(
                    query,
                    IngressProfile::Tcp,
                    Some(client_addr),
                    None,
                    &response,
                    started.elapsed(),
                );
                return result;
            }
        };
        let response = self
            .answer_query(&admission, query, metadata, IngressProfile::Tcp)
            .await;
        if self.retired_dns_delivery(scope) {
            return Err(PacketDnsScopeRetired.into());
        }
        let result = admission
            .run_reply(write_tcp_dns_response(
                stream,
                response.wire(),
                TCP_DNS_IO_TIMEOUT,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("DNS runtime retired during TCP response write"));
        if !matches!(result, Ok(Ok(()))) && self.retired_dns_delivery(scope) {
            return Err(PacketDnsScopeRetired.into());
        }
        crate::observe::flows::dns::reply_delivery(&result, |_| true, "client_write_failed");
        #[cfg(feature = "native-api")]
        self.dns_service.observer.observe_client(
            query,
            IngressProfile::Tcp,
            Some(client_addr),
            response.outcome(),
            response.wire(),
            started.elapsed(),
        );
        result?
    }
}

async fn write_tcp_dns_response(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    response: &[u8],
    timeout: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, write_length_prefixed(stream, response))
        .await
        .map_err(|_| anyhow::anyhow!("DNS TCP response write timed out"))?
}

async fn read_tcp_dns_query(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    query: &mut Vec<u8>,
    read_timeout: Option<Duration>,
) -> bool {
    read_length_prefixed_into(stream, query, read_timeout)
        .await
        .is_ok()
        && is_exact_dns_query(query)
}

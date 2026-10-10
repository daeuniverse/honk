use super::DnsController;
use crate::dns::query::{DnsRequestMeta, IngressProfile, ValidatedDnsQuery, is_exact_dns_query};
use crate::dns::response::build_dns_refused;
use crate::dns::transport::{read_length_prefixed_into, write_length_prefixed};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::debug;

pub(super) const TCP_DNS_IO_TIMEOUT: Duration = Duration::from_secs(30);

impl DnsController {
    pub(crate) async fn handle_udp_dns_admitted(
        &self,
        admission: &super::AdmittedDnsQuery,
        data: &[u8],
        client_addr: SocketAddr,
        original_dst: SocketAddr,
        validated: ValidatedDnsQuery,
    ) {
        let operation = self.handle_udp_dns_admitted_inner(
            admission,
            data,
            client_addr,
            original_dst,
            validated,
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
            .run_reply(super::super::send_udp_reply_from_orig_dst(
                response.wire(),
                client_addr,
                original_dst,
            ))
            .await;
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

    /// Handle a TCP DNS-over-TCP connection from TPROXY.
    pub async fn handle_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        original_dst: SocketAddr,
    ) -> anyhow::Result<bool> {
        if original_dst.port() != 53 {
            return Ok(false);
        }
        self.serve_tcp_frames(stream, client_addr, Some(original_dst))
            .await
    }

    /// Serve a standalone DNS-over-TCP connection in the host namespace.
    pub(crate) async fn serve_bound_tcp_dns(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let _ = self.serve_tcp_frames(stream, client_addr, None).await?;
        Ok(())
    }

    /// Sequential RFC 7766 request loop shared by transparent and bound TCP.
    /// Port 53 belongs to DNS once intercepted; malformed, idle, or partial
    /// frames close the connection rather than falling through after consuming bytes.
    async fn serve_tcp_frames(
        &self,
        stream: &mut TcpStream,
        client_addr: SocketAddr,
        original_dst: Option<SocketAddr>,
    ) -> anyhow::Result<bool> {
        stream.set_nodelay(true)?;
        let metadata = DnsRequestMeta::new(Some(client_addr.ip()), original_dst);
        let mut query = Vec::new();
        if !read_tcp_dns_query(stream, &mut query, Some(TCP_DNS_IO_TIMEOUT)).await {
            return Ok(original_dst.is_some());
        }

        debug!(%client_addr, "DNS controller (TCP): forwarding query");
        self.process_tcp_query(stream, &query, client_addr, metadata)
            .await?;

        loop {
            if !read_tcp_dns_query(stream, &mut query, Some(TCP_DNS_IO_TIMEOUT)).await {
                return Ok(true);
            }
            self.process_tcp_query(stream, &query, client_addr, metadata)
                .await?;
        }
    }

    async fn process_tcp_query(
        &self,
        stream: &mut TcpStream,
        query: &[u8],
        client_addr: SocketAddr,
        metadata: DnsRequestMeta,
    ) -> anyhow::Result<()> {
        let operation = self.process_tcp_query_inner(stream, query, client_addr, metadata);
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
        stream: &mut TcpStream,
        query: &[u8],
        client_addr: SocketAddr,
        metadata: DnsRequestMeta,
    ) -> anyhow::Result<()> {
        #[cfg(feature = "native-api")]
        let started = std::time::Instant::now();
        #[cfg(not(feature = "native-api"))]
        let _ = client_addr;
        // Each persistent frame gets the current generation independently.
        let admission = match self.try_admit_query(false) {
            Ok(admission) => admission,
            Err(_) => {
                crate::observe::flows::dns::decision("rejected", Some("admission_refused"));
                let response = build_dns_refused(query);
                let result = write_tcp_dns_response(stream, &response, TCP_DNS_IO_TIMEOUT).await;
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
        let result = admission
            .run_reply(write_tcp_dns_response(
                stream,
                response.wire(),
                TCP_DNS_IO_TIMEOUT,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("DNS runtime retired during TCP response write"));
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
        result??;
        Ok(())
    }
}

async fn write_tcp_dns_response(
    stream: &mut TcpStream,
    response: &[u8],
    timeout: Duration,
) -> anyhow::Result<()> {
    tokio::time::timeout(timeout, write_length_prefixed(stream, response))
        .await
        .map_err(|_| anyhow::anyhow!("DNS TCP response write timed out"))?
}

async fn read_tcp_dns_query(
    stream: &mut TcpStream,
    query: &mut Vec<u8>,
    read_timeout: Option<Duration>,
) -> bool {
    read_length_prefixed_into(stream, query, read_timeout)
        .await
        .is_ok()
        && is_exact_dns_query(query)
}

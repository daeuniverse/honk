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
        debug!(%client_addr, "DNS controller (UDP): forwarding query");
        let response = self
            .answer_query(
                admission,
                data,
                DnsRequestMeta::new(Some(client_addr.ip()), Some(original_dst)),
                validated.ingress(),
            )
            .await;
        let _ = admission
            .run_reply(super::super::send_udp_reply_from_orig_dst(
                &response,
                client_addr,
                original_dst,
            ))
            .await;
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
        self.process_tcp_query(stream, &query, metadata).await?;

        loop {
            if !read_tcp_dns_query(stream, &mut query, Some(TCP_DNS_IO_TIMEOUT)).await {
                return Ok(true);
            }
            self.process_tcp_query(stream, &query, metadata).await?;
        }
    }

    async fn process_tcp_query(
        &self,
        stream: &mut TcpStream,
        query: &[u8],
        metadata: DnsRequestMeta,
    ) -> anyhow::Result<()> {
        // Each persistent frame gets the current generation independently.
        let admission = match self.try_admit_query(false) {
            Ok(admission) => admission,
            Err(_) => {
                return write_tcp_dns_response(
                    stream,
                    &build_dns_refused(query),
                    TCP_DNS_IO_TIMEOUT,
                )
                .await;
            }
        };
        let response = self
            .answer_query(&admission, query, metadata, IngressProfile::Tcp)
            .await;
        admission
            .run_reply(write_tcp_dns_response(
                stream,
                &response,
                TCP_DNS_IO_TIMEOUT,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("DNS runtime retired during TCP response write"))??;
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

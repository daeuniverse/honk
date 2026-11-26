//! Zero-sized audit hooks for builds without `dns-syslog`.

use std::net::SocketAddr;

use crate::dns::{outcome::DnsOutcome, query::IngressProfile};

#[derive(Clone, Copy, Default)]
pub(crate) struct DnsAudit;

pub(crate) enum DnsAuditQuery {}
pub(crate) enum DnsAuditWorker {}

pub(crate) fn validate_config(global: &honk_config::config::GlobalConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        !global.syslog_dns_enabled,
        "DNS syslog requires the dns-syslog Cargo feature"
    );
    Ok(())
}

impl DnsAudit {
    #[inline]
    pub(crate) fn begin_udp(&self, _query: &[u8], _source: SocketAddr) -> Option<DnsAuditQuery> {
        None
    }

    #[inline]
    pub(crate) fn begin(
        &self,
        _query: &[u8],
        _ingress: IngressProfile,
        _source: SocketAddr,
    ) -> Option<DnsAuditQuery> {
        None
    }
}

impl DnsAuditQuery {
    #[inline]
    pub(crate) fn discard(self) {
        match self {}
    }

    #[inline]
    pub(crate) fn finish(self, _response: &[u8], _outcome: Option<&DnsOutcome>) {
        match self {}
    }
}

impl DnsAuditWorker {
    pub(crate) fn start(
        global: &honk_config::config::GlobalConfig,
    ) -> anyhow::Result<(DnsAudit, Option<Self>)> {
        validate_config(global)?;
        Ok((DnsAudit, None))
    }

    #[inline]
    pub(crate) async fn shutdown(&mut self) {
        match *self {}
    }
}

use honk_config::node::Node;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

use super::stream::start;
use super::{CMD_TCP, VLessHandler};
use crate::proxy::{AsyncReadWrite, ProxyStream};

impl VLessHandler {
    /// Build the connected stream for a dial. Encrypted Vision keeps the
    /// concrete `EncryptedStream` through response and Vision wrapping so
    /// Direct bypasses only AEAD while its boxed outer transport stays intact.
    /// Unencrypted raw TCP/TLS keeps its concrete type for the existing raw switch.
    async fn dial_carrier(
        &self,
        node: &Node,
        uuid: [u8; 16],
        header: Vec<u8>,
        tcp: Option<TcpStream>,
        connect_timeout: std::time::Duration,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let vless = node.vless().unwrap();
        let vision = vless.is_vision().then_some(uuid);
        let encryption = self.encryption_config(node)?;
        if node.is_xhttp() {
            let stream =
                crate::proxy::transport::wrap_transport(node, tcp, connect_timeout).await?;
            return if let Some(config) = encryption {
                Ok(start(config.connect(stream).await?, &header, vision).await?)
            } else {
                Ok(start(stream, &header, vision).await?)
            };
        }
        if encryption.is_none()
            && vision.is_some()
            && matches!(vless.transport.transport.as_str(), "" | "tcp")
        {
            let stream: Box<dyn AsyncReadWrite> =
                match crate::proxy::transport::maybe_tls_wrap_concrete(node, tcp, connect_timeout)
                    .await?
                {
                    crate::proxy::transport::MaybeTls::Tls(tls) => {
                        if tls.ssl().version2() != Some(boring::ssl::SslVersion::TLS1_3) {
                            anyhow::bail!("VLESS Vision requires negotiated TLS 1.3");
                        }
                        start(tls, &header, vision).await?
                    }
                    crate::proxy::transport::MaybeTls::Plain(_) => {
                        anyhow::bail!("unencrypted VLESS Vision requires TLS or REALITY");
                    }
                };
            return Ok(match permit {
                Some(permit) => Box::new(crate::proxy::RuntimeOwnedIo {
                    inner: stream,
                    _owner: permit,
                }),
                None => stream,
            });
        }

        let stream = crate::proxy::transport::maybe_tls_wrap(node, tcp, connect_timeout).await?;
        let stream: Box<dyn AsyncReadWrite> = match permit {
            Some(permit) => Box::new(crate::proxy::RuntimeOwnedIo {
                inner: stream,
                _owner: permit,
            }),
            None => stream,
        };
        let stream = crate::proxy::transport::wrap_after_tls(node, stream).await?;
        if let Some(config) = encryption {
            return Ok(start(config.connect(stream).await?, &header, vision).await?);
        }
        Ok(start(stream, &header, vision).await?)
    }

    pub(super) async fn dial_base(
        &self,
        node: &Node,
        target: SocketAddr,
        target_domain: Option<&str>,
        tcp: Option<TcpStream>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let vless = node.vless().unwrap();
        let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let header = Self::build_request_header(
            &uuid,
            CMD_TCP,
            Some(target),
            target_domain,
            vless.wire_flow(),
        )?;
        let stream = self
            .dial_carrier(node, uuid, header, tcp, connect_timeout, None)
            .await?;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    pub(super) async fn prepare_retained_carrier(
        &self,
        runtime: &Arc<crate::runtime::NodeRuntime>,
        uuid: [u8; 16],
        header: Vec<u8>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(
        Box<dyn AsyncReadWrite>,
        crate::proxy::transport::TransportPreparation,
    )> {
        if runtime.xhttp.is_none() {
            let permit = runtime.acquire_vless_carrier()?;
            let stream = runtime
                .transport_quality()
                .scope(self.dial_carrier(&runtime.node, uuid, header, None, timeout, Some(permit)))
                .await?;
            return Ok((
                stream,
                crate::proxy::transport::TransportPreparation::none(),
            ));
        }
        runtime
            .transport_quality()
            .scope(async {
                let (stream, preparation) =
                    crate::proxy::transport::prepare_transport_runtime(runtime, None, timeout)
                        .await?;
                let vision = runtime.node.vless().unwrap().is_vision().then_some(uuid);
                let stream = if let Some(config) = self.encryption_config(&runtime.node)? {
                    start(config.connect(stream).await?, &header, vision).await?
                } else {
                    start(stream, &header, vision).await?
                };
                Ok((stream, preparation))
            })
            .await
    }

    pub(super) async fn prepare_retained_base(
        &self,
        runtime: &Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<(ProxyStream, crate::proxy::transport::TransportPreparation)> {
        let vless = runtime.node.vless().unwrap();
        let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let header = Self::build_request_header(
            &uuid,
            CMD_TCP,
            Some(target),
            target_domain,
            vless.wire_flow(),
        )?;
        let (stream, preparation) = self
            .prepare_retained_carrier(runtime, uuid, header, connect_timeout)
            .await?;
        Ok((
            ProxyStream {
                stream,
                target_addr: target,
                target_domain: target_domain.map(str::to_string),
            },
            preparation,
        ))
    }

    pub(super) async fn prepare_retained_mux_carrier(
        &self,
        runtime: &Arc<crate::runtime::NodeRuntime>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<(
        Box<dyn AsyncReadWrite>,
        crate::proxy::transport::TransportPreparation,
    )> {
        let vless = runtime.node.vless().unwrap();
        let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let header = Self::build_request_header(
            &uuid,
            crate::proxy::vless::cool::VLESS_MUX_COMMAND,
            None,
            None,
            vless.wire_flow(),
        )?;
        self.prepare_retained_carrier(runtime, uuid, header, timeout)
            .await
    }
}

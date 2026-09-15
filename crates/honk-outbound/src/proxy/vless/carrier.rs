use super::*;

impl VLessHandler {
    /// Build the post-connect stream for a dial. Encrypted Vision keeps the
    /// concrete `EncryptedStream` through response and Vision wrapping so
    /// Direct bypasses only AEAD while its boxed outer transport stays intact.
    /// Unencrypted raw TCP/TLS keeps its concrete type for the existing raw switch.
    async fn dial_stream(
        &self,
        node: &Node,
        uuid: [u8; 16],
        tcp: TcpStream,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let vless = node.vless().unwrap();
        let encryption = self.encryption_config(node)?;
        if encryption.is_none()
            && vless.is_vision()
            && matches!(vless.transport.transport.as_str(), "" | "tcp")
        {
            let stream: Box<dyn AsyncReadWrite> =
                match crate::proxy::transport::maybe_tls_wrap_concrete(node, tcp).await? {
                    crate::proxy::transport::MaybeTls::Tls(tls) => {
                        if tls.ssl().version2() != Some(boring::ssl::SslVersion::TLS1_3) {
                            anyhow::bail!("VLESS Vision requires negotiated TLS 1.3");
                        }
                        Box::new(VisionStream::new(ResponseHeaderStrip::new(tls), uuid))
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

        let stream = crate::proxy::transport::maybe_tls_wrap(node, tcp).await?;
        let stream: Box<dyn AsyncReadWrite> = match permit {
            Some(permit) => Box::new(crate::proxy::RuntimeOwnedIo {
                inner: stream,
                _owner: permit,
            }),
            None => stream,
        };
        let stream = crate::proxy::transport::wrap_after_tls(node, stream).await?;
        if let Some(config) = encryption {
            let encrypted = config.connect(stream).await?;
            let stripped = ResponseHeaderStrip::new(encrypted);
            return if vless.is_vision() {
                Ok(Box::new(VisionStream::new(stripped, uuid)))
            } else {
                Ok(Box::new(stripped))
            };
        }
        Ok(Self::wrap_response_stream(node, uuid, stream))
    }

    fn wrap_response_stream(
        node: &Node,
        uuid: [u8; 16],
        stream: Box<dyn AsyncReadWrite>,
    ) -> Box<dyn AsyncReadWrite> {
        let stripped = ResponseHeaderStrip::new(stream);
        if node.vless().unwrap().is_vision() {
            Box::new(VisionStream::new(stripped, uuid))
        } else {
            Box::new(stripped)
        }
    }

    async fn dial_carrier(
        &self,
        node: &Node,
        uuid: [u8; 16],
        header: Vec<u8>,
        tcp: Option<TcpStream>,
        connect_timeout: std::time::Duration,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let tcp = match tcp {
            Some(tcp) => tcp,
            None => {
                let address = format!("{}:{}", node.host(), node.port);
                crate::util::connect_outbound(&address, connect_timeout).await?
            }
        };
        let mut stream = self.dial_stream(node, uuid, tcp, permit).await?;
        stream.write_all(&header).await?;
        stream.flush().await?;
        Ok(stream)
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

    pub(super) async fn dial_retained_carrier(
        &self,
        runtime: &Arc<crate::runtime::NodeRuntime>,
        uuid: [u8; 16],
        header: Vec<u8>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let permit = runtime.acquire_vless_carrier()?;
        self.dial_carrier(
            &runtime.node,
            uuid,
            header,
            None,
            connect_timeout,
            Some(permit),
        )
        .await
    }

    pub(super) async fn dial_retained_base(
        &self,
        runtime: &Arc<crate::runtime::NodeRuntime>,
        target: SocketAddr,
        target_domain: Option<&str>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<ProxyStream> {
        let vless = runtime.node.vless().unwrap();
        let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let header = Self::build_request_header(
            &uuid,
            CMD_TCP,
            Some(target),
            target_domain,
            vless.wire_flow(),
        )?;
        let stream = self
            .dial_retained_carrier(runtime, uuid, header, connect_timeout)
            .await?;
        Ok(ProxyStream {
            stream,
            target_addr: target,
            target_domain: target_domain.map(str::to_string),
        })
    }

    pub(super) async fn dial_retained_mux_carrier(
        &self,
        runtime: &Arc<crate::runtime::NodeRuntime>,
        connect_timeout: std::time::Duration,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let vless = runtime.node.vless().unwrap();
        let uuid = Self::parse_uuid(vless.uuid.as_deref().unwrap_or(""))?;
        let header = Self::build_request_header(
            &uuid,
            crate::proxy::vless_cool::VLESS_MUX_COMMAND,
            None,
            None,
            vless.wire_flow(),
        )?;
        self.dial_retained_carrier(runtime, uuid, header, connect_timeout)
            .await
    }
}

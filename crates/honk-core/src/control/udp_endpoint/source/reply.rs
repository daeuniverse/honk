use super::*;
use std::task::Poll;

pub(in crate::control::udp_endpoint) enum SourceReplyTarget {
    Flow {
        endpoint: Arc<UdpEndpoint>,
        source: SocketAddr,
    },
    Foreign(SocketAddr),
    Drop,
}

struct ForeignReplyGuard<'a>(&'a SourceOwner);

impl Drop for ForeignReplyGuard<'_> {
    fn drop(&mut self) {
        self.0.state.lock().active_foreign_reply = None;
    }
}

impl UdpEndpointPool {
    /// Admits a reply to the bound flow in one endpoint-map observation: the
    /// entry must be a live `Ready` view of this owner whose source is still
    /// attached. Nothing awaits between lookup and delivery, so there is no
    /// second lookup to revalidate generation, token, or endpoint identity.
    pub(in crate::control::udp_endpoint) fn classify_source_reply(
        &self,
        owner: &SourceOwner,
        peer: SocketAddr,
    ) -> SourceReplyTarget {
        let key = match owner.scope.reply {
            ReplyProjection::ActualPeer => EndpointKey::new(
                owner.scope.domain,
                owner.scope.client,
                peer,
                owner.scope.packet_source.map(|source| source.lineage),
            ),
            ReplyProjection::RewriteTo(original) => EndpointKey::new(
                owner.scope.domain,
                owner.scope.client,
                original,
                owner.scope.packet_source.map(|source| source.lineage),
            ),
        };
        let Some(entry) = self.endpoints.get(&key) else {
            return match owner.scope.reply {
                ReplyProjection::ActualPeer => {
                    let state = owner.state.lock();
                    if state
                        .retired_reply_peers
                        .contains(&normalize_socket_addr(peer))
                    {
                        SourceReplyTarget::Drop
                    } else {
                        SourceReplyTarget::Foreign(peer)
                    }
                }
                ReplyProjection::RewriteTo(_) => SourceReplyTarget::Drop,
            };
        };
        match entry.value() {
            EndpointEntry::Ready(ready)
                if ready.alive.load(Ordering::Acquire)
                    && !ready.endpoint.dead.load(Ordering::Acquire)
                    && ready.endpoint.begin_source_reply(owner.id) =>
            {
                SourceReplyTarget::Flow {
                    endpoint: Arc::clone(&ready.endpoint),
                    source: match owner.scope.reply {
                        ReplyProjection::ActualPeer => peer,
                        ReplyProjection::RewriteTo(original) => original,
                    },
                }
            }
            EndpointEntry::Initializing(_)
            | EndpointEntry::Ready(_)
            | EndpointEntry::Retiring { .. } => SourceReplyTarget::Drop,
        }
    }

    fn admit_foreign_source_reply<'a>(
        &self,
        owner: &'a SourceOwner,
        peer: SocketAddr,
    ) -> Option<ForeignReplyGuard<'a>> {
        if self
            .sources
            .get(&owner.scope)
            .is_none_or(|entry| entry.id != owner.id)
        {
            return None;
        }
        let entry = self.endpoints.entry(EndpointKey::new(
            owner.scope.domain,
            owner.scope.client,
            peer,
            owner.scope.packet_source.map(|source| source.lineage),
        ));
        if !matches!(entry, dashmap::mapref::entry::Entry::Vacant(_)) {
            return None;
        }
        let mut state = owner.state.lock();
        let peer = normalize_socket_addr(peer);
        if !matches!(owner.scope.reply, ReplyProjection::ActualPeer)
            || state.retirement.is_some()
            || state.retired_reply_peers.contains(&peer)
            || state.active_foreign_reply.is_some()
        {
            return None;
        }
        state.active_foreign_reply = Some(peer);
        Some(ForeignReplyGuard(owner))
    }
}

pub(super) enum SourceReplyDisposition {
    Delivered,
    Observed,
    Drop,
}

async fn send_reply(
    socket: &ReplySocket,
    data: &[u8],
    client: SocketAddr,
) -> SourceReplyDisposition {
    let send = socket.send_to(data, client);
    tokio::pin!(send);
    let sent = match std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx))).await {
        Poll::Ready(result) => result,
        Poll::Pending => match tokio::time::timeout(TRANSPORT_SEND_TIMEOUT, send).await {
            Ok(result) => result,
            Err(_) => return SourceReplyDisposition::Observed,
        },
    };
    match sent {
        Ok(_) => SourceReplyDisposition::Delivered,
        Err(error) if is_auxiliary_retirement(&error) => SourceReplyDisposition::Drop,
        Err(_) => SourceReplyDisposition::Observed,
    }
}

#[cfg(all(test, target_os = "linux"))]
#[tokio::test]
async fn source_reply_distinguishes_retired_binding_from_failed_delivery() {
    let root = honk_netstack::MemoryBudget::new(4 << 20);
    let (scope, owner) = crate::control::netstack::auxiliary_scope(1500, &root).unwrap();
    let mut driver = owner.hand_off();
    driver.resume_auxiliary(1500, || true).unwrap();
    let source = "198.51.100.1:4000".parse().unwrap();
    let client = "192.0.2.1:5000".parse().unwrap();
    let socket = ReplySocket {
        scope: scope.scope(),
        packet_source: None,
        socket: ReplySocketFd::Packet(scope.datagram_sender(source)),
        _permit: None,
    };
    assert!(matches!(
        send_reply(&socket, b"live", client).await,
        SourceReplyDisposition::Delivered
    ));
    assert!(matches!(
        send_reply(
            &socket,
            b"wrong family",
            "[2001:db8::1]:5000".parse().unwrap()
        )
        .await,
        SourceReplyDisposition::Observed
    ));
    driver.begin_auxiliary_pause().unwrap();
    assert!(matches!(
        send_reply(&socket, b"old", client).await,
        SourceReplyDisposition::Drop
    ));
}

pub(super) async fn deliver_source_reply(
    pool: &UdpEndpointPool,
    owner: &SourceOwner,
    peer: SocketAddr,
    data: &[u8],
) -> SourceReplyDisposition {
    match pool.classify_source_reply(owner, peer) {
        SourceReplyTarget::Flow { endpoint, source } => {
            endpoint.native.reply_received();
            if source.is_ipv4() != owner.scope.client.is_ipv4() {
                endpoint
                    .native
                    .dropped("reply_family_mismatch", Some("reply_family_mismatch"));
                return SourceReplyDisposition::Drop;
            }
            #[cfg(test)]
            {
                let hook = endpoint.source_reply_hook.lock().clone();
                if let Some(hook) = hook {
                    hook.entered.notify_one();
                    hook.release.notified().await;
                }
            }
            match send_reply(endpoint.source_reply_socket(), data, owner.scope.client).await {
                SourceReplyDisposition::Delivered => {}
                SourceReplyDisposition::Drop => return SourceReplyDisposition::Drop,
                SourceReplyDisposition::Observed => {
                    endpoint
                        .native
                        .dropped("client_delivery_failed", Some("client_send_failed"));
                    debug!("UDP source reply delivery failed");
                    return SourceReplyDisposition::Observed;
                }
            }
            endpoint.mark_reply();
            if let Some(elapsed) = endpoint.take_first_reply_metric() {
                owner.stats.record_udp_first_reply_latency(elapsed);
            }
            endpoint.record_source_reply(data.len() as u64);
            SourceReplyDisposition::Delivered
        }
        SourceReplyTarget::Foreign(source) => {
            if source.is_ipv4() != owner.scope.client.is_ipv4() {
                return SourceReplyDisposition::Drop;
            }
            let socket = match pool.foreign_replies.get(
                owner.scope.domain,
                source,
                owner.packet_source.as_ref(),
            ) {
                Ok(socket) => socket,
                Err(error) if is_auxiliary_retirement(&error) => {
                    return SourceReplyDisposition::Drop;
                }
                Err(error) => {
                    debug!("UDP foreign reply socket creation failed: {}", error);
                    return SourceReplyDisposition::Observed;
                }
            };
            let Some(_reply) = pool.admit_foreign_source_reply(owner, source) else {
                return SourceReplyDisposition::Drop;
            };
            #[cfg(test)]
            {
                let hook = owner.foreign_reply_hook.lock().clone();
                if let Some(hook) = hook {
                    hook.entered.notify_one();
                    hook.release.notified().await;
                }
            }
            let disposition = send_reply(&socket, data, owner.scope.client).await;
            match disposition {
                SourceReplyDisposition::Delivered => {
                    owner.node_tracker.add_bytes(0, data.len() as u64);
                }
                SourceReplyDisposition::Observed => debug!("UDP foreign reply delivery failed"),
                SourceReplyDisposition::Drop => {}
            }
            disposition
        }
        SourceReplyTarget::Drop => SourceReplyDisposition::Drop,
    }
}

use super::*;

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
            ReplyProjection::ActualPeer => EndpointKey::new(owner.scope.client, peer),
            ReplyProjection::RewriteTo(original) => EndpointKey::new(owner.scope.client, original),
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
        let entry = self
            .endpoints
            .entry(EndpointKey::new(owner.scope.client, peer));
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

/// Sends one reply within `TRANSPORT_SEND_TIMEOUT`. An immediately writable
/// socket completes synchronously, so the timer is armed only when the send
/// would block.
async fn send_reply(socket: &UdpSocket, data: &[u8], client: SocketAddr) -> bool {
    match socket.try_send_to(data, client) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => matches!(
            tokio::time::timeout(TRANSPORT_SEND_TIMEOUT, socket.send_to(data, client)).await,
            Ok(Ok(_))
        ),
        Err(_) => false,
    }
}

pub(super) async fn deliver_source_reply(
    pool: &UdpEndpointPool,
    owner: &SourceOwner,
    peer: SocketAddr,
    data: &[u8],
    alternate_reply_sockets: &mut Vec<(SocketAddr, ReplySocket)>,
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
            if !send_reply(endpoint.source_reply_socket(), data, owner.scope.client).await {
                endpoint
                    .native
                    .dropped("client_delivery_failed", Some("client_send_failed"));
                debug!("UDP source reply delivery failed");
                return SourceReplyDisposition::Observed;
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
            let socket = match alternate_reply_socket(alternate_reply_sockets, source, || {
                pool.create_reply_socket(source)
            }) {
                Ok(socket) => socket,
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
            if !send_reply(socket, data, owner.scope.client).await {
                debug!("UDP foreign reply delivery failed");
                SourceReplyDisposition::Observed
            } else {
                owner.node_tracker.add_bytes(0, data.len() as u64);
                SourceReplyDisposition::Delivered
            }
        }
        SourceReplyTarget::Drop => SourceReplyDisposition::Drop,
    }
}

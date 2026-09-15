use super::*;

pub(in crate::control::udp_endpoint) enum SourceReplyTarget {
    Flow {
        key: EndpointKey,
        generation: u64,
        token: u32,
        endpoint: Arc<UdpEndpoint>,
        source: SocketAddr,
    },
    Foreign(SocketAddr),
    Drop,
}

impl UdpEndpointPool {
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
                ReplyProjection::ActualPeer => SourceReplyTarget::Foreign(peer),
                ReplyProjection::RewriteTo(_) => SourceReplyTarget::Drop,
            };
        };
        match entry.value() {
            EndpointEntry::Ready(ready)
                if ready.alive.load(Ordering::Acquire)
                    && !ready.endpoint.dead.load(Ordering::Acquire)
                    && ready.endpoint.source_owner_id() == Some(owner.id) =>
            {
                SourceReplyTarget::Flow {
                    key,
                    generation: ready.generation,
                    token: ready.decision_token,
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

    fn source_flow_reply_admitted(
        &self,
        owner: &SourceOwner,
        key: EndpointKey,
        generation: u64,
        token: u32,
        endpoint: &Arc<UdpEndpoint>,
    ) -> bool {
        if !owner.is_ready() || !endpoint.begin_source_reply(owner.id) {
            return false;
        }
        self.endpoints.get(&key).is_some_and(|entry| {
            matches!(
                entry.value(),
                EndpointEntry::Ready(ready)
                    if ready.generation == generation
                        && ready.decision_token == token
                        && ready.alive.load(Ordering::Acquire)
                        && Arc::ptr_eq(&ready.endpoint, endpoint)
                        && ready.endpoint.source_owner_id() == Some(owner.id)
            )
        })
    }

    fn foreign_source_reply_admitted(&self, owner: &SourceOwner, peer: SocketAddr) -> bool {
        if !owner.is_ready()
            || self
                .sources
                .get(&owner.scope)
                .is_none_or(|entry| entry.id != owner.id)
        {
            return false;
        }
        matches!(owner.scope.reply, ReplyProjection::ActualPeer)
            && !self
                .endpoints
                .contains_key(&EndpointKey::new(owner.scope.client, peer))
    }
}

pub(super) enum SourceReplyDisposition {
    Delivered,
    Observed,
    Drop,
}

pub(super) async fn deliver_source_reply(
    pool: &UdpEndpointPool,
    owner: &SourceOwner,
    peer: SocketAddr,
    data: &[u8],
    alternate_reply_sockets: &mut Vec<(SocketAddr, ReplySocket)>,
) -> SourceReplyDisposition {
    match pool.classify_source_reply(owner, peer) {
        SourceReplyTarget::Flow {
            key,
            generation,
            token,
            endpoint,
            source,
        } => {
            if !pool.source_flow_reply_admitted(owner, key, generation, token, &endpoint)
                || source.is_ipv4() != owner.scope.client.is_ipv4()
            {
                return SourceReplyDisposition::Drop;
            }
            if let Err(error) = endpoint
                .source_reply_socket()
                .send_to(data, owner.scope.client)
                .await
            {
                debug!("VLESS UDP source reply delivery failed: {}", error);
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
            if !pool.foreign_source_reply_admitted(owner, source)
                || source.is_ipv4() != owner.scope.client.is_ipv4()
            {
                return SourceReplyDisposition::Drop;
            }
            let index = match alternate_reply_sockets
                .iter()
                .position(|(cached_source, _)| *cached_source == source)
            {
                Some(index) => index,
                None if alternate_reply_sockets.len() < MAX_REPLY_SOCKETS_PER_ENDPOINT - 1 => {
                    let socket = match pool.create_reply_socket(source) {
                        Ok(socket) => socket,
                        Err(error) => {
                            debug!("VLESS UDP foreign reply socket creation failed: {}", error);
                            return SourceReplyDisposition::Observed;
                        }
                    };
                    alternate_reply_sockets.push((source, socket));
                    alternate_reply_sockets.len() - 1
                }
                None => return SourceReplyDisposition::Observed,
            };
            if !pool.foreign_source_reply_admitted(owner, source) {
                return SourceReplyDisposition::Drop;
            }
            if let Err(error) = alternate_reply_sockets[index]
                .1
                .send_to(data, owner.scope.client)
                .await
            {
                debug!("VLESS UDP foreign reply delivery failed: {}", error);
                SourceReplyDisposition::Observed
            } else {
                owner.node_tracker.add_bytes(0, data.len() as u64);
                SourceReplyDisposition::Delivered
            }
        }
        SourceReplyTarget::Drop => SourceReplyDisposition::Drop,
    }
}

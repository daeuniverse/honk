use super::*;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct LocalReplyError(#[source] io::Error);

fn local_reply_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), LocalReplyError(error))
}

pub(super) fn is_local_reply_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<LocalReplyError>())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn receive_loop(
    endpoint: Arc<UdpEndpoint>,
    reply_socket: Arc<ReplySocket>,
    foreign_replies: Arc<ForeignReplySockets>,
    client_addr: SocketAddr,
    client_dst: SocketAddr,
    alive_set: Arc<honk_outbound::alive::AliveDialerSet>,
    stats: Arc<StatsManager>,
    outbound_tracker: OutboundTracker,
) -> io::Result<()> {
    let ipver = endpoint.health_family;
    let transport = endpoint
        .flow_transport()
        .expect("ordinary UDP receive loop requires a PacketTransport");
    // Heap, not inline: an inline array adds 64 KiB to every endpoint task.
    let mut buf = vec![0u8; 65536];
    let reply_idle_timeout = tokio::time::sleep(REPLY_IDLE_TIMEOUT);
    tokio::pin!(reply_idle_timeout);
    loop {
        reply_idle_timeout
            .as_mut()
            .reset(tokio::time::Instant::now() + REPLY_IDLE_TIMEOUT);
        let received = tokio::select! {
            biased;
            packet = transport.recv_packet(&mut buf) => Some(packet),
            _ = reply_idle_timeout.as_mut() => None,
        };
        let (n, source) = match received {
            Some(Ok(packet)) => packet,
            Some(Err(error)) => return Err(error),
            None => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, ReplyIdleTimeout));
            }
        };
        if source != endpoint.relay_addr
            && !transport.allows_full_cone_replies()
            && !endpoint.validate_reply_peer(source)
        {
            endpoint.native.dropped("unexpected_reply_peer", None);
            debug!(
                "UDP endpoint driver rejecting unexpected reply peer {}",
                source
            );
            continue;
        }
        endpoint.native.reply_received();
        // Remote DNS may choose another address or family for the same logical peer.
        let source = if endpoint.target_is_domain {
            client_dst
        } else {
            source
        };
        if source.is_ipv4() != client_addr.is_ipv4() {
            endpoint
                .native
                .dropped("reply_family_mismatch", Some("reply_family_mismatch"));
            endpoint.native.finish(UdpTerminal::ReplyFamilyMismatch);
            return Err(local_reply_error(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "UDP reply source {} and client {} use different address families",
                    source, client_addr
                ),
            )));
        }
        let foreign;
        let reply_socket = if source == client_dst {
            reply_socket.as_ref()
        } else {
            match foreign_replies.get(source) {
                Ok(socket) => {
                    foreign = socket;
                    foreign.as_ref()
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    debug!("UDP reply socket capacity exhausted for {}", source);
                    endpoint
                        .native
                        .dropped("reply_socket_capacity", Some("capacity"));
                    continue;
                }
                Err(error) => {
                    endpoint
                        .native
                        .dropped("reply_socket_failed", Some("reply_socket_failed"));
                    endpoint.native.finish(UdpTerminal::ReplySocketFailed);
                    return Err(local_reply_error(error));
                }
            }
        };
        let delivered = reply_socket.send_to(&buf[..n], client_addr).await;
        if delivered.is_err() {
            endpoint
                .native
                .dropped("client_delivery_failed", Some("client_send_failed"));
            endpoint.native.finish(UdpTerminal::ClientDeliveryFailed);
        }
        delivered.map_err(local_reply_error)?;
        endpoint.mark_reply();
        if let Some(elapsed) = endpoint.take_first_reply_metric() {
            stats.record_udp_first_reply_latency(elapsed);
        }
        endpoint.tracker_download(n as u64);
        endpoint.score_reply(n as u64);
        outbound_tracker.add_bytes(0, n as u64);
        if endpoint.take_alive_report_slot() {
            alive_set.report_available_traffic(
                endpoint.node_id,
                honk_outbound::alive::ProbeDomain::DataUdp,
                ipver,
            );
        }
    }
}

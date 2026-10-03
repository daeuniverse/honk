use super::*;

/// Retire an endpoint only through its token-bound backend incarnation, then
/// acknowledge the exact pool tombstone while preserving kernel handoffs.
pub(crate) fn spawn_udp_removal_worker(
    udp_pool: Arc<UdpEndpointPool>,
    ebpf: Arc<RwLock<Box<dyn EbpfBackend>>>,
    tracker: Arc<ConnectionTracker>,
    fatal_tx: mpsc::UnboundedSender<anyhow::Error>,
) -> tokio::task::JoinHandle<()> {
    use crate::control::udp_endpoint::RemovalReason;
    const UDP_REMOVAL_QUEUE_CAPACITY: usize = 1024;
    const UDP_REMOVAL_BATCH_SIZE: usize = 128;
    let (remove_tx, mut remove_rx) = tokio::sync::mpsc::channel::<
        crate::control::udp_endpoint::EndpointRemoval,
    >(UDP_REMOVAL_QUEUE_CAPACITY);
    udp_pool.set_remove_sink(remove_tx);
    tokio::spawn(async move {
        let mut removals = Vec::with_capacity(UDP_REMOVAL_BATCH_SIZE);
        while let Some(first) = remove_rx.recv().await {
            removals.clear();
            removals.push(first);
            while removals.len() < UDP_REMOVAL_BATCH_SIZE {
                match remove_rx.try_recv() {
                    Ok(removal) => removals.push(removal),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                    | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                }
            }

            for removal in removals.drain(..) {
                if !udp_pool.wait_removal_io(&removal).await {
                    udp_pool.finish_removal(&removal, false);
                    let _ = fatal_tx.send(anyhow::anyhow!(
                        "UDP retirement did not complete owned I/O: token={}, generation={}",
                        removal.decision_token,
                        removal.generation
                    ));
                    continue;
                }
                let mut backend = ebpf.write().await;
                let backend_clean = if removal.reason == RemovalReason::UserspaceEndpointRetired {
                    let key = crate::control::connection::build_tuples_key(
                        removal.dst.ip(),
                        removal.dst.port(),
                        removal.client.ip(),
                        removal.client.port(),
                        17,
                    );
                    match backend.remove_udp_flow(&key, removal.decision_token) {
                        Ok(crate::ebpf::UdpDecisionCommitResult::Applied)
                        | Ok(crate::ebpf::UdpDecisionCommitResult::Missing)
                        | Ok(crate::ebpf::UdpDecisionCommitResult::Superseded) => true,
                        Ok(result) => {
                            warn!(
                                ?result,
                                token = removal.decision_token,
                                generation = removal.generation,
                                "UDP retirement identity mismatch; retaining tombstone and signaling fatal"
                            );
                            let _ = fatal_tx.send(anyhow::anyhow!(
                                "UDP retirement identity mismatch: result={result:?}, token={}, generation={}",
                                removal.decision_token,
                                removal.generation
                            ));
                            false
                        }
                        Err(error) => {
                            error!(
                                %error,
                                token = removal.decision_token,
                                generation = removal.generation,
                                "token-bound UDP retirement failed; retaining tombstone and signaling fatal"
                            );
                            let _ = fatal_tx.send(anyhow::anyhow!(
                                "token-bound UDP retirement failed: {error}; token={}, generation={}",
                                removal.decision_token,
                                removal.generation
                            ));
                            false
                        }
                    }
                } else {
                    true
                };
                drop(backend);
                if backend_clean && let Some(id) = removal.conn_id.as_deref() {
                    tracker.remove(id);
                }
                udp_pool.finish_removal(&removal, backend_clean);
            }
            udp_pool.flush_removal_dirty();
        }
    })
}

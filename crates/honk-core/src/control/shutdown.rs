use super::lifecycle::STAGE_TIMEOUT;
use super::*;

impl ControlPlane {
    #[cfg(feature = "ebpf")]
    pub(super) async fn cleanup_nfqueue_startup_failure(
        &mut self,
        runtime: &mut Option<NfqueueRuntime>,
    ) {
        let Some(runtime) = runtime.as_mut() else {
            return;
        };
        runtime.begin_pending_drain().await;
        if let Err(error) = runtime.shutdown_service().await {
            error!(%error, "failed to stop NFQUEUE after startup failure");
        }
        if let Err(error) = runtime.finish_pending_drain().await {
            error!(%error, "failed to drain NFQUEUE after startup failure");
        }
        self.pending_udp_verdicts = None;
    }

    /// Stop the retained DNS/persistence owners and clean up backend state.
    pub(super) async fn finalize_shutdown(&mut self) -> anyhow::Result<()> {
        let state_tick = self.state_tick.stop_and_join().await;
        info!("shutdown: stopping DNS controller");
        self.dns_controller.shutdown(STAGE_TIMEOUT).await;
        let dns_cache = self.dns_controller.cache().await;
        let persistence = dns_cache.lock().await.persistence();
        if let Some(persistence) = persistence {
            // The worker is a std thread that cannot be aborted, but the
            // Shutdown command is queued before the join starts, and the
            // spawn_blocking join keeps owning the thread handle even if
            // this future is dropped on timeout — no detached writer.
            match tokio::time::timeout(STAGE_TIMEOUT, persistence.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "DNS persistence shutdown failed"),
                Err(_) => warn!(
                    "DNS persistence shutdown exceeded {:?}; continuing",
                    STAGE_TIMEOUT
                ),
            }
        }
        info!("shutdown: cleaning up eBPF backend");
        let backend = self.ebpf.write().await.cleanup().await;
        state_tick?;
        backend?;
        info!("Control plane stopped");
        Ok(())
    }
}

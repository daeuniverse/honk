use super::*;

impl ControlPlane {
    // Closes every NFQUEUE/UDP source of admitted work while the hooks are still
    // attached; callers detach or finish `stop_network_epoch` only afterward.
    pub(super) async fn quiesce_udp_epoch(
        &mut self,
        mut epoch: Option<&mut RuntimeEpoch>,
    ) -> anyhow::Result<()> {
        let mut error = None;
        if let Some(epoch) = epoch.as_mut() {
            #[cfg(feature = "ebpf")]
            if let Some(queue) = epoch.queue.as_mut() {
                retain_error(
                    &mut error,
                    queue
                        .check_startup_health()
                        .await
                        .map_err(anyhow::Error::from),
                );
                retain_error(
                    &mut error,
                    cleanup_stage(async {
                        queue.begin_pending_drain().await;
                        Ok(())
                    })
                    .await,
                );
            }
            epoch.stop.send_replace(true);
            if let Some(listener) = epoch.dns.as_ref() {
                listener.stop_accepting();
            }
            while let Some(result) = epoch.ingress.join_next().await {
                retain_error(&mut error, result.map_err(anyhow::Error::from));
            }
        }
        retain_error(
            &mut error,
            cleanup_stage(async {
                anyhow::ensure!(
                    self.stop_udp_warm_coordinator().await,
                    "UDP warm coordinator join failed"
                );
                Ok(())
            })
            .await,
        );
        retain_error(
            &mut error,
            cleanup_stage(async {
                anyhow::ensure!(
                    self.stop_selector_warm_coordinator().await,
                    "Selector warm coordinator join failed"
                );
                Ok(())
            })
            .await,
        );
        let udp = self.udp_pool.shutdown().await;
        if !udp.joined || !udp.graceful {
            error.get_or_insert_with(|| anyhow::anyhow!("UDP quiescence required forced cleanup"));
        }
        error.map_or(Ok(()), Err)
    }

    // Startup can fail before an epoch exists.
    // Always retire shared network owners; only listener/task joins need an epoch.
    // Runs after `quiesce_udp_epoch`.
    pub(super) async fn stop_network_epoch(
        &mut self,
        mut epoch: Option<&mut RuntimeEpoch>,
    ) -> anyhow::Result<()> {
        let mut error = None;
        if let Some(epoch) = epoch.as_mut() {
            if let Some(listener) = epoch.dns.as_mut() {
                retain_error(&mut error, cleanup_stage(listener.abort_and_join()).await);
            }
            epoch.dns.take();
        }
        let registry = self.runtime_registry.read().clone();
        registry.begin_retirement();
        if let Some(epoch) = epoch.as_mut() {
            retain_error(&mut error, epoch.maintenance.abort_and_join().await);
        }
        // The tracker covers published UUIDs; the epoch also owns pre-ID TCP work.
        if let Ok(summary) = self
            .connection_tracker
            .close_matching(Some("tcp"), None, usize::MAX)
            .await
            && summary.failed
        {
            error.get_or_insert_with(|| anyhow::anyhow!("TCP retirement could not be confirmed"));
        }
        if let Some(epoch) = epoch.as_mut() {
            epoch.tcp.abort_all();
            while let Some(result) = epoch.tcp.join_next().await {
                if let Err(join_error) = result
                    && !join_error.is_cancelled()
                {
                    error.get_or_insert_with(|| join_error.into());
                }
            }
        }
        self.retirement.sink.lock().take();
        if let Some(epoch) = epoch {
            match join_retirement_owner(&mut epoch.removals, "flow retirement worker").await {
                Ok(hints) => *self.retirement.hints.lock() = hints,
                Err(join_error) => {
                    error.get_or_insert(join_error);
                }
            }
            retain_error(
                &mut error,
                join_retirement_owner(&mut epoch.janitor, "BPF janitor").await,
            );
            if let Some(updates) = epoch.health_updates.as_mut() {
                retain_error(&mut error, updates.stop().await);
            }
            epoch.health_updates.take();
            #[cfg(feature = "ebpf")]
            if let Some(queue) = epoch.queue.as_mut() {
                // Not stage-bounded: see `shutdown_service`.
                retain_error(&mut error, queue.shutdown_service().await);
                if let Some(fatal) = queue.take_shutdown_fatal() {
                    error.get_or_insert_with(|| fatal.into());
                }
                retain_error(
                    &mut error,
                    cleanup_stage(queue.finish_pending_drain()).await,
                );
                queue.abort_tasks().await;
                self.pending_udp_verdicts = None;
            }
            #[cfg(feature = "ebpf")]
            {
                epoch.queue.take();
            }
            while let Ok(fatal) = epoch.removal_errors.try_recv() {
                error.get_or_insert(fatal);
            }
            while let Ok(fatal) = epoch.critical_errors.try_recv() {
                error.get_or_insert(fatal);
            }
        }
        retain_error(&mut error, self.ebpf.write().await.clear_listener_sockets());
        retain_error(
            &mut error,
            cleanup_stage(async {
                registry.shutdown().await;
                Ok(())
            })
            .await,
        );
        self.connection_pool.clear();
        for runtime in registry.values() {
            for reason in [
                crate::stats::WarmReason::Udp,
                crate::stats::WarmReason::Selector,
                crate::stats::WarmReason::Preconnect,
            ] {
                self.stats.clear_warm(runtime.node.id, reason);
            }
        }
        self.udp_warm_ids.lock().clear();
        self.selector_warm_ids.lock().clear();
        self.selector_bare_warm.lock().clear();
        if let Some(retry) = self.network_refresh_retry.as_mut() {
            retry.abort();
            if let Err(join_error) = retry.await
                && !join_error.is_cancelled()
            {
                error.get_or_insert_with(|| join_error.into());
            }
        }
        self.network_refresh_retry.take();
        error.map_or(Ok(()), Err)
    }

    /// Rolls back a startup that failed before `run`; the original error stays first.
    pub(crate) async fn abort_startup(&mut self, error: anyhow::Error) -> anyhow::Error {
        self.shutdown_runtime(None, Some(error))
            .await
            .expect_err("a retained startup error fails the rollback")
    }

    // Tests enter without an epoch, like a startup that failed before binding.
    pub(in crate::control) async fn shutdown_runtime(
        &mut self,
        mut epoch: Option<&mut RuntimeEpoch>,
        mut fatal: Option<anyhow::Error>,
    ) -> anyhow::Result<()> {
        if fatal.is_some() {
            self.datapath_healthy
                .store(false, std::sync::atomic::Ordering::Release);
        }
        #[cfg(feature = "native-api")]
        self.publish_phase(if fatal.is_some() {
            EnginePhase::Failed
        } else {
            EnginePhase::Draining
        });
        retain_error(&mut fatal, self.fence_runtime().await);
        retain_error(
            &mut fatal,
            self.quiesce_udp_epoch(epoch.as_deref_mut()).await,
        );
        #[cfg(feature = "ebpf")]
        if let Some(watcher) = self.iface_watcher.take() {
            watcher.shutdown(STAGE_TIMEOUT).await;
        }
        // No watcher can reattach after this terminal boundary.
        retain_error(&mut fatal, self.ebpf.write().await.detach_hooks());
        if self.health_task.is_some() {
            retain_error(
                &mut fatal,
                cleanup_stage(async {
                    self.alive_set
                        .shutdown_health_checks()
                        .await
                        .map_err(anyhow::Error::from)
                })
                .await,
            );
        }
        retain_error(&mut fatal, joined(&mut self.health_task).await);
        #[cfg(feature = "native-api")]
        if let Some(owner) = &self.native_owner {
            retain_error(&mut fatal, cleanup_stage(owner.pause_probes()).await);
        }
        #[cfg(feature = "clash-api")]
        {
            let mut slot = self.ui_download.lock().await;
            if let Some(download) = slot.as_mut() {
                let mut stopping = std::pin::pin!(download.stop_and_join());
                let result = match tokio::time::timeout(STAGE_TIMEOUT, &mut stopping).await {
                    Ok(result) => result,
                    Err(_) => {
                        warn!(
                            "external UI download exceeded its stop deadline; waiting for extraction"
                        );
                        stopping.await
                    }
                };
                retain_error(&mut fatal, result);
            }
            slot.take();
        }
        if fatal.is_none() && self.is_datapath_healthy() && epoch.is_some() {
            let wait_for_connections = self.config.read().await.global.shutdown_wait_connections;
            if wait_for_connections {
                retain_error(&mut fatal, self.drain_tracker.drain().await.map(|_| ()));
            }
        }
        retain_error(&mut fatal, self.stop_network_epoch(epoch).await);
        if let Some(flags) = &self.datapath_flags {
            retain_error(&mut fatal, flags.disable().await);
        }
        retain_error(&mut fatal, self.finalize_shutdown().await);
        fatal.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::support::control_plane;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn shutdown_wait_connections_controls_tcp_retirement() -> anyhow::Result<()> {
        for (wait, finish_after, fatal, unhealthy, expected_response, expected_seconds) in [
            (false, 1, false, false, &b""[..], 0),
            (true, 1, false, false, &b"finished"[..], 1),
            (true, 60, false, false, &b""[..], 5),
            (true, 1, true, false, &b""[..], 0),
            (true, 1, false, true, &b""[..], 0),
        ] {
            let mut config = Config::default();
            config.global.shutdown_wait_connections = wait;
            let mut plane = control_plane(config);
            plane.datapath_healthy.store(!unhealthy, Ordering::Release);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let (client, accepted) = tokio::join!(
                TcpStream::connect(listener.local_addr()?),
                listener.accept()
            );
            let mut client = client?;
            let (mut server, _) = accepted?;
            let listener = listener.into_std()?;
            // SAFETY: the owned listener keeps its descriptor stable and nonblocking.
            let tcp4 = unsafe { tokio::io::unix::AsyncFd::register(listener) }?;
            let mut epoch = RuntimeEpoch {
                listeners: BoundListeners {
                    tcp4,
                    tcp6: None,
                    udp4: Vec::new(),
                    udp6: Vec::new(),
                    dns: None,
                    nfqueue_enabled: false,
                },
                stop: watch::channel(false).0,
                ingress: JoinSet::new(),
                tcp: JoinSet::new(),
                maintenance: OwnedTasks::default(),
                dns: None,
                janitor: None,
                removals: None,
                removal_errors: mpsc::unbounded_channel().1,
                critical_errors: mpsc::unbounded_channel().1,
                health_updates: None,
                #[cfg(feature = "ebpf")]
                queue: None,
            };
            let guard = ConnectionGuard::new(plane.drain_tracker.clone());
            let config = plane.config.clone();
            epoch.tcp.spawn(async move {
                let _guard = guard;
                tokio::time::sleep(Duration::from_secs(finish_after)).await;
                // Connection completion must not be blocked by shutdown's config read.
                drop(config.write().await);
                server.write_all(b"finished").await.unwrap();
            });
            let started = tokio::time::Instant::now();
            let result = tokio::time::timeout(
                Duration::from_secs(8),
                plane.shutdown_runtime(
                    Some(&mut epoch),
                    fatal.then(|| anyhow::anyhow!("fatal shutdown")),
                ),
            )
            .await?;
            assert_eq!(result.is_err(), fatal);
            let elapsed = started.elapsed();
            assert!(elapsed >= Duration::from_secs(expected_seconds));
            assert!(elapsed < Duration::from_secs(expected_seconds + 1));
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
                .await??;
            assert_eq!(response, expected_response);
            assert!(plane.drain_tracker.should_reject());
            assert_eq!(plane.drain_tracker.active_count(), 0);
            assert!(epoch.tcp.is_empty());
        }
        Ok(())
    }
}

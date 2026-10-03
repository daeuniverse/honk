//! Bring-up and teardown of the native API for one `run`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use tokio::sync::mpsc;
use tracing::info;

use super::config::ConfigService;
use super::config_write;
use super::logs::{EngineLevel, LogBinding};
use super::observation::NativeObservation;
use super::store::{DatabaseStartup, SourceStore};
use super::{NativeServer, NativeState};
use crate::configuration::SourceUpdate;
use crate::control::{ControlCommand, ControlPlane, EnginePhase};
use crate::subscription::SubscriptionSupervisorHandle;

/// The native listener and, once started, the configuration coordinator.
pub(crate) struct NativeRuntime {
    server: NativeServer,
    observation: Arc<NativeObservation>,
    /// The coordinator's shutdown; its type is private to `config`.
    stop_configuration: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl NativeRuntime {
    /// Binds the native listener and serves it.
    pub(crate) async fn start(
        control_plane: &mut ControlPlane,
        observation: Arc<NativeObservation>,
        started_at: SystemTime,
        started: Instant,
        engine_level: EngineLevel,
        log_binding: &LogBinding,
    ) -> anyhow::Result<Self> {
        let listen = control_plane
            .config_handle()
            .read()
            .await
            .experimental
            .native_api
            .listen
            .clone();
        let listener = tokio::net::TcpListener::bind(&listen)
            .await
            .map_err(|_| anyhow::anyhow!("native API listener bind failed"))?;
        let listen = listener.local_addr()?;
        let state = NativeState::with_observation(
            control_plane,
            Arc::clone(&observation),
            listen,
            started_at,
            started,
        )
        .await?;
        let logs = &observation.logs;
        logs.attach_engine_level(engine_level);
        log_binding.bind(Arc::downgrade(logs));
        let server = NativeServer::start(listener, Arc::new(state));
        info!(target: "honk_core", %listen, message = "native API listener ready");
        Ok(Self {
            server,
            observation,
            stop_configuration: None,
        })
    }

    /// Attaches the provider view and starts the configuration coordinator.
    pub(crate) async fn start_configuration(
        &mut self,
        control_plane: &mut ControlPlane,
        database: Option<DatabaseStartup>,
        sources: Option<SourceUpdate>,
        config_path: &Path,
        commands: mpsc::Sender<ControlCommand>,
        subscriptions: SubscriptionSupervisorHandle,
    ) -> Arc<ConfigService> {
        let observation = &self.observation;
        observation.providers.attach(subscriptions.clone());
        let service = observation.configuration.clone();
        remove_stale_temporaries(sources.as_ref(), config_path);
        let store = match database {
            Some(database) => SourceStore::Db(database.store),
            None => SourceStore::File(
                sources
                    .as_ref()
                    .and_then(|sources| sources.sources.first())
                    .map_or_else(|| config_path.to_path_buf(), |source| source.path.clone())
                    .into(),
            ),
        };
        let owner = service
            .start(
                store,
                sources,
                honk_config::paths::data_dir().to_path_buf(),
                control_plane.config_handle(),
                control_plane.log_files(),
                control_plane.diagnostics_handle(),
                commands,
                subscriptions,
            )
            .await;
        self.stop_configuration = Some(Box::pin(owner.shutdown()));
        service
    }

    /// Stops the coordinator, publishes a failed run, then stops the listener.
    pub(crate) async fn shutdown(native: Option<Self>, control_plane: &ControlPlane, failed: bool) {
        let (server, stop_configuration) = match native {
            Some(native) => (Some(native.server), native.stop_configuration),
            None => (None, None),
        };
        if let Some(stop) = stop_configuration {
            stop.await;
        }
        if failed {
            control_plane.publish_phase(EnginePhase::Failed);
        }
        if let Some(server) = server {
            server.shutdown().await;
        }
    }
}

/// Sweeps every directory a configuration or geodata write stages into; runs before the
/// coordinator exists, so no temporary file of this process can be caught.
fn remove_stale_temporaries(sources: Option<&SourceUpdate>, config_path: &Path) {
    let files = sources.into_iter().flat_map(|sources| {
        let dependencies = sources
            .dependencies
            .iter()
            .map(|dependency| &dependency.path);
        sources
            .sources
            .iter()
            .map(|source| &source.path)
            .chain(dependencies)
    });
    let directories: BTreeSet<_> = files
        .map(PathBuf::as_path)
        .chain([config_path])
        .filter_map(Path::parent)
        .chain([honk_config::paths::data_dir()])
        .collect();
    for directory in directories {
        for path in config_write::remove_stale_temporaries(directory) {
            info!(target: "honk_core", path = %path.display(), message = "removed stale configuration write temporary file");
        }
    }
}

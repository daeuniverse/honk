use std::future::Future;
use std::sync::Arc;

use tokio::sync::{Mutex, watch};

use super::cache::DnsCache;
use super::forwarder::DnsForwarder;
use super::outcome::DnsOutcome;
use super::query::{DnsRequestMeta, IngressProfile};
use super::runtime::{DnsServiceProvider, RuntimeLease};

mod name_resolution;

#[derive(Clone)]
pub struct DnsService {
    backend: Arc<DnsServiceBackend>,
    flush_generation: watch::Sender<u64>,
}

enum DnsServiceBackend {
    Runtime(Arc<DnsServiceProvider>),
    Standalone(Arc<DnsForwarder>),
}

struct OperationToken {
    generation: u64,
    updates: watch::Receiver<u64>,
}

#[derive(Debug, thiserror::Error)]
#[error("DNS operation cancelled by cache flush at generation {generation}")]
struct OperationCancelled {
    generation: u64,
}

impl OperationToken {
    async fn run<T>(
        &mut self,
        operation: impl Future<Output = T>,
    ) -> Result<T, OperationCancelled> {
        if *self.updates.borrow() != self.generation {
            return Err(OperationCancelled {
                generation: self.generation,
            });
        }
        tokio::pin!(operation);
        tokio::select! {
            biased;
            _ = self.updates.changed() => Err(OperationCancelled {
                generation: self.generation,
            }),
            result = &mut operation => Ok(result),
        }
    }
}

impl DnsService {
    pub fn with_forwarder(forwarder: Arc<DnsForwarder>) -> Self {
        let (flush_generation, _) = watch::channel(0);
        Self {
            backend: Arc::new(DnsServiceBackend::Standalone(forwarder)),
            flush_generation,
        }
    }

    pub(crate) fn with_provider(provider: Arc<DnsServiceProvider>) -> Self {
        let (flush_generation, _) = watch::channel(0);
        Self {
            backend: Arc::new(DnsServiceBackend::Runtime(provider)),
            flush_generation,
        }
    }

    pub async fn resolve(
        &self,
        raw_query: &[u8],
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        self.resolve_with_context(raw_query, DnsRequestMeta::EMPTY, ingress)
            .await
    }

    pub async fn resolve_with_context(
        &self,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> anyhow::Result<Vec<u8>> {
        let mut operation = self.operation();
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => {
                let lease = provider.acquire();
                operation
                    .run(
                        lease.run(
                            lease
                                .runtime()
                                .forwarder()
                                .resolve_strict_with_context_and_profile(
                                    raw_query, metadata, ingress,
                                ),
                        ),
                    )
                    .await??
            }
            DnsServiceBackend::Standalone(forwarder) => {
                operation
                    .run(
                        forwarder
                            .resolve_strict_with_context_and_profile(raw_query, metadata, ingress),
                    )
                    .await?
            }
        }
    }

    pub(crate) async fn resolve_outcome_with_runtime(
        &self,
        runtime: &RuntimeLease,
        raw_query: &[u8],
        metadata: DnsRequestMeta,
        ingress: IngressProfile,
    ) -> anyhow::Result<DnsOutcome> {
        let mut operation = self.operation();
        operation
            .run(
                runtime.run(
                    runtime
                        .runtime()
                        .forwarder()
                        .resolve_outcome_with_context_and_profile(raw_query, metadata, ingress),
                ),
            )
            .await??
            .map_err(Into::into)
    }

    pub async fn flush_cache(&self) -> anyhow::Result<bool> {
        self.flush_generation
            .send_modify(|generation| *generation = generation.saturating_add(1));
        let cache_service = self.cache().lock().await.service();
        let flush = cache_service.begin_flush();
        if let Some(persistence) = flush.persistence() {
            persistence.flush().await.map(|()| true)
        } else {
            Ok(false)
        }
        .map_err(anyhow::Error::from)
    }

    pub fn cache(&self) -> Arc<Mutex<DnsCache>> {
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => provider.acquire().runtime().cache(),
            DnsServiceBackend::Standalone(forwarder) => forwarder.cache(),
        }
    }

    pub(crate) fn provider(&self) -> Option<Arc<DnsServiceProvider>> {
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => Some(Arc::clone(provider)),
            DnsServiceBackend::Standalone(_) => None,
        }
    }

    pub fn forwarder(&self) -> Arc<DnsForwarder> {
        match self.backend.as_ref() {
            DnsServiceBackend::Runtime(provider) => {
                Arc::clone(provider.acquire().runtime().forwarder())
            }
            DnsServiceBackend::Standalone(forwarder) => Arc::clone(forwarder),
        }
    }

    fn operation(&self) -> OperationToken {
        let updates = self.flush_generation.subscribe();
        let generation = *updates.borrow();
        OperationToken {
            generation,
            updates,
        }
    }
}

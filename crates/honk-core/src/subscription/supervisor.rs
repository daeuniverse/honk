use crate::config_diagnostics::DiagnosticBuckets;
use honk_config::{Config, node::Node, subscription::Subscription};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{info, warn};

use super::{SubscriptionManager, SubscriptionStore};
use crate::control::ControlCommand;
use crate::control::ReloadOutcome;
use tokio::time::Instant;

const MAX_ACTIVE_FETCHES: usize = 4;
const MAX_REFRESH_QUEUE: usize = 16;

#[derive(Debug)]
pub(crate) struct SubscriptionMergeReply {
    pub(crate) outcome: ReloadOutcome,
    pub(crate) node_count: usize,
    pub(crate) authorized: Vec<AuthorizedSubscription>,
    /// The configuration diagnostic code that rejected the publication.
    pub(crate) rejection: Option<&'static str>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ProviderLoad {
    pub(crate) updated_at: Option<SystemTime>,
    pub(crate) cached: bool,
    pub(crate) error: Option<&'static str>,
    /// The configuration diagnostic code behind a `publication_rejected` error.
    pub(crate) rejection: Option<&'static str>,
}

/// Why the supervisor refused an explicit provider refresh.
#[cfg(feature = "native-api")]
#[derive(Clone, Copy, Debug)]
pub(crate) enum RefreshRefusal {
    /// No supervised worker owns the provider.
    NotRefreshable,
    /// A refresh is in flight or the provider's worker spec is changing.
    Busy,
    /// The refresh queue is full or the supervisor has stopped.
    Unavailable,
}

/// Receives the lifecycle of one explicit provider refresh, so the supervisor
/// reports progress without depending on the API that asked for it.
#[cfg(feature = "native-api")]
pub(crate) trait RefreshReport: Send + Sync {
    fn accept(&self);
    fn running(&self);
    fn reject(self: Box<Self>, refusal: RefreshRefusal);
    fn finish(
        self: Box<Self>,
        subscription: &Subscription,
        load: ProviderLoad,
        result: Result<SubscriptionMergeReply, &'static str>,
    );
}

struct ObservedProvider {
    subscription: Subscription,
    load: ProviderLoad,
}

type Observations = Arc<parking_lot::RwLock<HashMap<uuid::Uuid, ObservedProvider>>>;

#[derive(Clone, Debug)]
pub(crate) struct AuthorizedSubscription {
    pub(crate) subscription: Subscription,
    pub(crate) revision: u64,
}

fn same_worker_spec(left: &Subscription, right: &Subscription) -> bool {
    left.id == right.id && same_subscription_source_spec(left, right)
}

pub(crate) fn same_subscription_source_spec(left: &Subscription, right: &Subscription) -> bool {
    left.name == right.name
        && left.url == right.url
        && left.sub_type == right.sub_type
        && left.update_interval == right.update_interval
        && left.user_agent == right.user_agent
        && left.headers == right.headers
        && left.enabled == right.enabled
        && left.cache == right.cache
        && left.download_detour == right.download_detour
}

pub(crate) fn same_subscription_worker_set(left: &[Subscription], right: &[Subscription]) -> bool {
    // ponytail: subscription lists are tiny; index by UUID if config scale changes.
    left.len() == right.len()
        && left.iter().all(|subscription| {
            right
                .iter()
                .any(|other| same_worker_spec(subscription, other))
        })
}

#[derive(Debug)]
pub(crate) struct SubscriptionAuthorizations {
    next_revision: u64,
    active: HashMap<uuid::Uuid, u64>,
}

impl SubscriptionAuthorizations {
    pub(crate) fn new(subscriptions: &[Subscription]) -> anyhow::Result<Self> {
        validate_subscription_ids(subscriptions)?;
        let mut authorizations = Self {
            next_revision: 0,
            active: HashMap::new(),
        };
        authorizations.publish(&[], subscriptions);
        Ok(authorizations)
    }

    pub(crate) fn publish(&mut self, current: &[Subscription], next: &[Subscription]) {
        let mut active = HashMap::new();
        for subscription in next.iter().filter(|subscription| subscription.enabled) {
            let unchanged = current
                .iter()
                .any(|previous| previous.enabled && same_worker_spec(previous, subscription));
            let revision = if unchanged {
                self.active.get(&subscription.id).copied()
            } else {
                None
            }
            .unwrap_or_else(|| {
                self.next_revision = self
                    .next_revision
                    .checked_add(1)
                    .expect("subscription revision exhausted");
                self.next_revision
            });
            active.insert(subscription.id, revision);
        }
        self.active = active;
    }

    pub(crate) fn authorizes(&self, subscription_id: uuid::Uuid, revision: u64) -> bool {
        self.active.get(&subscription_id) == Some(&revision)
    }

    #[cfg(test)]
    pub(crate) fn revision(&self, subscription_id: uuid::Uuid) -> Option<u64> {
        self.active.get(&subscription_id).copied()
    }

    pub(crate) fn committed(&self, subscriptions: &[Subscription]) -> Vec<AuthorizedSubscription> {
        subscriptions
            .iter()
            .filter(|subscription| subscription.enabled)
            .map(|subscription| AuthorizedSubscription {
                subscription: subscription.clone(),
                revision: self.active[&subscription.id],
            })
            .collect()
    }
}

pub(crate) fn validate_subscription_ids(subscriptions: &[Subscription]) -> anyhow::Result<()> {
    let mut ids = HashSet::with_capacity(subscriptions.len());
    for subscription in subscriptions {
        anyhow::ensure!(
            !subscription.id.is_nil(),
            "subscription '{}' has a nil id",
            subscription.name
        );
        anyhow::ensure!(
            ids.insert(subscription.id),
            "duplicate subscription id {}",
            subscription.id
        );
    }
    Ok(())
}

struct FetchCompletion {
    authorized: AuthorizedSubscription,
    result: Option<anyhow::Result<Vec<Node>>>,
    diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
}

async fn fetch_once(
    manager: Arc<SubscriptionManager>,
    store: Option<SubscriptionStore>,
    authorized: AuthorizedSubscription,
    mut stop: watch::Receiver<bool>,
) -> FetchCompletion {
    let mut diagnostics = Vec::new();
    let fetched = if *stop.borrow() {
        None
    } else {
        tokio::select! {
            biased;
            _ = stop.changed() => None,
            result = manager.fetch_content(&authorized.subscription, &mut diagnostics) => Some(result),
        }
    };
    let result = match fetched {
        Some(Ok((nodes, content))) => {
            // Once a blocking cache write starts, its owner must join it even on pause/shutdown.
            SubscriptionManager::persist_content(
                &authorized.subscription,
                store.as_ref(),
                content,
                &mut diagnostics,
                0,
            )
            .await;
            Some(Ok(nodes))
        }
        Some(Err(error)) => Some(Err(error)),
        None => None,
    };
    honk_config::diagnostic::report_detailed_diagnostics(&diagnostics);
    FetchCompletion {
        authorized,
        result,
        diagnostics,
    }
}
struct Flight {
    authorized: AuthorizedSubscription,
    #[cfg(feature = "native-api")]
    operation: Option<Box<dyn RefreshReport>>,
}

enum ProviderSchedule {
    #[cfg(feature = "native-api")]
    Deferred,
    RefreshEligible(Option<Instant>),
}

struct Provider {
    authorized: AuthorizedSubscription,
    schedule: ProviderSchedule,
}

impl Provider {
    fn new(authorized: AuthorizedSubscription) -> Self {
        let mut provider = Self {
            authorized,
            schedule: ProviderSchedule::RefreshEligible(None),
        };
        provider.reset_deadline(Instant::now());
        provider
    }

    fn reset_deadline(&mut self, now: Instant) {
        match &mut self.schedule {
            ProviderSchedule::RefreshEligible(next) => {
                let interval = self.authorized.subscription.update_interval;
                *next = (interval > 0)
                    .then(|| now.checked_add(Duration::from_secs(interval)))
                    .flatten();
            }
            #[cfg(feature = "native-api")]
            ProviderSchedule::Deferred => {}
        }
    }
}

struct SupervisorState {
    manager: Arc<SubscriptionManager>,
    store: Option<SubscriptionStore>,
    observations: Observations,
    providers: HashMap<uuid::Uuid, Provider>,
    fetches: JoinSet<FetchCompletion>,
    fetch_ids: HashMap<tokio::task::Id, uuid::Uuid>,
    publications: JoinSet<(uuid::Uuid, Result<SubscriptionMergeReply, ()>)>,
    publication_ids: HashMap<tokio::task::Id, uuid::Uuid>,
    flights: HashMap<uuid::Uuid, Flight>,
    pending: VecDeque<uuid::Uuid>,
    stop: watch::Sender<bool>,
    pause_failure: Option<String>,
}

impl SupervisorState {
    fn new(manager: Arc<SubscriptionManager>, store: Option<SubscriptionStore>) -> Self {
        Self {
            manager,
            store,
            observations: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            providers: HashMap::new(),
            fetches: JoinSet::new(),
            fetch_ids: HashMap::new(),
            publications: JoinSet::new(),
            publication_ids: HashMap::new(),
            flights: HashMap::new(),
            pending: VecDeque::new(),
            stop: watch::channel(false).0,
            pause_failure: None,
        }
    }

    fn schedule(&mut self, id: uuid::Uuid) {
        let Some(provider) = self.providers.get(&id) else {
            return;
        };
        #[cfg(feature = "native-api")]
        if matches!(provider.schedule, ProviderSchedule::Deferred) {
            return;
        }
        if self.flights.contains_key(&id) {
            return;
        }
        self.flights.insert(
            id,
            Flight {
                authorized: provider.authorized.clone(),
                #[cfg(feature = "native-api")]
                operation: None,
            },
        );
        self.pending.push_back(id);
    }

    fn start_pending(&mut self, limit: usize) {
        while self.fetches.len() + self.publications.len() < limit {
            let Some(id) = self.pending.pop_front() else {
                break;
            };
            let flight = &self.flights[&id];
            #[cfg(feature = "native-api")]
            if let Some(operation) = &flight.operation {
                operation.running();
            }
            let task = self.fetches.spawn(fetch_once(
                Arc::clone(&self.manager),
                self.store.clone(),
                flight.authorized.clone(),
                self.stop.subscribe(),
            ));
            self.fetch_ids.insert(task.id(), id);
        }
    }

    fn reconcile(&mut self, subscriptions: Vec<AuthorizedSubscription>) {
        let mut previous = std::mem::take(&mut self.providers);
        let ids: Vec<_> = subscriptions.iter().map(|a| a.subscription.id).collect();
        self.providers = subscriptions
            .into_iter()
            .map(|authorized| {
                let id = authorized.subscription.id;
                let provider = match previous.remove(&id) {
                    Some(mut provider) if provider.authorized.revision == authorized.revision => {
                        provider.authorized = authorized;
                        provider
                    }
                    _ => Provider::new(authorized),
                };
                (id, provider)
            })
            .collect();
        if let Some(store) = &self.store {
            store.set_enabled(
                self.providers
                    .values()
                    .map(|provider| &provider.authorized.subscription),
            );
        }
        {
            let mut observations = self.observations.write();
            observations.retain(|id, _| self.providers.contains_key(id));
            for (id, provider) in &self.providers {
                let authorized = &provider.authorized;
                let keep = observations.get(id).is_some_and(|old| {
                    same_worker_spec(&old.subscription, &authorized.subscription)
                });
                if !keep {
                    observations.insert(
                        *id,
                        ObservedProvider {
                            subscription: authorized.subscription.clone(),
                            load: ProviderLoad::default(),
                        },
                    );
                }
            }
        }
        let mut pending = std::mem::take(&mut self.pending);
        while let Some(id) = pending.pop_front() {
            let current = self.providers.get(&id).is_some_and(|provider| {
                provider.authorized.revision == self.flights[&id].authorized.revision
            });
            if current {
                self.pending.push_back(id);
            } else {
                self.finish(id, Err("provider_replaced"));
            }
        }
        // Existing work keeps its captured revision until the control owner fences its result.
        // Do not abort a task that may already have committed a runtime publication.
        for id in ids {
            self.schedule(id);
        }
    }

    fn finish(&mut self, id: uuid::Uuid, result: Result<SubscriptionMergeReply, &'static str>) {
        let Some(flight) = self.flights.remove(&id) else {
            return;
        };
        let current = self
            .providers
            .get(&id)
            .is_some_and(|provider| provider.authorized.revision == flight.authorized.revision);
        let result = match result {
            Ok(reply) if reply.outcome.accepted() => Ok(reply),
            result if current => result,
            _ => Err("provider_replaced"),
        };
        let mut observations = self.observations.write();
        let result = result.and_then(|reply| {
            if reply.outcome.accepted()
                && !reply
                    .authorized
                    .iter()
                    .any(|a| a.subscription.id == id && a.revision == flight.authorized.revision)
            {
                Err("provider_replaced")
            } else {
                Ok(reply)
            }
        });
        let observed = observations.get_mut(&id).filter(|_| current);
        let load = match (&result, observed) {
            (Ok(reply), Some(observed)) if reply.outcome.accepted() => {
                info!(
                    nodes = reply.node_count,
                    restored = observed.load.cached,
                    "Subscription runtime publication acknowledged"
                );
                observed.load.updated_at = Some(SystemTime::now());
                observed.load.cached = false;
                observed.load.error =
                    matches!(reply.outcome, ReloadOutcome::CommittedDegraded { .. })
                        .then_some("publication_degraded");
                observed.load.rejection = None;
                observed.load
            }
            (Err("supervisor_stopped"), Some(observed)) => observed.load,
            (_, Some(observed)) => {
                observed.load.error = Some(
                    result
                        .as_ref()
                        .err()
                        .copied()
                        .unwrap_or("publication_rejected"),
                );
                observed.load.rejection = result.as_ref().ok().and_then(|reply| reply.rejection);
                observed.load
            }
            (Ok(reply), None) if reply.outcome.accepted() => ProviderLoad {
                updated_at: Some(SystemTime::now()),
                cached: false,
                error: matches!(reply.outcome, ReloadOutcome::CommittedDegraded { .. })
                    .then_some("publication_degraded"),
                rejection: None,
            },
            _ => ProviderLoad::default(),
        };
        drop(observations);
        #[cfg(feature = "native-api")]
        if let Some(operation) = flight.operation {
            operation.finish(&flight.authorized.subscription, load, result);
        }
        #[cfg(not(feature = "native-api"))]
        let _ = load;
        if !current {
            self.schedule(id);
        }
    }

    fn fetched(&mut self, completion: FetchCompletion, command_tx: &mpsc::Sender<ControlCommand>) {
        let id = completion.authorized.subscription.id;
        match completion.result {
            Some(Ok(nodes)) => {
                let command_tx = command_tx.clone();
                let task = self.publications.spawn(async move {
                    let (result, wait) = oneshot::channel();
                    let command = ControlCommand::MergeSubscription {
                        subscription_id: id,
                        revision: completion.authorized.revision,
                        nodes,
                        diagnostics: completion.diagnostics,
                        result,
                    };
                    let reply = if command_tx.send(command).await.is_ok() {
                        wait.await.map_err(|_| ())
                    } else {
                        Err(())
                    };
                    (id, reply)
                });
                self.publication_ids.insert(task.id(), id);
            }
            Some(Err(error)) => {
                warn!(
                    subscription = %completion.authorized.subscription.name,
                    %error,
                    "Subscription refresh failed; keeping active nodes"
                );
                self.finish(id, Err(super::failure_code(&error)));
            }
            None => self.finish(id, Err("supervisor_stopped")),
        }
    }

    #[cfg(feature = "native-api")]
    fn refresh(&mut self, subscription: Subscription, operation: Box<dyn RefreshReport>) {
        let id = subscription.id;
        let Some(provider) = self.providers.get_mut(&id) else {
            operation.reject(RefreshRefusal::NotRefreshable);
            return;
        };
        if !same_worker_spec(&provider.authorized.subscription, &subscription) {
            operation.reject(RefreshRefusal::Busy);
            return;
        }
        if self.flights.contains_key(&id) {
            operation.reject(RefreshRefusal::Busy);
            return;
        }
        if self.pending.len() >= MAX_REFRESH_QUEUE {
            operation.reject(RefreshRefusal::Unavailable);
            return;
        }
        operation.accept();
        if matches!(provider.schedule, ProviderSchedule::Deferred) {
            provider.schedule = ProviderSchedule::RefreshEligible(None);
            provider.reset_deadline(Instant::now());
        }
        self.flights.insert(
            id,
            Flight {
                authorized: provider.authorized.clone(),
                operation: Some(operation),
            },
        );
        self.pending.push_back(id);
    }

    async fn stop_fetches(&mut self) -> anyhow::Result<()> {
        self.stop.send_replace(true);
        while let Some(id) = self.pending.pop_front() {
            self.finish(id, Err("supervisor_stopped"));
        }
        if let Err(error) = self.manager.pause_network().await {
            self.pause_failure.get_or_insert_with(|| error.to_string());
        }
        while let Some(result) = self.fetches.join_next_with_id().await {
            match result {
                Ok((task, completion)) => {
                    self.fetch_ids.remove(&task);
                    let id = completion.authorized.subscription.id;
                    match completion.result {
                        Some(Err(error)) => {
                            warn!(
                                subscription = %completion.authorized.subscription.name,
                                %error,
                                "Subscription refresh failed; keeping active nodes"
                            );
                            self.finish(id, Err("fetch_failed"));
                        }
                        Some(Ok(_)) | None => self.finish(id, Err("supervisor_stopped")),
                    }
                }
                Err(error) => {
                    if let Some(id) = self.fetch_ids.remove(&error.id()) {
                        self.finish(id, Err("fetch_failed"));
                    }
                }
            }
        }
        self.pause_result()
    }

    fn pause_result(&self) -> anyhow::Result<()> {
        match &self.pause_failure {
            Some(error) => Err(anyhow::anyhow!(error.clone())),
            None => Ok(()),
        }
    }

    async fn shutdown(&mut self) -> anyhow::Result<()> {
        let result = self.stop_fetches().await;
        // An admitted merge may already have committed; retain its acknowledgement owner.
        while let Some(result) = self.publications.join_next_with_id().await {
            match result {
                Ok((task, (id, reply))) => {
                    self.publication_ids.remove(&task);
                    self.finish(id, reply.map_err(|_| "publication_unavailable"));
                }
                Err(error) => {
                    if let Some(id) = self.publication_ids.remove(&error.id()) {
                        self.finish(id, Err("publication_unavailable"));
                    }
                }
            }
        }
        self.providers.clear();
        self.pending.clear();
        #[cfg(feature = "native-api")]
        for (_, flight) in self.flights.drain() {
            if let Some(operation) = flight.operation {
                operation.finish(
                    &flight.authorized.subscription,
                    ProviderLoad::default(),
                    Err("supervisor_stopped"),
                );
            }
        }
        #[cfg(not(feature = "native-api"))]
        self.flights.clear();
        self.fetch_ids.clear();
        result
    }

    fn owned_task_count(&self) -> usize {
        self.fetches.len() + self.publications.len()
    }

    async fn run(
        mut self,
        mut commands: mpsc::Receiver<SupervisorCommand>,
        merge_tx: mpsc::Sender<ControlCommand>,
    ) {
        let mut ticks = tokio::time::interval(Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            self.start_pending(MAX_ACTIVE_FETCHES);
            tokio::select! {
                command = commands.recv() => match command {
                    Some(SupervisorCommand::Reconcile { authorized, done }) => {
                        self.reconcile(authorized);
                        let _ = done.send(());
                    }
                    #[cfg(feature = "native-api")]
                    Some(SupervisorCommand::DeferredSubscriptions { done }) => {
                        let deferred = self.providers.values()
                            .filter(|provider| matches!(provider.schedule, ProviderSchedule::Deferred))
                            .map(|provider| provider.authorized.subscription.clone())
                            .collect();
                        let _ = done.send(deferred);
                    }
                    #[cfg(feature = "native-api")]
                    Some(SupervisorCommand::ReconcileManaged { authorized, deferred, done }) => {
                        let result = if let Some(provider) = authorized.iter().find(|a| a.subscription.id == deferred) {
                            if self.providers.contains_key(&deferred) || self.flights.contains_key(&deferred) {
                                Err(anyhow::anyhow!("managed provider identity was already scheduled"))
                            } else {
                                self.providers.insert(deferred, Provider {
                                    authorized: provider.clone(),
                                    schedule: ProviderSchedule::Deferred,
                                });
                                self.reconcile(authorized);
                                Ok(())
                            }
                        } else { Err(anyhow::anyhow!("managed provider was not authorized")) };
                        let _ = done.send(result);
                    }
                    #[cfg(feature = "native-api")]
                    Some(SupervisorCommand::Refresh { subscription, operation }) => self.refresh(subscription, operation),
                    Some(SupervisorCommand::Shutdown { done }) => {
                        commands.close();
                        let result = self.shutdown().await.map(|()| self.owned_task_count());
                        // Dropping queued reservations wakes every admission waiter.
                        drop(commands);
                        let _ = done.send(result);
                        return;
                    }
                    None => {
                        if let Err(error) = self.shutdown().await { warn!(%error, "Subscription shutdown failed"); }
                        return;
                    }
                },
                result = self.fetches.join_next_with_id(), if !self.fetches.is_empty() => match result {
                    Some(Ok((task, completion))) => {
                        self.fetch_ids.remove(&task);
                        self.fetched(completion, &merge_tx);
                    }
                    Some(Err(error)) => if let Some(id) = self.fetch_ids.remove(&error.id()) {
                        self.finish(id, Err("fetch_failed"));
                    },
                    None => {}
                },
                result = self.publications.join_next_with_id(), if !self.publications.is_empty() => match result {
                    Some(Ok((task, (id, reply)))) => {
                        self.publication_ids.remove(&task);
                        self.finish(id, reply.map_err(|_| "publication_unavailable"));
                    }
                    Some(Err(error)) => if let Some(id) = self.publication_ids.remove(&error.id()) {
                        self.finish(id, Err("publication_unavailable"));
                    },
                    None => {}
                },
                _ = ticks.tick() => {
                    let now = Instant::now();
                    let due: Vec<_> = self.providers.iter_mut().filter_map(|(id, provider)| {
                        match provider.schedule {
                            ProviderSchedule::RefreshEligible(Some(next)) if next <= now => {
                                provider.reset_deadline(now);
                                Some(*id)
                            }
                            _ => None,
                        }
                    }).collect();
                    for id in due { self.schedule(id); }
                }
            }
        }
    }
}

// ponytail: only 16 commands can queue; box refresh payloads if this bound grows.
#[allow(clippy::large_enum_variant)]
enum SupervisorCommand {
    Reconcile {
        authorized: Vec<AuthorizedSubscription>,
        done: oneshot::Sender<()>,
    },
    #[cfg(feature = "native-api")]
    ReconcileManaged {
        authorized: Vec<AuthorizedSubscription>,
        deferred: uuid::Uuid,
        done: oneshot::Sender<anyhow::Result<()>>,
    },
    #[cfg(feature = "native-api")]
    DeferredSubscriptions {
        done: oneshot::Sender<Vec<Subscription>>,
    },
    #[cfg(feature = "native-api")]
    Refresh {
        subscription: Subscription,
        operation: Box<dyn RefreshReport>,
    },
    Shutdown {
        done: oneshot::Sender<anyhow::Result<usize>>,
    },
}

#[derive(Clone)]
pub(crate) struct SubscriptionSupervisorHandle {
    command_tx: mpsc::Sender<SupervisorCommand>,
    #[cfg(feature = "native-api")]
    observations: Observations,
    /// A subscription store is open, so `cache` has an effect.
    #[cfg(feature = "native-api")]
    caches: bool,
}

impl SubscriptionSupervisorHandle {
    #[cfg(feature = "native-api")]
    pub(crate) fn running(&self) -> bool {
        !self.command_tx.is_closed()
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn caches(&self) -> bool {
        self.caches
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn observation(&self, subscription: &Subscription) -> ProviderLoad {
        self.observations
            .read()
            .get(&subscription.id)
            .filter(|observed| same_worker_spec(&observed.subscription, subscription))
            .map(|observed| observed.load)
            .unwrap_or_default()
    }

    #[cfg(feature = "native-api")]
    pub(crate) fn refresh(
        &self,
        subscription: Subscription,
        operation: Box<dyn RefreshReport>,
    ) -> Result<(), RefreshRefusal> {
        if let Err(error) = self.command_tx.try_send(SupervisorCommand::Refresh {
            subscription,
            operation,
        }) {
            if let SupervisorCommand::Refresh { operation, .. } = error.into_inner() {
                operation.reject(RefreshRefusal::Unavailable);
            }
            return Err(RefreshRefusal::Unavailable);
        }
        Ok(())
    }

    pub(crate) async fn reconcile(
        &self,
        authorized: Vec<AuthorizedSubscription>,
    ) -> anyhow::Result<()> {
        let (done, wait) = oneshot::channel();
        self.command_tx
            .send(SupervisorCommand::Reconcile { authorized, done })
            .await
            .map_err(|_| anyhow::anyhow!("subscription supervisor stopped before reconcile"))?;
        wait.await
            .map_err(|_| anyhow::anyhow!("subscription supervisor stopped during reconcile"))
    }

    #[cfg(feature = "native-api")]
    pub(crate) async fn reconcile_managed(
        &self,
        authorized: Vec<AuthorizedSubscription>,
        deferred: uuid::Uuid,
    ) -> anyhow::Result<()> {
        let (done, wait) = oneshot::channel();
        self.command_tx
            .send(SupervisorCommand::ReconcileManaged {
                authorized,
                deferred,
                done,
            })
            .await
            .map_err(|_| anyhow::anyhow!("subscription supervisor stopped before reconcile"))?;
        wait.await
            .map_err(|_| anyhow::anyhow!("subscription supervisor stopped during reconcile"))?
    }

    #[cfg(feature = "native-api")]
    pub(crate) async fn deferred_subscriptions(&self) -> anyhow::Result<Vec<Subscription>> {
        let (done, wait) = oneshot::channel();
        self.command_tx
            .send(SupervisorCommand::DeferredSubscriptions { done })
            .await
            .map_err(|_| anyhow::anyhow!("subscription supervisor stopped before snapshot"))?;
        wait.await
            .map_err(|_| anyhow::anyhow!("subscription supervisor stopped during snapshot"))
    }
}

pub(crate) struct SubscriptionSupervisor {
    prepared: Option<SupervisorState>,
    startup_diagnostics: Option<DiagnosticBuckets>,
    #[cfg(feature = "native-api")]
    observations: Observations,
    #[cfg(feature = "native-api")]
    caches: bool,
    command_tx: Option<mpsc::Sender<SupervisorCommand>>,
    task: Option<JoinHandle<()>>,
}

impl SubscriptionSupervisor {
    pub(crate) async fn prepare(
        config: &mut Config,
        store: Option<SubscriptionStore>,
        static_diagnostics: Vec<honk_config::diagnostic::DetailedDiagnostic>,
    ) -> anyhow::Result<Self> {
        let authorizations = SubscriptionAuthorizations::new(&config.subscriptions)?;
        let initial = authorizations.committed(&config.subscriptions);
        #[cfg(feature = "native-api")]
        let manager = if config.experimental.native_api.enabled {
            SubscriptionManager::new_owned().await?
        } else {
            SubscriptionManager::new()?
        };
        #[cfg(not(feature = "native-api"))]
        let manager = SubscriptionManager::new()?;
        let mut state = SupervisorState::new(Arc::new(manager), store);
        state.reconcile(initial);
        let startup_diagnostics = state.prepare_startup(config, static_diagnostics).await;

        Ok(Self {
            #[cfg(feature = "native-api")]
            observations: Arc::clone(&state.observations),
            #[cfg(feature = "native-api")]
            caches: state.store.is_some(),
            prepared: Some(state),
            startup_diagnostics: Some(startup_diagnostics),
            command_tx: None,
            task: None,
        })
    }
    /// Routed fetches wait for this, so it hands over routing before `start`.
    pub(crate) fn route_through(&self, routing: crate::download_route::SharedOutbounds) {
        self.prepared
            .as_ref()
            .expect("subscription supervisor already started")
            .manager
            .route_through(routing);
    }

    pub(crate) fn take_startup_diagnostics(&mut self) -> DiagnosticBuckets {
        self.startup_diagnostics
            .take()
            .expect("startup diagnostics already taken")
    }

    pub(crate) fn start(&mut self, merge_tx: mpsc::Sender<ControlCommand>) {
        assert!(
            self.task.is_none(),
            "subscription supervisor already started"
        );
        let (command_tx, commands) = mpsc::channel(MAX_REFRESH_QUEUE);
        let mut state = self
            .prepared
            .take()
            .expect("subscription startup state missing");
        let now = Instant::now();
        for provider in state.providers.values_mut() {
            provider.reset_deadline(now);
        }
        self.command_tx = Some(command_tx);
        self.task = Some(tokio::spawn(state.run(commands, merge_tx)));
    }

    pub(crate) fn handle(&self) -> SubscriptionSupervisorHandle {
        SubscriptionSupervisorHandle {
            #[cfg(feature = "native-api")]
            observations: Arc::clone(&self.observations),
            #[cfg(feature = "native-api")]
            caches: self.caches,
            command_tx: self
                .command_tx
                .as_ref()
                .expect("subscription supervisor not started")
                .clone(),
        }
    }

    pub(crate) async fn shutdown(mut self) -> anyhow::Result<usize> {
        let remaining = if let Some(command_tx) = self.command_tx.take() {
            let (done, wait) = oneshot::channel();
            if command_tx
                .send(SupervisorCommand::Shutdown { done })
                .await
                .is_ok()
            {
                wait.await.map_err(|_| {
                    anyhow::anyhow!("subscription supervisor stopped during shutdown")
                })?
            } else {
                Err(anyhow::anyhow!(
                    "subscription supervisor stopped before shutdown"
                ))
            }
        } else {
            self.prepared
                .as_mut()
                .expect("subscription startup state missing")
                .shutdown()
                .await
                .map(|()| 0)
        };
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|error| anyhow::anyhow!("subscription supervisor task failed: {error}"))?;
        }
        remaining
    }
}

mod startup;

#[cfg(test)]
mod tests;

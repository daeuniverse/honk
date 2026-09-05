use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use honk_config::{Config, node::Node, subscription::Subscription};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{info, warn};

use super::{SubscriptionManager, SubscriptionStore};
use crate::control::ControlCommand;

#[derive(Clone, Debug)]
struct AuthorizedSubscription {
    pub(crate) subscription: Subscription,
    pub(crate) revision: u64,
}

fn same_worker_spec(left: &Subscription, right: &Subscription) -> bool {
    left.id == right.id
        && left.name == right.name
        && left.url == right.url
        && left.sub_type == right.sub_type
        && left.update_interval == right.update_interval
        && left.user_agent == right.user_agent
        && left.headers == right.headers
        && left.enabled == right.enabled
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

    fn committed(&self, subscriptions: &[Subscription]) -> Vec<AuthorizedSubscription> {
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
    result: anyhow::Result<Vec<Node>>,
}

async fn fetch_once(
    manager: Arc<SubscriptionManager>,
    store: Option<SubscriptionStore>,
    authorized: AuthorizedSubscription,
) -> FetchCompletion {
    let result = manager
        .fetch_and_store(&authorized.subscription, store.as_ref())
        .await;
    FetchCompletion { authorized, result }
}

async fn deliver_fetch(completion: FetchCompletion, command_tx: &mpsc::Sender<ControlCommand>) {
    let subscription = completion.authorized.subscription;
    match completion.result {
        Ok(nodes) => {
            info!(
                subscription = %subscription.name,
                nodes = nodes.len(),
                "Subscription refreshed"
            );
            let _ = command_tx
                .send(ControlCommand::MergeSubscription {
                    subscription_id: subscription.id,
                    revision: completion.authorized.revision,
                    name: subscription.name,
                    nodes,
                })
                .await;
        }
        Err(error) => warn!(
            subscription = %subscription.name,
            %error,
            "Subscription refresh failed; keeping active nodes"
        ),
    }
}

struct PeriodicWorker {
    authorized: AuthorizedSubscription,
    task: JoinHandle<()>,
}

struct SupervisorState {
    manager: Arc<SubscriptionManager>,
    store: Option<SubscriptionStore>,
    command_tx: mpsc::Sender<ControlCommand>,
    authorizations: SubscriptionAuthorizations,
    subscriptions: Vec<Subscription>,
    startup: JoinSet<FetchCompletion>,
    immediate: JoinSet<()>,
    periodic: HashMap<uuid::Uuid, PeriodicWorker>,
}

impl SupervisorState {
    fn spawn_periodic(&mut self, authorized: AuthorizedSubscription) {
        let manager = Arc::clone(&self.manager);
        let store = self.store.clone();
        let command_tx = self.command_tx.clone();
        let interval = Duration::from_secs(authorized.subscription.update_interval);
        let task_authorized = authorized.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let completion =
                    fetch_once(Arc::clone(&manager), store.clone(), task_authorized.clone()).await;
                deliver_fetch(completion, &command_tx).await;
                if command_tx.is_closed() {
                    return;
                }
            }
        });
        self.periodic.insert(
            authorized.subscription.id,
            PeriodicWorker { authorized, task },
        );
    }

    fn spawn_immediate(&mut self, authorized: AuthorizedSubscription) {
        let manager = Arc::clone(&self.manager);
        let store = self.store.clone();
        let command_tx = self.command_tx.clone();
        self.immediate.spawn(async move {
            let completion = fetch_once(manager, store, authorized).await;
            deliver_fetch(completion, &command_tx).await;
        });
    }

    async fn reconcile(&mut self, subscriptions: Vec<Subscription>) {
        self.authorizations
            .publish(&self.subscriptions, &subscriptions);
        let authorized_subscriptions = self.authorizations.committed(&subscriptions);
        self.subscriptions = subscriptions;

        self.startup.abort_all();
        while self.startup.join_next().await.is_some() {}
        self.immediate.abort_all();
        while self.immediate.join_next().await.is_some() {}

        let desired: HashMap<_, _> = authorized_subscriptions
            .iter()
            .filter(|authorized| authorized.subscription.update_interval > 0)
            .map(|authorized| (authorized.subscription.id, authorized))
            .collect();
        let stale: Vec<_> = self
            .periodic
            .iter()
            .filter_map(|(id, worker)| {
                let keep = desired.get(id).is_some_and(|authorized| {
                    authorized.revision == worker.authorized.revision
                        && same_worker_spec(
                            &authorized.subscription,
                            &worker.authorized.subscription,
                        )
                });
                (!keep).then_some(*id)
            })
            .collect();
        for id in stale {
            if let Some(worker) = self.periodic.remove(&id) {
                worker.task.abort();
                let _ = worker.task.await;
            }
        }
        let new_periodic: Vec<_> = authorized_subscriptions
            .iter()
            .filter(|authorized| {
                authorized.subscription.update_interval > 0
                    && !self.periodic.contains_key(&authorized.subscription.id)
            })
            .cloned()
            .collect();
        for authorized in new_periodic {
            self.spawn_periodic(authorized);
        }
        for authorized in authorized_subscriptions {
            self.spawn_immediate(authorized);
        }
    }

    async fn shutdown(&mut self) {
        self.startup.abort_all();
        while self.startup.join_next().await.is_some() {}
        self.immediate.abort_all();
        while self.immediate.join_next().await.is_some() {}
        for (_, worker) in self.periodic.drain() {
            worker.task.abort();
            let _ = worker.task.await;
        }
    }

    fn owned_task_count(&self) -> usize {
        self.startup.len() + self.immediate.len() + self.periodic.len()
    }

    async fn run(mut self, mut commands: mpsc::Receiver<SupervisorCommand>) {
        loop {
            tokio::select! {
                command = commands.recv() => match command {
                    Some(SupervisorCommand::Reconcile { subscriptions, done }) => {
                        self.reconcile(subscriptions).await;
                        let _ = done.send(());
                    }
                    Some(SupervisorCommand::Shutdown { done }) => {
                        self.shutdown().await;
                        let _ = done.send(self.owned_task_count());
                        return;
                    }
                    None => {
                        self.shutdown().await;
                        return;
                    }
                },
                result = self.startup.join_next(), if !self.startup.is_empty() => {
                    if let Some(Ok(completion)) = result {
                        deliver_fetch(completion, &self.command_tx).await;
                    }
                },
                _ = self.immediate.join_next(), if !self.immediate.is_empty() => {}
            }
        }
    }
}

enum SupervisorCommand {
    Reconcile {
        subscriptions: Vec<Subscription>,
        done: oneshot::Sender<()>,
    },
    Shutdown {
        done: oneshot::Sender<usize>,
    },
}

#[derive(Clone)]
pub(crate) struct SubscriptionSupervisorHandle {
    command_tx: mpsc::Sender<SupervisorCommand>,
}

impl SubscriptionSupervisorHandle {
    pub(crate) async fn reconcile(&self, subscriptions: Vec<Subscription>) {
        let (done, wait) = oneshot::channel();
        if self
            .command_tx
            .send(SupervisorCommand::Reconcile {
                subscriptions,
                done,
            })
            .await
            .is_ok()
        {
            let _ = wait.await;
        }
    }
}

pub(crate) struct SubscriptionSupervisor {
    manager: Option<Arc<SubscriptionManager>>,
    store: Option<SubscriptionStore>,
    initial: Vec<AuthorizedSubscription>,
    authorizations: Option<SubscriptionAuthorizations>,
    subscriptions: Vec<Subscription>,
    startup: Option<JoinSet<FetchCompletion>>,
    command_tx: Option<mpsc::Sender<SupervisorCommand>>,
    task: Option<JoinHandle<()>>,
}

impl SubscriptionSupervisor {
    pub(crate) async fn prepare(
        config: &mut Config,
        store: Option<SubscriptionStore>,
    ) -> anyhow::Result<Self> {
        let authorizations = SubscriptionAuthorizations::new(&config.subscriptions)?;
        let initial = authorizations.committed(&config.subscriptions);
        let manager = Arc::new(SubscriptionManager::new()?);
        let mut requires_network = HashSet::new();

        for authorized in &initial {
            let subscription = &authorized.subscription;
            let Some(store) = store.as_ref() else {
                requires_network.insert(subscription.id);
                continue;
            };
            match store.load_nodes(subscription).await {
                Ok(Some(nodes)) => {
                    info!(
                        subscription = %subscription.name,
                        nodes = nodes.len(),
                        "Restored subscription"
                    );
                    config
                        .nodes
                        .retain(|node| node.subscription_id != Some(subscription.id));
                    config.nodes.extend(nodes);
                }
                Ok(None) => {
                    requires_network.insert(subscription.id);
                }
                Err(error) => {
                    warn!(
                        subscription = %subscription.name,
                        %error,
                        "Failed to restore subscription"
                    );
                    requires_network.insert(subscription.id);
                }
            }
        }

        let mut startup = JoinSet::new();
        for authorized in &initial {
            startup.spawn(fetch_once(
                Arc::clone(&manager),
                store.clone(),
                authorized.clone(),
            ));
        }

        let deadline = tokio::time::sleep(Duration::from_secs(5));
        tokio::pin!(deadline);
        let mut received = 0usize;
        while !requires_network.is_empty() {
            tokio::select! {
                result = startup.join_next() => match result {
                    Some(Ok(completion)) => {
                        received += 1;
                        let subscription = completion.authorized.subscription;
                        match completion.result {
                            Ok(nodes) => {
                                info!(
                                    subscription = %subscription.name,
                                    nodes = nodes.len(),
                                    "Subscription fetched"
                                );
                                config.nodes.retain(|node| {
                                    node.subscription_id != Some(subscription.id)
                                });
                                config.nodes.extend(nodes);
                            }
                            Err(error) => warn!(
                                subscription = %subscription.name,
                                %error,
                                "Failed to fetch subscription"
                            ),
                        }
                        requires_network.remove(&subscription.id);
                    }
                    Some(Err(error)) => warn!(%error, "Subscription startup task failed"),
                    None => break,
                },
                _ = &mut deadline => {
                    info!(
                        received,
                        total = initial.len(),
                        "Subscription fetch deadline reached; starting control plane"
                    );
                    break;
                }
            }
        }
        if !startup.is_empty() {
            info!(
                pending = startup.len(),
                "Subscriptions still refreshing in background"
            );
        }

        Ok(Self {
            manager: Some(manager),
            store,
            initial,
            authorizations: Some(authorizations),
            subscriptions: config.subscriptions.clone(),
            startup: Some(startup),
            command_tx: None,
            task: None,
        })
    }

    pub(crate) fn start(&mut self, merge_tx: mpsc::Sender<ControlCommand>) {
        assert!(
            self.task.is_none(),
            "subscription supervisor already started"
        );
        let (command_tx, commands) = mpsc::channel(4);
        let mut state = SupervisorState {
            manager: self.manager.take().expect("subscription manager missing"),
            store: self.store.take(),
            command_tx: merge_tx,
            authorizations: self
                .authorizations
                .take()
                .expect("subscription authorizations missing"),
            subscriptions: std::mem::take(&mut self.subscriptions),
            startup: self.startup.take().expect("startup tasks missing"),
            immediate: JoinSet::new(),
            periodic: HashMap::new(),
        };
        for authorized in &self.initial {
            if authorized.subscription.update_interval > 0 {
                state.spawn_periodic(authorized.clone());
            }
        }
        self.initial.clear();
        self.command_tx = Some(command_tx);
        self.task = Some(tokio::spawn(state.run(commands)));
    }

    pub(crate) fn handle(&self) -> SubscriptionSupervisorHandle {
        SubscriptionSupervisorHandle {
            command_tx: self
                .command_tx
                .as_ref()
                .expect("subscription supervisor not started")
                .clone(),
        }
    }

    pub(crate) async fn shutdown(mut self) -> usize {
        let remaining = if let Some(command_tx) = self.command_tx.take() {
            let (done, wait) = oneshot::channel();
            if command_tx
                .send(SupervisorCommand::Shutdown { done })
                .await
                .is_ok()
            {
                wait.await.unwrap_or_default()
            } else {
                0
            }
        } else {
            if let Some(startup) = self.startup.as_mut() {
                startup.abort_all();
                while startup.join_next().await.is_some() {}
            }
            0
        };
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        remaining
    }
}

//! Log streaming support for the clash API `/logs` endpoint.
//!
//! The API layer is disabled at the callsite while no client is attached.
//! Each client raises the layer's dynamic ceiling for its subscription lifetime;
//! console filtering remains independent because the layer uses a per-layer filter.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use parking_lot::Mutex;
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::subscriber::Interest;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Filter, Layer};

/// Bounded broadcast capacity; overflow drops the oldest entries.
pub const LOG_CHANNEL_CAPACITY: usize = 256;
const LEVEL_COUNT: usize = 5;

/// One formatted log event distributed to `/logs` subscribers.
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub level: tracing::Level,
    pub payload: String,
}

struct LogInterest {
    active_level: AtomicU8,
    subscriptions: Mutex<[usize; LEVEL_COUNT]>,
}

impl LogInterest {
    fn new() -> Self {
        Self {
            active_level: AtomicU8::new(0),
            subscriptions: Mutex::new([0; LEVEL_COUNT]),
        }
    }

    fn add(&self, level: tracing::Level) {
        let mut subscriptions = self.subscriptions.lock();
        subscriptions[level_rank(level) as usize - 1] += 1;
        self.publish_level(&subscriptions);
    }

    fn remove(&self, level: tracing::Level) {
        let mut subscriptions = self.subscriptions.lock();
        let count = &mut subscriptions[level_rank(level) as usize - 1];
        debug_assert!(*count > 0, "log subscription count underflow");
        *count = count.saturating_sub(1);
        self.publish_level(&subscriptions);
    }

    fn publish_level(&self, subscriptions: &[usize; LEVEL_COUNT]) {
        let active_level = subscriptions
            .iter()
            .rposition(|count| *count != 0)
            .map_or(0, |index| index as u8 + 1);
        if self.active_level.swap(active_level, Ordering::Release) != active_level {
            tracing::callsite::rebuild_interest_cache();
        }
    }

    fn includes(&self, level: tracing::Level) -> bool {
        level_rank(level) <= self.active_level.load(Ordering::Acquire)
    }

    fn level_filter(&self) -> LevelFilter {
        match self.active_level.load(Ordering::Acquire) {
            1 => LevelFilter::ERROR,
            2 => LevelFilter::WARN,
            3 => LevelFilter::INFO,
            4 => LevelFilter::DEBUG,
            5 => LevelFilter::TRACE,
            _ => LevelFilter::OFF,
        }
    }
}

fn level_rank(level: tracing::Level) -> u8 {
    match level {
        tracing::Level::ERROR => 1,
        tracing::Level::WARN => 2,
        tracing::Level::INFO => 3,
        tracing::Level::DEBUG => 4,
        tracing::Level::TRACE => 5,
    }
}

/// Active-level-aware handle shared by the Clash API state.
#[derive(Clone)]
pub struct ClashLogHandle {
    tx: broadcast::Sender<LogEvent>,
    interest: Arc<LogInterest>,
}

impl ClashLogHandle {
    /// Subscribe through `level` until the returned guard is dropped.
    pub fn subscribe(&self, level: tracing::Level) -> LogSubscription {
        let receiver = self.tx.subscribe();
        self.interest.add(level);
        LogSubscription {
            receiver,
            interest: Arc::clone(&self.interest),
            level,
        }
    }
}

/// Receiver whose lifetime controls the API tracing interest ceiling.
pub struct LogSubscription {
    receiver: broadcast::Receiver<LogEvent>,
    interest: Arc<LogInterest>,
    level: tracing::Level,
}

impl LogSubscription {
    pub async fn recv(&mut self) -> Result<LogEvent, broadcast::error::RecvError> {
        self.receiver.recv().await
    }
    pub fn includes(&self, level: tracing::Level) -> bool {
        level <= self.level
    }
}

impl Drop for LogSubscription {
    fn drop(&mut self) {
        self.interest.remove(self.level);
    }
}

struct ClashLogFilter {
    interest: Arc<LogInterest>,
}

impl<S> Filter<S> for ClashLogFilter {
    fn enabled(&self, metadata: &tracing::Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        // Same suppression as the default console filter: endpoint-driver
        // death is lifecycle noise, not an operator event.
        metadata.target() != "quinn::endpoint" && self.interest.includes(*metadata.level())
    }

    fn callsite_enabled(&self, metadata: &'static tracing::Metadata<'static>) -> Interest {
        if metadata.target() == "quinn::endpoint" {
            Interest::never()
        } else if self.interest.includes(*metadata.level()) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(self.interest.level_filter())
    }
}

/// Tracing layer that broadcasts formatted events.
pub struct ClashLogLayer {
    tx: broadcast::Sender<LogEvent>,
}

/// Create a dynamically filtered layer and handle for the Clash API state.
pub fn layer<S>() -> (impl Layer<S>, ClashLogHandle)
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    let (tx, _) = broadcast::channel(LOG_CHANNEL_CAPACITY);
    let interest = Arc::new(LogInterest::new());
    let handle = ClashLogHandle {
        tx: tx.clone(),
        interest: Arc::clone(&interest),
    };
    (
        ClashLogLayer { tx }.with_filter(ClashLogFilter { interest }),
        handle,
    )
}

/// Parse a clash `?level=` query value into a tracing level.
/// Returns `None` for unknown names (the endpoint maps that to a 400).
pub fn parse_level(level: &str) -> Option<tracing::Level> {
    match level.to_ascii_lowercase().as_str() {
        "trace" => Some(tracing::Level::TRACE),
        "debug" => Some(tracing::Level::DEBUG),
        "info" => Some(tracing::Level::INFO),
        "warn" | "warning" => Some(tracing::Level::WARN),
        "error" => Some(tracing::Level::ERROR),
        _ => None,
    }
}

#[derive(Default)]
struct EventFields {
    message: String,
    extra: String,
}

impl Visit for EventFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            let _ = write!(self.extra, " {}={}", field.name(), value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            let _ = write!(self.extra, " {}={:?}", field.name(), value);
        }
    }
}

impl<S> Layer<S> for ClashLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if self.tx.receiver_count() == 0 {
            return;
        }
        let mut fields = EventFields::default();
        event.record(&mut fields);
        let payload = if fields.message.is_empty() {
            format!("{}{}", event.metadata().target(), fields.extra)
        } else {
            format!("{}{}", fields.message, fields.extra)
        };
        let _ = self.tx.send(LogEvent {
            level: *event.metadata().level(),
            payload,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    #[test]
    fn api_interest_changes_do_not_change_console_filtering() {
        let (api_layer, handle) = layer();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::sink)
                    .with_filter(LevelFilter::INFO),
            )
            .with(api_layer);
        let dispatch = tracing::Dispatch::new(subscriber);

        assert_eq!(handle.interest.level_filter(), LevelFilter::OFF);

        let mut subscription = handle.subscribe(tracing::Level::DEBUG);
        assert_eq!(handle.interest.level_filter(), LevelFilter::DEBUG);
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::debug!("api-only-debug");
        });
        assert_eq!(
            subscription.receiver.try_recv().unwrap().payload,
            "api-only-debug"
        );

        drop(subscription);
        assert_eq!(handle.interest.level_filter(), LevelFilter::OFF);
    }

    #[test]
    fn verbose_console_events_stay_out_of_less_verbose_api_subscription() {
        let (api_layer, handle) = layer();
        let mut subscription = handle.subscribe(tracing::Level::INFO);
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::sink)
                    .with_filter(LevelFilter::TRACE),
            )
            .with(api_layer);
        let dispatch = tracing::Dispatch::new(subscriber);

        tracing::dispatcher::with_default(&dispatch, || {
            assert!(tracing::enabled!(tracing::Level::TRACE));
            tracing::trace!("console-only-trace");
            tracing::info!("shared-info");
        });

        let event = subscription.receiver.try_recv().unwrap();
        assert_eq!(event.level, tracing::Level::INFO);
        assert_eq!(event.payload, "shared-info");
        assert!(matches!(
            subscription.receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }
}

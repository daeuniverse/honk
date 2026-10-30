use super::AuthorizedSubscription;
use std::time::Duration;
use tokio::time::Instant;

const RETRY_BASE: Duration = Duration::from_secs(30);
const RETRY_MAX: Duration = Duration::from_secs(600);

pub(super) enum ProviderSchedule {
    #[cfg(feature = "native-api")]
    Deferred,
    RefreshEligible(Option<Instant>),
}

pub(super) struct Provider {
    pub(super) authorized: AuthorizedSubscription,
    pub(super) schedule: ProviderSchedule,
    pub(super) failures: u32,
}

impl Provider {
    pub(super) fn new(authorized: AuthorizedSubscription) -> Self {
        let mut provider = Self {
            authorized,
            schedule: ProviderSchedule::RefreshEligible(None),
            failures: 0,
        };
        provider.reset_deadline(Instant::now());
        provider
    }

    pub(super) fn reset_deadline(&mut self, now: Instant) {
        match &mut self.schedule {
            ProviderSchedule::RefreshEligible(next) => {
                let interval = Duration::from_secs(self.authorized.subscription.update_interval);
                let delay = if self.failures == 0 {
                    interval
                } else {
                    RETRY_BASE
                        .saturating_mul(1u32 << (self.failures - 1).min(8))
                        .min(RETRY_MAX)
                        .min(interval)
                };
                *next = (!interval.is_zero())
                    .then(|| now.checked_add(delay))
                    .flatten();
            }
            #[cfg(feature = "native-api")]
            ProviderSchedule::Deferred => {}
        }
    }

    pub(super) fn restart_deadline(&mut self, now: Instant) {
        if self.failures == 0 {
            self.reset_deadline(now);
        }
    }

    pub(super) fn finished(&mut self, now: Instant, error: Option<&str>) {
        #[cfg(feature = "native-api")]
        if matches!(self.schedule, ProviderSchedule::Deferred) {
            return;
        }
        let retry = matches!(error, Some("fetch_failed" | "route_unavailable"));
        if retry || self.failures != 0 {
            self.failures = if retry {
                self.failures.saturating_add(1)
            } else {
                0
            };
            self.reset_deadline(now);
        }
    }
}

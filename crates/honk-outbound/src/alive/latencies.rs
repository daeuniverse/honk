//! Ring buffer of the last N latency samples.

use parking_lot::Mutex;
use std::time::{Duration, SystemTime};

/// One latency sample. `synthetic` marks the 10s placeholder pushed on
/// failure: it is not a real measurement and must never be displayed as
/// clash delay history (dashboards otherwise show a bogus 10000ms), and it
/// never feeds the moving average. Selection demotion no longer reads this
/// flag — it lives in `DialerCollection`'s coherent failure state.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LatencySample {
    pub latency: Duration,
    pub at: SystemTime,
    pub synthetic: bool,
}

impl LatencySample {
    pub(crate) fn real(latency: Duration) -> Self {
        Self {
            latency,
            at: SystemTime::now(),
            synthetic: false,
        }
    }

    pub(crate) fn synthetic(latency: Duration) -> Self {
        Self {
            latency,
            at: SystemTime::now(),
            synthetic: true,
        }
    }
}

pub(crate) struct Latencies10 {
    buf: Vec<LatencySample>,
    head: usize,
    len: usize,
    cap: usize,
}

impl Latencies10 {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            buf: vec![LatencySample::real(Duration::ZERO); n],
            head: 0,
            len: 0,
            cap: n,
        }
    }

    pub(crate) fn append(&mut self, sample: LatencySample) {
        if self.len < self.cap {
            self.buf[self.len] = sample;
            self.len += 1;
        } else {
            self.buf[self.head] = sample;
            self.head = (self.head + 1) % self.cap;
        }
    }

    fn last_index(&self) -> Option<usize> {
        if self.len == 0 {
            return None;
        }
        let idx = if self.len < self.cap {
            self.len - 1
        } else {
            (self.head + self.cap - 1) % self.cap
        };
        Some(idx)
    }

    /// Latest sample's latency, synthetic included — selection semantics.
    pub(crate) fn last(&self) -> Option<Duration> {
        Some(self.buf[self.last_index()?].latency)
    }

    /// Latest REAL (non-synthetic) sample, scanning back from the tail —
    /// display semantics (clash delay history).
    pub(crate) fn last_real_sample(&self) -> Option<LatencySample> {
        let start = self.last_index()?;
        for i in 0..self.len {
            // Walk backwards through the logical order (newest first).
            let idx = if self.len < self.cap {
                start - i
            } else {
                (start + self.cap - i) % self.cap
            };
            let sample = self.buf[idx];
            if !sample.synthetic {
                return Some(sample);
            }
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.len
    }
}

pub(crate) struct SyncLatencies10 {
    inner: Mutex<Latencies10>,
}

impl SyncLatencies10 {
    pub(crate) fn new(n: usize) -> Self {
        Self {
            inner: Mutex::new(Latencies10::new(n)),
        }
    }

    pub(crate) fn append(&self, sample: LatencySample) {
        self.inner.lock().append(sample);
    }

    pub(crate) fn last(&self) -> Option<Duration> {
        self.inner.lock().last()
    }

    pub(crate) fn last_real_sample(&self) -> Option<LatencySample> {
        self.inner.lock().last_real_sample()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real(ms: u64) -> LatencySample {
        LatencySample::real(Duration::from_millis(ms))
    }

    #[test]
    fn test_append_and_last() {
        let mut l = Latencies10::new(10);
        l.append(real(5));
        l.append(real(15));
        assert_eq!(l.last(), Some(Duration::from_millis(15)));
        assert_eq!(l.count(), 2);
    }

    #[test]
    fn test_ring_overflow() {
        let mut l = Latencies10::new(3);
        l.append(real(1000));
        l.append(real(2000));
        l.append(real(3000));
        l.append(real(4000));
        assert_eq!(l.last(), Some(Duration::from_secs(4)));
        assert_eq!(l.count(), 3);
    }

    #[test]
    fn test_empty() {
        let l = Latencies10::new(5);
        assert_eq!(l.last(), None);
        assert_eq!(l.count(), 0);
    }

    #[test]
    fn test_last_real_sample_skips_synthetic() {
        let mut l = Latencies10::new(5);
        l.append(real(100));
        l.append(LatencySample::synthetic(Duration::from_secs(10)));
        // Selection path sees the synthetic timeout...
        assert_eq!(l.last(), Some(Duration::from_secs(10)));
        // ...display path sees the last real measurement.
        let sample = l.last_real_sample().expect("real sample");
        assert_eq!(sample.latency, Duration::from_millis(100));
        assert!(!sample.synthetic);

        // A ring full of only synthetic samples yields nothing to display.
        let mut l2 = Latencies10::new(3);
        l2.append(LatencySample::synthetic(Duration::from_secs(10)));
        assert!(l2.last_real_sample().is_none());
    }
}

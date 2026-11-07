//! Boundary-only clock observations; overlap is not proof of suspend exclusion.

use std::io;

use nix::sys::time::TimeSpec;
use nix::time::{ClockId, clock_getres, clock_gettime};

fn timespec_ns(value: TimeSpec) -> io::Result<u64> {
    let seconds =
        u64::try_from(value.tv_sec()).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let nanos =
        u64::try_from(value.tv_nsec()).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if nanos >= 1_000_000_000 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(nanos))
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

pub(crate) fn boottime_ns() -> io::Result<u64> {
    timespec_ns(clock_gettime(ClockId::CLOCK_BOOTTIME)?)
}

fn resolutions() -> Result<(u64, u64), &'static str> {
    let monotonic = timespec_ns(
        clock_getres(ClockId::CLOCK_MONOTONIC).map_err(|_| "clock_resolution_unavailable")?,
    )
    .map_err(|_| "clock_resolution_invalid")?;
    let boot = timespec_ns(
        clock_getres(ClockId::CLOCK_BOOTTIME).map_err(|_| "clock_resolution_unavailable")?,
    )
    .map_err(|_| "clock_resolution_invalid")?;
    if monotonic == 0 || boot == 0 || monotonic.checked_add(boot).is_none() {
        return Err("clock_resolution_invalid");
    }
    Ok((monotonic, boot))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ClockObservation {
    pub boot_ns: u64,
    pub continuous: bool,
    pub discontinuity: bool,
    pub offset_changed: bool,
    pub monotonic_resolution_ns: u64,
    pub boottime_resolution_ns: u64,
    pub read_duration_ns: u64,
    pub raw_offset_low_ns: i128,
    pub raw_offset_high_ns: i128,
    pub baseline_offset_low_ns: i128,
    pub baseline_offset_high_ns: i128,
}

#[derive(Clone, Copy)]
struct Sample {
    before: u64,
    boot: u64,
    after: u64,
}

pub(crate) struct SchedulingClock {
    resolutions: Option<(u64, u64)>,
    previous: Option<Sample>,
    baseline: Option<(i128, i128)>,
}

impl SchedulingClock {
    pub(crate) fn new() -> Self {
        Self {
            resolutions: resolutions().ok(),
            previous: None,
            baseline: None,
        }
    }

    pub(crate) fn sample(
        &mut self,
        max_gap_ns: Option<u64>,
    ) -> Result<ClockObservation, &'static str> {
        let result = (|| {
            if self.resolutions.is_none() {
                self.resolutions = Some(resolutions()?);
            }
            let before = timespec_ns(
                clock_gettime(ClockId::CLOCK_MONOTONIC).map_err(|_| "clock_unavailable")?,
            )
            .map_err(|_| "clock_conversion_invalid")?;
            let boot = boottime_ns().map_err(|_| "clock_unavailable")?;
            let after = timespec_ns(
                clock_gettime(ClockId::CLOCK_MONOTONIC).map_err(|_| "clock_unavailable")?,
            )
            .map_err(|_| "clock_conversion_invalid")?;
            Ok(Sample {
                before,
                boot,
                after,
            })
        })();
        self.accept(result, max_gap_ns)
    }

    fn accept(
        &mut self,
        sample: Result<Sample, &'static str>,
        max_gap_ns: Option<u64>,
    ) -> Result<ClockObservation, &'static str> {
        let result = sample.and_then(|sample| self.observe(sample, max_gap_ns));
        if result.is_err() {
            self.previous = None;
            self.baseline = None;
        }
        result
    }

    fn observe(
        &mut self,
        sample: Sample,
        max_gap_ns: Option<u64>,
    ) -> Result<ClockObservation, &'static str> {
        let (monotonic_resolution_ns, boottime_resolution_ns) =
            self.resolutions.ok_or("clock_resolution_unavailable")?;
        if sample.before > sample.after
            || self.previous.is_some_and(|previous| {
                sample.before < previous.after || sample.boot < previous.boot
            })
        {
            return Err("clock_backwards");
        }
        let q = monotonic_resolution_ns
            .checked_add(boottime_resolution_ns)
            .filter(|_| monotonic_resolution_ns != 0 && boottime_resolution_ns != 0)
            .ok_or("clock_resolution_invalid")?;
        let raw_low = i128::from(sample.boot) - i128::from(sample.after);
        let raw_high = i128::from(sample.boot) - i128::from(sample.before);
        let low = raw_low
            .checked_sub(i128::from(q))
            .ok_or("clock_interval_overflow")?;
        let high = raw_high
            .checked_add(i128::from(q))
            .ok_or("clock_interval_overflow")?;
        let gap = self.previous.is_some_and(|previous| {
            max_gap_ns.is_some_and(|limit| sample.boot - previous.boot >= limit)
        });
        let offset_changed = self
            .baseline
            .is_some_and(|(old_low, old_high)| old_low > high || old_high < low);
        let mut continuous = false;
        let mut discontinuity = gap;
        let baseline = match self.baseline {
            Some((old_low, old_high)) if !gap => {
                let intersection = (old_low.max(low), old_high.min(high));
                if intersection.0 <= intersection.1 {
                    continuous = true;
                    intersection
                } else {
                    discontinuity = true;
                    (low, high)
                }
            }
            _ => (low, high),
        };
        self.previous = Some(sample);
        self.baseline = Some(baseline);
        Ok(ClockObservation {
            boot_ns: sample.boot,
            continuous,
            discontinuity,
            offset_changed,
            monotonic_resolution_ns,
            boottime_resolution_ns,
            read_duration_ns: sample.after - sample.before,
            raw_offset_low_ns: raw_low,
            raw_offset_high_ns: raw_high,
            baseline_offset_low_ns: baseline.0,
            baseline_offset_high_ns: baseline.1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clock() -> SchedulingClock {
        SchedulingClock {
            resolutions: Some((2, 3)),
            previous: None,
            baseline: None,
        }
    }

    fn sample(clock: &mut SchedulingClock, before: u64, boot: u64, after: u64) -> ClockObservation {
        clock
            .accept(
                Ok(Sample {
                    before,
                    boot,
                    after,
                }),
                Some(100),
            )
            .unwrap()
    }

    #[test]
    fn signed_bracket_retains_intersection_not_last_interval() {
        let mut clock = clock();
        let first = sample(&mut clock, 10, 12, 20);
        assert!(!first.continuous && !first.discontinuity);
        assert_eq!((first.raw_offset_low_ns, first.raw_offset_high_ns), (-8, 2));
        assert_eq!(
            (first.baseline_offset_low_ns, first.baseline_offset_high_ns),
            (-13, 7)
        );
        assert_eq!(
            (first.monotonic_resolution_ns, first.boottime_resolution_ns),
            (2, 3)
        );
        assert_eq!(first.read_duration_ns, 10);
        let second = sample(&mut clock, 30, 35, 32);
        assert!(second.continuous);
        assert_eq!(
            (
                second.baseline_offset_low_ns,
                second.baseline_offset_high_ns
            ),
            (-2, 7)
        );
        let third = sample(&mut clock, 40, 51, 42);
        assert!(third.continuous);
        assert_eq!(
            (third.baseline_offset_low_ns, third.baseline_offset_high_ns),
            (4, 7)
        );
        // Overlaps the last sample, but not the retained intersection.
        let disjoint = sample(&mut clock, 50, 65, 52);
        assert!(disjoint.discontinuity && !disjoint.continuous);
        assert!(sample(&mut clock, 60, 75, 62).continuous);
    }

    #[test]
    fn gaps_backwards_and_errors_never_restore_old_epoch() {
        let mut clock = clock();
        sample(&mut clock, 0, 10, 2);
        let gap = sample(&mut clock, 100, 110, 102);
        assert!(gap.discontinuity && !gap.continuous);
        for bad in [
            Sample {
                before: 101,
                boot: 120,
                after: 103,
            },
            Sample {
                before: 200,
                boot: 100,
                after: 202,
            },
            Sample {
                before: 200,
                boot: 210,
                after: 199,
            },
        ] {
            assert!(clock.accept(Ok(bad), Some(100)).is_err());
            assert!(clock.baseline.is_none());
            assert!(!sample(&mut clock, 100, 110, 102).continuous);
        }
        assert!(clock.accept(Err("clock_unavailable"), Some(100)).is_err());
        assert!(!sample(&mut clock, 200, 210, 202).continuous);
        clock.resolutions = Some((u64::MAX, 1));
        assert!(
            clock
                .accept(
                    Ok(Sample {
                        before: 300,
                        boot: 310,
                        after: 302
                    }),
                    None
                )
                .is_err()
        );
        assert!(clock.baseline.is_none());
    }

    #[test]
    fn conversion_rejects_negative_and_overflow() {
        assert!(timespec_ns(TimeSpec::new(-1, 0)).is_err());
        assert!(timespec_ns(TimeSpec::new(i64::MAX, 0)).is_err());
        assert_eq!(timespec_ns(TimeSpec::new(2, 3)).unwrap(), 2_000_000_003);
    }

    #[test]
    fn positive_width_observed_continuity_allows_two_high_windows() {
        use super::super::window::ObservationWindows;
        use honk_config::datapath::BusyPollConfig;

        let config = BusyPollConfig {
            pps_enter: 10,
            pps_exit: 5,
            observation_window_us: 1_000_000,
            enter_windows: 2,
            exit_windows: 1,
            max_busy_us: 100,
            empty_rounds: 2,
            budget_window_us: 10_000,
            budget_us: 1_000,
            calibration: None,
        };
        let mut clock = clock();
        let mut windows = ObservationWindows::new();
        let t = 1_000_000_000;
        for (index, now) in [0, t / 2, t, t + t / 2, 2 * t].into_iter().enumerate() {
            let observation = clock
                .accept(
                    Ok(Sample {
                        before: now + 100,
                        boot: now + 102,
                        after: now + 104,
                    }),
                    Some(t),
                )
                .unwrap();
            assert!(observation.baseline_offset_low_ns < observation.baseline_offset_high_ns);
            if !observation.continuous {
                windows.reset();
            }
            let rx = if index == 0 || index == 2 { 11 } else { 0 };
            let status = windows
                .observe(observation.boot_ns, rx, 0, &config)
                .unwrap();
            assert_eq!(status.high, index == 4);
        }
    }

    #[test]
    fn native_clock_helpers_return_checked_resolutions_and_time() {
        let start = boottime_ns().unwrap();
        let mut clock = SchedulingClock::new();
        let first = clock.sample(None).unwrap();
        assert!(first.boot_ns >= start);
        assert!(first.monotonic_resolution_ns > 0);
        assert!(first.boottime_resolution_ns > 0);
        assert!(!first.continuous);
    }

    #[test]
    fn ordinary_gap_rebases_qualification_without_inventing_an_offset_change() {
        let mut clock = SchedulingClock {
            resolutions: Some((1, 1)),
            previous: None,
            baseline: None,
        };
        clock
            .accept(
                Ok(Sample {
                    before: 100,
                    boot: 1_000,
                    after: 110,
                }),
                Some(50),
            )
            .unwrap();
        let gap = clock
            .accept(
                Ok(Sample {
                    before: 200,
                    boot: 1_100,
                    after: 210,
                }),
                Some(50),
            )
            .unwrap();
        assert!(!gap.continuous);
        assert!(gap.discontinuity);
        assert!(
            !gap.offset_changed,
            "an idle gap is not evidence to recreate a pinned policy reader"
        );
        let next = clock
            .accept(
                Ok(Sample {
                    before: 211,
                    boot: 1_111,
                    after: 221,
                }),
                Some(50),
            )
            .unwrap();
        assert!(next.continuous);
        assert!(!next.offset_changed);
        let changed = clock
            .accept(
                Ok(Sample {
                    before: 240,
                    boot: 1_240,
                    after: 250,
                }),
                Some(50),
            )
            .unwrap();
        assert!(changed.offset_changed);
        assert!(!changed.continuous);
    }
}

//! Nonoverlapping windows count round deltas at their actual completion boundary.

use honk_config::datapath::BusyPollConfig;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WindowStatus {
    pub high: bool,
    pub low: bool,
    pub rx_high_windows: u16,
    pub tx_high_windows: u16,
    pub low_windows: u16,
}

pub(crate) struct ObservationWindows {
    parameters: Option<(u32, u32, u32, u16, u16)>,
    end_ns: u64,
    last_ns: u64,
    rx: u64,
    tx: u64,
    status: WindowStatus,
}

impl ObservationWindows {
    pub(crate) fn new() -> Self {
        Self {
            parameters: None,
            end_ns: 0,
            last_ns: 0,
            rx: 0,
            tx: 0,
            status: WindowStatus::default(),
        }
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }

    pub(crate) fn observe(
        &mut self,
        now_ns: u64,
        qualified_rx: u64,
        published_tx: u64,
        config: &BusyPollConfig,
    ) -> Result<WindowStatus, &'static str> {
        let result = self.observe_inner(now_ns, qualified_rx, published_tx, config);
        if result.is_err() {
            self.reset();
        }
        result
    }

    fn observe_inner(
        &mut self,
        now_ns: u64,
        qualified_rx: u64,
        published_tx: u64,
        config: &BusyPollConfig,
    ) -> Result<WindowStatus, &'static str> {
        if config.observation_window_us == 0
            || config.observation_window_us > 60_000_000
            || config.pps_enter == 0
            || config.pps_exit >= config.pps_enter
            || config.enter_windows < 2
            || config.exit_windows == 0
        {
            return Err("observation_parameters_invalid");
        }
        let window_ns = u64::from(config.observation_window_us)
            .checked_mul(1_000)
            .ok_or("observation_overflow")?;
        let parameters = (
            config.observation_window_us,
            config.pps_enter,
            config.pps_exit,
            config.enter_windows,
            config.exit_windows,
        );
        let restart = self.parameters != Some(parameters)
            || now_ns < self.last_ns
            || now_ns - self.last_ns >= window_ns
            || (now_ns >= self.end_ns && now_ns - self.end_ns >= window_ns);
        if restart {
            self.reset();
            self.end_ns = now_ns
                .checked_add(window_ns)
                .ok_or("observation_overflow")?;
            self.parameters = Some(parameters);
        } else if now_ns >= self.end_ns {
            let rx = u128::from(self.rx)
                .checked_mul(1_000_000_000)
                .ok_or("observation_overflow")?;
            let tx = u128::from(self.tx)
                .checked_mul(1_000_000_000)
                .ok_or("observation_overflow")?;
            let enter = u128::from(config.pps_enter)
                .checked_mul(u128::from(window_ns))
                .ok_or("observation_overflow")?;
            let exit = u128::from(config.pps_exit)
                .checked_mul(u128::from(window_ns))
                .ok_or("observation_overflow")?;
            self.status.rx_high_windows = dwell(
                self.status.rx_high_windows,
                rx > enter,
                config.enter_windows,
            )?;
            self.status.tx_high_windows = dwell(
                self.status.tx_high_windows,
                tx > enter,
                config.enter_windows,
            )?;
            self.status.low_windows = dwell(
                self.status.low_windows,
                rx < exit && tx < exit,
                config.exit_windows,
            )?;
            self.status.high = self.status.rx_high_windows == config.enter_windows
                || self.status.tx_high_windows == config.enter_windows;
            self.status.low = self.status.low_windows == config.exit_windows;
            self.end_ns = self
                .end_ns
                .checked_add(window_ns)
                .ok_or("observation_overflow")?;
            self.rx = 0;
            self.tx = 0;
        }
        // Close the old window before assigning this boundary's complete round.
        self.rx = self
            .rx
            .checked_add(qualified_rx)
            .ok_or("observation_count_overflow")?;
        self.tx = self
            .tx
            .checked_add(published_tx)
            .ok_or("observation_count_overflow")?;
        self.last_ns = now_ns;
        Ok(self.status)
    }
}

fn dwell(previous: u16, qualifies: bool, target: u16) -> Result<u16, &'static str> {
    if !qualifies {
        Ok(0)
    } else if previous >= target {
        Ok(target)
    } else {
        previous.checked_add(1).ok_or("observation_overflow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> BusyPollConfig {
        BusyPollConfig {
            pps_enter: 10,
            pps_exit: 5,
            observation_window_us: 1_000_000,
            enter_windows: 2,
            exit_windows: 2,
            max_busy_us: 100,
            empty_rounds: 2,
            budget_window_us: 10_000,
            budget_us: 1_000,
            calibration: None,
        }
    }

    const T: u64 = 1_000_000_000;

    fn close(
        windows: &mut ObservationWindows,
        start: u64,
        rx: u64,
        tx: u64,
        config: &BusyPollConfig,
    ) -> WindowStatus {
        windows.observe(start + T / 2, rx, tx, config).unwrap();
        windows.observe(start + T, 0, 0, config).unwrap()
    }

    #[test]
    fn directions_do_not_combine_and_entry_requires_two_complete_windows() {
        let config = config();
        let mut windows = ObservationWindows::new();
        assert!(!windows.observe(0, 0, 0, &config).unwrap().high);
        let first = close(&mut windows, 0, 11, 0, &config);
        assert_eq!(first.rx_high_windows, 1);
        assert!(!first.high);
        let second = close(&mut windows, T, 0, 11, &config);
        assert_eq!((second.rx_high_windows, second.tx_high_windows), (0, 1));
        assert!(!second.high);
        assert!(close(&mut windows, 2 * T, 0, 11, &config).high);
        let sum_only = close(&mut windows, 3 * T, 6, 6, &config);
        assert!(!sum_only.high && !sum_only.low);
    }

    #[test]
    fn equality_and_hysteresis_break_dwell_and_low_requires_both() {
        let config = config();
        let mut windows = ObservationWindows::new();
        windows.observe(0, 0, 0, &config).unwrap();
        close(&mut windows, 0, 11, 0, &config);
        let equal_enter = close(&mut windows, T, 10, 0, &config);
        assert_eq!(equal_enter.rx_high_windows, 0);
        assert_eq!(close(&mut windows, 2 * T, 0, 4, &config).low_windows, 1);
        assert_eq!(close(&mut windows, 3 * T, 0, 5, &config).low_windows, 0);
        assert_eq!(close(&mut windows, 4 * T, 0, 4, &config).low_windows, 1);
        assert_eq!(close(&mut windows, 5 * T, 6, 0, &config).low_windows, 0);
        close(&mut windows, 6 * T, 0, 0, &config);
        assert!(close(&mut windows, 7 * T, 0, 0, &config).low);
    }

    #[test]
    fn boundary_delta_goes_only_into_next_fixed_window() {
        let config = config();
        let mut windows = ObservationWindows::new();
        windows.observe(0, 0, 0, &config).unwrap();
        windows.observe(T / 2, 0, 0, &config).unwrap();
        let first = windows.observe(T + 10, 11, 0, &config).unwrap();
        assert_eq!(first.rx_high_windows, 0);
        windows.observe(T + T / 2, 0, 0, &config).unwrap();
        assert_eq!(
            windows
                .observe(2 * T, 0, 0, &config)
                .unwrap()
                .rx_high_windows,
            1
        );
        assert_eq!(windows.end_ns, 3 * T);
    }

    #[test]
    fn gaps_missed_windows_backwards_reload_and_errors_reset_without_replay() {
        let mut config = config();
        let mut windows = ObservationWindows::new();
        windows.observe(0, 11, 0, &config).unwrap();
        close(&mut windows, 0, 0, 0, &config);
        let gap = windows.observe(2 * T, 11, 0, &config).unwrap();
        assert_eq!(gap.rx_high_windows, 0);
        assert_eq!(windows.end_ns, 3 * T);
        assert_eq!(
            windows
                .observe(100 * T, 11, 0, &config)
                .unwrap()
                .rx_high_windows,
            0
        );
        assert_eq!(
            windows.observe(T, 11, 0, &config).unwrap().rx_high_windows,
            0
        );
        close(&mut windows, T, 0, 0, &config);
        config.pps_enter += 1;
        assert_eq!(
            windows
                .observe(2 * T + 1, 0, 0, &config)
                .unwrap()
                .rx_high_windows,
            0
        );
        windows.reset();
        windows.observe(0, u64::MAX, 0, &config).unwrap();
        assert!(windows.observe(1, 1, 0, &config).is_err());
        assert!(windows.parameters.is_none());
        assert!(windows.observe(u64::MAX, 0, 0, &config).is_err());
        assert!(windows.parameters.is_none());
        assert!(!windows.observe(0, 0, 0, &config).unwrap().high);
    }
}

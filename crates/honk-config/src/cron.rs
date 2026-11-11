//! Five-field cron expressions (`minute hour day-of-month month day-of-week`)
//! for scheduled downloads, evaluated in a caller-supplied time zone.

use std::fmt;

use chrono::{DateTime, Datelike as _, NaiveDate, TimeZone, Utc};
use serde::{Deserialize, Serialize};

/// The most times an expression may fire in one day, which keeps scheduled
/// downloads as rare as the six-hour minimum of the interval schedule.
pub const MAX_FIRES_PER_DAY: u32 = 4;

/// One Gregorian cycle: every month, day and weekday combination recurs
/// within it, so the search finds any time an accepted expression names.
const SEARCH_DAYS: usize = 146_097;

const DAYS_IN_MONTH: [u32; 12] = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// `(name, min, max)` of each field, in order.
const FIELDS: [(&str, u32, u32); 5] = [
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day-of-month", 1, 31),
    ("month", 1, 12),
    ("day-of-week", 0, 7),
];

/// A parsed expression. Each field is a set of bits; day of week 7 is folded
/// into 0, both Sunday.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Cron {
    expression: String,
    minutes: u64,
    hours: u64,
    days: u64,
    months: u64,
    weekdays: u64,
    /// Day of month or day of week starts with `*`, so a day has to match
    /// both; otherwise matching either is enough, as in Vixie cron.
    both_days: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CronError {
    #[error("expected five fields: minute hour day-of-month month day-of-week")]
    FieldCount,
    #[error("the {0} field is invalid")]
    Field(&'static str),
    #[error("the expression fires more than {MAX_FIRES_PER_DAY} times a day")]
    TooFrequent,
    #[error("the expression never fires")]
    NeverFires,
}

impl Cron {
    /// Accepts `*`, numbers, lists `a,b`, ranges `a-b` and steps `*/n` and
    /// `a-b/n` in each field; names, macros and a seconds field are refused.
    pub fn parse(expression: &str) -> Result<Self, CronError> {
        let fields: Vec<&str> = expression.split_ascii_whitespace().collect();
        let [_, _, day, _, weekday] = fields[..] else {
            return Err(CronError::FieldCount);
        };
        let mut sets = [0; 5];
        for ((set, text), (name, min, max)) in sets.iter_mut().zip(&fields).zip(FIELDS) {
            *set = parse_field(text, min, max).ok_or(CronError::Field(name))?;
        }
        let [minutes, hours, days, months, weekdays] = sets;
        let cron = Self {
            expression: fields.join(" "),
            minutes,
            hours,
            days,
            months,
            weekdays: (weekdays | weekdays >> 7) & 0x7f,
            both_days: day.starts_with('*') || weekday.starts_with('*'),
        };
        if minutes.count_ones() * hours.count_ones() > MAX_FIRES_PER_DAY {
            return Err(CronError::TooFrequent);
        }
        let can_fire = (1..=12).any(|month| {
            (1..=DAYS_IN_MONTH[month as usize - 1])
                .any(|day| (0..7).any(|weekday| cron.matches(month, day, weekday)))
        });
        if !can_fire {
            return Err(CronError::NeverFires);
        }
        Ok(cron)
    }

    pub fn as_str(&self) -> &str {
        &self.expression
    }

    /// The first time strictly after `after` that the expression names in
    /// `zone`'s local time. A local time that a forward offset change skips
    /// is skipped too; one that a backward change repeats fires only the
    /// first time.
    pub fn next_after<Tz: TimeZone>(
        &self,
        after: DateTime<Utc>,
        zone: &Tz,
    ) -> Option<DateTime<Utc>> {
        // A day earlier, because an offset change can put a time of the
        // previous local day after `after`.
        let first = after.with_timezone(zone).date_naive().pred_opt()?;
        first
            .iter_days()
            .take(SEARCH_DAYS)
            .filter(|date| self.fires_on(*date))
            .flat_map(|date| {
                self.times().filter_map(move |(hour, minute)| {
                    let local = date.and_hms_opt(hour, minute, 0)?;
                    zone.from_local_datetime(&local).earliest()
                })
            })
            .map(|time| time.with_timezone(&Utc))
            .find(|time| *time > after)
    }

    fn fires_on(&self, date: NaiveDate) -> bool {
        self.matches(
            date.month(),
            date.day(),
            date.weekday().num_days_from_sunday(),
        )
    }

    fn matches(&self, month: u32, day: u32, weekday: u32) -> bool {
        let by_day = contains(self.days, day);
        let by_weekday = contains(self.weekdays, weekday);
        contains(self.months, month)
            && if self.both_days {
                by_day && by_weekday
            } else {
                by_day || by_weekday
            }
    }

    /// `(hour, minute)` in ascending order.
    fn times(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        members(self.hours, 24)
            .flat_map(move |hour| members(self.minutes, 60).map(move |minute| (hour, minute)))
    }
}

fn contains(set: u64, value: u32) -> bool {
    set >> value & 1 == 1
}

fn members(set: u64, end: u32) -> impl Iterator<Item = u32> {
    (0..end).filter(move |value| contains(set, *value))
}

fn parse_field(text: &str, min: u32, max: u32) -> Option<u64> {
    let mut set = 0;
    for item in text.split(',') {
        let (range, step) = match item.split_once('/') {
            Some((range, step)) => (range, Some(number(step).filter(|step| *step > 0)?)),
            None => (item, None),
        };
        let (low, high) = if range == "*" {
            (min, max)
        } else if let Some((low, high)) = range.split_once('-') {
            (number(low)?, number(high)?)
        } else if step.is_none() {
            let value = number(range)?;
            (value, value)
        } else {
            return None;
        };
        if low < min || high > max || low > high {
            return None;
        }
        for value in (low..=high).step_by(step.unwrap_or(1) as usize) {
            set |= 1 << value;
        }
    }
    Some(set)
}

fn number(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

impl fmt::Display for Cron {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.expression)
    }
}

impl TryFrom<String> for Cron {
    type Error = CronError;

    fn try_from(expression: String) -> Result<Self, CronError> {
        Self::parse(&expression)
    }
}

impl From<Cron> for String {
    fn from(cron: Cron) -> Self {
        cron.expression
    }
}

#[cfg(test)]
mod tests;

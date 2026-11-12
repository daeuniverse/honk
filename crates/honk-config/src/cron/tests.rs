use chrono::{FixedOffset, Local, NaiveDateTime};

use super::*;

fn utc(text: &str) -> DateTime<Utc> {
    NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M")
        .unwrap()
        .and_utc()
}

fn next(expression: &str, after: &str) -> Option<DateTime<Utc>> {
    Cron::parse(expression)
        .unwrap()
        .next_after(utc(after), &Utc)
}

#[test]
fn fields_take_lists_ranges_and_steps() {
    let cron = Cron::parse(" 0,30  1-3/2 */10 1-12 * ").unwrap();
    assert_eq!(cron.as_str(), "0,30 1-3/2 */10 1-12 *");
    assert_eq!(
        cron.times().collect::<Vec<_>>(),
        [(1, 0), (1, 30), (3, 0), (3, 30)]
    );
    assert_eq!(cron.days, 1 << 1 | 1 << 11 | 1 << 21 | 1 << 31);
    assert_eq!(cron.months, 0x1ffe);
    let sunday = Cron::parse("0 3 * * 7").unwrap();
    assert_eq!(sunday.weekdays, 1);
    assert_eq!(sunday, Cron::parse("0 3 * * 0").unwrap().with("0 3 * * 7"));
    assert_eq!(Cron::parse("0 3 * * 5-7").unwrap().weekdays, 0b110_0001);
}

impl Cron {
    fn with(mut self, expression: &str) -> Self {
        self.expression = expression.to_owned();
        self
    }
}

#[test]
fn malformed_expressions_name_the_failing_field() {
    for (expression, error) in [
        ("", CronError::FieldCount),
        ("0 3 * *", CronError::FieldCount),
        ("0 0 3 * * *", CronError::FieldCount),
        ("60 3 * * *", CronError::Field("minute")),
        ("0 24 * * *", CronError::Field("hour")),
        ("0 3 0 * *", CronError::Field("day-of-month")),
        ("0 3 32 * *", CronError::Field("day-of-month")),
        ("0 3 * 13 *", CronError::Field("month")),
        ("0 3 * JAN *", CronError::Field("month")),
        ("0 3 * * 8", CronError::Field("day-of-week")),
        ("0 3 * * MON", CronError::Field("day-of-week")),
        ("0 3-1 * * *", CronError::Field("hour")),
        ("0 */0 * * *", CronError::Field("hour")),
        ("0 3/2 * * *", CronError::Field("hour")),
        ("0 1,,2 * * *", CronError::Field("hour")),
        ("0 -1 * * *", CronError::Field("hour")),
        ("0 +3 * * *", CronError::Field("hour")),
        ("@daily", CronError::FieldCount),
    ] {
        assert_eq!(Cron::parse(expression), Err(error), "{expression:?}");
    }
}

#[test]
fn more_than_four_fires_a_day_are_refused() {
    assert!(Cron::parse("0 */6 * * *").is_ok());
    assert!(Cron::parse("0,15 1,13 * * *").is_ok());
    assert_eq!(
        Cron::parse("0 */5 * * *"),
        Err(CronError::TooFrequent),
        "five hours"
    );
    assert_eq!(Cron::parse("* 3 * * *"), Err(CronError::TooFrequent));
    assert_eq!(
        Cron::parse("0,20,40 1,2 * * *"),
        Err(CronError::TooFrequent)
    );
}

#[test]
fn an_expression_that_names_no_date_is_refused() {
    for expression in ["0 0 31 2 *", "0 0 30 2 *", "0 0 31 4,6,9,11 *"] {
        assert_eq!(
            Cron::parse(expression),
            Err(CronError::NeverFires),
            "{expression}"
        );
    }
    // A weekday widens a restricted day of month, so this fires on Mondays.
    assert!(Cron::parse("0 0 31 2 1").is_ok());
    let leap = Cron::parse("0 0 29 2 *").unwrap();
    assert_eq!(
        leap.next_after(utc("2026-11-11 00:00"), &Utc),
        Some(utc("2028-02-29 00:00"))
    );
}

#[test]
fn the_next_fire_is_strictly_after_the_reference() {
    assert_eq!(
        next("0 3 * * *", "2026-11-11 02:59"),
        Some(utc("2026-11-11 03:00"))
    );
    assert_eq!(
        next("0 3 * * *", "2026-11-11 03:00"),
        Some(utc("2026-11-12 03:00"))
    );
    assert_eq!(
        next("30 1,13 * * *", "2026-11-11 12:00"),
        Some(utc("2026-11-11 13:30"))
    );
}

#[test]
fn the_next_fire_crosses_month_and_year_boundaries() {
    assert_eq!(
        next("0 3 1 * *", "2026-11-11 00:00"),
        Some(utc("2026-12-01 03:00"))
    );
    assert_eq!(
        next("0 3 31 * *", "2026-11-11 00:00"),
        Some(utc("2026-12-31 03:00"))
    );
    assert_eq!(
        next("0 3 * 1 *", "2026-11-11 00:00"),
        Some(utc("2027-01-01 03:00"))
    );
    assert_eq!(
        next("0 0 1 1 *", "2026-12-31 23:59"),
        Some(utc("2027-01-01 00:00"))
    );
}

#[test]
fn day_of_month_and_day_of_week_combine_as_in_cron() {
    // 2026-11-11 is a Wednesday. Both restricted: either matches.
    assert_eq!(
        next("0 3 15 * 5", "2026-11-11 04:00"),
        Some(utc("2026-11-13 03:00"))
    );
    assert_eq!(
        next("0 3 12 * 5", "2026-11-11 04:00"),
        Some(utc("2026-11-12 03:00"))
    );
    // One side starts with `*`: both have to match.
    assert_eq!(
        next("0 3 * * 5", "2026-11-11 04:00"),
        Some(utc("2026-11-13 03:00"))
    );
    assert_eq!(
        next("0 3 */2 * 5", "2026-11-11 04:00"),
        Some(utc("2026-11-13 03:00")),
        "the 13th is odd and a Friday"
    );
    assert_eq!(
        next("0 3 */2 * 0", "2026-11-11 04:00"),
        Some(utc("2026-11-15 03:00"))
    );
    assert_eq!(
        next("0 3 1 * *", "2026-11-11 04:00"),
        Some(utc("2026-12-01 03:00"))
    );
}

#[test]
fn local_times_follow_the_zone() {
    let cron = Cron::parse("0 3 * * *").unwrap();
    let east = FixedOffset::east_opt(10 * 3600).unwrap();
    assert_eq!(
        cron.next_after(utc("2026-11-11 00:00"), &east),
        Some(utc("2026-11-11 17:00")),
        "03:00 at UTC+10 is 17:00 UTC the day before"
    );
    let west = FixedOffset::west_opt(5 * 3600).unwrap();
    assert_eq!(
        cron.next_after(utc("2026-11-11 00:00"), &west),
        Some(utc("2026-11-11 08:00"))
    );
}

#[test]
fn local_dst_skips_gaps_and_fires_once_at_the_first_fold() {
    const CHILD: &str = "HONK_CRON_LOCAL_DST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cron::tests::local_dst_skips_gaps_and_fires_once_at_the_first_fold",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("TZ", "EST5EDT,M3.2.0/2,M11.1.0/2")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    for (expression, expected) in [
        ("59 1 * * *", "2026-03-08 06:59"),
        ("0 2 * * *", "2026-03-09 06:00"),
        ("1 2 * * *", "2026-03-09 06:01"),
        ("30 2 * * *", "2026-03-09 06:30"),
        ("0 3 * * *", "2026-03-08 07:00"),
    ] {
        assert_eq!(
            Cron::parse(expression)
                .unwrap()
                .next_after(utc("2026-03-07 12:00"), &Local),
            Some(utc(expected)),
            "{expression}"
        );
    }
    let cron = Cron::parse("30 1 * * *").unwrap();
    let first = cron.next_after(utc("2026-10-31 12:00"), &Local);
    assert_eq!(first, Some(utc("2026-11-01 05:30")));
    assert_eq!(
        cron.next_after(first.unwrap(), &Local),
        Some(utc("2026-11-02 06:30"))
    );
}

#[test]
fn expressions_round_trip_as_strings() {
    let cron = Cron::parse("0 3 * * *").unwrap();
    let json = serde_json::to_string(&cron).unwrap();
    assert_eq!(json, r#""0 3 * * *""#);
    assert_eq!(serde_json::from_str::<Cron>(&json).unwrap(), cron);
    assert!(serde_json::from_str::<Cron>(r#""0 0 31 2 *""#).is_err());
    assert_eq!(cron.to_string(), "0 3 * * *");
}

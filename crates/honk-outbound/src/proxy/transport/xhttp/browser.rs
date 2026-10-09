//! Xray's default XHTTP request headers (`common/utils/browser.go`): Chrome `fetch()` on Windows.

use std::sync::LazyLock;

use http::{HeaderMap, HeaderName, HeaderValue, header};

/// Match Xray `common/utils/browser.go` at 836a6fed385b902e437dde43ee9adc82d23a5303.
pub(super) fn chrome_major_at(unix_secs: u64, r: f64) -> i64 {
    const CHROME_144_DAY: i64 = 1_768_262_400 / 86_400;
    let day = (unix_secs / 86_400) as i64;
    let random_delay = (r * r * 105.0).floor() as i64;
    144 + (day - CHROME_144_DAY - 35 - random_delay) / 35
}

fn chrome_major(unix_secs: u64) -> i64 {
    static RANDOM_FACTOR: LazyLock<f64> = LazyLock::new(rand::random::<f64>);
    chrome_major_at(unix_secs, *RANDOM_FACTOR)
}

/// Chromium's brand GREASE, as Xray's `getGreasedChUa(major, "chrome")`.
pub(super) fn sec_ch_ua(major: i64) -> String {
    const GREASE: [&str; 11] = [" ", "(", ":", "-", ".", "/", ")", ";", "=", "?", "_"];
    const VERSIONS: [&str; 3] = ["8", "99", "24"];
    const ORDERS: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let seed = major as usize;
    let brands = [
        format!(
            "\"Not{}A{}Brand\";v=\"{}\"",
            GREASE[seed % GREASE.len()],
            GREASE[(seed + 1) % GREASE.len()],
            VERSIONS[seed % VERSIONS.len()]
        ),
        format!("\"Chromium\";v=\"{major}\""),
        format!("\"Google Chrome\";v=\"{major}\""),
    ];
    let mut shuffled = [const { String::new() }; 3];
    for (brand, slot) in brands.into_iter().zip(ORDERS[seed % ORDERS.len()]) {
        shuffled[slot] = brand;
    }
    shuffled.join(", ")
}

/// Without a configured User-Agent, Xray sends every XHTTP request as a Chrome
/// `fetch()`; CDN bot filters reject the bare requests. A configured User-Agent,
/// including Xray's `chrome`/`firefox`/`edge`/`golang` keywords, is sent verbatim.
pub(super) fn apply_chrome_fetch(headers: &mut HeaderMap) {
    if headers.contains_key(header::USER_AGENT) {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let major = chrome_major(now);
    for (name, value) in [
        ("sec-ch-ua", sec_ch_ua(major)),
        ("sec-ch-ua-mobile", "?0".into()),
        ("sec-ch-ua-platform", "\"Windows\"".into()),
        ("dnt", "1".into()),
        (
            "user-agent",
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"
            ),
        ),
        ("accept-language", "en-US,en;q=0.9".into()),
        ("sec-fetch-mode", "cors".into()),
        ("sec-fetch-dest", "empty".into()),
        ("sec-fetch-site", "same-origin".into()),
    ] {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::try_from(value).expect("browser header values are ASCII"),
        );
    }
    for (name, value) in [
        ("priority", "u=1, i"),
        ("cache-control", "no-cache"),
        ("pragma", "no-cache"),
        ("accept", "*/*"),
    ] {
        headers
            .entry(HeaderName::from_static(name))
            .or_insert(HeaderValue::from_static(value));
    }
}

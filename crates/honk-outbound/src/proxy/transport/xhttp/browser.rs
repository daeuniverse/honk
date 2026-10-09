//! Xray's default XHTTP request headers (`common/utils/browser.go`): Chrome `fetch()` on Windows.

use http::{HeaderMap, HeaderName, HeaderValue, header};

/// Chrome 144 shipped on 2026-01-13. Xray advances one major per 25–45 days
/// from a CPU-seeded PRNG; the mean step keeps its estimate without the seed.
pub(super) fn chrome_major(unix_secs: u64) -> u64 {
    const CHROME_144: u64 = 1_768_262_400;
    144 + unix_secs.saturating_sub(CHROME_144) / (35 * 86_400)
}

/// Chromium's brand GREASE, as Xray's `getGreasedChUa(major, "chrome")`.
pub(super) fn sec_ch_ua(major: u64) -> String {
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

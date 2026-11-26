//! Shared semantic conversion helpers used by config adapters.

/// Fold parsed alias claims, retaining one equal value and rejecting clashes.
///
/// Parsing stays with each adapter so dialect-specific normalization and source
/// bytes remain local; this helper owns only the repeated equality rule.
pub fn coalesce_equal<T: PartialEq>(
    values: impl IntoIterator<Item = Result<Option<T>, &'static str>>,
    conflict: &'static str,
) -> Result<Option<T>, &'static str> {
    let mut resolved = None;
    for value in values.into_iter() {
        let Some(value) = value? else { continue };
        match &resolved {
            None => resolved = Some(value),
            Some(previous) if *previous == value => {}
            Some(_) => return Err(conflict),
        }
    }
    Ok(resolved)
}

/// Resolve optional text claims without trimming nonempty values.
///
/// Claims containing only whitespace are absent. Remaining claims must carry
/// identical bytes; otherwise the semantic alias group conflicts.
pub fn optional_text<'a, I>(values: I) -> Result<Option<&'a str>, &'static str>
where
    I: IntoIterator<Item = Option<&'a str>>,
{
    coalesce_equal(
        values
            .into_iter()
            .map(|value| Ok(value.filter(|value| !value.trim().is_empty()))),
        "conflicting optional text claims",
    )
}

/// Normalize the optional VLESS flow value.
///
/// Empty and whitespace-only values are absent. Both supported Vision spellings
/// select the canonical base flow.
pub fn optional_flow(value: Option<&str>) -> Result<Option<&str>, &'static str> {
    let Some(value) = optional_text([value])? else {
        return Ok(None);
    };
    if matches!(value, "xtls-rprx-vision" | "xtls-rprx-vision-udp443") {
        Ok(Some("xtls-rprx-vision"))
    } else {
        Err("unsupported VLESS flow")
    }
}

/// Normalize a stream transport claim while retaining the caller's source
/// spelling for storage. Empty and TCP both mean raw TCP.
pub fn stream_transport(value: &str) -> Result<&'static str, &'static str> {
    match value {
        "" | "tcp" => Ok("tcp"),
        "ws" => Ok("ws"),
        "grpc" => Ok("grpc"),
        _ => Err("unsupported stream transport"),
    }
}

/// XHTTP-aware adapters share the sole alias-to-canonical transport mapping.
pub fn xhttp_stream_transport(value: &str) -> Result<&'static str, &'static str> {
    match value {
        "xhttp" | "splithttp" => Ok("xhttp"),
        _ => stream_transport(value),
    }
}

/// Resolve optional VMess cipher claims before any alias is discarded.
pub fn vmess_cipher<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<Option<&'static str>, &'static str> {
    let mut selected = None;
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        let cipher = if value.eq_ignore_ascii_case("auto") {
            "auto"
        } else if value.eq_ignore_ascii_case("aes-128-gcm") {
            "aes-128-gcm"
        } else {
            return Err("unsupported VMess cipher");
        };
        if selected.is_some_and(|previous| previous != cipher) {
            return Err("conflicting VMess cipher aliases");
        }
        selected = Some(cipher);
    }
    Ok(selected)
}

/// Resolve a packet-network capability list into the consumer's UDP flag.
pub fn packet_network(value: &str) -> Result<Option<bool>, &'static str> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let mut allows_udp = false;
    for token in value.split(',') {
        let token = token.trim();
        if token.eq_ignore_ascii_case("tcp") {
            continue;
        }
        if token.eq_ignore_ascii_case("udp") {
            allows_udp = true;
            continue;
        }
        return Err("invalid packet network");
    }
    Ok(Some(allows_udp))
}

/// Decode share-link certificate-verification text into the skip-verification
/// boolean used by the canonical TLS options.
pub fn verification_text(value: &str) -> Result<bool, &'static str> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("true")
        || value.eq_ignore_ascii_case("yes")
        || value == "1"
        || value.eq_ignore_ascii_case("on")
    {
        return Ok(true);
    }
    if value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("f")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("n")
        || value == "0"
        || value.eq_ignore_ascii_case("off")
        || value.eq_ignore_ascii_case("t")
        || value.eq_ignore_ascii_case("y")
    {
        return Ok(false);
    }
    Err("invalid certificate verification boolean")
}

/// Decode nonzero ports and inclusive ranges into sorted, merged disjoint ranges,
/// rejecting repeated or overlapping ports. Empty comma segments retain the mport
/// consumer's historical grammar.
pub fn port_hopping_ranges(spec: &str) -> Option<Vec<(u16, u16)>> {
    let mut ranges = Vec::new();
    for part in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (low, high) = match part.split_once('-') {
            Some((low, high)) => (
                low.trim().parse::<u16>().ok()?,
                high.trim().parse::<u16>().ok()?,
            ),
            None => {
                let port = part.parse::<u16>().ok()?;
                (port, port)
            }
        };
        if low == 0 || high < low {
            return None;
        }
        ranges.push((low, high));
    }
    if ranges.is_empty() {
        return None;
    }
    ranges.sort_unstable_by_key(|&(low, _)| low);
    let mut canonical: Vec<(u16, u16)> = Vec::with_capacity(ranges.len());
    for (low, high) in ranges {
        if let Some(prev) = canonical.last_mut() {
            if prev.1 >= low {
                return None;
            }
            if prev.1.checked_add(1) == Some(low) {
                prev.1 = high;
                continue;
            }
        }
        canonical.push((low, high));
    }
    Some(canonical)
}

/// Decode nonzero ports and inclusive ranges, rejecting repeated ports.
/// Empty comma segments retain the mport consumer's historical grammar.
pub fn parse_port_hopping(spec: &str) -> Option<Vec<u16>> {
    let mut ports = Vec::new();
    let mut seen = [0u64; 1024];
    for part in spec
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (low, high) = match part.split_once('-') {
            Some((low, high)) => (
                low.trim().parse::<u16>().ok()?,
                high.trim().parse::<u16>().ok()?,
            ),
            None => {
                let port = part.parse::<u16>().ok()?;
                (port, port)
            }
        };
        if low == 0 || high < low {
            return None;
        }
        for port in low..=high {
            let word = &mut seen[usize::from(port) / 64];
            let bit = 1u64 << (port % 64);
            if *word & bit != 0 {
                return None;
            }
            *word |= bit;
            ports.push(port);
        }
    }
    (!ports.is_empty()).then_some(ports)
}

#[cfg(test)]
mod tests {
    use super::port_hopping_ranges;

    #[test]
    fn port_hopping_ranges_canonicalizes_single_ports_ranges_and_adjacent_merges() {
        assert_eq!(port_hopping_ranges("443"), Some(vec![(443, 443)]));
        assert_eq!(port_hopping_ranges(" 443 , "), Some(vec![(443, 443)]));
        assert_eq!(
            port_hopping_ranges("35000-39000"),
            Some(vec![(35000, 39000)])
        );
        assert_eq!(
            port_hopping_ranges("6000, 4000 - 5000"),
            port_hopping_ranges("4000-5000,6000")
        );
        assert_eq!(
            port_hopping_ranges("5000-5005,5006-5010"),
            Some(vec![(5000, 5010)])
        );
        assert_eq!(
            port_hopping_ranges("5006-5010,5000-5005"),
            Some(vec![(5000, 5010)])
        );
        assert_eq!(port_hopping_ranges("102,100,101"), Some(vec![(100, 102)]));
    }

    #[test]
    fn port_hopping_ranges_handles_upper_bound_without_overflow() {
        assert_eq!(port_hopping_ranges("65535"), Some(vec![(65535, 65535)]));
        assert_eq!(
            port_hopping_ranges("65534,65535"),
            Some(vec![(65534, 65535)])
        );
        assert_eq!(port_hopping_ranges("1-65535"), Some(vec![(1, 65535)]));
        assert_eq!(port_hopping_ranges("65535,65535"), None);
        assert_eq!(port_hopping_ranges("65530-65535,65535"), None);
    }

    #[test]
    fn port_hopping_ranges_rejects_empty_zero_reversed_overlapping_and_duplicates() {
        for invalid in [
            "",
            "   ",
            ",",
            " , ",
            "0",
            "0-10",
            "9000-8000",
            "443,443",
            "100-200,150-250",
            "100-200,200-250",
            "35000-39000,35000",
            "bad",
            "1-2-3",
            "65536",
        ] {
            assert_eq!(port_hopping_ranges(invalid), None, "{invalid}");
        }
    }
}

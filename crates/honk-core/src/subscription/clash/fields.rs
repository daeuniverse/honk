use serde_yaml::{Mapping, Value};

use super::super::yaml_value;

pub(super) fn raw_alias<'a>(
    mapping: &'a Mapping,
    keys: &[&str],
) -> Result<Option<&'a Value>, &'static str> {
    let mut found = None;
    for key in keys {
        let Some(value) = yaml_value(mapping, key) else {
            continue;
        };
        if matches!(value, Value::Null) {
            continue;
        }
        match found {
            None => found = Some(value),
            Some(previous) if previous == value => {}
            Some(_) => return Err("conflicting aliases"),
        }
    }
    Ok(found)
}

fn parsed_alias<T: PartialEq>(
    mapping: &Mapping,
    keys: &[&str],
    parse: impl Fn(&Value) -> Result<Option<T>, &'static str>,
) -> Result<Option<T>, &'static str> {
    let mut found = None;
    for key in keys {
        let Some(value) = yaml_value(mapping, key) else {
            continue;
        };
        let Some(value) = parse(value)? else {
            continue;
        };
        match &found {
            None => found = Some(value),
            Some(previous) if previous == &value => {}
            Some(_) => return Err("conflicting aliases"),
        }
    }
    Ok(found)
}

pub(super) fn text(value: &Value) -> Result<Option<String>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value.clone())),
        Value::Number(value) => Ok(Some(value.to_string())),
        _ => Err("field must be a scalar"),
    }
}

pub(super) fn text_alias(mapping: &Mapping, keys: &[&str]) -> Result<Option<String>, &'static str> {
    parsed_alias(mapping, keys, text)
}

pub(super) fn bool_alias(mapping: &Mapping, keys: &[&str]) -> Result<Option<bool>, &'static str> {
    parsed_alias(mapping, keys, |value| match value {
        Value::Null => Ok(None),
        Value::Bool(value) => Ok(Some(*value)),
        _ => Err("field must be boolean"),
    })
}

fn u64_value(value: &Value) -> Result<u64, &'static str> {
    match value {
        Value::Number(value) => value.as_u64().ok_or("field must be a non-negative integer"),
        Value::String(value) => value
            .trim()
            .parse()
            .map_err(|_| "field must be a non-negative integer"),
        _ => Err("field must be a non-negative integer"),
    }
}

pub(super) fn u64_alias(mapping: &Mapping, keys: &[&str]) -> Result<Option<u64>, &'static str> {
    parsed_alias(mapping, keys, |value| match value {
        Value::Null => Ok(None),
        value => u64_value(value).map(Some),
    })
}

fn duration_secs(value: &Value) -> Result<u64, &'static str> {
    match value {
        Value::Number(_) => u64_value(value),
        Value::String(raw) => {
            let raw = raw.trim();
            let (number, multiplier) = if let Some(value) = raw.strip_suffix("ms") {
                (value, 0)
            } else if let Some(value) = raw.strip_suffix('s') {
                (value, 1)
            } else if let Some(value) = raw.strip_suffix('m') {
                (value, 60)
            } else if let Some(value) = raw.strip_suffix('h') {
                (value, 3600)
            } else {
                (raw, 1)
            };
            let number: u64 = number
                .trim()
                .parse()
                .map_err(|_| "field must be a duration")?;
            if multiplier == 0 {
                Ok(number / 1000)
            } else {
                number
                    .checked_mul(multiplier)
                    .ok_or("duration is too large")
            }
        }
        _ => Err("field must be a duration"),
    }
}

pub(super) fn duration_alias(
    mapping: &Mapping,
    keys: &[&str],
) -> Result<Option<u64>, &'static str> {
    parsed_alias(mapping, keys, |value| match value {
        Value::Null => Ok(None),
        value => duration_secs(value).map(Some),
    })
}

fn rate_mbps(value: &Value) -> Result<Option<u32>, &'static str> {
    let Some(raw) = text(value)? else {
        return Ok(None);
    };
    let raw = raw.trim();
    let raw = raw
        .strip_suffix("Mbps")
        .or_else(|| raw.strip_suffix("mbps"))
        .or_else(|| raw.strip_suffix("Mb/s"))
        .unwrap_or(raw)
        .trim();
    raw.parse().map(Some).map_err(|_| "field must be Mbps")
}

pub(super) fn rate_alias(mapping: &Mapping, keys: &[&str]) -> Result<Option<u32>, &'static str> {
    parsed_alias(mapping, keys, rate_mbps)
}

fn list_text(value: &Value) -> Result<Option<String>, &'static str> {
    match value {
        Value::Null => Ok(None),
        Value::Sequence(values) => {
            let mut joined = String::new();
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    joined.push(',');
                }
                if let Some(value) = text(value)? {
                    joined.push_str(&value);
                }
            }
            Ok(Some(joined))
        }
        value => text(value),
    }
}

pub(super) fn list_alias(mapping: &Mapping, keys: &[&str]) -> Result<Option<String>, &'static str> {
    parsed_alias(mapping, keys, list_text)
}

pub(super) fn ports(value: &Value) -> Result<Option<String>, &'static str> {
    let Some(value) = list_text(value)? else {
        return Ok(None);
    };
    let mut normalized = String::new();
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        if !normalized.is_empty() {
            normalized.push(',');
        }
        for character in part.chars() {
            normalized.push(if character == ':' { '-' } else { character });
        }
    }
    if normalized.is_empty() {
        return Err("port range is empty");
    }
    Ok(Some(normalized))
}

pub(super) fn active(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => {
            value.as_i64() != Some(0) && value.as_u64() != Some(0) && value.as_f64() != Some(0.0)
        }
        Value::String(value) => !value.trim().is_empty(),
        Value::Sequence(value) => !value.is_empty(),
        Value::Mapping(value) => {
            !value.is_empty()
                && yaml_value(value, "enabled")
                    .is_none_or(|enabled| !matches!(enabled, Value::Null | Value::Bool(false)))
        }
        Value::Tagged(_) => true,
    }
}

pub(super) fn active_for_key(key: &str, value: &Value) -> bool {
    if matches!(key, "pin-sha256" | "pin_sha256") {
        return !matches!(value, Value::Null);
    }
    if matches!(key, "packet-encoding" | "packet_encoding") {
        return match value {
            Value::Null => false,
            Value::String(value) => !matches!(value.trim(), "" | "none" | "legacy"),
            _ => active(value),
        };
    }
    active(value)
}

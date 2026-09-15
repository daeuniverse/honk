use honk_config::options::vocab::{
    coalesce_equal, optional_flow, optional_text, packet_network, stream_transport, vmess_cipher,
};
use serde_yaml::Value;

use super::{Dialect, RecordResult, parse_bool};

#[derive(Default)]
pub(super) struct RecordOptions {
    occurrences: Vec<(String, String)>,
}

impl RecordOptions {
    pub(super) fn insert(&mut self, key: String, value: String) {
        self.occurrences.push((key, value));
    }

    pub(super) fn contains(&self, key: &str) -> bool {
        self.occurrences.iter().any(|(name, _)| name == key)
    }
    pub(super) fn remove(&mut self, key: &str) -> Option<String> {
        let index = self.occurrences.iter().rposition(|(name, _)| name == key)?;
        let value = self.occurrences.remove(index).1;
        self.occurrences.retain(|(name, _)| name != key);
        Some(value)
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &String> {
        let mut seen = std::collections::HashSet::new();
        self.occurrences
            .iter()
            .rev()
            .filter(move |(name, _)| seen.insert(name.as_str()))
            .map(|(_, value)| value)
    }

    fn claims(&self, key: &str) -> impl Iterator<Item = &str> {
        self.occurrences
            .iter()
            .filter(move |(name, _)| name.as_str() == key)
            .map(|(_, value)| value.as_str())
    }

    fn clear_aliases(&mut self, keys: &[&str]) {
        self.occurrences
            .retain(|(name, _)| !keys.contains(&name.as_str()));
    }

    fn take_first_nonempty(&mut self, keys: &[&str]) -> Option<String> {
        let index = self
            .occurrences
            .iter()
            .position(|(key, value)| keys.contains(&key.as_str()) && !value.trim().is_empty());
        let value = index.map(|index| self.occurrences.remove(index).1);
        self.clear_aliases(keys);
        value
    }

    fn coalesce<'a, T: PartialEq>(
        &'a self,
        keys: &[&str],
        conflict: &'static str,
        parse: impl FnMut(&'a str) -> RecordResult<Option<T>>,
    ) -> RecordResult<Option<T>> {
        coalesce_equal(
            keys.iter().flat_map(|key| self.claims(key)).map(parse),
            conflict,
        )
    }
}

pub(super) fn take_raw(options: &mut RecordOptions, keys: &[&str]) -> Option<String> {
    let index = keys.iter().find_map(|key| {
        options
            .occurrences
            .iter()
            .rposition(|(name, _)| name == key)
    });
    let value = index.map(|index| options.occurrences.remove(index).1);
    options.clear_aliases(keys);
    value
}

pub(super) fn take_optional_text_alias(
    options: &mut RecordOptions,
    keys: &[&str],
) -> RecordResult<Option<String>> {
    optional_text(keys.iter().flat_map(|key| options.claims(key).map(Some)))?;
    Ok(options.take_first_nonempty(keys))
}

pub(super) fn take_optional_flow_alias(
    options: &mut RecordOptions,
    dialect: Dialect,
) -> RecordResult<Option<String>> {
    let keys = match dialect {
        Dialect::Named => &["flow", "vless-flow"][..],
        Dialect::QuantumultX => &["vless-flow", "flow"][..],
    };
    let Some(value) = take_optional_text_alias(options, keys)? else {
        return Ok(None);
    };
    optional_flow(Some(value.as_str()))?;
    Ok(Some(value))
}

pub(super) fn take_credential_alias(
    options: &mut RecordOptions,
    keys: &[&str],
) -> RecordResult<Option<String>> {
    options.coalesce(keys, "record credential aliases conflict", |value| {
        Ok(Some(value))
    })?;
    Ok(take_raw(options, keys))
}

pub(super) fn take_vmess_cipher_alias(
    options: &mut RecordOptions,
    keys: &[&str],
) -> RecordResult<Option<String>> {
    let cipher = vmess_cipher(keys.iter().flat_map(|key| options.claims(key)))?;
    options.clear_aliases(keys);
    Ok(cipher.map(str::to_owned))
}

pub(super) fn take_stream_transport_alias(
    options: &mut RecordOptions,
    keys: &[&str],
) -> RecordResult<Option<&'static str>> {
    for (key, value) in &mut options.occurrences {
        if keys.contains(&key.as_str()) {
            value.make_ascii_lowercase();
        }
    }
    let mut saw_nonempty_tcp = false;
    let selected = options.coalesce(keys, "record transport aliases conflict", |value| {
        let normalized = stream_transport(value)?;
        saw_nonempty_tcp |= normalized == "tcp" && !value.is_empty();
        Ok(Some(normalized))
    })?;
    options.clear_aliases(keys);
    Ok(selected.map(|normalized| {
        if normalized == "tcp" && !saw_nonempty_tcp {
            ""
        } else {
            normalized
        }
    }))
}

pub(super) fn take_packet_network(options: &mut RecordOptions) -> RecordResult<Option<String>> {
    options.coalesce(
        &["network"],
        "record packet network aliases conflict",
        packet_network,
    )?;
    Ok(options.take_first_nonempty(&["network"]))
}

pub(super) fn take_vless_packet_encoding_alias(
    options: &mut RecordOptions,
) -> RecordResult<Option<&'static str>> {
    let keys = &["packet-encoding", "packet_encoding", "packetencoding"];
    let encoding =
        options.coalesce(
            keys,
            "record packet encoding aliases conflict",
            |value| match value {
                "" | "none" => Ok(Some("none")),
                "xudp" => Ok(Some("xudp")),
                _ => Err("VLESS packet encoding is unsupported"),
            },
        )?;
    options.clear_aliases(keys);
    Ok(encoding)
}

pub(super) fn take_option(options: &mut RecordOptions, keys: &[&str]) -> Option<String> {
    take_raw(options, keys).filter(|value| !value.is_empty())
}

pub(super) fn take_bool(options: &mut RecordOptions, keys: &[&str]) -> RecordResult<Option<bool>> {
    take_raw(options, keys)
        .map(|value| parse_bool(&value).ok_or("record boolean option is invalid"))
        .transpose()
}

pub(super) fn take_bool_alias(
    options: &mut RecordOptions,
    keys: &[&str],
) -> RecordResult<Option<bool>> {
    let found = options.coalesce(keys, "record boolean aliases conflict", |value| {
        parse_bool(value)
            .map(Some)
            .ok_or("record boolean option is invalid")
    })?;
    options.clear_aliases(keys);
    Ok(found)
}
pub(super) fn take_duration_alias(options: &mut RecordOptions) -> RecordResult<Option<u64>> {
    let value = options.coalesce(
        &["mhop", "hop-interval", "hop_interval"],
        "record duration aliases conflict",
        |value| {
            super::super::clash::parse_feed_duration_secs(&Value::String(value.to_owned()))
                .map(Some)
        },
    )?;
    options.clear_aliases(&["mhop", "hop-interval", "hop_interval"]);
    Ok(value)
}

pub(super) fn take_any_matching(
    options: &mut RecordOptions,
    keys: &[&str],
    predicate: impl Fn(&str) -> bool,
) -> bool {
    let mut matched = false;
    for key in keys {
        if let Some(value) = options.remove(key) {
            matched |= predicate(&value);
        }
    }
    matched
}

pub(super) fn take_any_active(options: &mut RecordOptions, keys: &[&str]) -> bool {
    take_any_matching(options, keys, |value| !value.trim().is_empty())
}

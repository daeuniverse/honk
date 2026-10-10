//! Request body decoding with details that name what is wrong.
//!
//! Details carry `field` and `kind`, like the header and request part details at
//! the HTTP boundary. Submitted values and unknown keys are never echoed: body
//! types are closed structs, so every key left in a field path is a schema name.

use axum::body::Body;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, de::DeserializeOwned};
use serde_json::{Value, error::Category, json};
use serde_path_to_error::{Path, Segment};

use super::ApiError;

/// The HTTP boundary already read the whole body within `MAX_BODY_BYTES`, so this cannot fail.
pub(super) async fn buffered(body: Body) -> Bytes {
    axum::body::to_bytes(body, usize::MAX)
        .await
        .expect("the HTTP boundary buffers every API body")
}

/// Decodes a JSON body into `T`, or returns the caller's `invalid` error with details.
pub(super) fn decode<T: DeserializeOwned>(
    bytes: &[u8],
    invalid: impl FnOnce() -> ApiError,
) -> Result<T, ApiError> {
    from_slice(bytes).map_err(|details| invalid().with_details(details))
}

/// A JSON value with no schema: only its syntax can fail, so no path is tracked.
pub(super) fn value(bytes: &[u8], invalid: impl FnOnce() -> ApiError) -> Result<Value, ApiError> {
    serde_json::from_slice(bytes).map_err(|_| invalid().with_details(invalid_json()))
}

/// [`decode`] for part of a body already read as JSON; `at` names that part,
/// or is empty for the whole body.
pub(super) fn decode_value<T: DeserializeOwned>(
    value: Value,
    at: &str,
    invalid: impl FnOnce() -> ApiError,
) -> Result<T, ApiError> {
    tracked(value, at).map_err(|details| invalid().with_details(details))
}

/// Accepts an empty body or `{}`, the only bodies an action without inputs takes.
pub(super) fn no_inputs(bytes: &[u8], invalid: impl FnOnce() -> ApiError) -> Result<(), ApiError> {
    if bytes.is_empty() {
        return Ok(());
    }
    from_slice::<serde_json::Map<String, Value>>(bytes)
        .and_then(|object| {
            if object.is_empty() {
                Ok(())
            } else {
                Err(json!({"field":"body","kind":"unknown_field"}))
            }
        })
        .map_err(|details| invalid().with_details(details))
}

fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Value> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = tracked(&mut decoder, "")?;
    decoder.end().map_err(|_| invalid_json())?;
    Ok(value)
}

fn tracked<'de, T, D>(input: D, at: &str) -> Result<T, Value>
where
    T: Deserialize<'de>,
    D: Deserializer<'de, Error = serde_json::Error>,
{
    serde_path_to_error::deserialize(input)
        .map_err(|error| details(at, error.path(), error.inner()))
}

/// Details for a body over its size limit.
pub(super) fn too_large() -> Value {
    json!({"field":"body","kind":"too_large"})
}

fn invalid_json() -> Value {
    json!({"field":"body","kind":"invalid_json"})
}

fn details(at: &str, path: &Path, error: &serde_json::Error) -> Value {
    if error.classify() != Category::Data {
        return invalid_json();
    }
    // serde's standard messages; the names inside backticks are schema names.
    let text = error.to_string();
    let named = |prefix: &str| {
        text.strip_prefix(prefix)
            .and_then(|rest| rest.split_once('`'))
            .map(|(name, _)| name)
    };
    let segments: Vec<_> = path.iter().collect();
    let (segments, name, kind) = if let Some(name) = named("missing field `") {
        (&segments[..], Some(name), "missing")
    } else if let Some(name) = named("duplicate field `") {
        (&segments[..], Some(name), "duplicate")
    } else if text.starts_with("unknown field `") {
        // The path ends at the submitted key, except inside an internally
        // tagged enum, whose buffered fields leave it at the enclosing field.
        let key_tracked = matches!(segments.last(), Some(Segment::Map { key })
            if text.starts_with(&format!("unknown field `{key}`")));
        (
            &segments[..segments.len() - usize::from(key_tracked)],
            None,
            "unknown_field",
        )
    } else if text.starts_with("invalid type: ") {
        (&segments[..], None, "wrong_type")
    } else {
        (&segments[..], None, "invalid_value")
    };
    let mut field = at.to_owned();
    for segment in segments {
        match segment {
            Segment::Seq { index } => field.push_str(&format!("[{index}]")),
            Segment::Map { key } => push_name(&mut field, key),
            Segment::Enum { variant } => push_name(&mut field, variant),
            Segment::Unknown => push_name(&mut field, "?"),
        }
    }
    if let Some(name) = name {
        push_name(&mut field, name);
    }
    if field.is_empty() {
        field.push_str("body");
    }
    json!({"field": field, "kind": kind})
}

fn push_name(field: &mut String, name: &str) {
    if !field.is_empty() {
        field.push('.');
    }
    field.push_str(name);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_api::ErrorCode;
    use axum::http::StatusCode;
    use serde::Deserialize;

    fn invalid() -> ApiError {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidRequest,
            "Invalid",
            None,
        )
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Outer {
        name: String,
        inner: Option<Inner>,
        list: Option<Vec<Inner>>,
        mode: Option<Mode>,
        target: Option<Target>,
    }

    /// Internally tagged like the probe target: serde buffers its fields,
    /// so the tracked path stops at the enclosing field.
    #[derive(Debug, Deserialize)]
    #[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
    #[allow(dead_code)]
    enum Target {
        Node { node_id: String },
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum Mode {
        Tcp,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Inner {
        port: u16,
    }

    fn fails(body: &str) -> Value {
        let details = decode::<Outer>(body.as_bytes(), invalid)
            .unwrap_err()
            .into_details()
            .unwrap();
        assert!(!details.to_string().contains("secret"), "{details}");
        details
    }

    #[test]
    fn missing_field_names_its_path() {
        assert_eq!(fails("{}"), json!({"field":"name","kind":"missing"}));
        assert_eq!(
            fails(r#"{"name":"secret","list":[{"port":1},{}]}"#),
            json!({"field":"list[1].port","kind":"missing"})
        );
    }

    #[test]
    fn wrong_type_names_the_field_not_the_value() {
        assert_eq!(
            fails(r#"{"name":"n","inner":{"port":"secret"}}"#),
            json!({"field":"inner.port","kind":"wrong_type"})
        );
        assert_eq!(
            fails(r#""secret""#),
            json!({"field":"body","kind":"wrong_type"})
        );
    }

    #[test]
    fn unknown_field_names_the_object_not_the_key() {
        assert_eq!(
            fails(r#"{"name":"n","secret":1}"#),
            json!({"field":"body","kind":"unknown_field"})
        );
        assert_eq!(
            fails(r#"{"name":"n","inner":{"port":1,"secret":1}}"#),
            json!({"field":"inner","kind":"unknown_field"})
        );
        assert_eq!(
            fails(r#"{"name":"n","se`cret":1}"#),
            json!({"field":"body","kind":"unknown_field"})
        );
        assert_eq!(
            fails(r#"{"name":"n","target":{"type":"node","node_id":"n","secret":1}}"#),
            json!({"field":"target","kind":"unknown_field"})
        );
    }

    #[test]
    fn duplicate_and_out_of_range_fields_are_named() {
        assert_eq!(
            fails(r#"{"name":"a","name":"secret"}"#),
            json!({"field":"name","kind":"duplicate"})
        );
        assert_eq!(
            fails(r#"{"name":"n","inner":{"port":65536}}"#),
            json!({"field":"inner.port","kind":"invalid_value"})
        );
        assert_eq!(
            fails(r#"{"name":"n","mode":"secret"}"#),
            json!({"field":"mode","kind":"invalid_value"})
        );
    }

    #[test]
    fn decoded_values_name_the_field_too() {
        let details = |at| {
            decode_value::<Outer>(json!({"name":"n","inner":{"port":"secret"}}), at, invalid)
                .unwrap_err()
                .into_details()
                .unwrap()
        };
        assert_eq!(
            details(""),
            json!({"field":"inner.port","kind":"wrong_type"})
        );
        assert_eq!(
            details("part"),
            json!({"field":"part.inner.port","kind":"wrong_type"})
        );
    }

    #[test]
    fn syntax_errors_are_invalid_json() {
        // An empty body, bad syntax, and trailing data after a valid value.
        for body in ["", "secret", r#"{"name":"n"} secret"#] {
            assert_eq!(fails(body), json!({"field":"body","kind":"invalid_json"}));
        }
    }

    #[test]
    fn no_inputs_takes_only_nothing_or_an_empty_object() {
        for (body, kind) in [
            ("", None),
            ("{}", None),
            (r#"{"secret":1}"#, Some("unknown_field")),
            (r#"["secret"]"#, Some("wrong_type")),
            ("{secret", Some("invalid_json")),
        ] {
            let details = no_inputs(body.as_bytes(), invalid)
                .err()
                .map(|error| error.into_details().unwrap());
            if let Some(details) = &details {
                assert!(!details.to_string().contains("secret"), "{details}");
            }
            assert_eq!(
                details,
                kind.map(|kind| json!({"field":"body","kind":kind})),
                "{body}"
            );
        }
    }

    #[test]
    fn too_large_names_the_body() {
        assert_eq!(too_large(), json!({"field":"body","kind":"too_large"}));
    }
}

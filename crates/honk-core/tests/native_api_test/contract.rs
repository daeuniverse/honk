//! Checks every `/api` response the suite receives against the OpenAPI
//! contract pinned below, so handler drift fails CI.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use jsonschema::{Draft, Registry, Validator};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING};
use reqwest::{Client, IntoUrl, Method, RequestBuilder, Response, Url};
use serde_json::Value;

// api-standardize e6b0dbab5599689d965bc18a71be67c809d99d0f, copied from
// doona contract/api-standardize/openapi.yaml with its read_only_reason extension.
// SHA-256: ef3e1ce08392c26d256b70277318d61a7ec932f4f5825ac8117d839944a33646.
const CONTRACT: &str = include_str!("../fixtures/native_api_openapi.yaml");
const CONTRACT_URL: &str = "https://contract.honk.invalid/openapi.json";

/// Responses honk sends that the contract does not describe yet, awaiting an
/// owner decision: (method, path template or raw path, status, reason).
const KNOWN_DRIFT: &[(&str, &str, u16, &str)] = &[];

/// Values the contract rejects inside otherwise conforming responses, awaiting
/// an owner decision: (label, instance path, reason).
const KNOWN_VALUE_DRIFT: &[(&str, &str, &str)] = &[
    (
        "GET /api/v1/groups/{group_id} 200",
        "/config/check_url",
        MASKED_URL,
    ),
    (
        "GET /api/v1/groups/{group_id}/config 200",
        "/config/check_url",
        MASKED_URL,
    ),
];

const MASKED_URL: &str = "a masked listener secret leaves `<redacted>` in the URL, which \
    SafeHttpUrl's `format: uri` rejects; the contract does not say how a masked URL is spelled";

static DOCUMENT: LazyLock<Value> = LazyLock::new(|| serde_yaml::from_str(CONTRACT).unwrap());

static REGISTRY: LazyLock<Registry<'static>> = LazyLock::new(|| {
    Registry::new()
        .add(CONTRACT_URL, DOCUMENT.clone())
        .unwrap()
        .prepare()
        .unwrap()
});

static VALIDATORS: LazyLock<Mutex<HashMap<String, Arc<Validator>>>> = LazyLock::new(Mutex::default);

/// `TestApp`'s client: identical to reqwest's, except that `send` checks the response.
pub(super) struct ContractClient(pub(super) Client);

impl ContractClient {
    pub(super) fn get(&self, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.get(url))
    }

    pub(super) fn head(&self, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.head(url))
    }

    pub(super) fn post(&self, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.post(url))
    }

    pub(super) fn patch(&self, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.patch(url))
    }

    pub(super) fn request(&self, method: Method, url: impl IntoUrl) -> ContractRequest {
        ContractRequest(self.0.request(method, url))
    }
}

pub(super) struct ContractRequest(RequestBuilder);

impl ContractRequest {
    pub(super) fn header<K, V>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self(self.0.header(key, value))
    }

    pub(super) fn bearer_auth(self, token: impl std::fmt::Display) -> Self {
        Self(self.0.bearer_auth(token))
    }

    pub(super) fn body(self, body: impl Into<reqwest::Body>) -> Self {
        Self(self.0.body(body))
    }

    pub(super) fn json(self, json: &(impl serde::Serialize + ?Sized)) -> Self {
        Self(self.0.json(json))
    }

    pub(super) fn timeout(self, timeout: std::time::Duration) -> Self {
        Self(self.0.timeout(timeout))
    }

    pub(super) async fn send(self) -> reqwest::Result<Response> {
        let (client, request) = self.0.build_split();
        let request = request?;
        let (method, url) = (request.method().clone(), request.url().clone());
        let response = client.execute(request).await?;
        Ok(check(&method, &url, response).await)
    }
}

async fn check(method: &Method, url: &Url, response: Response) -> Response {
    let status = response.status();
    let Some((label, schema)) = inspect(method, url.path(), status.as_u16(), response.headers())
    else {
        return response;
    };
    let version = response.version();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.unwrap();
    check_json(&label, &schema, &bytes);
    let mut rebuilt = http::Response::builder().status(status).version(version);
    *rebuilt.headers_mut().unwrap() = headers;
    Response::from(rebuilt.body(bytes).unwrap())
}

/// Checks a response read off a raw socket: `target` is the request target as
/// sent and `head` the status line and headers as received.
pub(super) fn check_raw(method: Method, target: &str, head: &str, body: &[u8]) {
    let target = match target.strip_prefix("http://") {
        Some(rest) => rest.find('/').map_or("/", |start| &rest[start..]),
        None => target,
    };
    let path = target.split('?').next().unwrap();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split_whitespace().nth(1).unwrap();
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').unwrap();
        headers.append(
            HeaderName::try_from(name.trim()).unwrap(),
            HeaderValue::try_from(value.trim()).unwrap(),
        );
    }
    let Some((label, schema)) = inspect(&method, path, status.parse().unwrap(), &headers) else {
        return;
    };
    let chunked = headers
        .get(TRANSFER_ENCODING)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"chunked"));
    if chunked {
        check_json(&label, &schema, &dechunk(body));
    } else {
        check_json(&label, &schema, body);
    }
}

fn dechunk(mut body: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let end = body.windows(2).position(|part| part == b"\r\n").unwrap();
        let size = std::str::from_utf8(&body[..end]).unwrap();
        let size = usize::from_str_radix(size.split(';').next().unwrap().trim(), 16).unwrap();
        body = &body[end + 2..];
        if size == 0 {
            return decoded;
        }
        decoded.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// Checks one server-sent event's data against the schema its event name selects.
pub(super) fn check_event(url: &Url, kind: &str, data: &Value) {
    let path = url.path();
    let template = template_for(path).unwrap_or(path);
    let label = format!("GET {template} event {kind}");
    let schema = DOCUMENT
        .pointer(&format!(
            "/paths/{}/get/responses/200/content/text~1event-stream/x-event-data-schemas/{}",
            escape(template),
            escape(kind)
        ))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("contract: {label}: event is not documented"));
    check_value(&label, schema.strip_prefix('#').unwrap(), data);
}

/// Checks the status and headers, returning the label and the schema pointer
/// the JSON body still has to match, if any.
fn inspect(
    method: &Method,
    path: &str,
    status: u16,
    headers: &HeaderMap,
) -> Option<(String, String)> {
    // CORS preflight is transport negotiation, not a contract operation.
    if (path != "/api" && !path.starts_with("/api/")) || method == Method::OPTIONS {
        return None;
    }
    let media_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap().trim().to_ascii_lowercase());
    // HEAD answers as GET does, without the body.
    let lookup = if method == Method::HEAD {
        "get".to_owned()
    } else {
        method.as_str().to_ascii_lowercase()
    };
    let template = template_for(path);
    let label = format!("{method} {} {status}", template.unwrap_or(path));
    if KNOWN_DRIFT
        .iter()
        .any(|&(m, t, s, _)| m == method.as_str() && t == template.unwrap_or(path) && s == status)
    {
        return None;
    }
    let operation = template
        .map(|template| format!("/paths/{}/{lookup}", escape(template)))
        .filter(|pointer| DOCUMENT.pointer(pointer).is_some());
    let Some(operation) = operation else {
        // Outside the contract only the shared error envelope is acceptable.
        assert!(
            status >= 400 && media_type.as_deref() == Some("application/json"),
            "contract: {label}: operation is not in the contract"
        );
        return (method != Method::HEAD)
            .then(|| (label, "/components/schemas/ErrorResponse".to_owned()));
    };
    let responses = DOCUMENT.pointer(&format!("{operation}/responses")).unwrap();
    let key = [
        status.to_string(),
        format!("{}XX", status / 100),
        "default".into(),
    ]
    .into_iter()
    .find(|key| responses.get(key).is_some())
    .unwrap_or_else(|| panic!("contract: {label}: status is not documented"));
    let pointer = resolve(format!("{operation}/responses/{key}"));
    let declared = DOCUMENT.pointer(&pointer).unwrap();
    for name in declared["headers"]
        .as_object()
        .into_iter()
        .flat_map(|map| map.keys())
    {
        let header = resolve(format!("{pointer}/headers/{}", escape(name)));
        let values = headers.get_all(name);
        assert!(
            DOCUMENT.pointer(&header).unwrap()["required"] != Value::Bool(true)
                || values.iter().next().is_some(),
            "contract: {label}: required header {name} is missing"
        );
        let schema = resolve(format!("{header}/schema"));
        // Header values are text; a numeric schema describes the parsed value.
        let numeric = matches!(
            DOCUMENT.pointer(&schema).unwrap()["type"].as_str(),
            Some("integer" | "number")
        );
        for value in values {
            let text = value
                .to_str()
                .unwrap_or_else(|_| panic!("contract: {label}: header {name} is not text"));
            let instance = numeric
                .then(|| serde_json::from_str(text).ok())
                .flatten()
                .unwrap_or_else(|| Value::from(text));
            check_value(&format!("{label}: header {name}"), &schema, &instance);
        }
    }
    let content = declared["content"].as_object();
    let Some(media_type) = media_type else {
        assert!(
            content.is_none_or(|content| content.is_empty()) || method == Method::HEAD,
            "contract: {label}: response has no body but the contract declares one"
        );
        return None;
    };
    assert!(
        content.is_some_and(|content| content.contains_key(&media_type)),
        "contract: {label}: media type {media_type} is not documented"
    );
    // Event streams are checked frame by frame, through `check_event`.
    if media_type != "application/json" || method == Method::HEAD {
        return None;
    }
    let schema = format!("{pointer}/content/{}/schema", escape(&media_type));
    Some((label, schema))
}

/// Picks the template whose literal segments match the most of `path`, so
/// `/config/sources` beats `/config/{id}`.
fn template_for(path: &str) -> Option<&'static str> {
    let segments: Vec<_> = path.split('/').collect();
    DOCUMENT["paths"]
        .as_object()
        .unwrap()
        .keys()
        .filter_map(|template| {
            let parts: Vec<_> = template.split('/').collect();
            (parts.len() == segments.len()).then_some(())?;
            let mut literal = 0;
            for (part, segment) in parts.iter().zip(&segments) {
                if part.starts_with('{') && part.ends_with('}') {
                    (!segment.is_empty()).then_some(())?;
                } else if part == segment {
                    literal += 1;
                } else {
                    return None;
                }
            }
            Some((literal, template.as_str()))
        })
        .max_by_key(|(literal, _)| *literal)
        .map(|(_, template)| template)
}

/// Follows `$ref` chains from the object at `pointer` to the pointer of its target.
fn resolve(mut pointer: String) -> String {
    while let Some(target) = DOCUMENT.pointer(&pointer).unwrap()["$ref"].as_str() {
        pointer = target.strip_prefix('#').unwrap().to_owned();
    }
    pointer
}

fn escape(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn check_json(label: &str, pointer: &str, bytes: &[u8]) {
    let body: Value = serde_json::from_slice(bytes)
        .unwrap_or_else(|error| panic!("contract: {label}: body is not JSON: {error}"));
    check_value(label, pointer, &body);
}

fn check_value(label: &str, pointer: &str, instance: &Value) {
    let validator = VALIDATORS
        .lock()
        .unwrap()
        .entry(pointer.to_owned())
        .or_insert_with(|| {
            // JSON pointers in a URI fragment are percent-encoded.
            let fragment = pointer.replace('{', "%7B").replace('}', "%7D");
            let schema = serde_json::json!({ "$ref": format!("{CONTRACT_URL}#{fragment}") });
            let validator = jsonschema::options()
                .with_draft(Draft::Draft202012)
                // 2020-12 treats `format` as an annotation unless asked.
                .should_validate_formats(true)
                .with_registry(&REGISTRY)
                .build(&schema)
                .unwrap_or_else(|error| panic!("contract: {label}: {error}"));
            Arc::new(validator)
        })
        .clone();
    let errors: Vec<_> = validator
        .iter_errors(instance)
        .filter(|error| {
            let path = error.instance_path().to_string();
            !KNOWN_VALUE_DRIFT
                .iter()
                .any(|&(known, at, _)| known == label && at == path)
        })
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "contract: {label}: {}\nvalue: {instance}",
        errors.join("; ")
    );
}

/// Reads the suite's scenario tests never reach still have to match the contract.
#[tokio::test]
async fn every_parameterless_read_matches_the_contract() {
    let app = super::TestApp::new(|_| {}).await;
    for (template, item) in DOCUMENT["paths"].as_object().unwrap() {
        if item.get("get").is_some() && !template.contains('{') {
            app.get(template).send().await.unwrap();
        }
    }
    app.shutdown().await;
}

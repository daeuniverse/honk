//! Compiled DNS audit templates shared by admission and the sender.

use std::io::{self, Write};

use serde_json::Value;

mod header;
mod json;
mod text;

use json::{Json, JsonView};
use text::Text;

pub const DEFAULT_TEMPLATE: &str =
    "<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - ${json}";
pub const MAX_SOURCE_BYTES: usize = 64 * 1024;
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 1024;
const MAX_TAGS: usize = 2048;
const MAX_DEPTH: usize = 16;

const FIELDS: &[&str] = &[
    "schema_version",
    "event",
    "event_id",
    "hostname",
    "app_name",
    "message",
    "query_time",
    "completed_at",
    "duration_ms",
    "upstream",
    "client_ip",
    "client_port",
    "transport",
    "domain",
    "qtype",
    "qclass",
    "result",
    "rcode",
    "response_truncated",
    "answers",
    "answer_ips",
    "answer_cnames",
    "answer_types",
    "version",
    "template_version",
];

#[derive(Clone, Copy, Debug)]
struct Field(usize);

#[derive(Debug, thiserror::Error)]
#[error("{setting}: {reason}")]
pub struct TemplateError {
    pub setting: &'static str,
    pub reason: &'static str,
}

fn error(setting: &'static str, reason: &'static str) -> TemplateError {
    TemplateError { setting, reason }
}

#[derive(Default)]
struct Budget {
    nodes: usize,
    tags: usize,
}

impl Budget {
    fn node(&mut self, depth: usize, setting: &'static str) -> Result<(), TemplateError> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err(error(setting, "template exceeds depth or node limit"));
        }
        Ok(())
    }

    fn tag(&mut self, setting: &'static str) -> Result<(), TemplateError> {
        self.tags += 1;
        if self.tags > MAX_TAGS {
            return Err(error(setting, "template exceeds placeholder limit"));
        }
        Ok(())
    }
}

pub struct CompiledFormat {
    message: Text,
    json: Option<Json>,
}

impl CompiledFormat {
    pub fn compile(message: &str, json: &str) -> Result<Self, TemplateError> {
        if message.len().saturating_add(json.len()) > MAX_SOURCE_BYTES {
            return Err(error(
                "syslog_dns_template",
                "combined template source exceeds 64 KiB",
            ));
        }
        let mut budget = Budget::default();
        let mut message = Text::compile(message, true, "syslog_dns_template", &mut budget)?;
        let json = if json.is_empty() {
            None
        } else {
            Some(Json::compile(json, &mut budget)?)
        };
        let sample = sample_event();
        let version = Value::String("version1".into());
        let metadata = Value::String("0".repeat(64));
        let context = Context::new(&sample, &version, &metadata);
        message.classify_header(&context, json.as_ref())?;
        Ok(Self { message, json })
    }

    pub fn write(
        &self,
        event: &Value,
        version: &Value,
        template_version: &Value,
        output: &mut impl Write,
    ) -> io::Result<()> {
        self.message.write(
            &Context::new(event, version, template_version),
            self.json.as_ref(),
            output,
        )
    }
}

struct Context<'a> {
    event: &'a Value,
    version: &'a Value,
    template_version: &'a Value,
    values: [std::cell::OnceCell<&'a Value>; FIELDS.len()],
}

impl<'a> Context<'a> {
    fn new(event: &'a Value, version: &'a Value, template_version: &'a Value) -> Self {
        Self {
            event,
            version,
            template_version,
            values: [const { std::cell::OnceCell::new() }; FIELDS.len()],
        }
    }

    fn get(&self, field: Field) -> &Value {
        self.values[field.0].get_or_init(|| match FIELDS[field.0] {
            "version" => self.version,
            "template_version" => self.template_version,
            name => self.event.get(name).unwrap_or(&Value::Null),
        })
    }

    fn write_json(&self, json: Option<&Json>, output: &mut impl Write) -> io::Result<()> {
        match json {
            Some(node) => serde_json::to_writer(output, &JsonView(node, self)),
            None => serde_json::to_writer(output, self.event),
        }
        .map_err(io::Error::other)
    }
}

pub fn validate_header(message: &[u8]) -> io::Result<()> {
    header::parse(message).map(|_| ()).map_err(io::Error::other)
}

struct Buffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Buffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}

impl Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(bytes.len()) > self.limit {
            return Err(io::Error::other("template expansion exceeds byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn sample_event() -> Value {
    serde_json::json!({
        "schema_version": 1, "event": "dns.query", "event_id": "instance:1",
        "hostname": "router", "app_name": "honk", "message": "DNS example query",
        "query_time": "2026-01-01T00:00:00.000000Z", "completed_at": "2026-01-01T00:00:00.000001Z",
        "duration_ms": 0.001, "upstream": "default",
        "client_ip": "192.0.2.1", "client_port": 53000, "transport": "udp",
        "domain": "example.com.", "qtype": "A", "qclass": "IN", "result": "response",
        "rcode": "NOERROR", "response_truncated": false, "answers": [],
        "answer_ips": [], "answer_cnames": [], "answer_types": []
    })
}

#[cfg(test)]
mod tests;

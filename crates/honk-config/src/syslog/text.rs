use std::io::{self, Write};

use serde_json::Value;

use super::json::Json;
use super::{
    Budget, Buffer, Context, FIELDS, Field, MAX_MESSAGE_BYTES, TemplateError, error, header,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Filter {
    Text,
    Json,
    CefHeader,
    CefExt,
    Sd,
}

#[derive(Clone, Copy)]
pub(super) enum Position {
    Body,
    Token,
    SdName,
    SdValue,
}

pub(super) enum Segment {
    Literal(String),
    Field {
        field: Field,
        filter: Option<Filter>,
        position: Position,
    },
    Json,
}

pub(super) struct Text(pub Vec<Segment>);

impl Text {
    pub(super) fn compile(
        input: &str,
        allow_json: bool,
        setting: &'static str,
        budget: &mut Budget,
    ) -> Result<Self, TemplateError> {
        let mut segments = Vec::new();
        let mut literal = String::new();
        let mut chars = input.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch != '$' {
                literal.push(ch);
                continue;
            }
            if chars.peek() == Some(&'$') {
                chars.next();
                literal.push('$');
                continue;
            }
            if chars.peek() != Some(&'{') {
                literal.push('$');
                continue;
            }
            chars.next();
            if !literal.is_empty() {
                budget.node(0, setting)?;
                segments.push(Segment::Literal(std::mem::take(&mut literal)));
            }
            let mut tag = String::new();
            loop {
                match chars.next() {
                    Some('}') => break,
                    Some(ch) => tag.push(ch),
                    None => return Err(error(setting, "unclosed placeholder")),
                }
            }
            budget.node(0, setting)?;
            budget.tag(setting)?;
            let (name, filter) = match tag.split_once('|') {
                Some((name, filter)) => (
                    name,
                    Some(match filter {
                        "text" => Filter::Text,
                        "json" => Filter::Json,
                        "cef_header" => Filter::CefHeader,
                        "cef_ext" => Filter::CefExt,
                        "sd" => Filter::Sd,
                        _ => return Err(error(setting, "unknown placeholder filter")),
                    }),
                ),
                None => (tag.as_str(), None),
            };
            if name == "json" {
                if !allow_json || filter.is_some() {
                    return Err(error(
                        setting,
                        "json is only valid unfiltered in the message body",
                    ));
                }
                segments.push(Segment::Json);
            } else {
                let field = FIELDS
                    .iter()
                    .position(|candidate| *candidate == name)
                    .ok_or_else(|| error(setting, "unknown placeholder field"))?;
                segments.push(Segment::Field {
                    field: Field(field),
                    filter,
                    position: Position::Body,
                });
            }
        }
        if !literal.is_empty() {
            budget.node(0, setting)?;
            segments.push(Segment::Literal(literal));
        }
        Ok(Self(segments))
    }

    pub(super) fn classify_header(
        &mut self,
        context: &Context<'_>,
        json: Option<&Json>,
    ) -> Result<(), TemplateError> {
        let mut sample = Buffer::new(MAX_MESSAGE_BYTES);
        let mut ranges = Vec::new();
        for segment in &self.0 {
            let start = sample.bytes.len();
            segment
                .write(context, json, &mut sample)
                .map_err(|_| error("syslog_dns_template", "sample expansion exceeds byte limit"))?;
            ranges.push(start..sample.bytes.len());
        }
        let layout =
            header::parse(&sample.bytes).map_err(|reason| error("syslog_dns_template", reason))?;
        for (segment, range) in self.0.iter_mut().zip(ranges) {
            match segment {
                Segment::Json if range.start < layout.body => {
                    return Err(error(
                        "syslog_dns_template",
                        "json placeholder must be in the message body",
                    ));
                }
                Segment::Field {
                    filter, position, ..
                } if range.start < layout.body => {
                    *position = if range.end <= layout.sd.start {
                        Position::Token
                    } else if layout
                        .values
                        .iter()
                        .any(|r| r.start <= range.start && range.end <= r.end)
                    {
                        if *filter != Some(Filter::Sd) {
                            return Err(error(
                                "syslog_dns_template",
                                "structured-data values require the sd filter",
                            ));
                        }
                        Position::SdValue
                    } else if layout
                        .names
                        .iter()
                        .any(|r| r.start <= range.start && range.end <= r.end)
                    {
                        Position::SdName
                    } else {
                        return Err(error(
                            "syslog_dns_template",
                            "placeholder crosses header field boundaries",
                        ));
                    };
                }
                _ => {}
            }
        }
        let mut checked = Buffer::new(MAX_MESSAGE_BYTES);
        self.write(context, json, &mut checked)
            .map_err(|_| error("syslog_dns_template", "invalid dynamic header substitution"))?;
        Ok(())
    }

    pub(super) fn write(
        &self,
        context: &Context<'_>,
        json: Option<&Json>,
        output: &mut impl Write,
    ) -> io::Result<()> {
        for segment in &self.0 {
            segment.write(context, json, output)?;
        }
        Ok(())
    }

    pub(super) fn string(&self, context: &Context<'_>) -> io::Result<String> {
        let mut output = Buffer::new(MAX_MESSAGE_BYTES);
        self.write(context, None, &mut output)?;
        String::from_utf8(output.bytes).map_err(io::Error::other)
    }
}

impl Segment {
    fn write(
        &self,
        context: &Context<'_>,
        json: Option<&Json>,
        output: &mut impl Write,
    ) -> io::Result<()> {
        match self {
            Self::Literal(value) => output.write_all(value.as_bytes()),
            Self::Json => context.write_json(json, output),
            Self::Field {
                field,
                filter,
                position,
            } => {
                let value = context.get(*field);
                match position {
                    Position::Token | Position::SdName => {
                        let mut token = Buffer::new(255);
                        write_field(value, *filter, &mut token)?;
                        if token.bytes.is_empty()
                            || !token.bytes.iter().all(|b| {
                                (33..=126).contains(b)
                                    && (!matches!(position, Position::SdName)
                                        || !b"=]\"".contains(b))
                            })
                        {
                            return Err(io::Error::other("invalid dynamic syslog header token"));
                        }
                        output.write_all(&token.bytes)
                    }
                    Position::SdValue | Position::Body => write_field(value, *filter, output),
                }
            }
        }
    }
}

fn write_field(value: &Value, filter: Option<Filter>, output: &mut impl Write) -> io::Result<()> {
    if filter == Some(Filter::Json) {
        return serde_json::to_writer(output, value).map_err(io::Error::other);
    }
    let mut escaping = Escaping { output, filter };
    match value {
        Value::String(value) => escaping.write_all(value.as_bytes()),
        value => serde_json::to_writer(&mut escaping, value).map_err(io::Error::other),
    }
}

struct Escaping<'a, W> {
    output: &'a mut W,
    filter: Option<Filter>,
}

impl<W: Write> Write for Escaping<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if matches!(self.filter, None | Some(Filter::Text)) {
            self.output.write_all(bytes)?;
            return Ok(bytes.len());
        }
        for byte in bytes {
            let escaped: Option<&[u8]> = match (self.filter, byte) {
                (Some(Filter::CefHeader | Filter::CefExt | Filter::Sd), b'\\') => Some(b"\\\\"),
                (Some(Filter::CefHeader), b'|') => Some(b"\\|"),
                (Some(Filter::CefExt), b'=') => Some(b"\\="),
                (Some(Filter::CefHeader | Filter::CefExt), b'\n') => Some(b"\\n"),
                (Some(Filter::CefHeader | Filter::CefExt), b'\r') => Some(b"\\r"),
                (Some(Filter::Sd), b'"') => Some(b"\\\""),
                (Some(Filter::Sd), b']') => Some(b"\\]"),
                (Some(Filter::Sd), b) if b.is_ascii_control() => {
                    return Err(io::Error::other("control byte in structured-data value"));
                }
                _ => None,
            };
            match escaped {
                Some(escaped) => self.output.write_all(escaped)?,
                None => self.output.write_all(&[*byte])?,
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.output.flush()
    }
}

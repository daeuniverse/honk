use std::fmt;

use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::text::{Segment, Text};
use super::{Budget, Context, Field, TemplateError, error};

pub(super) enum Json {
    Constant(Value),
    Field(Field),
    Text(Text),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub(super) fn compile(input: &str, budget: &mut Budget) -> Result<Self, TemplateError> {
        let value: Unique = serde_json::from_str(input).map_err(|_| {
            error(
                "syslog_dns_json",
                "expected valid JSON with unique object keys",
            )
        })?;
        if !value.0.is_object() {
            return Err(error(
                "syslog_dns_json",
                "JSON template root must be an object",
            ));
        }
        Self::node(value.0, 0, budget)
    }

    fn node(value: Value, depth: usize, budget: &mut Budget) -> Result<Self, TemplateError> {
        budget.node(depth, "syslog_dns_json")?;
        Ok(match value {
            Value::Object(object) => Self::Object(
                object
                    .into_iter()
                    .map(|(key, value)| Ok((key, Self::node(value, depth + 1, budget)?)))
                    .collect::<Result<_, TemplateError>>()?,
            ),
            Value::Array(array) => Self::Array(
                array
                    .into_iter()
                    .map(|value| Self::node(value, depth + 1, budget))
                    .collect::<Result<_, _>>()?,
            ),
            Value::String(value) => {
                let text = Text::compile(&value, false, "syslog_dns_json", budget)?;
                if let [
                    Segment::Field {
                        field,
                        filter: None,
                        ..
                    },
                ] = text.0.as_slice()
                {
                    Self::Field(*field)
                } else {
                    Self::Text(text)
                }
            }
            value => Self::Constant(value),
        })
    }
}

pub(super) struct JsonView<'a, 'b>(pub &'a Json, pub &'a Context<'b>);

impl Serialize for JsonView<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Json::Constant(value) => value.serialize(serializer),
            Json::Field(field) => self.1.get(*field).serialize(serializer),
            Json::Text(text) => {
                let value = text.string(self.1).map_err(serde::ser::Error::custom)?;
                serializer.serialize_str(&value)
            }
            Json::Array(array) => {
                let mut seq = serializer.serialize_seq(Some(array.len()))?;
                for value in array {
                    seq.serialize_element(&JsonView(value, self.1))?;
                }
                seq.end()
            }
            Json::Object(object) => {
                let mut map = serializer.serialize_map(Some(object.len()))?;
                for (key, value) in object {
                    map.serialize_entry(key, &JsonView(value, self.1))?;
                }
                map.end()
            }
        }
    }
}

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}

struct UniqueVisitor;

impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.write_str("JSON")
    }
    fn visit_unit<E>(self) -> Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_bool<E>(self, value: bool) -> Result<Unique, E> {
        Ok(Unique(Value::Bool(value)))
    }
    fn visit_i64<E>(self, value: i64) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_u64<E>(self, value: u64) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Unique, E> {
        serde_json::Number::from_f64(value)
            .map(|n| Unique(Value::Number(n)))
            .ok_or_else(|| E::custom("invalid JSON number"))
    }
    fn visit_str<E>(self, value: &str) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_string<E>(self, value: String) -> Result<Unique, E> {
        Ok(Unique(value.into()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Unique, A::Error> {
        let mut values = Vec::new();
        while let Some(Unique(value)) = seq.next_element()? {
            values.push(value);
        }
        Ok(Unique(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Unique, A::Error> {
        let mut values = serde_json::Map::new();
        while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
            if values.insert(key, value).is_some() {
                return Err(A::Error::custom("duplicate JSON key"));
            }
        }
        Ok(Unique(Value::Object(values)))
    }
}

//! Lenient deserialization of CLI arguments.
//!
//! CLI arguments always arrive as strings (`Args = HashMap<String, String>`),
//! so `serde_json::from_value(serde_json::to_value(args))` fails for any
//! typed field (`Option<bool>`, `u64`, `Vec<String>`, nested structs). This
//! module deserializes a `serde_json::Value` while accepting strings wherever
//! the target type expects something else:
//!
//! - bool: `true|false|1|0|yes|no|on|off` (case-insensitive)
//! - integers and floats: parsed from the string
//! - sequences: a JSON array string (`["a","b"]`), or comma-separated items
//! - maps and structs: a JSON object string (`{"k":1}`)
//! - strings: numbers and bools are accepted and converted to text
//!
//! Values that already have the right JSON type are passed through, so
//! existing callers that build typed `Value`s keep working.

use serde::de::value::{MapDeserializer, SeqDeserializer};
use serde::de::{self, DeserializeOwned, IntoDeserializer, Visitor};
use serde::forward_to_deserialize_any;
use serde_json::{Error, Value};

/// Like `serde_json::from_value`, but string-tolerant for typed fields.
pub fn from_value<T: DeserializeOwned>(value: Value) -> Result<T, Error> {
    T::deserialize(Lenient(value))
}

struct Lenient(Value);

impl<'de> IntoDeserializer<'de, Error> for Lenient {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

/// The CLI boolean spellings: `true|false|1|0|yes|no|on|off`,
/// case-insensitive. Anything else is `None`.
pub fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Read boolean argument `key`: `None` when absent, an error when present
/// but not one of the `parse_bool` spellings. Callers never get a silent
/// default for a value they could not read.
pub fn bool_arg(args: &crate::core::Args, key: &str) -> anyhow::Result<Option<bool>> {
    match args.get(key) {
        None => Ok(None),
        Some(v) => parse_bool(v).map(Some).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid value for {}: {:?} (expected true/false, 1/0, yes/no or on/off)",
                key,
                v
            )
        }),
    }
}

/// The `dry_run` argument; absent means `false`. A malformed value is an
/// error, so a mistyped dry run is refused instead of making real changes.
pub fn dry_run(args: &crate::core::Args) -> anyhow::Result<bool> {
    Ok(bool_arg(args, "dry_run")?.unwrap_or(false))
}

fn visit_array<'de, V: Visitor<'de>>(items: Vec<Value>, visitor: V) -> Result<V::Value, Error> {
    let mut seq = SeqDeserializer::new(items.into_iter().map(Lenient));
    let out = visitor.visit_seq(&mut seq)?;
    seq.end()?;
    Ok(out)
}

fn visit_object<'de, V: Visitor<'de>>(
    map: serde_json::Map<String, Value>,
    visitor: V,
) -> Result<V::Value, Error> {
    let mut m = MapDeserializer::new(map.into_iter().map(|(k, v)| (k, Lenient(v))));
    let out = visitor.visit_map(&mut m)?;
    m.end()?;
    Ok(out)
}

macro_rules! lenient_number {
    ($method:ident, $ty:ty, $visit:ident) => {
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            match self.0 {
                Value::String(s) => match s.trim().parse::<$ty>() {
                    Ok(n) => visitor.$visit(n),
                    Err(_) => Err(de::Error::invalid_value(
                        de::Unexpected::Str(&s),
                        &stringify!($ty),
                    )),
                },
                other => other.$method(visitor),
            }
        }
    };
}

impl<'de> de::Deserializer<'de> for Lenient {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Array(items) => visit_array(items, visitor),
            Value::Object(map) => visit_object(map, visitor),
            other => other.deserialize_any(visitor),
        }
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::String(s) => match parse_bool(&s) {
                Some(b) => visitor.visit_bool(b),
                None => Err(de::Error::invalid_value(
                    de::Unexpected::Str(&s),
                    &"a boolean",
                )),
            },
            other => other.deserialize_bool(visitor),
        }
    }

    lenient_number!(deserialize_i8, i8, visit_i8);
    lenient_number!(deserialize_i16, i16, visit_i16);
    lenient_number!(deserialize_i32, i32, visit_i32);
    lenient_number!(deserialize_i64, i64, visit_i64);
    lenient_number!(deserialize_u8, u8, visit_u8);
    lenient_number!(deserialize_u16, u16, visit_u16);
    lenient_number!(deserialize_u32, u32, visit_u32);
    lenient_number!(deserialize_u64, u64, visit_u64);
    lenient_number!(deserialize_f32, f32, visit_f32);
    lenient_number!(deserialize_f64, f64, visit_f64);

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Number(n) => visitor.visit_string(n.to_string()),
            Value::Bool(b) => visitor.visit_string(b.to_string()),
            other => other.deserialize_string(visitor),
        }
    }

    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.deserialize_string(visitor)
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            other => visitor.visit_some(Lenient(other)),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Array(items) => visit_array(items, visitor),
            Value::String(s) => {
                let t = s.trim();
                if t.starts_with('[') {
                    match serde_json::from_str::<Value>(t)? {
                        Value::Array(items) => visit_array(items, visitor),
                        _ => unreachable!("a string starting with '[' parses as an array"),
                    }
                } else if t.is_empty() {
                    visit_array(Vec::new(), visitor)
                } else {
                    let items = t
                        .split(',')
                        .map(|p| Value::String(p.trim().to_string()))
                        .collect();
                    visit_array(items, visitor)
                }
            }
            other => other.deserialize_seq(visitor),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Object(map) => visit_object(map, visitor),
            Value::String(s) if s.trim_start().starts_with('{') => {
                match serde_json::from_str::<Value>(&s)? {
                    Value::Object(map) => visit_object(map, visitor),
                    _ => unreachable!("a string starting with '{{' parses as an object"),
                }
            }
            other => other.deserialize_map(visitor),
        }
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            Value::String(s) => visitor.visit_enum(s.into_deserializer()),
            other => other.deserialize_enum(name, variants, visitor),
        }
    }

    forward_to_deserialize_any! {
        i128 u128 char bytes byte_buf unit unit_struct identifier ignored_any
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(rename_all = "lowercase")]
    enum Mode {
        Fast,
        Safe,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Inner {
        depth: u32,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Opts {
        name: String,
        dry_run: Option<bool>,
        timeout_ms: Option<u64>,
        ratio: Option<f64>,
        tags: Option<Vec<String>>,
        ports: Option<Vec<u16>>,
        mode: Option<Mode>,
        inner: Option<Inner>,
        #[serde(default)]
        missing: Option<bool>,
    }

    #[test]
    fn coerces_cli_strings() {
        let v = json!({
            "name": "123",
            "dry_run": "true",
            "timeout_ms": "5000",
            "ratio": "0.5",
            "tags": "a, b",
            "ports": "[22,80]",
            "mode": "safe",
            "inner": "{\"depth\": \"3\"}"
        });
        let o: Opts = from_value(v).unwrap();
        assert_eq!(
            o,
            Opts {
                name: "123".into(),
                dry_run: Some(true),
                timeout_ms: Some(5000),
                ratio: Some(0.5),
                tags: Some(vec!["a".into(), "b".into()]),
                ports: Some(vec![22, 80]),
                mode: Some(Mode::Safe),
                inner: Some(Inner { depth: 3 }),
                missing: None,
            }
        );
    }

    #[test]
    fn typed_values_pass_through() {
        let v =
            json!({"name": "x", "dry_run": false, "timeout_ms": 7, "tags": ["t"], "mode": "fast"});
        let o: Opts = from_value(v).unwrap();
        assert_eq!(o.dry_run, Some(false));
        assert_eq!(o.timeout_ms, Some(7));
        assert_eq!(o.tags, Some(vec!["t".to_string()]));
        assert_eq!(o.mode, Some(Mode::Fast));
    }

    #[test]
    fn numbers_accepted_for_string_fields() {
        let o: Opts = from_value(json!({"name": 42})).unwrap();
        assert_eq!(o.name, "42");
    }

    // SEC-05: one boolean reader for dry_run everywhere.
    #[test]
    fn dry_run_spellings() {
        let a = |v: &str| -> crate::core::Args { [("dry_run".to_string(), v.to_string())].into() };
        for t in [
            "true", "TRUE", "True", "1", "yes", "YES", "on", "On", " true ",
        ] {
            assert!(dry_run(&a(t)).unwrap(), "{t:?}");
        }
        for f in ["false", "FALSE", "0", "no", "off", "Off"] {
            assert!(!dry_run(&a(f)).unwrap(), "{f:?}");
        }
        for bad in [
            "", "maybe", "2", "-1", "truee", "y", "n", "t", "dry_run", "null", "\"true\"",
        ] {
            let err = dry_run(&a(bad)).unwrap_err().to_string();
            assert!(err.contains("invalid value for dry_run"), "{bad:?}: {err}");
        }
        assert!(!dry_run(&crate::core::Args::new()).unwrap());
        assert_eq!(
            bool_arg(&crate::core::Args::new(), "dry_run").unwrap(),
            None
        );
    }

    #[test]
    fn rejects_bad_values() {
        assert!(from_value::<Opts>(json!({"name": "x", "dry_run": "maybe"})).is_err());
        assert!(from_value::<Opts>(json!({"name": "x", "timeout_ms": "soon"})).is_err());
        assert!(from_value::<Opts>(json!({"name": "x", "mode": "turbo"})).is_err());
    }
}

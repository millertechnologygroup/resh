//! Statement parameters and result rows as JSON.
//!
//! Parameters are bound, never spliced into SQL text. Each column is decoded
//! by its database type; a type with no JSON form is an error that tells the
//! caller to cast it in SQL, instead of a silent null.

use super::DbError;
use base64::engine::Engine;
use serde_json::{Map, Value, json};
use sqlx::{Column, Decode, Row, TypeInfo, ValueRef};

/// One bound parameter (from a JSON array item).
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
}

impl Param {
    /// Converts one JSON array item. Arrays, objects and integers outside
    /// the signed 64-bit range are refused.
    pub fn from_json(v: &Value, what: &str) -> Result<Self, String> {
        Ok(match v {
            Value::Null => Param::Null,
            Value::Bool(b) => Param::Bool(*b),
            Value::String(s) => Param::Text(s.clone()),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Param::Int(i)
                } else if n.as_u64().is_some() {
                    return Err(format!(
                        "{what}: {n} is outside the signed 64-bit integer range; pass it as a \
                         string and cast it in SQL"
                    ));
                } else {
                    Param::Float(n.as_f64().unwrap_or(f64::NAN))
                }
            }
            Value::Array(_) | Value::Object(_) => {
                return Err(format!(
                    "{what} must be a string, number, boolean or null, not {}",
                    if v.is_array() {
                        "an array"
                    } else {
                        "an object"
                    }
                ));
            }
        })
    }
}

/// Binds `params` to a `sqlx::query` in order.
macro_rules! bind_params {
    ($query:expr, $params:expr) => {{
        let mut q = $query;
        for p in $params {
            q = match p {
                $crate::handles::data::dbh::values::Param::Null => q.bind(None::<String>),
                $crate::handles::data::dbh::values::Param::Bool(b) => q.bind(*b),
                $crate::handles::data::dbh::values::Param::Int(i) => q.bind(*i),
                $crate::handles::data::dbh::values::Param::Float(f) => q.bind(*f),
                $crate::handles::data::dbh::values::Param::Text(s) => q.bind(s.as_str()),
            };
        }
        q
    }};
}
pub(crate) use bind_params;

type Decoded<T> = Result<T, sqlx::error::BoxDynError>;

fn pg<'r, T: Decode<'r, sqlx::Postgres>>(v: sqlx::postgres::PgValueRef<'r>) -> Decoded<T> {
    T::decode(v)
}

fn my<'r, T: Decode<'r, sqlx::MySql>>(v: sqlx::mysql::MySqlValueRef<'r>) -> Decoded<T> {
    T::decode(v)
}

fn lite<'r, T: Decode<'r, sqlx::Sqlite>>(v: sqlx::sqlite::SqliteValueRef<'r>) -> Decoded<T> {
    T::decode(v)
}

fn b64(bytes: &[u8]) -> Value {
    Value::String(format!(
        "base64:{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

/// A float as JSON; NaN and the infinities (which JSON cannot hold) as
/// strings.
fn float(f: f64) -> Value {
    if f.is_nan() {
        json!("NaN")
    } else if f.is_infinite() {
        json!(if f > 0.0 { "Infinity" } else { "-Infinity" })
    } else {
        json!(f)
    }
}

fn naive_dt(dt: chrono::NaiveDateTime) -> Value {
    json!(dt.format("%Y-%m-%dT%H:%M:%S%.f").to_string())
}

fn unsupported(column: &str, type_name: &str, hint: &str) -> DbError {
    DbError::new(
        "unsupported_column_type",
        format!(
            "column {column:?} has type {type_name}, which resh cannot convert to JSON; \
             cast it in SQL (for example {hint})"
        ),
    )
}

fn decode_err(column: &str, type_name: &str, e: impl std::fmt::Display) -> DbError {
    DbError::new(
        "query_failed",
        format!("cannot read column {column:?} ({type_name}): {e}"),
    )
}

/// Column metadata and JSON conversion for one driver's rows.
pub trait JsonRow: Row {
    fn cell(&self, i: usize) -> Result<Value, DbError>;

    /// `[{"name","type"}]` for the result columns.
    fn column_meta(&self) -> Vec<Value> {
        unique_names(self)
            .into_iter()
            .enumerate()
            .map(|(i, name)| json!({"name": name, "type": self.column_type(i)}))
            .collect()
    }

    /// The type name reported in the column metadata.
    fn column_type(&self, i: usize) -> String {
        self.columns()[i].type_info().name().to_string()
    }

    /// The row as a JSON object. A repeated column name gets a `_2`, `_3`
    /// ... suffix instead of overwriting the earlier value.
    fn to_json(&self) -> Result<Map<String, Value>, DbError> {
        let mut obj = Map::new();
        for (i, name) in unique_names(self).into_iter().enumerate() {
            obj.insert(name, self.cell(i)?);
        }
        Ok(obj)
    }
}

/// The column names of `row`, with repeated names made unique.
pub fn unique_names<R: Row + ?Sized>(row: &R) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for c in row.columns() {
        let base = c.name().to_string();
        let mut name = base.clone();
        let mut n = 2;
        while seen.contains(&name) {
            name = format!("{base}_{n}");
            n += 1;
        }
        seen.push(name);
    }
    seen
}

// --- PostgreSQL -------------------------------------------------------------

/// PostgreSQL NUMERIC in its binary wire form, as exact decimal text.
pub fn pg_numeric_text(buf: &[u8]) -> Result<String, String> {
    let word = |i: usize| -> Result<i16, String> {
        buf.get(i..i + 2)
            .map(|b| i16::from_be_bytes([b[0], b[1]]))
            .ok_or_else(|| "truncated NUMERIC value".to_string())
    };
    let ndigits = word(0)? as i32;
    let weight = word(2)? as i32;
    let sign = word(4)? as u16;
    let dscale = word(6)? as u16 as usize;
    match sign {
        0xC000 => return Ok("NaN".into()),
        0xD000 => return Ok("Infinity".into()),
        0xF000 => return Ok("-Infinity".into()),
        _ => {}
    }
    let digit = |g: i32| -> Result<i16, String> {
        if g < 0 || g >= ndigits {
            Ok(0)
        } else {
            word(8 + 2 * g as usize)
        }
    };
    let mut s = String::new();
    if sign == 0x4000 {
        s.push('-');
    }
    if weight < 0 {
        s.push('0');
    } else {
        for g in 0..=weight {
            let d = digit(g)?;
            if g == 0 {
                s.push_str(&d.to_string());
            } else {
                s.push_str(&format!("{d:04}"));
            }
        }
    }
    if dscale > 0 {
        let mut frac = String::new();
        let mut g = weight + 1;
        while frac.len() < dscale {
            frac.push_str(&format!("{:04}", digit(g)?));
            g += 1;
        }
        frac.truncate(dscale);
        s.push('.');
        s.push_str(&frac);
    }
    if s == "-0" || (s.starts_with("-0") && s[1..].chars().all(|c| c == '0' || c == '.')) {
        s.remove(0);
    }
    Ok(s)
}

fn pg_inet(buf: &[u8]) -> Option<String> {
    let (family, bits, _is_cidr, n) = (buf.first()?, buf.get(1)?, buf.get(2)?, buf.get(3)?);
    let addr = buf.get(4..4 + *n as usize)?;
    let ip: std::net::IpAddr = match (family, addr.len()) {
        (2, 4) => std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).into(),
        (3, 16) => {
            let a: [u8; 16] = addr.try_into().ok()?;
            std::net::Ipv6Addr::from(a).into()
        }
        _ => return None,
    };
    let full = if ip.is_ipv4() { 32 } else { 128 };
    Some(if *bits == full {
        ip.to_string()
    } else {
        format!("{ip}/{bits}")
    })
}

impl JsonRow for sqlx::postgres::PgRow {
    fn cell(&self, i: usize) -> Result<Value, DbError> {
        use sqlx::postgres::{PgTypeKind, PgValueFormat};
        let col = &self.columns()[i];
        let name = col.name();
        let raw = self
            .try_get_raw(i)
            .map_err(|e| decode_err(name, col.type_info().name(), e))?;
        if raw.is_null() {
            return Ok(Value::Null);
        }
        // A domain is decoded as its base type.
        let mut ty = col.type_info().clone();
        while let PgTypeKind::Domain(base) = ty.kind() {
            ty = base.clone();
        }
        let tname = ty.name().to_string();
        let err = |e: sqlx::error::BoxDynError| decode_err(name, &tname, e);
        if raw.format() == PgValueFormat::Text {
            return raw.as_str().map(|s| json!(s)).map_err(err);
        }
        if let PgTypeKind::Enum(_) = ty.kind() {
            return raw.as_str().map(|s| json!(s)).map_err(err);
        }
        use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};
        use sqlx::postgres::types::{Oid, PgInterval};
        Ok(match tname.as_str() {
            "BOOL" => json!(pg::<bool>(raw).map_err(err)?),
            "INT2" => json!(pg::<i16>(raw).map_err(err)?),
            "INT4" => json!(pg::<i32>(raw).map_err(err)?),
            "INT8" => json!(pg::<i64>(raw).map_err(err)?),
            "OID" => json!(pg::<Oid>(raw).map_err(err)?.0),
            "FLOAT4" => float(pg::<f32>(raw).map_err(err)? as f64),
            "FLOAT8" => float(pg::<f64>(raw).map_err(err)?),
            "NUMERIC" => json!(
                pg_numeric_text(raw.as_bytes().map_err(err)?)
                    .map_err(|e| { decode_err(name, &tname, e) })?
            ),
            "TEXT" | "VARCHAR" | "CHAR" | "BPCHAR" | "NAME" | "\"CHAR\"" | "UNKNOWN" | "CITEXT"
            | "XML" => json!(raw.as_str().map_err(err)?),
            "BYTEA" => b64(raw.as_bytes().map_err(err)?),
            "JSON" | "JSONB" => {
                let v = pg::<sqlx::types::Json<Value>>(raw).map_err(err)?;
                v.0
            }
            "UUID" => {
                let b = raw.as_bytes().map_err(err)?;
                if b.len() != 16 {
                    return Err(decode_err(name, &tname, "not 16 bytes"));
                }
                let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
                json!(format!(
                    "{}-{}-{}-{}-{}",
                    &h[0..8],
                    &h[8..12],
                    &h[12..16],
                    &h[16..20],
                    &h[20..32]
                ))
            }
            "INET" | "CIDR" => json!(
                pg_inet(raw.as_bytes().map_err(err)?).ok_or_else(|| decode_err(
                    name,
                    &tname,
                    "invalid address"
                ))?
            ),
            "MACADDR" => {
                let b = raw.as_bytes().map_err(err)?;
                json!(
                    b.iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<Vec<_>>()
                        .join(":")
                )
            }
            "TIMESTAMP" => naive_dt(pg::<NaiveDateTime>(raw).map_err(err)?),
            "TIMESTAMPTZ" => json!(
                pg::<DateTime::<Utc>>(raw)
                    .map_err(err)?
                    .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
            ),
            "DATE" => json!(pg::<NaiveDate>(raw).map_err(err)?.to_string()),
            "TIME" => json!(pg::<NaiveTime>(raw).map_err(err)?.to_string()),
            "INTERVAL" => {
                let v = pg::<PgInterval>(raw).map_err(err)?;
                json!({"months": v.months, "days": v.days, "microseconds": v.microseconds})
            }
            "BOOL[]" => json!(pg::<Vec::<Option<bool>>>(raw).map_err(err)?),
            "INT2[]" => json!(pg::<Vec::<Option<i16>>>(raw).map_err(err)?),
            "INT4[]" => json!(pg::<Vec::<Option<i32>>>(raw).map_err(err)?),
            "INT8[]" => json!(pg::<Vec::<Option<i64>>>(raw).map_err(err)?),
            "FLOAT4[]" => json!(
                pg::<Vec::<Option<f32>>>(raw)
                    .map_err(err)?
                    .into_iter()
                    .map(|f| f.map(|f| float(f as f64)).unwrap_or(Value::Null))
                    .collect::<Vec<_>>()
            ),
            "FLOAT8[]" => json!(
                pg::<Vec::<Option<f64>>>(raw)
                    .map_err(err)?
                    .into_iter()
                    .map(|f| f.map(float).unwrap_or(Value::Null))
                    .collect::<Vec<_>>()
            ),
            "TEXT[]" | "VARCHAR[]" | "NAME[]" | "BPCHAR[]" | "CHAR[]" => {
                json!(pg::<Vec::<Option<String>>>(raw).map_err(err)?)
            }
            other => return Err(unsupported(name, other, &format!("{name}::text"))),
        })
    }
}

// --- MySQL / MariaDB ---------------------------------------------------------

impl JsonRow for sqlx::mysql::MySqlRow {
    fn cell(&self, i: usize) -> Result<Value, DbError> {
        use chrono::{NaiveDate, NaiveDateTime};
        use sqlx::mysql::types::MySqlTime;
        let col = &self.columns()[i];
        let name = col.name();
        let tname = col.type_info().name().to_string();
        let raw = self
            .try_get_raw(i)
            .map_err(|e| decode_err(name, &tname, e))?;
        if raw.is_null() {
            return Ok(Value::Null);
        }
        let err = |e: sqlx::error::BoxDynError| decode_err(name, &tname, e);
        // Raw bytes, whatever the type (DECIMAL, ENUM, SET and BIT arrive
        // as bytes in both protocols).
        let bytes = || -> Result<Vec<u8>, DbError> {
            <Vec<u8> as Decode<sqlx::MySql>>::decode(raw.clone()).map_err(err)
        };
        let text = || -> Result<String, DbError> {
            String::from_utf8(bytes()?).map_err(|e| decode_err(name, &tname, e))
        };
        Ok(match tname.as_str() {
            "BOOLEAN" => match my::<i64>(raw.clone()).map_err(err)? {
                0 => json!(false),
                1 => json!(true),
                n => json!(n),
            },
            "TINYINT" | "SMALLINT" | "MEDIUMINT" | "INT" | "BIGINT" | "YEAR" => {
                json!(my::<i64>(raw).map_err(err)?)
            }
            "TINYINT UNSIGNED" | "SMALLINT UNSIGNED" | "MEDIUMINT UNSIGNED" | "INT UNSIGNED"
            | "BIGINT UNSIGNED" => json!(my::<u64>(raw).map_err(err)?),
            "FLOAT" => float(my::<f32>(raw).map_err(err)? as f64),
            "DOUBLE" => float(my::<f64>(raw).map_err(err)?),
            "DECIMAL" | "CHAR" | "VARCHAR" | "TINYTEXT" | "TEXT" | "MEDIUMTEXT" | "LONGTEXT"
            | "ENUM" | "SET" => json!(text()?),
            // The protocol marks text with a binary collation (utf8mb4_bin,
            // MariaDB JSON) like binary data, so valid UTF-8 is shown as
            // text and anything else as base64.
            "BINARY" | "VARBINARY" | "TINYBLOB" | "BLOB" | "MEDIUMBLOB" | "LONGBLOB" => {
                let b = bytes()?;
                match String::from_utf8(b) {
                    Ok(s) => json!(s),
                    Err(e) => b64(e.as_bytes()),
                }
            }
            "GEOMETRY" => b64(&bytes()?),
            "BIT" => {
                let b = bytes()?;
                if b.len() > 8 {
                    return Err(unsupported(name, "BIT(>64)", &format!("HEX({name})")));
                }
                json!(b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64))
            }
            "JSON" => serde_json::from_str(&text()?).map_err(|e| decode_err(name, &tname, e))?,
            "DATE" => match my::<NaiveDate>(raw.clone()) {
                Ok(d) => json!(d.to_string()),
                // A zero date ('0000-00-00') has no calendar form.
                Err(_) if text().is_ok_and(|t| t.starts_with("0000")) => json!("0000-00-00"),
                Err(_) if bytes().is_ok_and(|b| b.is_empty()) => json!("0000-00-00"),
                Err(e) => return Err(err(e)),
            },
            "DATETIME" | "TIMESTAMP" => match my::<NaiveDateTime>(raw.clone()) {
                Ok(d) => naive_dt(d),
                Err(_) if bytes().is_ok_and(|b| b.is_empty() || b.starts_with(b"0000")) => {
                    json!("0000-00-00T00:00:00")
                }
                Err(e) => return Err(err(e)),
            },
            "TIME" => json!(my::<MySqlTime>(raw).map_err(err)?.to_string()),
            "NULL" => Value::Null,
            other => return Err(unsupported(name, other, &format!("CAST({name} AS CHAR)"))),
        })
    }
}

// --- SQLite -------------------------------------------------------------------

impl JsonRow for sqlx::sqlite::SqliteRow {
    /// The declared type; for an expression (no declared type), the storage
    /// class of the value in this row.
    fn column_type(&self, i: usize) -> String {
        let declared = self.columns()[i].type_info().name();
        if declared != "NULL" {
            return declared.to_string();
        }
        self.try_get_raw(i)
            .map(|v| v.type_info().name().to_string())
            .unwrap_or_else(|_| declared.to_string())
    }

    fn cell(&self, i: usize) -> Result<Value, DbError> {
        let col = &self.columns()[i];
        let name = col.name();
        let declared = col.type_info().name().to_ascii_uppercase();
        let raw = self
            .try_get_raw(i)
            .map_err(|e| decode_err(name, &declared, e))?;
        if raw.is_null() {
            return Ok(Value::Null);
        }
        // SQLite types values, not columns: decode by the value's class.
        let class = raw.type_info().name().to_string();
        let err = |e: sqlx::error::BoxDynError| decode_err(name, &class, e);
        Ok(match class.as_str() {
            "INTEGER" | "BOOLEAN" | "INT8" => {
                let v = lite::<i64>(raw).map_err(err)?;
                if matches!(declared.as_str(), "BOOLEAN" | "BOOL") && (v == 0 || v == 1) {
                    json!(v == 1)
                } else {
                    json!(v)
                }
            }
            "REAL" => float(lite::<f64>(raw).map_err(err)?),
            "TEXT" => json!(lite::<String>(raw).map_err(err)?),
            "BLOB" => b64(&lite::<Vec<u8>>(raw).map_err(err)?),
            other => return Err(unsupported(name, other, &format!("CAST({name} AS TEXT)"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn numeric(ndigits: i16, weight: i16, sign: u16, dscale: u16, digits: &[i16]) -> Vec<u8> {
        let mut b = Vec::new();
        for w in [ndigits, weight, sign as i16, dscale as i16] {
            b.extend_from_slice(&w.to_be_bytes());
        }
        for d in digits {
            b.extend_from_slice(&d.to_be_bytes());
        }
        b
    }

    #[test]
    fn numeric_binary_to_text() {
        // 12345.6789 = [1, 2345, 6789], weight 1
        assert_eq!(
            pg_numeric_text(&numeric(3, 1, 0, 4, &[1, 2345, 6789])).unwrap(),
            "12345.6789"
        );
        // 12.50 with scale 2
        assert_eq!(
            pg_numeric_text(&numeric(2, 0, 0, 2, &[12, 5000])).unwrap(),
            "12.50"
        );
        // -0.0001: weight -1, digit 1
        assert_eq!(
            pg_numeric_text(&numeric(1, -1, 0x4000, 4, &[1])).unwrap(),
            "-0.0001"
        );
        // 0.000001: weight -2
        assert_eq!(
            pg_numeric_text(&numeric(1, -2, 0, 6, &[100])).unwrap(),
            "0.000001"
        );
        // 10000 (digits [1], weight 1, trailing zero group dropped)
        assert_eq!(
            pg_numeric_text(&numeric(1, 1, 0, 0, &[1])).unwrap(),
            "10000"
        );
        assert_eq!(pg_numeric_text(&numeric(0, 0, 0, 0, &[])).unwrap(), "0");
        assert_eq!(pg_numeric_text(&numeric(0, 0, 0, 2, &[])).unwrap(), "0.00");
        assert_eq!(
            pg_numeric_text(&numeric(0, 0, 0xC000, 0, &[])).unwrap(),
            "NaN"
        );
        assert!(pg_numeric_text(&[0, 1]).is_err());
    }

    #[test]
    fn inet_binary_to_text() {
        assert_eq!(pg_inet(&[2, 32, 0, 4, 10, 0, 0, 1]).unwrap(), "10.0.0.1");
        assert_eq!(pg_inet(&[2, 24, 1, 4, 10, 0, 0, 0]).unwrap(), "10.0.0.0/24");
        let mut v6 = vec![3, 128, 0, 16];
        v6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        assert_eq!(pg_inet(&v6).unwrap(), "::1");
        assert!(pg_inet(&[2, 32, 0, 3, 1, 2, 3]).is_none());
    }

    #[test]
    fn params_from_json() {
        assert_eq!(Param::from_json(&json!(null), "p").unwrap(), Param::Null);
        assert_eq!(
            Param::from_json(&json!(true), "p").unwrap(),
            Param::Bool(true)
        );
        assert_eq!(Param::from_json(&json!(-7), "p").unwrap(), Param::Int(-7));
        assert_eq!(
            Param::from_json(&json!(1.5), "p").unwrap(),
            Param::Float(1.5)
        );
        assert_eq!(
            Param::from_json(&json!("x"), "p").unwrap(),
            Param::Text("x".into())
        );
        assert!(
            Param::from_json(&json!(u64::MAX), "p")
                .unwrap_err()
                .contains("range")
        );
        assert!(
            Param::from_json(&json!([1]), "p")
                .unwrap_err()
                .contains("array")
        );
        assert!(
            Param::from_json(&json!({}), "p")
                .unwrap_err()
                .contains("object")
        );
    }

    #[test]
    fn floats_json_cannot_hold_are_strings() {
        assert_eq!(float(f64::NAN), json!("NaN"));
        assert_eq!(float(f64::INFINITY), json!("Infinity"));
        assert_eq!(float(f64::NEG_INFINITY), json!("-Infinity"));
        assert_eq!(float(1.25), json!(1.25));
    }
}

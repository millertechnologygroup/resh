//! The cache verbs on Redis. Multi-key verbs send one pipeline (one round
//! trip); each key is still a separate command, so a multi-key `set` is
//! not atomic.

use redis::aio::ConnectionManager;
use serde_json::{Value, json};

use super::{
    Cond, Fail, Op, TtlInfo, del_output, exists_output, get_output, set_output, ttl_output,
};

/// Creates a missing counter from ARGV[2], adds ARGV[1], sets the expiry
/// (ARGV[3] ms, 0 for none) and returns the new value as text (exact, unlike
/// a Lua number) and whether the key was created. An INCRBY error (not an
/// integer, overflow) stops the script before the expiry is touched.
const INCR_SCRIPT: &str = r#"
local created = 0
if redis.call('EXISTS', KEYS[1]) == 0 then
  redis.call('SET', KEYS[1], ARGV[2])
  created = 1
end
redis.call('INCRBY', KEYS[1], ARGV[1])
if ARGV[3] ~= '0' then
  redis.call('PEXPIRE', KEYS[1], ARGV[3])
end
return {redis.call('GET', KEYS[1]), created}
"#;

/// Maps a Redis error. `write`: the command may have changed the data.
pub(crate) fn redis_fail(e: redis::RedisError, what: &str, write: bool) -> Fail {
    if e.is_io_error() || e.is_connection_dropped() || e.is_timeout() {
        return Fail::lost(write, format!("{what}: {e}"));
    }
    let text = e.to_string();
    if e.code() == Some("WRONGTYPE") || text.contains("WRONGTYPE") {
        return Fail::new(1, "wrong_type", format!("{what}: {text}"));
    }
    if text.contains("not an integer") {
        return Fail::new(
            1,
            "wrong_type",
            format!("{what}: the value is not an integer counter ({text})"),
        );
    }
    Fail::server(format!("{what}: {text}"))
}

pub(crate) async fn execute(mut conn: ConnectionManager, op: &Op) -> Result<Value, Fail> {
    let write = op.writes();
    let fail = |what: &'static str| move |e| redis_fail(e, what, write);
    match op {
        Op::Connect => unreachable!("connect is answered before execute"),
        Op::Get {
            keys,
            decode,
            default,
        } => {
            let raw: Vec<Option<Vec<u8>>> = if keys.many {
                redis::cmd("MGET")
                    .arg(&keys.stored)
                    .query_async(&mut conn)
                    .await
                    .map_err(fail("redis MGET failed"))?
            } else {
                vec![
                    redis::cmd("GET")
                        .arg(&keys.stored[0])
                        .query_async(&mut conn)
                        .await
                        .map_err(fail("redis GET failed"))?,
                ]
            };
            get_output(keys, raw, *decode, default)
        }
        Op::Exists { keys } => {
            let mut p = redis::pipe();
            for k in &keys.stored {
                p.cmd("EXISTS").arg(k);
            }
            let found: Vec<i64> = p
                .query_async(&mut conn)
                .await
                .map_err(fail("redis EXISTS failed"))?;
            let found: Vec<bool> = found.into_iter().map(|n| n > 0).collect();
            Ok(exists_output(keys, &found))
        }
        Op::Ttl { keys } => {
            let mut p = redis::pipe();
            for k in &keys.stored {
                p.cmd("PTTL").arg(k);
            }
            let ttls: Vec<i64> = p
                .query_async(&mut conn)
                .await
                .map_err(fail("redis PTTL failed"))?;
            let infos: Vec<TtlInfo> = ttls
                .into_iter()
                .map(|t| TtlInfo {
                    // -2: no such key; -1: no expiry.
                    exists: t != -2,
                    supports_ttl: true,
                    ttl_ms: u64::try_from(t).ok(),
                })
                .collect();
            Ok(ttl_output(keys, &infos))
        }
        Op::Del { keys } => {
            let mut p = redis::pipe();
            for k in &keys.stored {
                p.cmd("DEL").arg(k);
            }
            let n: Vec<i64> = p
                .query_async(&mut conn)
                .await
                .map_err(fail("redis DEL failed"))?;
            let deleted: Vec<bool> = n.into_iter().map(|n| n > 0).collect();
            Ok(del_output(keys, &deleted))
        }
        Op::Set {
            keys,
            data,
            ttl_ms,
            cond,
        } => {
            let mut p = redis::pipe();
            for (k, d) in keys.stored.iter().zip(data) {
                let c = p.cmd("SET").arg(k).arg(d.as_slice());
                if let Some(ttl) = ttl_ms {
                    c.arg("PX").arg(*ttl);
                }
                match cond {
                    Cond::Always => {}
                    Cond::IfMissing => {
                        c.arg("NX");
                    }
                    Cond::IfExists => {
                        c.arg("XX");
                    }
                }
            }
            // "OK", or nil when the NX/XX condition was not met.
            let replies: Vec<Option<String>> = p
                .query_async(&mut conn)
                .await
                .map_err(fail("redis SET failed"))?;
            let stored: Vec<bool> = replies.iter().map(Option::is_some).collect();
            Ok(set_output(keys, &stored, *ttl_ms))
        }
        Op::Incr {
            key,
            stored,
            by,
            initial,
            ttl_ms,
        } => {
            let (value, created): (String, i64) = redis::Script::new(INCR_SCRIPT)
                .key(stored)
                .arg(*by)
                .arg(*initial)
                .arg(ttl_ms.unwrap_or(0))
                .invoke_async(&mut conn)
                .await
                .map_err(fail("redis INCRBY failed"))?;
            let value: i64 = value.parse().map_err(|_| {
                Fail::server(format!("redis INCRBY returned a non-integer: {value:?}"))
            })?;
            Ok(json!({ "key": key, "value": value, "created": created == 1 }))
        }
        Op::Keys {
            pattern,
            prefix_len,
            cursor,
            limit,
        } => {
            let start: u64 = cursor.as_deref().map_or(Ok(0), str::parse).unwrap_or(0);
            let (next, found): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
                .arg(start)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg((*limit).min(super::MAX_SCAN_COUNT))
                .query_async(&mut conn)
                .await
                .map_err(fail("redis SCAN failed"))?;
            let keys: Vec<String> = found
                .iter()
                .map(|k| String::from_utf8_lossy(&k[(*prefix_len).min(k.len())..]).into_owned())
                .collect();
            let has_more = next != 0;
            Ok(json!({
                "keys": keys,
                "count": keys.len(),
                "cursor": has_more.then(|| next.to_string()),
                "has_more": has_more,
            }))
        }
    }
}

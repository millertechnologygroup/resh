//! `available.info`: index details for one plugin.

pub mod index;
pub mod model;

use serde_json::{Value, json};

use super::catalog::{Outcome, raw_args};
use super::common::{ArgReader, CaFile, Deadline, PResult, PluginError};
use crate::core::Args;
use model::{AvailableInfoResult, PluginSelector};

struct InfoOptions {
    name: Option<String>,
    id: Option<String>,
    version: Option<String>,
    channel: &'static str,
    os: Option<String>,
    arch: Option<String>,
    source: &'static str,
    offline: bool,
    timeout_ms: u64,
    ca_file: Option<CaFile>,
}

/// `x.y` or `x.y.z`, numeric.
fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    (2..=3).contains(&parts.len())
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

fn parse(args: &Args) -> PResult<InfoOptions> {
    let r = ArgReader::new(args);
    let name = r.string("name")?;
    let id = r.string("id")?;
    if name.is_none() && id.is_none() {
        return Err(PluginError::usage(
            "available.info needs name=<name> or id=<id>; nothing was done",
        ));
    }
    let version = r.string("version")?;
    if let Some(v) = &version
        && !valid_version(v)
    {
        return Err(PluginError::usage(format!(
            "invalid version {v:?}: expected x.y or x.y.z with numbers; nothing was done"
        )));
    }
    let offline = r.bool("offline", false)?;
    let ca_file = r.ca_file()?;
    if offline && ca_file.is_some() {
        return Err(PluginError::usage(
            "ca_file has no use with offline=true (nothing is fetched); nothing was done",
        ));
    }
    Ok(InfoOptions {
        name,
        id,
        version,
        channel: r.choice("channel", &["stable", "beta", "nightly"], "stable")?,
        os: r.string("os")?,
        arch: r.string("arch")?,
        source: r.choice("source", &["default", "official", "community"], "default")?,
        offline,
        timeout_ms: r.timeout_ms(5000)?,
        ca_file,
    })
}

pub fn available_info(target: &str, args: &Args) -> Outcome {
    let o = match parse(args) {
        Ok(o) => o,
        Err(e) => return finish(target, raw_args(args), vec![], Value::Null, vec![], Some(e)),
    };
    let norm = json!({
        "name": o.name,
        "id": o.id,
        "version": o.version,
        "channel": o.channel,
        "os": o.os,
        "arch": o.arch,
        "source": o.source,
        "offline": o.offline,
        "timeout_ms": o.timeout_ms,
    });
    let deadline = Deadline::after_ms(o.timeout_ms);
    let mut warnings = Vec::new();
    let mut actions = Vec::new();
    let indexes = match index::load_indexes(
        &index::sources(o.source),
        o.channel,
        o.offline,
        o.ca_file.as_ref(),
        deadline,
        &mut warnings,
    ) {
        Ok(i) => i,
        Err(e) => {
            actions.push(json!({"type": "fetch", "id": "index.load", "ok": false, "detail": e.message, "meta": {}}));
            return finish(target, norm, actions, Value::Null, warnings, Some(e));
        }
    };
    actions.push(json!({
        "type": "fetch", "id": "index.load", "ok": true,
        "detail": format!("loaded {} indexes", indexes.len()),
        "meta": {"count": indexes.len()},
    }));
    let selector = PluginSelector {
        name: o.name.clone(),
        id: o.id.clone(),
        version: o.version.clone(),
        channel: o.channel.to_string(),
        os: o.os.clone(),
        arch: o.arch.clone(),
    };
    match selector.select_plugin(&indexes) {
        Ok(resolved) => {
            actions.push(json!({
                "type": "select", "id": "select.plugin", "ok": true,
                "detail": format!("resolved plugin {} version {}", resolved.plugin.name, resolved.plugin.version),
                "meta": {"source_index": resolved.source_index},
            }));
            let result = serde_json::to_value(AvailableInfoResult {
                plugin: resolved.plugin,
            })
            .unwrap_or(Value::Null);
            finish(target, norm, actions, result, warnings, None)
        }
        Err(e) => {
            actions.push(json!({"type": "select", "id": "select.plugin", "ok": false, "detail": e.message, "meta": {}}));
            finish(target, norm, actions, Value::Null, warnings, Some(e))
        }
    }
}

fn finish(
    target: &str,
    args: Value,
    actions: Vec<Value>,
    result: Value,
    warnings: Vec<String>,
    error: Option<PluginError>,
) -> Outcome {
    Outcome {
        envelope: json!({
            "op": "plugin.available.info",
            "ok": error.is_none(),
            "code": error.as_ref().map_or(0, |e| e.exit),
            "target": target,
            "ts": chrono::Utc::now().to_rfc3339(),
            "args": args,
            "actions": actions,
            "result": result,
            "warnings": warnings,
            "error": error.as_ref().map(PluginError::json),
        }),
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_format() {
        for ok in ["1.2", "1.2.3", "0.0"] {
            assert!(valid_version(ok), "{ok}");
        }
        for bad in ["1", "1.2.3.4", "a.b", "1..2", "1.2-rc"] {
            assert!(!valid_version(bad), "{bad}");
        }
    }
}

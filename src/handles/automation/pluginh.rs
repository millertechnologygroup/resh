//! The `plugin://` handle: installs, updates, removes, enables and disables
//! resh plugins, lists the plugin store and reads plugin catalogs. The verbs
//! live in `src/handles/pluginh/`.

use anyhow::Result;
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::Status,
};
use crate::handles::pluginh::common::{
    ArgReader, INVALID_TARGET, PResult, PluginError, VERBS, check_known, suggest,
};
use crate::handles::pluginh::net::parse_https_url;
use crate::handles::pluginh::plugin::engine;
use crate::handles::pluginh::plugin::registry::DEFAULT_REGISTRY;
use crate::handles::pluginh::plugin::store::validate_plugin_id;
use crate::handles::pluginh::{
    Mode, PluginOpArgs, RequestedVersion, Scope, SetEnabledOptions, SourceSpec, VerifyMode,
    available, catalog, state,
};

/// Metadata for `resh plugin --help` and `resh plugin <verb> --help`.
static PLUGIN_HELP: HandleHelp = HandleHelp {
    description: "The plugin handle installs, updates, removes, enables, and disables resh \
        plugins and searches plugin catalogs, printing a JSON envelope for every operation. \
        Lifecycle verbs name the plugin before the verb, such as plugin://aws.install or \
        plugin://aws.enable, while catalog and listing verbs take no plugin name, such as \
        plugin://available.list and plugin://installed.list.",
    usage: "resh plugin://<plugin-id>.<verb> [key=value ...]",
    verbs: &[
        VerbHelp {
            name: "available.list",
            definition: "Lists plugins from the catalog built into resh or from a catalog \
                file, filtered by query, tags, publisher, and platform, with pagination.",
            detail: Some(VerbDetail {
                usage: "resh plugin://available.list [query=<text>] [tags=<tag>,...]\n  \
                    [publisher=<name>] [platform=<os>-<arch>] [include_prerelease=true|false]\n  \
                    [limit=<n>] [offset=<n>] [format=summary|full]\n  \
                    [source=default|file:<path>]",
                example: "resh --json-pretty plugin://available.list query=docker limit=1",
                example_output: Some(
                    r#"{
  "actions": [
    {
      "bytes": 8806,
      "source": "default",
      "type": "catalog.load"
    },
    {
      "query": "docker",
      "tags": [],
      "type": "filter.apply"
    }
  ],
  "args": {
    "format": "summary",
    "include_prerelease": false,
    "limit": 1,
    "offset": 0,
    "platform": "linux-x86_64",
    "publisher": null,
    "query": "docker",
    "source": "default",
    "tags": ""
  },
  "code": 0,
  "error": null,
  "ok": true,
  "op": "plugin.available.list",
  "result": {
    "catalog_version": 1,
    "count": 1,
    "generated_at": "2025-12-13T00:00:00Z",
    "items": [
      {
        "description": "container:// plugin for Docker management",
        "homepage": "https://github.com/resh-community/docker-plugin",
        "id": "resh.docker",
        "license": "MIT",
        "name": "Docker Handle",
        "platforms": [
          "linux-x86_64",
          "linux-aarch64",
          "darwin-x86_64",
          "darwin-aarch64"
        ],
        "publisher": "resh-community",
        "repo": "https://github.com/resh-community/docker-plugin",
        "tags": [
          "container",
          "docker",
          "infrastructure"
        ],
        "version": "0.1.0"
      }
    ],
    "source": "default"
  },
  "target": "plugin://available.list",
  "ts": "2026-11-08T09:12:44.512309+00:00",
  "warnings": []
}

Shown with --json-pretty and the description shortened."#,
                ),
            }),
        },
        VerbHelp {
            name: "available.search",
            definition: "Searches a plugin index, from the local cache or fetched over \
                HTTPS, and returns scored matches for a query and filters.",
            detail: Some(VerbDetail {
                usage: "resh plugin://available.search [q=<text>]\n  \
                    [tags=<tag>;...] [owner=<name>] [name=<name>] [min_version=<version>]\n  \
                    [max_results=<n>] [source=default|<https-url>] [offline=true|false]\n  \
                    [refresh=true|false] [timeout_ms=<ms>] [ca_file=<pem>]",
                example: "resh --json-pretty plugin://available.search q=docker offline=true",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "available.info",
            definition: "Reports index details for one plugin selected by name or id, \
                optionally narrowed by version, channel, OS, and architecture.",
            detail: Some(VerbDetail {
                usage: "resh plugin://available.info name=<name>|id=<id>\n  \
                    [version=<x.y.z>] [channel=stable|beta|nightly] [os=<os>]\n  \
                    [arch=<arch>] [source=default|official|community]\n  \
                    [offline=true|false] [timeout_ms=<ms>] [ca_file=<pem>]",
                example: "resh --json-pretty plugin://available.info name=resh.docker offline=true",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "installed.list",
            definition: "Lists the plugins in the local plugin store with their version, \
                enabled state, and health, with filtering, sorting, and pagination.",
            detail: Some(VerbDetail {
                usage: "resh plugin://installed.list [enabled=true|false]\n  \
                    [name=<name>] [prefix=<text>] [tag=<tag>]\n  \
                    [source=registry|url|file] [limit=<n>] [offset=<n>]\n  \
                    [sort=name|installed_at|updated_at] [order=asc|desc]\n  \
                    [format=full|summary|names]",
                example: "resh --json-pretty plugin://installed.list format=names",
                example_output: Some(
                    r#"{
  "actions": [
    {
      "detail": {
        "exists": false,
        "path": "/home/alice/.local/share/resh/plugins"
      },
      "ok": true,
      "target": "installed_dir",
      "type": "scan.installed_dir"
    },
    {
      "detail": {
        "count": 0
      },
      "ok": true,
      "target": "enabled_registry",
      "type": "read.enabled_registry"
    }
  ],
  "args": {
    "enabled": null,
    "format": "names",
    "limit": 200,
    "name": null,
    "offset": 0,
    "order": "asc",
    "prefix": null,
    "sort": "name",
    "source": null,
    "tag": null
  },
  "code": 0,
  "error": null,
  "ok": true,
  "op": "plugin.installed.list",
  "result": {
    "count": 0,
    "items": [],
    "limit": 200,
    "offset": 0,
    "total": 0
  },
  "target": "plugin://installed.list",
  "ts": "2026-11-08T09:12:44.512309+00:00",
  "warnings": []
}

Shown for an empty plugin store with --json-pretty, and actions shortened.
The full list also has filter.apply, sort.apply, and paginate.apply."#,
                ),
            }),
        },
        VerbHelp {
            name: "install",
            definition: "Resolves a plugin from a registry, URL, or local file, then downloads, \
                verifies, and activates it in the local plugin store, or only reports the \
                plan when dry_run is true.",
            detail: Some(VerbDetail {
                usage: "resh plugin://<plugin-id>.install [source=registry|url|file]\n  \
                    [registry=<https-url>] [url=<https-url>] [path=<file>]\n  \
                    [version=<version>] [verify=sha256|none] [force=true|false]\n  \
                    [allow_downgrade=true|false] [dry_run=true|false]\n  \
                    [timeout_ms=<ms>] [ca_file=<pem>]",
                example: "resh plugin://aws.install source=file path=./aws-plugin dry_run=true",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "update",
            definition: "Resolves the newest version of an installed plugin and installs and \
                activates it, keeping the old version if anything fails, or only reports the \
                plan when dry_run is true.",
            detail: Some(VerbDetail {
                usage: "resh plugin://<plugin-id>.update [registry=<https-url>]\n  \
                    [url=<https-url>] [verify=sha256|none] [strict=true|false]\n  \
                    [dry_run=true|false] [timeout_ms=<ms>] [ca_file=<pem>]",
                example: "resh plugin://aws.update dry_run=true",
                example_output: None,
            }),
        },
        VerbHelp {
            name: "remove",
            definition: "Removes an installed plugin's files from the plugin store, \
                optionally purging its data, or only reports the planned steps when dry_run \
                is true.",
            detail: Some(VerbDetail {
                usage: "resh plugin://<plugin-id>.remove [force=true|false]\n  \
                    [purge=true|false] [dry_run=true|false] [timeout_ms=<ms>]",
                example: "resh --json-pretty plugin://aws.remove dry_run=true",
                example_output: Some(
                    r#"{
  "actions": [
    {
      "id": "check-0",
      "name": "resolve_installation",
      "ok": false,
      "type": "check"
    }
  ],
  "args": {
    "dry_run": true,
    "force": false,
    "purge": false,
    "timeout_ms": 30000
  },
  "code": 1,
  "error": {
    "code": "plugin.not_installed",
    "message": "plugin aws is not installed"
  },
  "ok": false,
  "op": "plugin.remove",
  "result": {},
  "target": {
    "install_root": "/home/alice/.local/share/resh/plugins",
    "name": "aws",
    "requested_name": "aws"
  },
  "ts": "2026-11-08T09:12:44.512309+00:00"
}

Shown for a plugin that is not installed with --json-pretty (exit 1).
For an installed plugin, ok is true, actions lists each step, and result
reports removed, purged, and previous_version."#,
                ),
            }),
        },
        VerbHelp {
            name: "enable",
            definition: "Marks an installed plugin as enabled in the user or system state \
                file.",
            detail: Some(VerbDetail {
                usage: "resh plugin://<plugin-id>.enable [scope=user|system]\n  \
                    [force=true|false] [reason=<text>] [dry_run=true|false]",
                example: "resh --json-pretty plugin://aws.enable dry_run=true",
                example_output: Some(
                    r#"{
  "actions": [
    {
      "id": "check-0",
      "name": "verify plugin installation",
      "ok": false,
      "type": "check"
    }
  ],
  "args": {
    "dry_run": true,
    "force": false,
    "scope": "user"
  },
  "code": 1,
  "error": {
    "code": "plugin.not_installed",
    "message": "plugin aws is not installed"
  },
  "ok": false,
  "op": "plugin.enable",
  "result": {
    "enabled": null,
    "installed": false,
    "scope": "user"
  },
  "target": {
    "install_root": "/home/alice/.local/share/resh/plugins",
    "name": "aws",
    "requested_name": "aws"
  },
  "ts": "2026-11-08T09:12:44.512309+00:00"
}

Shown with --json-pretty for a plugin that is not installed (exit 1). For
an installed plugin, ok is true and result reports enabled, was_enabled,
and changed."#,
                ),
            }),
        },
        VerbHelp {
            name: "disable",
            definition: "Marks an installed plugin as disabled in the user or system state \
                file, refusing while the plugin is running unless force is true.",
            detail: Some(VerbDetail {
                usage: "resh plugin://<plugin-id>.disable [scope=user|system]\n  \
                    [force=true|false] [reason=<text>] [dry_run=true|false]",
                example: "resh --json-pretty plugin://aws.disable dry_run=true",
                example_output: None,
            }),
        },
    ],
};

/// The plugin handle. `plugin_id` is the URL host and path, which is the
/// plugin id for lifecycle verbs and the verb itself for catalog verbs.
#[derive(Debug)]
pub struct PluginHandle {
    pub plugin_id: String,
    pub target: String,
}

impl PluginHandle {
    pub fn new(url: &Url) -> Result<Self> {
        let host = url.host_str().unwrap_or("");
        let path = url.path().trim_start_matches('/');
        let plugin_id = if path.is_empty() {
            host.to_string()
        } else if host.is_empty() {
            path.to_string()
        } else {
            format!("{host}/{path}")
        };
        Ok(Self {
            plugin_id,
            target: url.to_string(),
        })
    }

    fn help_requested(&self, verb: &str, args: &Args) -> bool {
        verb == "help"
            || crate::core::help::is_help_flag(verb)
            || verb.starts_with("--help=")
            || args.contains_key("help")
            || args.contains_key("--help")
            || args.contains_key("-h")
    }

    fn display_help(&self, io: &mut IoStreams, verb: Option<&str>) -> Result<Status> {
        write!(
            io.stdout,
            "{}",
            crate::core::help::render_legacy("plugin", &PLUGIN_HELP, self.verbs(), verb)
        )?;
        Ok(Status::success())
    }

    /// The plugin id of a lifecycle verb, checked (exit 2 when unsafe).
    fn lifecycle_id(&self, verb: &str) -> PResult<&str> {
        // plugin://install parses with the verb as the whole host.
        if self.plugin_id.is_empty() || self.plugin_id == verb {
            return Err(PluginError::new(
                2,
                INVALID_TARGET,
                format!(
                    "plugin {verb} needs a plugin id, for example plugin://<plugin-id>.{verb}; \
                     nothing was done"
                ),
            ));
        }
        validate_plugin_id(&self.plugin_id)
            .map_err(|e| PluginError::new(2, INVALID_TARGET, format!("{e}; nothing was done")))?;
        Ok(&self.plugin_id)
    }

    /// Catalog verbs take no plugin id: `plugin://available.list` (or the
    /// older doubled `plugin://available.available.list`).
    fn catalog_target(&self, verb: &str) -> PResult<()> {
        let prefix = verb.split('.').next().unwrap_or(verb);
        if self.plugin_id.is_empty() || self.plugin_id == verb || self.plugin_id == prefix {
            Ok(())
        } else {
            Err(PluginError::new(
                2,
                INVALID_TARGET,
                format!("plugin {verb} takes no plugin id: use plugin://{verb}; nothing was done"),
            ))
        }
    }
}

fn write_json(io: &mut IoStreams, v: &impl serde::Serialize) -> Result<()> {
    writeln!(io.stdout, "{}", serde_json::to_string(v)?)?;
    Ok(())
}

fn status_of(err: Option<&PluginError>) -> Status {
    match err {
        None => Status::ok(),
        Some(e) => Status::coded(e.exit, e.code, &e.message),
    }
}

/// Parsed install arguments.
fn install_args(id: &str, args: &Args) -> PResult<PluginOpArgs> {
    let r = ArgReader::new(args);
    let source_kind = r.choice("source", &["registry", "url", "file"], "registry")?;
    let refuse = |key: &str, why: &str| -> PResult<()> {
        if r.has(key) {
            Err(PluginError::usage(format!("{key} {why}; nothing was done")))
        } else {
            Ok(())
        }
    };
    let source = match source_kind {
        "registry" => {
            refuse("url", "applies to source=url")?;
            refuse("path", "applies to source=file")?;
            let reg = r
                .string("registry")?
                .unwrap_or_else(|| DEFAULT_REGISTRY.into());
            SourceSpec::Registry {
                url: parse_https_url("registry", &reg)?,
            }
        }
        "url" => {
            refuse("registry", "applies to source=registry")?;
            refuse("path", "applies to source=file")?;
            refuse(
                "version",
                "applies to source=registry (a url artifact has no version)",
            )?;
            let u = r.string("url")?.ok_or_else(|| {
                PluginError::usage("source=url needs url=<https-url>; nothing was done")
            })?;
            SourceSpec::Url {
                url: parse_https_url("url", &u)?,
            }
        }
        _ => {
            refuse("registry", "applies to source=registry")?;
            refuse("url", "applies to source=url")?;
            refuse(
                "version",
                "applies to source=registry (a local file installs as version local)",
            )?;
            refuse(
                "ca_file",
                "applies to downloads; source=file reads a local file",
            )?;
            let p = r.string("path")?.ok_or_else(|| {
                PluginError::usage("source=file needs path=<file>; nothing was done")
            })?;
            SourceSpec::File { path: p }
        }
    };
    let requested_version = match r.string("version")? {
        None => RequestedVersion::Latest,
        Some(v) if v == "latest" => RequestedVersion::Latest,
        Some(v) => {
            if let Some(p) = crate::handles::pluginh::plugin::store::component_problem(&v) {
                return Err(PluginError::usage(format!(
                    "invalid version {v:?}: it {p}; nothing was done"
                )));
            }
            RequestedVersion::Specific(v)
        }
    };
    let verify = verify_mode(&r)?;
    if matches!(source, SourceSpec::Url { .. }) && verify == VerifyMode::Sha256 {
        return Err(PluginError::usage(
            "a source=url artifact has no trusted SHA-256, so verify=sha256 (the default) cannot \
             be satisfied; install from a registry, or pass verify=none to install it \
             unverified; nothing was done",
        ));
    }
    Ok(PluginOpArgs {
        mode: Mode::Install,
        plugin_id: id.to_string(),
        source,
        requested_version,
        verify,
        force: r.bool("force", false)?,
        allow_downgrade: r.bool("allow_downgrade", false)?,
        dry_run: r.bool("dry_run", false)?,
        strict: false,
        purge: false,
        timeout_ms: r.timeout_ms(300_000)?,
        ca_file: r.ca_file()?,
    })
}

fn verify_mode(r: &ArgReader) -> PResult<VerifyMode> {
    Ok(match r.choice("verify", &["sha256", "none"], "sha256")? {
        "none" => VerifyMode::None,
        _ => VerifyMode::Sha256,
    })
}

fn update_args(id: &str, args: &Args) -> PResult<PluginOpArgs> {
    let r = ArgReader::new(args);
    if r.has("url") && r.has("registry") {
        return Err(PluginError::usage(
            "give registry=<https-url> or url=<https-url>, not both; nothing was done",
        ));
    }
    let verify = verify_mode(&r)?;
    let source = match r.string("url")? {
        Some(u) => {
            if verify == VerifyMode::Sha256 {
                return Err(PluginError::usage(
                    "a url artifact has no trusted SHA-256, so verify=sha256 (the default) cannot \
                     be satisfied; pass verify=none to update from it unverified; nothing was done",
                ));
            }
            SourceSpec::Url {
                url: parse_https_url("url", &u)?,
            }
        }
        None => SourceSpec::Registry {
            url: parse_https_url(
                "registry",
                &r.string("registry")?
                    .unwrap_or_else(|| DEFAULT_REGISTRY.into()),
            )?,
        },
    };
    Ok(PluginOpArgs {
        mode: Mode::Update,
        plugin_id: id.to_string(),
        source,
        requested_version: RequestedVersion::Latest,
        verify,
        force: false,
        allow_downgrade: false,
        dry_run: r.bool("dry_run", false)?,
        strict: r.bool("strict", false)?,
        purge: false,
        timeout_ms: r.timeout_ms(300_000)?,
        ca_file: r.ca_file()?,
    })
}

fn remove_args(id: &str, args: &Args) -> PResult<PluginOpArgs> {
    let r = ArgReader::new(args);
    Ok(PluginOpArgs {
        mode: Mode::Remove,
        plugin_id: id.to_string(),
        source: SourceSpec::File {
            path: String::new(),
        },
        requested_version: RequestedVersion::Latest,
        verify: VerifyMode::None,
        force: r.bool("force", false)?,
        allow_downgrade: false,
        dry_run: r.bool("dry_run", false)?,
        strict: false,
        purge: r.bool("purge", false)?,
        timeout_ms: r.timeout_ms(30_000)?,
        ca_file: None,
    })
}

fn enable_args(args: &Args) -> PResult<SetEnabledOptions> {
    let r = ArgReader::new(args);
    let scope = match r.choice("scope", &["user", "system"], "user")? {
        "system" => Scope::System,
        _ => Scope::User,
    };
    let reason = match args.get("reason") {
        None => None,
        Some(t) if t.chars().count() > 200 => {
            return Err(PluginError::usage(
                "reason is longer than 200 characters; nothing was done",
            ));
        }
        Some(t) if t.chars().any(char::is_control) => {
            return Err(PluginError::usage(
                "reason must not contain control characters; nothing was done",
            ));
        }
        Some(t) => Some(t.clone()),
    };
    Ok(SetEnabledOptions {
        scope,
        force: r.bool("force", false)?,
        dry_run: r.bool("dry_run", false)?,
        reason,
    })
}

impl PluginHandle {
    fn lifecycle(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let id = match self.lifecycle_id(verb) {
            Ok(id) => id.to_string(),
            Err(e) => return Ok(status_of(Some(&e))),
        };
        if matches!(verb, "enable" | "disable") {
            let opts = match enable_args(args) {
                Ok(o) => o,
                Err(e) => return Ok(status_of(Some(&e))),
            };
            let out = state::set_enabled(&id, verb == "enable", &opts);
            write_json(io, &out.envelope)?;
            return Ok(status_of(out.error.as_ref()));
        }
        let parsed = match verb {
            "install" => install_args(&id, args),
            "update" => update_args(&id, args),
            _ => remove_args(&id, args),
        };
        let op_args = match parsed {
            Ok(a) => a,
            Err(e) => return Ok(status_of(Some(&e))),
        };
        let out = engine::run(&op_args);
        write_json(io, &out.envelope)?;
        Ok(status_of(out.error.as_ref()))
    }

    fn catalog_verb(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Err(e) = self.catalog_target(verb) {
            return Ok(status_of(Some(&e)));
        }
        let out = match verb {
            "available.list" => catalog::available_list(&self.target, args),
            "available.search" => catalog::available_search(&self.target, args),
            "available.info" => available::available_info(&self.target, args),
            _ => catalog::installed_list(&self.target, args),
        };
        // Refused arguments (exit 2) print only the error line.
        if !out.error.as_ref().is_some_and(|e| e.exit == 2) {
            write_json(io, &out.envelope)?;
        }
        Ok(status_of(out.error.as_ref()))
    }
}

impl Handle for PluginHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "install",
            "update",
            "remove",
            "enable",
            "disable",
            "available.list",
            "available.search",
            "available.info",
            "installed.list",
            "--help",
            "-h",
            "help",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&PLUGIN_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // `plugin://<id>.<verb>?help` and `plugin://installed.list?help`:
        // the stage parser leaves the query on the verb.
        if let Some(base) = verb.strip_suffix("?help") {
            let specific = VERBS
                .iter()
                .find(|v| base == **v || base.ends_with(&format!(".{v}")))
                .copied();
            return self.display_help(io, specific);
        }
        if self.help_requested(verb, args) {
            fn named(v: Option<&String>) -> Option<&str> {
                v.map(|s| s.as_str())
                    .filter(|s| !s.is_empty() && *s != "true")
            }
            let specific = if let Some(v) = verb.strip_prefix("--help=") {
                Some(v)
            } else if VERBS.contains(&verb) {
                named(args.get("verb"))
                    .or(named(args.get("help")))
                    .or(Some(verb))
            } else {
                named(args.get("verb")).or(named(args.get("help")))
            };
            return self.display_help(io, specific);
        }
        if !VERBS.contains(&verb) {
            // plugin://aws.instal arrives as the verb "aws.instal".
            let last = verb.split_once('.').map_or(verb, |(_, v)| v);
            let suggestion = suggest(verb, VERBS).or_else(|| suggest(last, VERBS));
            return Ok(Status::coded(
                2,
                crate::handles::pluginh::common::UNKNOWN_VERB,
                format!(
                    "unknown verb {verb:?}{}; plugin verbs: {}",
                    suggestion
                        .map(|s| format!(" (did you mean `{s}`?)"))
                        .unwrap_or_default(),
                    VERBS.join(", ")
                ),
            ));
        }
        if let Err(e) = check_known(verb, args) {
            return Ok(status_of(Some(&e)));
        }
        match verb {
            "install" | "update" | "remove" | "enable" | "disable" => {
                self.lifecycle(verb, args, io)
            }
            _ => self.catalog_verb(verb, args, io),
        }
    }
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("plugin", |url: &Url| -> Result<Box<dyn Handle>> {
        Ok(Box::new(PluginHandle::new(url)?))
    });
}

/// The help metadata (for tests).
#[cfg(test)]
pub(crate) fn plugin_help() -> &'static HandleHelp {
    &PLUGIN_HELP
}

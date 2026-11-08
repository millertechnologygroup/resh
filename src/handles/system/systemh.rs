//! `system://`: read-only information about the local Linux host (CPU,
//! memory, disk, load, uptime, environment), read from `/proc`, `/sys` and
//! system calls. Nothing is changed and no program is run.

mod args;
mod cgroup;
mod disk;
mod env;
mod error;
mod host;
mod info;
mod metrics;
#[cfg(test)]
mod tests;
mod text;

use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, exit},
};
use args::{HELP_KEYS, OutputFormat};
use error::{SysError, exit_for};
use host::Host;

/// Metadata for `resh system --help` and `resh system <verb> --help`.
static SYSTEM_HELP: HandleHelp = HandleHelp {
    description: "The system handle reports information about the local Linux host, such as \
        CPU, memory, disk, load, uptime, and environment variables, read from the /proc and \
        /sys filesystems and system calls, and changes nothing; every command takes the form system://.<verb>, \
        since the stage URL has no target. Options are \
        key=value arguments, keys of one JSON object in the input argument, or both (an \
        unknown option or a bad value is refused with exit 2), and each verb prints JSON, \
        or text with format=text.",
    usage: "resh system://.<verb> [<option>=<value> ...] [input=<json>]",
    verbs: &[
        VerbHelp {
            name: "info",
            definition: "Gathers host information for selected scopes, such as os, kernel, \
                cpu, memory, and load, into one report; a scope that cannot be read is \
                marked available false.",
            detail: Some(VerbDetail {
                usage: "resh system://.info [scopes=<list>] [fields=<list>]\n  \
                    [sample_duration_ms=<n>] [sample_min_ms=<n>] [per_cpu=true|false]\n  \
                    [max_mounts=<n>] [max_process_classes=<n>] [include_raw=true|false]\n  \
                    [include_paths=true|false] [timeout_ms=<n>] [format=json|text]\n  \
                    [input=<json>]\n  \
                    scopes: os, kernel, cpu, memory, load, disk, process, pressure,\n    \
                    cgroup, virtualization (default os,kernel,cpu,memory,load)\n  \
                    fields: <scope> or <scope>.<key> entries; only these are reported\n  \
                    defaults: sample_duration_ms=0 (no CPU sampling; per_cpu needs it),\n    \
                    sample_min_ms=50, per_cpu=false, max_mounts=32,\n    \
                    max_process_classes=5, include_raw=false, include_paths=false,\n    \
                    timeout_ms=30000, format=json",
                example: "resh --json-pretty system://.info scopes=kernel,load",
                example_output: Some(
                    r##"{
  "kernel": {
    "available": true,
    "boot_time_unix": 1782329358,
    "machine": "x86_64",
    "release": "6.8.0-45-generic",
    "uptime_seconds": 9836564.18,
    "version": "#45-Ubuntu SMP PREEMPT_DYNAMIC Fri Aug 30 12:02:04 UTC 2024"
  },
  "load": {
    "available": true,
    "load_15m": 0.95,
    "load_1m": 0.33,
    "load_5m": 0.65,
    "runnable_processes": 1,
    "total_processes": 412
  },
  "ok": true,
  "scopes": [
    "kernel",
    "load"
  ],
  "timestamp_unix_ms": 1792165922676,
  "warnings": []
}

Shown with --json-pretty."##,
                ),
            }),
        },
        VerbHelp {
            name: "uptime",
            definition: "Reports system uptime, boot time, and idle time read from \
                /proc/uptime and /proc/stat.",
            detail: Some(VerbDetail {
                usage: "resh system://.uptime [include_idle=true|false]\n  \
                    [include_boot_time=true|false] [include_human=true|false]\n  \
                    [include_raw=true|false] [include_paths=true|false]\n  \
                    [format=json|text] [input=<json>]\n  \
                    defaults: include_idle, include_boot_time and include_human true;\n    \
                    include_raw and include_paths false; format=json",
                example: "resh --json-pretty system://.uptime",
                example_output: Some(
                    r#"{
  "boot_time_unix": 1782329358,
  "idle_seconds": 312700310.44,
  "idle_seconds_per_cpu": 39087538.805,
  "ok": true,
  "timestamp_unix_ms": 1792165902862,
  "uptime_human": "113d 20h 22m 24s",
  "uptime_seconds": 9836544.36,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "load",
            definition: "Reports the 1, 5, and 15 minute load averages, their values per \
                online CPU, and the runnable and total task counts from /proc/loadavg.",
            detail: Some(VerbDetail {
                usage: "resh system://.load [normalize_per_cpu=true|false]\n  \
                    [include_queue=true|false] [include_human=true|false]\n  \
                    [include_raw=true|false] [include_paths=true|false]\n  \
                    [min_cpu_count=<n>] [format=json|text] [input=<json>]\n  \
                    defaults: normalize_per_cpu, include_queue and include_human true;\n    \
                    include_raw and include_paths false; min_cpu_count=1 (the\n    \
                    smallest divisor for per-CPU values); format=json",
                example: "resh --json-pretty system://.load",
                example_output: Some(
                    r#"{
  "cpu_count_logical": 8,
  "human": {
    "load_vs_cpu_ratio": 0.04875,
    "status": "idle",
    "status_reason": "1m load per CPU is very low (< 0.1)"
  },
  "load_15m": 0.97,
  "load_15m_per_cpu": 0.12125,
  "load_1m": 0.39,
  "load_1m_per_cpu": 0.04875,
  "load_5m": 0.67,
  "load_5m_per_cpu": 0.08375,
  "ok": true,
  "runnable_processes": 1,
  "timestamp_unix_ms": 1792165915507,
  "total_processes": 412,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "memory",
            definition: "Reports RAM, swap, hugepage, and cgroup memory usage in bytes, with \
                each section and the human-readable summaries selectable by option.",
            detail: Some(VerbDetail {
                usage: "resh system://.memory [include_swap=true|false]\n  \
                    [include_cgroup=true|false] [include_hugepages=true|false]\n  \
                    [include_human=true|false] [include_raw=true|false]\n  \
                    [include_paths=true|false] [format=json|text] [input=<json>]\n  \
                    defaults: include_swap, include_cgroup, include_hugepages and\n    \
                    include_human true; include_raw and include_paths false;\n    \
                    format=json",
                example: "resh --json-pretty system://.memory include_hugepages=false",
                example_output: Some(
                    r#"{
  "cgroup": {
    "available": true,
    "memory_limit_bytes": 536870912,
    "memory_usage_bytes": 31457280,
    "memory_used_pct": 5.859375,
    "swap_limit_bytes": 0,
    "swap_usage_bytes": 0,
    "unified": true
  },
  "human": {
    "cgroup_summary": "0.5 GiB limit, 0.0 GiB used (5.9%)",
    "system_summary": "15.5 GiB total, 4.2 GiB used (27.1%), no swap"
  },
  "ok": true,
  "system": {
    "available": true,
    "buffers_bytes": 412090368,
    "cached_bytes": 6442450944,
    "mem_available_bytes": 12171116544,
    "mem_free_bytes": 5368709120,
    "mem_total_bytes": 16691884032,
    "mem_used_bytes": 4520767488,
    "mem_used_pct": 27.0836,
    "shmem_bytes": 268435456,
    "sreclaimable_bytes": 536870912,
    "swap_free_bytes": 0,
    "swap_total_bytes": 0,
    "swap_used_bytes": 0,
    "swap_used_pct": 0.0
  },
  "timestamp_unix_ms": 1792165915513,
  "warnings": []
}

Shown for a container started with --memory 512m, with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "cpu",
            definition: "Samples /proc/stat twice, sample_duration_ms apart, and reports \
                utilization percentages for that interval, with topology, frequency, and \
                cgroup CPU limits.",
            detail: Some(VerbDetail {
                usage: "resh system://.cpu [sample_duration_ms=<n>] [sample_min_ms=<n>]\n  \
                    [per_cpu=true|false] [include_topology=true|false]\n  \
                    [include_frequency=true|false] [include_cgroup=true|false]\n  \
                    [include_human=true|false] [include_raw=true|false]\n  \
                    [include_paths=true|false] [format=json|text] [input=<json>]\n  \
                    defaults: sample_duration_ms=250 (0 uses sample_min_ms; at most\n    \
                    60000), sample_min_ms=50, per_cpu, include_topology,\n    \
                    include_frequency, include_cgroup and include_human true;\n    \
                    include_raw and include_paths false; format=json",
                example: "resh --json-pretty system://.cpu per_cpu=false",
                example_output: Some(
                    r#"{
  "cgroup": {
    "available": true,
    "cpu_period_us": 100000,
    "unified": true,
    "usage_seconds": 5408.12,
    "usage_system_seconds": 1204.33,
    "usage_user_seconds": 4203.79
  },
  "human": {
    "per_cpu_hotspots": [],
    "status": "idle",
    "status_reason": "Overall CPU utilization is 2.2%, system is idle."
  },
  "ok": true,
  "sample_duration_ms": 250,
  "system": {
    "available": true,
    "cgroup_utilization_pct": null,
    "frequency_current_hz": 3364628000,
    "frequency_max_hz": 4800000000,
    "guest_nice_pct": 0.0,
    "guest_pct": 0.0,
    "idle_pct": 97.75,
    "iowait_pct": 0.0,
    "irq_pct": 0.0,
    "logical_count": 8,
    "nice_pct": 0.0,
    "physical_count": 4,
    "socket_count": 1,
    "softirq_pct": 0.125,
    "steal_pct": 0.0,
    "system_pct": 0.5,
    "user_pct": 1.625,
    "utilization_pct": 2.25
  },
  "timestamp_unix_ms": 1792165918857,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "disk",
            definition: "Reports capacity, inode usage, and I/O counters for mounted \
                filesystems, skipping pseudo filesystems such as proc and tmpfs by default.",
            detail: Some(VerbDetail {
                usage: "resh system://.disk [mount_points=<list>] [devices=<list>]\n  \
                    [fs_types=<list>] [include_virtual=true|false] [max_mounts=<n>]\n  \
                    [include_io=true|false] [include_fs_types=true|false]\n  \
                    [include_human=true|false] [include_raw=true|false]\n  \
                    [include_paths=true|false] [timeout_ms=<n>] [format=json|text]\n  \
                    [input=<json>]\n  \
                    mount_points, devices: each must be mounted (else exit 1)\n  \
                    defaults: include_virtual=false, max_mounts=64, include_io,\n    \
                    include_fs_types and include_human true; include_raw and\n    \
                    include_paths false; timeout_ms=30000; format=json",
                example: "resh --json-pretty system://.disk mount_points=/",
                example_output: Some(
                    r#"{
  "human": {
    "summaries": [
      "/: 468.3 GiB total, 143.3 GiB used (33%)"
    ]
  },
  "io": {
    "available": true,
    "devices": [
      {
        "ios_in_progress": 0,
        "maj_min": "259:0",
        "name": "nvme0n1",
        "read_bytes": 281699979264,
        "reads_completed": 5053657,
        "sectors_read": 550195272,
        "sectors_written": 2991165130,
        "time_in_io_ms": 38465574,
        "time_reading_ms": 1850688,
        "time_writing_ms": 143221834,
        "weighted_time_in_io_ms": 150129491,
        "write_bytes": 1531476546560,
        "writes_completed": 38571125
      }
    ]
  },
  "mounts": [
    {
      "avail_bytes": 323418742784,
      "device": "/dev/nvme0n1p2",
      "free_bytes": 348985356288,
      "free_pct": 69.41,
      "fs_type": "ext4",
      "human_summary": "/: 468.3 GiB total, 143.3 GiB used (33%)",
      "inodes_free": 30212143,
      "inodes_total": 31227904,
      "inodes_used": 1015761,
      "inodes_used_pct": 3.25,
      "io_device": "nvme0n1",
      "mount_point": "/",
      "tags": [
        "rootfs"
      ],
      "total_bytes": 502819409920,
      "used_bytes": 153834053632,
      "used_of_total_pct": 30.59,
      "used_pct": 33.0,
      "virtual_fs": false
    }
  ],
  "mounts_truncated": false,
  "ok": true,
  "timestamp_unix_ms": 1792165919116,
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
        VerbHelp {
            name: "env.list",
            definition: "Lists the environment variables of the resh process or of another \
                process by PID, masking sensitive values by default.",
            detail: Some(VerbDetail {
                usage: "resh system://.env.list [pid=<n>] [names=<list>]\n  \
                    [prefix_filters=<list>] [regex_filters=<list>]\n  \
                    [include_values=true|false] [include_sensitive=true|false]\n  \
                    [truncate_length=<n>] [max_vars=<n>] [sort_by=name|length|none]\n  \
                    [sort_order=asc|desc] [include_raw=true|false]\n  \
                    [include_paths=true|false] [format=json|text] [input=<json>]\n  \
                    defaults: pid is resh itself, include_values=true,\n    \
                    include_sensitive=false, truncate_length=512 (0 = no limit),\n    \
                    max_vars=1024, sort_by=name, sort_order=asc, include_raw and\n    \
                    include_paths false, format=json",
                example: "resh --json-pretty system://.env.list names=HOME,SHELL",
                example_output: Some(
                    r#"{
  "env_count_masked": 0,
  "env_count_returned": 2,
  "env_count_total": 31,
  "env_count_truncated": 0,
  "human": {
    "summary": "2 of 31 environment variables listed (0 masked, 0 truncated)"
  },
  "ok": true,
  "pid": 48211,
  "source": "process",
  "timestamp_unix_ms": 1792165919120,
  "truncated_vars": false,
  "variables": [
    {
      "masked": false,
      "name": "HOME",
      "source": "process",
      "truncated": false,
      "value": "/home/alice",
      "value_length": 11
    },
    {
      "masked": false,
      "name": "SHELL",
      "source": "process",
      "truncated": false,
      "value": "/bin/bash",
      "value_length": 9
    }
  ],
  "warnings": []
}

Shown with --json-pretty."#,
                ),
            }),
        },
    ],
};

/// Verbs registered by the system handle.
const SYSTEM_VERBS: &[&str] = &[
    "info", "uptime", "load", "memory", "cpu", "disk", "env.list",
];

/// Returns `Some(verb)` when the arguments ask for help: a help key
/// (`help`, `--help`, `-h`, `h`, optionally `=<verb>`), or an `input` value
/// that is exactly `--help`, `-h` or `--help=<verb>`. Matching is exact, so
/// input text that merely contains "-h" is not a help request.
fn help_request(args: &Args) -> Option<Option<String>> {
    for key in HELP_KEYS {
        if let Some(value) = args.get(*key) {
            let value = value.trim();
            let verb = (!value.is_empty() && value != "true").then(|| value.to_string());
            return Some(verb);
        }
    }
    let input = args.get("input")?.trim();
    if crate::core::help::is_help_flag(input) {
        return Some(None);
    }
    input
        .strip_prefix("--help=")
        .map(|verb| Some(verb.trim().to_string()).filter(|v| !v.is_empty()))
}

/// True when the call asked for text output (as a word or in `input`), so
/// a failure before the options are parsed is reported in that format.
fn wants_text(args: &Args) -> bool {
    if let Some(f) = args.get("format") {
        return f == "text";
    }
    args.get("input")
        .and_then(|i| serde_json::from_str::<Value>(i).ok())
        .is_some_and(|v| v["format"] == "text")
}

#[derive(Debug)]
pub struct SystemHandle;

impl SystemHandle {
    /// The URL must have no target: `system://.<verb>`.
    pub fn from_url(url: &Url) -> Result<Self> {
        let host = url.host_str().unwrap_or("");
        let path = url.path();
        // In-URL help forms (`system://--help`, `system://help`) name no target.
        let help_form = crate::core::help::is_help_flag(host)
            || crate::core::help::HELP_ALIASES.contains(&host);
        if (!host.is_empty() && !help_form) || !(path.is_empty() || path == "/") {
            anyhow::bail!(
                "system:// takes no target (got {:?}); use system://.<verb>",
                format!("{host}{path}")
            );
        }
        Ok(SystemHandle)
    }
}

/// Prints a failure (as JSON unless text output was asked for) and returns
/// its status; `main` prints `Error: [<code>] <message>`.
fn fail(io: &mut IoStreams, text: bool, err: &SysError) -> Result<Status> {
    if !text {
        let v = json!({ "ok": false, "error": err.to_json() });
        writeln!(io.stdout, "{}", serde_json::to_string_pretty(&v)?)?;
        io.stdout.flush()?;
    }
    Ok(Status::coded(err.exit(), err.code, &err.message))
}

/// Prints a response. A response with `"ok": false` (a timeout with partial
/// results) is a failure with the code in its `error` object.
fn emit<T: Serialize>(
    io: &mut IoStreams,
    format: OutputFormat,
    resp: &T,
    render: impl FnOnce(&T) -> String,
) -> Result<Status> {
    let v = serde_json::to_value(resp)?;
    if v["ok"] == false {
        let code = v["error"]["code"].as_str().unwrap_or("system.timeout");
        let msg = v["error"]["message"].as_str().unwrap_or_default();
        if format == OutputFormat::Json {
            writeln!(io.stdout, "{}", serde_json::to_string_pretty(&v)?)?;
            io.stdout.flush()?;
        }
        return Ok(Status::coded(exit_for(code), code, msg));
    }
    match format {
        OutputFormat::Json => writeln!(io.stdout, "{}", serde_json::to_string_pretty(&v)?)?,
        OutputFormat::Text => write!(io.stdout, "{}", render(resp))?,
    }
    io.stdout.flush()?;
    Ok(Status::ok())
}

/// Runs `verb` against `host`.
fn run(host: &Host, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
    let text = wants_text(args);
    macro_rules! go {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(e) => return fail(io, text, &e),
            }
        };
    }
    match verb {
        "info" => {
            let o: args::InfoOptions = go!(args::parse(verb, args));
            go!(args::validate_info(&o));
            let v = go!(info::info(host, &o));
            emit(io, o.format, &v, text::info)
        }
        "uptime" => {
            let o: args::UptimeOptions = go!(args::parse(verb, args));
            let r = go!(metrics::uptime(host, &o));
            emit(io, o.format, &r, text::uptime)
        }
        "load" => {
            let o: args::LoadOptions = go!(args::parse(verb, args));
            go!(args::validate_load(&o));
            let r = go!(metrics::load(host, &o));
            emit(io, o.format, &r, text::load)
        }
        "memory" => {
            let o: args::MemoryOptions = go!(args::parse(verb, args));
            let r = go!(metrics::memory(host, &o));
            emit(io, o.format, &r, text::memory)
        }
        "cpu" => {
            let o: args::CpuOptions = go!(args::parse(verb, args));
            go!(args::validate_cpu(&o));
            let r = go!(metrics::cpu(host, &o));
            emit(io, o.format, &r, text::cpu)
        }
        "disk" => {
            let o: args::DiskOptions = go!(args::parse(verb, args));
            go!(args::validate_disk(&o));
            let r = go!(disk::disk(host, &o));
            emit(io, o.format, &r, text::disk)
        }
        "env.list" => {
            let o: args::EnvListOptions = go!(args::parse(verb, args));
            let regexes = go!(args::validate_env_list(&o));
            let r = go!(env::env_list(host, &o, &regexes));
            emit(io, o.format, &r, text::env_list)
        }
        _ => {
            let msg = format!(
                "unknown verb for system: {verb:?}{} (verbs: {})",
                args::did_you_mean(verb, SYSTEM_VERBS),
                SYSTEM_VERBS.join(", ")
            );
            Ok(Status::coded(exit::USAGE, "system.unknown_verb", msg))
        }
    }
}

impl Handle for SystemHandle {
    fn verbs(&self) -> &'static [&'static str] {
        SYSTEM_VERBS
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        Some(&SYSTEM_HELP)
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let topic = if crate::core::help::HELP_ALIASES.contains(&verb) {
            Some(None)
        } else {
            help_request(args).map(|t| t.or_else(|| Some(verb.to_string())))
        };
        if let Some(topic) = topic {
            let text = crate::core::help::render_legacy(
                "system",
                &SYSTEM_HELP,
                SYSTEM_VERBS,
                topic.as_deref(),
            );
            write!(io.stdout, "{text}")?;
            return Ok(Status::ok());
        }
        run(&Host::real(), verb, args, io)
    }
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("system", |u| Ok(Box::new(SystemHandle::from_url(u)?)));
    reg.set_probe_url("system", "system://");
}

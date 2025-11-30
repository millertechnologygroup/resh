use anyhow::Result;
use chrono::{DateTime, TimeZone, Utc};
use cron::Schedule;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::str::FromStr;
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

// ===========================================================================
// CronHandle - Main handle struct
// ===========================================================================

#[derive(Debug)]
pub struct CronHandle {
    alias: String,
    provider: Box<dyn CronProvider + Send + Sync>,
}

impl CronHandle {
    pub fn new(alias: String, provider: Box<dyn CronProvider>) -> Self {
        Self { alias, provider }
    }

    pub fn from_url(url: &Url) -> Result<Self> {
        let alias = url.host_str().unwrap_or("default").to_string();
        let provider = Box::new(SystemCronProvider::new());
        Ok(Self::new(alias, provider))
    }

    fn list_verb(&self, _args: &Args) -> Result<String> {
        let options = CronListOptions {
            scope: "current".to_string(),
            users: Vec::new(),
            include_system: false,
            include_files: Vec::new(),
            state: "all".to_string(),
            match_command: None,
            match_comment: None,
            match_user: None,
            match_source: None,
            include_next_run: false,
            now_unix: None,
            timezone: None,
            max_entries: 1024,
            sort_by: "none".to_string(),
            sort_order: "asc".to_string(),
            include_raw: false,
            include_paths: false,
            format: OutputFormat::Json,
        };
        
        match self.provider.list_cron_entries(&options) {
            Ok(response) => Ok(serde_json::to_string_pretty(&response)?),
            Err(e) => {
                let error_response = CronListResponse {
                    ok: false,
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    scope: options.scope,
                    users: options.users,
                    include_system: options.include_system,
                    truncated: false,
                    entries_total: None,
                    entries_returned: 0,
                    entries_disabled: 0,
                    entries: Vec::new(),
                    raw: None,
                    paths: None,
                    human: None,
                    error: Some(json!({"code": "cron.list_error", "message": e.to_string()})),
                    warnings: Vec::new(),
                };
                Ok(serde_json::to_string_pretty(&error_response)?)
            }
        }
    }

    fn format_as_text(&self, response: &CronListResponse) -> String {
        let mut output = String::new();
        
        output.push_str("Cron Jobs\n");
        output.push_str("=========\n\n");
        
        output.push_str(&format!("Scope      : {}\n", response.scope));
        if !response.users.is_empty() {
            output.push_str(&format!("Users      : {}\n", response.users.join(", ")));
        }
        output.push_str(&format!("System     : {}\n", if response.include_system { "included" } else { "excluded" }));
        output.push_str(&format!("Returned   : {} ({} enabled, {} disabled)\n\n", 
            response.entries_returned, 
            response.entries_returned - response.entries_disabled, 
            response.entries_disabled));

        for entry in &response.entries {
            output.push_str(&format!("[{}]", entry.source));
            if let Some(ref file) = entry.source_file {
                output.push_str(&format!(" {}:{}", file, entry.source_line.unwrap_or(0)));
            } else if let Some(ref user) = entry.user {
                output.push_str(&format!(" crontab({})", user));
                if let Some(line) = entry.source_line {
                    output.push_str(&format!(":{}", line));
                }
            }
            output.push('\n');

            output.push_str(&format!("  Enabled  : {}\n", if entry.enabled { "yes" } else { "no (commented)" }));
            
            if let Some(ref user) = entry.user {
                output.push_str(&format!("  User     : {}\n", user));
            }
            
            if let Some(ref schedule) = entry.schedule {
                let description = match schedule.as_str() {
                    "0 2 * * *" => " (nightly)",
                    "0 0 * * *" => " (daily)",
                    "0 0 * * 0" => " (weekly)",
                    _ => "",
                };
                output.push_str(&format!("  Schedule : {}{}\n", schedule, description));
            }
            
            if let Some(ref special) = entry.special {
                output.push_str(&format!("  Special  : {}\n", special));
            }
            
            if let Some(ref command) = entry.command {
                output.push_str(&format!("  Command  : {}\n", command));
            }
            
            if let Some(ref comment) = entry.comment {
                output.push_str(&format!("  Comment  : {}\n", comment));
            }
            
            if let Some(ref next_run) = entry.next_run_iso8601 {
                output.push_str(&format!("  Next Run : {}\n", next_run));
            }
            
            output.push('\n');
        }

        if !response.warnings.is_empty() {
            output.push_str("Warnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        } else {
            output.push_str("Warnings:\n  (none)\n");
        }

        if response.truncated {
            output.push_str(&format!("\nNote: Entry list truncated to max_entries={}.\n", 
                response.entries_returned));
        }

        output
    }

    fn add_verb(&self, args: &Args) -> Result<String> {
        // Parse arguments from URL query parameters
        let schedule = args.get("schedule")
            .ok_or_else(|| anyhow::anyhow!("schedule parameter is required"))?
            .clone();
        let command = args.get("command")
            .ok_or_else(|| anyhow::anyhow!("command parameter is required"))?
            .clone();

        let options = CronAddOptions {
            schedule,
            command,
            backend: args.get("backend").unwrap_or(&"auto".to_string()).clone(),
            id: args.get("id").cloned(),
            description: args.get("description").cloned(),
            allow_duplicate: args.get("allow_duplicate").unwrap_or(&"true".to_string()) == "true",
            dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
            scope: args.get("scope").unwrap_or(&"current".to_string()).clone(),
            user: args.get("user").cloned(),
            cron_file: args.get("cron_file").cloned(),
            unit_name: args.get("unit_name").cloned(),
            unit_scope: args.get("unit_scope").unwrap_or(&"auto".to_string()).clone(),
            persistent: args.get("persistent").unwrap_or(&"true".to_string()) == "true",
            accuracy_sec: args.get("accuracy_sec").cloned(),
            random_delay_sec: args.get("random_delay_sec").cloned(),
            service_working_dir: args.get("service_working_dir").cloned(),
            service_user: args.get("service_user").cloned(),
            env: parse_env_from_args(args),
            include_next_run: args.get("include_next_run").unwrap_or(&"true".to_string()) == "true",
            now_unix: args.get("now_unix").and_then(|s| s.parse().ok()),
            timezone: args.get("timezone").cloned(),
            format: if args.get("format").unwrap_or(&"json".to_string()) == "text" {
                OutputFormat::Text
            } else {
                OutputFormat::Json
            },
        };

        match self.provider.add_cron_job(&options) {
            Ok(response) => {
                if matches!(options.format, OutputFormat::Text) {
                    Ok(self.format_add_as_text(&response))
                } else {
                    Ok(serde_json::to_string_pretty(&response)?)
                }
            }
            Err(e) => {
                let error_response = CronAddResponse {
                    ok: false,
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    backend_used: None,
                    dry_run: options.dry_run,
                    duplicate: false,
                    job: None,
                    preview: None,
                    error: Some(json!({"code": "cron.add_error", "message": e.to_string()})),
                    warnings: Vec::new(),
                };
                Ok(serde_json::to_string_pretty(&error_response)?)
            }
        }
    }

    fn format_add_as_text(&self, response: &CronAddResponse) -> String {
        let mut output = String::new();
        
        if response.ok {
            output.push_str("Cron Job Added Successfully\n");
            output.push_str("===========================\n\n");
            
            if let Some(ref job) = response.job {
                output.push_str(&format!("Backend    : {}\n", job.backend));
                output.push_str(&format!("Schedule   : {}\n", job.schedule));
                output.push_str(&format!("Command    : {}\n", job.command));
                if let Some(ref id) = job.id {
                    output.push_str(&format!("Job ID     : {}\n", id));
                }
                output.push_str(&format!("Location   : {} scope\n", job.location.scope));
                if let Some(ref file) = job.location.file {
                    output.push_str(&format!("File       : {}\n", file));
                }
                if let Some(ref unit_name) = job.location.unit_name {
                    output.push_str(&format!("Unit       : {}\n", unit_name));
                }
                if let Some(ref next_run) = job.next_run_iso8601 {
                    output.push_str(&format!("Next Run   : {}\n", next_run));
                }
            }
            
            if response.dry_run {
                output.push_str("\n[DRY RUN] No changes were made.\n");
            }
            
            if response.duplicate {
                output.push_str("\n[DUPLICATE] Job already exists - no changes made.\n");
            }
        } else {
            output.push_str("Cron Job Add Failed\n");
            output.push_str("===================\n\n");
            if let Some(ref error) = response.error {
                if let Some(code) = error.get("code").and_then(|c| c.as_str()) {
                    output.push_str(&format!("Error Code : {}\n", code));
                }
                if let Some(message) = error.get("message").and_then(|m| m.as_str()) {
                    output.push_str(&format!("Message    : {}\n", message));
                }
            }
        }

        if !response.warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        output
    }

    pub fn rm_verb(&self, args: &Args) -> Result<String> {
        // Validate backend
        let backend = args.get("backend").unwrap_or(&"both".to_string()).clone();
        if !["cron", "systemd", "both"].contains(&backend.as_str()) {
            let error_response = CronRmResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
                backend: backend.clone(),
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                removed: CronRmRemovedSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronRmMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                error: Some(json!({"code": "cron.rm_invalid_backend", "message": format!("Invalid backend '{}'. Must be one of: cron, systemd, both", backend)})),
                warnings: Vec::new(),
            };
            return Ok(serde_json::to_string_pretty(&error_response)?);
        }

        // Validate that at least one selector is provided
        let has_selector = args.get("id").is_some() 
            || args.get("schedule").is_some() 
            || args.get("command").is_some()
            || args.get("match_command").is_some()
            || args.get("match_comment").is_some()
            || args.get("unit_name").is_some()
            || args.get("match_unit").is_some();
            
        if !has_selector {
            let error_response = CronRmResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
                backend: backend.clone(),
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                removed: CronRmRemovedSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronRmMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                error: Some(json!({"code": "cron.rm_no_selector", "message": "At least one selector must be provided: id, schedule, command, match_command, match_comment, unit_name, or match_unit"})),
                warnings: Vec::new(),
            };
            return Ok(serde_json::to_string_pretty(&error_response)?);
        }

        // Build options from args
        let options = CronRmOptions {
            id: args.get("id").cloned(),
            backend,
            
            scope: args.get("scope").unwrap_or(&"all".to_string()).clone(),
            users: args.get("users")
                .map(|s| s.split(',').map(|u| u.trim().to_string()).collect())
                .unwrap_or_default(),
            schedule: args.get("schedule").cloned(),
            command: args.get("command").cloned(),
            match_command: args.get("match_command").cloned(),
            match_comment: args.get("match_comment").cloned(),
            cron_file: args.get("cron_file").cloned(),
            
            unit_name: args.get("unit_name").cloned(),
            unit_scope: args.get("unit_scope").unwrap_or(&"auto".to_string()).clone(),
            match_unit: args.get("match_unit").cloned(),
            
            require_match: args.get("require_match").unwrap_or(&"true".to_string()) == "true",
            remove_units: args.get("remove_units").unwrap_or(&"true".to_string()) == "true",
            dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
            
            format: if args.get("format").unwrap_or(&"json".to_string()) == "text" {
                OutputFormat::Text
            } else {
                OutputFormat::Json
            },
        };

        match self.provider.remove_cron_jobs(&options) {
            Ok(response) => {
                if matches!(options.format, OutputFormat::Text) {
                    Ok(self.format_rm_as_text(&response))
                } else {
                    Ok(serde_json::to_string_pretty(&response)?)
                }
            }
            Err(e) => {
                let error_response = CronRmResponse {
                    ok: false,
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    dry_run: options.dry_run,
                    backend: options.backend.clone(),
                    cron_modified_sources: Vec::new(),
                    systemd_scopes_touched: Vec::new(),
                    removed: CronRmRemovedSummary {
                        cron: Vec::new(),
                        systemd: Vec::new(),
                    },
                    matched_count: CronRmMatchedCount {
                        cron: 0,
                        systemd: 0,
                    },
                    error: Some(json!({"code": "cron.rm_error", "message": e.to_string()})),
                    warnings: Vec::new(),
                };
                Ok(serde_json::to_string_pretty(&error_response)?)
            }
        }
    }

    fn format_rm_as_text(&self, response: &CronRmResponse) -> String {
        let mut output = String::new();
        
        output.push_str("Remove Scheduled Jobs (cron + systemd)\n");
        output.push_str("======================================\n\n");
        
        output.push_str(&format!("Backend     : {}\n", response.backend));
        output.push_str(&format!("Dry Run     : {}\n", response.dry_run));
        output.push_str("\n");
        
        // Cron results
        output.push_str("Cron:\n");
        if response.removed.cron.is_empty() {
            output.push_str("  No cron jobs removed.\n");
        } else {
            output.push_str(&format!("  Removed {} job(s):\n", response.removed.cron.len()));
            for entry in &response.removed.cron {
                let line_info = entry.line_number.map(|n| format!(": line {}", n)).unwrap_or_default();
                output.push_str(&format!("    {}{}\n", entry.source, line_info));
                if let (Some(schedule), Some(command)) = (&entry.schedule, &entry.command) {
                    let id_info = entry.id.as_ref().map(|id| format!("  # id={}", id)).unwrap_or_default();
                    output.push_str(&format!("      {} {}{}\n", schedule, command, id_info));
                }
            }
        }
        output.push_str("\n");
        
        // systemd results
        output.push_str("Systemd:\n");
        if response.removed.systemd.is_empty() {
            output.push_str("  No systemd timers removed.\n");
        } else {
            output.push_str(&format!("  Removed {} timer(s):\n", response.removed.systemd.len()));
            for entry in &response.removed.systemd {
                let timer_name = entry.timer_unit.as_deref().unwrap_or("unknown");
                let service_info = entry.service_unit.as_ref()
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                output.push_str(&format!("    [{}] {}{}\n", entry.unit_scope, timer_name, service_info));
            }
        }
        output.push_str("\n");
        
        // Warnings
        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }
        
        if response.dry_run {
            output.push_str("\nNote: dry-run mode — no changes were applied.\n");
        }
        
        if response.matched_count.cron == 0 && response.matched_count.systemd == 0 {
            output.push_str("\nNo matching jobs found. No changes applied.\n");
        }

        output
    }

    pub fn enable_verb(&self, args: &Args) -> Result<String> {
        // Validate backend
        let backend = args.get("backend").unwrap_or(&"both".to_string()).clone();
        if !["cron", "systemd", "both"].contains(&backend.as_str()) {
            let error_response = CronEnableResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
                backend: backend.clone(),
                enabled: CronEnableEnabledSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronEnableMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                already_enabled_count: CronEnableAlreadyEnabledCount {
                    cron: 0,
                    systemd: 0,
                },
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                error: Some(json!({"code": "cron.enable_invalid_backend", "message": format!("Invalid backend '{}'. Must be one of: cron, systemd, both", backend)})),
                warnings: Vec::new(),
            };
            return Ok(serde_json::to_string_pretty(&error_response)?);
        }

        // Validate that at least one selector is provided
        let has_selector = args.get("id").is_some() 
            || args.get("schedule").is_some() 
            || args.get("command").is_some()
            || args.get("match_command").is_some()
            || args.get("match_comment").is_some()
            || args.get("unit_name").is_some()
            || args.get("match_unit").is_some();
            
        if !has_selector {
            let error_response = CronEnableResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
                backend: backend.clone(),
                enabled: CronEnableEnabledSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronEnableMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                already_enabled_count: CronEnableAlreadyEnabledCount {
                    cron: 0,
                    systemd: 0,
                },
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                error: Some(json!({"code": "cron.enable_no_selector", "message": "At least one selector must be provided: id, schedule, command, match_command, match_comment, unit_name, or match_unit"})),
                warnings: Vec::new(),
            };
            return Ok(serde_json::to_string_pretty(&error_response)?);
        }

        // Build options from args
        let options = CronEnableOptions {
            id: args.get("id").cloned(),
            backend,
            
            scope: args.get("scope").unwrap_or(&"all".to_string()).clone(),
            users: args.get("users")
                .map(|s| s.split(',').map(|u| u.trim().to_string()).collect())
                .unwrap_or_default(),
            schedule: args.get("schedule").cloned(),
            command: args.get("command").cloned(),
            match_command: args.get("match_command").cloned(),
            match_comment: args.get("match_comment").cloned(),
            cron_file: args.get("cron_file").cloned(),
            
            unit_name: args.get("unit_name").cloned(),
            unit_scope: args.get("unit_scope").unwrap_or(&"auto".to_string()).clone(),
            match_unit: args.get("match_unit").cloned(),
            
            require_match: args.get("require_match").unwrap_or(&"true".to_string()) == "true",
            start_now: args.get("start_now").unwrap_or(&"true".to_string()) == "true",
            dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
            
            format: if args.get("format").unwrap_or(&"json".to_string()) == "text" {
                OutputFormat::Text
            } else {
                OutputFormat::Json
            },
        };

        match self.provider.enable_cron_jobs(&options) {
            Ok(response) => {
                if matches!(options.format, OutputFormat::Text) {
                    Ok(self.format_enable_as_text(&response))
                } else {
                    Ok(serde_json::to_string_pretty(&response)?)
                }
            }
            Err(e) => {
                let error_response = CronEnableResponse {
                    ok: false,
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    dry_run: options.dry_run,
                    backend: options.backend.clone(),
                    enabled: CronEnableEnabledSummary {
                        cron: Vec::new(),
                        systemd: Vec::new(),
                    },
                    matched_count: CronEnableMatchedCount {
                        cron: 0,
                        systemd: 0,
                    },
                    already_enabled_count: CronEnableAlreadyEnabledCount {
                        cron: 0,
                        systemd: 0,
                    },
                    cron_modified_sources: Vec::new(),
                    systemd_scopes_touched: Vec::new(),
                    error: Some(json!({"code": "cron.enable_error", "message": e.to_string()})),
                    warnings: Vec::new(),
                };
                Ok(serde_json::to_string_pretty(&error_response)?)
            }
        }
    }

    fn format_enable_as_text(&self, response: &CronEnableResponse) -> String {
        let mut output = String::new();
        
        output.push_str("Enable Scheduled Jobs (cron + systemd)\n");
        output.push_str("======================================\n\n");
        
        output.push_str(&format!("Backend     : {}\n", response.backend));
        output.push_str(&format!("Dry Run     : {}\n", response.dry_run));
        output.push_str("\n");
        
        // Cron results
        output.push_str("Cron:\n");
        if response.enabled.cron.is_empty() {
            output.push_str("  No cron jobs enabled.\n");
        } else {
            output.push_str(&format!("  Enabled {} job(s):\n", response.enabled.cron.len()));
            for entry in &response.enabled.cron {
                let line_info = entry.line_number.map(|n| format!(": line {}", n)).unwrap_or_default();
                output.push_str(&format!("    {}{}\n", entry.source, line_info));
                if let (Some(schedule), Some(command)) = (&entry.schedule, &entry.command) {
                    let id_info = entry.id.as_ref().map(|id| format!("  # id={}", id)).unwrap_or_default();
                    output.push_str(&format!("      {} {}{}\n", schedule, command, id_info));
                }
            }
        }
        output.push_str("\n");
        
        // systemd results
        output.push_str("Systemd:\n");
        if response.enabled.systemd.is_empty() {
            output.push_str("  No systemd timers enabled.\n");
        } else {
            output.push_str(&format!("  Enabled {} timer(s):\n", response.enabled.systemd.len()));
            for entry in &response.enabled.systemd {
                let timer_name = entry.timer_unit.as_deref().unwrap_or("unknown");
                let service_info = entry.service_unit.as_ref()
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                output.push_str(&format!("    [{}] {}{}\n", entry.unit_scope, timer_name, service_info));
                output.push_str(&format!("    Started now: {}\n", if entry.started_now { "yes" } else { "no" }));
            }
        }
        output.push_str("\n");
        
        // Warnings
        output.push_str("Warnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }
        
        if response.dry_run {
            output.push_str("\nNote: dry-run mode — no changes were applied.\n");
        }
        
        if response.matched_count.cron == 0 && response.matched_count.systemd == 0 {
            output.push_str("\nNo matching jobs found. No changes applied.\n");
        }

        output
    }

    pub fn disable_verb(&self, args: &Args) -> Result<String> {
        // Validate backend
        let backend = args.get("backend").unwrap_or(&"both".to_string()).clone();
        if !["cron", "systemd", "both"].contains(&backend.as_str()) {
            let error_response = CronDisableResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
                backend: backend.clone(),
                disabled: CronDisableDisabledSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronDisableMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                already_disabled_count: CronDisableAlreadyDisabledCount {
                    cron: 0,
                    systemd: 0,
                },
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                error: Some(json!({"code": "cron.disable_invalid_backend", "message": format!("Invalid backend '{}'. Must be one of: cron, systemd, both", backend)})),
                warnings: Vec::new(),
            };
            return Ok(serde_json::to_string_pretty(&error_response)?);
        }

        // Validate that at least one selector is provided
        let has_selector = args.get("id").is_some() 
            || args.get("schedule").is_some() 
            || args.get("command").is_some()
            || args.get("match_command").is_some()
            || args.get("match_comment").is_some()
            || args.get("unit_name").is_some()
            || args.get("match_unit").is_some();
            
        if !has_selector {
            let error_response = CronDisableResponse {
                ok: false,
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
                backend: backend.clone(),
                disabled: CronDisableDisabledSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronDisableMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                already_disabled_count: CronDisableAlreadyDisabledCount {
                    cron: 0,
                    systemd: 0,
                },
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                error: Some(json!({"code": "cron.disable_no_selector", "message": "At least one selector must be provided: id, schedule, command, match_command, match_comment, unit_name, or match_unit"})),
                warnings: Vec::new(),
            };
            return Ok(serde_json::to_string_pretty(&error_response)?);
        }

        // Build options from args
        let options = CronDisableOptions {
            id: args.get("id").cloned(),
            backend,
            
            scope: args.get("scope").unwrap_or(&"all".to_string()).clone(),
            users: args.get("users")
                .map(|s| s.split(',').map(|u| u.trim().to_string()).collect())
                .unwrap_or_default(),
            schedule: args.get("schedule").cloned(),
            command: args.get("command").cloned(),
            match_command: args.get("match_command").cloned(),
            match_comment: args.get("match_comment").cloned(),
            cron_file: args.get("cron_file").cloned(),
            
            unit_name: args.get("unit_name").cloned(),
            unit_scope: args.get("unit_scope").unwrap_or(&"auto".to_string()).clone(),
            match_unit: args.get("match_unit").cloned(),
            
            require_match: args.get("require_match").unwrap_or(&"true".to_string()) == "true",
            stop_now: args.get("stop_now").unwrap_or(&"true".to_string()) == "true",
            dry_run: args.get("dry_run").unwrap_or(&"false".to_string()) == "true",
            
            format: if args.get("format").unwrap_or(&"json".to_string()) == "text" {
                OutputFormat::Text
            } else {
                OutputFormat::Json
            },
        };

        match self.provider.disable_cron_jobs(&options) {
            Ok(response) => {
                if matches!(options.format, OutputFormat::Text) {
                    Ok(self.format_disable_as_text(&response))
                } else {
                    Ok(serde_json::to_string_pretty(&response)?)
                }
            }
            Err(e) => {
                let error_response = CronDisableResponse {
                    ok: false,
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    dry_run: options.dry_run,
                    backend: options.backend.clone(),
                    disabled: CronDisableDisabledSummary {
                        cron: Vec::new(),
                        systemd: Vec::new(),
                    },
                    matched_count: CronDisableMatchedCount {
                        cron: 0,
                        systemd: 0,
                    },
                    already_disabled_count: CronDisableAlreadyDisabledCount {
                        cron: 0,
                        systemd: 0,
                    },
                    cron_modified_sources: Vec::new(),
                    systemd_scopes_touched: Vec::new(),
                    error: Some(json!({"code": "cron.disable_error", "message": e.to_string()})),
                    warnings: Vec::new(),
                };
                Ok(serde_json::to_string_pretty(&error_response)?)
            }
        }
    }

    fn format_disable_as_text(&self, response: &CronDisableResponse) -> String {
        let mut output = String::new();
        
        output.push_str("Disable Scheduled Jobs (cron + systemd)\n");
        output.push_str("=======================================\n\n");
        
        output.push_str(&format!("Backend     : {}\n", response.backend));
        output.push_str(&format!("Dry Run     : {}\n\n", response.dry_run));
        
        output.push_str("Cron:\n");
        if response.disabled.cron.is_empty() {
            output.push_str("  No cron jobs disabled.\n");
        } else {
            output.push_str(&format!("  Disabled {} job(s):\n", response.disabled.cron.len()));
            for entry in &response.disabled.cron {
                output.push_str(&format!("    {}", entry.source));
                if let Some(line_no) = entry.line_number {
                    output.push_str(&format!(": line {}", line_no));
                }
                output.push('\n');
                if let (Some(schedule), Some(command)) = (&entry.schedule, &entry.command) {
                    output.push_str(&format!("      {} {}", schedule, command));
                    if let Some(id) = &entry.id {
                        output.push_str(&format!("  # id={}", id));
                    }
                    output.push('\n');
                }
            }
        }
        
        output.push_str("\nSystemd:\n");
        if response.disabled.systemd.is_empty() {
            output.push_str("  No systemd timers disabled.\n");
        } else {
            output.push_str(&format!("  Disabled {} timer(s):\n", response.disabled.systemd.len()));
            for entry in &response.disabled.systemd {
                output.push_str(&format!("    [{}] ", entry.unit_scope));
                if let Some(timer_unit) = &entry.timer_unit {
                    output.push_str(timer_unit);
                    if let Some(service_unit) = &entry.service_unit {
                        output.push_str(&format!(" ({})", service_unit));
                    }
                } else {
                    output.push_str("(unknown)");
                }
                output.push('\n');
                output.push_str(&format!("    Stopped now: {}\n", if entry.stopped_now { "yes" } else { "no" }));
            }
        }
        
        output.push_str("\nWarnings:\n");
        if response.warnings.is_empty() {
            output.push_str("  (none)\n");
        } else {
            for warning in &response.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }
        
        if response.dry_run {
            output.push_str("\nNote: dry-run mode — no changes were applied.\n");
        }
        
        if response.matched_count.cron == 0 && response.matched_count.systemd == 0 {
            output.push_str("\nNo matching jobs found. No changes applied.\n");
        }

        output
    }
}

impl Handle for CronHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["list", "add", "rm", "enable", "disable"]
    }

    fn call(&self, method: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match method {
            "list" => {
                let result = self.list_verb(args)?;
                writeln!(io.stdout, "{}", result)?;
                Ok(Status::ok())
            }
            "add" => {
                let result = self.add_verb(args)?;
                writeln!(io.stdout, "{}", result)?;
                Ok(Status::ok())
            }
            "rm" => {
                let result = self.rm_verb(args)?;
                writeln!(io.stdout, "{}", result)?;
                Ok(Status::ok())
            }
            "enable" => {
                let result = self.enable_verb(args)?;
                writeln!(io.stdout, "{}", result)?;
                Ok(Status::ok())
            }
            "disable" => {
                let result = self.disable_verb(args)?;
                writeln!(io.stdout, "{}", result)?;
                Ok(Status::ok())
            }
            _ => Err(anyhow::anyhow!("Unknown method: {}", method)),
        }
    }
}

// ===========================================================================
// CronProvider trait for testability
// ===========================================================================

pub trait CronProvider: std::fmt::Debug + Send + Sync {
    fn list_cron_entries(&self, options: &CronListOptions) -> Result<CronListResponse>;
    fn read_user_crontab(&self, user: &str) -> Result<String>;
    fn read_system_crontab(&self) -> Result<String>;
    fn read_cron_d_files(&self) -> Result<Vec<(String, String)>>; // (filename, content)
    fn read_file(&self, path: &str) -> Result<String>;
    fn get_current_user(&self) -> String;
    fn get_current_time(&self) -> DateTime<Utc>;
    
    // Add functionality
    fn add_cron_job(&self, options: &CronAddOptions) -> Result<CronAddResponse>;
    
    // Remove functionality
    fn remove_cron_jobs(&self, options: &CronRmOptions) -> Result<CronRmResponse>;
    
    // Enable functionality
    fn enable_cron_jobs(&self, options: &CronEnableOptions) -> Result<CronEnableResponse>;
    
    // Disable functionality
    fn disable_cron_jobs(&self, options: &CronDisableOptions) -> Result<CronDisableResponse>;
}

// ===========================================================================
// System implementation of CronProvider
// ===========================================================================

#[derive(Debug)]
pub struct SystemCronProvider {
    current_user: String,
}

impl SystemCronProvider {
    pub fn new() -> Self {
        let current_user = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());
        
        Self { current_user }
    }
}

impl CronProvider for SystemCronProvider {
    fn list_cron_entries(&self, options: &CronListOptions) -> Result<CronListResponse> {
        let start_time = self.get_current_time();
        let mut entries = Vec::new();
        let mut warnings = Vec::new();
        let mut paths = HashMap::new();

        // Validate scope and users
        if options.scope == "user" && options.users.is_empty() {
            return Err(anyhow::anyhow!("cron.list_users_required: scope='user' but users array is empty"));
        }

        // Collect entries based on scope
        match options.scope.as_str() {
            "current" => {
                if let Ok(content) = self.read_user_crontab(&self.current_user) {
                    let user_entries = parse_user_crontab(&content, &self.current_user, None)?;
                    entries.extend(user_entries);
                    paths.insert(format!("user_{}", self.current_user), format!("/var/spool/cron/{}", self.current_user));
                } else {
                    warnings.push(format!("Could not read crontab for user: {}", self.current_user));
                }
            }
            "user" => {
                for user in &options.users {
                    if let Ok(content) = self.read_user_crontab(user) {
                        let user_entries = parse_user_crontab(&content, user, None)?;
                        entries.extend(user_entries);
                        paths.insert(format!("user_{}", user), format!("/var/spool/cron/{}", user));
                    } else {
                        warnings.push(format!("Could not read crontab for user: {}", user));
                    }
                }
            }
            "system" => {
                // Read system crontab
                if let Ok(content) = self.read_system_crontab() {
                    let sys_entries = parse_system_crontab(&content, "/etc/crontab")?;
                    entries.extend(sys_entries);
                    paths.insert("system_crontab".to_string(), "/etc/crontab".to_string());
                } else {
                    warnings.push("Could not read /etc/crontab".to_string());
                }

                // Read cron.d files
                if let Ok(cron_d_files) = self.read_cron_d_files() {
                    for (filename, content) in cron_d_files {
                        let file_path = format!("/etc/cron.d/{}", filename);
                        if let Ok(file_entries) = parse_system_crontab(&content, &file_path) {
                            entries.extend(file_entries);
                            paths.insert(format!("cron_d_{}", filename), file_path);
                        } else {
                            warnings.push(format!("Could not parse /etc/cron.d/{}", filename));
                        }
                    }
                }
            }
            "all" => {
                // Current user
                if let Ok(content) = self.read_user_crontab(&self.current_user) {
                    let user_entries = parse_user_crontab(&content, &self.current_user, None)?;
                    entries.extend(user_entries);
                    paths.insert(format!("user_{}", self.current_user), format!("/var/spool/cron/{}", self.current_user));
                }

                // Other users if specified
                for user in &options.users {
                    if user != &self.current_user {
                        if let Ok(content) = self.read_user_crontab(user) {
                            let user_entries = parse_user_crontab(&content, user, None)?;
                            entries.extend(user_entries);
                            paths.insert(format!("user_{}", user), format!("/var/spool/cron/{}", user));
                        } else {
                            warnings.push(format!("Could not read crontab for user: {}", user));
                        }
                    }
                }

                // System files if requested
                if options.include_system {
                    if let Ok(content) = self.read_system_crontab() {
                        let sys_entries = parse_system_crontab(&content, "/etc/crontab")?;
                        entries.extend(sys_entries);
                        paths.insert("system_crontab".to_string(), "/etc/crontab".to_string());
                    }

                    if let Ok(cron_d_files) = self.read_cron_d_files() {
                        for (filename, content) in cron_d_files {
                            let file_path = format!("/etc/cron.d/{}", filename);
                            if let Ok(file_entries) = parse_system_crontab(&content, &file_path) {
                                entries.extend(file_entries);
                                paths.insert(format!("cron_d_{}", filename), file_path);
                            }
                        }
                    }
                }
            }
            _ => {
                return Err(anyhow::anyhow!("cron.list_invalid_scope: unsupported scope value"));
            }
        }

        // Read additional files
        for file_path in &options.include_files {
            if let Ok(content) = self.read_file(file_path) {
                if let Ok(file_entries) = parse_system_crontab(&content, file_path) {
                    entries.extend(file_entries);
                    paths.insert(format!("include_{}", file_path.replace('/', "_")), file_path.clone());
                } else {
                    warnings.push(format!("Could not parse file: {}", file_path));
                }
            } else {
                warnings.push(format!("Could not read file: {}", file_path));
            }
        }

        // Apply filters
        entries = apply_filters(entries, options);

        // Compute next run times if requested
        let reference_time = if let Some(now_unix) = options.now_unix {
            Utc.timestamp_opt(now_unix, 0).single().unwrap_or(start_time)
        } else {
            start_time
        };

        if options.include_next_run {
            for entry in &mut entries {
                if entry.enabled && entry.schedule.is_some() {
                    entry.next_run_unix = compute_next_run(&entry.schedule.as_ref().unwrap(), reference_time);
                    if let Some(next_unix) = entry.next_run_unix {
                        entry.next_run_iso8601 = Some(
                            Utc.timestamp_opt(next_unix, 0)
                                .single()
                                .unwrap_or(reference_time)
                                .to_rfc3339()
                        );
                    }
                }
            }
        }

        // Apply sorting
        apply_sorting(&mut entries, &options.sort_by, &options.sort_order);

        let entries_total = entries.len() as u32;
        let entries_disabled = entries.iter().filter(|e| !e.enabled).count() as u32;
        
        // Apply max_entries limit
        let truncated = entries.len() > options.max_entries as usize;
        if truncated {
            entries.truncate(options.max_entries as usize);
            warnings.push(format!("Entry list truncated to max_entries={}.", options.max_entries));
        }

        let entries_returned = entries.len() as u32;

        Ok(CronListResponse {
            ok: true,
            timestamp_unix_ms: start_time.timestamp_millis(),
            scope: options.scope.clone(),
            users: if options.scope == "current" { 
                vec![self.current_user.clone()] 
            } else { 
                options.users.clone() 
            },
            include_system: options.include_system,
            truncated,
            entries_total: Some(entries_total),
            entries_returned,
            entries_disabled,
            entries,
            raw: if options.include_raw { Some(json!({})) } else { None },
            paths: if options.include_paths { Some(json!(paths)) } else { None },
            human: Some(CronListHumanSummary {
                summary: format!("{} cron entries ({} enabled, {} disabled) from scope '{}'{}.",
                    entries_total,
                    entries_total - entries_disabled,
                    entries_disabled,
                    options.scope,
                    if options.include_system { " and system files" } else { "" }
                ),
            }),
            error: None,
            warnings,
        })
    }

    fn read_user_crontab(&self, user: &str) -> Result<String> {
        // Try crontab -l command first
        if user == &self.current_user {
            if let Ok(output) = Command::new("crontab").arg("-l").output() {
                if output.status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).to_string());
                }
            }
        } else {
            // Try to read for another user (needs privileges)
            if let Ok(output) = Command::new("crontab").args(&["-u", user, "-l"]).output() {
                if output.status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).to_string());
                }
            }
        }

        // Fall back to reading spool file directly
        let spool_paths = [
            format!("/var/spool/cron/{}", user),
            format!("/var/spool/cron/crontabs/{}", user),
            format!("/usr/spool/cron/{}", user),
        ];

        for path in &spool_paths {
            if let Ok(content) = fs::read_to_string(path) {
                return Ok(content);
            }
        }

        Err(anyhow::anyhow!("cron.list_user_crontab_unavailable: Could not read crontab for user {}", user))
    }

    fn read_system_crontab(&self) -> Result<String> {
        fs::read_to_string("/etc/crontab")
            .map_err(|_| anyhow::anyhow!("cron.list_system_crontab_unavailable: Could not read /etc/crontab"))
    }

    fn read_cron_d_files(&self) -> Result<Vec<(String, String)>> {
        let cron_d_path = Path::new("/etc/cron.d");
        let mut files = Vec::new();

        if !cron_d_path.exists() {
            return Ok(files);
        }

        let entries = fs::read_dir(cron_d_path)
            .map_err(|_| anyhow::anyhow!("cron.list_cron_d_unavailable: Could not read /etc/cron.d"))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            // Skip directories and backup files
            if !path.is_file() || path.file_name().unwrap().to_string_lossy().contains('~') {
                continue;
            }

            let filename = path.file_name().unwrap().to_string_lossy().to_string();
            if let Ok(content) = fs::read_to_string(&path) {
                files.push((filename, content));
            }
        }

        Ok(files)
    }

    fn read_file(&self, path: &str) -> Result<String> {
        fs::read_to_string(path)
            .map_err(|_| anyhow::anyhow!("cron.list_file_unavailable: Could not read file {}", path))
    }

    fn get_current_user(&self) -> String {
        self.current_user.clone()
    }

    fn get_current_time(&self) -> DateTime<Utc> {
        Utc::now()
    }
    
    fn add_cron_job(&self, options: &CronAddOptions) -> Result<CronAddResponse> {
        let start_time = self.get_current_time();
        let timestamp_unix_ms = start_time.timestamp_millis();
        let mut warnings = Vec::new();

        // Validate schedule
        let schedule_validation = validate_cron_schedule(&options.schedule);
        if let Err(e) = schedule_validation {
            return Ok(CronAddResponse {
                ok: false,
                timestamp_unix_ms,
                backend_used: None,
                dry_run: options.dry_run,
                duplicate: false,
                job: None,
                preview: None,
                error: Some(json!({
                    "code": "cron.add_invalid_schedule",
                    "message": format!("Invalid cron schedule '{}': {}", options.schedule, e)
                })),
                warnings,
            });
        }

        // Validate command
        if options.command.trim().is_empty() {
            return Ok(CronAddResponse {
                ok: false,
                timestamp_unix_ms,
                backend_used: None,
                dry_run: options.dry_run,
                duplicate: false,
                job: None,
                preview: None,
                error: Some(json!({
                    "code": "cron.add_missing_command",
                    "message": "Command cannot be empty"
                })),
                warnings,
            });
        }

        // Choose backend
        let backend_choice = choose_backend(&options.backend, &mut warnings);
        let backend_used = match backend_choice {
            Ok(backend) => backend,
            Err(e) => {
                return Ok(CronAddResponse {
                    ok: false,
                    timestamp_unix_ms,
                    backend_used: None,
                    dry_run: options.dry_run,
                    duplicate: false,
                    job: None,
                    preview: None,
                    error: Some(json!({
                        "code": "cron.add_backend_unavailable",
                        "message": e.to_string()
                    })),
                    warnings,
                });
            }
        };

        // Dispatch to appropriate backend implementation
        match backend_used.as_str() {
            "cron" => self.add_cron_backend(options, timestamp_unix_ms, warnings),
            "systemd" => self.add_systemd_backend(options, timestamp_unix_ms, warnings),
            _ => Ok(CronAddResponse {
                ok: false,
                timestamp_unix_ms,
                backend_used: Some(backend_used),
                dry_run: options.dry_run,
                duplicate: false,
                job: None,
                preview: None,
                error: Some(json!({
                    "code": "cron.add_internal_error",
                    "message": "Unknown backend type"
                })),
                warnings,
            }),
        }
    }

    fn remove_cron_jobs(&self, options: &CronRmOptions) -> Result<CronRmResponse> {
        let start_time = self.get_current_time();
        let timestamp_unix_ms = start_time.timestamp_millis();
        let mut warnings = Vec::new();
        let mut cron_modified_sources = Vec::new();
        let mut systemd_scopes_touched = Vec::new();
        let mut removed_cron = Vec::new();
        let mut removed_systemd = Vec::new();

        // Validate that at least one selector is provided
        if options.id.is_none() 
            && options.unit_name.is_none()
            && options.schedule.is_none()
            && options.command.is_none()
            && options.match_command.is_none()
            && options.match_comment.is_none()
            && options.match_unit.is_none() {
            return Ok(CronRmResponse {
                ok: false,
                timestamp_unix_ms,
                dry_run: options.dry_run,
                backend: options.backend.clone(),
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                removed: CronRmRemovedSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronRmMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                error: Some(json!({"code": "cron.rm_no_selector", "message": "No selector provided (id, unit_name, schedule, command, or match filters required)"})),
                warnings: Vec::new(),
            });
        }

        // Handle backend selection
        match options.backend.as_str() {
            "cron" => {
                let result = self.remove_from_cron(options, &mut warnings)?;
                removed_cron = result.0;
                cron_modified_sources = result.1;
            }
            "systemd" => {
                let result = self.remove_from_systemd(options, &mut warnings)?;
                removed_systemd = result.0;
                systemd_scopes_touched = result.1;
            }
            "both" => {
                // Try both backends
                let cron_result = self.remove_from_cron(options, &mut warnings)?;
                removed_cron = cron_result.0;
                cron_modified_sources = cron_result.1;

                let systemd_result = self.remove_from_systemd(options, &mut warnings)?;
                removed_systemd = systemd_result.0;
                systemd_scopes_touched = systemd_result.1;
            }
            _ => {
                return Ok(CronRmResponse {
                    ok: false,
                    timestamp_unix_ms,
                    dry_run: options.dry_run,
                    backend: options.backend.clone(),
                    cron_modified_sources: Vec::new(),
                    systemd_scopes_touched: Vec::new(),
                    removed: CronRmRemovedSummary {
                        cron: Vec::new(),
                        systemd: Vec::new(),
                    },
                    matched_count: CronRmMatchedCount {
                        cron: 0,
                        systemd: 0,
                    },
                    error: Some(json!({"code": "cron.rm_invalid_backend", "message": format!("Invalid backend: {}", options.backend)})),
                    warnings: Vec::new(),
                });
            }
        }

        let total_removed = removed_cron.len() + removed_systemd.len();
        let ok = if options.require_match && total_removed == 0 {
            false
        } else {
            true
        };

        let error = if !ok {
            Some(json!({"code": "cron.rm_no_match", "message": "No scheduled jobs matched the provided criteria."}))
        } else {
            None
        };

        Ok(CronRmResponse {
            ok,
            timestamp_unix_ms,
            dry_run: options.dry_run,
            backend: options.backend.clone(),
            cron_modified_sources,
            systemd_scopes_touched,
            removed: CronRmRemovedSummary {
                cron: removed_cron.clone(),
                systemd: removed_systemd.clone(),
            },
            matched_count: CronRmMatchedCount {
                cron: removed_cron.len() as u32,
                systemd: removed_systemd.len() as u32,
            },
            error,
            warnings,
        })
    }
    
    fn enable_cron_jobs(&self, options: &CronEnableOptions) -> Result<CronEnableResponse> {
        let start_time = self.get_current_time();
        let timestamp_unix_ms = start_time.timestamp_millis();
        let mut warnings = Vec::new();
        let mut cron_modified_sources = Vec::new();
        let mut systemd_scopes_touched = Vec::new();
        let mut enabled_cron = Vec::new();
        let mut enabled_systemd = Vec::new();
        let mut already_enabled_cron = 0u32;
        let mut already_enabled_systemd = 0u32;

        // Validate that at least one selector is provided
        if options.id.is_none() 
            && options.unit_name.is_none()
            && options.schedule.is_none()
            && options.command.is_none()
            && options.match_command.is_none()
            && options.match_comment.is_none()
            && options.match_unit.is_none() {
            return Ok(CronEnableResponse {
                ok: false,
                timestamp_unix_ms,
                dry_run: options.dry_run,
                backend: options.backend.clone(),
                enabled: CronEnableEnabledSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronEnableMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                already_enabled_count: CronEnableAlreadyEnabledCount {
                    cron: 0,
                    systemd: 0,
                },
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                error: Some(json!({"code": "cron.enable_no_selector", "message": "No selector provided (id, unit_name, schedule, command, or match filters required)"})),
                warnings: Vec::new(),
            });
        }

        // Handle backend selection
        match options.backend.as_str() {
            "cron" => {
                let result = self.enable_from_cron(options, &mut warnings)?;
                enabled_cron = result.0;
                already_enabled_cron = result.1;
                cron_modified_sources = result.2;
            }
            "systemd" => {
                let result = self.enable_from_systemd(options, &mut warnings)?;
                enabled_systemd = result.0;
                already_enabled_systemd = result.1;
                systemd_scopes_touched = result.2;
            }
            "both" => {
                // Try both backends
                let cron_result = self.enable_from_cron(options, &mut warnings)?;
                enabled_cron = cron_result.0;
                already_enabled_cron = cron_result.1;
                cron_modified_sources = cron_result.2;

                let systemd_result = self.enable_from_systemd(options, &mut warnings)?;
                enabled_systemd = systemd_result.0;
                already_enabled_systemd = systemd_result.1;
                systemd_scopes_touched = systemd_result.2;
            }
            _ => {
                return Ok(CronEnableResponse {
                    ok: false,
                    timestamp_unix_ms,
                    dry_run: options.dry_run,
                    backend: options.backend.clone(),
                    enabled: CronEnableEnabledSummary {
                        cron: Vec::new(),
                        systemd: Vec::new(),
                    },
                    matched_count: CronEnableMatchedCount {
                        cron: 0,
                        systemd: 0,
                    },
                    already_enabled_count: CronEnableAlreadyEnabledCount {
                        cron: 0,
                        systemd: 0,
                    },
                    cron_modified_sources: Vec::new(),
                    systemd_scopes_touched: Vec::new(),
                    error: Some(json!({"code": "cron.enable_invalid_backend", "message": format!("Invalid backend: {}", options.backend)})),
                    warnings: Vec::new(),
                });
            }
        }

        let total_enabled = enabled_cron.len() + enabled_systemd.len();
        let ok = if options.require_match && total_enabled == 0 && already_enabled_cron == 0 && already_enabled_systemd == 0 {
            false
        } else {
            true
        };

        let error = if !ok {
            Some(json!({"code": "cron.enable_no_match", "message": "No scheduled jobs matched the provided criteria."}))
        } else {
            None
        };

        Ok(CronEnableResponse {
            ok,
            timestamp_unix_ms,
            dry_run: options.dry_run,
            backend: options.backend.clone(),
            enabled: CronEnableEnabledSummary {
                cron: enabled_cron.clone(),
                systemd: enabled_systemd.clone(),
            },
            matched_count: CronEnableMatchedCount {
                cron: (enabled_cron.len() + already_enabled_cron as usize) as u32,
                systemd: (enabled_systemd.len() + already_enabled_systemd as usize) as u32,
            },
            already_enabled_count: CronEnableAlreadyEnabledCount {
                cron: already_enabled_cron,
                systemd: already_enabled_systemd,
            },
            cron_modified_sources,
            systemd_scopes_touched,
            error,
            warnings,
        })
    }
    
    fn disable_cron_jobs(&self, options: &CronDisableOptions) -> Result<CronDisableResponse> {
        let start_time = self.get_current_time();
        let timestamp_unix_ms = start_time.timestamp_millis();
        let mut warnings = Vec::new();
        let mut cron_modified_sources = Vec::new();
        let mut systemd_scopes_touched = Vec::new();
        let mut disabled_cron = Vec::new();
        let mut disabled_systemd = Vec::new();
        let mut already_disabled_cron = 0u32;
        let mut already_disabled_systemd = 0u32;

        // Validate that at least one selector is provided
        if options.id.is_none() 
            && options.unit_name.is_none()
            && options.schedule.is_none()
            && options.command.is_none()
            && options.match_command.is_none()
            && options.match_comment.is_none()
            && options.match_unit.is_none() {
            return Ok(CronDisableResponse {
                ok: false,
                timestamp_unix_ms,
                dry_run: options.dry_run,
                backend: options.backend.clone(),
                disabled: CronDisableDisabledSummary {
                    cron: Vec::new(),
                    systemd: Vec::new(),
                },
                matched_count: CronDisableMatchedCount {
                    cron: 0,
                    systemd: 0,
                },
                already_disabled_count: CronDisableAlreadyDisabledCount {
                    cron: 0,
                    systemd: 0,
                },
                cron_modified_sources: Vec::new(),
                systemd_scopes_touched: Vec::new(),
                error: Some(json!({"code": "cron.disable_no_selector", "message": "No selector provided (id, unit_name, schedule, command, or match filters required)"})),
                warnings: Vec::new(),
            });
        }

        // Handle backend selection
        match options.backend.as_str() {
            "cron" => {
                let result = self.disable_from_cron(options, &mut warnings)?;
                disabled_cron = result.0;
                already_disabled_cron = result.1;
                cron_modified_sources = result.2;
            }
            "systemd" => {
                let result = self.disable_from_systemd(options, &mut warnings)?;
                disabled_systemd = result.0;
                already_disabled_systemd = result.1;
                systemd_scopes_touched = result.2;
            }
            "both" => {
                // Try both backends
                let cron_result = self.disable_from_cron(options, &mut warnings)?;
                disabled_cron = cron_result.0;
                already_disabled_cron = cron_result.1;
                cron_modified_sources = cron_result.2;

                let systemd_result = self.disable_from_systemd(options, &mut warnings)?;
                disabled_systemd = systemd_result.0;
                already_disabled_systemd = systemd_result.1;
                systemd_scopes_touched = systemd_result.2;
            }
            _ => {
                return Ok(CronDisableResponse {
                    ok: false,
                    timestamp_unix_ms,
                    dry_run: options.dry_run,
                    backend: options.backend.clone(),
                    disabled: CronDisableDisabledSummary {
                        cron: Vec::new(),
                        systemd: Vec::new(),
                    },
                    matched_count: CronDisableMatchedCount {
                        cron: 0,
                        systemd: 0,
                    },
                    already_disabled_count: CronDisableAlreadyDisabledCount {
                        cron: 0,
                        systemd: 0,
                    },
                    cron_modified_sources: Vec::new(),
                    systemd_scopes_touched: Vec::new(),
                    error: Some(json!({"code": "cron.disable_invalid_backend", "message": format!("Invalid backend: {}", options.backend)})),
                    warnings: Vec::new(),
                });
            }
        }

        let total_disabled = disabled_cron.len() + disabled_systemd.len();
        let ok = if options.require_match && total_disabled == 0 && already_disabled_cron == 0 && already_disabled_systemd == 0 {
            false
        } else {
            true
        };

        let error = if !ok {
            Some(json!({"code": "cron.disable_no_match", "message": "No scheduled jobs matched the provided criteria."}))
        } else {
            None
        };

        Ok(CronDisableResponse {
            ok,
            timestamp_unix_ms,
            dry_run: options.dry_run,
            backend: options.backend.clone(),
            disabled: CronDisableDisabledSummary {
                cron: disabled_cron.clone(),
                systemd: disabled_systemd.clone(),
            },
            matched_count: CronDisableMatchedCount {
                cron: (disabled_cron.len() + already_disabled_cron as usize) as u32,
                systemd: (disabled_systemd.len() + already_disabled_systemd as usize) as u32,
            },
            already_disabled_count: CronDisableAlreadyDisabledCount {
                cron: already_disabled_cron,
                systemd: already_disabled_systemd,
            },
            cron_modified_sources,
            systemd_scopes_touched,
            error,
            warnings,
        })
    }
}

impl SystemCronProvider {
    fn add_cron_backend(&self, options: &CronAddOptions, timestamp_unix_ms: i64, mut warnings: Vec<String>) -> Result<CronAddResponse> {
        let cron_editor = Box::new(SystemCronEditor::new());
        
        // Determine target crontab/file
        let (scope, user, file_path) = self.determine_cron_target(options, &mut warnings)?;
        
        // Check for duplicates if requested
        let duplicate = if !options.allow_duplicate {
            self.check_cron_duplicate(options, &scope, &user, &file_path)?
        } else {
            false
        };
        
        if duplicate {
            return Ok(CronAddResponse {
                ok: true,
                timestamp_unix_ms,
                backend_used: Some("cron".to_string()),
                dry_run: options.dry_run,
                duplicate: true,
                job: Some(self.build_cron_job_info(options, &scope, &user, &file_path, None)?),
                preview: None,
                error: None,
                warnings,
            });
        }
        
        // Build new cron line
        let (cron_line, comment_line) = self.build_cron_lines(options, &scope)?;
        
        if options.dry_run {
            return Ok(CronAddResponse {
                ok: true,
                timestamp_unix_ms,
                backend_used: Some("cron".to_string()),
                dry_run: true,
                duplicate: false,
                job: Some(self.build_cron_job_info(options, &scope, &user, &file_path, None)?),
                preview: Some(CronAddPreview {
                    cron_line: Some(format!("{}\n{}", comment_line.unwrap_or_default(), cron_line)),
                    service_unit: None,
                    timer_unit: None,
                }),
                error: None,
                warnings,
            });
        }
        
        // Actually add the job
        let line_added = match scope.as_str() {
            "current" => {
                self.add_to_user_crontab(&user, &cron_line, &comment_line, &*cron_editor)?
            }
            "user" => {
                self.add_to_user_crontab(&user, &cron_line, &comment_line, &*cron_editor)?
            }
            "system" => {
                self.add_to_system_file(&file_path, &cron_line, &comment_line, &*cron_editor)?
            }
            _ => return Err(anyhow::anyhow!("Invalid scope: {}", scope)),
        };
        
        Ok(CronAddResponse {
            ok: true,
            timestamp_unix_ms,
            backend_used: Some("cron".to_string()),
            dry_run: false,
            duplicate: false,
            job: Some(self.build_cron_job_info(options, &scope, &user, &file_path, Some(line_added))?),
            preview: None,
            error: None,
            warnings,
        })
    }
    
    fn add_systemd_backend(&self, options: &CronAddOptions, timestamp_unix_ms: i64, warnings: Vec<String>) -> Result<CronAddResponse> {
        let systemd_editor = Box::new(SystemSystemdEditor::new());
        
        // Check systemd availability
        let unit_scope = self.determine_systemd_scope(options);
        let user_mode = unit_scope == "user";
        
        if !systemd_editor.systemctl_is_available(user_mode) {
            return Ok(CronAddResponse {
                ok: false,
                timestamp_unix_ms,
                backend_used: Some("systemd".to_string()),
                dry_run: options.dry_run,
                duplicate: false,
                job: None,
                preview: None,
                error: Some(json!({
                    "code": "cron.add_systemd_unavailable",
                    "message": "systemctl not found or systemd not active on this system"
                })),
                warnings,
            });
        }
        
        // Convert schedule to OnCalendar format
        let on_calendar = match convert_cron_to_oncalendar(&options.schedule) {
            Ok(calendar) => calendar,
            Err(e) => {
                return Ok(CronAddResponse {
                    ok: false,
                    timestamp_unix_ms,
                    backend_used: Some("systemd".to_string()),
                    dry_run: options.dry_run,
                    duplicate: false,
                    job: None,
                    preview: None,
                    error: Some(json!({
                        "code": "cron.add_schedule_translation_unsupported",
                        "message": format!("Cannot convert cron schedule '{}' to systemd OnCalendar: {}", options.schedule, e)
                    })),
                    warnings,
                });
            }
        };
        
        // Determine unit name
        let unit_name = options.unit_name
            .clone()
            .or_else(|| options.id.clone())
            .unwrap_or_else(|| self.derive_unit_name_from_command(&options.command));
            
        // Check for duplicates
        let duplicate = if !options.allow_duplicate {
            self.check_systemd_duplicate(&unit_name, user_mode, &*systemd_editor)?
        } else {
            false
        };
        
        if duplicate {
            return Ok(CronAddResponse {
                ok: true,
                timestamp_unix_ms,
                backend_used: Some("systemd".to_string()),
                dry_run: options.dry_run,
                duplicate: true,
                job: Some(self.build_systemd_job_info(options, &unit_name, &unit_scope)?),
                preview: None,
                error: None,
                warnings,
            });
        }
        
        // Build unit files
        let service_content = self.build_service_unit(options, &unit_name)?;
        let timer_content = self.build_timer_unit(options, &unit_name, &on_calendar)?;
        
        if options.dry_run {
            return Ok(CronAddResponse {
                ok: true,
                timestamp_unix_ms,
                backend_used: Some("systemd".to_string()),
                dry_run: true,
                duplicate: false,
                job: Some(self.build_systemd_job_info(options, &unit_name, &unit_scope)?),
                preview: Some(CronAddPreview {
                    cron_line: None,
                    service_unit: Some(service_content),
                    timer_unit: Some(timer_content),
                }),
                error: None,
                warnings,
            });
        }
        
        // Write unit files and enable timer
        self.create_systemd_units(&unit_name, &service_content, &timer_content, user_mode, &*systemd_editor)?;
        
        Ok(CronAddResponse {
            ok: true,
            timestamp_unix_ms,
            backend_used: Some("systemd".to_string()),
            dry_run: false,
            duplicate: false,
            job: Some(self.build_systemd_job_info(options, &unit_name, &unit_scope)?),
            preview: None,
            error: None,
            warnings,
        })
    }
}

// ===========================================================================
// System implementations of editor traits
// ===========================================================================

#[derive(Debug)]
pub struct SystemCronEditor {
}

impl SystemCronEditor {
    pub fn new() -> Self {
        Self {}
    }
}

impl CronEditor for SystemCronEditor {
    fn read_user_crontab(&self, user: &str) -> Result<String> {
        let output = Command::new("crontab")
            .args(&["-u", user, "-l"])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run crontab -l: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            // Empty crontab is not an error
            Ok(String::new())
        }
    }

    fn write_user_crontab(&self, user: &str, content: &str) -> Result<()> {
        let mut cmd = Command::new("crontab")
            .args(&["-u", user, "-"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn crontab: {}", e))?;

        if let Some(stdin) = cmd.stdin.as_mut() {
            stdin.write_all(content.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to write to crontab: {}", e))?;
        }

        let status = cmd.wait()
            .map_err(|e| anyhow::anyhow!("Failed to wait for crontab: {}", e))?;

        if status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("crontab command failed"))
        }
    }

    fn read_system_file(&self, path: &str) -> Result<String> {
        fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path, e))
    }

    fn write_system_file(&self, path: &str, content: &str) -> Result<()> {
        // Atomic write using temp file
        let temp_path = format!("{}.tmp.{}", path, std::process::id());
        fs::write(&temp_path, content)
            .map_err(|e| anyhow::anyhow!("Failed to write temp file {}: {}", temp_path, e))?;
        
        fs::rename(&temp_path, path)
            .map_err(|e| anyhow::anyhow!("Failed to rename {} to {}: {}", temp_path, path, e))
    }

    fn file_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn create_directory(&self, path: &str) -> Result<()> {
        fs::create_dir_all(path)
            .map_err(|e| anyhow::anyhow!("Failed to create directory {}: {}", path, e))
    }
}

#[derive(Debug)]
pub struct SystemSystemdEditor {
}

impl SystemSystemdEditor {
    pub fn new() -> Self {
        Self {}
    }
}

impl SystemdEditor for SystemSystemdEditor {
    fn write_unit_file(&self, path: &str, content: &str) -> Result<()> {
        // Atomic write using temp file
        let temp_path = format!("{}.tmp.{}", path, std::process::id());
        fs::write(&temp_path, content)
            .map_err(|e| anyhow::anyhow!("Failed to write temp file {}: {}", temp_path, e))?;
        
        fs::rename(&temp_path, path)
            .map_err(|e| anyhow::anyhow!("Failed to rename {} to {}: {}", temp_path, path, e))
    }

    fn systemctl_daemon_reload(&self, user_mode: bool) -> Result<()> {
        let mut cmd = Command::new("systemctl");
        if user_mode {
            cmd.arg("--user");
        }
        cmd.arg("daemon-reload");

        let output = cmd.output()
            .map_err(|e| anyhow::anyhow!("Failed to run systemctl daemon-reload: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("systemctl daemon-reload failed: {}", String::from_utf8_lossy(&output.stderr)))
        }
    }

    fn systemctl_enable_timer(&self, timer_name: &str, user_mode: bool) -> Result<()> {
        let mut cmd = Command::new("systemctl");
        if user_mode {
            cmd.arg("--user");
        }
        cmd.args(&["enable", "--now", timer_name]);

        let output = cmd.output()
            .map_err(|e| anyhow::anyhow!("Failed to run systemctl enable: {}", e))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("systemctl enable failed: {}", String::from_utf8_lossy(&output.stderr)))
        }
    }

    fn systemctl_is_available(&self, user_mode: bool) -> bool {
        let mut cmd = Command::new("systemctl");
        if user_mode {
            cmd.arg("--user");
        }
        cmd.args(&["--version"]);

        cmd.output().map(|o| o.status.success()).unwrap_or(false)
    }

    fn list_timers(&self, user_mode: bool) -> Result<Vec<String>> {
        let mut cmd = Command::new("systemctl");
        if user_mode {
            cmd.arg("--user");
        }
        cmd.args(&["list-timers", "--all", "--no-legend", "--plain"]);

        let output = cmd.output()
            .map_err(|e| anyhow::anyhow!("Failed to run systemctl list-timers: {}", e))?;

        if output.status.success() {
            let timers = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if !parts.is_empty() {
                        Some(parts[0].to_string())
                    } else {
                        None
                    }
                })
                .collect();
            Ok(timers)
        } else {
            Err(anyhow::anyhow!("systemctl list-timers failed: {}", String::from_utf8_lossy(&output.stderr)))
        }
    }

    fn get_unit_dir(&self, user_mode: bool) -> Result<String> {
        if user_mode {
            if let Ok(home) = std::env::var("HOME") {
                Ok(format!("{}/.config/systemd/user", home))
            } else {
                Err(anyhow::anyhow!("HOME environment variable not set"))
            }
        } else {
            Ok("/etc/systemd/system".to_string())
        }
    }

    fn file_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn create_directory(&self, path: &str) -> Result<()> {
        fs::create_dir_all(path)
            .map_err(|e| anyhow::anyhow!("Failed to create directory {}: {}", path, e))
    }
}

// ===========================================================================
// Helper functions for cron add functionality
// ===========================================================================

fn validate_cron_schedule(schedule: &str) -> Result<()> {
    // Handle special cron entries
    if schedule.starts_with('@') {
        let valid_specials = ["@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@hourly"];
        if valid_specials.contains(&schedule) {
            return Ok(());
        } else {
            return Err(anyhow::anyhow!("Invalid special schedule: {}", schedule));
        }
    }
    
    // Try to validate as 6-field format first (with seconds)
    if let Ok(_) = Schedule::from_str(schedule) {
        return Ok(());
    }
    
    // If it fails, try converting from traditional 5-field to 6-field format
    let parts: Vec<&str> = schedule.split_whitespace().collect();
    if parts.len() == 5 {
        // Convert 5-field (min hour day month weekday) to 6-field (sec min hour day month weekday)
        let six_field = format!("0 {}", schedule);
        Schedule::from_str(&six_field)
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("Invalid cron schedule: {}", e))
    } else {
        Err(anyhow::anyhow!("Invalid cron schedule: {}", "Invalid cron expression."))
    }
}

fn choose_backend(requested: &str, warnings: &mut Vec<String>) -> Result<String> {
    match requested {
        "cron" => {
            // Check if crontab is available
            if Command::new("crontab").arg("-l").output().is_ok() {
                Ok("cron".to_string())
            } else {
                Err(anyhow::anyhow!("cron backend requested but crontab command not available"))
            }
        }
        "systemd" => {
            // Check if systemctl is available
            if Command::new("systemctl").arg("--version").output().is_ok() {
                Ok("systemd".to_string())
            } else {
                Err(anyhow::anyhow!("systemd backend requested but systemctl command not available"))
            }
        }
        "auto" => {
            // Try systemd first, fallback to cron
            if Command::new("systemctl").arg("--version").output().is_ok() {
                Ok("systemd".to_string())
            } else if Command::new("crontab").arg("-l").output().is_ok() {
                warnings.push("systemd not available, using cron backend".to_string());
                Ok("cron".to_string())
            } else {
                Err(anyhow::anyhow!("Neither systemd nor cron backends are available"))
            }
        }
        _ => Err(anyhow::anyhow!("Invalid backend: {}", requested)),
    }
}

// Parse environment variables from args
// Supports both formats:
// - Single env param with key=value pairs separated by commas: ?env=KEY1=value1,KEY2=value2
// - Multiple env_KEY params: ?env_HOME=/home/user&env_PATH=/usr/bin
fn parse_env_from_args(args: &Args) -> Option<HashMap<String, String>> {
    let mut env_vars = HashMap::new();
    
    // Check for single 'env' parameter with comma-separated key=value pairs
    if let Some(env_param) = args.get("env") {
        for pair in env_param.split(',') {
            let pair = pair.trim();
            if let Some((key, value)) = pair.split_once('=') {
                env_vars.insert(key.trim().to_string(), value.trim().to_string());
            }
        }
    }
    
    // Check for individual env_KEY parameters
    for (param_key, param_value) in args.iter() {
        if let Some(env_key) = param_key.strip_prefix("env_") {
            env_vars.insert(env_key.to_string(), param_value.clone());
        }
    }
    
    if env_vars.is_empty() {
        None
    } else {
        Some(env_vars)
    }
}

fn convert_cron_to_oncalendar(schedule: &str) -> Result<String> {
    // Handle special entries first
    match schedule {
        "@yearly" | "@annually" => return Ok("yearly".to_string()),
        "@monthly" => return Ok("monthly".to_string()),
        "@weekly" => return Ok("weekly".to_string()),
        "@daily" => return Ok("daily".to_string()),
        "@hourly" => return Ok("hourly".to_string()),
        "@reboot" => return Err(anyhow::anyhow!("@reboot not supported in systemd timers")),
        _ => {}
    }
    
    // Parse standard cron format: min hour dom mon dow
    let parts: Vec<&str> = schedule.split_whitespace().collect();
    if parts.len() != 5 {
        return Err(anyhow::anyhow!("Cron schedule must have exactly 5 fields"));
    }
    
    let (min, hour, dom, mon, dow) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
    
    // Handle some common patterns
    match (min, hour, dom, mon, dow) {
        ("*", "*", "*", "*", "*") => Ok("*:*:*".to_string()), // every minute
        ("0", "*", "*", "*", "*") => Ok("hourly".to_string()), // every hour
        ("0", "0", "*", "*", "*") => Ok("daily".to_string()), // every day at midnight
        ("0", "0", "*", "*", "0") => Ok("weekly".to_string()), // every Sunday at midnight
        ("0", "0", "1", "*", "*") => Ok("monthly".to_string()), // first of every month
        ("0", "0", "1", "1", "*") => Ok("yearly".to_string()), // January 1st
        (m, h, "*", "*", "*") if m != "*" && h != "*" => {
            // Daily at specific time
            Ok(format!("{}:{}", h, m))
        }
        _ => {
            // For complex schedules, attempt a basic conversion
            if dom == "*" && mon == "*" && dow == "*" && hour != "*" && min != "*" {
                Ok(format!("{}:{}", hour, min))
            } else {
                Err(anyhow::anyhow!("Complex cron schedule '{}' cannot be automatically converted to systemd OnCalendar. Please use a simpler schedule or specify OnCalendar= directly", schedule))
            }
        }
    }
}

// ===========================================================================
// Data structures
// ===========================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OutputFormat {
    Json,
    Text,
}

#[derive(Debug, Clone)]
pub struct CronListOptions {
    pub scope: String,
    pub users: Vec<String>,
    pub include_system: bool,
    pub include_files: Vec<String>,
    pub state: String,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    pub match_user: Option<String>,
    pub match_source: Option<String>,
    pub include_next_run: bool,
    pub now_unix: Option<i64>,
    pub timezone: Option<String>,
    pub max_entries: u32,
    pub sort_by: String,
    pub sort_order: String,
    pub include_raw: bool,
    pub include_paths: bool,
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronScheduleFields {
    pub minute: String,
    pub hour: String,
    pub day_of_month: String,
    pub month: String,
    pub day_of_week: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEntry {
    pub id: String,
    pub user: Option<String>,
    pub source: String,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub enabled: bool,
    pub comment_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule_fields: Option<CronScheduleFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub special: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_iso8601: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_line: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronListHumanSummary {
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronListResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    pub scope: String,
    pub users: Vec<String>,
    pub include_system: bool,
    pub truncated: bool,
    pub entries_total: Option<u32>,
    pub entries_returned: u32,
    pub entries_disabled: u32,
    pub entries: Vec<CronEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub human: Option<CronListHumanSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// CronAdd types and structures
// ===========================================================================

#[derive(Debug, Clone)]
pub struct CronAddOptions {
    pub schedule: String,
    pub command: String,

    pub backend: String,          // "auto" | "cron" | "systemd"

    pub id: Option<String>,
    pub description: Option<String>,
    pub allow_duplicate: bool,
    pub dry_run: bool,

    pub scope: String,            // "current" | "user" | "system"
    pub user: Option<String>,
    pub cron_file: Option<String>,

    pub unit_name: Option<String>,
    pub unit_scope: String,       // "auto" | "user" | "system"
    pub persistent: bool,
    pub accuracy_sec: Option<String>,
    pub random_delay_sec: Option<String>,
    pub service_working_dir: Option<String>,
    pub service_user: Option<String>,
    pub env: Option<HashMap<String, String>>,

    pub include_next_run: bool,
    pub now_unix: Option<i64>,
    pub timezone: Option<String>,

    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronAddJobLocation {
    pub scope: String,            // "current" | "user" | "system" | "user-unit" | "system-unit"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,     // cron file, if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_added: Option<u32>,  // for cron

    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronAddJobInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub backend: String,          // "cron" | "systemd"
    pub schedule: String,
    pub command: String,

    pub location: CronAddJobLocation,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_iso8601: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronAddPreview {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cron_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronAddResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_used: Option<String>,
    pub dry_run: bool,
    pub duplicate: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub job: Option<CronAddJobInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<CronAddPreview>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// CronRm types and structures  
// ===========================================================================

#[derive(Debug, Clone)]
pub struct CronRmOptions {
    pub id: Option<String>,
    pub backend: String,          // "both" | "cron" | "systemd"
    
    pub scope: String,            // "current" | "user" | "system" | "all"
    pub users: Vec<String>,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    pub cron_file: Option<String>,
    
    pub unit_name: Option<String>,
    pub unit_scope: String,       // "auto" | "user" | "system" | "both"
    pub match_unit: Option<String>,
    
    pub require_match: bool,
    pub remove_units: bool,
    pub dry_run: bool,
    
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmCronRemovedEntry {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmSystemdRemovedEntry {
    pub unit_scope: String,       // "user" | "system"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmRemovedSummary {
    pub cron: Vec<CronRmCronRemovedEntry>,
    pub systemd: Vec<CronRmSystemdRemovedEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmMatchedCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronRmResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,
    
    pub dry_run: bool,
    pub backend: String,
    pub cron_modified_sources: Vec<String>,
    pub systemd_scopes_touched: Vec<String>,
    
    pub removed: CronRmRemovedSummary,
    pub matched_count: CronRmMatchedCount,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// CronEnable types and structures
// ===========================================================================

#[derive(Debug, Clone)]
pub struct CronEnableOptions {
    pub id: Option<String>,
    pub backend: String,          // "both" | "cron" | "systemd"

    // Cron selectors
    pub scope: String,            // "current" | "user" | "system" | "all"
    pub users: Vec<String>,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    pub cron_file: Option<String>,

    // systemd selectors
    pub unit_name: Option<String>,
    pub unit_scope: String,       // "auto" | "user" | "system" | "both"
    pub match_unit: Option<String>,

    pub require_match: bool,
    pub start_now: bool,
    pub dry_run: bool,

    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableCronEntry {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub was_disabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableSystemdEntry {
    pub unit_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub was_enabled: bool,
    pub started_now: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableEnabledSummary {
    pub cron: Vec<CronEnableCronEntry>,
    pub systemd: Vec<CronEnableSystemdEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableMatchedCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableAlreadyEnabledCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronEnableResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub dry_run: bool,
    pub backend: String,

    pub enabled: CronEnableEnabledSummary,
    
    pub matched_count: CronEnableMatchedCount,
    pub already_enabled_count: CronEnableAlreadyEnabledCount,

    pub cron_modified_sources: Vec<String>,
    pub systemd_scopes_touched: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// CronDisable types and structures
// ===========================================================================

#[derive(Debug, Clone)]
pub struct CronDisableOptions {
    pub id: Option<String>,
    pub backend: String,          // "both" | "cron" | "systemd"

    // Cron selectors
    pub scope: String,            // "current" | "user" | "system" | "all"
    pub users: Vec<String>,
    pub schedule: Option<String>,
    pub command: Option<String>,
    pub match_command: Option<String>,
    pub match_comment: Option<String>,
    pub cron_file: Option<String>,

    // systemd selectors
    pub unit_name: Option<String>,
    pub unit_scope: String,       // "auto" | "user" | "system" | "both"
    pub match_unit: Option<String>,

    pub require_match: bool,
    pub stop_now: bool,
    pub dry_run: bool,

    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableCronEntry {
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    pub was_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableSystemdEntry {
    pub unit_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timer_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub was_enabled: bool,
    pub stopped_now: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableDisabledSummary {
    pub cron: Vec<CronDisableCronEntry>,
    pub systemd: Vec<CronDisableSystemdEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableMatchedCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableAlreadyDisabledCount {
    pub cron: u32,
    pub systemd: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronDisableResponse {
    pub ok: bool,
    pub timestamp_unix_ms: i64,

    pub dry_run: bool,
    pub backend: String,

    pub disabled: CronDisableDisabledSummary,
    
    pub matched_count: CronDisableMatchedCount,
    pub already_disabled_count: CronDisableAlreadyDisabledCount,

    pub cron_modified_sources: Vec<String>,
    pub systemd_scopes_touched: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    pub warnings: Vec<String>,
}

// ===========================================================================
// Editor traits for testability
// ===========================================================================

pub trait CronEditor: std::fmt::Debug + Send + Sync {
    fn read_user_crontab(&self, user: &str) -> Result<String>;
    fn write_user_crontab(&self, user: &str, content: &str) -> Result<()>;
    fn read_system_file(&self, path: &str) -> Result<String>;
    fn write_system_file(&self, path: &str, content: &str) -> Result<()>;
    fn file_exists(&self, path: &str) -> bool;
    fn create_directory(&self, path: &str) -> Result<()>;
}

pub trait SystemdEditor: std::fmt::Debug + Send + Sync {
    fn write_unit_file(&self, path: &str, content: &str) -> Result<()>;
    fn systemctl_daemon_reload(&self, user_mode: bool) -> Result<()>;
    fn systemctl_enable_timer(&self, timer_name: &str, user_mode: bool) -> Result<()>;
    fn systemctl_is_available(&self, user_mode: bool) -> bool;
    fn list_timers(&self, user_mode: bool) -> Result<Vec<String>>;
    fn get_unit_dir(&self, user_mode: bool) -> Result<String>;
    fn file_exists(&self, path: &str) -> bool;
    fn create_directory(&self, path: &str) -> Result<()>;
}

// ===========================================================================
// SystemCronProvider helper methods
// ===========================================================================

impl SystemCronProvider {
    fn determine_cron_target(&self, options: &CronAddOptions, _warnings: &mut Vec<String>) -> Result<(String, String, String)> {
        let scope = options.scope.clone();
        let user = options.user.clone().unwrap_or_else(|| self.current_user.clone());
        
        let file_path = match scope.as_str() {
            "current" => format!("/var/spool/cron/crontabs/{}", self.current_user),
            "user" => format!("/var/spool/cron/crontabs/{}", user),
            "system" => {
                if let Some(ref file) = options.cron_file {
                    file.clone()
                } else {
                    "/etc/crontab".to_string()
                }
            }
            _ => return Err(anyhow::anyhow!("Invalid scope: {}", scope)),
        };
        
        Ok((scope, user, file_path))
    }
    
    fn check_cron_duplicate(&self, options: &CronAddOptions, scope: &str, user: &str, file_path: &str) -> Result<bool> {
        let existing_content = match scope {
            "current" | "user" => {
                self.read_user_crontab(user).unwrap_or_default()
            }
            "system" => {
                fs::read_to_string(file_path).unwrap_or_default()
            }
            _ => return Ok(false),
        };
        
        for line in existing_content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            
            // Basic duplicate check: same schedule and command
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 6 {
                let existing_schedule = parts[0..5].join(" ");
                let existing_command = parts[5..].join(" ");
                
                if existing_schedule == options.schedule && existing_command == options.command {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }
    
    fn build_cron_lines(&self, options: &CronAddOptions, scope: &str) -> Result<(String, Option<String>)> {
        let mut comment_parts = Vec::new();
        
        if let Some(ref id) = options.id {
            comment_parts.push(format!("job-id={}", id));
        }
        
        if let Some(ref desc) = options.description {
            comment_parts.push(format!("description={}", desc));
        }
        
        let comment_line = if !comment_parts.is_empty() {
            Some(format!("# {}", comment_parts.join(" ")))
        } else {
            None
        };
        
        let cron_line = match scope {
            "system" => {
                let user = options.user.as_deref().unwrap_or("root");
                format!("{} {} {}", options.schedule, user, options.command)
            }
            _ => {
                format!("{} {}", options.schedule, options.command)
            }
        };
        
        Ok((cron_line, comment_line))
    }
    
    fn build_cron_job_info(&self, options: &CronAddOptions, scope: &str, user: &str, file_path: &str, line_added: Option<u32>) -> Result<CronAddJobInfo> {
        let next_run_unix = if options.include_next_run {
            compute_next_run(&options.schedule, self.get_current_time())
        } else {
            None
        };
        
        let next_run_iso8601 = next_run_unix.map(|unix| {
            Utc.timestamp_opt(unix, 0)
                .single()
                .unwrap_or_else(|| self.get_current_time())
                .to_rfc3339()
        });
        
        Ok(CronAddJobInfo {
            id: options.id.clone(),
            backend: "cron".to_string(),
            schedule: options.schedule.clone(),
            command: options.command.clone(),
            location: CronAddJobLocation {
                scope: scope.to_string(),
                file: Some(file_path.to_string()),
                user: Some(user.to_string()),
                line_added,
                unit_name: None,
                timer_unit: None,
                service_unit: None,
                unit_dir: None,
            },
            next_run_unix,
            next_run_iso8601,
        })
    }
    
    fn add_to_user_crontab(&self, user: &str, cron_line: &str, comment_line: &Option<String>, editor: &dyn CronEditor) -> Result<u32> {
        let existing_content = editor.read_user_crontab(user)?;
        let mut lines: Vec<&str> = existing_content.lines().collect();
        
        if let Some(comment) = comment_line {
            lines.push(comment);
        }
        lines.push(cron_line);
        
        let new_content = lines.join("\n");
        let new_content = if !new_content.ends_with('\n') {
            format!("{}\n", new_content)
        } else {
            new_content
        };
        
        editor.write_user_crontab(user, &new_content)?;
        Ok(lines.len() as u32)
    }
    
    fn add_to_system_file(&self, file_path: &str, cron_line: &str, comment_line: &Option<String>, editor: &dyn CronEditor) -> Result<u32> {
        let existing_content = editor.read_system_file(file_path).unwrap_or_default();
        let mut lines: Vec<&str> = existing_content.lines().collect();
        
        if let Some(comment) = comment_line {
            lines.push(comment);
        }
        lines.push(cron_line);
        
        let new_content = lines.join("\n");
        let new_content = if !new_content.ends_with('\n') {
            format!("{}\n", new_content)
        } else {
            new_content
        };
        
        editor.write_system_file(file_path, &new_content)?;
        Ok(lines.len() as u32)
    }
    
    fn determine_systemd_scope(&self, options: &CronAddOptions) -> String {
        match options.unit_scope.as_str() {
            "user" => "user".to_string(),
            "system" => "system".to_string(),
            "auto" => {
                if std::env::var("USER").unwrap_or_default() == "root" {
                    "system".to_string()
                } else {
                    "user".to_string()
                }
            }
            _ => "user".to_string(), // default fallback
        }
    }
    
    fn derive_unit_name_from_command(&self, command: &str) -> String {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if let Some(cmd_path) = parts.first() {
            if let Some(basename) = Path::new(cmd_path).file_name() {
                if let Some(name_str) = basename.to_str() {
                    // Remove extension and sanitize
                    let name = name_str.split('.').next().unwrap_or(name_str);
                    return name.chars()
                        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
                        .collect::<String>()
                        .trim_matches('-')
                        .to_string();
                }
            }
        }
        "cron-job".to_string()
    }
    
    fn check_systemd_duplicate(&self, unit_name: &str, user_mode: bool, editor: &dyn SystemdEditor) -> Result<bool> {
        let timer_name = format!("{}.timer", unit_name);
        let timers = editor.list_timers(user_mode).unwrap_or_default();
        Ok(timers.contains(&timer_name))
    }
    
    fn build_service_unit(&self, options: &CronAddOptions, unit_name: &str) -> Result<String> {
        let mut content = String::new();
        
        // [Unit] section
        content.push_str("[Unit]\n");
        let description = if let Some(ref desc) = options.description {
            if let Some(ref id) = options.id {
                format!("{} [id={}]", desc, id)
            } else {
                desc.clone()
            }
        } else if let Some(ref id) = options.id {
            format!("Cron job [id={}]", id)
        } else {
            format!("Cron job: {}", unit_name)
        };
        content.push_str(&format!("Description={}\n\n", description));
        
        // [Service] section
        content.push_str("[Service]\n");
        content.push_str("Type=oneshot\n");
        
        if let Some(ref working_dir) = options.service_working_dir {
            content.push_str(&format!("WorkingDirectory={}\n", working_dir));
        }
        
        if let Some(ref user) = options.service_user {
            content.push_str(&format!("User={}\n", user));
        }
        
        if let Some(ref env_map) = options.env {
            for (key, value) in env_map {
                content.push_str(&format!("Environment=\"{}={}\"\n", key, value));
            }
        }
        
        // Wrap command in shell if it contains shell metacharacters
        let exec_start = if options.command.contains('|') || options.command.contains('&') 
            || options.command.contains(';') || options.command.contains('>') 
            || options.command.contains('<') {
            format!("/bin/sh -c '{}'", options.command.replace('\'', "'\"'\"'"))
        } else {
            options.command.clone()
        };
        content.push_str(&format!("ExecStart={}\n\n", exec_start));
        
        // [Install] section
        content.push_str("[Install]\n");
        content.push_str("WantedBy=multi-user.target\n");
        
        Ok(content)
    }
    
    fn build_timer_unit(&self, options: &CronAddOptions, unit_name: &str, on_calendar: &str) -> Result<String> {
        let mut content = String::new();
        
        // [Unit] section
        content.push_str("[Unit]\n");
        let description = if let Some(ref desc) = options.description {
            if let Some(ref id) = options.id {
                format!("Timer for {} [id={}]", desc, id)
            } else {
                format!("Timer for {}", desc)
            }
        } else if let Some(ref id) = options.id {
            format!("Timer for cron job [id={}]", id)
        } else {
            format!("Timer for {}", unit_name)
        };
        content.push_str(&format!("Description={}\n\n", description));
        
        // [Timer] section
        content.push_str("[Timer]\n");
        content.push_str(&format!("OnCalendar={}\n", on_calendar));
        
        if options.persistent {
            content.push_str("Persistent=true\n");
        }
        
        if let Some(ref accuracy) = options.accuracy_sec {
            content.push_str(&format!("AccuracySec={}\n", accuracy));
        }
        
        if let Some(ref delay) = options.random_delay_sec {
            content.push_str(&format!("RandomizedDelaySec={}\n", delay));
        }
        
        content.push_str("\n[Install]\n");
        content.push_str("WantedBy=timers.target\n");
        
        Ok(content)
    }
    
    fn build_systemd_job_info(&self, options: &CronAddOptions, unit_name: &str, unit_scope: &str) -> Result<CronAddJobInfo> {
        let next_run_unix = if options.include_next_run {
            compute_next_run(&options.schedule, self.get_current_time())
        } else {
            None
        };
        
        let next_run_iso8601 = next_run_unix.map(|unix| {
            Utc.timestamp_opt(unix, 0)
                .single()
                .unwrap_or_else(|| self.get_current_time())
                .to_rfc3339()
        });
        
        let unit_dir = if unit_scope == "user" {
            std::env::var("HOME").map(|home| format!("{}/.config/systemd/user", home)).unwrap_or_default()
        } else {
            "/etc/systemd/system".to_string()
        };
        
        Ok(CronAddJobInfo {
            id: options.id.clone(),
            backend: "systemd".to_string(),
            schedule: format!("OnCalendar={}", convert_cron_to_oncalendar(&options.schedule)?),
            command: options.command.clone(),
            location: CronAddJobLocation {
                scope: format!("{}-unit", unit_scope),
                file: None,
                user: options.service_user.clone(),
                line_added: None,
                unit_name: Some(unit_name.to_string()),
                timer_unit: Some(format!("{}.timer", unit_name)),
                service_unit: Some(format!("{}.service", unit_name)),
                unit_dir: Some(unit_dir),
            },
            next_run_unix,
            next_run_iso8601,
        })
    }
    
    fn create_systemd_units(&self, unit_name: &str, service_content: &str, timer_content: &str, user_mode: bool, editor: &dyn SystemdEditor) -> Result<()> {
        let unit_dir = editor.get_unit_dir(user_mode)?;
        
        // Ensure unit directory exists
        editor.create_directory(&unit_dir)?;
        
        // Write unit files
        let service_path = format!("{}/{}.service", unit_dir, unit_name);
        let timer_path = format!("{}/{}.timer", unit_dir, unit_name);
        
        editor.write_unit_file(&service_path, service_content)?;
        editor.write_unit_file(&timer_path, timer_content)?;
        
        // Reload systemd and enable timer
        editor.systemctl_daemon_reload(user_mode)?;
        editor.systemctl_enable_timer(&format!("{}.timer", unit_name), user_mode)?;
        
        Ok(())
    }

    fn remove_from_cron(&self, options: &CronRmOptions, warnings: &mut Vec<String>) -> Result<(Vec<CronRmCronRemovedEntry>, Vec<String>)> {
        let mut removed_entries = Vec::new();
        let mut modified_sources = Vec::new();
        let cron_editor: Box<dyn CronEditor> = Box::new(SystemCronEditor::new());

        // Determine which cron sources to check based on scope
        let mut sources_to_check = Vec::new();
        
        match options.scope.as_str() {
            "current" => {
                sources_to_check.push(("user".to_string(), self.current_user.clone(), None));
            }
            "user" => {
                if options.users.is_empty() {
                    warnings.push("scope='user' specified but no users provided".to_string());
                } else {
                    for user in &options.users {
                        sources_to_check.push(("user".to_string(), user.clone(), None));
                    }
                }
            }
            "system" => {
                sources_to_check.push(("system".to_string(), "root".to_string(), Some("/etc/crontab".to_string())));
                
                // Add cron.d files
                if let Ok(cron_d_files) = self.read_cron_d_files() {
                    for (filename, _) in cron_d_files {
                        sources_to_check.push(("system".to_string(), "root".to_string(), Some(filename)));
                    }
                }
            }
            "all" => {
                // Current user
                sources_to_check.push(("user".to_string(), self.current_user.clone(), None));
                
                // System crontab
                sources_to_check.push(("system".to_string(), "root".to_string(), Some("/etc/crontab".to_string())));
                
                // Add cron.d files
                if let Ok(cron_d_files) = self.read_cron_d_files() {
                    for (filename, _) in cron_d_files {
                        sources_to_check.push(("system".to_string(), "root".to_string(), Some(filename)));
                    }
                }
            }
            _ => {
                warnings.push(format!("Invalid scope: {}", options.scope));
                return Ok((removed_entries, modified_sources));
            }
        }

        // Process each source
        for (scope_type, user, file_path) in sources_to_check {
            if let Ok(content) = self.read_cron_source(&scope_type, &user, file_path.as_deref()) {
                let (new_content, entries) = self.remove_matching_cron_entries(&content, options, &scope_type, &user, file_path.as_deref())?;
                
                if !entries.is_empty() && !options.dry_run {
                    // Write back the modified content
                    if let Err(e) = self.write_cron_source(&scope_type, &user, file_path.as_deref(), &new_content, cron_editor.as_ref()) {
                        warnings.push(format!("Failed to update {}: {}", self.get_source_name(&scope_type, &user, file_path.as_deref()), e));
                        continue;
                    }
                }
                
                if !entries.is_empty() {
                    modified_sources.push(self.get_source_name(&scope_type, &user, file_path.as_deref()));
                    removed_entries.extend(entries);
                }
            } else {
                warnings.push(format!("Failed to read {}", self.get_source_name(&scope_type, &user, file_path.as_deref())));
            }
        }

        Ok((removed_entries, modified_sources))
    }

    fn remove_from_systemd(&self, options: &CronRmOptions, warnings: &mut Vec<String>) -> Result<(Vec<CronRmSystemdRemovedEntry>, Vec<String>)> {
        let mut removed_entries = Vec::new();
        let mut scopes_touched = Vec::new();

        // Check if systemd is available
        if !self.is_systemd_available() {
            warnings.push("systemd not available".to_string());
            return Ok((removed_entries, scopes_touched));
        }

        // Determine unit scopes to check
        let scopes_to_check = match options.unit_scope.as_str() {
            "user" => vec!["user"],
            "system" => vec!["system"],
            "both" => vec!["user", "system"],
            "auto" => {
                if self.current_user == "root" {
                    vec!["system"]
                } else {
                    vec!["user"]
                }
            }
            _ => {
                warnings.push(format!("Invalid unit_scope: {}", options.unit_scope));
                return Ok((removed_entries, scopes_touched));
            }
        };

        for scope in scopes_to_check {
            // List all timers in this scope
            let output = std::process::Command::new("systemctl")
                .args(if scope == "user" { 
                    vec!["--user", "list-timers", "--all", "--no-pager", "--plain"] 
                } else { 
                    vec!["list-timers", "--all", "--no-pager", "--plain"] 
                })
                .output();

            let timers = match output {
                Ok(output) => {
                    if !output.status.success() {
                        warnings.push(format!("Failed to list {} timers: {}", scope, 
                            String::from_utf8_lossy(&output.stderr)));
                        continue;
                    }
                    String::from_utf8_lossy(&output.stdout).to_string()
                }
                Err(e) => {
                    warnings.push(format!("Failed to execute systemctl for {} scope: {}", scope, e));
                    continue;
                }
            };

            // Find matching timers
            for line in timers.lines().skip(1) { // Skip header
                if let Some(timer_name) = line.split_whitespace().next() {
                    if timer_name.ends_with(".timer") && self.timer_matches(timer_name, options, scope)? {
                        if !options.dry_run {
                            // Stop and disable the timer
                            let _ = std::process::Command::new("systemctl")
                                .args(if scope == "user" { 
                                    vec!["--user", "stop", timer_name] 
                                } else { 
                                    vec!["stop", timer_name] 
                                })
                                .output();

                            let _ = std::process::Command::new("systemctl")
                                .args(if scope == "user" { 
                                    vec!["--user", "disable", timer_name] 
                                } else { 
                                    vec!["disable", timer_name] 
                                })
                                .output();

                            // Optionally remove unit files
                            if options.remove_units {
                                self.remove_systemd_unit_files(timer_name, scope, warnings);
                            }
                        }

                        let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
                        removed_entries.push(CronRmSystemdRemovedEntry {
                            unit_scope: scope.to_string(),
                            timer_unit: Some(timer_name.to_string()),
                            service_unit: Some(service_name),
                            id: self.extract_id_from_timer(timer_name, scope).ok(),
                        });
                    }
                }
            }

            if !removed_entries.is_empty() && !scopes_touched.contains(&scope.to_string()) {
                scopes_touched.push(scope.to_string());
            }
        }

        Ok((removed_entries, scopes_touched))
    }

    fn enable_from_cron(&self, options: &CronEnableOptions, warnings: &mut Vec<String>) -> Result<(Vec<CronEnableCronEntry>, u32, Vec<String>)> {
        let mut enabled_entries = Vec::new();
        let mut already_enabled_count = 0u32;
        let mut modified_sources = Vec::new();
        let cron_editor: Box<dyn CronEditor> = Box::new(SystemCronEditor::new());

        // Determine which cron sources to check based on scope
        let mut sources_to_check = Vec::new();
        
        match options.scope.as_str() {
            "current" => {
                sources_to_check.push(("user".to_string(), self.current_user.clone(), None));
            }
            "user" => {
                if options.users.is_empty() {
                    warnings.push("scope='user' specified but no users provided".to_string());
                } else {
                    for user in &options.users {
                        sources_to_check.push(("user".to_string(), user.clone(), None));
                    }
                }
            }
            "system" => {
                sources_to_check.push(("system".to_string(), "root".to_string(), Some("/etc/crontab".to_string())));
                
                // Add cron.d files
                if let Ok(cron_d_files) = self.read_cron_d_files() {
                    for (filename, _) in cron_d_files {
                        sources_to_check.push(("system".to_string(), "root".to_string(), Some(filename)));
                    }
                }
            }
            "all" => {
                // Current user
                sources_to_check.push(("user".to_string(), self.current_user.clone(), None));
                
                // System crontab
                sources_to_check.push(("system".to_string(), "root".to_string(), Some("/etc/crontab".to_string())));
                
                // Add cron.d files
                if let Ok(cron_d_files) = self.read_cron_d_files() {
                    for (filename, _) in cron_d_files {
                        sources_to_check.push(("system".to_string(), "root".to_string(), Some(filename)));
                    }
                }
            }
            _ => {
                warnings.push(format!("Invalid scope: {}", options.scope));
            }
        }

        // Check each source
        for (scope_type, user, file_path) in sources_to_check {
            if let Ok(content) = self.read_cron_source(&scope_type, &user, file_path.as_deref()) {
                let (new_content, entries, already_enabled) = self.enable_matching_cron_entries(&content, options, &scope_type, &user, file_path.as_deref())?;
                
                already_enabled_count += already_enabled;
                
                if !entries.is_empty() && !options.dry_run {
                    // Write back the modified content
                    if let Err(e) = self.write_cron_source(&scope_type, &user, file_path.as_deref(), &new_content, cron_editor.as_ref()) {
                        warnings.push(format!("Failed to update {}: {}", self.get_source_name(&scope_type, &user, file_path.as_deref()), e));
                        continue;
                    }
                }
                
                if !entries.is_empty() {
                    modified_sources.push(self.get_source_name(&scope_type, &user, file_path.as_deref()));
                    enabled_entries.extend(entries);
                }
            } else {
                warnings.push(format!("Failed to read {}", self.get_source_name(&scope_type, &user, file_path.as_deref())));
            }
        }

        Ok((enabled_entries, already_enabled_count, modified_sources))
    }

    fn enable_from_systemd(&self, options: &CronEnableOptions, warnings: &mut Vec<String>) -> Result<(Vec<CronEnableSystemdEntry>, u32, Vec<String>)> {
        let mut enabled_entries = Vec::new();
        let mut already_enabled_count = 0u32;
        let mut scopes_touched = Vec::new();

        // Check if systemd is available
        if !self.is_systemd_available() {
            warnings.push("systemd not available".to_string());
            return Ok((enabled_entries, already_enabled_count, scopes_touched));
        }

        // Determine unit scopes to check
        let scopes_to_check = match options.unit_scope.as_str() {
            "user" => vec!["user"],
            "system" => vec!["system"],
            "both" => vec!["user", "system"],
            "auto" => {
                if self.current_user == "root" {
                    vec!["system"]
                } else {
                    vec!["user"]
                }
            }
            _ => {
                warnings.push(format!("Invalid unit_scope: {}", options.unit_scope));
                return Ok((enabled_entries, already_enabled_count, scopes_touched));
            }
        };

        for scope in scopes_to_check {
            // List all timers in this scope
            let output = std::process::Command::new("systemctl")
                .args(if scope == "user" { 
                    vec!["--user", "list-timers", "--all", "--no-pager", "--plain"] 
                } else { 
                    vec!["list-timers", "--all", "--no-pager", "--plain"] 
                })
                .output();

            let timers = match output {
                Ok(output) => {
                    if !output.status.success() {
                        warnings.push(format!("Failed to list {} timers: {}", scope, 
                            String::from_utf8_lossy(&output.stderr)));
                        continue;
                    }
                    String::from_utf8_lossy(&output.stdout).to_string()
                }
                Err(e) => {
                    warnings.push(format!("Failed to execute systemctl for {} scope: {}", scope, e));
                    continue;
                }
            };

            // Find matching timers
            for line in timers.lines().skip(1) { // Skip header
                if let Some(timer_name) = line.split_whitespace().next() {
                    if timer_name.ends_with(".timer") && self.timer_matches_enable(timer_name, options, scope)? {
                        // Check if timer is already enabled/active
                        let is_enabled = self.check_timer_enabled(timer_name, scope)?;
                        let is_active = self.check_timer_active(timer_name, scope)?;
                        
                        if is_enabled && is_active {
                            already_enabled_count += 1;
                        } else if !options.dry_run {
                            // Enable the timer
                            let enable_result = std::process::Command::new("systemctl")
                                .args(if scope == "user" { 
                                    if options.start_now {
                                        vec!["--user", "enable", "--now", timer_name]
                                    } else {
                                        vec!["--user", "enable", timer_name]
                                    }
                                } else { 
                                    if options.start_now {
                                        vec!["enable", "--now", timer_name]
                                    } else {
                                        vec!["enable", timer_name]
                                    }
                                })
                                .output();

                            match enable_result {
                                Ok(output) if output.status.success() => {
                                    let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
                                    enabled_entries.push(CronEnableSystemdEntry {
                                        unit_scope: scope.to_string(),
                                        timer_unit: Some(timer_name.to_string()),
                                        service_unit: Some(service_name),
                                        id: self.extract_id_from_timer(timer_name, scope).ok(),
                                        was_enabled: is_enabled,
                                        started_now: options.start_now,
                                    });
                                }
                                Ok(output) => {
                                    warnings.push(format!("Failed to enable {} timer: {}", timer_name, 
                                        String::from_utf8_lossy(&output.stderr)));
                                }
                                Err(e) => {
                                    warnings.push(format!("Failed to execute systemctl enable for {}: {}", timer_name, e));
                                }
                            }
                        } else {
                            // Dry run - just record what would be enabled
                            let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
                            enabled_entries.push(CronEnableSystemdEntry {
                                unit_scope: scope.to_string(),
                                timer_unit: Some(timer_name.to_string()),
                                service_unit: Some(service_name),
                                id: self.extract_id_from_timer(timer_name, scope).ok(),
                                was_enabled: is_enabled,
                                started_now: options.start_now,
                            });
                        }
                    }
                }
            }

            if (!enabled_entries.is_empty() || already_enabled_count > 0) && !scopes_touched.contains(&scope.to_string()) {
                scopes_touched.push(scope.to_string());
            }
        }

        Ok((enabled_entries, already_enabled_count, scopes_touched))
    }

    fn enable_matching_cron_entries(
        &self,
        content: &str,
        options: &CronEnableOptions,
        scope_type: &str,
        user: &str,
        file_path: Option<&str>
    ) -> Result<(String, Vec<CronEnableCronEntry>, u32)> {
        let mut new_lines = Vec::new();
        let mut enabled_entries = Vec::new();
        let mut already_enabled_count = 0u32;
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            
            // Skip empty lines
            if line.is_empty() {
                new_lines.push(lines[i].to_string());
                i += 1;
                continue;
            }

            // Check for job-id comment followed by cron line
            let mut job_id = None;
            if line.starts_with('#') && line.contains("job-id=") {
                // Extract job ID from comment
                if let Some(start) = line.find("job-id=") {
                    let id_part = &line[start + 8..];
                    if let Some(end) = id_part.find(' ') {
                        job_id = Some(id_part[..end].to_string());
                    } else {
                        job_id = Some(id_part.to_string());
                    }
                }
                new_lines.push(lines[i].to_string());
                i += 1;
                
                // Check if next line is the cron job
                if i < lines.len() {
                    let next_line = lines[i].trim();
                    if let Some((schedule, command, was_disabled)) = self.parse_potentially_disabled_cron_line(next_line) {
                        if self.cron_entry_matches_enable(&schedule, &command, &job_id, options) {
                            if was_disabled {
                                // Enable by uncommenting
                                let enabled_line = self.enable_cron_line(next_line);
                                new_lines.push(enabled_line.clone());
                                
                                enabled_entries.push(CronEnableCronEntry {
                                    source: self.get_source_name(scope_type, user, file_path),
                                    user: if scope_type == "user" { Some(user.to_string()) } else { None },
                                    schedule: Some(schedule),
                                    command: Some(command),
                                    id: job_id,
                                    line_number: Some((i + 1) as u32),
                                    was_disabled: true,
                                });
                            } else {
                                // Already enabled
                                already_enabled_count += 1;
                                new_lines.push(lines[i].to_string());
                            }
                        } else {
                            new_lines.push(lines[i].to_string());
                        }
                        i += 1;
                        continue;
                    } else {
                        // Next line is not a cron job, continue normally
                    }
                } else {
                    // No next line
                }
                continue;
            }

            // Check if this is a standalone cron line (not preceded by job-id comment)
            if let Some((schedule, command, was_disabled)) = self.parse_potentially_disabled_cron_line(line) {
                if self.cron_entry_matches_enable(&schedule, &command, &None, options) {
                    if was_disabled {
                        // Enable by uncommenting
                        let enabled_line = self.enable_cron_line(line);
                        new_lines.push(enabled_line.clone());
                        
                        enabled_entries.push(CronEnableCronEntry {
                            source: self.get_source_name(scope_type, user, file_path),
                            user: if scope_type == "user" { Some(user.to_string()) } else { None },
                            schedule: Some(schedule),
                            command: Some(command),
                            id: None,
                            line_number: Some((i + 1) as u32),
                            was_disabled: true,
                        });
                    } else {
                        // Already enabled
                        already_enabled_count += 1;
                        new_lines.push(lines[i].to_string());
                    }
                } else {
                    new_lines.push(lines[i].to_string());
                }
            } else {
                // Not a cron line (comment, etc.)
                new_lines.push(lines[i].to_string());
            }
            
            i += 1;
        }

        Ok((new_lines.join("\n") + "\n", enabled_entries, already_enabled_count))
    }

    fn timer_matches_enable(&self, timer_name: &str, options: &CronEnableOptions, scope: &str) -> Result<bool> {
        // Check if timer matches the enable criteria (similar to timer_matches but for enable options)
        
        // Match by unit_name
        if let Some(unit_name) = &options.unit_name {
            let base_name = timer_name.trim_end_matches(".timer");
            if unit_name == timer_name || unit_name == base_name {
                return Ok(true);
            }
        }

        // Match by match_unit substring
        if let Some(match_pattern) = &options.match_unit {
            if timer_name.to_lowercase().contains(&match_pattern.to_lowercase()) {
                return Ok(true);
            }
        }

        // Match by ID
        if let Some(id) = &options.id {
            if let Ok(timer_id) = self.extract_id_from_timer(timer_name, scope) {
                if timer_id == *id {
                    return Ok(true);
                }
            }
        }

        // Match by command (check service ExecStart)
        if options.match_command.is_some() {
            let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
            if let Ok(exec_start) = self.get_service_exec_start(&service_name, scope) {
                if let Some(pattern) = &options.match_command {
                    if exec_start.to_lowercase().contains(&pattern.to_lowercase()) {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn check_timer_enabled(&self, timer_name: &str, scope: &str) -> Result<bool> {
        let output = std::process::Command::new("systemctl")
            .args(if scope == "user" { 
                vec!["--user", "is-enabled", timer_name] 
            } else { 
                vec!["is-enabled", timer_name] 
            })
            .output()?;

        Ok(output.status.success())
    }

    fn check_timer_active(&self, timer_name: &str, scope: &str) -> Result<bool> {
        let output = std::process::Command::new("systemctl")
            .args(if scope == "user" { 
                vec!["--user", "is-active", timer_name] 
            } else { 
                vec!["is-active", timer_name] 
            })
            .output()?;

        Ok(output.status.success())
    }

    fn parse_potentially_disabled_cron_line(&self, line: &str) -> Option<(String, String, bool)> {
        let trimmed = line.trim();
        
        // Check if line is commented out (disabled)
        let (is_commented, content) = if trimmed.starts_with('#') {
            let content = trimmed.trim_start_matches('#').trim();
            (true, content)
        } else {
            (false, trimmed)
        };

        // Try to parse as cron line
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 6 {
            // Standard cron format: minute hour day month dow command...
            let schedule = format!("{} {} {} {} {}", parts[0], parts[1], parts[2], parts[3], parts[4]);
            let command = parts[5..].join(" ");
            
            // Remove inline comments from command
            let command = if let Some(comment_pos) = command.find(" #") {
                command[..comment_pos].trim().to_string()
            } else {
                command.trim().to_string()
            };
            
            return Some((schedule, command, is_commented));
        }

        // Check for special schedules like @reboot, @daily, etc.
        if parts.len() >= 2 && parts[0].starts_with('@') {
            let schedule = parts[0].to_string();
            let command = parts[1..].join(" ");
            
            // Remove inline comments from command
            let command = if let Some(comment_pos) = command.find(" #") {
                command[..comment_pos].trim().to_string()
            } else {
                command.trim().to_string()
            };
            
            return Some((schedule, command, is_commented));
        }

        None
    }

    fn cron_entry_matches_enable(&self, schedule: &str, command: &str, job_id: &Option<String>, options: &CronEnableOptions) -> bool {
        // Match by ID
        if let (Some(target_id), Some(entry_id)) = (&options.id, job_id) {
            return target_id == entry_id;
        }

        // Match by schedule + command (exact match)
        if let (Some(target_schedule), Some(target_command)) = (&options.schedule, &options.command) {
            let schedule_match = self.normalize_schedule(schedule) == self.normalize_schedule(target_schedule);
            let command_match = command.trim() == target_command.trim();
            if schedule_match && command_match {
                return true;
            }
        }

        // Match by command substring
        if let Some(pattern) = &options.match_command {
            if command.to_lowercase().contains(&pattern.to_lowercase()) {
                return true;
            }
        }

        false
    }

    fn enable_cron_line(&self, line: &str) -> String {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            // Remove the leading '#' and optionally one space
            let content = trimmed.trim_start_matches('#');
            if content.starts_with(' ') {
                content[1..].to_string()
            } else {
                content.to_string()
            }
        } else {
            // Already enabled
            line.to_string()
        }
    }

    fn normalize_schedule(&self, schedule: &str) -> String {
        // Normalize whitespace in cron schedule
        schedule.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn disable_from_cron(&self, options: &CronDisableOptions, warnings: &mut Vec<String>) -> Result<(Vec<CronDisableCronEntry>, u32, Vec<String>)> {
        let mut disabled_entries = Vec::new();
        let mut already_disabled_count = 0u32;
        let mut modified_sources = Vec::new();
        let cron_editor = Box::new(SystemCronEditor::new());

        // Determine sources to scan based on scope
        let sources = match options.scope.as_str() {
            "current" => vec![("user".to_string(), self.current_user.clone(), None)],
            "user" => {
                if options.users.is_empty() {
                    warnings.push("scope='user' requires 'users' parameter".to_string());
                    return Ok((disabled_entries, already_disabled_count, modified_sources));
                }
                options.users.iter()
                    .map(|user| ("user".to_string(), user.clone(), None))
                    .collect()
            }
            "system" => {
                let mut sources = vec![("system".to_string(), "root".to_string(), None)];
                
                // Add /etc/cron.d files
                if let Ok(cron_d_files) = self.read_cron_d_files() {
                    for (filename, _) in cron_d_files {
                        let file_path = format!("/etc/cron.d/{}", filename);
                        sources.push(("system".to_string(), "root".to_string(), Some(file_path)));
                    }
                }
                sources
            }
            "all" => {
                let mut sources = vec![("user".to_string(), self.current_user.clone(), None)];
                sources.push(("system".to_string(), "root".to_string(), None));
                
                // Add /etc/cron.d files
                if let Ok(cron_d_files) = self.read_cron_d_files() {
                    for (filename, _) in cron_d_files {
                        let file_path = format!("/etc/cron.d/{}", filename);
                        sources.push(("system".to_string(), "root".to_string(), Some(file_path)));
                    }
                }
                sources
            }
            _ => {
                warnings.push(format!("Invalid scope: {}", options.scope));
                return Ok((disabled_entries, already_disabled_count, modified_sources));
            }
        };

        // Check for specific cron_file override
        let sources = if let Some(cron_file) = &options.cron_file {
            vec![("system".to_string(), "root".to_string(), Some(cron_file.clone()))]
        } else {
            sources
        };

        for (scope_type, user, file_path) in sources {
            match self.read_cron_source(&scope_type, &user, file_path.as_deref()) {
                Ok(content) => {
                    let (new_content, mut entries, already_disabled) = self.disable_matching_cron_entries(
                        &content, options, &scope_type, &user, file_path.as_deref()
                    )?;

                    already_disabled_count += already_disabled;
                    
                    if !entries.is_empty() && new_content != content {
                        // Write changes if not dry run
                        if !options.dry_run {
                            if let Err(e) = self.write_cron_source(&scope_type, &user, file_path.as_deref(), &new_content, cron_editor.as_ref()) {
                                warnings.push(format!("Failed to write {}: {}", 
                                    self.get_source_name(&scope_type, &user, file_path.as_deref()), e));
                                continue;
                            }
                        }
                        
                        let source_name = self.get_source_name(&scope_type, &user, file_path.as_deref());
                        if !modified_sources.contains(&source_name) {
                            modified_sources.push(source_name);
                        }
                    }
                    
                    disabled_entries.append(&mut entries);
                }
                Err(e) => {
                    warnings.push(format!("Failed to read {}: {}", 
                        self.get_source_name(&scope_type, &user, file_path.as_deref()), e));
                }
            }
        }

        Ok((disabled_entries, already_disabled_count, modified_sources))
    }

    fn disable_from_systemd(&self, options: &CronDisableOptions, warnings: &mut Vec<String>) -> Result<(Vec<CronDisableSystemdEntry>, u32, Vec<String>)> {
        let mut disabled_entries = Vec::new();
        let mut already_disabled_count = 0u32;
        let mut scopes_touched = Vec::new();

        // Check if systemd is available
        if !self.is_systemd_available() {
            warnings.push("systemd not available".to_string());
            return Ok((disabled_entries, already_disabled_count, scopes_touched));
        }

        // Determine unit scopes to check
        let scopes_to_check = match options.unit_scope.as_str() {
            "user" => vec!["user"],
            "system" => vec!["system"],
            "both" => vec!["user", "system"],
            "auto" => {
                if self.current_user == "root" {
                    vec!["system"]
                } else {
                    vec!["user"]
                }
            }
            _ => {
                warnings.push(format!("Invalid unit_scope: {}", options.unit_scope));
                return Ok((disabled_entries, already_disabled_count, scopes_touched));
            }
        };

        for scope in scopes_to_check {
            // List all timers in this scope
            let output = std::process::Command::new("systemctl")
                .args(if scope == "user" { 
                    vec!["--user", "list-timers", "--all", "--no-pager", "--plain"] 
                } else { 
                    vec!["list-timers", "--all", "--no-pager", "--plain"] 
                })
                .output();

            let timers = match output {
                Ok(output) => {
                    if !output.status.success() {
                        warnings.push(format!("Failed to list {} timers: {}", scope, 
                            String::from_utf8_lossy(&output.stderr)));
                        continue;
                    }
                    String::from_utf8_lossy(&output.stdout).to_string()
                }
                Err(e) => {
                    warnings.push(format!("Failed to execute systemctl for {} scope: {}", scope, e));
                    continue;
                }
            };

            // Find matching timers
            for line in timers.lines().skip(1) { // Skip header
                if let Some(timer_name) = line.split_whitespace().next() {
                    if timer_name.ends_with(".timer") && self.timer_matches_disable(timer_name, options, scope)? {
                        // Check if timer is currently enabled/active
                        let is_enabled = self.check_timer_enabled(timer_name, scope)?;
                        let is_active = self.check_timer_active(timer_name, scope)?;
                        
                        if !is_enabled && !is_active {
                            already_disabled_count += 1;
                        } else if !options.dry_run {
                            // Disable the timer
                            let mut disable_success = true;
                            let mut stop_success = true;

                            // Stop the timer if requested and it's active
                            if options.stop_now && is_active {
                                let stop_result = std::process::Command::new("systemctl")
                                    .args(if scope == "user" { 
                                        vec!["--user", "stop", timer_name]
                                    } else { 
                                        vec!["stop", timer_name]
                                    })
                                    .output();

                                match stop_result {
                                    Ok(output) if !output.status.success() => {
                                        warnings.push(format!("Failed to stop {} timer: {}", timer_name, 
                                            String::from_utf8_lossy(&output.stderr)));
                                        stop_success = false;
                                    }
                                    Err(e) => {
                                        warnings.push(format!("Failed to execute systemctl stop for {}: {}", timer_name, e));
                                        stop_success = false;
                                    }
                                    _ => {} // Success
                                }
                            }

                            // Disable the timer if it's enabled
                            if is_enabled {
                                let disable_result = std::process::Command::new("systemctl")
                                    .args(if scope == "user" { 
                                        vec!["--user", "disable", timer_name]
                                    } else { 
                                        vec!["disable", timer_name]
                                    })
                                    .output();

                                match disable_result {
                                    Ok(output) if !output.status.success() => {
                                        warnings.push(format!("Failed to disable {} timer: {}", timer_name, 
                                            String::from_utf8_lossy(&output.stderr)));
                                        disable_success = false;
                                    }
                                    Err(e) => {
                                        warnings.push(format!("Failed to execute systemctl disable for {}: {}", timer_name, e));
                                        disable_success = false;
                                    }
                                    _ => {} // Success
                                }
                            }

                            if disable_success {
                                let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
                                disabled_entries.push(CronDisableSystemdEntry {
                                    unit_scope: scope.to_string(),
                                    timer_unit: Some(timer_name.to_string()),
                                    service_unit: Some(service_name),
                                    id: self.extract_id_from_timer(timer_name, scope).ok(),
                                    was_enabled: is_enabled,
                                    stopped_now: options.stop_now && stop_success,
                                });
                            }
                        } else {
                            // Dry run - just record what would be disabled
                            let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
                            disabled_entries.push(CronDisableSystemdEntry {
                                unit_scope: scope.to_string(),
                                timer_unit: Some(timer_name.to_string()),
                                service_unit: Some(service_name),
                                id: self.extract_id_from_timer(timer_name, scope).ok(),
                                was_enabled: is_enabled,
                                stopped_now: options.stop_now,
                            });
                        }
                    }
                }
            }

            if (!disabled_entries.is_empty() || already_disabled_count > 0) && !scopes_touched.contains(&scope.to_string()) {
                scopes_touched.push(scope.to_string());
            }
        }

        Ok((disabled_entries, already_disabled_count, scopes_touched))
    }

    fn disable_matching_cron_entries(
        &self,
        content: &str,
        options: &CronDisableOptions,
        scope_type: &str,
        user: &str,
        file_path: Option<&str>
    ) -> Result<(String, Vec<CronDisableCronEntry>, u32)> {
        let mut new_lines = Vec::new();
        let mut disabled_entries = Vec::new();
        let mut already_disabled_count = 0u32;
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            
            // Skip empty lines
            if line.is_empty() {
                new_lines.push(lines[i].to_string());
                i += 1;
                continue;
            }

            // Check for job-id comment followed by cron line
            let mut job_id = None;
            if line.starts_with('#') && line.contains("job-id=") {
                // Extract job ID from comment
                if let Some(start) = line.find("job-id=") {
                    let id_part = &line[start + 8..];
                    if let Some(end) = id_part.find(' ') {
                        job_id = Some(id_part[..end].to_string());
                    } else {
                        job_id = Some(id_part.to_string());
                    }
                }
                new_lines.push(lines[i].to_string());
                i += 1;
                
                // Check if next line is the cron job
                if i < lines.len() {
                    let next_line = lines[i].trim();
                    if let Some((schedule, command, was_disabled)) = self.parse_potentially_disabled_cron_line(next_line) {
                        if self.cron_entry_matches_disable(&schedule, &command, &job_id, options) {
                            if !was_disabled {
                                // Disable by commenting out
                                let disabled_line = self.disable_cron_line(next_line);
                                new_lines.push(disabled_line.clone());
                                
                                disabled_entries.push(CronDisableCronEntry {
                                    source: self.get_source_name(scope_type, user, file_path),
                                    user: if scope_type == "user" { Some(user.to_string()) } else { None },
                                    schedule: Some(schedule),
                                    command: Some(command),
                                    id: job_id,
                                    line_number: Some((i + 1) as u32),
                                    was_enabled: true,
                                });
                            } else {
                                // Already disabled
                                already_disabled_count += 1;
                                new_lines.push(lines[i].to_string());
                            }
                        } else {
                            new_lines.push(lines[i].to_string());
                        }
                        i += 1;
                        continue;
                    } else {
                        // Next line is not a cron job, continue normally
                    }
                } else {
                    // No next line
                }
                continue;
            }

            // Check if this is a standalone cron line (not preceded by job-id comment)
            if let Some((schedule, command, was_disabled)) = self.parse_potentially_disabled_cron_line(line) {
                if self.cron_entry_matches_disable(&schedule, &command, &None, options) {
                    if !was_disabled {
                        // Disable by commenting out
                        let disabled_line = self.disable_cron_line(line);
                        new_lines.push(disabled_line.clone());
                        
                        disabled_entries.push(CronDisableCronEntry {
                            source: self.get_source_name(scope_type, user, file_path),
                            user: if scope_type == "user" { Some(user.to_string()) } else { None },
                            schedule: Some(schedule),
                            command: Some(command),
                            id: None,
                            line_number: Some((i + 1) as u32),
                            was_enabled: true,
                        });
                    } else {
                        // Already disabled
                        already_disabled_count += 1;
                        new_lines.push(lines[i].to_string());
                    }
                } else {
                    new_lines.push(lines[i].to_string());
                }
            } else {
                // Not a cron line (comment, etc.)
                new_lines.push(lines[i].to_string());
            }
            
            i += 1;
        }

        Ok((new_lines.join("\n") + "\n", disabled_entries, already_disabled_count))
    }

    fn timer_matches_disable(&self, timer_name: &str, options: &CronDisableOptions, scope: &str) -> Result<bool> {
        // Check if timer matches the disable criteria
        
        // Match by unit_name
        if let Some(unit_name) = &options.unit_name {
            let base_name = timer_name.trim_end_matches(".timer");
            if unit_name == timer_name || unit_name == base_name {
                return Ok(true);
            }
        }

        // Match by match_unit substring
        if let Some(match_pattern) = &options.match_unit {
            if timer_name.to_lowercase().contains(&match_pattern.to_lowercase()) {
                return Ok(true);
            }
        }

        // Match by ID
        if let Some(id) = &options.id {
            if let Ok(timer_id) = self.extract_id_from_timer(timer_name, scope) {
                if timer_id == *id {
                    return Ok(true);
                }
            }
        }

        // Match by command (check service ExecStart)
        if options.match_command.is_some() {
            let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
            if let Ok(exec_start) = self.get_service_exec_start(&service_name, scope) {
                if let Some(pattern) = &options.match_command {
                    if exec_start.to_lowercase().contains(&pattern.to_lowercase()) {
                        return Ok(true);
                    }
                }
            }
        }

        // Match by comment (check timer or service Description)
        if options.match_comment.is_some() {
            if let Ok(description) = self.get_timer_description(timer_name, scope) {
                if let Some(pattern) = &options.match_comment {
                    if description.to_lowercase().contains(&pattern.to_lowercase()) {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn cron_entry_matches_disable(&self, schedule: &str, command: &str, job_id: &Option<String>, options: &CronDisableOptions) -> bool {
        // Match by ID
        if let (Some(target_id), Some(entry_id)) = (&options.id, job_id) {
            return target_id == entry_id;
        }

        // Match by schedule + command (exact match)
        if let (Some(target_schedule), Some(target_command)) = (&options.schedule, &options.command) {
            let schedule_match = self.normalize_schedule(schedule) == self.normalize_schedule(target_schedule);
            let command_match = command.trim() == target_command.trim();
            if schedule_match && command_match {
                return true;
            }
        }

        // Match by command substring
        if let Some(pattern) = &options.match_command {
            if command.to_lowercase().contains(&pattern.to_lowercase()) {
                return true;
            }
        }

        false
    }

    fn disable_cron_line(&self, line: &str) -> String {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            // Already disabled
            line.to_string()
        } else {
            // Comment out the line
            format!("# {}", line)
        }
    }

    fn get_timer_description(&self, timer_name: &str, scope: &str) -> Result<String> {
        let output = std::process::Command::new("systemctl")
            .args(if scope == "user" { 
                vec!["--user", "show", "--property=Description", timer_name] 
            } else { 
                vec!["show", "--property=Description", timer_name] 
            })
            .output()?;

        if !output.status.success() {
            return Err(anyhow::anyhow!("Failed to get timer description"));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        if let Some(line) = output_str.lines().find(|line| line.starts_with("Description=")) {
            Ok(line.strip_prefix("Description=").unwrap_or("").to_string())
        } else {
            Ok(String::new())
        }
    }

    fn read_cron_source(&self, scope_type: &str, user: &str, file_path: Option<&str>) -> Result<String> {
        match scope_type {
            "user" => self.read_user_crontab(user),
            "system" => {
                if let Some(path) = file_path {
                    self.read_file(path)
                } else {
                    self.read_system_crontab()
                }
            }
            _ => Err(anyhow::anyhow!("Invalid scope type: {}", scope_type))
        }
    }

    fn write_cron_source(&self, scope_type: &str, user: &str, file_path: Option<&str>, content: &str, cron_editor: &dyn CronEditor) -> Result<()> {
        match scope_type {
            "user" => cron_editor.write_user_crontab(user, content),
            "system" => {
                if let Some(path) = file_path {
                    cron_editor.write_system_file(path, content)
                } else {
                    cron_editor.write_system_file("/etc/crontab", content)
                }
            }
            _ => Err(anyhow::anyhow!("Invalid scope type: {}", scope_type))
        }
    }

    fn get_source_name(&self, scope_type: &str, user: &str, file_path: Option<&str>) -> String {
        match scope_type {
            "user" => format!("/var/spool/cron/{}", user),
            "system" => file_path.unwrap_or("/etc/crontab").to_string(),
            _ => "unknown".to_string()
        }
    }

    fn remove_matching_cron_entries(
        &self,
        content: &str,
        options: &CronRmOptions,
        scope_type: &str,
        user: &str,
        file_path: Option<&str>
    ) -> Result<(String, Vec<CronRmCronRemovedEntry>)> {
        let mut new_lines = Vec::new();
        let mut removed_entries = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut i = 0;

        while i < lines.len() {
            let line = lines[i].trim();
            
            // Skip empty lines and comments that aren't job-id comments
            if line.is_empty() || (line.starts_with('#') && !line.contains("job-id=")) {
                new_lines.push(lines[i].to_string());
                i += 1;
                continue;
            }

            // Check for job-id comment followed by cron line
            let mut job_id = None;
            let mut cron_line_idx = i;
            
            if line.starts_with('#') && line.contains("job-id=") {
                // Extract job-id from comment
                if let Some(start) = line.find("job-id=") {
                    let start = start + "job-id=".len();
                    if let Some(end) = line[start..].find(|c: char| c.is_whitespace()) {
                        job_id = Some(line[start..start + end].to_string());
                    } else {
                        job_id = Some(line[start..].to_string());
                    }
                }
                
                // Check if next line is a cron job
                if i + 1 < lines.len() {
                    cron_line_idx = i + 1;
                } else {
                    new_lines.push(lines[i].to_string());
                    i += 1;
                    continue;
                }
            }

            let cron_line = lines[cron_line_idx].trim();
            
            // Parse the cron line
            if let Some((schedule, command)) = self.parse_cron_line(cron_line, scope_type == "system") {
                let matches = self.cron_entry_matches(&schedule, &command, &job_id, options);
                
                if matches {
                    // This entry should be removed
                    removed_entries.push(CronRmCronRemovedEntry {
                        source: self.get_source_name(scope_type, user, file_path),
                        user: Some(user.to_string()),
                        schedule: Some(schedule),
                        command: Some(command),
                        id: job_id.clone(),
                        line_number: Some((cron_line_idx + 1) as u32),
                    });
                    
                    // Skip both the comment line (if any) and the cron line
                    if job_id.is_some() && cron_line_idx > i {
                        i = cron_line_idx + 1; // Skip both comment and cron line
                    } else {
                        i += 1; // Skip just the cron line
                    }
                } else {
                    // Keep this entry
                    if job_id.is_some() && cron_line_idx > i {
                        new_lines.push(lines[i].to_string()); // comment line
                        new_lines.push(lines[cron_line_idx].to_string()); // cron line
                        i = cron_line_idx + 1;
                    } else {
                        new_lines.push(lines[i].to_string());
                        i += 1;
                    }
                }
            } else {
                // Not a valid cron line, keep it
                new_lines.push(lines[i].to_string());
                i += 1;
            }
        }

        Ok((new_lines.join("\n") + "\n", removed_entries))
    }

    fn parse_cron_line(&self, line: &str, is_system: bool) -> Option<(String, String)> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        
        if is_system {
            // System cron format: min hour day month dow user command...
            if parts.len() >= 7 {
                let schedule = format!("{} {} {} {} {}", parts[0], parts[1], parts[2], parts[3], parts[4]);
                let command = parts[6..].join(" ");
                Some((schedule, command))
            } else {
                None
            }
        } else {
            // User cron format: min hour day month dow command...
            if parts.len() >= 6 {
                let schedule = format!("{} {} {} {} {}", parts[0], parts[1], parts[2], parts[3], parts[4]);
                let command = parts[5..].join(" ");
                Some((schedule, command))
            } else {
                None
            }
        }
    }

    fn cron_entry_matches(&self, schedule: &str, command: &str, job_id: &Option<String>, options: &CronRmOptions) -> bool {
        // Check id match
        if let Some(target_id) = &options.id {
            if let Some(entry_id) = job_id {
                return entry_id == target_id;
            } else {
                return false;
            }
        }

        // Check schedule + command match
        if let (Some(target_schedule), Some(target_command)) = (&options.schedule, &options.command) {
            return schedule == target_schedule && command == target_command;
        }

        // Check individual field matches
        let mut matches = true;

        if let Some(target_schedule) = &options.schedule {
            matches = matches && schedule == target_schedule;
        }

        if let Some(target_command) = &options.command {
            matches = matches && command == target_command;
        }

        if let Some(match_command) = &options.match_command {
            matches = matches && command.to_lowercase().contains(&match_command.to_lowercase());
        }

        if let Some(match_comment) = &options.match_comment {
            // For cron entries, we'd need to check any inline comments
            matches = matches && command.to_lowercase().contains(&match_comment.to_lowercase());
        }

        matches
    }

    fn is_systemd_available(&self) -> bool {
        std::process::Command::new("systemctl")
            .arg("--version")
            .output()
            .is_ok()
    }

    fn timer_matches(&self, timer_name: &str, options: &CronRmOptions, scope: &str) -> Result<bool> {
        // Check unit_name match
        if let Some(target_unit) = &options.unit_name {
            let base_name = timer_name.trim_end_matches(".timer");
            if base_name == target_unit || timer_name == target_unit {
                return Ok(true);
            }
        }

        // Check match_unit
        if let Some(match_unit) = &options.match_unit {
            if timer_name.to_lowercase().contains(&match_unit.to_lowercase()) {
                return Ok(true);
            }
        }

        // Check id match by reading unit file
        if let Some(target_id) = &options.id {
            if let Ok(id) = self.extract_id_from_timer(timer_name, scope) {
                if id == *target_id {
                    return Ok(true);
                }
            }
        }

        // Check match_command by reading ExecStart from service
        if let Some(match_command) = &options.match_command {
            let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
            if let Ok(exec_start) = self.get_service_exec_start(&service_name, scope) {
                if exec_start.to_lowercase().contains(&match_command.to_lowercase()) {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    fn extract_id_from_timer(&self, timer_name: &str, scope: &str) -> Result<String> {
        let unit_path = if scope == "user" {
            format!("{}/.config/systemd/user/{}", std::env::var("HOME").unwrap_or_default(), timer_name)
        } else {
            format!("/etc/systemd/system/{}", timer_name)
        };

        let content = std::fs::read_to_string(&unit_path)?;
        
        // Look for id= in Description or comments
        for line in content.lines() {
            if line.starts_with("Description=") && line.contains("id=") {
                if let Some(start) = line.find("id=") {
                    let start = start + 3;
                    if let Some(end) = line[start..].find(|c: char| c.is_whitespace() || c == ']') {
                        return Ok(line[start..start + end].to_string());
                    } else {
                        return Ok(line[start..].to_string());
                    }
                }
            }
        }
        
        Err(anyhow::anyhow!("No id found in timer unit"))
    }

    fn get_service_exec_start(&self, service_name: &str, scope: &str) -> Result<String> {
        let unit_path = if scope == "user" {
            format!("{}/.config/systemd/user/{}", std::env::var("HOME").unwrap_or_default(), service_name)
        } else {
            format!("/etc/systemd/system/{}", service_name)
        };

        let content = std::fs::read_to_string(&unit_path)?;
        
        for line in content.lines() {
            if line.starts_with("ExecStart=") {
                return Ok(line["ExecStart=".len()..].to_string());
            }
        }
        
        Err(anyhow::anyhow!("No ExecStart found in service unit"))
    }

    fn remove_systemd_unit_files(&self, timer_name: &str, scope: &str, warnings: &mut Vec<String>) {
        let service_name = timer_name.trim_end_matches(".timer").to_string() + ".service";
        
        let unit_dir = if scope == "user" {
            format!("{}/.config/systemd/user", std::env::var("HOME").unwrap_or_default())
        } else {
            "/etc/systemd/system".to_string()
        };

        // Remove timer unit
        let timer_path = format!("{}/{}", unit_dir, timer_name);
        if let Err(e) = std::fs::remove_file(&timer_path) {
            warnings.push(format!("Failed to remove {}: {}", timer_path, e));
        }

        // Remove service unit
        let service_path = format!("{}/{}", unit_dir, service_name);
        if let Err(e) = std::fs::remove_file(&service_path) {
            warnings.push(format!("Failed to remove {}: {}", service_path, e));
        }

        // Reload systemd daemon
        let _ = std::process::Command::new("systemctl")
            .args(if scope == "user" { 
                vec!["--user", "daemon-reload"] 
            } else { 
                vec!["daemon-reload"] 
            })
            .output();
    }
}

// ===========================================================================
// Parsing functions
// ===========================================================================

fn parse_user_crontab(content: &str, user: &str, source_file: Option<&str>) -> Result<Vec<CronEntry>> {
    let mut entries = Vec::new();
    
    for (line_num, line) in content.lines().enumerate() {
        let line_number = (line_num + 1) as u32;
        let trimmed = line.trim();
        
        if trimmed.is_empty() {
            continue;
        }
        
        let enabled = !trimmed.starts_with('#');
        let line_content = if !enabled {
            trimmed.strip_prefix('#').unwrap_or(trimmed).trim()
        } else {
            trimmed
        };
        
        // Check if it's a comment-only line
        if line_content.is_empty() || (!enabled && !line_content.contains(' ')) {
            entries.push(CronEntry {
                id: format!("user:{}:{}:{}", user, source_file.unwrap_or("crontab"), line_number),
                user: Some(user.to_string()),
                source: "user".to_string(),
                source_file: source_file.map(|s| s.to_string()),
                source_line: Some(line_number),
                enabled,
                comment_only: true,
                schedule: None,
                schedule_fields: None,
                special: None,
                command: None,
                comment: Some(line_content.to_string()),
                next_run_unix: None,
                next_run_iso8601: None,
                raw_line: Some(line.to_string()),
            });
            continue;
        }
        
        if let Some(entry) = parse_cron_line(line_content, user, "user", source_file, line_number, enabled, line)? {
            entries.push(entry);
        }
    }
    
    Ok(entries)
}

fn parse_system_crontab(content: &str, file_path: &str) -> Result<Vec<CronEntry>> {
    let mut entries = Vec::new();
    
    for (line_num, line) in content.lines().enumerate() {
        let line_number = (line_num + 1) as u32;
        let trimmed = line.trim();
        
        if trimmed.is_empty() {
            continue;
        }
        
        let enabled = !trimmed.starts_with('#');
        let line_content = if !enabled {
            trimmed.strip_prefix('#').unwrap_or(trimmed).trim()
        } else {
            trimmed
        };
        
        // Check if it's a comment-only line
        if line_content.is_empty() || (!enabled && !line_content.contains(' ')) {
            entries.push(CronEntry {
                id: format!("system:{}:{}", file_path, line_number),
                user: None,
                source: if file_path == "/etc/crontab" { "system" } else { "file" }.to_string(),
                source_file: Some(file_path.to_string()),
                source_line: Some(line_number),
                enabled,
                comment_only: true,
                schedule: None,
                schedule_fields: None,
                special: None,
                command: None,
                comment: Some(line_content.to_string()),
                next_run_unix: None,
                next_run_iso8601: None,
                raw_line: Some(line.to_string()),
            });
            continue;
        }
        
        // Parse system crontab line with user field
        let parts: Vec<&str> = line_content.split_whitespace().collect();
        if parts.len() >= 6 {
            let user = parts[5].to_string();
            let source_type = if file_path == "/etc/crontab" { "system" } else { "file" };
            
            if let Some(entry) = parse_cron_line(line_content, &user, source_type, Some(file_path), line_number, enabled, line)? {
                entries.push(entry);
            }
        }
    }
    
    Ok(entries)
}

fn parse_cron_line(
    line: &str, 
    user: &str, 
    source_type: &str, 
    source_file: Option<&str>, 
    line_number: u32, 
    enabled: bool,
    raw_line: &str
) -> Result<Option<CronEntry>> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    
    if parts.is_empty() {
        return Ok(None);
    }
    
    // Handle special cron entries (@reboot, @daily, etc.)
    if parts[0].starts_with('@') {
        let special = parts[0].to_string();
        let command = if parts.len() > 1 {
            let start_idx = if source_type == "user" { 1 } else { 2 }; // Skip user field in system crontab
            parts[start_idx..].join(" ")
        } else {
            String::new()
        };
        
        let (cmd, comment) = split_command_comment(&command);
        
        return Ok(Some(CronEntry {
            id: format!("{}:{}:{}:{}", source_type, user, source_file.unwrap_or("crontab"), line_number),
            user: Some(user.to_string()),
            source: source_type.to_string(),
            source_file: source_file.map(|s| s.to_string()),
            source_line: Some(line_number),
            enabled,
            comment_only: false,
            schedule: None,
            schedule_fields: None,
            special: Some(special),
            command: Some(cmd),
            comment,
            next_run_unix: None,
            next_run_iso8601: None,
            raw_line: Some(raw_line.to_string()),
        }));
    }
    
    // Parse regular cron schedule (5 or 6 fields)
    let field_count = if source_type == "user" { 5 } else { 6 };
    if parts.len() < field_count + 1 {
        return Ok(None); // Not enough fields for schedule + command
    }
    
    let schedule_parts = &parts[0..5];
    let schedule = schedule_parts.join(" ");
    
    let command = if source_type == "user" {
        parts[5..].join(" ")
    } else {
        parts[6..].join(" ") // Skip user field in system crontab
    };
    
    let (cmd, comment) = split_command_comment(&command);
    
    Ok(Some(CronEntry {
        id: format!("{}:{}:{}:{}", source_type, user, source_file.unwrap_or("crontab"), line_number),
        user: Some(user.to_string()),
        source: source_type.to_string(),
        source_file: source_file.map(|s| s.to_string()),
        source_line: Some(line_number),
        enabled,
        comment_only: false,
        schedule: Some(schedule.clone()),
        schedule_fields: Some(CronScheduleFields {
            minute: schedule_parts[0].to_string(),
            hour: schedule_parts[1].to_string(),
            day_of_month: schedule_parts[2].to_string(),
            month: schedule_parts[3].to_string(),
            day_of_week: schedule_parts[4].to_string(),
        }),
        special: None,
        command: Some(cmd),
        comment,
        next_run_unix: None,
        next_run_iso8601: None,
        raw_line: Some(raw_line.to_string()),
    }))
}

fn split_command_comment(input: &str) -> (String, Option<String>) {
    if let Some(hash_pos) = input.find('#') {
        let command = input[..hash_pos].trim().to_string();
        let comment = input[hash_pos + 1..].trim().to_string();
        (command, if comment.is_empty() { None } else { Some(comment) })
    } else {
        (input.trim().to_string(), None)
    }
}

// ===========================================================================
// Filtering and sorting functions
// ===========================================================================

fn apply_filters(mut entries: Vec<CronEntry>, options: &CronListOptions) -> Vec<CronEntry> {
    // Simple state filtering only for now
    entries.retain(|entry| {
        match options.state.as_str() {
            "enabled" => entry.enabled,
            "disabled" => !entry.enabled,
            _ => true, // "all" - no filtering
        }
    });
    
    entries
}

fn apply_sorting(entries: &mut Vec<CronEntry>, sort_by: &str, sort_order: &str) {
    use std::cmp::Ordering;
    
    let ascending = sort_order != "desc";
    
    entries.sort_by(|a, b| {
        let result = match sort_by {
            "user" => {
                let user_cmp = a.user.cmp(&b.user);
                if user_cmp != Ordering::Equal {
                    user_cmp
                } else {
                    a.schedule.cmp(&b.schedule)
                }
            },
            "schedule" => {
                // If we have next_run_unix, sort by that, otherwise by schedule string
                if a.next_run_unix.is_some() && b.next_run_unix.is_some() {
                    a.next_run_unix.cmp(&b.next_run_unix)
                } else {
                    a.schedule.cmp(&b.schedule)
                }
            },
            "command" => a.command.cmp(&b.command),
            "source" => {
                let source_cmp = a.source.cmp(&b.source);
                if source_cmp != Ordering::Equal {
                    source_cmp
                } else {
                    a.source_file.cmp(&b.source_file)
                }
            },
            _ => Ordering::Equal, // "none" or unknown
        };
        
        if ascending { result } else { result.reverse() }
    });
}

// ===========================================================================
// Next run computation
// ===========================================================================

fn compute_next_run(schedule_str: &str, reference_time: DateTime<Utc>) -> Option<i64> {
    // Handle special cron entries
    match schedule_str {
        "@reboot" => return None, // Can't compute next reboot time
        "@yearly" | "@annually" => return compute_next_run("0 0 0 1 1 *", reference_time),
        "@monthly" => return compute_next_run("0 0 0 1 * *", reference_time),
        "@weekly" => return compute_next_run("0 0 0 * * 0", reference_time),
        "@daily" | "@midnight" => return compute_next_run("0 0 0 * * *", reference_time),
        "@hourly" => return compute_next_run("0 0 * * * *", reference_time),
        _ => {}
    }
    
    // Try to parse as 6-field format first
    let schedule = if let Ok(sched) = Schedule::from_str(schedule_str) {
        sched
    } else {
        // Try converting from 5-field to 6-field format
        let parts: Vec<&str> = schedule_str.split_whitespace().collect();
        if parts.len() == 5 {
            let six_field = format!("0 {}", schedule_str);
            Schedule::from_str(&six_field).ok()?
        } else {
            return None;
        }
    };
    
    // Parse standard cron schedule
    if let Some(next) = schedule.upcoming(Utc).next() {
        // Only return if it's after reference time
        if next > reference_time {
            return Some(next.timestamp());
        }
    }
    
    None
}

// ===========================================================================
// Registration function
// ===========================================================================

pub fn register(registry: &mut crate::core::Registry) {
    registry.register_scheme("cron", |url| {
        Ok(Box::new(CronHandle::from_url(url)?))
    });
}
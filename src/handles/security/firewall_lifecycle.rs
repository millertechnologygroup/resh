//! `status`, `rules.reload`, `enable` and `disable`: reading a backend's
//! state and applying rule files, backend reloads and start/stop.
//!
//! Every value has been checked by `fw_args::check` before these run.
//! Each verb queries the real state first (also in a dry run, which only
//! reads), refuses what it cannot do before changing anything, takes the
//! requested backup before the first change, and reports the commands it
//! ran (or would run) in `actions`.

use super::*;

/// Options shared by `rules.reload`, `enable` and `disable`.
#[derive(Clone, Debug)]
pub(crate) struct ApplyOptions {
    pub backend: FirewallBackend,
    pub family: IpFamily,
    pub path: Option<String>,
    pub source_format: RulesReloadSourceFormat,
    pub dry_run: bool,
    pub validate_only: bool,
    pub backup_before_apply: bool,
    /// `fail_if_already_enabled` / `fail_if_already_disabled`.
    pub fail_if_already: bool,
    pub timeout_ms: u64,
    pub format_output: OutputFormat,
}

/// Where the rules of one apply step come from.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum RulesSource {
    /// The file given by `path`, used as is.
    File(String),
    /// Backend-native data taken from a `rules.save` snapshot.
    Data(String),
}

/// One rules file applied with one tool: an iptables family, or nft.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ApplyUnit {
    /// `ipv4`/`ipv6` for iptables; `None` for nftables.
    pub family: Option<&'static str>,
    pub source: RulesSource,
}

impl ApplyUnit {
    /// The restore (or check) tool and its arguments before the file.
    fn tool(&self, check: bool) -> (&'static str, Vec<&'static str>) {
        match (self.family, check) {
            (Some("ipv6"), false) => ("ip6tables-restore", vec![]),
            (Some("ipv6"), true) => ("ip6tables-restore", vec!["--test"]),
            (Some(_), false) => ("iptables-restore", vec![]),
            (Some(_), true) => ("iptables-restore", vec!["--test"]),
            (None, false) => ("nft", vec!["-f"]),
            (None, true) => ("nft", vec!["-c", "-f"]),
        }
    }

    /// The command line reported for this step.
    fn describe(&self, check: bool) -> String {
        let (tool, flags) = self.tool(check);
        let file = match &self.source {
            RulesSource::File(path) => path.clone(),
            RulesSource::Data(_) => format!(
                "<{} rules from the snapshot>",
                self.family.unwrap_or("nftables")
            ),
        };
        let mut argv: Vec<String> = std::iter::once(tool.to_string())
            .chain(flags.iter().map(|f| f.to_string()))
            .collect();
        argv.push(file);
        display_command(&argv)
    }
}

const BACKENDS: [FirewallBackend; 4] = [
    FirewallBackend::Iptables,
    FirewallBackend::Nftables,
    FirewallBackend::Ufw,
    FirewallBackend::Firewalld,
];

impl FwResponse for StatusResponse {
    fn output_format(&self) -> OutputFormat {
        self.output_format.clone()
    }
    fn json(&self) -> Value {
        self.json_format()
    }
    fn text(&self) -> String {
        self.text_format()
    }
    fn failed(error: FirewallError, format: OutputFormat) -> Self {
        StatusResponse::with_error(
            StatusOptions {
                backend: StatusBackend::Auto,
                family: StatusFamily::Any,
                include_metrics: true,
                include_rules_summary: false,
                timeout_ms: 5000,
                output_format: format,
            },
            error,
        )
    }
}

/// The program whose presence makes a backend available.
fn backend_tools(backend: &FirewallBackend) -> &'static [&'static str] {
    match backend {
        FirewallBackend::Iptables => &["iptables", "ip6tables"],
        FirewallBackend::Nftables => &["nft"],
        FirewallBackend::Ufw => &["ufw"],
        FirewallBackend::Firewalld => &["firewall-cmd"],
        FirewallBackend::Auto => &[],
    }
}

fn unavailable_status(backend: &FirewallBackend, warning: String) -> FirewallBackendStatus {
    FirewallBackendStatus {
        backend: backend.as_str().to_string(),
        available: false,
        active: false,
        enabled: false,
        default_policy: None,
        rule_count_ipv4: None,
        rule_count_ipv6: None,
        details: None,
        rules_summary: None,
        warnings: vec![warning],
    }
}

/// True when `rule` applies to traffic of `family` (`ipv4`/`ipv6`): its own
/// family, or a family-neutral rule (ufw/firewalld `any`, nft `inet`)
/// without an address of the other family.
pub(crate) fn rule_in_family(rule: &FirewallRule, family: &str) -> bool {
    match rule.family.as_str() {
        f if f == family => true,
        "any" | "inet" => {
            // An inet rule restricted with `meta nfproto` serves one family.
            let nfproto = rule.raw.as_deref().and_then(super::nft::raw_nfproto);
            // icmp and icmpv6 each imply their family.
            let by_proto = match rule.proto.as_deref() {
                Some("icmp") => Some("ipv4"),
                Some("icmpv6") => Some("ipv6"),
                _ => None,
            };
            nfproto.or(by_proto).is_none_or(|f| f == family)
                && [&rule.saddr, &rule.daddr].iter().all(|a| {
                    a.as_deref()
                        .map(|a| address_family(a.trim_start_matches('!')) == family)
                        .unwrap_or(true)
                })
        }
        _ => false,
    }
}

/// Counts of `rules` by action and by direction.
fn rules_summary(rules: &[&FirewallRule]) -> Value {
    let mut by_action = serde_json::Map::new();
    let mut by_direction = serde_json::Map::new();
    for rule in rules {
        for (map, key) in [
            (&mut by_action, rule.action.as_deref().unwrap_or("none")),
            (
                &mut by_direction,
                rule.direction.as_deref().unwrap_or("other"),
            ),
        ] {
            let n = map.get(key).and_then(Value::as_u64).unwrap_or(0);
            map.insert(key.to_string(), json!(n + 1));
        }
    }
    json!({
        "total": rules.len(),
        "by_action": by_action,
        "by_direction": by_direction,
    })
}

/// The policy of the first filter chain hooked to `input` in an `nft list
/// ruleset` listing (`ACCEPT`/`DROP`), preferring the inet and ip tables.
fn nft_input_policy(ruleset: &str) -> Option<String> {
    let mut family = String::new();
    let mut best: Option<(u8, String)> = None;
    for line in ruleset.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("table ") {
            family = rest.split_whitespace().next().unwrap_or("").to_string();
        } else if line.contains("type filter") && line.contains("hook input") {
            if let Some(policy) = line
                .split("policy ")
                .nth(1)
                .and_then(|p| p.split(';').next())
            {
                let rank = match family.as_str() {
                    "inet" => 0,
                    "ip" => 1,
                    _ => 2,
                };
                if best.as_ref().is_none_or(|(r, _)| rank < *r) {
                    best = Some((rank, policy.trim().to_uppercase()));
                }
            }
        }
    }
    best.map(|(_, p)| p)
}

/// The INPUT policy of the filter table in `iptables-save` output, and
/// whether the rules are active (any rule, or a filter policy other than
/// ACCEPT).
fn iptables_state(save: &str) -> (Option<String>, bool) {
    let mut table = "";
    let mut policy = None;
    let mut active = false;
    for line in save.lines() {
        let line = line.trim();
        if let Some(t) = line.strip_prefix('*') {
            table = if t == "filter" { "filter" } else { "other" };
        } else if let Some(chain) = line.strip_prefix(':') {
            let mut parts = chain.split_whitespace();
            let (name, pol) = (parts.next(), parts.next());
            if table == "filter" {
                if let (Some(name), Some(pol)) = (name, pol) {
                    if matches!(name, "INPUT" | "OUTPUT" | "FORWARD") && pol != "ACCEPT" {
                        active = true;
                    }
                    if name == "INPUT" {
                        policy = Some(pol.to_string());
                    }
                }
            }
        } else if line.starts_with("-A ") {
            active = true;
        }
    }
    (policy, active)
}

impl FirewallHandle {
    // =======================================================================
    // status
    // =======================================================================

    pub(super) fn handle_status(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let result = block_on(async {
            let opts = self.parse_status_options(args)?;
            self.status_async(&opts).await
        });
        respond(args, io, result)
    }

    pub(super) fn parse_status_options(&self, args: &Args) -> Result<StatusOptions> {
        Ok(StatusOptions {
            backend: StatusBackend::from_str(args.get("backend").map_or("auto", |s| s))?,
            family: StatusFamily::from_str(args.get("family").map_or("any", |s| s))?,
            include_metrics: fw_args::bool_or(args, "include_metrics", true)?,
            include_rules_summary: fw_args::bool_or(args, "include_rules_summary", false)?,
            timeout_ms: match args.get("timeout_ms") {
                Some(t) => t.parse()?,
                None => 5000,
            },
            output_format: format_of(args),
        })
    }

    async fn status_async(&self, opts: &StatusOptions) -> Result<StatusResponse> {
        let backends = match opts.backend {
            StatusBackend::Auto => {
                let backend = self.detect_available_backend(opts.timeout_ms).await?;
                vec![self.backend_status(&backend, opts).await?]
            }
            StatusBackend::All => {
                let mut all = Vec::new();
                for backend in BACKENDS {
                    match self.backend_status(&backend, opts).await {
                        Ok(status) => all.push(status),
                        Err(e) => {
                            let fe = as_firewall_error(&e);
                            if matches!(fe, FirewallError::Timeout { .. }) {
                                return Err(e);
                            }
                            all.push(unavailable_status(
                                &backend,
                                format!("{} could not be queried: {fe}", backend.as_str()),
                            ));
                        }
                    }
                }
                all
            }
            StatusBackend::Iptables => {
                vec![
                    self.backend_status(&FirewallBackend::Iptables, opts)
                        .await?,
                ]
            }
            StatusBackend::Nftables => {
                vec![
                    self.backend_status(&FirewallBackend::Nftables, opts)
                        .await?,
                ]
            }
            StatusBackend::Ufw => vec![self.backend_status(&FirewallBackend::Ufw, opts).await?],
            StatusBackend::Firewalld => {
                vec![
                    self.backend_status(&FirewallBackend::Firewalld, opts)
                        .await?,
                ]
            }
        };
        Ok(StatusResponse::success(opts.clone(), backends))
    }

    /// Runs `tool args` and fails unless it exits 0.
    async fn checked(&self, tool: &str, args: &[&str], timeout_ms: u64) -> Result<String> {
        let (code, stdout, stderr) = run_command_with_timeout(tool, args, timeout_ms).await?;
        if code != 0 {
            let mut argv = vec![tool.to_string()];
            argv.extend(args.iter().map(|a| a.to_string()));
            return Err(FirewallError::CommandFailed {
                command: display_command(&argv),
                code,
                stderr: stderr.trim().to_string(),
            }
            .into());
        }
        Ok(stdout)
    }

    /// The state of one backend. A backend whose tool is not installed is
    /// reported as unavailable; a tool that fails is an error.
    pub(super) async fn backend_status(
        &self,
        backend: &FirewallBackend,
        opts: &StatusOptions,
    ) -> Result<FirewallBackendStatus> {
        let tools = backend_tools(backend);
        if !tools.iter().any(|t| is_command_available(t)) {
            return Ok(unavailable_status(
                backend,
                format!("{} is not installed", tools.join(" or ")),
            ));
        }
        let t = opts.timeout_ms;
        let list_opts = RulesListOptions {
            backend: backend.clone(),
            family: IpFamily::Any,
            include_backend_raw: true,
            max_rules: u64::MAX,
            timeout_ms: t,
            ..RulesListOptions::default()
        };
        let mut warnings = Vec::new();
        let (active, policy, rules, extra) = match backend {
            FirewallBackend::Iptables => {
                let mut active = false;
                let mut policies: Vec<(String, String)> = Vec::new();
                for (family, save) in [("IPv4", "iptables-save"), ("IPv6", "ip6tables-save")] {
                    if !is_command_available(save) {
                        warnings.push(format!("{save} is not installed; {family} not read"));
                        continue;
                    }
                    let out = self.checked(save, &[], t).await?;
                    let (policy, family_active) = iptables_state(&out);
                    active |= family_active;
                    if let Some(p) = policy {
                        policies.push((family.to_string(), p));
                    }
                }
                let policy = match policies.as_slice() {
                    [] => None,
                    [(_, p)] => Some(p.clone()),
                    [(_, a), (_, b)] if a == b => Some(a.clone()),
                    many => Some(
                        many.iter()
                            .map(|(f, p)| format!("{f}: {p}"))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                };
                let rules = self.get_rules_from_backend(backend, &list_opts).await?;
                (active, policy, rules, String::new())
            }
            FirewallBackend::Nftables => {
                let out = self.checked("nft", &["list", "ruleset"], t).await?;
                let tables: Vec<String> = out
                    .lines()
                    .filter_map(|l| l.trim().strip_prefix("table "))
                    .map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
                    .collect();
                let rules = self.get_rules_from_backend(backend, &list_opts).await?;
                let extra = if tables.is_empty() {
                    "no tables".to_string()
                } else {
                    format!("tables: {}", tables.join(", "))
                };
                (!tables.is_empty(), nft_input_policy(&out), rules, extra)
            }
            FirewallBackend::Ufw => {
                let out = self.checked("ufw", &["status", "verbose"], t).await?;
                let active = out.contains("Status: active");
                let policy = out
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("Default:"))
                    .map(|p| p.trim().to_string());
                let rules = if active {
                    self.get_rules_from_backend(backend, &list_opts).await?
                } else {
                    Vec::new()
                };
                (active, policy, rules, String::new())
            }
            FirewallBackend::Firewalld => {
                let (code, out, err) =
                    run_command_with_timeout("firewall-cmd", &["--state"], t).await?;
                let running = code == 0 && out.trim() == "running";
                if !running && code != 252 && !err.contains("not running") {
                    return Err(FirewallError::CommandFailed {
                        command: "firewall-cmd --state".to_string(),
                        code,
                        stderr: err.trim().to_string(),
                    }
                    .into());
                }
                if running {
                    let zone = self
                        .checked("firewall-cmd", &["--get-default-zone"], t)
                        .await?
                        .trim()
                        .to_string();
                    let zone_arg = format!("--zone={zone}");
                    let listing = self
                        .checked("firewall-cmd", &[zone_arg.as_str(), "--list-all"], t)
                        .await?;
                    let target = listing
                        .lines()
                        .find_map(|l| l.trim().strip_prefix("target:"))
                        .map(|p| p.trim().to_string());
                    let rules = self.get_rules_from_backend(backend, &list_opts).await?;
                    (true, target, rules, format!("default zone: {zone}"))
                } else {
                    (
                        false,
                        None,
                        Vec::new(),
                        "firewalld is not running".to_string(),
                    )
                }
            }
            FirewallBackend::Auto => {
                return Err(FirewallError::InternalError {
                    message: "backend not resolved".to_string(),
                }
                .into());
            }
        };

        let in_family =
            |family: &str| rules.iter().filter(|r| rule_in_family(r, family)).count() as u64;
        let (v4, v6) = match opts.family {
            StatusFamily::Any => (Some(in_family("ipv4")), Some(in_family("ipv6"))),
            StatusFamily::Ipv4 => (Some(in_family("ipv4")), None),
            StatusFamily::Ipv6 => (None, Some(in_family("ipv6"))),
        };
        let counted: Vec<&FirewallRule> = rules
            .iter()
            .filter(|r| match opts.family {
                StatusFamily::Any => true,
                StatusFamily::Ipv4 => rule_in_family(r, "ipv4"),
                StatusFamily::Ipv6 => rule_in_family(r, "ipv6"),
            })
            .collect();
        let details = opts.include_metrics.then(|| {
            let mut parts = vec![format!(
                "{} {}",
                backend.as_str(),
                if active { "active" } else { "inactive" }
            )];
            if !extra.is_empty() {
                parts.push(extra.clone());
            }
            parts.push(format!(
                "rules: ipv4={}, ipv6={}",
                v4.map_or("n/a".to_string(), |n| n.to_string()),
                v6.map_or("n/a".to_string(), |n| n.to_string())
            ));
            if let Some(p) = &policy {
                parts.push(format!("default policy {p}"));
            }
            parts.join("; ")
        });
        Ok(FirewallBackendStatus {
            backend: backend.as_str().to_string(),
            available: true,
            active,
            enabled: active,
            default_policy: policy,
            rule_count_ipv4: v4,
            rule_count_ipv6: v6,
            details,
            rules_summary: opts.include_rules_summary.then(|| rules_summary(&counted)),
            warnings,
        })
    }

    /// The available/active/enabled state of `backend`.
    pub(super) async fn current_state(
        &self,
        backend: &FirewallBackend,
        timeout_ms: u64,
    ) -> Result<FirewallStateSnapshot> {
        let opts = StatusOptions {
            backend: StatusBackend::All,
            family: StatusFamily::Any,
            include_metrics: false,
            include_rules_summary: false,
            timeout_ms,
            output_format: OutputFormat::Json,
        };
        let status = self.backend_status(backend, &opts).await?;
        Ok(FirewallStateSnapshot {
            available: status.available,
            active: status.active,
            enabled: status.enabled,
        })
    }

    // =======================================================================
    // Options of rules.reload, enable and disable
    // =======================================================================

    pub(super) fn parse_apply_options(&self, verb: &str, args: &Args) -> Result<ApplyOptions> {
        let fail_key = match verb {
            "enable" => "fail_if_already_enabled",
            _ => "fail_if_already_disabled",
        };
        let path = args.get("path").cloned();
        if path.is_none() && args.contains_key("source_format") {
            return Err(FirewallError::InvalidArgument {
                message: "source_format describes the file given by path; give path=<file>"
                    .to_string(),
            }
            .into());
        }
        Ok(ApplyOptions {
            backend: FirewallBackend::from_str(args.get("backend").map_or("auto", |s| s))?,
            family: IpFamily::from_str(args.get("family").map_or("any", |s| s))?,
            path,
            source_format: RulesReloadSourceFormat::from_str(
                args.get("source_format").map_or("auto", |s| s),
            )?,
            dry_run: fw_args::bool_or(args, "dry_run", false)?,
            validate_only: fw_args::bool_or(args, "validate_only", false)?,
            backup_before_apply: fw_args::bool_or(args, "backup_before_apply", true)?,
            fail_if_already: verb != "rules.reload" && fw_args::bool_or(args, fail_key, false)?,
            timeout_ms: match args.get("timeout_ms") {
                Some(t) => t.parse()?,
                None => 10000,
            },
            format_output: format_of(args),
        })
    }

    fn apply_query(&self, verb: &str, opts: &ApplyOptions) -> Value {
        let mut q = json!({
            "backend": opts.backend.as_str(),
            "family": opts.family.as_str(),
            "path": opts.path,
            "source_format": opts.source_format.as_str(),
            "dry_run": opts.dry_run,
            "validate_only": opts.validate_only,
            "backup_before_apply": opts.backup_before_apply,
            "timeout_ms": opts.timeout_ms,
            "format_output": match opts.format_output {
                OutputFormat::Json => "json",
                OutputFormat::Text => "text",
            },
        });
        match verb {
            "enable" => q["fail_if_already_enabled"] = json!(opts.fail_if_already),
            "disable" => q["fail_if_already_disabled"] = json!(opts.fail_if_already),
            _ => {}
        }
        q
    }

    /// The backend to act on: the detected one for `auto`, otherwise the
    /// given one, which must be available.
    async fn resolve_backend(
        &self,
        backend: &FirewallBackend,
        timeout_ms: u64,
    ) -> Result<FirewallBackend> {
        if *backend == FirewallBackend::Auto {
            self.detect_available_backend(timeout_ms).await
        } else {
            self.check_backend_availability(backend, timeout_ms).await?;
            Ok(backend.clone())
        }
    }

    /// Refuses options `backend` cannot honor, before anything runs.
    fn check_apply_options(
        &self,
        verb: &str,
        backend: &FirewallBackend,
        opts: &ApplyOptions,
    ) -> Result<()> {
        let unsupported = |option: &str, message: &str| -> Result<()> {
            Err(FirewallError::UnsupportedOption {
                option: option.to_string(),
                backend: backend.as_str().to_string(),
                message: message.to_string(),
            }
            .into())
        };
        let service = matches!(backend, FirewallBackend::Ufw | FirewallBackend::Firewalld);
        if service {
            if opts.path.is_some() {
                return unsupported("path", "this backend does not load a rules file");
            }
            if opts.family != IpFamily::Any {
                return unsupported("family", "this backend covers both families at once");
            }
            if opts.validate_only
                && !(verb == "rules.reload" && *backend == FirewallBackend::Firewalld)
            {
                return unsupported(
                    "validate_only",
                    "there is no rules file to validate on this backend",
                );
            }
        } else if opts.path.is_none() {
            if verb == "rules.reload" {
                return Err(FirewallError::PathRequired {
                    message: format!(
                        "rules.reload on {} applies a rules file; give path=<file>",
                        backend.as_str()
                    ),
                }
                .into());
            }
            if opts.validate_only {
                return Err(FirewallError::PathRequired {
                    message: "validate_only checks a rules file; give path=<file>".to_string(),
                }
                .into());
            }
        }
        Ok(())
    }

    /// The apply steps for `opts.path` on iptables or nftables.
    pub(super) fn plan_units(
        &self,
        backend: &FirewallBackend,
        opts: &ApplyOptions,
    ) -> Result<(Vec<ApplyUnit>, RulesReloadSourceFormat)> {
        let path = opts.path.clone().unwrap_or_default();
        let bytes =
            fs::read(&path).map_err(|_| FirewallError::PathNotFound { path: path.clone() })?;
        let content = if bytes.starts_with(&[0x1f, 0x8b]) {
            let mut text = String::new();
            std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&bytes[..]), &mut text)
                .map_err(|e| FirewallError::InvalidSnapshot {
                    message: format!("{path} is gzip data that cannot be read: {e}"),
                })?;
            text
        } else {
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let snapshot = serde_json::from_str::<Value>(&content)
            .ok()
            .filter(|v| v.get("version").is_some() && v.get("backends").is_some());
        let format = match (&opts.source_format, &snapshot) {
            (RulesReloadSourceFormat::Auto, Some(_)) => RulesReloadSourceFormat::NormalizedJson,
            (RulesReloadSourceFormat::Auto, None) => RulesReloadSourceFormat::BackendNative,
            (other, _) => other.clone(),
        };

        if format == RulesReloadSourceFormat::BackendNative {
            let family = match (backend, &opts.family) {
                (FirewallBackend::Iptables, IpFamily::Ipv4) => Some("ipv4"),
                (FirewallBackend::Iptables, IpFamily::Ipv6) => Some("ipv6"),
                (FirewallBackend::Iptables, IpFamily::Any) => {
                    return Err(FirewallError::InvalidArgument {
                        message: "a backend-native iptables file holds one family; give \
                                  family=ipv4 or family=ipv6"
                            .to_string(),
                    }
                    .into());
                }
                (_, IpFamily::Any) => None,
                (_, _) => {
                    return Err(FirewallError::UnsupportedOption {
                        option: "family".to_string(),
                        backend: backend.as_str().to_string(),
                        message: "an nft rules file sets its own families; leave family=any"
                            .to_string(),
                    }
                    .into());
                }
            };
            return Ok((
                vec![ApplyUnit {
                    family,
                    source: RulesSource::File(path),
                }],
                format,
            ));
        }

        let snapshot = snapshot.ok_or_else(|| FirewallError::InvalidSnapshot {
            message: format!("{path} is not a rules.save JSON snapshot"),
        })?;
        let entries: Vec<&Value> = snapshot["backends"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|e| e["backend"] == backend.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let native = |e: &Value| e["native"]["data"].as_str().map(str::to_string);
        let mut units = Vec::new();
        match backend {
            FirewallBackend::Iptables => {
                let wanted: &[&'static str] = match opts.family {
                    IpFamily::Ipv4 => &["ipv4"],
                    IpFamily::Ipv6 => &["ipv6"],
                    IpFamily::Any => &["ipv4", "ipv6"],
                };
                for family in wanted {
                    // Snapshots made before both families were saved hold
                    // iptables-save (IPv4) data under family "any".
                    let found = entries.iter().find_map(|e| {
                        let f = e["family"].as_str().unwrap_or("");
                        let ipv4_any = f == "any" && e["native"]["format"] == "iptables-save";
                        (f == *family || (*family == "ipv4" && ipv4_any))
                            .then(|| native(e))
                            .flatten()
                    });
                    if let Some(data) = found {
                        units.push(ApplyUnit {
                            family: Some(family),
                            source: RulesSource::Data(data),
                        });
                    }
                }
            }
            _ => {
                if opts.family != IpFamily::Any {
                    return Err(FirewallError::UnsupportedOption {
                        option: "family".to_string(),
                        backend: backend.as_str().to_string(),
                        message: "an nft ruleset sets its own families; leave family=any"
                            .to_string(),
                    }
                    .into());
                }
                if let Some(data) = entries.iter().find_map(|e| native(e)) {
                    // A snapshot is the whole ruleset: replace, not add to,
                    // the live one.
                    units.push(ApplyUnit {
                        family: None,
                        source: RulesSource::Data(format!("flush ruleset\n{data}")),
                    });
                }
            }
        }
        if units.is_empty() {
            return Err(FirewallError::SnapshotNativeMissing {
                backend: backend.as_str().to_string(),
                family: match (backend, &opts.family) {
                    (FirewallBackend::Iptables, f) => format!(" ({})", f.as_str()),
                    _ => String::new(),
                },
            }
            .into());
        }
        Ok((units, format))
    }

    /// Runs the restore (or, with `check`, the check) tool on each unit.
    /// Snapshot data goes through an owner-only file in the backup
    /// directory that is removed afterwards.
    async fn run_units(
        &self,
        units: &[ApplyUnit],
        check: bool,
        timeout_ms: u64,
        actions: &mut Vec<String>,
    ) -> Result<()> {
        for unit in units {
            let (tool, flags) = unit.tool(check);
            let (file, temporary) = match &unit.source {
                RulesSource::File(path) => (path.clone(), false),
                RulesSource::Data(data) => (
                    write_rules_backup(
                        &firewall_backup_dir(),
                        &backup_file_name(
                            &format!("apply-{}", unit.family.unwrap_or("nftables")),
                            None,
                            "rules",
                        ),
                        data.as_bytes(),
                    )?,
                    true,
                ),
            };
            let mut args: Vec<&str> = flags.clone();
            args.push(&file);
            actions.push(unit.describe(check));
            let outcome = run_command_with_timeout(tool, &args, timeout_ms).await;
            if temporary {
                let _ = fs::remove_file(&file);
            }
            let (code, _, stderr) = outcome?;
            if code != 0 {
                return Err(FirewallError::CommandFailed {
                    command: unit.describe(check),
                    code,
                    stderr: stderr.trim().to_string(),
                }
                .into());
            }
        }
        Ok(())
    }

    /// Writes a backup of every family `units` (or a flush) will replace.
    async fn backup_before(
        &self,
        backend: &FirewallBackend,
        families: &[&str],
        timeout_ms: u64,
        actions: &mut Vec<String>,
    ) -> Result<Option<String>> {
        let mut first = None;
        let mut written = Vec::new();
        if *backend == FirewallBackend::Nftables {
            written.push(self.create_nftables_backup(timeout_ms).await?);
        } else {
            for family in families {
                written.push(self.create_iptables_backup(family, timeout_ms).await?);
            }
        }
        for path in written {
            actions.push(format!("backup -> {path}"));
            first.get_or_insert(path);
        }
        Ok(first)
    }

    /// Captures the live iptables rules for `family` and writes them to a
    /// new file in the backup directory. Returns the path only once the
    /// backup is on disk.
    pub(super) async fn create_iptables_backup(
        &self,
        family: &str,
        timeout_ms: u64,
    ) -> Result<String> {
        let save_cmd = if family == "ipv6" {
            "ip6tables-save"
        } else {
            "iptables-save"
        };
        let rules = self
            .checked(save_cmd, &[], timeout_ms)
            .await
            .map_err(backup_failure)?;
        write_rules_backup(
            &firewall_backup_dir(),
            &backup_file_name("iptables", Some(family), "rules"),
            rules.as_bytes(),
        )
    }

    /// Captures the live nftables ruleset into a new backup file. The file
    /// starts with `flush ruleset`, so applying it replaces the ruleset.
    pub(super) async fn create_nftables_backup(&self, timeout_ms: u64) -> Result<String> {
        let rules = self
            .checked("nft", &["list", "ruleset"], timeout_ms)
            .await
            .map_err(backup_failure)?;
        write_rules_backup(
            &firewall_backup_dir(),
            &backup_file_name("nftables", None, "rules"),
            format!("flush ruleset\n{rules}").as_bytes(),
        )
    }

    /// The families an iptables flush (disable without path) covers.
    fn flush_families(&self, family: &IpFamily) -> Vec<&'static str> {
        let mut out = Vec::new();
        if *family != IpFamily::Ipv6 && is_command_available("iptables") {
            out.push("ipv4");
        }
        if *family != IpFamily::Ipv4 && is_command_available("ip6tables") {
            out.push("ipv6");
        }
        out
    }

    /// Runs plain commands in order, stopping at the first failure.
    async fn run_steps(
        &self,
        steps: &[Vec<String>],
        timeout_ms: u64,
        actions: &mut Vec<String>,
    ) -> Result<()> {
        for argv in steps {
            let line = display_command(argv);
            actions.push(line.clone());
            let (code, _, stderr) = run_argv(argv, timeout_ms).await?;
            if code != 0 {
                return Err(FirewallError::CommandFailed {
                    command: line,
                    code,
                    stderr: stderr.trim().to_string(),
                }
                .into());
            }
        }
        Ok(())
    }

    // =======================================================================
    // rules.reload
    // =======================================================================

    pub(super) fn handle_rules_reload(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let mut response = RulesReloadResponse::new();
        response.format_output = format_of(args);
        let outcome = block_on(self.rules_reload_async(args, &mut response));
        if let Err(e) = outcome {
            response.ok = false;
            response.error = Some(as_firewall_error(&e).error_object());
        }
        finish(io, &response)
    }

    async fn rules_reload_async(
        &self,
        args: &Args,
        response: &mut RulesReloadResponse,
    ) -> Result<()> {
        let opts = self.parse_apply_options("rules.reload", args)?;
        response.query = self.apply_query("rules.reload", &opts);
        response.family = opts.family.as_str().to_string();
        let backend = self.resolve_backend(&opts.backend, opts.timeout_ms).await?;
        response.backend = backend.as_str().to_string();
        self.check_apply_options("rules.reload", &backend, &opts)?;
        let service = matches!(backend, FirewallBackend::Ufw | FirewallBackend::Firewalld);
        if service && opts.backup_before_apply {
            response.warnings.push(format!(
                "backup_before_apply is not supported for {}; no backup was taken",
                backend.as_str()
            ));
        }

        if service {
            response.mode = "backend_reload".to_string();
            let argv: Vec<String> = match (&backend, opts.validate_only) {
                (FirewallBackend::Ufw, _) => vec!["ufw".into(), "reload".into()],
                (_, true) => vec!["firewall-cmd".into(), "--check-config".into()],
                (_, false) => vec!["firewall-cmd".into(), "--reload".into()],
            };
            if opts.dry_run {
                response.actions.push(display_command(&argv));
                response
                    .warnings
                    .push(format!("Dry run: {} not executed.", display_command(&argv)));
            } else {
                self.run_steps(&[argv], opts.timeout_ms, &mut response.actions)
                    .await?;
            }
            response.result = Some(RulesReloadResult {
                changed: !opts.dry_run && !opts.validate_only,
                backup_path: None,
            });
            response.ok = true;
            return Ok(());
        }

        response.mode = "file_reload".to_string();
        let (units, format) = self.plan_units(&backend, &opts)?;
        response.source = RulesReloadSource {
            path: opts.path.clone(),
            source_format: Some(format.as_str().to_string()),
        };
        let changed = self
            .apply_units(
                &backend,
                &units,
                &opts,
                &mut response.actions,
                &mut response.warnings,
            )
            .await
            .map_err(|(e, _)| e)?;
        response.result = Some(RulesReloadResult {
            changed: changed.is_some(),
            backup_path: changed.flatten(),
        });
        response.ok = true;
        Ok(())
    }

    /// Validates, plans (dry run) or applies `units`, with the requested
    /// backup first. Returns `None` when nothing was changed, otherwise the
    /// backup path (if any). On failure after the backup, the error carries
    /// the backup path so it can be reported.
    async fn apply_units(
        &self,
        backend: &FirewallBackend,
        units: &[ApplyUnit],
        opts: &ApplyOptions,
        actions: &mut Vec<String>,
        warnings: &mut Vec<String>,
    ) -> std::result::Result<Option<Option<String>>, (anyhow::Error, Option<String>)> {
        if opts.validate_only {
            self.run_units(units, true, opts.timeout_ms, actions)
                .await
                .map_err(|e| (e, None))?;
            warnings.push("Validate-only: the rules were checked, not applied.".to_string());
            return Ok(None);
        }
        let families: Vec<&str> = units.iter().filter_map(|u| u.family).collect();
        if opts.dry_run {
            if opts.backup_before_apply {
                actions.push(format!(
                    "backup -> new file in {}/ (not written in dry run)",
                    FIREWALL_BACKUP_DIR
                ));
            }
            actions.extend(units.iter().map(|u| u.describe(false)));
            warnings.push("Dry run: no firewall changes applied.".to_string());
            return Ok(None);
        }
        let backup = if opts.backup_before_apply {
            self.backup_before(backend, &families, opts.timeout_ms, actions)
                .await
                .map_err(|e| (e, None))?
        } else {
            None
        };
        self.run_units(units, false, opts.timeout_ms, actions)
            .await
            .map_err(|e| (e, backup.clone()))?;
        Ok(Some(backup))
    }

    // =======================================================================
    // enable / disable
    // =======================================================================

    pub(super) fn handle_enable(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let mut response = EnableResponse::new("auto", format_of(args));
        let mut result = EnableResult {
            changed: false,
            already_enabled: false,
            backup_path: None,
        };
        let outcome = block_on(self.switch_async(
            "enable",
            args,
            &mut response.query,
            &mut response.backend,
            &mut response.previous_state,
            &mut response.current_state,
            &mut response.actions,
            &mut response.warnings,
            &mut result.changed,
            &mut result.already_enabled,
            &mut result.backup_path,
        ));
        response.result = Some(result);
        match outcome {
            Ok(()) => response.ok = true,
            Err(e) => response.error = Some(as_firewall_error(&e).error_object()),
        }
        finish(io, &response)
    }

    pub(super) fn handle_disable(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let mut response = DisableResponse::new("auto", format_of(args));
        let mut result = DisableResult {
            changed: false,
            already_disabled: false,
            backup_path: None,
        };
        let outcome = block_on(self.switch_async(
            "disable",
            args,
            &mut response.query,
            &mut response.backend,
            &mut response.previous_state,
            &mut response.current_state,
            &mut response.actions,
            &mut response.warnings,
            &mut result.changed,
            &mut result.already_disabled,
            &mut result.backup_path,
        ));
        response.result = Some(result);
        match outcome {
            Ok(()) => response.ok = true,
            Err(e) => response.error = Some(as_firewall_error(&e).error_object()),
        }
        finish(io, &response)
    }

    /// `enable` and `disable`, filling the response fields as it goes so a
    /// failure still reports what was done.
    #[allow(clippy::too_many_arguments)]
    async fn switch_async(
        &self,
        verb: &str,
        args: &Args,
        query: &mut Value,
        backend_name: &mut String,
        previous_state: &mut Option<FirewallStateSnapshot>,
        current_state: &mut Option<FirewallStateSnapshot>,
        actions: &mut Vec<String>,
        warnings: &mut Vec<String>,
        changed: &mut bool,
        already: &mut bool,
        backup_path: &mut Option<String>,
    ) -> Result<()> {
        let enable = verb == "enable";
        let opts = self.parse_apply_options(verb, args)?;
        *query = self.apply_query(verb, &opts);
        let backend = self.resolve_backend(&opts.backend, opts.timeout_ms).await?;
        *backend_name = backend.as_str().to_string();
        self.check_apply_options(verb, &backend, &opts)?;

        let before = self.current_state(&backend, opts.timeout_ms).await?;
        *previous_state = Some(before.clone());
        *current_state = Some(before.clone());
        let is_on = before.active || before.enabled;
        let already_there = if enable { is_on } else { !is_on };
        if already_there {
            if opts.fail_if_already {
                let backend = backend.as_str().to_string();
                return Err(if enable {
                    FirewallError::AlreadyEnabled { backend }
                } else {
                    FirewallError::AlreadyDisabled { backend }
                }
                .into());
            }
            if opts.path.is_none() {
                *already = true;
                warnings.push(format!(
                    "Firewall backend '{}' was already {}; no changes applied.",
                    backend.as_str(),
                    if enable { "enabled" } else { "disabled" }
                ));
                return Ok(());
            }
        }

        let service = matches!(backend, FirewallBackend::Ufw | FirewallBackend::Firewalld);
        if service {
            if opts.backup_before_apply {
                warnings.push(format!(
                    "backup_before_apply is not supported for {}; no backup was taken",
                    backend.as_str()
                ));
            }
            let steps: Vec<Vec<String>> = match (&backend, enable) {
                (FirewallBackend::Ufw, true) => {
                    vec![vec!["ufw".into(), "--force".into(), "enable".into()]]
                }
                (FirewallBackend::Ufw, false) => {
                    vec![vec!["ufw".into(), "--force".into(), "disable".into()]]
                }
                (_, true) => vec![
                    vec!["systemctl".into(), "enable".into(), "firewalld".into()],
                    vec!["systemctl".into(), "start".into(), "firewalld".into()],
                ],
                (_, false) => vec![vec!["systemctl".into(), "stop".into(), "firewalld".into()]],
            };
            if opts.dry_run {
                actions.extend(steps.iter().map(|s| display_command(s)));
                warnings.push("Dry run: no firewall changes applied.".to_string());
                return Ok(());
            }
            self.run_steps(&steps, opts.timeout_ms, actions).await?;
            *changed = true;
            *current_state = Some(self.current_state(&backend, opts.timeout_ms).await?);
            return Ok(());
        }

        // iptables / nftables
        if opts.path.is_some() {
            let (units, _) = self.plan_units(&backend, &opts)?;
            match self
                .apply_units(&backend, &units, &opts, actions, warnings)
                .await
            {
                Ok(None) => return Ok(()),
                Ok(Some(backup)) => {
                    *changed = true;
                    *backup_path = backup;
                }
                Err((e, backup)) => {
                    *backup_path = backup;
                    return Err(e);
                }
            }
        } else if enable {
            return Err(FirewallError::PathRequired {
                message: format!(
                    "no {} rules are active, so enable needs path=<rules file> to load",
                    backend.as_str()
                ),
            }
            .into());
        } else {
            // disable without a file: remove all filtering.
            let (families, steps): (Vec<&str>, Vec<Vec<String>>) =
                if backend == FirewallBackend::Nftables {
                    (
                        vec![],
                        vec![vec!["nft".into(), "flush".into(), "ruleset".into()]],
                    )
                } else {
                    let families = self.flush_families(&opts.family);
                    let mut steps = Vec::new();
                    for family in &families {
                        let tool = if *family == "ipv6" {
                            "ip6tables"
                        } else {
                            "iptables"
                        };
                        for args in [
                            &["-P", "INPUT", "ACCEPT"][..],
                            &["-P", "OUTPUT", "ACCEPT"],
                            &["-P", "FORWARD", "ACCEPT"],
                            &["-F"],
                            &["-t", "nat", "-F"],
                            &["-t", "mangle", "-F"],
                        ] {
                            let mut argv = vec![tool.to_string()];
                            argv.extend(args.iter().map(|a| a.to_string()));
                            steps.push(argv);
                        }
                    }
                    (families, steps)
                };
            if opts.dry_run {
                if opts.backup_before_apply {
                    actions.push(format!(
                        "backup -> new file in {}/ (not written in dry run)",
                        FIREWALL_BACKUP_DIR
                    ));
                }
                actions.extend(steps.iter().map(|s| display_command(s)));
                warnings.push("Dry run: no firewall changes applied.".to_string());
                return Ok(());
            }
            if opts.validate_only {
                return Ok(());
            }
            if opts.backup_before_apply {
                *backup_path = self
                    .backup_before(&backend, &families, opts.timeout_ms, actions)
                    .await?;
            }
            self.run_steps(&steps, opts.timeout_ms, actions).await?;
            *changed = true;
        }
        *current_state = Some(self.current_state(&backend, opts.timeout_ms).await?);
        Ok(())
    }
}

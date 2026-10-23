use anyhow::{Result, anyhow};
use regex::Regex;
use std::collections::HashMap;

use super::registry::Args;

#[derive(Debug)]
pub struct ParsedStage {
    pub target: String,
    pub verb: String,
    pub args: Args,
}

/// True for an in-URL help request: `--help`, `-h`, or `--help=<verb>`,
/// either alone or as the last segment of a target (`sqlite/x.--help=query`,
/// `sqlite/--help`). Whole segments only, so targets like `my-hosts` or
/// `plugin://my-helper` are not help requests.
fn is_help_request(s: &str) -> bool {
    let head = s.split('=').next().unwrap_or(s);
    let last = head.rsplit(['/', '.']).next().unwrap_or(head);
    super::help::is_help_flag(head) || super::help::is_help_flag(last)
}

/// A bare `dry_run` word (no `=value`), which means `dry_run=true`.
pub fn is_bare_dry_run(word: &str) -> bool {
    word.trim() == "dry_run"
}

pub fn parse_stage(s: &str) -> Result<ParsedStage> {
    // First, check if we have parentheses for args
    let (main_part, args_str) = if let Some(open_paren) = s.rfind('(') {
        let close_paren = s.rfind(')');
        if let Some(close_pos) = close_paren {
            if close_pos > open_paren {
                let main = &s[..open_paren].trim();
                let args = &s[open_paren+1..close_pos].trim();
                (main.to_string(), Some(args.to_string()))
            } else {
                (s.to_string(), None)
            }
        } else {
            (s.to_string(), None)
        }
    } else {
        (s.to_string(), None)
    };

    if !main_part.starts_with("plugin://") {
        if let Some(stage) = help_stage(&main_part, args_str.as_deref())? {
            return Ok(stage);
        }
    }

    // Parse known verbs with dots first (this should include plugin operations)
    let known_dotted_verbs = ["ea.get", "ea.set", "tag.add", "tag.rm", "nice.get", "nice.set", "nice.inc", "nice.dec", "io.peek", "limits.set", "route.list", "csr.create", "chain.info", "config.get", "keys.list", "key.add", "list-topics", "zone.fetch", "zone.update", "test", "install", "update", "remove", "available.list", "available.search", "available.info", "installed.list", "env.list", "send", "send_template", "config"];
    
    // Dotted verbs recognized only for one scheme, so that other handles'
    // targets ending in e.g. ".rules" keep splitting at the last dot.
    let scheme_dotted_verbs: &[&str] = if main_part.starts_with("event://") {
        &["hooks.list", "hooks.enable", "hooks.disable"]
    } else if main_part.starts_with("firewall://") {
        &["rules.list", "rules.add", "rules.delete", "rules.save", "rules.reload"]
    } else if main_part.starts_with("plugin://") {
        // plugin://<id>.enable; without this the plugin branch below would
        // take the whole host "<id>.enable" as the verb.
        &["enable", "disable"]
    } else {
        &[]
    };

    for &dotted_verb in known_dotted_verbs.iter().chain(scheme_dotted_verbs) {
        if main_part.ends_with(&format!(".{}", dotted_verb)) {
            let target_end = main_part.len() - dotted_verb.len() - 1;
            let target = &main_part[..target_end];
            
            // Validate that target looks like a URL
            let url_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")?;
            if url_regex.is_match(target) {
                let mut args: Args = HashMap::new();

                if let Some(args_content) = args_str {
                    if !args_content.is_empty() {
                        for kv in parse_arguments(&args_content) {
                            let kv = kv.trim();
                            if kv.is_empty() {
                                continue;
                            }
                            if let Some((k, v)) = kv.split_once('=') {
                                args.insert(
                                    k.trim().to_string(),
                                    v.trim().trim_matches('\"').to_string(),
                                );
                            } else if is_bare_dry_run(kv) {
                                args.insert("dry_run".to_string(), "true".to_string());
                            }
                        }
                    }
                }
                
                return Ok(ParsedStage { 
                    target: target.to_string(), 
                    verb: dotted_verb.to_string(), 
                    args 
                });
            }
        }
    }

    // Handle plugin:// URLs specially since they encode the verb in the host part
    let url_regex = Regex::new(r"^plugin://([^/]+)(?:/.*)?$")?;
    if let Some(captures) = url_regex.captures(&main_part) {
        let host_part = &captures[1];
        
        // Check for help patterns in plugin URLs first  
        if is_help_request(host_part) {
            let mut args: Args = HashMap::new();
            
            // Check for specific verb help request (e.g., plugin://--help=install)
            if let Some(eq_pos) = host_part.find('=') {
                let verb_name = &host_part[eq_pos + 1..];
                args.insert("verb".to_string(), verb_name.to_string());
            }
            
            // Add any arguments from parentheses
            if let Some(args_content) = args_str {
                if !args_content.is_empty() {
                    for kv in parse_arguments(&args_content) {
                        let kv = kv.trim();
                        if kv.is_empty() {
                            continue;
                        }
                        if let Some((k, v)) = kv.split_once('=') {
                            args.insert(
                                k.trim().to_string(),
                                v.trim().trim_matches('"').to_string(),
                            );
                        }
                    }
                }
            }
            
            // Use the appropriate help verb
            let help_verb = if host_part.ends_with("-h") {
                "-h".to_string()
            } else {
                "--help".to_string()
            };
            
            return Ok(ParsedStage { 
                target: main_part.clone(), 
                verb: help_verb,
                args 
            });
        }
        
        // For plugin URLs, the host is the verb and the entire URL is the target
        let mut args: Args = HashMap::new();

        if let Some(args_content) = args_str {
            if !args_content.is_empty() {
                for kv in parse_arguments(&args_content) {
                    let kv = kv.trim();
                    if kv.is_empty() {
                        continue;
                    }
                    if let Some((k, v)) = kv.split_once('=') {
                        args.insert(
                            k.trim().to_string(),
                            v.trim().trim_matches('"').to_string(),
                        );
                    } else if is_bare_dry_run(kv) {
                        args.insert("dry_run".to_string(), "true".to_string());
                    }
                }
            }
        }
        
        return Ok(ParsedStage { 
            target: main_part.clone(), 
            verb: host_part.to_string(), 
            args 
        });
    }

    // Handle mail:// URLs specially since they encode the verb in the path part
    // Support both function-call syntax: mail://send(args...)
    // and query parameter syntax: mail://send?arg1=val1&arg2=val2
    let mail_regex = Regex::new(r"^mail://([a-zA-Z_][a-zA-Z0-9_-]*)(?:/.*)?(?:\?.*)?$")?;
    if let Some(captures) = mail_regex.captures(&main_part) {
        let verb_part = &captures[1];
        // For mail URLs, the verb is in the path and the target is just "mail://"
        let mut args: Args = HashMap::new();

        // Check if we have query parameters instead of function-call syntax
        if let Some(query_start) = main_part.find('?') {
            // Parse query parameter syntax: mail://send?to=test@test.com&subject=test
            let query_part = &main_part[query_start + 1..];
            for param in query_part.split('&') {
                if let Some((key, value)) = param.split_once('=') {
                    let key = urlencoding::decode(key).map_err(|e| anyhow!("Failed to decode key: {}", e))?.to_string();
                    let value = urlencoding::decode(value).map_err(|e| anyhow!("Failed to decode value: {}", e))?.to_string();
                    
                    // Handle special cases for arrays (e.g., to=email1,email2)
                    if key == "to" || key == "cc" || key == "bcc" {
                        // Split comma-separated values into JSON array format
                        if value.contains(',') {
                            let emails: Vec<&str> = value.split(',').collect();
                            args.insert(key, serde_json::to_string(&emails).unwrap_or_else(|_| value));
                        } else {
                            // Single email, wrap in array format
                            args.insert(key, serde_json::to_string(&[&value]).unwrap_or_else(|_| value));
                        }
                    } else {
                        args.insert(key, value);
                    }
                }
            }
        } else if let Some(args_content) = args_str {
            // Parse traditional function-call syntax: mail://send(args...)
            if !args_content.is_empty() {
                for kv in parse_arguments(&args_content) {
                    let kv = kv.trim();
                    if kv.is_empty() {
                        continue;
                    }
                    if let Some((k, v)) = kv.split_once('=') {
                        let key = k.trim().to_string();
                        let mut value = v.trim();
                        
                        // Don't strip quotes from JSON arrays or objects for mail args
                        if value.starts_with('[') && value.ends_with(']') {
                            // Keep JSON array format intact
                            args.insert(key, value.to_string());
                        } else if value.starts_with('{') && value.ends_with('}') {
                            // Keep JSON object format intact
                            args.insert(key, value.to_string());
                        } else {
                            // Strip quotes from simple string values
                            args.insert(key, value.trim_matches('"').to_string());
                        }
                    } else if is_bare_dry_run(kv) {
                        args.insert("dry_run".to_string(), "true".to_string());
                    }
                }
            }
        }
        
        return Ok(ParsedStage { 
            target: "mail://".to_string(), 
            verb: verb_part.to_string(), 
            args 
        });
    }

    // Fall back to the original logic for simple verbs
    if let Some(last_dot) = main_part.rfind('.') {
        // Check if what comes after the dot looks like a verb (not a file extension)
        let potential_verb = &main_part[last_dot + 1..];
        let verb_regex = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_-]*$")?;
        
        if verb_regex.is_match(potential_verb) && potential_verb.len() > 1 {
            let target = &main_part[..last_dot];
            
            // Validate that target looks like a URL
            let url_regex = Regex::new(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")?;
            if url_regex.is_match(target) {
                let verb = potential_verb.to_string();
                let mut args: Args = HashMap::new();

                if let Some(args_content) = args_str {
                    if !args_content.is_empty() {
                        for kv in parse_arguments(&args_content) {
                            let kv = kv.trim();
                            if kv.is_empty() {
                                continue;
                            }
                            if let Some((k, v)) = kv.split_once('=') {
                                args.insert(
                                    k.trim().to_string(),
                                    v.trim().trim_matches('"').to_string(),
                                );
                            } else if is_bare_dry_run(kv) {
                                args.insert("dry_run".to_string(), "true".to_string());
                            }
                        }
                    }
                }
                
                return Ok(ParsedStage { 
                    target: target.to_string(), 
                    verb, 
                    args 
                });
            }
        }
    }
    
    if let Some(stage) = help_stage(&main_part, args_str.as_deref())? {
        return Ok(stage);
    }

    Err(anyhow!("Cannot parse stage: {}", s))
}

/// In-URL help request such as `file://--help` or `firewall://--help=rules.delete`.
/// Checked before verb splitting so a dotted verb name after `--help=` stays
/// intact. (plugin:// has its own help handling in `parse_stage`.)
fn help_stage(main_part: &str, args_str: Option<&str>) -> Result<Option<ParsedStage>> {
    // Check for help flags in URLs (e.g., file://--help, file://-h)
    let url_regex = Regex::new(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)(.*)$")?;
    if let Some(captures) = url_regex.captures(main_part) {
        let scheme_part = &captures[1];
        let path_part = &captures[2];
        
        // Check if path contains --help or -h
        if is_help_request(path_part) {
            let mut args: Args = HashMap::new();
            
            // Check for specific verb help request (e.g., file://--help=read)
            if let Some(eq_pos) = path_part.find('=') {
                let verb_name = &path_part[eq_pos + 1..];
                args.insert("verb".to_string(), verb_name.to_string());
            }
            
            // Add any arguments from parentheses
            if let Some(args_content) = args_str {
                if !args_content.is_empty() {
                    for kv in parse_arguments(&args_content) {
                        let kv = kv.trim();
                        if kv.is_empty() {
                            continue;
                        }
                        if let Some((k, v)) = kv.split_once('=') {
                            args.insert(
                                k.trim().to_string(),
                                v.trim().trim_matches('"').to_string(),
                            );
                        }
                    }
                }
            }
            
            return Ok(Some(ParsedStage {
                target: format!("{}--help", scheme_part),
                verb: "help".to_string(),
                args,
            }));
        }
    }
    Ok(None)
}

/// Parse argument string, handling quoted values that may contain commas
fn parse_arguments(args_str: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;
    let mut in_brackets = false;
    let mut chars = args_str.chars().peekable();
    
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current_arg.push(ch);
            }
            '[' if !in_quotes => {
                in_brackets = true;
                current_arg.push(ch);
            }
            ']' if !in_quotes => {
                in_brackets = false;
                current_arg.push(ch);
            }
            ',' if !in_quotes && !in_brackets => {
                if !current_arg.trim().is_empty() {
                    result.push(current_arg.trim().to_string());
                }
                current_arg.clear();
            }
            _ => {
                current_arg.push(ch);
            }
        }
    }
    
    // Add the last argument if it's not empty
    if !current_arg.trim().is_empty() {
        result.push(current_arg.trim().to_string());
    }
    
    result
}

#[cfg(test)]
mod scheme_dotted_verb_tests {
    use super::parse_stage;

    #[test]
    fn event_and_firewall_dotted_verbs() {
        for (stage, target, verb) in [
            ("event://.hooks.list", "event://", "hooks.list"),
            ("event://.hooks.enable", "event://", "hooks.enable"),
            ("firewall://.rules.list", "firewall://", "rules.list"),
            ("firewall://.rules.reload", "firewall://", "rules.reload"),
        ] {
            let p = parse_stage(stage).unwrap();
            assert_eq!((p.target.as_str(), p.verb.as_str()), (target, verb), "{stage}");
        }
    }

    #[test]
    fn scheme_dotted_verbs_do_not_apply_to_other_schemes() {
        let p = parse_stage("file:///etc/iptables.rules.delete").unwrap();
        assert_eq!((p.target.as_str(), p.verb.as_str()), ("file:///etc/iptables.rules", "delete"));
        let p = parse_stage("file:///srv/git.hooks.list").unwrap();
        assert_eq!(p.verb, "list");
        let p = parse_stage("cert://req.csr.sign").unwrap();
        assert_eq!((p.target.as_str(), p.verb.as_str()), ("cert://req.csr", "sign"));
        let p = parse_stage("file:///srv/feature.enable").unwrap();
        assert_eq!((p.target.as_str(), p.verb.as_str()), ("file:///srv/feature", "enable"));
    }

    #[test]
    fn help_requests_are_exact() {
        assert_eq!(parse_stage("plugin://--help").unwrap().verb, "--help");
        assert_eq!(parse_stage("plugin://-h").unwrap().verb, "-h");
        let p = parse_stage("plugin://--help=install").unwrap();
        assert_eq!((p.verb.as_str(), p.args.get("verb").map(String::as_str)), ("--help", Some("install")));
        let p = parse_stage("plugin://my-helper.install").unwrap();
        assert_eq!((p.target.as_str(), p.verb.as_str()), ("plugin://my-helper", "install"));
    }

    #[test]
    fn help_with_dotted_verb_name() {
        let p = parse_stage("firewall://--help=rules.delete").unwrap();
        assert_eq!(p.verb, "help");
        assert_eq!(p.args.get("verb").map(String::as_str), Some("rules.delete"));
        let p = parse_stage("file://--help").unwrap();
        assert_eq!((p.target.as_str(), p.verb.as_str()), ("file://--help", "help"));
        for stage in ["db://sqlite/x.--help=query", "db://sqlite/--help", "cache://redis/main.-h"] {
            assert_eq!(parse_stage(stage).unwrap().verb, "help", "{stage}");
        }
        assert_eq!(
            parse_stage("db://sqlite/x.--help=query").unwrap().args.get("verb").map(String::as_str),
            Some("query")
        );
        // Not a help request: an ordinary target and verb.
        let p = parse_stage("svc://my-httpd.status").unwrap();
        assert_eq!((p.target.as_str(), p.verb.as_str()), ("svc://my-httpd", "status"));
        let p = parse_stage("file:///etc/my-hosts.read").unwrap();
        assert_eq!((p.target.as_str(), p.verb.as_str()), ("file:///etc/my-hosts", "read"));
    }

    #[test]
    fn bare_dry_run_in_parentheses_means_true() {
        for stage in [
            "user://bob.delete(dry_run)",
            "user://bob.delete(force=false, dry_run)",
            "firewall://.rules.add(dry_run, dport=22)",
            "plugin://aws.install(dry_run)",
            "mail://send(to=a@b.c, dry_run)",
        ] {
            let p = parse_stage(stage).unwrap();
            assert_eq!(p.args.get("dry_run").map(String::as_str), Some("true"), "{stage}");
        }
        // Other bare words are still not arguments.
        assert!(parse_stage("user://bob.delete(dry_runx)").unwrap().args.is_empty());
    }

    #[test]
    fn plugin_enable_disable_take_plugin_id() {
        for verb in ["enable", "disable"] {
            let p = parse_stage(&format!("plugin://aws.{verb}")).unwrap();
            assert_eq!((p.target.as_str(), p.verb.as_str()), ("plugin://aws", verb));
        }
        let p = parse_stage("plugin://aws.install").unwrap();
        assert_eq!((p.target.as_str(), p.verb.as_str()), ("plugin://aws", "install"));
    }
}

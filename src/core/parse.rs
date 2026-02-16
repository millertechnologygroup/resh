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

    // Parse known verbs with dots first (this should include plugin operations)
    let known_dotted_verbs = ["ea.get", "ea.set", "tag.add", "tag.rm", "nice.get", "nice.set", "nice.inc", "nice.dec", "io.peek", "limits.set", "route.list", "csr.create", "chain.info", "config.get", "keys.list", "key.add", "list-topics", "zone.fetch", "zone.update", "test", "install", "update", "remove", "available.list", "available.search", "available.info", "installed.list", "env.list", "send", "send_template", "config"];
    
    for &dotted_verb in &known_dotted_verbs {
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
        if host_part.contains("--help") || host_part.contains("-h") {
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
    
    // Check for help flags in URLs (e.g., file://--help, file://-h)
    let url_regex = Regex::new(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)(.*)$")?;
    if let Some(captures) = url_regex.captures(&main_part) {
        let scheme_part = &captures[1];
        let path_part = &captures[2];
        
        // Check if path contains --help or -h
        if path_part.contains("--help") || path_part.contains("-h") {
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
            
            return Ok(ParsedStage { 
                target: format!("{}--help", scheme_part),
                verb: "help".to_string(), 
                args 
            });
        }
    }
    
    Err(anyhow!("Cannot parse stage: {}", s))
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

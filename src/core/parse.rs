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

    // Parse known verbs with dots first
    let known_dotted_verbs = ["ea.get", "ea.set", "tag.add", "tag.rm", "nice.get", "nice.set", "nice.inc", "nice.dec", "io.peek", "limits.set", "route.list", "csr.create", "chain.info", "config.get", "keys.list", "key.add", "list-topics", "zone.fetch", "zone.update"];
    
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
    
    Err(anyhow!("Cannot parse stage: {}", s))
}

/// Parse argument string, handling quoted values that may contain commas
fn parse_arguments(args_str: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;
    let mut chars = args_str.chars().peekable();
    
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current_arg.push(ch);
            }
            ',' if !in_quotes => {
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

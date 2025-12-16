use anyhow::{Context, Result, bail};
use tera::{Tera, Context as TeraContext};
use percent_encoding::percent_decode_str;
use serde_json::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, PathBuf};
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

/// JSON schema for validation results
#[derive(Debug, Serialize, Deserialize)]
struct ValidationError {
    kind: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TemplateInfo {
    source: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidationResult {
    ok: bool,
    template: TemplateInfo,
    strict: bool,
    errors: Vec<ValidationError>,
    warnings: Vec<ValidationError>,
}

/// JSON schema for render results
#[derive(Debug, Serialize, Deserialize)]
struct ContextInfo {
    keys: Vec<String>,
    raw: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct BodyInfo {
    #[serde(rename = "type")]
    body_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base64: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RenderResult {
    ok: bool,
    engine: String,
    template: TemplateInfo,
    context: ContextInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<BodyInfo>,
    errors: Vec<ValidationError>,
}

/// JSON schema for test cases and results
#[derive(Debug, Serialize, Deserialize)]
struct TemplateTestCase {
    name: String,
    context: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_contains: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestCaseResult {
    name: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_contains: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendered: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TestResult {
    template: String,
    ok: bool,
    total: usize,
    passed: usize,
    failed: usize,
    stop_on_first_fail: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    cases: Vec<TestCaseResult>,
}

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("template", |u| Ok(Box::new(TemplateHandle::from_url(u.clone())?)));
}

pub struct TemplateHandle {
    template_path: Option<PathBuf>,
}

fn unescape_backslashes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.peek() {
                Some(' ') => {
                    it.next();
                    out.push(' ');
                }
                Some('\\') => {
                    it.next();
                    out.push('\\');
                }
                Some('t') => {
                    it.next();
                    out.push('\t');
                }
                Some('n') => {
                    it.next();
                    out.push('\n');
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn normalize_path(p: &PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

impl TemplateHandle {
    pub fn from_url(url: Url) -> Result<TemplateHandle, anyhow::Error> {
        // For template URLs, we want to combine host and path to get the full template path
        // e.g., template://tests/fixtures/templates/hello.html should give us 
        // "tests/fixtures/templates/hello.html" not just "tests"
        let path_str = if url.host_str().is_some() && !url.host_str().unwrap().is_empty() {
            let host = url.host_str().unwrap();
            let path = url.path();
            if path == "/" || path.is_empty() {
                // Just the host: template://filename.html
                host.to_string()
            } else {
                // Host + path: template://dir/subdir/filename.html
                format!("{}{}", host, path)
            }
        } else {
            // No host, just path: template:///path/to/file.html
            let path = url.path();
            if path.starts_with('/') {
                path[1..].to_string() // Remove leading slash
            } else {
                path.to_string()
            }
        };

        // Check for special inline case
        if path_str.is_empty() || path_str == "/" || path_str == "/inline" || path_str == "inline" {
            return Ok(TemplateHandle {
                template_path: None,
            });
        }

        // Decode URL encoding and escape sequences
        let decoded = percent_decode_str(&path_str).decode_utf8_lossy().to_string();
        let unescaped = unescape_backslashes(&decoded);
        let path = PathBuf::from(unescaped);
        let normalized = normalize_path(&path);

        Ok(TemplateHandle {
            template_path: Some(normalized),
        })
    }

    fn get_template_content(&self, args: &Args) -> Result<String> {
        // Check for `from` argument for inline template content
        if let Some(from_content) = args.get("from") {
            return Ok(from_content.clone());
        }

        // Check for backward compatibility with `inline` argument
        if let Some(inline_content) = args.get("inline") {
            return Ok(inline_content.clone());
        }

        // Use template file path
        if let Some(path) = &self.template_path {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read template file: {}", path.display()))?;
            Ok(content)
        } else {
            bail!("no template source provided (missing 'from' argument or file path)");
        }
    }

    fn parse_context(&self, args: &Args) -> Result<TeraContext, ValidationError> {
        let encoding = args.get("encoding").map(|s| s.as_str()).unwrap_or("utf-8");
        if encoding != "utf-8" {
            return Err(ValidationError {
                kind: "encoding".to_string(),
                message: format!("unsupported encoding: {}. Only utf-8 is supported", encoding),
                line: None,
                column: None,
            });
        }

        let mut context = TeraContext::new();

        // Parse context argument if provided
        if let Some(context_str) = args.get("context") {
            if !context_str.trim().is_empty() {
                let context_value: Value = match serde_json::from_str(context_str) {
                    Ok(value) => value,
                    Err(e) => return Err(ValidationError {
                        kind: "context_parse".to_string(),
                        message: format!("failed to parse context JSON: {}", e),
                        line: None,
                        column: None,
                    }),
                };
                
                match TeraContext::from_serialize(&context_value) {
                    Ok(tera_context) => context = tera_context,
                    Err(e) => return Err(ValidationError {
                        kind: "context_parse".to_string(),
                        message: format!("failed to convert context to Tera context: {}", e),
                        line: None,
                        column: None,
                    }),
                }
            }
        }

        Ok(context)
    }

    fn create_template_info(&self, args: &Args, template_content: Option<&str>) -> TemplateInfo {
        if args.contains_key("template") {
            // Inline template from 'template' argument
            TemplateInfo {
                source: "inline".to_string(),
                name: "inline".to_string(),
                path: None,
                size: template_content.map(|s| s.len()),
            }
        } else if args.contains_key("from") {
            // Legacy inline template from 'from' argument
            TemplateInfo {
                source: "inline".to_string(),
                name: "inline".to_string(),
                path: None,
                size: template_content.map(|s| s.len()),
            }
        } else if let Some(path) = &self.template_path {
            TemplateInfo {
                source: "file".to_string(),
                name: path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                path: Some(path.to_string_lossy().to_string()),
                size: template_content.map(|s| s.len()),
            }
        } else {
            TemplateInfo {
                source: "named".to_string(),
                name: "unknown".to_string(),
                path: None,
                size: template_content.map(|s| s.len()),
            }
        }
    }

    fn parse_render_context(&self, args: &Args) -> Result<(ContextInfo, TeraContext), ValidationError> {
        let mut context_value = Value::Object(serde_json::Map::new());
        
        // Parse context_file first (lower priority)
        if let Some(context_file_path) = args.get("context_file") {
            match std::fs::read_to_string(context_file_path) {
                Ok(content) => {
                    match serde_json::from_str::<Value>(&content) {
                        Ok(file_value) => {
                            context_value = file_value;
                        }
                        Err(e) => {
                            return Err(ValidationError {
                                kind: "context_parse".to_string(),
                                message: format!("failed to parse context_file JSON: {}", e),
                                line: None,
                                column: None,
                            });
                        }
                    }
                }
                Err(e) => {
                    return Err(ValidationError {
                        kind: "io".to_string(),
                        message: format!("failed to read context_file: {}", e),
                        line: None,
                        column: None,
                    });
                }
            }
        }

        // Parse context argument (higher priority - overrides context_file)
        if let Some(context_str) = args.get("context") {
            if !context_str.trim().is_empty() {
                match serde_json::from_str::<Value>(context_str) {
                    Ok(value) => {
                        context_value = value;
                    }
                    Err(e) => {
                        return Err(ValidationError {
                            kind: "context_parse".to_string(),
                            message: format!("failed to parse context JSON: {}", e),
                            line: None,
                            column: None,
                        });
                    }
                }
            }
        }

        // Extract keys for ContextInfo
        let keys = match &context_value {
            Value::Object(map) => map.keys().cloned().collect(),
            _ => Vec::new(),
        };

        let context_info = ContextInfo {
            keys,
            raw: context_value.clone(),
        };

        // Convert to Tera context
        let tera_context = match TeraContext::from_serialize(&context_value) {
            Ok(ctx) => ctx,
            Err(e) => {
                return Err(ValidationError {
                    kind: "context_parse".to_string(),
                    message: format!("failed to convert context to Tera context: {}", e),
                    line: None,
                    column: None,
                });
            }
        };

        Ok((context_info, tera_context))
    }

    fn get_render_template_content(&self, args: &Args) -> Result<(String, String), ValidationError> {
        // Check for 'template' argument for inline template content (highest priority)
        if let Some(template_content) = args.get("template") {
            return Ok((template_content.clone(), "inline".to_string()));
        }

        // Check for 'from' argument for backward compatibility
        if let Some(from_content) = args.get("from") {
            return Ok((from_content.clone(), "inline".to_string()));
        }

        // Use template file path
        if let Some(path) = &self.template_path {
            match std::fs::read_to_string(path) {
                Ok(content) => Ok((content, path.to_string_lossy().to_string())),
                Err(e) => Err(ValidationError {
                    kind: if e.kind() == std::io::ErrorKind::NotFound {
                        "template_not_found".to_string()
                    } else {
                        "io".to_string()
                    },
                    message: format!("failed to read template file '{}': {}", path.display(), e),
                    line: None,
                    column: None,
                }),
            }
        } else {
            Err(ValidationError {
                kind: "template_not_found".to_string(),
                message: "no template source provided (missing 'template' argument or file path)".to_string(),
                line: None,
                column: None,
            })
        }
    }

    fn format_render_output(&self, rendered: String, format: &str) -> Result<BodyInfo, ValidationError> {
        match format {
            "text" => Ok(BodyInfo {
                body_type: "text".to_string(),
                value: Some(Value::String(rendered)),
                base64: None,
            }),
            "html" => Ok(BodyInfo {
                body_type: "html".to_string(),
                value: Some(Value::String(rendered)),
                base64: None,
            }),
            "json" => {
                match serde_json::from_str::<Value>(&rendered) {
                    Ok(json_value) => Ok(BodyInfo {
                        body_type: "json".to_string(),
                        value: Some(json_value),
                        base64: None,
                    }),
                    Err(e) => Err(ValidationError {
                        kind: "json_parse".to_string(),
                        message: format!("failed to parse rendered output as JSON: {}", e),
                        line: None,
                        column: None,
                    }),
                }
            },
            "bytes" => {
                use base64::{Engine as _, engine::general_purpose};
                let base64_encoded = general_purpose::STANDARD.encode(rendered.as_bytes());
                Ok(BodyInfo {
                    body_type: "bytes".to_string(),
                    value: None,
                    base64: Some(base64_encoded),
                })
            },
            _ => Err(ValidationError {
                kind: "invalid_format".to_string(),
                message: format!("invalid format '{}'. Allowed values: text, html, json, bytes", format),
                line: None,
                column: None,
            }),
        }
    }

        // Step 3: Merge data_file if provided
    fn validate(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let strict = args.get("strict")
            .map(|s| s == "true")
            .unwrap_or(true);

        // Get template content first so we can include size in template info
        let template_content = match self.get_template_content(args) {
            Ok(content) => content,
            Err(e) => {
                let template_info = self.create_template_info(args, None);
                
                let mut result = ValidationResult {
                    ok: false,
                    template: template_info,
                    strict,
                    errors: vec![ValidationError {
                        kind: "file_read".to_string(),
                        message: format!("Failed to read template: {}", e),
                        line: None,
                        column: None,
                    }],
                    warnings: Vec::new(),
                };
                
                let json_output = serde_json::to_string(&result)?;
                writeln!(io.stdout, "{}", json_output)?;
                return Ok(Status::err(1, "Failed to read template"));
            }
        };

        let template_info = self.create_template_info(args, Some(&template_content));
        
        let mut result = ValidationResult {
            ok: true,
            template: template_info,
            strict,
            errors: Vec::new(),
            warnings: Vec::new(),
        };

        // Parse context
        let context = match self.parse_context(args) {
            Ok(ctx) => ctx,
            Err(error) => {
                result.ok = false;
                result.errors.push(error);
                
                let json_output = serde_json::to_string(&result)?;
                writeln!(io.stdout, "{}", json_output)?;
                return Ok(Status::err(1, "Context parsing failed"));
            }
        };

        // Create Tera instance and try to parse template
        let mut tera = Tera::default();
        let template_name = "validate_template";
        
        // Try to add the template to validate syntax
        if let Err(e) = tera.add_raw_template(template_name, &template_content) {
            result.ok = false;
            result.errors.push(ValidationError {
                kind: "syntax".to_string(),
                message: format!("Template syntax error: {}", e),
                line: None, // Tera errors don't always provide line numbers easily
                column: None,
            });
            
            let json_output = serde_json::to_string(&result)?;
            writeln!(io.stdout, "{}", json_output)?;
            return Ok(Status::err(1, "Template syntax error"));
        }

        // Try to render template with context to check for missing variables
        match tera.render(template_name, &context) {
            Ok(_) => {
                // Template rendered successfully
                result.ok = true;
            }
            Err(e) => {
                let error_msg = e.to_string();
                
                // Check if it's a missing variable error
                if error_msg.contains("Variable") && (error_msg.contains("not found") || error_msg.contains("doesn't exist")) {
                    let validation_error = ValidationError {
                        kind: "missing_variable".to_string(),
                        message: format!("Missing variable: {}", e),
                        line: None,
                        column: None,
                    };
                    
                    if strict {
                        result.ok = false;
                        result.errors.push(validation_error);
                    } else {
                        result.ok = true;
                        result.warnings.push(validation_error);
                    }
                } else {
                    // Other render error
                    result.ok = false;
                    result.errors.push(ValidationError {
                        kind: "render".to_string(),
                        message: format!("Template render error: {}", e),
                        line: None,
                        column: None,
                    });
                }
            }
        }

        // Output JSON result
        let json_output = serde_json::to_string(&result)?;
        writeln!(io.stdout, "{}", json_output)?;
        
        let exit_code = if result.ok { 0 } else { 1 };
        Ok(Status { 
            ok: result.ok, 
            code: Some(exit_code),
            reason: if result.ok { None } else { Some("Template validation failed".to_string()) }
        })
    }

    fn render_template(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let format = args.get("format").map(|s| s.as_str()).unwrap_or("text");
        
        // Get template content and source name
        let (template_content, _source_name) = match self.get_render_template_content(args) {
            Ok((content, name)) => (content, name),
            Err(error) => {
                let result = RenderResult {
                    ok: false,
                    engine: "tera".to_string(),
                    template: self.create_template_info(args, None),
                    context: ContextInfo {
                        keys: Vec::new(),
                        raw: Value::Object(serde_json::Map::new()),
                    },
                    body: None,
                    errors: vec![error],
                };
                
                let json_output = serde_json::to_string(&result)?;
                writeln!(io.stdout, "{}", json_output)?;
                
                return Ok(Status {
                    ok: false,
                    code: Some(2),
                    reason: Some("template_not_found".to_string()),
                });
            }
        };

        // Parse context
        let (context_info, tera_context) = match self.parse_render_context(args) {
            Ok((ctx_info, tera_ctx)) => (ctx_info, tera_ctx),
            Err(error) => {
                let result = RenderResult {
                    ok: false,
                    engine: "tera".to_string(),
                    template: self.create_template_info(args, Some(&template_content)),
                    context: ContextInfo {
                        keys: Vec::new(),
                        raw: Value::Object(serde_json::Map::new()),
                    },
                    body: None,
                    errors: vec![error],
                };
                
                let json_output = serde_json::to_string(&result)?;
                writeln!(io.stdout, "{}", json_output)?;
                
                return Ok(Status {
                    ok: false,
                    code: Some(3),
                    reason: Some("context_parse".to_string()),
                });
            }
        };

        // Create Tera instance and add template
        let mut tera = Tera::default();
        let template_name = "render_template";
        
        if let Err(e) = tera.add_raw_template(template_name, &template_content) {
            let error = ValidationError {
                kind: "render".to_string(),
                message: format!("template parse error: {}", e),
                line: None,
                column: None,
            };
            
            let result = RenderResult {
                ok: false,
                engine: "tera".to_string(),
                template: self.create_template_info(args, Some(&template_content)),
                context: context_info,
                body: None,
                errors: vec![error],
            };
            
            let json_output = serde_json::to_string(&result)?;
            writeln!(io.stdout, "{}", json_output)?;
            
            return Ok(Status {
                ok: false,
                code: Some(4),
                reason: Some("tera_render_failed".to_string()),
            });
        }

        // Render template
        let rendered = match tera.render(template_name, &tera_context) {
            Ok(result) => result,
            Err(e) => {
                let error = ValidationError {
                    kind: "render".to_string(),
                    message: format!("template render error: {}", e),
                    line: None,
                    column: None,
                };
                
                let result = RenderResult {
                    ok: false,
                    engine: "tera".to_string(),
                    template: self.create_template_info(args, Some(&template_content)),
                    context: context_info,
                    body: None,
                    errors: vec![error],
                };
                
                let json_output = serde_json::to_string(&result)?;
                writeln!(io.stdout, "{}", json_output)?;
                
                return Ok(Status {
                    ok: false,
                    code: Some(4),
                    reason: Some("tera_render_failed".to_string()),
                });
            }
        };

        // Format output
        let body = match self.format_render_output(rendered, format) {
            Ok(body_info) => Some(body_info),
            Err(error) => {
                let result = RenderResult {
                    ok: false,
                    engine: "tera".to_string(),
                    template: self.create_template_info(args, Some(&template_content)),
                    context: context_info,
                    body: None,
                    errors: vec![error],
                };
                
                let json_output = serde_json::to_string(&result)?;
                writeln!(io.stdout, "{}", json_output)?;
                
                return Ok(Status {
                    ok: false,
                    code: Some(5),
                    reason: Some("json_parse_failed".to_string()),
                });
            }
        };

        // Success result
        let result = RenderResult {
            ok: true,
            engine: "tera".to_string(),
            template: self.create_template_info(args, Some(&template_content)),
            context: context_info,
            body,
            errors: Vec::new(),
        };
        
        let json_output = serde_json::to_string(&result)?;
        writeln!(io.stdout, "{}", json_output)?;
        
        Ok(Status::ok())
    }

    fn test_template(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse arguments
        let stop_on_first_fail = args.get("stop_on_first_fail")
            .map(|s| s == "true")
            .unwrap_or(false);
        
        let capture_output = args.get("capture_output")
            .map(|s| s.as_str())
            .unwrap_or("summary");

        // Get template content and name
        let (template_content, template_name) = match self.get_render_template_content(args) {
            Ok((content, name)) => (content, name),
            Err(error) => {
                let result = TestResult {
                    template: self.template_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_else(|| "inline".to_string()),
                    ok: false,
                    total: 0,
                    passed: 0,
                    failed: 0,
                    stop_on_first_fail,
                    error: Some(error.message),
                    cases: Vec::new(),
                };
                
                let json_output = serde_json::to_string(&result)?;
                writeln!(io.stdout, "{}", json_output)?;
                
                return Ok(Status {
                    ok: false,
                    code: Some(2),
                    reason: Some("template_not_found".to_string()),
                });
            }
        };

        // Load test cases
        let test_cases = match self.load_test_cases(args, &template_name) {
            Ok(cases) => cases,
            Err(e) => {
                let result = TestResult {
                    template: template_name,
                    ok: false,
                    total: 0,
                    passed: 0,
                    failed: 0,
                    stop_on_first_fail,
                    error: Some(e.to_string()),
                    cases: Vec::new(),
                };
                
                let json_output = serde_json::to_string(&result)?;
                writeln!(io.stdout, "{}", json_output)?;
                
                return Ok(Status {
                    ok: false,
                    code: Some(2),
                    reason: Some("no_test_cases".to_string()),
                });
            }
        };

        if test_cases.is_empty() {
            let result = TestResult {
                template: template_name,
                ok: false,
                total: 0,
                passed: 0,
                failed: 0,
                stop_on_first_fail,
                error: Some("no test cases supplied".to_string()),
                cases: Vec::new(),
            };
            
            let json_output = serde_json::to_string(&result)?;
            writeln!(io.stdout, "{}", json_output)?;
            
            return Ok(Status {
                ok: false,
                code: Some(1),
                reason: Some("no_test_cases".to_string()),
            });
        }

        // Create Tera instance and add template
        let mut tera = Tera::default();
        let template_name_key = "test_template";
        
        if let Err(e) = tera.add_raw_template(template_name_key, &template_content) {
            let result = TestResult {
                template: template_name,
                ok: false,
                total: test_cases.len(),
                passed: 0,
                failed: test_cases.len(),
                stop_on_first_fail,
                error: Some(format!("template parse error: {}", e)),
                cases: Vec::new(),
            };
            
            let json_output = serde_json::to_string(&result)?;
            writeln!(io.stdout, "{}", json_output)?;
            
            return Ok(Status {
                ok: false,
                code: Some(3),
                reason: Some("tera_parse_failed".to_string()),
            });
        }

        // Execute test cases
        let (case_results, passed, failed, total_executed) = self.execute_test_cases(
            &tera,
            template_name_key,
            &test_cases,
            stop_on_first_fail,
            capture_output
        );

        let ok = failed == 0 && total_executed > 0;

        let result = TestResult {
            template: template_name,
            ok,
            total: total_executed,
            passed,
            failed,
            stop_on_first_fail,
            error: None,
            cases: case_results,
        };
        
        let json_output = serde_json::to_string(&result)?;
        writeln!(io.stdout, "{}", json_output)?;
        
        Ok(Status {
            ok,
            code: if ok { Some(0) } else { Some(1) },
            reason: if ok { None } else { Some("tests_failed".to_string()) },
        })
    }

    fn load_test_cases(&self, args: &Args, template_name: &str) -> Result<Vec<TemplateTestCase>> {
        // Priority: 1. inline cases, 2. cases_file, 3. default test file
        if let Some(cases_json) = args.get("cases") {
            let cases: Vec<TemplateTestCase> = serde_json::from_str(cases_json)
                .with_context(|| format!("failed to parse inline cases JSON: {}", cases_json))?;
            return Ok(cases);
        }

        if let Some(cases_file) = args.get("cases_file") {
            let content = std::fs::read_to_string(cases_file)
                .with_context(|| format!("failed to read cases file: {}", cases_file))?;
            let cases: Vec<TemplateTestCase> = serde_json::from_str(&content)
                .with_context(|| format!("failed to parse cases file JSON: {}", cases_file))?;
            return Ok(cases);
        }

        // Try default test file
        if let Some(template_path) = &self.template_path {
            let default_test_file = template_path.with_extension("tests.json");
            if default_test_file.exists() {
                let content = std::fs::read_to_string(&default_test_file)
                    .with_context(|| format!("failed to read default test file: {}", default_test_file.display()))?;
                let cases: Vec<TemplateTestCase> = serde_json::from_str(&content)
                    .with_context(|| format!("failed to parse default test file JSON: {}", default_test_file.display()))?;
                return Ok(cases);
            }
        }

        bail!("no test cases provided and default tests file not found");
    }

    fn execute_test_cases(
        &self,
        tera: &Tera,
        template_name: &str,
        test_cases: &[TemplateTestCase],
        stop_on_first_fail: bool,
        capture_output: &str,
    ) -> (Vec<TestCaseResult>, usize, usize, usize) {
        let mut case_results = Vec::new();
        let mut passed = 0;
        let mut failed = 0;

        for (_i, test_case) in test_cases.iter().enumerate() {
            if stop_on_first_fail && failed > 0 {
                break;
            }

            let result = self.execute_single_test_case(tera, template_name, test_case, capture_output);
            
            if result.ok {
                passed += 1;
            } else {
                failed += 1;
            }
            
            case_results.push(result);
        }

        let total_executed = case_results.len();
        (case_results, passed, failed, total_executed)
    }

    fn execute_single_test_case(
        &self,
        tera: &Tera,
        template_name: &str,
        test_case: &TemplateTestCase,
        capture_output: &str,
    ) -> TestCaseResult {
        // Convert context to Tera context
        let tera_context = match TeraContext::from_serialize(&test_case.context) {
            Ok(ctx) => ctx,
            Err(e) => {
                return TestCaseResult {
                    name: test_case.name.clone(),
                    ok: false,
                    error: Some(format!("failed to convert context: {}", e)),
                    expected: test_case.expected.clone(),
                    contains: test_case.contains.clone(),
                    not_contains: test_case.not_contains.clone(),
                    rendered: None,
                    diff: None,
                };
            }
        };

        // Render template
        let rendered = match tera.render(template_name, &tera_context) {
            Ok(output) => output,
            Err(e) => {
                return TestCaseResult {
                    name: test_case.name.clone(),
                    ok: false,
                    error: Some(format!("template render error: {}", e)),
                    expected: test_case.expected.clone(),
                    contains: test_case.contains.clone(),
                    not_contains: test_case.not_contains.clone(),
                    rendered: None,
                    diff: None,
                };
            }
        };

        // Check expectations
        let (ok, error, diff) = self.check_expectations(test_case, &rendered);

        let rendered_output = match capture_output {
            "none" => None,
            "full" => Some(rendered.clone()),
            "summary" | _ => {
                if ok {
                    None
                } else {
                    Some(rendered.clone())
                }
            }
        };

        TestCaseResult {
            name: test_case.name.clone(),
            ok,
            error,
            expected: test_case.expected.clone(),
            contains: test_case.contains.clone(),
            not_contains: test_case.not_contains.clone(),
            rendered: rendered_output,
            diff,
        }
    }

    fn check_expectations(&self, test_case: &TemplateTestCase, rendered: &str) -> (bool, Option<String>, Option<String>) {
        // Check exact match
        if let Some(expected) = &test_case.expected {
            if rendered != expected {
                let diff = format!("Expected: {:?}, Got: {:?}", expected, rendered);
                return (false, Some("expected output mismatch".to_string()), Some(diff));
            }
        }

        // Check contains
        if let Some(contains) = &test_case.contains {
            if !rendered.contains(contains) {
                let diff = format!("Expected output to contain: {:?}, but got: {:?}", contains, rendered);
                return (false, Some("contains check failed".to_string()), Some(diff));
            }
        }

        // Check not_contains
        if let Some(not_contains) = &test_case.not_contains {
            if rendered.contains(not_contains) {
                let diff = format!("Expected output to NOT contain: {:?}, but got: {:?}", not_contains, rendered);
                return (false, Some("not_contains check failed".to_string()), Some(diff));
            }
        }

        (true, None, None)
    }
}

impl Handle for TemplateHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["render", "validate", "test"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "render" => self.render_template(args, io),
            "validate" => self.validate(args, io),
            "test" => self.test_template(args, io),
            _ => Ok(Status::err(1, format!("unknown verb: {}", verb))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;

    fn create_test_io() -> (Cursor<Vec<u8>>, Cursor<Vec<u8>>, Cursor<Vec<u8>>) {
        (
            Cursor::new(Vec::new()), // stdin
            Cursor::new(Vec::new()), // stdout
            Cursor::new(Vec::new()), // stderr
        )
    }

    // VALIDATE TESTS (NEW TERA FUNCTIONALITY)

    #[test]
    fn validate_syntax_ok_without_data() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name | default(value=\"world\") }}!".to_string());
        args.insert("strict".to_string(), "true".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.errors.len(), 0);
    }

    #[test]
    fn validate_syntax_error() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name ".to_string()); // Missing closing braces
        args.insert("strict".to_string(), "true".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.errors.len() > 0);
        assert_eq!(parsed.errors[0].kind, "syntax");
    }

    #[test]
    fn validate_with_data_missing_variable_strict() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name }}!".to_string());
        args.insert("context".to_string(), "{}".to_string());
        args.insert("strict".to_string(), "true".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.errors.len() > 0);
        assert_eq!(parsed.errors[0].kind, "missing_variable");
    }

    #[test]
    fn validate_with_data_missing_variable_non_strict() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name }}!".to_string());
        args.insert("context".to_string(), "{}".to_string());
        args.insert("strict".to_string(), "false".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(result.ok); // Should succeed in non-strict mode

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        // Should have warnings instead of errors
        assert!(parsed.warnings.len() > 0);
        assert_eq!(parsed.warnings[0].kind, "missing_variable");
    }

    #[test]
    fn validate_bad_json() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("from".to_string(), "Hello {{ name }}!".to_string());
        args.insert("context".to_string(), "{not valid json}".to_string());
        args.insert("strict".to_string(), "true".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.validate(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: ValidationResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.errors.len() > 0);
        assert_eq!(parsed.errors[0].kind, "context_parse");
    }

    // RENDER TESTS (NEW STRUCTURED OUTPUT)

    #[test]
    fn render_inline_basic() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}".to_string());
        args.insert("context".to_string(), r#"{"name": "Alice"}"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.engine, "tera");
        assert_eq!(parsed.template.source, "inline");
        assert_eq!(parsed.context.keys, vec!["name"]);
        assert_eq!(parsed.body.as_ref().unwrap().body_type, "text");
        assert_eq!(parsed.body.as_ref().unwrap().value, Some(Value::String("Hello Alice".to_string())));
        assert!(parsed.errors.is_empty());
    }

    #[test]
    fn render_file_with_data_json() {
        let temp_dir = TempDir::new().unwrap();
        let template_path = temp_dir.path().join("welcome.tera");
        let mut template_file = File::create(&template_path).unwrap();
        write!(template_file, "Hi {{ user }} from {{ env }}").unwrap();

        let handle = TemplateHandle {
            template_path: Some(template_path),
        };
        let mut args = HashMap::new();
        args.insert("context".to_string(), r#"{"user":"bob", "env":"prod"}"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.template.source, "file");
        assert_eq!(parsed.body.as_ref().unwrap().value, Some(Value::String("Hi bob from prod".to_string())));
    }

    #[test]
    fn render_format_json() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), r#"{"value": {{ n }}}"#.to_string());
        args.insert("context".to_string(), r#"{"n": 42}"#.to_string());
        args.insert("format".to_string(), "json".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.body.as_ref().unwrap().body_type, "json");
        
        let expected_value = serde_json::json!({"value": 42});
        assert_eq!(parsed.body.as_ref().unwrap().value, Some(expected_value));
    }

    #[test]
    fn render_format_bytes() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}".to_string());
        args.insert("context".to_string(), r#"{"name": "world"}"#.to_string());
        args.insert("format".to_string(), "bytes".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.body.as_ref().unwrap().body_type, "bytes");
        assert!(parsed.body.as_ref().unwrap().value.is_none());
        assert!(parsed.body.as_ref().unwrap().base64.is_some());

        // Decode base64 and verify content
        use base64::{Engine as _, engine::general_purpose};
        let decoded = general_purpose::STANDARD.decode(parsed.body.as_ref().unwrap().base64.as_ref().unwrap()).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello world");
    }

    #[test]
    fn render_context_file() {
        let temp_dir = TempDir::new().unwrap();
        let context_path = temp_dir.path().join("context.json");
        let mut context_file = File::create(&context_path).unwrap();
        write!(context_file, r##"{{"greeting": "Hi", "target": "universe"}}"##).unwrap();

        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "{{ greeting }} {{ target }}!".to_string());
        args.insert("context_file".to_string(), context_path.to_string_lossy().to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.body.as_ref().unwrap().value, Some(Value::String("Hi universe!".to_string())));
        assert_eq!(parsed.context.keys.len(), 2);
        assert!(parsed.context.keys.contains(&"greeting".to_string()));
        assert!(parsed.context.keys.contains(&"target".to_string()));
    }

    #[test]
    fn render_missing_variable_error() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ missing }}".to_string());
        args.insert("context".to_string(), "{}".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(4));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "render");
        assert!(parsed.body.is_none());
    }

    #[test]
    fn render_missing_template_source_fails() {
        let handle = TemplateHandle { template_path: None };
        let args = HashMap::new(); // No 'template' or file path

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(2));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "template_not_found");
    }

    #[test]
    fn render_invalid_json_context_fails() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "{{ test }}".to_string());
        args.insert("context".to_string(), "{bad json}".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(3));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "context_parse");
    }

    #[test]
    fn render_invalid_format_fails() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello world".to_string());
        args.insert("format".to_string(), "invalid_format".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(5));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "invalid_format");
    }

    #[test]
    fn render_invalid_json_output_fails() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "not valid json".to_string());
        args.insert("format".to_string(), "json".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(5));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.errors[0].kind, "json_parse");
    }

    #[test]
    fn render_context_overrides_context_file() {
        let temp_dir = TempDir::new().unwrap();
        let context_path = temp_dir.path().join("context.json");
        let mut context_file = File::create(&context_path).unwrap();
        context_file.write_all(br#"{"name": "file"}"#).unwrap();

        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}".to_string());
        args.insert("context_file".to_string(), context_path.to_string_lossy().to_string());
        args.insert("context".to_string(), r#"{"name": "arg"}"#.to_string()); // Should override file

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.render_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: RenderResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.body.as_ref().unwrap().value, Some(Value::String("Hello arg".to_string())));
    }

    // TEST VERB TESTS

    #[test]
    fn test_inline_cases_all_pass() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("cases".to_string(), r#"[
            {
                "name": "basic_test",
                "context": {"name": "Alice"},
                "expected": "Hello Alice!"
            },
            {
                "name": "contains_test",
                "context": {"name": "Bob"},
                "contains": "Bob"
            }
        ]"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.total, 2);
        assert_eq!(parsed.passed, 2);
        assert_eq!(parsed.failed, 0);
        assert_eq!(parsed.cases.len(), 2);
        assert!(parsed.cases[0].ok);
        assert!(parsed.cases[1].ok);
    }

    #[test]
    fn test_inline_cases_with_failure() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("cases".to_string(), r#"[
            {
                "name": "pass_test",
                "context": {"name": "Alice"},
                "expected": "Hello Alice!"
            },
            {
                "name": "fail_test",
                "context": {"name": "Bob"},
                "expected": "Hi Bob!"
            }
        ]"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.total, 2);
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.failed, 1);
        assert_eq!(parsed.cases.len(), 2);
        assert!(parsed.cases[0].ok);
        assert!(!parsed.cases[1].ok);
        assert!(parsed.cases[1].error.is_some());
        assert!(parsed.cases[1].diff.is_some());
    }

    #[test]
    fn test_stop_on_first_fail() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("stop_on_first_fail".to_string(), "true".to_string());
        args.insert("cases".to_string(), r#"[
            {
                "name": "fail_test",
                "context": {"name": "Bob"},
                "expected": "Hi Bob!"
            },
            {
                "name": "should_not_run",
                "context": {"name": "Charlie"},
                "expected": "Hello Charlie!"
            }
        ]"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.total, 1); // Only first test should run
        assert_eq!(parsed.passed, 0);
        assert_eq!(parsed.failed, 1);
        assert_eq!(parsed.cases.len(), 1); // Only first test result
        assert!(!parsed.cases[0].ok);
        assert!(parsed.stop_on_first_fail);
    }

    #[test]
    fn test_capture_output_modes() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("capture_output".to_string(), "full".to_string());
        args.insert("cases".to_string(), r#"[
            {
                "name": "pass_test",
                "context": {"name": "Alice"},
                "expected": "Hello Alice!"
            }
        ]"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.cases[0].rendered.is_some());
        assert_eq!(parsed.cases[0].rendered.as_ref().unwrap(), "Hello Alice!");
    }

    #[test]
    fn test_contains_and_not_contains() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}! Welcome to {{ place }}.".to_string());
        args.insert("cases".to_string(), r#"[
            {
                "name": "contains_pass",
                "context": {"name": "Alice", "place": "Earth"},
                "contains": "Alice"
            },
            {
                "name": "not_contains_pass",
                "context": {"name": "Bob", "place": "Mars"},
                "not_contains": "Earth"
            },
            {
                "name": "not_contains_fail",
                "context": {"name": "Charlie", "place": "Earth"},
                "not_contains": "Earth"
            }
        ]"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.total, 3);
        assert_eq!(parsed.passed, 2);
        assert_eq!(parsed.failed, 1);
        assert!(parsed.cases[0].ok); // contains pass
        assert!(parsed.cases[1].ok); // not_contains pass
        assert!(!parsed.cases[2].ok); // not_contains fail
    }

    #[test]
    fn test_no_cases_provided_error() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        // No cases, cases_file, or default file

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.total, 0);
        assert!(parsed.error.is_some());
    }

    #[test]
    fn test_invalid_cases_json() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("cases".to_string(), "{invalid json}".to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);
        assert_eq!(result.code, Some(2));

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert!(parsed.error.is_some());
        assert!(parsed.error.as_ref().unwrap().contains("parse"));
    }

    #[test]
    fn test_template_render_error() {
        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ missing_var }}!".to_string());
        args.insert("cases".to_string(), r#"[
            {
                "name": "missing_var",
                "context": {}
            }
        ]"#.to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(!result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.failed, 1);
        assert!(!parsed.cases[0].ok);
        assert!(parsed.cases[0].error.is_some());
        assert!(parsed.cases[0].error.as_ref().unwrap().contains("render"));
    }

    #[test]
    fn test_cases_file() {
        let temp_dir = TempDir::new().unwrap();
        let cases_file_path = temp_dir.path().join("test_cases.json");
        let mut cases_file = File::create(&cases_file_path).unwrap();
        cases_file.write_all(br#"[
            {
                "name": "file_test",
                "context": {"name": "FileTest"},
                "expected": "Hello FileTest!"
            }
        ]"#).unwrap();

        let handle = TemplateHandle { template_path: None };
        let mut args = HashMap::new();
        args.insert("template".to_string(), "Hello {{ name }}!".to_string());
        args.insert("cases_file".to_string(), cases_file_path.to_string_lossy().to_string());

        let (mut stdin, mut stdout, mut stderr) = create_test_io();
        let mut io = IoStreams {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
        };

        let result = handle.test_template(&args, &mut io).unwrap();
        assert!(result.ok);

        let output = String::from_utf8(stdout.into_inner()).unwrap();
        let parsed: TestResult = serde_json::from_str(&output).unwrap();
        assert!(parsed.ok);
        assert_eq!(parsed.total, 1);
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.cases[0].name, "file_test");
        assert!(parsed.cases[0].ok);
    }
}


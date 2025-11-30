use anyhow::{Context, Result, bail};
use base64::prelude::*;
use reqwest::blocking::Client;
use reqwest::Method;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use std::io::Write;
use url::Url;

use crate::core::{
    registry::{Args, Handle, IoStreams},
    status::Status,
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("http", |u| Ok(Box::new(HttpHandle::from_url(u)?)));
    reg.register_scheme("https", |u| Ok(Box::new(HttpHandle::from_url(u)?)));
}

pub struct HttpHandle {
    url: Url,
}

impl HttpHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        Ok(HttpHandle {
            url: url.clone(),
        })
    }

    fn parse_headers(headers_str: &str) -> Result<HashMap<String, String>, String> {
        let mut headers = HashMap::new();
        for pair in headers_str.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some(idx) = pair.find(':') {
                let key = pair[..idx].trim();
                let value = pair[idx + 1..].trim();
                if !key.is_empty() {
                    // Filter out hop-by-hop headers
                    let key_lower = key.to_lowercase();
                    if !["host", "content-length", "connection", "transfer-encoding"].contains(&key_lower.as_str()) {
                        headers.insert(key.to_string(), value.to_string());
                    }
                }
            } else {
                // Invalid header format - missing colon
                return Err(format!("invalid header format: '{}'", pair));
            }
        }
        Ok(headers)
    }

    fn parse_query_params(query_str: &str) -> Vec<(String, String)> {
        let mut params = Vec::new();
        for pair in query_str.split('&') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some(idx) = pair.find('=') {
                let key = pair[..idx].trim();
                let value = pair[idx + 1..].trim();
                if !key.is_empty() {
                    params.push((key.to_string(), value.to_string()));
                }
            } else {
                // Handle key without value
                params.push((pair.to_string(), String::new()));
            }
        }
        params
    }

    fn merge_query_params(mut url: Url, query_str: &str) -> Result<Url> {
        let new_params = Self::parse_query_params(query_str);
        
        for (key, value) in new_params {
            url.query_pairs_mut().append_pair(&key, &value);
        }
        
        Ok(url)
    }

    fn apply_query(mut base_url: Url, raw_query: &str) -> Url {
        if raw_query.is_empty() {
            return base_url;
        }
        
        // If URL already has a query, append with &, otherwise with ?
        let current_query = base_url.query().unwrap_or("");
        if current_query.is_empty() {
            base_url.set_query(Some(raw_query));
        } else {
            let merged = format!("{}&{}", current_query, raw_query);
            base_url.set_query(Some(&merged));
        }
        
        base_url
    }

    fn build_client(args: &Args, scheme: &str) -> Result<Client> {
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30_000);
        
        let mut builder = Client::builder()
            .timeout(Duration::from_millis(timeout_ms));
        
        // Handle allow_insecure for HTTPS
        if let Some(allow_insecure) = args.get("allow_insecure") {
            if allow_insecure.to_lowercase() == "true" && scheme == "https" {
                builder = builder.danger_accept_invalid_certs(true);
            }
        }
        
        builder.build().context("Failed to create HTTP client")
    }

    /// Parse comma or semicolon-separated header list and return normalized comma-separated string
    fn parse_header_list(value: &str) -> Vec<String> {
        value
            .split(&[',', ';'][..])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Parse boolean header value (case-insensitive "true")
    fn parse_bool_header(value: &str) -> bool {
        value.trim().to_lowercase() == "true"
    }

    /// Parse integer header value, returning None if invalid
    fn parse_int_header(value: &str) -> Option<i64> {
        value.trim().parse::<i64>().ok()
    }

    /// Parse request_headers argument into comma-separated list for Access-Control-Request-Headers
    fn parse_request_headers_arg(value: &str) -> String {
        let headers = Self::parse_header_list(value);
        headers.join(", ")
    }

    /// Implements the head verb according to spec
    fn verb_head(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Start with the original URL
        let mut request_url = self.url.clone();
        
        // Merge query parameters if provided
        if let Some(query) = args.get("query") {
            request_url = Self::merge_query_params(request_url, query)
                .context("Failed to merge query parameters")?;
        }

        // Build client with 10 second timeout
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the HEAD request
        let mut request_builder = client.head(request_url.clone());

        // Add headers if provided
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(e) => {
                    return Ok(Status::err(1, format!("invalid headers: {}", e)));
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Add Accept header based on accept parameter
        if let Some(accept) = args.get("accept") {
            let accept_header = match accept.as_str() {
                "json" => "application/json",
                "text" => "text/*",
                _ => "*/*", // bytes or anything else
            };
            request_builder = request_builder.header("Accept", accept_header);
        }

        // Execute the HEAD request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = if e.is_timeout() {
                    "Request timed out".to_string()
                } else if e.is_connect() {
                    "Connection failed".to_string()
                } else {
                    format!("Network error: {}", e)
                };
                
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Extract response data
        let final_url = response.url().to_string();
        let status_code = response.status().as_u16();
        let is_ok = response.status().is_success();
        let reason = response.status().canonical_reason().unwrap_or("Unknown").to_string();

        // Extract headers (lowercase keys)
        let mut response_headers = HashMap::new();
        for (name, value) in response.headers() {
            let header_name = name.to_string().to_lowercase();
            let header_value = value.to_str().unwrap_or("<invalid-utf8>").to_string();
            
            // For multi-valued headers, join with ", "
            if let Some(existing) = response_headers.get(&header_name) {
                response_headers.insert(header_name, format!("{}, {}", existing, header_value));
            } else {
                response_headers.insert(header_name, header_value);
            }
        }

        // Build response JSON according to spec
        let response_json = json!({
            "url": final_url,
            "status": status_code,
            "ok": is_ok,
            "reason": reason,
            "headers": response_headers
        });

        // Write JSON response to stdout
        write!(io.stdout, "{}", serde_json::to_string(&response_json)?)?;

        // Always return Status::ok() for successful transport
        Ok(Status::ok())
    }

    /// Implements the get verb with specific behavior for accept modes
    fn verb_get(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse timeout (default 10 seconds)
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10_000);

        // Parse accept mode (default "text")
        let accept = args.get("accept").map(|s| s.as_str()).unwrap_or("text");
        if !["json", "bytes", "text"].contains(&accept) {
            return Ok(Status::err(1, format!("Invalid accept mode: {}. Must be json, bytes, or text", accept)));
        }

        // Start with the original URL
        let mut request_url = self.url.clone();
        
        // Merge query parameters if provided
        if let Some(query) = args.get("query") {
            request_url = Self::merge_query_params(request_url, query)
                .context("Failed to merge query parameters")?;
        }

        // Build client with timeout
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the request
        let mut request_builder = client.get(request_url.clone());

        // Add headers if provided
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(e) => {
                    return Ok(Status::err(1, format!("invalid headers: {}", e)));
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Execute the request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = if e.is_timeout() {
                    "Request timed out".to_string()
                } else if e.is_connect() {
                    "Connection failed".to_string()
                } else {
                    format!("Request failed: {}", e)
                };
                
                return Ok(Status::err(1, error_msg));
            }
        };

        // Check status
        let status_code = response.status();
        let is_success = status_code.is_success();

        // Extract headers before consuming response
        let mut response_headers = std::collections::HashMap::new();
        for (name, value) in response.headers() {
            let header_name = name.to_string();
            let header_value = value.to_str().unwrap_or("<invalid-utf8>").to_string();
            
            response_headers
                .entry(header_name)
                .or_insert_with(Vec::new)
                .push(header_value);
        }

        // Get response body
        let body_bytes = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                return Ok(Status::err(1, format!("Failed to read response body: {}", e)));
            }
        };

        // Handle response based on accept mode
        match accept {
            "json" => {
                // Create structured JSON response like other HTTP methods
                
                // Determine if response content is JSON
                let content_type = response_headers
                    .get("content-type")
                    .and_then(|v| v.first())
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                
                let body_value = if content_type.contains("application/json") {
                    // Try to parse as JSON
                    match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                        Ok(json_val) => json_val,
                        Err(_) => {
                            // Parse failed, treat as string
                            let text = String::from_utf8_lossy(&body_bytes).to_string();
                            serde_json::Value::String(text)
                        }
                    }
                } else {
                    // Not JSON content type, treat as string
                    let text = String::from_utf8_lossy(&body_bytes).to_string();
                    serde_json::Value::String(text)
                };
                
                let response_json = json!({
                    "status": status_code.as_u16(),
                    "ok": is_success,
                    "method": "GET",
                    "headers": response_headers,
                    "body": body_value,
                    "body_text": String::from_utf8_lossy(&body_bytes).to_string()
                });
                
                write!(io.stdout, "{}", serde_json::to_string(&response_json)?)?;
            }
            "bytes" => {
                // Write raw bytes directly to stdout
                io.stdout.write_all(&body_bytes)?;
            }
            "text" => {
                // Try to decode as UTF-8, fallback to bytes
                match std::str::from_utf8(&body_bytes) {
                    Ok(text) => {
                        write!(io.stdout, "{}", text)?;
                    }
                    Err(_) => {
                        // Fall back to bytes behavior for robustness
                        io.stdout.write_all(&body_bytes)?;
                    }
                }
            }
            _ => unreachable!(), // Already validated above
        }

        // Return status based on HTTP response code
        if is_success {
            Ok(Status::ok())
        } else {
            Ok(Status::err(
                status_code.as_u16() as i32,
                format!("HTTP {}", status_code)
            ))
        }
    }

    /// Implements the post verb according to spec
    fn verb_post(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse timeout (default 10 seconds)
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10_000);

        // Start with the original URL
        let mut request_url = self.url.clone();
        
        // Merge query parameters if provided
        if let Some(query) = args.get("query") {
            request_url = Self::merge_query_params(request_url, query)
                .context("Failed to merge query parameters")?;
        }

        // Build client with timeout
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the POST request
        let mut request_builder = client.post(request_url.clone());

        // Add headers if provided
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(e) => {
                    return Ok(Status::err(1, format!("invalid headers: {}", e)));
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Add content type if provided
        if let Some(content_type) = args.get("content_type") {
            request_builder = request_builder.header("Content-Type", content_type);
        }

        // Determine request body
        let request_body: Vec<u8> = if let Some(body_file) = args.get("body_file") {
            // Read body from file (body_file wins over body)
            match std::fs::read(body_file) {
                Ok(contents) => contents,
                Err(e) => {
                    writeln!(io.stderr, "Failed to read body_file '{}': {}", body_file, e)?;
                    return Ok(Status::err(1, format!("Failed to read body_file: {}", e)));
                }
            }
        } else if let Some(body) = args.get("body") {
            // Use inline body string as UTF-8 bytes
            body.as_bytes().to_vec()
        } else {
            // Empty body
            Vec::new()
        };

        // Attach the body to the request
        request_builder = request_builder.body(request_body);

        // Execute the POST request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = if e.is_timeout() {
                    "Request timed out".to_string()
                } else if e.is_connect() {
                    "Connection failed".to_string()
                } else {
                    format!("Request failed: {}", e)
                };
                
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Check status
        let status_code = response.status();
        let is_success = status_code.is_success();

        // Get response body and write directly to stdout
        let body_bytes = match response.bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                let error_msg = format!("Failed to read response body: {}", e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Write raw response body bytes to stdout
        io.stdout.write_all(&body_bytes)?;

        // Return status based on HTTP response code
        if is_success {
            Ok(Status::ok())
        } else {
            Ok(Status::err(
                status_code.as_u16() as i32,
                format!("HTTP {}", status_code.as_u16())
            ))
        }
    }

    // Requirements for put verb:
    // Implement the put verb for the http handle so that the shell can perform real HTTP PUT requests
    // against arbitrary HTTP/HTTPS URLs, with proper headers, body handling, and structured output.
    // This must be production-ready, use strong error handling, and include tests that pass and compile.
    
    /// Implements the put verb according to spec
    fn verb_put(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Start with the original URL and apply query if provided
        let mut request_url = self.url.clone();
        if let Some(query) = args.get("query") {
            if !query.is_empty() {
                request_url = Self::apply_query(request_url, query);
            }
        }

        // Build client with timeout and TLS settings
        let client = Self::build_client(args, self.url.scheme())?;
        
        // Start building the PUT request
        let mut request_builder = client.put(request_url.clone());

        // Apply headers from headers parameter
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(e) => {
                    return Ok(Status::err(1, format!("invalid headers: {}", e)));
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }
        
        // Handle request body with body_file taking precedence over body
        let request_body: Vec<u8> = if let Some(body_file) = args.get("body_file") {
            if !body_file.is_empty() {
                match std::fs::read(body_file) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        writeln!(io.stderr, "failed to read body_file '{}': {}", body_file, e)?;
                        return Ok(Status::err(1, format!("failed to read body_file: {}", e)));
                    }
                }
            } else {
                Vec::new()
            }
        } else if let Some(body) = args.get("body") {
            body.as_bytes().to_vec()
        } else {
            Vec::new()
        };
        
        // Set Content-Type header
        if let Some(content_type) = args.get("content_type") {
            if !content_type.is_empty() {
                request_builder = request_builder.header("Content-Type", content_type);
            }
        } else {
            // Apply default Content-Type based on body source
            if args.get("body_file").is_some() {
                // For body_file, do not guess content type; leave unset
            } else if args.get("body").is_some() {
                // For body, default to text/plain
                request_builder = request_builder.header("Content-Type", "text/plain; charset=utf-8");
            }
        }
        
        // Attach the body to the request
        request_builder = request_builder.body(request_body);

        // Execute the PUT request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                let error_message = if e.is_timeout() {
                    "Request timed out".to_string()
                } else if e.is_connect() {
                    "Connection failed".to_string()
                } else {
                    format!("{}", e)
                };
                
                writeln!(io.stderr, "{}", error_message)?;
                return Ok(Status::err(1, error_message));
            }
        };

        // Extract response data
        let status_code = response.status().as_u16();
        let is_ok = response.status().is_success();
        
        // Extract headers as Map<String, Vec<String>>
        let mut response_headers = std::collections::HashMap::new();
        for (name, value) in response.headers() {
            let header_name = name.to_string();
            let header_value = value.to_str().unwrap_or("<invalid-utf8>").to_string();
            
            response_headers
                .entry(header_name)
                .or_insert_with(Vec::new)
                .push(header_value);
        }
        
        // Get response body
        let body_bytes = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                let error_msg = format!("Failed to read response body: {}", e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Parse accept mode (default "text")
        let accept = args.get("accept").map(|s| s.as_str()).unwrap_or("text");
        
        match accept {
            "bytes" => {
                // Stream raw response body bytes directly to stdout
                io.stdout.write_all(&body_bytes)?;
            }
            "text" => {
                // Decode as UTF-8, fallback to lossy decoding
                let text = match std::str::from_utf8(&body_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => String::from_utf8_lossy(&body_bytes).to_string(),
                };
                write!(io.stdout, "{}", text)?;
            }
            "json" => {
                // Determine if response is JSON based on Content-Type
                let content_type = response_headers
                    .get("content-type")
                    .and_then(|v| v.first())
                    .map(|s| s.to_lowercase())
                    .unwrap_or_default();
                
                let body_value = if content_type.contains("application/json") {
                    // Try to parse as JSON
                    match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                        Ok(json_val) => json_val,
                        Err(_) => {
                            // Parse failed, treat as string
                            let text = String::from_utf8_lossy(&body_bytes).to_string();
                            serde_json::Value::String(text)
                        }
                    }
                } else {
                    // Not JSON content type, treat as string
                    let text = String::from_utf8_lossy(&body_bytes).to_string();
                    serde_json::Value::String(text)
                };
                
                let response_json = json!({
                    "status": status_code,
                    "ok": is_ok,
                    "headers": response_headers,
                    "body": body_value
                });
                
                write!(io.stdout, "{}", serde_json::to_string(&response_json)?)?;
            }
            _ => {
                // Default to "text" behavior for unknown accept modes
                let text = match std::str::from_utf8(&body_bytes) {
                    Ok(s) => s.to_string(),
                    Err(_) => String::from_utf8_lossy(&body_bytes).to_string(),
                };
                write!(io.stdout, "{}", text)?;
            }
        }

        // Return status: if HTTP succeeded but status is not 2xx, return error status
        if is_ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(
                status_code as i32,
                "http error".to_string()
            ))
        }
    }

    /// Implements the patch verb according to spec
    fn verb_patch(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Validate accept parameter early
        let accept = args.get("accept").map(|s| s.as_str()).unwrap_or("bytes");
        if !matches!(accept, "json" | "text" | "bytes") {
            return Ok(Status::err(1, "unsupported accept value".to_string()));
        }

        // Start with the original URL
        let mut request_url = self.url.clone();
        
        // Merge query parameters if provided
        if let Some(query) = args.get("query") {
            request_url = Self::merge_query_params(request_url, query)
                .context("Failed to merge query parameters")?;
        }

        // Build client with timeout
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the PATCH request
        let mut request_builder = client.patch(request_url.clone());

        // Parse and add headers if provided
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(e) => {
                    return Ok(Status::err(1, format!("invalid headers: {}", e)));
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Add content type if provided (this will override any content-type from headers)
        if let Some(content_type) = args.get("content_type") {
            request_builder = request_builder.header("Content-Type", content_type);
        }

        // Determine request body with body taking precedence over body_file
        let request_body: Vec<u8> = if let Some(body) = args.get("body") {
            body.as_bytes().to_vec()
        } else if let Some(body_file) = args.get("body_file") {
            match std::fs::read(body_file) {
                Ok(contents) => contents,
                Err(e) => {
                    return Ok(Status::err(1, format!("failed to read body_file: {}", e)));
                }
            }
        } else {
            Vec::new()
        };

        // Attach the body to the request
        request_builder = request_builder.body(request_body);

        // Execute the PATCH request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = if e.is_timeout() {
                    "Request timed out".to_string()
                } else if e.is_connect() {
                    "Connection failed".to_string()
                } else {
                    format!("network error: {}", e)
                };
                
                return Ok(Status::err(1, error_msg));
            }
        };

        // Extract response data
        let status_code = response.status();
        let is_success = status_code.is_success();
        
        // Get response body
        let body_bytes = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                return Ok(Status::err(1, format!("Failed to read response body: {}", e)));
            }
        };

        // Handle response based on accept mode
        match accept {
            "json" => {
                // Parse response as JSON
                match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                    Ok(json_value) => {
                        write!(io.stdout, "{}", serde_json::to_string(&json_value)?)?;
                    }
                    Err(_) => {
                        return Ok(Status::err(1, "invalid json response".to_string()));
                    }
                }
            }
            "text" => {
                // Interpret as UTF-8 text (lossy)
                let text = String::from_utf8_lossy(&body_bytes);
                write!(io.stdout, "{}", text)?;
            }
            "bytes" => {
                // Stream raw bytes directly to stdout
                io.stdout.write_all(&body_bytes)?;
            }
            _ => unreachable!(), // Already validated above
        }

        // Return status based on HTTP response code
        if is_success {
            Ok(Status::ok())
        } else {
            Ok(Status::err(
                status_code.as_u16() as i32,
                format!("HTTP {}", status_code.as_u16())
            ))
        }
    }

    /// Implements the delete verb according to spec  
    fn verb_delete(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse accept mode (default "text")
        let accept = args.get("accept").map(|s| s.as_str()).unwrap_or("text");
        if !["json", "text", "bytes"].contains(&accept) {
            writeln!(io.stderr, "unsupported accept value: {}, defaulting to text", accept)?;
            // Fall back to text instead of erroring out
        }

        // Parse timeout (default 30 seconds)
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30_000);

        // Start with the original URL and apply query if provided
        let mut request_url = self.url.clone();
        if let Some(query) = args.get("query") {
            if !query.is_empty() {
                request_url = Self::apply_query(request_url, query);
            }
        }

        // Build client with timeout
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the DELETE request
        let mut request_builder = client.delete(request_url.clone());

        // Apply headers from headers parameter
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(_e) => {
                    // Instead of erroring, ignore malformed segments per requirements
                    HashMap::new()
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Handle request body with body taking precedence over body_file per requirements
        let request_body: Vec<u8> = if let Some(body) = args.get("body") {
            // body parameter wins over body_file
            body.as_bytes().to_vec()
        } else if let Some(body_file) = args.get("body_file") {
            if !body_file.is_empty() {
                match std::fs::read(body_file) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        writeln!(io.stderr, "failed to read body_file '{}': {}", body_file, e)?;
                        return Ok(Status::err(1, format!("failed to read body_file: {}", e)));
                    }
                }
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Set Content-Type header if body is present and content_type is specified
        // content_type argument should override any Content-Type from headers
        if !request_body.is_empty() {
            if let Some(content_type) = args.get("content_type") {
                if !content_type.is_empty() {
                    request_builder = request_builder.header("Content-Type", content_type);
                }
            } else {
                // Default Content-Type if body is present and content_type is missing
                request_builder = request_builder.header("Content-Type", "application/octet-stream");
            }
        }

        // Attach the body to the request
        if !request_body.is_empty() {
            request_builder = request_builder.body(request_body);
        }

        // Execute the DELETE request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                let error_message = if e.is_timeout() {
                    "http delete error: connection timed out".to_string()
                } else if e.is_connect() {
                    "http delete error: connection refused".to_string()
                } else {
                    format!("http delete error: {}", e)
                };
                
                writeln!(io.stderr, "{}", error_message)?;
                return Ok(Status::err(2, error_message));
            }
        };

        // Extract response data
        let status_code = response.status().as_u16();
        let is_ok = response.status().is_success();
        let status_reason = response.status().canonical_reason().unwrap_or("Unknown");

        // Get response body
        let body_bytes = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                let error_msg = format!("Failed to read response body: {}", e);
                writeln!(io.stderr, "{}", error_msg)?;
                return Ok(Status::err(1, error_msg));
            }
        };

        // Handle response based on accept mode
        let final_accept = if ["json", "text", "bytes"].contains(&accept) {
            accept
        } else {
            "text" // fallback for unsupported accept values
        };

        match final_accept {
            "json" => {
                // Try to parse response body as JSON
                match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                    Ok(json_value) => {
                        // Pretty-print the JSON
                        let pretty_json = serde_json::to_string_pretty(&json_value)?;
                        write!(io.stdout, "{}", pretty_json)?;
                    }
                    Err(_) => {
                        // Wrap in envelope as specified in requirements
                        let envelope = json!({
                            "status": { "code": status_code, "ok": is_ok },
                            "body": String::from_utf8_lossy(&body_bytes).to_string()
                        });
                        write!(io.stdout, "{}", serde_json::to_string_pretty(&envelope)?)?;
                    }
                }
            }
            "text" => {
                // Interpret body as UTF-8 (lossy if needed) and write directly to stdout
                let text = String::from_utf8_lossy(&body_bytes);
                write!(io.stdout, "{}", text)?;
            }
            "bytes" => {
                // Write raw body bytes to stdout with no transformation
                io.stdout.write_all(&body_bytes)?;
            }
            _ => unreachable!(),
        }

        // Return status based on HTTP response code
        if is_ok {
            Ok(Status::ok())
        } else {
            let reason = format!("HTTP {} {}", status_code, status_reason);
            Ok(Status::err(status_code as i32, reason))
        }
    }

    fn verb_to_method(verb: &str) -> Result<Method> {
        match verb {
            "get" => Ok(Method::GET),
            "head" => Ok(Method::HEAD),
            "post" => Ok(Method::POST),
            "put" => Ok(Method::PUT),
            "patch" => Ok(Method::PATCH),
            "delete" => Ok(Method::DELETE),
            _ => bail!("Unsupported HTTP verb: {}", verb),
        }
    }

    fn execute_request(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Status> {
        let method = Self::verb_to_method(verb)?;
        
        // Parse timeout
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(30_000);

        // Start with the original URL
        let mut request_url = self.url.clone();
        
        // Merge query parameters if provided
        if let Some(query) = args.get("query") {
            request_url = Self::merge_query_params(request_url, query)
                .context("Failed to merge query parameters")?;
        }

        // Build client with timeout
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the request
        let mut request_builder = client.request(method.clone(), request_url.clone());

        // Add headers if provided
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(e) => {
                    return Ok(Status::err(1, format!("invalid headers: {}", e)));
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Handle body content for non-GET/HEAD requests
        if method != Method::GET && method != Method::HEAD {
            if let Some(json_body) = args.get("json") {
                // JSON takes precedence over body
                request_builder = request_builder
                    .header("Content-Type", "application/json")
                    .body(json_body.clone());
            } else if let Some(body) = args.get("body") {
                request_builder = request_builder.body(body.clone());
            }
        }

        // Execute the request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                // Handle network errors (timeouts, connection failures, etc.)
                let error_json = json!({
                    "url": request_url.to_string(),
                    "method": method.to_string(),
                    "error": format!("Request failed: {}", e)
                });
                
                write!(io.stdout, "{}", error_json)?;
                
                let code = if e.is_timeout() { 124 } else { 1 };
                return Ok(Status::err(code, format!("Request failed: {}", e)));
            }
        };

        // Extract response data
        let status_code = response.status().as_u16();
        let is_ok = response.status().is_success();
        
        // Extract headers
        let mut response_headers = HashMap::new();
        for (name, value) in response.headers() {
            let header_name = name.to_string();
            let header_value = value.to_str().unwrap_or("<invalid-utf8>").to_string();
            
            response_headers
                .entry(header_name)
                .or_insert_with(Vec::new)
                .push(header_value);
        }

        // Get response body
        let body_bytes = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                let error_json = json!({
                    "url": request_url.to_string(),
                    "method": method.to_string(),
                    "error": format!("Failed to read response body: {}", e)
                });
                
                write!(io.stdout, "{}", error_json)?;
                return Ok(Status::err(1, format!("Failed to read response body: {}", e)));
            }
        };

        // Determine body_text and body_base64
        let (body_text, body_base64) = if body_bytes.is_empty() {
            (json!(null), json!(null))
        } else {
            let body_text_value = match std::str::from_utf8(&body_bytes) {
                Ok(text) => json!(text),
                Err(_) => json!(null),
            };
            
            let body_base64_value = json!(BASE64_STANDARD.encode(&body_bytes));
            
            (body_text_value, body_base64_value)
        };

        // Build response JSON
        let response_json = json!({
            "url": request_url.to_string(),
            "method": method.to_string(),
            "status": status_code,
            "ok": is_ok,
            "headers": response_headers,
            "body_text": body_text,
            "body_base64": body_base64
        });

        // Write JSON response to stdout
        write!(io.stdout, "{}", response_json)?;

        // Always return ok for successful requests, even with 4xx/5xx status codes
        Ok(Status::ok())
    }

    /// Implements the options verb according to spec
    fn verb_options(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse timeout_ms (default 10 seconds)
        let timeout_ms = match args.get("timeout_ms") {
            Some(timeout_str) => {
                match timeout_str.parse::<u64>() {
                    Ok(ms) => ms,
                    Err(_) => {
                        return Ok(Status::err(1, format!("invalid timeout_ms: {}", timeout_str)));
                    }
                }
            }
            None => 10_000,
        };

        // Parse follow_redirects (default true)
        let follow_redirects = match args.get("follow_redirects") {
            Some(redirect_str) => !redirect_str.to_lowercase().eq("false"),
            None => true,
        };

        // Parse include_body (default false)
        let include_body = match args.get("include_body") {
            Some(body_str) => body_str.to_lowercase().eq("true"),
            None => false,
        };

        // Build client with timeout and redirect policy
        let mut client_builder = Client::builder()
            .timeout(Duration::from_millis(timeout_ms));
        
        if !follow_redirects {
            client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
        }
        
        let client = client_builder
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the OPTIONS request with the full URL (including query)
        let mut request_builder = client.request(Method::OPTIONS, self.url.clone());

        // Parse and apply headers if provided
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(_) => {
                    // Ignore malformed headers but continue (as per requirements)
                    HashMap::new()
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Execute the OPTIONS request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = if e.is_timeout() {
                    "request timed out".to_string()
                } else if e.is_connect() {
                    "connection failed".to_string()
                } else {
                    format!("network error: {}", e)
                };
                return Ok(Status::err(1, error_msg));
            }
        };

        // Extract response data
        let final_url = response.url().to_string();
        let status_code = response.status().as_u16();
        let reason = response.status().canonical_reason().unwrap_or("").to_string();

        // Extract headers (lowercase keys)
        let mut response_headers = HashMap::new();
        for (name, value) in response.headers() {
            let header_name = name.to_string().to_lowercase();
            let header_value = value.to_str().unwrap_or("<invalid-utf8>").to_string();
            
            // For multi-valued headers, join with ", "
            if let Some(existing) = response_headers.get(&header_name) {
                response_headers.insert(header_name, format!("{}, {}", existing, header_value));
            } else {
                response_headers.insert(header_name, header_value);
            }
        }

        // Parse allowed methods from Allow header
        let allowed_methods: Vec<String> = response_headers
            .get("allow")
            .map(|allow_header| {
                allow_header
                    .split(',')
                    .map(|method| method.trim().to_string())
                    .collect()
            })
            .unwrap_or_else(Vec::new);

        // Read response body
        let body_bytes = response.bytes().unwrap_or_default();
        let has_body = !body_bytes.is_empty();
        
        // Build JSON response
        let mut response_json = json!({
            "url": final_url,
            "status": status_code,
            "reason": reason,
            "backend": "reqwest",
            "headers": response_headers,
            "allowed_methods": allowed_methods,
            "has_body": has_body
        });

        // Include body if requested and present
        if include_body && has_body {
            let body_text = String::from_utf8_lossy(&body_bytes).to_string();
            if let Some(obj) = response_json.as_object_mut() {
                obj.insert("body".to_string(), json!(body_text));
            }
        }

        // Write JSON to stdout
        write!(io.stdout, "{}", serde_json::to_string(&response_json)?)?;

        // Return status based on HTTP response code
        if (200..=399).contains(&status_code) {
            Ok(Status::ok())
        } else {
            Ok(Status::err(
                status_code as i32,
                format!("HTTP {}", status_code)
            ))
        }
    }

    /// Implements the preflight verb for CORS preflight requests
    fn verb_preflight(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse timeout (default 5000ms)
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5_000);

        // Build client with timeout
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the OPTIONS request
        let mut request_builder = client.request(Method::OPTIONS, self.url.clone());

        // Add CORS preflight headers if provided
        if let Some(origin) = args.get("origin") {
            request_builder = request_builder.header("Origin", origin);
        }

        if let Some(method) = args.get("method") {
            request_builder = request_builder.header("Access-Control-Request-Method", method);
        }

        if let Some(request_headers) = args.get("request_headers") {
            let normalized_headers = Self::parse_request_headers_arg(request_headers);
            if !normalized_headers.is_empty() {
                request_builder = request_builder.header("Access-Control-Request-Headers", &normalized_headers);
            }
        }

        // Add additional headers if provided
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(_) => {
                    // Ignore malformed headers but continue
                    HashMap::new()
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Execute the request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                // Build error response JSON
                let error_json = json!({
                    "url": self.url.to_string(),
                    "method": "OPTIONS",
                    "ok": false,
                    "error": if e.is_timeout() {
                        "timeout"
                    } else if e.is_connect() {
                        "connection refused"
                    } else {
                        "network error"
                    },
                    "status": null,
                    "cors": null,
                    "raw_headers": {}
                });
                
                write!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, format!("Request failed: {}", e)));
            }
        };

        // Extract response data
        let final_url = response.url().to_string();
        let status_code = response.status().as_u16();
        let is_ok = status_code >= 200 && status_code < 300;

        // Extract headers (case-insensitive lookup for CORS headers)
        let mut raw_headers = HashMap::new();
        let mut cors_headers = HashMap::new();
        
        for (name, value) in response.headers() {
            let header_name = name.to_string().to_lowercase();
            let header_value = value.to_str().unwrap_or("<invalid-utf8>").to_string();
            
            // Store in raw_headers with lowercase key
            if let Some(existing) = raw_headers.get(&header_name) {
                raw_headers.insert(header_name.clone(), format!("{}, {}", existing, header_value));
            } else {
                raw_headers.insert(header_name.clone(), header_value.clone());
            }
            
            // Extract CORS-specific headers
            match header_name.as_str() {
                "access-control-allow-origin" => {
                    cors_headers.insert("allowed_origins", header_value);
                }
                "access-control-allow-methods" => {
                    cors_headers.insert("allowed_methods", header_value);
                }
                "access-control-allow-headers" => {
                    cors_headers.insert("allowed_headers", header_value);
                }
                "access-control-expose-headers" => {
                    cors_headers.insert("exposed_headers", header_value);
                }
                "access-control-allow-credentials" => {
                    cors_headers.insert("allow_credentials", header_value);
                }
                "access-control-max-age" => {
                    cors_headers.insert("max_age", header_value);
                }
                _ => {}
            }
        }

        // Parse CORS data
        let cors_data = json!({
            "allowed_origins": cors_headers.get("allowed_origins")
                .map(|v| if v == "*" { vec!["*".to_string()] } else { Self::parse_header_list(v) })
                .unwrap_or_default(),
            "allowed_methods": cors_headers.get("allowed_methods")
                .map(|v| Self::parse_header_list(v))
                .unwrap_or_default(),
            "allowed_headers": cors_headers.get("allowed_headers")
                .map(|v| Self::parse_header_list(v))
                .unwrap_or_default(),
            "exposed_headers": cors_headers.get("exposed_headers")
                .map(|v| Self::parse_header_list(v))
                .unwrap_or_default(),
            "allow_credentials": cors_headers.get("allow_credentials")
                .map(|v| Self::parse_bool_header(v))
                .unwrap_or(false),
            "max_age_seconds": cors_headers.get("max_age")
                .and_then(|v| Self::parse_int_header(v))
        });

        // Build success response JSON
        let response_json = json!({
            "url": final_url,
            "method": "OPTIONS",
            "status": status_code,
            "ok": is_ok,
            "cors": cors_data,
            "raw_headers": raw_headers
        });

        // Write JSON to stdout
        write!(io.stdout, "{}", serde_json::to_string(&response_json)?)?;

        // Return appropriate status
        if is_ok {
            Ok(Status::ok())
        } else {
            Ok(Status::err(
                status_code as i32,
                format!("HTTP {}", status_code)
            ))
        }
    }

    /*
    ### Copilot Requirements: `http://…json` verb

    **Context**

    * This project is an OS/2-inspired shell implemented in Rust.
    * Handles are registered in a central `Registry` and must implement the shared `Handle` trait from `core::registry`.
    * We already have (or will have) an `HttpHandle` in `src/handles/httph.rs` that is registered for both `http` and `https` schemes.
    * The global CLI in `main.rs` already supports `--json-pretty` which will pretty-print *any* valid JSON output emitted by a verb; this verb should output valid JSON so the flag can work.

    **Goal**

    Implement a `json` verb on the `http://` / `https://` handle that:

    * Sends an HTTP request with a specified method and optional body/headers.
    * Assumes JSON semantics:

      * Automatically sets `Accept: application/json` unless overridden.
      * For methods with a body (POST/PUT/PATCH/DELETE), sets `Content-Type: application/json` by default when `body` is non-empty, unless overridden.
    * Parses the HTTP response body as JSON when possible and re-emits it as canonical JSON to `stdout` so that:

      * It integrates cleanly with the shell's typed pipeline model.
      * `--json-pretty` can pretty-print the result.
    * Returns a `Status` that reflects success or failure based on the HTTP status code and JSON parsing.
    */

    /// Implements the json verb according to the specification
    /// Returns a structured JSON envelope with url, status, status_text, headers, and body
    fn verb_json(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse method argument (default to "GET")
        let method_str = args.get("method").map(|s| s.as_str()).unwrap_or("GET");
        let method_upper = method_str.to_uppercase();
        
        // Validate method
        let method = match method_upper.as_str() {
            "GET" => reqwest::Method::GET,
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            "OPTIONS" => reqwest::Method::OPTIONS,
            _ => {
                return Ok(Status::err(1, format!("Unsupported method: {}", method_str)));
            }
        };

        // Parse timeout (default 10 seconds)
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10_000);

        // Parse accept mode (default "json")
        let accept_mode = args.get("accept").map(|s| s.as_str()).unwrap_or("json");
        if !["json", "text", "bytes"].contains(&accept_mode) {
            return Ok(Status::err(1, format!("Invalid accept mode: {}. Must be json, text, or bytes", accept_mode)));
        }

        // Parse body and content_type
        let body = args.get("body").unwrap_or(&String::new()).clone();
        let content_type = if let Some(ct) = args.get("content_type") {
            Some(ct.clone())
        } else if !body.is_empty() {
            Some("application/json".to_string())
        } else {
            None
        };

        // Build client with timeout
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the request
        let mut request_builder = client.request(method.clone(), self.url.clone());

        // Parse and apply headers from headers parameter
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(e) => {
                    return Ok(Status::err(1, format!("invalid headers: {}", e)));
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Set Content-Type header if specified
        if let Some(ct) = content_type {
            request_builder = request_builder.header("Content-Type", &ct);
        }

        // Add body if provided and method supports it
        if !body.is_empty() && matches!(method, reqwest::Method::POST | reqwest::Method::PUT | reqwest::Method::PATCH | reqwest::Method::DELETE) {
            request_builder = request_builder.body(body);
        }

        // Execute the request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                // Create error envelope
                let error_msg = if e.is_timeout() {
                    "Request timed out"
                } else if e.is_connect() {
                    "Connection failed" 
                } else {
                    "Network error"
                };

                let error_envelope = json!({
                    "url": self.url.to_string(),
                    "status": 0,
                    "status_text": "",
                    "headers": {},
                    "body": {
                        "type": "text",
                        "value": ""
                    },
                    "error": error_msg
                });

                write!(io.stdout, "{}", serde_json::to_string(&error_envelope)?)?;
                return Ok(Status::err(1, error_msg.to_string()));
            }
        };

        // Extract response details
        let final_url = response.url().to_string();
        let status_code = response.status().as_u16();
        let status_text = response.status().canonical_reason().unwrap_or("").to_string();

        // Extract headers - convert to lowercase keys with arrays of values
        let mut headers = std::collections::HashMap::<String, Vec<String>>::new();
        for (name, value) in response.headers() {
            let header_name = name.to_string().to_lowercase();
            let header_value = value.to_str().unwrap_or("<invalid-utf8>").to_string();
            
            headers
                .entry(header_name)
                .or_insert_with(Vec::new)
                .push(header_value);
        }

        // Read response body bytes
        let body_bytes = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                let error_envelope = json!({
                    "url": final_url,
                    "status": status_code,
                    "status_text": status_text,
                    "headers": headers,
                    "body": {
                        "type": "text",
                        "value": ""
                    },
                    "error": format!("Failed to read response body: {}", e)
                });

                write!(io.stdout, "{}", serde_json::to_string(&error_envelope)?)?;
                return Ok(Status::err(1, format!("Failed to read response body: {}", e)));
            }
        };

        // Process body according to accept mode
        let body_field = match accept_mode {
            "json" => {
                // Try to parse as JSON first
                match serde_json::from_slice::<serde_json::Value>(&body_bytes) {
                    Ok(json_value) => json!({
                        "type": "json",
                        "value": json_value
                    }),
                    Err(_) => {
                        // Fallback to text for invalid JSON
                        let text_value = String::from_utf8_lossy(&body_bytes).to_string();
                        json!({
                            "type": "text", 
                            "value": text_value
                        })
                    }
                }
            }
            "text" => {
                let text_value = String::from_utf8_lossy(&body_bytes).to_string();
                json!({
                    "type": "text",
                    "value": text_value
                })
            }
            "bytes" => {
                let base64_value = BASE64_STANDARD.encode(&body_bytes);
                json!({
                    "type": "bytes",
                    "base64": base64_value
                })
            }
            _ => unreachable!(), // Already validated above
        };

        // Create the response envelope
        let response_envelope = json!({
            "url": final_url,
            "status": status_code,
            "status_text": status_text,
            "headers": headers,
            "body": body_field
        });

        // Write JSON envelope to stdout
        write!(io.stdout, "{}", serde_json::to_string(&response_envelope)?)?;

        // Always return Status::ok() since we successfully created the envelope
        // The HTTP status is captured in the JSON response
        Ok(Status::ok())
    }

    /// Implements the headers verb according to spec
    fn verb_headers(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Parse method argument (default to "GET")
        let method_str = args.get("method").map(|s| s.as_str()).unwrap_or("GET");
        let method_upper = method_str.to_uppercase();
        
        // Validate method
        let method = match method_upper.as_str() {
            "GET" => Method::GET,
            "HEAD" => Method::HEAD,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "PATCH" => Method::PATCH,
            "DELETE" => Method::DELETE,
            "OPTIONS" => Method::OPTIONS,
            _ => {
                let error_json = json!({
                    "url": self.url.to_string(),
                    "error": {
                        "kind": "invalid_argument",
                        "message": format!("Unsupported method: {}. Supported methods: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS", method_str)
                    }
                });
                write!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(2, format!("Unsupported method: {}", method_str)));
            }
        };

        // Parse timeout (default 10 seconds)
        let timeout_ms = args
            .get("timeout_ms")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(10_000);

        // Parse follow_redirects (default true)
        let follow_redirects = args
            .get("follow_redirects")
            .map(|s| s.to_lowercase() != "false")
            .unwrap_or(true);

        // Start with the original URL
        let mut request_url = self.url.clone();
        
        // Merge query parameters if provided
        if let Some(query) = args.get("query") {
            request_url = Self::apply_query(request_url, query);
        }

        // Build client with timeout and redirect policy
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms))
            .redirect(if follow_redirects {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .build()
            .context("Failed to create HTTP client")?;

        // Start building the request
        let mut request_builder = client.request(method, request_url.clone());

        // Parse and apply headers from headers parameter
        if let Some(headers_str) = args.get("headers") {
            let headers = match Self::parse_headers(headers_str) {
                Ok(h) => h,
                Err(e) => {
                    let error_json = json!({
                        "url": self.url.to_string(),
                        "error": {
                            "kind": "invalid_argument",
                            "message": format!("invalid headers: {}", e)
                        }
                    });
                    write!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                    return Ok(Status::err(2, format!("invalid headers: {}", e)));
                }
            };
            for (key, value) in headers {
                request_builder = request_builder.header(&key, &value);
            }
        }

        // Execute the request
        let response = match request_builder.send() {
            Ok(resp) => resp,
            Err(e) => {
                // Determine error kind based on the error type
                let (kind, message) = if e.is_timeout() {
                    ("timeout", "Request timed out".to_string())
                } else if e.is_connect() {
                    ("network", "Connection failed".to_string()) 
                } else if e.is_request() {
                    ("invalid_url", "Invalid URL or request".to_string())
                } else {
                    ("other", format!("Request failed: {}", e))
                };

                let error_json = json!({
                    "url": self.url.to_string(),
                    "error": {
                        "kind": kind,
                        "message": message
                    }
                });

                write!(io.stdout, "{}", serde_json::to_string(&error_json)?)?;
                return Ok(Status::err(1, message));
            }
        };

        // Extract response details
        let final_url = response.url().to_string();
        let status_code = response.status().as_u16();
        let status_text = response.status().canonical_reason().unwrap_or("").to_string();

        // Extract headers - convert to lowercase keys with arrays of values
        let mut headers = std::collections::HashMap::<String, Vec<String>>::new();
        for (name, value) in response.headers() {
            let header_name = name.to_string().to_lowercase();
            let header_value = value.to_str().unwrap_or("<invalid-utf8>").to_string();
            
            headers
                .entry(header_name)
                .or_insert_with(Vec::new)
                .push(header_value);
        }

        // Create the response JSON
        let response_json = json!({
            "url": final_url,
            "status": status_code,
            "status_text": status_text,
            "headers": headers
        });

        // Write JSON response to stdout
        write!(io.stdout, "{}", serde_json::to_string(&response_json)?)?;

        // Always return Status::ok() for successful HTTP transport
        // The HTTP status code is captured in the JSON response
        Ok(Status::ok())
    }
}

impl Handle for HttpHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &["get", "head", "post", "put", "patch", "delete", "options", "preflight", "json", "headers"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "get" => self.verb_get(args, io),
            "head" => self.verb_head(args, io),
            "post" => self.verb_post(args, io),
            "put" => self.verb_put(args, io),
            "patch" => self.verb_patch(args, io),
            "delete" => self.verb_delete(args, io),
            "options" => self.verb_options(args, io),
            "preflight" => self.verb_preflight(args, io),
            "json" => self.verb_json(args, io),
            "headers" => self.verb_headers(args, io),
            _ => bail!("unknown verb for http://: {}", verb),
        }
    }
}
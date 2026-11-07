use anyhow::Result;
use base64::prelude::*;
use reqwest::Method;
use reqwest::StatusCode;
use reqwest::blocking::{Client, Response};
use reqwest::header::{
    ACCEPT, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, CONTENT_TYPE, HeaderMap,
    HeaderName, HeaderValue, ORIGIN,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Duration;
use url::Url;

use crate::core::{
    help::{HandleHelp, VerbDetail, VerbHelp},
    registry::{Args, Handle, IoStreams},
    status::{Status, error_json, exit},
};

pub fn register(reg: &mut crate::core::Registry) {
    reg.register_scheme("http", |u| Ok(Box::new(HttpHandle::from_url(u)?)));
    reg.register_scheme("https", |u| Ok(Box::new(HttpHandle::from_url(u)?)));
}

/// Builds the help metadata for one of the two schemes served by
/// `HttpHandle`, so usage lines and examples name the right scheme.
macro_rules! http_handle_help {
    ($scheme:literal) => {
        HandleHelp {
            description: concat!(
                "The ",
                $scheme,
                " handle sends HTTP requests to web servers and APIs \
                using the reqwest client. Verbs map to request methods, plus helpers \
                for CORS preflight checks, JSON response envelopes, and header \
                inspection. The stage URL is the request URL itself, such as ",
                $scheme,
                "://api.example.com/v1/users, followed by the verb."
            ),
            usage: concat!(
                "resh ",
                $scheme,
                "://<host>[:<port>]/<path>.<verb>[(key=value,...)]"
            ),
            verbs: &[
                VerbHelp {
                    name: "get",
                    definition: "Sends a GET request and prints the response body as text, \
                        raw bytes, or a JSON envelope with status and headers.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.get [accept=text|json|bytes]\n",
                            "  [query=<k=v&...>] [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!(
                            "resh ",
                            $scheme,
                            "://api.example.com/v1/users/42.get accept=json"
                        ),
                        example_output: Some(
                            r#"{
  "body": {
    "id": 42,
    "name": "alice"
  },
  "body_text": "{\"id\":42,\"name\":\"alice\"}",
  "headers": {
    "content-length": [
      "24"
    ],
    "content-type": [
      "application/json"
    ]
  },
  "method": "GET",
  "ok": true,
  "status": 200
}

Shown for accept=json with --json-pretty. The default accept=text prints
the response body as is."#,
                        ),
                    }),
                },
                VerbHelp {
                    name: "head",
                    definition: "Sends a HEAD request and reports the status and response \
                        headers as JSON.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.head [accept=json|text|bytes]\n",
                            "  [query=<k=v&...>] [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!("resh ", $scheme, "://example.com/index.html.head"),
                        example_output: Some(concat!(
                            r#"{
  "headers": {
    "content-length": "1256",
    "content-type": "text/html; charset=UTF-8",
    "last-modified": "Mon, 13 Jan 2025 20:11:20 GMT"
  },
  "ok": true,
  "reason": "OK",
  "status": 200,
  "url": ""#,
                            $scheme,
                            r#"://example.com/index.html"
}

Shown with --json-pretty."#
                        )),
                    }),
                },
                VerbHelp {
                    name: "headers",
                    definition: "Sends a request, GET by default, and reports the status and \
                        response headers as JSON without the body.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.headers [method=<method>]\n",
                            "  [query=<k=v&...>] [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!("resh ", $scheme, "://example.com.headers method=HEAD"),
                        example_output: Some(concat!(
                            r#"{
  "headers": {
    "content-type": [
      "text/html"
    ],
    "server": [
      "nginx"
    ]
  },
  "status": 200,
  "status_text": "OK",
  "url": ""#,
                            $scheme,
                            r#"://example.com/"
}

Shown with --json-pretty."#
                        )),
                    }),
                },
                VerbHelp {
                    name: "options",
                    definition: "Sends an OPTIONS request and reports the allowed methods, \
                        status, and response headers as JSON.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.options [include_body=true|false]\n",
                            "  [query=<k=v&...>] [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!("resh ", $scheme, "://api.example.com/v1/users.options"),
                        example_output: Some(concat!(
                            r#"{
  "allowed_methods": [
    "GET",
    "POST",
    "OPTIONS"
  ],
  "backend": "reqwest",
  "has_body": false,
  "headers": {
    "allow": "GET, POST, OPTIONS",
    "content-length": "0"
  },
  "reason": "No Content",
  "status": 204,
  "url": ""#,
                            $scheme,
                            r#"://api.example.com/v1/users"
}

Shown with --json-pretty. With include_body=true a non-empty body is
added as the body field."#
                        )),
                    }),
                },
                VerbHelp {
                    name: "preflight",
                    definition: "Sends a CORS preflight OPTIONS request and reports the \
                        parsed Access-Control response headers as JSON.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.preflight [origin=<origin>]\n",
                            "  [method=<method>] [request_headers=<name,...>] [query=<k=v&...>]\n",
                            "  [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!(
                            "resh ",
                            $scheme,
                            "://api.example.com/users.preflight origin=https://example.org"
                        ),
                        example_output: Some(concat!(
                            r#"{
  "cors": {
    "allow_credentials": false,
    "allowed_headers": [
      "Content-Type"
    ],
    "allowed_methods": [
      "GET",
      "POST"
    ],
    "allowed_origins": [
      "https://example.org"
    ],
    "exposed_headers": [],
    "max_age_seconds": 600
  },
  "method": "OPTIONS",
  "ok": true,
  "raw_headers": {
    "access-control-allow-headers": "Content-Type",
    "access-control-allow-methods": "GET, POST",
    "access-control-allow-origin": "https://example.org",
    "access-control-max-age": "600"
  },
  "status": 204,
  "url": ""#,
                            $scheme,
                            r#"://api.example.com/users"
}

Shown with --json-pretty."#
                        )),
                    }),
                },
                VerbHelp {
                    name: "json",
                    definition: "Sends a request with any method and prints a JSON envelope \
                        with the status, headers, and the body parsed as JSON when possible.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.json [method=<method>] [body=<data>]\n",
                            "  [content_type=<type>] [accept=json|text|bytes] [query=<k=v&...>]\n",
                            "  [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!("resh ", $scheme, "://api.example.com/v1/users/42.json"),
                        example_output: Some(concat!(
                            r#"{
  "body": {
    "type": "json",
    "value": {
      "id": 42,
      "name": "alice"
    }
  },
  "headers": {
    "content-type": [
      "application/json"
    ]
  },
  "status": 200,
  "status_text": "OK",
  "url": ""#,
                            $scheme,
                            r#"://api.example.com/v1/users/42"
}

Shown with --json-pretty. A body that is not JSON has type text, and
accept=bytes reports type bytes with a base64 field."#
                        )),
                    }),
                },
                VerbHelp {
                    name: "post",
                    definition: "Sends a POST request with an inline or file body and prints \
                        the raw response body.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.post [body=<data> | body_file=<path>]\n",
                            "  [content_type=<type>] [query=<k=v&...>]\n",
                            "  [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!(
                            "resh ",
                            $scheme,
                            "://api.example.com/v1/users.post body='{\"name\":\"alice\"}'"
                        ),
                        example_output: Some(
                            r#"{"id":43,"name":"alice"}

The response body is printed exactly as the server sent it."#,
                        ),
                    }),
                },
                VerbHelp {
                    name: "put",
                    definition: "Sends a PUT request with an inline or file body and prints \
                        the response body as text, raw bytes, or a JSON envelope.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.put [body=<data> | body_file=<path>]\n",
                            "  [content_type=<type>] [accept=text|json|bytes] [query=<k=v&...>]\n",
                            "  [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!(
                            "resh ",
                            $scheme,
                            "://api.example.com/v1/users/42.put body='{\"name\":\"alice\"}'"
                        ),
                        example_output: Some(
                            r#"{"id":42,"name":"alice"}

Shown for the default accept=text, which prints the response body."#,
                        ),
                    }),
                },
                VerbHelp {
                    name: "patch",
                    definition: "Sends a PATCH request with an inline or file body and prints \
                        the response body as raw bytes, text, or compact JSON.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.patch [body=<data> | body_file=<path>]\n",
                            "  [content_type=<type>] [accept=bytes|text|json] [query=<k=v&...>]\n",
                            "  [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!(
                            "resh ",
                            $scheme,
                            "://api.example.com/v1/users/42.patch body='{\"name\":\"bob\"}'"
                        ),
                        example_output: Some(
                            r#"{"id":42,"name":"bob"}

Shown for the default accept=bytes, which prints the response body."#,
                        ),
                    }),
                },
                VerbHelp {
                    name: "delete",
                    definition: "Sends a DELETE request, optionally with a body, and prints \
                        the response body as text, raw bytes, or pretty JSON.",
                    detail: Some(VerbDetail {
                        usage: concat!(
                            "resh ",
                            $scheme,
                            "://<host>/<path>.delete [body=<data> | body_file=<path>]\n",
                            "  [content_type=<type>] [accept=text|json|bytes] [query=<k=v&...>]\n",
                            "  [headers=<Name:value;...>] [timeout_ms=<ms>]\n",
                            "  [follow_redirects=true|false] [allow_insecure=true|false]"
                        ),
                        example: concat!(
                            "resh ",
                            $scheme,
                            "://api.example.com/v1/users/42.delete accept=json"
                        ),
                        example_output: Some(
                            r#"{
  "deleted": true,
  "id": 42
}

Shown for a JSON response body, which the verb pretty-prints. A body that
is not JSON is wrapped in an object with body and status fields."#,
                        ),
                    }),
                },
            ],
        }
    };
}

/// Metadata for `resh http --help` and `resh http <verb> --help`.
static HTTP_HELP: HandleHelp = http_handle_help!("http");

/// Metadata for `resh https --help` and `resh https <verb> --help`.
static HTTPS_HELP: HandleHelp = http_handle_help!("https");

/// Options every verb accepts.
const COMMON_ARGS: [&str; 5] = [
    "query",
    "headers",
    "timeout_ms",
    "follow_redirects",
    "allow_insecure",
];

/// The arguments each verb accepts, besides `COMMON_ARGS`. Help usage lists
/// exactly these plus the common ones, and anything else is refused (exit 2)
/// before a request is sent.
const GET_ARGS: &[&str] = &["accept"];
const HEAD_ARGS: &[&str] = &["accept"];
const HEADERS_ARGS: &[&str] = &["method"];
const OPTIONS_ARGS: &[&str] = &["include_body"];
const PREFLIGHT_ARGS: &[&str] = &["origin", "method", "request_headers"];
const JSON_ARGS: &[&str] = &["method", "body", "content_type", "accept"];
const POST_ARGS: &[&str] = &["body", "body_file", "content_type"];
const BODY_ACCEPT_ARGS: &[&str] = &["body", "body_file", "content_type", "accept"];

/// Verb-specific arguments of `verb`, or `None` for an unknown verb.
fn verb_args(verb: &str) -> Option<&'static [&'static str]> {
    Some(match verb {
        "get" => GET_ARGS,
        "head" => HEAD_ARGS,
        "headers" => HEADERS_ARGS,
        "options" => OPTIONS_ARGS,
        "preflight" => PREFLIGHT_ARGS,
        "json" => JSON_ARGS,
        "post" => POST_ARGS,
        "put" | "patch" | "delete" => BODY_ACCEPT_ARGS,
        _ => return None,
    })
}

/// Default whole-request timeout of each verb, in milliseconds.
fn default_timeout_ms(verb: &str) -> u64 {
    match verb {
        "preflight" => 5_000,
        "put" | "patch" | "delete" => 30_000,
        _ => 10_000,
    }
}

/// Request headers resh never forwards from `headers=`: the client sets
/// them from the URL and body.
const DROPPED_HEADERS: [&str; 4] = ["host", "content-length", "connection", "transfer-encoding"];

/// Every error code the handle reports (on stderr as
/// `Error: [<code>] <message>`, and as `"error": {"code", "message"}` in the
/// JSON of `headers`, `json` and `preflight`). Both schemes use the `http.`
/// prefix; docs/Network_RemoteOperations/http.md documents each code.
#[cfg(test)]
pub(crate) const ERROR_CODES: [&str; 11] = [
    UNKNOWN_VERB,
    UNKNOWN_ARGUMENT,
    INVALID_ARGUMENT,
    BODY_FILE_UNREADABLE,
    CLIENT_FAILED,
    CONNECTION_FAILED,
    TIMEOUT,
    REDIRECT_FAILED,
    REQUEST_FAILED,
    STATUS_ERROR,
    INVALID_JSON_RESPONSE,
];
const UNKNOWN_VERB: &str = "http.unknown_verb";
const UNKNOWN_ARGUMENT: &str = "http.unknown_argument";
const INVALID_ARGUMENT: &str = "http.invalid_argument";
const BODY_FILE_UNREADABLE: &str = "http.body_file_unreadable";
const CLIENT_FAILED: &str = "http.client_failed";
const CONNECTION_FAILED: &str = "http.connection_failed";
const TIMEOUT: &str = "http.timeout";
const REDIRECT_FAILED: &str = "http.redirect_failed";
const REQUEST_FAILED: &str = "http.request_failed";
const STATUS_ERROR: &str = "http.status_error";
const INVALID_JSON_RESPONSE: &str = "http.invalid_json_response";

/// Usage error (exit 2): an invalid argument value; nothing was sent.
fn usage(msg: impl AsRef<str>) -> Status {
    Status::coded(exit::USAGE, INVALID_ARGUMENT, msg)
}

/// The accepted argument closest to `bad` (edit distance at most 2, or a
/// case-only difference), for a "did you mean" hint.
fn suggest<'a>(bad: &str, allowed: &[&'a str]) -> Option<&'a str> {
    fn distance(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1];
            for (j, cb) in b.iter().enumerate() {
                let cost = usize::from(ca != *cb);
                cur.push((prev[j] + cost).min(prev[j + 1] + 1).min(cur[j] + 1));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    let lower = bad.to_ascii_lowercase().replace('-', "_");
    allowed
        .iter()
        .map(|a| (distance(&lower, a), *a))
        .filter(|(d, _)| *d <= 2)
        .min_by_key(|(d, _)| *d)
        .map(|(_, a)| a)
}

/// Refuses an argument `verb` does not take (exit 2), naming it and
/// suggesting the closest accepted one.
fn check_args(scheme: &str, verb: &str, specific: &[&str], args: &Args) -> Option<Status> {
    let allowed: Vec<&str> = specific.iter().chain(COMMON_ARGS.iter()).copied().collect();
    let mut keys: Vec<&String> = args.keys().collect();
    keys.sort();
    let bad = keys.into_iter().find(|k| !allowed.contains(&k.as_str()))?;
    if bad == "dry_run" {
        return Some(Status::coded(
            exit::USAGE,
            UNKNOWN_ARGUMENT,
            format!("{scheme} {verb} does not support dry_run; nothing was sent"),
        ));
    }
    let hint = suggest(bad, &allowed)
        .map(|s| format!(" (did you mean `{s}`?)"))
        .unwrap_or_default();
    Some(Status::coded(
        exit::USAGE,
        UNKNOWN_ARGUMENT,
        format!("unknown argument for {scheme} {verb}: {bad}{hint}"),
    ))
}

/// A boolean argument (`true|false|1|0|yes|no|on|off`); anything else is a
/// usage error, never a silent default.
fn bool_opt(args: &Args, key: &str, default: bool) -> std::result::Result<bool, Status> {
    crate::core::lenient::bool_arg(args, key)
        .map(|v| v.unwrap_or(default))
        .map_err(|e| usage(e.to_string()))
}

/// One of `allowed` for `key`, or `default` when absent.
fn choice<'a>(
    args: &'a Args,
    key: &str,
    allowed: &[&str],
    default: &'a str,
) -> std::result::Result<&'a str, Status> {
    match args.get(key) {
        None => Ok(default),
        Some(v) if allowed.contains(&v.as_str()) => Ok(v.as_str()),
        Some(v) => Err(usage(format!(
            "invalid {key}: {v:?} (expected {})",
            allowed.join(", ")
        ))),
    }
}

/// Methods `json` and `headers` can send.
const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// The `method=` argument (case-insensitive) or GET.
fn method_arg(args: &Args) -> std::result::Result<Method, String> {
    let raw = args.get("method").map(String::as_str).unwrap_or("GET");
    let upper = raw.to_ascii_uppercase();
    if !METHODS.contains(&upper.as_str()) {
        return Err(format!(
            "Unsupported method: {raw}. Supported methods: {}",
            METHODS.join(", ")
        ));
    }
    Method::from_bytes(upper.as_bytes()).map_err(|e| e.to_string())
}

/// Parses `Name:value;Name2:value2`. Every segment needs a `:` and a valid
/// header name and value; `Host`, `Content-Length`, `Connection` and
/// `Transfer-Encoding` are dropped. Repeated names are all sent.
fn parse_headers(headers_str: &str) -> std::result::Result<HeaderMap, String> {
    let mut map = HeaderMap::new();
    for pair in headers_str.split(';') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let Some((key, value)) = pair.split_once(':') else {
            return Err(format!(
                "invalid header format: '{pair}' (expected Name:value)"
            ));
        };
        let (key, value) = (key.trim(), value.trim());
        let name = HeaderName::from_bytes(key.as_bytes())
            .map_err(|_| format!("invalid header name: '{key}'"))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| format!("invalid value for header '{key}'"))?;
        if !DROPPED_HEADERS.contains(&name.as_str()) {
            map.append(name, value);
        }
    }
    Ok(map)
}

/// Comma- or semicolon-separated list, trimmed, empty items dropped.
fn parse_header_list(value: &str) -> Vec<String> {
    value
        .split([',', ';'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Response headers as `name -> [values]`.
fn header_arrays(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        out.entry(name.as_str().to_string())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    out
}

/// Response headers as `name -> "v1, v2"`.
fn header_joined(headers: &HeaderMap) -> BTreeMap<String, String> {
    header_arrays(headers)
        .into_iter()
        .map(|(k, v)| (k, v.join(", ")))
        .collect()
}

fn reason_of(status: StatusCode) -> &'static str {
    status.canonical_reason().unwrap_or("")
}

/// Exit status for an HTTP response: 0 for 2xx, and for 3xx when redirects
/// are not followed (the redirect is the answer asked for); otherwise 1
/// with `HTTP <code> <reason>`.
fn http_outcome(status: StatusCode, follow: bool) -> Status {
    if status.is_success() || (status.is_redirection() && !follow) {
        Status::ok()
    } else {
        Status::coded(
            exit::FAILED,
            STATUS_ERROR,
            format!("HTTP {} {}", status.as_u16(), reason_of(status)).trim_end(),
        )
    }
}

/// The innermost cause of `e`, which names the real problem (connection
/// refused, certificate not trusted, ...).
fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cur = e;
    while let Some(next) = cur.source() {
        cur = next;
    }
    cur.to_string()
}

/// What went wrong while sending or reading, and its exit code: 124 for a
/// timeout (the server may have acted on the request), 2 for a request
/// that could not be built (nothing was sent), 1 otherwise.
struct Failure {
    exit: i32,
    code: &'static str,
    message: String,
}

impl Failure {
    fn from_reqwest(e: &reqwest::Error, timeout: Duration) -> Self {
        if e.is_timeout() {
            Failure {
                exit: exit::TIMEOUT,
                code: TIMEOUT,
                message: format!("Request timed out after {} ms", timeout.as_millis()),
            }
        } else if e.is_builder() {
            Failure {
                exit: exit::USAGE,
                code: INVALID_ARGUMENT,
                message: format!("Invalid URL or request: {}", root_cause(e)),
            }
        } else if e.is_redirect() {
            Failure {
                exit: exit::FAILED,
                code: REDIRECT_FAILED,
                message: format!("Redirect failed: {}", root_cause(e)),
            }
        } else if e.is_connect() {
            Failure {
                exit: exit::FAILED,
                code: CONNECTION_FAILED,
                message: format!("Connection failed: {}", root_cause(e)),
            }
        } else {
            Failure {
                exit: exit::FAILED,
                code: REQUEST_FAILED,
                message: format!("Request failed: {}", root_cause(e)),
            }
        }
    }

    fn status(&self) -> Status {
        Status::coded(self.exit, self.code, &self.message)
    }

    fn json(&self) -> serde_json::Value {
        error_json(self.code, &self.message)
    }
}

/// Settings shared by every verb, validated before anything is sent.
struct Prepared {
    client: Client,
    url: Url,
    headers: HeaderMap,
    timeout: Duration,
    follow: bool,
}

impl Prepared {
    fn request(&self, method: Method) -> reqwest::blocking::RequestBuilder {
        self.client
            .request(method, self.url.clone())
            .headers(self.headers.clone())
            // Sets the whole-request deadline, which also bounds reading the
            // body (the client timeout alone restarts for the body).
            .timeout(self.timeout)
    }

    fn send(
        &self,
        rb: reqwest::blocking::RequestBuilder,
    ) -> std::result::Result<Response, Failure> {
        rb.send()
            .map_err(|e| Failure::from_reqwest(&e, self.timeout))
    }

    /// The whole body; the request timeout covers reading it.
    fn body(&self, resp: Response) -> std::result::Result<Vec<u8>, Failure> {
        resp.bytes()
            .map(|b| b.to_vec())
            .map_err(|e| Failure::from_reqwest(&e, self.timeout))
    }
}

/// The request body from `body=` or `body_file=` (not both). `None` when
/// neither is given. An unreadable file fails with exit 1 before sending.
fn body_source(args: &Args) -> std::result::Result<Option<Vec<u8>>, Status> {
    match (args.get("body"), args.get("body_file")) {
        (Some(_), Some(_)) => Err(usage(
            "body and body_file cannot be used together; give one of them",
        )),
        (Some(b), None) => Ok(Some(b.as_bytes().to_vec())),
        (None, Some(path)) if path.is_empty() => Err(usage("body_file is empty")),
        (None, Some(path)) => std::fs::read(path).map(Some).map_err(|e| {
            Status::coded(
                exit::FAILED,
                BODY_FILE_UNREADABLE,
                format!("failed to read body_file '{path}': {e}"),
            )
        }),
        (None, None) => Ok(None),
    }
}

/// The `content_type=` argument as a header value.
fn content_type_arg(args: &Args) -> std::result::Result<Option<HeaderValue>, Status> {
    match args.get("content_type") {
        None => Ok(None),
        Some(ct) => HeaderValue::from_str(ct)
            .map(Some)
            .map_err(|_| usage(format!("invalid content_type: {ct:?}"))),
    }
}

/// `body` as JSON when the response says it is JSON, otherwise as text.
fn json_or_text(content_type: Option<&HeaderValue>, body: &[u8]) -> serde_json::Value {
    let is_json = content_type
        .map(|v| String::from_utf8_lossy(v.as_bytes()).to_ascii_lowercase())
        .is_some_and(|ct| ct.contains("application/json"));
    if is_json {
        if let Ok(v) = serde_json::from_slice(body) {
            return v;
        }
    }
    json!(String::from_utf8_lossy(body))
}

pub struct HttpHandle {
    url: Url,
}

impl HttpHandle {
    pub fn from_url(url: &Url) -> Result<Self> {
        Ok(HttpHandle { url: url.clone() })
    }

    /// Check if this is a help request (`help`, `--help`, `-h`, or
    /// `--help=<verb>`) and, if so, write the approved help.
    fn check_and_display_help(
        &self,
        verb: &str,
        args: &Args,
        io: &mut IoStreams,
    ) -> Result<Option<Status>> {
        let specific = if crate::core::help::HELP_ALIASES.contains(&verb) {
            args.get("verb").map(String::as_str)
        } else if let Some(v) = verb.strip_prefix("--help=") {
            Some(v)
        } else {
            return Ok(None);
        };
        let help = self.help().unwrap_or(&HTTP_HELP);
        let text =
            crate::core::help::render_legacy(self.url.scheme(), help, self.verbs(), specific);
        write!(io.stdout, "{}", text)?;
        Ok(Some(Status::ok()))
    }

    /// The URL with `query=` appended to its query string as given.
    fn request_url(&self, args: &Args) -> Url {
        let mut url = self.url.clone();
        if let Some(q) = args.get("query").filter(|q| !q.is_empty()) {
            let merged = match url.query().filter(|c| !c.is_empty()) {
                Some(current) => format!("{current}&{q}"),
                None => q.clone(),
            };
            url.set_query(Some(&merged));
        }
        url
    }

    /// Validates the options every verb shares and builds the client.
    fn prepare(&self, verb: &str, args: &Args) -> std::result::Result<Prepared, Status> {
        let timeout_ms = match args.get("timeout_ms") {
            None => default_timeout_ms(verb),
            Some(v) => match v.trim().parse::<u64>() {
                Ok(ms) if ms > 0 => ms,
                _ => {
                    return Err(usage(format!(
                        "invalid timeout_ms: {v:?} (expected a positive number of milliseconds)"
                    )));
                }
            },
        };
        let timeout = Duration::from_millis(timeout_ms);
        let follow = bool_opt(args, "follow_redirects", true)?;
        let insecure = bool_opt(args, "allow_insecure", false)?;
        let headers = match args.get("headers") {
            None => HeaderMap::new(),
            Some(h) => parse_headers(h).map_err(|e| usage(format!("invalid headers: {e}")))?,
        };
        let client = Self::build_client(timeout, follow, insecure).map_err(|e| {
            Status::coded(
                exit::FAILED,
                CLIENT_FAILED,
                format!("Failed to create HTTP client: {e}"),
            )
        })?;
        Ok(Prepared {
            client,
            url: self.request_url(args),
            headers,
            timeout,
            follow,
        })
    }

    /// A client with a whole-request `timeout` (connect, send and reading
    /// the body), redirects followed (up to 10) unless `follow` is false, and
    /// certificate checks disabled only when `insecure` is set.
    fn build_client(timeout: Duration, follow: bool, insecure: bool) -> reqwest::Result<Client> {
        Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout)
            .redirect(if follow {
                reqwest::redirect::Policy::limited(10)
            } else {
                reqwest::redirect::Policy::none()
            })
            .danger_accept_invalid_certs(insecure)
            .build()
    }

    fn verb_get(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let accept = match choice(args, "accept", &["text", "bytes", "json"], "text") {
            Ok(a) => a,
            Err(s) => return Ok(s),
        };
        let p = match self.prepare("get", args) {
            Ok(p) => p,
            Err(s) => return Ok(s),
        };
        let resp = match p.send(p.request(Method::GET)) {
            Ok(r) => r,
            Err(f) => return Ok(f.status()),
        };
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = match p.body(resp) {
            Ok(b) => b,
            Err(f) => return Ok(f.status()),
        };
        match accept {
            "json" => {
                let envelope = json!({
                    "status": status.as_u16(),
                    "ok": status.is_success(),
                    "method": "GET",
                    "headers": header_arrays(&headers),
                    "body": json_or_text(headers.get(CONTENT_TYPE), &body),
                    "body_text": String::from_utf8_lossy(&body),
                });
                write!(io.stdout, "{}", serde_json::to_string(&envelope)?)?;
            }
            // text prints the body as received; bytes the same raw bytes.
            _ => io.stdout.write_all(&body)?,
        }
        Ok(http_outcome(status, p.follow))
    }

    fn verb_head(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let accept = match args.get("accept") {
            None => None,
            Some(_) => match choice(args, "accept", &["json", "text", "bytes"], "bytes") {
                Ok(a) => Some(a),
                Err(s) => return Ok(s),
            },
        };
        let mut p = match self.prepare("head", args) {
            Ok(p) => p,
            Err(s) => return Ok(s),
        };
        if let Some(accept) = accept {
            let value = match accept {
                "json" => "application/json",
                "text" => "text/*",
                _ => "*/*",
            };
            p.headers.insert(ACCEPT, HeaderValue::from_static(value));
        }
        let resp = match p.send(p.request(Method::HEAD)) {
            Ok(r) => r,
            Err(f) => return Ok(f.status()),
        };
        let status = resp.status();
        let out = json!({
            "url": resp.url().as_str(),
            "status": status.as_u16(),
            "ok": status.is_success(),
            "reason": status.canonical_reason().unwrap_or("Unknown"),
            "headers": header_joined(resp.headers()),
        });
        write!(io.stdout, "{}", serde_json::to_string(&out)?)?;
        Ok(http_outcome(status, p.follow))
    }

    /// `headers` reports its own argument and network errors as JSON.
    fn verb_headers(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let error_out =
            |error: serde_json::Value| json!({ "url": self.url.as_str(), "error": error });
        let method = match method_arg(args) {
            Ok(m) => m,
            Err(msg) => {
                write!(
                    io.stdout,
                    "{}",
                    serde_json::to_string(&error_out(error_json(INVALID_ARGUMENT, &msg)))?
                )?;
                return Ok(usage(msg));
            }
        };
        let p = match self.prepare("headers", args) {
            Ok(p) => p,
            Err(s) => {
                // Malformed headers are reported in the JSON too.
                if let Some(e) = args.get("headers").and_then(|h| parse_headers(h).err()) {
                    let msg = format!("invalid headers: {e}");
                    write!(
                        io.stdout,
                        "{}",
                        serde_json::to_string(&error_out(error_json(INVALID_ARGUMENT, &msg)))?
                    )?;
                }
                return Ok(s);
            }
        };
        let resp = match p.send(p.request(method)) {
            Ok(r) => r,
            Err(f) => {
                write!(
                    io.stdout,
                    "{}",
                    serde_json::to_string(&error_out(f.json()))?
                )?;
                return Ok(f.status());
            }
        };
        let status = resp.status();
        let out = json!({
            "url": resp.url().as_str(),
            "status": status.as_u16(),
            "status_text": reason_of(status),
            "headers": header_arrays(resp.headers()),
        });
        write!(io.stdout, "{}", serde_json::to_string(&out)?)?;
        Ok(http_outcome(status, p.follow))
    }

    fn verb_options(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let include_body = match bool_opt(args, "include_body", false) {
            Ok(b) => b,
            Err(s) => return Ok(s),
        };
        let p = match self.prepare("options", args) {
            Ok(p) => p,
            Err(s) => return Ok(s),
        };
        let resp = match p.send(p.request(Method::OPTIONS)) {
            Ok(r) => r,
            Err(f) => return Ok(f.status()),
        };
        let status = resp.status();
        let url = resp.url().to_string();
        let headers = header_joined(resp.headers());
        let body = match p.body(resp) {
            Ok(b) => b,
            Err(f) => return Ok(f.status()),
        };
        let allowed_methods: Vec<String> = headers
            .get("allow")
            .map(|a| {
                a.split(',')
                    .map(|m| m.trim().to_string())
                    .filter(|m| !m.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let mut out = json!({
            "url": url,
            "status": status.as_u16(),
            "reason": reason_of(status),
            "backend": "reqwest",
            "headers": headers,
            "allowed_methods": allowed_methods,
            "has_body": !body.is_empty(),
        });
        if include_body && !body.is_empty() {
            out["body"] = json!(String::from_utf8_lossy(&body));
        }
        write!(io.stdout, "{}", serde_json::to_string(&out)?)?;
        Ok(http_outcome(status, p.follow))
    }

    fn verb_preflight(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let mut extra = HeaderMap::new();
        if let Some(origin) = args.get("origin") {
            match HeaderValue::from_str(origin) {
                Ok(v) => extra.insert(ORIGIN, v),
                Err(_) => return Ok(usage(format!("invalid origin: {origin:?}"))),
            };
        }
        if let Some(method) = args.get("method") {
            let valid = !method.is_empty() && Method::from_bytes(method.as_bytes()).is_ok();
            match HeaderValue::from_str(method) {
                Ok(v) if valid => extra.insert(ACCESS_CONTROL_REQUEST_METHOD, v),
                _ => return Ok(usage(format!("invalid method: {method:?}"))),
            };
        }
        if let Some(list) = args.get("request_headers") {
            let names = parse_header_list(list);
            if let Some(bad) = names
                .iter()
                .find(|n| HeaderName::from_bytes(n.as_bytes()).is_err())
            {
                return Ok(usage(format!(
                    "invalid header name in request_headers: {bad:?}"
                )));
            }
            if !names.is_empty() {
                if let Ok(v) = HeaderValue::from_str(&names.join(", ")) {
                    extra.insert(ACCESS_CONTROL_REQUEST_HEADERS, v);
                }
            }
        }
        let mut p = match self.prepare("preflight", args) {
            Ok(p) => p,
            Err(s) => return Ok(s),
        };
        // The preflight arguments win over the same names in headers=.
        for (name, value) in &extra {
            p.headers.insert(name.clone(), value.clone());
        }
        let resp = match p.send(p.request(Method::OPTIONS)) {
            Ok(r) => r,
            Err(f) => {
                let out = json!({
                    "url": p.url.as_str(),
                    "method": "OPTIONS",
                    "ok": false,
                    "error": f.json(),
                    "status": null,
                    "cors": null,
                    "raw_headers": {},
                });
                write!(io.stdout, "{}", serde_json::to_string(&out)?)?;
                return Ok(f.status());
            }
        };
        let status = resp.status();
        let h = resp.headers();
        let get = |name: &str| {
            h.get_all(name)
                .iter()
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let list = |name: &str| parse_header_list(&get(name));
        let origins = get("access-control-allow-origin");
        let cors = json!({
            "allowed_origins": if origins.trim() == "*" { vec!["*".to_string()] } else { parse_header_list(&origins) },
            "allowed_methods": list("access-control-allow-methods"),
            "allowed_headers": list("access-control-allow-headers"),
            "exposed_headers": list("access-control-expose-headers"),
            "allow_credentials": get("access-control-allow-credentials").trim().eq_ignore_ascii_case("true"),
            "max_age_seconds": get("access-control-max-age").trim().parse::<i64>().ok(),
        });
        let out = json!({
            "url": resp.url().as_str(),
            "method": "OPTIONS",
            "status": status.as_u16(),
            "ok": status.is_success(),
            "cors": cors,
            "raw_headers": header_joined(h),
        });
        write!(io.stdout, "{}", serde_json::to_string(&out)?)?;
        Ok(http_outcome(status, p.follow))
    }

    fn verb_json(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let method = match method_arg(args) {
            Ok(m) => m,
            Err(msg) => return Ok(usage(msg)),
        };
        let accept = match choice(args, "accept", &["json", "text", "bytes"], "json") {
            Ok(a) => a,
            Err(s) => return Ok(s),
        };
        let body = args.get("body").filter(|b| !b.is_empty());
        let sends_body = matches!(
            method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        );
        if body.is_some() && !sends_body {
            return Ok(usage(format!(
                "body is sent only with POST, PUT, PATCH or DELETE, not {method}"
            )));
        }
        let content_type = match content_type_arg(args) {
            Ok(ct) => ct,
            Err(s) => return Ok(s),
        };
        let mut p = match self.prepare("json", args) {
            Ok(p) => p,
            Err(s) => return Ok(s),
        };
        match (content_type, body) {
            (Some(ct), _) => {
                p.headers.insert(CONTENT_TYPE, ct);
            }
            (None, Some(_)) => {
                p.headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }
            (None, None) => {}
        }
        let mut rb = p.request(method);
        if let Some(b) = body {
            rb = rb.body(b.clone());
        }
        let envelope_error = |f: &Failure| {
            json!({
                "url": p.url.as_str(),
                "status": 0,
                "status_text": "",
                "headers": {},
                "body": { "type": "text", "value": "" },
                "error": f.json(),
            })
        };
        let resp = match p.send(rb) {
            Ok(r) => r,
            Err(f) => {
                write!(io.stdout, "{}", serde_json::to_string(&envelope_error(&f))?)?;
                return Ok(f.status());
            }
        };
        let status = resp.status();
        let url = resp.url().to_string();
        let headers = header_arrays(resp.headers());
        let bytes = match p.body(resp) {
            Ok(b) => b,
            Err(f) => {
                let mut out = envelope_error(&f);
                out["url"] = json!(url);
                out["status"] = json!(status.as_u16());
                out["status_text"] = json!(reason_of(status));
                out["headers"] = json!(headers);
                write!(io.stdout, "{}", serde_json::to_string(&out)?)?;
                return Ok(f.status());
            }
        };
        let body_field = match accept {
            "bytes" => json!({ "type": "bytes", "base64": BASE64_STANDARD.encode(&bytes) }),
            "json" => match serde_json::from_slice::<serde_json::Value>(&bytes) {
                Ok(v) => json!({ "type": "json", "value": v }),
                Err(_) => json!({ "type": "text", "value": String::from_utf8_lossy(&bytes) }),
            },
            _ => json!({ "type": "text", "value": String::from_utf8_lossy(&bytes) }),
        };
        let out = json!({
            "url": url,
            "status": status.as_u16(),
            "status_text": reason_of(status),
            "headers": headers,
            "body": body_field,
        });
        write!(io.stdout, "{}", serde_json::to_string(&out)?)?;
        Ok(http_outcome(status, p.follow))
    }

    /// Shared request half of post, put, patch and delete: validates the
    /// body options, sends the request and reads the whole response.
    fn send_with_body(
        &self,
        verb: &str,
        method: Method,
        args: &Args,
    ) -> std::result::Result<(Prepared, StatusCode, HeaderMap, Vec<u8>), Status> {
        let content_type = content_type_arg(args)?;
        let mut p = self.prepare(verb, args)?;
        let body = body_source(args)?;
        match content_type {
            Some(ct) => {
                p.headers.insert(CONTENT_TYPE, ct);
            }
            None => {
                // put labels an inline body as text; delete labels any body
                // as octet-stream; post and patch send none.
                let default = match (verb, args.contains_key("body"), &body) {
                    ("put", true, _) => Some("text/plain; charset=utf-8"),
                    ("delete", _, Some(b)) if !b.is_empty() => Some("application/octet-stream"),
                    _ => None,
                };
                if let Some(d) = default {
                    if !p.headers.contains_key(CONTENT_TYPE) {
                        p.headers.insert(CONTENT_TYPE, HeaderValue::from_static(d));
                    }
                }
            }
        }
        let mut rb = p.request(method);
        if let Some(b) = body {
            rb = rb.body(b);
        }
        let resp = p.send(rb).map_err(|f| f.status())?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = p.body(resp).map_err(|f| f.status())?;
        Ok((p, status, headers, bytes))
    }

    fn verb_post(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let (p, status, _, body) = match self.send_with_body("post", Method::POST, args) {
            Ok(r) => r,
            Err(s) => return Ok(s),
        };
        io.stdout.write_all(&body)?;
        Ok(http_outcome(status, p.follow))
    }

    fn verb_put(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let accept = match choice(args, "accept", &["text", "bytes", "json"], "text") {
            Ok(a) => a,
            Err(s) => return Ok(s),
        };
        let (p, status, headers, body) = match self.send_with_body("put", Method::PUT, args) {
            Ok(r) => r,
            Err(s) => return Ok(s),
        };
        match accept {
            "bytes" => io.stdout.write_all(&body)?,
            "json" => {
                let out = json!({
                    "status": status.as_u16(),
                    "ok": status.is_success(),
                    "headers": header_arrays(&headers),
                    "body": json_or_text(headers.get(CONTENT_TYPE), &body),
                });
                write!(io.stdout, "{}", serde_json::to_string(&out)?)?;
            }
            _ => write!(io.stdout, "{}", String::from_utf8_lossy(&body))?,
        }
        Ok(http_outcome(status, p.follow))
    }

    fn verb_patch(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let accept = match choice(args, "accept", &["bytes", "text", "json"], "bytes") {
            Ok(a) => a,
            Err(s) => return Ok(s),
        };
        let (p, status, _, body) = match self.send_with_body("patch", Method::PATCH, args) {
            Ok(r) => r,
            Err(s) => return Ok(s),
        };
        let outcome = http_outcome(status, p.follow);
        match accept {
            "json" => match serde_json::from_slice::<serde_json::Value>(&body) {
                Ok(v) => write!(io.stdout, "{}", serde_json::to_string(&v)?)?,
                // A failed status is the more useful error; show its body.
                Err(_) if !outcome.ok => io.stdout.write_all(&body)?,
                Err(_) => {
                    return Ok(Status::coded(
                        exit::FAILED,
                        INVALID_JSON_RESPONSE,
                        "response body is not valid JSON (accept=json)",
                    ));
                }
            },
            "text" => write!(io.stdout, "{}", String::from_utf8_lossy(&body))?,
            _ => io.stdout.write_all(&body)?,
        }
        Ok(outcome)
    }

    fn verb_delete(&self, args: &Args, io: &mut IoStreams) -> Result<Status> {
        let accept = match choice(args, "accept", &["text", "bytes", "json"], "text") {
            Ok(a) => a,
            Err(s) => return Ok(s),
        };
        let (p, status, _, body) = match self.send_with_body("delete", Method::DELETE, args) {
            Ok(r) => r,
            Err(s) => return Ok(s),
        };
        match accept {
            "json" => {
                let out = serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_else(|_| {
                    json!({
                        "status": { "code": status.as_u16(), "ok": status.is_success() },
                        "body": String::from_utf8_lossy(&body),
                    })
                });
                write!(io.stdout, "{}", serde_json::to_string_pretty(&out)?)?;
            }
            "bytes" => io.stdout.write_all(&body)?,
            _ => write!(io.stdout, "{}", String::from_utf8_lossy(&body))?,
        }
        Ok(http_outcome(status, p.follow))
    }
}

impl Handle for HttpHandle {
    fn verbs(&self) -> &'static [&'static str] {
        &[
            "get",
            "head",
            "post",
            "put",
            "patch",
            "delete",
            "options",
            "preflight",
            "json",
            "headers",
            "help",
            "--help",
            "-h",
        ]
    }

    fn help(&self) -> Option<&'static HandleHelp> {
        match self.url.scheme() {
            "https" => Some(&HTTPS_HELP),
            _ => Some(&HTTP_HELP),
        }
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        if let Some(status) = self.check_and_display_help(verb, args, io)? {
            return Ok(status);
        }
        let scheme = self.url.scheme();
        let Some(specific) = verb_args(verb) else {
            return Ok(Status::coded(
                exit::USAGE,
                UNKNOWN_VERB,
                format!(
                    "unknown verb for {scheme}://: {verb} (verbs: get, head, headers, options, \
                     preflight, json, post, put, patch, delete)"
                ),
            ));
        };
        if let Some(refusal) = check_args(scheme, verb, specific, args) {
            return Ok(refusal);
        }
        match verb {
            "get" => self.verb_get(args, io),
            "head" => self.verb_head(args, io),
            "headers" => self.verb_headers(args, io),
            "options" => self.verb_options(args, io),
            "preflight" => self.verb_preflight(args, io),
            "json" => self.verb_json(args, io),
            "post" => self.verb_post(args, io),
            "put" => self.verb_put(args, io),
            "patch" => self.verb_patch(args, io),
            _ => self.verb_delete(args, io),
        }
    }
}

#[cfg(test)]
#[path = "httph_tests.rs"]
mod tests;

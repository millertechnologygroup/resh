# Resource Shell (resh): HTTP Handle

## 1. Overview

The `http` handle sends HTTP requests with the reqwest blocking client
(rustls TLS). The `http://` and `https://` schemes are served by the same
handle and accept the same verbs. Verbs map to request methods, plus helpers
for CORS preflight checks, a JSON response envelope, and header inspection.

Linux is the only supported and verified platform. Each `resh` invocation is a
separate process: there are no persistent connections, cookies or sessions
between commands.

```bash
resh http --help
resh https --help
resh http get --help
```

## 2. Command syntax

The stage URL is the request URL itself, followed by a dot and the verb:

```text
resh http[s]://<host>[:<port>]/<path>.<verb> key=value ...
resh 'http[s]://<host>/<path>.<verb>(key=value,...)'
```

```bash
resh http://api.example.com/v1/users/42.get accept=json
resh https://example.com.headers method=HEAD
resh 'https://api.example.com/v1/users.post(body={"name":"alice"},content_type=application/json)'
```

The verb is the text after the last dot, so the verb is always required. A
URL that ends in a file extension (for example `/index.html`) must still end
with `.get`, `.head` and so on: `https://example.com/index.html.get`. Add query
parameters with `query=` (see below) rather than inside the URL.

## 3. Verbs

| Verb        | Method        | Prints                                              |
| ----------- | ------------- | --------------------------------------------------- |
| `get`       | GET           | Body as text (default), raw bytes, or a JSON envelope |
| `head`      | HEAD          | JSON: url, status, ok, reason, headers              |
| `headers`   | any (default GET) | JSON: url, status, status_text, headers (no body) |
| `options`   | OPTIONS       | JSON: allowed methods, status, headers              |
| `preflight` | OPTIONS (CORS) | JSON: parsed Access-Control-* headers              |
| `json`      | any (default GET) | JSON envelope with the body parsed as JSON when possible |
| `post`      | POST          | Raw response body                                   |
| `put`       | PUT           | Body as text (default), raw bytes, or a JSON envelope |
| `patch`     | PATCH         | Raw bytes (default), text, or compact JSON          |
| `delete`    | DELETE        | Body as text (default), raw bytes, or pretty JSON   |

Every verb treats the HTTP status the same way: a 2xx response exits 0. A 3xx
response exits 0 only with `follow_redirects=false` (the redirect is then the
answer asked for). Any other status exits 1: the body or JSON is still printed
to stdout, and `Error: [http.status_error] HTTP <code> <reason>` (for
example `Error: [http.status_error] HTTP 404 Not Found`) goes to stderr. The JSON verbs also report the
status in their output.

## 4. Common arguments

Every verb accepts these:

| Argument           | Notes |
| ------------------ | ----- |
| `query`            | `k=v&k2=v2`, appended as given to the URL's query string (keep any percent-encoding you need). |
| `headers`          | `Name:value;Name2:value2`. Every segment needs a `:`, a valid header name and a valid value, or the stage is refused (exit 2). A repeated name sends every value. `Host`, `Content-Length`, `Connection` and `Transfer-Encoding` are dropped. Use it for authentication, for example `headers='Authorization:Bearer <token>'`. |
| `timeout_ms`       | Whole-request deadline in milliseconds (connect, send and reading the whole response body). A positive integer; anything else is refused (exit 2). Defaults: 5000 for `preflight`; 30000 for `put`, `patch` and `delete`; 10000 for the others. |
| `follow_redirects` | `true` (default) follows up to 10 redirects; `false` returns the redirect response itself. |
| `allow_insecure`   | `true` **disables TLS certificate and host name verification** for an `https://` URL. Default `false`. No effect on `http://`. Use it only against hosts you control. |
| `ca_file`          | PEM file of CA certificates to trust for this stage, **in addition to** the built-in public roots (webpki roots); verification stays on. Use it for servers with a certificate from a private CA. `https://` URLs only: refused (exit 2) on an `http://` URL, together with `allow_insecure=true`, and when the file cannot be read or holds no valid PEM certificate. |

Booleans accept `true|false|1|0|yes|no|on|off`; anything else is refused
(exit 2).

Verb-specific arguments:

| Argument          | Verbs | Notes |
| ----------------- | ----- | ----- |
| `accept`          | get, head, json, put, patch, delete | Output mode (`text`, `bytes`, `json`); see each verb. For `head` it only sets the request `Accept` header. Any other value is refused (exit 2). |
| `body`            | json, post, put, patch, delete | Inline request body. |
| `body_file`       | post, put, patch, delete | Local file sent as the body. `body_file=/dev/stdin` sends standard input. |
| `content_type`    | json, post, put, patch, delete | Sets `Content-Type` (wins over a `Content-Type` in `headers=`). |
| `method`          | headers, json, preflight | See each verb. |
| `include_body`    | options | |
| `origin`, `request_headers` | preflight | |

`body` and `body_file` cannot be given together (exit 2). An unreadable
`body_file` fails with exit 1 before anything is sent.

Default `Content-Type` (when neither `content_type` nor a `Content-Type` in
`headers=` is given): `put` sends `text/plain; charset=utf-8` for an inline
`body` (none for `body_file`); `delete` sends `application/octet-stream` when
the body is not empty; `json` sends `application/json` when `body` is not
empty; `post` and `patch` send none.

Any other argument, including `dry_run`, is refused with exit 2 and a
"did you mean" hint for a likely typo, before anything is sent. No verb has a
dry-run mode.

### Proxies

The standard proxy environment variables are honored: `http_proxy` /
`HTTP_PROXY` for `http://` URLs, `https_proxy` / `HTTPS_PROXY` for
`https://` URLs (sent through `CONNECT`), `all_proxy` / `ALL_PROXY`, and
`no_proxy` / `NO_PROXY` to bypass the proxy for listed hosts. There is no
proxy argument.

## 5. Verb reference

### get

```bash
resh http://api.example.com/v1/users/42.get
resh http://api.example.com/v1/users.get accept=json query='page=2&per_page=50'
resh https://example.com/logo.png.get accept=bytes > logo.png
```

`accept=text` (default) and `accept=bytes` print the body exactly as
received. `accept=json` prints an envelope:

```json
{"status":200,"ok":true,"method":"GET","headers":{"content-type":["application/json"]},"body":{"id":42,"name":"alice"},"body_text":"{\"id\":42,\"name\":\"alice\"}"}
```

`body` is parsed JSON only when the response `Content-Type` contains
`application/json` and the body parses; otherwise it is the body as a string.
Header values are arrays.

### head

```bash
resh https://example.com/index.html.head
```

Output: `{"url", "status", "ok", "reason", "headers"}` with lowercase header
names and repeated headers joined with `, `. `accept` sets the request
`Accept` header: `json` gives `application/json`, `text` gives `text/*`,
`bytes` gives `*/*` (it wins over an `Accept` in `headers=`).

### headers

```bash
resh https://example.com.headers
resh https://example.com.headers method=HEAD follow_redirects=false
```

`method` may be GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS
(case-insensitive, default GET); no body is sent. Output:
`{"url", "status", "status_text", "headers"}` with header values as arrays.
An unsupported method or malformed `headers` prints
`{"url", "error": {"code": "http.invalid_argument", "message"}}` and exits
2. A request failure prints the same shape with the failure's code (section
6) and its exit code.

### options

```bash
resh http://api.example.com/v1/users.options include_body=true
```

Output: `url`, `status`, `reason`, `backend` (`"reqwest"`), `headers`,
`allowed_methods` (parsed from `Allow`), `has_body`, and `body` when
`include_body=true` and the body is not empty.

### preflight

```bash
resh http://api.example.com/users.preflight origin=https://example.org method=POST request_headers=Content-Type,Authorization
```

Sends `OPTIONS` with `Origin`, `Access-Control-Request-Method` and
`Access-Control-Request-Headers` from `origin`, `method` (an HTTP method
token) and `request_headers` (comma or semicolon separated header names).
These win over the same headers in `headers=`. Output: `url`, `method`,
`status`, `ok`, `cors` (`allowed_origins`, `allowed_methods`,
`allowed_headers`, `exposed_headers`, `allow_credentials`,
`max_age_seconds`) and `raw_headers`. On a request failure it prints the
same shape with `ok: false`, `status: null`, `cors: null` and
`"error": {"code", "message"}`, and exits 1 (124 for a timeout).

### json

```bash
resh http://api.example.com/v1/users/42.json
resh http://api.example.com/v1/users.json method=POST body='{"name":"alice"}'
```

`method`: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS (case-insensitive,
default GET). `body` can be given only with POST, PUT, PATCH or DELETE; with
another method it is refused (exit 2). No `Accept` header is added. Output:

```json
{"url":"http://api.example.com/v1/users/42","status":200,"status_text":"OK","headers":{"content-type":["application/json"]},"body":{"type":"json","value":{"id":42,"name":"alice"}}}
```

`accept=json` (default) gives `type: "json"` when the body parses, otherwise
`type: "text"`. `accept=text` always gives text; `accept=bytes` gives
`{"type": "bytes", "base64": "..."}`. A request failure prints an envelope
with `status: 0` and `"error": {"code", "message"}`, and exits 1 (124 for a
timeout).

### post

```bash
resh http://api.example.com/v1/users.post body='{"name":"alice"}' content_type=application/json
resh http://api.example.com/upload.post body_file=./payload.bin content_type=application/octet-stream
generate-report | resh http://api.example.com/reports.post body_file=/dev/stdin
```

Prints the raw response body. No `accept` modes.

### put

```bash
resh http://api.example.com/v1/users/42.put body='{"name":"alice"}' content_type=application/json
resh https://staging.internal/v1/config.put body_file=./config.json accept=json allow_insecure=true
```

`accept`: `text` (default, invalid UTF-8 replaced), `bytes`, or `json`
(envelope `{"status", "ok", "headers", "body"}`; `body` is parsed JSON when
the response says `application/json` and parses, otherwise a string).

### patch

```bash
resh http://api.example.com/v1/users/42.patch body='{"name":"bob"}' content_type=application/json
```

`accept`: `bytes` (default), `text`, or `json` (the body re-printed as
compact JSON). With `accept=json`, a 2xx body that is not JSON prints nothing
and exits 1; for a failed status the body is printed as is.

### delete

```bash
resh http://api.example.com/v1/users/42.delete
resh http://api.example.com/v1/users/42.delete accept=json
```

`accept`: `text` (default), `bytes`, or `json` (pretty-printed JSON; a body
that is not JSON is wrapped as `{"status": {"code", "ok"}, "body": "..."}`).

## 6. Errors and exit codes

* 0: the response status is a success (2xx, or 3xx with
  `follow_redirects=false`).
* 1: the request failed (see the codes below).
* 2: invalid usage; nothing was sent.
* 124: the request did not finish within `timeout_ms`. The server may have
  received and acted on it.

A failure is printed on stderr as `Error: [<code>] <message>`, for example
`Error: [http.status_error] HTTP 404 Not Found` or
`Error: [http.timeout] Request timed out after 300 ms`. `headers`, `json` and
`preflight` also put `"error": {"code", "message"}` in their JSON output for
argument (headers only) and request failures. The `https` handle uses the
same `http.` codes.

| Code | Exit | Meaning |
| ---- | ---- | ------- |
| `http.unknown_verb` | 2 | The verb is not one of the ten above. |
| `http.unknown_argument` | 2 | An argument the verb does not take, including `dry_run`. The message suggests the closest accepted name. |
| `http.invalid_argument` | 2 | A bad value: malformed `headers`, `timeout_ms` or boolean; unknown `accept` or `method`; `body` with `body_file`; empty `body_file`; `body` with a `json` method that sends no body; invalid `origin`, `request_headers` or `content_type`; a URL the client cannot use; `ca_file` on an `http://` URL, with `allow_insecure=true`, or naming a file that cannot be read or holds no valid PEM certificate. |
| `http.body_file_unreadable` | 1 | `body_file` could not be read; nothing was sent. |
| `http.client_failed` | 1 | The HTTP client (TLS backend) could not be set up. |
| `http.connection_failed` | 1 | Connecting failed: refused, unreachable, DNS, TLS (untrusted certificate, wrong host name, not TLS), or a proxy that refused the tunnel. The message ends with the underlying cause. |
| `http.timeout` | 124 | `timeout_ms` passed before the response body was complete. |
| `http.redirect_failed` | 1 | More than 10 redirects (for example a loop). |
| `http.request_failed` | 1 | Any other transfer failure, such as a response that ends before its declared length. |
| `http.status_error` | 1 | The server answered with a failure status (see section 3); the output is still printed. |
| `http.invalid_json_response` | 1 | `patch accept=json` got a 2xx body that is not JSON. |

## 7. Security notes

* TLS verification is on by default for every verb. `allow_insecure=true`
  turns it off for that stage.
* A server whose certificate does not chain to a public root (webpki roots)
  is reached with `ca_file=<pem>` naming its CA, with verification still on.
  `allow_insecure=true` is the insecure alternative and cannot be combined
  with `ca_file`. There is no option for a client certificate.
* Request headers given with `headers=` (for example `Authorization:Bearer
  ...`) appear in the process list and shell history. Prefer a short-lived
  token.
* There is no cookie jar: each stage is a separate request.

## 8. Limitations

* The whole response body is held in memory before it is printed.
* `headers=` values cannot contain `;`.
* Linux only.

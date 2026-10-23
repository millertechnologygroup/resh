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

| Verb        | Method        | Prints                                              | Non-2xx exits |
| ----------- | ------------- | --------------------------------------------------- | ------------- |
| `get`       | GET           | Body as text (default), raw bytes, or a JSON envelope | 1 |
| `head`      | HEAD          | JSON: url, status, ok, reason, headers              | **0** (check `ok`) |
| `headers`   | any (default GET) | JSON: url, status, status_text, headers (no body) | **0** (check `status`) |
| `options`   | OPTIONS       | JSON: allowed methods, status, headers              | 1 outside 200-399 |
| `preflight` | OPTIONS (CORS) | JSON: parsed Access-Control-* headers              | 1 |
| `json`      | any (default GET) | JSON envelope with the body parsed as JSON when possible | **0** (check `status`) |
| `post`      | POST          | Raw response body                                   | 1 |
| `put`       | PUT           | Body as text (default), raw bytes, or a JSON envelope | 1 |
| `patch`     | PATCH         | Raw bytes (default), text, or compact JSON          | 1 |
| `delete`    | DELETE        | Body as text (default), raw bytes, or pretty JSON   | 1 |

"Non-2xx exits 1" means: the response body (or JSON) is still printed to
stdout, the process exits 1, and a reason such as `Error: HTTP 404 Not Found`
goes to stderr. The status code is not used as the exit code. `head`,
`headers` and `json` treat any HTTP response as success, so a script must read
the status from the JSON.

## 4. Common arguments

| Argument       | Verbs | Notes |
| -------------- | ----- | ----- |
| `headers`      | all   | `Name:value;Name2:value2`. `Host`, `Content-Length`, `Connection` and `Transfer-Encoding` are dropped. A segment without `:` is an error for most verbs, but is silently ignored by `delete`, `options` and `preflight`. |
| `query`        | get, head, headers, post, put, patch, delete | `k=v&k2=v2`, appended to the URL's query. Not read by `json`, `options` or `preflight`. |
| `timeout_ms`   | see section 6 | Whole-request timeout in milliseconds. |
| `body`         | post, put, patch, delete, json | Inline request body. |
| `body_file`    | post, put, patch, delete | Local file sent as the body. |
| `content_type` | post, put, patch, delete, json | Sets `Content-Type`. |
| `accept`       | get, put, patch, delete, json, head | Output mode (`text`, `bytes`, `json`); see each verb. For `head` it only sets the request `Accept` header. |

Body precedence differs by verb: `post` and `put` use `body_file` when both are
given; `patch` and `delete` use `body`.

Default `Content-Type`: `put` sends `text/plain; charset=utf-8` for an inline
`body` (none for `body_file`); `delete` sends `application/octet-stream` when
a body is present; `json` sends `application/json` when `body` is non-empty;
`post` and `patch` send none unless `content_type` is given.

Redirects are followed (reqwest default, up to 10) by every verb.
`follow_redirects=false` is honored only by `headers` and `options`.

## 5. Verb reference

### get

```bash
resh http://api.example.com/v1/users/42.get
resh http://api.example.com/v1/users.get accept=json query='page=2&per_page=50'
resh https://example.com/logo.png.get accept=bytes > logo.png
```

`accept=text` (default) prints the body as received (raw bytes if it is not
UTF-8). `accept=bytes` prints raw bytes. `accept=json` prints an envelope:

```json
{"status":200,"ok":true,"method":"GET","headers":{"content-type":["application/json"]},"body":{"id":42,"name":"alice"},"body_text":"{\"id\":42,\"name\":\"alice\"}"}
```

`body` is parsed JSON only when the response `Content-Type` contains
`application/json`; otherwise it is the body as a string. Header values are
arrays. Any other `accept` value is an error.

### head

```bash
resh https://example.com/index.html.head
```

Output: `{"url", "status", "ok", "reason", "headers"}` with lowercase header
names and repeated headers joined with `, `. Exits 0 for every HTTP status.
The timeout is fixed at 10 seconds.

### headers

```bash
resh https://example.com.headers
resh https://example.com.headers method=HEAD follow_redirects=false
```

`method` may be GET, HEAD, POST, PUT, PATCH, DELETE or OPTIONS (default GET);
no body is sent. Output: `{"url", "status", "status_text", "headers"}` with
header values as arrays. Exits 0 for every HTTP status. An unsupported method
or malformed `headers` prints `{"url", "error": {"kind", "message"}}` and
exits 2; a network failure prints the same shape and exits 1.

### options

```bash
resh http://api.example.com/v1/users.options include_body=true
```

Output: `url`, `status`, `reason`, `backend` (`"reqwest"`), `headers`,
`allowed_methods` (parsed from `Allow`), `has_body`, and `body` when
`include_body=true` and the body is non-empty. Exits 0 for statuses 200-399.
A non-numeric `timeout_ms` is an error.

### preflight

```bash
resh http://api.example.com/users.preflight origin=https://example.org method=POST request_headers=Content-Type,Authorization
```

Sends `OPTIONS` with `Origin`, `Access-Control-Request-Method` and
`Access-Control-Request-Headers` from `origin`, `method` and
`request_headers` (comma or semicolon separated). Output: `url`, `method`,
`status`, `ok`, `cors` (`allowed_origins`, `allowed_methods`,
`allowed_headers`, `exposed_headers`, `allow_credentials`,
`max_age_seconds`) and `raw_headers`. On a network failure it prints the same
shape with `ok: false`, `status: null` and an `error` string, and exits 1.

### json

```bash
resh http://api.example.com/v1/users/42.json
resh http://api.example.com/v1/users.json method=POST body='{"name":"alice"}'
```

`method`: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS (default GET). The body
is sent only for POST, PUT, PATCH and DELETE. No `Accept` header is added.
Output:

```json
{"url":"http://api.example.com/v1/users/42","status":200,"status_text":"OK","headers":{"content-type":["application/json"]},"body":{"type":"json","value":{"id":42,"name":"alice"}}}
```

`accept=json` (default) gives `type: "json"` when the body parses, otherwise
`type: "text"`. `accept=text` always gives text; `accept=bytes` gives
`{"type": "bytes", "base64": "..."}`. A network failure prints an envelope
with `status: 0` and an `error` string, and exits 1. Any HTTP status exits 0.

### post

```bash
resh http://api.example.com/v1/users.post body='{"name":"alice"}' content_type=application/json
resh http://api.example.com/upload.post body_file=./payload.bin content_type=application/octet-stream
```

Prints the raw response body. No `accept` modes.

### put

```bash
resh http://api.example.com/v1/users/42.put body='{"name":"alice"}' content_type=application/json
resh https://staging.internal/v1/config.put body_file=./config.json accept=json allow_insecure=true
```

`accept`: `text` (default), `bytes`, or `json` (envelope
`{"status", "ok", "headers", "body"}`); an unknown value falls back to text.

`allow_insecure=true` **disables TLS certificate and host name verification**
for an `https://` URL. It is parsed strictly (true/false/1/0/yes/no/on/off;
anything else is an error) and is honored **only by `put`**. Every other verb
ignores it and always verifies certificates. Use it only against hosts you
control.

### patch

```bash
resh http://api.example.com/v1/users/42.patch body='{"name":"bob"}' content_type=application/json
```

`accept`: `bytes` (default), `text`, or `json` (the body re-printed as compact
JSON; a body that is not JSON is an error). The timeout is fixed at 30
seconds.

### delete

```bash
resh http://api.example.com/v1/users/42.delete
resh http://api.example.com/v1/users/42.delete accept=json
```

`accept`: `text` (default), `bytes`, or `json` (pretty-printed JSON; a body
that is not JSON is wrapped as `{"status": {"code", "ok"}, "body": "..."}`).
An unknown `accept` value prints a warning on stderr and falls back to text.
A network failure exits 2.

## 6. Timeouts

| Verb        | `timeout_ms` |
| ----------- | ------------ |
| `get`, `post`, `json`, `headers` | Enforced, default 10000. A non-numeric value is silently replaced by the default. |
| `options`   | Enforced, default 10000. A non-numeric value is an error. |
| `preflight` | Enforced, default 5000. Non-numeric falls back to the default. |
| `put`, `delete` | Enforced, default 30000. Non-numeric falls back to the default. |
| `head`      | **Ignored.** Fixed 10-second timeout. |
| `patch`     | **Ignored.** Fixed 30-second timeout. |

A timeout is reported as `Request timed out` (or `http delete error:
connection timed out`) and exits 1 (2 for `delete`).

## 7. Errors and exit codes

* 0: the request completed and the verb considers the status a success
  (always, for `head`, `headers` and `json`).
* 1: a non-2xx status (non-200-399 for `options`), a network or TLS failure, a
  timeout, an unreadable `body_file`, or an invalid argument.
* 2: `delete` network failures; `headers` with an unsupported method or
  malformed `headers`.

The failure reason is printed on stderr. When the handle itself has not
written to stderr, resh prints `Error: <reason>` (for example
`Error: HTTP 404 Not Found`, `Error: Connection failed`). `head`, `post`,
`put` and `delete` print their network-error message to stderr themselves,
without the `Error:` prefix.

## 8. Security notes

* TLS verification is on by default for every verb. Only `put` can turn it
  off, through `allow_insecure`.
* Request headers given with `headers=` (for example `Authorization:Bearer
  ...`) appear in the process list and shell history. Prefer a short-lived
  token.
* There is no client certificate, proxy, or cookie-jar option.

## 9. Limitations

* `head`, `headers` and `json` exit 0 for 4xx/5xx responses.
* `head` and `patch` ignore `timeout_ms`.
* `allow_insecure` works only with `put`.
* `follow_redirects` works only with `headers` and `options`.
* `json`, `options` and `preflight` do not read `query`.
* Linux only.

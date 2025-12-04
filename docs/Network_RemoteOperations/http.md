# HTTP Handle Documentation

The HTTP handle in Resource Shell allows you to make HTTP requests to web servers and APIs. You can use it with both `http://` and `https://` URLs to perform various operations like retrieving data, sending information, or checking server capabilities.

## Available Verbs

The HTTP handle supports 10 different verbs, each designed for specific HTTP operations:

- `get` - Retrieve data from a server
- `head` - Get only response headers (no body)
- `post` - Send data to create new resources
- `put` - Send data to create or update resources
- `patch` - Send data to partially update resources
- `delete` - Remove resources from a server
- `options` - Check what HTTP methods are allowed
- `preflight` - Perform CORS preflight requests
- `json` - Make requests with JSON response envelope
- `headers` - Get only response headers as JSON

## Common Parameters

Most HTTP verbs support these common parameters:

- `headers` - Custom HTTP headers (format: "Header:value;Another:value")
- `query` - Query parameters (format: "param=value&other=param")
- `accept` - Response format: "json", "text", or "bytes"
- `timeout_ms` - Request timeout in milliseconds (default: 30000)
- `allow_insecure` - For HTTPS, allow invalid certificates (format: "true")

## GET Verb

The `get` verb retrieves data from a server.

### Basic GET Request

**Example:**
```
http://{server_addr}/text.get
```

**Expected Response:**
```
hello world
```

### GET with JSON Response

**Example:**
```
http://{server_addr}/foo.get(query="x=1",accept="json")
```

**Expected Response:**
```json
{"ok":true,"value":42}
```

### GET with Custom Headers

**Example:**
```
http://{server_addr}/test.get(headers="X-Foo:bar;X-Bar:baz")
```

**Expected Response:**
```
success
```

### GET with Query Parameters

**Example:**
```
http://{server_addr}/search.get(query="q=rust&lang=en")
```

**Expected Response:**
```
search results
```

### GET with Bytes Mode

**Example:**
```
http://{server_addr}/binary.get(accept="bytes")
```

**Expected Response:**
Binary data (raw bytes)

### GET with Timeout

**Example:**
```
http://{server_addr}/slow.get(timeout_ms="1")
```

**Expected Behavior:**
Request times out and fails due to very short timeout

## HEAD Verb

The `head` verb gets only response headers without the body. It always returns JSON with status and header information.

### Basic HEAD Request

**Example:**
```
http://{server_addr}/ok.head
```

**Expected Response:**
```json
{
  "status": 200,
  "ok": true,
  "headers": {
    "x-test": "head-basic",
    "content-type": "text/plain"
  }
}
```

### HEAD with Custom Headers

**Example:**
```
http://{server_addr}/ok.head(headers="X-Foo:bar;X-Bar:baz")
```

**Expected Response:**
```json
{
  "status": 200,
  "ok": true,
  "headers": {
    "x-server-received": "yes",
    "content-type": "application/json"
  }
}
```

## POST Verb

The `post` verb sends data to create new resources.

### POST with Body Text

**Example:**
```
http://{server_addr}/echo.post(body="hello")
```

**Expected Response:**
```
hello
```

### POST with Body File

**Example:**
```
http://{server_addr}/echo.post(body="ignored",body_file="{temp_file_path}")
```

**Expected Response:**
```
from file
```

**Note:** When both `body` and `body_file` are provided, `body_file` takes priority.

### POST with Headers and Content Type

**Example:**
```
http://{server_addr}/test.post(body="{}",headers="X-Foo:bar;X-Bar:baz",content_type="application/json")
```

**Expected Response:**
```
success
```

## PUT Verb

The `put` verb sends data to create or update resources completely.

### PUT with Body Text

**Example:**
```
http://127.0.0.1:{port}/resource.put(body="hello", content_type="text/plain", accept="json")
```

**Expected Response:**
Response contains `"status":200` and `"ok":true`

### PUT with Body File

**Example:**
```
http://127.0.0.1:{port}/upload.put(body_file="{file_path}", accept="text")
```

**Expected Response:**
```
File uploaded successfully
```

## PATCH Verb

The `patch` verb sends data to partially update resources.

### PATCH with JSON Body

**Example:**
```
http://{server_addr}/resource.patch(body="{\"name\":\"test\"}", content_type="application/json", accept="json")
```

**Expected Response:**
```json
{"ok":true,"method":"PATCH"}
```

### PATCH with Headers and Query

**Example:**
```
http://{server_addr}/resource.patch(query="a=1&b=2", headers="X-Foo:bar", body="hello", content_type="text/plain", accept="text")
```

**Expected Response:**
```
updated
```

### PATCH with Body File

**Example:**
```
http://{server_addr}/resource.patch(body_file="{temp_file_path}", content_type="text/plain")
```

**Expected Response:**
Varies based on server implementation

## DELETE Verb

The `delete` verb removes resources from a server.

### Simple DELETE Request

**Example:**
```
http://{server_host_with_port}/resource.delete(accept="json")
```

**Expected Response:**
```json
{"deleted": true}
```

### DELETE with Headers and Query

**Example:**
```
http://{server_host_with_port}/item.delete(query="force=true",headers="X-Test:Yes",accept="text")
```

**Expected Response:**
```
success
```

### DELETE with 404 Error

**Example:**
```
http://{server_host_with_port}/notfound.delete(accept="text")
```

**Expected Behavior:**
Command fails with non-zero exit code

**Expected Response:**
```
not found
```

## OPTIONS Verb

The `options` verb checks what HTTP methods are allowed for a resource.

### Basic OPTIONS Request

**Example:**
```
http://{server_url}/resource.options
```

**Expected Response:**
```json
{
  "status": 204,
  "reason": "No Content",
  "backend": "reqwest",
  "has_body": false,
  "allowed_methods": ["GET", "POST", "OPTIONS"],
  "headers": {
    "allow": "GET, POST, OPTIONS",
    "x-test": "options-basic"
  },
  "url": "{server_url}/resource"
}
```

### OPTIONS with Body Included

**Example:**
```
http://{server_url}/resource.options(include_body="true")
```

**Expected Response:**
```json
{
  "status": 200,
  "has_body": true,
  "body": "OPTIONS response body",
  "allowed_methods": ["GET", "HEAD", "OPTIONS"]
}
```

## PREFLIGHT Verb

The `preflight` verb performs CORS preflight requests for cross-origin resource sharing.

### Basic CORS Preflight

**Example:**
```
http://{server_url}/api/resource.preflight
```

**Expected Response:**
```json
{
  "method": "OPTIONS",
  "status": 204,
  "ok": true,
  "url": "{server_url}/api/resource",
  "cors": {
    "allowed_origins": ["*"],
    "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
    "allowed_headers": ["X-Auth-Token", "Content-Type"],
    "exposed_headers": ["X-RateLimit-Remaining"],
    "allow_credentials": true,
    "max_age_seconds": 600
  },
  "raw_headers": {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, PUT, DELETE",
    "access-control-allow-headers": "X-Auth-Token, Content-Type",
    "access-control-expose-headers": "X-RateLimit-Remaining",
    "access-control-allow-credentials": "true",
    "access-control-max-age": "600"
  }
}
```

### PREFLIGHT with CORS Request Headers

**Example:**
```
http://{server_url}/api/resource.preflight(origin="https://app.example.com", method="POST", request_headers="X-Auth-Token,X-Trace-Id")
```

**Expected Response:**
```json
{
  "status": 200,
  "cors": {
    "allowed_origins": ["https://app.example.com"],
    "allowed_methods": ["GET", "POST"],
    "allowed_headers": ["X-Auth-Token", "X-Trace-Id"]
  }
}
```

## JSON Verb

The `json` verb makes requests and returns responses in a structured JSON envelope format.

### JSON GET Request

**Example:**
```
http://{server_host}:{server_port}/test.json(method="GET", accept="json")
```

**Expected Response:**
```json
{
  "status": 200,
  "status_text": "OK",
  "url": "http://{server_host}:{server_port}/test",
  "body": {
    "type": "json",
    "value": {
      "ok": true,
      "value": 42
    }
  }
}
```

### JSON with Text Fallback

**Example:**
```
http://{server_host}:{server_port}/text.json(method="GET", accept="json")
```

**Expected Response:**
```json
{
  "status": 200,
  "body": {
    "type": "text",
    "value": "Hello World"
  }
}
```

### JSON with Text Mode

**Example:**
```
http://{server_host}:{server_port}/text.json(method="GET", accept="text")
```

**Expected Response:**
```json
{
  "status": 200,
  "body": {
    "type": "text",
    "value": "Hello World"
  }
}
```

## HEADERS Verb

The `headers` verb gets only response headers as a structured JSON response.

### Basic Headers Request

**Example:**
```
http://{server_addr}/test.headers(method="GET", headers="X-Client:reshell")
```

**Expected Response:**
```json
{
  "status": 200,
  "status_text": "OK",
  "url": "http://{server_addr}/test",
  "headers": {
    "content-type": ["application/json"],
    "x-foo": ["bar"],
    "set-cookie": ["a=1", "b=2"]
  },
  "body": null
}
```

### Headers with Different Methods

**Example:**
```
http://{server_addr}/head.headers(method="HEAD")
```

**Expected Response:**
```json
{
  "status": 200,
  "headers": {
    "x-method": ["HEAD"]
  }
}
```

**Example:**
```
http://{server_addr}/post.headers(method="POST")
```

**Expected Response:**
```json
{
  "status": 201,
  "headers": {
    "x-method": ["POST"]
  }
}
```

## Error Handling

### Non-2xx Status Codes

Most verbs (except `head`, `options`, `preflight`, `json`, and `headers`) will exit with a non-zero status code when the HTTP response is not in the 2xx range, but they will still output the response body.

**Example:**
```
http://{server_addr}/error.get(accept="json")
```

**Expected Behavior:**
Command exits with failure status

**Expected Response:**
```json
{"error":"unavailable"}
```

### Timeout Errors

When a request times out, the command will fail.

**Example:**
```
http://{server_addr}/slow.get(timeout_ms="1")
```

**Expected Behavior:**
Command exits with failure status due to timeout

### Invalid JSON

When `accept="json"` is specified but the response is not valid JSON, the command will fail.

**Example:**
```
http://{server_addr}/invalid.get(accept="json")
```

**Expected Behavior:**
Command exits with failure status due to invalid JSON

## Response Formats

### Text Mode (Default)

Returns the response body as plain text. If the response contains invalid UTF-8, it falls back to binary mode.

### JSON Mode

Attempts to parse the response body as JSON. If parsing fails, the command will fail.

### Bytes Mode

Returns the raw response bytes without any text conversion. Useful for binary data.

## HTTPS Support

The HTTP handle supports HTTPS URLs. For development or testing with self-signed certificates, use the `allow_insecure="true"` parameter.

**Example:**
```
https://example.com/api.get(allow_insecure="true")
```

## Tips

1. Use `head` verb when you only need to check if a resource exists or get metadata
2. Use `options` verb to discover what HTTP methods a server supports
3. Use `preflight` verb when working with CORS-enabled APIs
4. Use `json` verb when you need both response data and metadata in a single envelope
5. Use `headers` verb when you only need header information in a structured format
6. The `body_file` parameter always takes priority over the `body` parameter
7. Headers are automatically converted to lowercase in responses
8. Multiple headers with the same name (like `Set-Cookie`) are preserved as arrays
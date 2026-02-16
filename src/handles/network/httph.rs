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

const HTTP_HELP_TEXT: &str = r#"
RESOURCE SHELL - HTTP HANDLE
============================

USAGE:
  http://HOST:PORT/PATH.VERB(arguments)
  https://HOST:PORT/PATH.VERB(arguments)

DESCRIPTION:
  The HTTP handle allows you to make HTTP/HTTPS requests to web servers and
  APIs. Supports all standard REST methods, custom headers, request bodies,
  query parameters, CORS preflight, JSON/text/binary response modes, and
  HTTPS with certificate validation. Perfect for API testing, web scraping,
  and service integration.

URL FORMATS:
  http://example.com/path.VERB(arguments)
  https://api.example.com/v1/resource.VERB(arguments)
  http://localhost:8080/endpoint.VERB(arguments)
  https://example.com:443/api/data.VERB(arguments)

VERBS (10 total):

  Standard HTTP Methods:
    get             Retrieve data from a server (GET request)
    head            Get only response headers, no body (HEAD request)
    post            Send data to create new resources (POST request)
    put             Send data to create or update resources (PUT request)
    patch           Send data to partially update resources (PATCH request)
    delete          Remove resources from a server (DELETE request)
    options         Check what HTTP methods are allowed (OPTIONS request)

  Special Purpose:
    preflight       Perform CORS preflight requests (OPTIONS with CORS headers)
    json            Make requests with JSON response envelope
    headers         Get only response headers as structured JSON

EXAMPLES:

  GET Requests:
    # Basic GET request
    http://example.com/api/data.get

    # GET with JSON response
    http://api.example.com/users.get(accept="json")

    # GET with query parameters
    http://api.example.com/search.get(query="q=rust&limit=10")

    # GET with custom headers
    http://api.example.com/data.get(headers="Authorization:Bearer token123;Accept:application/json")

    # GET with timeout
    http://slow-api.com/data.get(timeout_ms=5000)

    # GET binary data
    http://example.com/image.png.get(accept="bytes")

    # GET with multiple query parameters
    http://api.example.com/items.get(query="category=books&sort=price&order=asc")

  HEAD Requests:
    # Check if resource exists
    http://example.com/file.txt.head

    # Get headers with custom request headers
    http://api.example.com/resource.head(headers="X-API-Key:secret")

    # Check content type and size
    http://cdn.example.com/large-file.zip.head

  POST Requests:
    # POST with text body
    http://api.example.com/echo.post(body="hello world")

    # POST with JSON body
    http://api.example.com/users.post(body="{{\"name\":\"Alice\",\"email\":\"alice@example.com\"}}",content_type="application/json")

    # POST from file
    http://api.example.com/upload.post(body_file="/path/to/data.json",content_type="application/json")

    # POST with headers and query
    http://api.example.com/items.post(body="{{\"title\":\"New Item\"}}",headers="Authorization:Bearer token;Content-Type:application/json",query="notify=true")

    # POST form data
    http://api.example.com/form.post(body="name=John&email=john@example.com",content_type="application/x-www-form-urlencoded")

  PUT Requests:
    # PUT to create/update resource
    http://api.example.com/users/123.put(body="{{\"name\":\"Bob\"}}",content_type="application/json")

    # PUT from file
    http://api.example.com/document.put(body_file="/path/to/doc.pdf",content_type="application/pdf")

    # PUT with JSON response
    http://api.example.com/config.put(body="{{\"setting\":\"value\"}}",content_type="application/json",accept="json")

  PATCH Requests:
    # PATCH partial update
    http://api.example.com/users/123.patch(body="{{\"email\":\"newemail@example.com\"}}",content_type="application/json")

    # PATCH with query parameters
    http://api.example.com/resource.patch(body="{{\"status\":\"active\"}}",query="version=2",content_type="application/json")

    # PATCH from file
    http://api.example.com/document.patch(body_file="/path/to/changes.json",content_type="application/json")

  DELETE Requests:
    # Simple DELETE
    http://api.example.com/users/123.delete

    # DELETE with confirmation parameter
    http://api.example.com/resource.delete(query="force=true")

    # DELETE with headers
    http://api.example.com/item.delete(headers="Authorization:Bearer token;X-Request-ID:abc123")

    # DELETE with JSON response
    http://api.example.com/resource/456.delete(accept="json")

  OPTIONS Requests:
    # Check allowed methods
    http://api.example.com/resource.options

    # OPTIONS with response body
    http://api.example.com/endpoint.options(include_body="true")

    # Check CORS support
    http://api.example.com/api/data.options

  CORS Preflight:
    # Basic preflight check
    http://api.example.com/resource.preflight

    # Preflight with origin
    http://api.example.com/api/users.preflight(origin="https://myapp.example.com")

    # Preflight with method and headers
    http://api.example.com/api/data.preflight(origin="https://app.com",method="POST",request_headers="Authorization,Content-Type")

    # Check credentials support
    http://api.example.com/auth.preflight(origin="https://app.com",method="POST")

  JSON Envelope:
    # GET with JSON envelope
    http://api.example.com/data.json(method="GET")

    # POST with JSON envelope
    http://api.example.com/users.json(method="POST",body="{{\"name\":\"Alice\"}}",content_type="application/json")

    # Include metadata in response
    http://api.example.com/resource.json(method="GET",accept="json")

  Headers Only:
    # Get headers as JSON
    http://api.example.com/resource.headers(method="GET")

    # Get POST response headers
    http://api.example.com/data.headers(method="POST",body="test")

    # Check authentication headers
    http://api.example.com/auth.headers(method="GET",headers="Authorization:Bearer token")

  HTTPS with Certificate Options:
    # HTTPS with valid certificate
    https://api.example.com/secure.get

    # HTTPS allowing self-signed certificates
    https://localhost:8443/api.get(allow_insecure="true")

    # HTTPS with custom headers
    https://secure-api.com/data.get(headers="Authorization:Bearer secret",allow_insecure="false")

  Authentication Examples:
    # Bearer token
    http://api.example.com/protected.get(headers="Authorization:Bearer eyJhbGc...")

    # API key in header
    http://api.example.com/data.get(headers="X-API-Key:your-api-key-here")

    # Basic auth (base64 encoded)
    http://api.example.com/resource.get(headers="Authorization:Basic dXNlcjpwYXNz")

    # Multiple auth headers
    http://api.example.com/data.get(headers="X-API-Key:key123;X-Client-ID:client456")

  API Integration Patterns:
    # List resources with pagination
    http://api.example.com/users.get(query="page=1&per_page=20",accept="json")

    # Create resource
    http://api.example.com/users.post(body="{{\"name\":\"New User\"}}",content_type="application/json",accept="json")

    # Update resource
    http://api.example.com/users/42.put(body="{{\"name\":\"Updated\"}}",content_type="application/json")

    # Partial update
    http://api.example.com/users/42.patch(body="{{\"active\":true}}",content_type="application/json")

    # Delete resource
    http://api.example.com/users/42.delete(accept="json")

    # Check resource status
    http://api.example.com/jobs/123.head

COMMON PARAMETERS:

  All Verbs:
    headers=HEADERS        Custom HTTP headers (format: "Key:value;Another:value")
    query=QUERY            Query parameters (format: "param=value&other=value")
    accept=FORMAT          Response format: json, text, bytes (default: text)
    timeout_ms=MILLISECONDS Request timeout (default: 30000)
    allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

  POST, PUT, PATCH:
    body=TEXT              Request body as text
    body_file=PATH         Request body from file (takes priority over body)
    content_type=TYPE      Content-Type header (e.g., "application/json")

  OPTIONS:
    include_body=BOOL      Include response body (default: false)

  PREFLIGHT:
    origin=URL             Origin for CORS check (e.g., "https://app.com")
    method=METHOD          HTTP method to preflight (default: GET)
    request_headers=HEADERS Headers to request permission for (comma-separated)

  JSON, HEADERS:
    method=METHOD          HTTP method to use (GET, POST, PUT, PATCH, DELETE, etc.)
    body=TEXT              Request body (when method is POST/PUT/PATCH)
    body_file=PATH         Request body from file
    content_type=TYPE      Content-Type header

HEADERS FORMAT:

  Headers are specified as semicolon-separated key:value pairs:
    "Header-Name:value"
    "Header1:value1;Header2:value2"
    "Authorization:Bearer token;Content-Type:application/json"

  Common headers:
    Authorization:Bearer TOKEN         Bearer token authentication
    Authorization:Basic BASE64         Basic authentication
    X-API-Key:KEY                      API key authentication
    Content-Type:application/json      JSON content type
    Content-Type:application/xml       XML content type
    Content-Type:text/plain            Plain text
    Accept:application/json            Request JSON response
    User-Agent:MyApp/1.0               Custom user agent
    X-Request-ID:uuid                  Request tracking ID

  Notes:
    • Header names are case-insensitive
    • Values can contain spaces
    • Use semicolon (;) to separate multiple headers
    • Colons (:) separate name from value

QUERY PARAMETERS FORMAT:

  Query parameters are specified as ampersand-separated key=value pairs:
    "param=value"
    "param1=value1&param2=value2"
    "search=rust%20programming&limit=10&offset=0"

  URL encoding:
    • Spaces → %20 or +
    • Special characters are URL-encoded
    • Example: "q=hello world&lang=en" → "q=hello%20world&lang=en"

  Notes:
    • Parameters are appended to the URL
    • Use & to separate multiple parameters
    • Use = to separate name from value

CONTENT TYPES:

  Common content types for request bodies:

  JSON:
    application/json                   JSON data

  Form Data:
    application/x-www-form-urlencoded  Form submissions
    multipart/form-data                File uploads (not directly supported)

  Text:
    text/plain                         Plain text
    text/html                          HTML content
    text/csv                           CSV data
    text/xml                           XML content

  Binary:
    application/octet-stream           Generic binary
    application/pdf                    PDF documents
    image/png                          PNG images
    image/jpeg                         JPEG images
    application/zip                    ZIP archives

RESPONSE FORMATS:

  text (default):
    Returns response body as plain text
    Falls back to binary if invalid UTF-8
    Suitable for HTML, plain text, JSON strings

  json:
    Parses response body as JSON
    Command fails if response is not valid JSON
    Returns structured JSON data
    Best for API responses

  bytes:
    Returns raw response bytes
    No text conversion
    Suitable for binary data (images, files)
    Preserves exact byte content

  Format selection:
    accept="text"     Plain text output
    accept="json"     Parsed JSON output
    accept="bytes"    Raw binary output

HTTPS SUPPORT:

  The HTTP handle supports HTTPS URLs with certificate validation:

  Valid certificates (default):
    https://example.com/api.get

  Self-signed or invalid certificates:
    https://localhost:8443/api.get(allow_insecure="true")

  Certificate validation:
    • Default: Certificates are validated
    • allow_insecure="true": Skip validation (development/testing only)
    • Production: Always use valid certificates

  Security notes:
    • Only use allow_insecure for development/testing
    • Never use allow_insecure in production
    • Valid certificates are free (Let's Encrypt)
    • Self-signed certificates should not be trusted in production

VERB-SPECIFIC BEHAVIORS:

  get, post, put, patch, delete:
    • Exit with non-zero code for non-2xx status
    • Output response body regardless of status
    • Text mode by default
    • Support all response formats

  head:
    • Always returns JSON with status and headers
    • No response body
    • Never fails on non-2xx status
    • Useful for checking resource existence

  options:
    • Returns JSON with allowed methods and headers
    • Includes "allowed_methods" array
    • Never fails on non-2xx status
    • Optional body inclusion with include_body="true"

  preflight:
    • Performs CORS preflight (OPTIONS with CORS headers)
    • Returns JSON with CORS policy
    • Includes allowed_origins, allowed_methods, allowed_headers
    • Never fails on non-2xx status

  json:
    • Wraps response in JSON envelope
    • Includes status, url, headers, body
    • Body type: "json", "text", or "bytes"
    • Never fails on non-2xx status
    • Useful for getting full response metadata

  headers:
    • Returns only headers as JSON
    • No response body in output
    • Never fails on non-2xx status
    • Headers with multiple values become arrays
    • Useful for inspecting server responses

OUTPUT FORMATS:

  Standard verbs (text mode):
    hello world

  Standard verbs (JSON mode):
    {{
      "ok": true,
      "data": {{...}}
    }}

  head verb:
    {{
      "status": 200,
      "ok": true,
      "headers": {{
        "content-type": "text/plain",
        "content-length": "42"
      }}
    }}

  options verb:
    {{
      "status": 204,
      "reason": "No Content",
      "backend": "reqwest",
      "has_body": false,
      "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
      "headers": {{
        "allow": "GET, POST, PUT, DELETE"
      }},
      "url": "http://example.com/resource"
    }}

  preflight verb:
    {{
      "method": "OPTIONS",
      "status": 204,
      "ok": true,
      "url": "http://api.example.com/resource",
      "cors": {{
        "allowed_origins": ["*"],
        "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
        "allowed_headers": ["Content-Type", "Authorization"],
        "exposed_headers": ["X-RateLimit-Remaining"],
        "allow_credentials": true,
        "max_age_seconds": 600
      }},
      "raw_headers": {{
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, PUT, DELETE"
      }}
    }}

  json verb:
    {{
      "status": 200,
      "status_text": "OK",
      "url": "http://api.example.com/data",
      "body": {{
        "type": "json",
        "value": {{
          "ok": true,
          "data": [...]
        }}
      }}
    }}

  headers verb:
    {{
      "status": 200,
      "status_text": "OK",
      "url": "http://api.example.com/resource",
      "headers": {{
        "content-type": ["application/json"],
        "x-custom": ["value"],
        "set-cookie": ["session=abc", "token=xyz"]
      }},
      "body": null
    }}

EXIT CODES:
  0                      Success (2xx status for standard verbs)
  1                      General error (network, timeout, invalid arguments)
  2                      Non-2xx HTTP status (for get, post, put, patch, delete)
  3                      Invalid JSON (when accept="json")

ERROR HANDLING:

  Network errors:
    • Connection refused
    • DNS resolution failure
    • Timeout exceeded
    • SSL/TLS handshake failure

  HTTP errors (standard verbs):
    • Non-2xx status codes cause non-zero exit
    • Response body is still output
    • Example: 404 Not Found, 500 Internal Server Error

  Parsing errors:
    • Invalid JSON with accept="json"
    • Command fails with error message
    • Use accept="text" as fallback

  Timeout errors:
    • Request exceeds timeout_ms
    • Default timeout: 30000ms (30 seconds)
    • Increase timeout for slow APIs

  Certificate errors:
    • Invalid HTTPS certificate
    • Use allow_insecure="true" for testing only
    • Fix certificate issues in production

  Error examples:

    Connection refused:
      Error: connection refused

    Timeout:
      Error: request timeout after 5000ms

    Invalid certificate:
      Error: invalid SSL certificate
      Solution: Use allow_insecure="true" or fix certificate

    404 Not Found:
      HTTP 404: {{"error": "resource not found"}}
      Exit code: 2

    Invalid JSON:
      Error: response is not valid JSON
      Use accept="text" to see raw response

COMMON WORKFLOWS:

  REST API CRUD Operations:
    # Create (POST)
    http://api.example.com/users.post(body="{{\"name\":\"Alice\"}}",content_type="application/json",accept="json")
    
    # Read (GET)
    http://api.example.com/users/123.get(accept="json")
    
    # Update (PUT - full replacement)
    http://api.example.com/users/123.put(body="{{\"name\":\"Alice Smith\"}}",content_type="application/json")
    
    # Partial Update (PATCH)
    http://api.example.com/users/123.patch(body="{{\"email\":\"alice@example.com\"}}",content_type="application/json")
    
    # Delete
    http://api.example.com/users/123.delete(accept="json")

  API Authentication Flow:
    # Get auth token
    http://api.example.com/auth/login.post(body="{{\"user\":\"alice\",\"pass\":\"secret\"}}",content_type="application/json",accept="json")
    
    # Use token in subsequent requests
    http://api.example.com/protected.get(headers="Authorization:Bearer eyJhbGc...")
    
    # Refresh token
    http://api.example.com/auth/refresh.post(headers="Authorization:Bearer old_token",accept="json")

  Health Checks and Monitoring:
    # Check if service is up
    http://api.example.com/health.head
    
    # Get service status
    http://api.example.com/health.get(accept="json")
    
    # Check response time
    http://api.example.com/ping.get(timeout_ms=1000)

  CORS Configuration Check:
    # Check CORS policy
    http://api.example.com/resource.preflight(origin="https://myapp.com")
    
    # Test specific method
    http://api.example.com/api/data.preflight(origin="https://myapp.com",method="POST")
    
    # Check allowed headers
    http://api.example.com/upload.preflight(origin="https://app.com",method="POST",request_headers="Authorization,Content-Type")

  File Download:
    # Download binary file
    http://cdn.example.com/file.pdf.get(accept="bytes") > file.pdf
    
    # Download JSON data
    http://api.example.com/export.get(accept="json") > data.json
    
    # Check file size before download
    http://cdn.example.com/largefile.zip.head

  Web Scraping:
    # Get HTML page
    http://example.com/page.html.get(accept="text")
    
    # Get with custom user agent
    http://example.com/data.get(headers="User-Agent:Mozilla/5.0 MyBot")
    
    # Follow redirects (automatic)
    http://example.com/redirect.get

  API Testing:
    # Test endpoint availability
    http://api.example.com/v1/users.options
    
    # Test with different content types
    http://api.example.com/data.post(body="test",content_type="text/plain")
    http://api.example.com/data.post(body="{{}}",content_type="application/json")
    
    # Test error handling
    http://api.example.com/error.get(accept="json")

  Pagination:
    # First page
    http://api.example.com/items.get(query="page=1&per_page=20",accept="json")
    
    # Next page
    http://api.example.com/items.get(query="page=2&per_page=20",accept="json")
    
    # With cursor-based pagination
    http://api.example.com/items.get(query="cursor=next_token",accept="json")

  Batch Operations:
    # Multiple creates
    for user in users; do
      http://api.example.com/users.post(body="$user",content_type="application/json")
    done
    
    # Bulk delete
    for id in ids; do
      http://api.example.com/items/$id.delete
    done

  Development and Testing:
    # Test against local server
    http://localhost:8080/api/test.get(accept="json")
    
    # Test with self-signed certificate
    https://localhost:8443/api.get(allow_insecure="true")
    
    # Debug response headers
    http://localhost:8080/debug.headers(method="GET")
    
    # Get full response envelope
    http://localhost:8080/test.json(method="GET")

BEST PRACTICES:
  • Use appropriate HTTP methods (GET for retrieval, POST for creation, etc.)
  • Include proper Content-Type headers for request bodies
  • Use accept="json" for API responses to get structured data
  • Set reasonable timeout values based on expected response times
  • Use HTTPS in production for secure communication
  • Never use allow_insecure="true" in production
  • Include authentication headers (Authorization, X-API-Key) for protected endpoints
  • Use query parameters for filtering and pagination
  • Use POST/PUT/PATCH appropriately (POST=create, PUT=replace, PATCH=update)
  • Check with HEAD before downloading large files
  • Use OPTIONS to discover API capabilities
  • Use preflight to verify CORS configuration
  • Handle errors gracefully (check exit codes)
  • Use body_file for large request bodies
  • Include User-Agent header for web scraping
  • Use X-Request-ID for request tracing
  • Implement retry logic for transient failures
  • Cache responses when appropriate
  • Use JSON envelope verb for metadata needs
  • Use headers verb to inspect server responses
  • Test with different content types
  • Validate JSON responses
  • Use proper URL encoding for query parameters
  • Include Accept header to specify response format
  • Use Bearer tokens for OAuth2
  • Use Basic auth only over HTTPS
  • Monitor rate limits via response headers
  • Use proper HTTP status codes in your own services
  • Document your API endpoints
  • Version your APIs (e.g., /v1/, /v2/)
  • Use standard HTTP headers
  • Implement proper CORS policies
  • Use compression when available (gzip, deflate)

CORS (Cross-Origin Resource Sharing):

  CORS allows web applications to make requests to different domains.

  Preflight requests:
    • Browser sends OPTIONS request before actual request
    • Checks if server allows the origin, method, and headers
    • Server responds with CORS headers

  CORS headers:
    Access-Control-Allow-Origin       Allowed origins (* or specific)
    Access-Control-Allow-Methods      Allowed HTTP methods
    Access-Control-Allow-Headers      Allowed request headers
    Access-Control-Expose-Headers     Headers exposed to client
    Access-Control-Allow-Credentials  Allow credentials (cookies)
    Access-Control-Max-Age            Cache duration for preflight

  Using preflight verb:
    # Check if cross-origin request is allowed
    http://api.example.com/data.preflight(origin="https://myapp.com",method="POST")

  Common scenarios:
    • JavaScript fetch() from different domain
    • AJAX requests to external APIs
    • WebSocket connections
    • Font loading from CDN

AUTHENTICATION PATTERNS:

  Bearer Token (OAuth2, JWT):
    headers="Authorization:Bearer eyJhbGciOiJIUzI1NiIs..."

  API Key (Header):
    headers="X-API-Key:your-api-key-here"

  API Key (Query):
    query="api_key=your-api-key"

  Basic Auth:
    # Encode "user:pass" as base64
    headers="Authorization:Basic dXNlcjpwYXNz"

  Custom Authentication:
    headers="X-Auth-Token:token123;X-Client-ID:client456"

  Multiple Headers:
    headers="Authorization:Bearer token;X-API-Key:key;X-Client-Version:1.0"

BODY PARAMETER PRIORITY:

  When both body and body_file are specified:
    • body_file takes priority
    • body parameter is ignored
    • Useful for conditional file uploads

  Example:
    http://api.example.com/data.post(body="fallback",body_file="/path/to/data.json")
    # Uses content from /path/to/data.json, ignores "fallback"

HEADER NORMALIZATION:

  Response headers are normalized:
    • Converted to lowercase
    • Multiple values preserved as arrays
    • Example: Set-Cookie becomes ["cookie1", "cookie2"]

  Request headers:
    • Case-insensitive
    • Standard format: "Header-Name:value"
    • Example: "content-type:application/json" or "Content-Type:application/json"

TIMEOUT BEHAVIOR:

  Default timeout: 30000ms (30 seconds)

  Timeout includes:
    • DNS resolution
    • Connection establishment
    • Request sending
    • Response receiving
    • SSL/TLS handshake

  Timeout examples:
    timeout_ms=1000          1 second (fast operations)
    timeout_ms=5000          5 seconds (typical API)
    timeout_ms=30000         30 seconds (default)
    timeout_ms=60000         1 minute (slow operations)
    timeout_ms=300000        5 minutes (large uploads/downloads)

BINARY DATA:

  Downloading binary files:
    http://cdn.example.com/file.pdf.get(accept="bytes") > output.pdf
    http://example.com/image.png.get(accept="bytes") > image.png

  Uploading binary files:
    http://api.example.com/upload.post(body_file="/path/to/file.bin",content_type="application/octet-stream")

  Binary response handling:
    • accept="bytes" preserves exact byte content
    • No text encoding/decoding
    • Suitable for images, PDFs, archives

RATE LIMITING:

  Many APIs implement rate limiting. Common patterns:

  Check rate limit headers:
    http://api.example.com/data.headers(method="GET")
    # Look for: X-RateLimit-Limit, X-RateLimit-Remaining

  Common rate limit headers:
    X-RateLimit-Limit         Total requests allowed
    X-RateLimit-Remaining     Requests remaining
    X-RateLimit-Reset         Reset timestamp
    Retry-After               Seconds until retry allowed

  Handling rate limits:
    • Check headers before making requests
    • Implement exponential backoff
    • Space out requests
    • Use appropriate timeout values

DEBUGGING:

  Inspect full response:
    http://api.example.com/data.json(method="GET")

  Check response headers:
    http://api.example.com/data.headers(method="GET")

  Test with verbose output:
    # Use json or headers verb for full details

  Common debugging steps:
    1. Check if server is reachable (HEAD request)
    2. Inspect response headers (headers verb)
    3. Get full response envelope (json verb)
    4. Test with different accept formats
    5. Verify authentication headers
    6. Check for rate limiting
    7. Test with increased timeout
    8. Verify request body format
    9. Check Content-Type header
    10. Test with allow_insecure for HTTPS issues

PERFORMANCE CONSIDERATIONS:

  Connection reuse:
    • HTTP/1.1 keep-alive (automatic)
    • Consider connection pooling for batch operations

  Response size:
    • Use HEAD to check Content-Length before GET
    • Use query parameters for filtering
    • Request only needed fields if API supports it

  Timeouts:
    • Set appropriate timeouts for operation type
    • Too short: false failures
    • Too long: wasted time on failures

  Compression:
    • Most servers support gzip/deflate (automatic)
    • Reduces transfer time for large responses

  Parallel requests:
    • Use shell job control for concurrent requests
    • Mind rate limits

LIMITATIONS:

  • No built-in retry logic (implement in shell scripts)
  • No connection pooling across commands
  • No cookie jar persistence
  • No automatic redirect following for all verbs (GET follows automatically)
  • No form-data multipart encoding (use application/x-www-form-urlencoded)
  • No WebSocket support
  • No HTTP/2 server push
  • No progress indicators for large transfers
  • Headers must be specified as single parameter
  • Query parameters must be URL-encoded manually

INTEGRATION WITH OTHER HANDLES:

  With file handle:
    # Download and save
    http://api.example.com/data.get(accept="json") > data.json
    file:///data.json.read

  With log handle:
    # Log API responses
    http://api.example.com/data.get | log://./api-log.txt.append

  With event handle:
    # Emit event on API call
    http://api.example.com/webhook.post(body="{{...}}",content_type="application/json")
    event://emit(topic="api.called")

  With config handle:
    # Store API configuration
    config://app/api_endpoint.set(value="https://api.example.com")
    config://app/api_key.set(value="secret-key")

SECURITY CONSIDERATIONS:

  • Always use HTTPS in production
  • Never log or expose authentication tokens
  • Use environment variables for secrets
  • Validate SSL certificates (don't use allow_insecure)
  • Implement proper authentication
  • Use short-lived tokens
  • Rotate API keys regularly
  • Use HTTPS for Basic auth
  • Validate and sanitize inputs
  • Implement rate limiting
  • Monitor for suspicious activity
  • Use proper CORS policies
  • Keep dependencies updated
  • Use strong authentication methods
  • Implement proper error handling
  • Don't expose internal errors to clients

MORE INFO:
  For complete documentation of HTTP handle operations:
  https://github.com/[your-org]/resource-shell/docs/Network_RemoteOperations/http.md

  HTTP specification:
  https://www.rfc-editor.org/rfc/rfc7230 (HTTP/1.1 Message Syntax)
  https://www.rfc-editor.org/rfc/rfc7231 (HTTP/1.1 Semantics)

  HTTP methods:
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods

  HTTP status codes:
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Status

  CORS:
  https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

  Use 'http:// --help=VERB' or 'https:// --help=VERB' for detailed help
  on a specific verb.
"#;

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

    /// Check if this is a help request and display help if so
    fn check_and_display_help(verb: &str, io: &mut IoStreams) -> Result<Option<Status>> {
        // Check for help verbs
        if verb == "--help" || verb == "-h" || verb == "help" {
            write!(io.stdout, "{}", HTTP_HELP_TEXT)?;
            return Ok(Some(Status::ok()));
        }
        
        // Check for verb-specific help
        if verb.starts_with("--help=") {
            let help_verb = verb.strip_prefix("--help=").unwrap_or("");
            Self::display_verb_help(help_verb, io)?;
            return Ok(Some(Status::ok()));
        }
        
        Ok(None)
    }
    
    /// Display help for a specific verb
    fn display_verb_help(verb: &str, io: &mut IoStreams) -> Result<Status> {
        match verb {
            "get" => {
                write!(io.stdout, r#"
GET VERB - HTTP HANDLE
=====================

DESCRIPTION:
  Retrieve data from a server using an HTTP GET request. This is the most
  common HTTP method for fetching data from APIs, web services, and websites.

SYNTAX:
  http://HOST:PORT/PATH.get(arguments)
  https://HOST:PORT/PATH.get(arguments)

COMMON PARAMETERS:
  headers=HEADERS        Custom HTTP headers (format: "Key:value;Another:value")
  query=QUERY            Query parameters (format: "param=value&other=value")
  accept=FORMAT          Response format: json, text, bytes (default: text)
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # Basic GET request
  http://example.com/api/data.get

  # GET with JSON response
  http://api.example.com/users.get(accept="json")

  # GET with query parameters
  http://api.example.com/search.get(query="q=rust&limit=10")

  # GET with authentication
  http://api.example.com/protected.get(headers="Authorization:Bearer token123")

  # GET with timeout
  http://slow-api.com/data.get(timeout_ms=5000)

  # GET binary data
  http://example.com/image.png.get(accept="bytes")

RESPONSE:
  • Text format (default): Returns response body as plain text
  • JSON format: Parses response as JSON, fails if invalid
  • Bytes format: Returns raw binary data

EXIT CODES:
  0    Success (2xx HTTP status)
  1    Network error or invalid arguments
  2    Non-2xx HTTP status
  3    Invalid JSON (when accept="json")

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "head" => {
                write!(io.stdout, r#"
HEAD VERB - HTTP HANDLE
======================

DESCRIPTION:
  Get only the response headers from a server without retrieving the body.
  Useful for checking if a resource exists, getting content length, or
  checking the last-modified date without downloading the entire resource.

SYNTAX:
  http://HOST:PORT/PATH.head(arguments)
  https://HOST:PORT/PATH.head(arguments)

COMMON PARAMETERS:
  headers=HEADERS        Custom HTTP headers for the request
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # Check if resource exists
  http://example.com/file.txt.head

  # Get headers with authentication
  http://api.example.com/resource.head(headers="X-API-Key:secret")

  # Check content type and size
  http://cdn.example.com/large-file.zip.head

RESPONSE:
  Always returns JSON with status and headers:
  {{
    "status": 200,
    "ok": true,
    "headers": {{
      "content-type": "text/plain",
      "content-length": "42"
    }}
  }}

EXIT CODES:
  Always returns 0 (never fails on HTTP status)

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "post" => {
                write!(io.stdout, r#"
POST VERB - HTTP HANDLE
======================

DESCRIPTION:
  Send data to a server to create new resources. Commonly used for form
  submissions, API resource creation, and uploading data.

SYNTAX:
  http://HOST:PORT/PATH.post(arguments)
  https://HOST:PORT/PATH.post(arguments)

PARAMETERS:
  body=TEXT              Request body as text
  body_file=PATH         Request body from file (takes priority over body)
  content_type=TYPE      Content-Type header (e.g., "application/json")
  headers=HEADERS        Custom HTTP headers
  query=QUERY            Query parameters
  accept=FORMAT          Response format: json, text, bytes (default: text)
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # POST with text body
  http://api.example.com/echo.post(body="hello world")

  # POST JSON data
  http://api.example.com/users.post(body="{{\"name\":\"Alice\"}}",content_type="application/json")

  # POST from file
  http://api.example.com/upload.post(body_file="/path/to/data.json",content_type="application/json")

  # POST form data
  http://api.example.com/form.post(body="name=John&email=john@example.com",content_type="application/x-www-form-urlencoded")

EXIT CODES:
  0    Success (2xx HTTP status)
  1    Network error or invalid arguments
  2    Non-2xx HTTP status
  3    Invalid JSON (when accept="json")

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "put" => {
                write!(io.stdout, r#"
PUT VERB - HTTP HANDLE
=====================

DESCRIPTION:
  Send data to a server to create or completely replace a resource.
  PUT is idempotent - multiple identical requests have the same effect.

SYNTAX:
  http://HOST:PORT/PATH.put(arguments)
  https://HOST:PORT/PATH.put(arguments)

PARAMETERS:
  body=TEXT              Request body as text
  body_file=PATH         Request body from file (takes priority over body)
  content_type=TYPE      Content-Type header (e.g., "application/json")
  headers=HEADERS        Custom HTTP headers
  query=QUERY            Query parameters
  accept=FORMAT          Response format: json, text, bytes (default: text)
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # PUT to create/update resource
  http://api.example.com/users/123.put(body="{{\"name\":\"Bob\"}}",content_type="application/json")

  # PUT from file
  http://api.example.com/document.put(body_file="/path/to/doc.pdf",content_type="application/pdf")

  # PUT with JSON response
  http://api.example.com/config.put(body="{{\"setting\":\"value\"}}",content_type="application/json",accept="json")

EXIT CODES:
  0    Success (2xx HTTP status)
  1    Network error or invalid arguments
  2    Non-2xx HTTP status
  3    Invalid JSON (when accept="json")

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "patch" => {
                write!(io.stdout, r#"
PATCH VERB - HTTP HANDLE
=======================

DESCRIPTION:
  Send data to a server to partially update a resource. Unlike PUT,
  PATCH only modifies the specified fields, leaving other fields unchanged.

SYNTAX:
  http://HOST:PORT/PATH.patch(arguments)
  https://HOST:PORT/PATH.patch(arguments)

PARAMETERS:
  body=TEXT              Request body as text
  body_file=PATH         Request body from file (takes priority over body)
  content_type=TYPE      Content-Type header (e.g., "application/json")
  headers=HEADERS        Custom HTTP headers
  query=QUERY            Query parameters
  accept=FORMAT          Response format: json, text, bytes (default: text)
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # PATCH partial update
  http://api.example.com/users/123.patch(body="{{\"email\":\"new@example.com\"}}",content_type="application/json")

  # PATCH with query parameters
  http://api.example.com/resource.patch(body="{{\"status\":\"active\"}}",query="version=2",content_type="application/json")

  # PATCH from file
  http://api.example.com/document.patch(body_file="/path/to/changes.json",content_type="application/json")

EXIT CODES:
  0    Success (2xx HTTP status)
  1    Network error or invalid arguments
  2    Non-2xx HTTP status
  3    Invalid JSON (when accept="json")

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "delete" => {
                write!(io.stdout, r#"
DELETE VERB - HTTP HANDLE
========================

DESCRIPTION:
  Remove a resource from the server. DELETE requests should be idempotent -
  deleting the same resource multiple times has the same effect.

SYNTAX:
  http://HOST:PORT/PATH.delete(arguments)
  https://HOST:PORT/PATH.delete(arguments)

PARAMETERS:
  headers=HEADERS        Custom HTTP headers
  query=QUERY            Query parameters
  accept=FORMAT          Response format: json, text, bytes (default: text)
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # Simple DELETE
  http://api.example.com/users/123.delete

  # DELETE with confirmation parameter
  http://api.example.com/resource.delete(query="force=true")

  # DELETE with authentication
  http://api.example.com/item.delete(headers="Authorization:Bearer token")

  # DELETE with JSON response
  http://api.example.com/resource/456.delete(accept="json")

EXIT CODES:
  0    Success (2xx HTTP status)
  1    Network error or invalid arguments
  2    Non-2xx HTTP status
  3    Invalid JSON (when accept="json")

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "options" => {
                write!(io.stdout, r#"
OPTIONS VERB - HTTP HANDLE
=========================

DESCRIPTION:
  Check what HTTP methods are allowed for a resource. Often used for
  API discovery and CORS preflight checks.

SYNTAX:
  http://HOST:PORT/PATH.options(arguments)
  https://HOST:PORT/PATH.options(arguments)

PARAMETERS:
  include_body=BOOL      Include response body (default: false)
  headers=HEADERS        Custom HTTP headers
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # Check allowed methods
  http://api.example.com/resource.options

  # OPTIONS with response body
  http://api.example.com/endpoint.options(include_body="true")

  # Check CORS support
  http://api.example.com/api/data.options

RESPONSE:
  Returns JSON with allowed methods and headers:
  {{
    "status": 204,
    "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
    "headers": {{
      "allow": "GET, POST, PUT, DELETE"
    }}
  }}

EXIT CODES:
  Always returns 0 (never fails on HTTP status)

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "preflight" => {
                write!(io.stdout, r#"
PREFLIGHT VERB - HTTP HANDLE
===========================

DESCRIPTION:
  Perform CORS preflight requests (OPTIONS with CORS headers) to check
  if a cross-origin request would be allowed.

SYNTAX:
  http://HOST:PORT/PATH.preflight(arguments)
  https://HOST:PORT/PATH.preflight(arguments)

PARAMETERS:
  origin=URL             Origin for CORS check (e.g., "https://app.com")
  method=METHOD          HTTP method to preflight (default: GET)
  request_headers=HEADERS Headers to request permission for (comma-separated)
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # Basic preflight check
  http://api.example.com/resource.preflight

  # Preflight with origin
  http://api.example.com/api/users.preflight(origin="https://myapp.example.com")

  # Preflight for POST with headers
  http://api.example.com/api/data.preflight(origin="https://app.com",method="POST",request_headers="Authorization,Content-Type")

RESPONSE:
  Returns JSON with CORS policy:
  {{
    "status": 204,
    "cors": {{
      "allowed_origins": ["*"],
      "allowed_methods": ["GET", "POST"],
      "allowed_headers": ["Content-Type", "Authorization"],
      "allow_credentials": true
    }}
  }}

EXIT CODES:
  Always returns 0 (never fails on HTTP status)

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "json" => {
                write!(io.stdout, r#"
JSON VERB - HTTP HANDLE
======================

DESCRIPTION:
  Make requests with JSON response envelope. Wraps the response in metadata
  including status, headers, and body type. Never fails on HTTP status.

SYNTAX:
  http://HOST:PORT/PATH.json(arguments)
  https://HOST:PORT/PATH.json(arguments)

PARAMETERS:
  method=METHOD          HTTP method to use (GET, POST, PUT, PATCH, DELETE, etc.)
  body=TEXT              Request body (when method is POST/PUT/PATCH)
  body_file=PATH         Request body from file
  content_type=TYPE      Content-Type header
  headers=HEADERS        Custom HTTP headers
  query=QUERY            Query parameters
  accept=FORMAT          Response format for body: json, text, bytes
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # GET with JSON envelope
  http://api.example.com/data.json(method="GET")

  # POST with JSON envelope
  http://api.example.com/users.json(method="POST",body="{{\"name\":\"Alice\"}}",content_type="application/json")

RESPONSE:
  Always returns JSON envelope:
  {{
    "status": 200,
    "status_text": "OK",
    "url": "http://api.example.com/data",
    "body": {{
      "type": "json",
      "value": {{...}}
    }}
  }}

EXIT CODES:
  Always returns 0 (never fails on HTTP status)

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            "headers" => {
                write!(io.stdout, r#"
HEADERS VERB - HTTP HANDLE
=========================

DESCRIPTION:
  Get only response headers as structured JSON. No response body is included
  in the output. Useful for inspecting server responses and debugging.

SYNTAX:
  http://HOST:PORT/PATH.headers(arguments)
  https://HOST:PORT/PATH.headers(arguments)

PARAMETERS:
  method=METHOD          HTTP method to use (GET, POST, PUT, PATCH, DELETE, etc.)
  body=TEXT              Request body (when method is POST/PUT/PATCH)
  body_file=PATH         Request body from file
  content_type=TYPE      Content-Type header
  headers=HEADERS        Custom HTTP headers
  query=QUERY            Query parameters
  timeout_ms=MILLISECONDS Request timeout (default: 30000)
  allow_insecure=BOOL    Allow invalid HTTPS certificates (default: false)

EXAMPLES:
  # Get headers as JSON
  http://api.example.com/resource.headers(method="GET")

  # Get POST response headers
  http://api.example.com/data.headers(method="POST",body="test")

  # Check authentication headers
  http://api.example.com/auth.headers(method="GET",headers="Authorization:Bearer token")

RESPONSE:
  Returns JSON with headers only:
  {{
    "status": 200,
    "status_text": "OK",
    "headers": {{
      "content-type": ["application/json"],
      "x-custom": ["value"]
    }},
    "body": null
  }}

EXIT CODES:
  Always returns 0 (never fails on HTTP status)

Use 'http:// --help' for complete HTTP handle documentation.
"#)?;
                Ok(Status::ok())
            }
            _ => {
                write!(io.stdout, "Unknown verb: {}. Available verbs are: get, head, post, put, patch, delete, options, preflight, json, headers.\n\nUse 'http:// --help' for complete documentation.\n", verb)?;
                Ok(Status::ok())
            }
        }
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
        &["get", "head", "post", "put", "patch", "delete", "options", "preflight", "json", "headers", "help", "--help", "-h"]
    }

    fn call(&self, verb: &str, args: &Args, io: &mut IoStreams) -> Result<Status> {
        // Check for help requests first
        if let Some(status) = Self::check_and_display_help(verb, io)? {
            return Ok(status);
        }
        
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
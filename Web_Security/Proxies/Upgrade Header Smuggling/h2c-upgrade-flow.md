# 代理如何判断进入"隧道模式" — 三种场景对比

## 场景一：正常 H2 (HTTPS + ALPN) — 代理全程可见 ✅

```
客户端                    反向代理                     后端
  │                         │                          │
  │  ──── TCP 三次握手 ────→│                          │
  │                         │                          │
  │  ──── TLS ClientHello ─→│                          │
  │      ALPN: h2           │                          │
  │                         │  ← 代理记住: 这是 HTTP/2  │
  │                         │                          │
  │  ←─── TLS ServerHello ──│                          │
  │      ALPN: h2           │                          │
  │                         │                          │
  │  ════ TLS 加密通道建立 ═══│                          │
  │                         │                          │
  │  ──── HTTP/2 Frame ────→│  ──── HTTP/1.1 ────────→│  ← 代理解析每帧
  │      :path: /admin      │      GET /admin          │     提取 :path
  │                         │                          │     做 ACL 检查
  │  ←─── HTTP/2 Frame ─────│  ←─── HTTP/1.1 ─────────│
  │      :status: 403       │      403 Forbidden       │     拒绝 /admin
  │                         │                          │
  │                         │                          │
  │  ──── HTTP/2 Frame ────→│  ──── HTTP/1.1 ────────→│
  │      :path: /public     │      GET /public         │     放行 /public
  │                         │                          │
  │  ←─── HTTP/2 Frame ─────│  ←─── HTTP/1.1 ─────────│
  │      :status: 200       │      200 OK              │
  │                         │                          │

关键: TLS 握手阶段 ALPN 已告知代理"这是 h2"。
     代理从第一帧起就在 HTTP 帧解析模式下工作，从未离开。
```

## 场景二：正常 H2C (明文 + Upgrade) — 代理被 Upgrade "踢出" ❌

```
客户端                    反向代理                     后端
  │                         │                          │
  │  ──── HTTP/1.1 ────────→│  ──── HTTP/1.1 ────────→│
  │      GET /public        │      GET /public         │
  │      Upgrade: h2c       │      Upgrade: h2c       │
  │      HTTP2-Settings: .. │      HTTP2-Settings: ..  │
  │      Connection: ...    │      Connection: ...     │
  │                         │                          │
  │                         │  ← 后端: "好，切到 h2c"  │
  │  ←─── HTTP/1.1 ─────────│  ←─── HTTP/1.1 ─────────│
  │      101 Switching      │      101 Switching       │
  │                         │                          │
  │                         │                          │
  │         代理看到 101 ↓ 进入 Tunnel Mode             │
  │         停止解析 HTTP，退化为 TCP 管道              │
  │                         │                          │
  │                         │                          │
  │  ════ HTTP/2 帧 ════════╪══════ HTTP/2 帧 ════════→│
  │      :path: /admin      │      :path: /admin      │
  │                         │                          │
  │                         │  ← 代理不解析此帧！！     │
  │                         │     盲传给后端            │
  │                         │                          │
  │  ════ HTTP/2 帧 ════════╪══════ HTTP/2 帧 ════════│
  │      :status: 200       │      :status: 200       │
  │                         │                          │

关键: 代理在收到 101 后切换到了"隧道模式"的代码分支。
     后续 HTTP/2 帧虽然是明文、可解析，但代码已经不解析了。
```

## 场景三：H2C 走私攻击 (TLS + 内部 h2c Upgrade) 🔴

```
客户端                    反向代理                     后端
  │                         │                          │
  │  ──── TLS 握手 ────────→│                          │
  │      ALPN: http/1.1    │                          │  注意: ALPN 说的是
  │                         │  ← 代理模式: HTTP/1.1    │  http/1.1，不是 h2
  │                         │                          │
  │  ════ TLS 加密 ════════╪                          │
  │                         │                          │
  │  ───TLS 内的 HTTP/1.1──→│  ──── HTTP/1.1 ────────→│
  │   GET /public           │  GET /public             │
  │   Upgrade: h2c   ←──────│  Upgrade: h2c   ←────────│  代理转发 Upgrade
  │   HTTP2-Settings: ..    │  HTTP2-Settings: ..      │  头部到后端
  │   Connection: ...       │  Connection: ...         │
  │                         │                          │
  │                         │  ← 后端支持 h2c，同意升级 │
  │  ←──TLS 内的 HTTP/1.1───│  ←─── HTTP/1.1 ─────────│
  │   101 Switching         │  101 Switching           │
  │                         │                          │
  │                         │                          │
  │         代理看到 101 ↓ 进入 Tunnel Mode             │
  │         代理认为: "协议切换了，我不管了"             │
  │                         │                          │
  │                         │                          │
  │  ═══TLS 内的 H2 帧══════╪══════ H2 帧 (明文) ═════→│
  │   :path: /flag          │   :path: /flag           │
  │                         │                          │
  │                         │  ← 代理 ACL: "禁止 /flag"│
  │                         │   但代理在隧道模式中      │
  │                         │   跳过所有检查！          │
  │                         │                          │
  │  ═══TLS 内的 H2 帧══════╪══════ H2 帧 (明文) ══════│
  │   :status: 200          │   :status: 200           │
  │   "You got the flag!"   │   "You got the flag!"    │
  │                         │                          │

RFC 违规点:
  1. h2c 升级应该发生在端到端明文连接，而非 TLS 连接内部的明文段
  2. HTTP2-Settings 是 hop-by-hop 头部，代理不应转发 (RFC 7540 §3.2.1)
  3. 代理应对非 WebSocket 的 Upgrade 进行限制

工具: curl 等标准客户端拒绝在 HTTPS 上发起 h2c 升级。
     h2csmuggler 使用自定义 TCP 连接绕过此限制。
```

## 汇总对比

```
                    ┌──────────────┬──────────────────┬──────────────────┐
                    │  H2 (正常)    │  H2C (正常)      │  H2C 走私         │
┌───────────────────┼──────────────┼──────────────────┼──────────────────┤
│ 客户端→代理       │  TLS         │  明文            │  TLS             │
│                   │              │                  │                  │
│ ALPN 协商         │  h2          │  (不适用,TLS无)  │  http/1.1        │
│                   │              │                  │                  │
│ 协议协商方式       │  ALPN        │  HTTP Upgrade    │  HTTP Upgrade    │
│                   │  (握手阶段)  │  (请求阶段)      │  (请求阶段)      │
│                   │              │                  │                  │
│ 代理初始代码路径   │  HTTP/2 帧解析│  HTTP/1.1 解析   │  HTTP/1.1 解析   │
│                   │              │                  │                  │
│ 代理是否看到 101?  │  否          │  是              │  是              │
│                   │              │                  │                  │
│ 代理最终代码路径   │  HTTP/2 帧解析│  TCP 隧道        │  TCP 隧道        │
│                   │  (全程保持)  │  (被 Upgrade踢出) │  (被 Upgrade踢出) │
│                   │              │                  │                  │
│ 代理能否审计流量?  │  能          │  不能            │  不能            │
│                   │              │  (代码不再解析)  │  (代码不再解析)  │
│                   │              │                  │                  │
│ ACL/WAF 有效?     │  是          │  否              │  否              │
└───────────────────┴──────────────┴──────────────────┴──────────────────┘
```

## 核心结论

**代理对 H2C "失明"不是加密问题，是代码路径问题。**

```
TLS-ALPN 协商 h2:
  代理代码路径: [HTTP/2 帧解析] ────────→ 永远停留在这个状态

HTTP/1.1 Upgrade h2c:
  代理代码路径: [HTTP/1.1 解析] → 101 → [TCP 隧道 (盲传)]

代理的能力始终没变——它完全有能力解析明文 H2C 的 HTTP/2 帧。
但 Upgrade 机制的设计意图就是"收 101 后放手"。
代理不区分 WebSocket 的 101 和 H2C 的 101，一视同仁地进入隧道模式。
```

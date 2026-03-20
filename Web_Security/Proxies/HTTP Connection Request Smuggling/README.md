## HTTP 连接请求走私 (Connection Request Smuggling)

# 0x01 概述

该漏洞源于现代协议（HTTP/1.1 Keep-Alive, HTTP/2, HTTP/3）中**连接状态（Connection-State）**的滥用。其核心矛盾在于：**前端代理仅在 TCP/TLS 连接建立后的“第一个请求”进行安全校验或路由判定，而后续复用该连接的请求则被信任并直接转发。**

这使得攻击者可以通过一个合法的“首次请求”打开通道，随后在同一连接中“走私”对内部受限主机的请求。

------

# 0x02 攻击分类与原理

#### 1. 首次请求校验绕过 (First-request Validation)

许多反向代理使用白名单机制拦截对内部 `Host` 的访问。

- **缺陷**：白名单检查仅作用于连接中的第一个 Request。

- **利用方式**：

  HTTP

  ```
  /* 请求 1：访问允许的外部域名，打开连接闸门 */
  GET / HTTP/1.1
  Host: allowed-external-host.example
  
  /* 请求 2：在同一 TCP 连接中发送，绕过校验访问内网 */
  GET /admin HTTP/1.1
  Host: internal-only.example
  ```

#### 2. 首次请求路由锁定 (First-request Routing)

反向代理根据第一个请求的 `Host` 头部选择后端连接池，并将该 TCP 嵌套字（Socket）与特定的后端服务器绑定。

- **后果**：后续所有请求无论 `Host` 是什么，都会被路由到第一个请求决定的后端。
- **风险**：结合 **Web 缓存污染** 或 **密码重置毒化**，可以实现类似 SSRF 的效果，攻击其他虚拟主机。

------

# 0x03 现代进阶：HTTP/2 & HTTP/3 连接合并滥用

这是 2023-2025 年间安全研究的热点（由 PortSwigger 的 James Kettle 提出）。

#### 核心逻辑：Connection Coalescing (连接合并)

现代浏览器（Chrome/Edge/Firefox）为了性能，如果满足以下条件，会将不同域名的请求合并到同一个 H2/H3 连接中：

1. **IP 地址一致**（解析到同一个 CDN 节点）。
2. **TLS 证书匹配**（通常是通配符证书 `*.company.com`）。
3. **协议一致**（ALPN 均为 h2 或 h3）。

#### 攻击场景：

1. 攻击者控制 `evil.com`，其与目标 `internal.company.com` 解析到同一 CDN IP，且共用通配符证书。
2. 受害者访问 `evil.com`，建立 H2 连接。
3. 攻击者在页面嵌入 `<img src="https://internal.company.com/admin">`。
4. 浏览器发现参数匹配，通过**已有连接**发送对 `internal` 的请求。
5. 如果前端代理只校验了第一个 `evil.com` 的请求，`internal` 的敏感接口将暴露给攻击者。

------

# 0x04 案例记录 (2022-2025)

| **年份** | **组件**                  | **编号**           | **备注**                                                     |
| -------- | ------------------------- | ------------------ | ------------------------------------------------------------ |
| **2022** | **AWS ALB**               | -                  | 仅校验首个请求的 Host，已由 SecurityLabs 报告并修复。        |
| **2023** | **Apache Traffic Server** | **CVE-2023-39852** | H2 连接复用导致的走私，影响版本 < 9.2.2。                    |
| **2024** | **Envoy Proxy**           | **CVE-2024-2470**  | 在共享 Mesh 环境中，对 `:authority` 校验不当导致跨租户走私。 |

------

# 0x05 检测与工具链

#### 1. 自动化探测

- **Burp Suite Professional**：
  - 启用 `HTTP Request Smuggler` 插件中的 **Connection-state probe**。
  - 利用 2023.12 引入的 **HTTP/2 Smuggler 插入点** 进行自动测试。
- **smuggleFuzz (2024)**：
  - 微软发布的 Python 框架，专门用于暴力破解 H2/H3 的 desync 向量及连接状态排列组合。

#### 2. 手动验证 Cheat-Sheet

- **HTTP/1.1**：
  1. 在 Repeater 中开启 `Keep-alive`。
  2. 发送请求 A（合法 Host），紧接着发送请求 B（内部 Host）。
  3. 观察请求 B 的响应是否来自预期的后端。
- **HTTP/2**：
  1. 在同一 TLS 连接中开启 Stream 1（访问正常页面）。
  2. 多路复用开启 Stream 3，修改 `:authority` 为内部域名。
  3. 检查 Stream 3 是否返回了不应被访问的内容。

------

# 0x06 防御与加固策略

- **原子化校验**：**必须**对连接中的每一个 Stream/Request 重新校验 `Host` 或 `:authority`，严禁只校验“首个请求”。
- **关闭 Origin Coalescing**：在 Nginx 等代理中，根据需求禁用 H2 的域名合并特性（如 `http2_origin_cn off`）。
- **证书/IP 隔离**：对内外网域名使用不同的证书或独立 IP，从根本上阻止浏览器合法的合并行为。
- **连接重置**：在处理完高敏感请求后，强制发送 `Connection: close` 或利用 `proxy_next_upstream` 重新选择后端。


